//! Portable, architecture-independent kllm primitives.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Maximum accepted interactive command-line length, in bytes.
pub const MAX_LINE_BYTES: usize = 512;
/// Maximum number of arguments in one pipeline stage, including the command.
pub const MAX_ARGS: usize = 32;
/// Maximum number of stages in one pipeline.
pub const MAX_PIPELINE_STAGES: usize = 8;
/// Maximum bytes passed between two pipeline stages.
pub const PIPE_CAPACITY: usize = 64 * 1024;

/// Failures produced by a byte stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError {
    /// The destination cannot accept more bytes.
    NoSpace,
    /// The stream is not readable or writable as requested.
    Unsupported,
    /// The underlying device failed.
    Device,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSpace => f.write_str("stream capacity exceeded"),
            Self::Unsupported => f.write_str("stream operation is unsupported"),
            Self::Device => f.write_str("stream device error"),
        }
    }
}

/// Byte-oriented input capability.
pub trait Input {
    /// Read up to `destination.len()` bytes. Zero means end of input.
    ///
    /// # Errors
    ///
    /// Returns a typed stream failure without modifying bytes beyond the
    /// reported count.
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, StreamError>;
}

/// Byte-oriented output capability.
pub trait Output {
    /// Write some bytes, returning the number accepted.
    ///
    /// # Errors
    ///
    /// Returns a typed capacity, support, or device failure.
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError>;
}

/// Write all bytes or return the first stream failure.
///
/// # Errors
///
/// Returns the underlying stream error, or `Device` if the implementation
/// violates the `Output` progress contract.
pub fn write_all(output: &mut dyn Output, mut bytes: &[u8]) -> Result<(), StreamError> {
    while !bytes.is_empty() {
        let count = output.write(bytes)?;
        if count == 0 || count > bytes.len() {
            return Err(StreamError::Device);
        }
        bytes = &bytes[count..];
    }
    Ok(())
}

/// An input stream over an immutable byte slice.
#[derive(Debug)]
pub struct SliceInput<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_chunk: usize,
}

impl<'a> SliceInput<'a> {
    /// Construct an input that may satisfy each read in one operation.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            max_chunk: usize::MAX,
        }
    }

    /// Restrict individual reads, useful for testing partial-I/O handling.
    #[must_use]
    pub const fn with_max_chunk(bytes: &'a [u8], max_chunk: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            max_chunk,
        }
    }
}

impl Input for SliceInput<'_> {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, StreamError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        let count = remaining.min(destination.len()).min(self.max_chunk);
        if count == 0 {
            return Ok(0);
        }
        destination[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

/// A growable output with an explicit hard byte limit.
#[derive(Debug)]
pub struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedOutput {
    /// Construct an empty bounded output.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    /// Borrow all accepted bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the stream and return its bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

impl Output for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(StreamError::NoSpace)?;
        if new_len > self.limit {
            return Err(StreamError::NoSpace);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
}

/// Stable command result categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandStatus {
    /// Command completed successfully.
    Success,
    /// Input or arguments were invalid.
    Usage,
    /// A named object did not exist.
    NotFound,
    /// An I/O or filesystem operation failed.
    Failure,
    /// The command was not granted the requested authority.
    Denied,
}

impl CommandStatus {
    /// Process-style numeric representation for the hosted model.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Usage => 2,
            Self::NotFound => 3,
            Self::Failure => 1,
            Self::Denied => 126,
        }
    }
}

/// Snapshot reported by `mem` and `/sys/memory`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryStats {
    /// Normalized usable bytes.
    pub total: u64,
    /// Permanently reserved bytes.
    pub reserved: u64,
    /// Estimated free bytes.
    pub free: u64,
    /// Live RAMFS payload bytes.
    pub ramfs_used: u64,
    /// RAMFS hard byte limit.
    pub ramfs_limit: u64,
    /// Maximum observed live RAMFS payload bytes.
    pub ramfs_high_water: u64,
}

#[cfg(test)]
mod tests {
    use super::{BoundedOutput, Input, Output, SliceInput, StreamError, write_all};

    struct PartialOutput {
        bytes: alloc::vec::Vec<u8>,
    }

    impl Output for PartialOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            let count = bytes.len().min(1);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
    }

    #[test]
    fn partial_reads_advance_safely() {
        let mut input = SliceInput::with_max_chunk(b"abcd", 2);
        let mut buffer = [0_u8; 4];
        assert_eq!(input.read(&mut buffer), Ok(2));
        assert_eq!(&buffer[..2], b"ab");
        assert_eq!(input.read(&mut buffer), Ok(2));
        assert_eq!(&buffer[..2], b"cd");
        assert_eq!(input.read(&mut buffer), Ok(0));
    }

    #[test]
    fn output_limit_is_atomic_per_write() {
        let mut output = BoundedOutput::new(3);
        assert_eq!(output.write(b"ab"), Ok(2));
        assert_eq!(output.write(b"cd"), Err(StreamError::NoSpace));
        assert_eq!(output.as_slice(), b"ab");
    }

    #[test]
    fn write_all_handles_stream_contract() {
        let mut output = PartialOutput {
            bytes: alloc::vec::Vec::new(),
        };
        assert_eq!(write_all(&mut output, b"test"), Ok(()));
        assert_eq!(output.bytes, b"test");
    }
}

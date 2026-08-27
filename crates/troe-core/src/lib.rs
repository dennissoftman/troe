//! Portable, architecture-independent TROE primitives.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Maximum accepted interactive command-line length, in bytes.
pub const MAX_LINE_BYTES: usize = 512;
/// Maximum number of arguments in one pipeline stage, including the command.
pub const MAX_ARGS: usize = 128;
/// Maximum number of stages in one pipeline.
pub const MAX_PIPELINE_STAGES: usize = 255;
/// Maximum aggregate bytes retained between sequential pipeline stages.
///
/// The current shell executes stages sequentially, so an intermediate stage
/// must be retained until its consumer runs. This limit does not apply to
/// terminal streams or file redirection and is not a transfer-chunk size.
pub const PIPE_CAPACITY: usize = 1024 * 1024;

/// Whether a terminal character requests deletion of the preceding character.
///
/// Interactive transports disagree on whether the Backspace key produces the
/// ASCII BS character or DEL. Firmware, UART, and future remote-terminal
/// frontends use this shared rule so terminal configuration does not alter the
/// editing semantics.
#[must_use]
pub const fn is_backspace(character: char) -> bool {
    matches!(character, '\u{8}' | '\u{7f}')
}

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
    /// Request a preferred downstream aggregation size.
    ///
    /// Implementations that buffer file writes may accept this hint; direct
    /// devices and retained diagnostic streams normally reject it. The value
    /// never changes the maximum stream or file length.
    ///
    /// # Errors
    ///
    /// Returns `Unsupported` when the sink is not configurable or the hint is
    /// outside its enforced policy.
    fn set_chunk_size(&mut self, _bytes: usize) -> Result<(), StreamError> {
        Err(StreamError::Unsupported)
    }

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
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| StreamError::NoSpace)?;
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
    /// Cooperative execution was cancelled by the user.
    Cancelled,
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
            Self::Cancelled => 130,
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

/// Component that currently owns and accounts for machine memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineMemoryOwner {
    /// The shell is running inside a hosted process.
    Host,
    /// UEFI boot services still own machine memory.
    Firmware,
    /// The kernel has completed the reviewed ownership transition.
    Kernel,
}

/// Machine-memory information supplied to portable reporting code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineMemorySnapshot {
    owner: MachineMemoryOwner,
    usable_bytes: Option<u64>,
    reserved_bytes: Option<u64>,
    total_frames: Option<u64>,
    free_frames: Option<u64>,
    heap_total_bytes: Option<u64>,
    heap_used_bytes: Option<u64>,
    heap_high_water_bytes: Option<u64>,
    failed_allocations: Option<u64>,
}

impl MachineMemorySnapshot {
    /// Construct a hosted snapshot without physical-memory visibility.
    #[must_use]
    pub const fn hosted() -> Self {
        Self {
            owner: MachineMemoryOwner::Host,
            usable_bytes: None,
            reserved_bytes: None,
            total_frames: None,
            free_frames: None,
            heap_total_bytes: None,
            heap_used_bytes: None,
            heap_high_water_bytes: None,
            failed_allocations: None,
        }
    }

    /// Construct an advisory snapshot while firmware still owns memory.
    #[must_use]
    pub const fn firmware(usable_bytes: u64, reserved_bytes: u64) -> Self {
        Self {
            owner: MachineMemoryOwner::Firmware,
            usable_bytes: Some(usable_bytes),
            reserved_bytes: Some(reserved_bytes),
            total_frames: None,
            free_frames: None,
            heap_total_bytes: None,
            heap_used_bytes: None,
            heap_high_water_bytes: None,
            failed_allocations: None,
        }
    }

    /// Construct a complete snapshot after kernel ownership begins.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn kernel(
        usable_bytes: u64,
        reserved_bytes: u64,
        total_frames: u64,
        free_frames: u64,
        heap_total_bytes: u64,
        heap_used_bytes: u64,
        heap_high_water_bytes: u64,
        failed_allocations: u64,
    ) -> Self {
        Self {
            owner: MachineMemoryOwner::Kernel,
            usable_bytes: Some(usable_bytes),
            reserved_bytes: Some(reserved_bytes),
            total_frames: Some(total_frames),
            free_frames: Some(free_frames),
            heap_total_bytes: Some(heap_total_bytes),
            heap_used_bytes: Some(heap_used_bytes),
            heap_high_water_bytes: Some(heap_high_water_bytes),
            failed_allocations: Some(failed_allocations),
        }
    }

    /// Current memory owner.
    #[must_use]
    pub const fn owner(self) -> MachineMemoryOwner {
        self.owner
    }

    /// Bytes currently classified as usable, when observable.
    #[must_use]
    pub const fn usable_bytes(self) -> Option<u64> {
        self.usable_bytes
    }

    /// Bytes currently classified as reserved or otherwise unusable.
    #[must_use]
    pub const fn reserved_bytes(self) -> Option<u64> {
        self.reserved_bytes
    }

    /// Number of usable physical frames, when owned.
    #[must_use]
    pub const fn total_frames(self) -> Option<u64> {
        self.total_frames
    }

    /// Number of currently free physical frames, when owned.
    #[must_use]
    pub const fn free_frames(self) -> Option<u64> {
        self.free_frames
    }

    /// General-heap arena bytes, when owned.
    #[must_use]
    pub const fn heap_total_bytes(self) -> Option<u64> {
        self.heap_total_bytes
    }

    /// Currently consumed general-heap bytes, when owned.
    #[must_use]
    pub const fn heap_used_bytes(self) -> Option<u64> {
        self.heap_used_bytes
    }

    /// Maximum observed general-heap consumption, when owned.
    #[must_use]
    pub const fn heap_high_water_bytes(self) -> Option<u64> {
        self.heap_high_water_bytes
    }

    /// Rejected general-heap allocation requests, when observable.
    #[must_use]
    pub const fn failed_allocations(self) -> Option<u64> {
        self.failed_allocations
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedOutput, CommandStatus, Input, Output, SliceInput, StreamError, is_backspace,
        write_all,
    };

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

    #[test]
    fn terminal_backspace_accepts_bs_and_del() {
        assert!(is_backspace('\u{8}'));
        assert!(is_backspace('\u{7f}'));
        assert!(!is_backspace('x'));
    }

    #[test]
    fn command_status_codes_are_exhaustive_and_stable() {
        assert_eq!(
            [
                CommandStatus::Success,
                CommandStatus::Failure,
                CommandStatus::Usage,
                CommandStatus::NotFound,
                CommandStatus::Denied,
                CommandStatus::Cancelled,
            ]
            .map(CommandStatus::code),
            [0, 1, 2, 3, 126, 130]
        );
    }
}

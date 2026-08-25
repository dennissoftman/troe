//! Stable, allocation-free application service protocols.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

use core::str;

/// Application ABI major implemented by the current kernel and SDK.
pub const ABI_MAJOR: u16 = 1;
/// Highest compatible application ABI minor implemented by the current kernel and SDK.
pub const ABI_MINOR: u16 = 0;
/// Maximum complete request or reply crossing the application call gate.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
/// Maximum service payload after the required two-byte opcode.
pub const MAX_SERVICE_PAYLOAD_BYTES: usize = MAX_MESSAGE_BYTES - 2;

/// Stable interface identifiers carried by startup handle descriptors.
pub mod interface {
    /// One immutable command invocation.
    pub const COMMAND: u32 = 1;
    /// Standard input byte stream for one command launch.
    pub const STANDARD_INPUT: u32 = 2;
    /// Standard output byte stream for one command launch.
    pub const STANDARD_OUTPUT: u32 = 3;
    /// Standard error byte stream for one command launch.
    pub const STANDARD_ERROR: u32 = 4;
    /// Owned IPv4 datagram endpoint for one application lifetime.
    pub const DATAGRAM: u32 = 5;
    /// Read-only view of one application namespace.
    pub const FILESYSTEM_READ: u32 = 6;
    /// Atomic create/replace and remove authority for one application namespace.
    pub const FILESYSTEM_MUTATE: u32 = 7;
}

/// Canonical package-side declaration of optional startup authorities.
pub mod requirements {
    /// Product-independent capability-manifest format identifier.
    pub const MAGIC: [u8; 8] = *b"KCAPv1\0\0";
    /// Fixed manifest header bytes.
    pub const HEADER_BYTES: usize = 16;
    /// Fixed bytes per required interface.
    pub const RECORD_BYTES: usize = 8;
    /// Maximum optional startup authorities declared by one package.
    pub const MAX_REQUIREMENTS: usize = 16;
    /// Largest canonical manifest accepted by the kernel.
    pub const MAX_MANIFEST_BYTES: usize = HEADER_BYTES + MAX_REQUIREMENTS * RECORD_BYTES;

    /// One exact interface version required at application startup.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Requirement {
        /// Stable interface identifier.
        pub interface: u32,
        /// Required interface major version.
        pub major: u16,
        /// Required interface minor version.
        pub minor: u16,
    }

    /// Invalid, excessive, unsorted, or noncanonical manifest bytes.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Borrowed validated capability manifest.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Manifest<'a> {
        bytes: &'a [u8],
        count: usize,
    }

    impl<'a> Manifest<'a> {
        /// Parse one exact manifest without allocation.
        ///
        /// # Errors
        ///
        /// Rejects every truncation, trailing byte, reserved field, zero
        /// identifier/version, duplicate, or non-ascending interface record.
        pub fn parse(bytes: &'a [u8]) -> Result<Self, EncodingError> {
            if bytes.len() < HEADER_BYTES || bytes[..8] != MAGIC {
                return Err(EncodingError);
            }
            let count = usize::from(read_u16(bytes, 8)?);
            let expected = HEADER_BYTES
                .checked_add(count.checked_mul(RECORD_BYTES).ok_or(EncodingError)?)
                .ok_or(EncodingError)?;
            if count > MAX_REQUIREMENTS
                || read_u16(bytes, 10)? != 0
                || usize::try_from(read_u32(bytes, 12)?).map_err(|_| EncodingError)? != expected
                || bytes.len() != expected
            {
                return Err(EncodingError);
            }
            let manifest = Self { bytes, count };
            let mut previous = 0_u32;
            for requirement in manifest.iter() {
                if requirement.interface <= previous || requirement.major == 0 {
                    return Err(EncodingError);
                }
                previous = requirement.interface;
            }
            Ok(manifest)
        }

        /// Number of optional authorities required by the package.
        #[must_use]
        pub const fn len(self) -> usize {
            self.count
        }

        /// Whether the package requests no optional authority.
        #[must_use]
        pub const fn is_empty(self) -> bool {
            self.count == 0
        }

        /// Iterate through ascending, unique interface requirements.
        #[must_use]
        pub const fn iter(self) -> Requirements<'a> {
            Requirements {
                manifest: self,
                index: 0,
            }
        }
    }

    /// Iterator over validated interface requirements.
    pub struct Requirements<'a> {
        manifest: Manifest<'a>,
        index: usize,
    }

    impl Iterator for Requirements<'_> {
        type Item = Requirement;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index >= self.manifest.count {
                return None;
            }
            let offset = HEADER_BYTES + self.index * RECORD_BYTES;
            self.index += 1;
            Some(Requirement {
                interface: read_u32(self.manifest.bytes, offset).ok()?,
                major: read_u16(self.manifest.bytes, offset + 4).ok()?,
                minor: read_u16(self.manifest.bytes, offset + 6).ok()?,
            })
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.manifest.count.saturating_sub(self.index);
            (remaining, Some(remaining))
        }
    }

    impl ExactSizeIterator for Requirements<'_> {}

    /// Encode ascending, unique optional interface requirements.
    ///
    /// # Errors
    ///
    /// Rejects policy excess, zero identifier/version, non-ascending records,
    /// or insufficient destination storage without modifying it.
    pub fn encode(
        requirements: &[Requirement],
        destination: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let count = requirements.len();
        let encoded_bytes = HEADER_BYTES
            .checked_add(count.checked_mul(RECORD_BYTES).ok_or(EncodingError)?)
            .ok_or(EncodingError)?;
        if count > MAX_REQUIREMENTS || destination.len() < encoded_bytes {
            return Err(EncodingError);
        }
        let mut previous = 0_u32;
        for requirement in requirements {
            if requirement.interface <= previous || requirement.major == 0 {
                return Err(EncodingError);
            }
            previous = requirement.interface;
        }
        let mut encoded = [0_u8; MAX_MANIFEST_BYTES];
        encoded[..8].copy_from_slice(&MAGIC);
        encoded[8..10].copy_from_slice(
            &u16::try_from(count)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        encoded[12..16].copy_from_slice(
            &u32::try_from(encoded_bytes)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        for (index, requirement) in requirements.iter().enumerate() {
            let offset = HEADER_BYTES + index * RECORD_BYTES;
            encoded[offset..offset + 4].copy_from_slice(&requirement.interface.to_le_bytes());
            encoded[offset + 4..offset + 6].copy_from_slice(&requirement.major.to_le_bytes());
            encoded[offset + 6..offset + 8].copy_from_slice(&requirement.minor.to_le_bytes());
        }
        destination[..encoded_bytes].copy_from_slice(&encoded[..encoded_bytes]);
        Ok(encoded_bytes)
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
        let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EncodingError> {
        let raw = bytes.get(offset..offset + 4).ok_or(EncodingError)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }
}

/// Stable service reply values returned by ABI `handle_call`.
pub mod reply {
    /// Operation completed and the reply payload is valid.
    pub const SUCCESS: u32 = 0;
    /// Opcode or request payload was invalid.
    pub const INVALID_REQUEST: u32 = 1;
    /// Requested service object does not exist.
    pub const NOT_FOUND: u32 = 2;
    /// Service could not complete the operation.
    pub const FAILURE: u32 = 3;
    /// A bounded service resource is exhausted.
    pub const EXHAUSTED: u32 = 4;
    /// The network service has no usable address configuration.
    pub const NOT_CONFIGURED: u32 = 5;
    /// Cooperative work was cancelled by the caller.
    pub const CANCELLED: u32 = 6;
    /// A bounded service wait expired.
    pub const TIMEOUT: u32 = 7;
    /// The requested resource is owned by another endpoint.
    pub const CONFLICT: u32 = 8;
    /// The request exceeds a service-domain payload limit.
    pub const TOO_LARGE: u32 = 9;
    /// A path or namespace request is syntactically invalid.
    pub const INVALID_PATH: u32 = 10;
    /// A file was used as a directory or the reverse.
    pub const WRONG_TYPE: u32 = 11;
    /// Mutation targeted immutable filesystem content.
    pub const READ_ONLY: u32 = 12;
    /// A filesystem byte, node, or file-size quota is exhausted.
    pub const NO_SPACE: u32 = 13;
    /// A filesystem object already exists.
    pub const EXISTS: u32 = 14;
    /// Filesystem metadata is corrupt.
    pub const CORRUPT: u32 = 15;
    /// The filesystem transport failed.
    pub const IO: u32 = 16;
    /// The filesystem requires an unsupported feature.
    pub const UNSUPPORTED: u32 = 17;
    /// Filesystem size or offset arithmetic overflowed.
    pub const OVERFLOW: u32 = 18;
}

/// Stable command exit values understood by the recovery shell.
pub mod exit {
    /// Command completed successfully.
    pub const SUCCESS: u32 = 0;
    /// Command failed.
    pub const FAILURE: u32 = 1;
    /// Arguments or input were invalid.
    pub const USAGE: u32 = 2;
    /// Requested object does not exist.
    pub const NOT_FOUND: u32 = 3;
    /// Required authority was not granted.
    pub const DENIED: u32 = 126;
    /// Cooperative execution was cancelled.
    pub const CANCELLED: u32 = 130;
}

/// Command-invocation protocol.
pub mod command {
    use super::{MAX_MESSAGE_BYTES, str};

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Return the immutable invocation record.
    pub const GET_INVOCATION: u16 = 1;
    /// Maximum arguments including the command name.
    pub const MAX_ARGUMENTS: usize = 32;
    /// Maximum encoded current-directory bytes.
    pub const MAX_CWD_BYTES: usize = 256;
    /// Maximum aggregate UTF-8 argument bytes.
    pub const MAX_ARGUMENT_BYTES: usize = 512;
    /// Fixed invocation header bytes.
    pub const HEADER_BYTES: usize = 8;
    /// Maximum complete canonical invocation reply.
    pub const MAX_INVOCATION_BYTES: usize =
        HEADER_BYTES + MAX_ARGUMENTS * 2 + MAX_CWD_BYTES + MAX_ARGUMENT_BYTES;

    /// Invocation encoding failure.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum EncodeError {
        /// Argument count, current directory, or total bytes exceeded a bound.
        LimitExceeded,
        /// The current directory was not an absolute path.
        InvalidCwd,
        /// The destination cannot hold the exact canonical record.
        DestinationTooSmall,
    }

    /// Invocation decoding failure.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum DecodeError {
        /// Header, version, length, or string-table layout was noncanonical.
        InvalidEncoding,
        /// Argument count or current-directory bytes exceeded a bound.
        LimitExceeded,
        /// Current-directory or argument bytes were not valid UTF-8.
        InvalidUtf8,
    }

    /// Borrowed, validated command invocation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Invocation<'a> {
        bytes: &'a [u8],
        argument_count: usize,
        cwd_start: usize,
        cwd_end: usize,
        arguments_start: usize,
    }

    impl<'a> Invocation<'a> {
        /// Parse one exact canonical invocation reply.
        ///
        /// # Errors
        ///
        /// Rejects every malformed, excessive, non-UTF-8, or trailing byte.
        pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
            if bytes.len() < HEADER_BYTES
                || usize::from(read_u16(bytes, 0)?) != bytes.len()
                || bytes[2] != u8::try_from(MAJOR).unwrap_or(u8::MAX)
                || bytes[3] != u8::try_from(MINOR).unwrap_or(u8::MAX)
            {
                return Err(DecodeError::InvalidEncoding);
            }
            let argument_count = usize::from(read_u16(bytes, 4)?);
            let cwd_bytes = usize::from(read_u16(bytes, 6)?);
            if !(1..=MAX_ARGUMENTS).contains(&argument_count) || cwd_bytes > MAX_CWD_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            let length_table_bytes = argument_count
                .checked_mul(2)
                .ok_or(DecodeError::InvalidEncoding)?;
            let cwd_start = HEADER_BYTES
                .checked_add(length_table_bytes)
                .ok_or(DecodeError::InvalidEncoding)?;
            let cwd_end = cwd_start
                .checked_add(cwd_bytes)
                .ok_or(DecodeError::InvalidEncoding)?;
            if cwd_end > bytes.len() {
                return Err(DecodeError::InvalidEncoding);
            }
            let cwd =
                str::from_utf8(&bytes[cwd_start..cwd_end]).map_err(|_| DecodeError::InvalidUtf8)?;
            if !cwd.starts_with('/') {
                return Err(DecodeError::InvalidEncoding);
            }
            let mut cursor = cwd_end;
            let mut argument_bytes = 0_usize;
            for index in 0..argument_count {
                let length = usize::from(read_u16(bytes, HEADER_BYTES + index * 2)?);
                argument_bytes = argument_bytes
                    .checked_add(length)
                    .ok_or(DecodeError::InvalidEncoding)?;
                if argument_bytes > MAX_ARGUMENT_BYTES {
                    return Err(DecodeError::LimitExceeded);
                }
                let end = cursor
                    .checked_add(length)
                    .ok_or(DecodeError::InvalidEncoding)?;
                if end > bytes.len() || str::from_utf8(&bytes[cursor..end]).is_err() {
                    return Err(if end > bytes.len() {
                        DecodeError::InvalidEncoding
                    } else {
                        DecodeError::InvalidUtf8
                    });
                }
                if index == 0 && length == 0 {
                    return Err(DecodeError::InvalidEncoding);
                }
                cursor = end;
            }
            if cursor != bytes.len() {
                return Err(DecodeError::InvalidEncoding);
            }
            Ok(Self {
                bytes,
                argument_count,
                cwd_start,
                cwd_end,
                arguments_start: cwd_end,
            })
        }

        /// Absolute logical working directory selected by the shell.
        #[must_use]
        pub fn cwd(self) -> &'a str {
            // Parsing validated this exact range as UTF-8.
            str::from_utf8(&self.bytes[self.cwd_start..self.cwd_end]).unwrap_or("")
        }

        /// Number of arguments, including the command name at index zero.
        #[must_use]
        pub const fn len(self) -> usize {
            self.argument_count
        }

        /// Invocations always contain a command name.
        #[must_use]
        pub const fn is_empty(self) -> bool {
            false
        }

        /// Return one validated argument.
        #[must_use]
        pub fn argument(self, wanted: usize) -> Option<&'a str> {
            if wanted >= self.argument_count {
                return None;
            }
            let mut cursor = self.arguments_start;
            for index in 0..self.argument_count {
                let length = usize::from(read_u16(self.bytes, HEADER_BYTES + index * 2).ok()?);
                let end = cursor.checked_add(length)?;
                if index == wanted {
                    return str::from_utf8(&self.bytes[cursor..end]).ok();
                }
                cursor = end;
            }
            None
        }

        /// Iterate over every validated argument.
        #[must_use]
        pub fn arguments(self) -> Arguments<'a> {
            Arguments {
                invocation: self,
                index: 0,
            }
        }
    }

    /// Iterator over borrowed invocation arguments.
    pub struct Arguments<'a> {
        invocation: Invocation<'a>,
        index: usize,
    }

    impl<'a> Iterator for Arguments<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            let value = self.invocation.argument(self.index)?;
            self.index += 1;
            Some(value)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.invocation.len().saturating_sub(self.index);
            (remaining, Some(remaining))
        }
    }

    impl ExactSizeIterator for Arguments<'_> {}

    /// Encode one canonical invocation into caller-owned storage.
    ///
    /// # Errors
    ///
    /// Rejects invalid current directories, policy excess, arithmetic overflow,
    /// or insufficient output space without modifying `destination`.
    pub fn encode<T: AsRef<str>>(
        cwd: &str,
        arguments: &[T],
        destination: &mut [u8],
    ) -> Result<usize, EncodeError> {
        if !cwd.starts_with('/') {
            return Err(EncodeError::InvalidCwd);
        }
        if cwd.len() > MAX_CWD_BYTES || !(1..=MAX_ARGUMENTS).contains(&arguments.len()) {
            return Err(EncodeError::LimitExceeded);
        }
        let mut total = HEADER_BYTES
            .checked_add(
                arguments
                    .len()
                    .checked_mul(2)
                    .ok_or(EncodeError::LimitExceeded)?,
            )
            .and_then(|value| value.checked_add(cwd.len()))
            .ok_or(EncodeError::LimitExceeded)?;
        let mut argument_bytes = 0_usize;
        for (index, argument) in arguments.iter().enumerate() {
            let length = argument.as_ref().len();
            if (index == 0 && length == 0) || length > usize::from(u16::MAX) {
                return Err(EncodeError::LimitExceeded);
            }
            argument_bytes = argument_bytes
                .checked_add(length)
                .ok_or(EncodeError::LimitExceeded)?;
            if argument_bytes > MAX_ARGUMENT_BYTES {
                return Err(EncodeError::LimitExceeded);
            }
            total = total
                .checked_add(length)
                .ok_or(EncodeError::LimitExceeded)?;
        }
        if total > MAX_INVOCATION_BYTES
            || total > MAX_MESSAGE_BYTES
            || total > usize::from(u16::MAX)
        {
            return Err(EncodeError::LimitExceeded);
        }
        if destination.len() < total {
            return Err(EncodeError::DestinationTooSmall);
        }
        let mut encoded = [0_u8; MAX_MESSAGE_BYTES];
        write_u16(
            &mut encoded,
            0,
            u16::try_from(total).map_err(|_| EncodeError::LimitExceeded)?,
        );
        encoded[2] = u8::try_from(MAJOR).map_err(|_| EncodeError::LimitExceeded)?;
        encoded[3] = u8::try_from(MINOR).map_err(|_| EncodeError::LimitExceeded)?;
        write_u16(
            &mut encoded,
            4,
            u16::try_from(arguments.len()).map_err(|_| EncodeError::LimitExceeded)?,
        );
        write_u16(
            &mut encoded,
            6,
            u16::try_from(cwd.len()).map_err(|_| EncodeError::LimitExceeded)?,
        );
        let mut cursor = HEADER_BYTES + arguments.len() * 2;
        encoded[cursor..cursor + cwd.len()].copy_from_slice(cwd.as_bytes());
        cursor += cwd.len();
        for (index, argument) in arguments.iter().enumerate() {
            let bytes = argument.as_ref().as_bytes();
            write_u16(
                &mut encoded,
                HEADER_BYTES + index * 2,
                u16::try_from(bytes.len()).map_err(|_| EncodeError::LimitExceeded)?,
            );
            encoded[cursor..cursor + bytes.len()].copy_from_slice(bytes);
            cursor += bytes.len();
        }
        destination[..total].copy_from_slice(&encoded[..total]);
        Ok(total)
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DecodeError> {
        let raw = bytes
            .get(offset..offset + 2)
            .ok_or(DecodeError::InvalidEncoding)?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
}

/// Byte-stream protocols.
pub mod stream {
    use super::MAX_SERVICE_PAYLOAD_BYTES;

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Read up to the requested byte count from a byte-input handle.
    pub const READ: u16 = 1;
    /// Write the complete payload to a byte-output handle.
    pub const WRITE: u16 = 1;

    /// Invalid byte-stream request encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct RequestError;

    /// Encode the two-byte input-read request payload.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above one service reply payload.
    pub fn encode_read_request(max_bytes: usize) -> Result<[u8; 2], RequestError> {
        if max_bytes == 0 || max_bytes > MAX_SERVICE_PAYLOAD_BYTES {
            return Err(RequestError);
        }
        let value = u16::try_from(max_bytes).map_err(|_| RequestError)?;
        Ok(value.to_le_bytes())
    }

    /// Decode one exact input-read request payload.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical length, zero, or excessive values.
    pub fn decode_read_request(bytes: &[u8]) -> Result<usize, RequestError> {
        if bytes.len() != 2 {
            return Err(RequestError);
        }
        let value = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if value == 0 || value > MAX_SERVICE_PAYLOAD_BYTES {
            return Err(RequestError);
        }
        Ok(value)
    }
}

/// Bounded read-only filesystem protocol.
pub mod filesystem {
    use core::str;

    use super::MAX_SERVICE_PAYLOAD_BYTES;

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Resolve and open one regular file.
    pub const OPEN: u16 = 1;
    /// Read one bounded range through an open-file token.
    pub const READ: u16 = 2;
    /// Release one open-file token.
    pub const CLOSE: u16 = 3;
    /// Return one bounded page of immediate directory children.
    pub const LIST: u16 = 4;
    /// Return metadata without opening an object.
    pub const METADATA: u16 = 5;
    /// Maximum path bytes accepted by this interface.
    pub const MAX_PATH_BYTES: usize = 256;
    /// Maximum simultaneously open files per application service.
    pub const MAX_OPEN_FILES: usize = 8;
    /// Maximum entries returned by one list call.
    pub const MAX_LIST_ENTRIES: usize = 64;
    /// Maximum encoded bytes in one entry name.
    pub const MAX_NAME_BYTES: usize = 64;
    /// Maximum aggregate name bytes returned by one list call.
    pub const MAX_LIST_NAME_BYTES: usize = 3 * 1024;
    /// Fixed open-file reply bytes.
    pub const OPEN_REPLY_BYTES: usize = 16;
    /// Fixed range-read request bytes.
    pub const READ_REQUEST_BYTES: usize = 16;
    /// Fixed list request bytes preceding its path.
    pub const LIST_REQUEST_HEADER_BYTES: usize = 12;
    /// Largest canonical list request.
    pub const MAX_LIST_REQUEST_BYTES: usize = LIST_REQUEST_HEADER_BYTES + MAX_PATH_BYTES;
    /// Fixed list reply bytes preceding entries.
    pub const LIST_REPLY_HEADER_BYTES: usize = 12;
    /// Fixed bytes preceding each variable entry name.
    pub const LIST_ENTRY_HEADER_BYTES: usize = 4;
    /// Largest canonical list reply.
    pub const MAX_LIST_REPLY_BYTES: usize =
        LIST_REPLY_HEADER_BYTES + MAX_LIST_ENTRIES * LIST_ENTRY_HEADER_BYTES + MAX_LIST_NAME_BYTES;
    /// Fixed metadata reply bytes.
    pub const METADATA_REPLY_BYTES: usize = 16;

    /// Invalid filesystem request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Visible filesystem object kind.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum NodeKind {
        /// Regular byte file.
        File = 1,
        /// Directory containing named children.
        Directory = 2,
    }

    impl NodeKind {
        fn parse(value: u8) -> Result<Self, EncodingError> {
            match value {
                1 => Ok(Self::File),
                2 => Ok(Self::Directory),
                _ => Err(EncodingError),
            }
        }
    }

    /// Metadata returned for one resolved object.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Metadata {
        /// Object kind.
        pub kind: NodeKind,
        /// Exact regular-file bytes, or zero for a directory.
        pub byte_count: u64,
    }

    /// Opaque open-file token plus immutable size observed at open time.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct OpenFile {
        token: u32,
        /// Exact file bytes observed at open time.
        pub byte_count: u64,
    }

    impl OpenFile {
        /// Construct a validated opaque token from a service reply.
        ///
        /// # Errors
        ///
        /// Rejects token zero.
        pub fn new(token: u32, byte_count: u64) -> Result<Self, EncodingError> {
            if token == 0 {
                return Err(EncodingError);
            }
            Ok(Self { token, byte_count })
        }

        /// Opaque token for protocol encoders; applications must not interpret it.
        #[must_use]
        pub const fn token(self) -> u32 {
            self.token
        }
    }

    /// Borrowed validated list request.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ListRequest<'a> {
        /// Opaque cursor; zero begins a traversal.
        pub cursor: u64,
        /// Maximum entries requested in this page.
        pub max_entries: usize,
        /// Maximum aggregate entry-name bytes.
        pub max_name_bytes: usize,
        /// Path resolved relative to the invocation cwd.
        pub path: &'a str,
    }

    /// One borrowed directory entry used by encoders and decoders.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct DirectoryEntry<'a> {
        /// Entry kind.
        pub kind: NodeKind,
        /// UTF-8 base name without a slash.
        pub name: &'a str,
    }

    /// Borrowed validated directory page.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct DirectoryPage<'a> {
        bytes: &'a [u8],
        entry_count: usize,
        next_cursor: Option<u64>,
    }

    impl<'a> DirectoryPage<'a> {
        /// Parse one exact bounded page.
        ///
        /// # Errors
        ///
        /// Rejects malformed flags, padding, counts, kinds, names, bounds, or
        /// trailing bytes.
        pub fn parse(bytes: &'a [u8]) -> Result<Self, EncodingError> {
            if bytes.len() < LIST_REPLY_HEADER_BYTES || bytes.len() > MAX_LIST_REPLY_BYTES {
                return Err(EncodingError);
            }
            let next = read_u64(bytes, 0)?;
            let next_cursor = match bytes[8] {
                0 if next == 0 => None,
                1 => Some(next),
                _ => return Err(EncodingError),
            };
            if bytes[9] != 0 {
                return Err(EncodingError);
            }
            let entry_count = usize::from(read_u16(bytes, 10)?);
            if entry_count > MAX_LIST_ENTRIES {
                return Err(EncodingError);
            }
            let page = Self {
                bytes,
                entry_count,
                next_cursor,
            };
            let mut cursor = LIST_REPLY_HEADER_BYTES;
            let mut name_bytes = 0_usize;
            let mut previous = None;
            for _ in 0..entry_count {
                let (entry, end) = decode_entry(bytes, cursor)?;
                if previous.is_some_and(|name| name >= entry.name) {
                    return Err(EncodingError);
                }
                previous = Some(entry.name);
                name_bytes = name_bytes
                    .checked_add(entry.name.len())
                    .ok_or(EncodingError)?;
                if name_bytes > MAX_LIST_NAME_BYTES {
                    return Err(EncodingError);
                }
                cursor = end;
            }
            if cursor != bytes.len() {
                return Err(EncodingError);
            }
            Ok(page)
        }

        /// Number of entries in this page.
        #[must_use]
        pub const fn len(self) -> usize {
            self.entry_count
        }

        /// Whether the page contains no entries.
        #[must_use]
        pub const fn is_empty(self) -> bool {
            self.entry_count == 0
        }

        /// Cursor to pass to the next list call, or `None` at end-of-directory.
        #[must_use]
        pub const fn next_cursor(self) -> Option<u64> {
            self.next_cursor
        }

        /// Iterate through lexical entries.
        #[must_use]
        pub const fn entries(self) -> DirectoryEntries<'a> {
            DirectoryEntries {
                page: self,
                index: 0,
                cursor: LIST_REPLY_HEADER_BYTES,
            }
        }
    }

    /// Iterator over one validated directory page.
    pub struct DirectoryEntries<'a> {
        page: DirectoryPage<'a>,
        index: usize,
        cursor: usize,
    }

    impl<'a> Iterator for DirectoryEntries<'a> {
        type Item = DirectoryEntry<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index >= self.page.entry_count {
                return None;
            }
            let (entry, end) = decode_entry(self.page.bytes, self.cursor).ok()?;
            self.index += 1;
            self.cursor = end;
            Some(entry)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.page.entry_count.saturating_sub(self.index);
            (remaining, Some(remaining))
        }
    }

    impl ExactSizeIterator for DirectoryEntries<'_> {}

    /// Encode a path-only request.
    ///
    /// # Errors
    ///
    /// Rejects empty/excessive paths or insufficient output without mutation.
    pub fn encode_path_request(path: &str, output: &mut [u8]) -> Result<usize, EncodingError> {
        validate_path(path)?;
        if output.len() < path.len() {
            return Err(EncodingError);
        }
        output[..path.len()].copy_from_slice(path.as_bytes());
        Ok(path.len())
    }

    /// Decode one exact path-only request.
    ///
    /// # Errors
    ///
    /// Rejects non-UTF-8, empty, excessive, or NUL-containing paths.
    pub fn decode_path_request(bytes: &[u8]) -> Result<&str, EncodingError> {
        let path = str::from_utf8(bytes).map_err(|_| EncodingError)?;
        validate_path(path)?;
        Ok(path)
    }

    /// Encode an open-file reply.
    #[must_use]
    pub fn encode_open_reply(file: OpenFile) -> [u8; OPEN_REPLY_BYTES] {
        let mut bytes = [0_u8; OPEN_REPLY_BYTES];
        bytes[..4].copy_from_slice(&file.token.to_le_bytes());
        bytes[8..16].copy_from_slice(&file.byte_count.to_le_bytes());
        bytes
    }

    /// Decode one exact open-file reply.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, padding, or token zero.
    pub fn decode_open_reply(bytes: &[u8]) -> Result<OpenFile, EncodingError> {
        if bytes.len() != OPEN_REPLY_BYTES || read_u32(bytes, 4)? != 0 {
            return Err(EncodingError);
        }
        OpenFile::new(read_u32(bytes, 0)?, read_u64(bytes, 8)?)
    }

    /// Encode one exact range-read request.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive requested bytes.
    pub fn encode_read_request(
        file: OpenFile,
        offset: u64,
        max_bytes: usize,
    ) -> Result<[u8; READ_REQUEST_BYTES], EncodingError> {
        if max_bytes == 0 || max_bytes > MAX_SERVICE_PAYLOAD_BYTES {
            return Err(EncodingError);
        }
        let mut bytes = [0_u8; READ_REQUEST_BYTES];
        bytes[..4].copy_from_slice(&file.token.to_le_bytes());
        bytes[4..6].copy_from_slice(
            &u16::try_from(max_bytes)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        bytes[8..16].copy_from_slice(&offset.to_le_bytes());
        Ok(bytes)
    }

    /// Decode one exact range-read request.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, padding, token zero, or invalid requested bytes.
    pub fn decode_read_request(bytes: &[u8]) -> Result<(u32, u64, usize), EncodingError> {
        if bytes.len() != READ_REQUEST_BYTES || read_u16(bytes, 6)? != 0 {
            return Err(EncodingError);
        }
        let token = read_u32(bytes, 0)?;
        let max_bytes = usize::from(read_u16(bytes, 4)?);
        if token == 0 || max_bytes == 0 || max_bytes > MAX_SERVICE_PAYLOAD_BYTES {
            return Err(EncodingError);
        }
        Ok((token, read_u64(bytes, 8)?, max_bytes))
    }

    /// Encode an exact close request.
    #[must_use]
    pub const fn encode_close_request(file: OpenFile) -> [u8; 4] {
        file.token.to_le_bytes()
    }

    /// Decode an exact close request.
    ///
    /// # Errors
    ///
    /// Rejects wrong length or token zero.
    pub fn decode_close_request(bytes: &[u8]) -> Result<u32, EncodingError> {
        if bytes.len() != 4 {
            return Err(EncodingError);
        }
        let token = read_u32(bytes, 0)?;
        if token == 0 {
            return Err(EncodingError);
        }
        Ok(token)
    }

    /// Encode one bounded directory-list request.
    ///
    /// # Errors
    ///
    /// Rejects invalid paths, zero/excessive budgets, overflow, or short output.
    pub fn encode_list_request(
        cursor: u64,
        max_entries: usize,
        max_name_bytes: usize,
        path: &str,
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        validate_path(path)?;
        let count = LIST_REQUEST_HEADER_BYTES
            .checked_add(path.len())
            .ok_or(EncodingError)?;
        if max_entries == 0
            || max_entries > MAX_LIST_ENTRIES
            || max_name_bytes == 0
            || max_name_bytes > MAX_LIST_NAME_BYTES
            || output.len() < count
        {
            return Err(EncodingError);
        }
        let mut encoded = [0_u8; MAX_LIST_REQUEST_BYTES];
        encoded[..8].copy_from_slice(&cursor.to_le_bytes());
        encoded[8..10].copy_from_slice(
            &u16::try_from(max_entries)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        encoded[10..12].copy_from_slice(
            &u16::try_from(max_name_bytes)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        encoded[LIST_REQUEST_HEADER_BYTES..count].copy_from_slice(path.as_bytes());
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Decode one exact bounded directory-list request.
    ///
    /// # Errors
    ///
    /// Rejects malformed length, path, or list budgets.
    pub fn decode_list_request(bytes: &[u8]) -> Result<ListRequest<'_>, EncodingError> {
        if bytes.len() <= LIST_REQUEST_HEADER_BYTES || bytes.len() > MAX_LIST_REQUEST_BYTES {
            return Err(EncodingError);
        }
        let max_entries = usize::from(read_u16(bytes, 8)?);
        let max_name_bytes = usize::from(read_u16(bytes, 10)?);
        let path = decode_path_request(&bytes[LIST_REQUEST_HEADER_BYTES..])?;
        if max_entries == 0
            || max_entries > MAX_LIST_ENTRIES
            || max_name_bytes == 0
            || max_name_bytes > MAX_LIST_NAME_BYTES
        {
            return Err(EncodingError);
        }
        Ok(ListRequest {
            cursor: read_u64(bytes, 0)?,
            max_entries,
            max_name_bytes,
            path,
        })
    }

    /// Encode one lexical bounded directory page.
    ///
    /// # Errors
    ///
    /// Rejects excessive, invalid, non-lexical entries or insufficient output.
    pub fn encode_list_reply(
        next_cursor: Option<u64>,
        entries: &[DirectoryEntry<'_>],
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        if entries.len() > MAX_LIST_ENTRIES {
            return Err(EncodingError);
        }
        let mut count = LIST_REPLY_HEADER_BYTES;
        let mut name_bytes = 0_usize;
        let mut previous = None;
        for entry in entries {
            validate_name(entry.name)?;
            if previous.is_some_and(|name| name >= entry.name) {
                return Err(EncodingError);
            }
            previous = Some(entry.name);
            name_bytes = name_bytes
                .checked_add(entry.name.len())
                .ok_or(EncodingError)?;
            count = count
                .checked_add(LIST_ENTRY_HEADER_BYTES)
                .and_then(|value| value.checked_add(entry.name.len()))
                .ok_or(EncodingError)?;
        }
        if name_bytes > MAX_LIST_NAME_BYTES || count > MAX_LIST_REPLY_BYTES || output.len() < count
        {
            return Err(EncodingError);
        }
        let mut encoded = [0_u8; MAX_LIST_REPLY_BYTES];
        if let Some(cursor) = next_cursor {
            encoded[..8].copy_from_slice(&cursor.to_le_bytes());
            encoded[8] = 1;
        }
        encoded[10..12].copy_from_slice(
            &u16::try_from(entries.len())
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        let mut cursor = LIST_REPLY_HEADER_BYTES;
        for entry in entries {
            encoded[cursor] = entry.kind as u8;
            encoded[cursor + 1] = u8::try_from(entry.name.len()).map_err(|_| EncodingError)?;
            cursor += LIST_ENTRY_HEADER_BYTES;
            let end = cursor + entry.name.len();
            encoded[cursor..end].copy_from_slice(entry.name.as_bytes());
            cursor = end;
        }
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Encode one exact metadata reply.
    #[must_use]
    pub fn encode_metadata_reply(metadata: Metadata) -> [u8; METADATA_REPLY_BYTES] {
        let mut bytes = [0_u8; METADATA_REPLY_BYTES];
        bytes[0] = metadata.kind as u8;
        bytes[8..16].copy_from_slice(&metadata.byte_count.to_le_bytes());
        bytes
    }

    /// Decode one exact metadata reply.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, padding, kind, or nonzero directory size.
    pub fn decode_metadata_reply(bytes: &[u8]) -> Result<Metadata, EncodingError> {
        if bytes.len() != METADATA_REPLY_BYTES || bytes[1..8].iter().any(|byte| *byte != 0) {
            return Err(EncodingError);
        }
        let kind = NodeKind::parse(bytes[0])?;
        let byte_count = read_u64(bytes, 8)?;
        if kind == NodeKind::Directory && byte_count != 0 {
            return Err(EncodingError);
        }
        Ok(Metadata { kind, byte_count })
    }

    fn validate_path(path: &str) -> Result<(), EncodingError> {
        if path.is_empty() || path.len() > MAX_PATH_BYTES || path.as_bytes().contains(&0) {
            return Err(EncodingError);
        }
        Ok(())
    }

    fn validate_name(name: &str) -> Result<(), EncodingError> {
        if name.is_empty()
            || name.len() > MAX_NAME_BYTES
            || name.contains('/')
            || matches!(name, "." | "..")
        {
            return Err(EncodingError);
        }
        Ok(())
    }

    fn decode_entry(
        bytes: &[u8],
        offset: usize,
    ) -> Result<(DirectoryEntry<'_>, usize), EncodingError> {
        let header = bytes
            .get(offset..offset + LIST_ENTRY_HEADER_BYTES)
            .ok_or(EncodingError)?;
        if header[2] != 0 || header[3] != 0 {
            return Err(EncodingError);
        }
        let end = offset
            .checked_add(LIST_ENTRY_HEADER_BYTES)
            .and_then(|value| value.checked_add(usize::from(header[1])))
            .ok_or(EncodingError)?;
        let name = str::from_utf8(
            bytes
                .get(offset + LIST_ENTRY_HEADER_BYTES..end)
                .ok_or(EncodingError)?,
        )
        .map_err(|_| EncodingError)?;
        validate_name(name)?;
        Ok((
            DirectoryEntry {
                kind: NodeKind::parse(header[0])?,
                name,
            },
            end,
        ))
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
        let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EncodingError> {
        let raw = bytes.get(offset..offset + 4).ok_or(EncodingError)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EncodingError> {
        let raw = bytes.get(offset..offset + 8).ok_or(EncodingError)?;
        Ok(u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]))
    }
}

/// Bounded transactional filesystem-mutation protocol.
pub mod filesystem_mutation {
    use super::{MAX_SERVICE_PAYLOAD_BYTES, filesystem};

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Begin one complete-file atomic replacement.
    pub const BEGIN_REPLACE: u16 = 1;
    /// Append one sequential chunk to the pending replacement.
    pub const APPEND: u16 = 2;
    /// Atomically publish the complete pending replacement.
    pub const COMMIT_REPLACE: u16 = 3;
    /// Discard the complete pending replacement.
    pub const ABORT_REPLACE: u16 = 4;
    /// Atomically remove one regular file.
    pub const REMOVE: u16 = 5;
    /// Maximum staged bytes in one replacement.
    pub const MAX_FILE_BYTES: usize = 64 * 1024;
    /// Fixed bytes preceding an append payload.
    pub const APPEND_HEADER_BYTES: usize = 8;
    /// Maximum bytes carried by one append call.
    pub const MAX_APPEND_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES - APPEND_HEADER_BYTES;
    /// Exact replacement-token reply/request bytes.
    pub const TOKEN_BYTES: usize = 4;

    /// Invalid mutation request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Borrowed validated append request.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AppendRequest<'a> {
        /// Opaque active replacement token.
        pub token: u32,
        /// Required sequential byte offset.
        pub offset: u32,
        /// Nonempty bytes appended at `offset`.
        pub bytes: &'a [u8],
    }

    /// Encode a begin-replace or remove path request.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, invalid, or short destinations atomically.
    pub fn encode_path_request(path: &str, output: &mut [u8]) -> Result<usize, EncodingError> {
        filesystem::encode_path_request(path, output).map_err(|_| EncodingError)
    }

    /// Decode a begin-replace or remove path request.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical filesystem paths.
    pub fn decode_path_request(bytes: &[u8]) -> Result<&str, EncodingError> {
        filesystem::decode_path_request(bytes).map_err(|_| EncodingError)
    }

    /// Encode one opaque nonzero replacement token.
    ///
    /// # Errors
    ///
    /// Rejects token zero.
    pub fn encode_token(token: u32) -> Result<[u8; TOKEN_BYTES], EncodingError> {
        if token == 0 {
            return Err(EncodingError);
        }
        Ok(token.to_le_bytes())
    }

    /// Decode one exact opaque replacement token.
    ///
    /// # Errors
    ///
    /// Rejects the wrong length or token zero.
    pub fn decode_token(bytes: &[u8]) -> Result<u32, EncodingError> {
        if bytes.len() != TOKEN_BYTES {
            return Err(EncodingError);
        }
        let token = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if token == 0 {
            return Err(EncodingError);
        }
        Ok(token)
    }

    /// Encode one nonempty sequential append request.
    ///
    /// # Errors
    ///
    /// Rejects zero tokens, empty/excessive chunks, offsets beyond the file
    /// ceiling, overflow, or insufficient output without modifying it.
    pub fn encode_append_request(
        token: u32,
        offset: usize,
        bytes: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let count = APPEND_HEADER_BYTES
            .checked_add(bytes.len())
            .ok_or(EncodingError)?;
        let end = offset.checked_add(bytes.len()).ok_or(EncodingError)?;
        if token == 0
            || bytes.is_empty()
            || bytes.len() > MAX_APPEND_BYTES
            || end > MAX_FILE_BYTES
            || output.len() < count
        {
            return Err(EncodingError);
        }
        let offset = u32::try_from(offset).map_err(|_| EncodingError)?;
        let mut encoded = [0_u8; MAX_SERVICE_PAYLOAD_BYTES];
        encoded[..4].copy_from_slice(&token.to_le_bytes());
        encoded[4..8].copy_from_slice(&offset.to_le_bytes());
        encoded[APPEND_HEADER_BYTES..count].copy_from_slice(bytes);
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Decode one exact sequential append request.
    ///
    /// # Errors
    ///
    /// Rejects zero tokens, empty/excessive bytes, or offsets whose complete
    /// chunk exceeds the file ceiling.
    pub fn decode_append_request(bytes: &[u8]) -> Result<AppendRequest<'_>, EncodingError> {
        if bytes.len() <= APPEND_HEADER_BYTES || bytes.len() > MAX_SERVICE_PAYLOAD_BYTES {
            return Err(EncodingError);
        }
        let token = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let offset = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let payload = &bytes[APPEND_HEADER_BYTES..];
        let end = usize::try_from(offset)
            .map_err(|_| EncodingError)?
            .checked_add(payload.len())
            .ok_or(EncodingError)?;
        if token == 0 || payload.len() > MAX_APPEND_BYTES || end > MAX_FILE_BYTES {
            return Err(EncodingError);
        }
        Ok(AppendRequest {
            token,
            offset,
            bytes: payload,
        })
    }
}

/// Owned IPv4/UDP datagram protocol.
pub mod datagram {
    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Send one datagram and retain ownership of its selected source port.
    pub const SEND: u16 = 1;
    /// Wait cooperatively for one datagram on an owned local port.
    pub const RECEIVE: u16 = 2;
    /// Maximum UDP payload admitted by the platform profile.
    pub const MAX_PAYLOAD_BYTES: usize = 1_472;
    /// Fixed bytes preceding the payload in a send request.
    pub const SEND_HEADER_BYTES: usize = 8;
    /// Largest canonical send request payload.
    pub const MAX_SEND_REQUEST_BYTES: usize = SEND_HEADER_BYTES + MAX_PAYLOAD_BYTES;
    /// Fixed bytes preceding the payload in a receive reply.
    pub const RECEIVE_HEADER_BYTES: usize = 6;
    /// Largest canonical receive reply.
    pub const MAX_RECEIVE_REPLY_BYTES: usize = RECEIVE_HEADER_BYTES + MAX_PAYLOAD_BYTES;

    /// Invalid datagram request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Borrowed, validated send request.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SendRequest<'a> {
        /// Zero requests an ephemeral source port.
        pub source_port: u16,
        /// Destination IPv4 address in network display order.
        pub destination: [u8; 4],
        /// Nonzero destination UDP port.
        pub destination_port: u16,
        /// Exact datagram payload.
        pub payload: &'a [u8],
    }

    /// Borrowed, validated received datagram.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ReceivedDatagram<'a> {
        /// Source IPv4 address in network display order.
        pub source: [u8; 4],
        /// Nonzero source UDP port.
        pub source_port: u16,
        /// Exact datagram payload.
        pub payload: &'a [u8],
    }

    /// Encode one canonical send request into caller-owned storage.
    ///
    /// A zero source port selects an ephemeral port. All other ports must be
    /// nonzero, and no destination bytes are modified on failure.
    ///
    /// # Errors
    ///
    /// Rejects zero explicit/destination ports, oversize payloads, overflow,
    /// or insufficient destination storage.
    pub fn encode_send_request(
        source_port: Option<u16>,
        destination: [u8; 4],
        destination_port: u16,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        if source_port == Some(0) {
            return Err(EncodingError);
        }
        let source_port = source_port.unwrap_or(0);
        let count = SEND_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(EncodingError)?;
        if destination_port == 0 || payload.len() > MAX_PAYLOAD_BYTES || output.len() < count {
            return Err(EncodingError);
        }
        let mut encoded = [0_u8; MAX_SEND_REQUEST_BYTES];
        encoded[0..2].copy_from_slice(&source_port.to_le_bytes());
        encoded[2..6].copy_from_slice(&destination);
        encoded[6..8].copy_from_slice(&destination_port.to_le_bytes());
        encoded[8..count].copy_from_slice(payload);
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Parse one exact send request.
    ///
    /// # Errors
    ///
    /// Rejects truncated, oversized, or zero-destination-port records.
    pub fn decode_send_request(bytes: &[u8]) -> Result<SendRequest<'_>, EncodingError> {
        if bytes.len() < SEND_HEADER_BYTES || bytes.len() > MAX_SEND_REQUEST_BYTES {
            return Err(EncodingError);
        }
        let destination_port = read_u16(bytes, 6)?;
        if destination_port == 0 {
            return Err(EncodingError);
        }
        Ok(SendRequest {
            source_port: read_u16(bytes, 0)?,
            destination: [bytes[2], bytes[3], bytes[4], bytes[5]],
            destination_port,
            payload: &bytes[SEND_HEADER_BYTES..],
        })
    }

    /// Encode the exact selected source-port reply.
    ///
    /// # Errors
    ///
    /// Rejects port zero.
    pub fn encode_send_reply(source_port: u16) -> Result<[u8; 2], EncodingError> {
        if source_port == 0 {
            return Err(EncodingError);
        }
        Ok(source_port.to_le_bytes())
    }

    /// Decode the exact selected source-port reply.
    ///
    /// # Errors
    ///
    /// Rejects any length other than two bytes or port zero.
    pub fn decode_send_reply(bytes: &[u8]) -> Result<u16, EncodingError> {
        let port = read_u16(bytes, 0)?;
        if bytes.len() != 2 || port == 0 {
            return Err(EncodingError);
        }
        Ok(port)
    }

    /// Encode one exact receive request.
    ///
    /// # Errors
    ///
    /// Rejects port zero.
    pub fn encode_receive_request(local_port: u16) -> Result<[u8; 2], EncodingError> {
        if local_port == 0 {
            return Err(EncodingError);
        }
        Ok(local_port.to_le_bytes())
    }

    /// Decode one exact receive request.
    ///
    /// # Errors
    ///
    /// Rejects any length other than two bytes or port zero.
    pub fn decode_receive_request(bytes: &[u8]) -> Result<u16, EncodingError> {
        let port = read_u16(bytes, 0)?;
        if bytes.len() != 2 || port == 0 {
            return Err(EncodingError);
        }
        Ok(port)
    }

    /// Encode one canonical received datagram into caller-owned storage.
    ///
    /// # Errors
    ///
    /// Rejects port zero, oversize payloads, overflow, or insufficient space.
    pub fn encode_receive_reply(
        source: [u8; 4],
        source_port: u16,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let count = RECEIVE_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(EncodingError)?;
        if source_port == 0 || payload.len() > MAX_PAYLOAD_BYTES || output.len() < count {
            return Err(EncodingError);
        }
        let mut encoded = [0_u8; MAX_RECEIVE_REPLY_BYTES];
        encoded[0..4].copy_from_slice(&source);
        encoded[4..6].copy_from_slice(&source_port.to_le_bytes());
        encoded[6..count].copy_from_slice(payload);
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Parse one exact received datagram reply.
    ///
    /// # Errors
    ///
    /// Rejects truncated, oversized, or zero-source-port records.
    pub fn decode_receive_reply(bytes: &[u8]) -> Result<ReceivedDatagram<'_>, EncodingError> {
        if bytes.len() < RECEIVE_HEADER_BYTES || bytes.len() > MAX_RECEIVE_REPLY_BYTES {
            return Err(EncodingError);
        }
        let source_port = read_u16(bytes, 4)?;
        if source_port == 0 {
            return Err(EncodingError);
        }
        Ok(ReceivedDatagram {
            source: [bytes[0], bytes[1], bytes[2], bytes[3]],
            source_port,
            payload: &bytes[RECEIVE_HEADER_BYTES..],
        })
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
        let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_MESSAGE_BYTES, command, datagram, filesystem, filesystem_mutation, interface,
        requirements, stream,
    };

    #[test]
    fn interface_registry_is_unique_and_nonzero() {
        let interfaces = [
            interface::COMMAND,
            interface::STANDARD_INPUT,
            interface::STANDARD_OUTPUT,
            interface::STANDARD_ERROR,
            interface::DATAGRAM,
            interface::FILESYSTEM_READ,
            interface::FILESYSTEM_MUTATE,
        ];
        assert!(interfaces.iter().all(|value| *value != 0));
        assert!(
            interfaces
                .iter()
                .enumerate()
                .all(|(index, value)| !interfaces[..index].contains(value))
        );
    }

    #[test]
    fn capability_manifest_is_exact_sorted_and_allocation_free() {
        let declared = [requirements::Requirement {
            interface: interface::DATAGRAM,
            major: datagram::MAJOR,
            minor: datagram::MINOR,
        }];
        let mut bytes = [0xa5_u8; requirements::MAX_MANIFEST_BYTES];
        let count =
            requirements::encode(&declared, &mut bytes).unwrap_or_else(|_| std::process::abort());
        let parsed = requirements::Manifest::parse(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(parsed.iter().collect::<std::vec::Vec<_>>(), declared);
        for end in 0..count {
            assert!(requirements::Manifest::parse(&bytes[..end]).is_err());
        }
        let mut trailing = bytes[..count].to_vec();
        trailing.push(0);
        assert!(requirements::Manifest::parse(&trailing).is_err());

        let duplicate = [declared[0], declared[0]];
        let mut unchanged = [0xa5_u8; requirements::MAX_MANIFEST_BYTES];
        assert!(requirements::encode(&duplicate, &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; requirements::MAX_MANIFEST_BYTES]);
    }

    #[test]
    fn invocation_round_trips_without_allocation() {
        let arguments = ["grep", "needle", ""];
        let mut bytes = [0_u8; MAX_MESSAGE_BYTES];
        let count = command::encode("/vol/root", &arguments, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let invocation =
            command::Invocation::parse(&bytes[..count]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(invocation.cwd(), "/vol/root");
        assert_eq!(
            invocation.arguments().collect::<std::vec::Vec<_>>(),
            arguments
        );
    }

    #[test]
    fn invocation_rejects_every_truncation_and_trailing_byte() {
        let mut bytes = [0_u8; MAX_MESSAGE_BYTES];
        let count = command::encode("/", &["echo", "ready"], &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        for end in 0..count {
            assert!(command::Invocation::parse(&bytes[..end]).is_err());
        }
        let mut trailing = bytes[..count].to_vec();
        trailing.push(0);
        assert!(command::Invocation::parse(&trailing).is_err());
    }

    #[test]
    fn failed_encoding_does_not_modify_destination() {
        let mut bytes = [0xa5_u8; 4];
        assert_eq!(
            command::encode("relative", &["echo"], &mut bytes),
            Err(command::EncodeError::InvalidCwd)
        );
        assert_eq!(bytes, [0xa5; 4]);
    }

    #[test]
    fn stream_read_request_has_exact_bounds() {
        assert!(stream::encode_read_request(0).is_err());
        let maximum = stream::encode_read_request(super::MAX_SERVICE_PAYLOAD_BYTES)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            stream::decode_read_request(&maximum),
            Ok(super::MAX_SERVICE_PAYLOAD_BYTES)
        );
        assert!(stream::encode_read_request(super::MAX_SERVICE_PAYLOAD_BYTES + 1).is_err());
        assert!(stream::decode_read_request(&[1]).is_err());
    }

    #[test]
    fn filesystem_records_round_trip_and_reject_ambiguity() {
        let file = filesystem::decode_open_reply(&filesystem::encode_open_reply(
            filesystem::OpenFile::new(0x101, 65_537).unwrap_or_else(|_| std::process::abort()),
        ))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(file.byte_count, 65_537);
        let read = filesystem::encode_read_request(file, 4096, 512)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem::decode_read_request(&read),
            Ok((0x101, 4096, 512))
        );

        let entries = [
            filesystem::DirectoryEntry {
                kind: filesystem::NodeKind::Directory,
                name: "etc",
            },
            filesystem::DirectoryEntry {
                kind: filesystem::NodeKind::File,
                name: "motd",
            },
        ];
        let mut bytes = [0_u8; filesystem::MAX_LIST_REPLY_BYTES];
        let count = filesystem::encode_list_reply(Some(2), &entries, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let page = filesystem::DirectoryPage::parse(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(page.next_cursor(), Some(2));
        assert_eq!(page.entries().collect::<std::vec::Vec<_>>(), entries);
        for end in 0..count {
            assert!(filesystem::DirectoryPage::parse(&bytes[..end]).is_err());
        }
        let mut trailing = bytes[..count].to_vec();
        trailing.push(0);
        assert!(filesystem::DirectoryPage::parse(&trailing).is_err());

        let mut unchanged = [0xa5_u8; filesystem::MAX_LIST_REPLY_BYTES];
        let unsorted = [entries[1], entries[0]];
        assert!(filesystem::encode_list_reply(None, &unsorted, &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; filesystem::MAX_LIST_REPLY_BYTES]);
    }

    #[test]
    fn filesystem_mutation_is_sequential_bounded_and_exact() {
        let token = filesystem_mutation::encode_token(7).unwrap_or_else(|_| std::process::abort());
        assert_eq!(filesystem_mutation::decode_token(&token), Ok(7));
        assert!(filesystem_mutation::decode_token(&[7, 0, 0, 0, 0]).is_err());
        assert!(filesystem_mutation::encode_token(0).is_err());

        let mut bytes = [0_u8; super::MAX_SERVICE_PAYLOAD_BYTES];
        let count = filesystem_mutation::encode_append_request(
            7,
            filesystem_mutation::MAX_FILE_BYTES - 3,
            b"end",
            &mut bytes,
        )
        .unwrap_or_else(|_| std::process::abort());
        let append = filesystem_mutation::decode_append_request(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(append.token, 7);
        assert_eq!(
            append.offset,
            u32::try_from(filesystem_mutation::MAX_FILE_BYTES - 3)
                .unwrap_or_else(|_| std::process::abort())
        );
        assert_eq!(append.bytes, b"end");
        assert!(
            filesystem_mutation::encode_append_request(
                7,
                filesystem_mutation::MAX_FILE_BYTES - 2,
                b"end",
                &mut bytes,
            )
            .is_err()
        );

        let mut unchanged = [0xa5_u8; 8];
        assert!(filesystem_mutation::encode_append_request(0, 0, b"x", &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; 8]);
    }

    #[test]
    fn datagram_records_round_trip_and_reject_noncanonical_ports() {
        let mut request = [0_u8; datagram::MAX_SEND_REQUEST_BYTES];
        let count = datagram::encode_send_request(
            Some(40_000),
            [10, 0, 2, 2],
            49_152,
            b"hello",
            &mut request,
        )
        .unwrap_or_else(|_| std::process::abort());
        let decoded = datagram::decode_send_request(&request[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.source_port, 40_000);
        assert_eq!(decoded.destination, [10, 0, 2, 2]);
        assert_eq!(decoded.destination_port, 49_152);
        assert_eq!(decoded.payload, b"hello");

        let mut reply = [0_u8; datagram::MAX_RECEIVE_REPLY_BYTES];
        let count = datagram::encode_receive_reply([192, 0, 2, 1], 7, b"reply", &mut reply)
            .unwrap_or_else(|_| std::process::abort());
        let decoded = datagram::decode_receive_reply(&reply[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.source, [192, 0, 2, 1]);
        assert_eq!(decoded.source_port, 7);
        assert_eq!(decoded.payload, b"reply");
        assert!(datagram::encode_receive_request(0).is_err());
        assert!(datagram::decode_send_reply(&[0, 0]).is_err());
    }
}

//! Stable, allocation-free application service protocols.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

use core::str;

/// Application ABI major implemented by the current kernel and SDK.
pub const ABI_MAJOR: u16 = 1;
/// Highest compatible application ABI minor implemented by the current kernel and SDK.
pub const ABI_MINOR: u16 = 1;
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
    /// Boot-relative monotonic time and cancellable waiting.
    pub const TIMER: u32 = 8;
    /// Immutable typed kernel and namespace diagnostics snapshot.
    pub const DIAGNOSTICS: u32 = 9;
    /// Read-only typed IPv4 configuration, counters, and neighbor state.
    pub const NETWORK_OBSERVE: u32 = 10;
    /// Bounded DHCP configuration authority.
    pub const NETWORK_CONFIGURE: u32 = 11;
    /// Bounded ICMP echo authority.
    pub const ICMP_ECHO: u32 = 12;
    /// One bounded outbound IPv4/TCP byte stream.
    pub const TCP_CONNECT: u32 = 13;
    /// List and activate manifest-authorized runtime volumes.
    pub const VOLUME_CONTROL: u32 = 14;
    /// Receive and reply to copied requests for one isolated user service.
    pub const SERVER_ENDPOINT: u32 = 15;
    /// Submit validated physical command lines to the owning shell session.
    pub const SHELL_SCRIPT: u32 = 16;
    /// Read the kernel-maintained Unix wall clock.
    pub const WALL_CLOCK: u32 = 17;
    /// Privileged authority to correct the kernel wall clock.
    pub const CLOCK_CONTROL: u32 = 18;
    /// Read-only bounded observation of registered application processes.
    pub const PROCESS_OBSERVE: u32 = 19;
    /// Owner-scoped authority to launch and control child KEX processes.
    pub const PROCESS_LAUNCH: u32 = 20;
    /// Owner-scoped bounded byte-pipe construction and endpoint I/O.
    pub const PIPE: u32 = 21;
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
    pub const MAX_REQUIREMENTS: usize = 128;
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
    /// A network exchange returned an invalid protocol response.
    pub const NETWORK_PROTOCOL: u32 = 19;
    /// The caller lacks authority for the requested operation.
    pub const DENIED: u32 = 20;
    /// A directory still contains entries.
    pub const NOT_EMPTY: u32 = 21;
    /// A name operation crossed filesystem-provider boundaries.
    pub const CROSS_DEVICE: u32 = 22;

    /// Whether a scalar is one defined service reply value.
    #[must_use]
    pub const fn is_known(value: u32) -> bool {
        value <= CROSS_DEVICE
    }
}

/// Copied request/reply transport for one isolated user service.
pub mod server {
    use super::{MAX_MESSAGE_BYTES, MAX_SERVICE_PAYLOAD_BYTES, reply};

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Receive the one copied request currently assigned to this server.
    pub const RECEIVE: u16 = 1;
    /// Complete one received request exactly once.
    pub const REPLY: u16 = 2;
    /// Fixed bytes before a received request payload.
    pub const RECEIVE_HEADER_BYTES: usize = 24;
    /// Fixed bytes before a server reply payload.
    pub const REPLY_HEADER_BYTES: usize = 16;
    /// Largest copied request that can be returned by `RECEIVE`.
    pub const MAX_RECEIVE_REQUEST_BYTES: usize = MAX_MESSAGE_BYTES - RECEIVE_HEADER_BYTES;
    /// Largest copied reply that can be supplied to `REPLY`.
    pub const MAX_REPLY_PAYLOAD_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES - REPLY_HEADER_BYTES;

    /// Invalid, excessive, or noncanonical server-transport bytes.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Borrowed request assigned to one isolated server.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ReceivedRequest<'a> {
        token: u64,
        interface: u32,
        opcode: u16,
        reply_capacity: u16,
        payload: &'a [u8],
    }

    impl<'a> ReceivedRequest<'a> {
        /// Opaque generation-checked token required by `REPLY`.
        #[must_use]
        pub const fn token(self) -> u64 {
            self.token
        }

        /// Client-visible service interface identifier.
        #[must_use]
        pub const fn interface(self) -> u32 {
            self.interface
        }

        /// Client-visible service operation.
        #[must_use]
        pub const fn opcode(self) -> u16 {
            self.opcode
        }

        /// Maximum copied reply bytes accepted by the client.
        #[must_use]
        pub const fn reply_capacity(self) -> usize {
            self.reply_capacity as usize
        }

        /// Immutable copied client request bytes.
        #[must_use]
        pub const fn payload(self) -> &'a [u8] {
            self.payload
        }
    }

    /// Borrowed completion supplied by an isolated server.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ReplyRequest<'a> {
        token: u64,
        status: u32,
        payload: &'a [u8],
    }

    impl<'a> ReplyRequest<'a> {
        /// Opaque generation-checked request token.
        #[must_use]
        pub const fn token(self) -> u64 {
            self.token
        }

        /// Stable service reply status returned to the client.
        #[must_use]
        pub const fn status(self) -> u32 {
            self.status
        }

        /// Immutable copied reply bytes.
        #[must_use]
        pub const fn payload(self) -> &'a [u8] {
            self.payload
        }
    }

    /// Encode one request for delivery to an isolated server.
    ///
    /// # Errors
    ///
    /// Rejects reserved scalar values, ABI bounds, or insufficient storage
    /// without modifying `destination`.
    pub fn encode_received_request(
        token: u64,
        interface: u32,
        opcode: u16,
        reply_capacity: usize,
        payload: &[u8],
        destination: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let encoded_bytes = RECEIVE_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(EncodingError)?;
        if token == 0
            || interface == 0
            || opcode == 0
            || payload.len() > MAX_RECEIVE_REQUEST_BYTES
            || reply_capacity > MAX_MESSAGE_BYTES
            || destination.len() < encoded_bytes
        {
            return Err(EncodingError);
        }
        let request_bytes = u16::try_from(payload.len()).map_err(|_| EncodingError)?;
        let reply_capacity = u16::try_from(reply_capacity).map_err(|_| EncodingError)?;
        destination[..encoded_bytes].fill(0);
        destination[0..8].copy_from_slice(&token.to_le_bytes());
        destination[8..12].copy_from_slice(&interface.to_le_bytes());
        destination[12..14].copy_from_slice(&opcode.to_le_bytes());
        destination[14..16].copy_from_slice(&request_bytes.to_le_bytes());
        destination[16..18].copy_from_slice(&reply_capacity.to_le_bytes());
        destination[RECEIVE_HEADER_BYTES..encoded_bytes].copy_from_slice(payload);
        Ok(encoded_bytes)
    }

    /// Decode one exact canonical request delivered to a server.
    ///
    /// # Errors
    ///
    /// Rejects every truncation, trailing byte, reserved field, or invalid
    /// scalar value.
    pub fn decode_received_request(bytes: &[u8]) -> Result<ReceivedRequest<'_>, EncodingError> {
        if bytes.len() < RECEIVE_HEADER_BYTES {
            return Err(EncodingError);
        }
        let token = read_u64(bytes, 0)?;
        let interface = read_u32(bytes, 8)?;
        let opcode = read_u16(bytes, 12)?;
        let request_bytes = usize::from(read_u16(bytes, 14)?);
        let reply_capacity = read_u16(bytes, 16)?;
        if token == 0
            || interface == 0
            || opcode == 0
            || usize::from(reply_capacity) > MAX_MESSAGE_BYTES
            || request_bytes > MAX_RECEIVE_REQUEST_BYTES
            || bytes.len() != RECEIVE_HEADER_BYTES + request_bytes
            || bytes[18..RECEIVE_HEADER_BYTES]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(EncodingError);
        }
        Ok(ReceivedRequest {
            token,
            interface,
            opcode,
            reply_capacity,
            payload: &bytes[RECEIVE_HEADER_BYTES..],
        })
    }

    /// Encode one completion supplied by an isolated server.
    ///
    /// # Errors
    ///
    /// Rejects a reserved token, unknown status, ABI bounds, or insufficient
    /// storage without modifying `destination`.
    pub fn encode_reply_request(
        token: u64,
        status: u32,
        payload: &[u8],
        destination: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let encoded_bytes = REPLY_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(EncodingError)?;
        if token == 0
            || !reply::is_known(status)
            || payload.len() > MAX_REPLY_PAYLOAD_BYTES
            || destination.len() < encoded_bytes
        {
            return Err(EncodingError);
        }
        let payload_bytes = u16::try_from(payload.len()).map_err(|_| EncodingError)?;
        destination[..encoded_bytes].fill(0);
        destination[0..8].copy_from_slice(&token.to_le_bytes());
        destination[8..12].copy_from_slice(&status.to_le_bytes());
        destination[12..14].copy_from_slice(&payload_bytes.to_le_bytes());
        destination[REPLY_HEADER_BYTES..encoded_bytes].copy_from_slice(payload);
        Ok(encoded_bytes)
    }

    /// Decode one exact canonical completion supplied by a server.
    ///
    /// # Errors
    ///
    /// Rejects every truncation, trailing byte, reserved field, unknown
    /// status, or excessive payload.
    pub fn decode_reply_request(bytes: &[u8]) -> Result<ReplyRequest<'_>, EncodingError> {
        if bytes.len() < REPLY_HEADER_BYTES {
            return Err(EncodingError);
        }
        let token = read_u64(bytes, 0)?;
        let status = read_u32(bytes, 8)?;
        let payload_bytes = usize::from(read_u16(bytes, 12)?);
        if token == 0
            || !reply::is_known(status)
            || payload_bytes > MAX_REPLY_PAYLOAD_BYTES
            || bytes.len() != REPLY_HEADER_BYTES + payload_bytes
            || bytes[14..REPLY_HEADER_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(EncodingError);
        }
        Ok(ReplyRequest {
            token,
            status,
            payload: &bytes[REPLY_HEADER_BYTES..],
        })
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

/// Stable results returned by ABI `grow_heap` (call 3).
pub mod heap_growth {
    /// The requested pages were committed and the returned byte length is current.
    pub const SUCCESS: u32 = 0;
    /// The per-application resident limit or system frame pool is exhausted.
    pub const EXHAUSTED: u32 = 1;
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
    pub const MINOR: u16 = 1;
    /// Return the immutable invocation record.
    pub const GET_INVOCATION: u16 = 1;
    /// Return the immutable launch environment.
    pub const GET_ENVIRONMENT: u16 = 2;
    /// Maximum arguments including the command name.
    pub const MAX_ARGUMENTS: usize = 128;
    /// Maximum encoded current-directory bytes.
    pub const MAX_CWD_BYTES: usize = 256;
    /// Maximum aggregate UTF-8 argument bytes.
    pub const MAX_ARGUMENT_BYTES: usize = 1024;
    /// Fixed invocation header bytes.
    pub const HEADER_BYTES: usize = 8;
    /// Maximum complete canonical invocation reply.
    pub const MAX_INVOCATION_BYTES: usize =
        HEADER_BYTES + MAX_ARGUMENTS * 2 + MAX_CWD_BYTES + MAX_ARGUMENT_BYTES;
    /// Maximum launch-environment entries.
    pub const MAX_ENVIRONMENT: usize = 128;
    /// Maximum aggregate UTF-8 environment bytes.
    pub const MAX_ENVIRONMENT_BYTES: usize = 2048;
    /// Fixed launch-environment header bytes.
    pub const ENVIRONMENT_HEADER_BYTES: usize = 4;
    /// Maximum canonical launch-environment reply.
    pub const MAX_ENCODED_ENVIRONMENT_BYTES: usize =
        ENVIRONMENT_HEADER_BYTES + MAX_ENVIRONMENT * 2 + MAX_ENVIRONMENT_BYTES;

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

    /// Borrowed validated `NAME=VALUE` launch environment.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Environment<'a> {
        bytes: &'a [u8],
        count: usize,
        values_start: usize,
    }

    impl<'a> Environment<'a> {
        /// Parse one exact canonical launch environment.
        ///
        /// # Errors
        ///
        /// Rejects malformed lengths, invalid UTF-8/names, bounds, or trailing bytes.
        pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
            if bytes.len() < ENVIRONMENT_HEADER_BYTES
                || usize::from(read_u16(bytes, 0)?) != bytes.len()
            {
                return Err(DecodeError::InvalidEncoding);
            }
            let count = usize::from(read_u16(bytes, 2)?);
            if count > MAX_ENVIRONMENT {
                return Err(DecodeError::LimitExceeded);
            }
            let values_start = ENVIRONMENT_HEADER_BYTES
                .checked_add(count.checked_mul(2).ok_or(DecodeError::InvalidEncoding)?)
                .ok_or(DecodeError::InvalidEncoding)?;
            if values_start > bytes.len()
                || bytes.len().saturating_sub(values_start) > MAX_ENVIRONMENT_BYTES
            {
                return Err(DecodeError::LimitExceeded);
            }
            let environment = Self {
                bytes,
                count,
                values_start,
            };
            let mut end = values_start;
            for value in environment.iter() {
                validate_environment(value).map_err(|_| DecodeError::InvalidEncoding)?;
                end = end
                    .checked_add(value.len())
                    .ok_or(DecodeError::InvalidEncoding)?;
            }
            if end != bytes.len() {
                return Err(DecodeError::InvalidEncoding);
            }
            Ok(environment)
        }

        /// Number of launch-environment entries.
        #[must_use]
        pub const fn len(self) -> usize {
            self.count
        }

        /// Whether no environment entries were supplied.
        #[must_use]
        pub const fn is_empty(self) -> bool {
            self.count == 0
        }

        /// Iterate over canonical `NAME=VALUE` entries in launch order.
        #[must_use]
        pub const fn iter(self) -> EnvironmentEntries<'a> {
            EnvironmentEntries {
                environment: self,
                index: 0,
                offset: self.values_start,
            }
        }
    }

    /// Iterator over validated launch-environment entries.
    pub struct EnvironmentEntries<'a> {
        environment: Environment<'a>,
        index: usize,
        offset: usize,
    }

    impl<'a> Iterator for EnvironmentEntries<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index >= self.environment.count {
                return None;
            }
            let length = usize::from(
                read_u16(
                    self.environment.bytes,
                    ENVIRONMENT_HEADER_BYTES + self.index * 2,
                )
                .ok()?,
            );
            let end = self.offset.checked_add(length)?;
            let value = str::from_utf8(self.environment.bytes.get(self.offset..end)?).ok()?;
            self.index += 1;
            self.offset = end;
            Some(value)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.environment.count.saturating_sub(self.index);
            (remaining, Some(remaining))
        }
    }

    impl ExactSizeIterator for EnvironmentEntries<'_> {}

    /// Encode canonical `NAME=VALUE` launch entries.
    ///
    /// # Errors
    ///
    /// Rejects invalid names, bounds, arithmetic overflow, or insufficient space.
    pub fn encode_environment(
        environment: &[&str],
        destination: &mut [u8],
    ) -> Result<usize, EncodeError> {
        if environment.len() > MAX_ENVIRONMENT {
            return Err(EncodeError::LimitExceeded);
        }
        let values_bytes = environment.iter().try_fold(0_usize, |total, value| {
            validate_environment(value)?;
            total
                .checked_add(value.len())
                .ok_or(EncodeError::LimitExceeded)
        })?;
        if values_bytes > MAX_ENVIRONMENT_BYTES {
            return Err(EncodeError::LimitExceeded);
        }
        let total = ENVIRONMENT_HEADER_BYTES
            .checked_add(
                environment
                    .len()
                    .checked_mul(2)
                    .ok_or(EncodeError::LimitExceeded)?,
            )
            .and_then(|value| value.checked_add(values_bytes))
            .ok_or(EncodeError::LimitExceeded)?;
        if total > MAX_ENCODED_ENVIRONMENT_BYTES || destination.len() < total {
            return Err(EncodeError::DestinationTooSmall);
        }
        let mut encoded = [0_u8; MAX_ENCODED_ENVIRONMENT_BYTES];
        write_u16(
            &mut encoded,
            0,
            u16::try_from(total).map_err(|_| EncodeError::LimitExceeded)?,
        );
        write_u16(
            &mut encoded,
            2,
            u16::try_from(environment.len()).map_err(|_| EncodeError::LimitExceeded)?,
        );
        let mut cursor = ENVIRONMENT_HEADER_BYTES + environment.len() * 2;
        for (index, value) in environment.iter().enumerate() {
            write_u16(
                &mut encoded,
                ENVIRONMENT_HEADER_BYTES + index * 2,
                u16::try_from(value.len()).map_err(|_| EncodeError::LimitExceeded)?,
            );
            let end = cursor
                .checked_add(value.len())
                .ok_or(EncodeError::LimitExceeded)?;
            encoded[cursor..end].copy_from_slice(value.as_bytes());
            cursor = end;
        }
        destination[..total].copy_from_slice(&encoded[..total]);
        Ok(total)
    }

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

    fn validate_environment(value: &str) -> Result<(), EncodeError> {
        let Some((name, _)) = value.split_once('=') else {
            return Err(EncodeError::LimitExceeded);
        };
        if name.is_empty()
            || name.as_bytes().first().is_some_and(u8::is_ascii_digit)
            || !name
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            || value.as_bytes().contains(&0)
        {
            return Err(EncodeError::LimitExceeded);
        }
        Ok(())
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
}

/// Bounded command-line submission protocol used by a shell interpreter.
pub mod shell_script {
    use super::{MAX_SERVICE_PAYLOAD_BYTES, str};

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Submit one nonempty physical source line.
    pub const SUBMIT_LINE: u16 = 1;
    /// Maximum UTF-8 bytes in one submitted command line.
    pub const MAX_LINE_BYTES: usize = 512;
    /// Maximum submitted command lines in one successful interpreter launch.
    pub const MAX_LINES: usize = 1024;
    /// Maximum aggregate submitted UTF-8 bytes in one interpreter launch.
    pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
    /// Fixed request bytes before the submitted UTF-8 line.
    pub const HEADER_BYTES: usize = 8;
    /// Largest canonical line-submission request.
    pub const MAX_REQUEST_BYTES: usize = HEADER_BYTES + MAX_LINE_BYTES;

    /// Invalid line number, source bytes, reserved fields, or destination size.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// One validated physical source line.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SubmittedLine<'a> {
        number: u32,
        source: &'a str,
    }

    impl<'a> SubmittedLine<'a> {
        /// One-based physical line number in the source file or input stream.
        #[must_use]
        pub const fn number(self) -> u32 {
            self.number
        }

        /// Exact UTF-8 source bytes excluding the line terminator.
        #[must_use]
        pub const fn source(self) -> &'a str {
            self.source
        }
    }

    /// Encode one canonical physical-line submission.
    ///
    /// # Errors
    ///
    /// Rejects line zero, empty or overlong source, embedded line terminators
    /// or NUL, and an insufficient destination without modifying it.
    pub fn encode_submit_line(
        number: u32,
        source: &str,
        destination: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let encoded_bytes = HEADER_BYTES
            .checked_add(source.len())
            .ok_or(EncodingError)?;
        if number == 0
            || source.is_empty()
            || source.len() > MAX_LINE_BYTES
            || source
                .as_bytes()
                .iter()
                .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
            || encoded_bytes > MAX_SERVICE_PAYLOAD_BYTES
            || destination.len() < encoded_bytes
        {
            return Err(EncodingError);
        }
        let source_bytes = u16::try_from(source.len()).map_err(|_| EncodingError)?;
        let mut encoded = [0_u8; MAX_REQUEST_BYTES];
        encoded[0..4].copy_from_slice(&number.to_le_bytes());
        encoded[4..6].copy_from_slice(&source_bytes.to_le_bytes());
        encoded[HEADER_BYTES..encoded_bytes].copy_from_slice(source.as_bytes());
        destination[..encoded_bytes].copy_from_slice(&encoded[..encoded_bytes]);
        Ok(encoded_bytes)
    }

    /// Decode one exact canonical physical-line submission.
    ///
    /// # Errors
    ///
    /// Rejects every truncation, trailing byte, reserved field, invalid UTF-8,
    /// embedded line terminator or NUL, empty line, or policy excess.
    pub fn decode_submit_line(bytes: &[u8]) -> Result<SubmittedLine<'_>, EncodingError> {
        if bytes.len() < HEADER_BYTES {
            return Err(EncodingError);
        }
        let number = read_u32(bytes, 0)?;
        let source_bytes = usize::from(read_u16(bytes, 4)?);
        let encoded_bytes = HEADER_BYTES
            .checked_add(source_bytes)
            .ok_or(EncodingError)?;
        if number == 0
            || source_bytes == 0
            || source_bytes > MAX_LINE_BYTES
            || bytes.len() != encoded_bytes
            || bytes[6..HEADER_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(EncodingError);
        }
        let source = str::from_utf8(&bytes[HEADER_BYTES..]).map_err(|_| EncodingError)?;
        if source
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
        {
            return Err(EncodingError);
        }
        Ok(SubmittedLine { number, source })
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

/// Byte-stream protocols.
pub mod stream {
    use super::MAX_SERVICE_PAYLOAD_BYTES;

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 1;
    /// Read up to the requested byte count from a byte-input handle.
    pub const READ: u16 = 1;
    /// Write the complete payload to a byte-output handle.
    pub const WRITE: u16 = 1;
    /// Select a bounded power-of-two downstream aggregation size.
    pub const SET_CHUNK_SIZE: u16 = 2;
    /// Smallest configurable aggregation size.
    pub const MIN_CHUNK_SIZE: usize = 4 * 1024;
    /// Largest configurable aggregation size.
    pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

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

    /// Encode one configurable output aggregation size.
    ///
    /// # Errors
    ///
    /// Rejects non-power-of-two values outside the enforced stream range.
    pub fn encode_chunk_size(bytes: usize) -> Result<[u8; 4], RequestError> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&bytes) || !bytes.is_power_of_two() {
            return Err(RequestError);
        }
        Ok(u32::try_from(bytes)
            .map_err(|_| RequestError)?
            .to_le_bytes())
    }

    /// Decode one exact configurable output aggregation size.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-power-of-two, or out-of-policy values.
    pub fn decode_chunk_size(bytes: &[u8]) -> Result<usize, RequestError> {
        if bytes.len() != 4 {
            return Err(RequestError);
        }
        let value = usize::try_from(u32::from_le_bytes(
            bytes.try_into().map_err(|_| RequestError)?,
        ))
        .map_err(|_| RequestError)?;
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&value) || !value.is_power_of_two() {
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
    pub const MINOR: u16 = 3;
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
    /// Read one symbolic-link target without following the final component.
    pub const READ_LINK: u16 = 6;
    /// Return metadata without following the final symbolic-link component.
    pub const METADATA_NO_FOLLOW: u16 = 7;
    /// Maximum path bytes accepted by this interface.
    pub const MAX_PATH_BYTES: usize = 256;
    /// Maximum simultaneously open files per application service.
    pub const MAX_OPEN_FILES: usize = 4096;
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
    /// Maximum encoded bytes in one symbolic-link target.
    pub const MAX_LINK_BYTES: usize = MAX_PATH_BYTES;

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
        /// Symbolic link owned and resolved by a filesystem provider.
        Symlink = 3,
    }

    impl NodeKind {
        fn parse(value: u8) -> Result<Self, EncodingError> {
            match value {
                1 => Ok(Self::File),
                2 => Ok(Self::Directory),
                3 => Ok(Self::Symlink),
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

    /// Encode one exact UTF-8 symbolic-link target.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, NUL-containing targets or short output.
    pub fn encode_link_reply(target: &str, output: &mut [u8]) -> Result<usize, EncodingError> {
        validate_link(target)?;
        if output.len() < target.len() {
            return Err(EncodingError);
        }
        output[..target.len()].copy_from_slice(target.as_bytes());
        Ok(target.len())
    }

    /// Decode one exact UTF-8 symbolic-link target.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, invalid UTF-8, or NUL-containing targets.
    pub fn decode_link_reply(bytes: &[u8]) -> Result<&str, EncodingError> {
        let target = str::from_utf8(bytes).map_err(|_| EncodingError)?;
        validate_link(target)?;
        Ok(target)
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

    fn validate_link(target: &str) -> Result<(), EncodingError> {
        if target.is_empty() || target.len() > MAX_LINK_BYTES || target.as_bytes().contains(&0) {
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

/// Streaming filesystem-mutation protocol.
pub mod filesystem_mutation {
    use core::str;

    use super::{MAX_SERVICE_PAYLOAD_BYTES, filesystem};

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 2;
    /// Truncate or create one file and begin a sequential streamed replacement.
    pub const BEGIN_REPLACE: u16 = 1;
    /// Append one sequential chunk to the pending replacement.
    pub const APPEND: u16 = 2;
    /// Flush and durably order the pending streamed replacement.
    pub const COMMIT_REPLACE: u16 = 3;
    /// End the replacement without flushing its final buffered chunk.
    pub const ABORT_REPLACE: u16 = 4;
    /// Atomically remove one regular file or symbolic link.
    pub const REMOVE: u16 = 5;
    /// Create one symbolic link with a provider-owned target.
    pub const CREATE_SYMLINK: u16 = 6;
    /// Create one same-provider hard link to an existing regular file.
    pub const CREATE_HARD_LINK: u16 = 7;
    /// Create one empty directory without replacing an existing entry.
    pub const CREATE_DIRECTORY: u16 = 8;
    /// Select the aggregation size for one pending streamed replacement.
    pub const SET_CHUNK_SIZE: u16 = 9;
    /// Atomically rename one same-provider object.
    pub const RENAME: u16 = 10;
    /// Atomically remove one empty directory.
    pub const REMOVE_DIRECTORY: u16 = 11;
    /// Fixed bytes preceding an append payload.
    pub const APPEND_HEADER_BYTES: usize = 12;
    /// Maximum bytes carried by one append call.
    pub const MAX_APPEND_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES - APPEND_HEADER_BYTES;
    /// Exact replacement-token reply/request bytes.
    pub const TOKEN_BYTES: usize = 4;
    /// Exact replacement-token plus chunk-size request bytes.
    pub const CHUNK_SIZE_REQUEST_BYTES: usize = 8;
    /// Fixed bytes preceding the two strings in a link request.
    pub const LINK_REQUEST_HEADER_BYTES: usize = 4;
    /// Largest canonical two-string link request.
    pub const MAX_LINK_REQUEST_BYTES: usize =
        LINK_REQUEST_HEADER_BYTES + 2 * filesystem::MAX_PATH_BYTES;
    /// Largest canonical two-path request.
    pub const MAX_TWO_PATH_REQUEST_BYTES: usize = MAX_LINK_REQUEST_BYTES;

    /// Invalid mutation request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Borrowed validated append request.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AppendRequest<'a> {
        /// Opaque active replacement token.
        pub token: u32,
        /// Required sequential byte offset.
        pub offset: u64,
        /// Nonempty bytes appended at `offset`.
        pub bytes: &'a [u8],
    }

    /// Borrowed validated symbolic- or hard-link request.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct LinkRequest<'a> {
        /// Symbolic target or existing regular-file path.
        pub target: &'a str,
        /// New directory-entry path.
        pub link_path: &'a str,
    }

    /// Borrowed validated request carrying two filesystem paths.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct TwoPathRequest<'a> {
        /// Existing source path.
        pub source: &'a str,
        /// New destination path.
        pub destination: &'a str,
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

    /// Encode one symbolic- or hard-link request.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, NUL-containing strings or insufficient
    /// output without modifying it.
    pub fn encode_link_request(
        target: &str,
        link_path: &str,
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        validate_link_string(target)?;
        validate_link_string(link_path)?;
        let count = LINK_REQUEST_HEADER_BYTES
            .checked_add(target.len())
            .and_then(|count| count.checked_add(link_path.len()))
            .ok_or(EncodingError)?;
        if output.len() < count {
            return Err(EncodingError);
        }
        let target_bytes = u16::try_from(target.len()).map_err(|_| EncodingError)?;
        let link_bytes = u16::try_from(link_path.len()).map_err(|_| EncodingError)?;
        let mut encoded = [0_u8; MAX_LINK_REQUEST_BYTES];
        encoded[..2].copy_from_slice(&target_bytes.to_le_bytes());
        encoded[2..4].copy_from_slice(&link_bytes.to_le_bytes());
        let target_end = LINK_REQUEST_HEADER_BYTES + target.len();
        encoded[LINK_REQUEST_HEADER_BYTES..target_end].copy_from_slice(target.as_bytes());
        encoded[target_end..count].copy_from_slice(link_path.as_bytes());
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Decode one exact symbolic- or hard-link request.
    ///
    /// # Errors
    ///
    /// Rejects malformed lengths, non-UTF-8, empty, excessive, NUL-containing,
    /// or trailing bytes.
    pub fn decode_link_request(bytes: &[u8]) -> Result<LinkRequest<'_>, EncodingError> {
        if bytes.len() < LINK_REQUEST_HEADER_BYTES || bytes.len() > MAX_LINK_REQUEST_BYTES {
            return Err(EncodingError);
        }
        let target_bytes = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        let link_bytes = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
        let target_end = LINK_REQUEST_HEADER_BYTES
            .checked_add(target_bytes)
            .ok_or(EncodingError)?;
        let end = target_end.checked_add(link_bytes).ok_or(EncodingError)?;
        if end != bytes.len() {
            return Err(EncodingError);
        }
        let target = str::from_utf8(
            bytes
                .get(LINK_REQUEST_HEADER_BYTES..target_end)
                .ok_or(EncodingError)?,
        )
        .map_err(|_| EncodingError)?;
        let link_path = str::from_utf8(bytes.get(target_end..end).ok_or(EncodingError)?)
            .map_err(|_| EncodingError)?;
        validate_link_string(target)?;
        validate_link_string(link_path)?;
        Ok(LinkRequest { target, link_path })
    }

    /// Encode one exact source/destination path pair.
    ///
    /// # Errors
    ///
    /// Rejects empty, excessive, NUL-containing paths or insufficient output
    /// without modifying it.
    pub fn encode_two_path_request(
        source: &str,
        destination: &str,
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        encode_link_request(source, destination, output)
    }

    /// Decode one exact source/destination path pair.
    ///
    /// # Errors
    ///
    /// Rejects malformed lengths, invalid UTF-8, empty, excessive,
    /// NUL-containing, or trailing bytes.
    pub fn decode_two_path_request(bytes: &[u8]) -> Result<TwoPathRequest<'_>, EncodingError> {
        let decoded = decode_link_request(bytes)?;
        Ok(TwoPathRequest {
            source: decoded.target,
            destination: decoded.link_path,
        })
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

    /// Encode a token-scoped streamed-write aggregation size.
    ///
    /// # Errors
    ///
    /// Rejects zero tokens and sizes outside the standard stream policy.
    pub fn encode_chunk_size_request(
        token: u32,
        bytes: usize,
    ) -> Result<[u8; CHUNK_SIZE_REQUEST_BYTES], EncodingError> {
        if token == 0 {
            return Err(EncodingError);
        }
        let size = super::stream::encode_chunk_size(bytes).map_err(|_| EncodingError)?;
        let mut output = [0_u8; CHUNK_SIZE_REQUEST_BYTES];
        output[..4].copy_from_slice(&token.to_le_bytes());
        output[4..].copy_from_slice(&size);
        Ok(output)
    }

    /// Decode a token-scoped streamed-write aggregation size.
    ///
    /// # Errors
    ///
    /// Rejects malformed tokens or out-of-policy sizes.
    pub fn decode_chunk_size_request(bytes: &[u8]) -> Result<(u32, usize), EncodingError> {
        if bytes.len() != CHUNK_SIZE_REQUEST_BYTES {
            return Err(EncodingError);
        }
        let token = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| EncodingError)?);
        if token == 0 {
            return Err(EncodingError);
        }
        let size = super::stream::decode_chunk_size(&bytes[4..]).map_err(|_| EncodingError)?;
        Ok((token, size))
    }

    /// Encode one nonempty sequential append request.
    ///
    /// # Errors
    ///
    /// Rejects zero tokens, empty/excessive chunks, or insufficient output
    /// without modifying it.
    pub fn encode_append_request(
        token: u32,
        offset: u64,
        bytes: &[u8],
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let count = APPEND_HEADER_BYTES
            .checked_add(bytes.len())
            .ok_or(EncodingError)?;
        if token == 0 || bytes.is_empty() || bytes.len() > MAX_APPEND_BYTES || output.len() < count
        {
            return Err(EncodingError);
        }
        let mut encoded = [0_u8; MAX_SERVICE_PAYLOAD_BYTES];
        encoded[..4].copy_from_slice(&token.to_le_bytes());
        encoded[4..12].copy_from_slice(&offset.to_le_bytes());
        encoded[APPEND_HEADER_BYTES..count].copy_from_slice(bytes);
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Decode one exact sequential append request.
    ///
    /// # Errors
    ///
    /// Rejects zero tokens or empty/excessive byte payloads.
    pub fn decode_append_request(bytes: &[u8]) -> Result<AppendRequest<'_>, EncodingError> {
        if bytes.len() <= APPEND_HEADER_BYTES || bytes.len() > MAX_SERVICE_PAYLOAD_BYTES {
            return Err(EncodingError);
        }
        let token = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let offset = u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| EncodingError)?);
        let payload = &bytes[APPEND_HEADER_BYTES..];
        if token == 0 || payload.len() > MAX_APPEND_BYTES {
            return Err(EncodingError);
        }
        Ok(AppendRequest {
            token,
            offset,
            bytes: payload,
        })
    }

    fn validate_link_string(value: &str) -> Result<(), EncodingError> {
        if value.is_empty()
            || value.len() > filesystem::MAX_PATH_BYTES
            || value.as_bytes().contains(&0)
        {
            return Err(EncodingError);
        }
        Ok(())
    }
}

/// Manifest-authorized runtime volume activation protocol.
pub mod volume_control {
    use core::str;

    use super::MAX_SERVICE_PAYLOAD_BYTES;

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// List every configured volume in canonical name order.
    pub const LIST: u16 = 1;
    /// Activate one prepared manual volume by manifest name.
    pub const ACTIVATE: u16 = 2;
    /// Maximum canonical volume-name bytes.
    pub const MAX_NAME_BYTES: usize = 32;
    /// Fixed list header bytes.
    pub const LIST_HEADER_BYTES: usize = 4;
    /// Fixed bytes per list record.
    pub const LIST_RECORD_BYTES: usize = 40;
    /// Maximum configured volume records.
    pub const MAX_VOLUMES: usize = 16;
    /// Largest canonical list reply.
    pub const MAX_LIST_REPLY_BYTES: usize = LIST_HEADER_BYTES + MAX_VOLUMES * LIST_RECORD_BYTES;
    /// Largest canonical activation request.
    pub const MAX_ACTIVATE_REQUEST_BYTES: usize = 1 + MAX_NAME_BYTES;

    const _: () = assert!(MAX_LIST_REPLY_BYTES <= MAX_SERVICE_PAYLOAD_BYTES);

    /// Filesystem provider selected by policy.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum Filesystem {
        /// FAT32 provider.
        Fat32 = 1,
        /// Constrained ext4-v1 provider.
        Ext4V1 = 2,
    }

    /// Authority granted to the mounted provider.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum Access {
        /// Read-only provider.
        ReadOnly = 1,
        /// Read/write provider.
        ReadWrite = 2,
    }

    /// Configured activation mode.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum Activation {
        /// Attached automatically during boot.
        Auto = 1,
        /// Requires an authorized activation request.
        Manual = 2,
    }

    /// Current runtime volume state.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum State {
        /// No unique matching provider was prepared.
        Unavailable = 1,
        /// A manual provider is validated and ready.
        Ready = 2,
        /// The provider is attached below `/vol`.
        Mounted = 3,
        /// An attachment attempt failed.
        Failed = 4,
    }

    /// One borrowed configured-volume record.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct VolumeInfo<'a> {
        /// Manifest name, mapping to `/vol/<name>`.
        pub name: &'a str,
        /// Filesystem provider profile.
        pub filesystem: Filesystem,
        /// Effective access mode.
        pub access: Access,
        /// Boot or manual activation policy.
        pub activation: Activation,
        /// Current runtime state.
        pub state: State,
    }

    /// Borrowed validated list reply.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct VolumeList<'a> {
        bytes: &'a [u8],
        count: usize,
    }

    impl<'a> VolumeList<'a> {
        /// Number of configured volumes.
        #[must_use]
        pub const fn len(self) -> usize {
            self.count
        }

        /// Whether the policy contains no volumes.
        #[must_use]
        pub const fn is_empty(self) -> bool {
            self.count == 0
        }

        /// Iterate canonical name-sorted volume records.
        #[must_use]
        pub const fn iter(self) -> VolumeIter<'a> {
            VolumeIter {
                list: self,
                index: 0,
            }
        }
    }

    /// Iterator over one validated list reply.
    pub struct VolumeIter<'a> {
        list: VolumeList<'a>,
        index: usize,
    }

    impl<'a> Iterator for VolumeIter<'a> {
        type Item = VolumeInfo<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index >= self.list.count {
                return None;
            }
            let offset = LIST_HEADER_BYTES + self.index * LIST_RECORD_BYTES;
            self.index += 1;
            decode_record(self.list.bytes.get(offset..offset + LIST_RECORD_BYTES)?).ok()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.list.count.saturating_sub(self.index);
            (remaining, Some(remaining))
        }
    }

    impl ExactSizeIterator for VolumeIter<'_> {}

    /// Invalid volume-control request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode one canonical configured-volume list.
    ///
    /// # Errors
    ///
    /// Rejects excessive, unsorted, invalid, or short output transactionally.
    pub fn encode_list(
        entries: &[VolumeInfo<'_>],
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let count = LIST_HEADER_BYTES
            .checked_add(
                entries
                    .len()
                    .checked_mul(LIST_RECORD_BYTES)
                    .ok_or(EncodingError)?,
            )
            .ok_or(EncodingError)?;
        if entries.len() > MAX_VOLUMES || output.len() < count {
            return Err(EncodingError);
        }
        let mut encoded = [0_u8; MAX_LIST_REPLY_BYTES];
        encoded[..2].copy_from_slice(
            &u16::try_from(entries.len())
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        encoded[2..4].copy_from_slice(
            &u16::try_from(LIST_RECORD_BYTES)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        let mut previous = "";
        for (index, entry) in entries.iter().enumerate() {
            validate_name(entry.name)?;
            if index != 0 && previous >= entry.name {
                return Err(EncodingError);
            }
            previous = entry.name;
            let offset = LIST_HEADER_BYTES + index * LIST_RECORD_BYTES;
            encoded[offset] = u8::try_from(entry.name.len()).map_err(|_| EncodingError)?;
            encoded[offset + 1] = entry.filesystem as u8;
            encoded[offset + 2] = entry.access as u8;
            encoded[offset + 3] = entry.activation as u8;
            encoded[offset + 4] = entry.state as u8;
            encoded[offset + 8..offset + 8 + entry.name.len()]
                .copy_from_slice(entry.name.as_bytes());
        }
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Decode one exact canonical configured-volume list.
    ///
    /// # Errors
    ///
    /// Rejects every invalid enum, name, order, length, or reserved byte.
    pub fn decode_list(bytes: &[u8]) -> Result<VolumeList<'_>, EncodingError> {
        if bytes.len() < LIST_HEADER_BYTES
            || bytes.len() > MAX_LIST_REPLY_BYTES
            || usize::from(read_u16(bytes, 2)?) != LIST_RECORD_BYTES
        {
            return Err(EncodingError);
        }
        let count = usize::from(read_u16(bytes, 0)?);
        let expected = LIST_HEADER_BYTES
            .checked_add(count.checked_mul(LIST_RECORD_BYTES).ok_or(EncodingError)?)
            .ok_or(EncodingError)?;
        if count > MAX_VOLUMES || expected != bytes.len() {
            return Err(EncodingError);
        }
        let mut previous = "";
        for index in 0..count {
            let offset = LIST_HEADER_BYTES + index * LIST_RECORD_BYTES;
            let entry = decode_record(
                bytes
                    .get(offset..offset + LIST_RECORD_BYTES)
                    .ok_or(EncodingError)?,
            )?;
            if index != 0 && previous >= entry.name {
                return Err(EncodingError);
            }
            previous = entry.name;
        }
        Ok(VolumeList { bytes, count })
    }

    /// Encode one manifest volume name for activation.
    ///
    /// # Errors
    ///
    /// Rejects invalid names or insufficient output without modifying it.
    pub fn encode_activate_request(name: &str, output: &mut [u8]) -> Result<usize, EncodingError> {
        validate_name(name)?;
        let count = 1 + name.len();
        if output.len() < count {
            return Err(EncodingError);
        }
        let mut encoded = [0_u8; MAX_ACTIVATE_REQUEST_BYTES];
        encoded[0] = u8::try_from(name.len()).map_err(|_| EncodingError)?;
        encoded[1..count].copy_from_slice(name.as_bytes());
        output[..count].copy_from_slice(&encoded[..count]);
        Ok(count)
    }

    /// Decode one exact manifest volume name for activation.
    ///
    /// # Errors
    ///
    /// Rejects malformed lengths, UTF-8, names, or trailing bytes.
    pub fn decode_activate_request(bytes: &[u8]) -> Result<&str, EncodingError> {
        let name_bytes = usize::from(*bytes.first().ok_or(EncodingError)?);
        if name_bytes + 1 != bytes.len() {
            return Err(EncodingError);
        }
        let name =
            str::from_utf8(bytes.get(1..).ok_or(EncodingError)?).map_err(|_| EncodingError)?;
        validate_name(name)?;
        Ok(name)
    }

    fn decode_record(record: &[u8]) -> Result<VolumeInfo<'_>, EncodingError> {
        if record.len() != LIST_RECORD_BYTES || record[5..8].iter().any(|byte| *byte != 0) {
            return Err(EncodingError);
        }
        let name_bytes = usize::from(record[0]);
        if name_bytes > MAX_NAME_BYTES || record[8 + name_bytes..].iter().any(|byte| *byte != 0) {
            return Err(EncodingError);
        }
        let name = str::from_utf8(record.get(8..8 + name_bytes).ok_or(EncodingError)?)
            .map_err(|_| EncodingError)?;
        validate_name(name)?;
        Ok(VolumeInfo {
            name,
            filesystem: match record[1] {
                1 => Filesystem::Fat32,
                2 => Filesystem::Ext4V1,
                _ => return Err(EncodingError),
            },
            access: match record[2] {
                1 => Access::ReadOnly,
                2 => Access::ReadWrite,
                _ => return Err(EncodingError),
            },
            activation: match record[3] {
                1 => Activation::Auto,
                2 => Activation::Manual,
                _ => return Err(EncodingError),
            },
            state: match record[4] {
                1 => State::Unavailable,
                2 => State::Ready,
                3 => State::Mounted,
                4 => State::Failed,
                _ => return Err(EncodingError),
            },
        })
    }

    fn validate_name(name: &str) -> Result<(), EncodingError> {
        if name.is_empty()
            || name.len() > MAX_NAME_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(EncodingError);
        }
        Ok(())
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
        let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }
}

/// Boot-relative monotonic timer protocol.
pub mod timer {
    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Read the current boot-relative monotonic millisecond count.
    pub const NOW: u16 = 1;
    /// Cooperatively wait until one boot-relative monotonic deadline.
    pub const SLEEP_UNTIL: u16 = 2;
    /// Read CPU ticks charged to the calling process and their frequency.
    pub const PROCESS_CPU_TIME: u16 = 3;
    /// Exact timestamp or deadline bytes.
    pub const MILLISECONDS_BYTES: usize = 8;
    /// Exact process CPU-time reply bytes.
    pub const PROCESS_CPU_TIME_BYTES: usize = 16;

    /// CPU time charged to one process in a machine-defined tick domain.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ProcessCpuTime {
        /// Accumulated execution ticks.
        pub ticks: u64,
        /// Tick frequency used to convert ticks into seconds.
        pub frequency_hz: u64,
    }

    /// Invalid timer request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode one boot-relative monotonic millisecond count.
    #[must_use]
    pub const fn encode_milliseconds(milliseconds: u64) -> [u8; MILLISECONDS_BYTES] {
        milliseconds.to_le_bytes()
    }

    /// Decode one exact boot-relative monotonic millisecond count.
    ///
    /// # Errors
    ///
    /// Rejects every length other than eight bytes.
    pub fn decode_milliseconds(bytes: &[u8]) -> Result<u64, EncodingError> {
        if bytes.len() != MILLISECONDS_BYTES {
            return Err(EncodingError);
        }
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Encode one exact process CPU-time sample.
    ///
    /// # Errors
    ///
    /// Rejects a zero tick frequency.
    pub fn encode_process_cpu_time(
        value: ProcessCpuTime,
    ) -> Result<[u8; PROCESS_CPU_TIME_BYTES], EncodingError> {
        if value.frequency_hz == 0 {
            return Err(EncodingError);
        }
        let mut bytes = [0_u8; PROCESS_CPU_TIME_BYTES];
        bytes[..8].copy_from_slice(&value.ticks.to_le_bytes());
        bytes[8..].copy_from_slice(&value.frequency_hz.to_le_bytes());
        Ok(bytes)
    }

    /// Decode one exact process CPU-time sample.
    ///
    /// # Errors
    ///
    /// Rejects the wrong length or a zero tick frequency.
    pub fn decode_process_cpu_time(bytes: &[u8]) -> Result<ProcessCpuTime, EncodingError> {
        if bytes.len() != PROCESS_CPU_TIME_BYTES {
            return Err(EncodingError);
        }
        let value = ProcessCpuTime {
            ticks: u64::from_le_bytes(bytes[..8].try_into().map_err(|_| EncodingError)?),
            frequency_hz: u64::from_le_bytes(bytes[8..].try_into().map_err(|_| EncodingError)?),
        };
        if value.frequency_hz == 0 {
            return Err(EncodingError);
        }
        Ok(value)
    }
}

/// Kernel-maintained Unix wall-clock protocol.
pub mod wall_clock {
    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Read whole Unix seconds at the current monotonic instant.
    pub const NOW: u16 = 1;
    /// Exact Unix timestamp bytes.
    pub const SECONDS_BYTES: usize = 8;

    /// Invalid timestamp request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode one Unix timestamp.
    #[must_use]
    pub const fn encode_seconds(seconds: u64) -> [u8; SECONDS_BYTES] {
        seconds.to_le_bytes()
    }

    /// Decode one exact Unix timestamp.
    ///
    /// # Errors
    ///
    /// Rejects every length other than eight bytes.
    pub fn decode_seconds(bytes: &[u8]) -> Result<u64, EncodingError> {
        let bytes: [u8; SECONDS_BYTES] = bytes.try_into().map_err(|_| EncodingError)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

/// Privileged kernel wall-clock correction protocol.
pub mod clock_control {
    pub use super::wall_clock::{EncodingError, SECONDS_BYTES, decode_seconds, encode_seconds};

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Replace the wall-clock anchor with one Unix timestamp.
    pub const SET: u16 = 1;
}

/// Immutable typed kernel and namespace diagnostics protocol.
pub mod diagnostics {
    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Read the launch-time diagnostics snapshot.
    pub const GET_SNAPSHOT: u16 = 1;
    /// Exact canonical snapshot bytes.
    pub const SNAPSHOT_BYTES: usize = 168;

    const MACHINE_PRESENT: u8 = 1 << 0;
    const INPUT_PRESENT: u8 = 1 << 1;
    const KNOWN_FLAGS: u8 = MACHINE_PRESENT | INPUT_PRESENT;
    const MACHINE_OFFSET: usize = 8;
    const INPUT_OFFSET: usize = 72;
    const RAMFS_OFFSET: usize = 128;
    const CACHES_OFFSET: usize = 152;

    /// Architecture that produced one diagnostics snapshot.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum Architecture {
        /// AMD64/Intel 64 machine profile.
        X86_64 = 1,
        /// `AArch64` machine profile.
        Aarch64 = 2,
    }

    /// Authority that owns the reported physical memory map.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum MemoryOwner {
        /// Hosted process; no physical memory map is exposed.
        Host = 1,
        /// Firmware snapshot retained for advisory reporting.
        Firmware = 2,
        /// Final map owned by the kernel.
        Kernel = 3,
    }

    /// Bounded memory-pressure state.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum Pressure {
        /// The bounded RAMFS policy is within its configured limit.
        Normal = 1,
    }

    /// Optional full machine-memory counters.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MachineMemory {
        /// Bytes available for kernel use.
        pub usable_bytes: u64,
        /// Bytes excluded from kernel use.
        pub reserved_bytes: u64,
        /// Total owned physical frames.
        pub total_frames: u64,
        /// Currently free owned physical frames.
        pub free_frames: u64,
        /// Configured kernel heap bytes.
        pub heap_total_bytes: u64,
        /// Currently used kernel heap bytes.
        pub heap_used_bytes: u64,
        /// Peak kernel heap use since boot.
        pub heap_high_water_bytes: u64,
        /// Failed kernel allocations since boot.
        pub failed_allocations: u64,
    }

    /// Optional bounded input-queue counters.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct InputQueue {
        /// Currently queued input events.
        pub queued: u64,
        /// Maximum queued input events.
        pub capacity: u64,
        /// Observed input interrupts.
        pub interrupts: u64,
        /// Delivered input events.
        pub delivered: u64,
        /// Dropped input events.
        pub dropped: u64,
        /// Cooperative input idle waits.
        pub idle_waits: u64,
        /// Input-driven cooperative wakeups.
        pub wakeups: u64,
    }

    /// One immutable launch-time diagnostics snapshot.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Snapshot {
        /// Machine architecture.
        pub architecture: Architecture,
        /// Physical memory-map owner.
        pub memory_owner: MemoryOwner,
        /// Current bounded pressure state.
        pub pressure: Pressure,
        /// Full machine counters when the platform owns them.
        pub machine_memory: Option<MachineMemory>,
        /// Input counters when the machine exposes an input queue.
        pub input: Option<InputQueue>,
        /// Current RAMFS use.
        pub ramfs_used_bytes: u64,
        /// Configured RAMFS limit.
        pub ramfs_limit_bytes: u64,
        /// Peak RAMFS use since boot.
        pub ramfs_high_water_bytes: u64,
        /// Current cache use.
        pub caches_used_bytes: u64,
        /// Configured cache limit.
        pub caches_limit_bytes: u64,
    }

    /// Invalid, inconsistent, or noncanonical snapshot encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode one canonical fixed-size diagnostics snapshot.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent counters before producing any bytes.
    pub fn encode_snapshot(snapshot: Snapshot) -> Result<[u8; SNAPSHOT_BYTES], EncodingError> {
        validate(snapshot)?;
        let mut bytes = [0_u8; SNAPSHOT_BYTES];
        bytes[0] = snapshot.architecture as u8;
        bytes[1] = snapshot.memory_owner as u8;
        bytes[2] = snapshot.pressure as u8;
        if let Some(memory) = snapshot.machine_memory {
            bytes[3] |= MACHINE_PRESENT;
            write_values(
                &mut bytes,
                MACHINE_OFFSET,
                &[
                    memory.usable_bytes,
                    memory.reserved_bytes,
                    memory.total_frames,
                    memory.free_frames,
                    memory.heap_total_bytes,
                    memory.heap_used_bytes,
                    memory.heap_high_water_bytes,
                    memory.failed_allocations,
                ],
            );
        }
        if let Some(input) = snapshot.input {
            bytes[3] |= INPUT_PRESENT;
            write_values(
                &mut bytes,
                INPUT_OFFSET,
                &[
                    input.queued,
                    input.capacity,
                    input.interrupts,
                    input.delivered,
                    input.dropped,
                    input.idle_waits,
                    input.wakeups,
                ],
            );
        }
        write_values(
            &mut bytes,
            RAMFS_OFFSET,
            &[
                snapshot.ramfs_used_bytes,
                snapshot.ramfs_limit_bytes,
                snapshot.ramfs_high_water_bytes,
            ],
        );
        write_values(
            &mut bytes,
            CACHES_OFFSET,
            &[snapshot.caches_used_bytes, snapshot.caches_limit_bytes],
        );
        Ok(bytes)
    }

    /// Decode one exact canonical diagnostics snapshot.
    ///
    /// # Errors
    ///
    /// Rejects unknown enums/flags, nonzero reserved or absent fields, the
    /// wrong length, and inconsistent counters.
    pub fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, EncodingError> {
        if bytes.len() != SNAPSHOT_BYTES || bytes[3] & !KNOWN_FLAGS != 0 || bytes[4..8] != [0; 4] {
            return Err(EncodingError);
        }
        let architecture = match bytes[0] {
            1 => Architecture::X86_64,
            2 => Architecture::Aarch64,
            _ => return Err(EncodingError),
        };
        let memory_owner = match bytes[1] {
            1 => MemoryOwner::Host,
            2 => MemoryOwner::Firmware,
            3 => MemoryOwner::Kernel,
            _ => return Err(EncodingError),
        };
        let pressure = match bytes[2] {
            1 => Pressure::Normal,
            _ => return Err(EncodingError),
        };
        let machine_values = read_values::<8>(bytes, MACHINE_OFFSET)?;
        let machine_memory = if bytes[3] & MACHINE_PRESENT != 0 {
            Some(MachineMemory {
                usable_bytes: machine_values[0],
                reserved_bytes: machine_values[1],
                total_frames: machine_values[2],
                free_frames: machine_values[3],
                heap_total_bytes: machine_values[4],
                heap_used_bytes: machine_values[5],
                heap_high_water_bytes: machine_values[6],
                failed_allocations: machine_values[7],
            })
        } else if machine_values == [0; 8] {
            None
        } else {
            return Err(EncodingError);
        };
        let input_values = read_values::<7>(bytes, INPUT_OFFSET)?;
        let input = if bytes[3] & INPUT_PRESENT != 0 {
            Some(InputQueue {
                queued: input_values[0],
                capacity: input_values[1],
                interrupts: input_values[2],
                delivered: input_values[3],
                dropped: input_values[4],
                idle_waits: input_values[5],
                wakeups: input_values[6],
            })
        } else if input_values == [0; 7] {
            None
        } else {
            return Err(EncodingError);
        };
        let ramfs = read_values::<3>(bytes, RAMFS_OFFSET)?;
        let caches = read_values::<2>(bytes, CACHES_OFFSET)?;
        let snapshot = Snapshot {
            architecture,
            memory_owner,
            pressure,
            machine_memory,
            input,
            ramfs_used_bytes: ramfs[0],
            ramfs_limit_bytes: ramfs[1],
            ramfs_high_water_bytes: ramfs[2],
            caches_used_bytes: caches[0],
            caches_limit_bytes: caches[1],
        };
        validate(snapshot)?;
        Ok(snapshot)
    }

    fn validate(snapshot: Snapshot) -> Result<(), EncodingError> {
        if let Some(memory) = snapshot.machine_memory
            && (memory.free_frames > memory.total_frames
                || memory.heap_used_bytes > memory.heap_total_bytes)
        {
            return Err(EncodingError);
        }
        if let Some(input) = snapshot.input
            && input.queued > input.capacity
        {
            return Err(EncodingError);
        }
        if snapshot.ramfs_used_bytes > snapshot.ramfs_limit_bytes
            || snapshot.ramfs_high_water_bytes > snapshot.ramfs_limit_bytes
            || snapshot.caches_used_bytes > snapshot.caches_limit_bytes
        {
            return Err(EncodingError);
        }
        Ok(())
    }

    fn write_values(bytes: &mut [u8], offset: usize, values: &[u64]) {
        for (index, value) in values.iter().copied().enumerate() {
            let start = offset + index * 8;
            bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn read_values<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u64; N], EncodingError> {
        let mut values = [0_u64; N];
        for (index, value) in values.iter_mut().enumerate() {
            let start = offset + index * 8;
            let raw = bytes.get(start..start + 8).ok_or(EncodingError)?;
            *value = u64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]);
        }
        Ok(values)
    }
}

/// Capability-scoped observation of foreground, background, and service processes.
pub mod process_observation {
    use core::str;

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 1;
    /// Read one current bounded process snapshot.
    pub const GET_SNAPSHOT: u16 = 1;
    /// Read one stable-ID-cursor page of current process records.
    pub const GET_PAGE: u16 = 2;
    /// Maximum observable live processes.
    pub const MAX_PROCESSES: usize = 16;
    /// Maximum UTF-8 bytes in one executable name.
    pub const MAX_NAME_BYTES: usize = 32;
    /// Fixed snapshot-header bytes.
    pub const HEADER_BYTES: usize = 32;
    /// Fixed process-record bytes.
    pub const RECORD_BYTES: usize = 112;
    /// Exact canonical snapshot bytes.
    pub const SNAPSHOT_BYTES: usize = HEADER_BYTES + MAX_PROCESSES * RECORD_BYTES;
    /// Maximum process records returned by one paginated call.
    pub const MAX_PAGE_PROCESSES: usize = 32;
    /// Fixed paginated-response header bytes.
    pub const PAGE_HEADER_BYTES: usize = 48;
    /// Exact canonical paginated-response bytes.
    pub const PAGE_BYTES: usize = PAGE_HEADER_BYTES + MAX_PAGE_PROCESSES * RECORD_BYTES;
    /// Exact stable-ID cursor request bytes.
    pub const PAGE_REQUEST_BYTES: usize = 8;

    const MAGIC: [u8; 8] = *b"PROCv1\0\0";
    const PAGE_MAGIC: [u8; 8] = *b"PROCpg1\0";

    /// Observable launcher placement.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum Origin {
        /// Shell foreground terminal owner.
        Foreground = 1,
        /// Session-owned background job.
        Background = 2,
        /// Supervised service.
        Service = 3,
        /// Owner-scoped nested child.
        Child = 4,
    }

    /// Observable process lifecycle.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum State {
        /// Eligible for execution.
        Ready = 1,
        /// Currently executing unprivileged code.
        Running = 2,
        /// Waiting for one typed completion.
        Blocked = 3,
        /// Cancellation requested; teardown pending.
        Stopping = 4,
    }

    /// Fixed-capacity UTF-8 executable name without arguments.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ProcessName {
        bytes: [u8; MAX_NAME_BYTES],
        len: u8,
    }

    impl ProcessName {
        /// Copy one nonempty bounded UTF-8 name.
        ///
        /// # Errors
        ///
        /// Rejects empty names and names above [`MAX_NAME_BYTES`].
        pub fn new(name: &str) -> Result<Self, EncodingError> {
            if name.is_empty() || name.len() > MAX_NAME_BYTES {
                return Err(EncodingError);
            }
            let mut bytes = [0_u8; MAX_NAME_BYTES];
            bytes[..name.len()].copy_from_slice(name.as_bytes());
            Ok(Self {
                bytes,
                len: u8::try_from(name.len()).map_err(|_| EncodingError)?,
            })
        }

        /// Borrow the validated UTF-8 name.
        #[must_use]
        pub fn as_str(&self) -> &str {
            str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("invalid-process-name")
        }
    }

    /// One immutable process observation record.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Process {
        /// Monotonic non-reused process identity.
        pub id: u64,
        /// Internal monotonic scheduler task identity.
        pub task_id: u64,
        /// Boot-relative process launch time.
        pub started_millis: u64,
        /// High-resolution ticks spent within user execution boundaries.
        pub cpu_ticks: u64,
        /// Total retained application pages.
        pub resident_pages: u64,
        /// Retained page-table pages.
        pub table_pages: u64,
        /// Retained private image, startup, heap, and stack pages.
        pub private_pages: u64,
        /// Scheduler dispatch selections.
        pub dispatches: u32,
        /// Voluntary yields.
        pub yields: u32,
        /// Timer-driven resumable preemptions.
        pub preemptions: u32,
        /// Live generation-checked handles.
        pub handles: u16,
        /// Current lifecycle state.
        pub state: State,
        /// Launcher placement.
        pub origin: Origin,
        /// Executable name without arguments.
        pub name: ProcessName,
    }

    const EMPTY_NAME: ProcessName = ProcessName {
        bytes: [0; MAX_NAME_BYTES],
        len: 0,
    };
    const EMPTY_PROCESS: Process = Process {
        id: 0,
        task_id: 0,
        started_millis: 0,
        cpu_ticks: 0,
        resident_pages: 0,
        table_pages: 0,
        private_pages: 0,
        dispatches: 0,
        yields: 0,
        preemptions: 0,
        handles: 0,
        state: State::Ready,
        origin: Origin::Foreground,
        name: EMPTY_NAME,
    };

    /// One exact bounded current-process snapshot.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Snapshot {
        observed_millis: u64,
        counter_frequency_hz: u64,
        processes: [Process; MAX_PROCESSES],
        count: usize,
    }

    /// One fixed-size page from a stable-ID-cursor process scan.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Page {
        observed_millis: u64,
        counter_frequency_hz: u64,
        next_cursor: u64,
        total_processes: u32,
        processes: [Process; MAX_PAGE_PROCESSES],
        count: usize,
    }

    impl Page {
        /// Construct one canonical process page.
        ///
        /// # Errors
        ///
        /// Rejects invalid frequency, cursor, counts, ordering, or records.
        pub fn new(
            observed_millis: u64,
            counter_frequency_hz: u64,
            next_cursor: u64,
            total_processes: u32,
            processes: &[Process],
        ) -> Result<Self, EncodingError> {
            if counter_frequency_hz == 0
                || processes.len() > MAX_PAGE_PROCESSES
                || usize::try_from(total_processes).map_err(|_| EncodingError)? < processes.len()
                || (processes.is_empty() && next_cursor != 0)
                || (next_cursor != 0
                    && processes.last().map(|process| process.id) != Some(next_cursor))
            {
                return Err(EncodingError);
            }
            let mut retained = [EMPTY_PROCESS; MAX_PAGE_PROCESSES];
            let mut previous = 0_u64;
            for (destination, process) in retained.iter_mut().zip(processes.iter().copied()) {
                validate_process(process)?;
                if process.id <= previous {
                    return Err(EncodingError);
                }
                previous = process.id;
                *destination = process;
            }
            Ok(Self {
                observed_millis,
                counter_frequency_hz,
                next_cursor,
                total_processes,
                processes: retained,
                count: processes.len(),
            })
        }

        /// Boot-relative observation time.
        #[must_use]
        pub const fn observed_millis(self) -> u64 {
            self.observed_millis
        }

        /// Counter frequency used by every record.
        #[must_use]
        pub const fn counter_frequency_hz(self) -> u64 {
            self.counter_frequency_hz
        }

        /// Last returned process ID, or zero when this scan is complete.
        #[must_use]
        pub const fn next_cursor(self) -> u64 {
            self.next_cursor
        }

        /// Number of live records when this page was observed.
        #[must_use]
        pub const fn total_processes(self) -> u32 {
            self.total_processes
        }

        /// Records in ascending process-ID order.
        #[must_use]
        pub fn processes(&self) -> &[Process] {
            &self.processes[..self.count]
        }
    }

    impl Snapshot {
        /// Construct one snapshot by copying current records.
        ///
        /// # Errors
        ///
        /// Rejects zero frequency, excess records, or inconsistent records.
        pub fn new(
            observed_millis: u64,
            counter_frequency_hz: u64,
            processes: &[Process],
        ) -> Result<Self, EncodingError> {
            if counter_frequency_hz == 0 || processes.len() > MAX_PROCESSES {
                return Err(EncodingError);
            }
            let mut retained = [EMPTY_PROCESS; MAX_PROCESSES];
            for (destination, process) in retained.iter_mut().zip(processes.iter().copied()) {
                validate_process(process)?;
                *destination = process;
            }
            Ok(Self {
                observed_millis,
                counter_frequency_hz,
                processes: retained,
                count: processes.len(),
            })
        }

        /// Boot-relative time at which the snapshot was encoded.
        #[must_use]
        pub const fn observed_millis(self) -> u64 {
            self.observed_millis
        }

        /// Frequency used to convert `cpu_ticks` into time.
        #[must_use]
        pub const fn counter_frequency_hz(self) -> u64 {
            self.counter_frequency_hz
        }

        /// Current records in stable registration order.
        #[must_use]
        pub fn processes(&self) -> &[Process] {
            &self.processes[..self.count]
        }
    }

    /// Invalid, inconsistent, or noncanonical process snapshot.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode one exact canonical fixed-size snapshot.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent record values or bounds.
    pub fn encode_snapshot(snapshot: Snapshot) -> Result<[u8; SNAPSHOT_BYTES], EncodingError> {
        if snapshot.counter_frequency_hz == 0 || snapshot.count > MAX_PROCESSES {
            return Err(EncodingError);
        }
        let mut bytes = [0_u8; SNAPSHOT_BYTES];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..10].copy_from_slice(
            &u16::try_from(snapshot.count)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        bytes[10..12].copy_from_slice(
            &u16::try_from(RECORD_BYTES)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        bytes[12..16].copy_from_slice(
            &u32::try_from(SNAPSHOT_BYTES)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        write_u64(&mut bytes, 16, snapshot.observed_millis);
        write_u64(&mut bytes, 24, snapshot.counter_frequency_hz);
        for (index, process) in snapshot.processes().iter().copied().enumerate() {
            let at = HEADER_BYTES + index * RECORD_BYTES;
            encode_process(&mut bytes[at..at + RECORD_BYTES], process)?;
        }
        Ok(bytes)
    }

    /// Decode one exact canonical fixed-size snapshot.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, truncated, or inconsistent bytes.
    pub fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, EncodingError> {
        if bytes.len() != SNAPSHOT_BYTES
            || bytes[..8] != MAGIC
            || usize::from(read_u16(bytes, 10)?) != RECORD_BYTES
            || usize::try_from(read_u32(bytes, 12)?).map_err(|_| EncodingError)? != SNAPSHOT_BYTES
        {
            return Err(EncodingError);
        }
        let count = usize::from(read_u16(bytes, 8)?);
        if count > MAX_PROCESSES || read_u64(bytes, 24)? == 0 {
            return Err(EncodingError);
        }
        let mut processes = [EMPTY_PROCESS; MAX_PROCESSES];
        for (index, destination) in processes.iter_mut().take(count).enumerate() {
            let at = HEADER_BYTES + index * RECORD_BYTES;
            *destination = decode_process(&bytes[at..at + RECORD_BYTES])?;
        }
        let used = HEADER_BYTES + count * RECORD_BYTES;
        if bytes[used..].iter().any(|byte| *byte != 0) {
            return Err(EncodingError);
        }
        Snapshot::new(
            read_u64(bytes, 16)?,
            read_u64(bytes, 24)?,
            &processes[..count],
        )
    }

    /// Encode one stable-ID cursor request.
    #[must_use]
    pub const fn encode_page_request(after_process_id: u64) -> [u8; PAGE_REQUEST_BYTES] {
        after_process_id.to_le_bytes()
    }

    /// Decode one stable-ID cursor request.
    ///
    /// # Errors
    ///
    /// Rejects every non-exact request.
    pub fn decode_page_request(bytes: &[u8]) -> Result<u64, EncodingError> {
        if bytes.len() != PAGE_REQUEST_BYTES {
            return Err(EncodingError);
        }
        read_u64(bytes, 0)
    }

    /// Encode one exact fixed-size process page.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent page metadata or records.
    pub fn encode_page(page: Page) -> Result<[u8; PAGE_BYTES], EncodingError> {
        let canonical = Page::new(
            page.observed_millis,
            page.counter_frequency_hz,
            page.next_cursor,
            page.total_processes,
            page.processes(),
        )?;
        let mut bytes = [0_u8; PAGE_BYTES];
        bytes[..8].copy_from_slice(&PAGE_MAGIC);
        bytes[8..10].copy_from_slice(
            &u16::try_from(canonical.count)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        bytes[10..12].copy_from_slice(
            &u16::try_from(RECORD_BYTES)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        bytes[12..16].copy_from_slice(
            &u32::try_from(PAGE_BYTES)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        write_u64(&mut bytes, 16, canonical.observed_millis);
        write_u64(&mut bytes, 24, canonical.counter_frequency_hz);
        write_u64(&mut bytes, 32, canonical.next_cursor);
        bytes[40..44].copy_from_slice(&canonical.total_processes.to_le_bytes());
        for (index, process) in canonical.processes().iter().copied().enumerate() {
            let at = PAGE_HEADER_BYTES + index * RECORD_BYTES;
            encode_process(&mut bytes[at..at + RECORD_BYTES], process)?;
        }
        Ok(bytes)
    }

    /// Decode one exact fixed-size process page.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, truncated, or inconsistent bytes.
    pub fn decode_page(bytes: &[u8]) -> Result<Page, EncodingError> {
        if bytes.len() != PAGE_BYTES
            || bytes[..8] != PAGE_MAGIC
            || usize::from(read_u16(bytes, 10)?) != RECORD_BYTES
            || usize::try_from(read_u32(bytes, 12)?).map_err(|_| EncodingError)? != PAGE_BYTES
            || bytes[44..PAGE_HEADER_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(EncodingError);
        }
        let count = usize::from(read_u16(bytes, 8)?);
        if count > MAX_PAGE_PROCESSES || read_u64(bytes, 24)? == 0 {
            return Err(EncodingError);
        }
        let mut processes = [EMPTY_PROCESS; MAX_PAGE_PROCESSES];
        for (index, destination) in processes.iter_mut().take(count).enumerate() {
            let at = PAGE_HEADER_BYTES + index * RECORD_BYTES;
            *destination = decode_process(&bytes[at..at + RECORD_BYTES])?;
        }
        let used = PAGE_HEADER_BYTES + count * RECORD_BYTES;
        if bytes[used..].iter().any(|byte| *byte != 0) {
            return Err(EncodingError);
        }
        Page::new(
            read_u64(bytes, 16)?,
            read_u64(bytes, 24)?,
            read_u64(bytes, 32)?,
            read_u32(bytes, 40)?,
            &processes[..count],
        )
    }

    fn encode_process(bytes: &mut [u8], process: Process) -> Result<(), EncodingError> {
        if bytes.len() != RECORD_BYTES {
            return Err(EncodingError);
        }
        validate_process(process)?;
        write_u64(bytes, 0, process.id);
        write_u64(bytes, 8, process.task_id);
        write_u64(bytes, 16, process.started_millis);
        write_u64(bytes, 24, process.cpu_ticks);
        write_u64(bytes, 32, process.resident_pages);
        write_u64(bytes, 40, process.table_pages);
        write_u64(bytes, 48, process.private_pages);
        write_u32(bytes, 56, process.dispatches);
        write_u32(bytes, 60, process.yields);
        write_u32(bytes, 64, process.preemptions);
        bytes[68..70].copy_from_slice(&process.handles.to_le_bytes());
        bytes[70] = process.state as u8;
        bytes[71] = process.origin as u8;
        bytes[72] = process.name.len;
        bytes[80..112].copy_from_slice(&process.name.bytes);
        Ok(())
    }

    fn decode_process(bytes: &[u8]) -> Result<Process, EncodingError> {
        if bytes.len() != RECORD_BYTES || bytes[73..80].iter().any(|byte| *byte != 0) {
            return Err(EncodingError);
        }
        let name_len = usize::from(bytes[72]);
        if name_len == 0
            || name_len > MAX_NAME_BYTES
            || bytes[80 + name_len..112].iter().any(|byte| *byte != 0)
        {
            return Err(EncodingError);
        }
        let name = str::from_utf8(&bytes[80..80 + name_len]).map_err(|_| EncodingError)?;
        let process = Process {
            id: read_u64(bytes, 0)?,
            task_id: read_u64(bytes, 8)?,
            started_millis: read_u64(bytes, 16)?,
            cpu_ticks: read_u64(bytes, 24)?,
            resident_pages: read_u64(bytes, 32)?,
            table_pages: read_u64(bytes, 40)?,
            private_pages: read_u64(bytes, 48)?,
            dispatches: read_u32(bytes, 56)?,
            yields: read_u32(bytes, 60)?,
            preemptions: read_u32(bytes, 64)?,
            handles: read_u16(bytes, 68)?,
            state: match bytes[70] {
                1 => State::Ready,
                2 => State::Running,
                3 => State::Blocked,
                4 => State::Stopping,
                _ => return Err(EncodingError),
            },
            origin: match bytes[71] {
                1 => Origin::Foreground,
                2 => Origin::Background,
                3 => Origin::Service,
                4 => Origin::Child,
                _ => return Err(EncodingError),
            },
            name: ProcessName::new(name)?,
        };
        validate_process(process)?;
        Ok(process)
    }

    fn validate_process(process: Process) -> Result<(), EncodingError> {
        if process.id == 0
            || process.task_id == 0
            || process.table_pages == 0
            || process.private_pages == 0
            || process.resident_pages != process.table_pages.saturating_add(process.private_pages)
            || process.name.as_str().is_empty()
        {
            return Err(EncodingError);
        }
        Ok(())
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
        let value = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
        Ok(u16::from_le_bytes([value[0], value[1]]))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EncodingError> {
        let value = bytes.get(offset..offset + 4).ok_or(EncodingError)?;
        Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EncodingError> {
        let value = bytes.get(offset..offset + 8).ok_or(EncodingError)?;
        Ok(u64::from_le_bytes([
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
        ]))
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

/// Owner-scoped child-process launch and lifecycle protocol.
pub mod process_launch {
    use super::{MAX_SERVICE_PAYLOAD_BYTES, command, exit, str};

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Admit one child and return its owner-scoped token.
    pub const SPAWN: u16 = 1;
    /// Return current child state without blocking.
    pub const POLL: u16 = 2;
    /// Wait until one child becomes terminal.
    pub const WAIT: u16 = 3;
    /// Request cooperative child cancellation.
    pub const CANCEL: u16 = 4;
    /// Revoke a terminal child token and release retained metadata.
    pub const REAP: u16 = 5;
    /// Maximum environment entries passed to one child.
    pub const MAX_ENVIRONMENT: usize = command::MAX_ENVIRONMENT;
    /// Maximum aggregate environment UTF-8 bytes.
    pub const MAX_ENVIRONMENT_BYTES: usize = command::MAX_ENVIRONMENT_BYTES;
    /// Fixed spawn-request header bytes.
    pub const SPAWN_HEADER_BYTES: usize = 48;
    /// Maximum canonical spawn payload.
    pub const MAX_SPAWN_BYTES: usize = SPAWN_HEADER_BYTES
        + command::MAX_INVOCATION_BYTES
        + MAX_ENVIRONMENT * 2
        + MAX_ENVIRONMENT_BYTES;
    /// Exact child-token request bytes.
    pub const TOKEN_BYTES: usize = 8;
    /// Exact spawn reply bytes.
    pub const SPAWN_REPLY_BYTES: usize = 16;
    /// Exact poll/wait reply bytes.
    pub const STATUS_BYTES: usize = 24;
    /// Shell-visible status used for a contained child fault.
    pub const FAULT_EXIT_STATUS: u32 = 125;

    const MAGIC: [u8; 8] = *b"PSPNv1\0\0";

    /// Standard-stream source or destination selected for a child.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum StreamMode {
        /// Share the launching process's corresponding standard stream.
        Inherit = 1,
        /// Attach an immediate EOF input or discarded output endpoint.
        Null = 2,
        /// Attach the corresponding endpoint of an owner-scoped pipe.
        Pipe = 3,
    }

    /// One child standard-stream selection.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct StreamSpec {
        /// Endpoint behavior.
        pub mode: StreamMode,
        /// Nonzero pipe token only when `mode` is [`StreamMode::Pipe`].
        pub pipe: u64,
    }

    impl StreamSpec {
        /// Inherit the launching process's corresponding stream.
        pub const INHERIT: Self = Self {
            mode: StreamMode::Inherit,
            pipe: 0,
        };
        /// Attach a null endpoint.
        pub const NULL: Self = Self {
            mode: StreamMode::Null,
            pipe: 0,
        };

        /// Attach one owner-scoped pipe token.
        ///
        /// # Errors
        ///
        /// Rejects the reserved zero token.
        pub const fn pipe(token: u64) -> Result<Self, EncodingError> {
            if token == 0 {
                Err(EncodingError)
            } else {
                Ok(Self {
                    mode: StreamMode::Pipe,
                    pipe: token,
                })
            }
        }
    }

    /// Borrowed validated child launch request.
    #[derive(Clone, Copy, Debug)]
    pub struct SpawnRequest<'a> {
        invocation: command::Invocation<'a>,
        environment_table: &'a [u8],
        environment_bytes: &'a [u8],
        environment_count: usize,
        stdin: StreamSpec,
        stdout: StreamSpec,
        stderr: StreamSpec,
    }

    impl<'a> SpawnRequest<'a> {
        /// Validated cwd and argv record, including command name as argument zero.
        #[must_use]
        pub const fn invocation(self) -> command::Invocation<'a> {
            self.invocation
        }

        /// Environment entries in canonical input order.
        #[must_use]
        pub const fn environment(self) -> Environment<'a> {
            Environment {
                lengths: self.environment_table,
                bytes: self.environment_bytes,
                count: self.environment_count,
                index: 0,
                offset: 0,
            }
        }

        /// Child standard input selection.
        #[must_use]
        pub const fn stdin(self) -> StreamSpec {
            self.stdin
        }

        /// Child standard output selection.
        #[must_use]
        pub const fn stdout(self) -> StreamSpec {
            self.stdout
        }

        /// Child standard error selection.
        #[must_use]
        pub const fn stderr(self) -> StreamSpec {
            self.stderr
        }
    }

    /// Iterator over validated `NAME=VALUE` environment strings.
    pub struct Environment<'a> {
        lengths: &'a [u8],
        bytes: &'a [u8],
        count: usize,
        index: usize,
        offset: usize,
    }

    impl<'a> Iterator for Environment<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index >= self.count {
                return None;
            }
            let at = self.index.checked_mul(2)?;
            let length = usize::from(u16::from_le_bytes([
                *self.lengths.get(at)?,
                *self.lengths.get(at + 1)?,
            ]));
            let end = self.offset.checked_add(length)?;
            let value = str::from_utf8(self.bytes.get(self.offset..end)?).ok()?;
            self.index += 1;
            self.offset = end;
            Some(value)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = self.count.saturating_sub(self.index);
            (remaining, Some(remaining))
        }
    }

    impl ExactSizeIterator for Environment<'_> {}

    /// Opaque owner-scoped child capability returned at admission.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ChildToken(u64);

    impl ChildToken {
        /// Validate one nonzero opaque value.
        ///
        /// # Errors
        ///
        /// Rejects the reserved zero value.
        pub const fn new(value: u64) -> Result<Self, EncodingError> {
            if value == 0 {
                Err(EncodingError)
            } else {
                Ok(Self(value))
            }
        }

        /// Stable opaque ABI value.
        #[must_use]
        pub const fn value(self) -> u64 {
            self.0
        }
    }

    /// Successfully admitted child identity.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SpawnedChild {
        /// Owner-scoped control capability.
        pub token: ChildToken,
        /// Read-only global observation identity.
        pub process_id: u64,
    }

    /// Current owner-visible child lifecycle.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    pub enum ChildState {
        /// Child has not reached a terminal state.
        Running = 1,
        /// Child exited normally with the returned status.
        Exited = 2,
        /// Child faulted and maps to [`FAULT_EXIT_STATUS`].
        Faulted = 3,
        /// Owner cancellation completed.
        Cancelled = 4,
    }

    /// Poll or wait result for one child.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ChildStatus {
        /// Owner-scoped child token.
        pub token: ChildToken,
        /// Read-only global process identity.
        pub process_id: u64,
        /// Preserved full application exit status.
        pub exit_status: u32,
        /// Current lifecycle.
        pub state: ChildState,
    }

    /// Invalid or noncanonical process-launch payload.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode one canonical spawn request.
    ///
    /// # Errors
    ///
    /// Rejects malformed invocation/environment data, stream tokens, bounds,
    /// or insufficient destination space without modifying it.
    pub fn encode_spawn(
        invocation: &[u8],
        environment: &[&str],
        stdin: StreamSpec,
        stdout: StreamSpec,
        stderr: StreamSpec,
        destination: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let _validated = command::Invocation::parse(invocation).map_err(|_| EncodingError)?;
        validate_stream(stdin)?;
        validate_stream(stdout)?;
        validate_stream(stderr)?;
        if environment.len() > MAX_ENVIRONMENT {
            return Err(EncodingError);
        }
        let mut environment_bytes = 0_usize;
        for value in environment {
            validate_environment(value)?;
            environment_bytes = environment_bytes
                .checked_add(value.len())
                .ok_or(EncodingError)?;
        }
        if environment_bytes > MAX_ENVIRONMENT_BYTES {
            return Err(EncodingError);
        }
        let table_bytes = environment.len().checked_mul(2).ok_or(EncodingError)?;
        let total = SPAWN_HEADER_BYTES
            .checked_add(invocation.len())
            .and_then(|value| value.checked_add(table_bytes))
            .and_then(|value| value.checked_add(environment_bytes))
            .ok_or(EncodingError)?;
        if total > MAX_SERVICE_PAYLOAD_BYTES || total > MAX_SPAWN_BYTES || destination.len() < total
        {
            return Err(EncodingError);
        }
        destination[..total].fill(0);
        destination[..8].copy_from_slice(&MAGIC);
        destination[8..10].copy_from_slice(
            &u16::try_from(total)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        destination[10..12].copy_from_slice(
            &u16::try_from(invocation.len())
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        destination[12..14].copy_from_slice(
            &u16::try_from(environment.len())
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        destination[14..16].copy_from_slice(
            &u16::try_from(environment_bytes)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        destination[16..24].copy_from_slice(&stdin.pipe.to_le_bytes());
        destination[24..32].copy_from_slice(&stdout.pipe.to_le_bytes());
        destination[32..40].copy_from_slice(&stderr.pipe.to_le_bytes());
        destination[40] = stdin.mode as u8;
        destination[41] = stdout.mode as u8;
        destination[42] = stderr.mode as u8;
        let invocation_end = SPAWN_HEADER_BYTES + invocation.len();
        destination[SPAWN_HEADER_BYTES..invocation_end].copy_from_slice(invocation);
        let table_start = invocation_end;
        let values_start = table_start + table_bytes;
        let mut cursor = values_start;
        for (index, value) in environment.iter().enumerate() {
            let at = table_start + index * 2;
            destination[at..at + 2].copy_from_slice(
                &u16::try_from(value.len())
                    .map_err(|_| EncodingError)?
                    .to_le_bytes(),
            );
            let end = cursor.checked_add(value.len()).ok_or(EncodingError)?;
            destination[cursor..end].copy_from_slice(value.as_bytes());
            cursor = end;
        }
        Ok(total)
    }

    /// Decode one exact canonical spawn request.
    ///
    /// # Errors
    ///
    /// Rejects every malformed, excessive, non-UTF-8, or trailing byte.
    pub fn decode_spawn(bytes: &[u8]) -> Result<SpawnRequest<'_>, EncodingError> {
        if bytes.len() < SPAWN_HEADER_BYTES
            || bytes[..8] != MAGIC
            || usize::from(read_u16(bytes, 8)?) != bytes.len()
            || bytes[43..SPAWN_HEADER_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(EncodingError);
        }
        let invocation_bytes = usize::from(read_u16(bytes, 10)?);
        let environment_count = usize::from(read_u16(bytes, 12)?);
        let environment_bytes = usize::from(read_u16(bytes, 14)?);
        if environment_count > MAX_ENVIRONMENT || environment_bytes > MAX_ENVIRONMENT_BYTES {
            return Err(EncodingError);
        }
        let table_bytes = environment_count.checked_mul(2).ok_or(EncodingError)?;
        let invocation_end = SPAWN_HEADER_BYTES
            .checked_add(invocation_bytes)
            .ok_or(EncodingError)?;
        let table_end = invocation_end
            .checked_add(table_bytes)
            .ok_or(EncodingError)?;
        let values_end = table_end
            .checked_add(environment_bytes)
            .ok_or(EncodingError)?;
        if values_end != bytes.len() {
            return Err(EncodingError);
        }
        let invocation = command::Invocation::parse(&bytes[SPAWN_HEADER_BYTES..invocation_end])
            .map_err(|_| EncodingError)?;
        let stdin = decode_stream(bytes[40], read_u64(bytes, 16)?)?;
        let stdout = decode_stream(bytes[41], read_u64(bytes, 24)?)?;
        let stderr = decode_stream(bytes[42], read_u64(bytes, 32)?)?;
        let environment_table = &bytes[invocation_end..table_end];
        let environment_values = &bytes[table_end..values_end];
        let environment = Environment {
            lengths: environment_table,
            bytes: environment_values,
            count: environment_count,
            index: 0,
            offset: 0,
        };
        let mut consumed = 0_usize;
        for value in environment {
            validate_environment(value)?;
            consumed = consumed.checked_add(value.len()).ok_or(EncodingError)?;
        }
        if consumed != environment_bytes {
            return Err(EncodingError);
        }
        Ok(SpawnRequest {
            invocation,
            environment_table,
            environment_bytes: environment_values,
            environment_count,
            stdin,
            stdout,
            stderr,
        })
    }

    /// Encode one child token request.
    #[must_use]
    pub const fn encode_token(token: ChildToken) -> [u8; TOKEN_BYTES] {
        token.value().to_le_bytes()
    }

    /// Decode one exact child token request.
    ///
    /// # Errors
    ///
    /// Rejects non-exact or zero tokens.
    pub fn decode_token(bytes: &[u8]) -> Result<ChildToken, EncodingError> {
        if bytes.len() != TOKEN_BYTES {
            return Err(EncodingError);
        }
        ChildToken::new(read_u64(bytes, 0)?)
    }

    /// Encode one successful spawn reply.
    #[must_use]
    pub fn encode_spawned(child: SpawnedChild) -> [u8; SPAWN_REPLY_BYTES] {
        let mut bytes = [0_u8; SPAWN_REPLY_BYTES];
        bytes[..8].copy_from_slice(&child.token.value().to_le_bytes());
        bytes[8..16].copy_from_slice(&child.process_id.to_le_bytes());
        bytes
    }

    /// Decode one successful spawn reply.
    ///
    /// # Errors
    ///
    /// Rejects non-exact, zero, or invalid identities.
    pub fn decode_spawned(bytes: &[u8]) -> Result<SpawnedChild, EncodingError> {
        if bytes.len() != SPAWN_REPLY_BYTES {
            return Err(EncodingError);
        }
        let process_id = read_u64(bytes, 8)?;
        if process_id == 0 {
            return Err(EncodingError);
        }
        Ok(SpawnedChild {
            token: ChildToken::new(read_u64(bytes, 0)?)?,
            process_id,
        })
    }

    /// Encode one canonical child status.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent state/status combinations.
    pub fn encode_status(status: ChildStatus) -> Result<[u8; STATUS_BYTES], EncodingError> {
        validate_status(status)?;
        let mut bytes = [0_u8; STATUS_BYTES];
        bytes[..8].copy_from_slice(&status.token.value().to_le_bytes());
        bytes[8..16].copy_from_slice(&status.process_id.to_le_bytes());
        bytes[16..20].copy_from_slice(&status.exit_status.to_le_bytes());
        bytes[20] = status.state as u8;
        Ok(bytes)
    }

    /// Decode one exact child status.
    ///
    /// # Errors
    ///
    /// Rejects malformed, reserved, or inconsistent values.
    pub fn decode_status(bytes: &[u8]) -> Result<ChildStatus, EncodingError> {
        if bytes.len() != STATUS_BYTES || bytes[21..].iter().any(|byte| *byte != 0) {
            return Err(EncodingError);
        }
        let status = ChildStatus {
            token: ChildToken::new(read_u64(bytes, 0)?)?,
            process_id: read_u64(bytes, 8)?,
            exit_status: read_u32(bytes, 16)?,
            state: match bytes[20] {
                1 => ChildState::Running,
                2 => ChildState::Exited,
                3 => ChildState::Faulted,
                4 => ChildState::Cancelled,
                _ => return Err(EncodingError),
            },
        };
        validate_status(status)?;
        Ok(status)
    }

    fn validate_stream(stream: StreamSpec) -> Result<(), EncodingError> {
        if (stream.mode == StreamMode::Pipe) != (stream.pipe != 0) {
            return Err(EncodingError);
        }
        Ok(())
    }

    fn decode_stream(mode: u8, pipe: u64) -> Result<StreamSpec, EncodingError> {
        let stream = StreamSpec {
            mode: match mode {
                1 => StreamMode::Inherit,
                2 => StreamMode::Null,
                3 => StreamMode::Pipe,
                _ => return Err(EncodingError),
            },
            pipe,
        };
        validate_stream(stream)?;
        Ok(stream)
    }

    fn validate_environment(value: &str) -> Result<(), EncodingError> {
        let Some((name, _value)) = value.split_once('=') else {
            return Err(EncodingError);
        };
        if name.is_empty()
            || name.as_bytes().first().is_some_and(u8::is_ascii_digit)
            || !name
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            || value.as_bytes().contains(&0)
        {
            return Err(EncodingError);
        }
        Ok(())
    }

    fn validate_status(status: ChildStatus) -> Result<(), EncodingError> {
        if status.process_id == 0
            || (status.state == ChildState::Running && status.exit_status != 0)
            || (status.state == ChildState::Faulted && status.exit_status != FAULT_EXIT_STATUS)
            || (status.state == ChildState::Cancelled && status.exit_status != exit::CANCELLED)
        {
            return Err(EncodingError);
        }
        Ok(())
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

/// Owner-scoped bounded byte-pipe protocol.
pub mod pipe {
    use super::MAX_SERVICE_PAYLOAD_BYTES;

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Create one pipe and return its opaque owner token.
    pub const CREATE: u16 = 1;
    /// Write bytes to a pipe's writer endpoint.
    pub const WRITE: u16 = 2;
    /// Read currently available bytes from a pipe's reader endpoint.
    pub const READ: u16 = 3;
    /// Close the owner's writer endpoint.
    pub const CLOSE_WRITER: u16 = 4;
    /// Close the owner's reader endpoint.
    pub const CLOSE_READER: u16 = 5;
    /// Minimum pipe byte capacity.
    pub const MIN_CAPACITY: usize = 4 * 1024;
    /// Maximum pipe byte capacity.
    pub const MAX_CAPACITY: usize = 1024 * 1024;
    /// Maximum bytes transferred in one pipe operation.
    pub const MAX_IO_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES - 8;
    /// Exact create request bytes.
    pub const CREATE_REQUEST_BYTES: usize = 4;
    /// Exact token-only request or create reply bytes.
    pub const TOKEN_BYTES: usize = 8;
    /// Exact read request bytes.
    pub const READ_REQUEST_BYTES: usize = 16;

    /// Opaque owner-scoped pipe identity.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct PipeToken(u64);

    impl PipeToken {
        /// Validate one nonzero opaque value.
        ///
        /// # Errors
        ///
        /// Rejects the reserved zero value.
        pub const fn new(value: u64) -> Result<Self, EncodingError> {
            if value == 0 {
                Err(EncodingError)
            } else {
                Ok(Self(value))
            }
        }

        /// Stable opaque ABI value.
        #[must_use]
        pub const fn value(self) -> u64 {
            self.0
        }
    }

    /// Invalid or noncanonical pipe payload.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode a requested pipe capacity.
    ///
    /// # Errors
    ///
    /// Rejects values outside the closed capacity policy.
    pub fn encode_create(capacity: usize) -> Result<[u8; CREATE_REQUEST_BYTES], EncodingError> {
        if !(MIN_CAPACITY..=MAX_CAPACITY).contains(&capacity) {
            return Err(EncodingError);
        }
        Ok(u32::try_from(capacity)
            .map_err(|_| EncodingError)?
            .to_le_bytes())
    }

    /// Decode one exact create request.
    ///
    /// # Errors
    ///
    /// Rejects non-exact or out-of-policy values.
    pub fn decode_create(bytes: &[u8]) -> Result<usize, EncodingError> {
        if bytes.len() != CREATE_REQUEST_BYTES {
            return Err(EncodingError);
        }
        let capacity = usize::try_from(read_u32(bytes, 0)?).map_err(|_| EncodingError)?;
        if !(MIN_CAPACITY..=MAX_CAPACITY).contains(&capacity) {
            return Err(EncodingError);
        }
        Ok(capacity)
    }

    /// Encode one pipe token.
    #[must_use]
    pub const fn encode_token(token: PipeToken) -> [u8; TOKEN_BYTES] {
        token.value().to_le_bytes()
    }

    /// Decode one exact pipe token.
    ///
    /// # Errors
    ///
    /// Rejects non-exact or zero tokens.
    pub fn decode_token(bytes: &[u8]) -> Result<PipeToken, EncodingError> {
        if bytes.len() != TOKEN_BYTES {
            return Err(EncodingError);
        }
        PipeToken::new(read_u64(bytes, 0)?)
    }

    /// Encode one bounded pipe write request into caller storage.
    ///
    /// # Errors
    ///
    /// Rejects empty/excess payloads or insufficient destination storage.
    pub fn encode_write(
        token: PipeToken,
        payload: &[u8],
        destination: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let total = TOKEN_BYTES
            .checked_add(payload.len())
            .ok_or(EncodingError)?;
        if payload.is_empty() || payload.len() > MAX_IO_BYTES || destination.len() < total {
            return Err(EncodingError);
        }
        destination[..TOKEN_BYTES].copy_from_slice(&encode_token(token));
        destination[TOKEN_BYTES..total].copy_from_slice(payload);
        Ok(total)
    }

    /// Decode one exact pipe write request.
    ///
    /// # Errors
    ///
    /// Rejects empty/excess payloads or invalid tokens.
    pub fn decode_write(bytes: &[u8]) -> Result<(PipeToken, &[u8]), EncodingError> {
        if !(TOKEN_BYTES + 1..=MAX_SERVICE_PAYLOAD_BYTES).contains(&bytes.len()) {
            return Err(EncodingError);
        }
        Ok((decode_token(&bytes[..TOKEN_BYTES])?, &bytes[TOKEN_BYTES..]))
    }

    /// Encode one bounded read request.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive requested lengths.
    pub fn encode_read(
        token: PipeToken,
        maximum_bytes: usize,
    ) -> Result<[u8; READ_REQUEST_BYTES], EncodingError> {
        if maximum_bytes == 0 || maximum_bytes > MAX_IO_BYTES {
            return Err(EncodingError);
        }
        let mut bytes = [0_u8; READ_REQUEST_BYTES];
        bytes[..8].copy_from_slice(&encode_token(token));
        bytes[8..10].copy_from_slice(
            &u16::try_from(maximum_bytes)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        Ok(bytes)
    }

    /// Decode one exact bounded read request.
    ///
    /// # Errors
    ///
    /// Rejects padding, invalid tokens, or invalid requested lengths.
    pub fn decode_read(bytes: &[u8]) -> Result<(PipeToken, usize), EncodingError> {
        if bytes.len() != READ_REQUEST_BYTES || bytes[10..].iter().any(|byte| *byte != 0) {
            return Err(EncodingError);
        }
        let maximum = usize::from(read_u16(bytes, 8)?);
        if maximum == 0 || maximum > MAX_IO_BYTES {
            return Err(EncodingError);
        }
        Ok((decode_token(&bytes[..8])?, maximum))
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

/// Read-only typed IPv4 configuration, counters, and neighbor protocol.
pub mod network_observation {
    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Read current link and IPv4 configuration.
    pub const GET_STATUS: u16 = 1;
    /// Read current ambient counters and bounded resource use.
    pub const GET_STATS: u16 = 2;
    /// Read the complete bounded neighbor cache.
    pub const GET_NEIGHBORS: u16 = 3;
    /// Exact link/configuration reply bytes.
    pub const STATUS_BYTES: usize = 24;
    /// Exact counter reply bytes.
    pub const STATS_BYTES: usize = 88;
    /// Maximum retained IPv4 neighbors.
    pub const MAX_NEIGHBORS: usize = 256;
    /// Maximum canonical neighbor-list reply bytes.
    pub const MAX_NEIGHBOR_REPLY_BYTES: usize = 8 + MAX_NEIGHBORS * 10;

    const CONFIGURED: u8 = 1 << 0;
    const LEASE_PRESENT: u8 = 1 << 1;
    const KNOWN_STATUS_FLAGS: u8 = CONFIGURED | LEASE_PRESENT;

    /// Current configured IPv4 values.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Ipv4Configuration {
        /// Interface address.
        pub address: [u8; 4],
        /// Subnet mask.
        pub subnet_mask: [u8; 4],
        /// Default gateway.
        pub gateway: [u8; 4],
        /// DHCP lease duration when supplied by the server.
        pub lease_seconds: Option<u32>,
    }

    /// Current link and optional IPv4 configuration.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Status {
        /// Attached interface Ethernet address.
        pub mac: [u8; 6],
        /// Complete IPv4 configuration when acquired.
        pub configuration: Option<Ipv4Configuration>,
    }

    /// Ambient network counters and bounded resource use.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Stats {
        /// Complete received frames.
        pub received_frames: u64,
        /// Complete transmitted frames.
        pub transmitted_frames: u64,
        /// Answered ARP requests.
        pub arp_replies: u64,
        /// Answered ICMP echo requests.
        pub icmp_replies: u64,
        /// UDP datagrams retained by bound ports.
        pub udp_retained: u64,
        /// UDP datagrams dropped without a bound port.
        pub udp_unbound: u64,
        /// UDP datagrams dropped at queue ceilings.
        pub udp_dropped: u64,
        /// Currently retained neighbor entries.
        pub arp_entries: u64,
        /// Currently bound UDP ports.
        pub udp_ports: u64,
        /// Ambient service checkpoints.
        pub checkpoints: u64,
        /// Device or packet-processing errors.
        pub errors: u64,
    }

    /// One retained IPv4-to-Ethernet neighbor mapping.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Neighbor {
        /// Neighbor IPv4 address.
        pub address: [u8; 4],
        /// Neighbor Ethernet address.
        pub mac: [u8; 6],
    }

    /// Complete fixed-capacity neighbor snapshot.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Neighbors {
        entries: [Neighbor; MAX_NEIGHBORS],
        count: usize,
    }

    impl Neighbors {
        /// Construct one bounded neighbor snapshot.
        ///
        /// # Errors
        ///
        /// Rejects excess or duplicate IPv4 entries.
        pub fn from_slice(entries: &[Neighbor]) -> Result<Self, EncodingError> {
            if entries.len() > MAX_NEIGHBORS
                || entries.iter().enumerate().any(|(index, entry)| {
                    entries[..index]
                        .iter()
                        .any(|prior| prior.address == entry.address)
                })
            {
                return Err(EncodingError);
            }
            let mut retained = [Neighbor::default(); MAX_NEIGHBORS];
            retained[..entries.len()].copy_from_slice(entries);
            Ok(Self {
                entries: retained,
                count: entries.len(),
            })
        }

        /// Number of retained entries.
        #[must_use]
        pub const fn len(self) -> usize {
            self.count
        }

        /// Whether the snapshot contains no neighbors.
        #[must_use]
        pub const fn is_empty(self) -> bool {
            self.count == 0
        }

        /// Iterate over retained entries in service order.
        #[must_use]
        pub fn iter(&self) -> impl ExactSizeIterator<Item = Neighbor> + '_ {
            self.entries[..self.count].iter().copied()
        }
    }

    /// Invalid, inconsistent, or noncanonical network-observation encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode one exact link/configuration status.
    ///
    /// # Errors
    ///
    /// Rejects a configured zero interface address.
    pub fn encode_status(status: Status) -> Result<[u8; STATUS_BYTES], EncodingError> {
        let mut bytes = [0_u8; STATUS_BYTES];
        bytes[..6].copy_from_slice(&status.mac);
        if let Some(configuration) = status.configuration {
            if configuration.address == [0; 4] {
                return Err(EncodingError);
            }
            bytes[6] = CONFIGURED;
            bytes[8..12].copy_from_slice(&configuration.address);
            bytes[12..16].copy_from_slice(&configuration.subnet_mask);
            bytes[16..20].copy_from_slice(&configuration.gateway);
            if let Some(lease) = configuration.lease_seconds {
                bytes[6] |= LEASE_PRESENT;
                bytes[20..24].copy_from_slice(&lease.to_le_bytes());
            }
        }
        Ok(bytes)
    }

    /// Decode one exact canonical link/configuration status.
    ///
    /// # Errors
    ///
    /// Rejects unknown flags, nonzero reserved/absent fields, a lease without
    /// configuration, a configured zero address, or the wrong length.
    pub fn decode_status(bytes: &[u8]) -> Result<Status, EncodingError> {
        if bytes.len() != STATUS_BYTES
            || bytes[6] & !KNOWN_STATUS_FLAGS != 0
            || bytes[7] != 0
            || bytes[6] & LEASE_PRESENT != 0 && bytes[6] & CONFIGURED == 0
        {
            return Err(EncodingError);
        }
        let configured_values_nonzero = bytes[8..24].iter().any(|byte| *byte != 0);
        let configuration = if bytes[6] & CONFIGURED != 0 {
            let address = [bytes[8], bytes[9], bytes[10], bytes[11]];
            if address == [0; 4] {
                return Err(EncodingError);
            }
            Some(Ipv4Configuration {
                address,
                subnet_mask: [bytes[12], bytes[13], bytes[14], bytes[15]],
                gateway: [bytes[16], bytes[17], bytes[18], bytes[19]],
                lease_seconds: if bytes[6] & LEASE_PRESENT != 0 {
                    Some(u32::from_le_bytes([
                        bytes[20], bytes[21], bytes[22], bytes[23],
                    ]))
                } else {
                    if bytes[20..24] != [0; 4] {
                        return Err(EncodingError);
                    }
                    None
                },
            })
        } else if configured_values_nonzero {
            return Err(EncodingError);
        } else {
            None
        };
        Ok(Status {
            mac: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
            configuration,
        })
    }

    /// Encode one exact counter snapshot.
    ///
    /// # Errors
    ///
    /// Rejects resource counts above their fixed service ceilings.
    pub fn encode_stats(stats: Stats) -> Result<[u8; STATS_BYTES], EncodingError> {
        if stats.arp_entries > MAX_NEIGHBORS as u64 || stats.udp_ports > MAX_NEIGHBORS as u64 {
            return Err(EncodingError);
        }
        let mut bytes = [0_u8; STATS_BYTES];
        write_values(
            &mut bytes,
            &[
                stats.received_frames,
                stats.transmitted_frames,
                stats.arp_replies,
                stats.icmp_replies,
                stats.udp_retained,
                stats.udp_unbound,
                stats.udp_dropped,
                stats.arp_entries,
                stats.udp_ports,
                stats.checkpoints,
                stats.errors,
            ],
        );
        Ok(bytes)
    }

    /// Decode one exact counter snapshot.
    ///
    /// # Errors
    ///
    /// Rejects the wrong length or resource counts above fixed ceilings.
    pub fn decode_stats(bytes: &[u8]) -> Result<Stats, EncodingError> {
        if bytes.len() != STATS_BYTES {
            return Err(EncodingError);
        }
        let values = read_values::<11>(bytes)?;
        let stats = Stats {
            received_frames: values[0],
            transmitted_frames: values[1],
            arp_replies: values[2],
            icmp_replies: values[3],
            udp_retained: values[4],
            udp_unbound: values[5],
            udp_dropped: values[6],
            arp_entries: values[7],
            udp_ports: values[8],
            checkpoints: values[9],
            errors: values[10],
        };
        encode_stats(stats)?;
        Ok(stats)
    }

    /// Encode one complete bounded neighbor snapshot.
    ///
    /// # Errors
    ///
    /// Rejects insufficient storage without modifying it.
    pub fn encode_neighbors(
        neighbors: Neighbors,
        output: &mut [u8],
    ) -> Result<usize, EncodingError> {
        let count = 8 + neighbors.count.checked_mul(10).ok_or(EncodingError)?;
        if output.len() < count {
            return Err(EncodingError);
        }
        let mut bytes = [0_u8; MAX_NEIGHBOR_REPLY_BYTES];
        bytes[..2].copy_from_slice(
            &u16::try_from(neighbors.count)
                .map_err(|_| EncodingError)?
                .to_le_bytes(),
        );
        for (index, entry) in neighbors.iter().enumerate() {
            let offset = 8 + index * 10;
            bytes[offset..offset + 4].copy_from_slice(&entry.address);
            bytes[offset + 4..offset + 10].copy_from_slice(&entry.mac);
        }
        output[..count].copy_from_slice(&bytes[..count]);
        Ok(count)
    }

    /// Decode one exact complete bounded neighbor snapshot.
    ///
    /// # Errors
    ///
    /// Rejects excess, truncation, trailing bytes, nonzero reserved fields, or
    /// duplicate IPv4 entries.
    pub fn decode_neighbors(bytes: &[u8]) -> Result<Neighbors, EncodingError> {
        if bytes.len() < 8 || bytes[2..8] != [0; 6] {
            return Err(EncodingError);
        }
        let count = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        let expected = 8_usize
            .checked_add(count.checked_mul(10).ok_or(EncodingError)?)
            .ok_or(EncodingError)?;
        if count > MAX_NEIGHBORS || bytes.len() != expected {
            return Err(EncodingError);
        }
        let mut entries = [Neighbor::default(); MAX_NEIGHBORS];
        for (index, entry) in entries[..count].iter_mut().enumerate() {
            let offset = 8 + index * 10;
            entry.address = [
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ];
            entry.mac.copy_from_slice(&bytes[offset + 4..offset + 10]);
        }
        Neighbors::from_slice(&entries[..count])
    }

    fn write_values(bytes: &mut [u8], values: &[u64]) {
        for (index, value) in values.iter().copied().enumerate() {
            let offset = index * 8;
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn read_values<const N: usize>(bytes: &[u8]) -> Result<[u64; N], EncodingError> {
        let mut values = [0_u64; N];
        for (index, value) in values.iter_mut().enumerate() {
            let offset = index * 8;
            let raw = bytes.get(offset..offset + 8).ok_or(EncodingError)?;
            *value = u64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]);
        }
        Ok(values)
    }
}

/// Bounded DHCP configuration protocol.
pub mod network_configuration {
    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Perform one bounded DHCP discover/request exchange.
    pub const DHCP: u16 = 1;
}

/// Bounded ICMP echo protocol.
pub mod icmp_echo {
    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Send one echo request and wait for its matching reply.
    pub const ECHO: u16 = 1;
    /// Exact destination request bytes.
    pub const REQUEST_BYTES: usize = 4;
    /// Exact echo reply bytes.
    pub const REPLY_BYTES: usize = 8;

    /// Successful typed ICMP echo result.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Reply {
        /// Reply source address.
        pub source: [u8; 4],
        /// Echo sequence number.
        pub sequence: u16,
        /// Echo payload byte count.
        pub bytes: u16,
    }

    /// Invalid ICMP echo request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// Encode one exact echo destination.
    #[must_use]
    pub const fn encode_request(destination: [u8; 4]) -> [u8; REQUEST_BYTES] {
        destination
    }

    /// Decode one exact echo destination.
    ///
    /// # Errors
    ///
    /// Rejects every length other than four bytes.
    pub fn decode_request(bytes: &[u8]) -> Result<[u8; 4], EncodingError> {
        if bytes.len() != REQUEST_BYTES {
            return Err(EncodingError);
        }
        Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Encode one exact typed echo reply.
    #[must_use]
    pub fn encode_reply(reply: Reply) -> [u8; REPLY_BYTES] {
        let mut bytes = [0_u8; REPLY_BYTES];
        bytes[..4].copy_from_slice(&reply.source);
        bytes[4..6].copy_from_slice(&reply.sequence.to_le_bytes());
        bytes[6..8].copy_from_slice(&reply.bytes.to_le_bytes());
        bytes
    }

    /// Decode one exact typed echo reply.
    ///
    /// # Errors
    ///
    /// Rejects every length other than eight bytes.
    pub fn decode_reply(bytes: &[u8]) -> Result<Reply, EncodingError> {
        if bytes.len() != REPLY_BYTES {
            return Err(EncodingError);
        }
        Ok(Reply {
            source: [bytes[0], bytes[1], bytes[2], bytes[3]],
            sequence: u16::from_le_bytes([bytes[4], bytes[5]]),
            bytes: u16::from_le_bytes([bytes[6], bytes[7]]),
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

/// One bounded outbound IPv4/TCP byte-stream protocol.
pub mod tcp_connect {
    use super::MAX_SERVICE_PAYLOAD_BYTES;

    /// Interface major version.
    pub const MAJOR: u16 = 1;
    /// Interface minor version.
    pub const MINOR: u16 = 0;
    /// Attempt one connection to one literal IPv4 endpoint.
    pub const CONNECT: u16 = 1;
    /// Write and acknowledge one bounded stream chunk.
    pub const WRITE: u16 = 2;
    /// Wait for and return one bounded stream chunk; zero bytes is EOF.
    pub const READ: u16 = 3;
    /// Gracefully close the one connection.
    pub const CLOSE: u16 = 4;
    /// Exact connect request bytes, including two reserved zero bytes.
    pub const CONNECT_REQUEST_BYTES: usize = 8;
    /// Exact selected-local-port connect reply bytes.
    pub const CONNECT_REPLY_BYTES: usize = 2;
    /// Largest write admitted as one TCP segment.
    pub const MAX_WRITE_BYTES: usize = 1_460;
    /// Largest read returned through the generic KEX service call gate.
    pub const MAX_READ_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES;
    /// Exact read request bytes.
    pub const READ_REQUEST_BYTES: usize = 2;

    /// Invalid TCP connect request or reply encoding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EncodingError;

    /// One validated literal IPv4 destination.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ConnectRequest {
        /// Destination in network display order.
        pub destination: [u8; 4],
        /// Nonzero destination TCP port.
        pub destination_port: u16,
    }

    /// Encode one exact literal endpoint request.
    ///
    /// # Errors
    ///
    /// Rejects unspecified, loopback, multicast, broadcast, and class-E
    /// destinations plus port zero.
    pub fn encode_connect_request(
        destination: [u8; 4],
        destination_port: u16,
    ) -> Result<[u8; CONNECT_REQUEST_BYTES], EncodingError> {
        if !valid_destination(destination) || destination_port == 0 {
            return Err(EncodingError);
        }
        let mut bytes = [0_u8; CONNECT_REQUEST_BYTES];
        bytes[..4].copy_from_slice(&destination);
        bytes[4..6].copy_from_slice(&destination_port.to_le_bytes());
        Ok(bytes)
    }

    /// Decode one exact literal endpoint request.
    ///
    /// # Errors
    ///
    /// Rejects every truncation/trailing byte, nonzero reserved field, invalid
    /// address class, and port zero.
    pub fn decode_connect_request(bytes: &[u8]) -> Result<ConnectRequest, EncodingError> {
        if bytes.len() != CONNECT_REQUEST_BYTES || bytes[6..8] != [0, 0] {
            return Err(EncodingError);
        }
        let destination = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let destination_port = u16::from_le_bytes([bytes[4], bytes[5]]);
        if !valid_destination(destination) || destination_port == 0 {
            return Err(EncodingError);
        }
        Ok(ConnectRequest {
            destination,
            destination_port,
        })
    }

    /// Encode the exact selected local port.
    ///
    /// # Errors
    ///
    /// Rejects port zero.
    pub fn encode_connect_reply(
        local_port: u16,
    ) -> Result<[u8; CONNECT_REPLY_BYTES], EncodingError> {
        if local_port == 0 {
            return Err(EncodingError);
        }
        Ok(local_port.to_le_bytes())
    }

    /// Decode the exact selected local port.
    ///
    /// # Errors
    ///
    /// Rejects every length other than two bytes and port zero.
    pub fn decode_connect_reply(bytes: &[u8]) -> Result<u16, EncodingError> {
        if bytes.len() != CONNECT_REPLY_BYTES {
            return Err(EncodingError);
        }
        let port = u16::from_le_bytes([bytes[0], bytes[1]]);
        if port == 0 {
            return Err(EncodingError);
        }
        Ok(port)
    }

    /// Validate one write payload and return it unchanged.
    ///
    /// # Errors
    ///
    /// Rejects empty or multi-segment writes.
    pub fn decode_write_request(bytes: &[u8]) -> Result<&[u8], EncodingError> {
        if bytes.is_empty() || bytes.len() > MAX_WRITE_BYTES {
            return Err(EncodingError);
        }
        Ok(bytes)
    }

    /// Encode one bounded read byte count.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above the KEX reply-payload ceiling.
    pub fn encode_read_request(
        requested: usize,
    ) -> Result<[u8; READ_REQUEST_BYTES], EncodingError> {
        if requested == 0 || requested > MAX_READ_BYTES {
            return Err(EncodingError);
        }
        Ok(u16::try_from(requested)
            .map_err(|_| EncodingError)?
            .to_le_bytes())
    }

    /// Decode one exact bounded read byte count.
    ///
    /// # Errors
    ///
    /// Rejects every length other than two bytes, zero, and values above the
    /// KEX reply-payload ceiling.
    pub fn decode_read_request(bytes: &[u8]) -> Result<usize, EncodingError> {
        if bytes.len() != READ_REQUEST_BYTES {
            return Err(EncodingError);
        }
        let requested = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        if requested == 0 || requested > MAX_READ_BYTES {
            return Err(EncodingError);
        }
        Ok(requested)
    }

    fn valid_destination(address: [u8; 4]) -> bool {
        address != [0; 4]
            && address != [255; 4]
            && address[0] != 0
            && address[0] != 127
            && address[0] < 224
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_MESSAGE_BYTES, command, datagram, diagnostics, filesystem, filesystem_mutation,
        icmp_echo, interface, network_observation, pipe, process_launch, process_observation,
        reply, requirements, server, shell_script, stream, tcp_connect, timer, volume_control,
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
            interface::TIMER,
            interface::DIAGNOSTICS,
            interface::NETWORK_OBSERVE,
            interface::NETWORK_CONFIGURE,
            interface::ICMP_ECHO,
            interface::TCP_CONNECT,
            interface::VOLUME_CONTROL,
            interface::SERVER_ENDPOINT,
            interface::SHELL_SCRIPT,
            interface::WALL_CLOCK,
            interface::CLOCK_CONTROL,
            interface::PROCESS_OBSERVE,
            interface::PROCESS_LAUNCH,
            interface::PIPE,
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
    fn shell_script_lines_are_exact_utf8_and_bounded() {
        let mut bytes = [0xa5_u8; shell_script::MAX_REQUEST_BYTES];
        let count = shell_script::encode_submit_line(7, "echo 'hello world'", &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let decoded = shell_script::decode_submit_line(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.number(), 7);
        assert_eq!(decoded.source(), "echo 'hello world'");
        for end in 0..count {
            assert!(shell_script::decode_submit_line(&bytes[..end]).is_err());
        }
        assert!(shell_script::decode_submit_line(&bytes[..=count]).is_err());
        assert!(shell_script::encode_submit_line(0, "echo", &mut bytes).is_err());
        assert!(shell_script::encode_submit_line(1, "", &mut bytes).is_err());
        assert!(shell_script::encode_submit_line(1, "echo\nnext", &mut bytes).is_err());
        assert!(
            shell_script::encode_submit_line(
                1,
                &"x".repeat(shell_script::MAX_LINE_BYTES + 1),
                &mut bytes,
            )
            .is_err()
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

        let mut environment_bytes = [0_u8; command::MAX_ENCODED_ENVIRONMENT_BYTES];
        let count =
            command::encode_environment(&["HOME=/vol/root", "PATH=/bin"], &mut environment_bytes)
                .unwrap_or_else(|_| std::process::abort());
        let environment = command::Environment::parse(&environment_bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            environment.iter().collect::<std::vec::Vec<_>>(),
            ["HOME=/vol/root", "PATH=/bin"]
        );
        assert!(command::encode_environment(&["BAD"], &mut environment_bytes).is_err());
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
    fn stream_requests_have_exact_bounds_and_chunk_policy() {
        assert!(stream::encode_read_request(0).is_err());
        let maximum = stream::encode_read_request(super::MAX_SERVICE_PAYLOAD_BYTES)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            stream::decode_read_request(&maximum),
            Ok(super::MAX_SERVICE_PAYLOAD_BYTES)
        );
        assert!(stream::encode_read_request(super::MAX_SERVICE_PAYLOAD_BYTES + 1).is_err());
        assert!(stream::decode_read_request(&[1]).is_err());
        for bytes in [stream::MIN_CHUNK_SIZE, stream::MAX_CHUNK_SIZE] {
            let encoded =
                stream::encode_chunk_size(bytes).unwrap_or_else(|_| std::process::abort());
            assert_eq!(stream::decode_chunk_size(&encoded), Ok(bytes));
        }
        assert!(stream::encode_chunk_size(stream::MIN_CHUNK_SIZE / 2).is_err());
        assert!(stream::encode_chunk_size(3 * stream::MIN_CHUNK_SIZE / 2).is_err());
        assert!(stream::encode_chunk_size(2 * stream::MAX_CHUNK_SIZE).is_err());
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
            filesystem::DirectoryEntry {
                kind: filesystem::NodeKind::Symlink,
                name: "motd-link",
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

        let mut link = [0_u8; filesystem::MAX_LINK_BYTES];
        let count = filesystem::encode_link_reply("../target", &mut link)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem::decode_link_reply(&link[..count]),
            Ok("../target")
        );
        assert!(filesystem::decode_link_reply(b"").is_err());
        assert!(filesystem::decode_link_reply(b"bad\0target").is_err());
    }

    #[test]
    fn filesystem_mutation_is_sequential_streamed_and_exact() {
        assert_eq!(filesystem_mutation::MAJOR, 1);
        assert_eq!(filesystem_mutation::MINOR, 2);
        assert_eq!(filesystem::MAJOR, 1);
        assert_eq!(filesystem::MINOR, 3);
        let token = filesystem_mutation::encode_token(7).unwrap_or_else(|_| std::process::abort());
        assert_eq!(filesystem_mutation::decode_token(&token), Ok(7));
        assert!(filesystem_mutation::decode_token(&[7, 0, 0, 0, 0]).is_err());
        assert!(filesystem_mutation::encode_token(0).is_err());

        let mut bytes = [0_u8; super::MAX_SERVICE_PAYLOAD_BYTES];
        let large_offset = u64::from(u32::MAX) + 9;
        let count = filesystem_mutation::encode_append_request(7, large_offset, b"end", &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let append = filesystem_mutation::decode_append_request(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(append.token, 7);
        assert_eq!(append.offset, large_offset);
        assert_eq!(append.bytes, b"end");
        let configured = filesystem_mutation::encode_chunk_size_request(7, 1024 * 1024)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem_mutation::decode_chunk_size_request(&configured),
            Ok((7, 1024 * 1024))
        );

        let mut unchanged = [0xa5_u8; 8];
        assert!(filesystem_mutation::encode_append_request(0, 0, b"x", &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; 8]);

        let mut link_bytes = [0_u8; filesystem_mutation::MAX_LINK_REQUEST_BYTES];
        let count = filesystem_mutation::encode_link_request(
            "../target",
            "/vol/root/link",
            &mut link_bytes,
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem_mutation::decode_link_request(&link_bytes[..count]),
            Ok(filesystem_mutation::LinkRequest {
                target: "../target",
                link_path: "/vol/root/link",
            })
        );
        assert!(filesystem_mutation::decode_link_request(&link_bytes[..count - 1]).is_err());
        let count = filesystem_mutation::encode_two_path_request(
            "/vol/root/old",
            "/vol/root/new",
            &mut link_bytes,
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem_mutation::decode_two_path_request(&link_bytes[..count]),
            Ok(filesystem_mutation::TwoPathRequest {
                source: "/vol/root/old",
                destination: "/vol/root/new",
            })
        );
        assert!(filesystem_mutation::decode_two_path_request(&link_bytes[..count - 1]).is_err());
        let mut unchanged = [0xa5_u8; 7];
        assert!(
            filesystem_mutation::encode_link_request("target", "link", &mut unchanged).is_err()
        );
        assert_eq!(unchanged, [0xa5; 7]);
        assert!(reply::is_known(reply::NOT_EMPTY));
        assert!(reply::is_known(reply::CROSS_DEVICE));
        assert!(!reply::is_known(reply::CROSS_DEVICE + 1));
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

    #[test]
    fn tcp_connect_records_are_exact_literal_and_bounded() {
        let encoded = tcp_connect::encode_connect_request([192, 0, 2, 1], 443)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            tcp_connect::decode_connect_request(&encoded),
            Ok(tcp_connect::ConnectRequest {
                destination: [192, 0, 2, 1],
                destination_port: 443,
            })
        );
        for end in 0..encoded.len() {
            assert!(tcp_connect::decode_connect_request(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(tcp_connect::decode_connect_request(&trailing).is_err());
        let mut reserved = encoded;
        reserved[7] = 1;
        assert!(tcp_connect::decode_connect_request(&reserved).is_err());

        for address in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
            assert!(tcp_connect::encode_connect_request(address, 80).is_err());
        }
        assert!(tcp_connect::encode_connect_request([192, 0, 2, 1], 0).is_err());
        assert_eq!(
            tcp_connect::decode_connect_reply(
                &tcp_connect::encode_connect_reply(49_152)
                    .unwrap_or_else(|_| std::process::abort())
            ),
            Ok(49_152)
        );
        assert!(tcp_connect::decode_connect_reply(&[0, 0]).is_err());

        let maximum = [0xa5_u8; tcp_connect::MAX_WRITE_BYTES];
        assert_eq!(
            tcp_connect::decode_write_request(&maximum)
                .unwrap_or_else(|_| std::process::abort())
                .len(),
            tcp_connect::MAX_WRITE_BYTES
        );
        assert!(tcp_connect::decode_write_request(&[]).is_err());
        let oversize = [0_u8; tcp_connect::MAX_WRITE_BYTES + 1];
        assert!(tcp_connect::decode_write_request(&oversize).is_err());

        let read = tcp_connect::encode_read_request(tcp_connect::MAX_READ_BYTES)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            tcp_connect::decode_read_request(&read),
            Ok(tcp_connect::MAX_READ_BYTES)
        );
        assert!(tcp_connect::decode_read_request(&[1]).is_err());
        assert!(tcp_connect::encode_read_request(0).is_err());
    }

    #[test]
    fn timer_values_are_exact() {
        let encoded = timer::encode_milliseconds(u64::MAX);
        assert_eq!(timer::decode_milliseconds(&encoded), Ok(u64::MAX));
        assert!(timer::decode_milliseconds(&encoded[..7]).is_err());

        let cpu = timer::ProcessCpuTime {
            ticks: u64::MAX,
            frequency_hz: 1_000_000_000,
        };
        let encoded = timer::encode_process_cpu_time(cpu).unwrap_or_else(|_| unreachable!());
        assert_eq!(timer::decode_process_cpu_time(&encoded), Ok(cpu));
        assert!(timer::decode_process_cpu_time(&encoded[..15]).is_err());
        assert!(
            timer::encode_process_cpu_time(timer::ProcessCpuTime {
                ticks: 1,
                frequency_hz: 0,
            })
            .is_err()
        );
    }

    #[test]
    fn volume_control_records_are_canonical_and_bounded() {
        let entries = [
            volume_control::VolumeInfo {
                name: "archive",
                filesystem: volume_control::Filesystem::Ext4V1,
                access: volume_control::Access::ReadOnly,
                activation: volume_control::Activation::Manual,
                state: volume_control::State::Ready,
            },
            volume_control::VolumeInfo {
                name: "root",
                filesystem: volume_control::Filesystem::Ext4V1,
                access: volume_control::Access::ReadWrite,
                activation: volume_control::Activation::Auto,
                state: volume_control::State::Mounted,
            },
        ];
        let mut bytes = [0_u8; volume_control::MAX_LIST_REPLY_BYTES];
        let count = volume_control::encode_list(&entries, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let decoded =
            volume_control::decode_list(&bytes[..count]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.iter().collect::<std::vec::Vec<_>>(), entries);
        assert!(volume_control::decode_list(&bytes[..count - 1]).is_err());

        let mut request = [0_u8; volume_control::MAX_ACTIVATE_REQUEST_BYTES];
        let request_bytes = volume_control::encode_activate_request("archive", &mut request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            volume_control::decode_activate_request(&request[..request_bytes]),
            Ok("archive")
        );
        assert!(volume_control::decode_activate_request(b"\x04bad/").is_err());
    }

    #[test]
    fn diagnostics_snapshot_is_fixed_typed_and_canonical() {
        let snapshot = diagnostics::Snapshot {
            architecture: diagnostics::Architecture::Aarch64,
            memory_owner: diagnostics::MemoryOwner::Kernel,
            pressure: diagnostics::Pressure::Normal,
            machine_memory: Some(diagnostics::MachineMemory {
                usable_bytes: 1024,
                reserved_bytes: 512,
                total_frames: 4,
                free_frames: 3,
                heap_total_bytes: 256,
                heap_used_bytes: 64,
                heap_high_water_bytes: 96,
                failed_allocations: 0,
            }),
            input: Some(diagnostics::InputQueue {
                queued: 1,
                capacity: 32,
                interrupts: 7,
                delivered: 6,
                dropped: 0,
                idle_waits: 4,
                wakeups: 2,
            }),
            ramfs_used_bytes: 11,
            ramfs_limit_bytes: 64,
            ramfs_high_water_bytes: 12,
            caches_used_bytes: 0,
            caches_limit_bytes: 0,
        };
        let bytes =
            diagnostics::encode_snapshot(snapshot).unwrap_or_else(|_| std::process::abort());
        assert_eq!(diagnostics::decode_snapshot(&bytes), Ok(snapshot));
        assert!(diagnostics::decode_snapshot(&bytes[..bytes.len() - 1]).is_err());

        let mut unknown_flag = bytes;
        unknown_flag[3] |= 0x80;
        assert!(diagnostics::decode_snapshot(&unknown_flag).is_err());

        let mut absent_nonzero = bytes;
        absent_nonzero[3] &= !1;
        assert!(diagnostics::decode_snapshot(&absent_nonzero).is_err());

        let invalid = diagnostics::Snapshot {
            ramfs_used_bytes: 65,
            ..snapshot
        };
        assert!(diagnostics::encode_snapshot(invalid).is_err());
    }

    #[test]
    fn process_snapshot_is_fixed_bounded_and_hides_arguments() {
        let process = process_observation::Process {
            id: 42,
            task_id: 7,
            started_millis: 100,
            cpu_ticks: 12_000,
            resident_pages: 21,
            table_pages: 9,
            private_pages: 12,
            dispatches: 4,
            yields: 1,
            preemptions: 2,
            handles: 6,
            state: process_observation::State::Running,
            origin: process_observation::Origin::Foreground,
            name: process_observation::ProcessName::new("top")
                .unwrap_or_else(|_| std::process::abort()),
        };
        let snapshot = process_observation::Snapshot::new(200, 1_000_000, &[process])
            .unwrap_or_else(|_| std::process::abort());
        let bytes = process_observation::encode_snapshot(snapshot)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bytes.len(), process_observation::SNAPSHOT_BYTES);
        let decoded =
            process_observation::decode_snapshot(&bytes).unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.observed_millis(), 200);
        assert_eq!(decoded.counter_frequency_hz(), 1_000_000);
        assert_eq!(decoded.processes(), &[process]);
        assert_eq!(decoded.processes()[0].name.as_str(), "top");

        let mut invalid_tail = bytes;
        invalid_tail[process_observation::SNAPSHOT_BYTES - 1] = 1;
        assert!(process_observation::decode_snapshot(&invalid_tail).is_err());
        let mut invalid_state = bytes;
        invalid_state[process_observation::HEADER_BYTES + 70] = 0;
        assert!(process_observation::decode_snapshot(&invalid_state).is_err());
        assert!(process_observation::ProcessName::new("").is_err());
        assert!(
            process_observation::ProcessName::new("123456789012345678901234567890123").is_err()
        );

        let page = process_observation::Page::new(200, 1_000_000, 42, 65_536, &[process])
            .unwrap_or_else(|_| std::process::abort());
        let page_bytes =
            process_observation::encode_page(page).unwrap_or_else(|_| std::process::abort());
        let decoded =
            process_observation::decode_page(&page_bytes).unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.next_cursor(), 42);
        assert_eq!(decoded.total_processes(), 65_536);
        assert_eq!(decoded.processes(), &[process]);
        assert_eq!(
            process_observation::decode_page_request(&process_observation::encode_page_request(
                u64::MAX
            )),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn process_launch_records_are_canonical_owner_scoped_and_full_status() {
        let mut invocation = [0_u8; command::MAX_INVOCATION_BYTES];
        let invocation_bytes = command::encode("/work", &["status", "203"], &mut invocation)
            .unwrap_or_else(|_| std::process::abort());
        let pipe_token =
            pipe::PipeToken::new(0x0000_0001_0000_0001).unwrap_or_else(|_| std::process::abort());
        let pipe_stream = process_launch::StreamSpec::pipe(pipe_token.value())
            .unwrap_or_else(|_| std::process::abort());
        let mut spawn = [0xa5_u8; process_launch::MAX_SPAWN_BYTES];
        let count = process_launch::encode_spawn(
            &invocation[..invocation_bytes],
            &["LANG=C", "PATH=/bin"],
            process_launch::StreamSpec::NULL,
            pipe_stream,
            process_launch::StreamSpec::INHERIT,
            &mut spawn,
        )
        .unwrap_or_else(|_| std::process::abort());
        let decoded =
            process_launch::decode_spawn(&spawn[..count]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.invocation().cwd(), "/work");
        assert_eq!(
            decoded
                .invocation()
                .arguments()
                .collect::<std::vec::Vec<_>>(),
            ["status", "203"]
        );
        assert_eq!(
            decoded.environment().collect::<std::vec::Vec<_>>(),
            ["LANG=C", "PATH=/bin"]
        );
        assert_eq!(decoded.stdout(), pipe_stream);
        assert!(process_launch::decode_spawn(&spawn[..count - 1]).is_err());
        assert!(
            process_launch::encode_spawn(
                &invocation[..invocation_bytes],
                &["9BAD=value"],
                process_launch::StreamSpec::NULL,
                pipe_stream,
                process_launch::StreamSpec::INHERIT,
                &mut spawn,
            )
            .is_err()
        );

        let token = process_launch::ChildToken::new(0x0000_0002_0000_0001)
            .unwrap_or_else(|_| std::process::abort());
        let status = process_launch::ChildStatus {
            token,
            process_id: u64::MAX,
            exit_status: u32::MAX,
            state: process_launch::ChildState::Exited,
        };
        let encoded =
            process_launch::encode_status(status).unwrap_or_else(|_| std::process::abort());
        assert_eq!(process_launch::decode_status(&encoded), Ok(status));
    }

    #[test]
    fn pipe_records_are_exact_and_bounded() {
        let token =
            pipe::PipeToken::new(0x0000_0001_0000_0001).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            pipe::decode_create(
                &pipe::encode_create(pipe::MAX_CAPACITY).unwrap_or_else(|_| std::process::abort())
            ),
            Ok(pipe::MAX_CAPACITY)
        );
        let mut write = [0_u8; 32];
        let count = pipe::encode_write(token, b"stream", &mut write)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            pipe::decode_write(&write[..count]),
            Ok((token, &b"stream"[..]))
        );
        assert_eq!(
            pipe::decode_read(
                &pipe::encode_read(token, pipe::MAX_IO_BYTES)
                    .unwrap_or_else(|_| std::process::abort())
            ),
            Ok((token, pipe::MAX_IO_BYTES))
        );
        assert!(pipe::decode_token(&[0; pipe::TOKEN_BYTES]).is_err());
    }

    #[test]
    fn network_observation_records_are_exact_and_bounded() {
        let configured_link = network_observation::Status {
            mac: [2, 0, 0, 0, 0, 1],
            configuration: Some(network_observation::Ipv4Configuration {
                address: [10, 0, 2, 15],
                subnet_mask: [255, 255, 255, 0],
                gateway: [10, 0, 2, 2],
                lease_seconds: Some(86_400),
            }),
        };
        let encoded = network_observation::encode_status(configured_link)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            network_observation::decode_status(&encoded),
            Ok(configured_link)
        );
        assert!(network_observation::decode_status(&encoded[..23]).is_err());

        let counters = network_observation::Stats {
            received_frames: 1,
            transmitted_frames: 2,
            arp_replies: 3,
            icmp_replies: 4,
            udp_retained: 5,
            udp_unbound: 6,
            udp_dropped: 7,
            arp_entries: 8,
            udp_ports: 8,
            checkpoints: 9,
            errors: 10,
        };
        let encoded =
            network_observation::encode_stats(counters).unwrap_or_else(|_| std::process::abort());
        assert_eq!(network_observation::decode_stats(&encoded), Ok(counters));

        let entries = [
            network_observation::Neighbor {
                address: [10, 0, 2, 2],
                mac: [0x52, 0x55, 0x0a, 0, 2, 2],
            },
            network_observation::Neighbor {
                address: [10, 0, 2, 3],
                mac: [0x52, 0x55, 0x0a, 0, 2, 3],
            },
        ];
        let neighbors = network_observation::Neighbors::from_slice(&entries)
            .unwrap_or_else(|_| std::process::abort());
        let mut bytes = [0_u8; network_observation::MAX_NEIGHBOR_REPLY_BYTES];
        let count = network_observation::encode_neighbors(neighbors, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let decoded = network_observation::decode_neighbors(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.iter().collect::<std::vec::Vec<_>>(), entries);
        assert!(network_observation::decode_neighbors(&bytes[..count - 1]).is_err());
        assert!(network_observation::Neighbors::from_slice(&[entries[0], entries[0]]).is_err());
    }

    #[test]
    fn icmp_echo_records_are_exact() {
        let destination = [192, 0, 2, 1];
        assert_eq!(
            icmp_echo::decode_request(&icmp_echo::encode_request(destination)),
            Ok(destination)
        );
        let reply = icmp_echo::Reply {
            source: destination,
            sequence: u16::MAX,
            bytes: 9,
        };
        assert_eq!(
            icmp_echo::decode_reply(&icmp_echo::encode_reply(reply)),
            Ok(reply)
        );
        assert!(icmp_echo::decode_request(&destination[..3]).is_err());
    }

    #[test]
    fn isolated_server_transport_is_exact_bounded_and_canonical() {
        let mut receive = [0_u8; MAX_MESSAGE_BYTES];
        let receive_bytes = server::encode_received_request(
            0x0000_0007_0000_0003,
            interface::DIAGNOSTICS,
            diagnostics::GET_SNAPSHOT,
            diagnostics::SNAPSHOT_BYTES,
            b"copied request",
            &mut receive,
        )
        .unwrap_or_else(|_| std::process::abort());
        let decoded = server::decode_received_request(&receive[..receive_bytes])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.token(), 0x0000_0007_0000_0003);
        assert_eq!(decoded.interface(), interface::DIAGNOSTICS);
        assert_eq!(decoded.opcode(), diagnostics::GET_SNAPSHOT);
        assert_eq!(decoded.reply_capacity(), diagnostics::SNAPSHOT_BYTES);
        assert_eq!(decoded.payload(), b"copied request");
        for end in 0..receive_bytes {
            assert!(server::decode_received_request(&receive[..end]).is_err());
        }
        let mut noncanonical = receive[..receive_bytes].to_vec();
        noncanonical[18] = 1;
        assert!(server::decode_received_request(&noncanonical).is_err());

        let mut completion = [0_u8; super::MAX_SERVICE_PAYLOAD_BYTES];
        let completion_bytes = server::encode_reply_request(
            decoded.token(),
            reply::SUCCESS,
            b"copied reply",
            &mut completion,
        )
        .unwrap_or_else(|_| std::process::abort());
        let completion = server::decode_reply_request(&completion[..completion_bytes])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(completion.token(), decoded.token());
        assert_eq!(completion.status(), reply::SUCCESS);
        assert_eq!(completion.payload(), b"copied reply");

        let mut unchanged = [0xa5_u8; 8];
        assert!(server::encode_received_request(0, 1, 1, 0, &[], &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; 8]);
        assert!(server::encode_reply_request(1, u32::MAX, &[], &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; 8]);
    }
}

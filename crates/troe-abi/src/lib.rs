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
    use super::{MAX_MESSAGE_BYTES, command, datagram, interface, requirements, stream};

    #[test]
    fn interface_registry_is_unique_and_nonzero() {
        let interfaces = [
            interface::COMMAND,
            interface::STANDARD_INPUT,
            interface::STANDARD_OUTPUT,
            interface::STANDARD_ERROR,
            interface::DATAGRAM,
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

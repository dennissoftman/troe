//! Owner-scoped bounded byte-pipe protocol.

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

#[cfg(test)]
mod tests {
    use crate::pipe;

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
}

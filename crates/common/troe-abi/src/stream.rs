//! Byte-stream protocols.

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

#[cfg(test)]
mod tests {
    use crate::stream;

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
}

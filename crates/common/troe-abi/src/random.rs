//! Capability-scoped kernel CSPRNG protocol.

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Fill one bounded reply with fresh CSPRNG bytes.
pub const GET: u16 = 1;
/// Exact request size.
pub const REQUEST_BYTES: usize = 8;
/// Maximum bytes returned by one call. Larger reads stream in user space.
pub const MAX_BYTES: u64 = 4096;

/// Invalid request or noncanonical count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Encode one nonzero bounded byte count.
///
/// # Errors
///
/// Rejects zero or a value above [`MAX_BYTES`].
pub fn encode_request(byte_count: u64) -> Result<[u8; REQUEST_BYTES], EncodingError> {
    if byte_count == 0 || byte_count > MAX_BYTES {
        return Err(EncodingError);
    }
    Ok(byte_count.to_le_bytes())
}

/// Decode one exact nonzero bounded byte count.
///
/// # Errors
///
/// Rejects truncation, trailing bytes, zero, or a value above [`MAX_BYTES`].
pub fn decode_request(bytes: &[u8]) -> Result<u64, EncodingError> {
    let bytes: [u8; REQUEST_BYTES] = bytes.try_into().map_err(|_| EncodingError)?;
    let byte_count = u64::from_le_bytes(bytes);
    if byte_count == 0 || byte_count > MAX_BYTES {
        return Err(EncodingError);
    }
    Ok(byte_count)
}

#[cfg(test)]
mod tests {
    use crate::random;

    #[test]
    fn random_request_is_exact_bounded_and_full_width() {
        let encoded =
            random::encode_request(random::MAX_BYTES).unwrap_or_else(|_| std::process::abort());
        assert_eq!(random::decode_request(&encoded), Ok(random::MAX_BYTES));
        assert!(random::decode_request(&encoded[..7]).is_err());
        assert!(random::decode_request(&[0; 8]).is_err());
        assert!(random::encode_request(random::MAX_BYTES + 1).is_err());
    }
}

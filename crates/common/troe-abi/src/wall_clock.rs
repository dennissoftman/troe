//! Kernel-maintained Unix wall-clock protocol.

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

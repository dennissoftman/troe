//! Kernel-maintained Unix wall-clock protocol.

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
///
/// Raised for `NOW_PRECISE`.
pub const MINOR: u16 = 1;
/// Read whole Unix seconds at the current monotonic instant.
pub const NOW: u16 = 1;
/// Read Unix seconds and their nanosecond remainder at one monotonic
/// instant.
pub const NOW_PRECISE: u16 = 2;
/// Exact Unix timestamp bytes.
pub const SECONDS_BYTES: usize = 8;
/// Exact precise-timestamp bytes.
pub const PRECISE_BYTES: usize = 16;

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

/// Nanoseconds in one second; a remainder is always below this.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// One Unix instant split the way `timespec` splits it.
///
/// The remainder is always below one second, so a consumer assigns the two
/// fields straight into `tv_sec` and `tv_nsec` without arithmetic. A single
/// nanosecond count would be simpler and wrong: `u64` nanoseconds since the
/// epoch stop in 2554, while the seconds field alone is accepted out to 9999.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WallTime {
    /// Whole Unix seconds.
    pub seconds: u64,
    /// Nanoseconds elapsed since that second, below `NANOS_PER_SECOND`.
    pub nanoseconds: u64,
}

/// Encode one precise Unix instant.
///
/// # Errors
///
/// Rejects a remainder of one second or more, which would name an instant the
/// seconds field already names.
pub fn encode_precise(value: WallTime) -> Result<[u8; PRECISE_BYTES], EncodingError> {
    if value.nanoseconds >= NANOS_PER_SECOND {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; PRECISE_BYTES];
    bytes[..8].copy_from_slice(&value.seconds.to_le_bytes());
    bytes[8..].copy_from_slice(&value.nanoseconds.to_le_bytes());
    Ok(bytes)
}

/// Decode one exact precise Unix instant.
///
/// # Errors
///
/// Rejects the wrong length and any remainder of one second or more.
pub fn decode_precise(bytes: &[u8]) -> Result<WallTime, EncodingError> {
    if bytes.len() != PRECISE_BYTES {
        return Err(EncodingError);
    }
    let value = WallTime {
        seconds: u64::from_le_bytes(bytes[..8].try_into().map_err(|_| EncodingError)?),
        nanoseconds: u64::from_le_bytes(bytes[8..].try_into().map_err(|_| EncodingError)?),
    };
    if value.nanoseconds >= NANOS_PER_SECOND {
        return Err(EncodingError);
    }
    Ok(value)
}

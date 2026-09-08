//! Privileged kernel wall-clock correction protocol.

pub use super::wall_clock::{
    EncodingError, NANOS_PER_SECOND, PRECISE_BYTES, SECONDS_BYTES, WallTime, decode_precise,
    decode_seconds, encode_precise, encode_seconds,
};

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
///
/// Raised for `SET_PRECISE`.
pub const MINOR: u16 = 1;
/// Replace the wall-clock anchor with one Unix timestamp.
pub const SET: u16 = 1;
/// Replace it with one instant carrying a nanosecond remainder.
///
/// Without this, a source that knows the sub-second phase, such as the NTP
/// transmit timestamp `timesync` receives, has nowhere to put it and the
/// remainder stays whatever the boot anchor happened to start at.
pub const SET_PRECISE: u16 = 2;

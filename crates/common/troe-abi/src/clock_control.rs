//! Privileged kernel wall-clock correction protocol.

pub use super::wall_clock::{EncodingError, SECONDS_BYTES, decode_seconds, encode_seconds};

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Replace the wall-clock anchor with one Unix timestamp.
pub const SET: u16 = 1;

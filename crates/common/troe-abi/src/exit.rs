//! Stable command exit values understood by the recovery shell.

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

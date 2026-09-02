//! Stable results returned by ABI `grow_heap` (call 3).

/// The requested pages were committed and the returned byte length is current.
pub const SUCCESS: u32 = 0;
/// The per-application resident limit or system frame pool is exhausted.
pub const EXHAUSTED: u32 = 1;

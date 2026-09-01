//! Stable service reply values returned by ABI `handle_call`.

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
/// A path or namespace request is syntactically invalid.
pub const INVALID_PATH: u32 = 10;
/// A file was used as a directory or the reverse.
pub const WRONG_TYPE: u32 = 11;
/// Mutation targeted immutable filesystem content.
pub const READ_ONLY: u32 = 12;
/// A filesystem byte, node, or file-size quota is exhausted.
pub const NO_SPACE: u32 = 13;
/// A filesystem object already exists.
pub const EXISTS: u32 = 14;
/// Filesystem metadata is corrupt.
pub const CORRUPT: u32 = 15;
/// The filesystem transport failed.
pub const IO: u32 = 16;
/// The filesystem requires an unsupported feature.
pub const UNSUPPORTED: u32 = 17;
/// Filesystem size or offset arithmetic overflowed.
pub const OVERFLOW: u32 = 18;
/// A network exchange returned an invalid protocol response.
pub const NETWORK_PROTOCOL: u32 = 19;
/// The caller lacks authority for the requested operation.
pub const DENIED: u32 = 20;
/// A directory still contains entries.
pub const NOT_EMPTY: u32 = 21;
/// A name operation crossed filesystem-provider boundaries.
pub const CROSS_DEVICE: u32 = 22;
/// An explicit configured resource policy rejected the request.
pub const RESOURCE_LIMIT: u32 = 23;

/// Whether a scalar is one defined service reply value.
#[must_use]
pub const fn is_known(value: u32) -> bool {
    value <= RESOURCE_LIMIT
}

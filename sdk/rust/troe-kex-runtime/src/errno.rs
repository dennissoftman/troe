//! Stable POSIX-style error numbers for compatibility layers.

use troe_kex_sdk::Error as KexError;

use crate::{Error as RuntimeError, environment, process};

/// Operation not permitted.
pub const EPERM: i32 = 1;
/// No such file or directory.
pub const ENOENT: i32 = 2;
/// Input/output error.
pub const EIO: i32 = 5;
/// Argument list is too long.
pub const E2BIG: i32 = 7;
/// Not enough memory.
pub const ENOMEM: i32 = 12;
/// Permission denied.
pub const EACCES: i32 = 13;
/// Resource busy.
pub const EBUSY: i32 = 16;
/// File exists.
pub const EEXIST: i32 = 17;
/// Cross-device operation.
pub const EXDEV: i32 = 18;
/// Not a directory.
pub const ENOTDIR: i32 = 20;
/// Is a directory.
pub const EISDIR: i32 = 21;
/// Invalid argument.
pub const EINVAL: i32 = 22;
/// File too large.
pub const EFBIG: i32 = 27;
/// No space left on device.
pub const ENOSPC: i32 = 28;
/// Read-only filesystem.
pub const EROFS: i32 = 30;
/// Function is not implemented.
pub const ENOSYS: i32 = 38;
/// Directory not empty.
pub const ENOTEMPTY: i32 = 39;
/// Value cannot be represented.
pub const EOVERFLOW: i32 = 75;
/// Operation is not supported.
pub const ENOTSUP: i32 = 95;
/// Operation timed out.
pub const ETIMEDOUT: i32 = 110;
/// Operation was cancelled.
pub const ECANCELED: i32 = 125;

/// Convert one typed KEX failure to the stable compatibility error profile.
#[must_use]
pub const fn from_kex(error: KexError) -> i32 {
    match error {
        KexError::NotFound => ENOENT,
        KexError::Exhausted | KexError::ResourceLimit => ENOMEM,
        KexError::Denied | KexError::MissingAuthority => EACCES,
        KexError::Conflict => EBUSY,
        KexError::TooLarge => EFBIG,
        KexError::Cancelled => ECANCELED,
        KexError::Timeout => ETIMEDOUT,
        KexError::WrongType => EISDIR,
        KexError::ReadOnly => EROFS,
        KexError::NoSpace => ENOSPC,
        KexError::Exists => EEXIST,
        KexError::Io | KexError::Corrupt | KexError::Failure => EIO,
        KexError::Unsupported | KexError::UnsupportedTarget => ENOTSUP,
        KexError::Overflow => EOVERFLOW,
        KexError::NotEmpty => ENOTEMPTY,
        KexError::CrossDevice => EXDEV,
        KexError::InvalidCall
        | KexError::InvalidRequest
        | KexError::NotConfigured
        | KexError::InvalidInvocation
        | KexError::InvalidPath
        | KexError::NetworkProtocol => EINVAL,
    }
}

/// Convert a higher-level filesystem runtime failure.
#[must_use]
pub const fn from_runtime(error: RuntimeError) -> i32 {
    match error {
        RuntimeError::Service(error) => from_kex(error),
        RuntimeError::InvalidPath => EINVAL,
        RuntimeError::MetadataExhausted => ENOMEM,
    }
}

/// Convert a direct-process runtime failure.
#[must_use]
pub const fn from_process(error: process::Error) -> i32 {
    match error {
        process::Error::LimitExceeded => E2BIG,
        process::Error::Service(error) => from_kex(error),
        process::Error::InvalidCommand
        | process::Error::UnclosedQuote
        | process::Error::TrailingEscape
        | process::Error::ShellSyntax => EINVAL,
    }
}

/// Convert an immutable-environment construction failure.
#[must_use]
pub const fn from_environment(error: environment::Error) -> i32 {
    match error {
        environment::Error::InvalidValue => EINVAL,
        environment::Error::TooManyEntries => E2BIG,
    }
}

#[cfg(test)]
mod tests {
    use super::{E2BIG, ENOTEMPTY, EXDEV, from_kex, from_process};
    use crate::process;
    use troe_kex_sdk::Error as KexError;

    #[test]
    fn stable_specific_failures_remain_distinct() {
        assert_eq!(from_kex(KexError::NotEmpty), ENOTEMPTY);
        assert_eq!(from_kex(KexError::CrossDevice), EXDEV);
        assert_eq!(from_process(process::Error::LimitExceeded), E2BIG);
    }
}

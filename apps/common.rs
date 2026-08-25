#![allow(dead_code)]

use troe_kex_sdk::{Error, StandardOutput, exit};

pub const COMMAND_BYTES: u64 = 64 * 1024;

pub fn report(stderr: &mut StandardOutput, command: &str, message: &[u8]) {
    let _ignored = stderr.write_all(command.as_bytes());
    let _ignored = stderr.write_all(b": ");
    let _ignored = stderr.write_all(message);
    let _ignored = stderr.write_all(b"\n");
}

pub fn report_path(stderr: &mut StandardOutput, command: &str, path: &str, message: &[u8]) {
    let _ignored = stderr.write_all(command.as_bytes());
    let _ignored = stderr.write_all(b": ");
    let _ignored = stderr.write_all(path.as_bytes());
    let _ignored = stderr.write_all(b": ");
    let _ignored = stderr.write_all(message);
    let _ignored = stderr.write_all(b"\n");
}

pub fn usage(stderr: &mut StandardOutput, command: &str, synopsis: &[u8]) -> u32 {
    report(stderr, command, synopsis);
    exit::USAGE
}

pub fn stream_failure(stderr: &mut StandardOutput, command: &str) -> u32 {
    report(stderr, command, b"stream I/O failed");
    exit::FAILURE
}

pub fn filesystem_failure(
    stderr: &mut StandardOutput,
    command: &str,
    path: &str,
    error: Error,
) -> u32 {
    report_path(stderr, command, path, filesystem_message(error));
    if error == Error::NotFound {
        exit::NOT_FOUND
    } else {
        exit::FAILURE
    }
}

pub const fn filesystem_message(error: Error) -> &'static [u8] {
    match error {
        Error::InvalidPath => b"invalid path or filesystem image",
        Error::NotFound => b"not found",
        Error::WrongType => b"wrong node type",
        Error::ReadOnly => b"read-only filesystem",
        Error::NoSpace => b"filesystem quota exceeded",
        Error::Overflow => b"filesystem size overflow",
        Error::Exists => b"already exists",
        Error::Corrupt => b"filesystem metadata is corrupt",
        Error::Io => b"filesystem transport failed",
        Error::Unsupported => b"filesystem feature is unsupported",
        Error::Exhausted => b"bounded filesystem resources exhausted",
        _ => b"filesystem service failed",
    }
}

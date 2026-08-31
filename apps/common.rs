#![allow(dead_code)]

use core::fmt::{self, Write as _};
use core::str;
use troe_kex_sdk::{Error, MAX_ARGUMENT_BYTES, StandardOutput, exit, network_observation};

/// Owned copy of one command argument.
///
/// The paged argument reader owns a single page buffer, so an argument read
/// from one page stops being borrowable as soon as another page is loaded.
/// A command that must hold one operand while streaming the rest -- `cp` and
/// `mv` holding their destination -- copies it here first.
pub struct ArgumentBuffer {
    bytes: [u8; MAX_ARGUMENT_BYTES],
    len: usize,
}

impl ArgumentBuffer {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_ARGUMENT_BYTES],
            len: 0,
        }
    }

    /// Retain one argument, rejecting anything past the single-argument bound.
    pub fn set(&mut self, value: &str) -> Result<(), ()> {
        if value.len() > self.bytes.len() {
            return Err(());
        }
        self.bytes[..value.len()].copy_from_slice(value.as_bytes());
        self.len = value.len();
        Ok(())
    }

    /// Borrow the retained argument.
    pub fn as_str(&self) -> &str {
        str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl Default for ArgumentBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Compose `directory/name` into one owned target path.
pub fn join_into(target: &mut ArgumentBuffer, directory: &str, name: &str) -> Result<(), ()> {
    let mut joined = [0_u8; MAX_ARGUMENT_BYTES];
    let trimmed = if directory == "/" {
        ""
    } else {
        directory.trim_end_matches('/')
    };
    let total = trimmed.len() + 1 + name.len();
    if total > joined.len() {
        return Err(());
    }
    joined[..trimmed.len()].copy_from_slice(trimmed.as_bytes());
    joined[trimmed.len()] = b'/';
    joined[trimmed.len() + 1..total].copy_from_slice(name.as_bytes());
    let value = str::from_utf8(&joined[..total]).map_err(|_| ())?;
    target.set(value)
}

/// Final path component used as the name inside a destination directory.
///
/// Returns `None` for a source whose base name cannot name a new child.
pub fn base_name(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches('/');
    let name = match trimmed.rsplit_once('/') {
        Some((_, name)) => name,
        None => trimmed,
    };
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    Some(name)
}

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

/// Report one failed stream operation, separating cooperative cancellation.
///
/// A foreground read of the session terminal blocks until input arrives, so
/// Ctrl-C is an ordinary outcome rather than a transport failure.
pub fn stream_read_failure(stderr: &mut StandardOutput, command: &str, error: Error) -> u32 {
    if error == Error::Cancelled {
        report(stderr, command, b"cancelled");
        return exit::CANCELLED;
    }
    stream_failure(stderr, command)
}

pub struct OutputWriter<'output>(pub &'output mut StandardOutput);

impl fmt::Write for OutputWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut parts = text.split('.');
    let address = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    if parts.next().is_some() {
        None
    } else {
        Some(address)
    }
}

pub fn write_ipv4(output: &mut impl fmt::Write, address: [u8; 4]) -> fmt::Result {
    write!(
        output,
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    )
}

pub fn write_network_status(
    output: &mut StandardOutput,
    status: network_observation::Status,
) -> Result<(), fmt::Error> {
    let mut output = OutputWriter(output);
    write!(
        output,
        "link: ready\nmac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\nipv4: ",
        status.mac[0], status.mac[1], status.mac[2], status.mac[3], status.mac[4], status.mac[5]
    )?;
    let Some(configuration) = status.configuration else {
        return output.write_str(
            "unconfigured\nsubnet: unconfigured\ngateway: unconfigured\nlease: unconfigured\n",
        );
    };
    write_ipv4(&mut output, configuration.address)?;
    output.write_str("\nsubnet: ")?;
    write_ipv4(&mut output, configuration.subnet_mask)?;
    output.write_str("\ngateway: ")?;
    write_ipv4(&mut output, configuration.gateway)?;
    match configuration.lease_seconds {
        Some(seconds) => writeln!(output, "\nlease: {seconds} seconds"),
        None => output.write_str("\nlease: unconfigured\n"),
    }
}

pub fn network_failure(stderr: &mut StandardOutput, command: &str, error: Error) -> u32 {
    let (message, status) = match error {
        Error::NotFound => (b"no network device".as_slice(), exit::NOT_FOUND),
        Error::NotConfigured => (
            b"IPv4 is not configured; run dhcp".as_slice(),
            exit::FAILURE,
        ),
        Error::Timeout => (b"operation timed out".as_slice(), exit::FAILURE),
        Error::Failure => (b"network device failed".as_slice(), exit::FAILURE),
        Error::NetworkProtocol => (b"invalid network response".as_slice(), exit::FAILURE),
        Error::TooLarge => (b"packet exceeds network limit".as_slice(), exit::FAILURE),
        Error::Exhausted => (
            b"bounded network resources exhausted".as_slice(),
            exit::FAILURE,
        ),
        Error::Cancelled => (b"cancelled".as_slice(), exit::CANCELLED),
        _ => (b"network service failed".as_slice(), exit::FAILURE),
    };
    report(stderr, command, message);
    status
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
        Error::NoSpace | Error::TooLarge => b"filesystem quota exceeded",
        Error::Overflow => b"filesystem size overflow",
        Error::Exists => b"already exists",
        Error::Corrupt => b"filesystem metadata is corrupt",
        Error::Io => b"filesystem transport failed",
        Error::Unsupported => b"filesystem feature is unsupported",
        Error::NotConfigured => b"wall clock is not set; run timesync",
        Error::Exhausted => b"bounded filesystem resources exhausted",
        Error::NotEmpty => b"directory not empty",
        Error::CrossDevice => b"cross-device operation",
        _ => b"filesystem service failed",
    }
}

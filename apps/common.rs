#![allow(dead_code)]

use core::fmt::{self, Write as _};
use troe_kex_sdk::{Error, StandardOutput, exit, network_observation};

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
        Error::Exhausted => b"bounded filesystem resources exhausted",
        _ => b"filesystem service failed",
    }
}

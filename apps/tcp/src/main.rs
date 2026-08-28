#![no_std]
#![no_main]

use core::fmt::{self, Write as _};
use troe_kex_sdk::{
    CommandContext, Error, INVOCATION_BUFFER_BYTES, StandardOutput, command, entry, exit,
    tcp_connect,
};

const SYNOPSIS: &str = "tcp ADDRESS PORT [TEXT...]";

struct Writer(StandardOutput);

impl fmt::Write for Writer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0.write_all(text.as_bytes()).map_err(|_| fmt::Error)
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let Some(destination) = invocation.argument(1).and_then(parse_ipv4) else {
        return usage(command, SYNOPSIS);
    };
    let Some(destination_port) = invocation.argument(2).and_then(parse_port) else {
        return usage(command, SYNOPSIS);
    };

    let connect = match command.tcp_connect() {
        Ok(connect) => connect,
        Err(error) => return network_failure(command, error),
    };
    let mut connection = match connect.connect(destination, destination_port) {
        Ok(connection) => connection,
        Err(error) => return network_failure(command, error),
    };
    if invocation.len() > 3 {
        let mut payload = [0_u8; tcp_connect::MAX_WRITE_BYTES];
        let count = match join_arguments(invocation, 3, &mut payload) {
            Ok(count) => count,
            Err(()) => return usage(command, "text exceeds TCP write limit"),
        };
        if let Err(error) = connection.write_all(&payload[..count]) {
            return network_failure(command, error);
        }
    }

    let mut received = [0_u8; tcp_connect::MAX_READ_BYTES];
    let count = match connection.read(&mut received) {
        Ok(count) => count,
        Err(error) => return network_failure(command, error),
    };
    if command.stdout().write_all(&received[..count]).is_err() {
        return stream_failure(command);
    }
    if let Err(error) = connection.close() {
        return network_failure(command, error);
    }
    exit::SUCCESS
}

fn join_arguments(
    invocation: command::Invocation<'_>,
    first: usize,
    output: &mut [u8],
) -> Result<usize, ()> {
    let mut count = 0_usize;
    for index in first..invocation.len() {
        let argument = invocation.argument(index).ok_or(())?.as_bytes();
        let separator = usize::from(index != first);
        let next = count
            .checked_add(separator)
            .and_then(|value| value.checked_add(argument.len()))
            .ok_or(())?;
        if next > output.len() {
            return Err(());
        }
        if separator != 0 {
            output[count] = b' ';
            count += 1;
        }
        output[count..next].copy_from_slice(argument);
        count = next;
    }
    Ok(count)
}

fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut parts = text.split('.');
    let address = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(address)
}

fn parse_port(text: &str) -> Option<u16> {
    let port = text.parse().ok()?;
    (port != 0).then_some(port)
}

fn usage(command: &CommandContext, message: &str) -> u32 {
    let mut error = Writer(command.stderr());
    let _ignored = writeln!(error, "tcp: {message}");
    exit::USAGE
}

fn stream_failure(command: &CommandContext) -> u32 {
    let mut error = Writer(command.stderr());
    let _ignored = error.write_str("tcp: stream I/O failed\n");
    exit::FAILURE
}

fn network_failure(command: &CommandContext, failure: Error) -> u32 {
    let (message, status) = match failure {
        Error::MissingAuthority | Error::NotFound => ("no network device", exit::NOT_FOUND),
        Error::NotConfigured => ("IPv4 is not configured; run dhcp", exit::FAILURE),
        Error::Timeout => ("operation timed out", exit::FAILURE),
        Error::Exhausted | Error::ResourceLimit | Error::Conflict => {
            ("bounded TCP resources exhausted", exit::FAILURE)
        }
        Error::Cancelled => ("cancelled", exit::CANCELLED),
        Error::Denied => ("permission denied", exit::DENIED),
        Error::Failure => ("connection closed or reset", exit::FAILURE),
        Error::InvalidCall
        | Error::InvalidRequest
        | Error::InvalidInvocation
        | Error::TooLarge
        | Error::InvalidPath
        | Error::WrongType
        | Error::ReadOnly
        | Error::NoSpace
        | Error::Exists
        | Error::Corrupt
        | Error::Io
        | Error::Unsupported
        | Error::Overflow
        | Error::NetworkProtocol => ("invalid network response", exit::FAILURE),
        Error::UnsupportedTarget => ("unsupported application target", exit::FAILURE),
        Error::NotEmpty => ("directory not empty", exit::FAILURE),
        Error::CrossDevice => ("cross-device operation", exit::FAILURE),
    };
    let mut error = Writer(command.stderr());
    let _ignored = writeln!(error, "tcp: {message}");
    status
}

entry!(main);

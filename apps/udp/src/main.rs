#![no_std]
#![no_main]

use core::fmt::{self, Write as _};
use troe_kex_sdk::{
    CommandContext, DATAGRAM_BUFFER_BYTES, Error, INVOCATION_BUFFER_BYTES, StandardInput,
    StandardOutput, command, datagram, entry, exit,
};

const SYNOPSIS: &str = "udp send [--source-port PORT] ADDRESS PORT [TEXT...] | udp listen PORT";

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
    match invocation.argument(1) {
        Some("send") => send(command, invocation),
        Some("listen" | "recv") => receive(command, invocation),
        _ => usage(command, SYNOPSIS),
    }
}

fn send(command: &CommandContext, invocation: command::Invocation<'_>) -> u32 {
    let (source_port, address_index) = if invocation.argument(2) == Some("--source-port") {
        let Some(port) = invocation.argument(3).and_then(parse_port) else {
            return usage(command, "invalid UDP source port");
        };
        (Some(port), 4)
    } else {
        (None, 2)
    };
    let Some(destination_text) = invocation.argument(address_index) else {
        return usage(command, "missing IPv4 address");
    };
    let Some(destination) = parse_ipv4(destination_text) else {
        return usage(command, "invalid IPv4 address");
    };
    let Some(destination_port) = invocation.argument(address_index + 1).and_then(parse_port) else {
        return usage(command, "invalid UDP port");
    };

    let mut payload = [0_u8; datagram::MAX_PAYLOAD_BYTES];
    let payload_index = address_index + 2;
    let payload_bytes = if invocation.len() > payload_index {
        match join_arguments(invocation, payload_index, &mut payload) {
            Ok(count) => count,
            Err(()) => return usage(command, "packet exceeds network limit"),
        }
    } else {
        let mut input = command.stdin();
        match read_payload(&mut input, &mut payload) {
            Ok(count) => count,
            Err(()) => return stream_failure(command),
        }
    };

    let mut network = match command.datagram() {
        Ok(network) => network,
        Err(error) => return network_failure(command, error),
    };
    let source_port = match network.send(
        source_port,
        destination,
        destination_port,
        &payload[..payload_bytes],
    ) {
        Ok(port) => port,
        Err(error) => return network_failure(command, error),
    };
    let mut output = Writer(command.stdout());
    if writeln!(
        output,
        "sent {payload_bytes} bytes from port {source_port} to {}.{}.{}.{}:{destination_port}",
        destination[0], destination[1], destination[2], destination[3]
    )
    .is_err()
    {
        return stream_failure(command);
    }
    exit::SUCCESS
}

fn receive(command: &CommandContext, invocation: command::Invocation<'_>) -> u32 {
    if invocation.len() != 3 {
        return usage(command, SYNOPSIS);
    }
    let Some(local_port) = invocation.argument(2).and_then(parse_port) else {
        return usage(command, "invalid UDP port");
    };
    let mut network = match command.datagram() {
        Ok(network) => network,
        Err(error) => return network_failure(command, error),
    };
    let mut bytes = [0_u8; DATAGRAM_BUFFER_BYTES];
    let received = match network.receive(local_port, &mut bytes) {
        Ok(received) => received,
        Err(error) => return network_failure(command, error),
    };
    let mut output = Writer(command.stdout());
    if writeln!(
        output,
        "from {}.{}.{}.{}:{} bytes={}",
        received.source[0],
        received.source[1],
        received.source[2],
        received.source[3],
        received.source_port,
        received.payload.len()
    )
    .is_err()
        || output.0.write_all(received.payload).is_err()
        || output.0.write_all(b"\n").is_err()
    {
        return stream_failure(command);
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

fn read_payload(input: &mut StandardInput, output: &mut [u8]) -> Result<usize, ()> {
    let mut count = 0_usize;
    while count < output.len() {
        let read = input.read(&mut output[count..]).map_err(|_| ())?;
        if read == 0 {
            return Ok(count);
        }
        count = count.checked_add(read).ok_or(())?;
    }
    let mut excess = [0_u8; 1];
    if input.read(&mut excess).map_err(|_| ())? == 0 {
        Ok(count)
    } else {
        Err(())
    }
}

fn usage(command: &CommandContext, message: &str) -> u32 {
    let mut error = Writer(command.stderr());
    let _ignored = writeln!(error, "udp: {message}");
    exit::USAGE
}

fn stream_failure(command: &CommandContext) -> u32 {
    let mut error = Writer(command.stderr());
    let _ignored = error.write_str("udp: stream I/O failed\n");
    exit::FAILURE
}

fn network_failure(command: &CommandContext, failure: Error) -> u32 {
    let (message, status) = match failure {
        Error::MissingAuthority => ("no network device", exit::NOT_FOUND),
        Error::NotConfigured => ("IPv4 is not configured; run dhcp", exit::FAILURE),
        Error::Timeout => ("operation timed out", exit::FAILURE),
        Error::TooLarge => ("packet exceeds network limit", exit::FAILURE),
        Error::Exhausted | Error::Conflict => {
            ("bounded network resources exhausted", exit::FAILURE)
        }
        Error::Cancelled => ("cancelled", exit::CANCELLED),
        Error::Denied => ("permission denied", exit::DENIED),
        Error::Failure | Error::NotFound => ("network device failed", exit::FAILURE),
        Error::InvalidCall
        | Error::InvalidRequest
        | Error::InvalidInvocation
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
    let _ignored = writeln!(error, "udp: {message}");
    status
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

entry!(main);

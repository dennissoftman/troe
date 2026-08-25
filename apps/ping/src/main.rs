#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt::Write as _;
use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let Some(address) = invocation.argument(1) else {
        return common::usage(&mut command.stderr(), "ping", b"ping ADDRESS");
    };
    if invocation.len() != 2 {
        return common::usage(&mut command.stderr(), "ping", b"ping ADDRESS");
    }
    let Some(destination) = common::parse_ipv4(address) else {
        return common::usage(&mut command.stderr(), "ping", b"invalid IPv4 address");
    };
    let Ok(mut icmp) = command.icmp_echo() else {
        return exit::DENIED;
    };
    let reply = match icmp.echo(destination) {
        Ok(reply) => reply,
        Err(error) => return common::network_failure(&mut command.stderr(), "ping", error),
    };
    let result = {
        let mut stdout = command.stdout();
        let mut output = common::OutputWriter(&mut stdout);
        output
            .write_str("reply from ")
            .and_then(|()| common::write_ipv4(&mut output, reply.source))
            .and_then(|()| {
                writeln!(
                    output,
                    ": icmp_seq={} bytes={}",
                    reply.sequence, reply.bytes
                )
            })
    };
    if result.is_err() {
        common::stream_failure(&mut command.stderr(), "ping")
    } else {
        exit::SUCCESS
    }
}

entry!(main);

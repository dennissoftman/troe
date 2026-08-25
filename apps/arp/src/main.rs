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
    if invocation.len() != 1 {
        return common::usage(&mut command.stderr(), "arp", b"arp");
    }
    let Ok(mut network) = command.network_observation() else {
        return exit::DENIED;
    };
    let neighbors = match network.neighbors() {
        Ok(neighbors) => neighbors,
        Err(error) => return common::network_failure(&mut command.stderr(), "arp", error),
    };
    if neighbors.is_empty() {
        return if command.stdout().write_all(b"ARP cache empty\n").is_err() {
            common::stream_failure(&mut command.stderr(), "arp")
        } else {
            exit::SUCCESS
        };
    }
    let result = {
        let mut stdout = command.stdout();
        let mut output = common::OutputWriter(&mut stdout);
        neighbors.iter().try_for_each(|entry| {
            common::write_ipv4(&mut output, entry.address)?;
            writeln!(
                output,
                " {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                entry.mac[0], entry.mac[1], entry.mac[2], entry.mac[3], entry.mac[4], entry.mac[5]
            )
        })
    };
    if result.is_err() {
        common::stream_failure(&mut command.stderr(), "arp")
    } else {
        exit::SUCCESS
    }
}

entry!(main);

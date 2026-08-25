#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() != 1 {
        return common::usage(&mut command.stderr(), "dhcp", b"dhcp");
    }
    let Ok(mut network) = command.network_configuration() else {
        return exit::DENIED;
    };
    let status = match network.dhcp() {
        Ok(status) => status,
        Err(error) => return common::network_failure(&mut command.stderr(), "dhcp", error),
    };
    if common::write_network_status(&mut command.stdout(), status).is_err() {
        common::stream_failure(&mut command.stderr(), "net")
    } else {
        exit::SUCCESS
    }
}

entry!(main);

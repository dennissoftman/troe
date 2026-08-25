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
    let Some(path) = invocation.argument(1) else {
        return common::usage(&mut command.stderr(), "rm", b"rm FILE");
    };
    if invocation.len() != 2 {
        return common::usage(&mut command.stderr(), "rm", b"rm FILE");
    }
    let Ok(mut mutation) = command.filesystem_mutation() else {
        return exit::DENIED;
    };
    match mutation.remove(path) {
        Ok(()) => exit::SUCCESS,
        Err(error) => common::filesystem_failure(&mut command.stderr(), "rm", path, error),
    }
}

entry!(main);

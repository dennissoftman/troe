#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_app_printf::{PrintError, render};
use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let Some(format) = invocation.argument(1) else {
        return common::usage(&mut command.stderr(), "printf", b"printf FORMAT [ARG...]");
    };
    let mut output = command.stdout();
    match render(format, invocation.arguments().skip(2), |bytes| {
        output.write_all(bytes)
    }) {
        Ok(()) => exit::SUCCESS,
        Err(PrintError::InvalidFormat) => {
            common::report(&mut command.stderr(), "printf", b"invalid format");
            exit::USAGE
        }
        Err(PrintError::InvalidNumber) => {
            common::report(&mut command.stderr(), "printf", b"invalid number");
            exit::USAGE
        }
        Err(PrintError::Output(_)) => common::stream_failure(&mut command.stderr(), "printf"),
    }
}

entry!(main);

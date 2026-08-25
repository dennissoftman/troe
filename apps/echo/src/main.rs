#![no_std]
#![no_main]

use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let mut output = command.stdout();
    for index in 1..invocation.len() {
        if index != 1 && output.write_all(b" ").is_err() {
            return exit::FAILURE;
        }
        let Some(argument) = invocation.argument(index) else {
            return exit::FAILURE;
        };
        if output.write_all(argument.as_bytes()).is_err() {
            return exit::FAILURE;
        }
    }
    if output.write_all(b"\n").is_err() {
        return exit::FAILURE;
    }
    exit::SUCCESS
}

entry!(main);

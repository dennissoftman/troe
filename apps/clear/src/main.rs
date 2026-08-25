#![no_std]
#![no_main]

use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, StandardOutput, entry, exit};

fn report(stderr: &mut StandardOutput, message: &[u8]) {
    let _ignored = stderr.write_all(b"clear: ");
    let _ignored = stderr.write_all(message);
    let _ignored = stderr.write_all(b"\n");
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() != 1 {
        report(&mut command.stderr(), b"clear");
        return exit::USAGE;
    }
    if command.stdout().write_all(b"\x1b[2J\x1b[H").is_err() {
        report(&mut command.stderr(), b"stream I/O failed");
        return exit::FAILURE;
    }
    exit::SUCCESS
}

entry!(main);

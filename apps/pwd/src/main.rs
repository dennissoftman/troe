#![no_std]
#![no_main]

use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, StandardOutput, entry, exit};

fn report(stderr: &mut StandardOutput, message: &[u8]) {
    let _ignored = stderr.write_all(b"pwd: ");
    let _ignored = stderr.write_all(message);
    let _ignored = stderr.write_all(b"\n");
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() != 1 {
        report(&mut command.stderr(), b"pwd");
        return exit::USAGE;
    }
    let mut output = command.stdout();
    if output.write_all(invocation.cwd().as_bytes()).is_err() || output.write_all(b"\n").is_err() {
        report(&mut command.stderr(), b"stream I/O failed");
        return exit::FAILURE;
    }
    exit::SUCCESS
}

entry!(main);

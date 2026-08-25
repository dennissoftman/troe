#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, Error, INVOCATION_BUFFER_BYTES, entry, exit};

fn mutation_failure(command: &mut CommandContext, path: &str, error: Error) -> u32 {
    common::filesystem_failure(&mut command.stderr(), "write", path, error)
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let Some(path) = invocation.argument(1) else {
        return common::usage(&mut command.stderr(), "write", b"write FILE [TEXT...]");
    };
    let Ok(mut mutation) = command.filesystem_mutation() else {
        return exit::DENIED;
    };
    let mut replacement = match mutation.begin_replace(path) {
        Ok(replacement) => replacement,
        Err(error) => return mutation_failure(command, path, error),
    };

    if invocation.len() > 2 {
        for index in 2..invocation.len() {
            if index > 2
                && let Err(error) = replacement.write_all(b" ")
            {
                let _ignored = replacement.abort();
                return mutation_failure(command, path, error);
            }
            let Some(argument) = invocation.argument(index) else {
                let _ignored = replacement.abort();
                return exit::FAILURE;
            };
            if let Err(error) = replacement.write_all(argument.as_bytes()) {
                let _ignored = replacement.abort();
                return mutation_failure(command, path, error);
            }
        }
    } else {
        let mut input = command.stdin();
        let mut bytes = [0_u8; 512];
        loop {
            let count = match input.read(&mut bytes) {
                Ok(count) => count,
                Err(_) => {
                    let _ignored = replacement.abort();
                    return common::stream_failure(&mut command.stderr(), "write");
                }
            };
            if count == 0 {
                break;
            }
            if let Err(error) = replacement.write_all(&bytes[..count]) {
                let _ignored = replacement.abort();
                return mutation_failure(command, path, error);
            }
        }
    }

    match replacement.commit() {
        Ok(()) => exit::SUCCESS,
        Err(error) => mutation_failure(command, path, error),
    }
}

entry!(main);

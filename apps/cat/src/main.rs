#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, Error, INVOCATION_BUFFER_BYTES, entry, exit};

fn copy_input(command: &mut CommandContext) -> u32 {
    let mut input = command.stdin();
    let mut output = command.stdout();
    let mut buffer = [0_u8; 512];
    loop {
        let Ok(count) = input.read(&mut buffer) else {
            return common::stream_failure(&mut command.stderr(), "cat");
        };
        if count == 0 {
            return exit::SUCCESS;
        }
        if output.write_all(&buffer[..count]).is_err() {
            return common::stream_failure(&mut command.stderr(), "cat");
        }
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() == 1 {
        return copy_input(command);
    }
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    let mut output = command.stdout();
    for index in 1..invocation.len() {
        let Some(path) = invocation.argument(index) else {
            return exit::FAILURE;
        };
        let file = match filesystem.open(path) {
            Ok(file) if file.byte_count <= common::COMMAND_BYTES => file,
            Ok(file) => {
                let _ignored = filesystem.close(file);
                return common::filesystem_failure(
                    &mut command.stderr(),
                    "cat",
                    path,
                    Error::NoSpace,
                );
            }
            Err(error) => {
                return common::filesystem_failure(&mut command.stderr(), "cat", path, error);
            }
        };
        let mut offset = 0_u64;
        let mut buffer = [0_u8; 512];
        while offset < file.byte_count {
            let count = match filesystem.read(file, offset, &mut buffer) {
                Ok(0) => {
                    let _ignored = filesystem.close(file);
                    return common::filesystem_failure(
                        &mut command.stderr(),
                        "cat",
                        path,
                        Error::Corrupt,
                    );
                }
                Ok(count) => count,
                Err(error) => {
                    let _ignored = filesystem.close(file);
                    return common::filesystem_failure(&mut command.stderr(), "cat", path, error);
                }
            };
            if output.write_all(&buffer[..count]).is_err() {
                let _ignored = filesystem.close(file);
                common::report(&mut command.stderr(), "cat", b"output failed");
                return exit::FAILURE;
            }
            let Ok(count) = u64::try_from(count) else {
                return exit::FAILURE;
            };
            let Some(next) = offset.checked_add(count) else {
                return exit::FAILURE;
            };
            if next > file.byte_count {
                return exit::FAILURE;
            }
            offset = next;
        }
        if filesystem.close(file).is_err() {
            return common::filesystem_failure(&mut command.stderr(), "cat", path, Error::Corrupt);
        }
    }
    exit::SUCCESS
}

entry!(main);

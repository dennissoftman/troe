#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::str;

use troe_kex_sdk::{CommandContext, Error, INVOCATION_BUFFER_BYTES, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() != 2 {
        return common::usage(&mut command.stderr(), "man", b"man COMMAND");
    }
    let Some(name) = invocation.argument(1) else {
        return exit::FAILURE;
    };
    if !valid_command_name(name) {
        common::report(&mut command.stderr(), "man", b"no manual entry for command");
        return exit::NOT_FOUND;
    }
    let mut path_bytes = [0_u8; 70];
    path_bytes[..5].copy_from_slice(b"/man/");
    let Some(end) = 5_usize.checked_add(name.len()) else {
        return exit::FAILURE;
    };
    if end > path_bytes.len() {
        return exit::FAILURE;
    }
    path_bytes[5..end].copy_from_slice(name.as_bytes());
    let Ok(path) = str::from_utf8(&path_bytes[..end]) else {
        return exit::FAILURE;
    };
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    let file = match filesystem.open(path) {
        Ok(file) if file.byte_count <= common::COMMAND_BYTES => file,
        Ok(file) => {
            let _ignored = filesystem.close(file);
            return common::filesystem_failure(&mut command.stderr(), "man", path, Error::NoSpace);
        }
        Err(Error::NotFound) => {
            common::report(&mut command.stderr(), "man", b"no manual entry for command");
            return exit::NOT_FOUND;
        }
        Err(error) => {
            return common::filesystem_failure(&mut command.stderr(), "man", path, error);
        }
    };
    let mut output = command.stdout();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 512];
    while offset < file.byte_count {
        let count = match filesystem.read(file, offset, &mut buffer) {
            Ok(0) => {
                let _ignored = filesystem.close(file);
                return common::filesystem_failure(
                    &mut command.stderr(),
                    "man",
                    path,
                    Error::Corrupt,
                );
            }
            Ok(count) => count,
            Err(error) => {
                let _ignored = filesystem.close(file);
                return common::filesystem_failure(&mut command.stderr(), "man", path, error);
            }
        };
        if output.write_all(&buffer[..count]).is_err() {
            let _ignored = filesystem.close(file);
            return common::stream_failure(&mut command.stderr(), "man");
        }
        let Some(next) = offset.checked_add(count as u64) else {
            return exit::FAILURE;
        };
        offset = next;
    }
    if filesystem.close(file).is_err() {
        return common::filesystem_failure(&mut command.stderr(), "man", path, Error::Corrupt);
    }
    exit::SUCCESS
}

fn valid_command_name(name: &str) -> bool {
    !name.is_empty()
        && name.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

entry!(main);

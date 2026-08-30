#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, entry, exit};

const SYNOPSIS: &[u8] = b"rmdir DIRECTORY...";

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let Ok(total) = arguments.total() else {
        return exit::FAILURE;
    };
    if total < 2 {
        return common::usage(&mut command.stderr(), "rmdir", SYNOPSIS);
    }
    let Ok(mut mutation) = command.filesystem_mutation() else {
        return exit::DENIED;
    };
    if arguments.seek(1).is_err() {
        return exit::FAILURE;
    }
    // Every operand is attempted; a nonempty directory in an expansion is
    // reported and skipped rather than stopping the empty ones.
    let mut status = exit::SUCCESS;
    loop {
        let path = match arguments.next_argument() {
            Ok(Some(path)) => path,
            Ok(None) => break,
            Err(_) => return exit::FAILURE,
        };
        if let Err(error) = mutation.remove_directory(path) {
            let path_status =
                common::filesystem_failure(&mut command.stderr(), "rmdir", path, error);
            if status == exit::SUCCESS {
                status = path_status;
            }
        }
    }
    status
}

entry!(main);

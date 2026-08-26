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
    let (symbolic, Some(target), Some(link_path)) = (
        invocation.argument(1) == Some("-s"),
        invocation.argument(if invocation.argument(1) == Some("-s") {
            2
        } else {
            1
        }),
        invocation.argument(if invocation.argument(1) == Some("-s") {
            3
        } else {
            2
        }),
    ) else {
        return common::usage(&mut command.stderr(), "ln", b"ln [-s] TARGET LINK_NAME");
    };
    let expected_arguments = if symbolic { 4 } else { 3 };
    if invocation.len() != expected_arguments {
        return common::usage(&mut command.stderr(), "ln", b"ln [-s] TARGET LINK_NAME");
    }
    let Ok(mut mutation) = command.filesystem_mutation() else {
        return exit::DENIED;
    };
    let result = if symbolic {
        mutation.create_symlink(target, link_path)
    } else {
        mutation.create_hard_link(target, link_path)
    };
    match result {
        Ok(()) => exit::SUCCESS,
        Err(error) => common::filesystem_failure(&mut command.stderr(), "ln", link_path, error),
    }
}

entry!(main);

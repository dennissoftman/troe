#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_alloc::GlobalAllocator;
use troe_kex_runtime::Error as RuntimeError;
use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, entry, exit};

#[global_allocator]
static ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let (Some(source), Some(destination)) = (invocation.argument(1), invocation.argument(2)) else {
        return common::usage(&mut command.stderr(), "mv", b"mv SOURCE DEST");
    };
    if invocation.len() != 3 {
        return common::usage(&mut command.stderr(), "mv", b"mv SOURCE DEST");
    }
    let Some(heap) = command.take_heap() else {
        return exit::DENIED;
    };
    if ALLOCATOR.initialize(heap).is_err() {
        return exit::FAILURE;
    }
    let (Ok(mut filesystem), Ok(mut mutation)) =
        (command.filesystem(), command.filesystem_mutation())
    else {
        return exit::DENIED;
    };
    match troe_kex_runtime::move_path(&mut filesystem, &mut mutation, source, destination) {
        Ok(()) => exit::SUCCESS,
        Err(RuntimeError::Service(error)) => {
            common::filesystem_failure(&mut command.stderr(), "mv", source, error)
        }
        Err(_) => {
            common::report_path(&mut command.stderr(), "mv", source, b"invalid path");
            exit::FAILURE
        }
    }
}

entry!(main);

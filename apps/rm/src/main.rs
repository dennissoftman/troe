#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_alloc::GlobalAllocator;
use troe_kex_runtime::Error as RuntimeError;
use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, entry, exit};

#[global_allocator]
static ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

fn failure(command: &mut CommandContext, path: &str, error: RuntimeError) -> u32 {
    match error.service_error() {
        Some(error) => common::filesystem_failure(&mut command.stderr(), "rm", path, error),
        None => {
            let message = match error {
                RuntimeError::InvalidPath => b"invalid path".as_slice(),
                RuntimeError::MetadataExhausted => {
                    b"bounded traversal metadata exhausted".as_slice()
                }
                RuntimeError::Service(_) => b"filesystem service failed".as_slice(),
            };
            common::report_path(&mut command.stderr(), "rm", path, message);
            exit::FAILURE
        }
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let recursive = matches!(invocation.argument(1), Some("-r" | "-R"));
    let path_index = if recursive { 2 } else { 1 };
    let Some(path) = invocation.argument(path_index) else {
        return common::usage(&mut command.stderr(), "rm", b"rm [-r|-R] PATH");
    };
    if invocation.len() != path_index + 1 {
        return common::usage(&mut command.stderr(), "rm", b"rm [-r|-R] PATH");
    }
    if recursive {
        let Some(heap) = command.take_heap() else {
            return exit::DENIED;
        };
        if ALLOCATOR.initialize(heap).is_err() {
            return exit::FAILURE;
        }
    }
    let Ok(mut mutation) = command.filesystem_mutation() else {
        return exit::DENIED;
    };
    let result = if recursive {
        let Ok(mut filesystem) = command.filesystem() else {
            return exit::DENIED;
        };
        troe_kex_runtime::remove_recursive(&mut filesystem, &mut mutation, path)
    } else {
        mutation.remove(path).map_err(RuntimeError::from)
    };
    match result {
        Ok(()) => exit::SUCCESS,
        Err(error) => failure(command, path, error),
    }
}

entry!(main);

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
        Some(error) => common::filesystem_failure(&mut command.stderr(), "cp", path, error),
        None => {
            let message = match error {
                RuntimeError::InvalidPath => b"invalid path".as_slice(),
                RuntimeError::MetadataExhausted => {
                    b"bounded traversal metadata exhausted".as_slice()
                }
                RuntimeError::Service(_) => b"filesystem service failed".as_slice(),
            };
            common::report_path(&mut command.stderr(), "cp", path, message);
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
    let source_index = if recursive { 2 } else { 1 };
    let (Some(source), Some(destination)) = (
        invocation.argument(source_index),
        invocation.argument(source_index + 1),
    ) else {
        return common::usage(&mut command.stderr(), "cp", b"cp [-r|-R] SOURCE DEST");
    };
    if invocation.len() != source_index + 2 {
        return common::usage(&mut command.stderr(), "cp", b"cp [-r|-R] SOURCE DEST");
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
    let result = if recursive {
        troe_kex_runtime::copy_recursive(&mut filesystem, &mut mutation, source, destination)
    } else {
        troe_kex_runtime::copy(&mut filesystem, &mut mutation, source, destination)
    };
    match result {
        Ok(()) => exit::SUCCESS,
        Err(error) => failure(command, source, error),
    }
}

entry!(main);

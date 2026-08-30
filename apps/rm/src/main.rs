#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_alloc::GlobalAllocator;
use troe_kex_runtime::Error as RuntimeError;
use troe_kex_sdk::{ArgumentReader, CommandContext, entry, exit};

#[global_allocator]
static ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

const SYNOPSIS: &[u8] = b"rm [-r|-R] PATH...";

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

/// Locate the first operand, accepting `-r`/`-R` and `--` before it.
///
/// Returns the operand index and whether recursive removal was requested.
fn parse_flags(arguments: &mut ArgumentReader) -> Result<(usize, bool), ()> {
    let mut recursive = false;
    let mut index = 1_usize;
    loop {
        let Ok(Some(argument)) = arguments.get(index) else {
            return Ok((index, recursive));
        };
        match argument {
            "-r" | "-R" => recursive = true,
            "--" => return Ok((index + 1, recursive)),
            value if value.starts_with('-') && value.len() > 1 => return Err(()),
            _ => return Ok((index, recursive)),
        }
        index += 1;
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let (Ok(total), Ok((operand_start, recursive))) =
        (arguments.total(), parse_flags(&mut arguments))
    else {
        return common::usage(&mut command.stderr(), "rm", SYNOPSIS);
    };
    if operand_start >= total {
        return common::usage(&mut command.stderr(), "rm", SYNOPSIS);
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
    let mut filesystem = if recursive {
        let Ok(filesystem) = command.filesystem() else {
            return exit::DENIED;
        };
        Some(filesystem)
    } else {
        None
    };

    // Every operand is attempted so that one missing name in an expansion does
    // not hide the removals the operator asked for.
    let mut status = exit::SUCCESS;
    if arguments.seek(operand_start).is_err() {
        return exit::FAILURE;
    }
    loop {
        let path = match arguments.next_argument() {
            Ok(Some(path)) => path,
            Ok(None) => break,
            Err(_) => return exit::FAILURE,
        };
        let result = match filesystem.as_mut() {
            Some(filesystem) => troe_kex_runtime::remove_recursive(filesystem, &mut mutation, path),
            None => mutation.remove(path).map_err(RuntimeError::from),
        };
        if let Err(error) = result {
            let path_status = failure(command, path, error);
            if status == exit::SUCCESS {
                status = path_status;
            }
        }
    }
    status
}

entry!(main);

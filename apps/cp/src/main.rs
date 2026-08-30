#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use common::ArgumentBuffer;
use troe_kex_alloc::GlobalAllocator;
use troe_kex_runtime::Error as RuntimeError;
use troe_kex_sdk::{ArgumentReader, CommandContext, Error, entry, exit, filesystem::NodeKind};

#[global_allocator]
static ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

const SYNOPSIS: &[u8] = b"cp [-r|-R] SOURCE DEST | cp [-r|-R] SOURCE... DIRECTORY";

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

/// Locate the first operand, accepting `-r`/`-R` and `--` before it.
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
        return common::usage(&mut command.stderr(), "cp", SYNOPSIS);
    };
    // One destination plus at least one source.
    if total < operand_start + 2 {
        return common::usage(&mut command.stderr(), "cp", SYNOPSIS);
    }
    let destination_index = total - 1;
    let mut destination = ArgumentBuffer::new();
    let Ok(Some(value)) = arguments.get(destination_index) else {
        return exit::FAILURE;
    };
    if destination.set(value).is_err() {
        return common::usage(&mut command.stderr(), "cp", SYNOPSIS);
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

    // The destination is classified once, before any mutation. More than one
    // source requires an existing directory, which is what stops several
    // sources from being copied over each other into one file.
    let into_directory = match filesystem.metadata(destination.as_str()) {
        Ok(metadata) => metadata.kind == NodeKind::Directory,
        Err(Error::NotFound) => false,
        Err(error) => {
            return common::filesystem_failure(
                &mut command.stderr(),
                "cp",
                destination.as_str(),
                error,
            );
        }
    };
    let sources = destination_index - operand_start;
    if sources > 1 && !into_directory {
        common::report_path(
            &mut command.stderr(),
            "cp",
            destination.as_str(),
            b"destination for several sources must be an existing directory",
        );
        return exit::USAGE;
    }

    if arguments.seek(operand_start).is_err() {
        return exit::FAILURE;
    }
    let mut status = exit::SUCCESS;
    let mut target = ArgumentBuffer::new();
    for _ in 0..sources {
        let source = match arguments.next_argument() {
            Ok(Some(source)) => source,
            Ok(None) => break,
            Err(_) => return exit::FAILURE,
        };
        let mut source_path = ArgumentBuffer::new();
        if source_path.set(source).is_err() {
            return exit::FAILURE;
        }
        if into_directory {
            let Some(name) = common::base_name(source_path.as_str()) else {
                common::report_path(
                    &mut command.stderr(),
                    "cp",
                    source_path.as_str(),
                    b"source has no copyable name",
                );
                status = exit::USAGE;
                continue;
            };
            if common::join_into(&mut target, destination.as_str(), name).is_err() {
                common::report_path(
                    &mut command.stderr(),
                    "cp",
                    source_path.as_str(),
                    b"destination path exceeds the path limit",
                );
                status = exit::FAILURE;
                continue;
            }
        } else if target.set(destination.as_str()).is_err() {
            return exit::FAILURE;
        }
        let result = if recursive {
            troe_kex_runtime::copy_recursive(
                &mut filesystem,
                &mut mutation,
                source_path.as_str(),
                target.as_str(),
            )
        } else {
            troe_kex_runtime::copy(
                &mut filesystem,
                &mut mutation,
                source_path.as_str(),
                target.as_str(),
            )
        };
        if let Err(error) = result {
            let source_status = failure(command, source_path.as_str(), error);
            if status == exit::SUCCESS {
                status = source_status;
            }
        }
    }
    status
}

entry!(main);

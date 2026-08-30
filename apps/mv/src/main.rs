#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use common::ArgumentBuffer;
use troe_kex_alloc::GlobalAllocator;
use troe_kex_runtime::Error as RuntimeError;
use troe_kex_sdk::{CommandContext, Error, entry, exit, filesystem::NodeKind};

#[global_allocator]
static ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

const SYNOPSIS: &[u8] = b"mv SOURCE DEST | mv SOURCE... DIRECTORY";

fn failure(command: &mut CommandContext, path: &str, error: RuntimeError) -> u32 {
    match error {
        RuntimeError::Service(error) => {
            common::filesystem_failure(&mut command.stderr(), "mv", path, error)
        }
        _ => {
            common::report_path(&mut command.stderr(), "mv", path, b"invalid path");
            exit::FAILURE
        }
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let Ok(total) = arguments.total() else {
        return exit::FAILURE;
    };
    let operand_start = if matches!(arguments.get(1), Ok(Some("--"))) {
        2
    } else {
        1
    };
    if total < operand_start + 2 {
        return common::usage(&mut command.stderr(), "mv", SYNOPSIS);
    }
    let destination_index = total - 1;
    let mut destination = ArgumentBuffer::new();
    let Ok(Some(value)) = arguments.get(destination_index) else {
        return exit::FAILURE;
    };
    if destination.set(value).is_err() {
        return common::usage(&mut command.stderr(), "mv", SYNOPSIS);
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

    // The destination is classified once, before any move. More than one source
    // requires an existing directory, so several sources can never be moved
    // over each other into one file.
    let into_directory = match filesystem.metadata(destination.as_str()) {
        Ok(metadata) => metadata.kind == NodeKind::Directory,
        Err(Error::NotFound) => false,
        Err(error) => {
            return common::filesystem_failure(
                &mut command.stderr(),
                "mv",
                destination.as_str(),
                error,
            );
        }
    };
    let sources = destination_index - operand_start;
    if sources > 1 && !into_directory {
        common::report_path(
            &mut command.stderr(),
            "mv",
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
                    "mv",
                    source_path.as_str(),
                    b"source has no movable name",
                );
                status = exit::USAGE;
                continue;
            };
            if common::join_into(&mut target, destination.as_str(), name).is_err() {
                common::report_path(
                    &mut command.stderr(),
                    "mv",
                    source_path.as_str(),
                    b"destination path exceeds the path limit",
                );
                status = exit::FAILURE;
                continue;
            }
        } else if target.set(destination.as_str()).is_err() {
            return exit::FAILURE;
        }
        if let Err(error) = troe_kex_runtime::move_path(
            &mut filesystem,
            &mut mutation,
            source_path.as_str(),
            target.as_str(),
        ) {
            let source_status = failure(command, source_path.as_str(), error);
            if status == exit::SUCCESS {
                status = source_status;
            }
        }
    }
    status
}

entry!(main);

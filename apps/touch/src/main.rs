#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, Error, FilesystemMutation, ReadOnlyFilesystem, entry, exit};

const SYNOPSIS: &[u8] = b"touch [-c] [-d SECONDS] FILE...";

#[derive(Clone, Copy, Default)]
struct Options {
    /// Do not create a file that does not exist.
    no_create: bool,
    /// Explicit instant, or the wall clock's own when absent.
    unix_seconds: Option<u64>,
}

/// Create one empty file without disturbing an existing one.
///
/// A replacement truncates its destination immediately, so an existing file is
/// never opened for replacement: its time is set in place instead.
fn create_empty(mutation: &mut FilesystemMutation, path: &str) -> Result<(), Error> {
    mutation.begin_replace(path)?.commit()
}

/// Stamp one operand, creating it when it does not exist and `-c` is absent.
fn touch(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    path: &str,
    options: Options,
) -> Result<(), Error> {
    match filesystem.metadata(path) {
        // A directory records a modification time like any other object, so
        // existence is all this needs to distinguish. A provider that records no
        // time at all reports success: the file exists, which is what `touch`
        // was asked for, and no filesystem anywhere refuses `touch` for this
        // reason. A clock that is merely unset is a different, transient
        // condition and is still reported.
        Ok(_) => match mutation.set_modified_time(path, options.unix_seconds) {
            Err(Error::Unsupported) => Ok(()),
            outcome => outcome,
        },
        Err(Error::NotFound) if options.no_create => Ok(()),
        Err(Error::NotFound) => {
            create_empty(mutation, path)?;
            // Creation already stamps the current instant, so an implicit time
            // needs no second write. An explicit one still has to be applied.
            match options.unix_seconds {
                None => Ok(()),
                Some(_) => match mutation.set_modified_time(path, options.unix_seconds) {
                    Err(Error::Unsupported) => Ok(()),
                    outcome => outcome,
                },
            }
        }
        Err(error) => Err(error),
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let Ok(total) = arguments.total() else {
        return exit::FAILURE;
    };
    let mut options = Options::default();
    let mut index = 1;
    let mut operand_start = total;
    // The paged reader lends one argument at a time, so an option that takes a
    // separate value copies both before inspecting either.
    let mut current = common::ArgumentBuffer::new();
    let mut value = common::ArgumentBuffer::new();
    while index < total {
        match arguments.get(index) {
            Ok(Some(argument)) => {
                if current.set(argument).is_err() {
                    return exit::FAILURE;
                }
            }
            _ => return exit::FAILURE,
        }
        let argument = current.as_str();
        if argument == "--" {
            operand_start = index + 1;
            break;
        }
        if !argument.starts_with('-') || argument.len() == 1 {
            operand_start = index;
            break;
        }
        let mut position = 1;
        let mut wants_value = false;
        while position < argument.len() {
            match argument.as_bytes()[position] {
                b'c' => options.no_create = true,
                // `-m` selects the modification time, which is the only time
                // this ABI records, so it is accepted and redundant.
                b'm' => {}
                b'd' => {
                    let attached = argument.get(position + 1..).unwrap_or("");
                    if attached.is_empty() {
                        wants_value = true;
                    } else {
                        let Ok(seconds) = attached.parse() else {
                            return common::usage(&mut command.stderr(), "touch", SYNOPSIS);
                        };
                        options.unix_seconds = Some(seconds);
                    }
                    position = argument.len();
                    continue;
                }
                _ => return common::usage(&mut command.stderr(), "touch", SYNOPSIS),
            }
            position += 1;
        }
        if wants_value {
            index += 1;
            match arguments.get(index) {
                Ok(Some(text)) => {
                    if value.set(text).is_err() {
                        return exit::FAILURE;
                    }
                }
                _ => return common::usage(&mut command.stderr(), "touch", SYNOPSIS),
            }
            let Ok(seconds) = value.as_str().parse() else {
                return common::usage(&mut command.stderr(), "touch", SYNOPSIS);
            };
            options.unix_seconds = Some(seconds);
        }
        index += 1;
    }
    if operand_start >= total {
        return common::usage(&mut command.stderr(), "touch", SYNOPSIS);
    }
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    let Ok(mut mutation) = command.filesystem_mutation() else {
        return exit::DENIED;
    };
    if arguments.seek(operand_start).is_err() {
        return exit::FAILURE;
    }
    // Every operand is attempted; one refusal does not abandon the rest.
    let mut status = exit::SUCCESS;
    loop {
        let path = match arguments.next_argument() {
            Ok(Some(path)) => path,
            Ok(None) => break,
            Err(_) => return exit::FAILURE,
        };
        if let Err(error) = touch(&mut filesystem, &mut mutation, path, options) {
            common::report_path(
                &mut command.stderr(),
                "touch",
                path,
                common::filesystem_message(error),
            );
            if status == exit::SUCCESS {
                status = if error == Error::NotFound {
                    exit::NOT_FOUND
                } else {
                    exit::FAILURE
                };
            }
        }
    }
    status
}

entry!(main);

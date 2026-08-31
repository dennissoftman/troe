#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{
    CommandContext, Error, FilesystemMutation, ReadOnlyFilesystem, StandardOutput, entry, exit,
    filesystem,
};

const SYNOPSIS: &[u8] = b"mkdir [-pv] DIRECTORY...";

#[derive(Clone, Copy, Default)]
struct Options {
    parents: bool,
    verbose: bool,
}

fn report_created(output: &mut StandardOutput, path: &str) -> Result<(), ()> {
    output
        .write_all(b"mkdir: created directory '")
        .map_err(|_| ())?;
    output.write_all(path.as_bytes()).map_err(|_| ())?;
    output.write_all(b"'\n").map_err(|_| ())
}

/// Create one directory, reporting it when `-v` is in force.
fn create(
    mutation: &mut FilesystemMutation,
    output: &mut StandardOutput,
    path: &str,
    verbose: bool,
) -> Result<(), Error> {
    mutation.create_directory(path)?;
    if verbose && report_created(output, path).is_err() {
        return Err(Error::Io);
    }
    Ok(())
}

/// Leave one existing directory alone, or create it.
///
/// Existence is tested rather than inferred from a failed creation, because a
/// refusal does not say which condition caused it: `/vol` sits above every
/// writable mount, so creating it reports the same read-only status as a mount
/// that does not exist at all. Testing first lets an ancestor that is merely
/// present be skipped while a genuinely bad one is still named.
fn ensure_directory(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    output: &mut StandardOutput,
    path: &str,
    verbose: bool,
) -> Result<(), Error> {
    match filesystem.metadata(path) {
        // An existing directory satisfies `-p` whether or not it is writable.
        Ok(metadata) if metadata.kind == filesystem::NodeKind::Directory => Ok(()),
        // A file or symbolic link in the way cannot become a directory.
        Ok(_) => Err(Error::WrongType),
        Err(Error::NotFound) => create(mutation, output, path, verbose),
        Err(error) => Err(error),
    }
}

/// Create every missing component of `path`, then `path` itself.
///
/// Returns the exact component that failed alongside its error, so a refusal
/// names the ancestor that caused it rather than the leaf that followed.
fn create_with_parents<'path>(
    filesystem: &mut ReadOnlyFilesystem,
    mutation: &mut FilesystemMutation,
    output: &mut StandardOutput,
    path: &'path str,
    verbose: bool,
) -> Result<(), (&'path str, Error)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        // `mkdir -p /` succeeds without creating anything.
        return Ok(());
    }
    for (index, byte) in trimmed.as_bytes().iter().enumerate() {
        if *byte != b'/' || index == 0 {
            continue;
        }
        let prefix = trimmed.get(..index).ok_or((path, Error::InvalidPath))?;
        if prefix.ends_with('/') {
            // A repeated separator names the prefix already handled.
            continue;
        }
        ensure_directory(filesystem, mutation, output, prefix, verbose)
            .map_err(|error| (prefix, error))?;
    }
    ensure_directory(filesystem, mutation, output, trimmed, verbose)
        .map_err(|error| (trimmed, error))
}

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let Ok(total) = arguments.total() else {
        return exit::FAILURE;
    };
    let mut options = Options::default();
    let mut operand_start = total;
    for index in 1..total {
        let Ok(Some(argument)) = arguments.get(index) else {
            return exit::FAILURE;
        };
        if argument == "--" {
            operand_start = index + 1;
            break;
        }
        if !argument.starts_with('-') || argument.len() == 1 {
            operand_start = index;
            break;
        }
        for option in argument.as_bytes().iter().skip(1) {
            match option {
                b'p' => options.parents = true,
                b'v' => options.verbose = true,
                _ => return common::usage(&mut command.stderr(), "mkdir", SYNOPSIS),
            }
        }
    }
    if operand_start >= total {
        return common::usage(&mut command.stderr(), "mkdir", SYNOPSIS);
    }
    let Ok(mut mutation) = command.filesystem_mutation() else {
        return exit::DENIED;
    };
    // The read capability is acquired only for `-p`, which alone needs to tell
    // an existing ancestor from one it must create.
    let mut filesystem = if options.parents {
        match command.filesystem() {
            Ok(opened) => Some(opened),
            Err(_) => return exit::DENIED,
        }
    } else {
        None
    };
    if arguments.seek(operand_start).is_err() {
        return exit::FAILURE;
    }
    // Every operand is attempted; one collision does not stop the rest.
    let mut status = exit::SUCCESS;
    loop {
        let path = match arguments.next_argument() {
            Ok(Some(path)) => path,
            Ok(None) => break,
            Err(_) => return exit::FAILURE,
        };
        let mut output = command.stdout();
        let outcome = match filesystem.as_mut() {
            Some(filesystem) => create_with_parents(
                filesystem,
                &mut mutation,
                &mut output,
                path,
                options.verbose,
            ),
            None => create(&mut mutation, &mut output, path, options.verbose)
                .map_err(|error| (path, error)),
        };
        if let Err((failed, error)) = outcome {
            let path_status =
                common::filesystem_failure(&mut command.stderr(), "mkdir", failed, error);
            if status == exit::SUCCESS {
                status = path_status;
            }
        }
    }
    status
}

entry!(main);

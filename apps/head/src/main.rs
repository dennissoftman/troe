#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, Error, ReadOnlyFilesystem, StandardOutput, entry, exit};

const SYNOPSIS: &[u8] = b"head [-c COUNT] [-n COUNT] [-qv] [FILE...]";
const DEFAULT_LINES: u64 = 10;
const CHUNK_BYTES: usize = 512;

/// How much of each input `head` emits.
#[derive(Clone, Copy)]
enum Limit {
    Lines(u64),
    Bytes(u64),
}

enum Failure {
    Source(Error),
    Output,
}

/// Parse one `-n`/`-c` operand as a plain decimal count.
///
/// A leading `+` is rejected rather than silently accepted: it selects
/// `tail`'s from-the-start form, which `head` does not have.
fn parse_count(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Emit the leading `limit` of one input.
///
/// Reads stop as soon as the limit is met, so a bounded prefix of a large
/// input costs only the bytes it emits.
fn copy_head(
    read: &mut impl FnMut(&mut [u8]) -> Result<usize, Error>,
    limit: Limit,
    output: &mut StandardOutput,
) -> Result<(), Failure> {
    let mut remaining_lines = match limit {
        Limit::Lines(lines) => lines,
        Limit::Bytes(bytes) => {
            let mut remaining = bytes;
            let mut buffer = [0_u8; CHUNK_BYTES];
            while remaining != 0 {
                let wanted = usize::try_from(remaining).unwrap_or(CHUNK_BYTES).min(CHUNK_BYTES);
                let count = read(&mut buffer[..wanted]).map_err(Failure::Source)?;
                if count == 0 {
                    return Ok(());
                }
                let chunk = buffer.get(..count).ok_or(Failure::Output)?;
                output.write_all(chunk).map_err(|_| Failure::Output)?;
                remaining = u64::try_from(count)
                    .ok()
                    .and_then(|count| remaining.checked_sub(count))
                    .ok_or(Failure::Output)?;
            }
            return Ok(());
        }
    };
    if remaining_lines == 0 {
        return Ok(());
    }
    let mut buffer = [0_u8; CHUNK_BYTES];
    loop {
        let count = read(&mut buffer).map_err(Failure::Source)?;
        if count == 0 {
            return Ok(());
        }
        let chunk = buffer.get(..count).ok_or(Failure::Output)?;
        let mut emit = count;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            remaining_lines -= 1;
            if remaining_lines == 0 {
                emit = index + 1;
                break;
            }
        }
        let emitted = chunk.get(..emit).ok_or(Failure::Output)?;
        output.write_all(emitted).map_err(|_| Failure::Output)?;
        if remaining_lines == 0 {
            return Ok(());
        }
    }
}

fn head_stdin(
    command: &mut CommandContext,
    limit: Limit,
    output: &mut StandardOutput,
) -> Result<(), Failure> {
    let mut input = command.stdin();
    copy_head(&mut |buffer| input.read(buffer), limit, output)
}

fn head_file(
    filesystem: &mut ReadOnlyFilesystem,
    path: &str,
    limit: Limit,
    output: &mut StandardOutput,
) -> Result<(), Failure> {
    let file = filesystem.open(path).map_err(Failure::Source)?;
    let mut offset = 0_u64;
    let outcome = copy_head(
        &mut |buffer| {
            if offset >= file.byte_count {
                return Ok(0);
            }
            let count = filesystem.read(file, offset, buffer)?;
            offset = u64::try_from(count)
                .ok()
                .and_then(|count| offset.checked_add(count))
                .ok_or(Error::Overflow)?;
            Ok(count)
        },
        limit,
        output,
    );
    let closed = filesystem.close(file);
    outcome?;
    closed.map_err(Failure::Source)
}

fn write_header(output: &mut StandardOutput, path: &str, first: bool) -> Result<(), Failure> {
    if !first {
        output.write_all(b"\n").map_err(|_| Failure::Output)?;
    }
    output.write_all(b"==> ").map_err(|_| Failure::Output)?;
    output
        .write_all(path.as_bytes())
        .map_err(|_| Failure::Output)?;
    output.write_all(b" <==\n").map_err(|_| Failure::Output)
}

fn report(command: &mut CommandContext, path: Option<&str>, failure: Failure) -> u32 {
    match failure {
        Failure::Source(error) => match path {
            Some(path) => common::filesystem_failure(&mut command.stderr(), "head", path, error),
            None => common::stream_read_failure(&mut command.stderr(), "head", error),
        },
        Failure::Output => common::stream_failure(&mut command.stderr(), "head"),
    }
}

#[allow(clippy::too_many_lines)]
fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let Ok(total) = arguments.total() else {
        return exit::FAILURE;
    };
    let mut limit = Limit::Lines(DEFAULT_LINES);
    let mut quiet = false;
    let mut verbose = false;
    let mut index = 1;
    let mut operand_start = total;
    // The paged reader lends one argument at a time, so an option that takes a
    // separate count operand copies both before inspecting either.
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
        // `head -5` is the obsolete count form and remains in wide use.
        if let Some(count) = parse_count(argument.get(1..).unwrap_or("")) {
            limit = Limit::Lines(count);
            index += 1;
            continue;
        }
        let mut position = 1;
        let mut wants_value = None;
        while position < argument.len() {
            let option = argument.as_bytes()[position];
            match option {
                b'q' => quiet = true,
                b'v' => verbose = true,
                b'c' | b'n' => {
                    // The count may be attached (`-n5`) or a separate operand.
                    let attached = argument.get(position + 1..).unwrap_or("");
                    if attached.is_empty() {
                        wants_value = Some(option);
                    } else {
                        let Some(count) = parse_count(attached) else {
                            return common::usage(&mut command.stderr(), "head", SYNOPSIS);
                        };
                        limit = if option == b'c' {
                            Limit::Bytes(count)
                        } else {
                            Limit::Lines(count)
                        };
                    }
                    position = argument.len();
                    continue;
                }
                _ => return common::usage(&mut command.stderr(), "head", SYNOPSIS),
            }
            position += 1;
        }
        if let Some(option) = wants_value {
            index += 1;
            match arguments.get(index) {
                Ok(Some(text)) => {
                    if value.set(text).is_err() {
                        return exit::FAILURE;
                    }
                }
                _ => return common::usage(&mut command.stderr(), "head", SYNOPSIS),
            }
            let Some(count) = parse_count(value.as_str()) else {
                return common::usage(&mut command.stderr(), "head", SYNOPSIS);
            };
            limit = if option == b'c' {
                Limit::Bytes(count)
            } else {
                Limit::Lines(count)
            };
        }
        index += 1;
    }

    if operand_start >= total {
        let mut output = command.stdout();
        if verbose && write_header(&mut output, "standard input", true).is_err() {
            return common::stream_failure(&mut command.stderr(), "head");
        }
        return match head_stdin(command, limit, &mut output) {
            Ok(()) => exit::SUCCESS,
            Err(failure) => report(command, None, failure),
        };
    }

    let operand_count = total - operand_start;
    let headers = verbose || (operand_count > 1 && !quiet);
    let mut filesystem: Option<ReadOnlyFilesystem> = None;
    let mut status = exit::SUCCESS;
    let mut first = true;
    for operand in operand_start..total {
        let Ok(Some(path)) = arguments.get(operand) else {
            return exit::FAILURE;
        };
        let mut output = command.stdout();
        if headers {
            let label = if path == "-" { "standard input" } else { path };
            if write_header(&mut output, label, first).is_err() {
                return common::stream_failure(&mut command.stderr(), "head");
            }
        }
        first = false;
        let outcome = if path == "-" {
            head_stdin(command, limit, &mut output)
        } else {
            if filesystem.is_none() {
                match command.filesystem() {
                    Ok(opened) => filesystem = Some(opened),
                    Err(_) => return exit::DENIED,
                }
            }
            let Some(filesystem) = filesystem.as_mut() else {
                return exit::DENIED;
            };
            head_file(filesystem, path, limit, &mut output)
        };
        if let Err(failure) = outcome {
            let operand_status = report(command, (path != "-").then_some(path), failure);
            if status == exit::SUCCESS {
                status = operand_status;
            }
        }
    }
    status
}

entry!(main);

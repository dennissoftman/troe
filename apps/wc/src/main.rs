#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt::Write as _;
use troe_app_wc::Counts;
use troe_kex_sdk::{
    CommandContext, Error, INVOCATION_BUFFER_BYTES, ReadOnlyFilesystem, entry, exit,
};

#[derive(Clone, Copy, Default)]
struct Selection {
    lines: bool,
    words: bool,
    bytes: bool,
}

impl Selection {
    const fn all() -> Self {
        Self {
            lines: true,
            words: true,
            bytes: true,
        }
    }
}

fn count_stdin(command: &mut CommandContext) -> Result<Counts, Error> {
    let mut counts = Counts::default();
    let mut input = command.stdin();
    let mut buffer = [0_u8; 512];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            return Ok(counts);
        }
        counts.feed(&buffer[..count]);
    }
}

fn count_file(filesystem: &mut ReadOnlyFilesystem, path: &str) -> Result<Counts, Error> {
    let file = filesystem.open(path)?;
    if file.byte_count > common::COMMAND_BYTES {
        let _ignored = filesystem.close(file);
        return Err(Error::NoSpace);
    }
    let mut counts = Counts::default();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 512];
    while offset < file.byte_count {
        let count = match filesystem.read(file, offset, &mut buffer) {
            Ok(0) => {
                let _ignored = filesystem.close(file);
                return Err(Error::Corrupt);
            }
            Ok(count) => count,
            Err(error) => {
                let _ignored = filesystem.close(file);
                return Err(error);
            }
        };
        counts.feed(&buffer[..count]);
        offset = offset.checked_add(count as u64).ok_or(Error::Overflow)?;
    }
    filesystem.close(file)?;
    Ok(counts)
}

fn write_counts(
    command: &mut CommandContext,
    selection: Selection,
    counts: Counts,
    label: Option<&str>,
) -> Result<(), ()> {
    let mut output = command.stdout();
    let mut writer = common::OutputWriter(&mut output);
    let mut separator = "";
    if selection.lines {
        write!(writer, "{}", counts.lines).map_err(|_| ())?;
        separator = " ";
    }
    if selection.words {
        write!(writer, "{separator}{}", counts.words).map_err(|_| ())?;
        separator = " ";
    }
    if selection.bytes {
        write!(writer, "{separator}{}", counts.bytes).map_err(|_| ())?;
    }
    if let Some(label) = label {
        write!(writer, " {label}").map_err(|_| ())?;
    }
    writer.write_str("\n").map_err(|_| ())
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let mut selection = Selection::default();
    let mut operand_start = invocation.len();
    let mut options_seen = false;
    for index in 1..invocation.len() {
        let Some(argument) = invocation.argument(index) else {
            return exit::FAILURE;
        };
        if argument == "--" {
            operand_start = index + 1;
            break;
        }
        if argument == "-" || !argument.starts_with('-') {
            operand_start = index;
            break;
        }
        if argument.len() == 1 {
            operand_start = index;
            break;
        }
        for option in argument.as_bytes().iter().skip(1) {
            match option {
                b'l' => selection.lines = true,
                b'w' => selection.words = true,
                b'c' => selection.bytes = true,
                _ => {
                    return common::usage(&mut command.stderr(), "wc", b"wc [-lwc] [FILE...]");
                }
            }
            options_seen = true;
        }
    }
    if !options_seen {
        selection = Selection::all();
    }
    if operand_start == invocation.len() {
        let counts = match count_stdin(command) {
            Ok(counts) => counts,
            Err(error) => {
                return common::stream_read_failure(&mut command.stderr(), "wc", error);
            }
        };
        return if write_counts(command, selection, counts, None).is_ok() {
            exit::SUCCESS
        } else {
            common::stream_failure(&mut command.stderr(), "wc")
        };
    }

    let operand_count = invocation.len() - operand_start;
    let requires_filesystem = (operand_start..invocation.len()).any(|index| {
        invocation
            .argument(index)
            .is_some_and(|argument| argument != "-")
    });
    let mut filesystem = if requires_filesystem {
        match command.filesystem() {
            Ok(filesystem) => Some(filesystem),
            Err(_) => return exit::DENIED,
        }
    } else {
        None
    };
    let mut total = Counts::default();
    for index in operand_start..invocation.len() {
        let Some(path) = invocation.argument(index) else {
            return exit::FAILURE;
        };
        let counts = if path == "-" {
            match count_stdin(command) {
                Ok(counts) => counts,
                Err(error) => {
                    return common::stream_read_failure(&mut command.stderr(), "wc", error);
                }
            }
        } else {
            let Some(filesystem) = filesystem.as_mut() else {
                return exit::DENIED;
            };
            match count_file(filesystem, path) {
                Ok(counts) => counts,
                Err(error) => {
                    return common::filesystem_failure(&mut command.stderr(), "wc", path, error);
                }
            }
        };
        if write_counts(command, selection, counts, Some(path)).is_err() {
            return common::stream_failure(&mut command.stderr(), "wc");
        }
        total.add(counts);
    }
    if operand_count > 1 && write_counts(command, selection, total, Some("total")).is_err() {
        return common::stream_failure(&mut command.stderr(), "wc");
    }
    exit::SUCCESS
}

entry!(main);

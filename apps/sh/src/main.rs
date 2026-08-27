#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::{fmt::Write as _, str};
use troe_kex_sdk::{
    CommandContext, INVOCATION_BUFFER_BYTES, ReadOnlyFilesystem, ShellScript, StandardInput, entry,
    exit, filesystem, shell_script,
};

const MAX_SOURCE_BYTES: u64 = 64 * 1024;

enum Source {
    StandardInput(StandardInput),
    File {
        filesystem: ReadOnlyFilesystem,
        file: filesystem::OpenFile,
        offset: u64,
    },
}

impl Source {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, ()> {
        match self {
            Self::StandardInput(input) => input.read(destination).map_err(|_| ()),
            Self::File {
                filesystem,
                file,
                offset,
            } => {
                let count = filesystem
                    .read(*file, *offset, destination)
                    .map_err(|_| ())?;
                *offset = offset
                    .checked_add(u64::try_from(count).map_err(|_| ())?)
                    .ok_or(())?;
                Ok(count)
            }
        }
    }

    fn close(&mut self) -> Result<(), ()> {
        match self {
            Self::File {
                filesystem, file, ..
            } => filesystem.close(*file).map_err(|_| ()),
            Self::StandardInput(_) => Ok(()),
        }
    }
}

fn report_line(command: &mut CommandContext, number: u32, message: &str) -> u32 {
    let mut stderr = command.stderr();
    let mut writer = common::OutputWriter(&mut stderr);
    let _ignored = writeln!(writer, "sh: line {number}: {message}");
    exit::FAILURE
}

fn submit_line(
    command: &mut CommandContext,
    script: &mut ShellScript,
    number: u32,
    bytes: &[u8],
) -> Result<(), u32> {
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    let source = str::from_utf8(bytes)
        .map_err(|_| report_line(command, number, "source is not valid UTF-8"))?;
    let trimmed = source.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(());
    }
    script
        .submit_line(number, source)
        .map_err(|_| report_line(command, number, "command line was rejected"))
}

fn run_source(command: &mut CommandContext, mut source: Source) -> u32 {
    let Ok(mut script) = command.shell_script() else {
        common::report(
            &mut command.stderr(),
            "sh",
            b"shell-script capability is unavailable",
        );
        return exit::DENIED;
    };
    let mut input = [0_u8; troe_kex_sdk::FILESYSTEM_IO_BUFFER_BYTES];
    let mut line = [0_u8; shell_script::MAX_LINE_BYTES];
    let mut line_bytes = 0_usize;
    let mut source_bytes = 0_u64;
    let mut line_number = 1_u32;
    loop {
        let count = match source.read(&mut input) {
            Ok(count) => count,
            Err(()) => {
                let _ignored = source.close();
                common::report(&mut command.stderr(), "sh", b"source read failed");
                return exit::FAILURE;
            }
        };
        if count == 0 {
            break;
        }
        source_bytes = match source_bytes.checked_add(count as u64) {
            Some(bytes) if bytes <= MAX_SOURCE_BYTES => bytes,
            _ => {
                let _ignored = source.close();
                common::report(&mut command.stderr(), "sh", b"source exceeds 64 KiB");
                return exit::FAILURE;
            }
        };
        for byte in &input[..count] {
            if *byte == b'\n' {
                if let Err(status) =
                    submit_line(command, &mut script, line_number, &line[..line_bytes])
                {
                    let _ignored = source.close();
                    return status;
                }
                line_bytes = 0;
                line_number = match line_number.checked_add(1) {
                    Some(number) => number,
                    None => {
                        let _ignored = source.close();
                        return exit::FAILURE;
                    }
                };
            } else if line_bytes == line.len() {
                let _ignored = source.close();
                return report_line(command, line_number, "line exceeds 512 bytes");
            } else {
                line[line_bytes] = *byte;
                line_bytes += 1;
            }
        }
    }
    if line_bytes != 0
        && let Err(status) = submit_line(command, &mut script, line_number, &line[..line_bytes])
    {
        let _ignored = source.close();
        return status;
    }
    if source.close().is_err() {
        common::report(&mut command.stderr(), "sh", b"cannot close source file");
        return exit::FAILURE;
    }
    exit::SUCCESS
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() == 2 && matches!(invocation.argument(1), Some("-h" | "--help")) {
        return if command
            .stdout()
            .write_all(b"usage: sh [FILE | -]\n")
            .is_ok()
        {
            exit::SUCCESS
        } else {
            exit::FAILURE
        };
    }
    if invocation.len() > 2 {
        return common::usage(&mut command.stderr(), "sh", b"sh [FILE | -]");
    }
    let source = match invocation.argument(1) {
        None | Some("-") => Source::StandardInput(command.stdin()),
        Some(path) => {
            let Ok(mut filesystem) = command.filesystem() else {
                return exit::DENIED;
            };
            let file = match filesystem.open(path) {
                Ok(file) if file.byte_count <= MAX_SOURCE_BYTES => file,
                Ok(file) => {
                    let _ignored = filesystem.close(file);
                    common::report_path(
                        &mut command.stderr(),
                        "sh",
                        path,
                        b"source exceeds 64 KiB",
                    );
                    return exit::FAILURE;
                }
                Err(error) => {
                    return common::filesystem_failure(&mut command.stderr(), "sh", path, error);
                }
            };
            Source::File {
                filesystem,
                file,
                offset: 0,
            }
        }
    };
    run_source(command, source)
}

entry!(main);

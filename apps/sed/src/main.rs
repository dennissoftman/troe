#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_app_sed::{Script, apply};
use troe_kex_sdk::{
    CommandContext, Error, INVOCATION_BUFFER_BYTES, ReadOnlyFilesystem, StandardOutput, entry, exit,
};

const LINE_BYTES: usize = 64 * 1024;

enum ProcessError {
    Input,
    Output,
    LineTooLong,
}

enum FileProcessError {
    Filesystem(Error),
    Process(ProcessError),
}

struct Processor<'script> {
    script: Script<'script>,
    quiet: bool,
    line: [u8; LINE_BYTES],
    used: usize,
    number: u64,
    output: StandardOutput,
}

impl<'script> Processor<'script> {
    fn new(
        script: Script<'script>,
        quiet: bool,
        start_number: u64,
        output: StandardOutput,
    ) -> Self {
        Self {
            script,
            quiet,
            line: [0; LINE_BYTES],
            used: 0,
            number: start_number,
            output,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<(), ProcessError> {
        for byte in bytes {
            if self.used == self.line.len() {
                return Err(ProcessError::LineTooLong);
            }
            self.line[self.used] = *byte;
            self.used += 1;
            if *byte == b'\n' {
                self.emit()?;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ProcessError> {
        if self.used != 0 {
            self.emit()?;
        }
        Ok(())
    }

    fn emit(&mut self) -> Result<(), ProcessError> {
        self.number = self.number.saturating_add(1);
        apply(
            self.script,
            self.quiet,
            self.number,
            &self.line[..self.used],
            |bytes| self.output.write_all(bytes),
        )
        .map_err(|_| ProcessError::Output)?;
        self.used = 0;
        Ok(())
    }
}

fn process_stdin(
    command: &mut CommandContext,
    script: Script<'_>,
    quiet: bool,
) -> Result<(), ProcessError> {
    let mut input = command.stdin();
    let mut processor = Processor::new(script, quiet, 0, command.stdout());
    let mut buffer = [0_u8; 512];
    loop {
        let count = input.read(&mut buffer).map_err(|_| ProcessError::Input)?;
        if count == 0 {
            return processor.finish();
        }
        processor.feed(&buffer[..count])?;
    }
}

fn process_file(
    command: &mut CommandContext,
    filesystem: &mut ReadOnlyFilesystem,
    path: &str,
    script: Script<'_>,
    quiet: bool,
    start_number: u64,
) -> Result<u64, FileProcessError> {
    let file = filesystem
        .open(path)
        .map_err(FileProcessError::Filesystem)?;
    if file.byte_count > common::COMMAND_BYTES {
        let _ignored = filesystem.close(file);
        return Err(FileProcessError::Filesystem(Error::NoSpace));
    }
    let mut processor = Processor::new(script, quiet, start_number, command.stdout());
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 512];
    while offset < file.byte_count {
        let count = match filesystem.read(file, offset, &mut buffer) {
            Ok(0) => {
                let _ignored = filesystem.close(file);
                return Err(FileProcessError::Filesystem(Error::Corrupt));
            }
            Ok(count) => count,
            Err(error) => {
                let _ignored = filesystem.close(file);
                return Err(FileProcessError::Filesystem(error));
            }
        };
        if let Err(error) = processor.feed(&buffer[..count]) {
            let _ignored = filesystem.close(file);
            return Err(FileProcessError::Process(error));
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or(FileProcessError::Filesystem(Error::Overflow))?;
    }
    if let Err(error) = processor.finish() {
        let _ignored = filesystem.close(file);
        return Err(FileProcessError::Process(error));
    }
    filesystem
        .close(file)
        .map_err(FileProcessError::Filesystem)?;
    Ok(processor.number)
}

fn processing_failure(command: &mut CommandContext, error: ProcessError) -> u32 {
    match error {
        ProcessError::LineTooLong => {
            common::report(&mut command.stderr(), "sed", b"line exceeds command limit");
            exit::FAILURE
        }
        ProcessError::Input | ProcessError::Output => {
            common::stream_failure(&mut command.stderr(), "sed")
        }
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let mut quiet = false;
    let mut cursor = 1;
    let mut script_text = None;
    while cursor < invocation.len() {
        let Some(argument) = invocation.argument(cursor) else {
            return exit::FAILURE;
        };
        match argument {
            "-n" => quiet = true,
            "-e" => {
                cursor += 1;
                script_text = invocation.argument(cursor);
                if script_text.is_none() {
                    return common::usage(
                        &mut command.stderr(),
                        "sed",
                        b"sed [-n] [-e SCRIPT | SCRIPT] [FILE...]",
                    );
                }
                cursor += 1;
                break;
            }
            _ if argument.starts_with('-') => {
                return common::usage(
                    &mut command.stderr(),
                    "sed",
                    b"sed [-n] [-e SCRIPT | SCRIPT] [FILE...]",
                );
            }
            _ => {
                script_text = Some(argument);
                cursor += 1;
                break;
            }
        }
        cursor += 1;
    }
    let Some(script_text) = script_text else {
        return common::usage(
            &mut command.stderr(),
            "sed",
            b"sed [-n] [-e SCRIPT | SCRIPT] [FILE...]",
        );
    };
    let Ok(script) = Script::parse(script_text) else {
        common::report(&mut command.stderr(), "sed", b"unsupported script");
        return exit::USAGE;
    };
    if cursor == invocation.len() {
        return match process_stdin(command, script, quiet) {
            Ok(()) => exit::SUCCESS,
            Err(error) => processing_failure(command, error),
        };
    }
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    let mut line_number = 0;
    while cursor < invocation.len() {
        let Some(path) = invocation.argument(cursor) else {
            return exit::FAILURE;
        };
        match process_file(command, &mut filesystem, path, script, quiet, line_number) {
            Ok(number) => line_number = number,
            Err(FileProcessError::Filesystem(error)) => {
                return common::filesystem_failure(&mut command.stderr(), "sed", path, error);
            }
            Err(FileProcessError::Process(error)) => return processing_failure(command, error),
        }
        cursor += 1;
    }
    exit::SUCCESS
}

entry!(main);

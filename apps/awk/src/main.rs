#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_app_awk::{Program, execute};
use troe_kex_sdk::{
    CommandContext, Error, INVOCATION_BUFFER_BYTES, ReadOnlyFilesystem, StandardOutput, entry, exit,
};

const LINE_BYTES: usize = 64 * 1024;

enum ProcessError {
    Input,
    Output,
    LineTooLong,
    Cancelled,
}

enum FileProcessError {
    Filesystem(Error),
    Process(ProcessError),
}

struct Processor<'program> {
    program: Program<'program>,
    separator: Option<u8>,
    line: [u8; LINE_BYTES],
    used: usize,
    number: u64,
    output: StandardOutput,
}

impl<'program> Processor<'program> {
    fn new(
        program: Program<'program>,
        separator: Option<u8>,
        start_number: u64,
        output: StandardOutput,
    ) -> Self {
        Self {
            program,
            separator,
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
        execute(
            self.program,
            self.separator,
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
    program: Program<'_>,
    separator: Option<u8>,
) -> Result<(), ProcessError> {
    let mut input = command.stdin();
    let mut processor = Processor::new(program, separator, 0, command.stdout());
    let mut buffer = [0_u8; 512];
    loop {
        let count = input.read(&mut buffer).map_err(|error| {
            if error == Error::Cancelled {
                ProcessError::Cancelled
            } else {
                ProcessError::Input
            }
        })?;
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
    program: Program<'_>,
    separator: Option<u8>,
    start_number: u64,
) -> Result<u64, FileProcessError> {
    let file = filesystem
        .open(path)
        .map_err(FileProcessError::Filesystem)?;
    if file.byte_count > common::COMMAND_BYTES {
        let _ignored = filesystem.close(file);
        return Err(FileProcessError::Filesystem(Error::NoSpace));
    }
    let mut processor = Processor::new(program, separator, start_number, command.stdout());
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
            common::report(&mut command.stderr(), "awk", b"line exceeds command limit");
            exit::FAILURE
        }
        ProcessError::Input | ProcessError::Output => {
            common::stream_failure(&mut command.stderr(), "awk")
        }
        ProcessError::Cancelled => {
            common::report(&mut command.stderr(), "awk", b"cancelled");
            exit::CANCELLED
        }
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let mut separator = None;
    let mut cursor = 1;
    if let Some(argument) = invocation.argument(cursor) {
        if let Some(value) = argument.strip_prefix("-F") {
            let field_separator = if value.is_empty() {
                cursor += 1;
                invocation.argument(cursor)
            } else {
                Some(value)
            };
            let Some(field_separator) = field_separator else {
                return common::usage(
                    &mut command.stderr(),
                    "awk",
                    b"awk [-F SEP] PROGRAM [FILE...]",
                );
            };
            if field_separator.len() != 1 {
                common::report(&mut command.stderr(), "awk", b"separator must be one byte");
                return exit::USAGE;
            }
            separator = field_separator.as_bytes().first().copied();
            cursor += 1;
        }
    }
    let Some(program_text) = invocation.argument(cursor) else {
        return common::usage(
            &mut command.stderr(),
            "awk",
            b"awk [-F SEP] PROGRAM [FILE...]",
        );
    };
    let Ok(program) = Program::parse(program_text) else {
        common::report(&mut command.stderr(), "awk", b"unsupported program");
        return exit::USAGE;
    };
    cursor += 1;
    if cursor == invocation.len() {
        return match process_stdin(command, program, separator) {
            Ok(()) => exit::SUCCESS,
            Err(error) => processing_failure(command, error),
        };
    }
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    let mut record_number = 0;
    while cursor < invocation.len() {
        let Some(path) = invocation.argument(cursor) else {
            return exit::FAILURE;
        };
        match process_file(
            command,
            &mut filesystem,
            path,
            program,
            separator,
            record_number,
        ) {
            Ok(number) => record_number = number,
            Err(FileProcessError::Filesystem(error)) => {
                return common::filesystem_failure(&mut command.stderr(), "awk", path, error);
            }
            Err(FileProcessError::Process(error)) => return processing_failure(command, error),
        }
        cursor += 1;
    }
    exit::SUCCESS
}

entry!(main);

#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, Error, INVOCATION_BUFFER_BYTES, StandardOutput, entry, exit};

const LINE_BYTES: usize = 64 * 1024;

enum GrepError {
    LineTooLong,
    Output,
}

struct Matcher<'pattern> {
    pattern: &'pattern [u8],
    line: [u8; LINE_BYTES],
    line_bytes: usize,
    output: StandardOutput,
}

impl<'pattern> Matcher<'pattern> {
    fn new(pattern: &'pattern [u8], output: StandardOutput) -> Self {
        Self {
            pattern,
            line: [0; LINE_BYTES],
            line_bytes: 0,
            output,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<(), GrepError> {
        for byte in bytes {
            if self.line_bytes >= self.line.len() {
                return Err(GrepError::LineTooLong);
            }
            self.line[self.line_bytes] = *byte;
            self.line_bytes += 1;
            if *byte == b'\n' {
                self.emit_match(false)?;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), GrepError> {
        if self.line_bytes != 0 {
            self.emit_match(true)?;
        }
        Ok(())
    }

    fn emit_match(&mut self, add_newline: bool) -> Result<(), GrepError> {
        let line = &self.line[..self.line_bytes];
        if contains(line, self.pattern) {
            self.output.write_all(line).map_err(|_| GrepError::Output)?;
            if add_newline && !line.ends_with(b"\n") {
                self.output
                    .write_all(b"\n")
                    .map_err(|_| GrepError::Output)?;
            }
        }
        self.line_bytes = 0;
        Ok(())
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn matcher_failure(command: &mut CommandContext, error: GrepError) -> u32 {
    match error {
        GrepError::LineTooLong => {
            common::report(
                &mut command.stderr(),
                "grep",
                b"line exceeds pipeline capacity",
            );
            exit::FAILURE
        }
        GrepError::Output => common::stream_failure(&mut command.stderr(), "grep"),
    }
}

fn grep_input(command: &mut CommandContext, pattern: &[u8]) -> u32 {
    let mut input = command.stdin();
    let mut matcher = Matcher::new(pattern, command.stdout());
    let mut buffer = [0_u8; 256];
    loop {
        let count = match input.read(&mut buffer) {
            Ok(count) => count,
            Err(_) => return common::stream_failure(&mut command.stderr(), "grep"),
        };
        if count == 0 {
            return match matcher.finish() {
                Ok(()) => exit::SUCCESS,
                Err(error) => matcher_failure(command, error),
            };
        }
        if let Err(error) = matcher.feed(&buffer[..count]) {
            return matcher_failure(command, error);
        }
    }
}

fn grep_file(
    command: &mut CommandContext,
    filesystem: &mut troe_kex_sdk::ReadOnlyFilesystem,
    pattern: &[u8],
    path: &str,
) -> u32 {
    let file = match filesystem.open(path) {
        Ok(file) if file.byte_count <= common::COMMAND_BYTES => file,
        Ok(file) => {
            let _ignored = filesystem.close(file);
            return common::filesystem_failure(&mut command.stderr(), "grep", path, Error::NoSpace);
        }
        Err(error) => {
            return common::filesystem_failure(&mut command.stderr(), "grep", path, error);
        }
    };
    let mut matcher = Matcher::new(pattern, command.stdout());
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 256];
    while offset < file.byte_count {
        let count = match filesystem.read(file, offset, &mut buffer) {
            Ok(0) => {
                let _ignored = filesystem.close(file);
                return common::filesystem_failure(
                    &mut command.stderr(),
                    "grep",
                    path,
                    Error::Corrupt,
                );
            }
            Ok(count) => count,
            Err(error) => {
                let _ignored = filesystem.close(file);
                return common::filesystem_failure(&mut command.stderr(), "grep", path, error);
            }
        };
        if let Err(error) = matcher.feed(&buffer[..count]) {
            let _ignored = filesystem.close(file);
            return matcher_failure(command, error);
        }
        let Some(next) = offset.checked_add(count as u64) else {
            return exit::FAILURE;
        };
        offset = next;
    }
    if let Err(error) = matcher.finish() {
        let _ignored = filesystem.close(file);
        return matcher_failure(command, error);
    }
    if filesystem.close(file).is_err() {
        return common::filesystem_failure(&mut command.stderr(), "grep", path, Error::Corrupt);
    }
    exit::SUCCESS
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let Some(pattern) = invocation.argument(1) else {
        return common::usage(&mut command.stderr(), "grep", b"grep PATTERN [FILE...]");
    };
    if invocation.len() == 2 {
        return grep_input(command, pattern.as_bytes());
    }
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    for index in 2..invocation.len() {
        let Some(path) = invocation.argument(index) else {
            return exit::FAILURE;
        };
        let status = grep_file(command, &mut filesystem, pattern.as_bytes(), path);
        if status != exit::SUCCESS {
            return status;
        }
    }
    exit::SUCCESS
}

entry!(main);

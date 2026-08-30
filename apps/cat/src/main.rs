#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt::{self, Write as _};
use troe_kex_sdk::{
    ArgumentReader, CommandContext, Error, ReadOnlyFilesystem, StandardOutput, entry, exit,
};

#[derive(Clone, Copy, Default)]
struct Options {
    number: bool,
    number_nonblank: bool,
    squeeze_blank: bool,
    show_ends: bool,
    show_tabs: bool,
    show_nonprinting: bool,
    unbuffered: bool,
}

struct BufferedOutput {
    output: StandardOutput,
    bytes: [u8; 512],
    length: usize,
    unbuffered: bool,
}

impl BufferedOutput {
    fn new(output: StandardOutput, unbuffered: bool) -> Self {
        Self {
            output,
            bytes: [0; 512],
            length: 0,
            unbuffered,
        }
    }

    fn write_bytes(&mut self, mut bytes: &[u8]) -> Result<(), ()> {
        if self.unbuffered {
            self.flush()?;
            return self.output.write_all(bytes).map_err(|_| ());
        }
        while !bytes.is_empty() {
            if self.length == self.bytes.len() {
                self.flush()?;
            }
            let count = bytes.len().min(self.bytes.len() - self.length);
            self.bytes[self.length..self.length + count].copy_from_slice(&bytes[..count]);
            self.length += count;
            bytes = &bytes[count..];
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ()> {
        if self.length != 0 {
            self.output
                .write_all(&self.bytes[..self.length])
                .map_err(|_| ())?;
            self.length = 0;
        }
        Ok(())
    }
}

impl fmt::Write for BufferedOutput {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.write_bytes(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

struct Transformer {
    options: Options,
    output: BufferedOutput,
    line_number: u64,
    at_line_start: bool,
    previous_line_blank: bool,
}

enum CopyError {
    Filesystem(Error),
    Output,
}

impl From<Error> for CopyError {
    fn from(error: Error) -> Self {
        Self::Filesystem(error)
    }
}

impl Transformer {
    fn new(options: Options, output: StandardOutput) -> Self {
        Self {
            options,
            output: BufferedOutput::new(output, options.unbuffered),
            line_number: 1,
            at_line_start: true,
            previous_line_blank: false,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<(), ()> {
        for byte in bytes {
            let blank = self.at_line_start && *byte == b'\n';
            if blank && self.options.squeeze_blank && self.previous_line_blank {
                continue;
            }
            if self.at_line_start
                && (self.options.number || (self.options.number_nonblank && !blank))
            {
                write!(self.output, "{:>6}\t", self.line_number).map_err(|_| ())?;
                self.line_number = self.line_number.checked_add(1).ok_or(())?;
            }
            if *byte == b'\n' && self.options.show_ends {
                self.output.write_bytes(b"$")?;
            }
            if *byte == b'\t' && self.options.show_tabs {
                self.output.write_bytes(b"^I")?;
            } else if self.options.show_nonprinting && !matches!(*byte, b'\n' | b'\t') {
                write_visible(&mut self.output, *byte)?;
            } else {
                self.output.write_bytes(&[*byte])?;
            }
            if *byte == b'\n' {
                self.previous_line_blank = blank;
                self.at_line_start = true;
            } else {
                self.previous_line_blank = false;
                self.at_line_start = false;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ()> {
        self.output.flush()
    }
}

fn write_visible(output: &mut BufferedOutput, byte: u8) -> Result<(), ()> {
    if byte >= 0x80 {
        output.write_bytes(b"M-")?;
    }
    match byte & 0x7f {
        value @ 0x00..=0x1f => output.write_bytes(&[b'^', value + b'@']),
        0x7f => output.write_bytes(b"^?"),
        value => output.write_bytes(&[value]),
    }
}

fn parse_options(arguments: &mut ArgumentReader, total: usize) -> Option<(Options, usize)> {
    let mut options = Options::default();
    let mut operand_start = total;
    for index in 1..total {
        let argument = arguments.get(index).ok()??;
        if argument == "--" {
            operand_start = index + 1;
            break;
        }
        if argument == "-" || !argument.starts_with('-') {
            operand_start = index;
            break;
        }
        for option in argument.as_bytes().iter().skip(1) {
            match option {
                b'n' => options.number = true,
                b'b' => options.number_nonblank = true,
                b's' => options.squeeze_blank = true,
                b'E' => options.show_ends = true,
                b'T' => options.show_tabs = true,
                b'v' => options.show_nonprinting = true,
                b'e' => {
                    options.show_ends = true;
                    options.show_nonprinting = true;
                }
                b't' => {
                    options.show_tabs = true;
                    options.show_nonprinting = true;
                }
                b'A' => {
                    options.show_ends = true;
                    options.show_tabs = true;
                    options.show_nonprinting = true;
                }
                b'u' => options.unbuffered = true,
                _ => return None,
            }
        }
    }
    if options.number_nonblank {
        options.number = false;
    }
    Some((options, operand_start))
}

fn copy_input(command: &mut CommandContext, transformer: &mut Transformer) -> Result<(), Error> {
    let mut input = command.stdin();
    let mut buffer = [0_u8; 512];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        transformer.feed(&buffer[..count]).map_err(|()| Error::Io)?;
    }
}

fn copy_file(
    filesystem: &mut ReadOnlyFilesystem,
    path: &str,
    transformer: &mut Transformer,
) -> Result<(), CopyError> {
    let file = filesystem.open(path)?;
    if file.byte_count > common::COMMAND_BYTES {
        let _ignored = filesystem.close(file);
        return Err(CopyError::Filesystem(Error::NoSpace));
    }
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 512];
    while offset < file.byte_count {
        let count = match filesystem.read(file, offset, &mut buffer) {
            Ok(0) => {
                let _ignored = filesystem.close(file);
                return Err(CopyError::Filesystem(Error::Corrupt));
            }
            Ok(count) => count,
            Err(error) => {
                let _ignored = filesystem.close(file);
                return Err(CopyError::Filesystem(error));
            }
        };
        if transformer.feed(&buffer[..count]).is_err() {
            let _ignored = filesystem.close(file);
            return Err(CopyError::Output);
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or(CopyError::Filesystem(Error::Overflow))?;
        if offset > file.byte_count {
            let _ignored = filesystem.close(file);
            return Err(CopyError::Filesystem(Error::Corrupt));
        }
    }
    filesystem.close(file).map_err(CopyError::Filesystem)
}

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let Ok(total) = arguments.total() else {
        return exit::FAILURE;
    };
    let Some((options, operand_start)) = parse_options(&mut arguments, total) else {
        return common::usage(&mut command.stderr(), "cat", b"cat [-AbEnstTuv] [FILE...]");
    };
    let mut transformer = Transformer::new(options, command.stdout());
    if operand_start == total {
        if let Err(error) = copy_input(command, &mut transformer) {
            return common::stream_read_failure(&mut command.stderr(), "cat", error);
        }
        if transformer.finish().is_err() {
            return common::stream_failure(&mut command.stderr(), "cat");
        }
        return exit::SUCCESS;
    }

    // The read capability is acquired on the first named operand rather than
    // pre-scanned, so an operand list of any length costs one pass.
    let mut filesystem: Option<ReadOnlyFilesystem> = None;
    if arguments.seek(operand_start).is_err() {
        return exit::FAILURE;
    }
    loop {
        let path = match arguments.next_argument() {
            Ok(Some(path)) => path,
            Ok(None) => break,
            Err(_) => return exit::FAILURE,
        };
        if path == "-" {
            if let Err(error) = copy_input(command, &mut transformer) {
                return common::stream_read_failure(&mut command.stderr(), "cat", error);
            }
            continue;
        }
        if filesystem.is_none() {
            match command.filesystem() {
                Ok(opened) => filesystem = Some(opened),
                Err(_) => return exit::DENIED,
            }
        }
        let Some(filesystem) = filesystem.as_mut() else {
            return exit::DENIED;
        };
        if let Err(error) = copy_file(filesystem, path, &mut transformer) {
            return match error {
                CopyError::Filesystem(error) => {
                    common::filesystem_failure(&mut command.stderr(), "cat", path, error)
                }
                CopyError::Output => common::stream_failure(&mut command.stderr(), "cat"),
            };
        }
    }
    if transformer.finish().is_err() {
        return common::stream_failure(&mut command.stderr(), "cat");
    }
    exit::SUCCESS
}

entry!(main);

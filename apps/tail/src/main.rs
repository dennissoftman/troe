#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{
    CommandContext, Error, ReadOnlyFilesystem, StandardOutput, entry, exit, filesystem,
};

const SYNOPSIS: &[u8] = b"tail [-c COUNT] [-n COUNT] [-qv] [FILE...]";
const DEFAULT_LINES: u64 = 10;
const CHUNK_BYTES: usize = 512;
/// Trailing bytes retained for one non-seekable input.
///
/// A file is read backwards from its end and needs no window, so this bounds
/// only a pipe or the session terminal. Output past it is reported rather than
/// silently truncated.
const WINDOW_BYTES: usize = 8 * 1024;

/// How much of each input `tail` emits, and from which end it is measured.
#[derive(Clone, Copy)]
struct Selection {
    count: u64,
    bytes: bool,
    from_start: bool,
}

enum Failure {
    Source(Error),
    Output,
    WindowExceeded,
}

/// Parse one `-n`/`-c` operand, reporting the leading `+` separately.
fn parse_count(text: &str) -> Option<(u64, bool)> {
    let from_start = text.starts_with('+');
    let digits = if from_start {
        text.get(1..).unwrap_or("")
    } else {
        text
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((digits.parse().ok()?, from_start))
}

/// Read exactly `destination.len()` bytes, since one read may be partial.
fn read_exact(
    filesystem: &mut ReadOnlyFilesystem,
    file: filesystem::OpenFile,
    offset: u64,
    destination: &mut [u8],
) -> Result<(), Error> {
    let mut filled = 0;
    while filled < destination.len() {
        let position = u64::try_from(filled)
            .ok()
            .and_then(|filled| offset.checked_add(filled))
            .ok_or(Error::Overflow)?;
        let slice = destination.get_mut(filled..).ok_or(Error::Overflow)?;
        let count = filesystem.read(file, position, slice)?;
        if count == 0 {
            return Err(Error::Corrupt);
        }
        filled += count;
    }
    Ok(())
}

/// Offset of the first byte `tail` emits, found by reading the file backwards.
///
/// Only the bytes actually scanned are read, so the trailing lines of a large
/// file cost their own size rather than the file's.
fn offset_of_last_lines(
    filesystem: &mut ReadOnlyFilesystem,
    file: filesystem::OpenFile,
    lines: u64,
) -> Result<u64, Error> {
    if lines == 0 || file.byte_count == 0 {
        return Ok(file.byte_count);
    }
    let mut scan_end = file.byte_count;
    // A trailing newline terminates the final line rather than starting one.
    let mut probe = [0_u8; 1];
    read_exact(filesystem, file, scan_end - 1, &mut probe)?;
    if probe[0] == b'\n' {
        scan_end -= 1;
    }
    let mut found = 0_u64;
    let mut position = scan_end;
    let mut buffer = [0_u8; CHUNK_BYTES];
    while position != 0 {
        let want =
            usize::try_from(position.min(CHUNK_BYTES as u64)).map_err(|_| Error::Overflow)?;
        let start = position.checked_sub(want as u64).ok_or(Error::Overflow)?;
        let slice = buffer.get_mut(..want).ok_or(Error::Overflow)?;
        read_exact(filesystem, file, start, slice)?;
        for index in (0..want).rev() {
            if slice.get(index).copied() != Some(b'\n') {
                continue;
            }
            found += 1;
            if found == lines {
                let offset = u64::try_from(index).map_err(|_| Error::Overflow)?;
                return start.checked_add(offset + 1).ok_or(Error::Overflow);
            }
        }
        position = start;
    }
    Ok(0)
}

/// Offset of the first byte of one-based `line`, scanning forwards.
fn offset_of_line(
    filesystem: &mut ReadOnlyFilesystem,
    file: filesystem::OpenFile,
    line: u64,
) -> Result<u64, Error> {
    if line <= 1 {
        return Ok(0);
    }
    let mut remaining = line - 1;
    let mut position = 0_u64;
    let mut buffer = [0_u8; CHUNK_BYTES];
    while position < file.byte_count {
        let count = filesystem.read(file, position, &mut buffer)?;
        if count == 0 {
            break;
        }
        let chunk = buffer.get(..count).ok_or(Error::Overflow)?;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            remaining -= 1;
            if remaining == 0 {
                let offset = u64::try_from(index).map_err(|_| Error::Overflow)?;
                return position.checked_add(offset + 1).ok_or(Error::Overflow);
            }
        }
        position = u64::try_from(count)
            .ok()
            .and_then(|count| position.checked_add(count))
            .ok_or(Error::Overflow)?;
    }
    Ok(file.byte_count)
}

fn copy_from(
    filesystem: &mut ReadOnlyFilesystem,
    file: filesystem::OpenFile,
    mut offset: u64,
    output: &mut StandardOutput,
) -> Result<(), Failure> {
    let mut buffer = [0_u8; CHUNK_BYTES];
    while offset < file.byte_count {
        let count = filesystem
            .read(file, offset, &mut buffer)
            .map_err(Failure::Source)?;
        if count == 0 {
            return Ok(());
        }
        let chunk = buffer.get(..count).ok_or(Failure::Output)?;
        output.write_all(chunk).map_err(|_| Failure::Output)?;
        offset = u64::try_from(count)
            .ok()
            .and_then(|count| offset.checked_add(count))
            .ok_or(Failure::Output)?;
    }
    Ok(())
}

fn tail_file(
    filesystem: &mut ReadOnlyFilesystem,
    path: &str,
    selection: Selection,
    output: &mut StandardOutput,
) -> Result<(), Failure> {
    let file = filesystem.open(path).map_err(Failure::Source)?;
    let offset = match (selection.bytes, selection.from_start) {
        // `-c +N` and `-n +N` are one-based positions from the start.
        (true, true) => Ok(selection.count.saturating_sub(1).min(file.byte_count)),
        (true, false) => Ok(file.byte_count.saturating_sub(selection.count)),
        (false, true) => offset_of_line(filesystem, file, selection.count),
        (false, false) => offset_of_last_lines(filesystem, file, selection.count),
    };
    let outcome = match offset {
        Ok(offset) => copy_from(filesystem, file, offset, output),
        Err(error) => Err(Failure::Source(error)),
    };
    let closed = filesystem.close(file);
    outcome?;
    closed.map_err(Failure::Source)
}

/// Fixed trailing window over one non-seekable input.
struct Window {
    bytes: [u8; WINDOW_BYTES],
    start: usize,
    length: usize,
    dropped: bool,
}

impl Window {
    const fn new() -> Self {
        Self {
            bytes: [0; WINDOW_BYTES],
            start: 0,
            length: 0,
            dropped: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        for byte in chunk {
            if self.length == WINDOW_BYTES {
                self.bytes[self.start] = *byte;
                self.start = (self.start + 1) % WINDOW_BYTES;
                self.dropped = true;
            } else {
                let index = (self.start + self.length) % WINDOW_BYTES;
                self.bytes[index] = *byte;
                self.length += 1;
            }
        }
    }

    fn at(&self, index: usize) -> u8 {
        self.bytes[(self.start + index) % WINDOW_BYTES]
    }

    /// Logical index of the first retained byte the selection emits.
    fn first_emitted(&self, selection: Selection) -> Option<usize> {
        if selection.bytes {
            let count = usize::try_from(selection.count).unwrap_or(self.length);
            return Some(self.length.saturating_sub(count));
        }
        if selection.count == 0 || self.length == 0 {
            return Some(self.length);
        }
        let mut scan_end = self.length;
        if self.at(scan_end - 1) == b'\n' {
            scan_end -= 1;
        }
        let mut found = 0_u64;
        for index in (0..scan_end).rev() {
            if self.at(index) != b'\n' {
                continue;
            }
            found += 1;
            if found == selection.count {
                return Some(index + 1);
            }
        }
        // Fewer separators than requested: the window holds the whole tail only
        // if nothing was evicted.
        if self.dropped { None } else { Some(0) }
    }

    fn emit(&self, selection: Selection, output: &mut StandardOutput) -> Result<(), Failure> {
        let Some(first) = self.first_emitted(selection) else {
            return Err(Failure::WindowExceeded);
        };
        let mut index = first;
        let mut chunk = [0_u8; CHUNK_BYTES];
        while index < self.length {
            let take = (self.length - index).min(CHUNK_BYTES);
            let slice = chunk.get_mut(..take).ok_or(Failure::Output)?;
            for (offset, destination) in slice.iter_mut().enumerate() {
                *destination = self.at(index + offset);
            }
            let slice = chunk.get(..take).ok_or(Failure::Output)?;
            output.write_all(slice).map_err(|_| Failure::Output)?;
            index += take;
        }
        Ok(())
    }
}

fn tail_stdin(
    command: &mut CommandContext,
    selection: Selection,
    output: &mut StandardOutput,
) -> Result<(), Failure> {
    let mut input = command.stdin();
    let mut buffer = [0_u8; CHUNK_BYTES];
    if selection.from_start {
        // Counting from the start streams without retaining anything.
        let mut skipped = 0_u64;
        let target = selection.count.saturating_sub(1);
        let mut emitting = target == 0;
        loop {
            let count = input.read(&mut buffer).map_err(Failure::Source)?;
            if count == 0 {
                return Ok(());
            }
            let chunk = buffer.get(..count).ok_or(Failure::Output)?;
            if emitting {
                output.write_all(chunk).map_err(|_| Failure::Output)?;
                continue;
            }
            for (index, byte) in chunk.iter().enumerate() {
                let boundary = if selection.bytes {
                    skipped += 1;
                    skipped >= target
                } else {
                    if *byte == b'\n' {
                        skipped += 1;
                    }
                    skipped >= target
                };
                if boundary {
                    let rest = chunk.get(index + 1..).ok_or(Failure::Output)?;
                    output.write_all(rest).map_err(|_| Failure::Output)?;
                    emitting = true;
                    break;
                }
            }
        }
    }
    let mut window = Window::new();
    loop {
        let count = input.read(&mut buffer).map_err(Failure::Source)?;
        if count == 0 {
            return window.emit(selection, output);
        }
        let chunk = buffer.get(..count).ok_or(Failure::Output)?;
        window.push(chunk);
    }
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
            Some(path) => common::filesystem_failure(&mut command.stderr(), "tail", path, error),
            None => common::stream_read_failure(&mut command.stderr(), "tail", error),
        },
        Failure::Output => common::stream_failure(&mut command.stderr(), "tail"),
        Failure::WindowExceeded => {
            common::report(
                &mut command.stderr(),
                "tail",
                b"requested tail exceeds the 8 KiB window retained for a non-seekable input",
            );
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
    let mut selection = Selection {
        count: DEFAULT_LINES,
        bytes: false,
        from_start: false,
    };
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
        // `tail -5` is the obsolete count form and remains in wide use.
        if let Some((count, from_start)) = parse_count(argument.get(1..).unwrap_or("")) {
            selection = Selection {
                count,
                bytes: false,
                from_start,
            };
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
                    let attached = argument.get(position + 1..).unwrap_or("");
                    if attached.is_empty() {
                        wants_value = Some(option);
                    } else {
                        let Some((count, from_start)) = parse_count(attached) else {
                            return common::usage(&mut command.stderr(), "tail", SYNOPSIS);
                        };
                        selection = Selection {
                            count,
                            bytes: option == b'c',
                            from_start,
                        };
                    }
                    position = argument.len();
                    continue;
                }
                _ => return common::usage(&mut command.stderr(), "tail", SYNOPSIS),
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
                _ => return common::usage(&mut command.stderr(), "tail", SYNOPSIS),
            }
            let Some((count, from_start)) = parse_count(value.as_str()) else {
                return common::usage(&mut command.stderr(), "tail", SYNOPSIS);
            };
            selection = Selection {
                count,
                bytes: option == b'c',
                from_start,
            };
        }
        index += 1;
    }

    if operand_start >= total {
        let mut output = command.stdout();
        if verbose && write_header(&mut output, "standard input", true).is_err() {
            return common::stream_failure(&mut command.stderr(), "tail");
        }
        return match tail_stdin(command, selection, &mut output) {
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
                return common::stream_failure(&mut command.stderr(), "tail");
            }
        }
        first = false;
        let outcome = if path == "-" {
            tail_stdin(command, selection, &mut output)
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
            tail_file(filesystem, path, selection, &mut output)
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

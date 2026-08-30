#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt::{self, Write as _};
use troe_kex_runtime::units::HumanBytes;
use troe_kex_sdk::{
    ArgumentReader, CommandContext, ENVIRONMENT_BUFFER_BYTES, Error, FILESYSTEM_LIST_BUFFER_BYTES,
    ReadOnlyFilesystem, StandardOutput, entry, exit, filesystem,
};

const DEFAULT_COLUMNS: usize = 80;
const MAX_ENTRIES: usize = 1024;

#[derive(Clone, Copy, Default)]
struct Flags {
    long: bool,
    human_readable: bool,
    one_per_line: bool,
    show_all: bool,
    almost_all: bool,
    classify: bool,
    slash_directories: bool,
    directory: bool,
}

#[derive(Clone, Copy)]
struct Options<'path> {
    flags: Flags,
    path: &'path str,
}

struct OutputWriter<'output>(&'output mut StandardOutput);

impl fmt::Write for OutputWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

enum VisitError<CallbackError> {
    Filesystem(Error),
    Callback(CallbackError),
}

#[derive(Clone, Copy)]
enum LongError {
    Filesystem(Error),
    Output,
}

fn parse_options(arguments: &mut ArgumentReader, total: usize) -> Option<(Flags, usize)> {
    let mut flags = Flags::default();
    let mut options = true;
    let mut operand_start = total;
    for index in 1..total {
        let argument = arguments.get(index).ok()??;
        if options && argument == "--" {
            options = false;
            operand_start = index + 1;
            continue;
        }
        if options && argument.starts_with('-') && argument != "-" {
            for option in argument.as_bytes().get(1..)? {
                match option {
                    b'l' => flags.long = true,
                    b'h' => flags.human_readable = true,
                    b'1' => flags.one_per_line = true,
                    b'C' => flags.one_per_line = false,
                    b'a' => flags.show_all = true,
                    b'A' => flags.almost_all = true,
                    b'F' => flags.classify = true,
                    b'p' => flags.slash_directories = true,
                    b'd' => flags.directory = true,
                    _ => return None,
                }
            }
            continue;
        }
        if operand_start == total {
            operand_start = index;
        }
        options = false;
    }
    Some((flags, operand_start))
}

fn terminal_columns(command: &CommandContext) -> usize {
    let mut environment_bytes = [0_u8; ENVIRONMENT_BUFFER_BYTES];
    let Ok(environment) = command.environment(&mut environment_bytes) else {
        return DEFAULT_COLUMNS;
    };
    environment
        .iter()
        .find_map(|entry| {
            entry
                .strip_prefix("COLUMNS=")?
                .parse::<usize>()
                .ok()
                .filter(|columns| *columns != 0)
        })
        .unwrap_or(DEFAULT_COLUMNS)
}

fn visit_entries<CallbackError>(
    filesystem: &mut ReadOnlyFilesystem,
    path: &str,
    mut callback: impl FnMut(
        &mut ReadOnlyFilesystem,
        filesystem::DirectoryEntry<'_>,
    ) -> Result<(), CallbackError>,
) -> Result<(), VisitError<CallbackError>> {
    let mut cursor = 0_u64;
    let mut entries_seen = 0_usize;
    loop {
        let mut buffer = [0_u8; FILESYSTEM_LIST_BUFFER_BYTES];
        let page = filesystem
            .list(
                path,
                cursor,
                filesystem::MAX_LIST_ENTRIES,
                filesystem::MAX_LIST_NAME_BYTES,
                &mut buffer,
            )
            .map_err(VisitError::Filesystem)?;
        for entry in page.entries() {
            entries_seen = entries_seen
                .checked_add(1)
                .ok_or(VisitError::Filesystem(Error::NoSpace))?;
            if entries_seen > MAX_ENTRIES {
                return Err(VisitError::Filesystem(Error::NoSpace));
            }
            callback(filesystem, entry).map_err(VisitError::Callback)?;
        }
        let Some(next) = page.next_cursor() else {
            return Ok(());
        };
        if page.is_empty() && next == cursor {
            return Err(VisitError::Filesystem(Error::Corrupt));
        }
        cursor = next;
    }
}

fn visible(flags: Flags, entry: filesystem::DirectoryEntry<'_>) -> bool {
    flags.show_all
        || (flags.almost_all && !matches!(entry.name, "." | ".."))
        || !entry.name.starts_with('.')
}

fn suffix(kind: filesystem::NodeKind, flags: Flags) -> Option<u8> {
    match kind {
        filesystem::NodeKind::Directory if flags.classify || flags.slash_directories => Some(b'/'),
        filesystem::NodeKind::Symlink if flags.classify => Some(b'@'),
        filesystem::NodeKind::File
        | filesystem::NodeKind::Directory
        | filesystem::NodeKind::Symlink => None,
    }
}

fn entry_width(entry: filesystem::DirectoryEntry<'_>, flags: Flags) -> usize {
    entry.name.chars().count() + usize::from(suffix(entry.kind, flags).is_some())
}

fn write_name(
    output: &mut StandardOutput,
    entry: filesystem::DirectoryEntry<'_>,
    flags: Flags,
) -> fmt::Result {
    let mut output = OutputWriter(output);
    output.write_str(entry.name)?;
    if let Some(suffix) = suffix(entry.kind, flags) {
        output.write_char(char::from(suffix))?;
    }
    Ok(())
}

fn child_path<'buffer>(
    directory: &str,
    name: &str,
    buffer: &'buffer mut [u8; filesystem::MAX_PATH_BYTES],
) -> Result<&'buffer str, Error> {
    let separator = usize::from(!directory.ends_with('/'));
    let length = directory
        .len()
        .checked_add(separator)
        .and_then(|length| length.checked_add(name.len()))
        .ok_or(Error::NoSpace)?;
    if length > buffer.len() {
        return Err(Error::NoSpace);
    }
    let mut cursor = directory.len();
    buffer[..cursor].copy_from_slice(directory.as_bytes());
    if separator != 0 {
        buffer[cursor] = b'/';
        cursor += 1;
    }
    buffer[cursor..length].copy_from_slice(name.as_bytes());
    core::str::from_utf8(&buffer[..length]).map_err(|_| Error::Corrupt)
}

fn decimal_width(mut value: u64) -> usize {
    let mut width = 1;
    while value >= 10 {
        value /= 10;
        width += 1;
    }
    width
}

fn size_width(bytes: u64, human_readable: bool) -> usize {
    if !human_readable {
        return decimal_width(bytes);
    }
    HumanBytes::new(bytes)
        .with_maximum_fraction_digits(1)
        .display_width()
}

fn write_size(output: &mut StandardOutput, bytes: u64, human_readable: bool) -> fmt::Result {
    let mut output = OutputWriter(output);
    if !human_readable {
        return write!(output, "{bytes}");
    }
    write!(
        output,
        "{}",
        HumanBytes::new(bytes).with_maximum_fraction_digits(1)
    )
}

fn metadata_for_entry(
    filesystem: &mut ReadOnlyFilesystem,
    path: &str,
    entry: filesystem::DirectoryEntry<'_>,
) -> Result<filesystem::Metadata, Error> {
    let mut child = [0_u8; filesystem::MAX_PATH_BYTES];
    let metadata = filesystem.metadata_no_follow(child_path(path, entry.name, &mut child)?)?;
    if metadata.kind != entry.kind {
        return Err(Error::Corrupt);
    }
    Ok(metadata)
}

fn list_columns(
    filesystem: &mut ReadOnlyFilesystem,
    output: &mut StandardOutput,
    options: Options<'_>,
    columns: usize,
) -> Result<(), VisitError<()>> {
    let mut column = 0_usize;
    let mut any = false;
    visit_entries(filesystem, options.path, |_, entry| {
        if !visible(options.flags, entry) {
            return Ok(());
        }
        let width = entry_width(entry, options.flags);
        if options.flags.one_per_line {
            write_name(output, entry, options.flags).map_err(|_| ())?;
            output.write_all(b"\n").map_err(|_| ())?;
        } else {
            let separator = usize::from(any) * 2;
            if any && column.saturating_add(separator).saturating_add(width) > columns {
                output.write_all(b"\n").map_err(|_| ())?;
                column = 0;
            } else if any {
                output.write_all(b"  ").map_err(|_| ())?;
                column = column.saturating_add(2);
            }
            write_name(output, entry, options.flags).map_err(|_| ())?;
            column = column.saturating_add(width);
        }
        any = true;
        Ok(())
    })?;
    if any && !options.flags.one_per_line {
        output
            .write_all(b"\n")
            .map_err(|_| VisitError::Callback(()))?;
    }
    Ok(())
}

fn list_long(
    filesystem: &mut ReadOnlyFilesystem,
    output: &mut StandardOutput,
    options: Options<'_>,
) -> Result<(), VisitError<LongError>> {
    let mut maximum_size_width = 1_usize;
    visit_entries(filesystem, options.path, |filesystem, entry| {
        if !visible(options.flags, entry) {
            return Ok(());
        }
        let metadata = metadata_for_entry(filesystem, options.path, entry)?;
        maximum_size_width = maximum_size_width.max(size_width(
            metadata.byte_count,
            options.flags.human_readable,
        ));
        Ok::<(), Error>(())
    })
    .map_err(|error| match error {
        VisitError::Filesystem(error) | VisitError::Callback(error) => {
            VisitError::Callback(LongError::Filesystem(error))
        }
    })?;

    visit_entries(filesystem, options.path, |filesystem, entry| {
        if !visible(options.flags, entry) {
            return Ok(());
        }
        let metadata =
            metadata_for_entry(filesystem, options.path, entry).map_err(LongError::Filesystem)?;
        let marker = match metadata.kind {
            filesystem::NodeKind::File => b'-',
            filesystem::NodeKind::Directory => b'd',
            filesystem::NodeKind::Symlink => b'l',
        };
        output.write_all(&[marker]).map_err(|_| LongError::Output)?;
        output.write_all(b" ").map_err(|_| LongError::Output)?;
        for _ in size_width(metadata.byte_count, options.flags.human_readable)..maximum_size_width {
            output.write_all(b" ").map_err(|_| LongError::Output)?;
        }
        write_size(output, metadata.byte_count, options.flags.human_readable)
            .map_err(|_| LongError::Output)?;
        output.write_all(b" ").map_err(|_| LongError::Output)?;
        write_name(output, entry, options.flags).map_err(|_| LongError::Output)?;
        output.write_all(b"\n").map_err(|_| LongError::Output)
    })
}

fn write_operand(
    output: &mut StandardOutput,
    path: &str,
    metadata: filesystem::Metadata,
    flags: Flags,
) -> Result<(), ()> {
    if flags.long {
        let marker = match metadata.kind {
            filesystem::NodeKind::File => b'-',
            filesystem::NodeKind::Directory => b'd',
            filesystem::NodeKind::Symlink => b'l',
        };
        output.write_all(&[marker]).map_err(|_| ())?;
        output.write_all(b" ").map_err(|_| ())?;
        write_size(output, metadata.byte_count, flags.human_readable).map_err(|_| ())?;
        output.write_all(b" ").map_err(|_| ())?;
    }
    let mut writer = OutputWriter(output);
    writer.write_str(path).map_err(|_| ())?;
    if let Some(suffix) = suffix(metadata.kind, flags) {
        writer.write_char(char::from(suffix)).map_err(|_| ())?;
    }
    writer.write_char('\n').map_err(|_| ())
}

fn list_directory(
    filesystem: &mut ReadOnlyFilesystem,
    output: &mut StandardOutput,
    options: Options<'_>,
    columns: usize,
) -> Result<(), LongError> {
    if options.flags.long {
        list_long(filesystem, output, options).map_err(|error| match error {
            VisitError::Filesystem(error) | VisitError::Callback(LongError::Filesystem(error)) => {
                LongError::Filesystem(error)
            }
            VisitError::Callback(LongError::Output) => LongError::Output,
        })
    } else {
        list_columns(filesystem, output, options, columns).map_err(|error| match error {
            VisitError::Filesystem(error) => LongError::Filesystem(error),
            VisitError::Callback(()) => LongError::Output,
        })
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let Ok(total) = arguments.total() else {
        return exit::FAILURE;
    };
    let Some((flags, operand_start)) = parse_options(&mut arguments, total) else {
        return common::usage(&mut command.stderr(), "ls", b"ls [-1ACFadhlp] [PATH...]");
    };
    let columns = terminal_columns(command);
    let Ok(mut filesystem) = command.filesystem() else {
        return exit::DENIED;
    };
    let mut output = command.stdout();
    let operand_count = total.saturating_sub(operand_start).max(1);
    if arguments.seek(operand_start).is_err() {
        return exit::FAILURE;
    }
    for operand_index in 0..operand_count {
        let path = if operand_start == total {
            "."
        } else {
            match arguments.next_argument() {
                Ok(Some(path)) => path,
                Ok(None) => return exit::FAILURE,
                Err(_) => return exit::FAILURE,
            }
        };
        let metadata = match filesystem.metadata_no_follow(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return common::filesystem_failure(&mut command.stderr(), "ls", path, error);
            }
        };
        let list_contents = metadata.kind == filesystem::NodeKind::Directory && !flags.directory;
        if operand_count > 1 {
            if operand_index != 0 && output.write_all(b"\n").is_err() {
                return common::stream_failure(&mut command.stderr(), "ls");
            }
            if list_contents {
                let mut writer = OutputWriter(&mut output);
                if writeln!(writer, "{path}:").is_err() {
                    return common::stream_failure(&mut command.stderr(), "ls");
                }
            }
        }
        let result = if list_contents {
            list_directory(
                &mut filesystem,
                &mut output,
                Options { flags, path },
                columns,
            )
        } else {
            write_operand(&mut output, path, metadata, flags).map_err(|()| LongError::Output)
        };
        match result {
            Ok(()) => {}
            Err(LongError::Filesystem(error)) => {
                return common::filesystem_failure(&mut command.stderr(), "ls", path, error);
            }
            Err(LongError::Output) => {
                return common::stream_failure(&mut command.stderr(), "ls");
            }
        }
    }
    exit::SUCCESS
}

entry!(main);

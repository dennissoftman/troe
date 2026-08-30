#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt::Write as _;
use core::str;
use troe_app_grep::{Program, RegexError, Syntax};
use troe_kex_sdk::{
    ArgumentReader, CommandContext, Error, ReadOnlyFilesystem, StandardOutput, entry, exit,
};

const LINE_BYTES: usize = 64 * 1024;
const MAX_PATTERNS: usize = 16;
const PATTERN_ARENA_BYTES: usize = 4096;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ListMode {
    Matching,
    NonMatching,
}

#[derive(Clone, Copy)]
struct Options {
    syntax: Syntax,
    ignore_case: bool,
    invert: bool,
    line_numbers: bool,
    byte_offsets: bool,
    count: bool,
    quiet: bool,
    suppress_errors: bool,
    only_matching: bool,
    whole_line: bool,
    whole_word: bool,
    show_filename: Option<bool>,
    list: Option<ListMode>,
    max_count: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            syntax: Syntax::Basic,
            ignore_case: false,
            invert: false,
            line_numbers: false,
            byte_offsets: false,
            count: false,
            quiet: false,
            suppress_errors: false,
            only_matching: false,
            whole_line: false,
            whole_word: false,
            show_filename: None,
            list: None,
            max_count: None,
        }
    }
}

struct Parsed {
    options: Options,
    operand_start: usize,
}

/// Owned copies of every pattern written on the command line.
///
/// Patterns are read through the paged argument reader, whose single page
/// buffer stops borrowing as soon as another page loads, so each pattern is
/// copied out before parsing continues.
struct PatternArena {
    bytes: [u8; PATTERN_ARENA_BYTES],
    spans: [(usize, usize); MAX_PATTERNS],
    count: usize,
    used: usize,
}

impl PatternArena {
    const fn new() -> Self {
        Self {
            bytes: [0; PATTERN_ARENA_BYTES],
            spans: [(0, 0); MAX_PATTERNS],
            count: 0,
            used: 0,
        }
    }

    /// Retain one pattern, rejecting excess count or aggregate bytes.
    fn push(&mut self, value: &str) -> Option<()> {
        let end = self.used.checked_add(value.len())?;
        if self.count == MAX_PATTERNS || end > self.bytes.len() {
            return None;
        }
        self.bytes[self.used..end].copy_from_slice(value.as_bytes());
        self.spans[self.count] = (self.used, end);
        self.count += 1;
        self.used = end;
        Some(())
    }

    /// Visit every retained pattern in the order it was written.
    fn iter(&self) -> impl Iterator<Item = &str> {
        self.spans[..self.count]
            .iter()
            .filter_map(|(start, end)| str::from_utf8(&self.bytes[*start..*end]).ok())
    }
}

enum GrepError {
    LineTooLong,
    Regex(RegexError),
    Input,
    Output,
    Cancelled,
}

enum FileGrepError {
    Filesystem(Error),
    Matcher(GrepError),
}

impl From<Error> for FileGrepError {
    fn from(error: Error) -> Self {
        Self::Filesystem(error)
    }
}

struct Matcher<'program, 'label, 'line> {
    program: &'program Program,
    options: Options,
    label: Option<&'label str>,
    line: &'line mut [u8; LINE_BYTES],
    line_bytes: usize,
    line_number: u64,
    line_offset: u64,
    match_count: u64,
    matched: bool,
    output: StandardOutput,
}

impl<'program, 'label, 'line> Matcher<'program, 'label, 'line> {
    fn new(
        program: &'program Program,
        options: Options,
        label: Option<&'label str>,
        line: &'line mut [u8; LINE_BYTES],
        output: StandardOutput,
    ) -> Self {
        Self {
            program,
            options,
            label,
            line,
            line_bytes: 0,
            line_number: 1,
            line_offset: 0,
            match_count: 0,
            matched: false,
            output,
        }
    }

    fn should_stop(&self) -> bool {
        self.options.max_count == Some(0)
            || (self.options.quiet && self.matched)
            || (self.options.list.is_some() && self.matched)
            || self
                .options
                .max_count
                .is_some_and(|maximum| self.match_count >= maximum)
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<bool, GrepError> {
        for byte in bytes {
            if self.line_bytes >= self.line.len() {
                return Err(GrepError::LineTooLong);
            }
            self.line[self.line_bytes] = *byte;
            self.line_bytes += 1;
            if *byte == b'\n' {
                self.emit_line(false)?;
                if self.should_stop() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn finish(&mut self) -> Result<(), GrepError> {
        if self.line_bytes != 0 && !self.should_stop() {
            self.emit_line(true)?;
        }
        if self.options.count && !self.options.quiet && self.options.list.is_none() {
            let mut writer = common::OutputWriter(&mut self.output);
            if let Some(label) = self.label {
                write!(writer, "{label}:").map_err(|_| GrepError::Output)?;
            }
            writeln!(writer, "{}", self.match_count).map_err(|_| GrepError::Output)?;
        }
        Ok(())
    }

    fn emit_line(&mut self, add_newline: bool) -> Result<(), GrepError> {
        let complete_line = &self.line[..self.line_bytes];
        let subject = complete_line.strip_suffix(b"\n").unwrap_or(complete_line);
        let first = self
            .program
            .find(
                subject,
                0,
                self.options.ignore_case,
                self.options.whole_line,
                self.options.whole_word,
            )
            .map_err(GrepError::Regex)?;
        let selected = first.is_some() != self.options.invert;
        if selected {
            self.matched = true;
            self.match_count = self
                .match_count
                .checked_add(1)
                .ok_or(GrepError::LineTooLong)?;
            if !self.options.quiet && self.options.list.is_none() && !self.options.count {
                if self.options.only_matching && !self.options.invert {
                    write_matches(
                        self.program,
                        self.options,
                        self.label,
                        self.line_number,
                        self.line_offset,
                        &mut self.output,
                        subject,
                        first,
                    )?;
                } else {
                    write_prefix(
                        &mut self.output,
                        self.options,
                        self.label,
                        self.line_number,
                        self.line_offset,
                    )?;
                    self.output
                        .write_all(complete_line)
                        .map_err(|_| GrepError::Output)?;
                    if add_newline && !complete_line.ends_with(b"\n") {
                        self.output
                            .write_all(b"\n")
                            .map_err(|_| GrepError::Output)?;
                    }
                }
            }
        }
        self.line_number = self
            .line_number
            .checked_add(1)
            .ok_or(GrepError::LineTooLong)?;
        self.line_offset = self
            .line_offset
            .checked_add(u64::try_from(self.line_bytes).map_err(|_| GrepError::LineTooLong)?)
            .ok_or(GrepError::LineTooLong)?;
        self.line_bytes = 0;
        Ok(())
    }
}

fn write_matches(
    program: &Program,
    options: Options,
    label: Option<&str>,
    line_number: u64,
    line_offset: u64,
    output: &mut StandardOutput,
    subject: &[u8],
    first: Option<core::ops::Range<usize>>,
) -> Result<(), GrepError> {
    let mut matched = first;
    while let Some(range) = matched {
        if range.start != range.end {
            let offset = line_offset
                .checked_add(u64::try_from(range.start).map_err(|_| GrepError::LineTooLong)?)
                .ok_or(GrepError::LineTooLong)?;
            write_prefix(output, options, label, line_number, offset)?;
            output
                .write_all(&subject[range.clone()])
                .map_err(|_| GrepError::Output)?;
            output.write_all(b"\n").map_err(|_| GrepError::Output)?;
        }
        let next = if range.end > range.start {
            range.end
        } else {
            range.end.saturating_add(1)
        };
        if next > subject.len() {
            break;
        }
        matched = program
            .find(
                subject,
                next,
                options.ignore_case,
                options.whole_line,
                options.whole_word,
            )
            .map_err(GrepError::Regex)?;
    }
    Ok(())
}

fn write_prefix(
    output: &mut StandardOutput,
    options: Options,
    label: Option<&str>,
    line_number: u64,
    byte_offset: u64,
) -> Result<(), GrepError> {
    let mut writer = common::OutputWriter(output);
    if let Some(label) = label {
        write!(writer, "{label}:").map_err(|_| GrepError::Output)?;
    }
    if options.line_numbers {
        write!(writer, "{line_number}:").map_err(|_| GrepError::Output)?;
    }
    if options.byte_offsets {
        write!(writer, "{byte_offset}:").map_err(|_| GrepError::Output)?;
    }
    Ok(())
}

fn parse(
    arguments: &mut ArgumentReader,
    total: usize,
    patterns: &mut PatternArena,
) -> Option<Parsed> {
    let mut options = Options::default();
    let mut index = 1_usize;
    // The current argument is copied out before it is scanned, so a `-e` or
    // `-m` value that lives in a later page can be fetched mid-scan.
    let mut current = common::ArgumentBuffer::new();
    while index < total {
        current.set(arguments.get(index).ok()??).ok()?;
        let argument = current.as_str();
        if argument == "--" {
            index += 1;
            break;
        }
        if argument == "-" || !argument.starts_with('-') {
            break;
        }
        let mut cursor = 1_usize;
        while cursor < argument.len() {
            let byte = *argument.as_bytes().get(cursor)?;
            match byte {
                b'E' => options.syntax = Syntax::Extended,
                b'F' => options.syntax = Syntax::Fixed,
                b'G' => options.syntax = Syntax::Basic,
                b'i' => options.ignore_case = true,
                b'v' => options.invert = true,
                b'n' => options.line_numbers = true,
                b'b' => options.byte_offsets = true,
                b'c' => options.count = true,
                b'q' => options.quiet = true,
                b's' => options.suppress_errors = true,
                b'o' => options.only_matching = true,
                b'x' => options.whole_line = true,
                b'w' => options.whole_word = true,
                b'h' => options.show_filename = Some(false),
                b'H' => options.show_filename = Some(true),
                b'l' => options.list = Some(ListMode::Matching),
                b'L' => options.list = Some(ListMode::NonMatching),
                b'e' | b'm' => {
                    // The attached form is a slice of the same argument, so the
                    // value is taken before any further page may be loaded.
                    let attached = argument.get(cursor + 1..).filter(|value| !value.is_empty());
                    match attached {
                        Some(value) => {
                            if byte == b'e' {
                                patterns.push(value)?;
                            } else {
                                options.max_count = Some(value.parse().ok()?);
                            }
                        }
                        None => {
                            index += 1;
                            let value = arguments.get(index).ok()??;
                            if byte == b'e' {
                                patterns.push(value)?;
                            } else {
                                options.max_count = Some(value.parse().ok()?);
                            }
                        }
                    }
                    cursor = argument.len();
                    continue;
                }
                _ => return None,
            }
            cursor += 1;
        }
        index += 1;
    }
    if patterns.count == 0 {
        let value = arguments.get(index).ok()??;
        patterns.push(value)?;
        index += 1;
    }
    Some(Parsed {
        options,
        operand_start: index,
    })
}

fn matcher_failure(command: &mut CommandContext, error: GrepError) -> u32 {
    match error {
        GrepError::LineTooLong => {
            common::report(
                &mut command.stderr(),
                "grep",
                b"line or count exceeds command capacity",
            );
            exit::FAILURE
        }
        GrepError::Regex(RegexError::MatchLimit) => {
            common::report(
                &mut command.stderr(),
                "grep",
                b"match complexity limit exceeded",
            );
            exit::FAILURE
        }
        GrepError::Regex(RegexError::Invalid | RegexError::TooComplex) => {
            common::report(
                &mut command.stderr(),
                "grep",
                b"invalid or excessive pattern",
            );
            exit::USAGE
        }
        GrepError::Input | GrepError::Output => {
            common::stream_failure(&mut command.stderr(), "grep")
        }
        GrepError::Cancelled => {
            common::report(&mut command.stderr(), "grep", b"cancelled");
            exit::CANCELLED
        }
    }
}

fn grep_input(
    command: &mut CommandContext,
    program: &Program,
    options: Options,
    label: Option<&str>,
) -> Result<bool, GrepError> {
    let mut input = command.stdin();
    let mut line = [0_u8; LINE_BYTES];
    let mut matcher = Matcher::new(program, options, label, &mut line, command.stdout());
    if !matcher.should_stop() {
        let mut buffer = [0_u8; 256];
        loop {
            let count = input.read(&mut buffer).map_err(|error| {
                if error == Error::Cancelled {
                    GrepError::Cancelled
                } else {
                    GrepError::Input
                }
            })?;
            if count == 0 || matcher.feed(&buffer[..count])? {
                break;
            }
        }
    }
    matcher.finish()?;
    Ok(matcher.matched)
}

fn grep_file(
    filesystem: &mut ReadOnlyFilesystem,
    output: StandardOutput,
    program: &Program,
    options: Options,
    label: Option<&str>,
    path: &str,
) -> Result<bool, FileGrepError> {
    let file = filesystem.open(path)?;
    if file.byte_count > common::COMMAND_BYTES {
        let _ignored = filesystem.close(file);
        return Err(FileGrepError::Filesystem(Error::NoSpace));
    }
    let mut line = [0_u8; LINE_BYTES];
    let mut matcher = Matcher::new(program, options, label, &mut line, output);
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 256];
    while offset < file.byte_count && !matcher.should_stop() {
        let count = match filesystem.read(file, offset, &mut buffer) {
            Ok(0) => {
                let _ignored = filesystem.close(file);
                return Err(FileGrepError::Filesystem(Error::Corrupt));
            }
            Ok(count) => count,
            Err(error) => {
                let _ignored = filesystem.close(file);
                return Err(FileGrepError::Filesystem(error));
            }
        };
        if let Err(error) = matcher.feed(&buffer[..count]) {
            let _ignored = filesystem.close(file);
            return Err(FileGrepError::Matcher(error));
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or(FileGrepError::Filesystem(Error::Overflow))?;
    }
    if let Err(error) = matcher.finish() {
        let _ignored = filesystem.close(file);
        return Err(FileGrepError::Matcher(error));
    }
    filesystem.close(file)?;
    Ok(matcher.matched)
}

fn write_list_result(
    output: &mut StandardOutput,
    options: Options,
    name: &str,
    matched: bool,
) -> Result<(), GrepError> {
    let selected = matches!(options.list, Some(ListMode::Matching)) && matched
        || matches!(options.list, Some(ListMode::NonMatching)) && !matched;
    if selected && !options.quiet {
        output
            .write_all(name.as_bytes())
            .and_then(|()| output.write_all(b"\n"))
            .map_err(|_| GrepError::Output)?;
    }
    Ok(())
}

fn status_selected(options: Options, matched: bool) -> bool {
    match options.list {
        Some(ListMode::Matching) => matched,
        Some(ListMode::NonMatching) => !matched,
        None => matched,
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let Ok(mut arguments) = command.arguments() else {
        return exit::FAILURE;
    };
    let Ok(argument_count) = arguments.total() else {
        return exit::FAILURE;
    };
    let mut patterns = PatternArena::new();
    let Some(parsed) = parse(&mut arguments, argument_count, &mut patterns) else {
        return common::usage(
            &mut command.stderr(),
            "grep",
            b"grep [-EFGivnbcqsowxhHlL] [-e PATTERN] [-m NUM] [PATTERN] [FILE...]",
        );
    };
    let mut program = Program::new();
    for pattern in patterns.iter() {
        if let Err(error) = program.add(pattern, parsed.options.syntax) {
            return matcher_failure(command, GrepError::Regex(error));
        }
    }
    if let Err(error) = program.finish() {
        return matcher_failure(command, GrepError::Regex(error));
    }

    if parsed.operand_start == argument_count {
        let result = grep_input(
            command,
            &program,
            parsed.options,
            parsed
                .options
                .show_filename
                .and_then(|show| show.then_some("(standard input)")),
        );
        return match result {
            Ok(matched) => {
                if let Err(error) = write_list_result(
                    &mut command.stdout(),
                    parsed.options,
                    "(standard input)",
                    matched,
                ) {
                    matcher_failure(command, error)
                } else if status_selected(parsed.options, matched) {
                    exit::SUCCESS
                } else {
                    exit::FAILURE
                }
            }
            Err(error) => matcher_failure(command, error),
        };
    }

    let operand_count = argument_count - parsed.operand_start;
    // The read capability is acquired on the first named operand rather than
    // pre-scanned, so an operand list of any length costs one pass.
    let mut filesystem: Option<ReadOnlyFilesystem> = None;
    let mut selected_any = false;
    let mut failure_status = None;
    if arguments.seek(parsed.operand_start).is_err() {
        return exit::FAILURE;
    }
    loop {
        let path = match arguments.next_argument() {
            Ok(Some(path)) => path,
            Ok(None) => break,
            Err(_) => return exit::FAILURE,
        };
        let show_filename = parsed.options.show_filename.unwrap_or(operand_count > 1);
        let label = show_filename.then_some(path);
        let result = if path == "-" {
            grep_input(command, &program, parsed.options, label).map_err(FileGrepError::Matcher)
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
            grep_file(
                filesystem,
                command.stdout(),
                &program,
                parsed.options,
                label,
                path,
            )
        };
        match result {
            Ok(matched) => {
                selected_any |= status_selected(parsed.options, matched);
                let list_name = if path == "-" {
                    "(standard input)"
                } else {
                    path
                };
                if let Err(error) =
                    write_list_result(&mut command.stdout(), parsed.options, list_name, matched)
                {
                    return matcher_failure(command, error);
                }
            }
            Err(FileGrepError::Matcher(error)) => return matcher_failure(command, error),
            Err(FileGrepError::Filesystem(error)) => {
                if !parsed.options.suppress_errors {
                    failure_status = Some(common::filesystem_failure(
                        &mut command.stderr(),
                        "grep",
                        path,
                        error,
                    ));
                } else {
                    failure_status = Some(exit::FAILURE);
                }
            }
        }
        if parsed.options.quiet && selected_any {
            return exit::SUCCESS;
        }
    }
    if let Some(status) = failure_status {
        status
    } else if selected_any {
        exit::SUCCESS
    } else {
        exit::FAILURE
    }
}

entry!(main);

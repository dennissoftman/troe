//! Bounded shell grammar, byte-stream pipelines, and statically linked commands.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use kllm_core::{
    BoundedOutput, CommandStatus, Input, MAX_ARGS, MAX_LINE_BYTES, MAX_PIPELINE_STAGES,
    MachineMemoryOwner, MachineMemorySnapshot, Output, PIPE_CAPACITY, SliceInput, StreamError,
    write_all,
};
use kllm_vfs::{FsError, Namespace, NodeKind};

/// Shell parse failures caused by untrusted command input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The configured line bound was exceeded.
    LineTooLong,
    /// A single command contains too many arguments.
    TooManyArguments,
    /// A pipeline contains too many stages.
    TooManyStages,
    /// A quote was not closed.
    UnclosedQuote,
    /// A pipeline begins, ends, or contains two adjacent separators.
    EmptyStage,
}

/// One parsed command invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stage {
    /// Command name followed by its arguments.
    pub words: Vec<String>,
}

/// A bounded sequence of commands connected by byte streams.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Pipeline {
    /// Parsed stages, in execution order.
    pub stages: Vec<Stage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Quote {
    None,
    Single,
    Double,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommandSpec {
    name: &'static str,
    synopsis: &'static str,
    requires_machine_control: bool,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "cat",
        synopsis: "cat [FILE...]",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "cd",
        synopsis: "cd PATH",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "clear",
        synopsis: "clear",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "echo",
        synopsis: "echo [ARG...]",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "grep",
        synopsis: "grep PATTERN [FILE...]",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "halt",
        synopsis: "halt",
        requires_machine_control: true,
    },
    CommandSpec {
        name: "help",
        synopsis: "help [COMMAND]",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "hexdump",
        synopsis: "hexdump [FILE]",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "ls",
        synopsis: "ls [PATH]",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "mem",
        synopsis: "mem",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "pwd",
        synopsis: "pwd",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "rm",
        synopsis: "rm FILE",
        requires_machine_control: false,
    },
    CommandSpec {
        name: "write",
        synopsis: "write FILE [TEXT...]",
        requires_machine_control: false,
    },
];

/// Parse quoting and `|` separators without expansion or recursion.
///
/// # Errors
///
/// Fails on configured line/word/stage bounds, malformed quotes, or empty stages.
pub fn parse_line(line: &str) -> Result<Pipeline, ParseError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(ParseError::LineTooLong);
    }
    let mut stages = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut word_started = false;
    let mut quote = Quote::None;

    for character in line.chars() {
        match quote {
            Quote::Single => {
                if character == '\'' {
                    quote = Quote::None;
                } else {
                    word.push(character);
                }
            }
            Quote::Double => {
                if character == '"' {
                    quote = Quote::None;
                } else {
                    word.push(character);
                }
            }
            Quote::None => match character {
                '\'' => {
                    quote = Quote::Single;
                    word_started = true;
                }
                '"' => {
                    quote = Quote::Double;
                    word_started = true;
                }
                '|' => {
                    push_word(&mut words, &mut word, &mut word_started)?;
                    if words.is_empty() {
                        return Err(ParseError::EmptyStage);
                    }
                    stages.push(Stage { words });
                    if stages.len() >= MAX_PIPELINE_STAGES {
                        return Err(ParseError::TooManyStages);
                    }
                    words = Vec::new();
                }
                value if value.is_whitespace() => {
                    push_word(&mut words, &mut word, &mut word_started)?;
                }
                value => {
                    word.push(value);
                    word_started = true;
                }
            },
        }
    }
    if quote != Quote::None {
        return Err(ParseError::UnclosedQuote);
    }
    push_word(&mut words, &mut word, &mut word_started)?;
    if words.is_empty() {
        if stages.is_empty() {
            return Ok(Pipeline::default());
        }
        return Err(ParseError::EmptyStage);
    }
    stages.push(Stage { words });
    Ok(Pipeline { stages })
}

fn push_word(
    words: &mut Vec<String>,
    word: &mut String,
    started: &mut bool,
) -> Result<(), ParseError> {
    if *started {
        if words.len() >= MAX_ARGS {
            return Err(ParseError::TooManyArguments);
        }
        words.push(core::mem::take(word));
        *started = false;
    }
    Ok(())
}

/// Stateful shell composition root. Authority is explicit in its fields.
#[derive(Debug)]
pub struct Shell {
    namespace: Namespace,
    cwd: String,
    architecture: String,
    machine_memory: MachineMemorySnapshot,
    machine_control: bool,
    halt_requested: bool,
}

impl Shell {
    /// Construct a shell and its generated system nodes.
    ///
    /// # Errors
    ///
    /// Fails if the supplied namespace cannot accept the required `/sys` nodes.
    pub fn new(
        mut namespace: Namespace,
        architecture: &str,
        machine_memory: MachineMemorySnapshot,
        machine_control: bool,
    ) -> Result<Self, FsError> {
        namespace.set_system_file("/sys/arch", format!("{architecture}\n").as_bytes())?;
        namespace.set_system_file("/sys/version", b"kllm 0.1.0\n")?;
        let mut shell = Self {
            namespace,
            cwd: "/".to_string(),
            architecture: architecture.to_string(),
            machine_memory,
            machine_control,
            halt_requested: false,
        };
        shell.refresh_memory_node()?;
        Ok(shell)
    }

    /// Whether an authorized `halt` command completed.
    #[must_use]
    pub const fn halt_requested(&self) -> bool {
        self.halt_requested
    }

    /// Current logical directory.
    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Replace the machine-accounting snapshot used by `mem` and `/sys/memory`.
    pub const fn set_machine_memory(&mut self, snapshot: MachineMemorySnapshot) {
        self.machine_memory = snapshot;
    }

    /// Execute a complete line, including any bounded pipeline.
    pub fn execute(
        &mut self,
        line: &str,
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        let pipeline = match parse_line(line) {
            Ok(value) => value,
            Err(error) => {
                let _ignored = write_error(stderr, "parse", parse_error_text(error));
                return CommandStatus::Usage;
            }
        };
        if pipeline.stages.is_empty() {
            return CommandStatus::Success;
        }

        let mut previous = Vec::new();
        for (index, stage) in pipeline.stages.iter().enumerate() {
            let last = index + 1 == pipeline.stages.len();
            if last {
                let status = if index == 0 {
                    self.dispatch(&stage.words, stdin, stdout, stderr)
                } else {
                    let mut input = SliceInput::new(&previous);
                    self.dispatch(&stage.words, &mut input, stdout, stderr)
                };
                return status;
            }

            let mut next = BoundedOutput::new(PIPE_CAPACITY);
            let status = if index == 0 {
                self.dispatch(&stage.words, stdin, &mut next, stderr)
            } else {
                let mut input = SliceInput::new(&previous);
                self.dispatch(&stage.words, &mut input, &mut next, stderr)
            };
            if status != CommandStatus::Success {
                return status;
            }
            previous = next.into_vec();
        }
        CommandStatus::Failure
    }

    fn dispatch(
        &mut self,
        words: &[String],
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        let Some(command) = words.first().map(String::as_str) else {
            return CommandStatus::Success;
        };
        let args = &words[1..];
        match command {
            "cat" => self.command_cat(args, stdin, stdout, stderr),
            "echo" => command_echo(args, stdout, stderr),
            "grep" => self.command_grep(args, stdin, stdout, stderr),
            "ls" => self.command_ls(args, stdout, stderr),
            "pwd" => self.command_pwd(args, stdout, stderr),
            "cd" => self.command_cd(args, stderr),
            "help" => command_help(args, stdout, stderr),
            "mem" => self.command_mem(args, stdout, stderr),
            "clear" => command_clear(args, stdout, stderr),
            "halt" => self.command_halt(args, stderr),
            "write" => self.command_write(args, stdin, stderr),
            "rm" => self.command_rm(args, stderr),
            "hexdump" => self.command_hexdump(args, stdin, stdout, stderr),
            _ => {
                let _ignored = write_error(stderr, command, "unknown command");
                CommandStatus::NotFound
            }
        }
    }

    fn command_cat(
        &mut self,
        args: &[String],
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        if self.refresh_memory_node().is_err() {
            return fs_failure(stderr, "cat", "/sys/memory", FsError::Invalid);
        }
        if args.is_empty() {
            return copy_stream(stdin, stdout, stderr, "cat");
        }
        for path in args {
            let bytes = match self.namespace.read_file(&self.cwd, path) {
                Ok(value) => value,
                Err(error) => return fs_failure(stderr, "cat", path, error),
            };
            if write_all(stdout, bytes).is_err() {
                let _ignored = write_error(stderr, "cat", "output failed");
                return CommandStatus::Failure;
            }
        }
        CommandStatus::Success
    }

    fn command_grep(
        &self,
        args: &[String],
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        let Some(pattern) = args.first() else {
            return usage(stderr, "grep", "grep PATTERN [FILE...]");
        };
        if args.len() == 1 {
            return grep_stream(stdin, pattern.as_bytes(), stdout, stderr);
        }
        for path in &args[1..] {
            let bytes = match self.namespace.read_file(&self.cwd, path) {
                Ok(value) => value,
                Err(error) => return fs_failure(stderr, "grep", path, error),
            };
            let mut input = SliceInput::with_max_chunk(bytes, 17);
            let status = grep_stream(&mut input, pattern.as_bytes(), stdout, stderr);
            if status != CommandStatus::Success {
                return status;
            }
        }
        CommandStatus::Success
    }

    fn command_ls(
        &self,
        args: &[String],
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        if args.len() > 1 {
            return usage(stderr, "ls", "ls [PATH]");
        }
        let path = args.first().map_or(".", String::as_str);
        let entries = match self.namespace.list(&self.cwd, path) {
            Ok(value) => value,
            Err(error) => return fs_failure(stderr, "ls", path, error),
        };
        for entry in entries {
            let suffix = if entry.kind == NodeKind::Directory {
                "/"
            } else {
                ""
            };
            if write_all(stdout, format!("{}{suffix}\n", entry.name).as_bytes()).is_err() {
                return stream_failure(stderr, "ls");
            }
        }
        CommandStatus::Success
    }

    fn command_pwd(
        &self,
        args: &[String],
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        if !args.is_empty() {
            return usage(stderr, "pwd", "pwd");
        }
        if write_all(stdout, format!("{}\n", self.cwd).as_bytes()).is_err() {
            return stream_failure(stderr, "pwd");
        }
        CommandStatus::Success
    }

    fn command_cd(&mut self, args: &[String], stderr: &mut dyn Output) -> CommandStatus {
        if args.len() != 1 {
            return usage(stderr, "cd", "cd PATH");
        }
        match self.namespace.resolve_dir(&self.cwd, &args[0]) {
            Ok(path) => {
                self.cwd = path;
                CommandStatus::Success
            }
            Err(error) => fs_failure(stderr, "cd", &args[0], error),
        }
    }

    fn command_mem(
        &mut self,
        args: &[String],
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        if !args.is_empty() {
            return usage(stderr, "mem", "mem");
        }
        let report = self.memory_report();
        if self
            .namespace
            .set_system_file("/sys/memory", report.as_bytes())
            .is_err()
        {
            return fs_failure(stderr, "mem", "/sys/memory", FsError::Invalid);
        }
        if write_all(stdout, report.as_bytes()).is_err() {
            return stream_failure(stderr, "mem");
        }
        CommandStatus::Success
    }

    fn command_halt(&mut self, args: &[String], stderr: &mut dyn Output) -> CommandStatus {
        if !args.is_empty() {
            return usage(stderr, "halt", "halt");
        }
        if !self.machine_control {
            let _ignored = write_error(stderr, "halt", "machine-control capability denied");
            return CommandStatus::Denied;
        }
        self.halt_requested = true;
        CommandStatus::Success
    }

    fn command_write(
        &mut self,
        args: &[String],
        stdin: &mut dyn Input,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        let Some(path) = args.first() else {
            return usage(stderr, "write", "write FILE [TEXT...]");
        };
        let bytes = if args.len() > 1 {
            args[1..].join(" ").into_bytes()
        } else {
            match read_bounded(stdin, PIPE_CAPACITY) {
                Ok(value) => value,
                Err(_) => return stream_failure(stderr, "write"),
            }
        };
        match self.namespace.write_file(&self.cwd, path, &bytes) {
            Ok(()) => CommandStatus::Success,
            Err(error) => fs_failure(stderr, "write", path, error),
        }
    }

    fn command_rm(&mut self, args: &[String], stderr: &mut dyn Output) -> CommandStatus {
        if args.len() != 1 {
            return usage(stderr, "rm", "rm FILE");
        }
        match self.namespace.remove_file(&self.cwd, &args[0]) {
            Ok(()) => CommandStatus::Success,
            Err(error) => fs_failure(stderr, "rm", &args[0], error),
        }
    }

    fn command_hexdump(
        &self,
        args: &[String],
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        if args.len() > 1 {
            return usage(stderr, "hexdump", "hexdump [FILE]");
        }
        let data = if let Some(path) = args.first() {
            match self.namespace.read_file(&self.cwd, path) {
                Ok(value) => value.to_vec(),
                Err(error) => return fs_failure(stderr, "hexdump", path, error),
            }
        } else {
            match read_bounded(stdin, PIPE_CAPACITY) {
                Ok(value) => value,
                Err(_) => return stream_failure(stderr, "hexdump"),
            }
        };
        for (row, chunk) in data.chunks(16).enumerate() {
            let mut line = format!("{:08x}  ", row * 16);
            for byte in chunk {
                if write!(line, "{byte:02x} ").is_err() {
                    return stream_failure(stderr, "hexdump");
                }
            }
            line.push('\n');
            if write_all(stdout, line.as_bytes()).is_err() {
                return stream_failure(stderr, "hexdump");
            }
        }
        CommandStatus::Success
    }

    fn memory_report(&self) -> String {
        let stats = self.namespace.memory_stats();
        let (owner, map) = match self.machine_memory.owner() {
            MachineMemoryOwner::Host => ("host process", "unavailable"),
            MachineMemoryOwner::Firmware => ("firmware", "firmware snapshot (advisory)"),
            MachineMemoryOwner::Kernel => ("kernel", "final map (owned)"),
        };
        let usable = optional_bytes(self.machine_memory.usable_bytes());
        let reserved = optional_bytes(self.machine_memory.reserved_bytes());
        let frames = optional_ratio(
            self.machine_memory.free_frames(),
            self.machine_memory.total_frames(),
            "free",
        );
        let heap = optional_ratio(
            self.machine_memory.heap_used_bytes(),
            self.machine_memory.heap_total_bytes(),
            "used",
        );
        let heap_high_water = optional_bytes(self.machine_memory.heap_high_water_bytes());
        let failed_allocations = optional_bytes(self.machine_memory.failed_allocations());
        format!(
            "arch: {}\nmemory owner: {owner}\nmemory map: {map}\ntotal usable: {usable}\nreserved: {reserved}\nframes: {frames}\nheap: {heap}\nheap high-water: {heap_high_water}\nallocation failures: {failed_allocations}\nramfs used: {}\nramfs limit: {}\nramfs high-water: {}\ncaches used: 0\ncaches limit: 0\npressure: normal (RAMFS policy only)\n",
            self.architecture, stats.ramfs_used, stats.ramfs_limit, stats.ramfs_high_water,
        )
    }

    fn refresh_memory_node(&mut self) -> Result<(), FsError> {
        let report = self.memory_report();
        self.namespace
            .set_system_file("/sys/memory", report.as_bytes())
    }
}

fn optional_bytes(value: Option<u64>) -> String {
    match value {
        Some(bytes) => bytes.to_string(),
        None => "unavailable".to_string(),
    }
}

fn optional_ratio(numerator: Option<u64>, denominator: Option<u64>, suffix: &str) -> String {
    match (numerator, denominator) {
        (Some(numerator), Some(denominator)) => {
            format!("{numerator}/{denominator} {suffix}")
        }
        _ => "unavailable".to_string(),
    }
}

fn command_echo(
    args: &[String],
    stdout: &mut dyn Output,
    stderr: &mut dyn Output,
) -> CommandStatus {
    if write_all(stdout, args.join(" ").as_bytes()).is_err() || write_all(stdout, b"\n").is_err() {
        return stream_failure(stderr, "echo");
    }
    CommandStatus::Success
}

fn command_clear(
    args: &[String],
    stdout: &mut dyn Output,
    stderr: &mut dyn Output,
) -> CommandStatus {
    if !args.is_empty() {
        return usage(stderr, "clear", "clear");
    }
    if write_all(stdout, b"\x1b[2J\x1b[H").is_err() {
        return stream_failure(stderr, "clear");
    }
    CommandStatus::Success
}

fn command_help(
    args: &[String],
    stdout: &mut dyn Output,
    stderr: &mut dyn Output,
) -> CommandStatus {
    if args.len() > 1 {
        return usage(stderr, "help", "help [COMMAND]");
    }
    if let Some(name) = args.first() {
        if let Some(spec) = COMMANDS.iter().find(|spec| spec.name == name) {
            if write_all(stdout, format!("{}\n", spec.synopsis).as_bytes()).is_err() {
                return stream_failure(stderr, "help");
            }
            return CommandStatus::Success;
        }
        let _ignored = write_error(stderr, "help", "unknown command");
        return CommandStatus::NotFound;
    }
    for spec in COMMANDS {
        let authority = if spec.requires_machine_control {
            " [machine-control]"
        } else {
            ""
        };
        if write_all(
            stdout,
            format!("{:<9} {}{authority}\n", spec.name, spec.synopsis).as_bytes(),
        )
        .is_err()
        {
            return stream_failure(stderr, "help");
        }
    }
    CommandStatus::Success
}

fn grep_stream(
    input: &mut dyn Input,
    pattern: &[u8],
    stdout: &mut dyn Output,
    stderr: &mut dyn Output,
) -> CommandStatus {
    let mut read_buffer = [0_u8; 256];
    let mut line = Vec::new();
    loop {
        let Ok(count) = input.read(&mut read_buffer) else {
            return stream_failure(stderr, "grep");
        };
        if count == 0 {
            break;
        }
        for byte in &read_buffer[..count] {
            if line.len() >= PIPE_CAPACITY {
                let _ignored = write_error(stderr, "grep", "line exceeds pipeline capacity");
                return CommandStatus::Failure;
            }
            line.push(*byte);
            if *byte == b'\n' {
                if contains_bytes(&line, pattern) && write_all(stdout, &line).is_err() {
                    return stream_failure(stderr, "grep");
                }
                line.clear();
            }
        }
    }
    if !line.is_empty() && contains_bytes(&line, pattern) {
        if write_all(stdout, &line).is_err() {
            return stream_failure(stderr, "grep");
        }
        if !line.ends_with(b"\n") && write_all(stdout, b"\n").is_err() {
            return stream_failure(stderr, "grep");
        }
    }
    CommandStatus::Success
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn copy_stream(
    input: &mut dyn Input,
    output: &mut dyn Output,
    stderr: &mut dyn Output,
    command: &str,
) -> CommandStatus {
    let mut buffer = [0_u8; 512];
    loop {
        let Ok(count) = input.read(&mut buffer) else {
            return stream_failure(stderr, command);
        };
        if count == 0 {
            return CommandStatus::Success;
        }
        if write_all(output, &buffer[..count]).is_err() {
            return stream_failure(stderr, command);
        }
    }
}

fn read_bounded(input: &mut dyn Input, limit: usize) -> Result<Vec<u8>, StreamError> {
    let mut output = BoundedOutput::new(limit);
    let mut buffer = [0_u8; 512];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            return Ok(output.into_vec());
        }
        write_all(&mut output, &buffer[..count])?;
    }
}

fn usage(stderr: &mut dyn Output, command: &str, synopsis: &str) -> CommandStatus {
    let _ignored = write_error(stderr, command, synopsis);
    CommandStatus::Usage
}

fn fs_failure(stderr: &mut dyn Output, command: &str, path: &str, error: FsError) -> CommandStatus {
    let _ignored = write_all(stderr, format!("{command}: {path}: {error}\n").as_bytes());
    if error == FsError::NotFound {
        CommandStatus::NotFound
    } else {
        CommandStatus::Failure
    }
}

fn stream_failure(stderr: &mut dyn Output, command: &str) -> CommandStatus {
    let _ignored = write_error(stderr, command, "stream I/O failed");
    CommandStatus::Failure
}

fn write_error(stderr: &mut dyn Output, command: &str, message: &str) -> Result<(), StreamError> {
    write_all(stderr, format!("{command}: {message}\n").as_bytes())
}

const fn parse_error_text(error: ParseError) -> &'static str {
    match error {
        ParseError::LineTooLong => "line is too long",
        ParseError::TooManyArguments => "too many arguments",
        ParseError::TooManyStages => "too many pipeline stages",
        ParseError::UnclosedQuote => "unclosed quote",
        ParseError::EmptyStage => "empty pipeline stage",
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseError, Shell, parse_line};
    use alloc::string::ToString;
    use kllm_core::{BoundedOutput, MachineMemorySnapshot, SliceInput};
    use kllm_vfs::{Namespace, RamFsQuota};

    fn shell() -> Shell {
        let mut namespace = Namespace::new(RamFsQuota::default());
        assert_eq!(namespace.add_read_only_dir("/help"), Ok(()));
        assert_eq!(
            namespace.add_read_only_file("/help/readme", b"alpha\nbeta alpha\n"),
            Ok(())
        );
        match Shell::new(namespace, "test", MachineMemorySnapshot::hosted(), true) {
            Ok(value) => value,
            Err(_error) => std::process::abort(),
        }
    }

    #[test]
    fn quotes_and_pipelines_parse_without_expansion() {
        let parsed = parse_line("echo 'a b' \"c|d\" | grep b").unwrap_or_default();
        assert_eq!(parsed.stages.len(), 2);
        assert_eq!(parsed.stages[0].words, ["echo", "a b", "c|d"]);
        assert_eq!(parsed.stages[1].words, ["grep", "b"]);
        assert_eq!(parse_line("echo 'bad"), Err(ParseError::UnclosedQuote));
        assert_eq!(parse_line("echo a || cat"), Err(ParseError::EmptyStage));
    }

    #[test]
    fn pipeline_connects_bounded_byte_streams() {
        let mut shell = shell();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(1024);
        let mut error = BoundedOutput::new(1024);
        let status = shell.execute(
            "cat /help/readme | grep beta | hexdump",
            &mut input,
            &mut output,
            &mut error,
        );
        assert_eq!(status.code(), 0);
        let text = core::str::from_utf8(output.as_slice()).unwrap_or_default();
        assert!(text.contains("62 65 74 61"));
        assert!(error.as_slice().is_empty());
    }

    #[test]
    fn writable_files_round_trip_and_account() {
        let mut shell = shell();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(4096);
        let mut error = BoundedOutput::new(4096);
        assert_eq!(
            shell
                .execute(
                    "echo hello | write /tmp/message",
                    &mut input,
                    &mut output,
                    &mut error
                )
                .code(),
            0
        );
        assert_eq!(
            shell
                .execute("cat /tmp/message", &mut input, &mut output, &mut error)
                .code(),
            0
        );
        assert!(output.as_slice().ends_with(b"hello\n"));
    }

    #[test]
    fn unknown_command_is_stable_failure() {
        let mut shell = shell();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(64);
        let mut error = BoundedOutput::new(128);
        let status = shell.execute("nope", &mut input, &mut output, &mut error);
        assert_eq!(status.code(), 3);
        assert_eq!(
            core::str::from_utf8(error.as_slice()).unwrap_or_default(),
            "nope: unknown command\n".to_string()
        );
    }

    #[test]
    fn oversized_intermediate_pipeline_fails_without_final_output() {
        let mut namespace = Namespace::new(RamFsQuota::default());
        assert_eq!(namespace.add_read_only_dir("/help"), Ok(()));
        let oversized = alloc::vec![b'x'; kllm_core::PIPE_CAPACITY + 1];
        assert_eq!(
            namespace.add_read_only_file("/help/large", &oversized),
            Ok(())
        );
        let mut shell = match Shell::new(namespace, "test", MachineMemorySnapshot::hosted(), true) {
            Ok(value) => value,
            Err(_error) => std::process::abort(),
        };
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(64);
        let mut error = BoundedOutput::new(256);
        let status = shell.execute("cat /help/large | cat", &mut input, &mut output, &mut error);
        assert_ne!(status.code(), 0);
        assert!(output.as_slice().is_empty());
        assert!(error.as_slice().ends_with(b"cat: output failed\n"));
    }

    #[test]
    fn memory_report_uses_supplied_machine_snapshot() {
        let namespace = Namespace::new(RamFsQuota::default());
        let mut shell = match Shell::new(
            namespace,
            "snapshot-test",
            MachineMemorySnapshot::firmware(123_456, 78_900),
            true,
        ) {
            Ok(value) => value,
            Err(_error) => std::process::abort(),
        };
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(1024);
        let mut error = BoundedOutput::new(128);

        assert_eq!(
            shell
                .execute("mem", &mut input, &mut output, &mut error)
                .code(),
            0
        );
        let report = core::str::from_utf8(output.as_slice()).unwrap_or_default();
        assert!(report.contains("memory owner: firmware\n"));
        assert!(report.contains("memory map: firmware snapshot (advisory)\n"));
        assert!(report.contains("total usable: 123456\n"));
        assert!(report.contains("reserved: 78900\n"));
        assert!(error.as_slice().is_empty());
    }

    #[test]
    fn memory_report_exposes_owned_frame_and_heap_counters() {
        let namespace = Namespace::new(RamFsQuota::default());
        let mut shell = match Shell::new(
            namespace,
            "owned-test",
            MachineMemorySnapshot::kernel(4096, 8192, 10, 9, 1024, 128, 256, 1),
            true,
        ) {
            Ok(value) => value,
            Err(_error) => std::process::abort(),
        };
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(1024);
        let mut error = BoundedOutput::new(128);

        assert_eq!(
            shell
                .execute("mem", &mut input, &mut output, &mut error)
                .code(),
            0
        );
        let report = core::str::from_utf8(output.as_slice()).unwrap_or_default();
        assert!(report.contains("memory owner: kernel\n"));
        assert!(report.contains("memory map: final map (owned)\n"));
        assert!(report.contains("frames: 9/10 free\n"));
        assert!(report.contains("heap: 128/1024 used\n"));
        assert!(report.contains("heap high-water: 256\n"));
        assert!(report.contains("allocation failures: 1\n"));
        assert!(error.as_slice().is_empty());
    }
}

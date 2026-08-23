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
use kllm_driver::InputQueueStats;
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
    id: CommandId,
    name: &'static str,
    synopsis: &'static str,
    requires_machine_control: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandId {
    Cat,
    Cd,
    Clear,
    Echo,
    Grep,
    Halt,
    Help,
    Hexdump,
    Ls,
    Mem,
    Pwd,
    Rm,
    Write,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        id: CommandId::Cat,
        name: "cat",
        synopsis: "cat [FILE...]",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Cd,
        name: "cd",
        synopsis: "cd PATH",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Clear,
        name: "clear",
        synopsis: "clear",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Echo,
        name: "echo",
        synopsis: "echo [ARG...]",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Grep,
        name: "grep",
        synopsis: "grep PATTERN [FILE...]",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Halt,
        name: "halt",
        synopsis: "halt",
        requires_machine_control: true,
    },
    CommandSpec {
        id: CommandId::Help,
        name: "help",
        synopsis: "help [COMMAND]",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Hexdump,
        name: "hexdump",
        synopsis: "hexdump [FILE]",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Ls,
        name: "ls",
        synopsis: "ls [PATH]",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Mem,
        name: "mem",
        synopsis: "mem",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Pwd,
        name: "pwd",
        synopsis: "pwd",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Rm,
        name: "rm",
        synopsis: "rm FILE",
        requires_machine_control: false,
    },
    CommandSpec {
        id: CommandId::Write,
        name: "write",
        synopsis: "write FILE [TEXT...]",
        requires_machine_control: false,
    },
];

/// Invalid shell-completion resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionConfigError {
    /// Candidate count and byte budgets must both be zero or both be non-zero.
    InconsistentCapacity,
}

/// Bounded shell-completion resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionConfig {
    max_candidates: usize,
    max_bytes: usize,
}

impl CompletionConfig {
    /// Construct a completion policy. Two zero values disable completion.
    ///
    /// # Errors
    ///
    /// Fails if exactly one capacity is zero.
    pub const fn new(
        max_candidates: usize,
        max_bytes: usize,
    ) -> Result<Self, CompletionConfigError> {
        if (max_candidates == 0) != (max_bytes == 0) {
            return Err(CompletionConfigError::InconsistentCapacity);
        }
        Ok(Self {
            max_candidates,
            max_bytes,
        })
    }

    /// A disabled completion policy.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            max_candidates: 0,
            max_bytes: 0,
        }
    }

    /// Default completion policy for the `tiny` resource profile.
    #[must_use]
    pub const fn tiny() -> Self {
        Self {
            max_candidates: 64,
            max_bytes: 4 * 1024,
        }
    }

    /// Maximum returned candidate count.
    #[must_use]
    pub const fn max_candidates(self) -> usize {
        self.max_candidates
    }

    /// Maximum returned candidate payload bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Whether completion is disabled.
    #[must_use]
    pub const fn is_disabled(self) -> bool {
        self.max_candidates == 0
    }
}

/// One display and insertion value proposed by shell completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionCandidate {
    /// Candidate text shown when alternatives are listed.
    pub display: String,
    /// Text that replaces the incomplete token.
    pub replacement: String,
}

/// Bounded completion result for one editable token.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Completion {
    /// UTF-8 byte offset at which token replacement begins.
    pub replacement_start: usize,
    /// UTF-8 byte offset at which token replacement ends.
    pub replacement_end: usize,
    /// Lexically ordered retained candidates.
    pub candidates: Vec<CompletionCandidate>,
    /// Whether configured budgets omitted at least one candidate.
    pub truncated: bool,
}

impl Completion {
    /// Longest UTF-8-safe replacement prefix shared by every candidate.
    #[must_use]
    pub fn common_replacement(&self) -> Option<&str> {
        let first = self.candidates.first()?.replacement.as_str();
        let mut length = first.len();
        for candidate in &self.candidates[1..] {
            length = common_prefix_bytes(first, &candidate.replacement, length);
        }
        while !first.is_char_boundary(length) {
            length = length.saturating_sub(1);
        }
        Some(&first[..length])
    }
}

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
    machine_input: Option<InputQueueStats>,
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
        namespace.set_system_file("/sys/version", b"0.1.0\n")?;
        let mut shell = Self {
            namespace,
            cwd: "/".to_string(),
            architecture: architecture.to_string(),
            machine_memory,
            machine_input: None,
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

    /// Complete the token ending at `cursor` without exceeding caller budgets.
    ///
    /// Incomplete quoted tokens are left unchanged in this first completion
    /// profile. Candidate insertion never performs shell expansion.
    #[must_use]
    pub fn complete(&self, line: &str, cursor: usize, config: CompletionConfig) -> Completion {
        if config.is_disabled()
            || cursor > line.len()
            || !line.is_char_boundary(cursor)
            || cursor > MAX_LINE_BYTES
        {
            return Completion::default();
        }
        let Some(context) = completion_context(line, cursor) else {
            return Completion::default();
        };
        if context.word_index == 0 {
            return complete_commands(context, config);
        }
        if context.command == Some("help") && context.word_index == 1 {
            return complete_commands(context, config);
        }
        let Some(directories_only) = path_completion_mode(context.command, context.word_index)
        else {
            return Completion::default();
        };
        self.complete_paths(context, directories_only, config)
    }

    /// Replace the machine-accounting snapshot used by `mem` and `/sys/memory`.
    pub const fn set_machine_memory(&mut self, snapshot: MachineMemorySnapshot) {
        self.machine_memory = snapshot;
    }

    /// Replace the interrupt-input snapshot used by `mem` and `/sys/memory`.
    pub const fn set_machine_input(&mut self, snapshot: Option<InputQueueStats>) {
        self.machine_input = snapshot;
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
        let Some(spec) = COMMANDS.iter().find(|spec| spec.name == command) else {
            let _ignored = write_error(stderr, command, "unknown command");
            return CommandStatus::NotFound;
        };
        match spec.id {
            CommandId::Cat => self.command_cat(args, stdin, stdout, stderr),
            CommandId::Cd => self.command_cd(args, stderr),
            CommandId::Clear => command_clear(args, stdout, stderr),
            CommandId::Echo => command_echo(args, stdout, stderr),
            CommandId::Grep => self.command_grep(args, stdin, stdout, stderr),
            CommandId::Halt => self.command_halt(args, stderr),
            CommandId::Help => command_help(args, stdout, stderr),
            CommandId::Hexdump => self.command_hexdump(args, stdin, stdout, stderr),
            CommandId::Ls => self.command_ls(args, stdout, stderr),
            CommandId::Mem => self.command_mem(args, stdout, stderr),
            CommandId::Pwd => self.command_pwd(args, stdout, stderr),
            CommandId::Rm => self.command_rm(args, stderr),
            CommandId::Write => self.command_write(args, stdin, stderr),
        }
    }

    fn complete_paths(
        &self,
        context: CompletionContext<'_>,
        directories_only: bool,
        config: CompletionConfig,
    ) -> Completion {
        let (directory, displayed_parent, name_prefix) = split_completion_path(context.prefix);
        let Ok(listing) = self.namespace.list_matching_bounded(
            &self.cwd,
            directory,
            name_prefix,
            directories_only,
            config.max_candidates(),
            config.max_bytes(),
        ) else {
            return Completion::default();
        };
        let mut completion = Completion {
            replacement_start: context.start,
            replacement_end: context.end,
            candidates: Vec::new(),
            truncated: listing.truncated,
        };
        let mut retained_bytes = 0_usize;
        for entry in listing.entries {
            if !is_bare_word_component(&entry.name) {
                completion.truncated = true;
                continue;
            }
            let suffix = if entry.kind == NodeKind::Directory {
                "/"
            } else {
                ""
            };
            let display = format!("{displayed_parent}{}{suffix}", entry.name);
            let replacement = if entry.kind == NodeKind::Directory {
                display.clone()
            } else {
                format!("{display} ")
            };
            let Some(next_bytes) = retained_bytes.checked_add(replacement.len()) else {
                completion.truncated = true;
                break;
            };
            if completion.candidates.len() >= config.max_candidates()
                || next_bytes > config.max_bytes()
            {
                completion.truncated = true;
                break;
            }
            completion.candidates.push(CompletionCandidate {
                display,
                replacement,
            });
            retained_bytes = next_bytes;
        }
        completion
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
        let usable = optional_byte_count(self.machine_memory.usable_bytes());
        let reserved = optional_byte_count(self.machine_memory.reserved_bytes());
        let frames = optional_ratio(
            self.machine_memory.free_frames(),
            self.machine_memory.total_frames(),
            "free",
        );
        let heap = optional_byte_ratio(
            self.machine_memory.heap_used_bytes(),
            self.machine_memory.heap_total_bytes(),
            "used",
        );
        let heap_high_water = optional_byte_count(self.machine_memory.heap_high_water_bytes());
        let failed_allocations = optional_bytes(self.machine_memory.failed_allocations());
        let ramfs_used = byte_count(stats.ramfs_used);
        let ramfs_limit = byte_count(stats.ramfs_limit);
        let ramfs_high_water = byte_count(stats.ramfs_high_water);
        let (input_queue, input_interrupts, input_delivered, input_dropped, idle_waits, wakeups) =
            match self.machine_input {
                Some(input) => (
                    format!("{}/{} queued", input.queued, input.capacity),
                    input.interrupts.to_string(),
                    input.delivered.to_string(),
                    input.dropped.to_string(),
                    input.idle_waits.to_string(),
                    input.wakeups.to_string(),
                ),
                None => (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                ),
            };
        format!(
            "arch: {}\nmemory owner: {owner}\nmemory map: {map}\ntotal usable: {usable}\nreserved: {reserved}\nframes: {frames}\nheap: {heap}\nheap high-water: {heap_high_water}\nallocation failures: {failed_allocations}\ninput queue: {input_queue}\ninput interrupts: {input_interrupts}\ninput delivered: {input_delivered}\ninput dropped: {input_dropped}\ninput idle waits: {idle_waits}\ninput wakeups: {wakeups}\nramfs used: {}\nramfs limit: {}\nramfs high-water: {}\ncaches used: 0\ncaches limit: 0\npressure: normal (RAMFS policy only)\n",
            self.architecture, ramfs_used, ramfs_limit, ramfs_high_water,
        )
    }

    fn refresh_memory_node(&mut self) -> Result<(), FsError> {
        let report = self.memory_report();
        self.namespace
            .set_system_file("/sys/memory", report.as_bytes())
    }
}

#[derive(Clone, Copy, Debug)]
struct CompletionContext<'a> {
    start: usize,
    end: usize,
    prefix: &'a str,
    word_index: usize,
    command: Option<&'a str>,
}

fn completion_context(line: &str, cursor: usize) -> Option<CompletionContext<'_>> {
    let mut quote = Quote::None;
    let mut word_started = false;
    let mut word_start = 0_usize;
    let mut word_quoted = false;
    let mut word_index = 0_usize;
    let mut command = None;

    for (index, character) in line[..cursor].char_indices() {
        match quote {
            Quote::Single => {
                if character == '\'' {
                    quote = Quote::None;
                }
            }
            Quote::Double => {
                if character == '"' {
                    quote = Quote::None;
                }
            }
            Quote::None => match character {
                '\'' | '"' => {
                    if !word_started {
                        word_started = true;
                        word_start = index;
                    }
                    word_quoted = true;
                    quote = if character == '\'' {
                        Quote::Single
                    } else {
                        Quote::Double
                    };
                }
                '|' => {
                    word_started = false;
                    word_quoted = false;
                    word_index = 0;
                    command = None;
                }
                value if value.is_whitespace() => {
                    if word_started {
                        if word_index == 0 && !word_quoted {
                            command = Some(&line[word_start..index]);
                        }
                        word_index = word_index.saturating_add(1);
                        word_started = false;
                        word_quoted = false;
                    }
                }
                _ => {
                    if !word_started {
                        word_started = true;
                        word_start = index;
                    }
                }
            },
        }
    }
    if quote != Quote::None || word_quoted {
        return None;
    }
    let start = if word_started { word_start } else { cursor };
    Some(CompletionContext {
        start,
        end: cursor,
        prefix: &line[start..cursor],
        word_index,
        command,
    })
}

fn complete_commands(context: CompletionContext<'_>, config: CompletionConfig) -> Completion {
    let mut completion = Completion {
        replacement_start: context.start,
        replacement_end: context.end,
        candidates: Vec::new(),
        truncated: false,
    };
    let mut retained_bytes = 0_usize;
    for spec in COMMANDS
        .iter()
        .filter(|spec| spec.name.starts_with(context.prefix))
    {
        let replacement = format!("{} ", spec.name);
        let Some(next_bytes) = retained_bytes.checked_add(replacement.len()) else {
            completion.truncated = true;
            break;
        };
        if completion.candidates.len() >= config.max_candidates() || next_bytes > config.max_bytes()
        {
            completion.truncated = true;
            break;
        }
        completion.candidates.push(CompletionCandidate {
            display: spec.name.to_string(),
            replacement,
        });
        retained_bytes = next_bytes;
    }
    completion
}

fn path_completion_mode(command: Option<&str>, word_index: usize) -> Option<bool> {
    match (command, word_index) {
        (Some("cd"), 1) => Some(true),
        (Some("cat"), 1..) | (Some("grep"), 2..) | (Some("hexdump" | "ls" | "rm" | "write"), 1) => {
            Some(false)
        }
        _ => None,
    }
}

fn split_completion_path(prefix: &str) -> (&str, &str, &str) {
    match prefix.rfind('/') {
        None => (".", "", prefix),
        Some(0) => ("/", "/", &prefix[1..]),
        Some(index) => (&prefix[..index], &prefix[..=index], &prefix[index + 1..]),
    }
}

fn is_bare_word_component(name: &str) -> bool {
    !name
        .chars()
        .any(|character| character.is_whitespace() || matches!(character, '\'' | '"' | '|'))
}

fn common_prefix_bytes(first: &str, candidate: &str, limit: usize) -> usize {
    let maximum = first.len().min(candidate.len()).min(limit);
    first
        .as_bytes()
        .iter()
        .zip(candidate.as_bytes())
        .take(maximum)
        .position(|(left, right)| left != right)
        .unwrap_or(maximum)
}

fn optional_bytes(value: Option<u64>) -> String {
    match value {
        Some(bytes) => bytes.to_string(),
        None => "unavailable".to_string(),
    }
}

fn optional_byte_count(value: Option<u64>) -> String {
    match value {
        Some(bytes) => byte_count(bytes),
        None => "unavailable".to_string(),
    }
}

fn byte_count(bytes: u64) -> String {
    format!("{bytes} ({})", human_bytes(bytes))
}

fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    let (unit, label) = if bytes >= GIB {
        (GIB, "GiB")
    } else if bytes >= MIB {
        (MIB, "MiB")
    } else if bytes >= KIB {
        (KIB, "KiB")
    } else {
        return format!("{bytes} B");
    };
    let whole = bytes / unit;
    let hundredths = ((bytes % unit) * 100) / unit;
    if hundredths == 0 {
        format!("{whole} {label}")
    } else if hundredths.is_multiple_of(10) {
        format!("{whole}.{} {label}", hundredths / 10)
    } else {
        format!("{whole}.{hundredths:02} {label}")
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

fn optional_byte_ratio(numerator: Option<u64>, denominator: Option<u64>, suffix: &str) -> String {
    match (numerator, denominator) {
        (Some(numerator), Some(denominator)) => format!(
            "{numerator}/{denominator} {suffix} ({}/{})",
            human_bytes(numerator),
            human_bytes(denominator)
        ),
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
    use super::{CompletionConfig, CompletionConfigError, ParseError, Shell, parse_line};
    use alloc::string::ToString;
    use kllm_core::{BoundedOutput, MachineMemorySnapshot, SliceInput};
    use kllm_driver::InputQueueStats;
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
    fn completion_uses_command_pipeline_and_vfs_context() {
        let shell = shell();
        let command = shell.complete("he", 2, CompletionConfig::tiny());
        assert_eq!(command.candidates.len(), 2);
        assert_eq!(command.common_replacement(), Some("he"));
        assert_eq!(command.candidates[0].display, "help");
        assert_eq!(command.candidates[1].display, "hexdump");

        let pipeline = shell.complete("echo x | pw", 11, CompletionConfig::tiny());
        assert_eq!(pipeline.candidates.len(), 1);
        assert_eq!(pipeline.candidates[0].replacement, "pwd ");

        let directory = shell.complete("cd /he", 6, CompletionConfig::tiny());
        assert_eq!(directory.candidates.len(), 1);
        assert_eq!(directory.candidates[0].replacement, "/help/");

        let file = shell.complete("cat /help/r", 11, CompletionConfig::tiny());
        assert_eq!(file.candidates.len(), 1);
        assert_eq!(file.candidates[0].replacement, "/help/readme ");
    }

    #[test]
    fn completion_configuration_is_validated_and_enforced() {
        assert_eq!(
            CompletionConfig::new(1, 0),
            Err(CompletionConfigError::InconsistentCapacity)
        );
        let shell = shell();
        let bounded = shell.complete(
            "",
            0,
            CompletionConfig::new(1, 16).unwrap_or_else(|_| CompletionConfig::disabled()),
        );
        assert_eq!(bounded.candidates.len(), 1);
        assert!(bounded.truncated);
        assert!(
            shell
                .complete("c", 1, CompletionConfig::disabled())
                .candidates
                .is_empty()
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
        assert!(report.contains("total usable: 123456 (120.56 KiB)\n"));
        assert!(report.contains("reserved: 78900 (77.05 KiB)\n"));
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
        shell.set_machine_input(Some(InputQueueStats {
            capacity: 256,
            queued: 2,
            delivered: 17,
            dropped: 0,
            interrupts: 9,
            idle_waits: 8,
            wakeups: 7,
        }));

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
        assert!(report.contains("heap: 128/1024 used (128 B/1 KiB)\n"));
        assert!(report.contains("heap high-water: 256 (256 B)\n"));
        assert!(report.contains("allocation failures: 1\n"));
        assert!(report.contains("input queue: 2/256 queued\n"));
        assert!(report.contains("input interrupts: 9\n"));
        assert!(report.contains("input delivered: 17\n"));
        assert!(report.contains("input dropped: 0\n"));
        assert!(report.contains("input idle waits: 8\n"));
        assert!(report.contains("input wakeups: 7\n"));
        assert!(error.as_slice().is_empty());
    }
}

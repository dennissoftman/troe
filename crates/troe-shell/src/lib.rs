//! Bounded shell grammar, byte-stream pipelines, and three session intrinsics.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use troe_core::{
    BoundedOutput, CommandStatus, Input, MAX_ARGS, MAX_LINE_BYTES, MAX_PIPELINE_STAGES,
    MachineMemoryOwner, MachineMemorySnapshot, MemoryStats, Output, PIPE_CAPACITY, SliceInput,
    StreamError, write_all,
};
use troe_driver::InputQueueStats;
use troe_vfs::{FsError, Namespace, NodeKind};

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
    intrinsic: Option<IntrinsicId>,
    name: &'static str,
    synopsis: &'static str,
    class: CommandClass,
}

/// Stable execution placement for a shell command name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandClass {
    /// Shell-owned behavior that cannot be replaced by an application.
    Intrinsic,
    /// A name that must resolve to a KEX application.
    Application,
}

/// Application resolver used for every non-intrinsic command.
///
/// Returning `None` means that no application was resolved. Registered
/// application names then report an unavailable artifact; unknown names report
/// an unknown command. Neither case falls back to shell-owned utility behavior.
pub trait ExternalCommand {
    /// Resolve and execute one complete command invocation.
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &mut self,
        command: &str,
        words: &[String],
        cwd: &str,
        namespace: &mut Namespace,
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> Option<CommandStatus>;
}

struct NoExternalCommand;

impl ExternalCommand for NoExternalCommand {
    fn execute(
        &mut self,
        _command: &str,
        _words: &[String],
        _cwd: &str,
        _namespace: &mut Namespace,
        _stdin: &mut dyn Input,
        _stdout: &mut dyn Output,
        _stderr: &mut dyn Output,
    ) -> Option<CommandStatus> {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntrinsicId {
    Cd,
    PowerOff,
    Reboot,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        intrinsic: None,
        name: "arp",
        synopsis: "arp",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "cat",
        synopsis: "cat [FILE...]",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: Some(IntrinsicId::Cd),
        name: "cd",
        synopsis: "cd PATH",
        class: CommandClass::Intrinsic,
    },
    CommandSpec {
        intrinsic: None,
        name: "clear",
        synopsis: "clear",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "dhcp",
        synopsis: "dhcp",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "echo",
        synopsis: "echo [ARG...]",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "grep",
        synopsis: "grep PATTERN [FILE...]",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "hexdump",
        synopsis: "hexdump [FILE]",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "ls",
        synopsis: "ls [PATH]",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "man",
        synopsis: "man COMMAND",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "mem",
        synopsis: "mem",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "net",
        synopsis: "net | net stats",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "ping",
        synopsis: "ping ADDRESS",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: Some(IntrinsicId::PowerOff),
        name: "poweroff",
        synopsis: "poweroff",
        class: CommandClass::Intrinsic,
    },
    CommandSpec {
        intrinsic: None,
        name: "printf",
        synopsis: "printf FORMAT [ARG...]",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "pwd",
        synopsis: "pwd",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: Some(IntrinsicId::Reboot),
        name: "reboot",
        synopsis: "reboot",
        class: CommandClass::Intrinsic,
    },
    CommandSpec {
        intrinsic: None,
        name: "rm",
        synopsis: "rm FILE",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "sleep",
        synopsis: "sleep MILLISECONDS",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "tcp",
        synopsis: "tcp ADDRESS PORT [TEXT...]",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "udp",
        synopsis: "udp send [--source-port PORT] ADDRESS PORT [TEXT...] | udp listen PORT",
        class: CommandClass::Application,
    },
    CommandSpec {
        intrinsic: None,
        name: "write",
        synopsis: "write FILE [TEXT...]",
        class: CommandClass::Application,
    },
];

/// Return the reserved execution placement for a registered command name.
///
/// External command discovery must consult this classification before trying
/// to resolve a KEX application. Intrinsic names always retain shell dispatch.
#[must_use]
pub fn command_class(name: &str) -> Option<CommandClass> {
    COMMANDS
        .iter()
        .find(|command| command.name == name)
        .map(|command| command.class)
}

/// Return the concise synopsis associated with a registered command name.
#[must_use]
pub fn command_synopsis(name: &str) -> Option<&'static str> {
    COMMANDS
        .iter()
        .find(|command| command.name == name)
        .map(|command| command.synopsis)
}

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

    /// Default completion policy for the Standard resource policy.
    #[must_use]
    pub const fn standard() -> Self {
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

/// Terminal platform transition requested by an authorized intrinsic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineAction {
    /// Flush owned state and enter the platform soft-off state.
    PowerOff,
    /// Flush owned state and request a cold platform reset.
    Reboot,
}

/// Stateful shell composition root. Authority is explicit in its fields.
#[derive(Debug)]
pub struct Shell {
    namespace: Namespace,
    cwd: String,
    machine_control: bool,
    machine_action: Option<MachineAction>,
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
        let memory_report =
            format_memory_report(architecture, machine_memory, None, namespace.memory_stats());
        namespace.set_system_file("/sys/memory", memory_report.as_bytes())?;
        Ok(Self {
            namespace,
            cwd: "/".to_string(),
            machine_control,
            machine_action: None,
        })
    }

    /// Terminal platform transition requested by an authorized command.
    #[must_use]
    pub const fn machine_action(&self) -> Option<MachineAction> {
        self.machine_action
    }

    /// Current logical directory.
    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Complete the token ending at `cursor` without exceeding caller budgets.
    ///
    /// Incomplete quoted tokens are left unchanged in this first completion
    /// implementation. Candidate insertion never performs shell expansion.
    #[must_use]
    pub fn complete(&mut self, line: &str, cursor: usize, config: CompletionConfig) -> Completion {
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
        if context.command == Some("man") && context.word_index == 1 {
            return complete_commands(context, config);
        }
        let Some(directories_only) = path_completion_mode(context.command, context.word_index)
        else {
            return Completion::default();
        };
        self.complete_paths(context, directories_only, config)
    }

    /// Execute a complete line, including any bounded pipeline.
    pub fn execute(
        &mut self,
        line: &str,
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        self.execute_inner(line, stdin, stdout, stderr, &mut NoExternalCommand)
    }

    /// Execute a line by resolving every name except the shell-owned intrinsics.
    pub fn execute_with_external(
        &mut self,
        line: &str,
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
        external: &mut dyn ExternalCommand,
    ) -> CommandStatus {
        self.execute_inner(line, stdin, stdout, stderr, external)
    }

    fn execute_inner<E: ExternalCommand + ?Sized>(
        &mut self,
        line: &str,
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
        external: &mut E,
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
                    self.dispatch(&stage.words, stdin, stdout, stderr, external)
                } else {
                    let mut input = SliceInput::new(&previous);
                    self.dispatch(&stage.words, &mut input, stdout, stderr, external)
                };
                return status;
            }

            let mut next = BoundedOutput::new(PIPE_CAPACITY);
            let status = if index == 0 {
                self.dispatch(&stage.words, stdin, &mut next, stderr, external)
            } else {
                let mut input = SliceInput::new(&previous);
                self.dispatch(&stage.words, &mut input, &mut next, stderr, external)
            };
            if status != CommandStatus::Success {
                return status;
            }
            previous = next.into_vec();
        }
        CommandStatus::Failure
    }

    fn dispatch<E: ExternalCommand + ?Sized>(
        &mut self,
        words: &[String],
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
        external: &mut E,
    ) -> CommandStatus {
        let Some(command) = words.first().map(String::as_str) else {
            return CommandStatus::Success;
        };
        let spec = COMMANDS.iter().find(|spec| spec.name == command);
        if spec.is_none_or(|spec| spec.class == CommandClass::Application)
            && let Some(status) = external.execute(
                command,
                words,
                &self.cwd,
                &mut self.namespace,
                stdin,
                stdout,
                stderr,
            )
        {
            return status;
        }
        let Some(spec) = spec else {
            let _ignored = write_error(stderr, command, "unknown command");
            return CommandStatus::NotFound;
        };
        let Some(intrinsic) = spec.intrinsic else {
            let _ignored = write_error(stderr, command, "application unavailable");
            return CommandStatus::NotFound;
        };
        let args = &words[1..];
        if matches!(intrinsic, IntrinsicId::PowerOff | IntrinsicId::Reboot) && !self.machine_control
        {
            let _ignored = write_error(stderr, command, "machine-control capability denied");
            return CommandStatus::Denied;
        }
        match intrinsic {
            IntrinsicId::Cd => self.command_cd(args, stderr),
            IntrinsicId::PowerOff => {
                self.command_machine_action(args, stderr, MachineAction::PowerOff)
            }
            IntrinsicId::Reboot => self.command_machine_action(args, stderr, MachineAction::Reboot),
        }
    }

    fn complete_paths(
        &mut self,
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

    fn command_machine_action(
        &mut self,
        args: &[String],
        stderr: &mut dyn Output,
        action: MachineAction,
    ) -> CommandStatus {
        let command = match action {
            MachineAction::PowerOff => "poweroff",
            MachineAction::Reboot => "reboot",
        };
        if !args.is_empty() {
            return usage(stderr, command, command);
        }
        if !self.machine_control {
            let _ignored = write_error(stderr, command, "machine-control capability denied");
            return CommandStatus::Denied;
        }
        self.machine_action = Some(action);
        CommandStatus::Success
    }
}

/// Format the canonical bounded memory/driver report published at `/sys/memory`.
#[must_use]
pub fn format_memory_report(
    architecture: &str,
    machine_memory: MachineMemorySnapshot,
    machine_input: Option<InputQueueStats>,
    stats: MemoryStats,
) -> String {
    let (owner, map) = match machine_memory.owner() {
        MachineMemoryOwner::Host => ("host process", "unavailable"),
        MachineMemoryOwner::Firmware => ("firmware", "firmware snapshot (advisory)"),
        MachineMemoryOwner::Kernel => ("kernel", "final map (owned)"),
    };
    let usable = optional_byte_count(machine_memory.usable_bytes());
    let reserved = optional_byte_count(machine_memory.reserved_bytes());
    let frames = optional_ratio(
        machine_memory.free_frames(),
        machine_memory.total_frames(),
        "free",
    );
    let heap = optional_byte_ratio(
        machine_memory.heap_used_bytes(),
        machine_memory.heap_total_bytes(),
        "used",
    );
    let heap_high_water = optional_byte_count(machine_memory.heap_high_water_bytes());
    let failed_allocations = optional_bytes(machine_memory.failed_allocations());
    let ramfs_used = byte_count(stats.ramfs_used);
    let ramfs_limit = byte_count(stats.ramfs_limit);
    let ramfs_high_water = byte_count(stats.ramfs_high_water);
    let (input_queue, input_interrupts, input_delivered, input_dropped, idle_waits, wakeups) =
        match machine_input {
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
        "arch: {architecture}\nmemory owner: {owner}\nmemory map: {map}\ntotal usable: {usable}\nreserved: {reserved}\nframes: {frames}\nheap: {heap}\nheap high-water: {heap_high_water}\nallocation failures: {failed_allocations}\ninput queue: {input_queue}\ninput interrupts: {input_interrupts}\ninput delivered: {input_delivered}\ninput dropped: {input_dropped}\ninput idle waits: {idle_waits}\ninput wakeups: {wakeups}\nramfs used: {ramfs_used}\nramfs limit: {ramfs_limit}\nramfs high-water: {ramfs_high_water}\ncaches used: 0\ncaches limit: 0\npressure: normal (RAMFS policy only)\n",
    )
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
    use super::{
        COMMANDS, CommandClass, CompletionConfig, CompletionConfigError, ExternalCommand,
        MachineAction, ParseError, Shell, command_class, command_synopsis, format_memory_report,
        parse_line,
    };
    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use troe_core::{
        BoundedOutput, CommandStatus, Input, MAX_ARGS, MAX_LINE_BYTES, MAX_PIPELINE_STAGES,
        MachineMemorySnapshot, Output, PIPE_CAPACITY, SliceInput, write_all,
    };
    use troe_driver::InputQueueStats;
    use troe_vfs::{FsError, Namespace, RamFsQuota};

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

    #[derive(Default)]
    struct FakeExternal {
        attempts: Vec<String>,
    }

    impl FakeExternal {
        #[allow(clippy::unnecessary_wraps)]
        fn failure(
            stderr: &mut dyn Output,
            command: &str,
            message: &str,
            status: CommandStatus,
        ) -> Option<CommandStatus> {
            let _ignored = write_all(stderr, format!("{command}: {message}\n").as_bytes());
            Some(status)
        }
    }

    impl ExternalCommand for FakeExternal {
        fn execute(
            &mut self,
            command: &str,
            words: &[String],
            cwd: &str,
            namespace: &mut Namespace,
            stdin: &mut dyn Input,
            stdout: &mut dyn Output,
            stderr: &mut dyn Output,
        ) -> Option<CommandStatus> {
            self.attempts.push(command.to_string());
            match command {
                "echo" | "external" => {
                    if write_all(stdout, b"external application\n").is_ok() {
                        Some(CommandStatus::Success)
                    } else {
                        Self::failure(stderr, command, "stream I/O failed", CommandStatus::Failure)
                    }
                }
                "cat" if words.len() == 2 => match namespace.read_file(cwd, &words[1]) {
                    Ok(bytes) if write_all(stdout, &bytes).is_ok() => Some(CommandStatus::Success),
                    Ok(_) => {
                        Self::failure(stderr, command, "stream I/O failed", CommandStatus::Failure)
                    }
                    Err(error) => {
                        let status = if error == FsError::NotFound {
                            CommandStatus::NotFound
                        } else {
                            CommandStatus::Failure
                        };
                        Self::failure(stderr, command, &format!("{}: {error}", words[1]), status)
                    }
                },
                "copy" if words.len() == 1 => {
                    let mut buffer = [0_u8; 512];
                    loop {
                        match stdin.read(&mut buffer) {
                            Ok(0) => return Some(CommandStatus::Success),
                            Ok(count) if write_all(stdout, &buffer[..count]).is_ok() => {}
                            Ok(_) | Err(_) => {
                                return Self::failure(
                                    stderr,
                                    command,
                                    "stream I/O failed",
                                    CommandStatus::Failure,
                                );
                            }
                        }
                    }
                }
                "write" if words.len() == 2 => {
                    let mut bytes = Vec::new();
                    let mut buffer = [0_u8; 512];
                    loop {
                        let Ok(count) = stdin.read(&mut buffer) else {
                            return Self::failure(
                                stderr,
                                command,
                                "stream I/O failed",
                                CommandStatus::Failure,
                            );
                        };
                        if count == 0 {
                            break;
                        }
                        if bytes.len().saturating_add(count) > PIPE_CAPACITY {
                            return Self::failure(
                                stderr,
                                command,
                                "input exceeds pipeline capacity",
                                CommandStatus::Failure,
                            );
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    match namespace.write_file(cwd, &words[1], &bytes) {
                        Ok(()) => Some(CommandStatus::Success),
                        Err(error) => Self::failure(
                            stderr,
                            command,
                            &format!("{}: {error}", words[1]),
                            CommandStatus::Failure,
                        ),
                    }
                }
                "fail" => {
                    Self::failure(stderr, command, "requested failure", CommandStatus::Failure)
                }
                _ => None,
            }
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
    fn parser_enforces_every_exact_byte_word_and_stage_boundary() {
        let exact_line = "x".repeat(MAX_LINE_BYTES);
        assert_eq!(
            parse_line(&exact_line).map(|pipeline| pipeline.stages.len()),
            Ok(1)
        );
        assert_eq!(
            parse_line(&format!("{exact_line}x")),
            Err(ParseError::LineTooLong)
        );

        let utf8_line = format!("echo a{}", "é".repeat(253));
        assert_eq!(utf8_line.len(), MAX_LINE_BYTES);
        assert!(parse_line(&utf8_line).is_ok());

        let exact_words = core::iter::repeat_n("x", MAX_ARGS)
            .collect::<Vec<_>>()
            .join(" ");
        let parsed = parse_line(&exact_words).unwrap_or_default();
        assert_eq!(parsed.stages[0].words.len(), MAX_ARGS);
        assert_eq!(
            parse_line(&format!("{exact_words} x")),
            Err(ParseError::TooManyArguments)
        );

        let exact_stages = core::iter::repeat_n("echo", MAX_PIPELINE_STAGES)
            .collect::<Vec<_>>()
            .join(" | ");
        assert_eq!(
            parse_line(&exact_stages).map(|pipeline| pipeline.stages.len()),
            Ok(MAX_PIPELINE_STAGES)
        );
        assert_eq!(
            parse_line(&format!("{exact_stages} | echo")),
            Err(ParseError::TooManyStages)
        );
    }

    #[test]
    fn pipeline_connects_bounded_byte_streams() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(1024);
        let mut error = BoundedOutput::new(1024);
        let status = shell.execute_with_external(
            "cat /help/readme | copy",
            &mut input,
            &mut output,
            &mut error,
            &mut external,
        );
        assert_eq!(status, CommandStatus::Success);
        assert_eq!(output.as_slice(), b"alpha\nbeta alpha\n");
        assert!(error.as_slice().is_empty());
    }

    #[test]
    fn ordinary_commands_require_applications_and_unknown_names_stay_distinct() {
        let mut shell = shell();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(64);
        let mut error = BoundedOutput::new(128);

        assert_eq!(
            shell.execute("cat /help/readme", &mut input, &mut output, &mut error),
            CommandStatus::NotFound
        );
        assert_eq!(error.as_slice(), b"cat: application unavailable\n");

        let mut error = BoundedOutput::new(128);
        assert_eq!(
            shell.execute("tcp 192.0.2.1 80", &mut input, &mut output, &mut error),
            CommandStatus::NotFound
        );
        assert_eq!(error.as_slice(), b"tcp: application unavailable\n");

        let mut error = BoundedOutput::new(128);
        assert_eq!(
            shell.execute("nope", &mut input, &mut output, &mut error),
            CommandStatus::NotFound
        );
        assert_eq!(error.as_slice(), b"nope: unknown command\n");
    }

    #[test]
    fn external_apps_execute_but_never_shadow_intrinsics() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(256);
        let mut error = BoundedOutput::new(256);

        assert_eq!(
            shell.execute_with_external(
                "echo ignored",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert_eq!(output.as_slice(), b"external application\n");

        assert_eq!(
            shell.execute_with_external(
                "cd /help",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert_eq!(shell.cwd(), "/help");
        assert!(!external.attempts.iter().any(|name| name == "cd"));

        let mut app_output = BoundedOutput::new(256);
        assert_eq!(
            shell.execute_with_external(
                "external",
                &mut input,
                &mut app_output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert_eq!(app_output.as_slice(), b"external application\n");
    }

    #[test]
    fn machine_control_commands_are_non_shadowable_intrinsics() {
        assert_eq!(command_class("cd"), Some(CommandClass::Intrinsic));
        assert_eq!(command_class("poweroff"), Some(CommandClass::Intrinsic));
        assert_eq!(command_class("reboot"), Some(CommandClass::Intrinsic));
        assert_eq!(command_class("cat"), Some(CommandClass::Application));
        assert_eq!(command_class("man"), Some(CommandClass::Application));
        assert_eq!(command_class("printf"), Some(CommandClass::Application));
        assert_eq!(command_class("tcp"), Some(CommandClass::Application));
        assert_eq!(command_class("help"), None);
        assert_eq!(command_synopsis("man"), Some("man COMMAND"));
        assert_eq!(command_synopsis("printf"), Some("printf FORMAT [ARG...]"));
        assert_eq!(command_synopsis("tcp"), Some("tcp ADDRESS PORT [TEXT...]"));
        assert!(COMMANDS.windows(2).all(|pair| pair[0].name < pair[1].name));

        let intrinsic_names: Vec<&str> = COMMANDS
            .iter()
            .filter(|command| command.class == CommandClass::Intrinsic)
            .map(|command| command.name)
            .collect();
        assert_eq!(intrinsic_names, ["cd", "poweroff", "reboot"]);
    }

    #[test]
    fn machine_control_commands_request_exact_terminal_action() {
        let mut poweroff_shell = shell();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(64);
        let mut error = BoundedOutput::new(64);
        assert_eq!(
            poweroff_shell.execute("poweroff", &mut input, &mut output, &mut error),
            CommandStatus::Success
        );
        assert_eq!(
            poweroff_shell.machine_action(),
            Some(MachineAction::PowerOff)
        );

        let mut reboot_shell = shell();
        assert_eq!(
            reboot_shell.execute("reboot", &mut input, &mut output, &mut error),
            CommandStatus::Success
        );
        assert_eq!(reboot_shell.machine_action(), Some(MachineAction::Reboot));
    }

    #[test]
    fn completion_uses_command_pipeline_and_vfs_context() {
        let mut shell = shell();
        let command = shell.complete("he", 2, CompletionConfig::standard());
        assert_eq!(command.common_replacement(), Some("hexdump "));

        let manual = shell.complete("man ec", 6, CompletionConfig::standard());
        assert_eq!(manual.candidates[0].replacement, "echo ");

        let pipeline = shell.complete("echo x | pw", 11, CompletionConfig::standard());
        assert_eq!(pipeline.candidates[0].replacement, "pwd ");

        let directory = shell.complete("cd /he", 6, CompletionConfig::standard());
        assert_eq!(directory.candidates[0].replacement, "/help/");

        let file = shell.complete("cat /help/r", 11, CompletionConfig::standard());
        assert_eq!(file.candidates[0].replacement, "/help/readme ");
    }

    #[test]
    fn completion_configuration_is_validated_and_enforced() {
        assert_eq!(
            CompletionConfig::new(1, 0),
            Err(CompletionConfigError::InconsistentCapacity)
        );
        let mut shell = shell();
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
    fn exact_capacity_pipeline_succeeds_and_one_extra_byte_is_atomic() {
        let mut namespace = Namespace::new(RamFsQuota::default());
        let exact = alloc::vec![b'x'; PIPE_CAPACITY];
        let oversized = alloc::vec![b'y'; PIPE_CAPACITY + 1];
        assert_eq!(namespace.add_read_only_file("/exact", &exact), Ok(()));
        assert_eq!(
            namespace.add_read_only_file("/oversized", &oversized),
            Ok(())
        );
        let mut shell = Shell::new(namespace, "test", MachineMemorySnapshot::hosted(), true)
            .unwrap_or_else(|_| std::process::abort());
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(PIPE_CAPACITY);
        let mut error = BoundedOutput::new(256);

        assert_eq!(
            shell.execute_with_external(
                "cat /exact | copy",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert_eq!(output.as_slice(), exact);

        let mut output = BoundedOutput::new(64);
        let mut error = BoundedOutput::new(256);
        assert_eq!(
            shell.execute_with_external(
                "cat /oversized | copy",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Failure
        );
        assert!(output.as_slice().is_empty());
    }

    #[test]
    fn failed_stage_stops_side_effects_and_stderr_never_enters_the_pipe() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(128);
        let mut error = BoundedOutput::new(256);
        let status = shell.execute_with_external(
            "fail | write /tmp/error-copy",
            &mut input,
            &mut output,
            &mut error,
            &mut external,
        );

        assert_eq!(status, CommandStatus::Failure);
        assert!(output.as_slice().is_empty());
        assert_eq!(error.as_slice(), b"fail: requested failure\n");
        assert_eq!(
            shell.namespace.read_file("/", "/tmp/error-copy"),
            Err(FsError::NotFound)
        );
        assert_eq!(external.attempts, ["fail"]);
    }

    #[test]
    fn memory_report_uses_supplied_machine_snapshot() {
        let report = format_memory_report(
            "snapshot-test",
            MachineMemorySnapshot::firmware(123_456, 78_900),
            None,
            Namespace::new(RamFsQuota::default()).memory_stats(),
        );
        assert!(report.contains("memory owner: firmware\n"));
        assert!(report.contains("memory map: firmware snapshot (advisory)\n"));
        assert!(report.contains("total usable: 123456 (120.56 KiB)\n"));
        assert!(report.contains("reserved: 78900 (77.05 KiB)\n"));
    }

    #[test]
    fn memory_report_exposes_owned_frame_and_heap_counters() {
        let report = format_memory_report(
            "owned-test",
            MachineMemorySnapshot::kernel(4096, 8192, 10, 9, 1024, 128, 256, 1),
            Some(InputQueueStats {
                capacity: 256,
                queued: 2,
                delivered: 17,
                dropped: 0,
                interrupts: 9,
                idle_waits: 8,
                wakeups: 7,
            }),
            Namespace::new(RamFsQuota::default()).memory_stats(),
        );
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
    }
}

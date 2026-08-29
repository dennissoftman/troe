//! Bounded shell grammar, logical lists, byte-stream pipelines, and session/job intrinsics.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod recovery_completion;

use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::str::FromStr;
use recovery_completion::{ActiveResolver, IntrinsicCompletionRegistry, PackageCompletionRegistry};
use troe_completion::{
    AddressConstraints, AddressFamily, CompletionLimits, CompletionRequest, IntegerConstraints,
    IntegerRadix, PathKind, PortRequirement, Resolver,
};
use troe_core::{
    BoundedOutput, CommandStatus, Input, MAX_ARGS, MAX_LINE_BYTES, MAX_PIPELINE_STAGES,
    MachineMemoryOwner, MachineMemorySnapshot, MemoryStats, Output, PIPE_CAPACITY, SliceInput,
    StreamError, write_all,
};
use troe_driver::InputQueueStats;
use troe_fs_api::{FILE_IO_BUFFER_BYTES, FsError, MAX_FILE_IO_BUFFER_BYTES, NodeKind};
use troe_vfs::Namespace;

/// Shared namespace ownership used by stream endpoints and KEX services.
pub type SharedNamespace = Rc<RefCell<Namespace>>;

/// Trusted dynamic state domains available to shell-owned completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicCompletionDomain {
    /// Numeric identifiers for jobs owned by this shell session.
    Job,
    /// Stable names from the active service-supervisor configuration.
    Service,
    /// Stable names from the configured volume policy.
    Volume,
}

/// Bounded visitor controlled by the shell's completion policy.
pub trait CompletionVisitor {
    /// Offer one current candidate. `false` asks the source to stop enumerating.
    fn candidate(&mut self, value: &str) -> bool;
}

/// Trusted composition-root access to dynamic completion state.
pub trait CompletionEnvironment {
    /// Visit current values for one semantic domain without executing an app.
    fn visit(&mut self, domain: DynamicCompletionDomain, visitor: &mut dyn CompletionVisitor);
}

struct EmptyCompletionEnvironment;

impl CompletionEnvironment for EmptyCompletionEnvironment {
    fn visit(&mut self, _domain: DynamicCompletionDomain, _visitor: &mut dyn CompletionVisitor) {}
}

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
    /// A logical operator begins, ends, or contains an empty command.
    EmptyCommand,
    /// A redirection operator has no following path.
    MissingRedirectionTarget,
    /// One stage specifies the same redirection direction more than once.
    DuplicateRedirection,
    /// Input or output redirection is attached to an unsupported pipeline stage.
    InvalidRedirectionPosition,
    /// Background placement was not the final operator on the line.
    InvalidBackgroundPosition,
    /// Concurrent background pipelines are not implemented.
    BackgroundPipeline,
}

/// Standard-output file redirection selected by one shell stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutputRedirection {
    /// Truncate the destination before executing, then stream command output.
    Replace(String),
    /// Open or create the destination, then stream output at its end.
    Append(String),
}

impl OutputRedirection {
    fn path(&self) -> &str {
        match self {
            Self::Replace(path) | Self::Append(path) => path,
        }
    }
}

/// One parsed command invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stage {
    /// Command name followed by its arguments.
    pub words: Vec<String>,
    /// Optional file used as this stage's standard input.
    pub input: Option<String>,
    /// Optional streamed file destination used as this stage's standard output.
    pub output: Option<OutputRedirection>,
}

/// A bounded sequence of commands connected by byte streams.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Pipeline {
    /// Parsed stages, in execution order.
    pub stages: Vec<Stage>,
    /// Whether the launcher should return the session prompt after admission.
    pub background: bool,
}

/// Short-circuit condition connecting one pipeline to the preceding pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalOperator {
    /// Execute the following pipeline only after success.
    And,
    /// Execute the following pipeline only after non-success.
    Or,
}

/// One pipeline in a left-associative logical command list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandListEntry {
    /// Condition applied to the preceding pipeline, absent for the first entry.
    pub operator: Option<LogicalOperator>,
    /// Pipeline executed when its condition is satisfied.
    pub pipeline: Pipeline,
}

/// A bounded sequence of pipelines connected by `&&` and `||`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommandList {
    /// Parsed pipelines and their short-circuit conditions.
    pub entries: Vec<CommandListEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Quote {
    None,
    Single,
    Double,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingRedirection {
    Input,
    Replace,
    Append,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IntrinsicSpec {
    id: IntrinsicId,
    name: &'static str,
    synopsis: &'static str,
}

/// Stable execution placement for a shell command name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandClass {
    /// Shell-owned behavior that cannot be replaced by an application.
    Intrinsic,
    /// A name that must resolve to a KEX application.
    Application,
}

/// Placement requested by the shell for one application launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPlacement {
    /// Attach the process to the owning shell's foreground job.
    Foreground,
    /// Retain the process as a session-owned background job.
    Background,
}

/// Shell-owned request for one session background job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobControl {
    /// List retained jobs and their current lifecycle state.
    List,
    /// Copy the retained output of one job.
    Log(u32),
    /// Request cancellation of one job.
    Cancel(u32),
    /// Wait for one job to become terminal.
    Wait(u32),
    /// Attach to one job until it becomes terminal.
    Foreground(u32),
}

/// Shell-owned request for the SCFG service supervisor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceControl {
    /// List every configured service.
    List,
    /// Show one configured service.
    Status(String),
    /// Select the desired up state.
    Start(String),
    /// Select the desired down state.
    Stop(String),
    /// Stop and relaunch one service.
    Restart(String),
    /// Copy one service's retained recent output.
    Log(String),
}

/// Application resolver used for every non-intrinsic command.
///
/// Returning `None` means that no application was resolved. No shell-owned
/// utility fallback is attempted.
pub trait ExternalCommand {
    /// Resolve and execute one complete command invocation.
    #[allow(clippy::too_many_arguments)]
    fn execute<'stream>(
        &mut self,
        command: &str,
        words: &[String],
        cwd: &str,
        namespace: &SharedNamespace,
        placement: ExecutionPlacement,
        stdin: &'stream mut dyn Input,
        stdout: &'stream mut dyn Output,
        stderr: &'stream mut dyn Output,
    ) -> Option<CommandStatus>;

    /// Take a successfully staged batch of physical command lines.
    ///
    /// Implementations return a batch only after the interpreter application
    /// exits successfully. The shell executes it synchronously in the current
    /// session, so intrinsics such as `cd` update the owning session.
    fn take_script_lines(&mut self) -> Option<Vec<String>> {
        None
    }

    /// Perform one shell-owned job-control operation.
    ///
    /// Returning `None` means resident process control is unavailable in this
    /// execution environment.
    fn control_job(
        &mut self,
        _request: JobControl,
        _stdout: &mut dyn Output,
        _stderr: &mut dyn Output,
    ) -> Option<CommandStatus> {
        None
    }

    /// Perform one shell-owned service-control operation.
    fn control_service(
        &mut self,
        _request: ServiceControl,
        _stdout: &mut dyn Output,
        _stderr: &mut dyn Output,
    ) -> Option<CommandStatus> {
        None
    }
}

const MAX_SCRIPT_DEPTH: u8 = 4;
const MAX_SCRIPT_COMMANDS: usize = 1024;

struct EmptyScriptInput;

impl Input for EmptyScriptInput {
    fn read(&mut self, _destination: &mut [u8]) -> Result<usize, StreamError> {
        Ok(0)
    }
}

struct NoExternalCommand;

impl ExternalCommand for NoExternalCommand {
    fn execute<'stream>(
        &mut self,
        _command: &str,
        _words: &[String],
        _cwd: &str,
        _namespace: &SharedNamespace,
        _placement: ExecutionPlacement,
        _stdin: &'stream mut dyn Input,
        _stdout: &'stream mut dyn Output,
        _stderr: &'stream mut dyn Output,
    ) -> Option<CommandStatus> {
        None
    }
}

const MIN_FILE_CHUNK_BYTES: usize = 4 * 1024;

struct NamespaceFileInput {
    namespace: SharedNamespace,
    cwd: String,
    path: String,
    offset: u64,
}

impl NamespaceFileInput {
    fn new(namespace: &SharedNamespace, cwd: &str, path: &str) -> Result<Self, FsError> {
        let metadata = namespace.borrow_mut().metadata(cwd, path)?;
        if metadata.kind != NodeKind::File {
            return Err(FsError::WrongType);
        }
        Ok(Self {
            namespace: Rc::clone(namespace),
            cwd: cwd.to_string(),
            path: path.to_string(),
            offset: 0,
        })
    }
}

impl Input for NamespaceFileInput {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, StreamError> {
        let count = self
            .namespace
            .borrow_mut()
            .read_file_at(&self.cwd, &self.path, self.offset, destination)
            .map_err(|_| StreamError::Device)?;
        self.offset = self
            .offset
            .checked_add(u64::try_from(count).map_err(|_| StreamError::Device)?)
            .ok_or(StreamError::Device)?;
        Ok(count)
    }
}

struct NamespaceFileOutput {
    namespace: SharedNamespace,
    cwd: String,
    path: String,
    buffer: Vec<u8>,
    chunk_bytes: usize,
    failure: Option<FsError>,
}

impl NamespaceFileOutput {
    fn new(
        namespace: &SharedNamespace,
        cwd: &str,
        redirection: &OutputRedirection,
    ) -> Result<Self, FsError> {
        let path = redirection.path();
        let mut namespace_ref = namespace.borrow_mut();
        match redirection {
            OutputRedirection::Replace(_) => namespace_ref.truncate_file(cwd, path)?,
            OutputRedirection::Append(_) => match namespace_ref.metadata(cwd, path) {
                Ok(metadata) if metadata.kind == NodeKind::File => {
                    namespace_ref.sync_file(cwd, path)?;
                }
                Ok(_) => return Err(FsError::WrongType),
                Err(FsError::NotFound) => namespace_ref.truncate_file(cwd, path)?,
                Err(error) => return Err(error),
            },
        }
        drop(namespace_ref);
        Ok(Self {
            namespace: Rc::clone(namespace),
            cwd: cwd.to_string(),
            path: path.to_string(),
            buffer: Vec::new(),
            chunk_bytes: FILE_IO_BUFFER_BYTES,
            failure: None,
        })
    }

    fn flush(&mut self) -> Result<(), FsError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.buffer.is_empty() {
            return Ok(());
        }
        if let Err(error) =
            self.namespace
                .borrow_mut()
                .append_file(&self.cwd, &self.path, &self.buffer)
        {
            self.failure = Some(error);
            return Err(error);
        }
        self.buffer.clear();
        Ok(())
    }

    fn finish(mut self) -> Result<(), FsError> {
        self.flush()?;
        self.namespace.borrow_mut().sync_file(&self.cwd, &self.path)
    }
}

impl Output for NamespaceFileOutput {
    fn set_chunk_size(&mut self, bytes: usize) -> Result<(), StreamError> {
        if !(MIN_FILE_CHUNK_BYTES..=MAX_FILE_IO_BUFFER_BYTES).contains(&bytes)
            || !bytes.is_power_of_two()
        {
            return Err(StreamError::Unsupported);
        }
        self.flush().map_err(|_| StreamError::Device)?;
        self.chunk_bytes = bytes;
        Ok(())
    }

    fn write(&mut self, mut bytes: &[u8]) -> Result<usize, StreamError> {
        if self.failure.is_some() {
            return Err(StreamError::Device);
        }
        let accepted = bytes.len();
        while !bytes.is_empty() {
            let available = self.chunk_bytes.saturating_sub(self.buffer.len());
            if available == 0 {
                self.flush().map_err(|_| StreamError::Device)?;
                continue;
            }
            let count = available.min(bytes.len());
            self.buffer
                .try_reserve_exact(count)
                .map_err(|_| StreamError::NoSpace)?;
            self.buffer.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.buffer.len() == self.chunk_bytes {
                self.flush().map_err(|_| StreamError::Device)?;
            }
        }
        Ok(accepted)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntrinsicId {
    Cd,
    Fg,
    Jobs,
    Kill,
    Log,
    PowerOff,
    Reboot,
    Svc,
    Wait,
}

const INTRINSICS: &[IntrinsicSpec] = &[
    IntrinsicSpec {
        id: IntrinsicId::Cd,
        name: "cd",
        synopsis: "cd PATH",
    },
    IntrinsicSpec {
        id: IntrinsicId::Fg,
        name: "fg",
        synopsis: "fg JOB",
    },
    IntrinsicSpec {
        id: IntrinsicId::Jobs,
        name: "jobs",
        synopsis: "jobs",
    },
    IntrinsicSpec {
        id: IntrinsicId::Kill,
        name: "kill",
        synopsis: "kill JOB",
    },
    IntrinsicSpec {
        id: IntrinsicId::Log,
        name: "log",
        synopsis: "log JOB",
    },
    IntrinsicSpec {
        id: IntrinsicId::PowerOff,
        name: "poweroff",
        synopsis: "poweroff",
    },
    IntrinsicSpec {
        id: IntrinsicId::Reboot,
        name: "reboot",
        synopsis: "reboot",
    },
    IntrinsicSpec {
        id: IntrinsicId::Svc,
        name: "svc",
        synopsis: "svc [status [NAME] | start|stop|restart|log NAME]",
    },
    IntrinsicSpec {
        id: IntrinsicId::Wait,
        name: "wait",
        synopsis: "wait JOB",
    },
];

const COMMAND_CATALOG_MAX_ENTRIES: usize = 1024;
const COMMAND_CATALOG_MAX_BYTES: usize = 64 * 1024;
const COMMAND_CATALOG_PAGE_ENTRIES: usize = 64;
const COMMAND_CATALOG_PAGE_BYTES: usize = 4096;

#[derive(Debug)]
struct CommandCatalog {
    revision: Option<u64>,
    names: Vec<String>,
    truncated: bool,
}

impl CommandCatalog {
    fn new() -> Result<Self, FsError> {
        let mut names = Vec::new();
        names
            .try_reserve_exact(INTRINSICS.len())
            .map_err(|_| FsError::NoSpace)?;
        for intrinsic in INTRINSICS {
            names.push(intrinsic.name.to_string());
        }
        Ok(Self {
            revision: None,
            names,
            truncated: false,
        })
    }

    fn refresh(&mut self, namespace: &mut Namespace) {
        let revision = namespace.command_revision();
        if self.revision == Some(revision) {
            return;
        }
        if let Ok((names, truncated)) = load_command_catalog(namespace) {
            self.names = names;
            self.truncated = truncated;
            self.revision = Some(revision);
        }
    }
}

fn load_command_catalog(namespace: &mut Namespace) -> Result<(Vec<String>, bool), FsError> {
    let mut names = Vec::new();
    names
        .try_reserve_exact(INTRINSICS.len())
        .map_err(|_| FsError::NoSpace)?;
    let mut retained_bytes = 0_usize;
    for intrinsic in INTRINSICS {
        retained_bytes = retained_bytes
            .checked_add(intrinsic.name.len())
            .ok_or(FsError::Overflow)?;
        names.push(intrinsic.name.to_string());
    }

    let mut cursor = 0_u64;
    let mut scanned = 0_usize;
    let mut truncated = false;
    'pages: loop {
        let page = match namespace.list_bounded(
            "/",
            "/bin",
            cursor,
            COMMAND_CATALOG_PAGE_ENTRIES,
            COMMAND_CATALOG_PAGE_BYTES,
        ) {
            Ok(page) => page,
            Err(FsError::NotFound) => break,
            Err(error) => return Err(error),
        };
        let page_len = page.entries.len();
        for entry in page.entries {
            scanned = scanned.checked_add(1).ok_or(FsError::Overflow)?;
            if scanned > COMMAND_CATALOG_MAX_ENTRIES {
                truncated = true;
                break 'pages;
            }
            if entry.kind != NodeKind::File {
                continue;
            }
            let Some(name) = entry
                .name
                .strip_suffix(".kex")
                .filter(|name| valid_command_name(name))
            else {
                continue;
            };
            let next_bytes = retained_bytes
                .checked_add(name.len())
                .ok_or(FsError::Overflow)?;
            if next_bytes > COMMAND_CATALOG_MAX_BYTES {
                truncated = true;
                break 'pages;
            }
            names.try_reserve(1).map_err(|_| FsError::NoSpace)?;
            names.push(name.to_string());
            retained_bytes = next_bytes;
        }
        match page.next_cursor {
            Some(next) if next != cursor && page_len != 0 => cursor = next,
            Some(_) => return Err(FsError::Corrupt),
            None => break,
        }
    }
    names.sort_unstable();
    names.dedup();
    Ok((names, truncated))
}

fn valid_command_name(name: &str) -> bool {
    !name.is_empty()
        && name.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// Resolver classification for one non-intrinsic command token.
///
/// Bare command names retain the trusted `/bin/<name>.kex` catalog contract.
/// A token containing `/` is an explicit filesystem path and is never looked
/// up in the catalog or rewritten with an extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalCommandReference<'a> {
    /// Valid bare name eligible for `/bin` catalog lookup.
    CatalogName(&'a str),
    /// Exact path selected by the caller, relative to its logical cwd or absolute.
    Path(&'a str),
}

/// Classify one non-intrinsic command token for an application resolver.
///
/// Invalid bare names are rejected. Explicit paths retain their exact spelling
/// so the VFS remains the sole authority for normalization and confinement.
#[must_use]
pub fn external_command_reference(command: &str) -> Option<ExternalCommandReference<'_>> {
    if command.as_bytes().contains(&b'/') {
        Some(ExternalCommandReference::Path(command))
    } else if valid_command_name(command) {
        Some(ExternalCommandReference::CatalogName(command))
    } else {
        None
    }
}

/// Return whether a name is reserved for shell-intrinsic execution.
///
/// Application names are discovered dynamically from `/bin` and therefore do
/// not appear in this static classification.
#[must_use]
pub fn command_class(name: &str) -> Option<CommandClass> {
    INTRINSICS
        .iter()
        .find(|command| command.name == name)
        .map(|_| CommandClass::Intrinsic)
}

/// Return the concise synopsis associated with a shell intrinsic.
#[must_use]
pub fn command_synopsis(name: &str) -> Option<&'static str> {
    INTRINSICS
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

/// Parse one pipeline with quoting and bounded file redirection without expansion.
///
/// # Errors
///
/// Fails on configured line/word/stage bounds, malformed quotes, or empty stages.
#[allow(clippy::too_many_lines)]
pub fn parse_line(line: &str) -> Result<Pipeline, ParseError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(ParseError::LineTooLong);
    }
    let mut stages = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut word_started = false;
    let mut quote = Quote::None;
    let mut input = None;
    let mut output = None;
    let mut pending = None;
    let mut background = false;

    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
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
                    push_token(
                        &mut words,
                        &mut input,
                        &mut output,
                        &mut pending,
                        &mut word,
                        &mut word_started,
                    )?;
                    if pending.is_some() {
                        return Err(ParseError::MissingRedirectionTarget);
                    }
                    if words.is_empty() {
                        return Err(ParseError::EmptyStage);
                    }
                    stages.push(Stage {
                        words,
                        input,
                        output,
                    });
                    if stages.len() >= MAX_PIPELINE_STAGES {
                        return Err(ParseError::TooManyStages);
                    }
                    words = Vec::new();
                    input = None;
                    output = None;
                }
                '&' => {
                    push_token(
                        &mut words,
                        &mut input,
                        &mut output,
                        &mut pending,
                        &mut word,
                        &mut word_started,
                    )?;
                    if pending.is_some()
                        || words.is_empty()
                        || characters.any(|remaining| !remaining.is_whitespace())
                    {
                        return Err(ParseError::InvalidBackgroundPosition);
                    }
                    background = true;
                    break;
                }
                '<' | '>' => {
                    push_token(
                        &mut words,
                        &mut input,
                        &mut output,
                        &mut pending,
                        &mut word,
                        &mut word_started,
                    )?;
                    if pending.is_some() {
                        return Err(ParseError::MissingRedirectionTarget);
                    }
                    pending = Some(if character == '<' {
                        PendingRedirection::Input
                    } else if characters.next_if_eq(&'>').is_some() {
                        PendingRedirection::Append
                    } else {
                        PendingRedirection::Replace
                    });
                }
                value if value.is_whitespace() => {
                    push_token(
                        &mut words,
                        &mut input,
                        &mut output,
                        &mut pending,
                        &mut word,
                        &mut word_started,
                    )?;
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
    push_token(
        &mut words,
        &mut input,
        &mut output,
        &mut pending,
        &mut word,
        &mut word_started,
    )?;
    if pending.is_some() {
        return Err(ParseError::MissingRedirectionTarget);
    }
    if words.is_empty() {
        if stages.is_empty() && input.is_none() && output.is_none() {
            return Ok(Pipeline::default());
        }
        return Err(ParseError::EmptyStage);
    }
    stages.push(Stage {
        words,
        input,
        output,
    });
    if background && stages.len() != 1 {
        return Err(ParseError::BackgroundPipeline);
    }
    let last = stages.len().saturating_sub(1);
    if stages.iter().enumerate().any(|(index, stage)| {
        (stage.input.is_some() && index != 0) || (stage.output.is_some() && index != last)
    }) {
        return Err(ParseError::InvalidRedirectionPosition);
    }
    Ok(Pipeline { stages, background })
}

/// Parse a complete line as left-associative pipelines connected by `&&` and `||`.
///
/// Logical operators have equal precedence. Quoted operators remain literal text.
///
/// # Errors
///
/// Fails on malformed logical operators or any error in a contained pipeline.
pub fn parse_command_list(line: &str) -> Result<CommandList, ParseError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(ParseError::LineTooLong);
    }

    let mut entries = Vec::new();
    let mut quote = Quote::None;
    let mut start = 0_usize;
    let mut pending_operator = None;
    let mut characters = line.char_indices().peekable();

    while let Some((index, character)) = characters.next() {
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
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '&' | '|' => {
                    let Some(&(next_index, next)) = characters.peek() else {
                        continue;
                    };
                    if next != character {
                        continue;
                    }
                    let operator = if character == '&' {
                        LogicalOperator::And
                    } else {
                        LogicalOperator::Or
                    };
                    let pipeline = parse_line(&line[start..index])?;
                    if pipeline.stages.is_empty() {
                        return Err(ParseError::EmptyCommand);
                    }
                    if pipeline.background {
                        return Err(ParseError::InvalidBackgroundPosition);
                    }
                    entries.push(CommandListEntry {
                        operator: pending_operator,
                        pipeline,
                    });
                    pending_operator = Some(operator);
                    start = next_index + next.len_utf8();
                    let _consumed = characters.next();
                }
                _ => {}
            },
        }
    }

    let pipeline = parse_line(&line[start..])?;
    if pipeline.stages.is_empty() {
        if entries.is_empty() && pending_operator.is_none() {
            return Ok(CommandList::default());
        }
        return Err(ParseError::EmptyCommand);
    }
    entries.push(CommandListEntry {
        operator: pending_operator,
        pipeline,
    });
    Ok(CommandList { entries })
}

fn push_token(
    words: &mut Vec<String>,
    input: &mut Option<String>,
    output: &mut Option<OutputRedirection>,
    pending: &mut Option<PendingRedirection>,
    word: &mut String,
    started: &mut bool,
) -> Result<(), ParseError> {
    if *started {
        let token = core::mem::take(word);
        match pending.take() {
            Some(PendingRedirection::Input) => {
                if input.replace(token).is_some() {
                    return Err(ParseError::DuplicateRedirection);
                }
            }
            Some(PendingRedirection::Replace) => {
                if output.replace(OutputRedirection::Replace(token)).is_some() {
                    return Err(ParseError::DuplicateRedirection);
                }
            }
            Some(PendingRedirection::Append) => {
                if output.replace(OutputRedirection::Append(token)).is_some() {
                    return Err(ParseError::DuplicateRedirection);
                }
            }
            None => {
                if words.len() >= MAX_ARGS {
                    return Err(ParseError::TooManyArguments);
                }
                words.push(token);
            }
        }
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
    namespace: SharedNamespace,
    command_catalog: CommandCatalog,
    package_completions: PackageCompletionRegistry,
    intrinsic_completions: IntrinsicCompletionRegistry,
    cwd: String,
    machine_control: bool,
    machine_action: Option<MachineAction>,
    script_depth: u8,
    script_commands_remaining: usize,
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
        let command_catalog = CommandCatalog::new()?;
        let package_completions = PackageCompletionRegistry::new();
        let intrinsic_completions =
            IntrinsicCompletionRegistry::new().map_err(|_| FsError::Corrupt)?;
        Ok(Self {
            namespace: Rc::new(RefCell::new(namespace)),
            command_catalog,
            package_completions,
            intrinsic_completions,
            cwd: "/".to_string(),
            machine_control,
            machine_action: None,
            script_depth: 0,
            script_commands_remaining: 0,
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
        self.complete_with_environment(line, cursor, config, &mut EmptyCompletionEnvironment)
    }

    /// Complete with explicitly supplied trusted job, service, and volume state.
    ///
    /// The environment is a data source only. The shell retains filtering,
    /// sorting, deduplication, insertion, and resource-budget ownership.
    #[must_use]
    pub fn complete_with_environment(
        &mut self,
        line: &str,
        cursor: usize,
        config: CompletionConfig,
        environment: &mut dyn CompletionEnvironment,
    ) -> Completion {
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
        if context.redirect_target {
            return self.complete_paths(context, PathKind::Any, config);
        }
        if context.word_index == 0 {
            if context.prefix.as_bytes().contains(&b'/') {
                return self.complete_paths(context, PathKind::File, config);
            }
            self.command_catalog
                .refresh(&mut self.namespace.borrow_mut());
            return complete_commands(
                context,
                &self.command_catalog.names,
                self.command_catalog.truncated,
                config,
            );
        }
        let Some(command) = context.command else {
            return Completion::default();
        };
        let Ok(limits) = CompletionLimits::new(config.max_candidates(), config.max_bytes()) else {
            return Completion::default();
        };
        let Ok(request) = CompletionRequest::new(
            context.word_index,
            context.prefix,
            &context.arguments,
            limits,
        ) else {
            return Completion::default();
        };
        if let Some(resolution) = self.intrinsic_completions.resolve(command, request) {
            return self.complete_static_resolver(
                context,
                resolution.resolver(),
                config,
                environment,
            );
        }
        self.package_completions
            .refresh(&mut self.namespace.borrow_mut());
        let Some(resolver) = self.package_completions.resolve(command, request) else {
            return Completion::default();
        };
        self.complete_active_resolver(context, resolver, config, environment)
    }

    fn complete_static_resolver(
        &mut self,
        context: CompletionContext<'_>,
        resolver: Resolver<'static>,
        config: CompletionConfig,
        environment: &mut dyn CompletionEnvironment,
    ) -> Completion {
        match resolver {
            Resolver::Values(values) => complete_values(context, values, config),
            Resolver::Path(constraints) => self.complete_paths(context, constraints.kind(), config),
            Resolver::Command => self.complete_command_names(context, config),
            Resolver::Address(constraints) => complete_address(context, constraints, config),
            Resolver::Integer(constraints) => complete_integer(context, constraints, config),
            Resolver::Job => {
                complete_dynamic(context, DynamicCompletionDomain::Job, config, environment)
            }
            Resolver::Service => complete_dynamic(
                context,
                DynamicCompletionDomain::Service,
                config,
                environment,
            ),
            Resolver::Volume => complete_dynamic(
                context,
                DynamicCompletionDomain::Volume,
                config,
                environment,
            ),
        }
    }

    fn complete_active_resolver(
        &mut self,
        context: CompletionContext<'_>,
        resolver: ActiveResolver,
        config: CompletionConfig,
        environment: &mut dyn CompletionEnvironment,
    ) -> Completion {
        match resolver {
            ActiveResolver::Values(values) => complete_string_values(context, &values, config),
            ActiveResolver::Path(constraints) => {
                self.complete_paths(context, constraints.kind(), config)
            }
            ActiveResolver::Command => self.complete_command_names(context, config),
            ActiveResolver::Address(constraints) => complete_address(context, constraints, config),
            ActiveResolver::Integer(constraints) => complete_integer(context, constraints, config),
            ActiveResolver::Job => {
                complete_dynamic(context, DynamicCompletionDomain::Job, config, environment)
            }
            ActiveResolver::Service => complete_dynamic(
                context,
                DynamicCompletionDomain::Service,
                config,
                environment,
            ),
            ActiveResolver::Volume => complete_dynamic(
                context,
                DynamicCompletionDomain::Volume,
                config,
                environment,
            ),
        }
    }

    fn complete_command_names(
        &mut self,
        context: CompletionContext<'_>,
        config: CompletionConfig,
    ) -> Completion {
        self.command_catalog
            .refresh(&mut self.namespace.borrow_mut());
        complete_commands(
            context,
            &self.command_catalog.names,
            self.command_catalog.truncated,
            config,
        )
    }

    /// Execute a complete line, including bounded pipelines and logical operators.
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
        let command_list = match parse_command_list(line) {
            Ok(value) => value,
            Err(error) => {
                let _ignored = write_error(stderr, "parse", parse_error_text(error));
                return CommandStatus::Usage;
            }
        };
        self.execute_command_list(&command_list, stdin, stdout, stderr, external)
    }

    fn execute_command_list<E: ExternalCommand + ?Sized>(
        &mut self,
        command_list: &CommandList,
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
        external: &mut E,
    ) -> CommandStatus {
        let mut status = CommandStatus::Success;
        for entry in &command_list.entries {
            let should_execute = match entry.operator {
                None => true,
                Some(LogicalOperator::And) => status == CommandStatus::Success,
                Some(LogicalOperator::Or) => status != CommandStatus::Success,
            };
            if should_execute {
                status = self.execute_pipeline(&entry.pipeline, stdin, stdout, stderr, external);
                if self.machine_action.is_some() {
                    break;
                }
            }
        }
        status
    }

    fn execute_pipeline<E: ExternalCommand + ?Sized>(
        &mut self,
        pipeline: &Pipeline,
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
        external: &mut E,
    ) -> CommandStatus {
        let placement = if pipeline.background {
            ExecutionPlacement::Background
        } else {
            ExecutionPlacement::Foreground
        };

        let mut previous = Vec::new();
        for (index, stage) in pipeline.stages.iter().enumerate() {
            let last = index + 1 == pipeline.stages.len();
            let redirected_input = match stage.input.as_deref() {
                Some(path) => match NamespaceFileInput::new(&self.namespace, &self.cwd, path) {
                    Ok(input) => Some(input),
                    Err(error) => return fs_failure(stderr, "sh", path, error),
                },
                None => None,
            };
            let mut redirected_input = redirected_input;
            if last {
                if let Some(redirection) = stage.output.as_ref() {
                    let mut redirected_output =
                        match NamespaceFileOutput::new(&self.namespace, &self.cwd, redirection) {
                            Ok(output) => output,
                            Err(error) => {
                                return fs_failure(stderr, "sh", redirection.path(), error);
                            }
                        };
                    let status = self.dispatch_stage(
                        &stage.words,
                        index == 0,
                        redirected_input
                            .as_mut()
                            .map(|input| input as &mut dyn Input),
                        &previous,
                        stdin,
                        &mut redirected_output,
                        stderr,
                        external,
                        placement,
                    );
                    return match redirected_output.finish() {
                        Ok(()) => status,
                        Err(error) => fs_failure(stderr, "sh", redirection.path(), error),
                    };
                }
                return self.dispatch_stage(
                    &stage.words,
                    index == 0,
                    redirected_input
                        .as_mut()
                        .map(|input| input as &mut dyn Input),
                    &previous,
                    stdin,
                    stdout,
                    stderr,
                    external,
                    placement,
                );
            }

            let mut next = BoundedOutput::new(PIPE_CAPACITY);
            let status = self.dispatch_stage(
                &stage.words,
                index == 0,
                redirected_input
                    .as_mut()
                    .map(|input| input as &mut dyn Input),
                &previous,
                stdin,
                &mut next,
                stderr,
                external,
                ExecutionPlacement::Foreground,
            );
            if status != CommandStatus::Success {
                return status;
            }
            previous = next.into_vec();
        }
        CommandStatus::Failure
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_stage<E: ExternalCommand + ?Sized>(
        &mut self,
        words: &[String],
        first: bool,
        redirected_input: Option<&mut dyn Input>,
        previous: &[u8],
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
        external: &mut E,
        placement: ExecutionPlacement,
    ) -> CommandStatus {
        if let Some(input) = redirected_input {
            self.dispatch(words, input, stdout, stderr, external, placement)
        } else if first {
            self.dispatch(words, stdin, stdout, stderr, external, placement)
        } else {
            let mut input = SliceInput::new(previous);
            self.dispatch(words, &mut input, stdout, stderr, external, placement)
        }
    }

    fn dispatch<E: ExternalCommand + ?Sized>(
        &mut self,
        words: &[String],
        stdin: &mut dyn Input,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
        external: &mut E,
        placement: ExecutionPlacement,
    ) -> CommandStatus {
        let Some(command) = words.first().map(String::as_str) else {
            return CommandStatus::Success;
        };
        let intrinsic = INTRINSICS.iter().find(|spec| spec.name == command);
        if intrinsic.is_none()
            && let Some(status) = external.execute(
                command,
                words,
                &self.cwd,
                &self.namespace,
                placement,
                stdin,
                stdout,
                stderr,
            )
        {
            let script = external.take_script_lines();
            if status == CommandStatus::Success
                && let Some(lines) = script
            {
                return self.execute_script_lines(lines, stdout, stderr, external);
            }
            return status;
        }
        let Some(spec) = intrinsic else {
            let _ignored = write_error(stderr, command, "unknown command");
            return CommandStatus::NotFound;
        };
        if placement == ExecutionPlacement::Background {
            let _ignored = write_error(stderr, command, "shell intrinsic cannot run in background");
            return CommandStatus::Usage;
        }
        let intrinsic = spec.id;
        let args = &words[1..];
        if matches!(intrinsic, IntrinsicId::PowerOff | IntrinsicId::Reboot) && !self.machine_control
        {
            let _ignored = write_error(stderr, command, "machine-control capability denied");
            return CommandStatus::Denied;
        }
        match intrinsic {
            IntrinsicId::Cd => self.command_cd(args, stderr),
            IntrinsicId::Fg => control_job(
                external,
                args,
                "fg",
                "fg JOB",
                JobControl::Foreground,
                stdout,
                stderr,
            ),
            IntrinsicId::Jobs => {
                if args.is_empty() {
                    external
                        .control_job(JobControl::List, stdout, stderr)
                        .unwrap_or_else(|| {
                            let _ignored = write_error(stderr, "jobs", "job control unavailable");
                            CommandStatus::Failure
                        })
                } else {
                    usage(stderr, "jobs", "jobs")
                }
            }
            IntrinsicId::Kill => control_job(
                external,
                args,
                "kill",
                "kill JOB",
                JobControl::Cancel,
                stdout,
                stderr,
            ),
            IntrinsicId::Log => control_job(
                external,
                args,
                "log",
                "log JOB",
                JobControl::Log,
                stdout,
                stderr,
            ),
            IntrinsicId::PowerOff => {
                self.command_machine_action(args, stderr, MachineAction::PowerOff)
            }
            IntrinsicId::Reboot => self.command_machine_action(args, stderr, MachineAction::Reboot),
            IntrinsicId::Svc => control_service(external, args, stdout, stderr),
            IntrinsicId::Wait => control_job(
                external,
                args,
                "wait",
                "wait JOB",
                JobControl::Wait,
                stdout,
                stderr,
            ),
        }
    }

    fn execute_script_lines<E: ExternalCommand + ?Sized>(
        &mut self,
        lines: Vec<String>,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
        external: &mut E,
    ) -> CommandStatus {
        if self.script_depth >= MAX_SCRIPT_DEPTH {
            let _ignored = write_error(stderr, "sh", "script nesting limit exceeded");
            return CommandStatus::Usage;
        }
        let outermost = self.script_depth == 0;
        if outermost {
            self.script_commands_remaining = MAX_SCRIPT_COMMANDS;
        }
        self.script_depth = self.script_depth.saturating_add(1);
        let mut status = CommandStatus::Success;
        for line in lines {
            let command_list = match parse_command_list(&line) {
                Ok(value) => value,
                Err(error) => {
                    let _ignored = write_error(stderr, "parse", parse_error_text(error));
                    status = CommandStatus::Usage;
                    continue;
                }
            };
            let command_count = command_list.entries.len();
            if command_count > self.script_commands_remaining {
                let _ignored = write_error(stderr, "sh", "script command limit exceeded");
                status = CommandStatus::Usage;
                break;
            }
            self.script_commands_remaining -= command_count;
            let mut input = EmptyScriptInput;
            status = self.execute_command_list(&command_list, &mut input, stdout, stderr, external);
            if self.machine_action.is_some() {
                break;
            }
        }
        self.script_depth = self.script_depth.saturating_sub(1);
        if outermost {
            self.script_commands_remaining = 0;
        }
        status
    }

    fn complete_paths(
        &mut self,
        context: CompletionContext<'_>,
        path_kind: PathKind,
        config: CompletionConfig,
    ) -> Completion {
        let (directory, displayed_parent, name_prefix) = split_completion_path(context.prefix);
        let Ok(listing) = self.namespace.borrow_mut().list_matching_bounded(
            &self.cwd,
            directory,
            name_prefix,
            path_kind == PathKind::Directory,
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
            if path_kind == PathKind::File
                && entry.kind != NodeKind::File
                && entry.kind != NodeKind::Directory
            {
                continue;
            }
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
        match self.namespace.borrow_mut().resolve_dir(&self.cwd, &args[0]) {
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
    arguments: [Option<&'a str>; 4],
    redirect_target: bool,
}

#[allow(clippy::too_many_lines)]
fn completion_context(line: &str, cursor: usize) -> Option<CompletionContext<'_>> {
    let mut quote = Quote::None;
    let mut word_started = false;
    let mut word_start = 0_usize;
    let mut word_quoted = false;
    let mut word_redirect_target = false;
    let mut pending_redirection = false;
    let mut word_index = 0_usize;
    let mut command = None;
    let mut arguments = [None; 4];

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
                        word_redirect_target = pending_redirection;
                    }
                    word_quoted = true;
                    quote = if character == '\'' {
                        Quote::Single
                    } else {
                        Quote::Double
                    };
                }
                '|' | '&' => {
                    if word_started {
                        retain_completion_word(
                            line,
                            index,
                            word_start,
                            word_index,
                            word_quoted,
                            word_redirect_target,
                            &mut command,
                            &mut arguments,
                        );
                    }
                    word_started = false;
                    word_quoted = false;
                    word_redirect_target = false;
                    pending_redirection = false;
                    word_index = 0;
                    command = None;
                    arguments = [None; 4];
                }
                '<' | '>' => {
                    if word_started {
                        retain_completion_word(
                            line,
                            index,
                            word_start,
                            word_index,
                            word_quoted,
                            word_redirect_target,
                            &mut command,
                            &mut arguments,
                        );
                        if !word_redirect_target {
                            word_index = word_index.saturating_add(1);
                        }
                    }
                    word_started = false;
                    word_quoted = false;
                    word_redirect_target = false;
                    pending_redirection = true;
                }
                value if value.is_whitespace() => {
                    if word_started {
                        retain_completion_word(
                            line,
                            index,
                            word_start,
                            word_index,
                            word_quoted,
                            word_redirect_target,
                            &mut command,
                            &mut arguments,
                        );
                        if word_redirect_target {
                            pending_redirection = false;
                        } else {
                            word_index = word_index.saturating_add(1);
                        }
                        word_started = false;
                        word_quoted = false;
                        word_redirect_target = false;
                    }
                }
                _ => {
                    if !word_started {
                        word_started = true;
                        word_start = index;
                        word_redirect_target = pending_redirection;
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
        arguments,
        redirect_target: pending_redirection || word_redirect_target,
    })
}

#[allow(clippy::too_many_arguments)]
fn retain_completion_word<'line>(
    line: &'line str,
    end: usize,
    start: usize,
    word_index: usize,
    quoted: bool,
    redirect_target: bool,
    command: &mut Option<&'line str>,
    arguments: &mut [Option<&'line str>; 4],
) {
    if quoted || redirect_target {
        return;
    }
    if word_index == 0 {
        *command = Some(&line[start..end]);
    } else if word_index <= arguments.len() {
        arguments[word_index - 1] = Some(&line[start..end]);
    }
}

fn complete_commands(
    context: CompletionContext<'_>,
    names: &[String],
    catalog_truncated: bool,
    config: CompletionConfig,
) -> Completion {
    let mut completion = Completion {
        replacement_start: context.start,
        replacement_end: context.end,
        candidates: Vec::new(),
        truncated: catalog_truncated,
    };
    let mut retained_bytes = 0_usize;
    for name in names.iter().filter(|name| name.starts_with(context.prefix)) {
        let replacement = format!("{name} ");
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
            display: name.clone(),
            replacement,
        });
        retained_bytes = next_bytes;
    }
    completion
}

fn complete_values(
    context: CompletionContext<'_>,
    values: &[&str],
    config: CompletionConfig,
) -> Completion {
    let mut completion = Completion {
        replacement_start: context.start,
        replacement_end: context.end,
        candidates: Vec::new(),
        truncated: false,
    };
    let mut retained_bytes = 0_usize;
    for value in values
        .iter()
        .copied()
        .filter(|value| value.starts_with(context.prefix))
    {
        let replacement = format!("{value} ");
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
            display: value.to_string(),
            replacement,
        });
        retained_bytes = next_bytes;
    }
    completion
}

fn complete_string_values(
    context: CompletionContext<'_>,
    values: &[String],
    config: CompletionConfig,
) -> Completion {
    let references = values.iter().map(String::as_str);
    complete_value_iterator(context, references, config)
}

fn complete_value_iterator<'value>(
    context: CompletionContext<'_>,
    values: impl Iterator<Item = &'value str>,
    config: CompletionConfig,
) -> Completion {
    let mut completion = Completion {
        replacement_start: context.start,
        replacement_end: context.end,
        candidates: Vec::new(),
        truncated: false,
    };
    let mut retained_bytes = 0_usize;
    for value in values.filter(|value| value.starts_with(context.prefix)) {
        let replacement = format!("{value} ");
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
            display: value.to_string(),
            replacement,
        });
        retained_bytes = next_bytes;
    }
    completion
}

struct DynamicCollector<'prefix> {
    prefix: &'prefix str,
    max_candidates: usize,
    max_bytes: usize,
    retained_bytes: usize,
    values: Vec<String>,
    truncated: bool,
}

impl CompletionVisitor for DynamicCollector<'_> {
    fn candidate(&mut self, value: &str) -> bool {
        if !value.starts_with(self.prefix) || !is_bare_word_component(value) || value.is_empty() {
            return true;
        }
        if self.values.iter().any(|candidate| candidate == value) {
            return true;
        }
        let Some(next_bytes) = self.retained_bytes.checked_add(value.len() + 1) else {
            self.truncated = true;
            return false;
        };
        if self.values.len() >= self.max_candidates || next_bytes > self.max_bytes {
            self.truncated = true;
            return false;
        }
        if self.values.try_reserve(1).is_err() {
            self.truncated = true;
            return false;
        }
        self.values.push(value.to_string());
        self.retained_bytes = next_bytes;
        true
    }
}

fn complete_dynamic(
    context: CompletionContext<'_>,
    domain: DynamicCompletionDomain,
    config: CompletionConfig,
    environment: &mut dyn CompletionEnvironment,
) -> Completion {
    let mut collector = DynamicCollector {
        prefix: context.prefix,
        max_candidates: config.max_candidates(),
        max_bytes: config.max_bytes(),
        retained_bytes: 0,
        values: Vec::new(),
        truncated: false,
    };
    environment.visit(domain, &mut collector);
    collector.values.sort_unstable();
    let mut completion = complete_string_values(context, &collector.values, config);
    completion.truncated |= collector.truncated;
    completion
}

fn complete_integer(
    context: CompletionContext<'_>,
    constraints: IntegerConstraints,
    config: CompletionConfig,
) -> Completion {
    let valid = parse_integer(context.prefix, constraints).is_some_and(|value| {
        constraints.minimum().is_none_or(|minimum| value >= minimum)
            && constraints.maximum().is_none_or(|maximum| value <= maximum)
    });
    complete_typed_value(context, valid, config)
}

fn parse_integer(value: &str, constraints: IntegerConstraints) -> Option<i64> {
    if value.is_empty() || value == "-" || value.starts_with('+') {
        return None;
    }
    let radix = match constraints.radix() {
        IntegerRadix::Binary => 2,
        IntegerRadix::Octal => 8,
        IntegerRadix::Decimal => 10,
        IntegerRadix::Hexadecimal => 16,
    };
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |digits| (true, digits));
    if digits.is_empty() {
        return None;
    }
    let magnitude = i64::from_str_radix(digits, radix).ok()?;
    if negative {
        magnitude.checked_neg()
    } else {
        Some(magnitude)
    }
}

fn complete_address(
    context: CompletionContext<'_>,
    constraints: AddressConstraints,
    config: CompletionConfig,
) -> Completion {
    complete_typed_value(context, valid_endpoint(context.prefix, constraints), config)
}

fn valid_endpoint(value: &str, constraints: AddressConstraints) -> bool {
    match constraints.port() {
        PortRequirement::Forbidden => valid_address(value, constraints.family()),
        PortRequirement::Required => split_endpoint(value).is_some_and(|(address, port)| {
            valid_address(address, constraints.family()) && port != 0
        }),
        PortRequirement::Optional => {
            valid_address(value, constraints.family())
                || split_endpoint(value).is_some_and(|(address, port)| {
                    valid_address(address, constraints.family()) && port != 0
                })
        }
    }
}

fn split_endpoint(value: &str) -> Option<(&str, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (address, port) = rest.split_once("]:")?;
        return port.parse().ok().map(|port| (address, port));
    }
    let (address, port) = value.rsplit_once(':')?;
    if address.contains(':') {
        return None;
    }
    port.parse().ok().map(|port| (address, port))
}

fn valid_address(value: &str, family: AddressFamily) -> bool {
    match family {
        AddressFamily::Ipv4 => Ipv4Addr::from_str(value).is_ok(),
        AddressFamily::Ipv6 => Ipv6Addr::from_str(value).is_ok(),
        AddressFamily::Ip => IpAddr::from_str(value).is_ok(),
        AddressFamily::HostName => valid_host_name(value),
        AddressFamily::Any => IpAddr::from_str(value).is_ok() || valid_host_name(value),
    }
}

fn valid_host_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

fn complete_typed_value(
    context: CompletionContext<'_>,
    valid: bool,
    config: CompletionConfig,
) -> Completion {
    if !valid {
        return Completion::default();
    }
    complete_value_iterator(context, core::iter::once(context.prefix), config)
}

fn split_completion_path(prefix: &str) -> (&str, &str, &str) {
    match prefix.rfind('/') {
        None => (".", "", prefix),
        Some(0) => ("/", "/", &prefix[1..]),
        Some(index) => (&prefix[..index], &prefix[..=index], &prefix[index + 1..]),
    }
}

fn is_bare_word_component(name: &str) -> bool {
    !name.chars().any(|character| {
        character.is_whitespace() || matches!(character, '\'' | '"' | '|' | '&' | '<' | '>')
    })
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

#[allow(clippy::too_many_arguments)]
fn control_job<E: ExternalCommand + ?Sized>(
    external: &mut E,
    arguments: &[String],
    command: &str,
    synopsis: &str,
    operation: fn(u32) -> JobControl,
    stdout: &mut dyn Output,
    stderr: &mut dyn Output,
) -> CommandStatus {
    let Some(job) = arguments
        .first()
        .filter(|_| arguments.len() == 1)
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|job| *job != 0)
    else {
        return usage(stderr, command, synopsis);
    };
    external
        .control_job(operation(job), stdout, stderr)
        .unwrap_or_else(|| {
            let _ignored = write_error(stderr, command, "job control unavailable");
            CommandStatus::Failure
        })
}

fn control_service<E: ExternalCommand + ?Sized>(
    external: &mut E,
    arguments: &[String],
    stdout: &mut dyn Output,
    stderr: &mut dyn Output,
) -> CommandStatus {
    let request = match arguments {
        [] => ServiceControl::List,
        [value] if value == "list" => ServiceControl::List,
        [value] if value == "status" => ServiceControl::List,
        [operation, name] if operation == "status" => ServiceControl::Status(name.clone()),
        [operation, name] if operation == "start" => ServiceControl::Start(name.clone()),
        [operation, name] if operation == "stop" => ServiceControl::Stop(name.clone()),
        [operation, name] if operation == "restart" => ServiceControl::Restart(name.clone()),
        [operation, name] if operation == "log" => ServiceControl::Log(name.clone()),
        _ => {
            return usage(
                stderr,
                "svc",
                "svc [status [NAME] | start|stop|restart|log NAME]",
            );
        }
    };
    external
        .control_service(request, stdout, stderr)
        .unwrap_or_else(|| {
            let _ignored = write_error(stderr, "svc", "service control unavailable");
            CommandStatus::Failure
        })
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
        ParseError::EmptyCommand => "empty logical command",
        ParseError::MissingRedirectionTarget => "missing redirection target",
        ParseError::DuplicateRedirection => "duplicate redirection",
        ParseError::InvalidRedirectionPosition => "invalid redirection position",
        ParseError::InvalidBackgroundPosition => "background operator must end the command",
        ParseError::BackgroundPipeline => "background pipelines are not supported",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CommandClass, CompletionConfig, CompletionConfigError, CompletionEnvironment,
        CompletionVisitor, DynamicCompletionDomain, ExecutionPlacement, ExternalCommand,
        ExternalCommandReference, INTRINSICS, JobControl, LogicalOperator, MachineAction,
        OutputRedirection, ParseError, ServiceControl, SharedNamespace, Shell, command_class,
        command_synopsis, external_command_reference, format_memory_report, parse_command_list,
        parse_line,
    };
    use alloc::boxed::Box;
    use alloc::format;
    use alloc::rc::Rc;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use troe_application::encode_kex_package_with_completion;
    use troe_core::{
        BoundedOutput, CommandStatus, Input, MAX_ARGS, MAX_LINE_BYTES, MAX_PIPELINE_STAGES,
        MachineMemorySnapshot, Output, PIPE_CAPACITY, SliceInput, write_all,
    };
    use troe_driver::InputQueueStats;
    use troe_fs_api::{
        FILE_IO_BUFFER_BYTES, FileMetadata, FileSystemProvider, FsError, MAX_FILE_IO_BUFFER_BYTES,
        NodeKind, ProviderListing,
    };
    use troe_vfs::{Namespace, RamFsQuota};

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct StreamState {
        bytes: u64,
        largest_chunk: usize,
        syncs: u32,
    }

    #[derive(Debug)]
    struct StreamProvider {
        state: Rc<RefCell<StreamState>>,
    }

    impl FileSystemProvider for StreamProvider {
        fn metadata(&mut self, path: &str) -> Result<FileMetadata, FsError> {
            match path {
                "/" => Ok(FileMetadata {
                    kind: NodeKind::Directory,
                    byte_count: 0,
                }),
                "/large" => Ok(FileMetadata {
                    kind: NodeKind::File,
                    byte_count: self.state.borrow().bytes,
                }),
                _ => Err(FsError::NotFound),
            }
        }

        fn read_file(
            &mut self,
            path: &str,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<usize, FsError> {
            if path != "/large" {
                return Err(FsError::NotFound);
            }
            let count = destination.len().min(
                usize::try_from(self.state.borrow().bytes.saturating_sub(offset))
                    .unwrap_or(usize::MAX),
            );
            destination[..count].fill(0x5a);
            Ok(count)
        }

        fn list(
            &mut self,
            _path: &str,
            _cursor: u64,
            _max_entries: usize,
            _max_name_bytes: usize,
        ) -> Result<ProviderListing, FsError> {
            Ok(ProviderListing {
                entries: Vec::new(),
                next_cursor: None,
            })
        }

        fn truncate_file(&mut self, path: &str) -> Result<(), FsError> {
            if path != "/large" {
                return Err(FsError::Invalid);
            }
            *self.state.borrow_mut() = StreamState::default();
            Ok(())
        }

        fn append_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
            if path != "/large" || bytes.is_empty() {
                return Err(FsError::Invalid);
            }
            let mut state = self.state.borrow_mut();
            state.bytes = state
                .bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| FsError::Overflow)?)
                .ok_or(FsError::Overflow)?;
            state.largest_chunk = state.largest_chunk.max(bytes.len());
            Ok(())
        }

        fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
            if path != "/large" {
                return Err(FsError::Invalid);
            }
            let mut state = self.state.borrow_mut();
            state.syncs = state.syncs.saturating_add(1);
            Ok(())
        }
    }

    fn shell() -> Shell {
        let mut namespace = Namespace::new(RamFsQuota::default());
        assert_eq!(namespace.add_read_only_dir("/help"), Ok(()));
        assert_eq!(namespace.add_read_only_dir("/bin"), Ok(()));
        for (command, completion) in [
            (
                "awk",
                include_bytes!("../../../apps/awk/completion.cmpl").as_slice(),
            ),
            (
                "cat",
                include_bytes!("../../../apps/cat/completion.cmpl").as_slice(),
            ),
            (
                "echo",
                include_bytes!("../../../apps/echo/completion.cmpl").as_slice(),
            ),
            (
                "grep",
                include_bytes!("../../../apps/grep/completion.cmpl").as_slice(),
            ),
            (
                "hexdump",
                include_bytes!("../../../apps/hexdump/completion.cmpl").as_slice(),
            ),
            (
                "ln",
                include_bytes!("../../../apps/ln/completion.cmpl").as_slice(),
            ),
            (
                "lua",
                include_bytes!("../../../apps/lua/completion.cmpl").as_slice(),
            ),
            (
                "ls",
                include_bytes!("../../../apps/ls/completion.cmpl").as_slice(),
            ),
            (
                "man",
                include_bytes!("../../../apps/man/completion.cmpl").as_slice(),
            ),
            (
                "mem",
                include_bytes!("../../../apps/mem/completion.cmpl").as_slice(),
            ),
            (
                "mount",
                include_bytes!("../../../apps/mount/completion.cmpl").as_slice(),
            ),
            (
                "net",
                include_bytes!("../../../apps/net/completion.cmpl").as_slice(),
            ),
            (
                "ping",
                include_bytes!("../../../apps/ping/completion.cmpl").as_slice(),
            ),
            (
                "pwd",
                include_bytes!("../../../apps/pwd/completion.cmpl").as_slice(),
            ),
            (
                "sed",
                include_bytes!("../../../apps/sed/completion.cmpl").as_slice(),
            ),
            (
                "sleep",
                include_bytes!("../../../apps/sleep/completion.cmpl").as_slice(),
            ),
            (
                "tar",
                include_bytes!("../../../apps/tar/completion.cmpl").as_slice(),
            ),
            (
                "udp",
                include_bytes!("../../../apps/udp/completion.cmpl").as_slice(),
            ),
            (
                "wc",
                include_bytes!("../../../apps/wc/completion.cmpl").as_slice(),
            ),
        ] {
            let package = encode_kex_package_with_completion(b"x", &[], Some(completion))
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(
                namespace.add_read_only_file(&format!("/bin/{command}.kex"), &package),
                Ok(())
            );
        }
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
        placements: Vec<ExecutionPlacement>,
        controls: Vec<JobControl>,
        service_controls: Vec<ServiceControl>,
        script: Option<Vec<String>>,
    }

    struct FakeCompletionEnvironment;

    impl CompletionEnvironment for FakeCompletionEnvironment {
        fn visit(&mut self, domain: DynamicCompletionDomain, visitor: &mut dyn CompletionVisitor) {
            let values: &[&str] = match domain {
                DynamicCompletionDomain::Job => &["12", "7"],
                DynamicCompletionDomain::Service => &["timesync", "diagnostics"],
                DynamicCompletionDomain::Volume => &["root", "boot"],
            };
            for value in values {
                if !visitor.candidate(value) {
                    break;
                }
            }
        }
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
        #[allow(clippy::too_many_lines)]
        fn execute<'stream>(
            &mut self,
            command: &str,
            words: &[String],
            cwd: &str,
            namespace: &SharedNamespace,
            placement: ExecutionPlacement,
            stdin: &'stream mut dyn Input,
            stdout: &'stream mut dyn Output,
            stderr: &'stream mut dyn Output,
        ) -> Option<CommandStatus> {
            self.attempts.push(command.to_string());
            self.placements.push(placement);
            match command {
                "script" => {
                    self.script = Some(alloc::vec![
                        "cd /help".to_string(),
                        "cat readme".to_string(),
                        "missing".to_string(),
                        "external".to_string(),
                    ]);
                    Some(CommandStatus::Success)
                }
                "echo" | "external" => {
                    if write_all(stdout, b"external application\n").is_ok() {
                        Some(CommandStatus::Success)
                    } else {
                        Self::failure(stderr, command, "stream I/O failed", CommandStatus::Failure)
                    }
                }
                "cat" if words.len() == 2 => {
                    let mut offset = 0_u64;
                    let mut chunk = [0_u8; 4096];
                    loop {
                        let result = namespace
                            .borrow_mut()
                            .read_file_at(cwd, &words[1], offset, &mut chunk);
                        match result {
                            Ok(0) => return Some(CommandStatus::Success),
                            Ok(count) if write_all(stdout, &chunk[..count]).is_ok() => {
                                offset = offset.saturating_add(count as u64);
                            }
                            Ok(_) => {
                                return Self::failure(
                                    stderr,
                                    command,
                                    "stream I/O failed",
                                    CommandStatus::Failure,
                                );
                            }
                            Err(error) => {
                                let status = if error == FsError::NotFound {
                                    CommandStatus::NotFound
                                } else {
                                    CommandStatus::Failure
                                };
                                return Self::failure(
                                    stderr,
                                    command,
                                    &format!("{}: {error}", words[1]),
                                    status,
                                );
                            }
                        }
                    }
                }
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
                "stream-default" | "stream-archive" => {
                    if command == "stream-archive"
                        && stdout.set_chunk_size(MAX_FILE_IO_BUFFER_BYTES).is_err()
                    {
                        return Self::failure(
                            stderr,
                            command,
                            "chunk policy failed",
                            CommandStatus::Failure,
                        );
                    }
                    let block = [0x5a; 4096];
                    for _ in 0..512 {
                        if write_all(stdout, &block).is_err() {
                            return Self::failure(
                                stderr,
                                command,
                                "stream I/O failed",
                                CommandStatus::Failure,
                            );
                        }
                    }
                    Some(CommandStatus::Success)
                }
                "fail" => {
                    Self::failure(stderr, command, "requested failure", CommandStatus::Failure)
                }
                _ => None,
            }
        }

        fn take_script_lines(&mut self) -> Option<Vec<String>> {
            self.script.take()
        }

        fn control_job(
            &mut self,
            request: JobControl,
            stdout: &mut dyn Output,
            _stderr: &mut dyn Output,
        ) -> Option<CommandStatus> {
            self.controls.push(request);
            let _ignored = write_all(stdout, b"job control\n");
            Some(CommandStatus::Success)
        }

        fn control_service(
            &mut self,
            request: ServiceControl,
            stdout: &mut dyn Output,
            _stderr: &mut dyn Output,
        ) -> Option<CommandStatus> {
            self.service_controls.push(request);
            let _ignored = write_all(stdout, b"service control\n");
            Some(CommandStatus::Success)
        }
    }

    #[test]
    fn staged_scripts_execute_in_the_owning_session_and_continue_after_failure() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut stdin = SliceInput::new(b"");
        let mut stdout = BoundedOutput::new(4096);
        let mut stderr = BoundedOutput::new(4096);
        let status = shell.execute_with_external(
            "script",
            &mut stdin,
            &mut stdout,
            &mut stderr,
            &mut external,
        );
        assert_eq!(status, CommandStatus::Success);
        assert_eq!(shell.cwd(), "/help");
        assert_eq!(
            core::str::from_utf8(stdout.as_slice()),
            Ok("alpha\nbeta alpha\nexternal application\n")
        );
        assert_eq!(
            core::str::from_utf8(stderr.as_slice()),
            Ok("missing: unknown command\n")
        );
        assert_eq!(external.attempts, ["script", "cat", "missing", "external"]);
    }

    #[test]
    fn staged_script_budget_counts_each_logical_pipeline() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut stdout = BoundedOutput::new(64);
        let mut stderr = BoundedOutput::new(128);
        let mut lines = (0..512)
            .map(|_| "cd / && cd /".to_string())
            .collect::<Vec<_>>();
        lines.push("external".to_string());

        assert_eq!(
            shell.execute_script_lines(lines, &mut stdout, &mut stderr, &mut external),
            CommandStatus::Usage
        );
        assert!(external.attempts.is_empty());
        assert_eq!(stderr.as_slice(), b"sh: script command limit exceeded\n");
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
    fn logical_command_lists_parse_outside_quotes() {
        let parsed =
            parse_command_list("echo 'a && b' | copy && fail || echo Fail").unwrap_or_default();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].operator, None);
        assert_eq!(parsed.entries[0].pipeline.stages.len(), 2);
        assert_eq!(
            parsed.entries[0].pipeline.stages[0].words,
            ["echo", "a && b"]
        );
        assert_eq!(parsed.entries[1].operator, Some(LogicalOperator::And));
        assert_eq!(parsed.entries[1].pipeline.stages[0].words, ["fail"]);
        assert_eq!(parsed.entries[2].operator, Some(LogicalOperator::Or));
        assert_eq!(parsed.entries[2].pipeline.stages[0].words, ["echo", "Fail"]);

        let quoted = parse_command_list("echo \"a || b\" && external &").unwrap_or_default();
        assert_eq!(quoted.entries.len(), 2);
        assert_eq!(
            quoted.entries[0].pipeline.stages[0].words,
            ["echo", "a || b"]
        );
        assert!(quoted.entries[1].pipeline.background);

        for malformed in ["&& echo", "echo ||", "echo && || fail"] {
            assert_eq!(parse_command_list(malformed), Err(ParseError::EmptyCommand));
        }
        assert_eq!(
            parse_command_list("echo &&& fail"),
            Err(ParseError::InvalidBackgroundPosition)
        );
        assert_eq!(
            parse_command_list("echo ||| fail"),
            Err(ParseError::EmptyStage)
        );
        assert_eq!(
            parse_command_list("external & && echo done"),
            Err(ParseError::InvalidBackgroundPosition)
        );
    }

    #[test]
    fn background_operator_is_bounded_to_one_external_stage() {
        let parsed = parse_line("echo 1000 &").unwrap_or_else(|_| std::process::abort());
        assert!(parsed.background);
        assert_eq!(parsed.stages[0].words, ["echo", "1000"]);

        let quoted = parse_line("echo '&'").unwrap_or_else(|_| std::process::abort());
        assert!(!quoted.background);
        assert_eq!(quoted.stages[0].words, ["echo", "&"]);

        assert_eq!(parse_line("&"), Err(ParseError::InvalidBackgroundPosition));
        assert_eq!(
            parse_line("echo & trailing"),
            Err(ParseError::InvalidBackgroundPosition)
        );
        assert_eq!(
            parse_line("echo one | copy &"),
            Err(ParseError::BackgroundPipeline)
        );
    }

    #[test]
    fn background_placement_reaches_external_resolver_and_rejects_intrinsics() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(256);
        let mut error = BoundedOutput::new(256);

        assert_eq!(
            shell.execute_with_external(
                "external &",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert_eq!(external.placements, [ExecutionPlacement::Background]);

        assert_eq!(
            shell.execute_with_external(
                "cd /help &",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Usage
        );
        assert_eq!(shell.cwd(), "/");
        assert_eq!(
            error.as_slice(),
            b"cd: shell intrinsic cannot run in background\n"
        );
    }

    #[test]
    fn redirection_parses_outside_quotes_and_never_enters_argv() {
        let parsed = parse_line("copy<'input file' | copy >>\"output file\"")
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(parsed.stages.len(), 2);
        assert_eq!(parsed.stages[0].words, ["copy"]);
        assert_eq!(parsed.stages[0].input.as_deref(), Some("input file"));
        assert_eq!(parsed.stages[0].output, None);
        assert_eq!(parsed.stages[1].words, ["copy"]);
        assert_eq!(parsed.stages[1].input, None);
        assert_eq!(
            parsed.stages[1].output,
            Some(OutputRedirection::Append("output file".to_string()))
        );

        let quoted = parse_line("echo 'a > b' \"c < d\"").unwrap_or_default();
        assert_eq!(quoted.stages[0].words, ["echo", "a > b", "c < d"]);
        assert_eq!(quoted.stages[0].input, None);
        assert_eq!(quoted.stages[0].output, None);

        assert_eq!(
            parse_line("echo >"),
            Err(ParseError::MissingRedirectionTarget)
        );
        assert_eq!(
            parse_line("echo > first > second"),
            Err(ParseError::DuplicateRedirection)
        );
        assert_eq!(
            parse_line("echo > file | copy"),
            Err(ParseError::InvalidRedirectionPosition)
        );
        assert_eq!(
            parse_line("echo | copy < file"),
            Err(ParseError::InvalidRedirectionPosition)
        );
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

        let exact_stages = core::iter::repeat_n("x", MAX_PIPELINE_STAGES)
            .collect::<Vec<_>>()
            .join("|");
        assert_eq!(
            parse_line(&exact_stages).map(|pipeline| pipeline.stages.len()),
            Ok(MAX_PIPELINE_STAGES)
        );
        assert_eq!(
            parse_line(&format!("{exact_stages}|x")),
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
    fn logical_operators_short_circuit_left_to_right() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(1024);
        let mut error = BoundedOutput::new(1024);

        let status = shell.execute_with_external(
            "fail && external || echo Fail",
            &mut input,
            &mut output,
            &mut error,
            &mut external,
        );
        assert_eq!(status, CommandStatus::Success);
        assert_eq!(external.attempts, ["fail", "echo"]);
        assert_eq!(output.as_slice(), b"external application\n");
        assert_eq!(error.as_slice(), b"fail: requested failure\n");

        external.attempts.clear();
        output = BoundedOutput::new(1024);
        error = BoundedOutput::new(1024);
        let status = shell.execute_with_external(
            "external || fail && echo OK",
            &mut input,
            &mut output,
            &mut error,
            &mut external,
        );
        assert_eq!(status, CommandStatus::Success);
        assert_eq!(external.attempts, ["external", "echo"]);
        assert_eq!(
            output.as_slice(),
            b"external application\nexternal application\n"
        );
        assert!(error.as_slice().is_empty());

        external.attempts.clear();
        external.placements.clear();
        output = BoundedOutput::new(1024);
        let status = shell.execute_with_external(
            "external && external &",
            &mut input,
            &mut output,
            &mut error,
            &mut external,
        );
        assert_eq!(status, CommandStatus::Success);
        assert_eq!(external.attempts, ["external", "external"]);
        assert_eq!(
            external.placements,
            [
                ExecutionPlacement::Foreground,
                ExecutionPlacement::Background
            ]
        );
    }

    #[test]
    fn redirection_replaces_appends_reads_and_leaves_normal_failure_result() {
        let mut shell = shell();
        assert_eq!(
            shell
                .namespace
                .borrow_mut()
                .write_file("/", "/tmp/result", b"old\n"),
            Ok(())
        );
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(64);
        let mut error = BoundedOutput::new(512);

        assert_eq!(
            shell.execute_with_external(
                "copy < /help/readme > /tmp/result",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert!(output.as_slice().is_empty());
        assert_eq!(
            shell.namespace.borrow_mut().read_file("/", "/tmp/result"),
            Ok(b"alpha\nbeta alpha\n".to_vec())
        );

        assert_eq!(
            shell.execute_with_external(
                "echo >> /tmp/result",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert_eq!(
            shell.namespace.borrow_mut().read_file("/", "/tmp/result"),
            Ok(b"alpha\nbeta alpha\nexternal application\n".to_vec())
        );

        assert_eq!(
            shell.execute_with_external(
                "fail > /tmp/result",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Failure
        );
        assert_eq!(
            shell.namespace.borrow_mut().read_file("/", "/tmp/result"),
            Ok(Vec::new())
        );
    }

    #[test]
    fn redirection_streams_past_old_limit_and_honors_archive_chunk_hint() {
        const TOTAL_BYTES: u64 = 2 * 1024 * 1024;
        let mut shell = shell();
        let state = Rc::new(RefCell::new(StreamState::default()));
        assert_eq!(
            shell.namespace.borrow_mut().mount_writable(
                "/media",
                Box::new(StreamProvider {
                    state: Rc::clone(&state),
                }),
            ),
            Ok(())
        );
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(64);
        let mut error = BoundedOutput::new(512);

        assert_eq!(
            shell.execute_with_external(
                "stream-default > /media/large",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert_eq!(
            *state.borrow(),
            StreamState {
                bytes: TOTAL_BYTES,
                largest_chunk: FILE_IO_BUFFER_BYTES,
                syncs: 1,
            }
        );

        assert_eq!(
            shell.execute_with_external(
                "stream-archive > /media/large",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert_eq!(
            *state.borrow(),
            StreamState {
                bytes: TOTAL_BYTES,
                largest_chunk: MAX_FILE_IO_BUFFER_BYTES,
                syncs: 1,
            }
        );
        assert!(error.as_slice().is_empty());
    }

    #[test]
    fn unresolved_non_intrinsic_commands_never_fall_back_to_shell_utilities() {
        let mut shell = shell();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(64);
        let mut error = BoundedOutput::new(128);

        assert_eq!(
            shell.execute("cat /help/readme", &mut input, &mut output, &mut error),
            CommandStatus::NotFound
        );
        assert_eq!(error.as_slice(), b"cat: unknown command\n");

        let mut error = BoundedOutput::new(128);
        assert_eq!(
            shell.execute("tcp 192.0.2.1 80", &mut input, &mut output, &mut error),
            CommandStatus::NotFound
        );
        assert_eq!(error.as_slice(), b"tcp: unknown command\n");

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
        assert_eq!(command_class("cat"), None);
        assert_eq!(command_class("help"), None);
        assert_eq!(command_synopsis("cd"), Some("cd PATH"));
        assert_eq!(command_synopsis("wc"), None);
        assert!(
            INTRINSICS
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name)
        );

        let intrinsic_names: Vec<&str> = INTRINSICS.iter().map(|command| command.name).collect();
        assert_eq!(
            intrinsic_names,
            [
                "cd", "fg", "jobs", "kill", "log", "poweroff", "reboot", "svc", "wait"
            ]
        );
    }

    #[test]
    fn job_control_intrinsics_are_shell_owned_and_validate_job_ids() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(256);
        let mut error = BoundedOutput::new(256);

        for (line, expected) in [
            ("jobs", JobControl::List),
            ("log 7", JobControl::Log(7)),
            ("kill 7", JobControl::Cancel(7)),
            ("wait 7", JobControl::Wait(7)),
            ("fg 7", JobControl::Foreground(7)),
        ] {
            assert_eq!(
                shell.execute_with_external(
                    line,
                    &mut input,
                    &mut output,
                    &mut error,
                    &mut external,
                ),
                CommandStatus::Success
            );
            assert_eq!(external.controls.last(), Some(&expected));
        }
        assert_eq!(
            shell.execute_with_external(
                "kill 0",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Usage
        );
        assert!(!external.attempts.iter().any(|name| name == "jobs"));
    }

    #[test]
    fn service_control_is_shell_owned_and_parses_closed_operations() {
        let mut shell = shell();
        let mut external = FakeExternal::default();
        let mut input = SliceInput::new(b"");
        let mut output = BoundedOutput::new(256);
        let mut error = BoundedOutput::new(256);

        for (line, expected) in [
            ("svc", ServiceControl::List),
            ("svc list", ServiceControl::List),
            ("svc status", ServiceControl::List),
            (
                "svc status timesync",
                ServiceControl::Status("timesync".to_string()),
            ),
            (
                "svc start timesync",
                ServiceControl::Start("timesync".to_string()),
            ),
            (
                "svc stop timesync",
                ServiceControl::Stop("timesync".to_string()),
            ),
            (
                "svc restart timesync",
                ServiceControl::Restart("timesync".to_string()),
            ),
            (
                "svc log timesync",
                ServiceControl::Log("timesync".to_string()),
            ),
        ] {
            assert_eq!(
                shell.execute_with_external(
                    line,
                    &mut input,
                    &mut output,
                    &mut error,
                    &mut external,
                ),
                CommandStatus::Success
            );
            assert_eq!(external.service_controls.last(), Some(&expected));
        }
        assert_eq!(
            shell.execute_with_external(
                "svc reload timesync",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Usage
        );
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

        let mut external = FakeExternal::default();
        assert_eq!(
            poweroff_shell.execute_with_external(
                "poweroff && external",
                &mut input,
                &mut output,
                &mut error,
                &mut external,
            ),
            CommandStatus::Success
        );
        assert!(external.attempts.is_empty());

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

        let explicit = shell.complete("/bin/ec", 7, CompletionConfig::standard());
        assert_eq!(explicit.candidates[0].replacement, "/bin/echo.kex ");

        let logical = shell.complete("missing || ec", 13, CompletionConfig::standard());
        assert_eq!(logical.candidates[0].replacement, "echo ");

        let directory = shell.complete("cd /he", 6, CompletionConfig::standard());
        assert_eq!(directory.candidates[0].replacement, "/help/");

        let file = shell.complete("cat /help/r", 11, CompletionConfig::standard());
        assert_eq!(file.candidates[0].replacement, "/help/readme ");
        let file_traversal = shell.complete("cat /he", 7, CompletionConfig::standard());
        assert_eq!(file_traversal.candidates[0].replacement, "/help/");

        for line in ["echo > /help/r", "echo >>/help/r", "copy </help/r"] {
            let completion = shell.complete(line, line.len(), CompletionConfig::standard());
            assert_eq!(completion.candidates[0].replacement, "/help/readme ");
        }

        let net_mode = "net st";
        let completion = shell.complete(net_mode, net_mode.len(), CompletionConfig::standard());
        assert_eq!(completion.candidates[0].replacement, "stats ");

        let udp_mode = "udp li";
        let completion = shell.complete(udp_mode, udp_mode.len(), CompletionConfig::standard());
        assert_eq!(completion.candidates[0].replacement, "listen ");

        for (line, expected) in [
            ("cat -A", "-A "),
            ("echo -n", "-n "),
            ("grep -m", "-m "),
            ("ls -l", "-l "),
            ("mem --s", "--self-test "),
            ("udp re", "recv "),
        ] {
            assert_eq!(
                shell
                    .complete(line, line.len(), CompletionConfig::standard())
                    .common_replacement(),
                Some(expected)
            );
        }

        let grep_count = "grep -m 25";
        assert_eq!(
            shell
                .complete(grep_count, grep_count.len(), CompletionConfig::standard(),)
                .common_replacement(),
            Some("25 ")
        );

        let wc_option = "wc -lw";
        let completion = shell.complete(wc_option, wc_option.len(), CompletionConfig::standard());
        assert!(
            completion
                .candidates
                .iter()
                .any(|candidate| candidate.replacement == "-lwc ")
        );

        let tar_mode = "tar -x";
        let completion = shell.complete(tar_mode, tar_mode.len(), CompletionConfig::standard());
        assert!(
            completion
                .candidates
                .iter()
                .any(|candidate| candidate.replacement == "-xf ")
        );

        for line in [
            "ln /help/r",
            "sed 's/a/b/' /help/r",
            "sed -e 's/a/b/' /help/r",
            "sed -n -e 's/a/b/' /help/r",
            "awk -F : '{ print $1 }' /help/r",
            "awk -F: '{ print $1 }' /help/r",
            "tar -cf /tmp/archive.tar /help/r",
        ] {
            let completion = shell.complete(line, line.len(), CompletionConfig::standard());
            assert_eq!(completion.candidates[0].replacement, "/help/readme ");
        }

        for line in [
            "sed -n /help/r",
            "awk -F /help/r",
            "tar -xf /tmp/archive.tar /help/r",
            "lua -e /help/r",
        ] {
            assert!(
                shell
                    .complete(line, line.len(), CompletionConfig::standard())
                    .candidates
                    .is_empty()
            );
        }
    }

    #[test]
    fn typed_and_dynamic_resolvers_are_shell_owned() {
        let mut shell = shell();
        let address = shell.complete(
            "ping 192.0.2.1",
            "ping 192.0.2.1".len(),
            CompletionConfig::standard(),
        );
        assert_eq!(address.common_replacement(), Some("192.0.2.1 "));
        assert!(
            shell
                .complete(
                    "ping 192.0.2",
                    "ping 192.0.2".len(),
                    CompletionConfig::standard(),
                )
                .candidates
                .is_empty()
        );
        let integer = shell.complete("sleep 125", 9, CompletionConfig::standard());
        assert_eq!(integer.common_replacement(), Some("125 "));

        let mut environment = FakeCompletionEnvironment;
        for (line, expected) in [
            ("wait 1", "12 "),
            ("svc status t", "timesync "),
            ("mount b", "boot "),
        ] {
            let completion = shell.complete_with_environment(
                line,
                line.len(),
                CompletionConfig::standard(),
                &mut environment,
            );
            assert_eq!(completion.common_replacement(), Some(expected));
        }
    }

    #[test]
    fn resolver_distinguishes_catalog_names_from_exact_paths() {
        assert_eq!(
            external_command_reference("echo"),
            Some(ExternalCommandReference::CatalogName("echo"))
        );
        for path in ["./echo", "../bin/echo.kex", "/vol/shared/tool"] {
            assert_eq!(
                external_command_reference(path),
                Some(ExternalCommandReference::Path(path))
            );
        }
        for invalid in ["", "Echo", "not.valid"] {
            assert_eq!(external_command_reference(invalid), None);
        }
    }

    #[test]
    fn lazy_catalog_is_cached_and_revision_invalidated() {
        let mut shell = shell();
        assert_eq!(shell.command_catalog.revision, None);

        let first = shell.complete("he", 2, CompletionConfig::standard());
        assert_eq!(first.common_replacement(), Some("hexdump "));
        assert_eq!(
            shell.command_catalog.revision,
            Some(shell.namespace.borrow().command_revision())
        );

        shell.command_catalog.names.push("cached-only".to_string());
        let cached = shell.complete("cached", 6, CompletionConfig::standard());
        assert_eq!(cached.common_replacement(), Some("cached-only "));

        assert_eq!(
            shell
                .namespace
                .borrow_mut()
                .add_read_only_file("/bin/beta.kex", b"package"),
            Ok(())
        );
        let refreshed = shell.complete("be", 2, CompletionConfig::standard());
        assert_eq!(refreshed.common_replacement(), Some("beta "));
        assert!(
            shell
                .complete("cached", 6, CompletionConfig::standard())
                .candidates
                .is_empty()
        );
    }

    #[test]
    fn large_catalog_retains_one_thousand_discovered_applications() {
        let mut namespace = Namespace::new(RamFsQuota::default());
        assert_eq!(namespace.add_read_only_dir("/bin"), Ok(()));
        for index in 0..1000 {
            assert_eq!(
                namespace.add_read_only_file(&format!("/bin/app{index:04}.kex"), b"package",),
                Ok(())
            );
        }
        let mut shell = Shell::new(namespace, "test", MachineMemorySnapshot::hosted(), true)
            .unwrap_or_else(|_| std::process::abort());
        let completion = shell.complete("app0999", 7, CompletionConfig::standard());
        assert_eq!(completion.common_replacement(), Some("app0999 "));
        assert!(!shell.command_catalog.truncated);
        assert_eq!(shell.command_catalog.names.len(), 1000 + INTRINSICS.len());
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
        assert_eq!(PIPE_CAPACITY, 1024 * 1024);
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
            "fail | copy > /tmp/error-copy",
            &mut input,
            &mut output,
            &mut error,
            &mut external,
        );

        assert_eq!(status, CommandStatus::Failure);
        assert!(output.as_slice().is_empty());
        assert_eq!(error.as_slice(), b"fail: requested failure\n");
        assert_eq!(
            shell
                .namespace
                .borrow_mut()
                .read_file("/", "/tmp/error-copy"),
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

//! Dependency-free hosted tooling for canonical TROE KEX applications.
#![forbid(unsafe_code)]

mod elf;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

pub use elf::convert_elf;
use troe_abi::{
    clock_control, datagram, diagnostics, filesystem, filesystem_mutation, icmp_echo, interface,
    network_configuration, network_observation, requirements, tcp_connect, timer, volume_control,
    wall_clock,
};
use troe_application::{
    ABI_MAJOR, ABI_MINOR, KEX_PACKAGE_V1_MAGIC, KEX_V1_HEADER_BYTES, KEX_V1_IMAGE_BASE,
    KEX_V1_MAGIC, MAX_KEX_PACKAGE_BYTES, Target, encode_kex_package, parse_kex, parse_kex_package,
};

const DEFAULT_STACK_PAGES: u32 = 4;
const DEFAULT_HEAP_PAGES: u32 = 0;
const ELF_MAX_BYTES: u64 = 64 * 1024 * 1024;
const RUST_FLAGS: &[&str] = &[
    "-C",
    "relocation-model=static",
    "-C",
    "code-model=large",
    "-C",
    "LINKER_SCRIPT",
    "-C",
    "link-arg=--build-id=none",
    "-C",
    "link-arg=--no-eh-frame-hdr",
    "-C",
    "link-arg=-z",
    "-C",
    "link-arg=norelro",
    "-C",
    "link-arg=-z",
    "-C",
    "link-arg=max-page-size=4096",
];
const RUSTC_WRAPPER_ENV: &str = "TROE_KEX_RUSTC_WRAPPER";

const HELP: &str = "\
Build, convert, and inspect canonical TROE KEX applications.

Usage:
  cargo kex build <app> [--name NAME] [--target all|x86_64|aarch64]
                       [--output DIR] [--stack-pages N] [--heap-pages N] [--check]
  cargo kex convert <input.elf> <output.kex> [--target x86_64|aarch64]
                       [--stack-pages N] [--heap-pages N] [--check]
  cargo kex inspect <artifact.kex> [--json]
  cargo kex --help
";

/// One deterministic CLI or conversion failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolError {
    message: String,
}

impl ToolError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ToolError {}

pub(crate) type ToolResult<T> = Result<T, ToolError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetSelection {
    All,
    One(Target),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppManifest {
    directory: PathBuf,
    binary: String,
    command: String,
    requirements: Vec<requirements::Requirement>,
    stack_pages: u32,
    heap_pages: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BuildOptions {
    app: PathBuf,
    command: Option<String>,
    target: TargetSelection,
    output: PathBuf,
    stack_pages: Option<u32>,
    heap_pages: Option<u32>,
    check: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConvertOptions {
    input: PathBuf,
    output: PathBuf,
    target: Option<Target>,
    stack_pages: u32,
    heap_pages: u32,
    check: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InspectReport {
    package: bool,
    target: Target,
    abi_minor: u16,
    bytes: usize,
    executable_bytes: usize,
    requirements: usize,
    records: usize,
    entry_offset: u64,
    stack_pages: u64,
    heap_pages: u64,
}

struct Arguments {
    values: Vec<OsString>,
    index: usize,
}

impl Arguments {
    fn new(values: impl Iterator<Item = OsString>) -> Self {
        Self {
            values: values.collect(),
            index: 0,
        }
    }

    fn next(&mut self) -> Option<OsString> {
        let value = self.values.get(self.index).cloned();
        self.index = self.index.saturating_add(usize::from(value.is_some()));
        value
    }

    fn value(&mut self, option: &str) -> ToolResult<OsString> {
        self.next()
            .ok_or_else(|| ToolError::new(format!("{option} requires a value")))
    }

    fn string(&mut self, option: &str) -> ToolResult<String> {
        self.value(option)?
            .into_string()
            .map_err(|_| ToolError::new(format!("{option} must be valid UTF-8")))
    }

    fn number(&mut self, option: &str) -> ToolResult<u32> {
        self.string(option)?
            .parse::<u32>()
            .map_err(|_| ToolError::new(format!("{option} must be an unsigned 32-bit integer")))
    }
}

fn target_name(target: Target) -> &'static str {
    match target {
        Target::X86_64 => "x86_64",
        Target::Aarch64 => "aarch64",
    }
}

fn target_triple(target: Target) -> &'static str {
    match target {
        Target::X86_64 => "x86_64-unknown-none",
        Target::Aarch64 => "aarch64-unknown-none",
    }
}

fn parse_target(value: &str) -> ToolResult<Target> {
    match value {
        "x86_64" => Ok(Target::X86_64),
        "aarch64" => Ok(Target::Aarch64),
        _ => Err(ToolError::new("target must be 'x86_64' or 'aarch64'")),
    }
}

fn parse_target_selection(value: &str) -> ToolResult<TargetSelection> {
    if value == "all" {
        Ok(TargetSelection::All)
    } else {
        parse_target(value).map(TargetSelection::One)
    }
}

fn require_positional(arguments: &mut Arguments, label: &str) -> ToolResult<PathBuf> {
    arguments
        .next()
        .filter(|value| !value.to_string_lossy().starts_with('-'))
        .map(PathBuf::from)
        .ok_or_else(|| ToolError::new(format!("missing {label}")))
}

fn parse_build(arguments: &mut Arguments) -> ToolResult<BuildOptions> {
    let app = require_positional(arguments, "application directory")?;
    let mut options = BuildOptions {
        app,
        command: None,
        target: TargetSelection::All,
        output: repo_root().join("rootfs/bin"),
        stack_pages: None,
        heap_pages: None,
        check: false,
    };
    while let Some(option) = arguments.next() {
        match option.to_str() {
            Some("--name") => options.command = Some(arguments.string("--name")?),
            Some("--target") => {
                options.target = parse_target_selection(&arguments.string("--target")?)?;
            }
            Some("--output") => options.output = PathBuf::from(arguments.value("--output")?),
            Some("--stack-pages") => {
                options.stack_pages = Some(arguments.number("--stack-pages")?);
            }
            Some("--heap-pages") => {
                options.heap_pages = Some(arguments.number("--heap-pages")?);
            }
            Some("--check") => options.check = true,
            Some("--help" | "-h") => return Err(ToolError::new(HELP)),
            _ => {
                return Err(ToolError::new(format!(
                    "unknown build option {}",
                    option.display()
                )));
            }
        }
    }
    Ok(options)
}

fn parse_convert(arguments: &mut Arguments) -> ToolResult<ConvertOptions> {
    let input = require_positional(arguments, "ELF input")?;
    let output = require_positional(arguments, "KEX output")?;
    let mut options = ConvertOptions {
        input,
        output,
        target: None,
        stack_pages: DEFAULT_STACK_PAGES,
        heap_pages: DEFAULT_HEAP_PAGES,
        check: false,
    };
    while let Some(option) = arguments.next() {
        match option.to_str() {
            Some("--target") => {
                options.target = Some(parse_target(&arguments.string("--target")?)?);
            }
            Some("--stack-pages") => options.stack_pages = arguments.number("--stack-pages")?,
            Some("--heap-pages") => options.heap_pages = arguments.number("--heap-pages")?,
            Some("--check") => options.check = true,
            Some("--help" | "-h") => return Err(ToolError::new(HELP)),
            _ => {
                return Err(ToolError::new(format!(
                    "unknown convert option {}",
                    option.display()
                )));
            }
        }
    }
    Ok(options)
}

fn io_error(action: &str, path: &Path, error: &std::io::Error) -> ToolError {
    ToolError::new(format!("cannot {action} {}: {error}", path.display()))
}

fn read_bounded(path: &Path, maximum: u64, kind: &str) -> ToolResult<Vec<u8>> {
    let file = fs::File::open(path).map_err(|error| io_error("open", path, &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect", path, &error))?;
    if !metadata.is_file() {
        return Err(ToolError::new(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(ToolError::new(format!(
            "{kind} exceeds the hosted size ceiling"
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| ToolError::new(format!("{kind} size is not representable")))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| ToolError::new(format!("cannot reserve memory for {kind}")))?;
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read", path, &error))?;
    if u64::try_from(bytes.len()).is_ok_and(|length| length > maximum) {
        return Err(ToolError::new(format!(
            "{kind} exceeds the hosted size ceiling"
        )));
    }
    if u64::try_from(bytes.len()) != Ok(metadata.len()) {
        return Err(ToolError::new(format!(
            "{} changed while it was being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn parse_simple_string(line: &str, key: &str) -> ToolResult<Option<String>> {
    let Some((candidate, value)) = line.split_once('=') else {
        return Ok(None);
    };
    if candidate.trim() != key {
        return Ok(None);
    }
    let value = value.trim();
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(ToolError::new(format!(
            "manifest {key} must be one simple quoted string"
        )));
    }
    let body = &value[1..value.len() - 1];
    if body.contains(['\\', '"']) || body.is_empty() {
        return Err(ToolError::new(format!(
            "manifest {key} uses unsupported string syntax"
        )));
    }
    Ok(Some(body.to_owned()))
}

fn parse_simple_string_array(line: &str, key: &str) -> ToolResult<Option<Vec<String>>> {
    let Some((candidate, value)) = line.split_once('=') else {
        return Ok(None);
    };
    if candidate.trim() != key {
        return Ok(None);
    }
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return Err(ToolError::new(format!(
            "manifest {key} must be one simple string array"
        )));
    }
    let body = value[1..value.len() - 1].trim();
    if body.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let mut values = Vec::new();
    for raw in body.split(',') {
        let raw = raw.trim();
        if raw.len() < 2 || !raw.starts_with('"') || !raw.ends_with('"') {
            return Err(ToolError::new(format!(
                "manifest {key} must contain only quoted strings"
            )));
        }
        let value = &raw[1..raw.len() - 1];
        if value.is_empty() || value.contains(['\\', '"']) {
            return Err(ToolError::new(format!(
                "manifest {key} uses unsupported string syntax"
            )));
        }
        values.push(value.to_owned());
    }
    Ok(Some(values))
}

fn parse_simple_u32(line: &str, key: &str) -> ToolResult<Option<u32>> {
    let Some((candidate, value)) = line.split_once('=') else {
        return Ok(None);
    };
    if candidate.trim() != key {
        return Ok(None);
    }
    value
        .trim()
        .parse::<u32>()
        .map(Some)
        .map_err(|_| ToolError::new(format!("manifest {key} must be an unsigned 32-bit integer")))
}

fn capability_requirement(name: &str) -> ToolResult<requirements::Requirement> {
    match name {
        "datagram" => Ok(requirements::Requirement {
            interface: interface::DATAGRAM,
            major: datagram::MAJOR,
            minor: datagram::MINOR,
        }),
        "filesystem-read" => Ok(requirements::Requirement {
            interface: interface::FILESYSTEM_READ,
            major: filesystem::MAJOR,
            minor: filesystem::MINOR,
        }),
        "filesystem-mutate" => Ok(requirements::Requirement {
            interface: interface::FILESYSTEM_MUTATE,
            major: filesystem_mutation::MAJOR,
            minor: filesystem_mutation::MINOR,
        }),
        "timer" => Ok(requirements::Requirement {
            interface: interface::TIMER,
            major: timer::MAJOR,
            minor: timer::MINOR,
        }),
        "diagnostics" => Ok(requirements::Requirement {
            interface: interface::DIAGNOSTICS,
            major: diagnostics::MAJOR,
            minor: diagnostics::MINOR,
        }),
        "network-observe" => Ok(requirements::Requirement {
            interface: interface::NETWORK_OBSERVE,
            major: network_observation::MAJOR,
            minor: network_observation::MINOR,
        }),
        "network-configure" => Ok(requirements::Requirement {
            interface: interface::NETWORK_CONFIGURE,
            major: network_configuration::MAJOR,
            minor: network_configuration::MINOR,
        }),
        "icmp-echo" => Ok(requirements::Requirement {
            interface: interface::ICMP_ECHO,
            major: icmp_echo::MAJOR,
            minor: icmp_echo::MINOR,
        }),
        "tcp-connect" => Ok(requirements::Requirement {
            interface: interface::TCP_CONNECT,
            major: tcp_connect::MAJOR,
            minor: tcp_connect::MINOR,
        }),
        "volume-control" => Ok(requirements::Requirement {
            interface: interface::VOLUME_CONTROL,
            major: volume_control::MAJOR,
            minor: volume_control::MINOR,
        }),
        "server-endpoint" => Ok(requirements::Requirement {
            interface: interface::SERVER_ENDPOINT,
            major: troe_abi::server::MAJOR,
            minor: troe_abi::server::MINOR,
        }),
        "shell-script" => Ok(requirements::Requirement {
            interface: interface::SHELL_SCRIPT,
            major: troe_abi::shell_script::MAJOR,
            minor: troe_abi::shell_script::MINOR,
        }),
        "wall-clock" => Ok(requirements::Requirement {
            interface: interface::WALL_CLOCK,
            major: wall_clock::MAJOR,
            minor: wall_clock::MINOR,
        }),
        "clock-control" => Ok(requirements::Requirement {
            interface: interface::CLOCK_CONTROL,
            major: clock_control::MAJOR,
            minor: clock_control::MINOR,
        }),
        _ => Err(ToolError::new(format!(
            "unknown TROE KEX capability '{name}'"
        ))),
    }
}

fn valid_command_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn absolute(path: &Path) -> ToolResult<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| ToolError::new(format!("cannot resolve current directory: {error}")))
    }
}

#[allow(clippy::too_many_lines)]
fn read_manifest(app: &Path, requested_command: Option<&str>) -> ToolResult<AppManifest> {
    let root = repo_root()
        .canonicalize()
        .map_err(|error| io_error("resolve", &repo_root(), &error))?;
    let directory = app
        .canonicalize()
        .map_err(|error| io_error("resolve", app, &error))?;
    if !directory.starts_with(&root) {
        return Err(ToolError::new(
            "application directory must remain inside the repository",
        ));
    }
    let path = directory.join("Cargo.toml");
    let source = fs::read_to_string(&path).map_err(|error| io_error("read", &path, &error))?;
    let mut section = "";
    let mut package = None;
    let mut binary = None;
    let mut bin_tables = 0_u8;
    let mut workspace = false;
    let mut capabilities = None;
    let mut stack_pages = None;
    let mut heap_pages = None;
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line;
            if line == "[workspace]" {
                workspace = true;
            } else if line == "[[bin]]" {
                bin_tables = bin_tables.saturating_add(1);
                if bin_tables > 1 {
                    return Err(ToolError::new(
                        "application manifests may define at most one binary",
                    ));
                }
            }
            continue;
        }
        if section == "[package]" {
            if let Some(name) = parse_simple_string(line, "name")? {
                package = Some(name);
            }
        } else if section == "[[bin]]"
            && let Some(name) = parse_simple_string(line, "name")?
        {
            binary = Some(name);
        } else if section == "[package.metadata.troe-kex]"
            && let Some(names) = parse_simple_string_array(line, "capabilities")?
        {
            if capabilities.replace(names).is_some() {
                return Err(ToolError::new(
                    "manifest declares capabilities more than once",
                ));
            }
        } else if section == "[package.metadata.troe-kex]"
            && let Some(value) = parse_simple_u32(line, "stack-pages")?
            && stack_pages.replace(value).is_some()
        {
            return Err(ToolError::new(
                "manifest declares stack-pages more than once",
            ));
        } else if section == "[package.metadata.troe-kex]"
            && let Some(value) = parse_simple_u32(line, "heap-pages")?
            && heap_pages.replace(value).is_some()
        {
            return Err(ToolError::new(
                "manifest declares heap-pages more than once",
            ));
        }
    }
    if !workspace {
        return Err(ToolError::new(
            "application must be a standalone Cargo workspace",
        ));
    }
    let package = package.ok_or_else(|| ToolError::new("manifest has no package name"))?;
    let binary = match (bin_tables, binary) {
        (0, _) => package,
        (_, Some(binary)) => binary,
        (_, None) => return Err(ToolError::new("manifest [[bin]] has no name")),
    };
    let default_command = directory
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| ToolError::new("application directory name must be valid UTF-8"))?;
    let command = requested_command.unwrap_or(default_command).to_owned();
    if !valid_command_name(&command) {
        return Err(ToolError::new(
            "command name must contain only lowercase ASCII, digits, '_' or '-'",
        ));
    }
    let mut required = capabilities
        .unwrap_or_default()
        .iter()
        .map(|name| capability_requirement(name))
        .collect::<ToolResult<Vec<_>>>()?;
    required.sort_unstable_by_key(|requirement| requirement.interface);
    let mut encoded = [0_u8; requirements::MAX_MANIFEST_BYTES];
    requirements::encode(&required, &mut encoded)
        .map_err(|_| ToolError::new("manifest capabilities must be unique and bounded"))?;
    Ok(AppManifest {
        directory,
        binary,
        command,
        requirements: required,
        stack_pages: stack_pages.unwrap_or(DEFAULT_STACK_PAGES),
        heap_pages: heap_pages.unwrap_or(DEFAULT_HEAP_PAGES),
    })
}

fn encoded_rust_flags() -> ToolResult<String> {
    let root = repo_root()
        .canonicalize()
        .map_err(|error| io_error("resolve", &repo_root(), &error))?;
    let root = root
        .to_str()
        .ok_or_else(|| ToolError::new("repository path must be valid UTF-8"))?;
    let mut flags = RUST_FLAGS
        .iter()
        .map(|flag| {
            if *flag == "LINKER_SCRIPT" {
                "link-arg=-T../../sdk/kex.ld".to_owned()
            } else {
                (*flag).to_owned()
            }
        })
        .collect::<Vec<_>>();
    flags.push(format!("--remap-path-prefix={root}=/troe"));
    Ok(flags.join("\x1f"))
}

fn run_cargo(manifest: &AppManifest, target: Target) -> ToolResult<PathBuf> {
    let target_dir = repo_root().join("target/kex").join(&manifest.command);
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let wrapper = env::current_exe()
        .map_err(|error| ToolError::new(format!("cannot resolve KEX tool executable: {error}")))?;
    let status = Command::new(cargo)
        .arg("build")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(manifest.directory.join("Cargo.toml"))
        .arg("--release")
        .arg("--target")
        .arg(target_triple(target))
        .current_dir(repo_root())
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rust_flags()?)
        .env("RUSTC_WRAPPER", wrapper)
        .env(RUSTC_WRAPPER_ENV, "1")
        .status()
        .map_err(|error| ToolError::new(format!("cannot run Cargo: {error}")))?;
    if !status.success() {
        return Err(ToolError::new(format!(
            "Cargo build failed for {}",
            target_name(target)
        )));
    }
    Ok(target_dir
        .join(target_triple(target))
        .join("release")
        .join(&manifest.binary))
}

fn filtered_rustc_arguments(
    arguments: impl Iterator<Item = OsString>,
) -> ToolResult<(OsString, Vec<OsString>)> {
    let mut arguments = arguments.peekable();
    let rustc = arguments
        .next()
        .ok_or_else(|| ToolError::new("rustc wrapper received no compiler path"))?;
    let mut filtered = Vec::new();
    while let Some(argument) = arguments.next() {
        if argument == OsStr::new("-C")
            && arguments
                .peek()
                .is_some_and(|value| value.to_string_lossy().starts_with("metadata="))
        {
            arguments.next();
            continue;
        }
        if argument
            .to_string_lossy()
            .strip_prefix("-C")
            .is_some_and(|value| value.starts_with("metadata="))
        {
            continue;
        }
        filtered.push(argument);
    }
    Ok((rustc, filtered))
}

/// Return whether this process was launched by Cargo as the canonical KEX rustc wrapper.
#[must_use]
pub fn is_rustc_wrapper() -> bool {
    env::var_os(RUSTC_WRAPPER_ENV).is_some()
}

/// Run rustc after removing Cargo's checkout-path-derived crate metadata.
///
/// # Errors
///
/// Returns an error when Cargo did not provide a compiler path or rustc could
/// not be launched.
pub fn run_rustc_wrapper(
    arguments: impl Iterator<Item = OsString>,
) -> ToolResult<std::process::ExitStatus> {
    let (rustc, arguments) = filtered_rustc_arguments(arguments)?;
    Command::new(rustc)
        .args(arguments)
        .status()
        .map_err(|error| ToolError::new(format!("cannot run rustc: {error}")))
}

fn write_or_check(path: &Path, artifact: &[u8], check: bool, label: &str) -> ToolResult<()> {
    if check {
        let existing = read_bounded(
            path,
            u64::try_from(MAX_KEX_PACKAGE_BYTES)
                .map_err(|_| ToolError::new("KEX package ceiling is not representable"))?,
            "KEX package",
        )?;
        if existing != artifact {
            return Err(ToolError::new(format!(
                "{} differs from the canonical build",
                path.display()
            )));
        }
        println!(
            "{label} verified: {} bytes -> {}",
            artifact.len(),
            path.display()
        );
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| ToolError::new("output path has no parent directory"))?;
    fs::create_dir_all(parent).map_err(|error| io_error("create", parent, &error))?;
    let temporary = path.with_extension("kex.tmp");
    fs::write(&temporary, artifact).map_err(|error| io_error("write", &temporary, &error))?;
    fs::rename(&temporary, path).map_err(|error| io_error("install", path, &error))?;
    println!("{label}: {} bytes -> {}", artifact.len(), path.display());
    Ok(())
}

fn remove_or_reject_legacy_sidecar(package: &Path, check: bool) -> ToolResult<()> {
    let sidecar = package.with_extension("kcap");
    if check {
        if sidecar.exists() {
            return Err(ToolError::new(format!(
                "legacy capability sidecar is still installed: {}",
                sidecar.display()
            )));
        }
        return Ok(());
    }
    match fs::remove_file(&sidecar) {
        Ok(()) => println!("removed legacy sidecar -> {}", sidecar.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("remove", &sidecar, &error)),
    }
    Ok(())
}

fn build_one(
    manifest: &AppManifest,
    target: Target,
    output: &Path,
    stack_pages: u32,
    heap_pages: u32,
    check: bool,
) -> ToolResult<()> {
    let executable = run_cargo(manifest, target)?;
    let image = read_bounded(&executable, ELF_MAX_BYTES, "ELF artifact")?;
    let executable = convert_elf(&image, Some(target), stack_pages, heap_pages)?;
    let package = encode_kex_package(&executable, &manifest.requirements)
        .map_err(|_| ToolError::new("cannot encode KEX package"))?;
    let output = output
        .join(target_name(target))
        .join(format!("{}.kex", manifest.command));
    write_or_check(&output, &package, check, "KEX package")?;
    remove_or_reject_legacy_sidecar(&output, check)
}

fn execute_build(options: &BuildOptions) -> ToolResult<()> {
    let manifest = read_manifest(&options.app, options.command.as_deref())?;
    let output = absolute(&options.output)?;
    match options.target {
        TargetSelection::All => {
            build_one(
                &manifest,
                Target::X86_64,
                &output,
                options.stack_pages.unwrap_or(manifest.stack_pages),
                options.heap_pages.unwrap_or(manifest.heap_pages),
                options.check,
            )?;
            build_one(
                &manifest,
                Target::Aarch64,
                &output,
                options.stack_pages.unwrap_or(manifest.stack_pages),
                options.heap_pages.unwrap_or(manifest.heap_pages),
                options.check,
            )
        }
        TargetSelection::One(target) => build_one(
            &manifest,
            target,
            &output,
            options.stack_pages.unwrap_or(manifest.stack_pages),
            options.heap_pages.unwrap_or(manifest.heap_pages),
            options.check,
        ),
    }
}

fn execute_convert(options: &ConvertOptions) -> ToolResult<()> {
    let input = absolute(&options.input)?;
    let output = absolute(&options.output)?;
    let image = read_bounded(&input, ELF_MAX_BYTES, "ELF artifact")?;
    let artifact = convert_elf(
        &image,
        options.target,
        options.stack_pages,
        options.heap_pages,
    )?;
    write_or_check(&output, &artifact, options.check, "KEX v1")
}

fn inspect(path: &Path) -> ToolResult<InspectReport> {
    let artifact = read_bounded(
        path,
        u64::try_from(MAX_KEX_PACKAGE_BYTES)
            .map_err(|_| ToolError::new("KEX package ceiling is not representable"))?,
        "KEX package",
    )?;
    let (package, executable, requirements) = if artifact.starts_with(&KEX_PACKAGE_V1_MAGIC) {
        let package = parse_kex_package(&artifact)
            .map_err(|error| ToolError::new(format!("invalid KEX package: {error}")))?;
        (true, package.executable(), package.requirements().len())
    } else if artifact.starts_with(&KEX_V1_MAGIC) {
        (false, artifact.as_slice(), 0)
    } else {
        return Err(ToolError::new(
            "artifact is neither a KEX package nor KEX v1",
        ));
    };
    if executable.len() < KEX_V1_HEADER_BYTES {
        return Err(ToolError::new("embedded KEX header is truncated"));
    }
    let target = match u16::from_le_bytes([executable[12], executable[13]]) {
        1 => Target::X86_64,
        2 => Target::Aarch64,
        _ => return Err(ToolError::new("embedded KEX target is unknown")),
    };
    let plan = parse_kex(executable, target, ABI_MINOR)
        .map_err(|error| ToolError::new(format!("invalid embedded KEX executable: {error}")))?;
    let entry_offset = plan
        .entry_address()
        .checked_sub(KEX_V1_IMAGE_BASE)
        .ok_or_else(|| ToolError::new("KEX entry is below the image base"))?;
    Ok(InspectReport {
        package,
        target,
        abi_minor: plan.abi_minor(),
        bytes: artifact.len(),
        executable_bytes: executable.len(),
        requirements,
        records: plan.segments().count(),
        entry_offset,
        stack_pages: plan.stack_pages(),
        heap_pages: plan.heap_pages(),
    })
}

fn execute_inspect(arguments: &mut Arguments) -> ToolResult<()> {
    let artifact = absolute(&require_positional(arguments, "KEX artifact")?)?;
    let mut json = false;
    while let Some(option) = arguments.next() {
        match option.to_str() {
            Some("--json") => json = true,
            Some("--help" | "-h") => return Err(ToolError::new(HELP)),
            _ => {
                return Err(ToolError::new(format!(
                    "unknown inspect option {}",
                    option.display()
                )));
            }
        }
    }
    let report = inspect(&artifact)?;
    let format = if report.package {
        "KEX package v1"
    } else {
        "KEX v1"
    };
    if json {
        println!(
            "{{\"abi\":\"{ABI_MAJOR}.{}\",\"bytes\":{},\"entry_offset\":{},\"executable_bytes\":{},\"executable_format\":\"KEX v1\",\"format\":\"{format}\",\"heap_pages\":{},\"records\":{},\"requirements\":{},\"stack_pages\":{},\"target\":\"{}\"}}",
            report.abi_minor,
            report.bytes,
            report.entry_offset,
            report.executable_bytes,
            report.heap_pages,
            report.records,
            report.requirements,
            report.stack_pages,
            target_name(report.target),
        );
    } else {
        println!(
            "{format}; target={}; ABI={ABI_MAJOR}.{}; bytes={}; executable={} bytes; requirements={}; records={}; entry={:#x}; stack={} pages; heap={} pages",
            target_name(report.target),
            report.abi_minor,
            report.bytes,
            report.executable_bytes,
            report.requirements,
            report.records,
            report.entry_offset,
            report.stack_pages,
            report.heap_pages,
        );
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            Path::to_path_buf,
        )
}

/// Run the `troe-kex-tool` command-line interface.
///
/// # Errors
///
/// Returns a concise error for invalid arguments, I/O failures, rejected ELF
/// or KEX input, failed application compilation, or canonical byte mismatch.
pub fn run(arguments: impl Iterator<Item = OsString>) -> Result<(), ToolError> {
    let mut arguments = Arguments::new(arguments);
    let Some(operation) = arguments.next() else {
        print!("{HELP}");
        return Ok(());
    };
    match operation.to_str() {
        Some("build") => execute_build(&parse_build(&mut arguments)?),
        Some("convert") => execute_convert(&parse_convert(&mut arguments)?),
        Some("inspect") => execute_inspect(&mut arguments),
        Some("--help" | "-h" | "help") => {
            print!("{HELP}");
            Ok(())
        }
        _ => Err(ToolError::new(format!(
            "unknown operation {}; expected build, convert, or inspect",
            operation.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::filtered_rustc_arguments;
    use std::ffi::OsString;

    #[test]
    fn rustc_wrapper_removes_only_cargo_metadata() -> Result<(), super::ToolError> {
        let (rustc, arguments) = filtered_rustc_arguments(
            [
                "rustc",
                "--crate-name",
                "example",
                "-C",
                "metadata=checkout-hash",
                "-Cmetadata=second-hash",
                "-C",
                "extra-filename=-checkout-hash",
                "-Copt-level=z",
            ]
            .into_iter()
            .map(OsString::from),
        )?;
        assert_eq!(rustc, "rustc");
        assert_eq!(
            arguments,
            [
                "--crate-name",
                "example",
                "-C",
                "extra-filename=-checkout-hash",
                "-Copt-level=z",
            ]
        );
        Ok(())
    }
}

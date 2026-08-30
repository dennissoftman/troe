//! Host executable for portable development and acceptance testing.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::rc::Rc;

use troe_core::{Input, MAX_LINE_BYTES, MachineMemorySnapshot, Output, StreamError};
use troe_fs_kefs::Kefs;

/// Directories the embedded image supplies but does not own, because
/// manifest-selected volumes mount beneath them.
const EMBEDDED_MOUNT_ROOTS: &[&str] = &["/vol"];
use troe_fs_ramfs::{RamFs, RamFsQuota};
use troe_namespace::Namespace;
use troe_shell::{SharedNamespace, Shell, format_memory_report};

#[cfg(target_arch = "x86_64")]
const ROOTFS: &[u8] = include_bytes!("../../assets/root-x86_64.kefs");
#[cfg(target_arch = "aarch64")]
const ROOTFS: &[u8] = include_bytes!("../../assets/root-aarch64.kefs");
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the TROE host model supports only x86_64 and aarch64");

struct HostInput;

impl Input for HostInput {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, StreamError> {
        io::stdin()
            .read(destination)
            .map_err(|_| StreamError::Device)
    }
}

struct HostOutput {
    stderr: bool,
}

impl Output for HostOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        let result = if self.stderr {
            io::stderr().write(bytes)
        } else {
            io::stdout().write(bytes)
        };
        result.map_err(|_| StreamError::Device)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            let _ignored = writeln!(io::stderr(), "host model: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, String> {
    let mut namespace = Namespace::new();
    namespace
        .mount_writable("/tmp", Box::new(RamFs::new(RamFsQuota::default())))
        .map_err(|error| format!("cannot mount the writable filesystem: {error}"))?;
    let embedded =
        Kefs::parse(ROOTFS).map_err(|error| format!("cannot mount embedded root: {error}"))?;
    let embedded = embedded.into_mounts(EMBEDDED_MOUNT_ROOTS);
    for path in embedded.directories {
        namespace
            .add_read_only_dir(&path)
            .map_err(|error| format!("cannot mount embedded root: {error}"))?;
    }
    for (path, bytes) in embedded.files {
        namespace
            .add_read_only_file(&path, &bytes)
            .map_err(|error| format!("cannot mount embedded root: {error}"))?;
    }
    for (path, view) in embedded.mounts {
        namespace
            .mount_read_only(&path, Box::new(view))
            .map_err(|error| format!("cannot mount embedded root: {error}"))?;
    }
    // Generated /sys state is composition, so it is written here rather than by
    // the session, which now holds only the namespace client contract.
    let architecture = env::consts::ARCH;
    let machine_memory = MachineMemorySnapshot::hosted();
    namespace
        .set_system_file("/sys/arch", format!("{architecture}\n").as_bytes())
        .map_err(|error| format!("cannot compose namespace: {error}"))?;
    namespace
        .set_system_file("/sys/version", b"0.1.0\n")
        .map_err(|error| format!("cannot compose namespace: {error}"))?;
    let memory_report =
        format_memory_report(architecture, machine_memory, None, namespace.memory_stats());
    namespace
        .set_system_file("/sys/memory", memory_report.as_bytes())
        .map_err(|error| format!("cannot compose namespace: {error}"))?;
    let namespace: SharedNamespace = Rc::new(RefCell::new(namespace));
    let mut shell = Shell::new(namespace, true)
        .map_err(|error| format!("cannot compose namespace: {error}"))?;

    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.first().is_some_and(|value| value == "--command") {
        if arguments.len() != 2 {
            return Err("usage: host-model --command 'COMMAND'".into());
        }
        return Ok(execute_line(&mut shell, &arguments[1]));
    }
    if arguments.first().is_some_and(|value| value == "--script") {
        if arguments.len() != 2 {
            return Err("usage: host-model --script FILE".into());
        }
        let script = fs::read_to_string(&arguments[1])
            .map_err(|error| format!("cannot read {}: {error}", arguments[1]))?;
        let mut last = 0;
        for line in script.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            last = execute_line(&mut shell, line);
            if last != 0 || shell.machine_action().is_some() {
                break;
            }
        }
        return Ok(last);
    }
    if !arguments.is_empty() {
        return Err("usage: host-model [--command 'COMMAND' | --script FILE]".into());
    }

    println!("hosted model 0.1.0 ({})", env::consts::ARCH);
    println!("parser/session model only; boot QEMU to execute KEX applications");
    loop {
        print!("sh:{}> ", shell.cwd());
        io::stdout()
            .flush()
            .map_err(|error| format!("cannot flush prompt: {error}"))?;
        let mut line = String::new();
        let count = io::stdin()
            .read_line(&mut line)
            .map_err(|error| format!("cannot read console: {error}"))?;
        if count == 0 {
            return Ok(0);
        }
        trim_newline(&mut line);
        if line.len() > MAX_LINE_BYTES {
            eprintln!("input: line is too long (maximum {MAX_LINE_BYTES} bytes)");
            continue;
        }
        let _status = execute_line(&mut shell, &line);
        if shell.machine_action().is_some() {
            return Ok(0);
        }
    }
}

fn execute_line(shell: &mut Shell, line: &str) -> u8 {
    let mut input = HostInput;
    let mut output = HostOutput { stderr: false };
    let mut error = HostOutput { stderr: true };
    shell
        .execute(line, &mut input, &mut output, &mut error)
        .code()
}

fn trim_newline(line: &mut String) {
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
}

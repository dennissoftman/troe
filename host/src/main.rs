//! Host executable for portable development and acceptance testing.
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use kllm_core::{Input, MAX_LINE_BYTES, MachineMemorySnapshot, Output, StreamError};
use kllm_shell::Shell;
use kllm_vfs::{Namespace, RamFsQuota};

const ROOTFS: &[u8] = include_bytes!("../../assets/root.kefs");

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
    let mut namespace = Namespace::new(RamFsQuota::default());
    namespace
        .mount_embedded(ROOTFS)
        .map_err(|error| format!("cannot mount embedded root: {error}"))?;
    let mut shell = Shell::new(
        namespace,
        env::consts::ARCH,
        MachineMemorySnapshot::hosted(),
        true,
    )
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
            if last != 0 || shell.halt_requested() {
                break;
            }
        }
        return Ok(last);
    }
    if !arguments.is_empty() {
        return Err("usage: host-model [--command 'COMMAND' | --script FILE]".into());
    }

    println!("hosted model 0.1.0 ({})", env::consts::ARCH);
    println!("Tab completes commands; use 'man COMMAND' for manuals");
    loop {
        print!("shell:{}> ", shell.cwd());
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
        if shell.halt_requested() {
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

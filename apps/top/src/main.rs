#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt::{self, Write as _};
use troe_kex_sdk::{
    CommandContext, Error, INVOCATION_BUFFER_BYTES, StandardOutput, entry, exit,
    process_observation,
};

struct OutputWriter<'output>(&'output mut StandardOutput);

impl fmt::Write for OutputWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

const fn state_label(state: process_observation::State) -> &'static str {
    match state {
        process_observation::State::Ready => "ready",
        process_observation::State::Running => "running",
        process_observation::State::Blocked => "blocked",
        process_observation::State::Stopping => "stopping",
    }
}

const fn origin_label(origin: process_observation::Origin) -> &'static str {
    match origin {
        process_observation::Origin::Foreground => "fg",
        process_observation::Origin::Background => "bg",
        process_observation::Origin::Service => "svc",
    }
}

fn ticks_to_millis(ticks: u64, frequency: u64) -> u64 {
    let seconds = ticks / frequency;
    let remainder = ticks % frequency;
    seconds
        .saturating_mul(1_000)
        .saturating_add(remainder.saturating_mul(1_000) / frequency)
}

fn report(output: &mut impl fmt::Write, snapshot: &process_observation::Snapshot) -> fmt::Result {
    writeln!(
        output,
        "TROE top  uptime={}ms  processes={}",
        snapshot.observed_millis(),
        snapshot.processes().len(),
    )?;
    writeln!(output, "PID ORIGIN STATE    CPU-MS PAGES HANDLES NAME")?;
    for process in snapshot.processes() {
        writeln!(
            output,
            "{} {:<6} {:<8} {} {} {} {}",
            process.id,
            origin_label(process.origin),
            state_label(process.state),
            ticks_to_millis(process.cpu_ticks, snapshot.counter_frequency_hz()),
            process.resident_pages,
            process.handles,
            process.name.as_str(),
        )?;
    }
    Ok(())
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let count = match (invocation.argument(1), invocation.len()) {
        (None, 1) => u64::MAX,
        (Some(value), 2) => match value.parse::<u64>() {
            Ok(0) | Err(_) => {
                return common::usage(&mut command.stderr(), "top", b"top [COUNT]");
            }
            Ok(value) => value,
        },
        _ => return common::usage(&mut command.stderr(), "top", b"top [COUNT]"),
    };
    let Ok(mut observation) = command.process_observation() else {
        return exit::DENIED;
    };
    let Ok(mut timer) = command.timer() else {
        return exit::DENIED;
    };
    for index in 0..count {
        let Ok(snapshot) = observation.snapshot() else {
            common::report(
                &mut command.stderr(),
                "top",
                b"process observation unavailable",
            );
            return exit::FAILURE;
        };
        let written = {
            let mut stdout = command.stdout();
            let mut output = OutputWriter(&mut stdout);
            output
                .write_str("\x1b[2J\x1b[H")
                .and_then(|()| report(&mut output, &snapshot))
        };
        if written.is_err() {
            return common::stream_failure(&mut command.stderr(), "top");
        }
        if index.saturating_add(1) == count {
            break;
        }
        let Ok(now) = timer.now() else {
            return exit::FAILURE;
        };
        match timer.sleep_until(now.saturating_add(1_000)) {
            Ok(()) => {}
            Err(Error::Cancelled) => return exit::CANCELLED,
            Err(_) => return exit::FAILURE,
        }
    }
    exit::SUCCESS
}

entry!(main);

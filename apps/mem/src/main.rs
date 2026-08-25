#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::fmt;
use troe_kex_sdk::{
    CommandContext, INVOCATION_BUFFER_BYTES, StandardOutput, diagnostics, entry, exit,
};

struct OutputWriter<'output>(&'output mut StandardOutput);

impl fmt::Write for OutputWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

fn human_bytes(output: &mut impl fmt::Write, bytes: u64) -> fmt::Result {
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
        return write!(output, "{bytes} B");
    };
    let whole = bytes / unit;
    let hundredths = ((bytes % unit) * 100) / unit;
    if hundredths == 0 {
        write!(output, "{whole} {label}")
    } else if hundredths.is_multiple_of(10) {
        write!(output, "{whole}.{} {label}", hundredths / 10)
    } else {
        write!(output, "{whole}.{hundredths:02} {label}")
    }
}

fn byte_count(output: &mut impl fmt::Write, bytes: u64) -> fmt::Result {
    write!(output, "{bytes} (")?;
    human_bytes(output, bytes)?;
    output.write_str(")")
}

fn machine_report(
    output: &mut impl fmt::Write,
    memory: Option<diagnostics::MachineMemory>,
) -> fmt::Result {
    let Some(memory) = memory else {
        return output.write_str(
            "total usable: unavailable\nreserved: unavailable\nframes: unavailable\nheap: unavailable\nheap high-water: unavailable\nallocation failures: unavailable\n",
        );
    };
    output.write_str("total usable: ")?;
    byte_count(output, memory.usable_bytes)?;
    output.write_str("\nreserved: ")?;
    byte_count(output, memory.reserved_bytes)?;
    write!(
        output,
        "\nframes: {}/{} free\nheap: {}/{} used (",
        memory.free_frames, memory.total_frames, memory.heap_used_bytes, memory.heap_total_bytes
    )?;
    human_bytes(output, memory.heap_used_bytes)?;
    output.write_str("/")?;
    human_bytes(output, memory.heap_total_bytes)?;
    output.write_str(")\nheap high-water: ")?;
    byte_count(output, memory.heap_high_water_bytes)?;
    writeln!(
        output,
        "\nallocation failures: {}",
        memory.failed_allocations
    )
}

fn input_report(
    output: &mut impl fmt::Write,
    input: Option<diagnostics::InputQueue>,
) -> fmt::Result {
    let Some(input) = input else {
        return output.write_str(
            "input queue: unavailable\ninput interrupts: unavailable\ninput delivered: unavailable\ninput dropped: unavailable\ninput idle waits: unavailable\ninput wakeups: unavailable\n",
        );
    };
    write!(
        output,
        "input queue: {}/{} queued\ninput interrupts: {}\ninput delivered: {}\ninput dropped: {}\ninput idle waits: {}\ninput wakeups: {}\n",
        input.queued,
        input.capacity,
        input.interrupts,
        input.delivered,
        input.dropped,
        input.idle_waits,
        input.wakeups,
    )
}

fn report_snapshot(
    output: &mut impl fmt::Write,
    snapshot: diagnostics::Snapshot,
) -> fmt::Result {
    let architecture = match snapshot.architecture {
        diagnostics::Architecture::X86_64 => "x86_64",
        diagnostics::Architecture::Aarch64 => "aarch64",
    };
    let (owner, map) = match snapshot.memory_owner {
        diagnostics::MemoryOwner::Host => ("host process", "unavailable"),
        diagnostics::MemoryOwner::Firmware => ("firmware", "firmware snapshot (advisory)"),
        diagnostics::MemoryOwner::Kernel => ("kernel", "final map (owned)"),
    };
    write!(
        output,
        "arch: {architecture}\nmemory owner: {owner}\nmemory map: {map}\n"
    )?;
    machine_report(output, snapshot.machine_memory)?;
    input_report(output, snapshot.input)?;
    output.write_str("ramfs used: ")?;
    byte_count(output, snapshot.ramfs_used_bytes)?;
    output.write_str("\nramfs limit: ")?;
    byte_count(output, snapshot.ramfs_limit_bytes)?;
    output.write_str("\nramfs high-water: ")?;
    byte_count(output, snapshot.ramfs_high_water_bytes)?;
    write!(
        output,
        "\ncaches used: {}\ncaches limit: {}",
        snapshot.caches_used_bytes, snapshot.caches_limit_bytes
    )?;
    match snapshot.pressure {
        diagnostics::Pressure::Normal => {
            output.write_str("\npressure: normal (RAMFS policy only)\n")
        }
    }
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() != 1 {
        return common::usage(&mut command.stderr(), "mem", b"mem");
    }
    let Ok(mut diagnostics) = command.diagnostics() else {
        return exit::DENIED;
    };
    let Ok(snapshot) = diagnostics.snapshot() else {
        common::report(&mut command.stderr(), "mem", b"diagnostics unavailable");
        return exit::FAILURE;
    };
    let result = {
        let mut stdout = command.stdout();
        report_snapshot(&mut OutputWriter(&mut stdout), snapshot)
    };
    if result.is_err() {
        common::stream_failure(&mut command.stderr(), "mem")
    } else {
        exit::SUCCESS
    }
}

entry!(main);

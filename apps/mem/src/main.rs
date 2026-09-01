#![no_std]
#![no_main]
// Reads and writes the three private pages this command maps for itself, to
// prove that the mapping, protection change, and unmapping are all honored.
// Every block carries a SAFETY note naming the ownership it relies on.
#![allow(unsafe_code)]

#[path = "../../common.rs"]
mod common;

use core::fmt;
use core::fmt::Write as _;
use troe_kex_runtime::units::HumanBytes;
use troe_kex_sdk::{
    CommandContext, INVOCATION_BUFFER_BYTES, StandardOutput, diagnostics, entry, exit,
    private_memory,
};

const PAGE_BYTES: u64 = 4096;

struct OutputWriter<'output>(&'output mut StandardOutput);

impl fmt::Write for OutputWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

fn human_bytes(output: &mut impl fmt::Write, bytes: u64) -> fmt::Result {
    write!(output, "{}", HumanBytes::new(bytes))
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

fn report_snapshot(output: &mut impl fmt::Write, snapshot: diagnostics::Snapshot) -> fmt::Result {
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

fn memory_self_test(command: &mut CommandContext) -> Result<(), ()> {
    let mut memory = command.private_memory().map_err(|_| ())?;
    let before = memory.statistics().map_err(|_| ())?;
    if before.operation_quantum_pages == 0 {
        return Err(());
    }
    let address = memory
        .map_zeroed(3, 1, 0, private_memory::Protection::ReadWrite)
        .map_err(|_| ())?;
    let pointer = usize::try_from(address).map_err(|_| ())? as *mut u8;
    if pointer.is_null() {
        let _cleaned = memory.unmap(address, 3);
        return Err(());
    }
    // SAFETY: The typed capability just returned three uniquely owned,
    // writable pages to this single-threaded application.
    unsafe {
        if pointer.read() != 0
            || pointer.add(PAGE_BYTES as usize).read() != 0
            || pointer.add(2 * PAGE_BYTES as usize).read() != 0
        {
            let _cleaned = memory.unmap(address, 3);
            return Err(());
        }
        pointer.write(0x11);
        pointer.add(PAGE_BYTES as usize).write(0x22);
        pointer.add(2 * PAGE_BYTES as usize).write(0x33);
    }
    let middle = address.checked_add(PAGE_BYTES).ok_or(())?;
    memory
        .protect(middle, 1, private_memory::Protection::None)
        .map_err(|_| ())?;
    memory
        .protect(middle, 1, private_memory::Protection::Read)
        .map_err(|_| ())?;
    // SAFETY: The middle page was restored read-only and remains owned.
    if unsafe { pointer.add(PAGE_BYTES as usize).read() } != 0x22 {
        let _cleaned = memory.unmap(address, 3);
        return Err(());
    }
    memory.unmap(middle, 1).map_err(|_| ())?;
    memory.unmap(address, 1).map_err(|_| ())?;
    memory
        .unmap(address.checked_add(2 * PAGE_BYTES).ok_or(())?, 1)
        .map_err(|_| ())?;
    let after = memory.statistics().map_err(|_| ())?;
    if after.reserved_pages != before.reserved_pages
        || after.committed_pages != before.committed_pages
        || after.mappings != before.mappings
        || after.metadata_bytes != before.metadata_bytes
    {
        return Err(());
    }

    let mut random = command.random().map_err(|_| ())?;
    let mut first = [0_u8; 64];
    let mut second = [0_u8; 64];
    random.fill(&mut first).map_err(|_| ())?;
    random.fill(&mut second).map_err(|_| ())?;
    if first == second
        || (first.iter().all(|byte| *byte == 0) && second.iter().all(|byte| *byte == 0))
    {
        return Err(());
    }

    let mut stdout = command.stdout();
    writeln!(
        OutputWriter(&mut stdout),
        "memory-self-test ok image={:#x} quantum={}",
        main as *const () as usize,
        before.operation_quantum_pages,
    )
    .map_err(|_| ())
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    if invocation.len() == 2 && invocation.argument(1) == Some("--self-test") {
        return if memory_self_test(command).is_ok() {
            exit::SUCCESS
        } else {
            common::report(
                &mut command.stderr(),
                "mem",
                b"private memory self-test failed",
            );
            exit::FAILURE
        };
    }
    if invocation.len() != 1 {
        return common::usage(&mut command.stderr(), "mem", b"mem [--self-test]");
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

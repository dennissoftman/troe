# Current architecture

The same portable graph is linked into two composition roots:

```text
host stdin/stdout ───────────┐                 ┌─ hosted process
                             ├─ shell ─ VFS ──┤
serial / PS/2 → IRQ → bounded queue → editor ─┘  └─ UART + GOP text console
```

Privileged built-ins retain the direct graph. Stage 6 can instead run a bounded
continuation in a fresh ring-3/EL0 address space and route its copied output
through generation-owned synchronous message dispatch without exposing kernel
pointers.

Repository `scripts` and Cargo commands are bootstrap developer tooling, not a
package manager or a privileged system-control plane. The future CLI described
in [../TOOLING-PACKAGING-SPEC.md](../TOOLING-PACKAGING-SPEC.md) must sit
above versioned libraries and service interfaces. It does not replace the
statically linked recovery shell.

## Input-to-output trace

1. A composition root selects validated driver and editor policies. Owned
   device handlers drain only a configured number of raw bytes into a
   preallocated queue, then acknowledge the controller. The portable editor
   enforces its UTF-8 byte bound, cursor-aware editing, volatile history limits,
   and decoded key events; ANSI serial input and x86 set-1 PS/2 input feed the
   same event type outside interrupt context.
2. The shell crate tokenizes iteratively. Quotes group bytes; no expansion,
   recursion, substitution, environment lookup, or globbing occurs.
3. The pipeline executor finds a statically linked command by name. Commands
   receive only stdin/stdout/stderr streams plus access mediated by `Shell`.
4. Each non-final command writes to a `BoundedOutput`. The next stage reads the
   frozen result through `SliceInput`; a stage cannot observe mutable internals.
5. Filesystem commands ask `Namespace` to canonicalize from the logical cwd.
   Immutable KEFS nodes and writable `/tmp` nodes share one object model.
6. The final output capability writes host bytes or the native UART.
   When validated GOP metadata is available, normal native shell output is also
   rendered into an owned fixed-glyph framebuffer console. UEFI text output is
   confined to the pre-handoff banner.

Pipelines remain sequential even though cooperative tasks now exist. This makes
backpressure an explicit capacity error rather than requiring hidden scheduling.
A future bounded-ring implementation may add cooperative wakeups, but must
preserve the current byte order, EOF, partial-I/O, and capacity-error semantics.

## Authority

There are no ambient device or reboot globals in portable crates. Only the UEFI
composition root and isolated machine mechanism import firmware/hardware APIs.
`Shell` receives a boolean machine-control grant; `halt` is denied without it.
Privileged recovery built-ins still rely on typed authority rather than a
hardware boundary. Stage 6 task mappings and handles are additionally enforced
by ring-3/EL0 page permissions and generation-revoked ownership.

## Allocation

Portable components use `alloc` but every untrusted growth path has a local
hard bound. Stage 1 obtained allocation from UEFI. Stage 2 installs a hybrid
adapter: it delegates only before the explicit arena exists, then routes all new
allocations to the owned TLSF heap. Once handoff completes, firmware fallback is
permanently disabled. Pre-arena loader allocations, if any, are retained rather
than passed to dead boot services.

Stage 2 begins with an architecture-independent memory-map model in
`kllm-memory`. It validates checked 4 KiB ranges, normalizes unordered firmware
descriptors, overlays bounded explicit reservations, and reports usable and
reserved bytes. It also models checked, aligned monotonic allocation over one
explicitly reserved boot arena, including padding, exhaustion, and sealing
accounting. The UEFI adapter and later pointer boundary consume these models;
firmware types do not enter the portable crate.

The final handoff reserves a 2,084-page LoaderData arena, carves and seals a
6 MiB general heap, dedicates 2 MiB to monotonic page-table construction, and
reserves 128 KiB/16 KiB kernel and emergency stacks. It installs native
16550/PL011 and bounded polling fatal paths, transfers to the owned stack, and
enters a non-returning `ExitBootServices` continuation. Interrupts are masked
before exception state changes. Only then does the kernel reclassify expired
boot-services code/data as usable and build a compact bitmap over genuinely
allocatable pages. Any usable frames overlapping the page-rounded GOP aperture
are marked unavailable in that bitmap; the aperture is mapped RW/NX as device
memory and never aliases a normal-memory mapping. `mem` and `/sys/memory`
publish owned-map bytes, free/total frames, and live heap use, capacity,
high-water, and failure counts.

Stage 3 adds a pure, bounded mapping plan. The composition root identity-maps
only runtime RAM, PE-classified image sections, the boot arena, framebuffer,
and selected UART/interrupt-controller apertures. Physical aliases are accepted
only when their combined permissions preserve global W^X. The native backend
emits fresh 4 KiB tables, validates CPU-reported physical-address limits,
enables W^X, and replaces firmware exception state with fixed x86-64
GDT/TSS/IDT state or an AArch64 VBAR.
Executable image pages are RX, immutable image pages are RO/NX, and writable
runtime/device pages are NX. Deliberate write and execute violations are
validated in fresh QEMU boots for both architectures.

The post-handoff shell invokes no firmware protocol or allocator and cannot
manipulate page tables or exception vectors. Authorized halt parks the CPU.
Stage 4 adds a bounded cooperative scheduler policy in `kllm-task`. Task IDs
are monotonic, records have ready/running/exited lifecycles, capability sets are
checked during dispatch, and a record retains its stack resource until explicit
reaping. The native mechanism executes one continuation step synchronously on
the task's mapped payload stack; yielding returns a typed result and keeps all
durable state in an explicitly owned continuation object rather than retaining
arbitrary native frames. The scheduler record accounts for that continuation's
identity, authority, lifecycle, and stack resource.
This makes every scheduling boundary explicit and keeps architecture register
state out of portable code.

The boot arena contains three reusable 32 KiB task payload slots. Each has an
unmapped 4 KiB page on both sides, while the payload is RW/NX. Boot verification
interleaves two services, checks deterministic yield/exit counts, reaps their
records, and reuses a returned slot before launching the shell on the third.
The shell record alone carries console, filesystem, and machine-control
capabilities. Cooperative scheduling still provides no preemption or hardware
isolation: code that never yields can monopolize the CPU, and privileged memory
unsafety can corrupt any task.

Stage 5 adds `kllm-dispatch` between selected clients and services. A port names
one registered service; a generation-checked handle names explicit call
authority to that port. Tables are bounded to 16 ports and 32 live handles, and
stale identities remain invalid when slots are reused. One synchronous request
borrows at most 4 KiB of immutable input and produces at most 4 KiB of owned
reply bytes with a matching monotonic request ID and typed service status.
Because the dispatcher is exclusively borrowed for delivery, Stage 5 has no
queued cancellation state: closing before a call invalidates the handle, and a
delivered call completes before another mutation can occur.

The first switched edge is native console output. `ConsoleService` converts a
bounded write request into the existing `Output` operation, while
`DispatchedOutput` presents the same byte-stream trait to the shell. Requests
larger than one message are split through ordinary partial-write semantics.
Fatal diagnostics and input delivery remain direct machine mechanisms. This is
still in-process dispatch, not IPC: service code shares the caller's privileged
address space, borrowed request bytes are not a wire format, and service faults
are not contained.

Stage 5.1 adds `kllm-terminal`, which keeps transport-independent input
decoding, line editing, history, and fixed-glyph text rendering outside the
machine mechanism. `kllm-shell` owns completion because it has the authoritative
command registry and VFS namespace; both command candidates and directory
listings are returned under caller-selected count and byte budgets. The native
composition root currently selects the named `tiny` policies. x86-64 decodes
US set-1 scan codes from q35 i8042, while both architectures retain serial
input. AArch64 native keyboard input is deferred to a bounded
virtio-input transport rather than adding a firmware dependency after handoff.

Stage 5.2 adds the portable `kllm-driver` resource and event boundary. The
selected queue capacity, maximum ISR drain, and programmable controller
priority come from validated profile configuration. The pinned x86-64 profile
masks the legacy PIC, owns LAPIC/I/O APIC, and routes COM1 and keyboard receive
interrupts through explicit IDT gates. The pinned AArch64 profile owns GICv2
and routes PL011 through its IRQ vector. Handlers preserve interrupted CPU
state, perform bounded non-allocating device work, and enqueue typed raw bytes;
decoding and editing remain in main context. An empty queue executes a
lost-wakeup-safe `sti; hlt` or IRQ-masked `dsb; wfi` transition followed by
pending-handler dispatch. Direct polling is retained only for bootstrap and
fatal recovery, and no timer or preemption is introduced. `mem` and
`/sys/memory` expose queue, interrupt, delivery, drop,
idle, and wakeup accounting; byte-valued memory counters retain exact values
and add binary IEC `KiB`/`MiB`/`GiB` displays.

Stage 6 adds fresh task roots built from the supervisor kernel plan. Stage 7
raises the bounded user-region summary to nineteen: at most sixteen KEX image
segments plus startup, heap, and stack. x86 page-table traversal and leaves use
U/S and enter through a DPL-3 gate with TSS RSP0; AArch64 leaves use AP/PXN/UXN
and enter EL0t through the lower-EL vector with SP_EL1. The native boundary
preserves ABI callee-saved integer and floating-point/SIMD state and masks
interrupts for the current cooperative, non-preemptive continuation.

One internal exit gate validates opcode, status, the complete readable user
range, and a preallocated 4 KiB destination before copying. Its result becomes
a kernel-owned `CopiedMessage`; it is deliberately not a stable syscall or wire
ABI. Translation, write, execute, illegal-instruction, and invalid-call fates
terminate only the active user record. Kernel-originated faults remain terminal.

Task creation and teardown are transactional. A record retains its root/private
frame counts and owned handle count. Teardown revokes all handles for the
monotonic task identity, reaps the exact record, zeroes the complete table/code/
data/stack allocation, and atomically returns it to the frame bitmap. Every
production boot exercises all fault classes, checks zero partial delivery and
zero frame loss, proves the same physical allocation can be reused, then enters
the shell. See
[ADR 0014](adr/0014-unprivileged-task-isolation-and-teardown.md).

The first native Stage 7 boundary copies KEX bytes into bounded kernel staging
and consumes the complete portable plan before allocating or mapping. It packs
fresh physical image pages behind a separate table reservation, maps sparse
image virtual ranges with their closed R/RX/RW permissions, places the startup,
heap, guards, and stack canonically, and keeps the root inactive. The root
retains supervisor mappings for the kernel image, devices, and only the explicit
boot-arena runtime ranges needed across an isolated transition; it does not copy
the general free-RAM identity map. This keeps both backends within the tiny
profile's 64-page table ceiling. A provisional task receives only the
loader-selected handle; boot acceptance then revokes it,
reaps the record, zeroes every provisional frame, and verifies exact reuse.
Malformed native corpus cases fail before frame allocation. Application entry
now resets visible register/control state, passes only the startup address and
length, and enables IRQs after arming a 50 ms one-shot. ABI call 0 exits through
the owned gate. A separate spinning KEX is terminated by the x86 local-APIC or
AArch64 generic physical timer, recorded as `execution-lease-expired`, and
reclaimed transactionally. ABI gates capture a bounded full user context;
`yield` returns through the cooperative scheduler, while `handle_call` validates
complete non-overlapping ranges, copies a two-byte opcode-prefixed request,
checks task handle ownership, and copies a successful bounded reply before a
fresh leased resume. Unknown calls and an attempted `_start` return are
contained and reclaimed as invalid-call and translation faults.

## Future persistent-storage boundary

Persistent storage preserves the same dependency direction. A transport
provides bounded block-region capabilities; partition discovery turns a whole
device into non-overlapping regions; independently selected filesystem
providers expose VFS objects. Format-specific structures do not enter the
machine backend, block transport, partition layer, or kernel composition root.

```text
block transport -> bounded region -> filesystem provider -> VFS namespace
                         ^
                  whole device or GPT
```

KEFS is the intentionally built-in recovery exception. The current FAT12 image
is read by firmware. General FAT12/16/32, exFAT, the default persistent ext4
profile, and later NTFS support are separate providers; before dynamic loading
they may be statically selected crates, and later writable providers should run
as capability-scoped services. An image does not carry providers it did not
select.

An external filesystem provider may be packaged under its own declared license,
but the module label alone is not a license boundary. Differently licensed
source and artifacts remain outside the Apache-licensed core and default image;
the service/module ABI, provenance, notices, and release treatment are reviewed
explicitly. Static linkage into the kernel image is not considered separation.

Initial partition support is discovery rather than management: accept a whole
device or validate a bounded GPT layout created by host/installer tooling. No
filesystem provider can address blocks outside its granted region. See
[ADR 0009](adr/0009-persistent-filesystems-and-partitions.md).

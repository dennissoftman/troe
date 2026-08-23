# Implementation roadmap

## Landed in the initial slice

- Stage 0 host runner and Stage 1 UEFI applications share portable code.
- Both EFI targets compile on stable Rust and fit well below component budgets.
- Root data is generated deterministically and validated again when mounted.
- RAMFS mutation, deletion accounting, parser failures, partial reads, grep
  boundary behavior, pipelines, and command status have host tests.
- Build, test, image, size, and QEMU entry points are repository scripts.
- Prompt-synchronized QEMU acceptance drives both production images through all
  built-ins, failure cases, RAMFS quota exhaustion and recovery, memory
  reporting, and authorized halt with bounded timeouts.

## Stage 2: owned machine (complete)

### 1. Owned memory and console substrate — complete

Normalize the UEFI memory map, reserve the image/stack/KEFS/map, introduce a
bounded monotonic boot allocator, implement a project-owned frame bitmap, and add
polling 16550/PL011 backends. Keep firmware services active until native fatal
diagnostics and allocator accounting are verified.

Landed: the portable normalization, monotonic boot allocator, and compact frame
bitmap are host tested. Both images reserve an explicit LoaderData arena and
run polling 16550/PL011 backends before firmware services are released.

Exit: allocator model tests cover discontiguous ranges, exhaustion, double
free, invalid free, and checked overflow; native UART output matches firmware
output in QEMU.

### 2. Exit boot services as one reviewed transition — complete

Select and audit the general heap, copy the final memory map into owned memory,
drop every firmware protocol reference, switch console and fatal paths, exit
boot services, and publish full memory counters through `mem`.

Exit: repeated pipeline/RAMFS workloads run without firmware services or leaks,
and allocation failure reaches a bounded diagnostic path.

Landed: `rlsf` TLSF was selected and measured, the final map is retained and
normalized, every console/fatal path is native, boot services are exited, and
`mem` exposes owned frame and heap counters. Dual-QEMU acceptance proves no net
heap growth across repeated transient workloads and exercises the bounded
allocation-failure probe.

MMU-owned page tables and W^X follow this transition; they should not be mixed
into the first memory-ownership patch.

## Stage 3: MMU-owned mappings and W^X (verified)

Build architecture-specific page tables from pure, host-tested range plans;
classify normal and device memory; protect immutable and executable regions;
and add deliberate permission-fault acceptance cases on both architectures.

Exit: mapping invariants hold in model tests and representative write and
execute violations reach stable native fault diagnostics in QEMU.

Landed: a bounded architecture-neutral mapping plan rejects virtual overlap,
unsafe physical aliases, overflow, W+X, executable devices, and unequal ranges
in host tests. The kernel builds a minimal identity plan for owned runtime RAM,
PE-classified image sections, and the PL011 device page; x86-64 and AArch64
translate it into fresh 4 KiB page
tables from a reserved 2 MiB arena. Kernel text is RX, immutable image data is
RO/NX, runtime memory is RW/NX, and device memory is RW/NX with device
attributes. A one-way owned-stack handoff precedes firmware-memory reclamation.
Native fixed-selector x86-64 GDT/TSS/IDT and masked AArch64 VBAR state provide
terminal coverage for unexpected exceptions. Destructive write, execute, and
native-exception probes exist only in separate acceptance images; production
images are scanned to exclude their command strings. Host tests, both target
Clippy gates, production/acceptance builds, and the pinned dependency audit pass.
The exhaustive normal-boot, write-fault, execute-fault, native-exception,
fatal-state, and terminal-halt matrix passes on both targets with QEMU 11.1.0.

## Stage 4: cooperative tasks (complete)

Introduce bounded task records, explicit owned stacks with guard pages,
cooperative yield, task lifecycle accounting, and capability-scoped dispatch
without adding preemption or per-task address spaces.

Exit: multiple tasks yield and terminate deterministically, stack guards reach
native fault diagnostics, and task-owned resources are reclaimed without
changing the single-address-space authority model.

Landed: `kllm-task` provides a 16-record hard ceiling, monotonic task IDs,
round-robin ready/running/exited transitions, typed capability sets, explicit
yield/exit accounting, and reaping that returns the exact guarded-stack slot.
The kernel reserves three 32 KiB task payloads, each between two unmapped 4 KiB
guards. Architecture-local trampolines run one explicit continuation step on a
task stack and restore the scheduler stack on yield or exit. Boot acceptance
executes two interleaved services, checks five deterministic yields, reaps both,
reuses a returned slot, then dispatches the console/filesystem/machine-control
shell task only with its declared capabilities. Feature-only acceptance images
write a task guard and reach the same terminal native fault state on both
architectures; production images exclude that dispatch string.

The continuation model deliberately stores durable state in an explicitly
owned continuation object, accounts for it through the bounded task record, and
discards native frames at each yield. It does not add preemption, saved
arbitrary call stacks, per-task address spaces, or a hardware isolation claim.
See [ADR 0010](adr/0010-cooperative-tasks-and-guarded-stacks.md).

## Stage 5: in-process message dispatch (complete)

Introduce handles, ports, bounded messages, request/reply semantics, and a
service adapter that can replace a selected direct call without changing its
conceptual API.

Exit: a filesystem or console service can switch between direct and dispatched
implementations in tests.

Landed: `kllm-dispatch` provides generation-checked opaque port and handle
identities, per-handle call rights, hard ceilings of 16 ports, 32 handles, and
4 KiB per request or reply, monotonic request IDs, owned bounded replies, typed
service statuses, explicit close/invalidation, and live call/reply accounting.
Requests borrow immutable bytes only for one synchronous call; no queued state,
blocking, cancellation race, shared-memory contract, or wire ABI is implied.

`ConsoleService` and `DispatchedOutput` preserve the existing byte-oriented
`Output` interface. Host tests send the same payload through direct and
dispatched console implementations and compare exact bytes, including a payload
that requires multiple bounded calls. The native shell registers one console
port and emits prompts and normal stdout through its one explicitly granted call
handle. Native fatal output and input delivery stay at the machine boundary so a
dispatcher failure cannot recurse through itself. Both QEMU targets require the
dispatch-ready boot marker. See
[ADR 0011](adr/0011-bounded-in-process-message-dispatch.md).

## Stage 5.1: native text console and shell usability — complete

The portable `kllm-terminal` crate now provides configurable input decoding,
cursor-aware line editing, bounded volatile history, set-1 keyboard decoding,
and fixed-glyph framebuffer rendering. `kllm-shell` provides bounded
command/VFS completion from one authoritative command registry. The kernel
copies and validates UEFI GOP metadata before handoff and mirrors normal output
to an owned RW/NX device mapping while retaining UART for early, fatal,
headless, and acceptance paths.

Exit: both architectures can display and edit a shell line through the owned
text-console abstraction; every retained-entry and byte budget comes from a
validated selected profile; unknown serial escape sequences cannot corrupt the
line; and the existing deterministic UART acceptance matrix remains available.
The x86-64 q35 profile also accepts a native PS/2 keyboard. AArch64 native
keyboard input is a later virtio-input increment; serial input and owned ramfb
output are covered now.
See [ADR 0012](adr/0012-native-text-console-and-editor-policy.md).

## Stage 5.2: interrupt-driven input and driver resources — complete

The portable `kllm-driver` crate now provides checked MMIO, I/O-port, and
interrupt resources plus a preallocated raw-input FIFO. Its capacity,
per-interrupt drain budget, overflow accounting, and programmable priority are
selected by validated configuration. The machine layer owns q35 LAPIC/I/O APIC
and AArch64 `virt` GICv2, routes PS/2, 16550, and PL011 receive interrupts, and
replaces the shell's busy poll loop with race-free `hlt`/`wfi` idle. Bootstrap
and fatal recovery retain direct polling, and the cooperative scheduler remains
non-preemptive.

Exit: both QEMU architectures receive serial shell input only through owned
interrupt delivery after initialization; x86 native keyboard input uses IRQ1;
all ISR loops and retained events obey selected profile bounds; overflow and
interrupt counters are observable; idle wakeups cannot be lost; and fault,
terminal, and recovery-console acceptance remains green. QEMU acceptance checks
positive delivery/idle counters and zero drops under ordinary input. See
[ADR 0013](adr/0013-interrupt-driven-input-and-driver-resources.md).

## Stage 6: optional isolation (complete)

Landed: fresh per-task roots execute at x86-64 ring 3 and AArch64 EL0t with
kernel mappings supervisor-only, explicit RX/RW user mappings, unmapped stack
guards, and global W^X across safe aliases. The internal exit gate validates a
complete user range before copying at most 4 KiB into kernel-owned memory.
Handles carry monotonic task ownership and are generation-revoked before exact
record reaping, page zeroization, and atomic frame-range return.

Exit: a deliberately faulting isolated task cannot corrupt the kernel or an
unrelated service; its memory, handles, and task resources are reclaimed, and
authority transfer remains explicit. Stage 6 does not imply loadable
applications, a stable userspace ABI, or preemption; those require separate
decisions and later milestones. Every boot on both architectures contains
translation, write, execute, illegal-instruction, disabled alternate-entry,
invalid-opcode, invalid-pointer, oversize-message, and invalid-status faults;
AArch64 also rejects a nonzero `SVC` encoding. The matrix proves no partial
copy or net frame loss, reuses the returned physical range, then enters the
ordinary shell. See
[ADR 0014](adr/0014-unprivileged-task-isolation-and-teardown.md).

## Stage 7: loadable applications (next; design accepted)

Stage 6 supplies the privilege, copied-message, fault-fate, and transactional
teardown boundary required by a loader.
[ADR 0015](adr/0015-kex-application-abi-and-execution-bounds.md) selects the
small static KEX v1 container, application ABI 1.0, per-profile staging and
resident-memory ceilings, and a 50 ms maximum uninterrupted user lease
terminated by an owned timer. Those choices are intentionally independent of
the internal Stage 6 probe format.

The first implementation slice has landed: `kllm-application` provides the
allocation-free KEX v1 parser, fixed profile limits, bounded load plans, exact
and conservative page charges, and a shared host-test rejection corpus. The
crate also compiles as a direct native-kernel dependency. Kernel-owned staging,
frame allocation, mapping, startup-page construction, ABI entry/calls, and the
owned execution timer remain to be implemented.

The next kernel slice must copy artifacts into kernel-owned staging, consume the
portable plan before mapping any application page, grant only explicit initial
handles, and reuse the Stage 6 one-shot root, copied-message, fault containment,
zeroization, and reclamation paths. The rejection corpus must then run through
the native load boundary on both targets in addition to its host coverage.

Exit: a valid target-specific static application can start, call a documented
minimal ABI, exit or fault without harming the kernel or another service, and
leave no memory or handle ownership behind. Malformed artifacts fail before
execution with no partial mappings. Dynamic linking, POSIX compatibility,
preemption, persistence, and a public package registry are not part of the
first Stage 7 increment.

## Deferred tooling and packaging track

The tooling/package architecture is documented now so early formats and
interfaces do not foreclose it, but it is not part of the next three
increments. Until loadable applications and persistence exist, Cargo,
repository scripts, KEFS, and FAT images remain explicit bootstrap mechanisms,
not public package or generation formats.

Hosted manifest, lock, and artifact validation may be prototyped before native
application loading. Native execution begins with core Stage 7; a persistent
store, system generations, and rollback begin with Stage 8; supported updates,
registry trust, and deployment belong to Stage 9. See
[../TOOLING-PACKAGING-SPEC.md](../TOOLING-PACKAGING-SPEC.md#511-alignment-with-the-core-roadmap).

The Stage 8 storage direction is already bounded by
[ADR 0009](adr/0009-persistent-filesystems-and-partitions.md): keep KEFS as the
built-in recovery root and FAT12 as the current firmware container; introduce
whole-device regions and read-only GPT discovery; provide read/write
FAT12/16/32, exFAT, constrained ext4, and later NTFS as separately selected
filesystem modules. Ext4 is the default native persistent data provider;
FAT/exFAT serve removable-media interchange. Partition creation remains
host-side, and writable filesystem providers should move behind isolated
service boundaries when the task/application model can support that transition.
Separately licensed modules remain outside the default Apache-2.0 image and
require explicit packaging and distribution review.

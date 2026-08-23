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

Landed: a bounded architecture-neutral mapping plan rejects virtual and physical
overlap, overflow, W+X, executable devices, and unequal ranges in host tests. The kernel builds a
minimal identity plan for owned runtime RAM, PE-classified image sections, and
the PL011 device page; x86-64 and AArch64 translate it into fresh 4 KiB page
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

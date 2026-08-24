# ADR 0008: owned page tables and W^X

Status: accepted, 2026-08-22.

## Decision

Stage 3 keeps the existing low identity layout but replaces firmware page
tables on both primary architectures. A pure `troe-memory` mapping plan records
virtual and physical ranges, read/write/execute permissions, normal or device
memory type, owner, lifetime, and remapping policy. It is bounded to 512 sorted
records and rejects overlap, checked-arithmetic failure, unequal range lengths,
unreadable mappings, writable executable mappings, and executable devices.
Physical aliases are rejected entirely in Stage 3, so no physical byte can be
exposed through mappings with conflicting permissions or attributes.

The running PE/COFF image is parsed through the bounded UEFI `LoadedImage`
view. Headers and gaps are RO/NX, executable sections are RX, writable sections
are RW/NX, and all other sections are RO/NX. Reclaimable conventional and boot
services RAM plus the explicit boot arena are RW/NX. AArch64 additionally maps
the single PL011 register page as device RW/NX; x86-64 uses port I/O for COM1.
No other firmware or physical range is carried into the new address space.

The 2,084-page LoaderData boot reservation is split into a 6 MiB TLSF heap, a
2 MiB monotonic page-table arena, a 128 KiB kernel stack, and a 16 KiB x86
emergency exception stack. A non-returning architecture trampoline switches to
the owned stack before `ExitBootServices`; only then can the former firmware
stack become allocatable. Each backend emits 4 KiB mappings: x86-64 validates
CPUID address width and enables EFER.NXE and CR0.WP before loading CR3, while
AArch64 derives TCR.IPS from ID_AA64MMFR0_EL1 and validates 4 KiB granule
support. Page tables and active stacks are never returned to the frame allocator.

x86-64 disables maskable interrupts and installs fixed code/data selectors, a
TSS with a double-fault IST, and terminal gates for all architectural exceptions.
AArch64 masks DAIF and installs a 2 KiB-aligned VBAR table covering all vector
slots. Fatal handlers avoid allocation and filesystem access, print a stable
native-UART diagnostic, and park the CPU. Feature-only acceptance images boot a
fresh machine for write-to-RO, execute-from-NX, and unexpected native exceptions;
production images are checked to contain none of the probe command strings.

Maskable interrupts remain disabled because Stage 3 does not own APIC/GIC
routing. x86 NMI and machine-check vectors have present terminal gates, but a
diagnostic is not promised when hardware has already corrupted execution state;
the pinned QEMU profile does not inject either condition. Double fault alone uses
the dedicated IST so a normal-stack failure does not immediately triple fault.
On AArch64 DAIF remains fully masked; synchronous exceptions use the owned VBAR
while asynchronous interrupt-controller ownership is deferred.

## Consequences

Identity mapping avoids introducing a platform-independent high-half layout
before it simplifies anything. It does not create isolation: built-ins still
share one privileged address space. The dedicated table arena is deliberately
larger than the pinned 64/128 MiB QEMU profiles require, trading two reserved
MiB for a simple, bounded builder with no recursive allocation during handoff.

Guard pages remain deferred until Stage 4 introduces task stacks and scheduling.
Stage 3 nevertheless leaves the UEFI dispatcher stack through a reviewed
non-returning transition before it exposes expired boot-services memory to the
frame allocator. The shell therefore runs on an explicit owned and accounted
RW/NX stack; Stage 4 will replace it with per-task guarded stacks.

Implementation note, 2026-08-23: Stage 4 subsequently added three guarded
32 KiB task-stack payloads. The 128 KiB owned kernel stack remains the scheduler
and handoff stack; the shell now runs on a guarded task stack. See
[ADR 0010](0010-cooperative-tasks-and-guarded-stacks.md).

Implementation note, 2026-08-23: Stage 6 permits a narrowly safer alias class:
RO aliases and RW/NX aliases are valid, while the union of permissions across
every alias must still exclude write plus execute. Fresh task roots use this to
map private pages at user virtual addresses without weakening global W^X. See
[ADR 0014](0014-unprivileged-task-isolation-and-teardown.md).

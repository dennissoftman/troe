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

## Next three increments

### 1. Owned memory and console substrate

Normalize the UEFI memory map, reserve the image/stack/KEFS/map, introduce a
bounded monotonic boot allocator, implement a project-owned frame bitmap, and add
polling 16550/PL011 backends. Keep firmware services active until native fatal
diagnostics and allocator accounting are verified.

In progress: the bounded, architecture-independent normalization and monotonic
boot-allocation models and their host tests have landed. Adapting the live UEFI
descriptors and identifying the first explicit reserved arena are next; no
machine memory is claimed yet.

Exit: allocator model tests cover discontiguous ranges, exhaustion, double
free, invalid free, and checked overflow; native UART output matches firmware
output in QEMU.

### 2. Exit boot services as one reviewed transition

Select and audit the general heap, copy the final memory map into owned memory,
drop every firmware protocol reference, switch console and fatal paths, exit
boot services, and publish full memory counters through `mem`.

Exit: repeated pipeline/RAMFS workloads run without firmware services or leaks,
and allocation failure reaches a bounded diagnostic path.

MMU-owned page tables and W^X follow this transition; they should not be mixed
into the first memory-ownership patch.

### 3. MMU-owned mappings and W^X

Build architecture-specific page tables from pure, host-tested range plans;
classify normal and device memory; protect immutable and executable regions;
and add deliberate permission-fault acceptance cases on both architectures.

Exit: mapping invariants hold in model tests and representative write and
execute violations reach stable native fault diagnostics in QEMU.

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

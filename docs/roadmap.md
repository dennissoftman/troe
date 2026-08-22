# Implementation roadmap

## Landed in the initial slice

- Stage 0 host runner and Stage 1 UEFI applications share portable code.
- Both EFI targets compile on stable Rust and fit well below component budgets.
- Root data is generated deterministically and validated again when mounted.
- RAMFS mutation, deletion accounting, parser failures, partial reads, grep
  boundary behavior, pipelines, and command status have host tests.
- Build, test, image, size, and QEMU entry points are repository scripts.

## Next three increments

### 1. QEMU acceptance harness

Install the pinned QEMU/firmware pair in CI, drive the UEFI console, assert the
stable prompt/transcript, and test both images. Add a serial-first machine
console because UEFI Simple Text Input is difficult to automate consistently.

Exit: both architectures execute `tests/smoke.ksh` equivalents and return to
firmware within a timeout.

### 2. Owned memory and console substrate

Normalize the UEFI memory map, reserve the image/stack/KEFS/map, introduce a
bounded monotonic boot allocator, implement a project-owned frame bitmap, and add
polling 16550/PL011 backends. Keep firmware services active until native fatal
diagnostics and allocator accounting are verified.

Exit: allocator model tests cover discontiguous ranges, exhaustion, double
free, invalid free, and checked overflow; native UART output matches firmware
output in QEMU.

### 3. Exit boot services as one reviewed transition

Select and audit the general heap, copy the final memory map into owned memory,
drop every firmware protocol reference, switch console and fatal paths, exit
boot services, and publish full memory counters through `mem`.

Exit: repeated pipeline/RAMFS workloads run without firmware services or leaks,
and allocation failure reaches a bounded diagnostic path.

MMU-owned page tables and W^X follow this transition; they should not be mixed
into the first memory-ownership patch.

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

# ADR 0005: memory ownership direction

Status: accepted and implemented for Stage 2, 2026-08-22.

Implement the physical-frame mechanism as paired compact bitmaps over normalized
4 KiB pages: one records live allocations and one records permanent reservations
for discontiguous firmware and device regions. Reserved frames cannot be freed,
and reserving a range never changes the ownership of a live allocation. Debug and
model builds detect invalid and double frees. Use a bounded monotonic allocator
before the general heap.

The general-heap decision selected pinned `rlsf` 0.2.3: a maintained,
constant-time, two-level segregated-fit implementation supporting `no_std` and
MIT OR Apache-2.0 licensing. The machine adapter supplies locking, UEFI fallback
before arena installation, ownership switching, counters, and bounded failure
probing.

A linked-list-only frame allocator was rejected because fragmented firmware
maps make ownership queries and invalid-free detection harder. A general buddy
allocator was rejected as the first frame mechanism because coalescing adds
metadata and invariants before workloads justify it.

Revisit the bitmap only if very large-memory metadata is measured as material.

Stage 2 introduced the LoaderData boot arena and a checked monotonic model for a
6 MiB heap. Stage 3 extends that arena to 2,084 pages for the 2 MiB page-table
arena and explicit 128 KiB/16 KiB kernel and emergency stacks. The final map keeps LoaderCode,
LoaderData (including image, stack, embedded KEFS, arena, and map buffer),
runtime, ACPI, and device regions reserved. Conventional and expired boot-
services regions become usable. Both compact bitmaps track only usable pages, so
high MMIO ranges do not inflate metadata. The final-map buffer remains a
permanent loader reservation after handoff.

The transition installs native UART and fatal output first, ends all protocol
borrows, moves to the owned stack, and calls ExitBootServices through an audited
non-returning machine boundary. It then disables firmware allocation fallback,
masks interrupts, and never returns to UEFI. Stage 3 installs MMU-owned mappings
and CPU exception vectors before entering the shell.

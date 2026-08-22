# ADR 0005: memory ownership direction

Status: accepted and implemented for Stage 2, 2026-08-22.

Implement the physical-frame mechanism as a compact bitmap over normalized
4 KiB pages, with explicit reservations for discontiguous firmware and device
regions. Debug and model builds detect invalid and double frees. Use a bounded
monotonic allocator before the general heap.

The general-heap evaluation selected pinned `rlsf` 0.2.3: a maintained,
constant-time, two-level segregated-fit implementation supporting `no_std` and
MIT OR Apache-2.0 licensing. The machine adapter supplies locking, UEFI fallback
before arena installation, ownership switching, counters, and bounded failure
probing. See [../evaluations/0001-general-heap.md](../evaluations/0001-general-heap.md).

A linked-list-only frame allocator was rejected because fragmented firmware
maps make ownership queries and invalid-free detection harder. A general buddy
allocator was rejected as the first frame mechanism because coalescing adds
metadata and invariants before workloads justify it.

Revisit the bitmap only if very large-memory metadata is measured as material.

Stage 2 reserves an 8 MiB LoaderData boot arena and uses the checked monotonic
model to carve a 6 MiB heap before sealing it. The final map keeps LoaderCode,
LoaderData (including image, stack, embedded KEFS, arena, and map buffer),
runtime, ACPI, and device regions reserved. Conventional and expired boot-
services regions become usable. A compact bitmap tracks only usable pages, so
high MMIO ranges do not inflate metadata. The final-map buffer remains a
permanent loader reservation after handoff.

The transition installs native UART and fatal output first, ends all protocol
borrows, captures the final map, calls ExitBootServices once through the audited
machine boundary, disables firmware allocation fallback, and never returns to
UEFI. MMU-owned mappings and CPU exception vectors remain Stage 3 work.

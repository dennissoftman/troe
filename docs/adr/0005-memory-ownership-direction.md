# ADR 0005: memory ownership direction

Status: accepted direction; Stage 2 implementation pending.

Implement the physical-frame mechanism as a compact bitmap over normalized
4 KiB pages, with explicit reservations for discontiguous firmware and device
regions. Debug and model builds detect invalid and double frees. Use a bounded
monotonic allocator before the general heap.

Do not invent the general heap until a short evaluation measures at least a
segregated free-list and TLSF-style audited implementation against alignment,
failure propagation, metadata, code size, `no_std`, and license requirements.
Stage 1 temporarily uses the UEFI pool allocator and clearly reports that fact.

A linked-list-only frame allocator was rejected because fragmented firmware
maps make ownership queries and invalid-free detection harder. A general buddy
allocator was rejected as the first frame mechanism because coalescing adds
metadata and invariants before workloads justify it.

Revisit the bitmap only if very large-memory metadata is measured as material.

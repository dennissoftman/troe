# General heap evaluation

Status: selected for Stage 2, 2026-08-22.

The fixed 6 MiB single-core heap needs checked alignment, explicit failure,
coalescing, `no_std`, a compatible license, and a small auditable adapter. It
does not yet need SMP throughput or returning pages to the frame allocator.

| Candidate | Result |
|---|---|
| Provisional in-tree address-ordered first fit | Alignment, split/coalesce, reuse, and failure tests passed, but allocation is linear and the prototype raised authored unsafe tokens to 67. Rejected because the project would own an unnecessary allocator implementation. |
| [`embedded-alloc` 0.7 TLSF](https://docs.rs/embedded-alloc/0.7.0/embedded_alloc/struct.TlsfHeap.html) | Maintained Rust Embedded wrapper around `rlsf`, `no_std`, MIT/Apache-2.0. Its critical-section integration does not replace kllm's required UEFI fallback, ownership phase, counters, or machine lock, so the wrapper adds no useful boundary here. |
| [`rlsf` 0.2.3](https://github.com/yvt/rlsf) | Selected. Maintained two-level segregated fit, constant-time allocation/deallocation, `no_std`, MIT/Apache-2.0, fallible allocation, arbitrary fixed pools, and adjustable first/second-level metadata. |

The selected `Tlsf<'static, u32, u16, 20, 16>` accepts pools up to 32 MiB and
uses about 2.6 KiB of static class metadata for the 6 MiB arena. Measured release
artifacts are 53,248 bytes (x86-64) and 48,128 bytes (AArch64). Relative to the
rejected prototype, TLSF changes the rounded EFI sizes by +512 and 0 bytes,
respectively, while reducing project-authored unsafe tokens from 67 to 40.

Host tests cover 64-byte alignment, split/coalesce reuse, and atomic oversized
failure. Dual-QEMU acceptance additionally checks a bounded live failure probe,
full counters, and exact heap-use stability across repeated pipeline and RAMFS
create/delete workloads. Revisit TLSF parameters when SMP, multiple arenas, or
measured fragmentation requires it.

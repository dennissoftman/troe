# Unsafe inventory

Stage 2 contains exactly 40 project-authored Rust `unsafe` tokens, all in
`crates/kllm-machine/src/mechanism.rs`. The verification gate fails if this
count changes without a same-change inventory review. Portable crates and the
kernel composition root continue to forbid unsafe code.

| Boundary | Tokens | Invariant |
|---|---:|---|
| TLSF pool and hybrid global allocator | 16 | One fresh, page-aligned LoaderData range is transferred once; a spin lock serializes metadata; `GlobalAlloc` layouts match; non-heap loader pointers are never returned through exited firmware. |
| x86-64 16550 and `hlt` | 10 | The pinned q35 profile owns COM1 at `0x3f8`; byte I/O uses readiness bits and bounded transmit polling; halt is terminal. |
| AArch64 PL011 and `wfe` | 10 | The pinned virt profile owns PL011 at `0x09000000`; aligned volatile accesses target documented registers; transmit polling is bounded; park is terminal. |
| Heap host tests | 4 | Test arenas remain live, exclusively borrowed, and allocations are deallocated once with their original layouts. |

The UEFI ExitBootServices call is inside the same mechanism file. Its sole call
site has ended protocol borrows, installed native console/fatal output and the
owned heap, and never invokes boot services afterward. The retained final-map
buffer is deliberately leaked as a mapped LoaderData reservation.

Transitive unsafe implementation also exists in pinned `uefi`, `rlsf`, and
their bindings/dependencies. Their APIs, licenses, and boundary assumptions are
recorded in `THIRD_PARTY.md`; this inventory is an engineering audit, not a
formal proof.

# Unsafe inventory

Stage 5.1 contains exactly 87 project-authored Rust `unsafe` tokens, all in the
two audited modules of `crates/kllm-machine`. The verification gate fails if
this count changes without a same-change inventory review. Portable crates and
the kernel composition root continue to forbid unsafe code.

| Boundary | Tokens | Invariant |
|---|---:|---|
| TLSF pool and hybrid global allocator | 16 | One fresh, page-aligned LoaderData range is transferred once; a spin lock serializes metadata; `GlobalAlloc` layouts match; non-heap loader pointers are never returned through exited firmware. |
| Owned-stack and interrupt transition | 8 | A checked, reserved stack receives one leaked continuation record; architecture trampolines replace SP/RSP once and cannot return; x86 IF and AArch64 DAIF are masked before firmware exception state is replaced. |
| Cooperative task-stack calls | 4 | One unique call record and task state borrow remain live while an architecture trampoline replaces SP/RSP synchronously; the old stack is saved inside the mapped task payload and restored before Rust resumes. |
| Owned framebuffer writes | 1 | GOP scalar metadata is checked before handoff; page-rounded bytes are allocator-reserved and mapped RW/NX as device memory; checked pixel offsets precede each volatile byte write. |
| x86-64 16550, i8042, and `hlt` | 12 | The pinned q35 profile owns COM1 at `0x3f8` and the PS/2 controller at `0x60`/`0x64`; byte I/O checks readiness/status bits, ignores auxiliary-device data, and bounds transmit polling; halt is terminal. |
| AArch64 PL011 and `wfe` | 10 | The pinned virt profile owns PL011 at `0x09000000`; aligned volatile accesses target documented registers; transmit polling is bounded; park is terminal. |
| Heap host tests | 4 | Test arenas remain live, exclusively borrowed, and allocations are deallocated once with their original layouts. |
| Loaded PE view and terminal acceptance probes | 6 | Checked protocol metadata proves every raw-slice bound; feature-only probes target validated mappings or raise one native exception and never return. |
| Page-table arena and native entries | 9 | One reserved, identity-mapped 2 MiB arena is exclusively zeroed and filled before activation; every table and leaf pointer is page/index checked; mapping-plan validation excludes overlap and W+X. |
| x86-64 MMU controls and fault vectors | 12 | CPUID proves NX and the physical width; EFER.NXE and CR0.WP enforce permissions; fixed GDT selectors, a TSS/IST emergency stack, and all exception gates are installed before CR3 receives the owned root. |
| AArch64 MMU controls and fault vectors | 5 | EL1, PARange, and 4 KiB granule support are verified; TCR.IPS matches accepted table/leaf addresses; the complete VBAR table receives every exception class. |

The UEFI ExitBootServices call is inside the mechanism module. Its sole call
site has ended protocol borrows, installed native console/fatal output and the
owned heap, and transferred to a reserved 128 KiB stack. The successful call
enters a non-returning continuation, masks interrupts, and never invokes boot
services afterward. The retained final-map buffer lives inside mapped owned
memory. Stage 3 then replaces firmware translation and exception state before
entering the task scheduler; table, kernel-stack, and guarded task-stack pool
arenas are permanent LoaderData reservations. Task payload slots are returned
to the bounded pool when a record is reaped; their surrounding pages remain
unmapped under the owned page tables.

Transitive unsafe implementation also exists in pinned `uefi`, `rlsf`, and
their bindings/dependencies. Their APIs, licenses, and boundary assumptions are
recorded in `THIRD_PARTY.md`; this inventory is an engineering audit, not a
formal proof.

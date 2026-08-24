# Unsafe inventory

The current kernel contains exactly 226 project-authored Rust `unsafe` tokens,
all in the four audited modules of `crates/troe-machine`. The verification gate
fails if this count changes without a same-change inventory review. Portable
crates and the kernel composition root continue to forbid unsafe code.

| Boundary | Tokens | Invariant |
|---|---:|---|
| TLSF pool and hybrid global allocator | 16 | One fresh, page-aligned LoaderData range is transferred once; a spin lock serializes metadata; `GlobalAlloc` layouts match; non-heap loader pointers are never returned through exited firmware. |
| Owned-stack and interrupt transition | 8 | A checked, reserved stack receives one leaked continuation record; architecture trampolines replace SP/RSP once and cannot return; x86 IF and AArch64 DAIF are masked before firmware exception state is replaced. |
| Cooperative task-stack calls | 4 | One unique call record and task state borrow remain live while an architecture trampoline replaces SP/RSP synchronously; the old stack is saved inside the mapped task payload and restored before Rust resumes. |
| Owned framebuffer writes | 1 | GOP scalar metadata is checked before handoff; page-rounded bytes are allocator-reserved and mapped RW/NX as device memory; checked pixel offsets precede each volatile byte write. |
| Bounded input-queue synchronization | 11 | The boot CPU initializes one preallocated queue before IRQ enablement; the current single-CPU profile masks owned IRQ delivery around main-context access, while interrupt gates enter masked, so the audited `UnsafeCell` never yields overlapping mutable references. Application IRQ dispatch and nonblocking cooperative cancellation use the same unique queue access. |
| Architecture monotonic counters | 2 | The pinned single-vCPU x86-64 profile reads its invariant TSC only after CPUID supplies a nonzero frequency; AArch64 reads the architected physical counter and frequency at EL1. Checked scaling produces boot-relative milliseconds and runtime state clamps observations against regression. |
| x86-64 APIC input/timer delivery and entry | 25 | Mapped LAPIC/I/O APIC registers and owned PIC/UART/PIT ports are accessed only from the pinned q35 profile; PIT channel 2 calibrates a masked local-APIC one-shot before the 50 ms lease is armed; explicit IDT gates preserve interrupted integer and floating-point state; `sti; hlt; cli` closes the empty-check sleep race. |
| AArch64 GICv2 input/timer delivery and entry | 24 | The pinned `virt` GICv2 aperture is mapped RW/NX as device memory; distributor/CPU-interface operations are bounded by `GICD_TYPER`; PPI 30 carries the checked generic physical-timer deadline; the IRQ vector preserves all general and SIMD state; IRQ-masked `dsb; wfi` closes the pre-sleep handler race before pending dispatch returns to masked queue access. |
| x86-64 16550, i8042, and `hlt` | 12 | The pinned q35 profile owns COM1 at `0x3f8` and the PS/2 controller at `0x60`/`0x64`; byte I/O checks readiness/status bits, ignores auxiliary-device data, and bounds transmit polling; halt is terminal. |
| AArch64 PL011 and `wfe` | 10 | The pinned virt profile owns PL011 at `0x09000000`; aligned volatile accesses target documented registers; transmit polling is bounded; park is terminal. |
| AArch64 virtio-MMIO block/network DMA | 9 | The pinned `virt` aperture is mapped RW/NX before register access; page-aligned live allocations retain split queues and fixed buffers; descriptor payload addresses name exclusively borrowed or owned identity-mapped heap memory; outer-shareable barriers order publication and completion; bounded timeouts return only after confirmed reset, while failed reset parks forever so DMA cannot outlive Rust storage. |
| x86-64 q35 virtio PCI block/network DMA | 15 | Bounded mechanism-1 configuration access scans bus zero only; capability loops, duplicates, BAR types/sizes, and offsets fail closed; BAR probing disables decode and restores configuration exactly; only validated capability pages are mapped RW/NX; bus mastering starts after mapping; page-aligned split queues, fixed network buffers, and confirmed-reset timeout rules keep DMA inside Rust lifetimes. |
| Heap host tests | 4 | Test arenas remain live, exclusively borrowed, and allocations are deallocated once with their original layouts. |
| Loaded PE view and terminal acceptance probes | 6 | Checked protocol metadata proves every raw-slice bound; feature-only probes target validated mappings or raise one native exception and never return. |
| Page-table arena and native entries | 9 | One reserved, identity-mapped 2 MiB arena is exclusively zeroed and filled before activation; every table and leaf pointer is page/index checked; mapping-plan validation rejects virtual overlap, unsafe physical aliases, and W+X. |
| x86-64 MMU controls and fault vectors | 14 | CPUID proves NX, the physical width, SMEP, and SMAP; EFER.NXE, CR0.WP, and supported supervisor protections enforce permissions; fixed GDT selectors, a TSS/IST emergency stack, and all exception gates are installed before CR3 receives the owned root. |
| AArch64 MMU controls and fault vectors | 5 | EL1, PARange, and 4 KiB granule support are verified; TCR.IPS matches accepted table/leaf addresses; the complete VBAR table receives every exception class. |
| Isolated physical-page lifecycle | 2 | Checked identity-mapped ranges are zeroed before user exposure and before atomic frame return; initialized code/data copies prove complete non-overlapping bounds first. |
| Isolated run state and copied-user access | 21 | One single-CPU active flag grants unique access to a synchronous raw-pointer record; the record distinguishes the internal Stage 6 probe gate from ABI 1.0 execution and retains at most one bounded context/call pair. Entry and message ranges are validated completely before physical translation; suspended task pages remain allocated and identity-mapped only to the supervisor; invalid calls copy no bytes and successful replies are checked before any copy-out. |
| x86-64 ring-3 mappings and entries | 15 | Every user leaf and traversal level carries U/S while supervisor leaves do not; DPL-3 gates and TSS RSP0 enter the kernel; application entry resets visible GPR/SSE/x87 state, and the syscall gate captures a compile-time-checked 672-byte full context for leased resume; all kernel callee-saved state survives root switches; faults and timer expiry return only through the saved kernel context. |
| AArch64 EL0 mappings and entries | 13 | AP, PXN, and UXN distinguish EL0 code/data from EL1 mappings; application entry resets visible GPR/SIMD/FP/thread state, and the lower-EL gate captures a compile-time-checked 816-byte full context for leased resume; LDTRB honors user access under PAN; all kernel AAPCS64 state survives TTBR0 replacement. |

The UEFI ExitBootServices call is inside the mechanism module. Its sole call
site has ended protocol borrows, installed native console/fatal output and the
owned heap, and transferred to a reserved 128 KiB stack. The successful call
enters a non-returning continuation, masks interrupts, and never invokes boot
services afterward. The retained final-map buffer lives inside mapped owned
memory. Stage 3 then replaces firmware translation and exception state before
entering the task scheduler. The kernel table, kernel-stack, and cooperative
guarded-stack arenas are permanent LoaderData reservations. Stage 6 task roots
and private pages instead come from the frame bitmap, are zeroed on both
ownership transitions, and are returned only after handle revocation and
record reaping.

Transitive unsafe implementation also exists in pinned `uefi`, `rlsf`, and
their bindings/dependencies. Their APIs, licenses, and boundary assumptions are
recorded in `THIRD_PARTY.md`; this inventory is an engineering audit, not a
formal proof.

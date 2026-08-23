# Architecture-specific implementation notes

This page records machine details that are easy to erase accidentally during a
portable refactor. These are current implementation invariants, not generic
driver policy. Any change to interrupt entry, idle waiting, controller setup,
or the pinned QEMU profiles must review this page, ADR 0013, ADR 0014, the unsafe
inventory, and both exhaustive QEMU suites together.

## Shared ordering rules

- Allocate and initialize the complete raw-input queue before enabling a device
  source, controller route, or CPU interrupt class.
- Map controller and UART apertures RW/NX as device memory before the first
  volatile access. Never alias an aperture through a normal-memory mapping.
- An ISR may drain at most the selected profile budget. It must acknowledge the
  device/controller even if the drop-newest queue is full.
- Decode UTF-8, ANSI, and scan codes only after main context removes a raw event.
- Main-context queue access occurs with the owned IRQ class masked. The current
  synchronization proof is single-CPU and must be replaced before SMP.
- Bootstrap and terminal fatal output may poll. Normal post-initialization shell
  input must use the interrupt queue.
- Isolated execution remains single-CPU and synchronous. Interrupts are masked,
  exactly one native active-state record may exist, and the kernel root must be
  restored with stale translations invalidated before Rust regains control.
- Validate user entry, stack, and complete message ranges against retained user
  mapping metadata. Invalid calls must not copy a prefix. Never expose device
  mappings or a writable/executable physical alias at user privilege.

## x86-64 q35

- Mask both legacy 8259 PICs before enabling LAPIC/I/O APIC routing. Leaving a
  firmware PIC route live can deliver an unexpected legacy vector into the
  owned IDT.
- Read the I/O APIC version and bound redirection-table initialization by its
  reported maximum entry. Route q35 IRQ1 (i8042) and IRQ4 (COM1) to explicit
  non-exception vectors targeting the BSP LAPIC ID.
- Install the input and spurious IDT gates before setting LAPIC software enable
  or unmasking CPU interrupts. External interrupt gates have no hardware error
  code, so their entry layout must stay distinct from exception entries.
- The common input entry preserves all general registers plus x87/SSE state
  before calling Rust. If Rust gains AVX usage, the save policy must be reviewed;
  `fxsave64` does not preserve extended AVX state.
- Drain the device before writing LAPIC EOI. A normal routed interrupt needs one
  EOI; the LAPIC spurious vector must return without one.
- Keep the empty-queue transition as `sti; hlt; cli`. x86 delays maskable
  interrupt recognition until after the instruction following `sti`, so `hlt`
  cannot sleep after an input IRQ has already run and filled the queue. Splitting
  or reordering those instructions recreates a lost-wakeup window.
- User mappings require U/S on every traversal entry and terminal PTE; sibling
  supervisor leaves remain protected by their terminal U/S bit. The DPL-3
  `int 0x80` gate is the only current user entry and terminates the continuation.
- TSS RSP0 and the user code/data descriptors must be installed before ring-3
  entry. The boundary preserves callee-saved GPRs and the full FXSAVE area,
  restores CR3 and kernel RFLAGS before returning, clears DF on every user
  exception entry, and never converts a kernel-originated exception into a
  contained task fault. Firmware `SYSCALL`, `SYSENTER`, FSGSBASE, and protection
  key entry state is disabled before userspace exists. CPUID-supported SMEP and
  SMAP are enabled; AC is cleared on entry and raised only around each validated
  copied-message load. Inherited five-level paging, CET, or supervisor
  protection-key state is rejected before descriptor/page-table replacement
  because this backend does not yet own those modes.

## AArch64 QEMU `virt`

- Keep the machine profile pinned to GICv2 while using the memory-mapped
  distributor and CPU interface implemented here. GICv3 system-register setup
  is a different driver path, not a transparent version bump.
- Bound all implemented-interrupt register loops by `GICD_TYPER`; never assume a
  fixed distributor entry count.
- The current UEFI handoff runs at EL1 in a security state where PL011 INTID 33
  must be visible to the enabled GICv2 group. Clear its `GICD_IGROUPR` bit for
  the current Group 0 path. In a non-secure alias view that write can be ignored,
  leaving the corresponding Group 1 route; changing firmware security state
  therefore requires an explicit group/CPU-interface review.
- Configure PL011 as level-triggered, clear only its serviced RX/timeout latch,
  then drain its FIFO under the selected ISR budget. This order ensures a byte
  arriving during the drain remains observable through that drain or a fresh
  interrupt. Return the original non-spurious IAR value to EOIR; do not EOI IDs
  1020 through 1023.
- The IRQ vector preserves x0-x30, FPCR/FPSR, and q0-q31 before calling Rust and
  restores them before `eret`. All four architectural IRQ slots branch to that
  entry; synchronous, FIQ, and SError slots remain fatal in this profile.
- Do not unmask IRQ and then execute `wfi`. An IRQ can be taken in between, the
  handler can fill the queue, and execution can resume at `wfi` with no pending
  wake source. The safe sequence keeps PSTATE.I set, executes `dsb sy; wfi`,
  briefly unmasks after wake so the pending GIC interrupt is dispatched, then
  masks again before checking the queue. GICC_PMR must leave the input priority
  eligible as a wake source.
- EL0 mappings use AP plus distinct PXN/UXN policy: kernel pages are EL0
  inaccessible and UXN, user code is EL0 RO/X and PXN, and user data/stack are
  EL0 RW/NX and PXN. The lower-EL synchronous vector is separate from current-EL
  fatal handling.
- The copied-message path uses `LDTRB` so its source access keeps unprivileged
  semantics even when PAN is active. The entry/return boundary preserves
  x19-x30, q8-q15, FPCR, FPSR, DAIF, SP_EL0, and TPIDR_EL0, restores TTBR0_EL1,
  and completes a global TLB invalidation before returning to Rust.

## Regression evidence

The smoke suite proves initial interrupt delivery, positive idle/wakeup
accounting, zero ordinary-input drops, framebuffer mirroring, x86 native
keyboard input, and the complete contained-isolation fault/reclaim matrix. The
exhaustive suite is also required: its long paced serial workload has caught an
AArch64 unmask-before-`wfi` race that short boots did not reproduce. Fault, W^X,
stack-guard, fatal-console, and non-reboot assertions must remain enabled
because interrupt entry shares exception state with them.

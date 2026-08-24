# Architecture-specific implementation notes

This page records machine details that are easy to erase accidentally during a
portable refactor. These are current implementation invariants, not generic
driver policy. Any change to interrupt entry, idle waiting, controller setup,
or a current machine profile must review this page, ADR 0013, ADR 0014, ADR
0016, the unsafe inventory, and both exhaustive QEMU suites together. The q35
and `virt` sections describe implemented test profiles; they are not generic
x86-64 or AArch64 platform contracts.

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

## x86-64 q35 test profile

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
- The q35 storage profile scans only bus zero through PCI configuration
  mechanism 1. It accepts modern virtio block functions, bounds and de-loops the
  capability chain, probes referenced memory BAR sizes with decode disabled,
  restores every BAR/command field exactly, and maps only page-rounded
  common/notify/ISR/device capability spans. The polling queue masks MSI-X and
  uses bus-master DMA only after owned mappings are active.
- The same bounded q35 scanner recognizes modern virtio-net functions. The
  initial NIC profile owns one eight-entry RX queue and one TX queue, publishes
  only one fixed complete-frame buffer per queue, uses the 12-byte modern v1
  header, and negotiates no offload, mergeable-buffer, control, or multiqueue
  features. Its receive queue permits used-buffer notification through the
  validated PCI interrupt pin/line, routed active-low and level-triggered to a
  dedicated IDT vector. The ISR capability read deasserts INTx and only sets a
  coalesced service-work bit. AArch64 applies the identical queue contract
  through modern virtio-MMIO with outer-shareable DMA barriers.
- Terminal machine control is profile-owned: `poweroff` writes the q35 ICH9
  PM1 control register at `0x604` with SLP_EN set for its S5 type, while
  `reboot` requests a full reset through q35 reset control at `0xcf9`. These
  constants are not a generic x86-64 hardware contract; a physical PC profile
  must derive equivalent resources from validated ACPI data.
- Keep the empty-queue transition as `sti; hlt; cli`. x86 delays maskable
  interrupt recognition until after the instruction following `sti`, so `hlt`
  cannot sleep after an input IRQ has already run and filled the queue. Splitting
  or reordering those instructions recreates a lost-wakeup window.
- User mappings require U/S on every traversal entry and terminal PTE; sibling
  supervisor leaves remain protected by their terminal U/S bit. The DPL-3
  `int 0x80` gate is the ABI entry. Exit terminates the continuation; yield and
  handle calls capture a compile-time-checked 672-byte GPR/FXSAVE/return frame
  that only the scheduler-controlled leased resume path can consume.
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

## AArch64 QEMU `virt` test profile

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
  fatal handling. SVC entry captures a compile-time-checked 816-byte
  x0-x30/q0-q31/control/return frame for yield and handle-call resume.
- The copied-message path uses `LDTRB` so its source access keeps unprivileged
  semantics even when PAN is active. The entry/return boundary preserves
  x19-x30, q8-q15, FPCR, FPSR, DAIF, SP_EL0, and TPIDR_EL0, restores TTBR0_EL1,
  and completes a global TLB invalidation before returning to Rust.
- The profile maps all 32 documented virtio-MMIO slots as one RW/NX device
  aperture, then probes only modern magic/version/device identifiers. Block
  devices negotiate `VERSION_1` plus the small understood feature subset and
  use request queue zero with an eight-entry split ring and one request in
  flight. Queue/header/status memory remains page-aligned, identity-mapped, and
  live for the complete device lifetime. `dmb oshst` precedes notification and
  `dmb oshld` follows used-index observation. A timed-out request resets and
  confirms the device before returning; failure to confirm reset parks forever
  because returning could let DMA outlive the borrowed payload.
- A virtio-net slot derives its QEMU `virt` SPI from the fixed slot-to-INTID
  profile, validates it against `GICD_TYPER`, and enables it as a level source.
  The IRQ path acknowledges only the MMIO status and coalesces cooperative
  service work. Empty receive checks are constant-time and never spin.
- The pinned QEMU `virt` command explicitly disables legacy virtio-MMIO. Its
  secondary read-only fixture contains deterministic primary/backup GPT copies
  and a constrained ext4 volume; acceptance reaches that volume only through
  the BMNT disk GUID, partition GUID, and filesystem UUID tuple.
- The profile advertises PSCI 1.0 with the HVC conduit. Terminal `poweroff` and
  `reboot` therefore issue `SYSTEM_OFF` and `SYSTEM_RESET`; an unexpected PSCI
  return falls back to the terminal CPU park path.
- Polling block completion suppresses used interrupts and acknowledges any
  observed transport status. GIC initialization keeps unrelated virtio SPIs
  masked; the network profile explicitly enables its one completion SPI. A
  later interrupt-driven block profile must add explicit routing, ISR budgets,
  and teardown synchronization rather than reusing the network path implicitly.
- Suspended application handle calls translate only previously validated user
  ranges to retained task-owned physical pages. The supervisor kernel root
  identity-maps those allocated pages for the bounded request and reply copies;
  the EL0 root is inactive and cannot race the copy.

## Stage 7.5 platform separation

New machine support must separate reusable CPU mechanisms, device drivers, and
board integration. `cfg(target_arch)` selects instruction-set mechanisms; it
must not silently select q35, QEMU `virt`, Raspberry Pi, or any other board.
Each platform profile supplies or validates its own firmware contract, device
resources, interrupt topology, timer, console, boot media, and power behavior.

The planned Raspberry Pi 4 profile is the first common AArch64 hardware
acceptance machine. It does not replace the generic AArch64/UEFI direction and
does not make Raspberry Pi peripherals architectural requirements. Likewise,
q35 remains one x86-64 emulator profile rather than a PC compatibility promise.
Where firmware can describe resources through ACPI, device tree, or UEFI,
bring-up must validate those descriptions before constructing typed resources;
fixed constants belong only in an explicitly identified board profile.

See [ADR 0016](adr/0016-hardware-targets-and-emulator-role.md) for the profile
boundary and hardware acceptance policy.

## Regression evidence

The smoke suite proves initial interrupt delivery, positive idle/wakeup
accounting, zero ordinary-input drops, framebuffer mirroring, x86 native
keyboard input, and the complete contained-isolation fault/reclaim matrix. The
exhaustive suite is also required: its long paced serial workload has caught an
AArch64 unmask-before-`wfi` race that short boots did not reproduce. Fault, W^X,
stack-guard, fatal-console, and non-reboot assertions must remain enabled
because interrupt entry shares exception state with them.

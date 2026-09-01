# ADR 0063: the SBSA reference machine replaces QEMU `virt` on AArch64

Status: accepted and implemented, 2026-09-01. Replaces the pinned
`aarch64-virt-uefi` platform named in
[ADR 0016](0016-hardware-targets-and-emulator-role.md). The discoverable
device-tree platform `aarch64-uefi-virtio-mmio` is unaffected.

## Context

x86-64 inherited a contract from the PC: a machine can be assumed to have an
APIC, an 8254, a 16550, and PCI at known places, and firmware fills in the
rest. That inheritance is why `x86_64-q35-uefi` is a fair stand-in for a real
machine. AArch64 has no such inheritance, and QEMU's `virt` board is not one
either — it is a board QEMU invented, with a memory map QEMU chose.

Pinning `virt` therefore bought a green gate that answered a question nobody
asks. Nothing about booting `virt` says whether the same image would boot on an
Arm laptop or server, because the two agree on almost nothing below UEFI.

The closest thing AArch64 does have is Arm's Server Base System Architecture
and the SystemReady certifications built on it: a `GICv3` or later, the
architected generic timer, a PL011-compatible generic UART, PSCI, and PCI
Express, discovered through ACPI. QEMU ships `sbsa-ref`, a machine built to
that contract rather than to QEMU's convenience, and it boots the same way real
hardware does — Trusted Firmware at EL3, then edk2 as its non-secure payload.

## Decision

Replace `aarch64-virt-uefi` with `aarch64-sbsa-ref`, keeping its platform
identity 2 and its `fixed` discovery source. Keep virtio as the device model.

### Virtio arrives over PCI Express

SBSA describes no virtio-MMIO aperture, so the transport moves to PCI. This is
not a retreat from virtio: the same modern virtio block and network devices are
driven, over the transport the platform actually offers.

The interrupt model is what differs, and it differs enough to be its own
descriptor variant rather than a flag on the existing one. On x86-64 a
function's platform interrupt is named in its configuration Interrupt Line
byte. On Arm that byte means nothing; the pin reaches one of four consecutive
shared peripheral interrupts through the standard swizzle. A separate
`VirtioTransportKind::PciGic` makes every site that resolves an interrupt fail
to compile until it handles both, which is how the two models were kept from
being silently confused.

### The kernel descends from EL2 to EL1

Firmware built on Trusted Firmware hands its payload EL2, not the EL1 that
`virt` hands an EFI application. Every `*_EL1` register the kernel programs
would otherwise be the wrong register. The kernel therefore descends once, on
the boot CPU, immediately after taking interrupt ownership.

The descent keeps translation enabled across the transition, handing EL1 the
firmware's own live mapping rather than disabling the MMU and re-enabling it
later. Turning it off between two cacheable mappings would strand dirty lines
that the following accesses could not see, and recovering from that needs a
full cache maintenance pass that buys nothing here.

Three EL2 settings are corrected on the way down, each of which is silent when
missed. `HCR_EL2` is written absolutely rather than merged, because firmware
that never intends to run an EL1 sets `TGE` — which makes the exception return
itself illegal — along with `FMO`, `IMO`, and `AMO`, which would hold
interrupts at an EL2 the kernel has left. `CPACR_EL1` is opened for SIMD before
the return, because the compiler is free to emit a SIMD instruction as the
first thing that runs at EL1 and the register still holds its trapping reset
value. `TCR_EL2` is translated field by field into the `TCR_EL1` layout,
including the large-address bit that a 52-bit firmware map depends on.

### PSCI reaches EL3 through SMC

The conduit is a property of the platform, not of the architecture. With PSCI
in a Trusted Firmware EL3 runtime, a hypervisor call from EL1 reaches an EL2
with nothing to answer it, so `PowerKind` gains an SMC conduit beside the HVC
one that `virt` needs.

### The boot volume arrives on AHCI

The reference firmware carries no virtio driver, so it cannot read a virtio
boot volume. The volume is presented on the machine's own AHCI controller
instead, which is also how a real machine works: firmware boots from the
platform's own storage, and the operating system then brings its own drivers.
Everything the kernel drives itself stays on virtio.

## Consequences

The gate now exercises a machine whose contract is published and certified
against, so a green AArch64 run means something about hardware outside QEMU.

The firmware is the cost. No distribution packages a Trusted Firmware and edk2
pair for this machine, so `tools/build_sbsa_firmware.py` builds both banks from
commits pinned in `tools/sbsa-firmware-sources.lock.json`. That is a heavier
dependency than the `AAVMF` package `virt` needed: LLVM with `lld`, a GNU make
newer than the one macOS ships, OpenSSL headers, and ACPICA.

Only the submodules the platform actually needs are fetched, which is six of
edk2's thirteen and about half the checkout. The set is not only what gets
compiled: a package description declares its include directories and the build
rejects one that is absent, so a tree nothing includes from still has to be on
disk. That is why `libspdm` is fetched for a platform that never links it.

The machine must be given a CPU implementing `FEAT_RNG`: the reference firmware
draws its entropy from it, and the kernel reads the UEFI protocol that depends
on it before boot services end.

Discovery is still `fixed`. Pinning the reference memory map is a smaller lie
than pinning `virt`'s, because the reference map is the one SystemReady
machines are built against, but it is still a pinned map. Moving this platform
to ACPI discovery — MADT `GICC`/`GICD`/`GICR`, GTDT, SPCR, and MCFG — is what
would let one image boot an arbitrary SystemReady machine, and it is the
natural successor to this decision.

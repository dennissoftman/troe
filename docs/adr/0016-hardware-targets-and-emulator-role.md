# ADR 0016: hardware targets and the emulator role

Status: accepted, 2026-08-24.

## Context

TROE currently boots native x86-64 and AArch64 UEFI images under pinned QEMU
q35 and `virt` configurations. Those profiles are valuable: they are fast,
repeatable, scriptable, and capable of destructive fault testing that should
not run on a developer's workstation or an unattended board.

The implementation also embeds platform facts near architecture mechanisms:
q35 I/O APIC routes and legacy ports on x86-64, and QEMU `virt` GICv2, PL011,
and timer choices on AArch64. That is acceptable evidence for the implemented
profiles but not a compatibility definition. A CPU architecture does not imply
one board, interrupt controller, UART address, firmware, storage device, or
power controller. Adding more QEMU-only devices would deepen the wrong
boundary and make physical-machine support harder.

## Decision

### Separate architecture, platform, and environment

TROE treats these as independent axes:

- an **architecture** implementation owns CPU feature validation, privilege
  transition, MMU/page-table encoding, exception entry, cache/TLB operations,
  context switching, and architecture timer primitives;
- a **platform profile** owns the firmware contract, hardware description,
  memory discovery, interrupt topology, timer selection, UART, buses, boot
  media, framebuffer/input integration, and halt/reboot mechanisms; and
- an **execution environment** says whether that platform runs in QEMU, another
  virtual machine, or physical hardware.

An architecture build flag must not silently select a board. Platform resources
are constructed from a named, validated profile or from bounded ACPI, device
tree, and UEFI discovery. Fixed addresses and interrupt IDs are permitted only
inside an explicitly identified profile when the hardware contract requires
them. Portable crates receive typed capabilities and remain unaware of boards.

The intended source boundary is conceptually:

```text
portable policy -> typed machine capabilities
                         ^
reusable driver -> platform profile/discovery -> architecture mechanisms
```

This does not require premature trait abstraction. A boundary may begin as
modules and checked data when there is only one implementation, but q35 or
`virt` constants may not be presented as architecture constants.

### Keep QEMU as a test backend

The implemented `x86_64-q35-uefi` and `aarch64-virt-uefi` profiles remain
pinned acceptance targets. Host tests cover portable state spaces, QEMU covers
full boot and destructive fault injection, and physical hardware covers real
firmware, memory maps, buses, interrupt delivery, clocks, devices, and boot
media. Hardware smoke tests complement rather than replace the exhaustive host
and QEMU gates.

Support for another VM or emulator is a separately named profile. It may share
discoverable standards and drivers, but compatibility is not inferred from
QEMU success.

### Add representative physical profiles without defining architectures by them

The first planned AArch64 physical profile is `aarch64-rpi4-uefi`, using a
Raspberry Pi 4 as a common, obtainable bring-up and regression machine. The
accepted profile must pin the board revision, firmware build and configuration,
serial wiring/settings, boot medium, memory limits, and required peripherals.
Raspberry Pi is not the AArch64 platform definition: server-class UEFI/ACPI
machines, other SBCs, and future boards remain independent profiles.

The first x86-64 physical profile is `x86_64-pc-uefi`. Stage 7.5 must replace
that family name with an exact tested machine/firmware record before claiming
hardware acceptance. It should use validated UEFI/ACPI/PCI discovery where
available and document a serial or other dependable recovery console. q35
behavior is not assumed on the physical PC.

The production kernel composition and safety invariants remain shared. Target
profiles may select different drivers and produce different boot artifacts;
binary identity across unrelated boards is not required.

### Make boot and test artifacts hardware-usable

The small deterministic FAT image remains a useful emulator artifact. Physical
bring-up adds a deterministic GPT disk image with an EFI System Partition that
can be written to bounded USB or SD media. Media-writing tools must require an
explicit destination, validate its size and identity, and never run as an
implicit build or test step.

A hardware smoke run records:

- target profile, board model/revision, firmware version/configuration, and
  relevant attached devices;
- TROE revision and image digest;
- bounded serial transcript and timeout results; and
- at minimum, bootstrap, firmware exit, owned mappings/vectors, timer and
  interrupt initialization, recovery-shell input/output, memory reporting, and
  controlled halt or reboot behavior.

Destructive permission-fault, invalid-opcode, and fatal-state matrices remain
in QEMU unless a dedicated recoverable hardware rig explicitly opts in.

## Consequences

- Machine code needs a deliberate split before adding substantial storage,
  networking, USB, or board-specific support.
- Some existing q35 and `virt` constants will move rather than disappear; their
  scope becomes honest and testable.
- Hardware CI is slower and may initially be a documented lab or manual release
  gate, while QEMU remains the per-change deterministic gate.
- A new AArch64 board does not need to imitate Raspberry Pi, and Raspberry Pi
  support does not require unrelated AArch64 builds to carry its drivers.
- A new emulator does not become supported merely because it resembles an
  existing profile.

## Rejected alternatives

- **Treat QEMU `virt` and q35 as the architecture contracts.** This makes real
  machines special cases and spreads emulator-specific assumptions.
- **Replace QEMU tests with hardware tests.** This loses deterministic fault
  injection, parallelism, and fast feedback.
- **Call Raspberry Pi the AArch64 target.** One accessible board is useful
  evidence but cannot represent the architecture's firmware and device space.
- **Promise a universal PC or SBC image immediately.** Discovery and reusable
  drivers can grow toward broader compatibility only after exact reference
  profiles make current claims reproducible.

## Revisit when

Revisit the selected physical references when they become unobtainable, their
firmware is unsupported, or a different board materially reduces test or driver
complexity. Revisit the UEFI-first boot contract if a valuable deployment class
requires direct firmware or device-tree entry, but retain named profiles and the
architecture/platform separation.

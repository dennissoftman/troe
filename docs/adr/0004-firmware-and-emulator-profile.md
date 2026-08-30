# ADR 0004: firmware-hosted machine profile

Status: accepted, 2026-08-22.

Implementation note, 2026-08-24: `tools/qemu-firmware-profile.json` records the
exact code and variable-store sizes and SHA-256 digests for both architecture
artifacts. Strict release evidence accepts discovery and explicit overrides
only after matching that manifest; a filename or QEMU version match alone is
insufficient.

Compatibility amendment, 2026-08-28: ordinary development and exhaustive merge
verification accept QEMU 8.x through 11.x and matching distribution firmware.
Firmware must be a regular image of at least 256 KiB, be 4-KiB aligned, and
contain a UEFI firmware-volume header. Those runs retain the exact machine
records and guest assertions but are behavioral compatibility evidence, not a
reproduction of the pinned release environment. `--strict-tool-versions`
selects the original QEMU 11.1.0 and exact-digest policy.

Stage 1 targets Rust's `x86_64-unknown-uefi` and `aarch64-unknown-uefi` using
UEFI Simple Text Input/Output and the firmware allocator. The repeatable test
profile is QEMU 11.1.0 with rust-osdev ovmf-prebuilt
`edk2-stable202605-r1`: `q35`, `max` TCG CPU, 128 MiB on x86-64; `virt`, GICv2, plus
`cortex-a72`, 128 MiB on AArch64. Firmware Simple Text I/O is attached to host standard I/O
through the 16550-backed console on x86-64 and the PL011-backed console on
AArch64, with the QEMU monitor disabled. This is firmware console routing, not
direct UART ownership by TROE.

This firmware-hosted behavior remains the historical Stage 1 contract. Stage 2
keeps the same pinned boot profile but uses Simple Text Output only for its
bootstrap banner, then initializes the native UART and exits boot services.
Authorized `poweroff` and `reboot` use profile-owned native control mechanisms.
The image still makes no claim of userspace or hardware isolation.

Revisit exact machine versions only through this ADR and update transcript
goldens at the same time.

Scope note, 2026-08-24: [ADR 0016](0016-hardware-targets-and-emulator-role.md)
retains this exact profile as deterministic historical and regression evidence,
but rejects QEMU devices as the general x86-64 or AArch64 hardware contract.
New VM platforms and execution environments are independently named and
reviewed. Physical-board profiles are outside the current roadmap.

Implementation note, 2026-08-23: Stage 6 explicitly selected QEMU's `max` x86
TCG CPU so acceptance exercises CPUID-reported SMEP/SMAP rather than silently
omitting those supported isolation controls under the legacy default CPU.

# ADR 0004: firmware-hosted machine profile

Status: accepted, 2026-08-22.

Stage 1 targets Rust's `x86_64-unknown-uefi` and `aarch64-unknown-uefi` using
UEFI Simple Text Input/Output and the firmware allocator. The repeatable test
profile is QEMU 11.1.0 with rust-osdev ovmf-prebuilt
`edk2-stable202605-r1`: `q35`, 64 MiB on x86-64; `virt`, GICv2, plus
`cortex-a72`, 128 MiB on AArch64. Firmware Simple Text I/O is attached to host standard I/O
through the 16550-backed console on x86-64 and the PL011-backed console on
AArch64, with the QEMU monitor disabled. This is firmware console routing, not
direct UART ownership by kllm.

This firmware-hosted behavior remains the historical Stage 1 contract. Stage 2
keeps the same pinned boot profile but uses Simple Text Output only for its
bootstrap banner, then initializes the native UART, exits boot services, and
parks the CPU for authorized `halt`. The image still makes no claim of
userspace or hardware isolation.

Revisit exact machine versions only through this ADR and update transcript
goldens at the same time.

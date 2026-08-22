# ADR 0004: firmware-hosted machine profile

Status: accepted, 2026-08-22.

Stage 1 targets Rust's `x86_64-unknown-uefi` and `aarch64-unknown-uefi` using
UEFI Simple Text Input/Output and the firmware allocator. The repeatable test
profile is QEMU 11.1.0 with rust-osdev ovmf-prebuilt
`edk2-stable202605-r1`: `q35`, 64 MiB on x86-64; `virt` plus `cortex-a72`,
128 MiB on AArch64. Firmware Simple Text I/O is attached to host standard I/O
through the 16550-backed console on x86-64 and the PL011-backed console on
AArch64, with the QEMU monitor disabled. This is firmware console routing, not
direct UART ownership by kllm.

The firmware application returns to firmware for authorized `halt`. It does not
claim ownership of the machine or hardware isolation. Direct UART and
ExitBootServices are intentionally coupled to the owned-memory increment rather
than being partially simulated.

Revisit exact machine versions only through this ADR and update transcript
goldens at the same time.

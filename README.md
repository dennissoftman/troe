# Tiny Rust Operating Environment

This project is a tiny Rust operating environment: a bounded command shell, a
small VFS, and just enough machine layer to grow into an owned kernel. The
current slice runs as a normal host program and as native x86-64/AArch64 UEFI
images.

This is pre-isolation software. Built-ins in the firmware image share one
privileged address space, and typed capabilities prevent accidental authority
use rather than providing a hardware security boundary.

## What works now

- stable Rust 1.97.1, edition 2024, `no_std` portable crates;
- deterministic, versioned, bounds-checked KEFS root image;
- quota-bound writable `/tmp` and live `/sys` reporting;
- bounded, checked physical-memory map normalization plus advisory live UEFI
  accounting for Stage 2 ownership;
- single/double quotes and pipelines of up to eight stages;
- 64 KiB bounded intermediate byte streams;
- `cat`, `echo`, literal `grep`, `ls`, `pwd`, `cd`, `help`, `mem`, `clear`,
  `halt`, `write`, `rm`, and `hexdump`;
- deterministic 1.44 MiB FAT12 images for both primary architectures;
- host/unit/smoke gates and prompt-synchronized QEMU acceptance on both
  architectures.

## Quick start

Host model:

```console
cargo run --manifest-path host/Cargo.toml
cargo run --manifest-path host/Cargo.toml -- --command "echo ready | grep ready"
cargo run --manifest-path host/Cargo.toml -- --script tests/smoke.ksh
```

Build both boot images:

```console
python scripts/build.py
```

Artifacts are written under `build/`, and the script reports their exact
filenames. The build regenerates KEFS, uses Cargo's locked dependency graph,
builds release EFI executables, constructs deterministic FAT images, and
enforces the 16 MiB hard ceiling.

Run all local gates:

```console
python scripts/test.py
```

This includes the pinned x86-64 and AArch64 QEMU boot suites. If that exact
QEMU/firmware pair is not installed, run the non-emulator gates explicitly with
`python scripts/test.py --skip-qemu`. Run only the boot suites with
`python scripts/test-qemu.py`; the two architectures run concurrently after
their images have been built. For a quick terminal-focused iteration, use
`python scripts/test-qemu.py --smoke`; the exhaustive suite remains the standard
gate.

Build the x86-64 image and open it in QEMU:

```console
cargo qemu
```

The launcher discovers firmware bundled with QEMU in conventional installation
locations. Select AArch64 with `cargo qemu --architecture aarch64`. If QEMU does
not bundle firmware, provide code and variable-store images from rust-osdev
`ovmf-prebuilt` release `edk2-stable202605-r1` using `--firmware-code` and
`--firmware-vars`.

The launcher and acceptance harness refuse a QEMU version other than 11.1.0 unless
`--skip-version-check` is supplied deliberately. Firmware is not silently
downloaded. Stage 1 uses UEFI Simple Text I/O, routed directly through the
invoking terminal using the firmware's 16550-backed console on x86-64 and its
PL011-backed console on AArch64. Native serial I/O owned by kllm belongs to the
next machine-owned increment.

## Repository map

- `crates`: portable byte streams, memory models, shell, VFS, and accounting
  crates;
- `host`: Stage 0 composition and acceptance runner;
- `kernel`: Stage 1 UEFI machine boundary and console loop;
- `rootfs`, `assets`: source tree and generated KEFS image;
- `tools`: dependency-free deterministic image builders;
- `scripts`: build, verification, and emulator entry points;
- `docs`: ADRs, formats, security notes, and staged design.

The core design is [CORE-SPEC.md](CORE-SPEC.md). The future, currently
unimplemented tooling and package-composition design is
[TOOLING-PACKAGING-SPEC.md](TOOLING-PACKAGING-SPEC.md). The
implementation status and immediate sequence are in
[docs/roadmap.md](docs/roadmap.md).

## Resource profiles

The system has three profiles rather than a continuous ladder of subtly
different defaults: `micro` for MCU-class systems without an MMU assumption,
`tiny` for constrained machines, and `full` for larger systems. They select
capacities and compiled hardware capabilities while preserving the same shell,
stream, VFS, and authority semantics.

## Naming

The public project and CLI names are intentionally unset. Documentation uses
neutral terms and explicit metavariables until naming, trademark, and package
availability checks are complete. Existing repository identifiers and on-disk
magic are provisional implementation/compatibility details, not public naming
contracts.

Licensed under Apache-2.0.

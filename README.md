# kllm

`kllm` is a tiny Rust operating environment: a bounded command shell, a small
VFS, and just enough machine layer to grow into an owned kernel. The current
slice runs as a normal host program and as native x86-64/AArch64 UEFI images.

This is pre-isolation software. Built-ins in the firmware image share one
privileged address space, and typed capabilities prevent accidental authority
use rather than providing a hardware security boundary.

## What works now

- stable Rust 1.97.1, edition 2024, `no_std` portable crates;
- deterministic, versioned, bounds-checked KEFS root image;
- quota-bound writable `/tmp` and live `/sys` reporting;
- single/double quotes and pipelines of up to eight stages;
- 64 KiB bounded intermediate byte streams;
- `cat`, `echo`, literal `grep`, `ls`, `pwd`, `cd`, `help`, `mem`, `clear`,
  `halt`, `write`, `rm`, and `hexdump`;
- deterministic 1.44 MiB FAT12 images for both primary architectures;
- host/unit/smoke plumbing and QEMU launch plumbing.

## Quick start

Host model:

```console
cargo run -p kllm-host
cargo run -p kllm-host -- --command "cat /etc/motd | grep kllm"
cargo run -p kllm-host -- --script tests/smoke.ksh
```

Build both boot images:

```console
python scripts/build.py
```

Artifacts are `build/kllm-x86_64.img` and `build/kllm-aarch64.img`. The build
regenerates KEFS, uses Cargo's locked dependency graph, builds release EFI
executables, constructs deterministic FAT images, and enforces the 16 MiB hard
ceiling.

Run all local gates:

```console
python scripts/test.py
```

Run QEMU 11.1.0 with a code firmware image from rust-osdev
`ovmf-prebuilt` release `edk2-stable202605-r1`:

```console
python scripts/run-qemu.py --architecture x86_64 --firmware-code path/to/x64/code.fd --firmware-vars path/to/x64/vars.fd
python scripts/run-qemu.py --architecture aarch64 --firmware-code path/to/aarch64/code.fd --firmware-vars path/to/aarch64/vars.fd
```

The launcher refuses a different QEMU version unless
`--skip-version-check` is supplied deliberately. QEMU/firmware are not silently
downloaded by repository scripts. Stage 1 uses UEFI Simple Text I/O, so the
interactive shell appears in QEMU's graphical firmware console; native serial
I/O belongs to the next machine-owned increment.

## Repository map

- `crates/kllm-core`: byte streams, statuses, hard limits, accounting types;
- `crates/kllm-vfs`: path normalization, KEFS mount, namespace, RAMFS quotas;
- `crates/kllm-shell`: parser, pipeline executor, static built-ins;
- `host`: Stage 0 composition and acceptance runner;
- `kernel`: Stage 1 UEFI machine boundary and console loop;
- `rootfs`, `assets`: source tree and generated KEFS image;
- `tools`: dependency-free deterministic image builders;
- `scripts`: build, verification, and emulator entry points;
- `docs`: ADRs, formats, security notes, and staged design.

The detailed draft is [KLLM-SPEC.md](KLLM-SPEC.md). The implementation status
and immediate sequence are in [docs/roadmap.md](docs/roadmap.md).

## Resource profiles

kllm has three profiles rather than a continuous ladder of subtly different
defaults: `micro` for MCU-class systems without an MMU assumption, `tiny` for
constrained machines, and `full` for larger systems. They select capacities and
compiled hardware capabilities while preserving the same shell, stream, VFS,
and authority semantics.

## Name

`kllm` is short, visually distinctive, and already embedded in the on-disk
format magic, so it remains the project name for 0.1. Before a public release,
we should do a trademark/package-name search. A possible expansion is
“kernel-like little machine”; the project does not need to force an acronym.

Licensed under Apache-2.0.

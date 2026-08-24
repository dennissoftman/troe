# TROE

TROE (Tiny Rust Operating Environment) is a tiny Rust operating system: a
bounded command shell, a small VFS, and an owned kernel that is growing toward
useful virtual-machine and physical-machine deployments. The current slice runs
as a normal host program and as native x86-64/AArch64 UEFI images.

Statically linked recovery built-ins still share the privileged kernel address
space. Stage 6 additionally runs bounded test tasks in fresh ring-3/EL0 address
spaces; their typed handles, memory faults, and teardown now form a hardware
security boundary. Loadable applications and a public userspace ABI begin in
Stage 7. The bounded KEX v1 parser and native validate/map/reclaim boundary are
implemented. Target-native KEX code enters with reset register state, exits,
yields through scheduler-controlled re-entry, performs owner-checked copied
handle calls, or is terminated by the 50 ms execution lease.

## What works now

- stable Rust 1.97.1, edition 2024, `no_std` portable crates;
- deterministic, versioned, bounds-checked KEFS root image;
- quota-bound writable `/tmp` and live `/sys` reporting;
- final UEFI handoff into a checked frame bitmap, a 6 MiB owned TLSF heap, and
  full live memory accounting;
- architecture-owned 4 KiB page tables with RX text, RO/NX immutable data,
  RW/NX runtime memory, typed device mappings, and native fault vectors;
- bounded cooperative task records, capability-scoped dispatch, deterministic
  yield/exit/reap accounting, and guarded 32 KiB task stacks;
- generation-checked service handles, bounded synchronous request/reply
  messages, and a dispatched native console output path;
- per-task ring-3/EL0 address spaces, copied user messages, contained task
  faults, owner-wide handle revocation, zeroization, and physical-frame reuse;
- allocation-free KEX v1 validation with target, ABI, W^X, canonical-layout,
  entry-point, and per-profile memory-budget checks;
- kernel-owned KEX staging, canonical startup pages, validate-before-map native
  load transactions, explicit initial handles, and zeroized rollback;
- complete ring-3/EL0 ABI 1.0 entry, exit, resumable yield, and owner-checked
  copied handle calls, with owned x86 local-APIC/AArch64 timer leases;
- portable bounded block-region capabilities, strict primary/backup GPT
  discovery, read-only FAT32 and constrained checksummed ext4 VFS providers,
  checksummed SCFG v1 service startup policy, and a checksummed BMNT v1 boot
  mount manifest with deterministic stable-identity resolution;
- a bounded modern virtio block core and native AArch64 `virtio-mmio` transport
  with a QEMU-proven post-handoff read (q35 virtio PCI, mount activation, and
  persistence remain Stage 8 work);
- owned receive interrupts through q35 LAPIC/I/O APIC and AArch64 GICv2,
  bounded raw-event delivery, and race-free `hlt`/`wfi` shell idle;
- project-owned polling 16550 and PL011 early/fatal recovery output, plus an
  owned GOP framebuffer text console on both architectures;
- configurable cursor-aware UTF-8 line editing, volatile bounded history,
  command/VFS completion, ANSI serial-key decoding, and x86-64 PS/2 input;
- single/double quotes and pipelines of up to eight stages;
- 64 KiB bounded intermediate byte streams;
- `cat`, `echo`, literal `grep`, `ls`, `pwd`, `cd`, `man`, `mem`, `clear`,
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
python3 scripts/build.py
```

Artifacts are written under `build/`, and the script reports their exact
filenames. The build regenerates KEFS, uses Cargo's locked dependency graph,
builds release EFI executables, constructs deterministic FAT images, and
enforces the 16 MiB hard ceiling.

Run all local gates:

```console
python3 scripts/test.py
```

This includes the pinned x86-64 and AArch64 QEMU boot suites. If that exact
QEMU/firmware pair is not installed, run the non-emulator gates explicitly with
`python3 scripts/test.py --skip-qemu`. Run only the boot suites with
`python3 scripts/test-qemu.py`; the two architectures run concurrently after
their images have been built. For a quick terminal-focused iteration, use
`python3 scripts/test-qemu.py --smoke`; the exhaustive suite remains the standard
gate.

The FAT32 and ext4 providers include optional real-tool interoperability tests.
On macOS, install their independent image builders/checkers with:

```console
brew install e2fsprogs dosfstools mtools
```

They run automatically when discovered. To make missing tools a test failure,
add `--require-filesystem-tools`; for example:

```console
python3 scripts/test.py --skip-qemu --require-filesystem-tools
```

The tests build temporary images only: dosfstools/mtools create nested FAT32
content and e2fsprogs creates the exact ADR 0017 ext4 profile. The corresponding
host checker must accept each image before TROE mounts, lists, and reads it.

The dependency gate requires exactly `cargo-audit 0.22.1` and checks the full
lockfile against the RustSec database revision committed in
`tools/rustsec-advisory-db.rev`. Install the tool with:

```console
cargo install cargo-audit --version 0.22.1 --locked
```

The exhaustive QEMU gate builds separate `*-acceptance.img` artifacts containing
terminal permission/exception probes. Normal `scripts/build.py` output is a
production image and is rejected if any probe command marker is present.

Build the x86-64 image and open it in QEMU:

```console
cargo qemu
```

Open the owned framebuffer console while retaining serial stdio as the recovery
transport:

```console
cargo qemu --graphical
cargo qemu --architecture aarch64 --graphical
```

The launcher discovers firmware bundled with QEMU in conventional installation
locations. Select AArch64 with `cargo qemu --architecture aarch64`. If QEMU does
not bundle firmware, provide code and variable-store images from rust-osdev
`ovmf-prebuilt` release `edk2-stable202605-r1` using `--firmware-code` and
`--firmware-vars`.

The launcher and acceptance harness refuse a QEMU version other than 11.1.0 unless
`--skip-version-check` is supplied deliberately. Firmware is not silently
downloaded. UEFI Simple Text Output carries only the bootstrap banner. The image
then initializes its native 16550 backend on x86-64 or PL011 backend on
AArch64, copies validated GOP metadata, moves to an explicitly reserved kernel
stack, captures the final map, and exits boot services through a non-returning
continuation. After owned mappings and vectors are active, the shell receives
serial input through the owned interrupt controller and sleeps with `hlt` or
`wfi` when its bounded queue is empty. Normal shell output is mirrored to the
owned framebuffer when GOP is available; early and fatal diagnostics remain
serial-first.

## Repository map

- `crates`: portable byte streams, KEX/config/GPT/FAT parsing, block regions,
  memory models, shell, VFS/provider mounts, terminal/editor, accounting, and
  the isolated native machine mechanism crate;
- `host`: Stage 0 composition and acceptance runner;
- `kernel`: UEFI bootstrap and Stage 7 isolated owned-machine composition root;
- `rootfs`, `assets`: source tree and generated KEFS image;
- `tools`: dependency-free deterministic image builders;
- `scripts`: build, verification, and emulator entry points;
- `docs`: ADRs, formats, security notes, and staged design.

The core design is [CORE-SPEC.md](CORE-SPEC.md). The future, currently
unimplemented tooling and package-composition design is
[TOOLING-PACKAGING-SPEC.md](TOOLING-PACKAGING-SPEC.md). The
implementation status and immediate sequence are in
[docs/roadmap.md](docs/roadmap.md), and [docs/README.md](docs/README.md)
classifies the design records, evaluations, format references, and security
notes by purpose and status.

## Resource profiles

The design defines three future build-time profiles rather than a continuous
ladder of subtly different defaults: `micro` for MCU-class systems without an
MMU assumption, `tiny` for constrained machines, and `full` for larger systems.
The current QEMU images select the named `tiny` configuration in their
composition root; command-line profile selection is not implemented yet. The
terminal/editor, completion, and driver crates expose validated constructors
for line, history-entry, history-byte, escape-sequence, completion-candidate,
completion-byte, text-cell, tab-width, color, keyboard-layout, raw-input queue,
per-interrupt drain, and interrupt-priority policy, so these tunables are not
scattered kernel literals. Future build profiles can replace that selection
while preserving the same shell, stream, VFS, and authority semantics.

## Hardware direction

QEMU remains a pinned, deterministic acceptance environment, but it is not the
hardware contract. Stage 7.5 separates CPU architecture, machine platform, and
execution environment so the kernel can support documented physical machines
without treating QEMU devices as architectural facts. The first planned
AArch64 hardware reference is Raspberry Pi 4, chosen as a common bring-up and
regression machine; it is one board profile among future AArch64 targets, not a
limit on the architecture. A documented UEFI x86-64 PC reference is planned in
the same stage. See the [implementation roadmap](docs/roadmap.md) and
[ADR 0016](docs/adr/0016-hardware-targets-and-emulator-role.md).

## Name

The public project name is **TROE**, expanded as **Tiny Rust Operating
Environment**. Cargo packages, crate directories, Rust identifiers, assembly
symbols, documentation, and test-only volume labels use the `troe`/`TROE`
forms. KEX, KEFS, and SCFG remain product-name-independent wire formats.

Licensed under Apache-2.0.

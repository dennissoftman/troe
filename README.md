# TROE

TROE (Tiny Rust Operating Environment) is a tiny Rust operating system: a
bounded command shell, a small VFS, and an owned kernel that is growing toward
useful cloud virtual-machine deployments. The current slice runs as a normal
host program and as native x86-64/AArch64 UEFI images.

Statically linked recovery built-ins remain available, but ordinary shell names
can now resolve immutable KEX command applications in fresh ring-3/EL0 address
spaces. The repo-local Rust SDK and dual-target builder produce strict KEX v1;
the shell grants versioned cwd/argv and standard-stream handles plus only the
optional capabilities declared by each package. Target-native code enters with
reset register state, exits, yields through scheduler-
controlled re-entry, performs owner-checked copied calls, or is terminated by
the 50 ms execution lease and transactionally reclaimed.

## What works now

- stable Rust 1.97.1, edition 2024, `no_std` portable crates;
- deterministic, versioned, bounds-checked KEFS root image;
- quota-bound writable `/tmp` and live `/sys` reporting;
- final UEFI handoff into a checked frame bitmap, a 6 MiB owned TLSF heap, and
  full live memory accounting;
- architecture-owned 4 KiB page tables with RX text, RO/NX immutable data,
  RW/NX runtime memory, typed device mappings, and native fault vectors;
- bounded cooperative task records, capability-scoped dispatch, deterministic
  yield/exit/reap accounting, and guarded 64 KiB task stacks;
- generation-checked service handles, bounded synchronous request/reply
  messages, and a dispatched native console output path;
- per-task ring-3/EL0 address spaces, copied user messages, contained task
  faults, owner-wide handle revocation, zeroization, and physical-frame reuse;
- allocation-free KEX v1 validation with target, ABI, W^X, canonical-layout,
  entry-point, and standard memory-budget checks;
- kernel-owned KEX staging, canonical startup pages, validate-before-map native
  load transactions, explicit initial handles, and zeroized rollback;
- complete ring-3/EL0 ABI 1.0 entry, exit, resumable yield, and owner-checked
  copied handle calls, with owned x86 local-APIC/AArch64 timer leases;
- exact `/bin/<command>.kex` shell discovery from a target-selected root, external-first
  replaceable commands with static recovery fallback, four bounded command and
  standard-stream services, optional owned datagram and read-only filesystem
  services, a repo-local Rust SDK/skill, and canonical dual-target
  build/check/inspect tooling;
- portable bounded block-region capabilities, strict primary/backup GPT
  discovery, read-only FAT32 and constrained checksummed ext4 VFS providers,
  checksummed SCFG v1 service startup policy, and a checksummed BMNT v1 boot
  mount manifest with deterministic stable-identity resolution;
- a four-block dual-slot persistence transaction with exact
  data/flush/commit/flush ordering, host fault injection at every boundary,
  a checksummed exact-GPT-identity region selector, and native process-reopen
  recovery on both QEMU transports; plus a bounded SHA-256-addressed immutable
  content pack loaded from the exactly selected ext4 root and a digest-bound
  active/predecessor SCFG publication pointer with QEMU-proven health rollback;
- a bounded single-file persistent state filesystem mounted writable at
  `/vol/state`, with native flush/reopen recovery on both architectures;
- bounded Ethernet/ARP/IPv4/UDP primitives and native fixed-buffer modern
  virtio-net PCI/MMIO transports, with checksum/fragment/truncation rejection,
  a 10,000-frame resource-ceiling test, and QEMU-proven host UDP exchange;
- canonical bounded identity registry, foreign mapping, mount-policy, and
  native ACL snapshots, bound as typed immutable roots to active/predecessor
  generations and revalidated through QEMU rollback/reopen;
- a bounded modern virtio block core with native AArch64 `virtio-mmio` and
  x86-64 q35 virtio PCI transports; both have QEMU-proven post-handoff GPT
  discovery, exact BMNT disk/partition/ext4 identity selection, and a live
  read-only `/vol/root` mount;
- owned receive interrupts through q35 LAPIC/I/O APIC and AArch64 GICv2,
  bounded raw-event delivery, and race-free `hlt`/`wfi` shell idle;
- project-owned polling 16550 and PL011 early/fatal recovery output, plus an
  owned GOP framebuffer text console on both architectures;
- configurable cursor-aware UTF-8 line editing, volatile bounded history,
  command/VFS completion, ANSI serial-key decoding, and x86-64 PS/2 input;
- single/double quotes and pipelines of up to eight stages;
- 64 KiB bounded intermediate byte streams;
- `cat`, `echo`, literal `grep`, `ls`, `pwd`, `cd`, `man`, `mem`, `clear`,
  `poweroff`, `reboot`, `write`, `rm`, and `hexdump`;
- deterministic 1.44 MiB FAT12 images for both primary architectures;
- host/unit/smoke gates and prompt-synchronized QEMU acceptance on both
  architectures.

### Current networking scope

Normal QEMU images attach one modern virtio-net device and acquire an IPv4
address, subnet mask, default gateway, and lease through a bounded DHCP
discover/request exchange. The recovery shell exposes `net`, `dhcp`, `ping`,
`arp`, `net stats`, `udp send --source-port`, and `udp listen`. A shared ambient
service answers ARP and ICMP while the prompt or a cooperative command is idle,
retains eight ARP neighbors, and owns eight persistent UDP ports with four
datagrams and 4 KiB per-port receive capacity. Commands use a boot-relative
monotonic clock and explicit cancellation checkpoints; Ctrl-C cancels waits and
`sleep` without introducing background jobs. Receive completions wake the
ambient service through bounded q35 INTx or GICv2 handlers; an empty receive
check never spins. DNS, IPv6, TCP, HTTP, TLS,
fragmentation, and general sockets remain outside this milestone.
KEX apps may receive optional owner-scoped IPv4/UDP and read-only filesystem
handles when their KCAP manifests request them. `cat`, `grep`, `hexdump`, `ls`,
and `man` exercise generation-checked files, bounded reads, metadata, and
lexically paginated directories. Mutation, timer, diagnostics, and typed
network capabilities are the next lower-level migration boundaries before TCP.

## Quick start

Host model:

```console
cargo run --manifest-path host/Cargo.toml
cargo run --manifest-path host/Cargo.toml -- --command "echo ready | grep ready"
cargo run --manifest-path host/Cargo.toml -- --script tests/smoke.sh
```

Build and inspect the example KEX command for both native targets:

```console
cargo kex build apps/echo --target all
cargo kex build apps/echo --target all --check
cargo kex inspect rootfs/bin/x86_64/echo.kex
```

Each installed `.kex` has a canonical `.kcap` sidecar; app manifests declare
only the optional versioned interfaces they require.

Build deterministic local/QEMU images with reserved test identities:

```console
python3 scripts/build.py --platform all --fixture-identities
```

For a deployment artifact, provision identities once and supply them explicitly:

```console
python3 tools/mkidentity.py --output build/deployment-identities.json
python3 scripts/build.py --platform all \
  --identity-file build/deployment-identities.json
```

The build command has no implicit identity mode. Reserved fixture identities
are reproducible test data and are rejected by production cloud packaging.

Artifacts are written under `build/`, and the script reports their exact
filenames. The build regenerates KEFS, uses Cargo's locked dependency graph,
builds release EFI executables, constructs deterministic FAT images and the
BMNT policy, and enforces the 16 MiB hard ceiling. QEMU acceptance additionally
creates a reproducible GPT/ext4 storage disk with e2fsprogs plus separate
four-block writable TXSLOT media for each architecture.

Run all local gates:

```console
python3 scripts/test.py
```

This includes the pinned x86-64 and AArch64 QEMU boot suites. If that exact
QEMU/firmware pair is not installed, run the non-emulator gates explicitly with
`python3 scripts/test.py --skip-qemu`. Run only the boot suites with
`python3 scripts/test-qemu.py --platform all --environment qemu`; all named
platforms run concurrently after their images have been built. The complete
repository gate also requires owned
framebuffer activation on both architectures and native PS/2 input on x86-64.
For a quick terminal-focused iteration, use
`python3 scripts/test-qemu.py --platform all --environment qemu --smoke`; the
exhaustive suite remains the standard gate.

The FAT32 and ext4 providers include optional real-tool interoperability tests.
On macOS, install their independent image builders/checkers with:

```console
brew install e2fsprogs dosfstools mtools
```

The canonical ext4 builder accepts exactly e2fsprogs 1.47.4
(`6-Mar-2025`); another installed version is treated as an on-media format
change and fails before formatting.

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
terminal permission/exception probes. A build without `--acceptance-probes` is
rejected if any probe marker is present; deployment status additionally requires
an explicit non-fixture identity file.

Build the default `x86_64-q35-uefi` image and open it in QEMU:

```console
cargo qemu
```

Select another exact platform when needed:

```console
cargo qemu --platform x86_64-q35-uefi --environment qemu
```

Open the owned framebuffer console while retaining serial stdio as the recovery
transport:

```console
cargo qemu --platform x86_64-q35-uefi --environment qemu --graphical
cargo qemu --platform aarch64-virt-uefi --environment qemu --graphical
```

The Cargo convenience wrapper supplies the named `x86_64-q35-uefi`/`qemu`
default when either selector is omitted; the underlying launcher and all test
APIs remain explicit. The launcher discovers firmware bundled with QEMU in
conventional installation locations. Architecture, target triple, firmware
family, machine type, CPU, RAM, and virtio transport derive from the selected
named platform and are never inferred in the other direction.
If QEMU does
not bundle firmware, provide code and variable-store images from rust-osdev
`ovmf-prebuilt` release `edk2-stable202605-r1` using `--firmware-code` and
`--firmware-vars`. Whether discovered or supplied explicitly, every code and
variable-store image must match the committed size and SHA-256 provenance
record in `tools/qemu-firmware-profile.json`.

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

- `crates`: portable byte streams, KEX/ABI/config/GPT/FAT parsing, block regions,
  memory models, shell, VFS/provider mounts, terminal/editor, accounting, and
  the isolated native machine mechanism crate;
- `host`: Stage 0 composition and acceptance runner;
- `kernel`: UEFI bootstrap and Stage 9 owned-machine composition root;
- `apps`, `sdk`, `skills`: KEX examples, freestanding SDK, and concise authoring
  guidance;
- `rootfs`, `assets`: source tree, installed KEX files, and generated KEFS image;
- `tools`: dependency-free deterministic image and KEX builders;
- `scripts`: build, verification, and emulator entry points;
- `docs`: ADRs, formats, security notes, and staged design.

The core design is [CORE-SPEC.md](CORE-SPEC.md). The future, currently
unimplemented tooling and package-composition design is
[TOOLING-PACKAGING-SPEC.md](TOOLING-PACKAGING-SPEC.md). The
implementation status and immediate sequence are in
[docs/roadmap.md](docs/roadmap.md), and [docs/README.md](docs/README.md)
classifies the design records, evaluations, format references, and security
notes by purpose and status.

## Resource policy

Every supported build uses one bounded `standard` policy for cloud virtual
machines and the pinned QEMU acceptance environments. There is no
micro/tiny/full selector or embedded/no-MMU composition. The standard limits
are safety ceilings, not boot-time reservations: resources are charged as they
are owned, and usable RAM may refine cache and growth budgets without changing
the selected policy or system semantics. Terminal/editor, completion, driver,
identity, and application code expose validated `standard()` policies or
explicit checked limits so externally controlled sizes remain bounded without
scattering magic constants through the kernel.

## Hardware direction

QEMU remains a pinned, deterministic acceptance environment, but it is not the
cloud hardware contract. Stage 7.5 separates CPU architecture, virtual-machine
platform, and execution environment; q35 and QEMU `virt` resources no longer
masquerade as architecture facts. Bounded ACPI/FDT discovery and exact combined
cloud bundles are accepted on the two discoverable QEMU contracts. KVM and
provider clouds remain unaccepted until independently proven.
Physical boards, embedded targets, and no-MMU machines are outside the current
roadmap. See the
[implementation roadmap](docs/roadmap.md) and
[ADR 0016](docs/adr/0016-hardware-targets-and-emulator-role.md), plus the
[cloud support matrix](docs/cloud-platform-support.md).

## Name

The public project name is **TROE**, expanded as **Tiny Rust Operating
Environment**. Cargo packages, crate directories, Rust identifiers, assembly
symbols, documentation, and test-only volume labels use the `troe`/`TROE`
forms. KEX, KEFS, and SCFG remain product-name-independent wire formats.

Licensed under Apache-2.0.

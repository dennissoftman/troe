# TROE

### Tiny Rust Operating Environment

**A small, strict, capability-oriented operating system for x86-64 and AArch64.**

[![Rust](https://img.shields.io/badge/Rust-1.97.1-dea584?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Platforms](https://img.shields.io/badge/platforms-x86--64%20%7C%20AArch64-5865f2)](docs/cloud-platform-support.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

TROE is an experimental Rust operating system for small, predictable virtual
machines. It boots as a native UEFI image and provides an interactive shell,
isolated command-line applications, persistent state, and virtio networking.

Most of TROE is portable `no_std` Rust. Project-authored unsafe code is confined
to one audited machine boundary; portable crates forbid it.

> **Project status:** TROE runs in QEMU today. It is a research and development
> project, not yet a general-purpose OS or production cloud image. See the
> [Stage 9 tracking issue](https://github.com/dennissoftman/troe/issues/14).

## Why TROE?

- ⚡ **Efficient by construction.** The current boot image is 1.44 MiB, the
  kernel owns a fixed 6 MiB heap, and resources are charged only when used.
- 🛡️ **Isolated by default.** Every ordinary command starts in a fresh
  ring-3/EL0 address space with only its declared, typed capabilities.
- ✅ **Strict at every boundary.** Executables, filesystems, configuration,
  memory mappings, and network input are bounds-checked and validated before use.
- 🔁 **Predictable under failure.** Work has hard ceilings, applications have a
  bounded preemptive timeslice without an arbitrary total runtime deadline,
  faults are contained, and teardown revokes handles,
  zeroizes memory, and returns owned frames.

TROE also enforces W^X mappings, guarded task stacks, generation-checked handles,
fixed-size queues, deterministic image builds, and exact dependency and firmware
profiles. Small is a policy here, not just a current measurement.

## What runs today

- Native UEFI boots on x86-64 and AArch64.
- Serial and framebuffer consoles with UTF-8 line editing, history, completion,
  literal single/double quoting, pipelines, and streamed `<`, `>`, and `>>`
  redirection, plus session-owned background jobs and bounded logs.
- SCFG boot-service supervision with stable service names, restart/backoff
  policy, `svc` control, and an example long-running SNTP clock service.
- A bounded VFS with KEFS, a default read-write persistent ext4 volume at
  `/vol/root`, read/write FAT32, bounded ext4 symbolic/hard links, quota-bound
  `/tmp`, live `/sys`, and crash-consistent state under `/vol/state`.
- Ethernet, ARP, DHCP, IPv4, ICMP, UDP, and outbound TCP over virtio-net.
- KEX applications for `arp`, `awk`, `cat`, `clear`, `dhcp`, `echo`, `grep`,
  `hexdump`, `ln`, `ls`, `lua`, `man`, `mem`, `mount`, `net`, `ping`, `printf`,
  `ps`, `pwd`, `rm`, `sed`, `sh`, `sleep`, `tar`, `tcp`, `timesync`, `top`,
  `udp`, and `wc`.

`cd`, session job control, `svc`, `poweroff`, and `reboot` are non-shadowable
shell intrinsics because they mutate shell- or supervisor-owned state. Ordinary
commands remain immutable KEX applications discovered from `/bin`.

## 🎬 Demos

### Shell and filesystem

```console
sh:/> cat /recovery/motd
Tiny Rust Operating Environment 0.1.0
Small by design. Alive on the wire.

sh:/> printf 'first\nsecond\t%s\n' value | grep second
second  value

sh:/> echo alpha beta | grep beta > /tmp/result
sh:/> cat /tmp/result
alpha beta

sh:/> printf persistent > /vol/root/note
sh:/> ln -s note /vol/root/latest
sh:/> cat /vol/root/latest
persistent

sh:/> lua -e 'print(string.format("Lua %.1f", math.sqrt(81)))'
Lua 9.0

sh:/> cd /vol/shared
sh:/vol/shared> sh /share/sh/bench.sh
===== F00 building fixtures with printf
...
===== END of transcript
```

Additional ext4-v1 or FAT32 partitions can be declared in the strict
human-editable [`config/volumes.toml`](config/volumes.toml). Names map to
`/vol/<name>` and exact stable identities are compiled into the bounded
`EFI/BOOT/VOLUMES.BMT` boot file. The kernel reads that file through UEFI before
handoff, so changing the volume policy does not relink the kernel. Attach custom
QEMU media with:

```console
cargo qemu --volume-table path/to/volumes.toml --data-disk path/to/disk.raw
```

Entries with `activation = "auto"` attach during boot. Entries with
`activation = "manual"` are retained as validated providers until
`mount VOLUME`; plain `mount` lists policy and state. `cat /sys/storage` reports
every device, candidate, configured role, and failure state. See the
[volume-table format](docs/formats/volume-table-v1.md) for the complete schema.

Every `cargo qemu` invocation also creates or preserves the sparse, exact 1 GiB
`build/troe-shared-fat32.img` and attaches it as the optional writable
`/vol/shared` volume. Unlike the generated root fixture,
this interchange disk is not rebuilt, so files survive normal QEMU launches:

```console
sh:/> printf hello-from-troe > /vol/shared/from-troe.txt
sh:/> cat /vol/shared/from-troe.txt
hello-from-troe
```

Stop QEMU cleanly with `poweroff`, then attach the persistent image through the
host developer command:

```console
cargo mount
# copy files below the printed mount point
cargo mount --unmount
```

`cargo mount` creates or validates the image, mounts it read-write, and prints
the host path. Repeating it is idempotent. `--read-only` requests a read-only
attachment, `--open` opens the mounted directory in Finder or the Linux file
manager, and `--status` reports its lifecycle state. On macOS it uses the native
DiskImages service. On Linux it prefers the unprivileged desktop UDisks service
and falls back to direct loop devices when already running as root; install the
distribution's `udisks2` package when `udisksctl` is absent. A native Windows
backend is intentionally deferred.

The mount command and QEMU share an exclusive lifecycle lock, and `cargo qemu`
refuses to start while the host attachment remains live. Always detach before
QEMU because the image must never have two writable owners. A busy detach fails
without forcing open files closed. `cargo qemu --reset-shared-disk`
deliberately replaces the image with an empty filesystem, while
`cargo qemu --no-shared-disk` opts out for one run. The FAT32 medium is the
macOS/Linux interchange starting point; macOS does not mount ext4 natively.
If a guest was stopped before unmounting the medium, the next interactive
launcher or `cargo mount` validates the canonical GPT/FAT metadata and offers a
narrow repair with a safe `y/N` default. The repair only clears the
unclean-unmount marker and keeps the filesystem contents; other metadata
deviations still fail closed. Use `cargo mount --repair` for the same explicit,
lock-protected non-interactive repair without mounting the image.

### Networking

This is an abridged session from the x86-64 QEMU profile:

```console
sh:/> net
link: ready
mac: 52:54:00:12:34:56
ipv4: 10.0.2.15
gateway: 10.0.2.2

sh:/> ping 10.0.2.2
reply from 10.0.2.2: icmp_seq=1 bytes=9

sh:/> udp send --source-port 40001 10.0.2.2 9 hello-from-troe
sent 15 bytes from port 40001 to 10.0.2.2:9
```

Networking is currently literal IPv4. DNS, IPv6, HTTP, TLS, and inbound TCP are
outside the implemented scope.

### KEX applications

KEX packages combine a native executable with a manifest declaring only the
capabilities that application needs:

```text
KEX package → validate → fresh user space → grant typed handles
            → bounded execution → revoke → zeroize → reclaim
```

Build and inspect the example `echo` application for both targets:

```console
$ cargo kex build apps/echo --target all --check
$ cargo kex inspect rootfs/bin/x86_64/echo.kex
```

Start exploring with [`apps/echo`](apps/echo) and the
[`troe-kex` Rust SDK](sdk/rust/troe-kex).

[`apps/lua`](apps/lua) is a complete freestanding Lua 5.5.1 interpreter. It
streams source from `-e`, stdin, or the bounded read-only filesystem service,
starts with a 1 MiB TLSF application heap that commits more physical memory on
demand, and exposes only base, coroutine, table,
string, math, UTF-8, and a capability-aware OS shim. The shim implements
process-CPU `os.clock`, whole-second Unix `os.time`, controlled `os.exit`, and
`os.difftime`; its remaining
standard entries fail explicitly until TROE grants and implements the required
authority. Lua has no ambient libc, environment, process, dynamic-module, OS,
or raw filesystem access.

[`apps/sh`](apps/sh) transactionally stages a bounded UTF-8 command file through
the typed shell-script sidecar, then the owning session executes each validated
physical line with the normal TROE pipeline and redirection grammar. The first
version intentionally omits variables, control flow, substitution, multiline
constructs, and direct shebang execution.

KEX images are statically linked today. A bounded, single-package dynamic
linking design for reusable libc and language runtimes is tracked in
[GitHub issue #10](https://github.com/dennissoftman/troe/issues/10).

Hosted Stage 9 tooling now models deterministic multi-package locks, signed
release verification, and transactional system generations without making the
kernel invoke host tools. Start with `python3 tools/troe.py --help`,
`python3 tools/troe_trust.py --help`, and
`python3 tools/troe_system.py --help`. The lifecycle CLI leaves a verified
candidate `pending`; native bounded health orchestration must report `passed` or
`failed` before it becomes healthy or automatically returns to its predecessor.
See [ADR 0044](docs/adr/0044-transactional-system-lifecycle.md).

## 🚀 Quick start

### Prerequisites

- Rust `1.97.1` via [rustup](https://rustup.rs/); the repository toolchain file
  selects the required components and targets.
- Python `3.13` or newer.
- QEMU `11.1.0` with matching x86-64 or AArch64 UEFI firmware.

From a repository checkout, build and boot the platform matching your host:

```console
cargo qemu
```

The launcher opens TROE on the serial console. Use `poweroff` inside the guest
to shut it down, or add `--graphical` to open the framebuffer console:

```console
cargo qemu --graphical
```

Choose a target explicitly when needed:

```console
cargo qemu --platform x86_64-q35-uefi --environment qemu
cargo qemu --platform aarch64-virt-uefi --environment qemu
```

Boot the pinned Alpine virtual image under the same QEMU machine resources for
an end-to-end comparison. Each platform gets a separate persistent 8 GiB Alpine
system image, while the independent shared FAT32 disk is attached as
`TROE SHARE` so the same workload data can be used by both guests:

```console
cargo alpine --platform x86_64-q35-uefi --environment qemu
cargo alpine --platform aarch64-virt-uefi --environment qemu
```

Alpine defaults to 256 MiB because its current ISO cannot boot with TROE's
128 MiB acceptance limit. Use `cargo qemu --memory 256M` for matched comparison
runs; normal TROE and acceptance launches retain their 128 MiB default. On the
first Alpine boot, run `setup-alpine`, install to the device identified by
`/dev/disk/by-id/virtio-ALPINE_ROOT` in `sys` mode, and reboot. The installed OS
and packages then persist; `TROE SHARE` remains a data-only interchange disk.
An empty system image triggers a first-install guide automatically; use
`cargo alpine --install-help` to print it again without launching QEMU.

See the [Alpine performance comparison guide](docs/alpine-performance.md) for
the guest mount command, four-guest matrix, and interpretation limits.

The first non-QEMU target is separately pinned to Cloud Hypervisor v53.0 on a
Linux x86-64 KVM host. It has a production-only acceptance harness but remains
`compatible-unverified` until the live matrix passes; see the
[exact target and operator runbook](docs/cloud-hypervisor-production.md).

Without the exact QEMU setup, the hosted model still exercises the shell parser
and sessions. It intentionally does not execute KEX applications.

```console
cargo run --manifest-path host/Cargo.toml
```

## Build and test

Build deterministic test images for every supported platform:

```console
python3 scripts/build.py --platform all --fixture-identities
```

Run the complete local and QEMU gate, or select checks affected by your changes:

```console
python3 scripts/test.py
python3 scripts/test_changed.py --explain
```

Use `python3 scripts/test.py --skip-qemu` when the pinned emulator and firmware
are unavailable. Fixture identities are test data and cannot produce deployment
artifacts; see the [cloud platform guide](docs/cloud-platform-support.md) for the
explicit provisioning workflow.

## Project guide

| Path | Purpose |
| --- | --- |
| [`kernel/`](kernel) | UEFI entry point and native kernel composition |
| [`crates/`](crates) | Portable shell, VFS, storage, networking, task, and driver components |
| [`apps/`](apps) | Isolated KEX command applications |
| [`sdk/`](sdk) | Rust application SDK and linker support |
| [`rootfs/`](rootfs) | Root filesystem and packaged applications |
| [`host/`](host) | Hosted shell model |
| [`scripts/`](scripts) | Build, test, and QEMU entry points |
| [`docs/`](docs) | Architecture, formats, decisions, security notes, and historical evaluations |

The [documentation guide](docs/README.md) indexes the deeper material:

- [Architecture](docs/architecture.md)
- [Testing guide](docs/testing.md)
- [Cloud platform support](docs/cloud-platform-support.md)
- [Security policy](SECURITY.md)
- [Open work](https://github.com/dennissoftman/troe/issues)

## Contributing and license

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening
a change. TROE is licensed under the [Apache License 2.0](LICENSE).

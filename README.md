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

> **Project status:** TROE runs in the accepted QEMU environments. It is a
> research and development project, not a general-purpose OS or production
> cloud image. See the
> [Stage 9 tracking issue](https://github.com/dennissoftman/troe/issues/14).

## Why TROE?

- ⚡ **Efficient by construction.** The current boot image is 8 MiB, the
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
bounded fallibly growing resource tables, deterministic image builds, and exact
dependency and firmware profiles. Small is a policy here, not just a current
measurement.

## What runs

- Native UEFI boots on x86-64 and AArch64.
- Serial and framebuffer consoles with UTF-8 line editing, history,
  package-owned typed completion, literal single/double quoting, pipelines, and
  short-circuit `&&`/`||`, and streamed `<`, `>`, and `>>` redirection, plus
  session-owned background jobs and bounded logs.
- A foreground terminal-input loan: one interactive command at a time reads
  typed lines from the session terminal, ends input with `Ctrl-D`, and cancels
  with `Ctrl-C`, while background jobs and services keep observing end of input
  and cannot consume prompt keystrokes.
- SCFG boot-service supervision with stable service names, restart/backoff
  policy, `svc` control, and an example long-running SNTP clock service.
- A bounded VFS with KEFS, a default read-write persistent ext4 volume at
  `/vol/root`, read/write FAT32, bounded ext4 symbolic/hard links, quota-bound
  `/tmp`, live `/sys`, and crash-consistent state under `/vol/state`.
- Ethernet, ARP, DHCP, IPv4, ICMP, UDP, and outbound TCP over virtio-net.
- KEX applications for `arp`, `awk`, `cat`, `clear`, `cp`, `dhcp`, `echo`,
  `grep`, `head`, `hexdump`, `ln`, `ls`, `lua`, `man`, `mem`, `mkdir`, `mount`,
  `mv`, `net`, `ping`, `printf`, `ps`, `pwd`, `rm`, `rmdir`, `sed`, `sh`,
  `sleep`, `spawn`, `tail`, `tar`, `tcp`, `timesync`, `top`, `touch`, `udp`, and
  `wc`.

`cd`, session job control, `svc`, `poweroff`, and `reboot` are non-shadowable
shell intrinsics because they mutate shell- or supervisor-owned state. Ordinary
bare commands remain immutable KEX applications discovered from `/bin`.
An explicit command token containing `/` instead resolves the exact KEX file
through the caller's VFS working directory, so copied applications can be run
as `./app` without adding writable volumes to an ambient search path.

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

sh:/> cp /bin/echo.kex /vol/shared/echo-copy
sh:/> cd /vol/shared
sh:/vol/shared> ./echo-copy explicit KEX path
Run untrusted application './echo-copy' outside /bin? [y/N] y
explicit KEX path

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

Large optional runtime executables use the versioned
`/vol/shared/bin/<architecture>/<name>.kex` tree. They are never
copied into rootfs, KEFS, or the EFI image. `tools/mkruntime.py` builds a
canonical SHA-256 manifest, verifies the exact file set and every artifact
byte, and installs either below a mounted shared-media root or directly into a
detached TROE shared image:

```console
python3 tools/mkruntime.py build --output build/runtime-v1 \
  --artifact x86_64:runtime=build/packages/x86_64/runtime.kex \
  --artifact aarch64:runtime=build/packages/aarch64/runtime.kex
python3 tools/mkruntime.py verify build/runtime-v1
python3 tools/mkruntime.py install build/runtime-v1 --shared-root /path/to/mounted/shared
# Or: python3 tools/mkruntime.py install-image build/runtime-v1 \
#       --image build/troe-shared-fat32.img
```

Install and verification reject missing media, wrong schemas, symlinks,
unmanifested files, malformed records, oversize artifacts, and hash or length
mismatches with a specific error.

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

Bare names use the bounded `/bin/<name>.kex` catalog. Tokens containing `/`
are exact relative or absolute VFS paths: no `.kex` suffix is inferred, and
there is no `PATH` or implicit current-directory search. The selected regular
file must pass the same complete package, manifest, target, and executable
validation as an installed command. Symlinks may resolve to a regular KEX file;
package requirements still cannot exceed the launcher's authority.
The interactive shell asks for a default-negative confirmation before directly
executing a path outside `/bin`. This is an advisory provenance warning, not a
substitute for executable permission bits or package trust policy.

Externally stored packages are validated and materialized with fixed 4 KiB
chunks and a 24 KiB format-verifier buffer ceiling, including a fallibly
allocated maximum 16 KiB completion descriptor buffer. The kernel fingerprints every
package byte, independently validates and fingerprints relocations, streams
load bytes only into inactive zeroed frames, and rechecks both fingerprints
before activation. It never retains a package-sized kernel-heap copy. Direct,
background, service, and owner-scoped nested launch all use this path and retain
the same W^X, ASLR, capability attenuation, transactional rollback, teardown,
and page accounting.

The essential filesystem command set includes streamed `cp`, iterative
`cp -r`/`cp -R`, atomic same-provider `mv`, recursive `rm -r`/`rm -R`, and
`rmdir`. Recursive commands reproduce symbolic links without following them
and retain only fallibly grown, explicitly bounded traversal metadata. Shared
algorithms live in the small `no_std`
[`troe-kex-runtime`](sdk/rust/troe-kex-runtime) layer; the lower-level
[`troe-kex`](sdk/rust/troe-kex) crate remains the typed ABI client. The runtime
also supplies allocation-free environment, errno, direct-process, UTC calendar,
C-locale formatting/classification, decimal/math, capability-backed CSPRNG
reads, and POSIX-shaped private-memory helpers. Allocation-backed recursive filesystem operations are a separate
feature so embedders can retain their own allocator policy.

KEX container 1.1 is position-independent. The kernel fails closed unless UEFI
supplies an approved RNG seed, retains a ChaCha20 CSPRNG, gives applications
random bytes only through an explicit read capability, and independently
randomizes every image, stack, and anonymous private mapping. Each application
declares the image span it needs, so a small command reserves 2 MiB of image
address space rather than a fixed window sized for the largest artifact the
format permits. Initial and
runtime commitment use full-width accounting under the active
`/config/system/resources/memory.toml` policy; valid large requests consume
resources on demand rather than reserving their ceiling at boot.

[`apps/spawn`](apps/spawn) resolves a
nested KEX package through the owner-scoped launch capability, inherits or
captures standard output through a bounded pipe, waits, reaps, and preserves
the child's complete exit status without putting shell grammar in the kernel.

[`apps/lua`](apps/lua) is a complete freestanding Lua 5.5.1 interpreter. Like
CPython it is an optional runtime rather than a recovery command: it ships on
`/vol/shared/bin/<architecture>` and is reached by explicit path, so the
read-only root keeps only what booting, recovering, and administering a
machine actually needs. It
supports the stock batch command-line actions and standard library surface,
including file mutation, `os.execute`, and read/write `io.popen` through explicit
KEX capabilities. It starts with a 1 MiB TLSF application heap, reports
process-CPU time through `os.clock`, and exposes whole-second Unix wall time
through `os.time`. Its hybrid allocator keeps ordinary objects in a growable
TLSF heap and returns large private mappings during the process lifetime; Lua
hash/math seeds come from the typed CSPRNG. Lua statically links the shared Rust
KEX runtime plus the shared SDK-owned freestanding C runtime instead of owning
duplicate filesystem, environment, process, calendar, decimal, math, or
C-locale algorithms. Decimal rendering performs correctly rounded binary64
`%f`, `%e`, and `%g` conversions. The remaining platform limits are explicit:
interactive `-i`/REPL operation is absent, UTC and the C locale are fixed, C
dynamic modules have no loader, and Lua has no ambient host OS or raw filesystem
access.

[`apps/python`](apps/python) is upstream CPython built as one statically linked
KEX. It is the only application delivered on `/vol/shared` instead of rootfs:
the interpreter and its library do not fit the rootfs and EFI budgets.
`tools/build_cpython.py` authenticates and cross-builds the pinned 3.14.7,
3.13.15, and 3.12.14 releases for both targets, and the package exposes
version-addressable `python3.14.7.kex` through `python3.12.kex` names plus a
`python.kex` default bound to the newest pinned release. Initialization is an
explicit isolated `PyConfig`: fixed TROE paths, UTF-8 mode, no ambient
environment, no user site directory, and no bytecode writes, so a read-only
interpreter tree stays fully usable. Imports resolve from the shipped library
and from `/vol/shared/lib/<architecture>/packages`, where bootstrap tooling installs
ordinary pure-Python packages. File I/O, the working directory, clocks, private
memory, temporary files, and `os.urandom`/`secrets` reach the granted
capabilities through the shared C runtime; withholding entropy authority stops
interpreter initialization outright rather than falling back to weak seeding.
`sys.platform` is `troe` rather than a POSIX claim. The limits are explicit and
tested: no `pip`, virtual environments,
shared libraries, native extensions, `ctypes`, sockets, TLS, SQLite,
subprocesses, real threads, or signals; creating a thread fails explicitly while
main-thread locks and thread-local storage work; and every module needing an
excluded facility is absent rather than broken. Every build records its own
interpreter, mapped-page, and library measurements next to the accepted
per-component ceilings and fails when any one regresses past them. Started with
no arguments on the terminal it runs its basic REPL over the session
terminal-input loan, retaining state between statements and ending on end of
input; redirected and piped standard input keep their noninteractive behavior.
`site` is never imported, so no search path, per-user directory, or `.pth` file
can affect startup; the launcher installs only that module's `exit` and `quit`
conveniences.

The reusable freestanding C SDK lives under
[`sdk/c`](sdk/c/troe-kex-sysroot). `tools/build_c_sysroot.py` produces an LP64
sysroot for both supported targets with target headers and
`lib/libtroe_c.a`; builds use `-nostdlibinc` and never inherit host libc. This
is a build sysroot library, not a guest `/lib` payload. The
static library owns the C allocator ABI, UTF-8 and wide-character conversion,
`setjmp`/`longjmp`, bounded descriptors, buffered `FILE` and directory streams,
filesystem replacement, preserved append, read-write descriptors that read back
their own staged bytes, and links, argv/environment,
UTC/C-locale time, secure
randomness, exit handling, and coherent single-execution-thread locks and TSS.
The Rust [`troe-kex-c-runtime`](sdk/rust/troe-kex-c-runtime) bridge supplies only
the typed capabilities present in the package manifest. Missing capabilities
fail with `EACCES`; unsupported flags and facilities fail explicitly. There is
no guest `/lib` dependency because every KEX remains statically linked.

[`apps/sh`](apps/sh) transactionally stages a bounded UTF-8 command file through
the typed shell-script sidecar, then the owning session executes each validated
physical line with the normal TROE logical-list, pipeline, and redirection
grammar. The current grammar omits variables, control-flow blocks, substitution,
multiline constructs, and direct shebang execution.

KEX images are statically linked. A bounded, single-package dynamic
linking design for reusable libc and language runtimes is tracked in
[GitHub issue #10](https://github.com/dennissoftman/troe/issues/10).

Hosted Stage 9 tooling models deterministic multi-package locks, signed
release verification, and transactional system generations without making the
kernel invoke host tools. Start with `python3 tools/troe.py --help`,
`python3 tools/troe_trust.py --help`, and
`python3 tools/troe_system.py --help`. The lifecycle CLI leaves a verified
candidate `pending`; native bounded health orchestration must report `passed` or
`failed` before it becomes healthy or automatically returns to its predecessor.
See [ADR 0044](docs/adr/0044-transactional-system-lifecycle.md).

`python3 tools/setup_troe.py install` provisions a clean machine from one
verified bundle onto the exact `system`, `activation`, and `state` targets. It
verifies every bundle byte before touching a destination, reads every installed
byte back, and records the result so an interrupted install is never mistaken
for a completed one. See
[cloud platform support](docs/cloud-platform-support.md).

## 🚀 Quick start

### Prerequisites

- Rust `1.97.1` via [rustup](https://rustup.rs/); the repository toolchain file
  selects the required components and targets.
- Git LFS; run `git lfs install` once before checking out repository artifacts.
- Python `3.13` or newer.
- e2fsprogs `1.47.x` (`mke2fs` and `e2fsck`).
- QEMU `8.x` through `11.x` with matching x86-64 or AArch64 distribution UEFI
  firmware. QEMU `11.1.0` and the committed firmware digests remain the strict
  release-evidence profile.

From a repository checkout, build and boot the platform matching your host:

```console
cargo qemu
```

The launcher opens TROE on the serial console. Use `poweroff` inside the guest
to shut it down, or add `--gui` to open the framebuffer console:

```console
cargo qemu --gui
```

Focus the QEMU window to send keyboard input, including `Ctrl-C`, to the guest.
`Ctrl-C` in the host terminal still cancels QEMU. The older `--graphical` name
remains an alias for `--gui`. The same option is available for `cargo alpine`.

Choose a target explicitly when needed:

```console
cargo qemu --platform x86_64-q35-uefi --environment qemu
cargo qemu --platform aarch64-sbsa-ref --environment qemu
```

Boot the pinned Alpine virtual image under the same QEMU machine resources for
an end-to-end comparison. Each platform gets a separate persistent 4 GiB Alpine
system image, while the independent shared FAT32 disk is attached as
`TROE SHARE` so the same workload data can be used by both guests:

```console
cargo alpine --platform x86_64-q35-uefi --environment qemu
cargo alpine --platform aarch64-sbsa-ref --environment qemu
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

Without a supported QEMU setup, the hosted model still exercises the shell parser
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

The normal build and test commands accept the compatible tool ranges above and
still enforce the same ext4 byte-level verifier and guest acceptance scenarios.
Use `python3 scripts/test.py --strict-tool-versions --require-filesystem-tools`
for release-grade evidence tied to QEMU `11.1.0`, the committed firmware
digests, and e2fsprogs `1.47.4`. Use `--skip-qemu` only when no supported
emulator and firmware are available. Fixture identities are test data and
cannot produce deployment artifacts; see the
[cloud platform guide](docs/cloud-platform-support.md) for the explicit
provisioning workflow.

## Project guide

| Path | Purpose |
| --- | --- |
| [`kernel/`](kernel) | UEFI entry point and native kernel composition |
| [`crates/`](crates) | Portable components grouped by domain: `common/`, `storage/`, `net/`, `device/`, `runtime/`, and `shell/` |
| [`apps/`](apps) | Isolated KEX command applications |
| [`sdk/`](sdk) | Rust and freestanding C application SDKs, runtimes, and linker support |
| [`rootfs/`](rootfs) | Root filesystem and packaged applications |
| [`host/`](host) | Hosted shell model |
| [`scripts/`](scripts) | Build, test, and QEMU entry points |
| [`docs/`](docs) | Current architecture, formats, decisions, security, and testing guidance |

The [documentation guide](docs/README.md) indexes the deeper material:

- [Architecture](docs/architecture.md)
- [Testing guide](docs/testing.md)
- [Cloud platform support](docs/cloud-platform-support.md)
- [Security policy](SECURITY.md)
- [Open work](https://github.com/dennissoftman/troe/issues)

## Contributing and license

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening
a change. TROE is licensed under the [Apache License 2.0](LICENSE).

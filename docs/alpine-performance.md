# Comparing TROE with Alpine Linux

`cargo alpine` boots the pinned Alpine Linux 3.24.1 virtual image with the same
QEMU runner record used by `cargo qemu`: the same machine type, emulated
CPU, UEFI firmware, one virtual CPU, virtio transport, and user network. Alpine's
current virtual ISO requires more than TROE's 128 MiB acceptance default, so the
comparison commands give both guests 256 MiB. The launcher attaches two distinct
writable devices: a platform-specific 4 GiB Alpine system disk and TROE's
persistent 1 GiB FAT32 interchange image.

## Install Alpine persistently

The first `cargo alpine` run creates a sparse system image at
`build/alpine/root-<platform>.raw`. The empty system disk has first boot priority,
then firmware falls through to the pinned installer ISO. At the live login, log
in as `root` with no password and identify the stable root device:

```console
readlink -f /dev/disk/by-id/virtio-ALPINE_ROOT
setup-alpine
```

Use the printed device (for example `vda`) when `setup-alpine` asks which disk to
use, select `sys` mode, and reboot when installation finishes. Later
`cargo alpine` runs preserve both that raw disk and its platform-specific UEFI
variable store, and boot the installed system before the ISO. Packages installed
there persist normally:

```console
apk update
apk add lua5.5
lua5.5 -v
```

`cargo alpine --reset-root-disk` deliberately replaces both the selected
platform's system disk and UEFI state, returning it to first-install state.
`--no-root-disk` provides an explicitly ephemeral live-ISO run. Neither option
changes `TROE SHARE`.

The launcher detects an unpartitioned Alpine system image and prints the full
first-install guide before starting QEMU. Reprint it at any time without
launching QEMU or downloading an ISO:

```console
cargo alpine --install-help
```

This makes controlled end-to-end comparisons convenient. It does not turn a
BusyBox-versus-KEX result into a kernel-only measurement: command runtime,
standard library, allocator, filesystem, and kernel all contribute to the
result. QEMU TCG measurements are useful for regressions and architecture
parity, but results intended as native performance claims must be repeated on
named physical x86-64 and AArch64 systems.

## Prepare the shared workload

Attach the shared image on the host, copy inputs and scripts into the printed
mount point, and detach it before either guest starts:

```console
cargo mount
# Copy benchmark scripts and data into the printed directory.
cargo mount --unmount
```

The repository's portable shell workload is a useful functional starting
point. Copy `rootfs/share/sh/bench.sh` to the shared disk. It exercises `printf`,
`wc`, `sed`, and `awk`; elapsed time measures their complete guest stacks, not
just their kernels.

For a like-for-like Lua comparison, also copy
`rootfs/share/lua/benchmark.lua`. The script runs unchanged on TROE and Alpine
with Lua 5.5. Use identical scale and sample arguments in both guests:

```console
# TROE
lua /vol/shared/benchmark.lua 1 5 troe-x86_64

# Alpine, after mounting the shared volume and installing lua5.5
lua5.5 /mnt/shared/benchmark.lua 1 5 alpine-x86_64
```

Repeat with architecture-specific labels on AArch64. The first argument scales
the work from 1 through 4 and the second selects 1 through 9 measured samples;
the defaults are `1 5`. Each phase performs its own warmup and prints median,
minimum, maximum, throughput, and a deterministic checksum. Compare matching
`RESULT` rows rather than combining them into one score. A checksum mismatch
between guests invalidates that row.

## Run the four-guest matrix

Run TROE and Alpine once per architecture. Keep QEMU, firmware, host load, and
the workload bytes unchanged:

```console
cargo qemu --platform x86_64-q35-uefi --environment qemu --memory 256M
cargo alpine --platform x86_64-q35-uefi --environment qemu

cargo qemu --platform aarch64-sbsa-ref --environment qemu --memory 256M
cargo alpine --platform aarch64-sbsa-ref --environment qemu
```

Add `--gui` to either `cargo qemu` or `cargo alpine` to open the QEMU window.
While that window is focused, keyboard input such as `Ctrl-C` is delivered to
the guest instead of cancelling the host-side serial runner. `--graphical`
remains a compatibility alias.

`cargo alpine` downloads the architecture's pinned official virtual ISO on its
first run and verifies its exact length and SHA-256. Later runs verify and reuse
the cached image under `build/alpine/`. `--refresh` deliberately replaces that
cache. `--iso PATH` permits an explicit local image, but such a run is outside
the pinned comparison matrix and should record the image digest separately.

TROE mounts the interchange medium at `/vol/shared`. At the Alpine login prompt,
log in as `root` (the virtual ISO has no initial password), then mount the shared
volume:

```console
mkdir -p /mnt/shared
mount -t vfat '/dev/disk/by-label/TROE\x20SHARE' /mnt/shared
cd /mnt/shared
sh ./bench.sh
```

Before shutting Alpine down, leave the shared directory and unmount it cleanly:

```console
cd /
umount /mnt/shared
```

If Alpine was stopped first, the next interactive launcher or `cargo mount`
offers to clear the validated unclean-unmount marker with a `y/N` default
without erasing files. Non-interactive workflows can run
`cargo mount --repair` while the image is detached.

The label-based path is stable even though virtio enumeration order differs
between the PCI and MMIO machines. The launcher prints the mount command before
each interactive Alpine run. Both launchers take the same shared-media lifecycle
lock and refuse to start while
`cargo mount` still owns the host attachment. `cargo alpine --no-shared-disk`
opts out, and `cargo alpine --reset-shared-disk` deliberately erases and
recreates the medium.

## Measurement discipline

For each row, record the exact guest/version, architecture, QEMU command from a
`--dry-run`, host model, and host power policy. Use a workload large enough to
dominate serial output and boot time; redirect verbose output to a file on the
shared disk when appropriate. Run at least one warmup followed by several
measured repetitions, report the median and spread, and alternate guest order
to reduce temperature and host-load bias.

Separate useful questions instead of combining them into one score:

- boot-to-ready latency;
- cached CPU/syscall workloads with output suppressed;
- sequential and small-file I/O on the same FAT32 interchange medium;
- resident and peak memory at the same point in the workload;
- architecture parity within each guest.

For a kernel-focused benchmark, implement the smallest equivalent native
workload on both sides and count operations, bytes, allocations, and context
switches alongside elapsed time. TROE's diagnostics benchmark is valuable for
internal protected-IPC regressions, but it has no direct Alpine equivalent and
should not be presented as a cross-kernel result.

The Lua benchmark's compute timings use `os.clock`, so they measure process CPU
time rather than boot or wall-clock latency. Its allocation fields come from
`collectgarbage("count")`: `live_kib` is the retained Lua-heap growth at the end
of a phase, `peak_kib` is an observed Lua-heap high-water delta, and
`reclaimed_kib` is the portion released by a full collection. They exclude the
interpreter executable, native allocator overhead, kernel memory, and guest
page accounting. Use guest-level memory telemetry as a separate measurement
when comparing total footprint.

## Separate application cost from environment cost

Elapsed time alone cannot distinguish an application that executes more
instructions from an environment that makes the same instructions cost more.
Both guests run under QEMU TCG, so a TCG plugin can count the work directly.
Build it once against the QEMU headers already installed on the host:

```console
python3 tools/build_qemu_plugin.py
```

Add the resulting object to the QEMU command produced by `--dry-run`, naming
the address window that holds application code. TROE maps command applications
at its user code base, and Linux places user space in the low canonical half:

```console
# TROE
-plugin build/qemu-plugin/troe_count.so,user_lo=0x400000000000,user_hi=0x400100000000 -d plugin

# Alpine
-plugin build/qemu-plugin/troe_count.so,user_lo=0,user_hi=0x800000000000 -d plugin
```

Each run reports executed instructions, translation blocks, and memory reads
and writes for the application window and for everything else:

```
guest-work user_instructions=… user_blocks=… user_reads=… user_writes=…
  other_instructions=… other_blocks=… other_reads=… other_writes=…
```

The counters cover the complete run, including firmware and boot. Run each
workload at one size and at twice that size and use the difference between the
two runs; every fixed cost then cancels exactly, without measuring boot
separately. From the differences, form two ratios:

- work: TROE application instructions divided by Alpine's;
- rate: TROE time per application instruction divided by Alpine's.

Their product is the observed slowdown, and their split is the diagnosis. A
work ratio above one with a rate ratio near one is a code-generation
difference in the application. A work ratio near one with a rate ratio above
one is an environment difference, and the `other_instructions` ratio then says
whether the kernel is the part doing more. Matching instruction counts with
higher `user_reads` or `user_writes` indicate more memory traffic rather than
more computation.

`-icount shift=N` makes guest time proportional to instructions executed and
removes host-load noise, which is useful for regression comparisons. Confirm
that it does not disturb timeslice preemption before relying on it.

Inside TROE, `ps` and `top` report `PREEMPTS` and `YIELDS` per process. These
are lifetime counters, so their growth across two `top` snapshots is the rate
at which a process left unprivileged execution. Read them alongside
`other_instructions` when the ratios point at the environment.

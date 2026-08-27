# Comparing TROE with Alpine Linux

`cargo alpine` boots the pinned Alpine Linux 3.24.1 virtual image with the same
QEMU 11.1.0 runner record used by `cargo qemu`: the same machine type, emulated
CPU, UEFI firmware, one virtual CPU, virtio transport, and user network. Alpine's
current virtual ISO requires more than TROE's 128 MiB acceptance default, so the
comparison commands give both guests 256 MiB. The launcher attaches two distinct
writable devices: a platform-specific 8 GiB Alpine system disk and TROE's
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

## Run the four-guest matrix

Run TROE and Alpine once per architecture. Keep QEMU, firmware, host load, and
the workload bytes unchanged:

```console
cargo qemu --platform x86_64-q35-uefi --environment qemu --memory 256M
cargo alpine --platform x86_64-q35-uefi --environment qemu

cargo qemu --platform aarch64-virt-uefi --environment qemu --memory 256M
cargo alpine --platform aarch64-virt-uefi --environment qemu
```

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

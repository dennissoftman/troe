# Volume table v1

The volume table is TROE's human-editable source for the bounded BMNT v1 boot
mount manifest. `tools/mkstorage.py` compiles it into a checksummed canonical
binary installed as `EFI/BOOT/VOLUMES.BMT`. The kernel never parses TOML and
does not embed the resulting policy in its executable.

The top level contains exactly `version = 1` and one or more `[[volumes]]`
tables. Each name deterministically maps to `/vol/<name>`; arbitrary target
paths and option strings are intentionally absent.

```toml
version = 1

[[volumes]]
name = "archive"
selector = "gpt"
filesystem = "ext4-v1"
disk_guid = "11111111-2222-3333-4444-555555555555"
partition_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
filesystem_uuid = "99999999-8888-7777-6666-555555555555"
access = "read-only"
availability = "optional"
activation = "auto"
```

Supported profiles are:

- GPT ext4-v1: `disk_guid`, `partition_guid`, and `filesystem_uuid`.
- Whole-device ext4-v1: `filesystem_uuid` and no GPT identifiers.
- GPT FAT32: `disk_guid`, `partition_guid`, and an eight-hex-digit `volume_id`.

`access` is `read-only` or `read-write`. `availability` is `required` or
`optional`; a missing required entry keeps TROE in recovery mode, while a
missing optional entry is only reported. `activation` is `auto` or `manual`.
Automatic entries attach during boot. Matching manual entries remain prepared
until `mount NAME` activates them. `root` must always use `auto`.

Names contain lowercase ASCII letters, digits, and internal hyphens, are at
most 32 bytes, and become paths below `/vol`. `root` is reserved for ext4-v1
and `boot` for FAT32. At most 16 entries and 4 KiB of compiled BMNT data are
accepted. Duplicate names and duplicate stable selectors fail the build.

GPT identifiers use the usual UUID text printed by GPT tools. The compiler
performs GPT's mixed-endian on-media conversion. ext4 UUIDs use the usual
`blkid`/`tune2fs` text. FAT32 IDs are written as eight hexadecimal digits.

Compile a standalone manifest with:

```console
python3 tools/mkstorage.py \
  --volume-table path/to/volumes.toml \
  --manifest build/custom.bmnt
```

For QEMU, build with a custom table and attach one or more raw disk images:

```console
cargo qemu --volume-table path/to/volumes.toml \
  --data-disk path/to/archive.raw
```

The launcher rebuilds the boot image when `--volume-table` is supplied, so that
option cannot be combined with `--skip-build`. This recompiles BMNT and replaces
the boot file; it does not compile the policy into the kernel. To restart the
already-built image without recreating its mutable root disk, reuse the same
attached media with:

```console
cargo qemu --skip-build --data-disk path/to/archive.raw
```

Every attached filesystem is still required to match its complete configured
identity and strict provider profile. Discovery order, labels, and device names
never grant a mount role. Run `mount` to list active, ready, and unavailable
entries; run `mount NAME` for an authorized manual entry. The detailed device
topology remains available through `cat /sys/storage`.

The repository default is [`config/volumes.toml`](../../config/volumes.toml).
It contains the required generated ext4 `root` plus an optional writable FAT32
`shared` entry. `cargo qemu` creates the latter's sparse 1 GiB GPT image once,
preserves it at `build/troe-shared-fat32.img`, and attaches it on later runs.
`--reset-shared-disk` is the explicit destructive reset and `--no-shared-disk`
disables the automatic attachment. The generated QEMU root image requires the
canonical root entry; custom entries may be added alongside it.

Because this is one raw block device rather than a synchronized folder, only
one operating system may mount it writable at a time. Power TROE off before
attaching it on the host, and detach it from the host before launching QEMU.

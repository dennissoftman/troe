# Volume table v1

The volume table is TROE's human-editable source for the bounded BMNT v1 boot
mount manifest. `tools/mkstorage.py` compiles it into a checksummed canonical
binary before the kernel is built. The kernel never parses TOML.

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
missing optional entry is only reported. The first implementation accepts only
`activation = "auto"`. The field is explicit so a later preauthorized
`mount NAME` command can add `manual` without inventing a second policy format.

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

The table is compiled during the build, so `--volume-table` cannot be combined
with `--skip-build`. To restart the already-built image without recreating its
mutable root disk, reuse the same attached media with:

```console
cargo qemu --skip-build --data-disk path/to/archive.raw
```

Every attached filesystem is still required to match its complete configured
identity and strict provider profile. Discovery order, labels, and device names
never grant a mount role. Active and missing entries are reported by
`cat /sys/storage`.

The repository default is [`config/volumes.toml`](../../config/volumes.toml).
The generated QEMU root image requires that canonical root entry; custom
entries may be added alongside it.

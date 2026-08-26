# BMNT version 1

BMNT v1 is the boot-side mount manifest required to select persistent volumes
without relying on device enumeration order or mutable filesystem labels. All
integers are little-endian. The product-name-independent magic is `BMNTv1`,
followed by two zero bytes.

Humans configure this format through the strict
[`volume-table-v1`](volume-table-v1.md) TOML source. The build tooling compiles
that source into BMNT; the kernel consumes only the bounded binary form defined
here.

The complete image is at most 4 KiB and contains at most 16 entries. Its
64-byte header contains the format version, exact header and 96-byte record
sizes, exact total bytes, a CRC-32 covering the complete image with its own
field zeroed, entry count, and exact string-table bytes. Unknown flags and
nonzero reserved bytes are rejected.

Each record contains a mount name, filesystem profile, access mode,
availability policy, selector kind, and stable identifiers. A whole-device
selector is valid only for ext4 and carries its nonzero 128-bit filesystem
UUID. A GPT selector carries a nonzero GPT disk GUID, nonzero unique partition
GUID, and the filesystem identity. Ext4 identities are exact nonzero 128-bit
UUIDs. FAT32 identities encode the nonzero 32-bit volume ID in little-endian
order followed by twelve zero bytes. Labels are never selectors.

Names are tightly packed in a gapless string table and records are strictly
sorted by name. Names are 1–32 bytes and contain only lowercase ASCII letters,
digits, or `-`. The reserved names `root` and `boot` identify their fixed roles:
`root` requires the ext4 profile and `boot` requires FAT32. Other names describe
explicit `/vol/<name>` mounts. Duplicate names and duplicate selectors are
rejected.

## Header

| Offset | Bytes | Field | BMNT v1 rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `42 4d 4e 54 76 31 00 00` |
| 8 | 2 | major | 1 |
| 10 | 2 | minor | 0 |
| 12 | 2 | header bytes | 64 |
| 14 | 2 | record bytes | 96 |
| 16 | 4 | total bytes | exact input length, at most 4,096 |
| 20 | 4 | CRC-32 | complete image with bytes 20–23 zeroed |
| 24 | 2 | entry count | at most 16 |
| 26 | 2 | flags | zero |
| 28 | 4 | string bytes | exact trailing table length |
| 32 | 32 | reserved | zero |

## Entry record

| Offset | Bytes | Field | BMNT v1 rule |
| ---: | ---: | --- | --- |
| 0 | 1 | selector kind | 1 whole device, 2 GPT partition |
| 1 | 1 | filesystem profile | 1 FAT32, 2 constrained ext4 v1 |
| 2 | 1 | access mode | 1 read-only, 2 read-write |
| 3 | 1 | availability | 1 optional, 2 required |
| 4 | 4 | name offset | exact next byte in the string table |
| 8 | 2 | name bytes | 1–32 |
| 10 | 2 | selector flags | zero |
| 12 | 4 | reserved | zero |
| 16 | 16 | GPT disk GUID | nonzero for GPT, zero for whole device |
| 32 | 16 | GPT partition GUID | nonzero for GPT, zero for whole device |
| 48 | 16 | filesystem identity | canonical profile-specific identity |
| 64 | 32 | reserved | zero |

Read-write is encoded now so provisioning policy is explicit, but parsing a
manifest does not grant write authority. A later mount activator must reject a
requested mode until the selected provider, transport durability semantics,
dirty-state policy, and caller authority all permit it.

## Resolution

Discovery produces bounded candidates independently from this parser. Each
candidate has the same selector kind, filesystem profile, and complete stable
identity tuple as its manifest selector. Resolution compares every supplied
identity exactly. A single exact match selects a candidate; no match is
reported missing; multiple exact matches are ambiguous. Unmatched recognized
volumes remain discoverable but are not mounted.

A missing optional entry does not make the desired system unavailable. A
missing required entry or any ambiguous entry does. An empty manifest is the
canonical intentionally diskless configuration. Resolution is bounded to 64
discovered candidates and preserves manifest order for diagnostics and mount
activation.

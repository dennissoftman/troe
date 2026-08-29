# ADR 0056: general ext4 compatibility profile

Status: accepted and implemented, 2026-08-29. Supersedes the exact-feature and
fixed-geometry decision in ADR 0017; the mutation, journaling, and recovery
contract in ADR 0055 is unchanged and applies to every volume admitted here.

## Context

ADR 0017 pinned the provider to one exact feature set and one exact geometry:
4 KiB blocks, 32-byte group descriptors, at most 32 block groups, and byte-equal
compatible, incompatible, and read-only-compatible masks. That is precisely the
image TROE's own recipe produces and nothing else.

The consequence was measured rather than assumed. A volume produced by plain
`mke2fs -t ext4` was refused on all three masks: it carries `resize_inode`,
`dir_index` and `orphan_file`; `64bit`, `flex_bg` and `metadata_csum_seed`; and
`huge_file` and `dir_nlink`. It also uses 64-byte group descriptors, one block
group per 128 MiB, and 1 KiB blocks below roughly 512 MiB. TROE could not read
an ordinary Linux volume at all.

Refusing was safe — the provider never touched such media — but it made the
provider unusable for anything not authored by TROE.

## Decision

The provider implements ext4's own compatibility rules instead of an exact
match.

An unknown incompatible feature changes structure the provider would misread,
so the volume is refused outright. An unknown read-only-compatible feature only
changes what a writer must maintain, so the volume mounts and is readable but
can never be mutated. Compatible features are ignored, because by definition
they do not change how existing metadata is read.

The provider requires `filetype` and `extents`, because it has no block-map or
typeless-directory reader, and requires `extra_isize` and `metadata_csum`,
because it validates the extended inode area and every metadata checksum. It
additionally understands `64bit`, `flex_bg`, `metadata_csum_seed`, `huge_file`,
`dir_nlink`, `sparse_super` and `large_file`.

Geometry is read rather than assumed:

- block size 1024, 2048 or 4096, taken from `s_log_block_size`, with the
  cluster size required to agree because `bigalloc` is not implemented;
- group descriptors of 32 or 64 bytes, with the 64-byte form required whenever
  `64bit` is set;
- the checksum seed taken from `s_checksum_seed` when `metadata_csum_seed` is
  set, and derived from the UUID otherwise;
- bitmap checksums as a full 32-bit value split across their low and high
  halves whenever the descriptor is long enough to hold the high half;
- `s_first_data_block`, which is 1 at the 1 KiB block size, so the superblock
  is a whole block, the group descriptor table follows it, and bit zero of a
  block bitmap describes `s_first_data_block` rather than block zero;
- up to 8192 block groups, admitting volumes to 1 TiB at the ext4 default.

A group flagged `BLOCK_UNINIT` or `INODE_UNINIT` has never had its bitmap
written, so it holds no allocation. Allocation skips such groups entirely
rather than reading and rewriting an uninitialized bitmap. This is why an
ordinary volume, whose groups are mostly uninitialized after `mke2fs`, can be
written without first initializing it.

A hashed directory index is a per-directory property. The `dir_index` feature
only states that indexed directories may exist, so a volume carrying it stays
fully writable and only a directory whose inode sets `EXT4_INDEX_FL` is
refused, explicitly, because its interior blocks do not follow the linear
record layout this provider parses.

Free-block search stops as soon as the retained runs can satisfy the request,
so admitting large volumes does not make allocation scan a whole volume.

## Consequences

An ordinary Linux ext4 volume mounts, reads, and takes the full create,
replace, directory-create and remove surface, and `e2fsck -f -n` accepts the
result. This is proven directly rather than argued: the suite builds volumes
with `mke2fs` defaults at 64 MiB, 1 GiB and 16 GiB — covering 1 KiB and 4 KiB
blocks and 128 block groups — mutates them, and requires the independent
checker to pass.

Ownership and permissions are still not interpreted. Existing mode, UID and GID
bytes are preserved exactly, new inodes take the configured defaults, and no
raw identity gains authority. TROE has no permission system, so a volume's
access control is data, not policy.

Unsupported by design, and refused explicitly rather than misread: `bigalloc`,
`inline_data`, `encrypt`, `casefold`, `ea_inode`, `meta_bg`, `mmp`, `dirdata`,
`largedir`, and every other unknown incompatible feature. Hashed directories,
filenames beyond the VFS name ceiling, and extent trees deeper than one remain
unsupported. Backup superblocks and backup group descriptors are still never
updated, and no timestamp is written on any mutation; both remain divergences a
Linux host can observe.

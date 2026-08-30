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
- block groups across the whole 32-bit block space, admitting volumes to
  16 TiB at the 4 KiB block size. A larger volume sets `s_blocks_count_hi`,
  which the mount parser refuses rather than truncating to 32 bits.

A group flagged `BLOCK_UNINIT` or `INODE_UNINIT` has never had its bitmap
written, so it holds no allocation. Allocation skips such groups entirely
rather than reading and rewriting an uninitialized bitmap. This is why an
ordinary volume, whose groups are mostly uninitialized after `mke2fs`, can be
written without first initializing it.

A hashed directory index is walked and maintained rather than refused.
Enumeration reads the root and any interior node, collects the leaf blocks, and
parses those leaves linearly, so a name resolves without computing any hash.
Removal edits the leaf that holds the record and leaves the index describing
that same leaf, so no index rewrite is needed. Insertion computes the name's
hash with ext4's own function and admits the record only into the leaf the index
maps that hash to. A record is never placed where the index cannot find it.

A full leaf splits instead of refusing the name. Its records are redistributed
by hash into two leaves, and the separator is inserted beside the entry the walk
followed, which is what keeps every name in the leaf its own hash selects. Two
records that share a hash cannot be separated, so the split point is always a
strict hash change nearest the byte midpoint; a leaf whose records all share one
hash has no split point and the insert is refused rather than producing a leaf
the index cannot address. A parent with no room is reshaped first: a root that
still addresses leaves directly moves its entries down into one interior node
and gains a level, and a full interior node splits under a root that still has
room. Both levels full is the end of what ext4 defines here, and is refused.

Moving a directory rewrites the `..` record of the directory that moved. In an
indexed one that record shares the root block with the index, so it is located
by the layout the index fixes rather than by walking record lengths, and the
index checksum that covers it is refreshed. An indexed directory therefore
renames between parents like any other.

Names are limited by ext4 rather than by this provider: a path component may be
255 bytes and a path 1024, which the VFS and the KEX filesystem service both
carry.

Extent trees are walked and built to whatever depth the file needs, with every
interior node checksum-validated and each level bounded. The write path plans
the shallowest tree that describes the extents: leaves first, then a level of
interior nodes for as long as the top one does not fit the inode's four
records. The ceiling is not the depth ext4 permits but the per-level tree-block
bound the read path enforces, so a tree that would be unreadable is refused
before it is written rather than after. Releasing a file releases every level,
not only its leaves, and a rewrite builds the new tree beside the old one so a
failure leaves the file intact.

Timestamps advance when, and only when, the namespace has a wall clock. The
provider holds a shared handle and reads it at each mutation, so a volume
mounted at boot stamps the instant of the write rather than the instant of the
mount. A created inode carries that instant in its access, change, modification
and creation times; a later write advances the change and modification times and
leaves the access time alone. Without a clock, or when the clock reports no
time, the provider leaves every timestamp exactly as it found it rather than
inventing one. [ADR 0058](0058-provider-wall-clock-timestamps.md) records the
shared-handle decision, the encoding range, and why the final unlink zeroes the
inode record instead of setting `i_dtime`.

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
`largedir`, and every other unknown incompatible feature. Splitting a full
hashed-directory leaf, rewriting a file into an extent tree deeper than one,
and volumes beyond the 32-bit block space are all refused rather than
approximated.

Backup superblocks and backup group descriptors are not updated. This is not a
divergence: ext4 itself refreshes them from `resize2fs`, `tune2fs` and `e2fsck`
rather than from ordinary writes, and a full `e2fsck -f` does not check them,
which every mutation test here relies on.

A deep extent tree is verified at the parser rather than on a naturally
fragmented volume, because producing one requires a mounted Linux filesystem.
Hashed directories are verified end to end against indexes that `e2fsck -D`
built, including that this provider's name hash places every one of two
thousand names in exactly the leaf the on-disk index assigns it.

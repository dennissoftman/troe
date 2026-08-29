# ADR 0017: constrained ext4 profile v1

Status: accepted and implemented, 2026-08-24; amended with streamed writes and
checksummed depth-one extent leaves, 2026-08-26. The exact-feature and fixed-geometry
decision below is superseded by ADR 0056, which implements ext4's own
compatibility rules. The no-replay and external
`e2fsck` recovery statements below are superseded by ADR 0055, which journals
metadata mutations and adds a bounded recovery path; the incompatible-feature
set below is extended there with `needs_recovery`.

## Context

ADR 0009 selects a constrained ext4 provider for native persistent data but
intentionally leaves its exact first feature profile open. Accepting host
`mkfs.ext4` defaults would make the kernel's parser surface change whenever
host tooling changes. Full journal replay and general mutation also require
durability and crash-recovery work that the first storage increment does not
yet provide.

The first provider must nevertheless read useful, host-created data volumes
through the same bounded block-region and VFS interfaces as FAT32. A small
system volume mostly contains configuration, generation metadata, secrets, and
immutable content; it does not require every ext4 layout optimization.

## Decision

The `troe-fs-ext4` v1 profile is a strict, clean ext4 subset. Read-only mounts
retain the original parser contract, while a read-write block capability may
perform bounded-memory streamed mutation:

- one block device, a 4 KiB filesystem block, 256-byte inodes, 32-byte group
  descriptors, and at most 32 block groups;
- dynamic revision, a valid ext4 magic, a clean filesystem state, no pending
  journal recovery, and an internal journal inode;
- the exact compatible features `has_journal` and `ext_attr`;
- the exact incompatible features `filetype` and `extents`;
- the exact read-only-compatible features `sparse_super`, `large_file`,
  `extra_isize`, and `metadata_csum`;
- CRC32C validation of the superblock, every consumed group descriptor, inode,
  and directory block;
- regular files, directories, and symbolic links with UTF-8 names and file-type
  directory entries; special files, xattr interpretation, and ACL interpretation
  are outside the VFS surface;
- inline inode extent roots at depth zero or a checksummed depth-one root with
  at most four leaf blocks and 1,360 ordered extents; holes in regular files
  read as zero, and directories use neither holes nor unwritten extents; and
- explicit per-mount ceilings for groups, traversed inodes, directory entries,
  directory blocks, file bytes, read bytes, and name bytes.

Unknown or merely unneeded feature bits fail the mount. The provider does not
replay the journal and therefore refuses dirty media and `needs_recovery`.
Directory indexing, 64-bit block numbers, flex groups, bigalloc, inline data,
encryption, case folding, external journals, and extent trees deeper than one
level are not in v1. The volume UUID is exposed so mount policy can select a
filesystem by stable identity.

Writable mounts require flush or force-unit-access durability and implement
regular-file create/truncate/sequential append, non-directory unlink,
empty-directory creation, symbolic-link creation, and regular-file hard-link
creation. Data blocks and extent records grow incrementally from bounded caller
chunks. Allocation bitmaps, group and superblock counters, inode extents and
extent-leaf checksums, directory records, and every other affected checksum are
updated within the same bounded profile.

Symbolic-link targets are UTF-8 and at most 256 bytes. Both inline fast
symlinks and depth-zero extent-backed symlinks are accepted. Traversal follows
at most eight links, charges every restarted inode lookup to the operation
ceiling, and resolves absolute targets within the provider root; cycles and
over-budget expansion fail closed. Hard links are limited to regular files,
cannot cross providers, update only the inode link count/checksum plus the new
directory record, and preserve the shared inode's remaining metadata.

Truncating or extending a file starts from its exact existing 256-byte inode.
Only file size, the data-derived part of its allocated-sector count, extent
root/leaf records, and inode checksum may change. Any sector count belonging to
preserved metadata blocks remains accounted. Mode bits (including `0777`), raw UID/GID,
timestamps, flags, generation, inline metadata, ACL/xattr references, and all
other inode bytes are preserved. A newly created regular file has raw UID 1000,
raw GID 1000, and mode `0600`; these are storage defaults, not an authorization
decision. A newly created symbolic link uses the same UID/GID defaults and the
conventional raw mode `0777`.

Before each metadata mutation the provider clears `EXT4_VALID_FS` and flushes
it. It restores clean state only after the new chunk and its metadata are
durable. A failed multi-chunk operation can therefore leave a valid written
prefix after the last completed chunk; it does not promise rollback. Because
v1 still does not replay the journal, interruption inside a mutation requires
external `e2fsck`; dirty media fail closed rather than being accepted as a
completed transaction.

A host image for this exact profile can be created by selecting only these
features rather than relying on defaults, for example with `mke2fs -t ext4 -b
4096 -I 256 -O
none,has_journal,ext_attr,extent,filetype,sparse_super,large_file,extra_isize,metadata_csum
-E lazy_itable_init=0,lazy_journal_init=0`. The build/installer tooling must
still inspect the result and validate the produced feature bitmap exactly.

Strict release evidence formats and checks the production fixture with exactly
e2fsprogs `1.47.4` (`6-Mar-2025`). `tools/mkstorage.py` checks the complete
`mke2fs -V` and `e2fsck -V` banners in that mode. Ordinary development accepts
matching tool and library versions in the `1.47.x` feature line, while still
rejecting added wrapper output and independently validating the generated
image as described below. A strict pin change remains an on-media-format
review, not a transparent host-tool upgrade; compatible results do not replace
strict release evidence.

After formatting and the read-only `e2fsck -fn` pass, the builder independently
parses the generated bytes. It checks the fixed geometry and exact feature
masks; clean internal-journal state; CRC32C superblock, group-descriptor,
block-bitmap, inode-bitmap, inode, and directory-tail checksums; free counters
and bitmap padding; and equality between allocated blocks and the complete set
of superblock, descriptor, bitmap, inode-table, and inline-extent blocks. It
also requires zeroed unallocated inode records, rejects unsupported inode kinds,
xattrs, ACL blocks, pre-populated extent trees, directory holes, and unreachable
live inodes, and compares the complete canonical directory tree and file payloads. This
verification is deliberately independent of both e2fsck's verdict and the
kernel provider.

## Consequences

Small real ext4 data volumes can now be mounted and routed through the portable
VFS without coupling the parser to a transport, platform, shell command, or
kernel composition root. Corrupt metadata and unsupported format evolution
fail closed under deterministic memory and traversal ceilings.

The subset is intentionally narrower than general ext4. Expanding it requires
new corruption tests and an update to this versioned profile. Journal replay,
ACL authorization, xattr exposure and external-xattr final unlink, hard links
to directories or symlinks, indexed-directory mutation, directory removal/rename,
and extent trees deeper than one remain later increments. Writer
interoperability is checked by remounting and running read-only `e2fsck` after
file/directory create, replacement, and removal. An explicit stress test also
streams and samples a 128 MiB real image; a separate metadata test describes a
2 GiB file without staging its payload.

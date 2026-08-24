# ADR 0017: constrained ext4 read-only profile v1

Status: accepted and implemented, 2026-08-24.

## Context

ADR 0009 selects a constrained ext4 provider for native persistent data but
intentionally leaves its exact first feature profile open. Accepting host
`mkfs.ext4` defaults would make the kernel's parser surface change whenever
host tooling changes. Full journal replay and mutation also require durability
and crash-recovery work that the first storage increment does not yet provide.

The first provider must nevertheless read useful, host-created data volumes
through the same bounded block-region and VFS interfaces as FAT32. A small
system volume mostly contains configuration, generation metadata, secrets, and
immutable content; it does not require every ext4 layout optimization.

## Decision

The `troe-ext4` v1 profile is a strict, clean, read-only ext4 subset:

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
- regular files and directories with UTF-8 names and file-type directory
  entries; symlinks, special files, xattr interpretation, ACL interpretation,
  and mutation are outside the VFS surface for this increment;
- inline inode extent roots only (tree depth zero), at most four ordered
  extents, holes in regular files read as zero, and no holes or unwritten
  extents in directories; and
- explicit per-mount ceilings for groups, traversed inodes, directory entries,
  directory blocks, file bytes, read bytes, and name bytes.

Unknown or merely unneeded feature bits fail the mount. The provider does not
replay the journal and therefore refuses dirty media and `needs_recovery`.
Directory indexing, 64-bit block numbers, flex groups, bigalloc, inline data,
encryption, case folding, external journals, and extent-tree blocks are not in
v1. The volume UUID is exposed so mount policy can select a filesystem by
stable identity.

A host image for this exact profile can be created by selecting only these
features rather than relying on defaults, for example with `mke2fs -t ext4 -b
4096 -I 256 -O
none,has_journal,ext_attr,extent,filetype,sparse_super,large_file,extra_isize,metadata_csum
-E lazy_itable_init=0,lazy_journal_init=0`. The build/installer tooling must
still inspect the result and validate the produced feature bitmap exactly.

## Consequences

Small real ext4 data volumes can now be mounted and routed through the portable
VFS without coupling the parser to a transport, platform, shell command, or
kernel composition root. Corrupt metadata and unsupported format evolution
fail closed under deterministic memory and traversal ceilings.

The subset is intentionally narrower than general ext4. Expanding it requires
new corruption tests and an update to this versioned profile. Writable mount,
journal replay, ACL authorization, xattr exposure, indexed directories, and
deep extent trees remain later Stage 8 increments; read-only v1 does not claim
crash recovery or persistent activation.

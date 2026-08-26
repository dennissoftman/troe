# ADR 0009: persistent filesystems and lean partition discovery

Status: accepted direction, 2026-08-23; implementation scope clarified
2026-08-25. Stage 8 implements bounded block regions and GPT discovery, strict
read/write FAT32 and constrained ext4-v1 providers, BMNT-authorized read-only or
read-write activation, and separate PRGN/TXSLOT-backed activation and `StateFS`
mutation. FAT12/16, exFAT, NTFS, dynamic provider loading, journal replay, and
repair remain explicitly future work.

## Context

The current system boots from a deterministic FAT12 container, mounts embedded
read-only KEFS content, and provides a quota-bound RAMFS. Stage 8 adds persistent
operation, but the storage choices must preserve the project's auditability,
bounded-resource, recovery, identity-mapping, and capability principles.

One filesystem cannot serve every role well. The boot container, native mutable
state, removable interchange media, and foreign Windows volumes have different
trust and metadata requirements. Filesystem support also must not turn the
kernel composition root into a collection of inseparable format parsers.

## Decision

### Filesystem roles

- KEFS remains the embedded, immutable recovery and bootstrap filesystem. Its
  small built-in reader is a deliberate exception because recovery must not
  depend on persistent media or a loadable driver.
- The existing fixed FAT12 image remains the architecture-native UEFI boot
  container. Firmware reads this container; the native kernel does not need a
  general FAT12 driver merely to boot it.
- A general FAT provider targets read/write FAT12, FAT16, and FAT32 removable
  media, with FAT32 first because it covers EFI system partitions and broad
  modern interchange. The current fixed FAT12 boot-image builder remains
  independent of that runtime provider.
- exFAT is a separate optional read/write interchange provider for large
  removable media and files that exceed FAT32's practical limits. It
  complements FAT32 rather than replacing it: firmware and older systems cannot
  be assumed to boot or interoperate with exFAT.
- FAT12/16/32 and exFAT have no trustworthy per-object native identity or
  metadata journal, so mount policy supplies synthetic ownership and none is the
  default writable system store. Format checksums and exFAT's volume-dirty state
  do not provide journal transaction semantics.
- A constrained, explicitly versioned ext4 profile is the default native
  persistent data-volume format. It is selected for metadata journaling,
  extents, checksummed metadata, UID/GID and mode fields, POSIX ACLs, extended
  attributes, mature host tooling, and broad recovery interoperability. This is
  not permission to accept every ext4 feature or evolving host `mkfs` default.
- NTFS is a later optional foreign-filesystem module. The maintained Linux
  NTFS3 driver is the preferred behavioral reference, interoperability oracle,
  and potential porting source, subject to architecture and license review.
  Read-only support and lossless inspection of SIDs and security descriptors
  precede write support.

The implemented ext4-v1 provider supports metadata-preserving streamed file
mutation plus bounded symbolic/hard links when the manifest and block
capability are writable. Generation
activation and the initial named mutable state still use separately selected
TXSLOT/StateFS regions; the constrained writer does not claim journal replay,
secrets policy, or filesystem rollback. Ext4 does not replace KEFS as the
independent recovery path, and filesystem snapshots are not required for
system-generation rollback.

### Filesystem modules

The kernel owns the VFS object model, mount namespace, capability checks, and a
small block-I/O contract. FAT12/16/32, exFAT, ext4, NTFS, and future disk
formats are separate filesystem providers with explicit dependencies and
composition selection. They must not be implemented inside the machine backend
or kernel composition root. Cargo feature gates become mandatory once one
production composition can choose among multiple interchangeable providers;
the current image links its sole ext4-v1 native-root provider explicitly as a
crate dependency rather than presenting an unused feature switch as selection.

Before dynamic loading exists, a filesystem provider may be a statically
selected crate linked into a particular image. This is a composition mechanism,
not permission for ambient device access or format-specific types to escape
through the VFS. A build includes only the selected providers. Once the task,
application-loading, and service boundaries can isolate privileged I/O, writable
filesystem providers should move behind capability-scoped service interfaces so
a parser or recovery failure does not automatically become a kernel-memory
failure.

A permanently built-in disk filesystem requires a focused ADR demonstrating a
boot or recovery dependency that cannot be satisfied by KEFS and a selectable
provider. Convenience or marginal performance is not sufficient.

### Module licensing boundary

The core kernel, VFS contracts, block-region interface, and in-tree providers
remain Apache-2.0. The module architecture may also load separately packaged
providers under another declared license. Such a package must keep its source,
build artifact, SPDX identity, notices, provenance, and update lifecycle
distinct from the Apache-licensed core. No differently licensed source is
copied or mechanically translated into an Apache-licensed file.

A module boundary is useful license separation, but its name alone does not
decide whether a linked or bundled release is a combined work. In particular,
statically linking a GPL-derived provider into the EFI/kernel image is not
treated as license isolation. Separately distributed providers should use the
stable filesystem-service or module ABI, and a capability/message boundary is
preferred when available. The default Apache-2.0 system image does not bundle a
license-incompatible provider. Each release form still requires an explicit
license review; this ADR is an engineering policy, not legal advice.

References:

- [Apache-2.0 and GPL compatibility](https://www.apache.org/licenses/GPL-compatibility)
- [Linux kernel licensing rules](https://docs.kernel.org/process/license-rules.html)

Each provider must define and test:

- accepted incompatible, read-only-compatible, and optional format features;
- bounds for paths, trees, extents, attributes, ACLs, journal records, caches,
  and recovery work;
- malformed-media and checksum-failure behavior;
- flush, force-unit-access, `fsync`, directory-sync, and atomic-rename
  guarantees;
- clean, dirty, degraded, read-only, and repair-required mount states;
- identity-domain mapping and lossless raw security-metadata inspection;
- host-side creation, checking, repair, and differential-test tooling.

### Ext4 profile direction

The first ext4 profile should prefer a single device, 4 KiB blocks, an internal
journal, extents, 256-byte inodes, file-type directory entries, metadata and
journal checksums, xattrs, and POSIX ACLs. The exact feature bitmap, journal
mode, maximum volume size, directory indexing, 64-bit descriptors, and recovery
limits require a follow-up format ADR and measured implementation plan.

Initially unnecessary features should remain outside the accepted profile,
including external journals, online resize, bigalloc, inline data, encryption,
case folding, fast commits, and filesystem-level generation snapshots. Unknown
incompatible features fail the mount. An unknown read-only-compatible feature
may permit a read-only mount only when the provider can prove that every
structure it will traverse remains safely interpretable.

Metadata journaling protects filesystem structure; it does not make arbitrary
application data transactional. The generation-activation and content-store
specifications must still define exact write, flush, rename, directory-flush,
content-verification, and recovery sequences.

### exFAT scope

The exFAT provider should implement the published Microsoft on-disk
specification with explicit bounds for sector and cluster geometry, allocation
bitmaps, FAT chains, directory-entry sets, UTF-16 names, the required up-case
table, unknown benign entries, and all defined checksums. The supported end
state is normal read/write removable-media interoperability. Read-only support
precedes mutation as a validation milestone; writable support must define its
power-loss behavior and must not claim journaled durability.

The maintained Linux exFAT driver is a useful differential oracle but is
GPL-2.0-or-later code. The same source-reuse rule as NTFS3 applies: use the
published format specification and black-box interoperability tests unless a
compatible licensing decision is made, or deliver a port as a separately
licensed external module under the boundary above.

References:

- [Microsoft exFAT specification](https://learn.microsoft.com/windows/win32/fileio/exfat-specification)
- [Linux exFAT source tree](https://github.com/torvalds/linux/tree/master/fs/exfat)

### Linux filesystem reuse and NTFS licensing

Linux NTFS3 is active, read-write code with journal replay and native security
descriptor exposure. It is also GPL-2.0 code, while this repository is
Apache-2.0. Directly copying or mechanically translating that implementation is
therefore not accepted into the Apache-licensed core or providers unless a later
license decision explicitly permits it or suitably licensed upstream code is
obtained. A port may instead be delivered as a separately licensed external
filesystem module under the module-licensing boundary above.

NTFS3 may guide format understanding, test-image construction, differential
behavior, and conformance testing. A clean implementation can reuse knowledge
of the documented on-disk format without copying protected implementation text.
A separately distributed port remains responsible for its license terms and
requires its own legal, ABI, isolation, and technical review.

References:

- [Linux NTFS3 documentation](https://docs.kernel.org/filesystems/ntfs3.html)
- [Linux NTFS3 source tree](https://github.com/torvalds/linux/tree/master/fs/ntfs3)

### Lean partition discovery

Filesystem providers receive a bounded block-region capability: one device,
starting logical block, length, and supported flush/alignment properties. They
do not parse partition tables themselves and cannot access blocks outside that
region.

The first persistent-storage milestone supports:

- an unpartitioned whole-device volume for tests and deliberately simple
  deployments;
- bounded, read-only GPT discovery for installed UEFI disks;
- a fixed host-created layout consisting initially of a FAT32 EFI system
  partition and one ext4 persistent-data partition;
- lookup by validated partition type/unique identifier and filesystem UUID,
  never only by enumeration order.

GPT validation must bound the entry count and entry size, check arithmetic,
header and array checksums, device limits, overlaps, primary/backup consistency,
and duplicate identifiers. The protective MBR is recognized only as part of a
GPT disk. General MBR/extended-partition traversal, an in-kernel partition
editor, dynamic repartitioning, resizing, LVM, software RAID, and automatic
repair are deferred.

Partition creation and destructive layout changes belong in explicit host or
installer tooling with preview and recovery guidance, not in ordinary kernel
mount logic.

## Consequences

- Native persistent state has journaled metadata and permission/ACL storage
  without coupling boot recovery to a mutable filesystem.
- FAT12/16/32 and exFAT interoperability do not weaken the native identity
  model because ownership is explicitly synthetic.
- The general FAT provider remains available for EFI and legacy compatibility
  while exFAT covers large removable media without pretending to be a native
  system store.
- NTFS interoperability can grow from a maintained reference implementation,
  but source reuse cannot silently change the repository's license.
- Filesystem code remains selectable and can later become fault-isolated without
  changing the VFS-facing object model.
- The initial partition surface is sufficient for UEFI installation without
  becoming a general storage-volume manager.
- A custom native writable filesystem is deferred unless the constrained ext4
  profile proves measurably more costly or less safe than owning a new format,
  checker, repair tool, and recovery ecosystem.

## Revisit conditions

Revisit this direction if the ext4 profile cannot meet bounded-memory recovery,
if native authorization cannot be represented without ambiguous duplicate
metadata, if a target requires raw-flash wear management, if service isolation
changes the driver cost materially, or if a supported deployment requires
partition resizing, multi-device storage, or richer integrity guarantees.

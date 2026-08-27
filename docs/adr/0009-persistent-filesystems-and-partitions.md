# ADR 0009: persistent filesystems and lean partition discovery

Status: accepted and implemented for the bounded Stage 8 storage profiles,
2026-08-25.

## Context

TROE needs persistent content and mutable state without making one filesystem
format, partition enumerator, or host utility part of the kernel's ambient
authority. Provider input is untrusted, memory use must be bounded, and a
deployment must select volumes by stable identity rather than discovery order.

## Decision

The VFS consumes capability-scoped filesystem providers. Each provider owns its
format parser, exact feature profile, mutation rules, corruption behavior,
resource bounds, and tests. Filesystem type does not grant raw device access;
native block regions are explicit capabilities.

The implemented provider set is:

- KEFS v1 for immutable embedded recovery content;
- quota-bound RAMFS for volatile `/tmp` data;
- the constrained ext4 v1 profile from ADR 0017 for the default persistent
  content volume;
- strict read/write FAT32 for bounded interoperability and the shared developer
  volume; and
- StateFS for one bounded crash-consistent state object.

Foreign ownership and authorization metadata use the versioned identity objects
from ADR 0007. A provider preserves metadata it cannot interpret when its format
contract requires that behavior; it does not silently invent native authority.

Partition discovery validates protective MBR and GPT metadata with fixed entry,
size, overlap, and checksum bounds. BMNT and the volume table bind configured
roles to exact disk, partition, filesystem, and policy identities. Enumeration
order is never identity, and no in-kernel partition editor exists.

Filesystem implementations remain removable modules behind the VFS boundary.
Project code stays Apache-2.0-compatible; imported format knowledge or code must
pass the repository's dependency, provenance, and license review.

## Consequences

- Current filesystem support means only the documented versioned profiles, not
  general support for a family of formats.
- Malformed metadata fails within the provider's explicit bounds and cannot
  widen its block-region authority.
- Mount, provider, block, read, and mutation authority remain separate.
- Broader format profiles and provider isolation are not implemented. Their
  design and acceptance work is tracked in
  [GitHub issue #12](https://github.com/dennissoftman/troe/issues/12).

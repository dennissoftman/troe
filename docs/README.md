# Documentation guide

Use this page to distinguish current behavior from forward-looking design and
historical review evidence.

## Current implementation

- [Implementation roadmap](roadmap.md) is the source of truth for landed stages
  and the next kernel milestone.
- [Architecture](architecture.md) describes the current Stage 7 composition and
  its boundaries.
- [Architecture-specific notes](architecture-specific-notes.md) preserve the
  x86-64 and AArch64 interrupt, idle, and controller invariants that portable
  refactors must not erase.
- [Unsafe inventory](security/unsafe-inventory.md) records the current audited
  project-authored unsafe surface through the runnable Stage 7 increment.
- [KEFS v1](formats/kefs-v1.md) defines the implemented embedded-filesystem
  format.
- [KEX v1](formats/kex-v1.md) defines the implemented portable executable
  parser, native loader, startup layout, and complete ABI 1.0 boundary.
- [SCFG v1](formats/scfg-v1.md) defines the implemented portable desired-system
  and bounded service-startup parser for the first Stage 8 slice.
- [BMNT v1](formats/bmnt-v1.md) defines the implemented boot-side mount manifest
  and deterministic stable-identity volume resolution policy.
- [TXSLOT v1](formats/txslot-v1.md) defines the implemented four-block
  dual-slot durability transaction and predecessor recovery rules.
- [PRGN v1](formats/prgn-v1.md) defines the exact GPT identity selector that
  gates native writable authority for a TXSLOT region.
- [SACT v1](formats/sact-v1.md) defines the active and predecessor SCFG content
  references committed as a TXSLOT payload.
- [CSPK v1](formats/cspk-v1.md) defines bounded SHA-256-addressed immutable
  object packs and their verify-before-publish collection contract.
- [GMAN v1](formats/gman-v1.md) defines immutable active/predecessor generation
  roots and their bounded chain/garbage-collection traversal.

The repository root [README](../README.md), [security policy](../SECURITY.md),
[contribution guide](../CONTRIBUTING.md), and [third-party inventory](../THIRD_PARTY.md)
are also current operational documentation.

## Specifications

- [Core specification](../CORE-SPEC.md) combines implemented requirements with
  the staged kernel roadmap. Each roadmap stage is marked with its status.
- [Tooling and packaging specification](../TOOLING-PACKAGING-SPEC.md) is a
  post-MVP design. Its examples are not current commands or implemented package
  formats.

## Architecture decision records

Files under [adr](adr) preserve decisions and their context. Accepted ADRs are
not deprecated merely because their stage has completed; later implementation
notes identify decisions that were revisited. ADR 0007 now fixes the Stage 8
native-principal, foreign-identity, mapping, mount-policy, and fail-closed ACL
direction; its serialized formats remain gated before persistent writes. ADR
0009 is the accepted storage direction; its block, GPT, VFS-provider, read-only
FAT32, and first constrained ext4 slices are implemented, while mutation
remains open. [ADR 0017](adr/0017-constrained-ext4-read-only-profile.md) fixes
the exact clean read-only ext4 v1 feature bitmap and parser bounds.
[ADR 0018](adr/0018-volume-namespace-and-root-discovery.md) reserves the
`/vol/root` and `/vol/boot` roles, keeps KEFS as the diskless recovery root, and
requires deterministic root selection through the now-implemented BMNT v1
boot-side manifest and stable disk, partition, and filesystem identities.
[ADR 0019](adr/0019-bounded-virtio-block-transport.md) fixes the modern,
single-request virtio block core and the native AArch64 `virtio-mmio` and q35
virtio PCI transports, including their DMA lifetime and reset-on-timeout rules.
[ADR 0020](adr/0020-dual-slot-durability-transaction.md) fixes the first
portable writable transaction and its exact write/flush recovery contract;
strict PRGN-selected GPT media now exercise it through both native virtio
transports.
[ADR 0021](adr/0021-immutable-content-store-and-generation-rollback.md) fixes
the bounded SHA-256-addressed immutable store, predecessor retention, and
mark-and-copy garbage-collection direction.
ADR 0012 governs the completed Stage 5.1 terminal and
framebuffer increment; AArch64 native keyboard input remains a later
virtio-input transport decision. ADR 0013 governs the completed Stage 5.2
interrupt-driven input and bounded driver-resource increment.
ADR 0014 governs the completed Stage 6 unprivileged address-space,
copied-message, contained-fault, and transactional teardown boundary.
[ADR 0015](adr/0015-kex-application-abi-and-execution-bounds.md) accepts the KEX
v1 container, application ABI 1.0, profile memory ceilings, and bounded
execution-lease policy for the completed Stage 7. Portable parsing, native
owned loading, explicit handle grant, all ABI 1.0 calls, resume leases, copied
dispatch, contained call/fault fates, and zeroized teardown are implemented.
[ADR 0016](adr/0016-hardware-targets-and-emulator-role.md) separates CPU
architecture, board/platform, and emulator roles for planned Stage 7.5 physical
machine support. It retains q35 and `virt` as deterministic QEMU test profiles,
selects Raspberry Pi 4 as the first AArch64 hardware reference without limiting
other AArch64 boards, and requires a separately documented x86-64 UEFI PC.

## Evaluations

Files under [evaluations](evaluations) are point-in-time evidence. They retain
the baselines, counts, findings, and instructions that applied when written and
must not be used as live status:

- [General heap evaluation](evaluations/0001-general-heap.md) records the Stage 2
  allocator selection that remains in use.
- [Stage 3 strict security review](evaluations/0002-stage-3-strict-security-review.md)
  is archived; its remediation was finalized before Stages 4 and 5 landed.

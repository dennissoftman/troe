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
0009 is the accepted storage direction; its block, GPT, VFS-provider, and first
read-only FAT32 slices are implemented, while ext4 and mutation remain open.
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

## Evaluations

Files under [evaluations](evaluations) are point-in-time evidence. They retain
the baselines, counts, findings, and instructions that applied when written and
must not be used as live status:

- [General heap evaluation](evaluations/0001-general-heap.md) records the Stage 2
  allocator selection that remains in use.
- [Stage 3 strict security review](evaluations/0002-stage-3-strict-security-review.md)
  is archived; its remediation was finalized before Stages 4 and 5 landed.

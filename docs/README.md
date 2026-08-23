# Documentation guide

Use this page to distinguish current behavior from forward-looking design and
historical review evidence.

## Current implementation

- [Implementation roadmap](roadmap.md) is the source of truth for landed stages
  and the next kernel milestone.
- [Architecture](architecture.md) describes the current Stage 5 composition and
  its boundaries.
- [Unsafe inventory](security/unsafe-inventory.md) records the current audited
  project-authored unsafe surface through Stage 5.1.
- [KEFS v1](formats/kefs-v1.md) defines the implemented embedded-filesystem
  format.

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
notes identify decisions that were revisited. ADR 0007 remains proposed and
must be resolved before persistent security metadata or foreign-filesystem
writes. ADR 0009 is an accepted future storage direction, not implemented
filesystem support. ADR 0012 governs the completed Stage 5.1 terminal and
framebuffer increment; AArch64 native keyboard input remains a later
virtio-input transport decision. ADR 0013 governs the in-progress Stage 5.2
interrupt-driven input and bounded driver-resource increment.

## Evaluations

Files under [evaluations](evaluations) are point-in-time evidence. They retain
the baselines, counts, findings, and instructions that applied when written and
must not be used as live status:

- [General heap evaluation](evaluations/0001-general-heap.md) records the Stage 2
  allocator selection that remains in use.
- [Stage 3 strict security review](evaluations/0002-stage-3-strict-security-review.md)
  is archived; its remediation was finalized before Stages 4 and 5 landed.

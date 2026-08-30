# Documentation guide

TROE keeps current behavior, normative contracts, accepted decisions, and
current verification guidance in the repository. Work that is not implemented
belongs in the GitHub issue tracker so proposed behavior cannot be mistaken for
a current contract. Obsolete behavior and past evidence remain available in Git
history rather than in current documentation.

## Where to look

| Need | Authoritative document |
| --- | --- |
| Project overview and quick start | [Repository README](../README.md) |
| Current system composition and safety boundaries | [Architecture](architecture.md) |
| Remaining work and delivery status | [GitHub issues](https://github.com/dennissoftman/troe/issues) |
| Stage 9 production-usability work | [Stage 9 milestone](https://github.com/dennissoftman/troe/milestone/1) |
| Test commands, selection rules, native entry contract, and IPC baseline | [Testing and verification](testing.md) |
| Supported VM contracts and deployable raw artifacts | [Cloud platform support](cloud-platform-support.md) |
| Exact Cloud Hypervisor v53 Linux/KVM target and runbook | [Cloud Hypervisor production target](cloud-hypervisor-production.md) |
| Security boundary and reporting | [Security policy](../SECURITY.md) |
| Contribution and merge expectations | [Contribution guide](../CONTRIBUTING.md) |
| Core normative requirements | [Core specification](../CORE-SPEC.md) |
| Bounded KEX command scripts without nested execution | [ADR 0036](adr/0036-bounded-kex-shell-scripts.md) |
| Resident applications and shell jobs | [ADR 0037](adr/0037-resident-kex-processes-and-jobs.md) |
| Boot and on-demand service supervision | [ADR 0038](adr/0038-scfg-service-supervision.md) |
| Wall-clock discipline and SNTP synchronization | [ADR 0039](adr/0039-wall-clock-and-sntp-service.md) |
| Package-resolved directory authority | [ADR 0040](adr/0040-package-resolved-directory-capabilities.md) |
| Desired and active configuration namespaces | [ADR 0043](adr/0043-desired-and-active-configuration.md) |
| Transactional system lifecycle and migration | [ADR 0044](adr/0044-transactional-system-lifecycle.md) |
| Process registry, observation, and accounting | [ADR 0045](adr/0045-process-registry-observation-and-accounting.md) |
| Owner-scoped launch, pipes, and scalable resource tables | [ADR 0046](adr/0046-owner-scoped-process-launch-and-scalable-resource-tables.md) |
| Filesystem rename/removal and user-space POSIX facade | [ADR 0047](adr/0047-kex-filesystem-tools-and-runtime.md) |
| Capability-scoped private memory and configurable policy | [ADR 0048](adr/0048-capability-scoped-private-memory-and-resource-policy.md) |
| Kernel CSPRNG, readable random capability, and KEX ASLR | [ADR 0049](adr/0049-kernel-csprng-and-kex-aslr.md) |
| Explicit relative and absolute KEX execution paths | [ADR 0050](adr/0050-explicit-kex-path-execution.md) |
| Package-owned declarative shell completions | [ADR 0051](adr/0051-package-owned-declarative-completions.md) |
| Streamed KEX loading, shared runtime trees, and static C runtime | [ADR 0052](adr/0052-streamed-kex-and-static-c-runtime.md) |
| Session terminal input as a foreground loan | [ADR 0053](adr/0053-session-terminal-input-loan.md) |
| Launch environment composition | [ADR 0054](adr/0054-launch-environment-composition.md) |
| Journaled ext4 mutation and bounded recovery | [ADR 0055](adr/0055-journaled-ext4-mutation-and-recovery.md) |
| General ext4 compatibility profile | [ADR 0056](adr/0056-general-ext4-compatibility-profile.md) |
| Bounded shell pathname expansion and paged operands | [ADR 0057](adr/0057-bounded-shell-pathname-expansion.md) |

The current serialized contracts are versioned independently under
[`formats/`](formats):

- applications and packages: [KEX](formats/kex-v1.md),
  [KEX package](formats/kex-package-v1.md),
  [shared runtime tree](formats/runtime-tree-v2.md), [KCAP](formats/kcap-v1.md),
  and [CMPL](formats/completion-v1.md);
- process services: [process observation 1.1](formats/process-observation-v1.md) and
  [process launch and pipes 1.0](formats/process-launch-pipe-v1.md);
- KEX filesystem services: [filesystem read and mutation 1.3](formats/kex-filesystem-v1.md);
- embedded and persistent filesystems: [KEFS](formats/kefs-v1.md) and
  [StateFS](formats/stfs-v1.md);
- volume selection and durability: [BMNT](formats/bmnt-v1.md),
  [volume table](formats/volume-table-v1.md), [PRGN](formats/prgn-v1.md), and
  [TXSLOT](formats/txslot-v1.md);
- configuration and generations: [SCFG](formats/scfg-v1.md),
  [SACT](formats/sact-v1.md), [CSPK](formats/cspk-v1.md),
  [package model](formats/package-model-v1.md),
  [package trust](formats/package-trust-v1.md), and
  [configuration projection](formats/config-projection-v1.md),
  [hosted system lifecycle](formats/system-lifecycle-v1.md),
  [installation record](formats/installation-record-v1.md),
  [GMAN](formats/gman-v1.md), and
  [memory policy](formats/memory-policy-v1.md); and
- identity and authorization metadata: [identity security v1](formats/identity-v1.md).

## Document status and precedence

- Files under [`adr/`](adr) are the only documentation allowed to preserve
  historical decisions and rationale. Each ADR's status header records
  implementation or supersession state.
- Other repository documentation describes the current implementation,
  contracts, and verification only. Point-in-time results, previous limits, and
  superseded behavior belong in Git history.
- The Core Specification contains durable requirements for implemented system
  boundaries. GitHub issues carry proposed extensions and their acceptance
  criteria.

Before deleting still-useful roadmap or deferred-work direction, verify that a
live issue or milestone carries it and move it there first if necessary.

Closing an issue does not by itself make a capability current. Source, tests,
formats, and current-behavior documentation must land together before the
repository claims it.

When prose conflicts with an implemented serialized format, the versioned
format wins. When current-behavior prose conflicts with source and tests, treat
that as documentation drift and fix it rather than teaching another exception.

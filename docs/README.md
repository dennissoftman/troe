# Documentation guide

TROE keeps current behavior, normative contracts, accepted decisions, and
historical evidence in the repository. Work that is not implemented belongs in
the GitHub issue tracker so proposed behavior cannot be mistaken for a current
contract.

## Where to look

| Need | Authoritative document |
| --- | --- |
| Project overview and quick start | [Repository README](../README.md) |
| Current system composition and safety boundaries | [Architecture](architecture.md) |
| Remaining work and delivery status | [GitHub issues](https://github.com/dennissoftman/troe/issues) |
| Stage 9 production-usability work | [Stage 9 milestone](https://github.com/dennissoftman/troe/milestone/1) |
| Test commands, selection rules, native entry contract, and IPC baseline | [Testing and verification](testing.md) |
| Supported VM contracts and deployable raw artifacts | [Cloud platform support](cloud-platform-support.md) |
| Security boundary and reporting | [Security policy](../SECURITY.md) |
| Contribution and merge expectations | [Contribution guide](../CONTRIBUTING.md) |
| Core normative requirements | [Core specification](../CORE-SPEC.md) |
| Bounded KEX command scripts without nested execution | [ADR 0036](adr/0036-bounded-kex-shell-scripts.md) |
| Resident applications and shell jobs | [ADR 0037](adr/0037-resident-kex-processes-and-jobs.md) |
| Boot and on-demand service supervision | [ADR 0038](adr/0038-scfg-service-supervision.md) |
| Wall-clock discipline and SNTP synchronization | [ADR 0039](adr/0039-wall-clock-and-sntp-service.md) |

The current serialized contracts are versioned independently under
[`formats/`](formats):

- applications and packages: [KEX](formats/kex-v1.md),
  [KEX package](formats/kex-package-v1.md), and [KCAP](formats/kcap-v1.md);
- embedded and persistent filesystems: [KEFS](formats/kefs-v1.md) and
  [StateFS](formats/stfs-v1.md);
- volume selection and durability: [BMNT](formats/bmnt-v1.md),
  [volume table](formats/volume-table-v1.md), [PRGN](formats/prgn-v1.md), and
  [TXSLOT](formats/txslot-v1.md);
- configuration and generations: [SCFG](formats/scfg-v1.md),
  [SACT](formats/sact-v1.md), [CSPK](formats/cspk-v1.md), and
  [GMAN](formats/gman-v1.md); and
- identity and authorization metadata: [identity security v1](formats/identity-v1.md).

## How to interpret older material

- Files under [`adr/`](adr) preserve accepted decisions and rationale for
  implemented behavior. Each ADR's status header records implementation or
  supersession state.
- Files under [`evaluations/`](evaluations) are point-in-time evidence. Their
  measurements and findings remain useful, but their status prose is not live.
- The Core Specification contains durable requirements for implemented system
  boundaries. GitHub issues carry proposed extensions and their acceptance
  criteria.

Closing an issue does not by itself make a capability current. Source, tests,
formats, and current-behavior documentation must land together before the
repository claims it.

When prose conflicts with an implemented serialized format, the versioned
format wins. When current-behavior prose conflicts with source and tests, treat
that as documentation drift and fix it rather than teaching another exception.

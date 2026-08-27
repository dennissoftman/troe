# Documentation guide

TROE separates current behavior, normative contracts, plans, and historical
evidence so a reader does not accidentally implement an old proposal.

## Where to look

| Need | Authoritative document |
| --- | --- |
| Project overview and quick start | [Repository README](../README.md) |
| Current system composition and safety boundaries | [Architecture](architecture.md) |
| Landed stages and remaining work | [Implementation roadmap](roadmap.md) |
| Test commands, selection rules, native entry contract, and IPC baseline | [Testing and verification](testing.md) |
| Supported VM contracts and deployable raw artifacts | [Cloud platform support](cloud-platform-support.md) |
| Security boundary and reporting | [Security policy](../SECURITY.md) |
| Contribution and merge expectations | [Contribution guide](../CONTRIBUTING.md) |
| Core normative requirements | [Core specification](../CORE-SPEC.md) |
| Future package/tooling design | [Tooling and packaging specification](../TOOLING-PACKAGING-SPEC.md) |
| Proposed persistent-service and fast-IPC implementation contract | [ADR 0035](adr/0035-persistent-isolated-services-and-fast-ipc.md) |
| ADR closure state | [ADR implementation ledger](adr/implementation-status.md) |

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

- Files under [`adr/`](adr) preserve accepted decisions and rationale. They are
  not deleted when implementation lands or a later ADR narrows them. Read the
  implementation ledger for current closure and supersession state.
- Files under [`evaluations/`](evaluations) are point-in-time evidence. Their
  measurements and findings remain useful, but their status prose is not live.
- The Core Specification contains both durable requirements and staged exit
  criteria. The roadmap carries current stage status and must be updated when
  implementation changes it.
- The Tooling and Packaging Specification is explicitly forward-looking. Its
  examples are not current shell commands, public formats, or released APIs.

When prose conflicts with an implemented serialized format, the versioned
format wins. When current-behavior prose conflicts with source and tests, treat
that as documentation drift and fix it rather than teaching another exception.

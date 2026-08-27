# ADR 0042: package trust and atomic publication

Status: accepted and implemented for hosted Stage 9 package verification and
registry publication, 2026-08-27. Native generation activation consumes the
verified result separately and never treats a signature as runtime authority.

## Context

SHA-256 content identities make TPKG and generation objects deterministic and
corruption evident, but do not identify a publisher, constrain registry replay,
or state what survives a compromised builder. A single signing key would also
collapse offline policy, online publication, and build provenance into one
failure domain. Finally, replacing release files one at a time would let a
reader observe a partially published repository.

## Decision

Adopt package trust metadata v1 as specified in
[`package-trust-v1.md`](../formats/package-trust-v1.md). Ed25519 signatures are
performed and verified through OpenSSL 3 over one domain-separated canonical
payload. TROOT separates offline root, online snapshot, two-key provenance, and
per-package publisher roles. TREL requires publisher and provenance thresholds,
binds the complete package/manifest/lock/target identity, and carries a
monotonic sequence and bounded expiry. TSNP binds an exact registry generation.

Initial roots require an out-of-band payload digest. Root rotation is
consecutive and dual-authorized. Revoked or removed signing keys cannot
authorize active releases. The root may retain a bounded list of exact recovery
package digests; a release failing current activation authority or freshness
can then become only `recovery-only`, never silently active.

Registry publication stages and flushes a complete immutable generation,
independently verifies it, and atomically replaces one small current pointer.
No reader enumerates staging directories or guesses the latest directory name.
Monotonic root, snapshot, and release state is owned by the deployment
lifecycle in [ADR 0044](0044-transactional-system-lifecycle.md) rather than
hidden inside read-only verification.

## Consequences

- Content integrity, publisher identity, provenance, registry freshness,
  deployment approval, and runtime capability grants are distinct decisions.
- Offline verification has a hard seven-day release/snapshot grace and never
  extends root expiry.
- Registry or transport compromise cannot forge package bytes, while offline
  root compromise remains explicitly catastrophic for future authorization.
- Publication can leave an unreferenced complete directory after host failure;
  it cannot make a partial generation current.
- Hosted private keys are explicit file inputs. The repository stores no
  deployment key, credential, signature fixture with production authority, or
  ambient key-discovery rule.

# TROE package trust metadata v1

Package trust v1 defines Ed25519 signed envelopes, TROOT root metadata, TREL
release metadata, and TSNP registry snapshots. The hosted reference is
[`tools/package_trust.py`](../../tools/package_trust.py); the stable operator
interface is [`tools/troe_trust.py`](../../tools/troe_trust.py). OpenSSL 3 is the
reviewed cryptographic command boundary. Earlier OpenSSL/LibreSSL variants and
ambient Python cryptography packages are not accepted substitutes.

## Signed envelope and exact coverage

An envelope is canonical JSON containing exactly `schema`, `payload`, and
`signatures`. `schema` is 1. `payload` is canonical base64 of the complete
canonical metadata bytes. Signatures are unique and sorted by key identity;
each contains a lowercase SHA-256 key ID and a canonical 64-byte Ed25519
signature. A signature covers exactly:

```text
"TROE-SIGNED-METADATA-V1\0" || payload-bytes
```

The public-key ID is SHA-256 of its exact SubjectPublicKeyInfo DER. The envelope
signature array, envelope whitespace, registry pathname, filesystem metadata,
transport framing, TLS session, mirror identity, and download time are not
signed. They grant no trust. Canonical parsing, the signed payload, role
thresholds, monotonic state, exact lengths, and content digests remove their
ability to alter an accepted result.

TREL does not embed the potentially multi-megabyte package in signed metadata.
It signs the exact package byte length and SHA-256. The TPKG parser then binds
those package bytes to the PMAN manifest, PLOCK target lock, selected KEX
artifact, SDK, and toolchain. Consequently every trusted package byte is under
the signed digest; no filename, sidecar, or unrecorded byte is trusted.

## TROOT v1

TROOT contains exactly:

- schema/type, generation, issuance, expiry, and the preceding root payload
  SHA-256 (null only for generation 1);
- at most 32 sorted Ed25519 public keys;
- offline `root`, online `snapshot`, and independent `provenance` threshold
  roles;
- at most 64 sorted per-package publisher roles;
- at most 32 timestamped key revocations with nonempty reasons; and
- at most four sorted package digests permitted only as last-known recovery.

An initial root is trusted only when its payload SHA-256 matches an
out-of-band value and its own offline-root threshold verifies. Rotation must be
exactly one generation, name the previous canonical root payload, be signed by
the old root threshold, and be self-signed by the new root threshold. Skipping
a generation, changing a predecessor, or supplying only one side of the
rotation fails.

Revocation takes effect at its signed timestamp. A revoked publisher or build
attestor cannot authorize a new active release. If and only if the exact package
SHA-256 is pinned in `recovery_packages`, a previously signed release may
verify as `recovery-only`: it may boot the immutable recovery environment but
cannot be installed, published, promoted, or used as an update. Recovery still
requires the historical publisher and provenance thresholds to verify
cryptographically. A root revoking those signers retains their public keys and
role membership while revocation removes active authority. Rotation and
revocation therefore fail closed without silently making the last recovery
generation unbootable.

## TREL v1

TREL contains package name/version/target, exact package length/SHA-256,
manifest SHA-256, target-lock SHA-256, monotonic release sequence, publication
and expiry timestamps, and provenance. Provenance binds the source digest,
build-recipe digest, builder profile, and independently reproduced package
digest. The release envelope must satisfy both its per-package publisher role
and the two-key provenance threshold. A publisher cannot invent a successful
build attestation; one builder cannot publish or satisfy reproducibility.

Verification reparses TPKG and requires its target, package, manifest, and lock
identities to equal TREL. Wrong-target replay, valid metadata paired with other
package bytes, incomplete provenance, insufficient role signatures, and a
sequence older than retained client state fail closed.

## TSNP v1 and atomic publication

TSNP contains a monotonic generation, publication/expiry times, and at most 256
unique sorted `(package, version, target)` records. Each record binds the TREL
envelope and TPKG by SHA-256. It requires the online snapshot threshold.

Publication creates an immutable `generations/<20-digit-generation>` directory
containing the exact snapshot, release, and package file sets. Every file and
directory is flushed, then the staged directory is independently verified. A
single flushed `current` pointer is atomically replaced only afterward. A crash
before pointer replacement leaves the old generation authoritative. A complete
unreferenced generation may remain after a host crash; later publication skips
its number rather than treating partial state as current. Unexpected, missing,
truncated, corrupt, or extra files invalidate a generation.

## Freshness and offline policy

Root metadata must always be within its signed issuance/expiry window. Online
verification also requires unexpired TREL and TSNP. An explicitly offline
operation may accept release and snapshot metadata for at most seven days past
expiry; the requested grace is itself bounded to that ceiling. It does not
extend root expiry, bypass revocation already present in the trusted root, or
permit a sequence/snapshot generation older than retained client state. An
operator unable to refresh the root must use the pinned recovery package or
restore metadata connectivity; ordinary activation is denied.

Clients persist the largest accepted root generation, snapshot generation, and
per-package release sequence in the generation lifecycle state. Supplying those
values as minimums rejects otherwise valid replayed metadata. The trust library
does not silently create or mutate that client state.

## Compromise analysis

| Compromised component | Guarantees retained | Guarantees lost / response |
| --- | --- | --- |
| Transport or mirror | Cannot alter, cross-target, inject, or partially publish trusted bytes; can deny service or replay, bounded by retained generations/sequences. | Availability is lost; refresh from another mirror. |
| Registry/snapshot key | Cannot forge publisher or two-builder release authorization or change TPKG bytes. | Can reorder/omit already signed releases or deny service until the snapshot key is revoked and root rotated. |
| One builder | Cannot satisfy the two-key provenance threshold or publisher role. | Its attestations are revoked and builds repeated independently. |
| Both provenance builders | Cannot satisfy the package publisher role or silently widen runtime capabilities. | Can attest malicious/reproducibly colluding bytes; revoke both, rotate root, audit publisher approvals. |
| Package publisher | Cannot satisfy provenance or snapshot roles. | Can authorize an independently attested but unwanted version; revoke publisher and apply deployment allow/downgrade policy. |
| Offline root quorum | All metadata policy can be replaced for future activation. TPKG structural validation, content digests, capability/resource enforcement, and immutable recovery digest matching remain. | This is total trust-root compromise. Reprovision a new out-of-band root and inspect every newly authorized release; do not silently rotate from the compromised root. |

Runtime capability grants remain a separate activation decision. A valid
signature authenticates named bytes and policy metadata; it does not grant a
directory, network endpoint, device, secret, or deployment approval.

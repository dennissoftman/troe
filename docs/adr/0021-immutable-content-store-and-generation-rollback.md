# ADR 0021: immutable content store and generation rollback

Status: accepted for Stage 8, 2026-08-24.

Stage 8 stores executable artifacts, SCFG images, and generation manifests as
immutable objects addressed by SHA-256. A canonical CSPK v1 pack contains a
bounded, digest-sorted object table followed by gapless object bytes. The pack
has an independent whole-image CRC32 for fast corruption rejection, while every
object is verified against its SHA-256 identity before use. Duplicate digests,
unknown kinds, aliases, gaps, trailing bytes, and objects outside declared size
or count ceilings fail before returning a partial store.

The mutable SACT pointer remains outside the pack in PRGN-selected TXSLOT. It
names the active SCFG and optional predecessor by exact immutable identity.
Activation never edits an object. Construction writes and verifies a complete
new pack or append segment before publishing a new pointer. A health failure may
publish only the already-validated predecessor; the static KEFS recovery shell
remains available when neither reference resolves.

The initial implementation may consume a host-built pack through a read-only
provider. Native garbage collection is deliberately mark-and-copy rather than
in-place deletion: retain the active generation, its predecessor, and their
transitive objects within explicit object/byte ceilings; construct a new pack;
verify it completely; then atomically publish its root. Interruption leaves the
old pack and pointer usable. Reclamation of the old allocation occurs only
after the new root is durable and is never required for boot correctness.

This decision does not authorize mutable executable objects, digest-only trust,
or unbounded dependency traversal. Signatures and registry trust remain Stage 9;
Stage 8 SHA-256 identities provide integrity and deterministic deduplication,
not publisher authentication.

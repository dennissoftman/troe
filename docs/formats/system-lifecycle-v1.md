# TROE hosted system lifecycle v1

Lifecycle v1 defines the persistent hosted reference for verified install,
update, health, rollback, data migration, diagnostics, and reachability garbage
collection. Canonical JSON means UTF-8, sorted keys, no insignificant
whitespace, no duplicate fields or non-integer numbers, and one trailing
newline. Every referenced digest is lowercase SHA-256 of the exact file bytes.

## Store layout

```text
STORE/
├── desired/config.json
├── objects/{roots,releases,packages}/DIGEST.{json,tpkg}
├── generations/00000000000000000001/
│   ├── generation.json
│   └── sys-config/...
├── state/{pointer,trust,transaction}.json
├── data/PACKAGE.json
├── snapshots/GENERATION/PACKAGE.json
├── health/GENERATION.json
└── diagnostics/SEQUENCE.json
```

No lifecycle input, object, generation, or state file may be a symbolic link.
The per-store operator lock serializes writers. Files are flushed before their
directory entries; replacement state is written to a fresh file, flushed,
renamed, and followed by a directory flush.

`desired/config.json` uses the canonical projection document described below.
It changes independently of the active pointer. A generation materializes that
document as exact raw files below its private `sys-config` directory; activation
projects this complete tree at `/sys/config`.

## Configuration projection document

The document contains exactly `schema: 1` and a unique byte-lexically sorted
`files` array. Each file contains exactly `path` and canonical base64 `data`.
The path and byte ceilings are those in
[`config-projection-v1.md`](config-projection-v1.md): 128 files, 8 KiB each,
and 64 KiB total. No path can also be an ancestor of another file.

## Generation record

`generation.json` contains exactly:

- schema and a nonzero generation at or below 4096;
- the optional strictly smaller predecessor generation;
- the complete canonical PLOCK plus its SHA-256;
- the activation plan reproduced from every locked PMAN;
- one unique sorted package record per lock member, binding version, manifest,
  artifact, TPKG, signed release, and retained release sequence;
- anchored root envelope/payload identities and root generation;
- the desired projection SHA-256 and materialized `sys-config` tree;
- unique sorted package names explicitly authorized to decrease version; and
- zero to 32 canonical migration descriptors.

Independent verification reparses every TPKG, requires its embedded lock to be
the generation lock, rebuilds the plan, reparses every signed release payload,
checks every object and configuration digest, and rejects extra top-level
generation entries. Optional deep verification repeats TROOT anchoring,
signature thresholds, provenance, target, replay, and freshness checks.

## Pointer and activation states

`state/pointer.json` contains exactly `schema`, `active`, `previous`,
`recovery`, `status`, and `transaction`. Generation fields are nonzero integers
or null. Valid statuses are:

- `recovery`: no package generation is active;
- `migrating`: the candidate is selected while its durable migration intent is
  applied; predecessor services must remain quiesced;
- `pending`: candidate migration is complete and bounded health is outstanding;
- `healthy`: the candidate is committed; or
- `recovery-required`: forward-only data prevents predecessor code selection.

A complete generation is staged and verified before publication. Only then may
the pointer name it. A normal status read never resolves `pending`; the health
producer records `health/GENERATION.json` and commits or rejects it. Explicit
crash recovery consumes a durable health receipt when present. Without one it
rolls a reversible candidate back, but replays an idempotent forward-only
migration and enters `recovery-required`.

After operator repair, the same forward-only generation may submit a new passed
health receipt and commit. It cannot submit a different package generation,
select predecessor code, or erase the failed result without this explicit
recovery-state transition.

The first healthy generation becomes the retained package recovery generation.
The previous and recovery roots remain independently verified. Retained trust
state stores the greatest accepted root generation and release sequence per
package; rollback never lowers those replay floors.

## Migration descriptor and transaction

A migration contains exactly `schema: 1`, package, from/to versions, mode, and
one to 64 operations. `from_version` is null only for a newly installed package.
Mode is `reversible` or `forward-only`. An operation is either:

```json
{"op":"set","path":["schema"],"value":2}
{"op":"delete","path":["obsolete"]}
```

Paths contain one to eight canonical 64-byte keys. Package data is a canonical
JSON object capped at 64 KiB. Set creates missing object parents but refuses a
non-object parent; delete of an absent key is an idempotent no-op. The complete
result must remain within the data ceiling.

`state/transaction.json` binds an operation (`deploy` or `rollback`), one
candidate/current generation, predecessor, complete descriptor list, and sorted
applied-package set. Reversible snapshots are durable before intent publication.
Candidate selection occurs before any mutation, so old code cannot resume over
new data. Replay is safe because both operations are idempotent. Manual rollback
uses the same durable intent and migrating pointer before it restores a snapshot.

## Rollback, garbage collection, and diagnostics

Manual rollback may select only the pointer's verified predecessor. It restores
the active generation's reversible snapshots before pointer replacement.
Forward-only migration instead rejects manual rollback and leaves the compatible
healthy generation selected. A failed-health candidate whose forward-only data
is already applied enters `recovery-required`.

GC roots are active, previous, recovery, pointer transaction, and durable
migration transaction generations. Their package, release, root, snapshot, and
health objects are retained. Numeric generations and content objects outside
that closure may be deleted one at a time. An interruption can leave garbage;
it cannot remove a root.

Diagnostics contain exactly schema, monotonic sequence, code, detail, and
optional generation. Codes are canonical bounded keys, detail is at most 1 KiB,
and only the latest 64 files remain. Cleanup is restartable after interruption.

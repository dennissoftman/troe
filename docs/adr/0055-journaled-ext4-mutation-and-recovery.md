# ADR 0055: journaled ext4 mutation and bounded recovery

Status: accepted and implemented, 2026-08-29. Supersedes the no-replay and
external-`e2fsck` recovery statements in ADR 0017, and extends that profile's
incompatible-feature set with `needs_recovery`.

## Context

ADR 0017 accepted a constrained ext4 v1 profile whose writer clears
`EXT4_VALID_FS` before a metadata mutation and restores it only once the new
metadata is durable. That fails closed, but it does not recover. An
interruption inside a mutation left media that the provider refuses and that
only an external `e2fsck` could repair, so an installed system could not
complete its own recovery lifecycle.

The gap was wider than power loss. Every mutation that failed after
`begin_mutation` — a full volume, a rejected step, a device error — left the
volume permanently dirty even when the media was consistent. Interruption also
had many distinct fates rather than one. Writes were individually issued with no
ordering between them, so a torn inode-bitmap update could break the bitmap
checksum that every inode read validates and make a whole group unreadable; a
`rename` interrupted between adding the destination entry and removing the
source left two directory entries for one directory inode; `create_hard_link`
interrupted before its link-count bump left two names on an inode claiming one
link, so a later unlink freed an inode another name still used.

The profile already requires the `has_journal` compatible feature and ships an
allocated, initialized internal journal. In a shipped 16 MiB root that journal
is inode 8, one contiguous extent of 1024 blocks. It was present and unused.

## Decision

Mutations are journaled as physical block redo transactions in that existing
journal. No new on-disk structure is introduced.

A mutation stages every block it writes in memory. Reads inside the mutation see
the staged image, so the operation composes exactly as before. On success the
provider writes one descriptor block, the staged block images, and one commit
record into the log, then checkpoints the images in place, then retires the log.
Ordering is load-bearing and enforced with flushes: the log payload is durable
before the commit record, the commit record is durable before any in-place
checkpoint write is issued, the checkpoint is durable before the log head is
retired, and the head is retired before the volume is marked clean.

Because staging is in memory, a mutation that fails or is interrupted before its
commit record leaves media at its exact pre-mutation state. There is nothing to
undo. That is what makes recovery on an empty log safe rather than dangerous.

The emitted dialect is the one a feature-less JBD2 journal superblock describes:
8-byte tags, no journal checksums, no revoke records, and no 64-bit block
numbers. `mke2fs` writes exactly that superblock, and the format is the standard
one, so host `e2fsprogs` can read and replay the same log independently.

One mutation is one transaction, and a transaction is checkpointed and retired
before the next begins. At most one transaction is ever replayable. That
invariant is why the dialect needs no revoke records: a block journaled as
metadata can never be reallocated as unjournaled file data while a replay of the
older transaction is still possible. Batching mutations into one transaction, or
checkpointing lazily, would break it and require revoke records.

`EXT4_VALID_FS` and the `needs_recovery` incompatible feature are written
together in one flushed block-0 update, so the cost is exactly the previous
dirty marker. The ordinary mount refuses on either signal; a foreign Linux host
is forced to recover rather than mount half-applied metadata.

Recovery is a separate, explicitly authorized entry point. It is the only path
that may open a volume whose journal still needs replay, and it refuses a volume
that is already clean, so recovery authority is explicit at the call site and
unavailable to a caller that only holds the ordinary mount. Replay is
idempotent: it re-blits whole block images, so an interrupted recovery can be
re-run. A transaction with a valid commit record is replayed; one without is
discarded.

The transaction ceiling is 128 blocks, checked before the first staged write so
a transaction can never overflow the log after payload has reached media. The
worst admissible geometry needs far less: a shipped single-group volume touches
about sixteen blocks, and the accepted 32-group maximum about seventy-nine, of
1023 usable log blocks.

## Consequences

Interruption now has exactly two fates instead of many: a committed transaction
is replayed to the post-state, and an uncommitted one is discarded to the
pre-state. Torn checkpoint writes are healed because replay restores whole block
images. The bitmap-then-descriptor-then-superblock ordering gap disappears
because those images land together or not at all.

The in-place rewrite of an append's partial tail block is inside the
transaction, so an interrupted append can no longer leave a torn mixture of old
and new bytes in a block that was already durable.

Metadata write amplification roughly doubles, because every metadata block is
written to the log and then checkpointed, and a mutation performs about four
flushes. On the shipped volume that is roughly thirty block writes per mutation.

The mount parser now accepts `needs_recovery` only to reject it on the ordinary
path and to admit it on the recovery path; every other incompatible feature bit
still matches exactly, so an unknown bit is still refused.

Fault injection covers this contract directly. A test device models a volatile
write-back cache in which unflushed writes are unordered and lost on power loss,
and the suite interrupts every write boundary of a create and of an append,
proving each one recovers to exactly one valid state and that recovery is
idempotent. Writer interoperability is still checked against real `mke2fs` and
read-only `e2fsck`. Note that `e2fsck -fn` does not replay a pending journal, so
it cannot by itself prove replay correctness; byte-level assertions carry that
evidence.

Journal size is not yet pinned by the build tooling, and the independent
verifier asserts only that the journal superblock agrees with inode 8's length
rather than an absolute size. Pinning `-J size=` and asserting an absolute
`s_maxlen` remain follow-on work tracked in
[GitHub issue #56](https://github.com/dennissoftman/troe/issues/56).

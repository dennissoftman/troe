# ADR 0062: change and creation times, and no access time

Status: accepted and implemented, 2026-08-31. Extends
[ADR 0061](0061-readable-and-settable-modification-time.md) to the remaining
fields providers already write, and closes the question of access time.

## Context

ADR 0061 carried the modification time up through `FileMetadata` and the KEX
ABI because it is the one time every provider that stores any time stores, and
the one `touch`, `ls -l` and incremental comparison need. It deliberately left
the other three fields on the media unreachable.

Those fields are not uniform, and the uneven picture is the whole difficulty.
Measured against the code rather than against POSIX expectations:

| | ext4 | FAT32 | KEFS, RAMFS, StateFS |
| --- | --- | --- | --- |
| modification | written at birth, advanced when the payload changes | write time and date | none |
| change | written at birth, advanced on every inode write | absent from the format | none |
| creation | written at birth, never advanced | creation time plus a tenths byte | none |
| access | written at birth, **never advanced** | access date, advanced on **write**, to the day | none |

Change and creation are what they claim to be. Access is not, on either
provider, and the two are wrong in different directions: ext4's `atime` holds
the instant the inode was born, and FAT32's access date holds the day of the
last write.

## Decision

`FileMetadata` and `filesystem::Metadata` gain `changed_unix_seconds` and
`created_unix_seconds` beside the existing modification time. The metadata
reply grows from 24 to 40 bytes, each time carrying its own presence flag
because the three are independently absent, and interface 6 goes to minor 1.5.

**A provider reports absence rather than a substitute.** ADR 0058's rule that a
provider never invents an instant applies to a field the format has no room
for, not only to a clock that is not yet set. FAT32 has no change time, so it
reports `None` rather than its write or creation stamp. This keeps a caller's
comparison honest: an absent change time means "unknown", and a present one is
always a real change time, so `None` never has to be distinguished from a value
that was quietly filled in from somewhere else.

**There is no access time.** Exposing one would give a single field two
meanings, since it would be a creation instant on ext4 and a last-write day on
FAT32, and a caller could not tell which it received. Reporting a field that
never advances is worse than reporting nothing: nothing is a fact a caller can
act on, whereas a stale instant invites a false comparison.

The alternative — updating the access time on read, so it means what it says —
is the one ADR 0058 rejected on purpose, and this decision does not reopen it.
It turns every read into a write, which costs an inode write per read, defeats
the read-only mount that most of the tree runs on, and makes reading a file a
mutation for quota and wear purposes. That price buys a field nothing in the
tree reads.

ext4 keeps writing `atime` at inode birth. It is what every other ext4
implementation does, it costs nothing since the inode is being written anyway,
and leaving the field zero would be a deviation an external `e2fsck` could
notice. The field is written and simply not exposed.

`ls -l` shows the modification time unless `-c` selects the change time or `-U`
the creation time, following the BSD spelling. The column continues to appear
only when at least one listed entry has the *selected* time, so `ls -lc` on a
FAT32 mount omits the column entirely rather than printing a blank one. There
is no `-u`, and `man ls` says why.

## Consequences

Three of the four fields ext4 writes are now reachable, and the fourth is
documented as deliberately unreachable rather than merely missing. A caller
that needs to detect a rename can compare change times on ext4, which a
modification time cannot see; issue #102 tracks the separate defect that a
directory's own times do not advance when names inside it change.

The uneven per-provider picture is now visible to callers instead of hidden.
`ls -lc` is useful on `/vol/root` and shows nothing on a FAT32 volume, which is
the honest rendering of a format that has no such field.

A provider that gains a real access time later — one that tracks reads because
its medium makes that free — can be exposed by a further minor without
revisiting this decision, because absence is already per-field and per-provider
rather than a property of the ABI.

# ADR 0061: readable and settable modification time

Status: accepted and implemented, 2026-08-31. Completes the timestamp work
[ADR 0058](0058-provider-wall-clock-timestamps.md) began.

## Context

ADR 0058 gave the namespace one wall clock and made providers stamp timestamps
at each mutation. An ext4 inode created by TROE carries access, change,
modification and creation times with the epoch bits that span 1970 to 2446, and
a FAT32 entry carries a real DOS date instead of the zeroes it used to keep.
Both are proven against the tools that read the media rather than against their
own parsers.

Nothing read them back. Every layer above the media dropped them: provider
`FileMetadata` and `DirEntry` carried `kind` and `byte_count`, and so did the
KEX ABI `filesystem::Metadata`. ADR 0058 said as much twice — "nothing in this
profile reads them" — and the only readers of `WallClock::unix_seconds` in the
tree were the two providers writing stamps.

The result was good data on disk that nothing could reach. `ls -l` had no time
column because there was nothing to render, and comparing times rather than
contents — what `make`, `rsync` and incremental backup do — was impossible even
though the media recorded exactly what they needed. `touch` could not exist at
all: it could have created an empty file, but never updated one, and could not
report the field it failed to change.

## Decision

Carry the modification time up through every layer, and add one bounded
operation that sets it.

`FileMetadata` and the ABI `Metadata` reply gain `modified_unix_seconds:
Option<u64>`, whole Unix UTC seconds, matching the single representation
ADR 0058 chose for the VFS. The `filesystem` interface minor becomes 4 and its
metadata reply grows from 16 to 24 bytes.

**Modification time only.** Every provider that stores any time stores this one,
and it is the field `touch`, `ls -l` and incremental comparison use. Access,
change and creation times are uneven across formats and raise questions this
decision does not have to answer, so they are deferred to their own decision
along with the rule for a field a format has no room for.

**An absent time is `None`, and zero is absent.** A provider that stores no
timestamp reports `None`, and so does one whose record was never stamped:
ADR 0058 leaves the fields it would write exactly as it found them whenever no
wall time is known, which for a new FAT32 entry means zero. Zero is therefore
what "never stamped" looks like on the media, so it is reported as absent rather
than as 1970. The reply encodes the option as a present flag plus a value, and a
value without its flag or a flag outside its closed domain is rejected, so an
instant can never be mistaken for absence or the reverse.

`FileSystemProvider::set_modified_time(path, Option<u64>)` sets one object's
time, and the `filesystem_mutation` interface minor becomes 5 with a new
opcode. `None` requests the namespace clock's current instant, which is what
`touch` with no explicit time asks for; `Some` requests an exact one, which is
what `touch -d` asks for. Two refusals are deliberate:

- A provider that stores no timestamp keeps the trait default and refuses, so a
  caller learns the time was not recorded rather than receiving success for a
  write that could not happen.
- A request for the clock's instant while no wall time is known is refused
  rather than satisfied with a substitute, which is ADR 0058's rule that a
  provider never invents an instant, applied to an explicit caller.

`ls -l` renders `YYYY-MM-DD HH:MM` in UTC. The column appears only when at
least one listed entry has a time, so listing a provider that stores none — the
read-only root, or a quota-bound `/tmp` — reads exactly as it did before rather
than gaining a blank field. Within a listing the width is fixed, so a directory
holding both stamped and unstamped entries keeps its name column aligned.

## Consequences

Times that were already being written become usable. `ls -l` reports them, and
`touch` becomes implementable rather than a command that could only lie about
its own name.

Both interface minors change, so every committed `.kex` artifact is rebuilt.
The kernel requires an exact major *and* minor match, so a stale artifact loses
the capability silently rather than failing loudly; the 64 artifacts under
`rootfs/bin` all carry a filesystem record and all change, while the shared
corpus declares no filesystem capability and correctly does not.

FAT32 gained the exact inverse of the civil-date conversion it already had, so a
stamp written from an instant reads back as that instant to FAT's two-second
granularity. ext4 gained the reader for the epoch bits its writer already
produced, so an instant past 2038 survives the round trip rather than being
truncated on the way back.

Reading a time does not update one. ADR 0058 excluded access-time updates on
read to avoid an inode write per read, and that exclusion still holds: nothing
here advances any timestamp except the explicit set and the mutations that
already advanced them.

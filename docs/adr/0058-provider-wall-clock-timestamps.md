# ADR 0058: one namespace wall clock for provider timestamps

Status: accepted and implemented, 2026-08-30. Refines the timestamp paragraph
of ADR 0056 and adds the first filesystem consumer of the wall clock in
ADR 0039.

## Context

The kernel has held Unix wall time since ADR 0039, and the ext4 provider has
been able to stamp an inode since ADR 0056, but nothing connected the two. Every
file TROE wrote therefore carried no usable time: an ext4 inode kept whatever
its record already held, and a FAT32 entry kept the zeroes it was created with.
A zero DOS date is not an old date — its year field counts from 1980, so zero is
an encoding no calendar can express. Tools that compare times rather than
contents, such as `make`, `rsync` and incremental backup, cannot work against
either result.

Two shapes were available. A per-mutation argument would put the instant next to
the write that uses it, but `FileSystemProvider` has more than a dozen mutating
methods and every provider — including those that store no time at all — would
carry the parameter. A clock handed to a provider at `mount_writable` would cost
nothing at the trait boundary, but a value sampled at mount is the mount's own
instant, and a volume attached at boot would stamp that same instant onto every
write for the rest of the uptime.

## Decision

The namespace owns one clock and shares it as a handle, not as a value.

`WallClock` returns whole Unix UTC seconds, or `None` when no time is known.
`Namespace::set_wall_clock` stores one handle, hands it to every provider
already mounted, and hands it to every provider mounted afterwards.
`FileSystemProvider::set_wall_clock` defaults to doing nothing, so a provider
that stores no timestamps is unchanged and no mutation signature moves.

A provider reads the handle at the mutation, never at the mount. That keeps the
trait boundary the size of the mount decision while giving each write the time
it actually happened at.

The VFS carries exactly one representation — Unix UTC seconds — and each
provider converts. The VFS does not learn a per-format timestamp rule.

Three behaviours are common to every provider. Before a clock is installed, and
whenever the installed clock reports no time, the provider leaves the timestamps
it would otherwise write exactly as it found them; for a new FAT32 entry that
means its fields stay zero, which is what the provider already wrote. A clock
that steps backwards is recorded as it reads, because a provider reports the
time it was told rather than one of its own; monotonicity belongs to the clock
domain in ADR 0039, not to the media.

### ext4

A created inode carries the instant in its access, change, modification and
creation times. A later write advances the change time, and advances the
modification time when the payload changed; the access time is left alone.

A directory's own inode is stamped when it is written, which is when it gains
or loses a block, not on every entry added to or removed from a block it
already has. Advancing a directory's times on every name change would mean an
extra inode write per create, and nothing in this profile reads them.

Each time is written as its 32-bit field together with the two epoch bits of the
record's extra word, which spans 1970 to 2446. When a record declares no room
for that word the instant is clamped to 2038-01-19 instead, because the bare
field is read as signed and a later value would render as 1901.

Unlinking the final link continues to zero the whole inode record rather than
setting `i_dtime`. Nothing in this profile reads a freed record, so a deletion
time in a record whose mode and link count are already zero would preserve
nothing recoverable, and keeping it would mean retaining fields the provider
deliberately discards.

### FAT32

FAT stores local time with no timezone field. TROE has no timezone source, so
the clock's UTC reading is written unconverted and a host reads back UTC.
Inventing an offset was rejected: a wrong guess is indistinguishable on the
media from a correct one.

The fields are what FAT defines. The write time counts two-second units; the
creation entry carries the odd second in its separate tenths field; last access
is a date with no time part at all. Creation is stamped when the entry is
created and the write time on every mutation of a file's contents, and the `.`
and `..` entries of a new directory carry that directory's own stamp. A rename
moves a name and not its contents, so the destination record inherits the
source's stamps.

As on ext4, a directory's own entry is not restamped when names are added to or
removed from it; only the `.` and `..` records it was created with carry a time.
The root directory has no entry at all, so it never carries one.

The representable range is 1980-01-01 through 2107-12-31. A clock outside it is
clamped to the nearer end rather than refused, because refusing would leave the
fields zero and a zero DOS date is invalid rather than merely old.

## Verification and consequences

Both providers are proven against the host tools that read the media rather than
against their own parsers. An ext4 volume written with a clock passes
`e2fsck -f -n`, and `debugfs` decodes the stamped modification time — including
an instant past 2038, which it can only render correctly if the epoch bits were
written. A FAT32 volume written with a clock passes `fsck.vfat -n`, and `mdir`
renders the exact date and time the clock reported, which is the same decoding a
`vfat` mount performs.

Portable tests cover the absent clock, the present-but-unreadable clock, the
backwards step, and the FAT encoding at both ends of its range and outside it.

This decision adds no timezone database, no leap-second handling, no
sub-second time on ext4 beyond the fields already zeroed, and no access-time
updates on read. StateFS stores no timestamps and retains the default.

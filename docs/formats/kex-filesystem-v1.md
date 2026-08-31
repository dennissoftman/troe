# KEX filesystem interfaces 1.x

The read and mutation interfaces are independent typed KEX capabilities. All
paths are nonempty bounded UTF-8 byte strings without NUL; namespace
normalization and provider routing occur in the service.

## Filesystem read 1.4

Interface 6 retains the 1.2 open/read/close, paginated list, metadata, and
read-link operations. Minor 1.3 adds `METADATA_NO_FOLLOW` (opcode 7), which has
the same path request and metadata reply as `METADATA` but reports the final
symbolic link itself. This lets recursive user-space algorithms avoid link
cycles without exposing provider internals.

Minor 1.4 grows the metadata reply from 16 to 24 bytes to carry the last
payload modification in whole Unix UTC seconds:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 1 | node kind |
| 1 | 1 | modification time present, 0 or 1 |
| 2 | 6 | reserved, zero |
| 8 | 8 | exact file bytes, zero for a directory |
| 16 | 8 | modification time, zero when absent |

An absent time is a zero flag together with an all-zero value, so the epoch is
never a sentinel. A value without its flag, a flag outside its closed domain,
and nonzero reserved bytes are all rejected. A provider that stores no
timestamp reports absent, and so does one whose record was never stamped: a
zero on the media is what "never stamped" looks like, not 1970.

## Filesystem mutation 1.5

Interface 7 is a deliberate pre-production 1.x compatibility reset of the
briefly unreleased 2.0 streamed protocol. Its operations are:

| Opcode | Operation | Request |
| ---: | --- | --- |
| 1 | begin streamed replacement | one path |
| 2 | append sequential bytes | token, `u64` offset, bytes |
| 3 | commit replacement | token |
| 4 | abort replacement | token |
| 5 | remove file or symbolic link | one path |
| 6 | create symbolic link | two-string request |
| 7 | create hard link | two-path request |
| 8 | create empty directory | one path |
| 9 | set aggregation size | token and size |
| 10 | same-provider rename | source and destination paths |
| 11 | remove empty directory | one path |
| 12 | begin preserved append | one path |
| 13 | read staged replacement bytes | token, `u64` offset, `u32` length |
| 14 | set modification time | present flag, `u64` instant, one path |

`READ_REPLACEMENT` reads back bytes the active replacement has already staged.
Its 16-byte request is a little-endian nonzero token, `u64` offset, and nonzero
`u32` length; the reply carries only the bytes actually available. Offsets at or
beyond the staged end return an empty reply, so end of staged content is
distinguishable from failure. The service flushes its aggregation buffer before
reading, and it never exposes content the caller did not stage. Minor 1.4 adds
this operation; the interface remains an exact-minor match, so every consumer is
rebuilt when it changes.

`SET_MODIFIED_TIME` (opcode 14) sets one object's modification time. Its
request is a 16-byte header — a present flag, six reserved zero bytes, and a
little-endian `u64` instant — followed by the canonical path encoding. An absent
instant requests the namespace clock's current time; an exact instant is used as
given. The service refuses a provider that stores no timestamp, and refuses an
absent instant while no wall time is known, rather than substituting one. Minor
1.5 adds this operation.

`BEGIN_APPEND` succeeds only for an existing regular file and returns a
12-byte little-endian reply containing the nonzero token and exact initial
`u64` offset. Subsequent opcode 2 chunks must begin at that offset and remain
strictly sequential. The service does not read or duplicate the existing file;
the provider extends it in place with the same bounded aggregation policy used
by replacement writes.

The canonical two-path encoding starts with little-endian `u16` source and
destination byte lengths followed by exactly those UTF-8 bytes, with no padding
or trailing data. Each path is at most 1024 bytes and each path component at
most 255, which is ext4's own name limit; the request is at most 2052 bytes. Rename rejects existing destinations, roots, mountpoints, immutable
objects, and provider crossings. Directory removal rejects roots, mountpoints,
files, symlinks, and nonempty directories.

Stable generic reply values 21 and 22 are `NOT_EMPTY` and `CROSS_DEVICE`.
Malformed lengths, UTF-8, NUL, truncation, padding, or trailing bytes are invalid
requests and never reach a provider.

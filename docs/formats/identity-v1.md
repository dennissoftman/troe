# Identity security formats v1

Stage 8 identity state is four immutable, checksummed objects selected together
by one ISEC v1 content-store manifest. All integers are little-endian. Every
format requires major/minor `1.0`, exact total length, CRC32 coverage with the
checksum field zero, and zero reserved bytes. The `tiny` profile accepts 256
principals, 32 direct memberships per principal, 1,024 mappings, 32 ACL entries,
and 2 MiB per encoded object. The `full` profile accepts 65,536 principals, 256
direct memberships, 262,144 mappings, 256 ACL entries, and 64 MiB per object.
The `micro` profile carries none of these objects.

## IREG v1 registry

The 64-byte header is followed by fixed 64-byte principal records, a gapless
array of 16-byte group identifiers, then one gapless UTF-8 label table.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `IREGv1\0\0` |
| 8 | 2 | major 1 |
| 10 | 2 | minor 0 |
| 12 | 2 | header bytes, 64 |
| 14 | 2 | principal record bytes, 64 |
| 16 | 4 | exact total bytes |
| 20 | 4 | CRC32 |
| 24 | 4 | principal count |
| 28 | 4 | direct-membership count |
| 32 | 4 | label-table bytes |
| 36 | 8 | nonzero system generation |
| 44 | 20 | zero |

A principal record stores its nonzero opaque 16-byte ID at 0, kind/state/
compatibility-kind bytes at 16/17/18, zero at 19, compatibility `u32` at 20,
label offset/length at 24/28, membership count/start at 30/32, and zero through
64. Kinds are user, group, service, and system. States are active, disabled,
and permanent tombstone. Compatibility kinds are absent, UID, or GID and must
match a user or group record; `(kind, number)` attributes are unique but never
authorize. Records and each membership list are strictly ID-sorted. Membership
targets must exist as non-tombstoned groups. Iterative bounded expansion rejects
self-membership and cycles. Tombstones have no label or memberships.

## IMAP v1 foreign mapping snapshot

The 64-byte header contains `IMAPv1\0\0`, the common version/length/CRC fields,
128-byte record size, entry count at 24, zero at 28, nonzero version at 32,
nonzero 16-byte domain at 40, and zero through 64. Each record stores nonzero
scheme `u32` at 0, foreign kind (user/group) at 4, value length at 5, zero at
6, native target ID at 8, up to 64 exact value bytes at 24, and zero padding
through 128. Entries are strictly sorted by `(scheme, kind, value)`.

Scheme 1 is an exact four-byte POSIX UID/GID. Scheme 2 is a revision-1 Windows
SID with its six-byte authority and 0–15 little-endian subauthorities; count and
length must agree. Other nonzero schemes retain 1–64 opaque bytes and are
non-authorizing until a scheme evaluator is accepted. Every target must be an
active native user/group of the compatible kind.

## IMNT v1 mount identity policy

IMNT is exactly 192 bytes: magic/version/length at 0–13; mode at 14; the
lossless-raw-metadata boolean at 15; CRC32 at 16; role length at 20; zero to 32;
a zero-padded 32-byte canonical role at 32; optional domain at 64; mapping
version at 80; optional owner/group IDs at 88/104; signed UID/GID display shifts
at 120/128; and zero through 192. Modes are native-mapped, explicit-mapping,
shifted-view, fixed-owner, foreign-unmapped, and read-only-untrusted. Fields not
used by the selected mode must be zero. Mapping modes require the exact IMAP
domain/version; fixed-owner requires active native user/group records.

## IACL v1 native ACL

The 64-byte common header uses `IACLv1\0\0`, a 32-byte record size, and entry
count at 24. Each record stores tag at 0, `rwx` rights at 1, zero to 8, an
optional named principal at 8, and zero through 32. Canonical order is owner,
sorted named users, group object, sorted named groups, mask, other. Owner,
group-object, and other occur exactly once; named entries require exactly one
mask. Only named entries carry IDs, which must resolve to active compatible
native principals.

## Provisioning and activation

Production installers obtain each 128-bit principal/domain identifier directly
from the host operating system CSPRNG, reject zero and registry collisions, and
write a complete new immutable snapshot. The post-handoff kernel never mints a
persistent identity. Deterministic IDs `01…01`, `02…02`, and `03…03` are reserved
for acceptance fixtures and must not be emitted by deployment tooling.

ISEC v1 is an exact 192-byte object: magic/version/length at 0–15, generation at
16, registry/mapping/mount/ACL SHA-256 identities at 24/56/88/120, CRC32 at 152,
and zero through 192. GMAN flag bit 1 names the ISEC digest at 96. Activation
requires the GMAN, ISEC, all four exact CSPK kinds, matching generations, and
all cross-references to validate before SCFG activation. Failure rejects that
generation and leaves predecessor/recovery behavior in control; no name, UID,
GID, SID, or partial snapshot becomes a fallback authority.

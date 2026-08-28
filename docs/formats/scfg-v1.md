# SCFG version 1

SCFG v1 is the immutable desired-system and service-startup configuration used
by the current configuration boundary. All integers are little-endian.
The product-name-independent magic is `SCFGv1`, followed by two zero bytes.

The 144-byte header contains the format major/minor, fixed header and record
sizes, exact total bytes, a CRC-32 covering the complete image with its own
field zeroed, nonzero generation and optional predecessor identities, service
count, bounded activation attempts, recovery flags, generation health window,
and exact string-table bytes. SCFG 1.1 adds the typed memory-policy fields
defined below. Every reserved byte is zero.

The first 64 bytes retain the SCFG 1.0 generation and service-table fields.
Bytes 64 through 135 contain nine little-endian `u64` values: optional-limit
flags, minimum free pages, system application-commit maximum, default process
committed-page maximum, default process reserved-page maximum, default maximum
mapping records, default maximum metadata bytes, global metadata bytes, and VM
operation quantum pages. Bytes 136 through 143 are zero. Optional maxima are
nonzero exactly when their flag is true and zero otherwise; zero is an encoded
absence only inside SCFG and is never operator-authored policy syntax. The full
validation and TOML projection are specified by
[`memory-policy-v1.md`](memory-policy-v1.md).

The recovery-shell flag is mandatory. Previous-generation fallback is present
if and only if the predecessor identity is nonzero, and a generation cannot
name itself as predecessor. Activation attempts are limited to eight and the
health window to ten minutes.

Each 64-byte service record contains a nonzero strictly increasing service ID;
a closed startup mode and failure action; restart, initial-handle, 50 ms lease,
health, and lifetime ceilings; capability bits; up to four dependencies that
must name preceding records; canonical string offsets; and reserved-zero fields.

The SCFG v1 service capability word is a closed launcher-authority mask:

| Bit | Authority |
| ---: | --- |
| 0 | owned IPv4 datagram endpoint |
| 1 | monotonic timer and waits |
| 2 | privileged wall-clock correction |
| 3 | read-only Unix wall clock |

Every other bit is rejected. A KEX manifest must request a subset of this mask,
and its four mandatory command/stream handles plus optional capability handles
must fit the record's initial-handle ceiling. The current supervisor rejects
service manifests requesting optional interfaces not expressible by this v1
mask.

Strings form one exact, gapless, non-aliased table in record/name/artifact
order. Names contain lowercase ASCII letters, digits, `-`, or `_` and are at
most 32 bytes. Artifact paths obey the VFS 256-byte path and depth bounds. The
complete image is at most 16 KiB and contains at most 32 services.

Required services cannot silently continue after failure. Restart limits are
nonzero only for the restart action. Recovery-only services cannot select an
ordinary-generation rollback action. Boot services have nonzero health
deadlines; nonzero lifetime limits cannot precede their health deadline.

Parsing is transactional: no partial configuration is returned after any
structural, checksum, dependency, policy, string, or allocation failure.

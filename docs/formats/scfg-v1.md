# SCFG version 1

SCFG v1 is the immutable desired-system and service-startup configuration used
by the first Stage 8 configuration boundary. All integers are little-endian.
The product-name-independent magic is `SCFGv1`, followed by two zero bytes.

The 64-byte header contains the format major/minor, fixed header and record
sizes, exact total bytes, a CRC-32 covering the complete image with its own
field zeroed, nonzero generation and optional predecessor identities, service
count, bounded activation attempts, recovery flags, generation health window,
and exact string-table bytes. Every reserved byte is zero.

The recovery-shell flag is mandatory. Previous-generation fallback is present
if and only if the predecessor identity is nonzero, and a generation cannot
name itself as predecessor. Activation attempts are limited to eight and the
health window to ten minutes.

Each 64-byte service record contains a nonzero strictly increasing service ID;
a closed startup mode and failure action; restart, initial-handle, 50 ms lease,
health, and lifetime ceilings; capability bits; up to four dependencies that
must name preceding records; canonical string offsets; and reserved-zero fields.

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

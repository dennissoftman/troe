# CSPK v1 immutable content pack

CSPK v1 is a bounded immutable pack of SHA-256-addressed objects. The exact
64-byte header is followed by zero-gap 64-byte records sorted by digest, then
gapless object bytes in the same order. The initial hard profile accepts 1–64
objects, at most 1 MiB per object, and at most 4 MiB per pack.

The header carries `CSPKv1\0\0`, version 1.0, 64-byte header and record sizes,
exact total bytes, a whole-pack CRC32 at offset 20, object count at offset 24,
and zero reserved bytes through offset 64. Each record contains SHA-256 at
offset 0, object kind at 32, object offset/length at 40/44, and zero elsewhere.
Kinds are SCFG, KEX application, generation manifest, and immutable data.

Parsing verifies the whole-pack CRC, exact gapless layout, strict digest order,
unique identities, all ceilings, and every object's SHA-256 before exposing a
lookup result. Mark-and-copy rebuilding accepts an explicitly bounded root set,
deduplicates and sorts it, copies only verified objects, and produces a pack
that must parse again before publication.

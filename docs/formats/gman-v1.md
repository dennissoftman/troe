# GMAN v1 generation manifest

GMAN v1 is the exact 128-byte immutable root for one desired-system
generation. It is stored as a CSPK generation-manifest object and names one
SCFG object plus, optionally, one predecessor GMAN object by SHA-256.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `GMANv1\0\0` |
| 8 | 2 | major version, exactly 1 |
| 10 | 2 | minor version, exactly 0 |
| 12 | 2 | record bytes, exactly 128 |
| 14 | 2 | flags; bit 0 means predecessor present |
| 16 | 8 | nonzero generation |
| 24 | 32 | SCFG object SHA-256 |
| 56 | 32 | predecessor GMAN SHA-256, or zero |
| 88 | 4 | CRC32 of all 128 bytes with this field zero |
| 92 | 36 | zero |

All identities are nonzero when present. Chain resolution is bounded by an
explicit generation ceiling, rejects cycles and non-descending generation
numbers, and requires each referenced object to have its declared CSPK kind.
The active and predecessor manifests and their SCFG objects form the initial
mark-and-copy garbage-collection roots.

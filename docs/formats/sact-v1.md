# SACT v1 SCFG activation pointer

SACT v1 is the exact 64-byte payload committed through TXSLOT v1 to select one
immutable SCFG image and, optionally, one rollback predecessor. Each reference
contains the SCFG generation, exact encoded byte length, and the CRC32 stored in
that canonical SCFG header.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `SACTv1\0\0` |
| 8 | 2 | major version, exactly 1 |
| 10 | 2 | minor version, exactly 0 |
| 12 | 2 | record bytes, exactly 64 |
| 14 | 2 | flags; bit 0 means predecessor present |
| 16 | 8 | active SCFG generation |
| 24 | 4 | active SCFG byte length |
| 28 | 4 | active SCFG CRC32 |
| 32 | 8 | predecessor generation, or zero |
| 40 | 4 | predecessor byte length, or zero |
| 44 | 4 | predecessor SCFG CRC32, or zero |
| 48 | 4 | CRC32 of all 64 bytes with this field zero |
| 52 | 12 | zero |

The active generation and byte length are nonzero and bounded by the SCFG v1
profile. A present predecessor must be strictly older than the active
generation. An absent predecessor has an entirely zero reference. Resolution
requires the referenced SCFG bytes to parse canonically and reproduce all
three identity fields before activation. TXSLOT supplies atomic predecessor
selection for pointer updates; SACT does not make the referenced immutable
objects mutable.

# SACT v1 SCFG activation pointer

SACT v1 is the exact 128-byte payload committed through TXSLOT v1 to select one
immutable SCFG image and, optionally, one rollback predecessor. Each reference
contains the SCFG generation, exact encoded byte length, and the CRC32 stored in
that canonical SCFG header plus its SHA-256 content-store address.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `SACTv1\0\0` |
| 8 | 2 | major version, exactly 1 |
| 10 | 2 | minor version, exactly 0 |
| 12 | 2 | record bytes, exactly 128 |
| 14 | 2 | flags; bit 0 means predecessor present |
| 16 | 8 | active SCFG generation |
| 24 | 4 | active SCFG byte length |
| 28 | 4 | active SCFG CRC32 |
| 32 | 32 | active SCFG SHA-256 |
| 64 | 8 | predecessor generation, or zero |
| 72 | 4 | predecessor byte length, or zero |
| 76 | 4 | predecessor SCFG CRC32, or zero |
| 80 | 32 | predecessor SCFG SHA-256, or zero |
| 112 | 4 | CRC32 of all 128 bytes with this field zero |
| 116 | 12 | zero |

The active generation and byte length are nonzero and bounded by the SCFG v1
profile. A present predecessor must be strictly older than the active
generation. An absent predecessor has an entirely zero reference. Resolution
requires the referenced SCFG bytes to parse canonically and reproduce all
four identity fields before activation. TXSLOT supplies atomic predecessor
selection for pointer updates; SACT does not make the referenced immutable
objects mutable.

# STFS v1 single-file state filesystem

STFS v1 is a bounded complete-filesystem payload committed through TXSLOT v1.
It exposes a root directory and, when present, one file named `/state.bin`.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `STFSv1\0\0` |
| 8 | 2 | major version, exactly 1 |
| 10 | 2 | minor version, exactly 0 |
| 12 | 2 | header bytes, exactly 32 |
| 14 | 2 | flags; bit 0 means `/state.bin` is present |
| 16 | 4 | file payload bytes |
| 20 | 4 | CRC32 of the complete image with this field zero |
| 24 | 8 | zero |
| 32 | variable | exact file bytes |

The absent form has a zero length and no trailing bytes. The present form is
bounded by the selected TXSLOT block size minus both transaction and STFS
headers. Unknown flags, gaps, trailing bytes, checksum failure, and a valid
outer transaction containing a malformed STFS image fail closed.

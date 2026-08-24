# PRGN v1 persistence-region selector

PRGN v1 is an exact 80-byte boot-policy record that selects one GPT partition
for exclusive persistent mutation authority. Multi-byte integers are
little-endian. GUIDs use their exact 16-byte GPT field representation; no
display-string byte swapping is performed.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `PRGNv1\0\0` |
| 8 | 2 | major version, exactly 1 |
| 10 | 2 | minor version, exactly 0 |
| 12 | 2 | header bytes, exactly 80 |
| 14 | 2 | flags, exactly zero |
| 16 | 4 | total bytes, exactly 80 |
| 20 | 4 | CRC32 of all 80 bytes with this field zero |
| 24 | 16 | nonzero GPT disk GUID |
| 40 | 16 | nonzero GPT unique partition GUID |
| 56 | 16 | nonzero GPT partition-type GUID |
| 72 | 8 | zero |

CRC32 uses reflected polynomial `0xedb88320`, initial state `0xffffffff`, and a
final complement.

The selector grants no authority by parsing alone. Native discovery must first
validate consistent primary and backup GPT metadata, then find exactly one
writable, explicit-flush device whose disk GUID and partition entry match all
three identities. The selected partition must contain exactly four logical
blocks before it can be opened as [TXSLOT v1](txslot-v1.md). Missing, duplicate,
wrong-type, wrong-size, read-only, or flushless candidates fail closed.

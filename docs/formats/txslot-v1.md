# TXSLOT v1 dual-slot transaction

TXSLOT v1 occupies exactly four logical blocks in an exclusively granted
writable block region. Slot 0 uses blocks 0 and 1; slot 1 uses blocks 2 and 3.
Each slot's first block is data and its second block is the commit marker.
Multi-byte integers are little-endian. Bytes not assigned below are zero.

## Data block

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `TXDTv1\0\0` |
| 8 | 8 | nonzero generation |
| 16 | 4 | payload byte length |
| 20 | 4 | CRC32 of the complete logical block with this field zero |
| 24 | 8 | zero |
| 32 | variable | payload |
| remainder | variable | zero |

The payload maximum is the logical block size minus 32 bytes.

## Commit block

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `TXCMv1\0\0` |
| 8 | 8 | generation copied from the data block |
| 16 | 4 | data-block CRC32 copied from offset 20 |
| 20 | 4 | CRC32 of the complete commit block with this field zero |
| 24 | remainder | zero |

CRC32 uses reflected polynomial `0xedb88320`, initial state `0xffffffff`, and a
final complement.

## Commit and recovery

The writer chooses the inactive slot, writes its complete data block, flushes,
writes its complete commit block, and flushes again. It must not report the new
generation active before the second flush succeeds.

Recovery independently validates both slots. A slot is eligible only when both
blocks are canonical, both CRCs pass, and generation plus data checksum agree.
The greater generation wins. Equal eligible generations are corruption; no
generation may wrap. Zero-filled media is the canonical empty state. Invalid or
torn slots are ignored so the fully committed predecessor remains selectable.

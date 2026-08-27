# Process observation 1.0

Process observation is KEX interface 19. Opcode 1 accepts an empty request and
returns one exact 1,824-byte little-endian snapshot. The capability is
read-only; it carries no control operation.

The 32-byte header is:

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `PROCv1`, two zero bytes |
| 8 | 2 | process count | 0–16 |
| 10 | 2 | record bytes | exactly 112 |
| 12 | 4 | snapshot bytes | exactly 1,824 |
| 16 | 8 | observed milliseconds | boot-relative monotonic time |
| 24 | 8 | counter frequency | nonzero ticks per second |

Sixteen 112-byte record slots follow. Only the first `count` slots are present;
every unused byte in the fixed snapshot is zero.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | monotonic process ID, nonzero |
| 8 | 8 | internal task ID, nonzero |
| 16 | 8 | boot-relative start milliseconds |
| 24 | 8 | charged unprivileged CPU ticks |
| 32 | 8 | resident pages |
| 40 | 8 | page-table pages, nonzero |
| 48 | 8 | private pages, nonzero |
| 56 | 4 | dispatch count |
| 60 | 4 | yield count |
| 64 | 4 | preemption count |
| 68 | 2 | live handle count |
| 70 | 1 | state: 1 ready, 2 running, 3 blocked, 4 stopping |
| 71 | 1 | origin: 1 foreground, 2 background, 3 service |
| 72 | 1 | executable-name byte count, 1–32 |
| 73 | 7 | reserved, zero |
| 80 | 32 | UTF-8 executable name, zero-padded |

`resident pages` must equal the saturating sum of table and private pages.
Names never contain argv or a source path. Unknown enum values, invalid UTF-8,
nonzero padding, inconsistent counts, truncation, or trailing bytes reject the
whole snapshot.

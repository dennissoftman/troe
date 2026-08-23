# KEX v1 executable format

KEX v1 is the canonical static executable input for the Stage 7 application
loader selected by
[ADR 0015](../adr/0015-kex-application-abi-and-execution-bounds.md). The
portable application-format parser is authoritative. This document fixes its
byte representation for SDK converters and rejection-corpus tools.

All integers are unsigned little-endian values. KEX structures are decoded from
bytes and have no Rust or C in-memory-layout contract. The v1 base page size is
4,096 bytes and the statically linked image base is
`0x0000_4000_0000_0000`.

## Header

The header is exactly 64 bytes.

| Offset | Bytes | Field | KEX v1 rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `KEX`, zero, `FMT`, zero (`4b 45 58 00 46 4d 54 00`) |
| 8 | 2 | container major | 1 |
| 10 | 2 | container minor | 0 |
| 12 | 2 | target | 1 = x86-64, 2 = AArch64 |
| 14 | 2 | header bytes | 64 |
| 16 | 2 | load-record bytes | 40 |
| 18 | 2 | ABI major | 1 |
| 20 | 2 | minimum ABI minor | at most the kernel-supported minor; initially 0 |
| 22 | 2 | flags | zero |
| 24 | 8 | entry offset | image-relative byte inside an RX segment |
| 32 | 2 | load-record count | bounded, nonzero |
| 34 | 2 | reserved | zero |
| 36 | 4 | initial stack pages | within the selected profile range |
| 40 | 4 | zeroed heap pages | within the selected profile ceiling |
| 44 | 4 | load-record offset | 64 |
| 48 | 4 | payload offset | `64 + record_count * 40` |
| 52 | 4 | reserved | zero |
| 56 | 8 | artifact bytes | exact input length |

Header sizes and offsets are exact canonical values, not forward-extension
fields. Unknown container versions, targets, flags, and ABI requirements are
rejected. The magic identifies KEX itself and deliberately contains no product,
repository, or vendor name.

## Load records

Each 40-byte record has this layout:

| Offset | Bytes | Field | KEX v1 rule |
| ---: | ---: | --- | --- |
| 0 | 8 | image offset | 4 KiB aligned, relative to the fixed image base |
| 8 | 8 | file offset | exact next byte in the canonical payload stream |
| 16 | 8 | file bytes | at most `memory bytes` |
| 24 | 8 | memory bytes | nonzero multiple of 4 KiB |
| 32 | 4 | permissions | 1 = R, 2 = RX, 3 = RW |
| 36 | 4 | reserved | zero |

Records are strictly ordered by image offset and their mapped page ranges do
not overlap. Gaps in virtual space are permitted only within the selected
profile's image-span ceiling; they remain unmapped. Writable-executable and
execute-only encodings do not exist.

File payloads are tightly concatenated in record order beginning at the header's
payload offset. A zero-length payload uses the current file offset and advances
it by zero. The final payload ends exactly at `artifact bytes`; gaps, duplicate
descriptions, and trailing bytes are noncanonical. Each segment's remaining
`memory bytes - file bytes` are zero-filled in fresh frames.

At least one segment is RX, and the single entry byte must fall within an RX
segment. The loader verifies all header, table, file, image, fixed-base, page,
and profile arithmetic before allocating or mapping application memory.

## Profile ceilings

| Limit | `micro` | `tiny` | `full` |
| --- | ---: | ---: | ---: |
| Encoded bytes | disabled | 512 KiB | 16 MiB |
| Load records | disabled | 8 | 16 |
| Image span | disabled | 4 MiB | 128 MiB |
| Mapped image pages | disabled | 256 | 8,192 |
| Stack pages | disabled | 4–16 | 4–256 |
| Heap pages | disabled | 0–64 | 0–4,096 |
| Page-table pages | disabled | 64 | 512 |
| Resident pages | disabled | 512 | 16,384 |

The preliminary portable plan charges exact image, startup, heap, and stack
pages plus the profile's complete page-table ceiling. Native table construction
may refine that reservation downward but may not exceed either the table or
aggregate resident ceiling.

## ABI 1.0 virtual layout and startup page

The portable plan fixes the non-image virtual regions so every native backend
consumes identical checked address arithmetic. The startup page begins at
`image base + profile image-span ceiling`. The heap slot follows it and reserves
the profile's maximum heap span in virtual space, although only the requested
prefix is mapped. One unmapped lower guard follows the heap slot. The fixed
maximum stack slot follows that guard; the requested stack pages are mapped at
the top of the slot so they end immediately before an unmapped upper guard.
All unused heap and stack-slot pages remain unmapped.

The startup page is 4 KiB, little-endian, and zero-padded. Its fixed header is
64 bytes:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | encoded bytes: `64 + handle_count * 24` |
| 4 | 2 | ABI major, 1 |
| 6 | 2 | ABI minor, 0 |
| 8 | 4 | page bytes, 4,096 |
| 12 | 2 | resource profile: 1 micro, 2 tiny, 3 full |
| 14 | 2 | initial handle count |
| 16 | 8 | image base |
| 24 | 8 | heap base |
| 32 | 8 | mapped heap bytes |
| 40 | 8 | mapped stack bottom |
| 48 | 8 | mapped stack top / initial stack pointer |
| 56 | 8 | monotonic nonzero task identity |

Each 24-byte initial handle descriptor then contains an opaque handle value
(`u64`), rights bits (`u32`), interface identifier (`u32`), interface major and
minor (`u16` each), and four reserved zero bytes. Values must be nonzero and
unique within the page. Handle count cannot exceed the selected profile. The
kernel validates the complete descriptor set before clearing and encoding the
destination, so rejection cannot leave a partial startup record.

## Deliberate omissions

KEX v1 carries no sections, symbols, interpreter, dynamic metadata, imports,
exports, relocations, TLS, compression, capabilities, signatures, device
mappings, or shared-memory contract. A hosted converter must apply link-time
relocations for the fixed image base and reject any residual runtime requirement
before emitting KEX. Future package identity and trust metadata wrap KEX rather
than changing this executable parser implicitly.

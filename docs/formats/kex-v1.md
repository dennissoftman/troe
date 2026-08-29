# KEX v1 executable format

KEX v1 is the canonical static executable input for the application loader selected by
[ADR 0015](../adr/0015-kex-application-abi-and-execution-bounds.md). The
portable application-format parser is authoritative. This document fixes its
byte representation for SDK converters and rejection-corpus tools. Installed
commands carry this executable inside the
[KEX package v1](kex-package-v1.md) single-file envelope.

All integers are unsigned little-endian values. KEX structures are decoded from
bytes and have no Rust or C in-memory-layout contract. The v1 base page size is
4,096 bytes. Container 1.1 images are position-independent and use
image-relative addresses; `0x0000_4000_0000_0000` is only the deterministic
hosted inspection placement.

## Header

The container-1.1 header is exactly 88 bytes.

| Offset | Bytes | Field | KEX v1 rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `KEX`, zero, `FMT`, zero (`4b 45 58 00 46 4d 54 00`) |
| 8 | 2 | container major | 1 |
| 10 | 2 | container minor | 1 |
| 12 | 2 | target | 1 = x86-64, 2 = AArch64 |
| 14 | 2 | header bytes | 88 |
| 16 | 2 | load-record bytes | 40 |
| 18 | 2 | ABI major | 1 |
| 20 | 2 | minimum ABI minor | at most the kernel-supported minor; currently 1 |
| 22 | 2 | flags | zero |
| 24 | 8 | entry offset | image-relative byte inside an RX segment |
| 32 | 2 | load-record count | bounded, nonzero |
| 34 | 2 | reserved | zero |
| 36 | 4 | reserved | zero |
| 40 | 8 | initial stack pages | within the standard range |
| 48 | 8 | zeroed heap pages | within the standard ceiling |
| 56 | 4 | load-record offset | 88 |
| 60 | 4 | payload offset | exact byte after the relocation table |
| 64 | 4 | relocation-table offset | `88 + record_count * 40` |
| 68 | 4 | relocation count | bounded by exact artifact layout |
| 72 | 2 | relocation-record bytes | 16 |
| 74 | 2 | reserved | zero |
| 76 | 4 | reserved | zero |
| 80 | 8 | artifact bytes | exact input length |

Header sizes and offsets are exact canonical values, not forward-extension
fields. Unknown container versions, targets, flags, and ABI requirements are
rejected. The magic identifies KEX itself and deliberately contains no product,
repository, or vendor name.

## Load records

Each 40-byte record has this layout:

| Offset | Bytes | Field | KEX v1 rule |
| ---: | ---: | --- | --- |
| 0 | 8 | image offset | 4 KiB aligned, relative to the selected image base |
| 8 | 8 | file offset | exact next byte in the canonical payload stream |
| 16 | 8 | file bytes | at most `memory bytes` |
| 24 | 8 | memory bytes | nonzero multiple of 4 KiB |
| 32 | 4 | permissions | 1 = R, 2 = RX, 3 = RW |
| 36 | 4 | reserved | zero |

Records are strictly ordered by image offset and their mapped page ranges do
not overlap. Gaps in virtual space are permitted only within the standard
image-span ceiling; they remain unmapped. Writable-executable and
execute-only encodings do not exist.

The load-record table is followed by sorted 16-byte relative-relocation records.
Each contains an image-relative data target offset and an image-relative value
offset. Each eight-byte target span is unique, ordered by byte offset, wholly
inside one mapped image segment, and its value lies inside the image span. The
byte offset itself may be unaligned because Rust target libraries can place
pointer constants in packed read-only data and, on some targets, instruction
literals. This permits position-independent prebuilt `core`/`alloc` without a
custom sysroot. The loader patches fresh owned backing before installing the
final RX/R/RW mappings, so no executable or read-only runtime page is ever
temporarily writable and no writable-executable alias exists. No symbol,
import, or general relocation kind is representable.

File payloads are tightly concatenated in record order beginning at the header's
payload offset. A zero-length payload uses the current file offset and advances
it by zero. The final payload ends exactly at `artifact bytes`; gaps, duplicate
descriptions, and trailing bytes are noncanonical. Each segment's remaining
`memory bytes - file bytes` are zero-filled in fresh frames.

At least one segment is RX, and the single entry byte must fall within an RX
segment. The loader verifies all header, table, file, image, placement, page,
and standard-policy arithmetic before allocating or mapping application memory.

## Standard ceilings

| Limit | Standard |
| --- | ---: |
| Encoded bytes | 32 MiB |
| Load records | 16 |
| Image span | 128 MiB |
| Mapped image pages | 8,192 |
| Stack pages | 4–4,294,967,296 (16 TiB) |
| Heap pages | 0–4,294,967,296 (16 TiB) |
| Conservative format table charge | 512 pages |
| Initial resident admission | 8,589,943,297 pages |

The preliminary portable plan charges exact image, startup, initial heap, and
stack pages plus a conservative table amount for format admission. Native
launch computes and retains the exact tables implied by the complete mapping
plan. Physical availability, the active 64-bit memory policy, and the protected
free-frame reserve decide whether a valid large request is admitted; no maximum
table is preallocated. ABI 1.1 heap growth and private mappings use the same
system/process commitment accounting.

## Hosted ELF input contract

`tools/troe-kex-tool` is the canonical dependency-free Rust converter. Its
input is a final, statically linked, position-independent little-endian System V
ELF64 `ET_DYN` for x86-64 or AArch64 linked at virtual base zero. Program headers begin at byte 64
and use 56-byte records. `PT_LOAD` records use 4 KiB-aligned file and virtual
addresses, are ordered and page-disjoint, and request only R, RX, or RW. The
entry is file-backed RX (and four-byte aligned on AArch64). A consistent
read-only `PT_PHDR` and a non-executable GNU stack record are the only other
accepted program types.

The SDK linker resolves symbols and emits only `R_X86_64_RELATIVE` or
`R_AARCH64_RELATIVE` dynamic relocations, including data relocations needed by
the target's prebuilt Rust `core`/`alloc`. The converter requires one canonical
writable `PT_DYNAMIC`, converts those records into the closed KEX relocation
table, sorts unique in-image targets canonically, and rejects imports,
symbol-based relocations, `REL`, `RELR`, negative or out-of-image addends, and
every unknown kind. It also rejects interpreters, TLS,
notes, GNU properties, unwind-header/RELRO requirements, unknown program
records, W+X, noncanonical section metadata, and unexplained nonzero bytes. An
optional section table is validation input only and is never copied as KEX metadata. After conversion,
an independent KEX decoder compares every emitted record and payload with the
validated loads and rechecks canonical layout and exact standard budgets.

Create or verify an artifact with:

```console
cargo kex convert app.elf app.kex --target x86_64
cargo kex convert app.elf app.kex --target x86_64 --check
```

`tools/elf2kex.py` remains an independent parity and rejection oracle; it is not
the build entrypoint.

The shared generated corpus lives under `tests/kex-corpus`; its exact file set
and bytes are checked with `python3 tools/gen_kex_corpus.py --check`.

## ABI 1.1 randomized virtual layout and startup page

The kernel draws an independently randomized 2 MiB-aligned image base from the
4 GiB–64 TiB window and a 2 MiB-aligned stack placement from the 96–128 TiB
window. Placement uses the kernel CSPRNG and fails closed if firmware entropy
was unavailable at boot. The startup page begins at `selected image base +
standard image-span ceiling`. For an application requiring ABI
minor 1, the heap follows it and may grow through the otherwise unused user
virtual-address gap. A lower guard and the fixed maximum stack slot are placed
at the top of the user half; the requested stack pages are mapped at the top of
that slot so they end immediately before an unmapped upper guard. All
uncommitted heap-gap and unused stack-slot pages remain unmapped and consume no
physical frames. ABI-minor-0 artifacts retain their adjacent guarded-stack
layout selected by the startup page; no pre-release artifact may assume a
literal virtual address.

The startup page is 4 KiB, little-endian, and zero-padded. Its fixed header is
64 bytes:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | encoded bytes: `64 + handle_count * 24` |
| 4 | 2 | ABI major, 1 |
| 6 | 2 | negotiated ABI minor selected for this application |
| 8 | 4 | page bytes, 4,096 |
| 12 | 2 | reserved, zero |
| 14 | 2 | initial handle count |
| 16 | 8 | image base |
| 24 | 8 | heap base |
| 32 | 8 | initially mapped heap bytes |
| 40 | 8 | mapped stack bottom |
| 48 | 8 | mapped stack top / initial stack pointer |
| 56 | 8 | monotonic nonzero task identity |

Each 24-byte initial handle descriptor then contains an opaque handle value
(`u64`), rights bits (`u32`), interface identifier (`u32`), interface major and
minor (`u16` each), and four reserved zero bytes. Values must be nonzero and
unique within the page. Handle count cannot exceed the standard ceiling. The
kernel validates the complete descriptor set before clearing and encoding the
destination, so rejection cannot leave a partial startup record.

ABI call 3 may grow the mapped heap prefix without moving its base. Each
successful request commits actual zeroed frames and any supplemental page-table
frames; physical backing may be non-contiguous. Ordinary exhaustion leaves the
mapping unchanged. There is no format-level lifetime heap-byte ceiling other
than the remaining v1 user virtual range; on the current no-swap system,
available physical memory is the practical bound.

## Deliberate omissions

KEX v1 carries no sections, symbols, interpreter, imports, exports, general
dynamic linking, TLS, compression, capabilities, signatures, device mappings,
or shared-memory contract. Its relative relocation table is deliberately only
the load-time mechanism needed for ASLR. Future package identity and trust
metadata wrap KEX rather than changing this executable parser implicitly.

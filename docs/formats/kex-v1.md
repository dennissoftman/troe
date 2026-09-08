# KEX v1 executable format

KEX v1 is the canonical static executable input for the application loader selected by
[ADR 0015](../adr/0015-kex-application-abi-and-execution-bounds.md). The
portable application-format parser is authoritative. This document fixes its
byte representation for SDK converters and rejection-corpus tools. Installed
commands carry this executable inside the
[KEX package v1](kex-package-v1.md) single-file envelope.

All integers are unsigned little-endian values. KEX structures are decoded from
bytes and have no Rust or C in-memory-layout contract. The v1 base page size is
4,096 bytes. Container 1.2 images are position-independent and use
image-relative addresses; `0x0000_4000_0000_0000` is only the deterministic
hosted inspection placement.

## Header

The container-1.2 header is exactly 96 bytes.

| Offset | Bytes | Field | KEX v1 rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `KEX`, zero, `FMT`, zero (`4b 45 58 00 46 4d 54 00`) |
| 8 | 2 | container major | 1 |
| 10 | 2 | container minor | 2 |
| 12 | 2 | target | 1 = x86-64, 2 = AArch64 |
| 14 | 2 | header bytes | 96 |
| 16 | 2 | load-record bytes | 40 |
| 18 | 2 | ABI major | 1 |
| 20 | 2 | minimum ABI minor | at most the kernel-supported minor; currently 2 |
| 22 | 2 | flags | zero |
| 24 | 8 | entry offset | image-relative byte inside an RX segment |
| 32 | 2 | load-record count | bounded, nonzero |
| 34 | 2 | reserved | zero |
| 36 | 4 | image span pages | ABI minor 2 and above; reserved zero below |
| 40 | 8 | initial stack pages | within the standard range |
| 48 | 8 | zeroed heap pages | within the standard ceiling |
| 56 | 4 | load-record offset | 96 |
| 60 | 4 | payload offset | exact byte after the relocation table |
| 64 | 4 | relocation-table offset | `96 + record_count * 40` |
| 68 | 4 | relocation count | bounded by exact artifact layout |
| 72 | 2 | relocation-record bytes | 16 |
| 74 | 2 | reserved | zero |
| 76 | 4 | reserved | zero |
| 80 | 8 | artifact bytes | exact input length |
| 88 | 8 | reserved | zero |

Flag bit 0 is reserved for a block-mappable image and bit 1 for a TLS template.
Both are unimplemented reservations: the loader requires all flags to be zero.

Header sizes and offsets are exact canonical assertions. Reserved fields must
be zero; they do not permit implicit extension. Unknown container versions,
targets, flags, and ABI requirements are rejected. The magic identifies KEX itself and deliberately contains no product,
repository, or vendor name.

## Load records

Each 40-byte record has this layout:

| Offset | Bytes | Field | KEX v1 rule |
| ---: | ---: | --- | --- |
| 0 | 8 | image offset | 4 KiB aligned, relative to the selected image base |
| 8 | 8 | file offset | exact next byte in the canonical payload stream |
| 16 | 8 | file bytes | at most `memory bytes` |
| 24 | 8 | memory bytes | nonzero multiple of 4 KiB |
| 32 | 4 | permissions | 1 = R, 2 = RX, 3 = RW; 4 reserved for a TLS template and rejected |
| 36 | 4 | reserved | zero |

Records are strictly ordered by image offset and their mapped page ranges do
not overlap. Gaps in virtual space are permitted only within the declared image
span; they remain unmapped. Writable-executable and
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
| Encoded bytes | 2 GiB |
| Load records | 16 |
| Declared image span | 2 MiB–1 GiB, exactly the rounded image end |
| Mapped image pages | bounded by the declared span |
| Stack pages | 4–4,294,967,296 (16 TiB) |
| Heap pages | 0–4,294,967,296 (16 TiB) |
| Conservative format table charge | derived from the mapped layout |
| Initial resident admission | maximum private pages plus their table bound |
| Initial handles | 167 for ABI 1.3; 168 for ABI 1.0–1.2 |

An ABI-minor-2-or-newer artifact declares its own image span as a page count. The span
is nonzero, 2 MiB-aligned, within the standard maximum, and exactly the image
end rounded up to that alignment, so it bounds the mapped image without a
separate page ceiling and reserves no address space the artifact never maps.
ABI minor 0 and 1 artifacts leave the field zero and take the fixed 128 MiB
implied span.

The preliminary portable plan charges exact image, startup, private IPC (ABI 1.3), initial heap, and
stack pages plus a table amount derived from that layout. Native launch
computes and retains the exact tables implied by the complete mapping plan.
Physical availability, the active 64-bit memory policy, and the protected
free-frame reserve decide whether a valid large request is admitted; no maximum
table is preallocated. Launch zeroing is bounded by the configured operation
quantum. Heap growth and private mappings use the same system/process
commitment accounting.

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

## ABI 1.0–1.3 virtual layout and startup region

The kernel draws an independently randomized 2 MiB-aligned image base from the
4 GiB–64 TiB window and a 2 MiB-aligned stack placement from the 96–128 TiB
window. Placement uses the kernel CSPRNG and fails closed if firmware entropy
was unavailable at boot. The startup region begins at `selected image base +
declared image span`. For an application requiring ABI
minor 1 or above, the heap follows the startup and any private IPC pages and may grow through the otherwise unused user
virtual-address gap. A lower guard and the fixed maximum stack slot are placed
at the top of the user half; the requested stack pages are mapped at the top of
that slot so they end immediately before an unmapped upper guard. All
uncommitted heap-gap and unused stack-slot pages remain unmapped and consume no
physical frames. ABI-minor-0 artifacts retain their adjacent guarded-stack
layout selected by the startup record; no pre-release artifact may assume a
literal virtual address.

The immutable startup region is `troe_abi::startup::REGION_PAGES` pages
(currently one 4 KiB page), little-endian, and zero-padded. Entry receives both
its address and mapped byte count. The SDK accepts page-multiple lengths from
64 bytes through `REGION_BYTES` and derives the image span from
`heap_base - mapped_startup_bytes - ipc_bytes - image_base`. Here `ipc_bytes`
is 8,192 for ABI 1.3 and zero for ABI 1.0–1.2. The fixed prefix is 80 bytes
for ABI 1.3 and 64 bytes for ABI 1.0–1.2:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | encoded bytes: `header_bytes(minor) + handle_count * 24` |
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
| 64 | 8 | ABI 1.3 only: private TX virtual address |
| 72 | 8 | ABI 1.3 only: private RX virtual address |

Each 24-byte initial handle descriptor then contains an opaque handle value
(`u64`), rights bits (`u32`), interface identifier (`u32`), interface major and
minor (`u16` each), and four reserved zero bytes. Values must be nonzero and
unique within the region. The shared initial-handle ceiling is
`max_initial_handles(minor)`: `(4096 - 80) / 24 = 167` for ABI 1.3 and
`(4096 - 64) / 24 = 168` for ABI 1.0–1.2. Handle records start at that version's
prefix length. The SCFG format accepts up to the legacy maximum, while launch
also enforces the selected application's versioned capacity. The kernel
asserts that its physical backing and machine mapping agree with the region.
The kernel validates the complete descriptor set before clearing and encoding the
destination, so rejection cannot leave a partial startup record.

For ABI 1.3, `ipc_tx = startup + 4096`, `ipc_rx = startup + 8192`, and
`heap = startup + 12288`. Both IPC pages are private user RW/NX normal memory.
The boot arena retains 16 task pairs and four separate kernel-only pairs (40
pages, 160 KiB). All roots share supervisor-only aliases; only the owner has
user mappings. Task admission charges both pages. Allocation and rollback zero
the complete pair; terminal teardown revokes authority and roots before zeroing
and releasing the slot. Slot generations never wrap.

ABI call 3 may grow the mapped heap prefix without moving its base. Each
successful request commits actual zeroed frames and any supplemental page-table
frames; physical backing may be non-contiguous. Ordinary exhaustion leaves the
mapping unchanged. There is no format-level lifetime heap-byte ceiling other
than the remaining v1 user virtual range; on the current no-swap system,
available physical memory is the practical bound.

## ABI 1.3 private-page IPC calls

The acceptance harness binds one isolated client and one persistent echo task.
Calls 0–3 retain their existing contracts for all supported minors. Call 4 is
`ipc_call(handle, opcode, request_bytes, reply_capacity, deadline_millis,
object_parameter)`. It sends the exact TX prefix and returns `(status,
reply_bytes)` for the exact RX prefix. Both lengths range from zero through
4,096; opcode is a `u16`; user endpoints require object parameter zero. The
absolute boot-relative deadline must be bounded by 4,000 ms from admission;
a past deadline returns `timeout` without delivery. Invalid scalar or authority
arguments fault the caller before copying.

Call 5 is `ipc_reply_wait(wait_set, token, status, reply_bytes, deadline_millis)`;
the sixth argument register must be zero. It requires endpoint interface 15
version 2.0 with receive/reply rights and wait-set interface 24 version 1.0
with wait rights. The nonzero token names exactly one delivered call and is
consumed once. With no delivered inbound call, token, status, and reply length
are all zero. Reply validation/copy and the next wait are atomic. The new wait's
deadline is independent of the reply; a past deadline returns a deadline event,
and `u64::MAX` means an idle server wait.

The six receive words use x86-64 `RAX, RDX, RDI, RSI, R8, R9` or AArch64
`X0`–`X5`; every other ABI-visible register is preserved. Call 4 preserves the
normal two-result convention. Receive words are:

| Word | Encoding |
| ---: | --- |
| 0 | kind: 1 call, 2 resource ready, 3 deadline, 4 closed, 5 revoked, 6 client closed |
| 1 | nonzero call token; zero for non-call events |
| 2 | source index in bits 0–15; bits 16–31 zero; opaque client badge in bits 32–63 |
| 3 | interface in bits 0–31; opcode in bits 32–47; bits 48–63 zero |
| 4 | exact received request bytes |
| 5 | maximum permitted reply bytes |

Non-call events zero words 1 and 3–5. Only calls and client-closed events carry
a badge. The synthetic harness exercises calls and deadlines; the codec also
validates the remaining closed event vocabulary. Badges use an eight-bit slot
and 24-bit nonwrapping generation. Service statuses remain 0–23; transport
results add 24 `closed`, 25 `peer-died`, and 26 `deadlock`. Services cannot forge
these terminal transport results. Existing `exhausted` and `timeout` statuses
retain values 4 and 7.

`CommandContext::take_ipc` transfers the SDK's unique, non-cloneable `IpcPages`
owner once. Its `tx`, `rx`, and `buffers` borrows cannot survive another mutable
call. `PersistentContext` and `persistent_entry!` expose the typed server event
and atomic reply/wait operation. ABI 1.0–1.2 contexts have no IPC page owner. The generated raw `_start` symbols
are unsafe Rust entry points: only one native startup invocation may construct
these owners. Their native calling convention is unchanged.

## Deliberate omissions

KEX v1 carries no sections, symbols, interpreter, imports, exports, general
dynamic linking, TLS, compression, capabilities, signatures, device mappings,
or shared-memory contract. Its relative relocation table is deliberately only
the load-time mechanism needed for ASLR. Package identity and trust
metadata belong to the surrounding trust formats.

# KEX static TLS container 1.3

`troe-application::tls_artifact` validates this format for offline inspection
and converter verification. It produces no native load plan, startup layout,
mapping, capability grant, or resource admission. Native and streaming loaders
accept only [container 1.2](kex-v1.md), and the active SDK accepts application
ABI 1.3. Both loaders reject container 1.3 even with a higher caller ABI ceiling.

## Encoding

All fields are unsigned little-endian. The header is exactly 160 bytes. Its
first 96 bytes use the container-1.2 field offsets with these exact values:

| Offset | Bytes | Field | Value |
| ---: | ---: | --- | --- |
| 8 | 2 | container major | 1 |
| 10 | 2 | container minor | 3 |
| 14 | 2 | header bytes | 160 |
| 18 | 2 | application ABI major | 1 |
| 20 | 2 | application ABI minor | 4 |
| 22 | 2 | flags | 2; every other bit rejected |
| 56 | 4 | load-record offset | 160 |
| 64 | 4 | relocation-table offset | `160 + record_count * 40` |
| 80 | 8 | artifact bytes | exact length including the TLS suffix |

The remaining base fields retain their meanings. Reserved bytes remain zero.
The exact extension at bytes 96–159 is:

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 96 | 8 | source image offset | initialized source in a nonexecutable image segment; zero if `F = 0` |
| 104 | 8 | template file offset | exact end of all image payloads |
| 112 | 8 | initialized bytes `F` | at most `M` |
| 120 | 8 | TLS memory extent `M` | complete initialized and zero-filled template |
| 128 | 8 | alignment `A` | nonzero power of two, zero residue |
| 136 | 8 | worker trampoline offset | image-relative file-backed RX entry |
| 144 | 4 | profile | 1 |
| 148 | 4 | reserved | zero |
| 152 | 8 | reserved | zero |

Load and relative-relocation records use the existing 40-byte and 16-byte
encodings. Tables and image payloads remain tightly concatenated, with ordered,
page-disjoint R/RX/RW segments and the exact image-span declaration. Permission
value 4 remains rejected; TLS is not an executable-image mapping permission.
The main and worker entries must both be file-backed RX, with four-byte
instruction alignment on AArch64. Executable zero-fill cannot contain either entry.

The final image payload is followed immediately by exactly `F` initialized TLS
bytes. This suffix ends at the exact artifact length. For nonempty initializers,
it must equal the file-backed source range at `source image offset`, wholly
inside one nonexecutable segment. No eight-byte image relocation target may
intersect that source range, including a target beginning before its first byte.
There are no TLS pointer fixups in profile 1. Zero-filled TLS has no encoded
payload. An empty or BSS-only template still has the explicit extension and
canonical empty suffix; its source offset is zero.

The 2 GiB encoded ceiling includes the suffix. Header, image, stack, and heap
scalar limits are checked, but this reader does not compute or grant a complete
resident budget. Decoding allocates nothing and borrows immutable artifact bytes.
It never reads a running application's writable data as an initializer.

## Profile 1 geometry and entry convention

The portable `static_tls` planner enforces `F <= M`, a common 16 MiB local-exec
displacement window, and checked control-block/alignment/page arithmetic.
With `round(n, a)` denoting checked upward alignment:

| Target | Thread-pointer offset | Template offset | Allocation end |
| --- | --- | --- | --- |
| x86-64 | `round(round(M, A), 8)` | `TP - round(M, A)` | `TP + 8` |
| AArch64 | 0 | `round(16, A)` | `template + M` |

The mapping base alignment is `max(A, 4096)`. Allocation ends round up to pages;
even an empty template needs a control page. Initialization validates the entire
destination before writing, zeroes every mapped byte, copies `F` bytes, and
writes the x86 self pointer at FS:0. The Arm thread pointer addresses its 16-byte
control prefix through TPIDR_EL0. These bytes do not freeze a libc-private TCB,
DTV, thread-specific-key lifetime, or trusted kernel identity.

The worker trampoline receives `(descriptor_address, descriptor_bytes)` using
the ordinary target C argument convention: RDI/RSI on x86-64, X0/X1 on AArch64.
The descriptor uses the [thread v1 codec](thread-v1.md). Encoding this entry
does not establish that its implementation obeys runtime ownership or cleanup
rules. The format carries no user-selected physical addresses or per-thread
isolation within a shared process.

## Explicit hosted conversion

```console
cargo kex convert app.elf app.kex --target x86_64 --threaded
cargo kex convert app.elf app.kex --target x86_64 --threaded --check
cargo kex inspect app.kex --json
```

The opt-in emits a raw container-1.3 artifact. `inspect` accepts either the raw
artifact or the existing package envelope and reports `container_minor: 3`,
`native_admission: false`, and the extension fields. Ordinary conversion and
`cargo kex build` retain the single-thread profile. The Python ELF converter is
an independent oracle for container 1.2 only.

The ordinary closed ELF contract applies, with these explicit additions:

- At most one read-only `PT_TLS`, using the
  [ELF program-header template fields](https://www.sco.com/developers/gabi/latest/ch5.pheader.html).
  Alignment zero normalizes to one; every other admitted alignment is a power
  of two within the planner's ceiling. Both virtual and file offsets have zero
  residue. A nonempty initializer must have consistent file/address geometry
  inside a nonexecutable `PT_LOAD`.
- `SHF_TLS` sections must be allocated PROGBITS or NOBITS, optionally writable,
  with no executable or unknown flags. Their ordered, nonoverlapping extents
  start at zero and end exactly at `M`; initialized sections end exactly at `F`.
  Initialized sections match file geometry, and NOBITS starts at or after `F`.
  The initialized prefix cannot alias ordinary allocated sections. ELF `.tbss`
  may overlap ordinary image addresses because it occupies separate TLS storage.
- The complete non-dynamic symbol table is mandatory. Every TLS symbol must
  name a TLS section and fit its template-relative extent. Exactly one defined
  strong global, nonempty `STT_FUNC` named `__troe_thread_start_v1` must fit a
  file-backed RX section, with default or hidden visibility. Missing, weak,
  undefined, duplicate, stripped, and malformed definitions are rejected.
- Larger power-of-two load alignment up to 16 MiB is accepted while retaining
  page-aligned file/virtual addresses and congruence. Ordinary allocated section
  alignment may not exceed KEX's 2 MiB image-base alignment. TLS placement uses
  its separately checked alignment.

No `PT_TLS` is also valid when there are no TLS sections or symbols: the
converter emits `F = M = 0`, `A = 1`, and still requires the worker trampoline.
Dynamic TLS, module registration, symbol-based relocations, residual TLS
relocations, and initializers requiring image pointer fixups are rejected.
Conversion validates the complete input and independently decodes and compares
the output before writing or checking its destination.

The compiler probes in [testing guidance](../testing.md#static-tls-layout-and-compiler-probes)
check actual local-exec address sequences on both architectures. ELF metadata
validation alone is not a proof of arbitrary machine code's TLS model or a
production libc's thread safety. Native execution remains disabled.

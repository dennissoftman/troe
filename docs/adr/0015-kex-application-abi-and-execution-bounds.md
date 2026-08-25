# ADR 0015: KEX v1 application format, ABI, and execution bounds

Status: accepted and implemented, 2026-08-25.

Implementation note, 2026-08-23: the portable parser, canonical virtual layout,
startup-page encoder, and native owned-staging/validate/map/reclaim transaction
are implemented. The native root maps only the supervisor image, devices, and
explicit boot-arena runtime ranges needed across an isolated transition, keeping
both backends inside the standard policy's 512-page table ceiling. A subsequent increment
added reset ring-3/EL0 entry, ABI call 0 exit, and enforced 50 ms one-shot leases
using the x86 local APIC calibrated by typed PIT resources and the AArch64
generic physical timer through GICv2 PPI 30. The final Stage 7 increment added
bounded full-context suspension, scheduler-selected yield resume, owner-checked
copied handle calls, reply copy-out, and native invalid-call/unexpected-return
acceptance on both primary architectures.

Closure note, 2026-08-25: `tools/troe-kex-tool` now provides the dependency-free
Rust ELF64-to-KEX conversion boundary and validates every artifact it emits
through the portable parser. The prior `tools/elf2kex.py` remains an independent
parity oracle during migration. `tools/gen_kex_corpus.py` deterministically
generates the shared x86-64/AArch64 acceptance, rejection, native-exercise,
and exact-budget corpus consumed by both hosted tests and the portable Rust
parser. The kernel's
production Stage 7 exercise embeds only the generated valid call/yield/exit
artifact. Malformed, spinning, invalid-call, and unexpected-return artifacts
are compiled only with `acceptance-probes`; every destructive artifact carries
a stable marker that the production EFI build gate rejects without needing
QEMU. The production-used provisional loader ledger and hosted failpoint tests
cover staging, frames, inactive tables, task records, and handles, including
reverse rollback and the rule that no root becomes active before complete
commit.

## Decision

Stage 7 introduces a project-owned, target-specific static executable container
named KEX. The first loader accepts only KEX container major 1, minor 0, and
application ABI major 1. KEX is the executable inside a future immutable package
artifact; it is not itself a package, trust envelope, manifest, lock file, or
signature format.

The hosted SDK links a freestanding static ELF for the KEX v1 image base
`0x0000_4000_0000_0000` and then converts it into canonical KEX. ELF remains a
toolchain interchange format and is never parsed by the kernel. The SDK linker
must apply all link-time relocations; the converter rejects every residual
relocation record and any result that still needs an interpreter, dynamic
loader, runtime relocation, thread-local-storage model, writable executable
mapping, or another facility absent from KEX v1.

This keeps the native parser smaller than a policy-rich ELF loader without
requiring a custom compiler or linker.

### Hosted ELF conversion contract

The converter accepts only a bounded, final ELF64 little-endian System V
`ET_EXEC` for `EM_X86_64` or `EM_AARCH64`. It requires the canonical 64-byte
ELF header, 56-byte program records beginning immediately after it, no extended
header counts, at most 64 program headers and 16 load segments, zero target
flags, and 4 KiB-aligned `PT_LOAD` file and virtual addresses at or above the
fixed image base. Load records must already be ordered and disjoint after page
rounding, use exactly R, RX, or RW permissions, and contain a file-backed
executable entry; AArch64 entries are additionally four-byte aligned. A
canonical read-only `PT_PHDR` and non-executable GNU stack record are allowed.

Interpreter, dynamic, TLS, note, GNU property, unwind-header, RELRO, and unknown
program records are rejected. A section table may be absent. If present, it is
bounded to 4,096 canonical 64-byte records and is checked against its owning
load segment; residual `REL`, `RELA`, or `RELR`, dynamic metadata, TLS, W+X,
invalid links/names/alignments, and allocated sections outside their load
mapping are rejected. Nonzero bytes outside the ELF header, tables, segments,
or described sections are also rejected. The converter emits tightly packed
KEX records in validated load order, independently parses the result, and
compares its target, entry, requested stack/heap, records, payloads, and exact
length with the validated ELF before writing it. The input ceiling is 64 MiB;
the standard KEX policy then applies its smaller encoded and resident limits.

### KEX v1 container

The exact byte offsets and numeric encodings are fixed by the
[KEX v1 format specification](../formats/kex-v1.md).

KEX v1 is little-endian and consists of one fixed header, a fixed-width load
record table, and segment payload bytes. Its eight-byte magic is the ASCII byte
sequence `KEX`, zero, `FMT`, zero. It is a format identity, not a product or
vendor identity, so changing the project name cannot invalidate executables.
The header contains:

- the eight-byte KEX magic and container major/minor;
- a closed target value for x86-64 or AArch64;
- header and load-record sizes;
- required application ABI major and minimum minor;
- entry offset from the application image base;
- load-record count;
- requested zeroed heap pages and initial stack pages;
- table and payload offsets, exact artifact byte length, and reserved fields.

Each load record contains an image-relative virtual offset, file offset, file
byte count, memory byte count, and closed permission value: read-only,
read/execute, or read/write. All integers have fixed widths. Reserved fields and
unoccupied flag bits must be zero. Header and record sizes must equal the v1
sizes; they are not extension escape hatches.

The loader accepts an artifact only when all of the following hold:

- its target exactly matches the running architecture and its declared length
  equals the bounded input length;
- the header, table, payload ranges, and every addition, multiplication,
  rounding operation, and host-width conversion are representable;
- there is between one and the standard maximum number of load records;
- image offsets and memory sizes describe nonempty 4 KiB page ranges, file bytes
  do not exceed memory bytes, and the remaining bytes can be deterministically
  zero-filled;
- load records are ordered by image offset, neither their file ranges nor their
  page-rounded image ranges overlap, and every file range follows the record
  table and lies wholly inside the artifact;
- the image span, mapped pages, stack, heap, page tables, staging bytes, and
  total resident ownership all fit the standard policy;
- permissions are exactly one of the three v1 values, at least one segment is
  executable, no page or physical alias is writable and executable, and the
  entry lies wholly inside an executable segment;
- the image, a read-only startup page, zeroed heap, guarded zeroed stack, and
  unmapped guard gaps fit the architecture's user range without overlap with
  one another, the kernel, devices, or reserved call entry state; and
- all padding is zero and there are no trailing or multiply described bytes.

KEX v1 is statically relocated and must be mapped at its fixed image base. The
same address can be reused safely because every application has a separate
page-table root; v1 makes no ASLR claim. KEX contains no section table,
interpreter, dynamic table, imports, exports, relocations, symbol contract,
compression, embedded capabilities, device mapping, or shared-memory
description. Segment bytes are copied into newly allocated zeroed frames rather
than executed from the staging buffer.

A later compatible container minor may only tighten canonical validation or add
semantics that a minor-aware parser can unambiguously skip. The kernel rejects
every container minor it has not explicitly implemented. Changes to field
meaning, required records, permissions, or execution semantics require a new
container major.

### Application ABI v1

The application ABI is versioned independently of KEX. An application declares
one ABI major and the minimum minor it needs. A kernel may load it only when the
major is equal and the kernel's supported minor is at least the requested
minor. Existing calls, layouts, status meanings, and rights may only be
extended compatibly within a major. Removing or reinterpreting any of them
requires a new major. The first implementation exposes ABI 1.0 only.

The kernel maps one immutable, read-only/non-executable startup page and enters
the raw `_start(startup_address, startup_bytes) -> !` boundary. On x86-64,
`RDI` and `RSI` carry those two values; on AArch64, `X0` and `X1` do. The stack
pointer is 16-byte aligned, all other application-visible general registers are
zero, floating-point/SIMD registers and control state are reset to documented
defaults, the x86 direction and alignment-check flags are clear, and application
interrupt delivery is enabled so the execution lease can be enforced. The
startup page uses fixed-width little-endian fields and contains:

- its byte size and ABI major/minor;
- the 4 KiB page size and a required zero reserved field;
- image base, heap base and length, and stack bounds;
- the application's monotonic task identity; and
- a bounded inline list of initial handle descriptors, each carrying an opaque
  handle value, rights, interface identifier, and interface major/minor.

There are no ambient arguments, environment, filesystem namespace, devices, or
kernel pointers in ABI 1.0. Initial handles are the intersection of explicit
loader policy and the launching principal's authority. KEX cannot grant or
request authority by itself.

ABI calls use `int 0x80` on x86-64 and `svc #0` on AArch64. x86-64 places the
call number in `RAX`, up to six arguments in `RDI`, `RSI`, `RDX`, `R10`, `R8`,
and `R9`, and receives status and secondary result in `RAX` and `RDX`.
AArch64 places the call number in `X8`, up to six arguments in `X0` through
`X5`, and receives status and secondary result in `X0` and `X1`. Statuses and
call numbers are unsigned fixed-width ABI values, not host `usize`, Rust enum,
or POSIX errno representations. A returning call preserves every other
application-visible register.

ABI 1.0 defines exactly three calls:

0. `exit(status)` takes one unsigned 32-bit status, terminates the application,
   and never resumes it;
1. `yield()` returns control to the scheduler voluntarily and resumes only if
   the scheduler selects the application again; and
2. `handle_call(handle, request_address, request_bytes, reply_address,
   reply_capacity)` performs one synchronous request/reply through a granted
   handle and returns a typed status plus reply length.

The copied request begins with a little-endian unsigned 16-bit service opcode;
the remaining bytes are the service payload. The reply buffer receives only
the service payload.

Requests and replies are each limited to the existing 4 KiB dispatch bound.
The kernel validates the complete request range, reply range, handle ownership,
rights, lengths, and non-overlap needed by the operation before dispatch or any
copy. Requests are copied into kernel-owned memory before delivery; replies are
copied out only after successful bounded delivery. Invalid calls, unknown call
numbers, nonzero AArch64 `SVC` immediates, and incomplete ranges terminate the
application as contained invalid-call faults. They never produce a partial
service effect or partial reply.

Returning from `_start` is not an exit operation. The initial link register or
return target is zero, address zero is never mapped, and an attempted return is
reported as a contained unexpected-return fault. Applications must call
`exit` to report a status.

### Memory and retained-resource budgets

All sizes below are hard compile-time ceilings. An application may request less
stack or heap, and the loader may impose a smaller launch policy, but neither a
manifest nor detected RAM may raise these limits. Guard pages consume virtual
space but no frames. The total resident ceiling includes image, startup, heap,
stack, and application page-table frames. Kernel staging is separately bounded
and is released before entry.

| Limit | Standard |
| --- | ---: |
| Loadable isolated applications | enabled |
| Encoded KEX bytes | 16 MiB |
| Load records | 16 |
| Image virtual span | 128 MiB |
| Mapped image pages | 8,192 |
| Initial stack pages | 4–256 |
| Zeroed heap pages | 0–4,096 |
| Application page-table pages | 512 |
| Total resident pages | 16,384 (64 MiB) |
| Initial handles | 32 |

There is one application resource policy. These values are safety maxima, not
boot-time reservations or a machine-size selector. Every launch charges its
exact staging, image, startup, heap, and stack ownership, plus bounded table,
task, address-space, and handle capacity before commit. There is no overcommit,
demand paging, stack growth, `brk`, `mmap`, shared page, or runtime
executable-memory operation in ABI 1.0. An SDK allocator may manage only the
fixed zeroed heap described by the startup page.

The loader first copies at most the encoded-byte ceiling into kernel-owned
staging memory, parses and validates the complete artifact into a bounded load
plan, computes every resource charge, and checks all initial handles. Only then
may it reserve frames and slots. It initializes and zeroes every private page
while supervisor-only, builds but does not activate the page-table root, and
commits the task and handle ownership together. Any failure before commit
zeroes and returns the entire provisional allocation. Any exit, fault, timeout,
or cancellation uses ADR 0014's ordered handle revocation, zeroization, and
atomic reclamation transaction.

### Non-returning and non-yielding applications

Stage 7 remains cooperative between ABI boundaries, but untrusted code does not
receive an unlimited uninterrupted CPU lease. Each entry or resumption arms an
architecture-owned one-shot timer for at most 50 ms. A call or voluntary yield
disarms the timer before kernel work begins. If the timer expires while the CPU
is in application privilege, the kernel switches to its own root and stack,
marks the task `execution-lease-expired`, and tears it down without resuming it.
The application cannot catch, mask, extend, or handle this event.

A successful call or yield merely makes the task eligible for another lease;
the scheduler regains control and may cancel it or run another ready task first.
Consequently, code that periodically reaches a gate cannot trap the kernel in a
single synchronous launch loop. An application may live for many leases, but a
caller may set a smaller lease or an additional total
lifetime/call-count policy. The ABI exposes no promise of a minimum quantum or
forward progress.

The timer is a containment deadline, not resumable general preemption. Expiry
discards the user context. A timer or other exception taken while already in
kernel privilege remains a kernel event or terminal kernel fault according to
the existing exception policy; it must not be mislabeled as an application
timeout. Stage 7 must enable and test the owned x86 local-APIC timer and AArch64
generic timer path before executing external KEX bytes.

## Verification

One portable parser and load-plan implementation must run against the same
acceptance and rejection corpus on the host and both native targets. The corpus
must cover every header field and target, truncation at every structural
boundary, noncanonical padding, integer overflow, reordered/overlapping file
and virtual ranges, sparse spans, invalid permissions, entry-point errors,
zero-fill boundaries, ABI mismatches, and every individual and aggregate
budget.

Property tests must establish that accepted plans are ordered, disjoint,
bounded, W^X, and charge exactly the frames later retained by the task record.
Allocation-failure injection at every staging, frame, table, task, and handle
step must prove no mapping becomes active and no resource remains owned after a
rejection.

The committed generated corpus is authoritative only together with its
generator: `python3 tools/gen_kex_corpus.py --check` must reproduce the exact
file set and bytes. The `tests.test_elf2kex` and `tests.test_build_policy`
stdlib suites exercise deterministic conversion, the closed ELF
rejection surface, corpus regeneration, and the production marker policy.
`cargo test -p troe-application` runs every generated KEX through the portable
parser, checks exact boundary charges, covers every truncation of a valid
artifact, and exercises deterministic segment properties and all five loader
transaction failpoints.

Native acceptance on x86-64 and AArch64 must run a valid SDK-built KEX that
receives only declared handles, yields, performs a copied request/reply, and
exits. Separate applications must return unexpectedly, issue each invalid ABI
form, fault in each existing contained class, and spin without calling a gate.
Every case must preserve an unrelated service, revoke stale handles, report its
distinct fate, restore exact frame counts, reuse the returned allocation, and
continue into the recovery shell. Production images must not contain the
malformed or destructive acceptance payloads.

## Consequences

The first Stage 7 increment has one small parser and no in-kernel ELF, dynamic
linker, relocation engine, symbol resolver, executable allocator, or package
trust policy. Conventional compilers remain usable through the hosted KEX
converter, at the cost of making raw third-party ELF binaries unsupported.
The fixed v1 image base also excludes load-time ASLR; adding relocation-aware
loading requires a separately reviewed container revision.

Direct in-kernel ELF loading was rejected because program headers, section
headers, interpreter and dynamic metadata, relocation families, notes, and
platform extensions create a much larger ambiguity and rejection surface than
the first loader needs. WebAssembly was rejected for this increment because it
would add an instruction runtime and a different memory/host-call model rather
than reuse Stage 6's native isolation. An indefinitely cooperative policy was
rejected because malformed external code would otherwise retain the only CPU
without returning control to the scheduler.

ABI 1.0 is deliberately sufficient for bounded service clients, not a POSIX
process model. Arguments, environment, persistent package identity, clocks,
threads, shared memory, dynamic libraries, signals, executable memory, and
driver/device ABIs require later decisions and compatible minor additions or a
new major. General resumable preemption and SMP are still out of scope.

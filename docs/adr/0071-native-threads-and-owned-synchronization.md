# ADR 0071: Native threads and owned synchronization

Status: architectural direction accepted, 2026-09-09. Implementation tracked by
[#65](https://github.com/dennissoftman/troe/issues/65) and delivery issues
[#204](https://github.com/dennissoftman/troe/issues/204) through
[#208](https://github.com/dennissoftman/troe/issues/208).
No native thread execution, native TLS, or pthread support is claimed by this document.
Current single-execution-thread application contracts remain in force.
Portable lifecycle/synchronization models, an independently compiler-checked
static TLS layout/initializer, guarded thread-memory planning, and composed
initial-process geometry/peak memory charges implement portions of this direction.
The owned-initializer annex implements coherent staged-buffer ownership, immutable
TLS copying and retained logical charges; native frame/context integration remains open. The implemented offline
[KEX static TLS container 1.3](../formats/kex-static-tls-v1.md) encodes the
initializer, extent, alignment and worker trampoline under application ABI 1.4.
Its reader and explicit converter produce no complete native admission proof.
The portable table constructors also enforce compiled metadata-byte budgets;
the paired admission annex below constrains record/wait capacity and protected
IPC headroom without enabling native execution.
Allocation-free wire/startup codecs implement the numeric assignments described
in the wire annex below. Application ABI 1.4 and native entry 6 remain disabled;
these assignments do not supersede the active ABI 1.3 contract. Complete native
admission and the remaining gates below are still required.

## Context and priorities

The reusable C runtime exists, but its create/join and condition waits are
unsupported, mutexes model one execution thread, and TSS values are global.
CPython's TROE patch erases `_Py_thread_local`; its timed-condition shim ignores
the deadline and its thread-exit shim aborts. The Rust C bridge returns an
exclusive mutable reference to a shared invocation object. None of these
assumptions survives enabling another execution context unchanged.

The resident runtime already supplies isolated roots, resumable user contexts,
preemption, process ownership, guarded mappings, and bounded wait models.
`ApplicationSession` currently owns both a root and one register context;
`ResidentApplication` similarly combines process and execution ownership.
AArch64 already saves a thread-pointer field; the x86 saved context does not
yet carry a corresponding TLS base. Native KEX loaders reject TLS metadata;
the separate offline container reader does not change that boundary.
These are starting points, not evidence of thread support.

The ordering of design goals is:

1. preserve authority, memory isolation, and trustworthy kernel ownership;
2. make lifecycle, failures, resource use, and teardown reliable and bounded;
3. offer useful native concurrency and an honest compatibility subset;
4. optimize measured workloads without weakening the first three goals.

Compatibility is a userspace adaptation, not a reason to import every POSIX
operation into the kernel. Familiar APIs are not intrinsically unsafe; their
cost and failure semantics must justify each selected feature.

## Decision 1: the process remains the security and fault boundary

A process owns its address space, capability table, invocation, descriptors,
children, terminal loan, memory budget, CPU entitlement, and supervision policy.
A thread owns its saved registers, guarded stack, TLS storage, errno, pending
operation, wait registration, execution accounting, and completion state.

Threads in one process share memory and process authority. A sibling can read
another thread's stack, TLS, and IPC pages through the shared root. There is
no promise of secret TLS, isolated thread faults, or trustworthy attenuation
between threads. Per-thread operation handles organize use; they cannot keep
a hostile sibling from using process memory or copied handles. Use separate
processes and copied IPC for mutually untrusted components.

An unhandled machine fault in any thread terminates the process. An ordinary
language exception is not such a fault: Python's thread exception hook and
normal language cleanup retain their semantics. Task failure is an expected
application event, not proof of corrupt memory and not assumed to be rare.

An application mutex abandoned by an exiting owner becomes poisoned: waiters
receive a failure without ownership, and new acquisitions fail. Unrelated
threads can continue. Essential runtime invariants may instead select an
immutable fail-process owner-death policy when creating their mutex. The kernel never
repairs application data, releases a dead owner's mutex as if it were healthy,
or invokes application recovery callbacks under privilege. A language exception
caught by a runtime's thread entry wrapper is not a machine fault; language
semantics remain the runtime's responsibility.

This contains damage to other processes; it does not prevent application data
races, prove application consistency after a normal thread return, undo an
already committed filesystem/network side effect, or eliminate timing channels.
Untracked application spinlocks cannot receive kernel owner-death guarantees.

## Decision 2: explicit authority and versioned ownership

Thread creation requires a manifest-selected typed thread service and an
effective process quota greater than one. The launcher may attenuate the quota;
requests cannot enlarge system limits or grant memory, clock, network, process
launch, or terminal authority. The initial thread counts against all applicable
thread and execution-context budgets. Existing single-thread packages continue
without an additional capability or a hidden worker.

Thread and synchronization references are opaque process-owned, typed,
generation-checked tokens. Every operation derives the caller's process and
thread from trusted execution state and checks object type, owner, generation,
rights, and lifecycle. An integer thread ID, TLS value, or user-supplied owner
field never establishes authority. No global name lookup, cross-process import,
arbitrary kernel address, or user-selected physical address is exposed.
Generation exhaustion retires the slot; identities never wrap into validity.

Control operations have separate create/start/join/detach/stop/observe rights
where meaningful. These are API discipline within one process, not an intra-
process security boundary. External supervisors retain process-level control;
the initial profile exposes no authority to kill or suspend one sibling.

The interface and startup assignments are recorded in the wire annex below.
The TLS container assignment is recorded in the format annex below. Capability
requirements still need allocation against the live registries before native admission.
Do not reuse ABI 1.3 startup fields or activate the reserved TLS flag in an old
version. Old readers reject new requirements before execution. Old artifacts
keep their exact layouts and remain single-threaded even if a caller supplies
extra authority. Library linkage alone is not a declaration of thread safety.

### Wire and startup annex

The implemented [thread codec v1](../formats/thread-v1.md) assigns interfaces
30/31, interface version 1.0, operation rights in bits 9–14, entry 6 with a
64-byte request and 32-byte response, and the standalone ABI 1.4 startup
extension. Typed tokens carry a nonzero generation and kind, with no caller
process field. Current kernel/SDK admission remains capped at ABI 1.3; startup
encoding/decoding rejects the new interfaces in older profiles. KCAP grants
and native KEX admission are separate prerequisites, not inferred from codec availability.
Collapse internal wrong-process and stale-generation lookup failures to the
same public stale result. A caller must not probe another process's record
existence through a more specific ownership error. Mutex-not-owner remains a
distinct error for an already authenticated object inside the same process.

Native entry 6 must authenticate an actual built-in scheduler capability,
including owner, interface version and operation rights. An application endpoint
advertising the same interface number cannot become a scheduler service. Copy
the complete request into owned kernel storage before validating or suspending;
no borrowed TX bytes survive admission. Sibling writes to shared memory can
corrupt application requests but cannot bypass trusted owner/state checks.
Resume uses the retained operation identity and caller's live IPC generation,
never a payload-supplied destination or another thread's pending result. Before
return, clear unused RX bytes; rejected frames expose zero response bytes.

Thread/synchronization waits are scheduler operations, separate from service IPC
deadlines and lease status. A timeout, cooperative stop, poison or self-deadlock
is an operation result, not a transport fault. Suspending on a wait cannot
renew an active delegated IPC execution lease, transfer that lease to a sibling,
or grant another process CPU entitlement. The complete native attribution proof
remains a #206 gate. Frame/profile/capability rejection does not perform an
operation; native faults still use the process-wide failure boundary.

ABI 1.4 keeps the initial entry's process-startup pointer and mapped-byte-count
convention. Its header points to a separate immutable initial-thread descriptor.
A worker enters a kernel-selected, admitted image trampoline with its own
descriptor address and 128-byte prefix count in the normal first two argument
registers. The descriptor contains shared process startup, private stack/TLS/IPC,
resolved worker entry and the scalar argument. The trampoline is selected from
validated executable metadata, never supplied as a syscall callback. Its native
implementation and compiler profile are not established by decoding addresses.

## Decision 3: transactional creation and precise lifecycle

The native lifecycle is:

```text
prepare -> prepared -> start -> ready <-> running
                                  ^          |
                                  |          v
                                  +------- blocked
                                             |
running -- captured after user cleanup --> exiting -> completed -> reaped
any nonterminal state -- process termination --> revoked -> reaped
```

`prepare` validates entry/trampoline offsets in immutable executable mappings,
stack/TLS geometry, quota, capability, and all arithmetic before publication.
It reserves a context, stack and guards, TLS, IPC buffers, pending-call and wait
capacity, completion record, and exact mapping/metadata charges. Backing pages
are committed and zeroed; no demand allocation occurs on a worker's first
stack access. No allocation failure may leave a runnable partial thread.
Work beyond one memory-operation quantum uses an owned preparation continuation
and yields kernel control; it retains no borrowed application request.

`start` publishes initialization with release semantics and enqueues exactly
once; first entry has acquire semantics. The child may run before the caller
observes the successful return. It enters a reviewed userspace trampoline with
kernel-selected stack/TLS state and a copied scalar argument. The trampoline
calls the application entry and translates return into thread exit. The kernel
does not dereference an application result pointer or run an entry callback.
Creating and initializing userspace bookkeeping precedes start.

A prepared object is charged and attached to its creator until start; creator
exit aborts its unstarted preparations. Start versus abort/stop/exit has one
serialized winner. Process stopping forbids new preparations and starts. Drop
of a handle never implicitly starts, detaches, or kills a thread. The C facade
combines prepare/start into one operation, with complete rollback on failure.

There is one consuming join right and at most one admitted joining waiter per
target. Self-join is rejected. Concurrent join/detach and join/timeout have one
linearization point; a failed or timed-out join does not consume completion.
Successful join acquires the exiting thread's published writes, copies only
the bounded scalar result, and consumes completion exactly once. A second join
or stale token fails explicitly. A result pointing into a dead stack remains an
application bug; the kernel neither extends its lifetime nor dereferences it.

Detach relinquishes joinability, not process ownership, resource charges, or
supervision. A detached thread is reaped automatically after terminal cleanup.
A process's initial thread has a supervisor-owned, non-joinable completion in
this native profile; the compatibility manifest must disclose that restriction.
A joinable completion retains only bounded result/identity state; stacks, TLS,
IPC and pending resources are released after execution and references quiesce.
Completed-but-unjoined records still consume a quota so zombies cannot grow
unboundedly. Storage is never recycled while a continuation can reference it.

Returning from the main C entry calls process exit. `pthread_exit` ends the
calling thread; other threads can keep the process alive. Last-thread normal
exit triggers process completion. Simultaneous terminal events record one
stable process fate, with a fault/forced-stop cause taking precedence over a
not-yet-committed successful completion. Finalization is never performed twice.

## Decision 4: TLS and memory are owned resources

Start with static TLS for a statically linked KEX. There is one canonical
immutable TLS template plus a zero-fill extent, exact alignment, and checked
per-thread size. The converter rejects unimplemented TLS models and residual
dynamic TLS relocations. No runtime loader, module TLS registration, or
`dlopen` follows from this decision. Thread-specific keys are a separate bounded
runtime facility and do not replace compiler TLS.

An implementation annex must specify the complete template encoding and both
compiler ABIs, including x86 FS base and AArch64 TPIDR_EL0, TCB placement,
alignment, startup trampoline, and relocations. Host-generated ELF and target
disassembly must prove the compiler model. The kernel initializes and saves
all supported architectural state, including TLS bases, FP/SIMD state, flags,
and privileged-return constraints. Unsupported vector/debug extensions remain
disabled; a context switch cannot leak stale state from another process.
The kernel never trusts a user-writable TLS base or TCB for its own identity.

### Portable local-exec layout annex

The allocation-free `troe-application::static_tls` component defines geometry
for one fully linked template. Let `F` be initialized bytes, `M` total template
bytes, `A` a nonzero power-of-two alignment, and `round(x, a)` checked upward
alignment. Require `F <= M` and zero template alignment residue. An eventual
ELF adapter must normalize `p_align = 0` to one and reject nonzero
`p_vaddr mod A`; the scalar planner does not parse or authenticate ELF.

| Target | Template offset from allocation base | Thread pointer offset | Required bytes before page rounding |
| --- | --- | --- | --- |
| x86-64 | `round(S, 8) - S`, where `S = round(M, A)` | `round(S, 8)` | thread pointer offset + 8 |
| AArch64 | `round(16, A)` | 0 | template offset + `M` |

The x86-64 self-pointer word occupies FS:0. Prefix padding aligns that word
without changing the linker's negative template displacement. This is the
compiler requirement documented by the
[x86-64 psABI TLS specification](https://gitlab.com/x86-psABIs/x86-64-ABI/-/tree/usr/hjl/tls)
and its [FS:0 clarification](https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/14/commits).
On AArch64, TPIDR_EL0 addresses a 16-byte control prefix. The template follows
that prefix and alignment padding, consistent with the zero-residue case of
the [Arm System V ABI TLS layout](https://github.com/ARM-software/abi-aa/blob/main/sysvabi64/sysvabi64.rst).
The Arm System V document labels its 2025Q4 revision Alpha; emitted compiler
and linker instructions are therefore part of the verification, not an
assumption about every historical platform runtime.

This component uses a conservative common 16 MiB local-exec window: x86-64's
rounded negative span and AArch64's template end must fit that window, and
`A` may not exceed it. AArch64's default local-exec relocation has a 24-bit
offset; see [AAELF64 relocation definitions](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst).
This bound is not a grant to allocate 16 MiB per thread. The caller must supply
an adequate page budget for the entire rounded mapping. The allocation base
must be aligned to `max(A, 4096)`, exclude page zero, and fit wholly inside the
48-bit lower user range. An empty template still needs its control bytes.

Initialization first checks exact input/output sizes and the complete virtual
range. Rejected initialization writes nothing. Success clears the entire
mapping, copies the initialized prefix, and writes the x86 self pointer.
Zero-filled TLS, internal padding, control bytes and final-page slack cannot
retain another allocation's contents. This deliberately costs work proportional
to all mapped bytes. The caller owns unpublished, quiescent storage. Container
profile 1 rejects
initializers requiring pointer fixups; any broader initializer profile requires
a separately specified relocation and ownership contract.

These control bytes do not freeze a musl, glibc, Darwin or BSD private TCB/DTV
layout. They carry no trusted kernel identity. Libc-private state and TSS key
destructors need their own explicit ownership and lifetime; neither can be
inferred from an FS:0 self pointer. Complete thread budgets must additionally
charge page tables, virtual guard/alignment reservations, stacks, IPC pairs,
context records, wait records and runtime metadata. The complete native
resource proof remains in
[#206](https://github.com/dennissoftman/troe/issues/206), together with the
selected and pinned production compiler profile. No native admission or
converter acceptance is implied by the layout component itself.

### Static TLS format and immutable-source annex

The implemented [container 1.3](../formats/kex-static-tls-v1.md) uses a 160-byte
header and requires ABI 1.4. An exact initializer suffix follows all image
payloads; it must agree with its file-backed nonexecutable image source.
Keeping this duplicate in the artifact makes immutable per-process ownership
explicit. A thread created after a sibling changes the image's writable `.tdata`
cannot inherit those modified bytes. This costs encoded space and validation
work proportional to the initializer; correctness takes precedence here.

The allocation-free artifact reader reuses image/relocation grammar but returns
no native load plan or startup placement. Native and streaming readers retain
container 1.2 and fail closed on the new revision, even under a higher caller
ABI ceiling. Opt-in conversion requires the complete ELF symbol table, exact
TLS extents and one strong `__troe_thread_start_v1` function. Empty TLS is an
explicit profile with a control block, not an absent thread-pointer contract.

Profile 1 rejects every image relocation overlapping initialized TLS bytes.
Copying unrelocated addresses would produce plausible but incorrect pointers;
applying relocations to user-writable source later would introduce races and
lifetime ambiguity. General TLS modules and runtime initializer fixups are
outside this profile. ELF validation checks metadata, not arbitrary code's
semantic conformance to the compiler model or libc ownership rules.

Native integration under #206/#207 must retain a coherent immutable initializer
for the process lifetime, including while any worker can be prepared. Charge its
owned bytes/pages and verification staging separately from the ordinary image
and each thread's initialized mapping. Reserve before copying, rollback on any
failure, and release only after creation is revoked and every context/backing
reader is quiescent. Reconstructing the template from a running process's image
or retaining a borrowed transient converter/source buffer is not valid.
The C source/profile boundary is selected in the next annex. The implemented
initial-process planner below supplies geometry and peak memory preflight; native
backing ownership, startup publication and the production runtime remain prerequisites.

### C compiler and runtime ownership annex

The selected source compatibility baseline for initial integration is C11 and
this ADR's explicit pthread/C11 subset, interpreted against POSIX.1-2024 where
that subset claims POSIX behavior. Use the repository's source-linked TROE C
sysroot/runtime and Rust capability bridge. Do not import musl or glibc's opaque
TCB, DTV, pthread object representation, Linux syscall assembly, or dynamic TLS
loader. This settles the bounded source/profile dependency of #206; #63 still
owns the broader musl-derived maintenance architecture, upstream components,
standards tiers, licensing and general libc ABI.

The implemented compiler qualification recipe is
`tools/thread_profile.py`, with the Clang/LLD release pair pinned in
`sdk/c/thread-profile-v1.json`. It checks C11 freestanding LP64/LE, 32-bit
`wchar_t`, aligned 64-bit lock-free atomics, static local-exec TLS, and the
TROE headers on both `*-unknown-none-elf` backend triples. These are LLVM code
selection triples, not a promise of a third-party OS ABI or host libc.
X86 code is limited to the baseline/SSE2 state with no red zone or AVX; Arm code
uses Armv8-A SIMD without outlined atomics. The compiled instruction probes and
strict KEX converter establish the tested layout contract. They do not prove
arbitrary C code thread-safe, restore architectural state, or publish workers.

Exact-release qualification records binary/header/source fingerprints and
rejects a changed observed input, missing required probe, skipped test, or
failed test. Compatible-tool checks remain useful CI evidence but do not claim
the pinned release pair. Reports are provenance and regression evidence, not a
signature, toolchain supply-chain attestation, or runtime admission credential.

The C runtime's ABI 1 is exclusively single-threaded. Its global `errno`,
process-global TSS values and callback `&mut Runtime` borrows must not become
reachable from concurrent workers. A threaded bridge requires a separately
versioned, source-linked binding; changing `pthread_create` alone or mixing an
ABI-1 archive with threaded headers is invalid. No general binary ABI is frozen.
The required ownership split before publication is:

| Owner | State and callback rule |
| --- | --- |
| Process | allocator, descriptor/open-file objects, stream metadata, cwd/environment snapshots, atexit registration and TSS key definitions; explicit synchronization and bounded metadata |
| Thread | compiler TLS, errno, TSS values/generations, temporary conversion state, IPC pages, active operation and cleanup phase |
| Suspended operation | copied scalar inputs and stable leases on referenced objects; no whole-runtime mutable borrow or table lock survives a blocking capability call |
| Bootstrap | process initialization completes once before a worker is published; bind zeroed thread-local state and validated startup before application callbacks |

Keep critical sections short enough to avoid a process-wide stall: reserve an
operation and retain its object, release metadata locks, block with the caller's
private IPC, then reacquire and validate identity/generation before commit.
Close/delete races invalidate new use while retained in-flight references stay
charged. The allocator's locking/bootstrap path cannot depend on allocating a
new lock, and a callback must never return two overlapping mutable Rust borrows.
This proof belongs to the synchronized bridge in #208, with IPC ownership from
#188/#207; the compiler qualification does not satisfy it.

TSS keys and compiler TLS are separate lifetimes. Retain 32 bounded process key
slots, with nonwrapping generations and per-thread value/generation pairs.
This is an explicit initial-subset capacity, not a claim to all POSIX resource
minimums.
A new generation sees null even if a sibling still holds an older value. Key
deletion invalidates the definition without invoking destructors; it does not
scan or free other threads' TLS. Reuse cannot revive stale values or callbacks.
A destructor pass clears the selected value before calling out, commits its
key-generation snapshot under metadata protection, and releases protection
before invoking application code. A committed callback may finish during a
concurrent delete; deletion prevents later commitments for that generation.
At most four passes run, including values re-registered by callbacks. Normal
thread exit clears that thread's values, never the process's key definitions.
Forced process teardown runs no application destructors. Static linkage keeps
callback code alive; no module-unload lifetime is implied. The applicable
[POSIX key creation](https://pubs.opengroup.org/onlinepubs/9799919799/functions/pthread_key_create.html)
and [deletion](https://pubs.opengroup.org/onlinepubs/9799919799/functions/pthread_key_delete.html)
contracts inform these decisions; generation checks and bounded cleanup are
explicit TROE requirements, not a claim that all legacy behavior is implemented.
[OpenBSD also bounds repeated destructor passes](https://man.openbsd.org/pthread_key_create.3),
supporting a finite cleanup policy without importing its private thread layout.

The compiler layout probes deliberately disable stack protection and RELRO
because they isolate TLS geometry and pass through the closed converter.
Those switches are not a production security decision. Before native C thread
admission, specify and test strong stack protection, unpredictable guard
initialization before protected C code, guard ownership across thread creation,
a nonreturning process-fault path, and complete context preservation. Audit any
unprotected bootstrap instructions separately. A guard cannot be sourced from
uninitialized/reused TLS or silently replaced with a constant. Likewise,
production writable relocation metadata must not imply permanently writable
control state. Until these requirements and complete resource admission pass,
the profile remains qualification-only and native execution stays disabled.

### Portable managed-memory layout annex

`troe-application::thread_memory` composes the checked TLS layout with one fixed,
fully committed stack, one task IPC pair and one read-only startup descriptor
page. Its kernel-selected reservation
base is page aligned, excludes page zero, and the complete window must fit
below or end at the exclusive 48-bit user limit. An empty stack is rejected;
the final stack minimum/default remains a profile acceptance input in #206.

In ascending addresses the canonical window contains one lower guard page,
the stack, one upper stack guard page, an unmapped alignment gap, TLS aligned
to its required mapping alignment, two adjacent IPC pages in TX/RX order, a
read-only startup page, and one final guard page. The gap may be empty. The four
mapped regions are nonempty and disjoint. Stack, TLS and IPC are RW/NX; startup
is read-only/NX. Every other byte remains unmapped but reserved.
The stack top is 16-byte aligned. Architecture entry frames, stack probes and
publication of startup mappings remain native obligations. Keeping guards around
the stack reduces accidental adjacent-object corruption; neither the guards
nor the final guard isolates one sibling from another.

The planner distinguishes five simultaneous memory constraints:

| Charge | Included resources |
| --- | --- |
| Mapped pages | stack + full TLS allocation + 2 IPC pages + startup page |
| Logical resident pages | mapped pages + supplemental page tables |
| Reserved virtual pages | complete window, including three guards and alignment gaps |
| Ordinary frames | stack + TLS + startup + maximum additional page-table pages |
| Task IPC pairs | one, from task capacity after essential-service reservations |

The logical resident charge adds supplemental tables to mapped pages. The IPC
pool already owns its physical backing in the boot arena, so admitting a thread
must not allocate or charge those same pages as ordinary free frames again.
Global physical accounting counts the whole pool once; per-thread logical
charges and slot occupancy attribute that existing storage to its current user.
Kernel-continuation pairs are not available for application admission.

For each of the three levels below the shared process root, count the union of
page-table prefixes intersecting the ordered mapped regions. This takes twelve
range calculations, independent of stack size. It excludes prefixes touched
only by gaps, deduplicates prefixes shared within one plan and includes all
boundary crossings. It is exact for otherwise absent lower tables and an
upper bound when the process already owns some tables. The shared root is
charged once to the process. Summing separately admitted plans conservatively
reserves possible additional tables again; unused frames remain charged until
their physical owner returns them. No optimistic sharing credit is needed to
pass preflight.

Checked aggregate charges cover prepared, live and unreleased plans and reject
overflow in every stored or derived count. A budget is a trusted snapshot after
existing charges, system minimum-free, service and teardown reserves have been
removed. Checking it neither reserves resources nor prevents a competing
admission from consuming them. Native composition must serialize reservation,
validate the whole window against all existing mapped and reserved ranges,
own/zero backing and enforce mapping permissions before publication. The
planner does not establish these facts. Compiled context/wait/mapping/runtime
metadata, object/key capacities, final defaults and the supervisor/service
allocation remain acceptance work in #206. Native loading remains unchanged.

### Initial process layout and peak-memory annex

`ProcessMemoryPlan` composes a validated container-1.3 artifact with a trusted
image base, heap capacity and initial-thread reservation base. It preserves the
native image minimum and 2 MiB alignment. The shared reservation is the complete
image span, one read-only/NX process startup page, then an explicit heap capacity
at least as large as the initial commit and no larger than the application heap
limit. Its initially committed heap prefix is RW/NX; the remainder stays unmapped
but reserved. Image holes are reserved too. Heap growth requires new backing and
table charges before extending this prefix, without invading thread reservations.
This layout is specific to the new preflight; ABI 1.0–1.3 meanings do not change.

The initial thread uses `ThreadMemoryPlan` without treating it as a worker or
omitting any of its guards, TLS, IPC or descriptor charges. Its entire reservation
may be below or above the shared reservation, never overlapping even unmapped
bytes. Placement still supplies no ASLR entropy or collision check against other
live owners. Entry and trampoline offsets are resolved only from the validated
artifact. The standalone initial descriptor has the composed addresses and TLS
pointer, with worker entry/argument zero; its token is informational. A complete
native process startup, publication and executable authority are not supplied.

At most sixteen image mappings, process startup, optional committed heap and
four thread regions fit a fixed array of twenty-two regions. Count the union of
lower-table prefixes across this array and add one process root; do not add the
thread's separately conservative table bound again. This counts tables needed by
user mappings. Architecture-specific kernel/shared root entries and their owned
tables must be separately accounted by native composition.

The loading model uses dedicated pages for the full executable staging buffer
and an independent retained initializer copied from its validated immutable
suffix. Round each allocation separately; zero initialized bytes require zero
initializer backing pages, while empty compiler TLS still has its own control
allocation. The original image-source bytes, retained initializer and each
thread TLS mapping all count independently. Logical steady pages are shared
mappings plus thread mappings plus combined tables plus initializer backing.
Peak pages additionally include the complete staged executable. Ordinary frames
subtract the two already-owned boot IPC pages, while logical residency and one
task IPC slot still attribute them to the initial thread. The reserved virtual
charge sums both full, disjoint windows; intervening unreserved addresses do not
count. Mapped, peak resident, reserved, peak ordinary-frame, task IPC, complete
TLS, initializer and staging-byte limits must all hold together.

This calculation acquires nothing and promises no successful allocation. Reserve
before copying, and keep the peak charged until the staging owner is actually
released. Package headers/manifests, signature or I/O staging, allocator overhead,
context/mapping/wait/runtime metadata and service reserves are additional inputs.
The native integration must retain an immutable process-lifetime initializer,
rollback partial preparation, revoke creation and wait for quiescence before
releasing it. Those ownership and complete native-admission obligations remain
in #206/#207; a copyable plan is not evidence that they have been satisfied.

### Owned initializer and logical backing annex

`StagedTlsImage::prepare` consumes an owned executable `Vec<u8>`, charges its full
capacity to a shared `TlsBackingAccount`, validates its immutable bytes, and builds
`ProcessMemoryPlan` from that same artifact. It reserves initializer pages before
fallible allocation. Both actual capacities, independently rounded to pages, must
fit the shared backing account and the process's peak memory budget before any
initializer zeroing/copying. Extra staging capacity is checked before attempting
initializer allocation. The plan updates capacity charges atomically; it rejects
undercharges, overflow and budget exhaustion without changing its previous value.
The exact staged executable length remains the format/staging-byte constraint.

The initializer copy reads only the exact validated suffix, never a running image.
All of its available capacity is cleared before copying the initialized prefix.
Preparation has no fallible step after the checked copy. Failure drops accepted
buffers and refunds their private, non-cloneable reservations exactly once.
Declaration and field drop order release allocations before their logical charge.
There are no persistent raw template pointers, clones, user callbacks or resumable
readers. Revalidating an immutable artifact view avoids a self-referential owner
and unsafe lifetime extension; it is bounded by the existing artifact limits.

Image consumers can borrow the staged artifact. Consuming `release_staging` requires
all such borrows to have ended; it drops executable storage and transfers the
unchanged initializer owner/reservation into `ProcessTls`. Future TLS copies use
its stored compiler layout and immutable prefix, fully initializing exclusively
borrowed destinations. Mutating another thread's TLS or the ordinary writable
image cannot change this source. `stop_creation` takes exclusive access, permanently
rejects new copies and retains storage and charges. Drop releases the buffer then
its reservation. Safe Rust borrowing establishes synchronous reader quiescence.

The shared account uses `Cell` and deliberately is not `Sync`; introducing SMP
requires a reviewed synchronization/ownership boundary. The caller keeps the
account alive for every owner and supplies an allowance after protected reserves.
This is logical heap-buffer accounting, not a new physical frame pool: allocator
bookkeeping, size classes and transient allocation behavior need the allocator's
own bound, and inline owner/account metadata needs separate compiled charges.
The incoming staging allocation remains the caller's responsibility until transfer;
a failed preparation consumes and drops it. No physical admission credit follows
from successful logical reservation, and heap drop is not certified erasure.

Native #206/#207 integration must keep the process owner until creation is revoked
and machine contexts/page-table users are quiescent, and perform physical release
and zeroization in the established order. The Rust owner cannot establish those
machine facts. Native package verification, process startup publication, global
context/runtime budgets and the separately versioned C binding remain distinct
acceptance requirements. Current native admission remains closed.

### Native mapping and TSS ownership

Stack, TLS and IPC mappings are RW/NX and process-owned; guards remain unmapped.
The mapping service refuses arbitrary unmap/protection changes to live managed
thread regions. Partial overlap, arithmetic overflow, aliasing, mapped guards,
and executable TLS/stack are rejected. All published regions count toward
mapping and committed/reserved-page budgets. Thread metadata has kernel-owned
lifetime independent of a user pointer. Freed backing is zeroed before reuse.

Guard pages do not stop a large stack-pointer jump over the guard. Compiler
stack probing and its target coverage must be verified for the supported
toolchain; do not claim guards alone prevent every stack overflow. Stale user
pointers after a stack/TLS free are not prevented by generation-checked tokens.
They remain within the shared process trust boundary.

TLS keys have process-owned definitions and thread-owned values. Key deletion
invalidates a generation and does not call destructors. Reuse cannot expose an
old value to a new key. Normal thread exit clears a value before calling its
destructor in userspace, snapshots callback metadata safely, and permits at
most four destructor passes. No runtime metadata lock is held while calling
application code. Re-registering values cannot extend the pass count. A
callback may still loop forever: preemption and supervisor stop remain the
escape, not an unsafe forced return into surviving sibling state.

## Decision 5: first synchronization backend owns state in the kernel

### BSD, macOS and BeOS comparison

This comparison informs the mechanism, not source reuse or a compatibility
claim. FreeBSD is the BSD implementation examined here; other BSDs may differ.
The BeOS references are historical documents hosted by Haiku, not evidence that
every current Haiku implementation detail is identical.

- FreeBSD's `_umtx_op` separates private from shared sleep queues and combines
  userspace lock state with kernel blocking. Private keys avoid unnecessary
  shared-mapping identity work. Its robust-lock machinery also records an
  in-progress lock/list operation, illustrating that owner death must cover
  transitions as well as fully acquired locks. Reuse the scoped wait and
  publication principles; TROE does not adopt address-derived authority or
  user linked-list traversal. See the
  [FreeBSD interface manual](https://man.freebsd.org/cgi/man.cgi?manpath=FreeBSD+14.2-RELEASE+and+Ports&query=_umtx_op&sektion=2).
- Apple's published pthread implementation uses atomic acquisition and distinct
  ulock/psynch paths; the shown ulock eligibility is restricted by mutex type,
  sharing and scheduling policy. First-fit permits acquisition ahead of a woken
  waiter, while fair handoff has different costs. We should measure throughput
  and worst-waiter latency separately, rather than claiming FIFO is always
  fastest. See [Apple libpthread](https://github.com/apple-oss-distributions/libpthread/blob/main/src/pthread_mutex.c).
  XNU reads the user lock value while serializing the wait decision and handles
  faulting/alignment-sensitive copyin explicitly. A userspace atomic path still
  needs a careful kernel sleep boundary; see
  [XNU ulock](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_ulock.c).
- BeOS's benaphore combines an atomic counter with a kernel semaphore so
  uncontended entry/exit avoids semaphore calls. Reuse that separation as an
  optimization candidate for ownerless notification, not an unexamined mutex
  replacement. The short historical algorithm does not settle TROE's timeout,
  stop, overflow, poisoning or reclamation requirements. Do not transplant its
  historical performance numbers. See the original
  [Be engineering article](https://www.haiku-os.org/legacy-docs/benewsletter/Issue1-26.html).
  BeOS team-owned semaphore cleanup and explicit errors on deleted semaphores
  also support making lifetime failure visible; TROE keeps its stricter
  generational ownership and admitted-operation references. See the
  [Be Book semaphore contract](https://www.haiku-os.org/legacy-docs/bebook/TheKernelKit_Semaphores.html).

The engineering conclusion is that uncontended userspace work plus kernel
blocking is a credible efficient destination. It is not inherently less secure.
The first kernel-owned backend below is a correctness reference and initial
implementation, not a permanent requirement that every lock take a syscall.
[#209](https://github.com/dennissoftman/troe/issues/209) owns a measured fast-path
decision after the baseline exists. Any replacement must retain the same
publication, owner-death and lifetime semantics. No spinning is introduced on
the single CPU while the owner cannot run, and bounded barging requires separate
starvation evidence before replacing FIFO handoff. Numeric thread IDs remain
identities rather than authority; kill/suspend and realtime-priority APIs from
other systems do not follow from reusing their synchronization ideas.

### Initial backend

Use a small process-private synchronization service built on one portable
bounded wait engine. Its first object types are an owner-tracked mutex, a
condition queue, and an ownerless bounded permit counter. Thread completion,
sleep, and stop notification use the same wait-registration lifecycle.

Objects are explicit handles, not raw user addresses. No user linked lists,
robust-list traversal, arbitrary futex words, address-keyed global hash table,
PI requeue operations, or implicit cross-process shared-memory synchronization
enter this profile. A user object may store an opaque token, but the kernel
stores authoritative owner, queue and generation state.

Uncontended synchronization also enters the kernel in this first backend. That
cost buys consistent ownership validation and eliminates a second user/kernel
state-reconciliation algorithm. This is a deliberate performance tradeoff, not
a claim that address-based futex designs cannot be safe. Do not add an atomic
fast path until measurements justify its separate proof of publication,
owner-death, unmap/reuse, memory ordering, and rollback behavior.

Kernel-managed objects also enlarge the privileged parsing/state-machine
surface and consume kernel metadata. They are not automatically more secure
than a carefully verified userspace fast path. Keep the object types closed,
reuse the wait engine, cap every collection, fuzz malformed requests, and
compare both designs only after the baseline's cost is measured. The chosen
first backend favors a smaller ownership proof, not moving application policy
or lock-protected data into the kernel.

### Common wait rules

- Each thread has one active blocking operation and pre-reserved queue/deadline
  metadata. A condition-to-mutex transfer reuses the reservation; timeout and
  process teardown require no allocation. Stop observation is a second event
  source of that same operation, not a second uncontrolled waiter.
- Validation and capacity checks precede side effects. Queue insertion and
  state testing are atomic with respect to wake, timeout, stop and destruction.
  A wake cannot fall between checking a predicate and publishing the waiter.
- Every completion owns one generation-checked operation identity and commits
  once. Late timer, IPC and wake events become stale and cannot complete a new
  wait in a reused thread slot. Tokens alone do not keep storage alive: owned
  references and removal acknowledgements do.
- Admission uses FIFO queues; unlock/release transfers ownership or a permit
  directly to the selected waiter, preventing newcomers from stealing a grant.
  No busy-spinning or repeated polling is used while an owner is descheduled.
- Broadcast work is bounded by the admitted thread ceiling and processed in
  chunks if it exceeds the kernel's work quantum. Its selected waiter cohort
  is fixed at linearization; later arrivals cannot join an old broadcast.
- Native deadlines are absolute monotonic values or an explicit no-deadline
  tag. Invalid, overflowed or unavailable-clock requests fail before enqueue.
  An already expired blocking deadline returns timeout before acquisition; a
  separate try operation tests immediate availability without a deadline.
  An already requested opt-in stop likewise returns before side effects. In a
  condition call either early return leaves the supplied mutex held. Timer
  granularity is reported; hardware timer
  range is handled by bounded rearming without shortening a long deadline.
- Before granting a queued operation, check its deadline against the same
  monotonic clock. An expired waiter cannot acquire through a late wake. A
  grant committed before expiry wins over a later timeout or stop; never report
  cancellation after silently handing ownership to the caller.
- Compiler barriers in SDK calls and architectural barriers implement release
  on unlock/permit release/start/exit and acquire on successful lock/permit
  acquisition/first entry/join. Failed acquisition grants no synchronization.
  A trap or disabled interrupts is not itself a C/Rust memory-order proof.

### Mutexes

Native mutexes are non-recursive and owner-checked. Self-lock reports deadlock;
non-owner unlock reports an ownership error. Destroy requires no owner, waiter,
pending grant, or condition reacquisition reference; otherwise it returns busy.
Unknown attributes fail before creation. The owner list is kernel-owned and
bounded by the process object quota. An owner exiting with a held mutex applies
its immutable owner-death policy. The application default is permanent poison:
clear the dead ownership, complete admitted waiters with `Poisoned`, and reject
future acquisition without granting a guard. Destroy requires all waiter and
completion references to drain. There is no clear-poison operation or automatic
repair in this profile. A separately selected fail-process policy terminates
the process when allocator or other essential runtime invariants are lost.
A malformed caller token does not crash the kernel.

Poisoning protects clients that honor the synchronization protocol. It cannot
prevent a sibling from reading raw shared memory, recognize every language
exception, or prove application state consistent. If language unwinding releases
a mutex before native thread exit, any language-level poisoning belongs to the
runtime. Neither native poisoning nor process-fatal owner death is silently
advertised as POSIX robust-mutex behavior; that requires an explicit recovery
contract, including ownership on `EOWNERDEAD`.

The initial profile has no priority inheritance or priority ceilings because
it exposes no application-selected scheduling priorities and no cross-process
mutex. Process fairness and within-process FIFO ordering address scheduling
starvation, not arbitrary application deadlock. Self-join/self-lock are detected;
there is no promise of detecting every mutex/join/IPC/permit dependency cycle.
Wait-state diagnostics, optional deadlines and owner-authorized process stop
remain available when application logic deadlocks.

### Condition queues

`condition_wait(condition, mutex, deadline, optional_stop)` validates ownership,
binds the condition to that mutex while waits/reacquisitions exist, publishes
the waiter, and releases the mutex in one kernel transition. Mixed concurrent
mutex bindings fail before releasing anything. Notification is not a stored
permit: notifying with no admitted waiter has no future effect. The predicate
belongs to the application and must be retested under the mutex.

Notification, timeout and cooperative stop all move a waiter to reacquire its
original mutex before returning. The condition binding and references survive
that transfer. The pre-reserved wait node makes the transfer allocation-free.
A timed condition wait may therefore return after its deadline while awaiting
the mutex; its deadline bounds the condition phase, not mutex reacquisition.
Pretending otherwise would return code to an unprotected critical section.
Process termination ends the operation without returning to user code.

If the mutex becomes poisoned before reacquisition, the operation instead
returns `Poisoned` without ownership. This is a distinct terminal resource
failure, not a timeout or successful condition return; the caller must not
access the protected data. The libc adapter must preserve that distinction and
declare its exact unsupported/recovery behavior rather than mapping it to an
error that promises the mutex is held.

If a selected notification races with timeout/stop before selection commits,
skip that waiter and select the next eligible one; no notification disappears
into a waiter already committed to timeout. After selection commits, later stop
does not retroactively change its result. Notify-all affects its entire fixed
eligible cohort. Destroy is busy until queued and reacquiring waiters are gone.
No automatic mutex unlock occurs on timeout or return.

### Ownerless permits

A permit counter has an immutable maximum and a checked current count. Release
is allowed by a different thread; overflow is an error. A grant atomically
consumes one permit or transfers one to an admitted waiter. Cancellation before
a grant consumes nothing; a committed grant returns success. There is no owner
to repair or automatically refund on thread exit.

This is intentionally separate from a mutex. It supports producer/consumer
notification and the ownerless semantics required by Python's basic `Lock`.
A maximum of one provides its binary state; recursive `RLock` requires explicit
runtime ownership tracking. A permit leak can stall the application but cannot
strand kernel memory after process teardown. Private permits are not a claim
of POSIX named or process-shared semaphore support.

Destroy requires no admitted waiter or pending grant/reference. It invalidates
the token even if the remaining count is below the maximum; unlike a mutex,
there is no owner whose outstanding use the kernel can prove. An application
must quiesce its consumers first. Closing a handle does not wake unrelated
objects or recycle a token while an admitted operation still references it.

## Decision 6: cooperative stop and process-wide forced termination

Native stop requests are sticky, idempotent notifications. An opt-in wait can
return `stop_requested`; ordinary CPU work checks explicitly. The operation
does not unwind stacks, run cleanup handlers, release locks, inject exceptions,
or guarantee that the recipient has stopped. A thread may deliberately ignore
it. Requesting stop after completion is an idempotent observation of completion.

There is no asynchronous thread cancellation, thread-directed Unix signal,
forced sibling suspension, or privileged callback injection. These could stop
a thread inside allocator/runtime invariants while leaving siblings alive.
A supervisor needing a hard deadline terminates the whole process after its
configured grace period. Application-level timeouts do not silently escalate
to process termination; that is an explicit supervision policy.

Native SDK examples should use owned task scopes: finish or request stop, join,
and only then release borrowed application state. A scope must not detach on
timeout and free memory still in use. Scope shutdown can wait indefinitely
without supervisor policy; reliable reclamation is supplied by process stop,
not a promise that every application cooperates.

Graceful C process exit is a userspace protocol: stop admission, ask siblings
to finish, and wait for quiescence before process-wide callbacks or shared
runtime destruction. In the new threaded profile this protocol runs only under
a finite supervisor-granted monotonic shutdown deadline, which includes joins,
flushes and callbacks together and cannot be extended by user progress reports.
With no granted grace, use immediate process termination. The package/profile
declares this cleanup contract; existing single-thread artifacts keep their
existing exit behavior. Do not advertise unconditional atexit execution in the
threaded facade.

A caller holding locks needed by siblings can prevent graceful quiescence;
deadline expiry then stops the whole process. It must not execute callbacks
concurrently or secretly kill one thread to proceed. Concurrent exit callers
elect one finalizer; others finish their own orderly thread shutdown rather
than waiting in a way that prevents the finalizer's quiescence. No new thread,
atexit registration, or second finalization cycle is admitted once finalization
begins. Immediate exit and supervisor force-stop skip user callbacks and
terminate all threads. Destructors, flushes and atexit are never prerequisites
for kernel reclamation and are not promised after forced termination.

## Decision 7: scheduling, IPC and shared services must become thread-aware

The first implementation remains single-CPU. A process owns one address-space
root; each thread owns one register context. Sharing a root requires a new owned
process/session split, not cloning a root-owning `ApplicationSession`. Mapping
mutation, context activation and final root destruction are serialized.

Schedule processes fairly first, then select a runnable thread within the
chosen process. Creating, waking, joining, yielding or handing work to siblings
does not multiply the process's service share or reset its remaining slice.
All ordinary execution charges the owning process; delegated service execution
also retains its existing call-chain attribution without double charging CPU.
Normal slice expiry preempts; it is not an application fault. The existing
absolute protected-IPC lease and terminal failure semantics stay intact.

Lifecycle churn and repeated failed requests also consume CPU. Bound kernel
work per dispatch, charge resource-management continuations to their requesting
process, and return to scheduling between batches. A sequence of cheap traps
must not reset the same process's scheduling entitlement. Critical kernel
sections cannot sleep on a user mutex or execute application callbacks.

Every direct handoff and nested call retains the original chain identity and
deadline. No thread may mint a new donated lease by relaying a call to a sibling.
The first profile forbids transfer of an active reply/continuation to another
server thread. The initiating server thread must complete it. A thread blocked
on a private mutex does not implicitly donate its client's budget to the owner.
Other runnable threads remain schedulable under the process policy; outstanding
service deadlines continue to bound the blocked client. Supporting a worker
pool with continuation transfer requires a separate ownership/lease extension.

Each admitted thread needs its own IPC TX/RX pair, pending call, completion
generation and wait association. Handle ownership remains process-wide; call
identity is thread-specific. No process-global scratch buffer may carry two
concurrent requests. Existing ABI 1.3 startup addresses continue to describe
only the initial thread; a new thread descriptor supplies per-thread addresses.
The current finite IPC pool is an admission dependency, not an invitation to
multiply its size without accounting. Supervisor aliases never grant a sibling
process a user mapping. Siblings within this process can modify these buffers
and are treated as untrusted callers, not protected peers.

Before parsing a request, copy it into bounded kernel-owned storage or consume
it through the already validated synchronous copy boundary. Validate the copied
representation, not a later reread of mutable user fields. Retain no user pointer
or kernel borrow across a blocking operation. Reply delivery uses owned pinned
regions and checks process/thread/operation generation before publication.
Unmap, close, revoke, completion and teardown races have one serialized winner.
Pinning a page protects lifetime, not the integrity of its mutable contents.

Legacy services may have one operation per handle. Preserve that contract by
an explicit per-handle serialization or a typed busy result; do not race their
state or pretend to support concurrent calls. Descriptor close during blocked
I/O marks it closed to new calls while the admitted operation keeps an owned
generation reference; reuse cannot redirect the old result to a new file.
Terminal input remains one process/session loan with one serialized reader;
threads acquire no extra input authority. Process launch and descendant quotas
remain shared, including concurrent launch attempts.

The C bridge must be decomposed so no two callbacks form overlapping mutable
Rust references. Acquire synchronization before constructing an exclusive
reference and bound its lifetime to the protected component. A global bridge
lock held across sleep, terminal read or IPC is not acceptable: it could stop
the sibling required to make progress. Stage copied arguments and release
metadata borrows before blocking; use owned per-operation and per-resource
state. Audit allocator growth, FILE buffers, shared offsets, cwd, environment,
atexit, time conversion buffers, error state, and TSS initialization. Application
callbacks run outside internal runtime metadata locks. A once initializer holds
only its own logical initialization mutex, which deliberately serializes that
application initialization and detects recursive entry. The GIL does not
protect the C runtime.

Future SMP requires explicit kernel synchronization, cross-CPU quiescence,
mapping shootdown, memory-order tests, and per-CPU architectural-state ownership.
Interrupt masking on one CPU is not a lock. This design preserves the ownership
boundaries needed for that work but makes no untested SMP correctness claim.

## Decision 8: bounded admission and teardown

All limits are simultaneous constraints, not promises that physical resources
exist. There are separate per-process and global limits for prepared/live/
completed thread records, synchronization objects, TLS keys, waits, pending
calls, IPC pairs, mapping records, stack/TLS pages, and kernel metadata bytes.
Prepared and completed objects cannot evade quotas. Growth is fallible;
ordinary unlock, wake, timeout, completion and revocation allocate nothing.

For the first implementation, retain the protected IPC pool's existing global
context ceiling rather than adding a new larger pool. A worker consumes the
same scarce context resources as an initial thread. Reserve boot-service and
supervisor capacity before admitting application workers. Per-process worker
ceilings must be lower than the unreserved global allowance so one process
cannot exhaust every context needed for essential progress. Single-thread
legacy execution outside that pool keeps its existing admission rules.

### Portable metadata and paired-capacity annex

`ThreadTable` and `SyncTable` require a metadata-byte budget at construction.
Their `metadata_layout` methods compute `core::alloc::Layout` values from the
actual compiled types: each inline owner, two lifecycle buffers (process slots
and retained thread slots), and three synchronization buffers (process slots,
object slots and wait slots). Full `Option`/enum and record padding is included;
no wire layout or guessed per-thread byte constant stands in for these records.
Requested totals are checked without allocation. After fallible reservation,
actual vector capacities are charged and checked before the owner is returned.
Any failure drops the unpublished buffers. Empty slots, completion tombstones,
unused wait slots and process removal never refund this retained backing;
`metadata_bytes()` stays constant until the entire table is dropped.

This is logical allocated storage, not a complete heap/physical-memory bound.
Allocator bookkeeping, size-class rounding, fragmentation, and transient
allocator behavior remain outside these requests and need the allocator's own
bounded backing. `try_reserve_exact` is fallible and does not promise physical
success merely because preflight fits. Native contexts, mapping records, IPC
state and libc/TSS metadata are additional compiled owners in #206/#207.

`ThreadAdmissionPlan` composes both table requests. It requires valid process,
thread and object counts, a positive per-process thread ceiling strictly below
the global thread count, and nonzero protected task IPC headroom. Subtract that
headroom with checked arithmetic before comparing retained thread capacity;
kernel-continuation pairs never enter the task allowance. Reserving headroom
outside the application table prevents its workers and unreaped records from
consuming capacity assigned to essential services and teardown progress. The
exact reservation is supplied by composition, not guessed or expanded by the
planner. One global wait slot is reserved for every thread record, including
the initial thread. Per-process quotas remain simultaneous ceilings, not a
guarantee that all processes can attain their maximum together.
The global table may not exceed the aggregate process quotas: such slots could
never be used and would waste reserved metadata. Together with the strict
per-process ceiling, this paired application pool needs capacity for at least
two processes; this is not a requirement that two processes be running.

`maximum_capacity` derives the largest fitting global thread count for fixed
process/object counts and a per-process ceiling. Start with the minimum valid
configuration, subtract its fixed metadata charge, and divide remaining bytes
by the compiled cost of one lifecycle slot plus one wait slot. Cap the result
by aggregate process quotas, unreserved task context capacity and the existing
record backstop, then validate the resulting plan. The calculation allocates nothing and selects no
product default; it exposes the actual binding constraints for profile review.

Pair construction leaves the synchronization request available while creating
the lifecycle table, checks its actual charge, then uses the remaining budget
to construct synchronization storage. Only both complete empty tables are
returned, with the configured per-process ceiling installed in lifecycle quota
validation. No process or native thread is published during this operation.
The page allowance supplied to this operation is independent of metadata and
does not allocate those pages. The plan is a copyable configuration, not a
unique reservation token: native composition must still serialize global
admission, subtract existing owners/retired IPC slots, reserve actual resources,
and establish the mapping and quiescence obligations.

### Complete native admission and teardown

Exact worker/object limits and default stack sizes are acceptance inputs,
not invented performance claims. Derive them from compiled record sizes,
page-table geometry, two IPC pages per thread, TLS extent, guarded stack
commit, service reservations, and existing system memory reserves. Count the
whole expression, including preparation rollback and completion tombstones:

```text
process logical charge = shared image/root/runtime
               + sum(thread stack + TLS + IPC + mapping overhead + metadata)
               + synchronization objects + retained completions
global physical charge = shared process physical owners + ordinary thread frames
                       + IPC boot pool once + other supervisor/service storage
```

Preflight rejects an impossible declared configuration before boot services
publish readiness. The default must admit the selected Python demonstration
alongside essential services; otherwise reduce consumer scope or review an
explicit pool expansion with evidence. Do not silently raise all resource
ceilings to make a stress test pass. Accounting reports shared pages once and
per-thread pages separately, with zeroization work and high-water marks visible.

Forced teardown is an owned, bounded continuation:

1. Mark the process stopping, prohibit admission/publication, and prevent every
   thread from returning to userspace. Recapture the executing thread by the
   existing timer/mechanism boundary. No cleanup callback is invoked.
2. Revoke new calls and stop authority, cancel pending calls and waits, invalidate
   generations, remove ready entries, and resolve externally visible call fates.
   Never replay a possibly delivered mutation as a cleanup convenience.
3. Drain owned event/completion references and detach IPC/endpoint associations.
   No waiter needs to reacquire a user mutex to acknowledge forced teardown.
4. Retire architecture contexts and mapping references, zero and free thread
   regions, and release shared process resources only after the last reference
   is gone. Return quota and physical ownership once, in bounded batches.
5. Publish one bounded process result, then reap according to its owner policy.

Quarantined or deferred resources stay charged and unavailable for reuse until
reclamation is proven. An inconsistent accounting/reference invariant follows
the kernel's fail-closed fatal path; do not free uncertain live storage merely
to report a successful cleanup. Failure of an application callback cannot
force the kernel to run it again or retain memory indefinitely after forced stop.

## Decision 9: a deliberately selected compatibility profile

This is source compatibility through the TROE sysroot, not a Linux syscall ABI
or a claim of complete POSIX conformance. Build manifests enumerate symbols,
attributes, clocks, limits and error mappings. Never advertise a standards
option macro for a partial implementation. Absence is preferable to fabricated
success; APIs without an error return must not conceal admission failure.

| Surface | Proposed treatment |
| --- | --- |
| create, join, detach, self/equal, exit | Implement over native lifecycle; reject caller-owned stacks and unsupported attributes. |
| process exit / atexit | Threaded profile uses bounded supervised quiescence before callbacks; absent grace or deadline expiry skips callbacks and terminates the process. Declare this cleanup limitation. |
| mutex, trylock, unlock | Implement owner-checked private mutexes; default uses defined error-checking behavior. |
| recursive mutex | Optional libc adapter with bounded depth, actual owner identity, and tests; not a native default. |
| condition wait/signal/broadcast | Implement atomic release/wait/reacquire; ordinary results retain mutex ownership. Poison is a separate resource failure returning without ownership, with explicit compatibility mapping. |
| monotonic timed waits | First supported clock, with exact timeout conversions and rounding. |
| realtime timed waits | Excluded initially. Requests using the default pthread realtime clock return an explicit unsupported error; ports select a monotonic attribute/API. Preserve the default clock identifier rather than silently changing its meaning. A future adapter needs clock-change tests and a separate acceptance decision. |
| once / C11 call_once | Serialize initialization with a native owned mutex; publish success only after normal return. Recursive entry or admission failure is process-fatal, including for void-returning call_once; this extension is documented rather than advertised as complete POSIX conformance. |
| thread-specific keys | Implement generational keys, per-thread values and bounded destructor passes. |
| C11 thread/mutex/condition APIs | Map only fully specified selected operations; document return-code translation. |
| private bounded semaphores | Add only with a named consumer and overflow contract; the ownerless native permit already supplies the mechanism. |
| rwlocks / barriers | Defer until a named workload justifies them; require writer-starvation, upgrade/downgrade and broken-participant decisions. |
| pthread_cancel / asynchronous cancellation | Excluded from the initial facade; native stop is not silently substituted for POSIX cancellation. |
| robust mutex / owner-state repair | Excluded initially. Native poison and opt-in fail-process policies are explicit; neither claims robust POSIX recovery. A future repair protocol must prove consistency before reuse. |
| process-shared/named synchronization | Excluded; separate IPC authority/lifetime design required. |
| priorities, priority inheritance, realtime policy, affinity | Unsupported settings fail explicitly; queries describe actual single-CPU scheduling. |
| fork, atfork, thread-directed signals, forced suspension | Excluded; no implied process or signal facility. |
| dynamic TLS, native module loading, free-threaded CPython | Separate work; none is required for ordinary GIL-based Python threads. |

Static pthread initializers require a race-safe lazy object admission path.
Concurrent first use admits one object, reclaims losing provisional objects,
and reports exhaustion through APIs that can report it. Bootstrap synchronization
cannot itself call malloc or a once initializer that depends on that same
object. Explicit initialization is preferred for native callers. Copying or
reinitializing a live libc synchronization object is invalid; the kernel still
validates any token and contains malformed userspace state.

Timed compatibility wrappers must preserve their own immediate-acquisition
and expired-deadline semantics. For example, an API permitting acquisition of
an available mutex despite a past deadline tries first; a condition API
requiring release/reacquire even on immediate timeout performs that transition.
Do not infer source compatibility from matching function names. Port probes
must verify these details as well as the explicit realtime-clock rejection.

For once, the facade reserves a fail-process native mutex without using the allocator or
once machinery it may be initializing. It holds that logical mutex across the
initializer, marks completion only on normal return, then unlocks. No internal
metadata lock is held across the callback. Exiting inside initialization is
owner death and process-fatal; there is no retry over partially initialized
shared state. Repeated completed calls observe publication through the same
mutex. The documented process-fatal recursion/exhaustion extension applies to
both pthread_once and C11 call_once, never a false successful return.

POSIX cancellation and robust mutex behavior are defined, substantial semantics,
not miscellaneous flags. The standards describe cancellation cleanup around
condition waits and owner-death recovery states; importing them would require
those obligations. This profile chooses a smaller failure model. See the
[POSIX.1-2024 general interface rules](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html)
and [condition wait contract](https://pubs.opengroup.org/onlinepubs/9799919799/functions/pthread_cond_clockwait.html).
Linux's [FUTEX_WAIT contract](https://www.man7.org/linux/man-pages/man2/FUTEX_WAIT.2const.html)
is a useful reference for atomic check-and-block, not an ABI to copy here.

## Python consumer boundary

First support ordinary GIL-based CPython. Restore real compiler TLS, thread-
specific error state, honest timed waits, thread exit, and synchronized runtime
callbacks before removing any negative thread test. Audit the exact pinned
versions' platform backends instead of assuming they all use identical locks.

Python's basic `Lock` is ownerless; `RLock` tracks an owner and recursion level.
Condition waiting may fully release and then restore a recursive lock. Preserve
these distinctions with the runtime adapter, not relaxed native mutex checks.
Python daemon-thread shutdown is interpreter policy, not a kernel detach mode
or permission for a thread to outlive its process. Interpreter finalization
must quiesce access before shared runtime destruction. These requirements are
documented by [Python's threading reference](https://docs.python.org/3/library/threading.html).

The first useful consumer gate is `Thread`, `Lock`, `RLock`, `Event`,
`Condition`, `local`, and `Queue` with timed blocking and orderly shutdown.
Test a compute-bound Python thread alongside a timer/progress thread to expose
GIL/timer starvation. Package demos using tqdm monitoring and alive-progress
follow; successful threads alone do not prove their imports, dependencies,
terminal rendering, or whole-package compatibility.

## Failure and adversarial acceptance matrix

Every row needs portable state-machine coverage and applicable native coverage
on x86-64 and AArch64. Test both legitimate races and hostile ABI requests.

| Boundary | Required cases and invariant |
| --- | --- |
| creation | Exhaust every reservation stage; malformed entry, alignment, size and flags; stop/start/creator-exit races. No partial runnable object or uncharged reservation. |
| identity | Wrong process/type/right, stale generations, slot reuse and generation exhaustion. Never alias another lifetime. |
| context | Interleave registers, TLS, errno, FP/SIMD, rounding state and stack canaries; fault on forbidden mappings. No cross-process residue or privilege restoration. |
| lifetime | Immediate child exit, double start, join-before-exit, exit-before-join, self/concurrent join, detach/join/timeout, main-thread exit and last-thread exit. One result and one reap. |
| wait | Exhaustion before enqueue, notify-before/after publication, stale timeout, repeated wake, timeout/stop/grant permutations and deadline overflow. One completion and no lost eligible wake. |
| condition | Mixed mutexes, non-owner call, notification cohort, timeout during reacquire, destroy during reacquire, stop after selection and owner exit. Ordinary returns own the mutex; poison returns explicitly without ownership. |
| mutex | Wrong owner unlock, self-lock, destroy-held, FIFO contention, both owner-death policies and granted-but-not-resumed owner during stop. Poison grants no ownership; fail-process requests termination; neither silently repairs state. |
| permit | Cross-thread release, double release/overflow, queued transfer, timeout versus grant, exiting consumer. No invented owner or duplicate permit. |
| libc | Simultaneous static initialization, once recursion/failure, allocator growth during callbacks, shared FILE/offset, blocked read plus sibling write/close, cwd/environment access. No aliasing, lock bootstrap cycle or unintended global stall. |
| TLS | Template overflows/relocations, key reuse/delete race, repeated destructor registration, destructor fault/loop. No stale value or privileged callback. |
| IPC | Concurrent calls with same handle, separate buffers, endpoint restart, stale reply, unmap attempt, sibling-buffer mutation, thread/process exit and nested lease expiry. No cross-call delivery, new authority or renewed lease. |
| scheduling | Many workers versus one worker, yield/wake storms, busy loops, all threads blocked, timer wrap boundary and idle wake. Thread count cannot multiply process share. |
| cleanup | Forced stop at every state and failpoint; unjoined and detached threads, queued broadcasts, callbacks that never return and outstanding I/O. Resource baseline restored without user cooperation. |
| bounds | Essential services under maximum admitted application load, minimum free memory and saturated metadata; measured zeroing/reaping quanta. No starvation of control/teardown resources. |

Explore all short schedules of the portable lifecycle/wait models, including
reordered and duplicated external events. Add memory-order litmus coverage for
the chosen acquire/release boundaries and inspect generated atomics on both
targets. Native tests must reproduce actual preemption, IPC suspension and
mapping reclamation; passing host models cannot establish those mechanisms.
No finite suite proves all schedules safe; reviews must state the residual
assumptions and keep the single-CPU acceptance boundary explicit.

Measure uncontended and contended lock cost, handoff latency, timeout error,
CPU fairness, allocations on steady paths, memory per admitted thread/object,
teardown latency, and Python producer/consumer throughput. Compare against the
same pinned consumer on conventional systems as context, not as an instruction
to remove ownership checks. Preserve raw failures and distributions. If cost
is excessive, reduce advertised scope or leave the feature disabled rather
than weakening authority, ordering, cleanup or verification requirements.

## Dependencies and implementation gates

[#11](https://github.com/dennissoftman/troe/issues/11) supplies the implemented
C runtime. [#63](https://github.com/dennissoftman/troe/issues/63) must settle the
selected libc source/profile and ABI boundary for its adapter; completing a
whole musl migration is not required to model native threads. Integration
should use the merged ownership/IPC result of
[#188](https://github.com/dennissoftman/troe/pull/188), not a competing rewrite
of the same suspended-context and supervision paths. This does not depend on
the remaining filesystem/network service migrations in #8. SMP, fork, signals,
dynamic linking and full Stage 11 completion are not prerequisites.

Implementation is gated in this order; these are acceptance partitions of this
decision, not a claim that every partition is complete or a calendar commitment:

1. Accept process/thread ownership, fault/stop behavior, the synchronization
   subset, and the #63 boundary. Write the exact wire/TLS/compiler annex and
   resource proof; verify ports against the selected clock and once policies.
2. Verify portable lifecycle, quota, synchronization and event-race models.
3. Implement shared-root native contexts, thread regions, static TLS and
   thread-specific IPC ownership together, behind explicit admission. Prove
   cross-process isolation and stop/reap on both architectures before enabling
   concurrent C callbacks.
4. Implement wait/mutex/condition/permit operations and the synchronized libc
   bridge. No user-visible thread enablement until allocator/runtime safety and
   no-allocation completion are demonstrated.
5. Port the selected pthread/C11 profile and ordinary CPython; run native and
   upstream consumer gates. Deferred compatibility features stay unadvertised.
6. Publish measured limits and compatibility evidence, complete the hosted
   platform gates, and update current-behavior documentation in the same change.

Before native integration, remaining decisions are explicit blockers:
native composition of the assigned TLS/wire formats; complete resource accounting
and essential-service reservations, including the finite graceful-shutdown
policy; lock ordering and ownership proof for each
blocking C bridge callback. The architectural choices
above narrow these decisions but do not pretend their evidence already exists.

The documentation review at implementation must include README, CORE-SPEC,
SECURITY, architecture/testing guidance, KEX/KCAP/startup contracts, C and Rust
SDK docs, CPython module/build manifests and negative probes, and status notes
in ADRs 0015, 0037, 0052 and 0069. Until native thread enablement, their current
single-thread and native rejected-TLS statements remain correct. Offline
conversion and inspection use the explicit container-1.3 contract. Follow-on delivery
tracking belongs in live issues; this ADR records rationale and acceptance
boundaries, not a parallel repository roadmap.

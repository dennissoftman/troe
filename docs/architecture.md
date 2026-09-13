# Current architecture

The same portable graph is linked into two composition roots:

```text
host stdin/stdout ───────────┐                 ┌─ hosted process
                             ├─ shell ─ VFS ──┤
serial / PS/2 → IRQ → bounded queue → editor ─┘  └─ UART + GOP text console
```

The shell owns parsing, short-circuit logical lists, pipelines, streamed file
redirection, completion orchestration, cwd, session job control, service
control, and nine non-shadowable intrinsics. Portable `troe-completion` descriptors select
trusted semantic resolvers for application arguments without executing the
application or moving replacement, quoting, sorting, and budget policy out of
the shell.
Ordinary commands always load an immutable architecture-specific KEX artifact
into a fresh ring-3/EL0 address space and route cwd/argv, standard streams, and
declared optional services through generation-owned synchronous message dispatch
without exposing kernel pointers.

Repository `scripts` and Cargo commands are bootstrap developer tooling, not a
package manager or a privileged system-control plane. No public TROE package
CLI or privileged system-control plane is implemented. That work is tracked in
[GitHub issues](https://github.com/dennissoftman/troe/issues?q=is%3Aissue+is%3Aopen+label%3Aarea%3Atooling).

`troe-platform` defines immutable named VM descriptions independently of CPU
architecture and execution environment. Build and launch tooling selects the
full platform ID explicitly; the machine crate consumes a validated token for
MMIO/I/O ownership, interrupt topology, console, timer, lifecycle, keyboard,
and virtio transport facts before owned device access. Four platforms are
named, never architecture defaults: `x86_64-q35-uefi` on q35 and
`aarch64-sbsa-ref` on the SBSA reference machine pin their facts, while
`x86_64-uefi-virtio-pci` and `aarch64-uefi-virtio-mmio` obtain the same facts
from bounded ACPI or FDT discovery and boot the deterministic three-disk cloud
bundle. Unsupported firmware fails before device publication or volatile I/O.

## Input-to-output trace

1. A composition root selects validated driver and editor policies. Owned
   device handlers drain only a configured number of raw bytes into a
   preallocated queue, then acknowledge the controller. The portable editor
   enforces its UTF-8 byte bound, cursor-aware editing, volatile history limits,
   and decoded key events; ANSI serial input and x86 set-1 PS/2 input feed the
   same event type outside interrupt context.
2. The shell crate tokenizes iteratively. Single and double quotes group literal
   bytes and record, per character, that quoting made them literal; no
   recursion, substitution, or environment lookup occurs. Bounded pathname
   expansion matches an argument word holding an unquoted `*`, `?`, or `[`
   against the namespace one path component at a time, leaves the command word
   and redirection targets alone, passes a pattern that matches nothing through
   as written, and fails the whole stage before dispatch when it exceeds its
   word, byte, or directory-scan bound (ADR 0057). Unquoted `&&` and `||` form
   left-associative short-circuit lists; `<`, `>`, and `>>` select
   bounded-memory file streams.
3. The pipeline executor protects shell intrinsics, then resolves the KEX
   command path. Absence reports an unavailable application and never selects
   privileged utility behavior. KEX receives bounded stdin/stdout/stderr streams
   plus only declared optional datagram, read-only VFS, streamed file mutation,
   monotonic timer, wall-clock observation or correction, diagnostics,
   process observation, network-observation, DHCP, ICMP, outbound TCP-connect, or inbound TCP-listen handles. Privileged
   wall-clock correction is service-launcher-only. The `sh.kex` interpreter
   alone requests a bounded
   shell-script sidecar: it transactionally stages physical command lines, exits,
   and lets the resumed owning session execute them without nested KEX launch.
   No application receives ambient `Shell`, provider, block, device, or machine
   authority.
4. Each non-final command writes to a dynamically growing, 1 MiB-bounded
   `BoundedOutput`. The next stage reads the frozen result through `SliceInput`;
   a stage cannot observe mutable internals. Final output redirection instead
   range-reads or incrementally writes the namespace with a 16 KiB default
   buffer. Applications may request power-of-two chunks from 4 KiB to 1 MiB;
   file length is governed by the provider format, media, and configured quota.
5. Filesystem commands ask the session's `NamespaceClient` to canonicalize from
   the logical cwd. Immutable KEFS content and the writable `/tmp` RAMFS are
   separate providers behind one contract, not one shared node model.
   The current recovery root keeps executables in `/bin`, recovery-only
   bootstrap files in `/recovery`, architecture-independent package data in
   producer-owned `/share/<name>` directories, and persistent or mounted data
   under `/vol`. `/config` is the persistent desired-state mount point;
   `/sys/config` is an immutable, bounded projection resolved for exactly one
   active package generation. The system has no `/etc` directory or alias. KEX
   applications are statically linked, `/lib` is not present, and executable
   code does not belong in `/share`. Optional large runtime executables live
   only in `/vol/shared/bin/<architecture>`, outside rootfs and EFI,
   and optional runtimes own `/vol/shared/bin/<architecture>` with their
   libraries in `/vol/shared/lib/<architecture>` on the same terms.
6. The final output capability writes host bytes or the native UART.
   When validated GOP metadata is available, normal native shell output is also
   rendered into an owned fixed-glyph framebuffer console. UEFI text output is
   confined to the pre-handoff banner.

`tools/mkruntime.py` owns the shared runtime-tree boundary. It emits the exact
`bin/<architecture>` layout, canonical path-sorted length/SHA-256 manifest, and at most
128 architecture-owned KEX entries. Verification rejects symlinks, extra or
missing files, noncanonical records, unsupported schemas, wrong lengths,
oversized artifacts, and digest changes. Mounted-root and detached-image
installation both verify the source and destination; unavailable shared media
is an explicit terminal error. Rootfs and EFI builders do not consume this
tree.

`tools/build_cpython.py` owns the CPython package boundary on the same terms.
It emits `bin/<architecture>` and `lib/<architecture>` with version-addressable
interpreters, a default `python.kex` alias for the newest pinned release, the
filtered pure-Python library, per-release build and module manifests, and one
path-sorted SHA-256 manifest for the whole tree. Installation verifies the
source tree, rejects a medium that already owns the directory, and re-reads
every installed byte. Administrator-supplied pure-Python packages install
separately below `lib/<architecture>/packages` in every installed architecture;
bytecode caches and non-Python files are
refused. Rootfs and EFI builders do not consume this tree either.

Pipelines remain sequential even though cooperative tasks now exist. This makes
backpressure an explicit capacity error rather than requiring hidden scheduling
and preserves current byte order, EOF, partial-I/O, and capacity-error semantics.

A final unquoted `&` admits one external command into the dynamically growing
resident table under the system task ceiling. The shell input loop pumps
resident tasks on a 10 ms boundary; background
stdin is EOF and combined output/error enters a 64 KiB recent log. Stable session
job numbers back `jobs`, `log`, `kill`, `wait`, and `fg`. SCFG services use the
same resident mechanism under a separate bounded supervisor with exact task
ownership, dependency/restart state, and service logs. The selected boot
configuration starts `timesync` with datagram, timer, and clock-control
authority. Foreground KEX commands use a locally retained resident continuation
with borrowed session streams; the shared pump continues to run background jobs
and service processes between foreground slices and blocked waits.

The session owns one decoder pair and one cooked line discipline, and lends them
to at most one foreground process at a time. A foreground command started from
the prompt without input redirection reads typed lines through its ordinary
standard-input handle; Enter completes a line, Ctrl-D reports end of input, and
Ctrl-C stays session cancellation. A read with nothing buffered registers a
generation-checked wait exactly like a pipe read, so the pump keeps draining
machine events, servicing the network, and stepping resident jobs while the
reader blocks. Background jobs, services, staged script lines, and owner-scoped
children never receive the loan, and the loan is released with its unread bytes
on exit, fault, or cancellation.

## Authority

There are no ambient device or reboot globals in portable crates. Only the UEFI
composition root and isolated machine mechanism import firmware/hardware APIs.
`Shell` receives a boolean machine-control grant; `poweroff` and `reboot` are
denied without it.
Ordinary commands have no shell-privileged implementation. Their task mappings
and handles are enforced by ring-3/EL0 page permissions and generation-revoked
ownership.

The shell reserves `cd`, `fg`, `jobs`, `kill`, `log`, `poweroff`, `reboot`,
`svc`, and `wait` as non-shadowable intrinsics. `cd` owns the logical
working-directory transition, the job and service commands operate only on
their owning bounded tables, while both terminal machine
actions consume only the shell's machine-control grant. Bare KEX command
discovery resolves immutable architecture-specific `/bin/<name>.kex` paths and
cannot intercept intrinsic names. A token containing `/` bypasses discovery
and selects one exact relative or absolute VFS file; it adds neither a `PATH`
search nor implicit current-directory execution. The interactive shell asks a
default-negative confirmation before direct execution outside `/bin`; nested
typed process launch remains noninteractive. The application ABI exposes no platform-transition operation.

Native KEX interfaces follow ADR 0034: opaque handles share generation,
ownership, accounting, cancellation, waiting, and teardown machinery, while
files, directories, byte streams, datagrams, listeners, timers, and control
services keep typed protocols. There is no universal native file-descriptor,
generic socket namespace, `ioctl`-style escape hatch, kernel POSIX subsystem, or
package-resolved scoped-root grant in the native recovery command path. Shared
`no_std` Rust services and the freestanding C sysroot layer filesystem
algorithms, the hybrid allocator, bounded descriptors that may be opened
read-write over one streamed replacement, buffered `FILE` and
directory streams, immutable environment handling, exit processing, clocks,
UTC calendar/formatting, UTF-8/wide conversion, C-locale helpers, randomness,
`setjmp`, and single-execution-thread pthread-compatible locks and TSS over
those typed handles. The C host bridge snapshots only the capabilities granted
to the application. It returns `EACCES` at a missing-authority boundary and
`ENOTSUP` for unsupported operations; it cannot manufacture ambient filesystem
or process authority. Thread creation, signals, dynamic linking, executable
private mappings, networking, additional locales, and timezone databases are
not part of this facade. `localtime`, `mktime`, and `strftime` resolve a POSIX
`TZ` string from the launch environment through the one rule evaluator in the
KEX runtime; see [ADR 0067](adr/0067-posix-timezone-strings-and-local-time.md).

SCFG obtains its initial-handle ceiling from the dependency-free
`troe-abi::startup` vocabulary shared with the loader and SDK. Format codecs may
link this vocabulary, other format codecs, the checksum and filesystem
contracts, and block transport; repository-policy tests reject links to
providers, namespaces, or runtime policy and require `troe-abi` to remain a leaf.

## Allocation

Portable components use `alloc` but every untrusted growth path has a local
hard bound. Before the explicit arena exists, the hybrid adapter delegates to
UEFI; afterward it routes every new allocation to the owned TLSF heap. Once
handoff completes, firmware fallback is permanently disabled. Pre-arena loader
allocations, if any, are retained rather than passed to dead boot services.

The architecture-independent memory-map model in `troe-memory` validates
checked 4 KiB ranges, normalizes unordered firmware
descriptors, overlays bounded explicit reservations, and reports usable and
reserved bytes. It also models an ordered sequence of physical extents addressed
as one logical page sequence, so a reservation that is not physically contiguous
is still addressed by logical page or byte offset. It also models checked, aligned monotonic allocation over one
explicitly reserved boot arena, including padding, exhaustion, and sealing
accounting. The UEFI adapter consumes these models at its pointer boundary;
firmware types do not enter the portable crate.

The final handoff reserves a 2,084-page LoaderData arena, carves and seals a
6 MiB general heap, dedicates 2 MiB to monotonic page-table construction, and
reserves 128 KiB/16 KiB kernel and emergency stacks. It installs native
16550/PL011 and bounded polling fatal paths, transfers to the owned stack, and
enters a non-returning `ExitBootServices` continuation. Interrupts are masked
before exception state changes. Only then does the kernel reclassify expired
boot-services code/data as usable and build a compact bitmap over genuinely
allocatable pages. Any usable frames overlapping the page-rounded GOP aperture
are marked unavailable in that bitmap; the aperture is mapped RW/NX as device
memory and never aliases a normal-memory mapping. `mem` and `/sys/memory`
publish owned-map bytes, free/total frames, and live heap use, capacity,
high-water, and failure counts.

A pure, bounded mapping plan identity-maps
only runtime RAM, PE-classified image sections, the boot arena, framebuffer,
and selected UART/interrupt-controller apertures. Physical aliases are accepted
only when their combined permissions preserve global W^X. The native backend
emits fresh 4 KiB tables, validates CPU-reported physical-address limits,
enables W^X, and replaces firmware exception state with fixed x86-64
GDT/TSS/IDT state or an AArch64 VBAR.
Executable image pages are RX, immutable image pages are RO/NX, and writable
runtime/device pages are NX. Deliberate write and execute violations are
validated in fresh QEMU boots for both architectures.

The post-handoff shell invokes no firmware protocol or allocator and cannot
manipulate page tables or exception vectors. Authorized `poweroff` and `reboot`
use the selected platform's native ACPI or PSCI control mechanism; a request
that unexpectedly returns parks the CPU terminally.
`troe-task` provides a bounded cooperative scheduler policy. Task IDs
are monotonic, records have ready/running/exited lifecycles, capability sets are
checked during dispatch, and a record retains its stack resource until explicit
reaping. The native mechanism executes one continuation step synchronously on
the task's mapped payload stack; yielding returns a typed result and keeps all
durable state in an explicitly owned continuation object rather than retaining
arbitrary native frames. The scheduler record accounts for that continuation's
identity, authority, lifecycle, and stack resource.
This makes every scheduling boundary explicit and keeps architecture register
state out of portable code.

`troe-task::thread` separately models process-owned thread lifetimes. Its
metadata slots are reserved at construction; preparation, publication, waits,
join claims, stop, completion and reaping allocate nothing. Prepared and
unreaped completion records consume process quotas, while native page charges
remain until composition explicitly acknowledges reclamation. The model uses
generation-checked identities and does not execute native threads, establish
physical quiescence, or enable pthread support. The application runtime still
has one execution thread per process.

The paired `troe-task::thread::sync` model owns typed mutex, condition and permit
records and intrusive FIFO wait queues. Mutex ownership transfers before a
waiter resumes. Condition timeout and notification preserve the original mutex
reference through reacquisition and result consumption; permanent poison is a
distinct failure without ownership. An immutable essential-mutex policy instead
revokes the process on owner exit. Permits remain ownerless and are not refunded
on thread exit. Object/wait quotas include pending completions, and the lifecycle
model refuses thread resource release while synchronization references remain.
These serialized transitions allocate nothing after table construction. Native
clock delivery, instruction-level memory ordering and work-quantum enforcement
are outside these portable models.

Both table constructors require an explicit metadata-byte budget. Their
`metadata_layout` methods derive inline-owner and backing-array sizes/alignment
from the compiled Rust types. Constructors check those requests before allocating
and check actual vector capacities before returning an owner. Unused slots stay
charged through process removal and slot reuse, until the table is dropped.
Allocator bookkeeping, rounding and fragmentation are separate physical costs.

`troe-task::thread::admission` checks a paired table configuration against a
combined metadata allowance and task IPC capacity after nonzero protected
headroom. It reserves one synchronization wait slot per retained thread and
enforces a per-process thread ceiling below the global record count. Its
`maximum_capacity` calculation derives the largest fitting thread count from
the compiled lifecycle/wait strides, aggregate process quotas and remaining context/metadata limits,
holding the process/object counts and per-process ceiling fixed. Pair
construction leaves the complete synchronization request available while
allocating lifecycle storage, then assigns the remaining budget using actual
capacity. It returns two empty owners only after both constructions succeed.
The caller supplies capacity and reserve counts; this portable check does not
reserve native IPC slots or establish a complete native admission budget.

`troe-application::static_tls` computes and initializes a separate local-exec
TLS allocation without allocating memory itself. The x86-64 layout preserves
negative offsets from FS base and writes the self pointer at FS:0; AArch64
places the template after an aligned 16-byte control prefix at TPIDR_EL0.
The caller's page budget includes control bytes and all padding. Initialization
checks exact buffer lengths and the complete aligned user-address range before
writing, then clears every mapped byte and copies the initialized template.
The helper has a common 16 MiB displacement window and accepts only a template
with zero alignment residue. It does not map memory, publish a thread, define
libc-private metadata, or account for complete thread admission.
`troe-application::tls_artifact` validates the separate
[container 1.3](formats/kex-static-tls-v1.md) for offline conversion/inspection.
Its exact immutable initializer suffix is checked against its nonexecutable
image source; initializers requiring pointer fixups are rejected. Explicit
`cargo kex convert --threaded` checks ELF TLS extents and the worker trampoline.
Native and streaming loaders still reject this format. Compiler probes verify
the portable geometry and emitted bytes independently of native execution.
The shared C11 qualification recipe pins Clang/LLD releases, excludes host
headers/configuration, and records binary/header/source fingerprints only after
the required checks pass. Its reports grant no admission. The C ABI-1 runtime
retains its single-thread ownership; [ADR 0071](adr/0071-native-threads-and-owned-synchronization.md)
specifies the separate process/thread/callback ownership needed by its adapter.

`troe-application::thread_memory` places one fixed, fully committed stack, the
checked TLS allocation, a two-page IPC pair and a read-only startup descriptor
page inside a page-aligned user
window. The stack has a guard on each side; TLS alignment gaps and a final
guard after startup also stay unmapped. The complete window counts against virtual
reservation limits. Mapped-page charges include IPC and startup, while ordinary-frame
demand includes stack, TLS, startup and supplemental page tables: IPC backing already
belongs to the boot arena. The table bound counts distinct prefixes at each
of the three levels below the shared root in twelve range calculations, without
walking individual pages or charging unmapped gaps as leaf mappings.
Checked cumulative charges and simultaneous budget checks are pure preflight
calculations. They do not acquire ownership, detect collisions with existing
reservations, or select service reserves. Context/wait/runtime metadata and
the shared process root remain separate charges. The native loader does not
consume these plans or admit additional execution threads.

`troe-application::process_memory` composes a validated static-TLS artifact
with shared image/startup/heap geometry and the initial thread window. The shared
reservation covers image holes and an explicit heap growth capacity; the thread
may lie on either side, but neither its mappings nor its guards and alignment
gaps may intersect that reservation. Only the initially committed heap prefix
is mapped. Image permissions are preserved; both startup pages are read-only/NX.
The planner resolves main/trampoline addresses and composes the initial thread's
descriptor using its checked TLS pointer and private IPC addresses.

Whole-process charges include the shared mappings once, the initial thread,
one user page-table root and the union of lower-table prefixes across at most
22 regions. They do not add the thread's independent table bound again. Dedicated
immutable initializer pages and full-executable staging pages are rounded and
charged separately. Resident and ordinary-frame budgets use the peak while both
coexist; steady charges exclude staging only after it is actually released.
The two boot-owned IPC pages count logically and occupy a task pair, but do not
consume ordinary free frames again. This is an allocation-free preflight model,
not a native load plan or owner: package/I/O staging, allocator overhead,
architecture kernel mapping tables and context/runtime metadata are separate.
Native loading does not consume this plan or admit ABI 1.4.

`troe-application::tls_owner` takes ownership of a staged executable buffer,
validates its coherent contents, and creates an independent immutable initializer.
`TlsBackingAccount` reserves page-rounded buffer capacity across all live owners,
including spare capacity. Initializer pages are reserved before fallible allocation;
actual capacity is then checked against the shared account and process peak budgets
before initialization. Failure drops provisional buffers before refunding their
charges. The composed plan retains the actual staging/initializer capacities.

`StagedTlsImage` retains the executable while image consumers borrow it. Consuming
`release_staging` requires those borrows to end and transfers the initializer to
`ProcessTls` without releasing its charge. TLS copies use the stored compiler layout
and immutable source, initialize the entire destination, and expose no initializer
pointer or mutable access. Copies are synchronous and run no callbacks. Stopping
creation requires exclusive access, permanently rejects new copies and retains
storage/charges until drop. The account is not `Sync`; this is serialized ownership.
These are logical heap-buffer charges, with allocator overhead/transient backing
and inline metadata accounted separately. Rust borrows establish copy-reader
quiescence, not native context quiescence. Native loaders still do not consume
these owners; heap drop does not certify physical zeroization or native admission.

`troe-abi::threading` provides closed request/response and immutable startup
descriptor codecs for assigned interfaces 30/31 and entry 6. The
[wire contract](formats/thread-v1.md) separates scheduler outcomes from IPC
transport failures and validates token kinds, wait flags and response payloads.
It authenticates no capability or pending operation. Application ABI 1.4 is
assigned but rejected by the active loader and SDK; older startup profiles
also reject the two thread interfaces.

The boot arena contains one reusable 64 KiB cooperative task payload plus
128 KiB isolated-server and 192 KiB shell payloads. The shell reserve covers
eight nested launch levels including private IPC/root metadata. Each has an unmapped 4 KiB page on
both sides, while the payload is RW/NX. Boot verification
interleaves two services, checks deterministic yield/exit counts, reaps their
records, and reuses a returned slot before launching the shell on the third.
The shell record alone carries console, filesystem, and machine-control
capabilities. This privileged cooperative scheduler does not preempt its own
continuations or provide a protection boundary: code that never yields can
monopolize the CPU, and privileged memory unsafety can corrupt any task.
Isolated KEX applications use the separate 50 ms leased preemption boundary
described below.

`troe-dispatch` connects selected clients and services. A port names
one registered service; a generation-checked handle names explicit call
authority to that port. Port and handle tables grow fallibly from small initial
reservations to hard ceilings of 65,536 ports and 262,144 handles, and stale
identities remain invalid when slots are reused. One synchronous request
borrows at most 4 KiB of immutable input and produces at most 4 KiB of owned
reply bytes with a matching monotonic request ID and typed service status.
Because the dispatcher is exclusively borrowed for delivery, it has no
queued cancellation state: closing before a call invalidates the handle, and a
delivered call completes before another mutation can occur.

Native console output uses `ConsoleService` to convert a
bounded write request into the existing `Output` operation, while
`DispatchedOutput` presents the same byte-stream trait to the shell. Requests
larger than one message are split through ordinary partial-write semantics.
Fatal diagnostics and input delivery remain direct machine mechanisms. This
path is in-process dispatch, not IPC: service code shares the
caller's privileged address space, borrowed request bytes are not a wire format,
and service faults are not contained. Diagnostics is a narrow
exception: its immutable snapshot crosses a canonical copied
receive/reply transport to an isolated KEX server, while the remaining
registered services stay in-process.

Diagnostics runs as one persistent ABI 1.3 KEX instance. Its boot record fixes a
256-page resident ceiling, a 4,000 ms initialization deadline, and at most three
starts in 60 seconds. Ordinary handles become available only after the empty
successful lifecycle initialization reply. Task, endpoint, handle, wait and tag
identities belong to an incarnation; a replacement never inherits client handles
or replays requests. Clean unsolicited exit remains offline. Poweroff and reboot
request the lifecycle shutdown handshake before reclaiming the service.
Boot artifacts are immutable image bytes, limited to 4 MiB each and 8 MiB in
aggregate; configured resident ceilings must fit the 8,192-page aggregate bound.

`troe-service::ipc::Runtime` composes the bounded endpoint, badge, pending-call,
call-chain and immutable wait-set models. `ProtectedRuntime` owns up to 16 live
KEX contexts and four kernel IPC pairs; the persistent profile admits eight
servers, 16 endpoints, 256 handles (32 per owner), 32 pending calls, eight queued
calls per endpoint, 128 KiB of copied queue storage, four chain members and four
sources per wait set. Endpoint calls are FIFO, closure events cannot be dropped,
and ready sources are selected round-robin. Cancellation and absolute deadlines
consume one client fate; cancelled reply tokens cannot write client RX.

Native diagnostics clients submit a copied snapshot and a scalar continuation
containing task, operation, service incarnation and the original absolute
deadline. The client step returns before the scheduler pump runs a server.
Completion is consumed in a subsequent step. No client Rust frame, borrow or
payload pointer is retained as a server continuation. Other product services
remain in-process; the compatibility diagnostics runner is acceptance-only.

`troe-terminal` keeps transport-independent input
decoding, line editing, and history outside the machine mechanism, and
`troe-console` keeps the framebuffer descriptor, pixel encoding, pixel surface,
and fixed-glyph text rendering there as well. Both are device-domain crates.
The machine mechanism links only `troe-console`; the composition root links
both. `troe-shell` owns completion orchestration because it has
the VFS namespace and its revision-aware `/bin` catalog; both command candidates
and directory listings are returned under caller-selected count and byte
budgets. `troe-completion` validates and evaluates bounded package-owned CMPL
descriptors into closed semantic resolver kinds whose values may come from open
current domains, such as filesystem entries, addresses, integers, jobs,
services, and configured volumes. CMPL bytes are embedded in the KEX package;
the shell reads only the fixed package header and bounded descriptor range to
construct a revision-bound active registry. The native composition root
uses the single Standard resource policy. x86-64 decodes US set-1 scan codes
from q35 i8042, while both architectures retain serial input. AArch64 has no
native keyboard transport and uses serial input.

The portable `troe-driver` crate defines the resource and event boundary. Queue
capacity and maximum ISR drain come from the Standard portable policy;
controller routes, vectors, trigger/polarity, and priority come from the
validated VM platform descriptor. Both x86-64 platforms mask the legacy PIC,
own LAPIC/I/O APIC, and route COM1 and keyboard receive interrupts through
explicit IDT gates. Both AArch64 platforms own GICv3 and route PL011 through
the IRQ vector. Handlers preserve interrupted CPU
state, perform bounded non-allocating device work, and enqueue typed raw bytes;
decoding and editing remain in main context. An empty queue executes a
lost-wakeup-safe `sti; hlt` or IRQ-masked `dsb; wfi` transition followed by
pending-handler dispatch. Direct polling is retained only for bootstrap and
fatal recovery. `mem` and
`/sys/memory` expose queue, interrupt, delivery, drop,
idle, and wakeup accounting; byte-valued memory counters retain exact values
and add binary IEC `KiB`/`MiB`/`GiB` displays.

Fresh task roots are built from the supervisor kernel plan. The bounded
user-region summary has nineteen entries: at most sixteen KEX image
segments plus startup, heap, and stack. x86 page-table traversal and leaves use
U/S and enter through a DPL-3 gate with TSS RSP0; AArch64 leaves use AP/PXN/UXN
and enter EL0t through the lower-EL vector with SP_EL1. The native boundary
preserves ABI callee-saved integer and floating-point/SIMD state for the current
resumable leased continuation.

One internal exit gate validates opcode, status, the complete readable user
range, and a preallocated 4 KiB destination before copying. Its result becomes
a kernel-owned `CopiedMessage`; it is deliberately not a stable syscall or wire
ABI. Translation, write, execute, illegal-instruction, and invalid-call fates
terminate only the active user record. Kernel-originated faults remain terminal.

Task creation and teardown are transactional. A record retains its root/private
frame counts and owned handle count. Teardown revokes all handles for the
monotonic task identity, reaps the exact record, zeroes the complete table/code/
data/stack allocation, and atomically returns it to the frame bitmap. Every
acceptance-probe boot exercises all fault classes, checks zero partial delivery
and zero frame loss, proves the same physical allocation can be reused, then
enters the shell. Production retains only the valid call/yield/exit loader
exercise; destructive KEX payloads and malformed corpus cases are feature-gated
and marker-rejected by the production EFI builder. See
[ADR 0014](adr/0014-unprivileged-task-isolation-and-teardown.md).

The native KEX boundary retains one 4 KiB format prefix, one 4 KiB replay
buffer, and at most one fallibly allocated 16 KiB completion-validation buffer. It validates the
complete envelope, manifest, executable geometry,
payload, and relocation set through bounded offset reads, fingerprints the full
source and relocations independently, and produces a pointer-free plan before
allocating frames. It packs fresh zeroed physical image pages beside a separate
exact table allocation, streams file-backed segment bytes into those inactive
frames, replays validated relocations, and requires both fingerprints to match
before activation. Source mutation, short reads, malformed data, or any sink
failure aborts the provisional transaction. It maps sparse
image virtual ranges with their closed R/RX/RW permissions, places the startup,
heap, guards, and stack canonically, and keeps the root inactive. The root
retains supervisor mappings for the kernel image, devices, and only the explicit
boot-arena runtime ranges needed across an isolated transition; it does not copy
the general free-RAM identity map. The kernel counts the exact four-level tables
implied by the complete plan and allocates only those retained frames; both
backends account for the complete mapped layout. A provisional task receives only the
loader-selected handle; boot acceptance then revokes it,
reaps the record, zeroes every provisional frame, and verifies exact reuse.
Malformed native corpus cases fail before frame allocation. Application entry
resets visible register/control state, passes only the startup address and
length, and enables IRQs after arming a 50 ms one-shot. x86 normalizes x87 and
SSE operation and saves the complete FXSAVE image; AArch64 enables baseline
FP/Advanced SIMD and saves all 32 128-bit vector registers plus FPCR/FPSR.
The 688-byte x86 context retains FS/GS/DS/ES selectors and the independent FS
base across syscalls, preemption and IPC handoffs. Fresh application entry
clears all four selectors. Kernel entry clears FS/GS selectors and FS base,
and restores fixed kernel DS/ES selectors before Rust handlers run; resume
restores the saved selectors before FS base. The owned GDT contains only flat
code/data descriptors, the LDT is disabled, and FSGSBASE remains disabled, so
GS base stays zero. Neither a segment base nor user TLS supplies kernel identity.
AArch64 retains TPIDR_EL0 in each saved context. These register mechanisms do
not enable threaded KEX admission or the pthread facade.
`NativeProcessContext` retains one root and a bounded array of private register
continuations keyed by process-owned thread tokens. It validates initial stack
guards, executable entry, TLS geometry and nonoverlapping stack/TLS payloads.
Its logical metadata charge includes actual context/mapping vector capacities
and the compiled inline owner. Admission and switching allocate no new metadata.
Saved execution moves only the mapping summary into the masked trap state;
the unique root stays with the caller and its summary is restored before IRQs
are enabled. Process exit, native fault and explicit stop revoke all sibling
contexts without user cleanup; their register bytes are erased before metadata
release. Composition retains physical frame ownership until this native owner
has been retired. The current mechanism supports copied-call continuations and
rejects roots bound to the single-thread IPC profile. It accepts a caller-supplied
remaining slice of at most 50 ms; process-share scheduling, per-thread IPC and
threaded package admission are not enabled by this mechanism.
Unsaved AVX-family, SVE, and SME state remains disabled rather than leaking or
corrupting across tasks. ABI call 0 exits through the owned gate. The x86
local-APIC and AArch64 generic physical timers capture a complete resumable
user context when the 50 ms timeslice expires. A separate spinning KEX proves
that preemption boundary before acceptance cleanup. Ordinary commands have no
command-wide runtime deadline. ABI gates also capture a
bounded full user context; `yield` remains an optional scheduling hint, while
`handle_call` validates
complete non-overlapping ranges, copies a two-byte opcode-prefixed request,
checks task handle ownership, and copies a successful bounded reply before a
fresh leased resume. Unknown calls and an attempted `_start` return are
contained and reclaimed as invalid-call and translation faults.
The application ABI also suspends on `grow_heap`; the kernel atomically commits owned,
zeroed physical extents at the end of the virtual heap prefix, falling back to
discontiguous frames when necessary, adds page-table frames as mappings
require, updates scheduler ownership accounting, and resumes with the new
mapped length. Expected physical-memory exhaustion leaves the mapping
unchanged. The initial launch reservation is itself a sequence of coalesced physical
extents rather than one contiguous run, so a large application starts on a
fragmented machine; an unfragmented one still reserves exactly one extent.
Initial mappings, heap growth, and dynamic private mappings share
full-width per-process and system commitment accounting under the active SCFG
memory policy; the kernel protects a configured minimum-free reserve without
preallocating any policy ceiling.

ABI 1.3 additionally reserves private TX/RX pages from the boot arena for up to
16 live task incarnations, plus four kernel-only pairs. `troe-machine` owns
these slots, retained PCID/ASID identities, and the protected context runtime.
The kernel supervisor binds each instance to exact startup capabilities;
`kernel/src/ipc.rs` also retains the two-context acceptance comparison. The same virtual addresses map distinct
physical pages in each root. The fast gate touches only shared supervisor
mappings, including the IPC aliases, and never the general free-RAM identity map.

The direct path copies one request and one reply, switches user roots twice,
and retains the initiating segment's already armed absolute 50 ms lease.
Waiting-server delivery uses no queue, allocation, scheduler selection, or TLB
invalidation. A runnable server uses the retained copied queue slot, which is
zeroed after delivery. Invalid tokens/scalars fault their owner; a server fault
resumes the caller with `peer-died` and no replay. Lease expiry terminates the
active member of this IPC segment. A queued or blocked continuation resumes
with a fresh bounded execution segment while retaining the call's original
absolute deadline. All native peer identities are validated before a masked
segment; owned sessions and tag leases cannot change during that segment, and
each root activation additionally checks its retained tag. Fixed boot-service
reservations cannot be widened by heap-growth calls; exhaustion is typed.

PCID/ASID 0 belongs to the kernel; task slots use 1–16. x86 enables PCID only
with both PCID and INVPCID support, otherwise reporting full-flush fallback.
AArch64 checks ASID feature width, uses non-global user leaves, and retains the
ASID in TTBR0. Mapping changes invalidate only their address/tag range; terminal
root release and slot reuse invalidate the complete old tag with completion
barriers. A stale incarnation or unsupported ownership state fails closed.
See the [wire contract](formats/kex-v1.md#abi-13-private-page-ipc-calls) and
[native acceptance requirements](testing.md#private-page-ipc-and-tagged-root-gate).

ADR 0048 adds a separate typed private-memory capability for zeroed anonymous
data. It provides reservation, mapping, partial protection, partial unmapping,
and statistics without exposing page tables, physical addresses, executable
memory, other processes, or a POSIX policy surface. Metadata starts empty,
grows fallibly under configured record/byte budgets, and recoalesces compatible
neighbors. Large requests are acquired and zeroed in configured work quanta,
but the quantum is not a mapping-size limit. The shared `no_std` runtime owns
the POSIX-shaped `mmap`/`mprotect`/`munmap` facade and the hybrid allocator can
return large Lua allocations to the system during the process lifetime.

ADR 0049 adds boot-seeded kernel randomness and KEX ASLR. UEFI must supply an
approved seed before application admission; the kernel retains a ChaCha20
CSPRNG and exposes fresh bytes only through the caller's typed `random`
capability. There is a bounded request size but no artificial lifetime entropy
quota. Container-1.2 KEX images carry only validated relative relocations and
receive independent randomized image and stack placements; private mappings
also use unbiased randomized free-slot selection.

ADR 0037 retains foreground, background, and service applications in
one bounded event loop. A single CPU executes only one ring-3/EL0 continuation
at an instant, but timer preemption, yields, service calls, and typed waits let
the resident set make concurrent progress. ADR 0045 defines a process registry
with stable process IDs, scheduler-paired ready/running/blocked/stopping states,
exact retained-page counts, and high-resolution CPU ticks charged only around
unprivileged execution. The `process-observe` capability exposes this bounded
metadata to `ps.kex` and `top.kex`; it hides argv and grants neither memory
inspection nor process control.

ADR 0046 defines owner-scoped nested process launch and byte pipes, and ADR 0054
defines how the environment it carries is composed. A launcher passes canonical
cwd, argv, environment, and explicit inherited/null/pipe standard streams. The
launcher composes that environment and the application only reads it: the
interactive session supplies the conventional entries to every ordinary command
and service, `PWD` resolves from the invocation directory rather than being
stored, and a name carries exactly one value because both the encoder and the
decoder reject a duplicate. `spawn --env NAME=VALUE` narrows a child by
replacing an inherited entry. A bare `argv[0]` resolves `/bin/<name>.kex`; one containing
`/` resolves against the supplied cwd, trying the exact path before one `.kex`
suffix fallback on not-found when the filename does not already end in `.kex`.
The kernel streams and validates the selected regular KEX file through the same
coherent bounded loader used by
direct launches, grants only a child-manifest attenuation of the
launcher's own capabilities, and
returns an opaque control token separate from the observable process ID.
Blocking wait, cancellation, terminal reap, pipe backpressure/EOF, and recursive
descendant teardown are resident-process operations. The kernel steps a nested
child on the launching task's stack, so nesting is bounded at eight levels below
the session or a service and a deeper launch is refused as exhausted. The kernel
exposes no command parser. `spawn.kex` exercises the mechanism; the current `sh.kex`
continues to use its transactional script sidecar until its language moves onto
these APIs.

Task, process, wait, pending-call, dispatch, child, pipe, and resident tables use
small initial `Vec` reservations and fallible on-demand growth. Tasks, process
records, waits, pending calls, children, and pipes have 65,536-object system
hard ceilings; handles have a 262,144 ceiling. These are allocation and token
safety backstops, not preallocated arrays. These object registries do not yet
have typed per-process soft-limit configuration, so their compiled hard ceilings
are authoritative. Memory policy is already typed: desired restricted TOML under
`/config/system/resources/memory.toml` is compiled into the immutable SCFG
record consumed by the kernel and a normalized read-only
`/sys/config/system/resources/memory.toml` projection. The kernel never parses
the human-readable projection.
The same registry rule gives each application up to 4,096 generation-checked
read-only file tokens, grows UDP bindings from 64 to the 16,384-port ephemeral
range ceiling, and grows the ARP cache to 256 entries without a maximum-sized
initial allocation. Fixed wire batches and parser/security depth bounds remain
separate versioned policies.

The command path installs one canonical package per command. Its KCAP
manifest is validated from the same coherently fingerprinted source before optional services are
constructed, and its embedded KEX v1 executable is validated before mapping.
It layers command-invocation 1.1 and standard-stream 1.1 services on that
mechanism: immutable cwd/argv, stdin, stdout, and stderr. The shell logically yields while
one foreground application runs, then resumes only after owner-wide handle
revocation, record reaping, page zeroization, and exact frame return. Bare
artifacts are read from target-selected `/bin/<name>.kex`; explicit path
artifacts are resolved through the same VFS namespace against the immutable
invocation cwd. Direct and nested launches share the same resolver: an explicit
path is tried exactly, then with `.kex` appended only on not-found if the final
component is nonempty, neither `.` nor `..`, and does not already end in `.kex`.
Existing nodes, other lookup errors, and package rejection never trigger a retry.
No search path is inferred, and absence of both candidates is a terminal
not-found result. Individual service payloads and retained tables have hard ceilings;
ordinary applications have no cumulative service-call ceiling. Heap and
private-memory commitment are bounded by physical availability, exact owned
accounting, and the active configurable memory policy. Standard streams themselves
forward without an aggregate byte cap. Optional interfaces
expose only bounded IPv4/UDP send/receive, read-only VFS operations, one
sequential streamed file mutation, a boot-relative monotonic timer with
self-only process CPU time, one immutable typed diagnostics snapshot, current
read-only process accounting, caller-private anonymous memory, fresh CSPRNG
bytes, read-only typed network observation, one DHCP exchange, one ICMP
   echo exchange, one literal-IPv4 outbound TCP stream, or one bounded inbound
   listener. The [listener contract](formats/tcp-listen-v1.md) specifies its
   port ownership, backlog, connection identifiers, and shared limits. Network observation,
   configuration, echo, datagrams, and TCP are independent authorities; none
   exposes raw frames, routes, DNS, TLS, or devices. Datagram
ports are exclusive to the launch; read-only
open tokens are generation-checked; directory traversal is
lexically paginated and final-component link targets are bounded. Mutation
working state is sequential, 16 KiB by default, and selectable through 1 MiB;
teardown does not roll back already written bytes. Empty-directory creation is
a separate bounded operation. Mutation interface 1.2 also exposes canonical
two-path same-provider rename and empty-directory removal, with stable
directory-not-empty and cross-device statuses. The kernel routes these typed,
capability-scoped primitives only; streamed copying, iterative traversal,
recursive copy/delete, destination joining, and move behavior remain in the
`no_std` user-space runtime.
Timer waits are foreground
and cancellable; diagnostics retains fixed copied bytes rather than accounting
   borrows. TCP retains at most one unacknowledged 1,460-byte segment and one
   4 KiB receive FIFO per connection, retransmits four times on fixed timers,
   and admits only the exact tuple and next sequence. Dispatcher teardown
   unbinds ports, removes live connections, and invalidates every token.
   Gracefully closed tuples remain in the ambient network table until their
   retention deadline; runtime checkpoints drive TCP emissions and expiry. No
raw-network, route-control, provider, block, device, or machine handle is
granted. The separate volume-control interface can list the boot policy and
activate only a BMNT-authorized provider already prepared by stable-identity
discovery; it cannot name raw devices or arbitrary target paths.

## Persistent-storage boundary

The portable block-region, GPT, VFS-provider, read/write FAT32, constrained
metadata-preserving ext4 with bounded symbolic/hard links, native virtio
transport, dual-slot durability, and
selected STFS mutation pieces preserve this dependency direction. Empty
directory removal and same-provider rename are implemented for RAMFS, FAT32,
and the ext4 provider. The namespace holds one wall clock and shares it with
every mounted provider, which reads it at each mutation, so both the ext4 and
FAT32 providers stamp the instant a write happened; each converts the single
Unix-seconds representation itself, and without a readable clock neither invents
a time. Its ext4 mutations are
journaled as physical block redo transactions in the profile's existing internal
journal, and a separate explicitly authorized recovery path replays a committed
transaction or discards an uncommitted one, so an interrupted mutation recovers
to exactly one valid state without external repair. The provider follows ext4's own compatibility
rules rather than one exact feature set: an unknown incompatible feature is
refused, an unknown read-only-compatible feature mounts read-only, and
compatible features are ignored. It reads 1 KiB, 2 KiB and 4 KiB blocks,
32- and 64-byte group descriptors, stored checksum seeds, flexible block
groups, uninitialized groups, hashed directory indexes, and extent trees to the
depth ext4 builds them, so an ordinary Linux ext4 volume mounts and takes the
full mutation surface. A hashed directory grows by splitting a full leaf and
rewriting its index, and a heavily fragmented file is rewritten through an
extent tree as deep as its extents require. General ext4 repair and mutations outside the documented
profile remain unsupported. A transport provides bounded block-region capabilities; partition
discovery turns a whole device into non-overlapping regions; independently
selected filesystem providers expose VFS objects. Every provider maps block
conditions to filesystem errors exhaustively, so a transport whose completion
wait expired reaches an application as a timeout rather than as the same
transport failure a device-reported read error produces.
Format-specific structures do not enter the machine backend, block transport,
partition layer, or kernel composition root.

```text
block transport -> bounded region -> filesystem provider -> VFS namespace
                         ^
                  whole device or GPT
```

CSPK immutable objects sit above the selected provider. SACT is the separate
mutable publication pointer committed through a PRGN-selected dual-slot block
region; it names verified CSPK objects by SHA-256 and never turns them mutable.
Early activation borrows the exactly BMNT-selected ext4 provider to read the
bounded pack before normal namespace attachment, preserving ownership of both
the root-volume device and the separately selected writable transaction device.

Each GMAN optionally names one ISEC security root for the same generation. ISEC
names exact typed IREG registry, IMAP foreign mapping, IMNT mount-policy, and
IACL native ACL objects. `troe-identity` parses and cross-validates the complete
snapshot before activation; partial objects, wrong kinds, generation mismatch,
unresolved principals, or membership cycles reject the generation. Predecessor
traversal and mark-and-copy retention carry all five security objects together.

STFS is the separate narrow mutation provider. It consumes its own exact
PRGN-selected writable region, commits the entire single-file filesystem
through TXSLOT, and attaches at `/vol/state`. The VFS mount records writable
authority explicitly; ext4 and FAT mutate only through manifest-selected
writable block-region capabilities.

The hosted deployment control-plane reference consumes one complete PLOCK and
active signed release per locked
member, stages and independently verifies immutable generation objects, and
publishes one pending/healthy pointer. Desired configuration persists outside
generations while each generation owns an exact read-only `/sys/config`
projection. Reversible data migrations retain canonical snapshots and roll back
with failed health; forward-only data instead enters an explicit
recovery-required state so predecessor code never runs over incompatible data.
Reachability GC retains active, previous, recovery, and in-flight transaction
roots. Native boot continues to consume CSPK/GMAN and SACT/TXSLOT rather than
parsing hosted filesystem metadata. See [ADR 0044](adr/0044-transactional-system-lifecycle.md).

The network boundary is split between safe protocol policy and
machine transport. `troe-net` owns strict bounded Ethernet/ARP/IPv4/UDP parsing,
construction, and count-plus-byte receive admission. `troe-machine` owns the
fixed-buffer modern virtio-net queues for the pinned PCI and MMIO profiles.
Receive completion is interrupt-driven: the machine handler acknowledges and
coalesces work, then the cooperative ambient service performs bounded parsing
outside interrupt context. Empty receive probes are constant-time and prompt
idle sleeps until input or network work. Acceptance resolves the QEMU gateway
by ARP and completes a UDP exchange with a host peer after rejecting unrelated
traffic; no packet-declared allocation or unbounded device wait enters either
side of the boundary.

KEFS is the intentionally built-in recovery exception. The current FAT16 image
is read by firmware. FAT32 and the default persistent ext4 profile are the
implemented runtime providers; general FAT12/16, exFAT, and NTFS are
unsupported. The exact ext4 read/write subset is fixed by ADR 0017. Providers
are statically selected crates, and an image does not carry providers it did
not select. Additional profiles and provider isolation are tracked in
[GitHub issue #12](https://github.com/dennissoftman/troe/issues/12).

An external filesystem provider may be packaged under its own declared license,
but the module label alone is not a license boundary. Differently licensed
source and artifacts remain outside the Apache-licensed core and default image;
the service/module ABI, provenance, notices, and release treatment are reviewed
explicitly. Static linkage into the kernel image is not considered separation.

Initial partition support is discovery rather than management: accept a whole
device or validate a bounded GPT layout created by host/installer tooling. No
filesystem provider can address blocks outside its granted region. See
[ADR 0009](adr/0009-persistent-filesystems-and-partitions.md).

## Native machine invariants

These implementation details are recorded here because a portable refactor can
erase them while leaving high-level interfaces apparently unchanged. Any change
to interrupt entry, idle waiting, controller setup, isolated execution, or a
named machine profile must review ADRs 0013, 0014, and 0016, the native contract
tests, and all four exhaustive QEMU platform suites together. Each named
platform is exact rather than a generic x86-64 or AArch64 contract, and the two
that share an architecture still differ, so the subsections below mark every
fact that belongs to one platform rather than to both.

### Shared ordering

- Allocate the complete raw-input queue before enabling a source, controller
  route, or CPU interrupt class. An ISR drains at most the selected budget,
  acknowledges delivery even when the drop-newest queue is full, and leaves
  decoding to main context.
- Configure a network route while its transport and controller source are
  masked. Publish ISR state before unmasking. Teardown reverses that order and
  confirms device reset before DMA storage can drop.
- Map controller, UART, and transport apertures RW/NX as device memory before
  volatile access. Never retain a normal-memory alias to device pages.
- Bound a device-completion wait by elapsed monotonic milliseconds, never by a
  poll count. A count bounds guest instructions, so an emulated vCPU competing
  for host CPU with the thread that services the completion can exhaust it while
  the device is merely slow. Report an expiry as its own error, distinct from a
  device-reported failure, because it leaves the request's outcome unknown.
- Main-context queue access keeps the owned IRQ class masked. The proof is
  single-CPU and must be replaced before SMP. Polling is limited to bootstrap
  and terminal fatal output; the normal shell uses interrupt delivery.
- Application entry publishes the complete kernel return context before user
  IRQ delivery. Completion masks IRQs, disables the lease, restores the kernel
  root, invalidates stale translations, unpublishes the active record, and only
  then re-enables delivery.
- Validate the entry, stack, and complete message range against retained user
  mappings before copying any byte. User privilege never receives a device
  mapping or writable/executable alias.

### Timers and clocks

- Two clocks exist and they are not interchangeable. The monotonic clock is
  boot-relative and never moves backwards; the wall clock reports Unix time and
  can be set at runtime through `clock_control`. Bound every wait, deadline,
  and timeout on the monotonic clock.
- `initialize_monotonic_clock` runs during handoff preparation, after console
  initialization and before any device or service that bounds work by time. A
  platform that cannot supply a counter fails the boot rather than continuing
  without one.
- Counter scaling divides before multiplying, splitting whole units from the
  remainder, at both the millisecond and nanosecond scales. Multiplying a
  full-width counter by the scale first overflows and silently truncates a long
  uptime, so the split is load-bearing rather than stylistic.
- The monotonic source is a platform fact, and the counter must keep advancing
  while the vCPU is not scheduled — that property is what makes it a valid bound
  for a completion serviced by a separate host thread. `x86_64-q35-uefi`
  calibrates the TSC from PIT channel 2; `x86_64-uefi-virtio-pci` calibrates the
  TSC and the local-APIC timer from the ACPI PM timer, whose counter is 24 or 32
  bits wide; both AArch64 platforms read `CNTPCT_EL0` scaled by `CNTFRQ_EL0`.
  Calibration is cached after the first nonzero result, so repeated reads cannot
  re-time a running machine.
- Reads and deadlines have different resolutions, deliberately. Both clocks are
  read in nanoseconds: `timer::NOW_NANOS` scales the raw counter, and
  `wall_clock::NOW_PRECISE` reports seconds with a nanosecond remainder shaped
  like a `timespec`. The millisecond opcodes remain, because deadlines are
  expressed in them. The execution timer is still armed in whole milliseconds,
  so a sub-millisecond deadline is not expressible and returns immediately: a
  finer reading is not a finer sleep.
- The wall clock's remainder is only as true as its anchor's phase. Firmware
  reports whole seconds, so the anchor starts on a second boundary and the
  remainder is monotonic elapsed time from it, which makes differences exact
  and the absolute phase arbitrary. `clock_control::SET_PRECISE` is what
  establishes a real phase, and `timesync` supplies one from the NTP transmit
  timestamp's fraction. The anchor keeps seconds and a remainder rather than
  one nanosecond count because the accepted range reaches year 9999, which
  `u64` nanoseconds since the epoch does not.
- Acceptance storage and network probes sample the high-resolution architecture counter
  through an acceptance-only timer payload. The counter includes kernel and
  I/O time; it does not change production timer or execution-lease resolution.
  The [storage measurement contract](testing.md#storage-baseline-capture)
  defines the intervals and fixture validation. The
  [IPC, network, and boot contract](testing.md#ipc-network-and-boot-baseline-capture)
  also specifies raw compatibility samples and internal boot timing.
- A sleep is a deadline, not a duration. The wait re-arms the one-shot timer in
  slices no longer than the application timeslice and recomputes the remainder
  from the counter on every pass, so a long wait cannot accumulate per-slice
  error and cannot be capped by the hardware counter's exact range. A wake from
  any other source re-arms on the recomputed remainder instead of restarting the
  original interval.
- The wall clock is anchored once. Firmware time is read through UEFI
  `get_time`, normalized to UTC using the firmware's own offset, and advanced
  from the monotonic counter afterwards; it is never re-read. A reading before
  1970 leaves the clock unconfigured and its service says so rather than
  inventing an epoch.

### x86-64 q35 profiles

- Both legacy PICs stay masked. LAPIC/I/O APIC bounds come from the reported
  controller topology; q35 IRQ1 and IRQ4 route to explicit non-exception IDT
  vectors targeting the BSP.
- Rust-calling entries preserve the required GPR and FXSAVE state, execute
  `cld`, and clear application-controlled AC before Rust. Device service
  precedes LAPIC EOI; the spurious vector returns without EOI.
- Empty-queue idle remains the single ordered `sti; hlt; cli` transition.
  Splitting it recreates a lost-wakeup window.
- User mappings require U/S on every traversal entry and terminal PTE. TSS RSP0
  and user descriptors precede ring-3 entry; SMEP and SMAP are enabled, while
  inherited LA57, CET, supervisor protection keys, `SYSCALL`, `SYSENTER`, and
  FSGSBASE state are rejected or disabled before userspace.
- The bounded PCI scanner covers bus zero, validates/de-loops modern virtio PCI
  capabilities, probes BAR sizes with decode disabled, restores configuration,
  and maps only the referenced page-rounded spans. Block and network queues use
  fixed modern-v1 contracts and reset-before-DMA-drop teardown. The scanner is
  shared: `x86_64-q35-uefi` reaches configuration space through legacy
  mechanism 1 I/O ports, while `x86_64-uefi-virtio-pci` and `aarch64-sbsa-ref`
  use an ECAM aperture.
- Lifecycle is a platform fact, not an architectural one. `x86_64-q35-uefi`
  owns q35 ACPI PM1 S5 and reset-control ports and serves both `poweroff` and
  `reboot`; `x86_64-uefi-virtio-pci` has a firmware-validated reset port only,
  so soft-off is unsupported and `poweroff` parks the CPU instead. Neither set
  of ports is an architecture default and another platform must supply
  validated equivalents.

### AArch64 `sbsa-ref` and `virt` profiles

- Both named AArch64 platforms use GICv3, the only generation the platform
  descriptors describe. FDT discovery still parses a GICv2 device tree, but
  only to reject it, and no mechanism drives version 2. Distributor loops are
  bounded by `GICD_TYPER`; PL011 INTID 33 and each virtio SPI are validated
  against it before enable. A different firmware security state, or the ITS
  and LPI support both platforms omit, requires a distinct review.
- The CPU interface is the `ICC_*` system registers rather than an MMIO
  aperture, and `ICC_SRE_EL1` precedes the remaining interface writes.
  `GICR_WAKER` wakes the redistributor before any enable, because it delivers
  nothing while asleep and acknowledges the wake asynchronously. Private
  interrupts are configured in its SGI frame; the distributor's registers below
  INTID 32 are RES0 once `GICD_CTLR.ARE_NS` routes by affinity, which must be
  live before the enable write so the `GICD_IROUTER` route is the one
  consulted. Owned interrupts are non-secure group 1, so their `GICD_IGROUPR`
  bit is set where version 2 cleared it.
- The IRQ vector preserves x0–x30, q0–q31, FPCR/FPSR, and the saved exception
  origin before Rust. Synchronous, FIQ, and SError paths that are not the lower
  application gate remain fatal.
- Idle keeps PSTATE.I set for `dsb sy; wfi`, briefly unmasks after wake so the
  pending GIC interrupt dispatches, then masks again before checking queues.
  Unmasking before `wfi` recreates a lost-wakeup race.
- EL0 mappings use distinct AP/PXN/UXN policy. Copied messages use unprivileged
  loads while PAN is active; return restores TTBR0_EL1 and completes the global
  invalidation before Rust resumes.
- Virtio transport is a platform fact. `aarch64-uefi-virtio-mmio` maps only its
  documented virtio-MMIO aperture, while `aarch64-sbsa-ref` carries virtio as
  PCI functions through the shared scanner above, because SBSA describes no
  MMIO transport aperture. Both accept modern devices only, use page-aligned
  live queue memory and outer-shareable DMA barriers, and park on an
  unconfirmed reset rather than allowing DMA to outlive storage.
- PSCI 1.0 supplies terminal poweroff and reboot, but the conduit belongs to the
  platform: `aarch64-uefi-virtio-mmio` calls HVC and reaches an implementation
  at EL2, while `aarch64-sbsa-ref` calls SMC because Trusted Firmware places
  PSCI in its EL3 runtime. An unexpected PSCI return falls back to the terminal
  CPU park path.

### Platform separation and regression evidence

`cfg(target_arch)` selects instruction-set mechanisms, never a VM. Each named
platform descriptor supplies or validates firmware, memory, interrupt, timer,
console, storage/network transport, and lifecycle facts before typed resources
are constructed. The discoverable x86 QEMU contract uses bounded ACPI; the
discoverable AArch64 contract uses the edk2-published FDT. Both consume the
combined raw bundle and pass persistence, networking, lifecycle, and fault
acceptance. See [ADR 0016](adr/0016-hardware-targets-and-emulator-role.md) and
[cloud platform support](cloud-platform-support.md).

Short smoke runs are insufficient for these invariants. The exhaustive paced
serial workload has caught an AArch64 unmask-before-`wfi` race that short boots
did not reproduce. Fault, W^X, guard, fatal-console, non-reboot, input-drop, and
idle/wakeup assertions remain enabled because their entry paths share state.

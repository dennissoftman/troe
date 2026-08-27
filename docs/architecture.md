# Current architecture

The same portable graph is linked into two composition roots:

```text
host stdin/stdout ───────────┐                 ┌─ hosted process
                             ├─ shell ─ VFS ──┤
serial / PS/2 → IRQ → bounded queue → editor ─┘  └─ UART + GOP text console
```

The shell owns parsing, pipelines, streamed file redirection, completion, cwd,
session job control, service control, and nine non-shadowable intrinsics.
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
and virtio transport facts before owned device access. q35 and QEMU `virt`
therefore remain two exact platforms rather than architecture defaults.
Two additional QEMU contracts obtain those facts from bounded ACPI or FDT
discovery and boot the deterministic three-disk cloud bundle; unsupported
firmware fails before device publication or volatile I/O.

## Input-to-output trace

1. A composition root selects validated driver and editor policies. Owned
   device handlers drain only a configured number of raw bytes into a
   preallocated queue, then acknowledge the controller. The portable editor
   enforces its UTF-8 byte bound, cursor-aware editing, volatile history limits,
   and decoded key events; ANSI serial input and x86 set-1 PS/2 input feed the
   same event type outside interrupt context.
2. The shell crate tokenizes iteratively. Single and double quotes group literal
   bytes; no expansion, recursion, substitution, environment lookup, or
   globbing occurs. Unquoted `<`, `>`, and `>>` select bounded-memory file
   streams.
3. The pipeline executor protects shell intrinsics, then resolves the exact KEX
   command path. Absence reports an unavailable application and never selects
   privileged utility behavior. KEX receives bounded stdin/stdout/stderr streams
   plus only declared optional datagram, read-only VFS, streamed file mutation,
   monotonic timer, wall-clock observation or correction, diagnostics,
   process observation, network-observation, DHCP, ICMP, or outbound TCP-connect handles. Privileged
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
5. Filesystem commands ask `Namespace` to canonicalize from the logical cwd.
   Immutable KEFS nodes and writable `/tmp` nodes share one object model.
   The current recovery root keeps executables in `/bin`, recovery-only
   bootstrap files in `/recovery`, architecture-independent package data in
   producer-owned `/share/<name>` directories, and persistent or mounted data
   under `/vol`. `/config` is the persistent desired-state mount point;
   `/sys/config` is an immutable, bounded projection resolved for exactly one
   active package generation. The system has no `/etc` directory or alias. KEX
   applications are statically linked, `/lib` is not present, and executable
   code does not belong in `/share`.
6. The final output capability writes host bytes or the native UART.
   When validated GOP metadata is available, normal native shell output is also
   rendered into an owned fixed-glyph framebuffer console. UEFI text output is
   confined to the pre-handoff banner.

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
actions consume only the shell's machine-control grant. KEX command discovery
resolves every ordinary command from exact immutable architecture-specific
paths, but cannot intercept intrinsic names; ABI 1.1
exposes no platform-transition operation.

Native KEX interfaces follow ADR 0034: opaque handles share generation,
ownership, accounting, cancellation, waiting, and teardown machinery, while
files, directories, byte streams, datagrams, listeners, timers, and control
services keep typed protocols. There is no universal native file-descriptor,
generic socket namespace, `ioctl`-style escape hatch, userspace POSIX facade, or
package-resolved scoped-root grant today. Those compatibility and authority
extensions are tracked in
[issues #11](https://github.com/dennissoftman/troe/issues/11) and
[#6](https://github.com/dennissoftman/troe/issues/6).

## Allocation

Portable components use `alloc` but every untrusted growth path has a local
hard bound. Stage 1 obtained allocation from UEFI. Stage 2 installs a hybrid
adapter: it delegates only before the explicit arena exists, then routes all new
allocations to the owned TLSF heap. Once handoff completes, firmware fallback is
permanently disabled. Pre-arena loader allocations, if any, are retained rather
than passed to dead boot services.

Stage 2 begins with an architecture-independent memory-map model in
`troe-memory`. It validates checked 4 KiB ranges, normalizes unordered firmware
descriptors, overlays bounded explicit reservations, and reports usable and
reserved bytes. It also models checked, aligned monotonic allocation over one
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

Stage 3 adds a pure, bounded mapping plan. The composition root identity-maps
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
use the pinned platform profile's native ACPI/PSCI control mechanism; a request
that unexpectedly returns parks the CPU terminally.
Stage 4 adds a bounded cooperative scheduler policy in `troe-task`. Task IDs
are monotonic, records have ready/running/exited lifecycles, capability sets are
checked during dispatch, and a record retains its stack resource until explicit
reaping. The native mechanism executes one continuation step synchronously on
the task's mapped payload stack; yielding returns a typed result and keeps all
durable state in an explicitly owned continuation object rather than retaining
arbitrary native frames. The scheduler record accounts for that continuation's
identity, authority, lifecycle, and stack resource.
This makes every scheduling boundary explicit and keeps architecture register
state out of portable code.

The boot arena contains one reusable 64 KiB cooperative task payload plus
128 KiB isolated-server and shell payloads. Each has an unmapped 4 KiB page on
both sides, while the payload is RW/NX. Boot verification
interleaves two services, checks deterministic yield/exit counts, reaps their
records, and reuses a returned slot before launching the shell on the third.
The shell record alone carries console, filesystem, and machine-control
capabilities. Cooperative scheduling still provides no preemption or hardware
isolation: code that never yields can monopolize the CPU, and privileged memory
unsafety can corrupt any task.

Stage 5 adds `troe-dispatch` between selected clients and services. A port names
one registered service; a generation-checked handle names explicit call
authority to that port. Port and handle tables grow fallibly from small initial
reservations to hard ceilings of 65,536 ports and 262,144 handles, and stale
identities remain invalid when slots are reused. One synchronous request
borrows at most 4 KiB of immutable input and produces at most 4 KiB of owned
reply bytes with a matching monotonic request ID and typed service status.
Because the dispatcher is exclusively borrowed for delivery, Stage 5 has no
queued cancellation state: closing before a call invalidates the handle, and a
delivered call completes before another mutation can occur.

The first switched edge is native console output. `ConsoleService` converts a
bounded write request into the existing `Output` operation, while
`DispatchedOutput` presents the same byte-stream trait to the shell. Requests
larger than one message are split through ordinary partial-write semantics.
Fatal diagnostics and input delivery remain direct machine mechanisms. This
original path is still in-process dispatch, not IPC: service code shares the
caller's privileged address space, borrowed request bytes are not a wire format,
and service faults are not contained. Diagnostics is the first narrow
exception: its immutable snapshot crosses a canonical copied
receive/reply transport to an isolated KEX server, while the remaining
registered services stay in-process.

Server-endpoint calls use fixed kernel request/reply buffers and let the
endpoint encode directly into caller-owned reply storage. The protected
receive-to-reply interval therefore performs no dynamic allocation while still
copying across the protection boundary. The first composition retains at most
one request and one suspended server context. It launches one server process
per client request and implements no persistent residency or restart policy.
Persistent services are tracked in
[GitHub issue #8](https://github.com/dennissoftman/troe/issues/8).

Stage 5.1 adds `troe-terminal`, which keeps transport-independent input
decoding, line editing, history, and fixed-glyph text rendering outside the
machine mechanism. `troe-shell` owns completion because it has the VFS namespace
and its revision-aware `/bin` catalog; both command candidates and directory
listings are returned under caller-selected count and byte budgets. The native
composition root uses the single Standard resource policy. x86-64 decodes
US set-1 scan codes from q35 i8042, while both architectures retain serial
input. AArch64 has no native keyboard transport and uses serial input.

Stage 5.2 adds the portable `troe-driver` resource and event boundary. Queue
capacity and maximum ISR drain come from the Standard portable policy;
controller routes, vectors, trigger/polarity, and priority come from the
validated VM platform descriptor. The pinned x86-64 platform
masks the legacy PIC, owns LAPIC/I/O APIC, and routes COM1 and keyboard receive
interrupts through explicit IDT gates. The pinned AArch64 platform owns GICv2
and routes PL011 through its IRQ vector. Handlers preserve interrupted CPU
state, perform bounded non-allocating device work, and enqueue typed raw bytes;
decoding and editing remain in main context. An empty queue executes a
lost-wakeup-safe `sti; hlt` or IRQ-masked `dsb; wfi` transition followed by
pending-handler dispatch. Direct polling is retained only for bootstrap and
fatal recovery, and no timer or preemption is introduced. `mem` and
`/sys/memory` expose queue, interrupt, delivery, drop,
idle, and wakeup accounting; byte-valued memory counters retain exact values
and add binary IEC `KiB`/`MiB`/`GiB` displays.

Stage 6 adds fresh task roots built from the supervisor kernel plan. Stage 7
raises the bounded user-region summary to nineteen: at most sixteen KEX image
segments plus startup, heap, and stack. x86 page-table traversal and leaves use
U/S and enter through a DPL-3 gate with TSS RSP0; AArch64 leaves use AP/PXN/UXN
and enter EL0t through the lower-EL vector with SP_EL1. The native boundary
preserves ABI callee-saved integer and floating-point/SIMD state and masks
interrupts for the current cooperative, non-preemptive continuation.

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

The native Stage 7 boundary copies KEX bytes into bounded kernel staging
and consumes the complete portable plan before allocating or mapping. It packs
fresh physical image pages beside a separate exact table allocation, maps sparse
image virtual ranges with their closed R/RX/RW permissions, places the startup,
heap, guards, and stack canonically, and keeps the root inactive. The root
retains supervisor mappings for the kernel image, devices, and only the explicit
boot-arena runtime ranges needed across an isolated transition; it does not copy
the general free-RAM identity map. The kernel counts the exact four-level tables
implied by the complete plan and allocates only those retained frames; both
backends still enforce the standard 512-page ceiling. A provisional task receives only the
loader-selected handle; boot acceptance then revokes it,
reaps the record, zeroes every provisional frame, and verifies exact reuse.
Malformed native corpus cases fail before frame allocation. Application entry
now resets visible register/control state, passes only the startup address and
length, and enables IRQs after arming a 50 ms one-shot. x86 normalizes x87 and
SSE operation and saves the complete FXSAVE image; AArch64 enables baseline
FP/Advanced SIMD and saves all 32 128-bit vector registers plus FPCR/FPSR.
Unsaved AVX-family, SVE, and SME state remains disabled rather than leaking or
corrupting across tasks. ABI call 0 exits through the owned gate. The x86
local-APIC and AArch64 generic physical timers now capture a complete resumable
user context when the 50 ms timeslice expires. A separate spinning KEX proves
that preemption boundary before acceptance cleanup. Ordinary commands have no
command-wide runtime deadline. ABI gates also capture a
bounded full user context; `yield` remains an optional scheduling hint, while
`handle_call` validates
complete non-overlapping ranges, copies a two-byte opcode-prefixed request,
checks task handle ownership, and copies a successful bounded reply before a
fresh leased resume. Unknown calls and an attempted `_start` return are
contained and reclaimed as invalid-call and translation faults.
ABI 1.1 also suspends on `grow_heap`; the kernel atomically commits owned,
zeroed physical extents at the end of the virtual heap prefix, falling back to
discontiguous frames when necessary, adds page-table frames as mappings
require, updates scheduler ownership accounting, and resumes with the new
mapped length. A large allocation requests its complete page deficit in one
call; the allocator's 256 KiB quantum is only a batching floor for small
requests. Expected physical-memory exhaustion leaves the mapping unchanged;
no fixed lifetime heap-size policy is applied.

ADR 0037 retains foreground, background, and service applications in
one bounded event loop. A single CPU executes only one ring-3/EL0 continuation
at an instant, but timer preemption, yields, service calls, and typed waits let
the resident set make concurrent progress. ADR 0045 adds a process registry
with stable process IDs, scheduler-paired ready/running/blocked/stopping states,
exact retained-page counts, and high-resolution CPU ticks charged only around
unprivileged execution. The `process-observe` capability exposes this bounded
metadata to `ps.kex` and `top.kex`; it hides argv and grants neither memory
inspection nor process control.

ADR 0046 adds owner-scoped nested process launch and byte pipes. A launcher
passes canonical cwd, argv, environment, and explicit inherited/null/pipe
standard streams; the kernel resolves and validates `/bin/<name>.kex`, grants
only a child-manifest attenuation of the launcher's own capabilities, and
returns an opaque control token separate from the observable process ID.
Blocking wait, cancellation, terminal reap, pipe backpressure/EOF, and recursive
descendant teardown are resident-process operations. The kernel exposes no
command parser. `spawn.kex` exercises the mechanism; the current `sh.kex`
continues to use its transactional script sidecar until its language moves onto
these APIs.

Task, process, wait, pending-call, dispatch, child, pipe, and resident tables use
small initial `Vec` reservations and fallible on-demand growth. Tasks, process
records, waits, pending calls, children, and pipes have 65,536-object system
hard ceilings; handles have a 262,144 ceiling. These are allocation and token
safety backstops, not preallocated arrays. A future typed system configuration
can impose lower per-process soft limits and raise them up to the compiled hard
ceiling.
The same registry rule gives each application up to 4,096 generation-checked
read-only file tokens, grows UDP bindings from 64 to the 16,384-port ephemeral
range ceiling, and grows the ARP cache to 256 entries without a maximum-sized
initial allocation. Fixed wire batches and parser/security depth bounds remain
separate versioned policies.

The Stage 9 command slice installs one canonical package per command. Its KCAP
manifest is validated from the same staged file before optional services are
constructed, and its embedded KEX v1 executable is validated before mapping.
It layers command-invocation 1.0 and standard-stream 1.1 services on that
mechanism: immutable cwd/argv, stdin, stdout, and stderr. The shell logically yields while
one foreground application runs, then resumes only after owner-wide handle
revocation, record reaping, page zeroization, and exact frame return. Artifacts
are read from target-selected `/bin/<name>.kex`; absence is a terminal not-found
result. Individual service payloads and retained tables have hard ceilings;
ordinary applications have no cumulative service-call ceiling. Heap growth is
bounded by allocator ownership and resident-page limits. Standard streams themselves
forward without an aggregate byte cap. Optional interfaces
expose only bounded IPv4/UDP send/receive, read-only VFS operations, one
sequential streamed file mutation, a boot-relative monotonic timer with
self-only process CPU time, one immutable typed diagnostics snapshot, current
read-only process accounting, read-only typed network observation, one DHCP exchange, one ICMP
   echo exchange, or one literal-IPv4 outbound TCP stream. Network observation,
   configuration, echo, datagrams, and TCP are independent authorities; none
   exposes raw frames, routes, DNS, TLS, or devices. Datagram
ports are exclusive to the launch; read-only
open tokens are generation-checked; directory traversal is
lexically paginated and final-component link targets are bounded. Mutation
working state is sequential, 16 KiB by default, and selectable through 1 MiB;
teardown does not roll back already written bytes. Empty-directory creation is
a separate bounded operation.
Timer waits are foreground
and cancellable; diagnostics retains fixed copied bytes rather than accounting
   borrows. TCP retains at most one unacknowledged 1,460-byte segment and one
   4 KiB receive FIFO per connection, retransmits four times on fixed timers,
   and admits only the exact tuple and next sequence. Dispatcher teardown
   unbinds ports, removes connections, and invalidates every token. No
raw-network, route-control, provider, block, device, or machine handle is
granted. The separate volume-control interface can list the boot policy and
activate only a BMNT-authorized provider already prepared by stable-identity
discovery; it cannot name raw devices or arbitrary target paths.

## Stage 8 persistent-storage boundary

The portable block-region, GPT, VFS-provider, read/write FAT32, constrained
metadata-preserving ext4 with bounded symbolic/hard links, native virtio
transport, dual-slot durability, and
selected STFS mutation pieces preserve this dependency direction. Directory,
rename, journal-replay, and repair mutation outside the documented profiles is
unsupported. A transport provides bounded block-region capabilities; partition
discovery turns a whole device into non-overlapping regions; independently
selected filesystem providers expose VFS objects.
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

Stage 9 adds a hosted deployment control-plane reference above these native
primitives. It consumes one complete PLOCK and active signed release per locked
member, stages and independently verifies immutable generation objects, and
publishes one pending/healthy pointer. Desired configuration persists outside
generations while each generation owns an exact read-only `/sys/config`
projection. Reversible data migrations retain canonical snapshots and roll back
with failed health; forward-only data instead enters an explicit
recovery-required state so predecessor code never runs over incompatible data.
Reachability GC retains active, previous, recovery, and in-flight transaction
roots. Native boot continues to consume CSPK/GMAN and SACT/TXSLOT rather than
parsing hosted filesystem metadata. See [ADR 0044](adr/0044-transactional-system-lifecycle.md).

The first network boundary is likewise split between safe protocol policy and
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
tests, and all four exhaustive QEMU platform suites together. q35 and QEMU
`virt` are exact profiles, not generic x86-64 or AArch64 contracts.

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

### x86-64 q35 profile

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
- The bounded q35 scanner covers bus zero, validates/de-loops modern virtio PCI
  capabilities, probes BAR sizes with decode disabled, restores configuration,
  and maps only the referenced page-rounded spans. Block and network queues use
  fixed modern-v1 contracts and reset-before-DMA-drop teardown.
- `poweroff` and `reboot` use q35 profile resources. Their I/O ports are not
  architecture defaults and another platform must supply validated equivalents.

### AArch64 QEMU `virt` profile

- The pinned profile uses GICv2. Distributor loops are bounded by
  `GICD_TYPER`; PL011 INTID 33 and each virtio SPI are validated before enable.
  GICv3 or a different firmware security state requires a distinct review.
- The IRQ vector preserves x0–x30, q0–q31, FPCR/FPSR, and the saved exception
  origin before Rust. Synchronous, FIQ, and SError paths that are not the lower
  application gate remain fatal.
- Idle keeps PSTATE.I set for `dsb sy; wfi`, briefly unmasks after wake so the
  pending GIC interrupt dispatches, then masks again before checking queues.
  Unmasking before `wfi` recreates a lost-wakeup race.
- EL0 mappings use distinct AP/PXN/UXN policy. Copied messages use unprivileged
  loads while PAN is active; return restores TTBR0_EL1 and completes the global
  invalidation before Rust resumes.
- The profile maps only its documented virtio-MMIO aperture, accepts modern
  devices, uses page-aligned live queue memory and outer-shareable DMA barriers,
  and parks on an unconfirmed reset rather than allowing DMA to outlive storage.
- PSCI 1.0 HVC supplies terminal poweroff and reboot. An unexpected PSCI return
  falls back to the terminal CPU park path.

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

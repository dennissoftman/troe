# TROE Core Specification

**Status:** Draft design specification  
**Version:** 0.1.0  
**Primary targets:** QEMU `x86_64`, QEMU `aarch64`  
**Future targets:** named x86-64 and AArch64 cloud VM platforms
**Implementation language:** Rust (`no_std`)  

**Implementation status:** Stages 0–8 are implemented. Stage 8 includes bounded
native block/network transports, deterministic persistent-volume selection,
immutable generation content, crash-consistent activation/rollback and selected
state mutation, plus generation-bound identity/mapping metadata. Stage 7 includes
the portable KEX parser/load-plan policy, native
validate/map/reclaim transactions, all three ABI 1.0 calls, contained fault
fates, and enforced 50 ms execution leases. See
[docs/roadmap.md](docs/roadmap.md).

The product name is TROE (Tiny Rust Operating Environment), and `troe` is the
reserved CLI executable name. This document also uses “the project” and “the
system” in prose.

Serialized format identifiers name only their technical formats and versions.
They MUST NOT embed a product, repository, vendor, or TROE CLI name. A project
rename must not invalidate KEX, KEFS, or boot-container artifacts.

The future developer tooling and package-composition model is specified in
[TOOLING-PACKAGING-SPEC.md](TOOLING-PACKAGING-SPEC.md). That document
extends this roadmap and inherits this specification's authority, resource,
security, and staging constraints. It does not describe functionality present
in release 0.1.

## 1. Purpose

The system is a tiny, autonomous command environment with just enough kernel beneath it to own a machine. It boots to a terminal, exposes a minimal filesystem, and provides a small set of composable isolated KEX commands.

It is an experiment in whether an operating environment can be simultaneously:

- small enough to understand as a whole;
- useful enough for interactive inspection and text manipulation;
- portable across x86-64 and AArch64 through a narrow machine boundary;
- robust by construction, with unsafe code isolated and audited;
- capable of evolving toward tasks, message passing, and isolation without beginning as a full microkernel;
- compact enough to aspire to a 1.44 MB boot image, while never exceeding a 16 MB experimental ceiling without an explicit specification change.

The system is not a miniature Linux distribution. It does not initially host conventional userspace programs, implement POSIX, or reproduce historical Unix internals. It borrows selected ideas and discards their accidental complexity.

## 2. Design thesis

> The system is a mechanically simple operating environment built around typed authority and composable objects, with architecture-dependent code confined to a small compile-time machine layer.

Its influences are selective:

- **Unix:** textual tools, simple names, streams, paths, composition, and unsurprising command behavior.
- **Linux VFS:** callers use one object model while filesystem implementations remain replaceable.
- **Hurd and microkernels:** mechanism/policy separation, service-shaped interfaces, explicit authority, and the ability to move a service behind IPC later.
- **PALcode-style layering:** architecture and machine details live below a narrow privileged interface rather than leaking through the portable core.
- **Rust:** ownership and types make invalid states difficult to express; unsafe operations are explicit and reviewable.

Architectural separation does not initially imply address-space separation. A logical service starts as an ordinary Rust module or object. It becomes a task or isolated server only when doing so yields a concrete benefit.

## 3. Normative language

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** describe requirements in this specification.

## 4. Goals

### 4.1 Primary goals

1. Boot reproducibly under QEMU on x86-64 and AArch64.
2. Present an interactive terminal and shell prompt.
3. Provide a tiny VFS with an embedded read-only root and writable RAMFS.
4. Provide KEX commands including `cat`, `echo`, `grep`, and `ls`.
5. Keep the portable core independent of CPU, firmware, UART, and interrupt-controller details.
6. Make memory consumption bounded, observable, and controlled by an explicit policy.
7. Minimize trusted and unsafe code, and test portable logic on the host.
8. Keep every feature removable at compile time where practical.
9. Preserve an evolution path from direct calls to dispatch, IPC, and optional isolation.
10. Measure binary size, boot memory, heap high-water mark, and cache use continuously.

### 4.2 Secondary goals

- Deterministic builds where the toolchain permits them.
- Fast boot and immediate terminal availability.
- Efficient operation on bounded cloud virtual machines across supported CPU
  architectures and hypervisors.
- Simple on-disk and in-memory formats that can be inspected manually.
- A shared source tree that produces separate, architecture-native binaries.

## 5. Non-goals

The MVP intentionally excludes the following. These are **deferred capabilities, not permanent project prohibitions**. The purpose of this list is to protect the first implementation from becoming a general-purpose OS before its foundations are understandable and reliable.

- POSIX conformance;
- `fork`, `exec`, signals, pipes as kernel objects, and a stable Unix syscall ABI;
- ELF userspace loading or dynamic linking;
- users, groups, discretionary permissions, ACLs, and login authentication;
- preemptive multitasking, SMP, and general-purpose scheduling;
- sockets and a network stack;
- a general device manager, USB stack, graphics stack, or audio stack;
- demand paging, swap, memory overcommit, and copy-on-write;
- a Linux-compatible `/proc`, `/sys`, or `/dev` ABI;
- arbitrary loadable kernel modules;
- full shell scripting, globbing, job control, or command substitution;
- a claim of zero defects or zero vulnerabilities.

The project instead aims for **no known vulnerabilities, explicit invariants, bounded behavior, and a small auditable attack surface**. “Clean from the start” is an engineering discipline, not a proof of perfection.

After the MVP proves the boot, memory, VFS, command, and architecture boundaries, the project is expected to grow into a genuinely usable small operating system. Candidate production capabilities include loadable ELF or another versioned executable container, isolated applications, networking, persistent filesystems, and a deliberately selected compatibility layer. Each addition must preserve the project's size, comprehensibility, authority, and resource-accounting principles.

## 6. System model

The current native command execution model remains deliberately narrow:

```text
+------------------------------------------+
| session shell: cd, poweroff, reboot      |
+------------------------------------------+
| scheduler | handles | copied call gate  |
+------------------------------------------+
| one bounded ring-3/EL0 KEX application   |
+------------------------------------------+
| streams | VFS | memory | terminal       |
+------------------------------------------+
| compile-time x86-64/AArch64 backend      |
+------------------------------------------+
| UEFI bootstrap / QEMU / hardware         |
+------------------------------------------+
```

There is:

- one active CPU;
- one privileged kernel root and at most one synchronously active isolated task
  root;
- one owned kernel scheduler/handoff stack, three privileged guarded task-stack
  slots, and one ephemeral unmapped-guard user stack per isolated launch;
- one global physical-memory owner;
- one command executing at a time;
- a ring-3/EL0 memory and fault boundary for the bounded isolated continuation;
- no application ABI for shell session or machine-control mutation;
- cooperative continuations without preemption or protection from a task that
  never returns through the internal gate.

Ordinary commands are target-native immutable KEX files, not privileged shell
functions. The shell registry retains only names/synopses and the three
intrinsics; the kernel resolver validates, maps, services, and tears down each
application through ABI 1.0.

## 7. Boot strategy

### 7.1 Staged boot

The recommended path is:

1. **Hosted prototype:** portable parser, commands, VFS, embedded FS, and RAMFS run as a normal host program for rapid testing.
2. **UEFI application:** x86-64 and AArch64 builds use firmware console, memory-map, and filesystem services while boot services remain active.
3. **Owned-machine kernel:** firmware is used only to enter the image and obtain a memory map; the system then exits boot services and owns memory, console, exceptions, and selected devices.
4. **Raw platform ports:** direct boot and board-specific initialization are added only for named, documented machines.

UEFI is a bootstrap strategy, not a permanent dependency of the portable core.

### 7.2 Images

The build MUST produce separate native executables for x86-64 and AArch64. A combined removable-media image MAY contain both architecture-specific UEFI fallback executables.

The image builder MUST be deterministic with respect to file order, metadata, and padding. It MUST report the size of:

- boot container;
- executable code and read-only data;
- embedded filesystem;
- architecture backend;
- debug information, if present;
- final image.

## 8. Architecture and machine abstraction

### 8.1 Boundary

The machine layer is the only portable-core dependency on privileged hardware behavior. It is conceptually PALcode-like: it hides CPU and platform mechanisms behind a small stable contract. It is technically a compile-time HAL, not runtime firmware and not a promise of cross-architecture binary compatibility.

Each image MUST select exactly one machine backend at compile time. Dynamic backend discovery and virtual dispatch MUST NOT be required for core boot.

Illustrative contract:

```rust
pub trait Machine {
    fn early_console_write(bytes: &[u8]);
    fn console_read_byte() -> Option<u8>;
    fn console_write(bytes: &[u8]) -> Result<(), MachineError>;

    fn memory_map() -> Result<&'static [MemoryRegion], MachineError>;
    fn install_exception_vectors() -> Result<(), MachineError>;
    fn enable_mmu(plan: &MappingPlan) -> Result<(), MachineError>;

    fn monotonic_ticks() -> u64;
    fn idle();
    fn halt() -> !;
    fn reboot() -> Result<Never, MachineError>;
}
```

Block I/O SHOULD be a separate optional capability so a terminal-only build does not carry storage code.

### 8.2 Backend responsibilities

A backend owns:

- entry assembly and initial stack;
- CPU feature validation;
- firmware handoff;
- exception-vector installation;
- page-table format and MMU activation;
- cache and TLB maintenance primitives;
- interrupt masking and minimal interrupt dispatch;
- timer access when enabled;
- UART or firmware console implementation;
- reboot, halt, and idle behavior;
- platform memory-map normalization;
- optional block-device transport.

The portable core MUST NOT contain architecture-specific registers, assembly, MMIO addresses, page-table bit encodings, or interrupt numbers.

### 8.3 Platforms and test environments

CPU architecture, machine platform, and execution environment are independent
axes. An architecture backend owns instruction-set mechanisms; a platform
descriptor supplies validated firmware, memory discovery, interrupt, timer,
console, bus, boot-media, and power resources. Selecting `x86_64` or `aarch64`
MUST NOT silently imply q35, QEMU `virt`, or another virtual machine.

| Platform | Role | Console | Boot | MMU page size |
|---|---|---|---|---|
| `x86_64-q35-uefi` | implemented QEMU acceptance | UEFI bootstrap; owned 16550 after handoff | UEFI/OVMF | 4 KiB |
| `aarch64-virt-uefi` | implemented QEMU acceptance | UEFI bootstrap; owned PL011 after handoff | UEFI/AAVMF | 4 KiB |

Exact emulator invocations MUST be pinned in CI scripts. New cloud platforms
MUST identify the architecture, firmware contract, discovery source,
transports, interrupt model, required features, and tested hypervisor/machine
combination. Physical boards and no-MMU/embedded targets are outside the
current scope. See
[ADR 0016](docs/adr/0016-hardware-targets-and-emulator-role.md).

## 9. Core object and authority model

### 9.1 Authority is passed, not globally discovered

Subsystems and commands MUST receive the capabilities they need. They SHOULD NOT reach through unrestricted globals to discover devices, filesystems, allocators, or reboot controls.

Illustrative command context:

```rust
pub struct CommandContext<'a> {
    pub stdin: &'a mut dyn Input,
    pub stdout: &'a mut dyn Output,
    pub stderr: &'a mut dyn Output,
    pub cwd: DirectoryHandle,
    pub namespace: &'a dyn Namespace,
    pub scratch: &'a mut dyn ScratchAllocator,
}
```

A command that receives only streams and a directory handle cannot reboot the machine or access arbitrary physical memory. Rust visibility, lifetimes, ownership, and sealed traits SHOULD enforce this structure before runtime permission checks are introduced.

### 9.2 Service-shaped interfaces

Interfaces that may later cross an IPC boundary MUST be message-shaped:

- explicit handles instead of internal pointers;
- owned or borrowed byte buffers with defined lifetimes;
- bounded request and response sizes;
- explicit error values;
- no exposure of private implementation layout;
- documented cancellation and partial-operation semantics.

The initial implementation MAY use direct function calls. The semantics MUST NOT depend on shared internal pointers that prevent later dispatch or IPC.

## 10. Terminal and streams

The terminal subsystem MUST expose byte-oriented input and output interfaces. UTF-8 SHOULD be the text encoding; invalid input MUST be handled without panic, using replacement, byte-preserving display, or an explicit error according to the command.

Minimum behavior:

- printable input;
- backspace, accepting both ASCII BS (`0x08`) and DEL (`0x7f`) from terminal
  transports;
- carriage-return/newline normalization;
- a visible prompt;
- bounded editable line length;
- deterministic handling of overflow;
- no terminal escape interpretation requirement in the first release.

`stdin`, `stdout`, and `stderr` are stream capabilities. Built-ins SHOULD operate
on streams where useful so pipelines, tests, and later composition do not depend
on a physical console.

## 11. Shell

### 11.1 Grammar

The release 0.1 shell grammar is intentionally small:

```text
line        := whitespace? pipeline whitespace?
pipeline    := stage (whitespace? "|" whitespace? stage)*
stage       := word (whitespace word)*
word        := one-or-more bare or quoted byte segments
```

Single and double quotes group bytes and may appear within a word. Quotes do not
perform interpolation. The parser MUST:

- use bounded input;
- reject malformed quoting;
- place a configured upper bound on arguments;
- avoid recursive parsing;
- never panic on arbitrary byte input.

There are no shell expansions, redirections, variables, background jobs, or
command substitution. Pipelines contain at most eight sequential stages and
each intermediate stream is capped at 64 KiB; overflow fails explicitly.

### 11.2 Command registry

Ordinary commands MUST be installed as immutable target-selected KEX artifacts.
Each package declares its name, synopsis, required typed capabilities, and entry
point. Unknown or unavailable commands return stable distinct errors and do not
terminate the shell.

`cd`, `poweroff`, and `reboot` are the only permanent shell intrinsics and their
names MUST NOT be shadowed or replaced by a KEX application. `cd` mutates
shell-owned session state and therefore executes in the invoking shell. The two
terminal actions remain behind the shell's explicit machine-control capability;
ordinary KEX applications cannot acquire that authority or invoke an intrinsic
through application ABI 1.0. No ordinary command has a privileged fallback.

### 11.3 Required commands

| Command | Minimum semantics |
|---|---|
| `cat [FILE...]` | Copy files to standard output; use standard input when no file is given. |
| `echo [ARG...]` | Write arguments separated by one space and followed by one newline. |
| `grep PATTERN [FILE...]` | Print lines containing a literal byte/string pattern; regex is not required. |
| `ls [PATH]` | List one directory in deterministic lexical order. |
| `pwd` | Print the logical current directory. |
| `cd PATH` | Change the shell's current directory. |
| `man COMMAND` | Read the embedded manual page for one registered command. |
| `mem` | Report memory totals, free pages, heap use, caches, and high-water marks. |
| `clear` | MAY emit a minimal ANSI clear sequence when enabled. |
| `halt` | Halt only when the shell possesses the machine-control capability. |
| `write FILE [TEXT...]` | Atomically create or replace a RAMFS file from arguments, or from standard input when no text follows the path. |
| `rm FILE` | Remove a writable RAMFS file. |
| `hexdump [FILE]` | Render a file or standard input as bounded hexadecimal output. |

`write FILE [TEXT...]` provides deliberate RAMFS mutation without adding shell
redirection.

Commands MUST report errors to `stderr` and return a typed status. Partial output is permitted only when documented and followed by a non-success status.

## 12. Filesystem and namespace

### 12.1 VFS philosophy

The VFS adopts Linux's common-object idea but not Linux's internal complexity. It MUST support at least directories, regular byte files, and generated service nodes through one namespace.

Illustrative interfaces:

```rust
pub trait Node {
    fn kind(&self) -> NodeKind;
    fn len(&self) -> Result<u64, FsError>;
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> Result<usize, FsError>;
    fn write_at(&self, offset: u64, src: &[u8]) -> Result<usize, FsError>;
}

pub trait Directory {
    fn lookup(&self, name: &Name) -> Result<NodeHandle, FsError>;
    fn visit(&self, visitor: &mut dyn DirVisitor) -> Result<(), FsError>;
}
```

These signatures are illustrative, not frozen ABI. The implementation SHOULD avoid heap-allocated iterators on hot or boot paths.

### 12.2 Initial namespace

```text
/
├── man/         embedded read-only command manual pages
├── etc/         embedded read-only configuration
├── tmp/         writable RAMFS
├── sys/         generated system-information nodes
└── dev/         capability-backed device nodes, if enabled
```

`/sys` and `/dev` are project-defined namespaces, not Linux-compatible ABIs.

Useful generated nodes include:

- `/sys/arch`;
- `/sys/memory`;
- `/sys/version`;
- `/sys/uptime` when a timer exists;
- `/dev/console` when safe read/write semantics are defined.

Generated nodes borrow the spirit of Hurd translators: a path can name behavior, not only stored bytes. They execute in-process initially.

### 12.3 Embedded read-only filesystem

The embedded filesystem MUST be generated at build time from a directory tree. Its format MUST be versioned, bounds-checkable, deterministic, and simple enough to audit manually.

It does not initially require:

- inodes;
- timestamps;
- owners or permissions;
- links;
- journaling;
- extents;
- compression.

All offsets, lengths, and path-table operations MUST be checked before access. Malformed images MUST fail mounting cleanly and MUST NOT lead to out-of-bounds reads.

### 12.4 RAMFS

RAMFS provides writable files and directories under `/tmp`. It MUST obey explicit quotas:

- total bytes;
- node count;
- maximum file size;
- maximum path depth;
- maximum name length.

Quota exhaustion MUST return `NoSpace` without destabilizing unrelated subsystems. Deleting a file MUST release its charged storage. Sparse files are not required.

### 12.5 Path rules

- `/` is the separator and root.
- Repeated separators SHOULD normalize to one.
- `.` and `..` MUST be handled without escaping the namespace root.
- NUL is forbidden in names.
- Name and total-path lengths are bounded compile-time constants.
- Symlinks are initially absent, eliminating link traversal cycles.
- Directory order exposed by `ls` MUST be deterministic.

### 12.6 Identity and foreign filesystem metadata (TBD)

Persistent and external filesystem support MUST NOT assume that a raw numeric
UID/GID, a Windows SID, or a familiar account name is proof of a local system
identity. The planning direction is to use stable, opaque native principals
and explicit mount/import identity mappings while retaining first-class
UID/GID compatibility. Authentication, identity mapping, ownership, and active
capability authority are separate concerns.

Filesystem drivers SHOULD preserve security metadata in its native form when
the source format can be round-tripped. In particular, ext4/XFS-style numeric
UIDs, GIDs, mode bits, and supported ACL metadata should remain representable,
while NTFS owner/group SIDs and complete supported security descriptors should
not be irreversibly reduced to Unix mode bits. Unmapped identities remain
distinguishable and inspectable; they MUST NOT silently collapse to a local
user, group, administrator, or all-powerful fallback identity. Translation
that is approximate or lossy must be reported explicitly.

The exact principal representation, group model, mapping-domain format,
authorization descriptor, copy/archive behavior, and fail-closed rules require
a focused ADR before a persistent writable filesystem, foreign-filesystem
write support, or stable VFS metadata ABI is accepted. The proposed direction
and unresolved questions are recorded in
[ADR 0007](docs/adr/0007-identity-and-foreign-filesystem-mapping.md).

### 12.7 Persistent filesystem modules and partitions

Persistent disk formats MUST be replaceable filesystem providers behind the
VFS and a bounded block-region capability. The kernel composition root and
machine backends MUST NOT absorb FAT12/16/32, exFAT, ext4, NTFS, or
partition-format logic. Before dynamic modules exist, a build may statically
select a provider crate; this temporary composition choice must preserve the
same narrow interface and include only the selected providers. Writable
providers SHOULD become capability-scoped filesystem services once the task and
application boundaries can isolate them.

KEFS remains the built-in immutable recovery filesystem, and the fixed FAT12
image remains the firmware-read boot container. A separate general FAT provider
targets read/write FAT12/16/32 media, with FAT32 first for EFI and broad
interchange compatibility; exFAT is a complementary optional provider for
read/write access to large removable media. These formats use synthetic
ownership and are not journaled native stores. A constrained, versioned ext4
profile is the default native persistent data-volume format. NTFS is a later
optional foreign-filesystem provider, read-only before read-write, using the
maintained Linux NTFS3 project as a behavioral and interoperability reference
subject to license review. No raw foreign UID, GID, SID, ACL, or security
descriptor gains native authority merely because a provider can parse it.

Filesystem providers receive a whole-device or partition-bounded region; they
do not discover partitions themselves. Initial installed media SHOULD use
bounded read-only GPT discovery and a fixed host-created FAT32 EFI plus ext4
data layout. Whole-device volumes remain valid for tests and simple
deployments. General MBR traversal, in-kernel partition editing, resizing, LVM,
software RAID, and automatic partition repair are deferred.

The accepted roles, modularity rule, ext4 profile direction, NTFS licensing
gate, and lean partition scope are recorded in
[ADR 0009](docs/adr/0009-persistent-filesystems-and-partitions.md).

Filesystem module packaging MAY carry a license distinct from the Apache-2.0
core only when source, artifact, SPDX/notices, provenance, and lifecycle remain
explicitly separate. Static linking or bundling is not presumed to create a
license boundary. The default system image MUST NOT silently combine
license-incompatible code; each distribution form requires review.

## 13. Memory management

### 13.1 Principles

Memory management MUST favor predictable ownership and observability over sophisticated utilization. It MUST avoid both extremes:

- retaining large caches on constrained systems;
- spending code, metadata, and CPU time to save tiny amounts on large systems.

Mechanism and policy are separate:

```text
firmware memory map
        ↓
physical frame mechanism
        ↓
virtual mapping mechanism
        ↓
heap allocator mechanism
        ↓
runtime memory policy
        ↓
RAMFS / caches / commands
```

No subsystem except the physical-memory manager and architecture MMU backend may manipulate frame ownership directly.

### 13.2 Boot allocator

Before the general allocator is available, boot code MUST use a bounded monotonic allocator over an explicitly reserved region. Allocations are aligned and checked. Individual frees are not supported.

The boot allocator MUST record bytes used and MUST be retired, sealed, or transferred to the physical allocator after initialization. Silent overlap with the kernel image, firmware data, page tables, or embedded FS is forbidden.

### 13.3 Physical frame allocator

The physical allocator owns normalized usable RAM ranges and tracks fixed-size base pages. The initial implementation SHOULD use a proven, compact bitmap or free-range allocator rather than inventing a complex allocator.

Selection criteria include:

- no hidden OS dependencies;
- bounded metadata;
- compatibility with `no_std`;
- clear provenance and compatible license;
- straightforward auditability;
- checked arithmetic;
- tests covering fragmentation, exhaustion, and invalid frees;
- ability to reserve discontiguous firmware and device regions.

Borrowed code MUST be pinned to a revision, wrapped behind a project-owned interface, documented in `THIRD_PARTY.md`, and audited before becoming part of the trusted base.

The frame allocator MUST detect or prevent double-free, freeing unowned frames, and range overflow in debug/test builds. Production behavior MUST be defined and MUST NOT corrupt allocator metadata.

### 13.4 Heap allocator

The first heap SHOULD be one of:

- a small audited segregated free-list allocator;
- a TLSF-style allocator when bounded allocation latency is important;
- a buddy-backed slab/size-class allocator if page allocation is already required.

A home-grown general allocator is discouraged unless its simplicity is materially better than an audited dependency. The chosen allocator MUST support alignment required by Rust, checked size calculations, graceful allocation failure, and accounting.

Allocation failure MUST NOT default to an opaque infinite loop. The system MUST either propagate `OutOfMemory`, shed reclaimable memory and retry once under policy control, or enter a diagnostic fatal path when failure occurs in a non-recoverable boot operation.

### 13.5 Standard memory policy

Every supported build uses one bounded standard policy for page-backed cloud
virtual machines. There is no build-time memory-profile selector and no
embedded/no-MMU variant. Detected usable RAM may refine runtime budgets, but
all externally influenced lengths and counts remain below absolute compile-time
ceilings so corrupt discovery cannot request absurd allocations.

Large ceilings are not reservations. The heap, application frames, RAMFS, and
caches are charged only as memory is acquired; ownership and high-water
accounting remain exact. Policy SHOULD favor clear metadata and straightforward
failure handling over elaborate packing that saves negligible memory on the
supported VM class.

### 13.6 Adaptive policy

Adaptation MUST remain explainable and deterministic. A policy object receives:

- total usable RAM;
- reserved and permanently allocated RAM;
- current free pages;
- heap live bytes and high-water mark;
- RAMFS charged bytes;
- reclaimable cache bytes;
- standard hard ceilings.

It returns explicit budgets for the heap growth reserve, RAMFS, and each cache. Subsystems MUST NOT infer “plenty of memory” independently.

Initial pressure thresholds:

- **Normal:** more than 25% of usable pages free. Caches may grow to their budget.
- **Pressure:** 10–25% free. Cache growth stops and cold reclaimable entries may be dropped.
- **Critical:** below 10% free or after an allocation failure. Reclaimable caches are drained, RAMFS rejects growth beyond its current charge, and the failed allocation may be retried once.

Thresholds MUST be configurable and tested at their boundaries. Reclamation MUST NOT discard RAMFS file contents or other non-reclaimable user state.

### 13.7 Caching rules

The embedded FS initially reads directly from its immutable image and requires no page cache. RAMFS contents are already resident and MUST NOT be duplicated in a second cache.

Directory lookup or generated-node caches MAY be added only after measurement demonstrates value. Every cache MUST declare:

- ownership of cached memory;
- maximum charge;
- eviction policy;
- whether entries are reconstructible;
- pressure behavior;
- accounting exposed through `mem` and `/sys/memory`.

An unbounded cache is a specification violation.

## 14. MMU and virtual memory

### 14.1 Initial purpose

The MMU is initially used for safety and hardware correctness, not for virtual-memory illusion. The first mapping plan SHOULD provide:

- executable, read-only kernel text;
- read-only data and embedded FS;
- non-executable writable data, heap, and stacks;
- guard pages around stacks when feasible;
- explicitly typed device mappings;
- no writable-plus-executable mappings after initialization;
- no mapping of unusable or unowned physical memory.

Demand paging, swapping, overcommit, and per-command address spaces are absent.

### 14.2 Mapping model

The portable memory subsystem constructs an architecture-neutral `MappingPlan`. The backend validates alignment and translates it to native page tables.

Each mapping records:

- virtual range;
- physical range or allocator source;
- permissions: read, write, execute;
- memory type: normal, device, or firmware-defined;
- lifetime and owner;
- whether the range may be remapped after boot.

All range arithmetic MUST use checked operations. Mapping overlaps MUST be rejected unless an explicit, narrowly scoped replacement operation authorizes them.

### 14.3 Staging

1. Run with firmware mappings while validating portable subsystems.
2. Build minimal identity or direct mappings required to take control safely.
3. Enable W^X permissions and guarded stacks.
4. Add a stable kernel virtual layout only when it simplifies multiple platforms.
5. Add per-task address spaces only with the isolation milestone.

Page-table construction is architecture-specific unsafe code and MUST have pure model tests for range planning plus QEMU integration tests for actual permission faults.

## 15. Error handling and robustness

Expected failures MUST use typed `Result` values. Panics indicate invariant violations, not normal input errors.

The system MUST define behavior for:

- malformed commands and excessive arguments;
- invalid UTF-8 or arbitrary file bytes;
- nonexistent paths and wrong node types;
- end of file and partial reads/writes;
- allocation and quota exhaustion;
- corrupt embedded filesystem metadata;
- unsupported machine features;
- unexpected exceptions and page faults.

Fatal faults MUST print the most reliable available diagnostic using the early console, then halt or reboot according to build policy. Fatal handlers MUST avoid allocation and filesystem access.

Integer parsing, size addition, alignment, offset calculation, and pointer-range conversion MUST use checked arithmetic.

## 16. Unsafe code policy

The portable core SHOULD use `#![forbid(unsafe_code)]` where crate boundaries permit it. Unsafe code is restricted to narrowly scoped crates or modules for:

- entry and context assembly;
- privileged registers and instructions;
- MMIO access;
- page-table activation and TLB maintenance;
- allocator internals where unavoidable;
- conversion of validated firmware or linker ranges into Rust slices;
- interrupt and exception boundaries.

Every unsafe block MUST include a `SAFETY:` comment stating the invariant that makes it valid. Unsafe modules MUST document:

- inputs assumed valid;
- memory and aliasing invariants;
- synchronization assumptions;
- lifetime ownership;
- how callers uphold the contract;
- tests or review evidence.

CI MUST report unsafe block count and SHOULD fail if it increases without an accompanying audit note.

## 17. Concurrency and synchronization

The initial kernel is single-core and non-preemptive. Interrupt handlers, if enabled, MUST do bounded work and MUST NOT allocate unless the allocator explicitly supports that context.

Synchronization primitives MUST NOT be introduced merely for hypothetical SMP. Interior mutability and globals still require documented ownership because interrupt context can create concurrency even on one CPU.

SMP is a separate future milestone requiring a memory model, lock ordering, per-CPU state, interrupt routing, and allocator review.

## 18. Observability

At Stage 5, `mem` and `/sys/memory` expose:

- total normalized usable RAM;
- permanently reserved RAM;
- free and total managed frames;
- heap live, capacity, and high-water bytes;
- allocation-failure count;
- RAMFS live, limit, and high-water bytes;
- cache live and limit bytes (both zero in the current configuration);
- current memory-pressure state;

Later memory-policy work SHOULD add separately charged page-table memory,
allocated-frame totals, and reclamation counters when those distinctions become
actionable.

Debug builds SHOULD expose a boot log and invariant checks. Release builds MAY compile out verbose logging, but fatal diagnostics and resource counters SHOULD remain.

## 19. Size and resource budgets

### 19.1 Image limits

- **Aspirational target:** a useful bootable image at or below 1,474,560 bytes (1.44 MB).
- **Hard experimental ceiling:** 16 MiB for a release image, including boot container and embedded filesystem.

Crossing 1.44 MB is not a correctness failure, but MUST be visible in CI. Crossing 16 MiB fails the release build unless this specification is deliberately revised with a recorded rationale.

Debug symbols and host-side test artifacts are excluded. A stripped deployable image is measured.

### 19.2 Feature accounting

Every optional feature SHOULD report its approximate image-size and steady-state memory delta. Size regressions MUST be attributed to code, read-only data, embedded files, alignment, or boot-container overhead.

Recommended initial budgets for the 1.44 MB profile:

| Component | Budget |
|---|---:|
| boot and architecture backend | 192 KiB |
| portable kernel/core services | 384 KiB |
| shell and commands | 256 KiB |
| embedded filesystem content | 384 KiB |
| format/alignment/reserve | 224 KiB |

These are planning budgets, not ABI guarantees. Code clarity MUST NOT be sacrificed for tiny savings that do not affect a measured target.

## 20. Build and source organization

Current workspace structure:

```text
troe/
├── crates/
│   ├── troe-core/        portable types and bounded streams
│   ├── troe-dispatch/    bounded synchronous service dispatch
│   ├── troe-machine/     audited x86-64/AArch64 mechanisms
│   ├── troe-memory/      memory-map, frame, and mapping models
│   ├── troe-shell/       parser, pipelines, and session intrinsics
│   ├── troe-task/        cooperative task policy
│   └── troe-vfs/         KEFS, RAMFS, namespace, and generated nodes
├── host/                 hosted composition and acceptance runner
├── kernel/               native UEFI entry and composition root
├── xtask/                Cargo QEMU launcher shim
├── rootfs/, assets/      embedded source tree and generated KEFS image
├── scripts/, tools/      build, test, audit, QEMU, and image utilities
├── tests/                hosted shell acceptance script
└── docs/                 architecture, decisions, evaluations, and audits
```

Crates are boundaries for reasoning, testing, and unsafe-code policy. They SHOULD NOT become tiny crates without a concrete ownership or dependency benefit.

Production targets use `no_std`. `alloc` MAY be used after the global allocator is initialized. Portable crates SHOULD support host tests with `std` behind test or feature configuration.

## 21. Testing and verification

### 21.1 Host tests

Host tests MUST cover:

- shell tokenization and malformed input;
- command semantics and status values;
- VFS path normalization;
- embedded FS parsing, including corrupt images;
- RAMFS quotas and deletion accounting;
- literal `grep` across chunk and line boundaries;
- partial stream operations;
- physical allocator allocation/free/exhaustion behavior;
- memory-policy thresholds and caps;
- mapping-plan overlap and overflow rejection.

Property tests and fuzzing SHOULD target parsers, path handling, filesystem images, arithmetic boundaries, and allocators.

### 21.2 QEMU tests

Each primary architecture MUST have automated tests that:

1. boot to the prompt within a timeout;
2. run every required KEX application;
3. read embedded files and write/read RAMFS files;
4. exercise missing paths, malformed commands, and quota exhaustion;
5. print memory accounting;
6. halt cleanly;
7. verify a representative write-to-read-only or execute-from-non-executable fault after MMU hardening.

The serial transcript SHOULD be stable enough for golden assertions, with variable addresses and timing isolated from deterministic output.

### 21.3 Review gates

A release candidate MUST pass:

- formatting and linting;
- host unit, property, and available fuzz-regression tests;
- both architecture boot suites;
- image-size ceiling check;
- unsafe-code inventory check;
- third-party license and pinned-revision check;
- no known failing invariant or unresolved critical audit finding.

## 22. Security model

Ordinary commands execute only as isolated KEX applications. Supervisor page
permissions, copied messages, contained user faults, owner-revoked handles, and
zeroized teardown protect the kernel from that execution context. The three
intrinsics remain small kernel/session transitions and expose no general
application-callable machine authority.

Accordingly:

- executable code is loaded only after complete KEX/KCAP validation;
- embedded FS input is treated as potentially malformed;
- console input is untrusted and bounded;
- external block filesystems remain optional until separately specified and fuzzed;
- no network attack surface exists initially;
- no command may access raw memory or devices unless explicitly given that capability;
- release documentation MUST state whether hardware isolation exists.

Application isolation does not provide preemption or make the system multi-user
secure. Every application artifact and application-controlled address remains
untrusted.

## 23. Evolution roadmap

### Stage 0 — Portable model

**Status:** complete.

- Host executable with shell, streams, VFS, embedded FS, RAMFS, and commands.
- No unsafe code in portable crates.
- Resource quotas and deterministic tests.

**Exit criterion:** arbitrary parser and filesystem test inputs do not panic; required commands pass host tests.

### Stage 1 — Firmware-hosted QEMU environment

**Status:** complete.

- UEFI x86-64 and AArch64 images.
- Firmware console and memory services.
- Same portable command and VFS code.

**Exit criterion:** both targets boot and pass serial smoke tests.

### Stage 2 — Machine-owning kernel

**Status:** complete.

- Exit firmware boot services.
- Boot allocator, physical allocator, heap, native console.
- Exception handling and explicit memory accounting.

**Exit criterion:** repeated command and RAMFS workloads run without leaks or firmware services.

### Stage 3 — MMU hardening

**Status:** complete and verified.

- Owned page tables.
- W^X kernel mappings, device memory types, guarded stacks where feasible.
- Permission-fault integration tests.

**Exit criterion:** mapping invariants hold on both architectures and deliberate violations fault predictably.

### Stage 4 — Cooperative tasks

**Status:** complete.

- Multiple tasks in one address space.
- Explicit stacks, lifecycle states, and capabilities.
- Cooperative yield only; no preemption requirement.

**Exit criterion:** multiple continuations yield and exit deterministically, and
task identity, capability, lifecycle, and stack ownership are accounted. This
stage does not claim fault containment or protection from memory-unsafe code.

### Stage 5 — In-process message dispatch

**Status:** complete.

- Handles, ports, bounded messages, request/reply semantics.
- Selected direct service calls move behind dispatch without changing their conceptual API.

**Exit criterion:** filesystem or console service can switch between direct and dispatched implementations in tests.

### Stage 5.1 — Native text console and shell usability

**Status:** complete; accepted by
[ADR 0012](docs/adr/0012-native-text-console-and-editor-policy.md).

- Portable, policy-configured terminal input and cursor-aware line editing.
- Bounded volatile history and shell/VFS completion.
- Owned framebuffer text output while UART remains the recovery and acceptance
  transport.

**Exit criterion:** both architectures support the owned text-console
abstraction within explicit input, history, completion, and framebuffer bounds,
without weakening deterministic UART recovery and acceptance.

### Stage 6 — Optional isolation

**Status:** complete; accepted by
[ADR 0014](docs/adr/0014-unprivileged-task-isolation-and-teardown.md).

- Per-task address spaces.
- Bounded copied-message transfer; no shared-memory contract.
- Fault containment and task teardown.
- Owner-scoped handle revocation and zeroized frame reclamation.

**Exit criterion:** met on both primary architectures. An isolated task fault
does not corrupt the kernel or unrelated service, authority transfer is
explicit, and all owned resources are revoked, zeroed, and reclaimed.

### Stage 7 — Loadable applications

**Status:** implemented from the design accepted by
[ADR 0015](docs/adr/0015-kex-application-abi-and-execution-bounds.md). The
portable KEX plan, native transaction, complete ABI 1.0 gate, scheduler-owned
resume, copied handle dispatch, contained call/fault fates, and execution lease
are active on both primary architectures.

The kernel/security exit criterion is complete. Loading KEX files from a
mounted filesystem or shell command, providing hosted SDK `build`/`run`/`inspect`
flows, and defining package-manifest and target-lock formats are explicitly
deferred integration work. They do not block Stage 7.5 or Stage 8; the
authoritative order for resuming work is recorded in
[docs/roadmap.md](docs/roadmap.md#stage-75-cloud-platform-separation-phase-a-implemented-phase-b-planned).

- Load target-specific static KEX v1 artifacts selected by ADR 0015; keep ELF as
  a hosted toolchain interchange format rather than a kernel input.
- Validate every header, segment, permission, alignment, relocation, entry point, and address range before mapping.
- Give each application an explicit set of handles/capabilities and a bounded memory budget.
- Implement the small versioned application ABI 1.0 independently of POSIX.
- Provide application startup, exit status, fault reporting, and resource reclamation.
- Support architecture-native binaries; cross-architecture instruction emulation is not required.
- Keep the immutable target-selected KEX root available for recovery.
- Before released tooling consumes them, define a versioned
  application/package manifest and target-specific lock format and validate
  immutable artifacts on the host using the native boundary's rules.
- Introduce the first native SDK and hosted `troe build`, `troe run`,
  `troe inspect`, and `troe explain` flows without granting the tooling client
  ambient system authority; this is deferred integration rather than part of
  the completed kernel exit criterion.

Dynamic linking is optional and SHOULD follow a working static executable format rather than ship with the first loader.

**Exit criterion:** an untrusted test application can be loaded, run, exit, and fault without corrupting the kernel, while malformed binaries are rejected deterministically.

### Stage 7.5 — Cloud platform separation

**Status:** Phase A platform separation implemented; Phase B cloud discovery
and named matrix entries planned under
[ADR 0016](docs/adr/0016-hardware-targets-and-emulator-role.md).

- Separate reusable x86-64/AArch64 CPU mechanisms from platform integration and
  execution-environment selection.
- Preserve q35 and QEMU `virt` as pinned deterministic test profiles without
  treating their devices, addresses, or firmware behavior as architecture
  contracts.
- Validate platform resources from an explicit profile, ACPI, device tree, or
  UEFI handoff before constructing typed machine resources.
- Add named virtio-capable VM descriptors and bounded ACPI, device-tree, and
  UEFI discovery without ambient probing.
- Test a declared multi-hypervisor/cloud matrix and record the exact firmware,
  machine type, transports, and required features for every supported entry.
- Keep physical boards, USB/SD bring-up, and embedded/no-MMU targets outside
  the current roadmap.

**Exit criterion:** both pinned QEMU platforms and every named cloud-matrix
entry reach the recovery shell and pass bounded boot, storage, networking, and
lifecycle smoke tests without introducing VM assumptions into portable crates
or architecture-wide mechanisms.

### Stage 8 — Networking and persistent operation

**Status:** implemented. Portable block/GPT/VFS/config/content/identity layers
are host verified. Both native virtio block and network transports are QEMU
verified on x86-64 PCI and AArch64 MMIO. Exact BMNT/GPT/ext4 selection activates
`/vol/root`; PRGN/TXSLOT persists SACT activation and a separate STFS mutation
through real flush/reopen cycles. CSPK/GMAN/ISEC bind SCFG plus identity registry,
foreign mapping, mount policy, and native ACL objects to immutable generations.
Configured health failure rolls generation 2 back durably to generation 1.

- Introduce network-device capabilities and a bounded-buffer network stack.
- Begin with a small practical protocol set such as Ethernet, ARP/NDP as appropriate, IPv4 and/or IPv6, ICMP, UDP, DHCP or static configuration, and DNS.
- Keep TCP behind the ADR 0031 typed outbound-connect service whose state,
  timer, retransmission, and memory bounds are specified and adversarially
  tested; do not widen it into a general socket interface.
- Expose networking through handles or service interfaces rather than ambient global access.
- Resolve the native-principal and foreign-filesystem identity-mapping ADR
  before accepting persistent VFS metadata or enabling foreign-filesystem
  writes.
- Add bounded block I/O and block-region capabilities, whole-device volumes,
  and read-only GPT discovery without an in-kernel partition editor.
- Add the constrained ext4 provider as the default selected persistent content
  volume and prove a bounded writable filesystem through the same block/VFS
  capability boundary. Broader read/write ext4, FAT, and exFAT providers are
  deployment/usability expansions after this stage and remain independently
  selectable; NTFS remains optional and foreign.
- Define configuration, service startup, and recovery behavior suitable for unattended use.
- Add the persistent content store and desired-system manifest only after their
  on-disk formats, bounds, corruption behavior, and recovery paths are tested.
- Construct immutable system generations separately from mutable volumes and
  secrets; activate a generation through a crash-consistent pointer.
- Preserve the previous bootable generation and immutable recovery KEX root when
  activation or bounded health checks fail.

**Exit criterion:** the system can boot, configure a supported network device, exchange data with another host, persist selected state, and remain within declared memory budgets under malformed and high-volume input.

### Stage 9 — Production usability

**Status:** not implemented.

- Establish a supported native application SDK and versioned ABI policy.
- Add selected utilities and services driven by real use cases.
- Decide whether a documented POSIX subset materially improves portability without dominating the design.
- Add supported update, rollback, garbage-collection, crash-diagnostic, and
  reproducible-release procedures, including explicit data-migration limits.
- Establish registry trust roots, signature and revocation policy, provenance
  requirements, and stable machine-readable tooling schemas.
- Define threat models and hardening profiles for supported deployment classes.
- Maintain a minimal recovery image even when the full production image grows beyond the floppy-size target.

**Exit criterion:** a named end-to-end deployment can be installed, operated, updated, diagnosed, and recovered using documented procedures.

Preemption, SMP, external filesystems, networking, executable loading, and POSIX subsets each require focused proposals and security review. They are part of the intended post-MVP design space, but no specific implementation is implied merely by completing an earlier stage.

## 24. API evolution rule

The intended internal progression is:

```text
direct Rust call
        ↓
handle-based dispatch
        ↓
bounded in-process message
        ↓
isolated message transport
```

Semantics should remain stable across these transitions. An interface MAY be split out when it improves testability, portability, authority control, or isolation. It SHOULD remain an ordinary module when separation only adds indirection.

General abstractions SHOULD normally have at least two real consumers or implementations. Expected early examples are:

- machine API: x86-64 and AArch64;
- console: firmware and native UART;
- VFS node: embedded file, RAMFS file, and generated node;
- platform descriptors: at least two named VM machines per reusable discovery
  or transport boundary.

## 25. Versioning and compatibility

Before `1.0`, internal Rust APIs are unstable. The following formats MUST still carry explicit versions from their introduction:

- embedded filesystem image;
- boot configuration, if any;
- message wire format, once introduced;
- crash or diagnostic record, if persisted;
- application/package manifest and immutable artifact envelope;
- dependency lock file;
- desired-system manifest and generation record;
- registry metadata and stable machine-readable CLI output, when introduced.

No installed release or live-machine state exists yet, so provisional format
versions have no backward-compatibility obligation. A format may be replaced or
renumbered when that materially improves simplicity, efficiency, reliability,
or security, provided its specification, independent builder/verifier,
fixtures, corruption tests, and every in-tree consumer change atomically.
Versioning remains mandatory so test evidence identifies the exact contract;
it is not a reason to retain accidental fields or migration code for artifacts
that were never deployed.

Command behavior SHOULD remain backward compatible within a minor release series, but POSIX compatibility MUST NOT be inferred from familiar command names.

## 26. Definition of the first useful release

Release 0.1 is complete when:

- separate x86-64 and AArch64 images boot under pinned QEMU configurations;
- each reaches an interactive recovery prompt;
- `cat`, `echo`, literal `grep`, `ls`, `pwd`, `cd`, `man`, `mem`, and `halt` work as specified;
- `/` includes an embedded read-only filesystem and `/tmp` is a quota-bound RAMFS;
- `/sys/arch`, `/sys/version`, and `/sys/memory` are readable through the VFS;
- malformed input, nonexistent paths, oversized input, and memory exhaustion fail cleanly;
- the build reports image and runtime memory budgets;
- the stripped image is below 16 MiB;
- all host and QEMU acceptance tests pass;
- every unsafe block is inventoried and justified.

Fitting the same useful configuration at or below 1.44 MB is the next optimization objective, not a reason to weaken correctness or auditability.

## 27. Decision principles

When design choices compete, use this order:

1. memory safety and explicit invariants;
2. comprehensibility and auditability;
3. deterministic bounded behavior;
4. correctness on both primary architectures;
5. measured resource efficiency;
6. performance;
7. compatibility and feature breadth.

A feature belongs in the project only when its value exceeds its cost in code size, runtime memory, unsafe surface, test burden, and conceptual complexity.

## 28. Open decisions

Decisions resolved through the Stage 7 design are recorded in
[docs/adr](docs/adr) and summarized in [docs/roadmap.md](docs/roadmap.md).
The following later-stage choices remain open and require short architecture
decision records before implementation:

- canonical package-artifact encoding and digest/signature scope;
- dependency/version semantics and multi-target lock-file representation;
- content-store layout, generation activation record, and recovery protocol;
- persistent-data migration and rollback contract;
- exact versioned ext4 feature profile, journal/durability contract, recovery
  bounds, host-tool versions, and maximum supported volume geometry;
- exact FAT12/16/32 and exFAT interoperability profiles, mutation scope,
  synthetic metadata policy, and dirty-volume recovery behavior;
- filesystem-provider loading/isolation transition and the bounded GPT plus
  block-region contract;
- native principal/group representation, identity domains, UID/GID and SID
  mappings, foreign security-descriptor preservation, and lossy-copy policy;
- package trust roots, key rotation, revocation, and offline verification policy.

Each decision record MUST state alternatives, measurable costs, safety impact, and conditions under which the choice should be revisited.

---

The project succeeds if a reader can trace the path from a byte arriving at the console, through parsing, namespace lookup, memory allocation, and architecture-specific output—and understand why every boundary exists. Small image size matters; small conceptual size matters more.

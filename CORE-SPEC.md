# TROE Core Specification

**Status:** Current system specification
**Version:** 0.1.0  
**Primary targets:** QEMU `x86_64`, QEMU `aarch64`  
**Implementation language:** Rust (`no_std`)  

**Implementation status:** The current native system has bounded block/network
transports, deterministic persistent-volume selection, immutable generations,
crash-consistent activation/rollback, generation-bound identity/configuration,
static KEX validation and isolation, resident scheduling and process launch,
typed application services, and a repo-local SDK. No non-QEMU production
environment is accepted. Work beyond the implemented contract is tracked in
[GitHub issues](https://github.com/dennissoftman/troe/issues).

The product name is TROE (Tiny Rust Operating Environment), and `troe` is the
reserved CLI executable name. This document also uses “the project” and “the
system” in prose.

Serialized format identifiers name only their technical formats and versions.
They MUST NOT embed a product, repository, vendor, or TROE CLI name. A project
rename must not invalidate KEX, KEFS, or boot-container artifacts.

Repository scripts, Cargo commands, the KEX SDK, and deterministic image tools
are the current developer surface. They do not imply a public package manager,
registry, or privileged system-control CLI.

## 1. Purpose

The system is a tiny, autonomous command environment with just enough kernel beneath it to own a machine. It boots to a terminal, exposes a minimal filesystem, and provides a small set of composable isolated KEX commands.

It is an experiment in whether an operating environment can be simultaneously:

- small enough to understand as a whole;
- useful enough for interactive inspection and text manipulation;
- portable across x86-64 and AArch64 through a narrow machine boundary;
- robust by construction, with unsafe code isolated and audited;
- built around bounded tasks, typed message passing, and isolated KEX processes
  without claiming a complete microkernel service split; and
- compact enough to fit the current 8 MiB boot container while never exceeding
  a 16 MiB experimental ceiling without an explicit specification change.

The system is not a miniature Linux distribution. It does not load conventional
host ELF programs, implement POSIX, or reproduce Unix internals wholesale. It
borrows selected ideas and discards their accidental complexity.

## 2. Design thesis

> The system is a mechanically simple operating environment built around typed authority and composable objects, with architecture-dependent code confined to a small compile-time machine layer.

Its influences are selective:

- **Unix:** textual tools, simple names, streams, paths, composition, and unsurprising command behavior.
- **Linux VFS:** callers use one object model while filesystem implementations remain replaceable.
- **Hurd and microkernels:** mechanism/policy separation, service-shaped interfaces, and explicit authority across protection boundaries.
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

The current system intentionally makes none of the following claims. This list
defines the implemented boundary; it is not automatically a backlog:

- POSIX conformance;
- `fork`, address-space replacement `exec`, signals, and a stable Unix syscall ABI;
- ELF userspace loading or dynamic linking;
- interactive users, login authentication, or a general multi-principal
  authorization engine;
- SMP and general-purpose scheduling policy;
- a POSIX socket API or general-purpose network stack;
- a general device manager, USB stack, graphics stack, or audio stack;
- demand paging, swap, memory overcommit, and copy-on-write;
- a Linux-compatible `/proc`, `/sys`, or `/dev` ABI;
- arbitrary loadable kernel modules;
- full shell scripting, globbing, POSIX process groups, or command substitution;
- a claim of zero defects or zero vulnerabilities.

The project instead aims for **no known vulnerabilities, explicit invariants,
bounded behavior, and a small auditable attack surface**. “Clean from the
start” is an engineering discipline, not a proof of perfection. Only accepted
GitHub issues represent work beyond this boundary.

## 6. System model

The current native command execution model remains deliberately narrow:

```text
+--------------------------------------------------------------+
| shell: cwd, jobs, services, lifecycle, immutable KEX lookup   |
+--------------------------------------------------------------+
| resident scheduler | process registry | handles | copied IPC |
+--------------------------------------------------------------+
| isolated KEX set; one ring-3/EL0 continuation executes/CPU   |
+--------------------------------------------------------------+
| typed streams | pipes | VFS | network | timer | diagnostics  |
+--------------------------------------------------------------+
| named x86-64/AArch64 platform and execution environment      |
+--------------------------------------------------------------+
| UEFI bootstrap and owned kernel machine boundary             |
+--------------------------------------------------------------+
```

There is:

- one active CPU;
- one privileged kernel root and at most one executing isolated task root;
- one owned kernel scheduler/handoff stack, three privileged guarded task-stack
  slots, and an owned unmapped-guard user stack for each admitted isolated
  process;
- one global physical-memory owner;
- at most 65,533 retained resident application records under the 65,536-task
  system ceiling, with one selected for an execution slice at a time;
- a ring-3/EL0 memory and fault boundary for the bounded isolated continuation;
- no application ABI for shell session or machine-control mutation;
- scheduler-owned resumable preemption with a 50 ms maximum uninterrupted
  application lease.

Ordinary commands are target-native immutable KEX files, not privileged shell
functions. The shell registry retains only names/synopses and the nine
session-, supervisor-, or machine-owned intrinsics. The kernel resolver
validates and maps each application through ABI 1.1; resident ownership survives
individual execution slices and is revoked, zeroized, and reclaimed only at its
terminal fate.

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

Interfaces used across an IPC boundary MUST be message-shaped:

- explicit handles instead of internal pointers;
- owned or borrowed byte buffers with defined lifetimes;
- bounded request and response sizes;
- explicit error values;
- no exposure of private implementation layout;
- documented cancellation and partial-operation semantics.

ADR 0034 unifies ownership, generation, accounting, close, cancellation, wait,
and teardown mechanics across handles without erasing object type. Only genuine
byte streams share stream operations. Files, directories, datagrams, listeners,
timers, and system-control interfaces retain distinct bounded protocols. The
native ABI MUST NOT acquire an open-ended descriptor, `ioctl`, `fcntl`, socket
option, or generic socket escape hatch.

An in-process implementation MAY use direct function calls. Its semantics MUST
NOT depend on shared internal pointers that prevent dispatch or IPC.

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
on streams where useful so pipelines, tests, and composition do not depend
on a physical console.

## 11. Shell

### 11.1 Grammar

The release 0.1 shell grammar is intentionally small:

```text
line        := whitespace? command-list whitespace? background?
command-list := pipeline (whitespace? logical whitespace? pipeline)*
logical     := "&&" | "||"
pipeline    := stage (whitespace? "|" whitespace? stage)*
stage       := word (whitespace (word | redirection))*
background  := "&"
redirection := "<" word | ">" word | ">>" word
word        := one-or-more bare or quoted byte segments
```

Single and double quotes group bytes and may appear within a word. Quotes do not
perform interpolation. The parser MUST:

- use bounded input;
- reject malformed quoting;
- place a configured upper bound on arguments;
- avoid recursive parsing;
- never panic on arbitrary byte input.

There are no shell expansions, variables, or command substitution. Pipelines
contain at most 255 sequential stages and each intermediate stream is capped
at 1 MiB; overflow fails explicitly. Unquoted `&&` and `||` have equal
precedence, associate left to right, and short-circuit on success and
non-success respectively. A final unquoted `&` is accepted only for one
external-command stage. Background standard input is EOF and output/error enter
a bounded 64 KiB recent log, so asynchronous bytes do not corrupt the
interactive prompt. Concurrent background pipelines are not part of this
grammar.

### 11.2 Command registry

Ordinary commands MUST be installed as immutable target-selected KEX artifacts.
Each package declares its name, synopsis, required typed capabilities, and entry
point. Unknown or unavailable commands return stable distinct errors and do not
terminate the shell.

A bare ordinary command MUST resolve only through the bounded immutable
`/bin/<name>.kex` catalog. A command token containing `/` MUST instead resolve
the exact relative or absolute VFS path against the invocation cwd, without
extension inference or a directory search. The target MUST be a regular file
whose complete package, capability manifest, target, and embedded executable
validate before admission. Explicit path selection MUST NOT manufacture
capabilities: nested launch requirements remain an attenuation of the
launcher's authority. Writable mounts are therefore usable only through an
explicit path such as `./app`, never through implicit current-directory lookup.
Under the current policy, a direct interactive path outside `/bin` MUST require
an explicit `y` confirmation and default to denial. The warning is advisory:
already-running applications with process-launch authority use their typed
launch capability without a kernel terminal prompt.

An installed package MAY embed one bounded canonical CMPL descriptor for its
command arguments. The shell MUST validate package and command identity before
using it and MUST retain authority over replacement offsets, quoting, sorting,
deduplication, candidate budgets, and trusted dynamic resolvers. Pressing Tab
MUST NOT execute the ordinary application or grant its runtime capabilities.
Completion metadata is not authority and MUST NOT be interpreted as KCAP.

Externally stored KEX files MUST be admitted through bounded offset reads and
MUST NOT require a package-sized kernel-heap copy. Complete envelope, manifest,
target, segment, payload, relocation, and source-coherence validation MUST
finish before the provisional address space becomes active. File-backed bytes
MAY stream directly into zeroed inactive frames, but any changed source, short
or invalid read, relocation mismatch, materialization failure, or resource
failure MUST roll back the provisional launch. Direct, background, service, and
owner-scoped nested launch MUST preserve the same validation, W^X, randomized
placement, capability attenuation, accounting, teardown, and reclamation.

Optional large runtime executables MUST be installed only below
`/vol/shared/runtime/v1/<architecture>/bin`. A canonical version manifest MUST
bind the exact path set, byte lengths, and SHA-256 digests and reject symbolic
links, unmanifested entries, unsupported schemas, and changed artifacts.
Runtime artifacts MUST NOT be copied into rootfs, KEFS, or EFI, and unavailable
shared media MUST fail explicitly without an embedded fallback.

The reusable C target MUST be LP64 and freestanding on both supported
architectures. Its headers and static library MUST define their own audited
types, layouts, constants, errno contract, setjmp state, UTF-8/wide behavior,
allocator ABI, bounded descriptors, buffered file/directory streams,
argv/environment, exit processing, clocks, UTC/C locale, secure randomness,
and coherent single-execution-thread locks and TSS without inheriting host
libc. Every filesystem and process service MUST remain scoped to typed KEX
capabilities; missing authority and unsupported operations MUST fail
explicitly. Thread creation, signals, fork/exec, executable private mappings,
networking, dynamic linking, additional locales, and timezone databases are not
part of this C target.

`cd`, `fg`, `jobs`, `kill`, `log`, `poweroff`, `reboot`, `svc`, and `wait` are
permanent shell intrinsics and their names MUST NOT be shadowed or replaced by a
KEX application. They mutate shell-session, resident-job, service-supervisor,
or machine lifecycle state and therefore execute in the invoking shell. The two
terminal actions remain behind the shell's explicit machine-control capability;
ordinary KEX applications cannot acquire that authority or invoke an intrinsic
through application ABI 1.1. No ordinary command has a privileged fallback.

### 11.3 Resident jobs and services

Ordinary KEX execution has no default total runtime deadline and no cumulative
service-call ceiling. The architecture execution lease still bounds one
uninterrupted user-mode slice; local handle, message, wait, memory, output, and
resident-table bounds remain mandatory.

A foreground KEX owns the invoking session's streams and result, but it MUST
use the same bounded execution loop as resident work. Background jobs and
already-launched services continue to receive execution slices and wait
completion while the shell waits for the foreground result. Logical hour- or
day-scale waits MUST NOT depend on fitting the entire deadline into one
architecture timer counter.

A session background job is owned by the launching shell and addressed by its
stable job number. `jobs`, `log`, `kill`, `wait`, and `fg` MUST NOT search by
executable name or expose another session's jobs. Cancellation is explicit
contained teardown, not a POSIX signal ABI.

SCFG services stay in the foreground under one bounded direct supervisor. They
do not fork, detach, use PID files, or become shell jobs. The supervisor retains
exact task ownership, desired and observed state, dependency and restart policy,
and bounded recent logs. The `svc` intrinsic controls stable SCFG names.
Transactional process admission is the current service-readiness signal; KEX
has no explicit lifecycle-ready ABI.

### 11.4 Required commands

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

The current command filesystem service begins relative resolution at the
launching shell's working directory and uses that live namespace. It does not
implement package-resolved scoped roots; that authority change is tracked in
[GitHub issue #6](https://github.com/dennissoftman/troe/issues/6).

### 12.2 Initial namespace

```text
/
├── config/      writable desired configuration on a persistent provider
├── man/         embedded read-only command manual pages
├── recovery/    embedded read-only recovery-only bootstrap files
├── tmp/         writable RAMFS
├── sys/
│   └── config/  read-only configuration resolved for the active generation
└── dev/         capability-backed device nodes, if enabled
```

The recovery image contributes `/recovery`; it does not contribute `/etc` and
the system defines no `/etc` compatibility alias. `/config` is the stable
desired-state mount point and is never replaced merely because a package
generation changes. `/sys/config` contains only the normalized, non-secret
configuration files bound to the active generation. A candidate projection is
validated and constructed out of view, then replaces the complete active view
atomically. Applications cannot mutate it.

Boot creates both namespace roots even when persistent storage or an active
package generation is unavailable. In recovery that leaves `/config` without a
writable provider and `/sys/config` empty at generation zero. Native deployment
activation MUST attach the persistent desired-state provider before accepting
configuration edits and MUST publish the selected immutable projection before
starting package services.

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

### 12.6 Identity and foreign filesystem metadata

Persistent and external filesystem support MUST NOT assume that a raw numeric
UID/GID, a Windows SID, or a familiar account name is proof of a local system
identity. Stable opaque native principals and explicit mount/import mappings
retain foreign UID/GID identity without treating it as active authority.
Authentication, identity mapping, ownership, and capability authority are
separate concerns.

Filesystem drivers SHOULD preserve security metadata in its native form when
the source format can be round-tripped. In particular, ext4/XFS-style numeric
UIDs, GIDs, mode bits, and supported ACL metadata should remain representable,
while NTFS owner/group SIDs and complete supported security descriptors should
not be irreversibly reduced to Unix mode bits. Unmapped identities remain
distinguishable and inspectable; they MUST NOT silently collapse to a local
user, group, administrator, or all-powerful fallback identity. Translation
that is approximate or lossy must be reported explicitly.

[ADR 0007](docs/adr/0007-identity-and-foreign-filesystem-mapping.md) accepts the
native-principal, foreign-identity, mapping, mount-policy, ACL, and fail-closed
direction. [Identity security v1](docs/formats/identity-v1.md) fixes the current
IREG/IMAP/IMNT/IACL/ISEC serialization and generation binding. A broader
multi-principal authorization engine, stable security-metadata VFS surface, and
additional foreign writers require their own decisions; implemented metadata
formats do not silently grant those capabilities.

### 12.7 Persistent filesystem modules and partitions

Persistent disk formats are replaceable filesystem providers behind the VFS
and a bounded block-region capability. The kernel machine backends do not own
filesystem or partition-format logic. The current build statically composes
only the selected KEFS, RAMFS, FAT32, constrained ext4 v1, and StateFS
providers.

KEFS is the immutable recovery filesystem, the fixed FAT16 image is only the
firmware-read boot container, constrained ext4 v1 is the default persistent
content volume, FAT32 provides bounded interoperability, and StateFS owns its
single bounded state object. No raw foreign UID, GID, SID, ACL, or security
descriptor gains native authority merely because a provider can parse it.

Providers receive a whole-device or partition-bounded region and do not
discover partitions themselves. Installed media uses bounded read-only GPT
discovery and host-created layouts. General MBR traversal, in-kernel partition
editing, resizing, LVM, software RAID, and automatic repair are unsupported.

The accepted provider and lean-partition scope is recorded in
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

Demand paging, swapping, and overcommit are absent. Each admitted KEX command
uses a separate, eagerly populated address-space root with independently
randomized image and stack placements plus private startup, heap,
guarded-stack, and page-table frames. KEX v1 defines no shared-memory mapping.

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

The kernel is single-core. The resident scheduler may preempt an unprivileged
application at the 50 ms lease boundary; only one isolated continuation executes
at a time. Interrupt handlers MUST do bounded work and MUST NOT allocate unless
the allocator explicitly supports that context.

Synchronization primitives MUST NOT be introduced merely for hypothetical SMP. Interior mutability and globals still require documented ownership because interrupt context can create concurrency even on one CPU.

SMP is unsupported. Introducing it would require a separately accepted memory
model, lock ordering, per-CPU state, interrupt routing, and allocator review.

## 18. Observability

`mem` and `/sys/memory` expose:

- total normalized usable RAM;
- permanently reserved RAM;
- free and total managed frames;
- heap live, capacity, and high-water bytes;
- allocation-failure count;
- RAMFS live, limit, and high-water bytes;
- cache live and limit bytes (both zero in the current configuration);
- current memory-pressure state;

The native process-observation interface additionally exposes the bounded live
registry through stable-ID pagination of at most 16 records per reply. Records
carry process identity, launch origin, lifecycle, charged unprivileged CPU
ticks, retained page-table/private-page counts, live handle count, and bounded
executable name. The interface MUST NOT expose argv, process memory, register
contents, or control authority. Page-table memory is accounted per process;
system-wide allocated-frame totals and reclamation counters are not separately
exposed in the current observability contract.

Debug builds SHOULD expose a boot log and invariant checks. Release builds MAY compile out verbose logging, but fatal diagnostics and resource counters SHOULD remain.

## 19. Size and resource budgets

### 19.1 Image limits

- **Current boot container:** fixed 8 MiB FAT16 image.
- **Hard experimental ceiling:** 16 MiB for a release image, including boot container and embedded filesystem.

Crossing 16 MiB fails the release build unless this specification is
deliberately revised with a recorded rationale. Container growth below that
ceiling MUST remain visible in verification output.

Debug symbols and host-side test artifacts are excluded. A stripped deployable image is measured.

### 19.2 Feature accounting

Every optional feature SHOULD report its approximate image-size and steady-state memory delta. Size regressions MUST be attributed to code, read-only data, embedded files, alignment, or boot-container overhead.

Code clarity MUST NOT be sacrificed for tiny savings that do not affect the
measured 8 MiB container or 16 MiB hard ceiling.

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
zeroized teardown protect the kernel from that execution context. The nine
intrinsics remain small kernel/session/supervisor transitions and expose no general
application-callable machine authority.

Accordingly:

- executable code is loaded only after complete KEX package, embedded KCAP,
  and inner KEX validation;
- embedded FS input is treated as potentially malformed;
- console input is untrusted and bounded;
- KEFS, FAT32, constrained ext4, StateFS, GPT, volume policy, configuration,
  generation, and activation inputs are parsed through exact bounded profiles;
- Ethernet, ARP, DHCP, IPv4, ICMP, UDP, and outbound TCP input is untrusted and
  admitted only through the implemented bounded network profiles;
- no command may access raw memory or devices unless explicitly given that capability;
- release documentation MUST state whether hardware isolation exists.

Application isolation includes resumable timer preemption, but does not make the
system multi-user secure. Every application artifact and application-controlled
address remains untrusted.

## 23. Current delivery boundary

TROE currently boots native x86-64 and AArch64 UEFI images under the four exact
QEMU contracts in the support matrix. It owns memory and page tables after UEFI
handoff, enforces W^X and isolated KEX address spaces, and contains application
faults with generation-checked capability teardown.

The current runtime includes resident foreground commands, session background
jobs, supervised services, timer preemption, stable process observation,
owner-scoped nested KEX launch, and bounded byte pipes. Static KEX v1 packages
receive only typed declared services. Externally stored packages use coherent
bounded streaming into inactive frames, and optional large runtime packages use
the verified `/vol/shared/runtime/v1` tree. The shared freestanding C SDK and
static library provide the bounded capability-scoped single-execution-thread
runtime surface described in section 11.2. Dynamic linking and shared objects
are not implemented; their design gate is tracked in
[issue #10](https://github.com/dennissoftman/troe/issues/10).

The implemented data plane includes the documented bounded VFS providers,
persistent generations and configuration projection, virtio block/network,
Ethernet/ARP/DHCP/IPv4/ICMP/UDP, and typed outbound TCP. Hosted tools implement
the current package-model, trust, publication, and transactional-lifecycle
formats without claiming that host tooling is a native package manager.

TROE is not a production release and no non-QEMU environment is accepted. The
live production exit criteria and remaining work are maintained only in the
[Stage 9 milestone](https://github.com/dennissoftman/troe/milestone/1) and
[tracking issue #14](https://github.com/dennissoftman/troe/issues/14), with
concrete lifecycle and deployment work in issues #3, #5, and #21.

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

## 26. Current release boundary

TROE remains an experimental QEMU-targeted system rather than a production
release. Every accepted revision MUST keep both architecture images below the
16 MiB ceiling, pass the complete host and four-platform QEMU gate, fail cleanly
under malformed and exhausted inputs, and keep every authored unsafe boundary
inventoried and justified. A production claim additionally requires the live
Stage 9 milestone to close on an exact non-QEMU environment.

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

---

The project succeeds if a reader can trace the path from a byte arriving at the console, through parsing, namespace lookup, memory allocation, and architecture-specific output—and understand why every boundary exists. Small image size matters; small conceptual size matters more.

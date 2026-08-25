# Implementation roadmap

## Landed in the initial slice

- Stage 0 host runner and Stage 1 UEFI applications share portable code.
- Both EFI targets compile on stable Rust and fit well below component budgets.
- Root data is generated deterministically and validated again when mounted.
- RAMFS mutation, deletion accounting, parser failures, partial reads, grep
  boundary behavior, pipelines, and command status have host tests.
- Build, test, image, size, and QEMU entry points are repository scripts.
- Prompt-synchronized QEMU acceptance drives both production images through all
  built-ins, failure cases, RAMFS quota exhaustion and recovery, memory
  reporting, and authorized poweroff/reboot with bounded timeouts.

## Stage 2: owned machine (complete)

### 1. Owned memory and console substrate — complete

Normalize the UEFI memory map, reserve the image/stack/KEFS/map, introduce a
bounded monotonic boot allocator, implement a project-owned frame bitmap, and add
polling 16550/PL011 backends. Keep firmware services active until native fatal
diagnostics and allocator accounting are verified.

Landed: the portable normalization, monotonic boot allocator, and compact frame
bitmap are host tested. Both images reserve an explicit LoaderData arena and
run polling 16550/PL011 backends before firmware services are released.

Exit: allocator model tests cover discontiguous ranges, exhaustion, double
free, invalid free, and checked overflow; native UART output matches firmware
output in QEMU.

### 2. Exit boot services as one reviewed transition — complete

Select and audit the general heap, copy the final memory map into owned memory,
drop every firmware protocol reference, switch console and fatal paths, exit
boot services, and publish full memory counters through `mem`.

Exit: repeated pipeline/RAMFS workloads run without firmware services or leaks,
and allocation failure reaches a bounded diagnostic path.

Landed: `rlsf` TLSF was selected and measured, the final map is retained and
normalized, every console/fatal path is native, boot services are exited, and
`mem` exposes owned frame and heap counters. Dual-QEMU acceptance proves no net
heap growth across repeated transient workloads and exercises the bounded
allocation-failure probe.

MMU-owned page tables and W^X follow this transition; they should not be mixed
into the first memory-ownership patch.

## Stage 3: MMU-owned mappings and W^X (verified)

Build architecture-specific page tables from pure, host-tested range plans;
classify normal and device memory; protect immutable and executable regions;
and add deliberate permission-fault acceptance cases on both architectures.

Exit: mapping invariants hold in model tests and representative write and
execute violations reach stable native fault diagnostics in QEMU.

Landed: a bounded architecture-neutral mapping plan rejects virtual overlap,
unsafe physical aliases, overflow, W+X, executable devices, and unequal ranges
in host tests. The kernel builds a minimal identity plan for owned runtime RAM,
PE-classified image sections, and the PL011 device page; x86-64 and AArch64
translate it into fresh 4 KiB page
tables from a reserved 2 MiB arena. Kernel text is RX, immutable image data is
RO/NX, runtime memory is RW/NX, and device memory is RW/NX with device
attributes. A one-way owned-stack handoff precedes firmware-memory reclamation.
Native fixed-selector x86-64 GDT/TSS/IDT and masked AArch64 VBAR state provide
terminal coverage for unexpected exceptions. Destructive write, execute, and
native-exception probes exist only in separate acceptance images; production
images are scanned to exclude their command strings. Host tests, both target
Clippy gates, production/acceptance builds, and the pinned dependency audit pass.
The exhaustive normal-boot, write-fault, execute-fault, native-exception,
fatal-state, poweroff, and reboot matrix passes on both targets with QEMU 11.1.0.

## Stage 4: cooperative tasks (complete)

Introduce bounded task records, explicit owned stacks with guard pages,
cooperative yield, task lifecycle accounting, and capability-scoped dispatch
without adding preemption or per-task address spaces.

Exit: multiple tasks yield and terminate deterministically, stack guards reach
native fault diagnostics, and task-owned resources are reclaimed without
changing the single-address-space authority model.

Landed: `troe-task` provides a 16-record hard ceiling, monotonic task IDs,
round-robin ready/running/exited transitions, typed capability sets, explicit
yield/exit accounting, and reaping that returns the exact guarded-stack slot.
The kernel reserves three 64 KiB task payloads, each between two unmapped 4 KiB
guards. Architecture-local trampolines run one explicit continuation step on a
task stack and restore the scheduler stack on yield or exit. Boot acceptance
executes two interleaved services, checks five deterministic yields, reaps both,
reuses a returned slot, then dispatches the console/filesystem/machine-control
shell task only with its declared capabilities. Feature-only acceptance images
write a task guard and reach the same terminal native fault state on both
architectures; production images exclude that dispatch string.

The continuation model deliberately stores durable state in an explicitly
owned continuation object, accounts for it through the bounded task record, and
discards native frames at each yield. It does not add preemption, saved
arbitrary call stacks, per-task address spaces, or a hardware isolation claim.
See [ADR 0010](adr/0010-cooperative-tasks-and-guarded-stacks.md).

## Stage 5: in-process message dispatch (complete)

Introduce handles, ports, bounded messages, request/reply semantics, and a
service adapter that can replace a selected direct call without changing its
conceptual API.

Exit: a filesystem or console service can switch between direct and dispatched
implementations in tests.

Landed: `troe-dispatch` provides generation-checked opaque port and handle
identities, per-handle call rights, hard ceilings of 16 ports, 32 handles, and
4 KiB per request or reply, monotonic request IDs, owned bounded replies, typed
service statuses, explicit close/invalidation, and live call/reply accounting.
Requests borrow immutable bytes only for one synchronous call; no queued state,
blocking, cancellation race, shared-memory contract, or wire ABI is implied.

`ConsoleService` and `DispatchedOutput` preserve the existing byte-oriented
`Output` interface. Host tests send the same payload through direct and
dispatched console implementations and compare exact bytes, including a payload
that requires multiple bounded calls. The native shell registers one console
port and emits prompts and normal stdout through its one explicitly granted call
handle. Native fatal output and input delivery stay at the machine boundary so a
dispatcher failure cannot recurse through itself. Both QEMU targets require the
dispatch-ready boot marker. See
[ADR 0011](adr/0011-bounded-in-process-message-dispatch.md).

## Stage 5.1: native text console and shell usability — complete

The portable `troe-terminal` crate now provides configurable input decoding,
cursor-aware line editing, bounded volatile history, set-1 keyboard decoding,
and fixed-glyph framebuffer rendering. `troe-shell` provides bounded
command/VFS completion from one authoritative command registry. The kernel
copies and validates UEFI GOP metadata before handoff and mirrors normal output
to an owned RW/NX device mapping while retaining UART for early, fatal,
headless, and acceptance paths.

Exit: both architectures can display and edit a shell line through the owned
text-console abstraction; every retained-entry and byte budget comes from a
validated selected profile; unknown serial escape sequences cannot corrupt the
line; and the existing deterministic UART acceptance matrix remains available.
The x86-64 q35 profile also accepts a native PS/2 keyboard. AArch64 native
keyboard input is a later virtio-input increment; serial input and owned ramfb
output are covered now.
See [ADR 0012](adr/0012-native-text-console-and-editor-policy.md).

## Stage 5.2: interrupt-driven input and driver resources — complete

The portable `troe-driver` crate now provides checked MMIO, I/O-port, and
interrupt resources plus a preallocated raw-input FIFO. Its capacity,
per-interrupt drain budget, overflow accounting, and programmable priority are
selected by validated configuration. The machine layer owns q35 LAPIC/I/O APIC
and AArch64 `virt` GICv2, routes PS/2, 16550, and PL011 receive interrupts, and
replaces the shell's busy poll loop with race-free `hlt`/`wfi` idle. Bootstrap
and fatal recovery retain direct polling, and the cooperative scheduler remains
non-preemptive.

Exit: both QEMU architectures receive serial shell input only through owned
interrupt delivery after initialization; x86 native keyboard input uses IRQ1;
all ISR loops and retained events obey selected profile bounds; overflow and
interrupt counters are observable; idle wakeups cannot be lost; and fault,
terminal, and recovery-console acceptance remains green. QEMU acceptance checks
positive delivery/idle counters and zero drops under ordinary input. See
[ADR 0013](adr/0013-interrupt-driven-input-and-driver-resources.md).

## Stage 6: optional isolation (complete)

Landed: fresh per-task roots execute at x86-64 ring 3 and AArch64 EL0t with
kernel mappings supervisor-only, explicit RX/RW user mappings, unmapped stack
guards, and global W^X across safe aliases. The internal exit gate validates a
complete user range before copying at most 4 KiB into kernel-owned memory.
Handles carry monotonic task ownership and are generation-revoked before exact
record reaping, page zeroization, and atomic frame-range return.

Exit: a deliberately faulting isolated task cannot corrupt the kernel or an
unrelated service; its memory, handles, and task resources are reclaimed, and
authority transfer remains explicit. Stage 6 does not imply loadable
applications, a stable userspace ABI, or preemption; those require separate
decisions and later milestones. Every boot on both architectures contains
translation, write, execute, illegal-instruction, disabled alternate-entry,
invalid-opcode, invalid-pointer, oversize-message, and invalid-status faults;
AArch64 also rejects a nonzero `SVC` encoding. The matrix proves no partial
copy or net frame loss, reuses the returned physical range, then enters the
ordinary shell. See
[ADR 0014](adr/0014-unprivileged-task-isolation-and-teardown.md).

## Stage 7: loadable applications (complete)

Stage 6 supplies the privilege, copied-message, fault-fate, and transactional
teardown boundary required by a loader.
[ADR 0015](adr/0015-kex-application-abi-and-execution-bounds.md) selects the
small static KEX v1 container, application ABI 1.0, per-profile staging and
resident-memory ceilings, and a 50 ms maximum uninterrupted user lease
terminated by an owned timer. Those choices are intentionally independent of
the internal Stage 6 probe format.

The first two implementation slices established the loader.
`troe-application` provides the
allocation-free KEX v1 parser, fixed profile limits, bounded load plans, exact
and conservative page charges, canonical virtual placement, and ABI 1.0 startup
page encoding. The native composition copies each artifact into bounded
kernel-owned staging before parsing, allocates exact private pages plus the
profile's table reservation, initializes fresh frames, builds an inactive root
from the portable plan, grants one explicit owner-scoped handle, and then proves
revocation, zeroization, exact reclamation, and malformed-input rejection on
both targets. No external artifact byte is executed in this slice.

The third slice makes the boundary runnable. Both architectures reset documented
application-visible integer, floating-point/SIMD, and control state; pass the
immutable startup pair; enable interrupt delivery; implement ABI call 0 exit;
and arm a 50 ms one-shot before external KEX instructions execute. x86 uses an
owned local-APIC timer calibrated from typed PIT channel-2 resources; AArch64
uses the generic physical timer through owned GICv2 PPI 30. Native boot runs a
target-specific exit application and terminates a spinning application by lease
expiry, then proves stale-handle rejection, exact frame return, and allocation
reuse on both targets.

The fourth slice completes ABI 1.0. Architecture gates capture bounded full user
contexts at `yield` and `handle_call`; the scheduler explicitly reselects a
yielded task; every resume receives a fresh lease. Handle calls validate complete
non-overlapping request/reply ranges, copy the opcode-prefixed request, prove the
opaque handle still belongs to the task, synchronously dispatch it, and copy out
only a successful bounded reply. Native acceptance checks register preservation,
reply bytes, unknown-call fate, attempted-return fate, exact teardown, and frame
reuse on both targets.

Exit: a valid target-specific static application can start, call a documented
minimal ABI, exit or fault without harming the kernel or another service, and
leave no memory or handle ownership behind. Malformed artifacts fail before
execution with no partial mappings. Dynamic linking, POSIX compatibility,
preemption, persistence, and a public package registry are not part of the
Stage 7 implementation.

### Stage 9 command-application integration (complete vertical slice)

The first product-facing integration is implemented. The shell resolves exact
immutable `/bin/<command>.kex` artifacts from a target-selected root, stages
them through bounded offset reads, and grants versioned
command/stdin/stdout/stderr handles.
`echo`, `clear`, and `pwd` are externally replaceable with static recovery
fallbacks, while the unknown `kex-echo` name proves general discovery on every
QEMU composition.
The repo-local Rust SDK, linker script, canonical dual-target build/inspect
tool, canonical least-authority KCAP sidecars, example source, and concise
authoring skill are checked in.

KEX command discovery excludes the permanently intrinsic `cd`, `poweroff`, and
`reboot` names. `cd` remains a shell-session state transition; the platform
transitions remain machine-control-capability operations unavailable to
application ABI 1.0.

Absent artifacts alone select recovery built-ins; present corrupt or faulting
artifacts fail closed. Public package manifests, target locks, signatures, and
content-store application publication remain on the packaging track.

The bounded UDP substrate is now exposed through the optional owner-scoped
application datagram service. `udp.kex` proves send, receive backpressure,
waiting/cancellation, and teardown to zero live ports on every QEMU composition.
The optional read-only filesystem service now supplies generation-checked open
tokens, bounded offset reads and metadata, and lexical pagination. `cat`,
`grep`, `hexdump`, `ls`, and `man` exercise it on every QEMU composition.
Atomic complete-file mutation is now implemented and exercised by `write.kex`
and `rm.kex`. Next sequence: migrate the remaining replaceable utilities through
separate timer, diagnostics, and typed network capabilities. TCP follows only
after those lower-level contracts and their adversarial portable tests are fixed.
DNS, TLS, jobs, and general sockets are not implied by these ABIs.

The shell keeps bounded command-name and path completion, including candidate
listing for an empty or partial command and command-name completion after
`man`. Rich Bash/Zsh-style option, argument, provider, and application-aware
completion is a later usability increment; it must use explicit schemas and
retain deterministic candidate-count and byte ceilings.

## Stage 7.5: cloud platform separation (Phases A and B verified)

QEMU remains the fast, deterministic acceptance backend; it must not define the
meaning of either supported CPU architecture or the complete cloud VM contract.
This stage separates three axes that the current machine crate partly
conflates:

- architecture: x86-64 or AArch64 CPU, MMU, exception, and context mechanisms;
- platform: interrupt controller, timers, firmware tables, buses, UARTs, boot
  media, and shutdown/reboot mechanisms; and
- execution environment: emulator or named cloud/hypervisor VM.

Physical boards, embedded/no-MMU targets, and a hardware lab are not part of
the current product plan. The next portability target is a documented matrix of
virtio-capable cloud VM platforms, with bounded ACPI, device-tree, or UEFI
discovery where fixed QEMU resources are insufficient.

Phases A and B complete items 1–6 for the two named discoverable QEMU
contracts:

1. introduce an explicit validated platform descriptor and split CPU mechanisms
   from q35, QEMU `virt`, and other VM-platform resources;
2. move MMIO bases, interrupt IDs/routes, timers, UART choice, framebuffer
   metadata, and power control out of architecture-wide assumptions and obtain
   them from a validated profile, ACPI, device tree, or UEFI handoff;
3. retain `x86_64-q35-uefi` and `aarch64-virt-uefi` as pinned QEMU test profiles
   and keep their complete deterministic acceptance matrix green;
4. add bounded ACPI, device-tree, and UEFI discovery needed by named cloud VM
   platforms, rejecting missing, ambiguous, overlapping, or unsupported
   resources before volatile I/O or interrupt enable;
5. define a multi-hypervisor/cloud acceptance matrix with exact firmware,
   machine type, virtio transports, required features, and image contract; and
6. run bounded boot, storage, networking, and lifecycle smoke tests for every
   supported matrix entry while retaining exhaustive host/QEMU fault gates.

Drivers remain capability-producing components selected by a platform
descriptor; VM support must not leak fixed addresses or ambient device
discovery into portable crates. Reusable UART, interrupt, block, network, PCI,
and virtio drivers remain independently selectable.

Exit: the production kernel reaches the recovery shell and passes bounded boot,
storage, networking, lifecycle, persistence, and fault tests on both accepted
discoverable QEMU matrix entries. Pinned split-media QEMU profiles remain
regression environments; KVM and real provider rows remain unaccepted until
their exact contracts pass independently. See
[ADR 0016](adr/0016-hardware-targets-and-emulator-role.md).

## Stage 8: networking and persistent operation (verified)

The first portable storage/configuration boundary is landed:

- `troe-block` provides owned or borrowed synchronous device capabilities,
  checked subregions, exact request buffers, read/write authority, transfer and
  alignment ceilings, explicit flush/FUA properties, and a one-request queue
  bound enforced by exclusive borrowing;
- `troe-gpt` performs bounded read-only GPT discovery with a canonical
  protective MBR, independently checksummed primary and backup headers/arrays,
  copy consistency, duplicate-ID and overlap rejection, strict entry bounds,
  and validated UTF-16 names;
- ADR 0007 now accepts native-principal, foreign-identity, mapping,
  mount-policy, ACL, and fail-closed recovery rules before persistent writes;
- `troe-vfs` exposes a bounded read-only provider contract and namespace mount
  routing; `troe-fat` implements the first strict read-only FAT32 provider with
  mirrored FAT, BPB/backup/FSInfo, cycle, short-name, and LFN validation; and
- ADR 0017 fixes the first ext4 feature bitmap; `troe-ext4` implements its
  clean read-only, 4 KiB-block, inline-extent profile with UUID selection,
  CRC32C-protected superblock/group/inode/directory traversal, sparse-file
  reads, and hard group/inode/directory/file/read/name ceilings. Real-tool
  interoperability fixtures are accepted by e2fsprogs/dosfstools checkers
  before the ext4/FAT32 providers mount, list, and read them; and
- `troe-config` implements checksummed SCFG v1 desired-system/service startup
  policy with canonical dependencies, bounded health/restart behavior, explicit
  predecessor fallback, and a mandatory static recovery shell; and
- `troe-mount` implements the checksummed BMNT v1 boot-side mount manifest,
  bounded canonical role names, explicit whole-device/GPT selectors, access and
  availability policy, duplicate-selector rejection, and deterministic exact
  stable-identity resolution for diskless, matched, missing, and ambiguous
  media; and
- `troe-virtio` implements the bounded modern single-request block profile, and
  the AArch64 `virt` machine profile now discovers `virtio-mmio` block devices,
  establishes an eight-entry split queue with explicit DMA ordering and
  reset-before-return timeout safety, and completes a native post-handoff read
  in QEMU acceptance; and
- `troe-storage` shares native devices across exclusive synchronous region
  capabilities, validates exact BMNT-selected GPT/ext4 identities, and prepares
  only read-only providers. Both QEMU fixtures mount the matched volume at
  `/vol/root` and read it through the live shell; and
- the q35 front end discovers modern virtio PCI capabilities, validates and
  maps their sized BAR regions, and drives the shared synchronous queue without
  exposing PCI details above `troe-machine`; and
- `troe-persist` implements the first writable durability primitive: a
  four-block dual-slot record with data/flush/commit/flush ordering, exact
  generation/checksum recovery, and host fault injection at every boundary;
  PRGN v1 selects a strict four-block GPT partition by exact disk, unique
  partition, and partition-type GUIDs; dedicated per-architecture QEMU media
  exercise real native virtio writes and flushes across five process
  termination/reopen cycles; SACT v1 now binds the TXSLOT payload to an exact
  canonical SCFG generation, length, checksum, and SHA-256 content address and
  revalidates that immutable configuration after every reopen; and
- `troe-content` implements the bounded CSPK v1 immutable object pack with
  canonical SHA-256 addressing, strict whole-pack and per-object verification,
  binary lookup, deduplication, and budgeted mark-and-copy retention. Both
  native acceptance paths borrow the BMNT-selected ext4 provider to read
  `/system.cspk`, resolve its digest-bound SCFG, and only then publish or
  recover its SACT pointer. The kernel embeds only the 128-byte bootstrap SACT
  record, not the CSPK or SCFG bytes; and
- GMAN v1 supplies checksummed immutable generation roots. Bounded traversal
  rejects cycles, non-descending predecessors, missing objects, and kind
  confusion before producing mark-and-copy roots. Native acceptance publishes
  generation 2, applies its configured health failure, durably rolls back to
  generation 1, and verifies the exact recovered SACT payload after every
  subsequent process termination.
- STFS v1 supplies the first writable filesystem provider: one bounded
  `/state.bin` on its own exact PRGN-selected GPT region, with whole-filesystem
  TXSLOT publication and explicit flushes. It mounts at `/vol/state`; both QEMU
  profiles mutate it across five process terminations while the harness
  independently checks transaction generation, STFS checksum, and file bytes.
- `troe-net` supplies safe bounded Ethernet/ARP/IPv4/ICMP/UDP and DHCP
  construction and parsing, checksum and fragment rejection, plus a
  count-and-byte-bounded receive FIFO. Truncation and 10,000-frame flood tests
  are host verified. Native fixed-buffer modern virtio-net queues run through
  q35 PCI and AArch64 MMIO. Normal QEMU compositions now acquire an IPv4 lease,
  run one ambient eight-frame checkpoint service that answers ARP and ICMP at
  the idle prompt. Eight ARP records and eight persistent UDP ports are fixed
  ceilings; every port drops newest beyond four datagrams or 4 KiB. Replaceable
  `arp`, `net stats`, `udp send --source-port`, and cancellable `udp listen`
  surfaces sit on the same service. A monotonic millisecond clock, cooperative
  `sleep`, and Ctrl-C checkpoints prepare later applications and jobs without
  adding them. The independent acceptance peer exchange remains the transport
  regression gate.
- `troe-identity` implements canonical checksummed IREG registry, IMAP foreign
  mapping, IMNT mount-policy, and IACL native ACL formats under the accepted
  Standard ceilings. It rejects every truncated/corrupted fixture,
  duplicate compatibility and foreign keys, invalid SID/POSIX encodings,
  missing or kind-incompatible principals, and iterative membership cycles.
  ISEC v1 binds the four typed CSPK objects to GMAN; activation validates the
  complete active and predecessor snapshots, and generation GC retains them as
  transitive roots.

These mechanisms are host verified; both VM block and network transports,
read-only mount activation, the bounded TXSLOT transaction, digest-bound ext4
CSPK/SACT/ISEC recovery, selected state-filesystem mutation, and host UDP
exchange are QEMU verified. Five independent acceptance processes per
architecture revalidate the rolled-back generation-1 security snapshot and
persist incremented state after deliberate terminal faults.

ADR 0018 fixes the bootstrap semantics for the next storage increments. KEFS
provides the immutable `/`, `/vol/root` is the selected persistent ext4 role,
`/vol/boot` is the normally read-only EFI system partition, and additional
configured media mounts below `/vol/<name>`. Host or installer tooling creates
the filesystems and a bounded boot-side mount manifest. Native discovery must
match its stable disk, partition, and filesystem identities exactly; no disk,
several disks, duplicate identities, and missing/corrupt root media all retain
the KEFS recovery shell without guessing from enumeration order or labels.

Exit audit: the system boots both primary targets, configures one supported
modern virtio NIC, exchanges UDP data with an independent host peer, persists
activation and selected filesystem state across process termination/reopen, and
holds declared memory ceilings under exhaustive truncation/checksum cases and a
10,000-frame flood. Stage 8 is complete. Stage 9 deployment, update trust,
diagnostics, migration, and broader filesystem/provider work must preserve the
independently testable transport, region, provider, VFS, configuration, content,
identity, and command boundaries established here.

## Deferred tooling and packaging track

The tooling/package architecture is documented now so early formats and
interfaces do not foreclose it, but it is not part of the next three
increments. Until loadable applications and persistence exist, Cargo,
repository scripts, KEFS, and FAT images remain explicit bootstrap mechanisms,
not public package or generation formats.

Hosted manifest, lock, and artifact validation may be prototyped before native
application loading. Native execution begins with core Stage 7; a persistent
store, system generations, and rollback begin with Stage 8; supported updates,
registry trust, and deployment belong to Stage 9. See
[../TOOLING-PACKAGING-SPEC.md](../TOOLING-PACKAGING-SPEC.md#511-alignment-with-the-core-roadmap).

The Stage 8 storage direction is already bounded by
[ADR 0009](adr/0009-persistent-filesystems-and-partitions.md): keep KEFS as the
built-in recovery root and FAT12 as the current firmware container; introduce
whole-device regions and read-only GPT discovery; provide read/write
FAT12/16/32, exFAT, constrained ext4, and later NTFS as separately selected
filesystem modules. Ext4 is the default native persistent data provider;
FAT/exFAT serve removable-media interchange. Partition creation remains
host-side, and writable filesystem providers should move behind isolated
service boundaries when the task/application model can support that transition.
Separately licensed modules remain outside the default Apache-2.0 image and
require explicit packaging and distribution review.

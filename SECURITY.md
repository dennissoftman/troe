# Security policy

## Current boundary

The hosted model has the security properties of its host process and models
only parsing, short-circuit logical lists, sequential pipelines, redirection,
completion, session state, and the grammar and authority checks for the nine
shell intrinsics. It does not
execute KEX applications or model native isolation. The native image exits UEFI
boot services. Every ordinary command is a validated KEX application with a
fresh ring-3/EL0 root, explicit typed handles, bounded memory, contained fault
fate, and zeroized teardown; no privileged utility fallback exists. The shell
retains only `cd`, `fg`, `jobs`, `kill`, `log`, `poweroff`, `reboot`, `svc`, and
`wait`. Hosted tooling verifies the current signed package/trust formats, but
the native image has no secure-boot integration, accepted production
publication path, or multi-user boundary. DNS, TLS, and general sockets are not implemented.

The portable crates and kernel forbid unsafe Rust. Project-authored unsafe
operations are confined to `troe-machine` and are verified through native
boundary contract tests, both target builds, and exhaustive QEMU acceptance
rather than a raw token-count gate. Transitive unsafe code is limited to the
pinned UEFI and TLSF boundaries. Console input, KEX packages, configuration and
generation objects, network packets, and every supported filesystem or disk
format are treated as untrusted and bounded.

Package-owned CMPL metadata is separately bounded and validated before the
shell selects a trusted resolver. It grants no application capability, and Tab
never executes the ordinary application.

## Invariants enforced now

- command input: 512 bytes, 128 arguments per stage, 255 stages per pipeline;
- launch environment: 128 entries and 2,048 aggregate UTF-8 bytes, one value
  per name with duplicates rejected at both encoding boundaries, composed by the
  launcher and never synthesized by the application, and exposed by no process
  observation or diagnostic surface;
- foreground terminal input: one loan at a time, held only by a foreground
  command whose standard input is the session terminal, never inherited by a
  background job, service, staged script line, or owner-scoped child; a 512-byte
  pending line and four unread lines, with excess refused rather than buffered;
- shell scripts: 1,024 submitted lines, 64 KiB source, four nesting levels, and
  one shared 1,024-pipeline execution budget across nested scripts;
- sequential intermediate pipeline: 1 MiB and atomic overflow failure;
- paths: 256 bytes, 64-byte names, 16 components, no NUL or root escape;
- RAMFS: explicit total-byte, file-byte, and node limits;
- KEFS: magic, version, exact total length, sorted unique normalized paths,
  checked arithmetic, valid kinds, and exact record consumption;
- FAT builder: fixed geometry, duplicated FATs, finite acyclic chain, and exact
  executable round-trip verification;
- release boot images: fixed 8 MiB FAT16 container and 16 MiB hard ceiling;
- owned heap: 6 MiB fixed arena with use, high-water, and failure accounting;
- physical frames: checked 4 KiB bitmap with invalid/double-free detection;
- native UART transmit waits: finite polling bound on both architectures;
- active kernel stack: explicit LoaderData reservation, RW/NX mapping, and
  post-handoff stack-pointer assertion before frame allocation;
- mappings: no virtual or physical overlap, no writable executable mapping, and
  CPU-reported physical-address limits checked before activation;
- exception state: interrupts masked during ownership transition, all x86
  exception gates present, and double fault uses a dedicated IST stack;
- x86 segment context: saved FS/GS/DS/ES selectors and independent FS base;
  Rust trap handlers and application completion use zero FS/GS selectors/bases
  and fixed kernel DS/ES selectors. Resume restores the retained selectors
  before FS base. The owned flat GDT, disabled LDT and disabled FSGSBASE keep
  GS base zero; TLS never supplies kernel identity;
- portable process dispatch: one non-cloneable turn selects a process before
  its siblings. Process and sibling cursors survive wake and thread churn;
  fixed process-slot indices permit one scan of the thread table. An immutable
  checked raw-counter deadline, floored whole-millisecond observations and at
  most 256 charged work batches bound a turn. Regressing clocks invalidate that
  turn; stale completion cannot release a later dispatch. These policy mechanisms
  do not program native timers or enable production thread scheduling;
- native process dispatch: a Running sibling and its exact retained process turn
  are checked and charged before entry. The timer boundary validates the boot
  frequency and monotonic observations after controller preparation. Arm retains
  the absolute counter deadline; x86 floors its remainder for the calibrated
  LAPIC one-shot and checks expiry again before entry. Expiry preserves the saved
  continuation and permits no user entry; clock/invariant failure stops the root.
  This is not a hard real-time guarantee or production resident scheduling;
- native ordinary call ownership: shared-root calls require the caller's retained
  TX/RX prefixes. Each context reserves and charges a 4 KiB immutable request
  buffer before execution; capture completes before another sibling can run.
  Checked operation, caller and IPC generations identify once-only claims.
  Completion validates the original binding, service status and capacity before
  clearing/publishing RX, and grants no execution time. Stale, foreign, duplicate
  and malformed completions do not write. Request buffers are erased on completion
  and context destruction. Production service and C runtime concurrency remain
  separate from this mechanism;
- native context owner: one retained root with bounded process-scoped register
  records, checked stack guards and disjoint stack/TLS payloads, actual retained
  metadata accounting, and process-wide continuation revocation on native fault
  or exit. Register records are erased before their backing is released;
  retained per-thread IPC owners outlive every root mapping that references
  them. Bindings validate process/thread identity, live task-pair ownership,
  physical pages and RW/NX geometry before publication; replies clear the entire
  RX page before copying a bounded prefix. Sibling threads share these user
  mappings; the bindings select kernel destinations, not isolation between siblings.
  The native owner captures fixed scheduler requests before switching siblings;
  completion validates the retained caller, nonwrapping operation identity and
  live IPC generation, rejects stale/corrupt responses before writing, and clears
  RX before publishing. A captured canonical call can be claimed once into an
  owned, non-cloneable execution; claimed calls reject direct completion and
  repeat claims. Completion failure returns the owned execution for safe recovery
  or retirement after process stop. Capability and operation authority remain
  composition obligations; native acceptance uses the owned operation dispatcher
  for captured Current/Join calls and synchronization requests under separate closed
  handles. Pending synchronization claims cannot complete after a sibling's
  native fault. Ordinary application admission does not enable scheduler calls;
- native prepared mapping admission: the current lifecycle table must match the
  exact Prepared identity, initial/worker role and mapped-page charge. The native
  owner reserves and charges IPC-owner capacity before publication. It checks the
  complete virtual window, guards and alignment gaps, physical extents, existing
  user aliases, root-table exclusion and conservative unused table capacity
  before changing mappings. Stack, private descriptor and IPC are cleared; the
  descriptor is encoded from trusted fields and published read-only/NX. The first
  mapped initial thread binds one uniquely mapped shared-header page to the root;
  worker descriptors cannot substitute another header after initial exit. Compiler
  TLS initialization and ordinary physical ownership remain composition duties.
  A rejected preflight returns the IPC owner. Failure after mutation begins stops
  the whole process and retains root and IPC until teardown. No allocation,
  callback, logical Start or resource refund occurs in mapping admission;
- native creation publication: Prepare retains its copied request and exact
  reserved target through initialization. Native completion matches the caller's
  claimed operation, complete admitted context, live IPC and immutable descriptor,
  including image-relative entry, scalar argument and stack size. Start additionally
  requires the current creator's Prepared child before publishing Ready with release
  ordering. Scheduled first entry checks Running policy state and acquires that
  initialization; unresolved native or policy work cannot be resumed by this path.
  Start and Abort reject another creator's preparation. Failed preparation retains
  its target through revocation, native/physical reclamation, acknowledgement and
  reaping before a failure reply. Partial mapping requires process teardown;
  these mechanisms do not establish production allocation or scheduling policy;
- native thread retirement: a claimed Exit can remove one inactive context's
  stack, TLS, optional private read-only startup and IPC mappings. Read-only
  preflight checks kernel-owned physical extents, permissions, sibling references,
  all user aliases and bounded metadata capacity before any page-table write.
  Partial mutation failure stops the whole process and retains backing until
  root teardown. Success erases the register record in place and releases only
  the unmapped IPC pair; ordinary physical owners must still zero/reclaim frames
  before logical resource acknowledgement or a join result becomes available.
  Untagged single-CPU execution flushes translations at native boundaries.
  Discarding a never-executed preparation additionally rechecks its live Revoked
  lifecycle record and unreleased resources; a Ready thread cannot be discarded
  merely because it has not executed. Both retirement paths share preflight and
  terminal mutation-failure handling. An initial thread's private descriptor is
  retired with that thread; the shared process header's reference is bootstrap
  data, not a process-lifetime guarantee for the descriptor. Shared startup and
  page-table backing retain process lifetime;
- tasks and process records: at most 65,536, with monotonic identities, explicit
  capabilities, deterministic lifecycle accounting, fallible metadata growth,
  and guarded native stack payloads. Portable thread and synchronization lookup
  resolves slot/generation against the trusted process and exact object kind,
  collapsing foreign/absent/mismatched lifetimes to stale. A retained identity
  grants no capability and does not bypass operation-specific state checks;
- owned thread operations: the portable dispatcher binds authenticated capability
  ownership to a captured caller and trusted process snapshot, validates running
  state and rejects new work with an unconsumed synchronization or control wait.
  Owned wait records carry no user pointer, callback or table borrow. Absolute deadlines do
  not restart on resumption; condition timeout/stop retains mutex reacquisition.
  Permit batches check complete capacity before any grant or timeout publication.
  Join waits consume only quiescent results; timeout/stop cancels an uncommitted
  claim without consuming its target. A committed scalar result remains owned
  through target reaping and cannot be replaced by a later timeout or stop.
  Ordinary wake and orderly exit cannot bypass the completion interlock.
  Exit returns an owned terminal action after mutex owner-death policy; it has
  no success reply and cannot acknowledge memory. Native retirement precedes
  scalar completion, physical reclamation precedes Join readiness, and essential
  owner death requires process stop. Prepared children retain charges until
  their backing is reclaimed. Abort wins Prepared-to-Revoked before returning an
  owned action; its target remains retained until physical reclamation and resource
  acknowledgement. Only then can a running caller finish the action, reap that
  exact target and publish its checked reply. Stopping or target reuse rejects
  late completion without affecting another incarnation.
  Internal clock/configuration failures require process stop without replay.
  Native execution claims and retained operation storage remain separately owned
  and charged by composition; ordinary package grants remain disabled;
- dispatch: at most 65,536 ports and 262,144 handles, generation-checked
  identities, explicit call rights, and 4 KiB request/reply limits. Built-in
  scheduler targets share the handle bound and generation/owner revocation,
  but have a closed interface/version type distinct from service ports.
  Admission checks the trusted process principal, live handle, canonical copied
  request and complete operation rights without callbacks or retained borrows.
  Service handles cannot acquire scheduler authority from payload interface IDs;
  scheduler handles cannot invoke service callbacks. This authorization mechanism
  does not publish startup grants or execute native scheduler operations;
- KEX: exact target/version/layout validation before allocation, closed R/RX/RW
  permissions, fixed standard ceilings, a 24 KiB format-verifier buffer ceiling
  with fallible heap-backed completion scratch,
  coherent full-source and relocation fingerprints, inactive-frame streaming,
  canonical startup pages, explicit initial handles, and transactional zeroized
  reclamation without a package-sized kernel-heap copy;
- ABI 1.3 IPC: 16 private task TX/RX pairs and four kernel-only pairs in the
  owned boot arena, owner-only user mappings, supervisor aliases in every root,
  complete zeroization before publication/reuse and after terminal revocation;
  retained PCID/ASID generations reject stale roots, and mapping changes use
  targeted invalidation with a full-flush correctness fallback on unsupported
  x86 CPUs. Direct handoffs preserve the absolute 50 ms lease; expiry faults
  the active IPC participant and does not replay the call;
- thread preflight: allocation-free typed wire/startup codecs and checked memory
  plans, including a separately charged read-only descriptor page. Whole-process
  preflight rejects overlap with image holes, heap growth reservations and thread
  guards; peak budgets include separate immutable-initializer and executable
  staging backing. Preflight does not acquire or authenticate that backing. The active
  loader and SDK reject the assigned threaded startup revision and reject thread
  interfaces in older startup records. Offline TLS conversion requires an explicit
  container revision, validates the immutable initializer against its image source,
  and rejects initializer pointer fixups. Native and streaming loaders reject this
  container; these components enable no native workers;
- TLS initializer ownership: exclusively owned staging supplies an independent
  immutable process initializer. Fallible preparation reserves logical backing,
  checks actual capacity and process peak budgets, and drops buffers before
  refunding charges. Stopping creation retains storage; synchronous Rust borrows
  prevent release during a copy. Native context quiescence, physical accounting
  and zeroization are not established by this heap-buffer owner;
- compiler qualification: explicit C11 target/TLS options and isolated headers,
  exact release checks and observed-input fingerprints; missing, skipped or
  failed qualification cannot publish a success report. These reports grant
  no native authority and do not certify production runtime hardening;
- KEX resolution: bare names select only `/bin/<name>.kex`; a command containing
  `/` tries its exact VFS path relative to its explicit cwd, then appends `.kex`
  only if the path is missing and the filename does not already end in `.kex`;
  existing nodes and other errors never trigger a retry, and there is no `PATH`
  or implicit writable-directory search; every selected file passes the same
  complete KEX/KCAP validation and capability attenuation, and
  direct interactive execution outside `/bin` requires a default-negative
  confirmation;
- runtime media: optional large executables exist only in the exact
  `/vol/shared/bin/<architecture>` tree; the canonical manifest
  binds every path, length, and SHA-256 digest, and missing, extra, linked,
  malformed, oversized, or changed artifacts fail before launch;
- C facade: bounded process-local descriptor, `FILE`, directory, environment,
  atexit, and TSS tables delegate only to manifest-granted typed services;
  absent authority is `EACCES`, unsupported flags and operations fail
  explicitly, and the allocator retains exact live/private-map accounting;
- application execution: reset ring-3/EL0 state, bounded saved contexts,
  scheduler-selected resume, copied owner-checked request/reply calls, and a
  50 ms maximum uninterrupted user lease; ordinary resident commands have no
  default total-runtime or cumulative-service-call ceiling, while every handle,
  message, pending call, wait, mapping, heap, and stream retains its local hard
  bound;
- residency and supervision: at most 65,533 retained application records under
  the system task ceiling, at most one executing unprivileged root on the single
  CPU, 64 KiB recent output per background job or service, owner-scoped
  cancellation and reaping, and SCFG-bounded dependency, restart, health,
  lifetime, and stop policy;
- process launch: at most 65,536 retained children and 65,536 pipes per owner,
  256 MiB aggregate pipe capacity per owner, at most eight nested application
  levels below the session or a service because each level occupies one kernel
  stack frame, explicit attenuation, recursive descendant teardown, and
  generation-checked lifecycle and pipe tokens;
- process observation: the system registry spans up to 65,536 foreground,
  background, nested, and service launches and is exposed in stable-ID pages of
  at most 16 records; monotonic non-reused process IDs, scheduler-paired states,
  exact retained pages, and CPU ticks are charged only around ring-3/EL0
  execution; the explicit read-only capability hides argv and grants no memory
  access or process control;
- outbound TCP: one connection per declared handle, sixteen system-wide across
  accepted connections, half-open passive opens, and tuples still retained
  after close, one 1,460-byte unacknowledged segment and 4 KiB receive FIFO per
  connection, exact-tuple/sequence admission, four retransmissions, four-second
  cancellable operations, a four-second tuple retention on the active closer,
  and owner-teardown removal of live streams; no DNS, TLS, or raw packets;
- inbound TCP: independent `tcp-listen` authority, one local port per handle,
  two listeners system-wide, backlog 1 through 4, and eight accepted streams
  per handle within the shared sixteen-connection ceiling. Connection IDs are
  handle-local and never reused. Owner teardown removes the listener and live
  accepted streams; gracefully closed tuples remain until expiry. See the
  [listener contract](docs/formats/tcp-listen-v1.md).
- dependencies: complete `Cargo.lock` checked by pinned `cargo-audit` against the
  exact RustSec database revision in `tools/rustsec-advisory-db.rev`.

RustSec exceptions are not implicit. Any future ignored advisory must be reviewed
in the same change, identify the affected crate and advisory, explain why it is
not currently exploitable, name an owner, and include an expiry date. Expired
exceptions fail the release review and must be removed or renewed explicitly.

Persistent diagnostics uses an initialized, incarnation-bound KEX service. Its
256-page boot reservation and three-start/60-second policy bound residency and
restart. Revocation cancels inbound/outbound calls and waits before native roots,
tags and frames are reclaimed; IPC and copied queue storage are zeroed before
reuse. Old client handles never address a replacement. Server reply statuses
remain 0–23; only the kernel synthesizes closed, peer-died and deadlock outcomes.
Kernel clients retain copied data and scalar continuation identities, with no
borrowed client frame or pointer serving as a suspended continuation. Direct
handoffs preserve the original absolute 50 ms lease; slow waits preserve the
original absolute service deadline.

## Reporting

Until a private reporting address exists, do not publish a suspected
vulnerability with exploit details while it remains unfixed. Contact the
repository owner privately. Reports should include affected revision,
architecture, reproduction steps, impact, and whether malformed console or
image input is involved.

That restriction covers unfixed issues only. Once the fix is published, the
change carrying it should state the mechanism, the reproduction, and the bound
or invariant it restores, so a reader can judge whether the fix is complete. A
fix and its full explanation may land in the same public change.

No release is claimed to have zero vulnerabilities. A release may claim only
that it has no known unresolved vulnerability at its publication time.

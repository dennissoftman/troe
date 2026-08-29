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
publication path, or multi-user boundary. DNS, TLS, inbound TCP listening, and
general sockets are not implemented.

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
- tasks and process records: at most 65,536, with monotonic identities, explicit
  capabilities, deterministic lifecycle accounting, fallible metadata growth,
  and guarded native stack payloads;
- dispatch: at most 65,536 ports and 262,144 handles, generation-checked
  identities, explicit call rights, and 4 KiB request/reply limits;
- KEX: exact target/version/layout validation before allocation, closed R/RX/RW
  permissions, fixed standard ceilings, a 24 KiB format-verifier buffer ceiling
  with fallible heap-backed completion scratch,
  coherent full-source and relocation fingerprints, inactive-frame streaming,
  canonical startup pages, explicit initial handles, and transactional zeroized
  reclamation without a package-sized kernel-heap copy;
- KEX resolution: bare names select only `/bin/<name>.kex`; a command containing
  `/` selects one exact VFS path relative to its explicit cwd, with no suffix
  inference, `PATH`, or implicit writable-directory search; every selected file
  passes the same complete KEX/KCAP validation and capability attenuation, and
  direct interactive execution outside `/bin` requires a default-negative
  confirmation;
- runtime media: optional large executables exist only in the exact
  `/vol/shared/runtime/v1/<architecture>/bin` tree; the canonical manifest
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
- outbound TCP: one connection per declared handle, four system-wide, one
  1,460-byte unacknowledged segment and 4 KiB receive FIFO per connection,
  exact-tuple/sequence admission, four retransmissions, four-second cancellable
  operations, and owner-teardown removal; no DNS, TLS, listen, or raw packets;
- dependencies: complete `Cargo.lock` checked by pinned `cargo-audit` against the
  exact RustSec database revision in `tools/rustsec-advisory-db.rev`.

RustSec exceptions are not implicit. Any future ignored advisory must be reviewed
in the same change, identify the affected crate and advisory, explain why it is
not currently exploitable, name an owner, and include an expiry date. Expired
exceptions fail the release review and must be removed or renewed explicitly.

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

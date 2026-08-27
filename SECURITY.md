# Security policy

## Current boundary

The hosted model has the security properties of its host process and models
only parsing, sequential pipelines, redirection, completion, session state, and
the grammar and authority checks for the nine shell intrinsics. It does not
execute KEX applications or model native isolation. The native image exits UEFI
boot services. Every ordinary command is a validated KEX application with a
fresh ring-3/EL0 root, explicit typed handles, bounded memory, contained fault
fate, and zeroized teardown; no privileged utility fallback exists. The shell
retains only `cd`, `fg`, `jobs`, `kill`, `log`, `poweroff`, `reboot`, `svc`, and
`wait`. There is no secure-boot integration or multi-user boundary in this
milestone; package signing, DNS, TLS, inbound TCP listening, and general sockets
remain future decisions.

The portable crates and kernel forbid unsafe Rust. Project-authored unsafe
operations are confined to `troe-machine` and are verified through native
boundary contract tests, both target builds, and exhaustive QEMU acceptance
rather than a raw token-count gate. Transitive unsafe code is limited to the
pinned UEFI and TLSF boundaries. Console input, KEX packages, configuration and
generation objects, network packets, and every supported filesystem or disk
format are treated as untrusted and bounded.

## Invariants enforced now

- command input: 512 bytes, 32 words per stage, 8 stages;
- intermediate pipeline: 64 KiB and atomic overflow failure;
- paths: 256 bytes, 64-byte names, 16 components, no NUL or root escape;
- RAMFS: explicit total-byte, file-byte, and node limits;
- KEFS: magic, version, exact total length, sorted unique normalized paths,
  checked arithmetic, valid kinds, and exact record consumption;
- FAT builder: fixed geometry, duplicated FATs, finite acyclic chain, and exact
  executable round-trip verification;
- release boot images: 16 MiB hard ceiling (currently exactly 1.44 MiB).
- owned heap: 6 MiB fixed arena with use, high-water, and failure accounting;
- physical frames: checked 4 KiB bitmap with invalid/double-free detection;
- native UART transmit waits: finite polling bound on both architectures.
- active kernel stack: explicit LoaderData reservation, RW/NX mapping, and
  post-handoff stack-pointer assertion before frame allocation;
- mappings: no virtual or physical overlap, no writable executable mapping, and
  CPU-reported physical-address limits checked before activation;
- exception state: interrupts masked during ownership transition, all x86
  exception gates present, and double fault uses a dedicated IST stack;
- tasks: at most 16 records, with monotonic identities, explicit capabilities,
  deterministic lifecycle accounting, and guarded native stack payloads;
- dispatch: at most 16 ports and 32 handles, generation-checked identities,
  explicit call rights, and 4 KiB request/reply limits;
- KEX: exact target/version/layout validation before allocation, closed R/RX/RW
  permissions, fixed standard ceilings, kernel-owned staging, canonical startup
  pages, explicit initial handles, and transactional zeroized reclamation;
- application execution: reset ring-3/EL0 state, bounded saved contexts,
  scheduler-selected resume, copied owner-checked request/reply calls, and a
  50 ms maximum uninterrupted user lease; ordinary resident commands have no
  default total-runtime or cumulative-service-call ceiling, while every handle,
  message, pending call, wait, mapping, heap, and stream retains its local hard
  bound;
- residency and supervision: at most eight retained application records, at
  most one executing unprivileged root on the single CPU, 64 KiB recent output
  per background job or service, owner-scoped cancellation and reaping, and
  SCFG-bounded dependency, restart, health, lifetime, and stop policy;
- process observation: one 16-record registry spans foreground, background,
  and service launches with monotonic non-reused process IDs, scheduler-paired
  states, exact retained pages, and CPU ticks charged only around ring-3/EL0
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
vulnerability with exploit details. Contact the repository owner privately.
Reports should include affected revision, architecture, reproduction steps,
impact, and whether malformed console or image input is involved.

No release is claimed to have zero vulnerabilities. A release may claim only
that it has no known unresolved vulnerability at its publication time.

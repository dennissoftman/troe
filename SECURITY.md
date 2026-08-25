# Security policy

## Current boundary

The hosted model has the security properties of its host process. The native
image exits UEFI boot services. Recovery commands remain privileged, while
validated KEX applications receive fresh ring-3/EL0 roots, explicit handles,
bounded memory, contained fault fate, and zeroized teardown. The current native
acceptance artifacts exercise ABI exit and lease expiry; no shell/package path
loads arbitrary external applications yet. There is no secure-boot integration,
persistent storage parser, network stack, multi-user boundary, or mutually
isolated privileged built-ins in this milestone.

The portable crates forbid unsafe Rust. Project-authored unsafe operations are
confined to `troe-machine`, counted by the verification gate, and documented in
the unsafe inventory. Transitive unsafe code is limited to the pinned UEFI and
TLSF boundaries. Console input and both filesystem image formats are treated as
untrusted and bounded.

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
  scheduler-selected resume, copied owner-checked request/reply calls, and an
  architecture-owned 50 ms one-shot that terminates non-returning code;
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

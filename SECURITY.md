# Security policy

## Current boundary

The hosted model has the security properties of its host process. The native
image exits UEFI boot services but remains single-address-space: all commands
execute with kernel privilege. There is no userspace isolation, secure boot
integration, persistent storage parser, network stack, or untrusted executable
loading in this milestone.

The portable crates forbid unsafe Rust. Project-authored unsafe operations are
confined to `kllm-machine`, counted by the verification gate, and documented in
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

## Reporting

Until a private reporting address exists, do not publish a suspected
vulnerability with exploit details. Contact the repository owner privately.
Reports should include affected revision, architecture, reproduction steps,
impact, and whether malformed console or image input is involved.

No release is claimed to have zero vulnerabilities. A release may claim only
that it has no known unresolved vulnerability at its publication time.

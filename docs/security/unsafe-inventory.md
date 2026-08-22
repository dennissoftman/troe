# Unsafe inventory

As of the initial Stage 0/1 slice, all project-authored Rust crates and binaries
use `#![forbid(unsafe_code)]`; the authored unsafe-block count is zero.

Unsafe implementation exists transitively in `uefi` and its raw bindings. That
dependency is isolated by Cargo target configuration to `target_os = "uefi"`
and is used for entry ABI, firmware tables/protocols, console access, boot
service waiting, and pool allocation. It is recorded in `THIRD_PARTY.md`.

Future native entry, MMIO, exception, page-table, and allocator unsafe code must
be placed in machine/mechanism crates, include local `SAFETY:` invariants, and
update this inventory in the same change.

# ADR 0001: toolchain, license, and dependencies

Status: accepted, 2026-08-22.

Use Rust 1.97.1 stable, edition 2024, and Python 3.13 or newer for repository
tools. License the project under Apache-2.0. Portable crates have no external
runtime dependencies. Use `uefi` 0.39.0 only at the firmware boundary and pin
the graph in `Cargo.lock`.

Nightly was rejected because the first two milestones need no unstable feature.
Raw hand-written UEFI bindings were rejected because they enlarge the unsafe
surface without differentiating the project. A large host build framework was
rejected because standard Cargo and small deterministic tools cover the current
needs.

Revisit the MSRV only on a planned release. Review each `uefi` update as a
machine-boundary change, including feature and license diffs.

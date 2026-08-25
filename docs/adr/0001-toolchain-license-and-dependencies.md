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

Release verification uses exactly `cargo-audit 0.22.1` with the RustSec database
commit recorded in `tools/rustsec-advisory-db.rev`. The audit runs without a
database fetch after checking out that revision, fails on vulnerability and
informational warning categories, and requires reviewed, owned, expiring
repository documentation for any future exception.

Implementation amendment, 2026-08-24: `scripts/test.py` and
`scripts/audit.py` reject Python versions older than 3.13 before running any
gate. Direct registry dependencies are checked by the repository policy tests:
only exact `uefi` 0.39.0 at the firmware boundary and exact `rlsf` 0.2.3 in the
owned machine allocator are permitted. `tools/rustsec-exceptions.json` is the
closed exception record: each future entry must have a unique advisory ID,
non-empty owner and rationale, and a strictly future ISO-8601 expiry date before
the audit can pass the matching `--ignore` option.

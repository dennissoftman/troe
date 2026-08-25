# Contributing

Keep changes small enough that a reviewer can trace their authority, memory
charge, failure behavior, and machine dependency.

During development, run `python3 scripts/test_changed.py --explain`; it selects
changed packages and reverse dependencies, owned Python suites, affected KEX
apps, and granular QEMU scenarios. Unknown or global changes widen to the full
gate. Before submitting a change, run `python3 scripts/test.py`, which includes
all QEMU platforms and scenario groups, or require the repository's exhaustive
merge check. Use `--skip-qemu` only when the pinned emulator and firmware are
unavailable, and ensure the full gate runs before merge. See
[`docs/testing.md`](docs/testing.md) for impact rules and LLM instructions. New
parsers require corrupt and boundary tests. New caches require
an owner, hard cap, eviction policy, pressure behavior, and accounting. New
unsafe code requires a `SAFETY:` comment, an audit note under `docs/security`,
and a narrowly scoped crate boundary.

Storage-provider changes should also run
`python3 scripts/test.py --skip-qemu --require-filesystem-tools` with
e2fsprogs, dosfstools, and mtools installed. This makes absence of the external
format/check oracles a failure instead of silently skipping interoperability.

During interactive-console development,
`python3 scripts/test-qemu.py --platform all --environment qemu --smoke`
provides a fast concurrent boot check for all named platforms. It does not
replace the exhaustive gate.

Dependencies must provide concrete value over a small local implementation,
support `no_std` where required, have a compatible license, and be recorded in
`THIRD_PARTY.md`. Commit `Cargo.lock` for reproducibility.

# Contributing

Keep changes small enough that a reviewer can trace their authority, memory
charge, failure behavior, and machine dependency.

Before submitting a change, run `python scripts/test.py`. New parsers require
corrupt and boundary tests. New caches require an owner, hard cap, eviction policy,
pressure behavior, and accounting. New unsafe code requires a `SAFETY:` comment,
an audit note under `docs/security`, and a narrowly scoped crate boundary.

Dependencies must provide concrete value over a small local implementation,
support `no_std` where required, have a compatible license, and be recorded in
`THIRD_PARTY.md`. Commit `Cargo.lock` for reproducibility.

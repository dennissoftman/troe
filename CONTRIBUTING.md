# Contributing

Keep changes small enough that a reviewer can trace their authority, memory
charge, failure behavior, and machine dependency.

## Issues

Repository documentation describes implemented behavior, accepted decisions,
formats, and historical evidence. GitHub issues own unimplemented work, design
questions, and delivery status. Search open and closed issues before filing a
new one, then choose the matching issue form:

- **Bug:** implemented behavior differs from its documented or tested contract.
- **Implementation:** a concrete, actionable outcome with acceptance and
  verification criteria.
- **Design:** a decision is still required before implementation can be
  accepted. A design issue makes no implementation claim.
- **Tracking:** an umbrella outcome whose checklist links independently useful
  child issues; it must not duplicate their detailed specifications.

Use an imperative, outcome-oriented title. Prefix only umbrella issues with
`[Tracking]` and design archives or broad design questions with `[Design]`.
Every issue must identify the current evidence or motivating use case, exact
scope, non-goals, dependencies, measurable acceptance criteria, and required
verification. Name affected platforms and authority, memory, persistence, or
compatibility boundaries rather than relying on a generic feature label.

Apply the narrowest `area:*` labels that fit. Use `stage-9` and the Stage 9
milestone only when the issue is required by the exit criteria in
[the Stage 9 tracking issue](https://github.com/dennissoftman/troe/issues/14).
Use `design` while behavior is unresolved and `tracking` only for umbrella
issues. Explicitly unsupported behavior is not automatically backlog: a new
feature issue needs a named consumer, deployment, measurement, or failure that
justifies the work.

Closing an issue does not by itself make a capability current. The implementing
change must update source, tests, formats, and current-behavior documentation
together, link the issue, and show that every acceptance criterion is satisfied.
Report security vulnerabilities through [`SECURITY.md`](SECURITY.md), not a
public issue.

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

# Contributing

Keep changes small enough that a reviewer can trace their authority, memory
charge, failure behavior, and machine dependency.

## Issues

Repository documentation describes current implemented behavior, accepted
decisions, formats, and verification. GitHub issues own unimplemented work,
design questions, and delivery status. Git history owns obsolete behavior and
past evidence. Search open and closed issues before filing a new one, then
choose the matching issue form:

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
Before removing useful roadmap or deferred-work direction from documentation,
ensure that it is represented by a live issue or milestone; move it there first
when necessary. Do not retain superseded limits, old status snapshots, or
point-in-time measurements outside ADRs merely as an archive because Git
already preserves them.
Report security vulnerabilities through [`SECURITY.md`](SECURITY.md), not a
public issue.

During development, run `python3 scripts/test_changed.py --explain`; it selects
changed packages and reverse dependencies, owned Python suites, affected KEX
apps, and granular QEMU scenarios. Unknown or global changes widen to the full
gate. Before submitting a change, run `python3 scripts/test.py`, which includes
all QEMU platforms and scenario groups, or require the repository's exhaustive
merge check. QEMU `8.x` through `11.x` and matching distribution UEFI firmware
are accepted. Use `--skip-qemu` only when a supported emulator and firmware are
unavailable, and ensure the full gate runs before merge. Release evidence uses

```console
python3 scripts/test.py --strict-tool-versions --require-filesystem-tools --require-python-tools
```

See [`docs/testing.md`](docs/testing.md) for impact rules and LLM instructions.
New parsers require corrupt and boundary tests. New caches require
an owner, hard cap, eviction policy, pressure behavior, and accounting. New
unsafe code requires a `SAFETY:` comment at each operation, a narrowly scoped
crate boundary, and the same change updating the unsafe boundary that
[`SECURITY.md`](SECURITY.md) records.

Repository Python is formatted and linted by `ruff`, configured in
`pyproject.toml`, which is the only reason that file exists. Both runners
execute `ruff format --check` and `ruff check`; the focused selector runs them
over the Python files that changed. Install `ruff` before running either
runner, or accept that both gates skip with a notice on standard error;
`--require-python-tools` turns that skip into a failure. Disable a rule that is
wrong for this repository in `pyproject.toml` with a rationale comment rather
than adding a `noqa`. Reach for a `noqa` only in the opposite case, where the
rule is right in general and wrong on the one line: `pyproject.toml` inventories
the nineteen that survive, and `RUF100` fails the gate on a directive that has
stopped suppressing anything. The CPython guest probes under
`tests/fixtures/cpython` are formatted and linted like everything else, but the
three rules whose fixes would rewrite what the guest interpreter executes are
disabled for that tree; changes there are proved by the QEMU `cpython` group,
not by the host gates.

Storage-provider changes should also run
`python3 scripts/test.py --skip-qemu --require-filesystem-tools` with
e2fsprogs `1.47.x`, dosfstools, and mtools installed. This makes absence of the
external format/check oracles a failure instead of silently skipping
interoperability.

`cargo mount` attaches the persistent developer FAT32 interchange disk using
native macOS facilities or Linux UDisks. Linux development hosts should install
the distribution's `udisks2` package; already-root environments can use the
tool's direct loop-device fallback. Detach with `cargo mount --unmount` before
starting QEMU. A native Windows backend is not currently provided.

During interactive-console development,
`python3 scripts/test-qemu.py --platform all --environment qemu --smoke`
provides a fast concurrent boot check for all named platforms. It does not
replace the exhaustive gate.

Dependencies must provide concrete value over a small local implementation,
support `no_std` where required, have a compatible license, and be recorded in
`THIRD_PARTY.md`. Commit every `Cargo.lock` for reproducibility: the root
workspace, `apps/`, `services/`, and `tests/runtime-probe`. A new command or
service is a member of the `apps/` or `services/` workspace; it inherits
`[workspace.package]` and `[workspace.lints]` and declares no workspace root,
release profile, or lint levels of its own, so the format, lint, and test gates
reach it. See [`docs/testing.md`](docs/testing.md) for those gates.

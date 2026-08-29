# ADR 0054: Launch environment composition and duplicate names

Status: accepted and implemented, 2026-08-29. Refines the environment carriage
described in ADR 0046.

## Context

ADR 0046 gave every launch a bounded immutable `NAME=VALUE` environment and made
owner-scoped launch carry it transactionally. It did not answer two questions
that every consumer then had to answer for itself.

The first is duplicate names. The encoding validated each entry's syntax but not
the set, so an environment could carry one name twice. Lookup resolved that by
returning the first match, which is a precedence rule no format document stated
and no test pinned. A reply built outside the encoder could carry duplicates
past a decoder that never checked.

The second is who supplies values. The interactive session supplied none, and
the shared KEX runtime filled `HOME`, `PATH`, `TMPDIR`, `SHELL`, `USER`, and
`LOGNAME` from a list compiled into every application. An application therefore
answered `os.getenv("PATH")` from its own binary rather than from its launch, so
"applications receive values, never ambient host state" was not true: the
ambient state had simply moved inside the application.

## Decision

### One value per name, refused at the boundary

A name carries exactly one value. `command::encode_environment`,
`command::Environment::parse`, `process_launch::encode_spawn`, and the spawn
request decoder all reject a duplicate name.

Rejecting is chosen over specifying first-entry-wins because this codebase
already resolves ambiguity at canonical boundaries rather than by convention:
KEFS requires sorted unique paths and KCAP rejects duplicate interface records.
A positional precedence rule would have to be remembered by every consumer and
re-tested at every layer, and it would let a forged reply express an environment
whose meaning depends on entry order. Both the encoding and the decoding side
check, so an environment that reaches an application is unambiguous no matter
who produced it.

### Launchers compose, applications read

The launcher owns composition; the application owns nothing.

- The interactive session is the trusted top-level component. It supplies the
  conventional entries explicitly on every ordinary command and service launch.
- The conventional list lives in the ABI, so every composing component agrees on
  it without any of them copying it.
- The shared KEX runtime no longer answers a lookup from that list. An
  application reads the entries its launcher supplied, resolves `PWD` from the
  invocation's current directory, and gets nothing for any other name.
- A launcher narrows a child environment by replacing the inherited entry of the
  same name. `spawn --env NAME=VALUE` is that surface: it replaces an inherited
  entry, appends an unknown one, and refuses a name given twice.

`PWD` stays derived rather than stored. It is the one value that must always
describe the launch rather than the launcher, and deriving it makes a stale or
contradictory `PWD` unrepresentable.

### Lua startup follows upstream

`LUA_INIT_5_5` runs before command-line actions and falls back to `LUA_INIT`,
with upstream `@file` and inline-source behavior. `-E` sets `LUA_NOENV` before
the libraries open, so module paths keep their built-in defaults and no
initialization chunk runs. `-E` does not change `os.getenv`, which reads the
launch environment rather than Lua configuration.

## Consequences

An absent name is now absent. A launcher that supplies nothing produces an
application that sees nothing, which is what makes the composition boundary
real; the session supplies the conventional entries so ordinary commands are
unaffected.

Composition can fail, and it fails before a child exists: an over-budget
environment, an entry that is not `NAME=VALUE`, or one name given twice is
refused with no partial launch.

Module-path precedence is verified in QEMU rather than on the host. The host
test build links the real libc, so upstream `setpath` reads the host process
environment instead of the injected guest environment; only the freestanding KEX
build routes `getenv` through the launch environment.

`spawn` remains bounded by attenuation: it can only launch children whose
manifest is a subset of its own `filesystem-read`, `process-launch`, and `pipe`
authority. Its `--env` narrowing is therefore exercised end to end by nesting
`spawn` within `spawn`, where a duplicate would be refused by the encoding
boundary and the launch would fail. Widening `spawn`'s manifest to reach a
richer child would grant authority it does not use, which is not a trade this
contract makes for test convenience.

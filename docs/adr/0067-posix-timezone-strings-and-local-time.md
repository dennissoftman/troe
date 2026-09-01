# ADR 0067: POSIX timezone strings and local time without a database

Status: accepted, 2026-09-01. Amends the "no timezone source" premise of
ADR 0039 and the FAT32 reasoning in ADR 0058, and narrows the remaining scope of
[issue #34](https://github.com/dennissoftman/troe/issues/34) to dataset work.

## Context

TROE has held Unix wall time since ADR 0039 and has stamped provider timestamps
with it since ADR 0058, but nothing in the system can express a civil time other
than UTC. Four places say so independently: `localtime_r` in the C runtime
returns `gmtime_r`, both calendar formatters emit the literal `UTC` for `%Z` and
implement no `%z`, CPython is configured with an empty `--with-tzpath=`, and the
FAT32 provider writes its UTC reading unconverted because it has no offset to
apply.

Issue #34 asks for capability-scoped locale, encoding, and timezone datasets as
one Stage 11 deliverable. That framing put local time behind a versioned
immutable dataset, a package-root grant, and a skew and rollback contract, and
so behind persistent-storage work that has not settled. It also conflated two
independent things. The IANA database answers *what were the rules in 1974*. A
POSIX TZ string answers *what are the rules now*, in a few dozen bytes, with no
file, no capability, and no version to pin.

The second question is the one an operator actually asks of a machine whose
clock is set by SNTP at boot, and it is separable. Nothing about it needs
writable persistence: the value is a launch input, not stored state.

## Decision

### The accepted grammar, and what is refused

`TZ` carries the POSIX `std offset [dst [offset] [,start[/time],end[/time]]]`
form and nothing else. Abbreviations are three to sixteen bytes, either from the
portable character set or in the quoted `<+04>` form that modern zones require.
Offsets are `[+|-]hh[:mm[:ss]]` with `hh` in 0 through 24, positive west of
Greenwich. Transition times use the same syntax with `hh` in -167 through 167,
which is the TZif version 3 range rather than the narrower POSIX one, so that a
footer lifted from a TZif file later parses unchanged. Rules are `Mm.w.d` with
`w` of 5 meaning the last such weekday, `Jn` never counting February 29, and
bare `n` counting it. A rule pair whose start follows its end is the southern
hemisphere and is ordinary, not an error. An omitted DST offset is one hour
ahead of standard time.

Three things are refused rather than guessed:

- A leading `:` selects the implementation-defined form, which means *look up
  this name in a database*. There is no database, so the string is rejected
  instead of quietly resolving to something else.
- A `dst` abbreviation with no following rules is implementation-defined in
  POSIX and historically resolves to United States rules. Guessing them here
  would produce a wrong answer indistinguishable from a right one, which is the
  reasoning ADR 0058 used to refuse inventing a FAT offset.
- Any other malformed string is refused at the launcher, below.

### Refusal happens at the launcher, so evaluation is total

`localtime_r` returns a calendar, not a status; making it fail on a bad `TZ`
would break every caller that does not check a pointer POSIX says is non-null in
practice. Validation therefore sits where ADR 0054 already put environment
composition: the launcher. The session validates the string it composes, and
`spawn --env TZ=...` refuses an invalid value at the spawn boundary with a
diagnostic, before a child process exists. This matches how ADR 0054 resolved
duplicate names — reject at both the encoding and decoding side rather than
inventing a precedence rule every consumer must remember. The runtime's parse is
then a total function over an already-validated string, and its unreachable
invalid path resolves to `UTC0`.

`TZ=UTC0` joins `command::CONVENTIONAL_ENVIRONMENT` as its seventh entry, so
every launch carries an explicit zone and no code path reads an absent `TZ` as a
special case.

This ADR does not decide where an operator's persistent zone is stored.
`/sys/config` has a projection API in the namespace crate with no kernel caller,
and SCFG v1 carries a CRC over a fixed header and fixed service records with no
free-form settings, so a zone field there is a format revision. Neither should
be pulled into a change about formatting time. Until one of them lands,
`spawn --env TZ=...` is the surface and the default is UTC.

### One evaluator, called from both runtimes

The Lua shim already reaches the Rust runtime for calendar work through
`troe_runtime_calendar_from_seconds`, `troe_runtime_normalize_calendar`, and
`troe_runtime_format_calendar`, while the C runtime carries its own duplicate
civil-calendar arithmetic. The zone rules are not duplicated across that seam.

The parser and rule evaluator live in the Rust KEX runtime and are exported as
one pointer-free call that maps a Unix second to its offset, abbreviation, and
DST flag. `troe_posix.c` calls that export; the Lua shim calls it through the
existing calendar entry points. Applications link both objects already, so this
costs a call and no new dependency. Issue #34 requires one implementation shared
across libc, Lua, and CPython rather than language-private databases; that
requirement starts here, with the rules, rather than later with the dataset.

Retained state is one fixed-size record holding two abbreviations, two offsets,
and two rules. Parsing is linear in the string with no allocation. Evaluation is
constant time: the two candidate transition instants for the query's year, then
a comparison. There is no table, no file, no lock, and no cache to invalidate.

`setenv` and `unsetenv` return `ENOTSUP` and ADR 0054 makes the launch
environment immutable, so parsing once at first use is observably identical to
re-reading `TZ` on every `tzset()`.

### `struct tm` gains the offset and the abbreviation

`struct tm` gains `tm_gmtoff`, seconds *east* of UTC, and `tm_zone`. This
happens now rather than with the dataset work because `struct tm` is compiled
into every `.kex` in the package set, so widening it later breaks that ABI for
all of them at once. It also makes `%z` and `%Z` functions of the argument
rather than of global state, which is what per-thread zones will need when
issue #65 lands pthreads.

The globals POSIX and CPython read — `tzname[2]`, `timezone` as seconds *west*,
and `daylight` — are provided alongside, with `tzset()` idempotent. `timegm` is
added as the UTC inverse of `mktime`, which is newly necessary because `mktime`
stops meaning UTC.

### Ambiguous and nonexistent local times

Both edge cases are pinned rather than left to emerge from the arithmetic.

`mktime` with `tm_isdst` above zero selects the DST offset and with zero selects
standard time. Below zero it determines the offset from the rules. For a local
time inside a spring-forward gap it applies the offset in effect before the
transition, which yields an instant after it, and then normalizes the caller's
fields to that instant — the field rewrite POSIX normalization already
prescribes. For a local time inside a fall-back overlap it selects the first
occurrence, the pre-transition offset.

### What stays UTC

The kernel wall clock and the `clock-control` interface stay UTC. No timezone
crosses that boundary; the zone is a property of a launch, not of the machine.

The FAT32 provider keeps writing UTC unconverted. ADR 0058 justified that by
TROE having no timezone source, which this decision makes false, but the
behavior is unchanged for a better reason: the provider is in the kernel
namespace and stamps writes on behalf of any process, so there is no single
launch whose zone it could apply. ext4 stores POSIX epoch seconds by definition
and is unaffected. The generated `/sys` nodes stay UTC.

### CPython and Lua

`--with-tzpath=` stays empty and `zoneinfo` stays unavailable — that is the
dataset tier, not this one. `time.localtime`, `time.tzname`, `time.timezone`,
`time.altzone`, `time.daylight`, `datetime.astimezone`, and `os.date` in Lua all
become correct for the configured zone by way of the shared evaluator.

`ac_cv_working_tzset` stays `no`, so `time.tzset` remains absent. The probe
means *a tzset that observes a changed `TZ`*, and with `setenv` unsupported
this one cannot. Python code that mutates `os.environ["TZ"]` and calls
`time.tzset()` should raise `AttributeError` rather than silently keep the
launch zone.

## Verification and consequences

Portable tests cover the grammar at its edges: quoted and portable
abbreviations, all three rule forms, the last-weekday case, a southern
hemisphere pair that wraps the year, offsets at both ends of the accepted
range, and each refused form. Transition behavior is pinned on both sides of a
spring and an autumn boundary, at the exact transition second, and for the gap
and overlap cases through `mktime` in all three `tm_isdst` states. Negative
timestamps and leap years keep their existing coverage against the new
offsets.

Fixtures are pinned against a reference implementation for a small fixed set of
strings covering the northern hemisphere, the southern hemisphere, a
half-hour-offset zone, a quoted-abbreviation zone, and a zone with no DST.
Because the rules are the *current* ones, a fixture is a statement about the
present rule set and is dated as such; a fixture whose zone changes its rules is
expected to need updating, and that is the honest cost of this tier.

The `CalendarTime`, result, and summary structures cross the C boundary by
value, and the C runtime and the Lua test host each mirror them field for field.
A portable test pins their exact sizes and offsets rather than trusting three
declarations to stay in step, because a silent layout drift would misread every
field rather than fail.

Native acceptance observes the tier from a prompt two ways. `date`, from
[issue #115](https://github.com/dennissoftman/troe/issues/115), lands with a
`%Z` and `%z` capable rendering; its scope note that local time is not
expressible is superseded. Because it reads the live clock, its assertions are
properties of the zone rather than of an instant: the session default renders
as UTC, `-u` agrees, and an unsupported conversion is refused. Lua supplies the
instant-exact half, rendering both sides of a transition for a northern and a
southern zone under a `TZ` the launcher narrowed, and a refused zone is proven
to fail before its child runs.

`date` itself cannot be reached through `spawn --env`. A child's capabilities
must attenuate its launcher's, and `spawn` holds no `wall-clock` authority to
pass on, so the launch is refused rather than starting `date` without a clock.
The zone `date` reports is therefore whatever the session supplies, which today
is the compiled `UTC0`. This is a consequence of the capability model rather
than of this decision, but it means the one command an operator would reach for
cannot yet show a local time, and it will stay that way until either a
configured session zone lands or `spawn` is given the authority to delegate.
Acceptance pins the refusal so the boundary is stated rather than discovered.

The limitation this tier keeps is that a POSIX string applies today's rules to
every instant, so a timestamp before the zone's last rule change renders with
the wrong offset. That is not a divergent path: a TZif version 2 or later file
ends with exactly this string, which is the normative encoding for instants past
its final recorded transition. The dataset tier adds a transition table in front
of the same evaluator rather than replacing it.

This decision adds no IANA database, no `zoneinfo`, no historical transitions,
no leap-second table, no locale or collation, no per-thread zone before
issue #65, and no detection of a zone from firmware, the network, or any other
ambient source.

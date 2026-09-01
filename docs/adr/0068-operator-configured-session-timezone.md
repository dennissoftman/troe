# ADR 0068: operator-configured session timezone

Status: accepted and implemented, 2026-09-01. Completes the configuration
source ADR 0067 deliberately left open, and resolves
[issue #148](https://github.com/dennissoftman/troe/issues/148).

## Context

ADR 0067 gave TROE local time from a POSIX `TZ` string and proved it through
libc, Lua and CPython. It did not give an operator any way to choose the zone.
The session composes the conventional `TZ=UTC0` compiled into the ABI, and
nothing replaces it, so every process on the machine runs in UTC.

The obvious workaround does not exist either. Narrowing a zone for one command
means `spawn --env TZ=...`, but a child's capabilities must attenuate its
launcher's and `spawn` holds no `wall-clock`, so `spawn` cannot launch `date`
at all. The command an operator would actually reach for is precisely the one
that cannot show a local time.

ADR 0067 left the source open for a stated reason: `/sys/config` has a
projection API in the namespace crate with no kernel caller, and SCFG v1 carries
a CRC over a fixed header and fixed service records with no free-form settings,
so a zone field there is a format revision. Neither belonged in a change about
formatting time. That reason has expired now that the formatting change has
landed and the gap is the only thing left.

## Decision

### The session reads one zone file at start

The interactive session resolves its `TZ` value once, when it starts, from
`/config/timezone`, and composes that value into every launch in place of the
conventional default. The file holds one POSIX `TZ` string and nothing else:
no key, no syntax, no comments, at most `timezone::MAX_TZ_BYTES` bytes, with an
optional trailing newline.

`/config` is where this belongs. ADR 0043 reserved it for "a stable, writable
desired-state tree which survives generation replacement", on a persistent
provider, which is exactly what a machine's timezone is. Setting it is
`printf 'EST5EDT,M3.2.0,M11.1.0' > /config/timezone`, and it survives reboot
because the provider does.

Reading it at session start rather than per command is what keeps ADR 0043's
separation intact. That ADR requires that "updating `/config` alone does not
change a running service", and a zone resolved once per session honours it: an
edit takes effect at the next session, which is what desired state means. A
per-command read would make `/config` ambient authority over every running
process, which is the thing ADR 0043 exists to prevent.

### Refusal stays at the launcher

The session validates the string with `troe_abi::timezone::parse` before
composing it, which is the same total boundary ADR 0067 put in front of
`spawn --env`. A file that does not parse is refused loudly on the boot
diagnostic and the session falls back to `UTC0`; it does not silently run in
the wrong zone, and it does not refuse to boot over a configuration typo. An
absent file, an absent `/config` provider, and recovery mode are all the same
ordinary case and yield `UTC0`.

### What is rejected

Granting `spawn` the `wall-clock` capability would make `spawn --env TZ=...
date` work in three lines of manifest. It is rejected. A launcher would then
hold standing authority for no reason except to pass it on, which is the
laundering the attenuation rule exists to prevent, and it would fix only
`spawn`-launched commands while leaving the machine's own default in UTC. The
capability model is right here; the missing piece is configuration, not
authority.

Putting the zone in SCFG is also rejected for now. It would bind the value to a
generation and get rollback for free, but it costs a format revision with a CRC
and fixed records, and it would make setting a timezone a deployment operation
rather than an ordinary edit. If a later decision needs the zone under
generation control, the projection is the place for it, and `/config/timezone`
remains the desired-state input that feeds it.

## Verification and acceptance

- Portable tests cover a valid file, a file with a trailing newline, an
  over-long file, a file that does not parse, an empty file, and an absent file,
  each resolving to the stated value or to `UTC0`.
- A refused file is reported on the boot diagnostic with the reason, and the
  session still starts.
- Native acceptance sets `/config/timezone`, restarts, and observes `date`
  rendering that zone's abbreviation and offset, on both architectures. The
  assertion uses a fixed-offset zone so it states a property rather than an
  instant, as ADR 0067's acceptance does.
- Acceptance proves the value survives a reboot, which is the whole point of
  putting it on a persistent provider.
- The existing assertion that `spawn --env TZ=... date` is refused stays, since
  this decision does not change the capability model.

## Consequences

`date`, Lua, CPython and every future runtime pick the zone up without knowing
where it came from, because they read the launch environment exactly as ADR 0067
already has them do. Nothing about the evaluator, the grammar, or the C runtime
changes.

An operator sets one file and reboots. That is a coarser workflow than a live
`timedatectl`-style command, and deliberately so: a zone that can change under a
running process would make every timestamp in a log ambiguous about which zone
produced it.

This decision adds no IANA database, no `zoneinfo`, no per-process zone beyond
what a launcher already composes, and no way for an application to change its
own zone. It does not give `spawn` new authority, and it does not make
`/config` readable by anything other than the trusted top-level session.

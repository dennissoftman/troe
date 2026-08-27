# ADR 0039: Wall-clock discipline and SNTP synchronization service

Status: accepted; whole-second wall-clock and SNTP increment implemented,
2026-08-27.

## Context

TROE exposes only a boot-relative nondecreasing monotonic millisecond clock.
That is the correct source for execution leases, wait deadlines, retransmission,
health checks, and scheduling, but it cannot represent civil or Unix time. The
first supervised network service should synchronize wall time at boot and once
per day during a long uptime without introducing cron or coupling scheduler
deadlines to an adjustable clock.

No supported platform contract currently promises a battery-backed RTC. A
persisted timestamp cannot reveal how much time elapsed while the machine was
powered off, so network synchronization is required again after every boot.

## Decision

The kernel owns separate monotonic and wall-clock domains. Monotonic time is
never adjusted. Wall time is represented by a checked base pair:

```text
wall_now = unix_base + (monotonic_now - monotonic_base)
```

A read-only wall-clock interface returns whole Unix seconds. The initial anchor
comes from a valid UEFI runtime clock when present; otherwise reads report that
the clock is not configured until a correction arrives. It does not expose
locale, timezone, calendar formatting, scheduler control, or a writable clock.

A distinct privileged clock-control interface accepts one canonical whole-
second Unix sample. Only a service launcher explicitly authorized by active
SCFG policy may receive it. The kernel validates the representable Unix range
before atomically replacing the wall-clock base. Scheduling,
timeouts, leases, and service backoff continue to use monotonic time even when
wall time steps forward or backward.

The first client is `/bin/timesync.kex`, a supervised SNTPv4 client rather than
a general NTP server. It receives only invocation and standard streams,
datagram, monotonic timer, and clock-control handles.

`timesync` performs this loop:

1. use the first immutable literal endpoint, `10.0.2.2:123`;
2. become supervisor-ready when transactionally admitted, independently of
   external network availability;
3. attempt one synchronization immediately after boot;
4. validate server address/port, minimum packet length, echoed originate token,
   leap state, NTP version/mode, stratum, and nonzero receive/transmit stamps;
5. submit the era-zero whole transmit second as a checked sample;
6. after success, sleep on one deferred monotonic deadline for 24 hours; and
7. after failure, retry at bounded 1 minute, 5 minute, 30 minute, then 1 hour
   intervals until a valid sample succeeds.

The initial client accepts NTP era zero, through 2036-02-07. It does not guess
wraparound from unchecked host state. Fractional correction, round-trip offset,
era extension, configurable endpoints, and clock uncertainty metadata require
later protocol/API revisions.

The daily interval lives inside the long-running service as one blocked wait.
It is not a periodic kernel registration, callback, timer unit, cron entry, or
repeated process launch. Service cancellation removes the blocked wait and lets
the supervisor reclaim the contained process at an execution boundary; a later
lifecycle-aware stop may first let user code observe cancellation.

## Verification and consequences

Portable tests cover request encoding and malformed header, originate replay,
zero timestamp, and era-zero arithmetic. Native acceptance proves boot-service
status, shell responsiveness with a resident five-second wait, service-owned
UDP accounting, background cancellation/reaping, and exact transient frame
reclamation on both architectures. Deterministic successful SNTP exchange and
wall-clock observation acceptance remain follow-up coverage.

This decision adds no RTC guarantee, timezone database, leap-second table,
kernel NTP protocol, DNS, TLS, cron, calendar scheduler, or claim of high-grade
clock discipline. Slewing and frequency correction require later measured need;
the first interface deliberately permits a controlled wall-clock step while
keeping every correctness deadline monotonic.

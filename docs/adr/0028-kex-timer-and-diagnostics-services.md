# ADR 0028: KEX monotonic timer and diagnostics services

Status: accepted and implemented for the Stage 9 timer and diagnostics command
migration, 2026-08-25.

## Decision

Timer and diagnostics remain separate least-authority KEX interfaces. A package
requests interface 8 version 1.0 with `timer`, or interface 9 version 1.0 with
`diagnostics`; neither grant implies the other or any filesystem, network,
input, memory-mutation, device, or machine-control authority.

The timer service exposes only the current boot-relative monotonic millisecond
count and a cancellable `sleep-until` operation with an exact eight-byte
deadline. It has no wall-clock meaning, calendar state, periodic registration,
callback, background task, or interrupt control. The kernel reuses its
nondecreasing monotonic runtime and cooperative cancellation checkpoints.
`sleep.kex` obtains `now`, forms a saturating deadline, and preserves the
existing usage and Ctrl-C exit behavior.

The diagnostics service exposes one immutable typed snapshot captured before
application service setup. Its fixed 168-byte canonical record identifies the
architecture, memory-map owner, pressure state, optional complete machine and
input counters, RAMFS accounting, and cache accounting. Decoding rejects the
wrong length, unknown enums or flags, nonzero reserved/absent fields, and
inconsistent bounded counters. The service retains encoded copied bytes, not a
borrow of live accounting or a mutable kernel object.

`mem.kex` formats that record without allocation. The kernel refreshes
`/sys/memory` from the same captured machine, input, and namespace values before
launch, so `mem` and read-only filesystem consumers retain one canonical report
without granting diagnostics apps filesystem authority.

## Security and sequencing consequences

Sleeping remains a foreground synchronous call and is bounded by cancellation;
this decision introduces no jobs, timer handles, wakeup queues, or preemption.
Diagnostics cannot poll, enumerate principals, read arbitrary memory, consume
input events, or change accounting. Both interfaces use copied request/reply
messages, exact version checks, and normal owner-wide handle revocation at
application teardown.

These contracts are suitable primitives for later bounded interpreters and TCP
state machines, but do not define either. Typed route, DHCP, ARP, ICMP, and
network-stat services remain the next command-migration boundary. TCP then
requires a separate bounded connection/state/retransmission design.

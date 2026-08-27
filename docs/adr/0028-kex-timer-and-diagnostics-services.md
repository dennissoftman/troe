# ADR 0028: KEX monotonic timer and diagnostics services

Status: accepted and implemented for the Stage 9 timer and diagnostics command
migration, 2026-08-25; isolated diagnostics-server amendment, 2026-08-26.

## Decision

Timer and diagnostics remain separate least-authority KEX interfaces. A package
requests interface 8 version 1.0 with `timer`, or interface 9 version 1.0 with
`diagnostics`; neither grant implies the other or any filesystem, network,
input, memory-mutation, device, or machine-control authority.

The timer service exposes the current boot-relative monotonic millisecond
count, a cancellable `sleep-until` operation with an exact eight-byte deadline,
and the calling process's charged CPU ticks with their counter frequency. The
CPU-time read is self-only and does not grant process enumeration. The timer
has no wall-clock meaning, calendar state, periodic registration, callback,
background task, or interrupt control. The kernel reuses its
nondecreasing monotonic runtime and cooperative cancellation checkpoints. A
synchronous sleep may wait at most four seconds; a later deadline returns the
stable timeout status without entering the wait. `sleep.kex` obtains `now`,
forms a saturating deadline, and reports success, cancellation, or timeout
distinctly.

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

Amendment, 2026-08-26: the snapshot implementation moved out of the privileged
dispatcher into the first isolated KEX user server. The client call is retained
as one bounded pending operation; a separate `server-endpoint` handle delivers
one canonical copied request containing a generation-checked token and accepts
one canonical copied reply. The server receives no filesystem, device, DMA,
network, mutation, input, memory-management, or machine-control authority. A
server exit closes the peer, while a server fault or composition rejection
revokes it and completes the blocked client with terminal cancellation.
One-shot launch is the current composition policy; persistent service processes
and automatic restart remain separate decisions.

The follow-up IPC matrix preserves that fault-domain design while removing
steady transport allocation. Server calls copy into fixed kernel request and
reply buffers, and the endpoint encodes directly into caller-owned reply
storage. Native acceptance snapshots successful heap-allocation calls around
every measured receive-to-reply interval and requires a zero delta. The
composition retains at most one request and one server context. The 4 KiB
logical benchmark row uses two generation-checked fragments because the v1
server envelope shares the 4 KiB gate with its fixed header; the result reports
the extra copies, root switches, TLB invalidations, and timer programs.

## Security and sequencing consequences

Sleeping remains a foreground synchronous call and is bounded by both
cancellation and the four-second deadline; this decision introduces no jobs,
timer handles, wakeup queues, or preemption. Longer non-spinning waits require
the blocked-task and deferred-reply design proposed by ADR 0032.
Diagnostics cannot poll, enumerate principals, read arbitrary memory, consume
input events, or change accounting. Both interfaces use copied request/reply
messages, exact version checks, and normal owner-wide handle revocation at
application teardown. Native acceptance faults the diagnostics server after it
receives a request, verifies exact frame return and a single cancelled client
completion, retains the shell, and then proves that a normal server launch
still succeeds.

These contracts are suitable primitives for later bounded interpreters and TCP
state machines, but do not define either. ADR 0029 separately supplies the
typed observation, DHCP, and ICMP command boundary. TCP still requires a
separate bounded connection/state/retransmission design.

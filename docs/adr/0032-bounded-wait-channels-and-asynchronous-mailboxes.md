# ADR 0032: Bounded wait channels and asynchronous capability mailboxes

Status: accepted staged direction, 2026-08-26. The portable blocked lifecycle,
wait-registration, and pending-call models are implemented; native suspended
contexts, deferred replies, idle integration, and mailboxes remain later
explicit slices and are not current behavior.

## Existing-contract review

The current dispatcher, scheduler, and application boundary already contain
several pieces that a BeOS-style message design would need, but their present
contracts are deliberately narrower:

- ADR 0011's `PortId` names one synchronous service endpoint; it is not a FIFO
  queue. A call exclusively borrows the dispatcher until one reply completes.
- ADRs 0010 and 0014 retain ready, running, exited, and faulted task states.
  The portable scheduler now also models `Blocked(wait key)`, but no native KEX
  enters that state until the composition-owned suspended-context slice lands.
- ADR 0015 can suspend a KEX application only at an ABI call, yield, fault, or
  lease expiry. Its 50 ms timer terminates an uninterrupted application; it is
  not resumable general preemption.
- ADRs 0025, 0028, and 0031 implement four-second, cancellable foreground waits
  inside a synchronous service call. Their cooperative checkpoints make bounded
  ambient input and network progress, but the application record remains
  logically running, the kernel retains the service call stack, and the CPU
  does not enter a scheduler-visible blocked state.
- ADR 0002 keeps shell pipelines sequential and stops at the first unsuccessful
  stage. Starting all stages concurrently would change when downstream side
  effects can occur, even if byte order, EOF, and final status were preserved.
- ADR 0013 and the architecture-specific notes prove interrupt-queue ownership
  only for one CPU. That proof does not survive SMP without a new memory,
  locking, interrupt-routing, allocator, and TLB decision.

Consequently, adding only `TaskState::Blocked` would be incomplete. A blocked
KEX call also needs an owned suspended user context, copied request, deferred
reply destination, wait registration, cancellation fate, and teardown rule.
None may be hidden in arbitrary suspended kernel frames.

This review also revises terminology from the initial design discussion. The
existing service `PortId` remains unchanged. A queued repository is called a
*mailbox* so synchronous service ports and asynchronous queues cannot be
confused. Producer and consumer authority should be represented by distinct
typed handles or interfaces rather than adding broad ambient send/receive
rights to every existing service handle.

## Accepted direction

Introduce two separable portable mechanisms. The wait mechanism may be useful
before mailboxes have enough real consumers to justify implementation.

Implementation note, 2026-08-26: `troe-task` now provides preallocated tables
for at most 16 generation-checked waits and 16 copied pending calls. Its atomic
observe-or-publish operation handles already-ready, expired, closed, cancelled,
and revoked conditions without publishing a stale wait. Pending requests have a
4 KiB per-call ceiling, a construction-time system byte ceiling, strictly
monotonic request identities, exact state transitions, owner teardown, and
zeroization before slot reuse. Portable scheduler tests cover blocking, running
other ready work, exact-key wakeup, stale/double-wake rejection, and ordered
terminal teardown. These types retain no native context or pointer.

### Wait channels and deferred replies

A wait key is an opaque slot-plus-generation identity. One bounded wait table
retains at most one registration per blocked task. A registration identifies
the task owner, awaited resource generation, closed set of wake conditions, and
optional boot-relative monotonic deadline. It never retains a raw kernel or
user pointer.

The scheduler gains these transitions:

```text
Ready -> Running -> Ready
                 -> Blocked(wait key) -> Ready
                 -> Exited | Faulted
Blocked(wait key) -> Exited | Faulted
```

Only the scheduler owns lifecycle state. A separate composition-owned table
retains the architecture-specific suspended-application token and pending ABI
call metadata. Blocking is permitted only after the application has crossed an
owned ABI gate and its complete visible context has been captured. No ordinary
kernel Rust frame, borrow, lock guard, dispatcher borrow, or device/DMA borrow
may span the blocked interval.

Application-visible `handle_call` remains synchronous: it eventually returns
one reply or terminal cancellation/fault. Internally, dispatch may complete
immediately or return a bounded pending-operation token. A pending operation
must have made no externally visible partial effect. Its copied request and
monotonic request identity are retained, and wakeup resumes or redelivers that
same operation without allocating another identity. A service that cannot
provide this no-partial-effect property remains synchronous.

Wakeup is a checked transition, not a hint. Publication of a wait registration
and observation of the awaited condition must form one lost-wakeup-safe
operation. A stale resource generation, duplicate wake, wake after cancellation,
or wake for another task is rejected and counted. Closing or revoking a
resource wakes its waiters with a terminal typed result. Owner teardown marks
the task terminal and, as part of handle revocation, cancels every matching
pending call and wait registration before user memory is zeroed or returned.

The first implementation remains single-CPU and non-preemptive. When no task is
ready, the composition root may enter the existing architecture idle boundary
only after the wait table, device work bits, input queue, and timer deadline
have been checked with the architecture's lost-wakeup exclusion intact. The
application execution-lease timer and a future kernel wait-deadline timer are
separate modes with explicit ownership; one must not silently reuse armed state
from the other.

### Capability mailboxes

A mailbox is a preallocated, bounded FIFO of complete copied messages. Its
identity and every producer/consumer handle are generation checked and owned.
Construction fixes both message-slot and retained-byte budgets. Admission is
atomic: a message is either copied completely or has no effect. Queue-full,
queue-empty, closed, cancelled, and timed-out are distinct typed outcomes.

The first proposed hard ceilings are subject to measurement before acceptance:

- at most 16 live mailboxes;
- at most 8 retained messages per mailbox;
- at most 4 KiB per message and 16 KiB retained message bytes per mailbox;
- at most 16 system-wide pending calls or wait registrations; and
- no allocation after successful mailbox construction.

Closing a producer rejects new sends. Existing messages remain drainable until
the last producer closes and the queue reaches EOF. Closing a consumer revokes
its receive authority and wakes a blocked producer; policy must decide whether
remaining messages are discarded or another consumer may drain them before
this ADR can be accepted. There is no peek, queue mutation, implicit broadcast,
global queue-slot pool, priority insertion, shared mutable buffer, or
application-visible kernel pointer.

Small control messages are copied. A future high-throughput buffer/page loan is
a separate capability and ownership decision; mailbox payloads must not become
an accidental shared-memory escape hatch.

## Sequencing and first consumers

Implementation is split so speculative general IPC does not enter the kernel
without a measured use:

1. Measure current cooperative checkpoint spins, idle transitions, network
   waits, cancellations, and maximum retained service-call bytes.
2. Add the portable wait-key, blocked-state, wake-reason, pending-call, and
   teardown models with exhaustive transition tests. No native behavior changes
   in this increment.
3. Add a bounded composition-owned suspended-call table and deferred dispatch
   result. Convert two existing real consumers--the monotonic timer wait and UDP
   receive--before treating the abstraction as justified. TCP may follow only
   after its retransmission and four-second operation deadlines retain their
   current semantics.
4. Prove native single-CPU blocking, cancellation, timeout, close/revoke wakeup,
   exact handle revocation, zeroization, frame return, and absence of idle
   spinning on both architectures.
5. Implement the portable mailbox only when two named non-test consumers need
   queued complete messages. A synthetic boot probe alone is verification, not
   product justification.
6. Consider multiple simultaneously live KEX tasks only after the loader,
   address-space-slot ownership, suspended-context table, total lifetime/step
   policy, and service reentrancy bounds are separately accepted.

Concurrent shell pipelines are not an initial consumer. A later ADR must state
whether starting every stage concurrently supersedes ADR 0002's first-failure
and side-effect ordering, how cancellation propagates in both directions, which
status wins when several stages fail, and how all stream handles close on every
exit or fault. Until then pipelines remain sequential.

## Verification required before acceptance

The portable portion of this gate is implemented in `crates/troe-task`: tests
cover observe-before-publish readiness, every terminal wake reason, deadline
and close/cancellation first-consumer races, stale wait and resource
generations, exact slot and retained-byte ceilings, pending identity reuse,
counter failpoints, copied-request detachment, zeroization, and owner teardown.
The following native evidence remains required before the deferred-reply slice
is accepted as current behavior.

Portable model tests must cover every legal lifecycle transition and reject
double block, double wake, stale generations, wake-before-publication races,
timeout/cancellation races, close with pending send/receive, owner teardown,
request-ID reuse, partial admission, queue wraparound, and every exact capacity
boundary. Allocation failure must leave no published mailbox, pending call, or
wait registration.

Native acceptance on x86-64 and AArch64 must prove:

- a blocked application retains its exact address-space, frame, stack, handle,
  and context ownership and resumes only through scheduler selection;
- input, network completion, timeout, cancellation, service close, and owner
  revocation cannot lose a wakeup or resume a stale task;
- a cancelled/faulted blocked task follows ADR 0014's revocation, zeroization,
  and exact frame-return transaction;
- ready tasks make progress while another task is blocked, while a task that
  never reaches an ABI gate is still contained by ADR 0015's execution lease;
- idle and wake counters demonstrate that an empty ready set does not busy
  spin; and
- pending-call/message live counts, byte high-water marks, wakes, cancellations,
  timeouts, full-queue events, and stale-wake rejections are observable.

The complete existing test gate remains mandatory. A host-only queue test or a
successful emulator demo is insufficient evidence for suspended-context and
teardown safety.

## Explicitly deferred BeOS-derived ideas

- Preemption and SMP remain separate milestones. Fine-grained locking or
  scheduling classes must not be introduced merely because the mailbox model
  could eventually run on several CPUs.
- Media-style recyclable buffer pools, format negotiation, performance clocks,
  and latency admission are promising only after TROE has two streaming
  consumers such as audio/video nodes or another high-rate graph. They require
  a separate buffer-ownership ADR.
- BFS-style attributes, indices, and live queries belong, if needed, in a
  read-only generation-bound package/catalog service. They must not widen KEFS,
  STFS, exact `/bin/<name>.kex` command resolution, or filesystem authority by
  implication.
- A thread or native stack per mailbox, service, handler, or future window is
  rejected. Logical handlers should be multiplexed over bounded scheduler
  records and explicitly owned continuations.

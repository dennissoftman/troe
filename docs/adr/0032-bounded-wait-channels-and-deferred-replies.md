# ADR 0032: bounded wait channels and deferred application calls

Status: accepted and implemented for the one-foreground-KEX profile,
2026-08-26.

## Context

A synchronous application service call cannot keep an arbitrary kernel Rust
frame, borrow, lock guard, device borrow, or user pointer alive while waiting
for a timer or network event. Busy polling also violates the native idle and
bounded-work contracts.

## Decision

`troe-task` owns preallocated, generation-checked tables for at most 16 waits
and 16 copied pending calls. A wait registration identifies the task owner,
resource generation, closed wake-condition set, and optional boot-relative
deadline. It retains no kernel or user pointer.

The scheduler owns these lifecycle transitions:

```text
Ready -> Running -> Ready
                 -> Blocked(wait key) -> Ready
                 -> Exited | Faulted
Blocked(wait key) -> Exited | Faulted
```

The composition root separately owns the suspended architecture context and
pending ABI metadata. Blocking begins only after the complete application
context and copied request are captured at an owned ABI gate. The pending
operation has one monotonic identity and must expose either no effect or one
complete typed result.

Publication and readiness observation form one lost-wakeup-safe operation.
Wakeup rejects stale resources, stale wait generations, duplicate delivery,
and delivery to another owner. Close, cancellation, timeout, and revocation are
distinct terminal fates. Owner teardown cancels pending work before user memory
is zeroed and frames are returned.

Timer sleep and UDP receive are the implemented deferred consumers. The single
foreground KEX may enter the native idle boundary only after wait, device,
input, and deadline state is checked under the architecture's lost-wakeup
exclusion. Application execution-lease timing and kernel wait deadlines retain
separate entry and return paths.

## Verification

Portable tests cover observe-before-publish readiness, terminal wake reasons,
deadline/cancel/close races, generation reuse, exact slot and retained-byte
ceilings, copied-request detachment, zeroization, and owner teardown. Native
acceptance covers timer and UDP completion, cancellation, timeout, idle/wakeup
counters, exact frame return, and subsequent filesystem activity on x86-64 and
AArch64 across all four supported QEMU profiles.

## Consequences

- The existing synchronous service `PortId` remains an endpoint, not a queue.
- No arbitrary native stack or kernel borrow spans a blocked interval.
- General FIFO mailboxes are not implemented and are tracked in
  [GitHub issue #9](https://github.com/dennissoftman/troe/issues/9).
- Multiple persistent KEX services and protected IPC are not implemented and
  are tracked in
  [GitHub issue #8](https://github.com/dennissoftman/troe/issues/8).

# ADR 0010: cooperative continuations and guarded task stacks

Status: accepted, 2026-08-23.

## Decision

Stage 4 introduces an architecture-independent `kllm-task` policy crate. One
scheduler retains at most 16 records, assigns non-reused monotonic identities,
and permits only ready, running, and exited lifecycle states. Exactly one task
may be running on the single CPU. Selection is deterministic round robin and
filters ready records by a typed capability set. Yield and exit are explicit
transitions with checked accounting. An exited record continues to own its
stack until reaping returns that exact resource to the bounded stack pool.

Tasks use explicit continuations rather than saved arbitrary call stacks. A
continuation keeps durable state in an explicitly owned object, while its
scheduler record retains identity, authority, lifecycle, and stack ownership.
It runs one step on its mapped native stack and returns `Yield`, `ExitSuccess`,
or `ExitFailure` to the scheduler. Yield therefore discards the step's native
frames. References and locks cannot accidentally remain hidden on a suspended
call stack, and the architecture boundary needs only a synchronous stack-call
trampoline rather than a portable saved-register layout.

The reserved boot arena contains three task-stack slots. Each slot is one
unmapped 4 KiB lower guard, a 32 KiB RW/NX payload, and one unmapped 4 KiB upper
guard. The owned mapping plan lists payloads individually instead of mapping
the whole boot arena, so guards are absent from both architecture page tables.
The kernel validates the adjacency and sizes before scheduling. A feature-only
acceptance command writes the active shell task's lower guard and must reach a
stable native write-fault diagnostic without rebooting. Production artifacts
are scanned for both MMU and task probe markers.

Boot runs two service continuations with different yield counts, observes five
round-robin yields, exits and reaps both, and dispatches a third continuation on
a returned slot. It then creates the shell task with only console, filesystem,
and machine-control capabilities and dispatches it using that complete request.
The shell asserts that its current stack pointer lies in its retained payload;
its halt authority is derived from the task capability rather than an ambient
composition-root boolean.

## Consequences

This stage accounts for task records and reusable stack slots without claiming
physical-page reclamation: all three slots remain in the permanent reserved
boot arena and are returned to their bounded pool, not the general frame
allocator. This prevents runtime page-table mutation from entering Stage 4 and
keeps guard mappings immutable after activation.

The model is cooperative, single-core, and single-address-space. A task that
does not yield can monopolize the machine. Capabilities constrain intended
dispatch and API authority but are not a hardware security boundary. Preemption,
arbitrary suspended native frames, per-task page tables, fault containment, and
message dispatch remain later-stage work.

Implementation note, 2026-08-23: Stage 5 subsequently added bounded synchronous
in-process message dispatch and routed ordinary native console output through
it. Per-task page tables and fault containment remain deferred to Stage 6. See
[ADR 0011](0011-bounded-in-process-message-dispatch.md).

# ADR 0045: Process registry, observation, and accounting

Status: accepted and implemented, 2026-08-27; fixed-capacity and control
portions superseded by ADR 0046.

## Context

ADR 0037 made KEX applications resident and allowed the shell event loop to
interleave foreground commands, background jobs, and supervised services. Its
job table was intentionally shell-owned: job numbers were not global process
identities, service state lived in a separate supervisor, and there was no
typed way for an application to observe the whole execution set.

A useful process foundation needs one authoritative lifecycle record, stable
identities that are not confused with shell job numbers, truthful resource and
CPU accounting, and read-only tools. It does not require copying the POSIX
process API, exposing arbitrary memory, or granting global termination rights.

## Decision

The kernel owns one bounded `troe-task` process registry covering every
successfully committed foreground command, background job, and service. Each
launch receives a monotonic,
non-reused `ProcessId`; the scheduler's `TaskId` remains a separate internal
identity, and the shell's session-local job number remains a control token only
for that session.

One record retains only bounded metadata: executable name without arguments,
origin, boot-relative start time, state, charged CPU ticks, exact retained
page-table and private-page counts, handle count, dispatches, yields, and
preemptions. Lifecycle transitions are paired with successful scheduler
transitions: `ready`, `running`, `blocked`, and `stopping`. Registration occurs
after transactional task and handle setup; removal occurs only after authority
revocation and scheduler reaping.

CPU accounting samples the architecture's highest-resolution monotonic counter
immediately around each ring-3/EL0 entry or resume. Only the checked delta is
charged. Kernel dispatch, service execution, waiting, and shell work are not
misreported as application CPU time. The observation snapshot includes the
counter frequency so consumers can convert without assuming an architecture.
Timer interface 1.0 additionally exposes only the calling task's charged ticks
and frequency. This supports standard process-CPU clocks without granting the
global `process-observe` authority.

Initial page-table storage is allocated from the exact number of four-level
tables implied by the complete mapping plan, subject to the existing 512-page
ceiling. The builder must consume exactly that allocation. Heap growth adds
supplemental table frames only when a new mapping prefix requires them. Process
resident-page accounting therefore reports retained frames, not a conservative
per-process reservation.

Interface 19, process observation 1.0, returns one fixed-size canonical legacy
snapshot of at most 16 records. Version 1.1 adds stable-ID pagination for the
full registry. The `process-observe` KCAP name grants only this call right. It
exposes no user pointers, register state, command arguments, memory contents,
handles, or control operation. `ps.kex` and `top.kex` use pagination.

## Scheduling and concurrency

Several applications can be alive and make progress concurrently. On the
current single-CPU targets, only one unprivileged continuation executes at an
instant. The kernel interleaves ready processes at the execution lease,
cooperative yield, service-call, and wait boundaries while blocked processes
retain their owned state. This is concurrent multiprocess execution, not SMP
parallelism.

The model deliberately adds no `fork`, ambient process tree, Unix signals,
process groups, `/proc`, ptrace, shared writable address spaces, or global
process-control capability. Shell `kill` remains owner-scoped job cancellation;
service stop remains supervisor-scoped.

## Consequences

Process identity and observation now have one source of truth across launch
origins, and accounting follows actual retained resources. An observer sees
itself as running while its snapshot call is serviced. A process may disappear
between snapshots after complete teardown; identities are never recycled
within a boot.

ADR 0046 replaces the original small fixed tables with fallibly growing
metadata under a 65,536-record system hard ceiling, adds owner-scoped child
control separately from observation, and makes resident admission scale to the
same task policy. Admission can still fail earlier on memory, handles, frames,
or service metadata. Supporting SMP, shared memory, cross-session control, or
richer historical accounting requires a separate authority and synchronization
decision.

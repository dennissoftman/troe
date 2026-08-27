# ADR 0037: Resident KEX processes and shell jobs

Status: accepted; first resident-process increment implemented, 2026-08-27.

## Context

The original command runner owned one isolated KEX launch in a Rust call frame,
runs it synchronously to termination, then revokes its handles and reclaims its
address space before the shell resumes. A 50 ms architecture timer already
captures a complete resumable application context, and `troe-task` already
models ready, running, blocked, exited, and faulted tasks. Deferred timer and
UDP calls likewise retain copied requests and generation-checked waits without
retaining a kernel borrow or user pointer.

That composition also imposed two unrelated lifetime limits:
an ordinary command is faulted after ten seconds and after 1,024 service calls.
Those are incompatible with an operating environment in which a valid compute
job, interactive command, or blocked network client may run for minutes, hours,
or days. Elapsed time and call count do not distinguish useful work from a
logical hang.

Background execution also cannot be represented by keeping the current command
runner frame alive. Persistent execution state, streams, handles, pending calls,
and owned frames need a supervisor-owned lifetime independent of one shell
dispatch.

## Decision

An isolated KEX launch becomes a resident process retained in a bounded process
table. `TaskId` remains its monotonic scheduler identity; ADR 0045 adds a
separate stable `ProcessId` for observation. One resident slot owns the
complete launch transaction after commit:

- fresh-entry metadata or one opaque resumable `ApplicationSession`;
- task, isolation, stack, page-table, private-frame, and heap-growth ownership;
- generation-owned startup handles and copied pending-call state;
- immutable invocation data and owned standard-stream endpoints;
- launch origin, start time, final status or fault, and accounting; and
- a globally unique resident resource-slot identity.

The native application mechanism still permits only one active unprivileged
root on the single CPU. Residency means that multiple suspended roots may be
retained, not that application code executes simultaneously. The supervisor
event loop drains bounded machine events, completes waits, processes shell
input, selects one ready task through `troe-task`, enters it for its configured
timeslice, and regains control on preemption, yield, ABI call, exit, or fault.
When no task is ready it sleeps until the earliest retained deadline or an
owned device/input interrupt.

There is no default total runtime deadline and no cumulative lifetime
service-call ceiling. The 50 ms maximum uninterrupted execution lease remains
a fairness and containment boundary, not a kill deadline. Message sizes,
resident task count, wait and pending-call tables, initial mappings, live
handles, heap commits, file tokens, network state, and output buffers retain
their existing local bounds. Admission failure is explicit and leaves no
partial resident process.

The first process table has eight resident records, within
`troe_task::MAX_TASKS`. Actual admission
also depends on exact available physical frames and handle/table capacity.
Terminal records are retained only while a bounded shell or service status
consumer needs their result, then owner-wide cancellation, handle revocation,
zeroization, and frame reclamation occur in the existing order.

### Foreground and background placement

Placement belongs to the launcher; an application cannot detach itself.

- A foreground process owns the session terminal input and direct terminal
  output. The shell session waits for its terminal result while the same event
  loop continues to run resident jobs and services between its bounded
  execution slices and deferred waits.
- A background job remains associated with its launching shell session and
  receives EOF as terminal input. Output and error use one explicitly bounded
  64 KiB per-job log, so asynchronous bytes never corrupt the prompt.
- A service is not a shell job and is defined separately by ADR 0038.

The shell grammar has a final unquoted `&` placement operator. The first
increment accepts it only for one command stage; concurrent pipelines require a
separate bounded stream-ring and backpressure decision because current pipelines
are intentionally sequential. Shell-owned `jobs`, `log`, `kill`, `wait`, and
`fg` commands operate only on the launching session's stable job numbers.
ADR 0045 adds capability-scoped process-wide observation without termination.
There is no ambient PID namespace or executable-name search.

### Cancellation and termination

No POSIX signal ABI is introduced. Terminal cancellation, `kill`, service stop,
and owner teardown set an explicit supervisor cancellation request.

A blocked operation is completed with its typed cancellation fate. A task that
continues executing is always recaptured by the execution timer; the supervisor
may then terminate it without resuming user code. Graceful service stop may
first resume a cancelled lifecycle wait for a bounded interval, after which the
same contained teardown is mandatory. Termination never depends on voluntary
yielding and never scans by executable name.

## Consequences

Long computations and long deferred sleeps are ordinary processes. A spinning
application can consume its scheduled CPU share but cannot monopolize the shell
or prevent termination. A supervisor cannot infer that arbitrary application
logic is stuck merely because it made no ABI call; promised service readiness
and watchdog behavior belong to ADR 0038.

The implementation splits background launch into transactional preparation,
one-step run/resume, and terminal reap operations. Stream and service objects
retained by a resident process own their state rather than borrowing one
`ExternalCommand::execute` frame. The shell input loop pumps resident work at a
10 ms boundary while waiting for input and during job-control waits.

Foreground dispatch has no total runtime or cumulative service-call ceiling.
Logical waits are polled through bounded architecture-timer slices rather than
assuming that an hour- or day-scale deadline fits in one hardware counter.
Service-policy transitions that require re-entering the shell resolver remain
serialized until the foreground command returns, but already resident service
and job processes continue to execute and complete waits.

Native acceptance admits and cancels a whole-day foreground wait and a
whole-day background wait, and proves that a shorter background wait reaches
its terminal state while a longer foreground wait owns the shell session.

This ADR introduces no threads, SMP, `fork`, `exec`, POSIX signals, process
groups, terminal sessions, concurrent pipelines, swap, demand paging, or
unbounded process metadata.

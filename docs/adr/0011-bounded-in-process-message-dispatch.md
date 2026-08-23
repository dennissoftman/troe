# ADR 0011: bounded in-process message dispatch

Status: accepted, 2026-08-23.

## Decision

Stage 5 introduces a portable `kllm-dispatch` crate with a synchronous
request/reply model. A dispatcher owns at most 16 service ports and 32 client
handles. Ports and handles are opaque slot-plus-generation identities. Closing
an endpoint invalidates every copied stale identity, and a recycled slot receives
a different generation. Each handle carries explicit call rights; possession of
a port identity alone does not authorize delivery.

A request contains a monotonic 64-bit identity, a 16-bit service-defined opcode,
and at most 4 KiB of immutable borrowed payload. The borrow lasts only for the
synchronous call. A service returns one owned reply of at most 4 KiB with a
typed success, invalid-request, not-found, or failure status; the dispatcher
attaches the matching request identity. Oversized input is rejected before
service delivery. Delivered calls consume their request identity even if reply
construction fails, preventing identity reuse after a service has observed it.

There is no queue in Stage 5. The dispatcher is exclusively borrowed for one
call, so a handle can be closed before delivery or after completion but not
raced with a call. Cancellation, deadlines, backpressure, blocking receive,
and partial request delivery are therefore absent rather than underspecified.
The request structure is an in-process API, not a stable wire format.

The first service adapter is console output. `ConsoleService<O>` accepts a write
opcode and forwards the payload through the existing byte-oriented `Output`
trait. `DispatchedOutput` implements the same trait for clients and uses normal
partial-write behavior to split larger buffers into bounded calls. Tests compare
exact output bytes between direct and dispatched implementations. The native
shell registers one console port and one call-capable handle for prompts and
ordinary stdout.

## Consequences

Fatal diagnostics bypass dispatch so transport or service failure cannot
recursively depend on the failed path. Polling input remains direct because a
synchronous blocking read protocol would need cancellation and wakeup semantics
that this stage intentionally does not claim.

This model improves interface shape and authority accounting but adds no
hardware isolation. Services and callers still share pointers, heap, privilege,
and failure fate. Stage 6 may replace borrowed input with copied messages or a
validated shared-memory transfer and may add fault containment; doing so must
define a versioned wire representation independently of this Rust structure.

# ADR 0044: transactional system lifecycle and data migration

Status: accepted and implemented for the hosted Stage 9 deployment reference,
2026-08-27. Native activation consumes the same verified immutable inputs and
continues to publish its compact SACT/TXSLOT pointer rather than parsing hosted
filesystem metadata in the kernel.

## Context

Package resolution and signatures answer which bytes form a complete plan and
who authorized them. They do not make a partially copied plan bootable, decide
when a candidate becomes healthy, preserve data across schema changes, or say
which unreachable objects are safe to delete. Treating those as unrelated
operator scripts would reintroduce the exact partial-state and rollback
ambiguities that immutable generations are meant to remove.

## Decision

Adopt the lifecycle v1 store and state machine specified in
[`system-lifecycle-v1.md`](../formats/system-lifecycle-v1.md). The hosted
reference is [`system_lifecycle.py`](../../tools/system_lifecycle.py); the
stable machine interface is [`troe_system.py`](../../tools/troe_system.py).

A deployment begins only from `healthy` or embedded `recovery` state. It
out-of-band anchors TROOT, verifies an active signed release for every member of
one exact PLOCK, repeats PMAN/TPKG/plan validation, enforces retained root and
release sequences, and snapshots the current desired configuration. Package,
release, and root objects are content addressed. The complete generation and
its `/sys/config` projection are staged, flushed, independently reopened, and
renamed before one atomic pointer can name it `pending`.

Health is a separate explicit event because the hosted reference cannot run a
UEFI KEX service as a host process. Native orchestration boots the pending
generation and supplies its bounded health result. A passed receipt atomically
commits the candidate. A failed receipt restores the known predecessor and all
reversible data snapshots. If any applied migration is forward-only, old code
is never selected over new data; the pointer enters `recovery-required` for an
operator decision.

Migration descriptors contain only bounded idempotent JSON `set` and `delete`
operations. A durable intent exists before candidate selection or mutation.
Reversible migrations retain exact canonical snapshots; forward-only migration
recovery replays the idempotent operations and cannot return to predecessor
code. Explicit downgrade authorization must name exactly the packages whose
versions decrease.

Garbage collection traces active, previous, recovery, and in-flight migration
generations before deleting anything. Persistent diagnostics retain only the
latest 64 bounded events. Every durable object, generation, migration,
activation, health, rollback, GC, and cleanup boundary accepts failure
injection; process-reopen tests require a complete old or new state after each
injected stop.

## Consequences

- A verified signature is necessary but never sufficient for activation.
- Pending health survives a normal process boundary; resolving an ambiguous
  interrupted pending state requires the explicit recovery operation.
- Reversible rollback can restore code, configuration, and data together.
- Forward-only migration failure sacrifices automatic rollback, never data/code
  compatibility, and is surfaced durably rather than guessed away.
- Hosted filesystem layout is an operator/reference contract. Native SACT,
  CSPK/GMAN, PRGN, and TXSLOT remain the compact boot-time contracts.

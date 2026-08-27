# ADR 0038: SCFG service supervision and boot activation

Status: accepted; bounded supervisor and boot-service increment implemented,
2026-08-27.

## Context

SCFG v1 already describes service identities, boot-required, boot-optional,
on-demand, and recovery-only startup modes, hard dependencies, initial-handle
ceilings, maximum uninterrupted execution leases, health timeouts, optional
lifetime ceilings, restart limits, and failure actions. Native generation
recovery currently validates that policy but does not retain and activate its
service graph. Isolated server composition is one-shot, and the shell has no
system service control surface.

Traditional Unix daemons often fork away from their launcher and are later
found using PID files or process-name matching. OpenRC supervision, runit, and
s6 instead work best when a daemon stays in the foreground under a known
supervisor. BSD `rc.d` and OpenRC provide useful dependency-oriented start and
stop policy, while systemd deliberately extends its manager across many object
types and implicit activation relationships. TROE needs direct process
supervision and explicit dependencies, not a generic unit framework.

## Decision

The kernel composition owns one bounded service supervisor over the resident
process mechanism from ADR 0037. A service executable is an ordinary isolated
KEX package. It never forks, writes a PID file, changes its own supervision
state, or detaches. The supervisor knows the exact `TaskId`, address-space
ownership, configuration record, and granted handles for every attempt.

The immutable SCFG selected through the active generation is retained through
namespace composition. Every configured artifact is resolved by its canonical
absolute path from immutable executable content. The KEX package requirements,
SCFG capability bits, initial-handle ceiling, launcher authority, and currently
available typed providers must all agree before any task or handle becomes
live. No service script executes with supervisor authority.

Each service has a desired state, `Up` or `Down`, and one observed state:

```text
Stopped -> Starting -> Ready -> Stopping -> Stopped
              |          |
              v          v
           Backoff <- Failed
              |
              +-------> Starting
```

`Starting` begins only after every hard dependency is `Ready`. Ordering alone
does not satisfy a dependency. The portable state machine keeps a distinct
readiness transition and health deadline. The first kernel composition defines
`Ready` as successful transactional admission of the foreground-style service
process under its exact `TaskId`; it does not yet expose a KEX lifecycle-ready
notification. This matches the initial OpenRC-like “started under supervision”
contract while preserving a state boundary that a later typed readiness handle
can tighten. Dependencies that lose readiness make dependents ineligible for a
new start and cause running dependents to stop.

Boot-required services are selected `Up` and participate in the supervisor's
required-health predicate. Boot-optional services are
attempted without withholding the recovery shell or interactive session.
On-demand services start only for an authorized control request. Recovery-only
services are eligible only in the immutable recovery environment.

### Failure and restart policy

A normal zero exit is still unexpected while the desired state is `Up`, unless
a future service kind explicitly defines one-shot completion. Fault, nonzero
exit, readiness timeout, watchdog timeout, and lifetime expiry are distinct
observable reasons.

The portable supervisor retains SCFG's closed failure meanings:

- `Continue` records the failure and leaves an optional service down;
- `Restart` retries no more than the configured restart ceiling;
- `PreviousGeneration` rejects candidate health and commits the already
  validated predecessor activation; and
- `RecoveryShell` rejects ordinary activation and retains only the immutable
  recovery environment.

Restart attempts use a fixed bounded exponential delay of 1, 2, 4, 8, 16, 32,
then 60 seconds. A successful readiness transition resets the current startup
failure delay but does not erase lifetime restart accounting. This prevents a
fast crash loop without adding SCFG fields or an unbounded event history.

`lifetime_limit_ms == 0` means no total lifetime limit. The execution lease is
only one uninterrupted timeslice. A future watchdog must be an explicit promise
made through a lifecycle handle; absence of calls or elapsed process age is
never treated as proof that arbitrary code is stuck.

### Control, shutdown, and logs

The first control surface is a non-shadowable, shell-owned `svc` intrinsic:

```text
svc [list]
svc status NAME
svc start NAME
svc stop NAME
svc restart NAME
svc log NAME
```

Control uses stable SCFG service identity, never guessed PIDs. `restart` is a
dependency-aware stop followed by start and has no separately customizable
hook. Stop cancels blocked calls and performs contained teardown at an
execution boundary. The supervisor retains a bounded stop deadline and exact
force-stop action for a future lifecycle-aware graceful-stop ABI.

Each service receives EOF rather than the session terminal as standard input.
Standard output and error feed one bounded in-memory ring retaining service
identity, monotonic record order, dropped-byte accounting, and the most recent
bytes. Logging is not a filesystem, journal, structured event database, or
unbounded kernel allocation. Persistent logs require a later separately
authorized logging service.

Orderly machine-shutdown integration remains a follow-up: the current
`poweroff` and `reboot` paths do not yet drain the service graph.

## Consequences

TROE gains an init/service manager without PID files, daemonization, shell
hooks, runlevels, targets, generic units, D-Bus, implicit dependency synthesis,
socket activation, cron, or timer units. SCFG startup modes already provide the
small selection vocabulary needed by the current system.

The implemented increment includes the portable bounded state machine, retained
selected `SystemConfig`, SCFG/KEX launch-authority intersection, boot launch,
restart/backoff policy, bounded logs, shell control, and adversarial portable
restart/readiness/dependency tests. The production fixture preserves its
existing previous-generation/recovery health policy. Applying those system-wide
actions to a post-activation runtime failure, explicit KEX readiness/watchdog
notification, graceful stop, and shutdown draining remain separate follow-up
work and must not be inferred from the presence of their portable policy states.

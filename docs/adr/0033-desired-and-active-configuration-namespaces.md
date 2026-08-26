# ADR 0033: Desired and active configuration namespaces

Status: accepted direction, 2026-08-26; implementation deferred to native
package activation. The current KEFS recovery image still exposes bootstrap
files under `/etc`; this ADR defines the package-managed namespace and does not
claim that migration is implemented.

## Context

TROE generations already bind executable objects, service definitions,
capability grants, and non-secret configuration. Operators nevertheless need a
writable place to author configuration without mutating the configuration used
by the running generation.

A single writable live tree would make generation identity incomplete. Two
machines on the same generation could behave differently, a multi-file edit
could become partially visible, and executable rollback could retain
incompatible configuration. The traditional `/etc` name also carries no
compatibility value for TROE: it does not distinguish desired input from active
resolved output. `/var` would conflate configuration with caches, logs, leases,
databases, and other mutable state.

## Decision

The package-managed namespace reserves two distinct configuration surfaces:

```text
/config/       writable desired configuration
/sys/config/   read-only configuration resolved for the active generation
```

`/config` contains operator-authored intent. Editing it never changes a running
service or the active namespace directly. It may contain an incomplete or
invalid draft. Write authority is explicit; the path being writable does not
grant ordinary applications ambient access to it.

The system control plane parses bounded, versioned desired configuration,
resolves packages and interfaces, checks policy and capability changes, and
constructs a complete immutable generation. A configuration-only change may
reuse every existing package object. Activation publishes that already
validated generation through the existing crash-consistent active pointer.

`/sys/config` is a generated projection of the active generation's normalized,
non-secret configuration. It changes as one unit with generation activation and
must never expose a mixture of old and new generation data during a lookup or
directory traversal. It is inspectable but not an authoring surface. Secrets
appear only as references or redacted metadata; secret material remains in its
separate authority domain.

Rollback selects the preceding immutable configuration together with its
executables and service definitions, so `/sys/config` follows the rolled-back
generation. Rollback does not silently rewrite `/config`: desired drafts have a
lifetime independent of the active generation and remain available for repair,
comparison, or explicit reversion.

Applications receive only declared, resolved configuration through scoped
startup handles or package-owned interfaces. They do not gain ambient access to
all of `/config` merely because they consume configuration. Mutable application
data and deliberately live application-owned settings belong in explicitly
declared `/vol/<name>` storage, not in either global configuration surface.

The future installed namespace does not retain `/etc` as an alias. The current
KEFS `/etc` directory is a bootstrap/recovery implementation detail and may
remain until the recovery image and its tests migrate deliberately. It is not a
package installation target or a future public configuration ABI.

## Consequences

- The active generation completely identifies its effective non-secret
  configuration.
- Invalid or half-written desired configuration cannot alter the running
  system.
- Configuration-only generations, health checks, and rollback use the same
  construction and activation path as package changes.
- Tooling can provide validation and desired-versus-active diff operations
  without guessing which live files a package may have changed.
- Operators must perform an explicit validation/activation step after editing
  `/config`; ordinary file writes are not disguised system transactions.
- The provider, on-disk format, authorization policy, and bounded snapshot
  semantics for `/config` remain implementation decisions. They must be settled
  before native package activation.

## Rejected alternatives

- **Writable `/etc`:** makes effective configuration mutable outside generation
  identity and preserves an imprecise Unix convention without compatibility
  need.
- **`/var`:** mixes desired configuration with unrelated variable runtime and
  application state.
- **`/cfg`:** architecturally workable, but the small abbreviation is less
  self-describing for a permanent public root name than `/config`.
- **A transaction-emulating writable active view:** ordinary editors use
  temporary files, replacement, rename, and locking patterns. Secretly turning
  those filesystem operations into generation activation would be surprising
  and would substantially widen the VFS contract.

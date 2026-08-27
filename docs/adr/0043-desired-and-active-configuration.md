# ADR 0043: desired and active configuration namespaces

Status: accepted and implemented for the VFS namespace and configuration
projection boundary, 2026-08-27. Deployment construction and durable generation
selection use this boundary rather than introducing another configuration path.

## Context

Package updates need two different kinds of configuration state. Operators need
a stable, writable desired-state tree which survives generation replacement.
Applications need an immutable view that has already been normalized and
validated against the exact generation they run. Treating both as one tree
would let a partial edit change a running service, make rollback ambiguous, and
turn path conventions into ambient authority. Retaining an `/etc` convention
would also obscure which of these meanings a file has.

## Decision

Reserve `/config` for desired state on a writable persistent provider and
`/sys/config` for the complete non-secret projection selected for the active
generation. The recovery image moves its own bootstrap files to `/recovery`.
TROE has no `/etc` directory and provides no alias, fallback search, or package
ABI for it.

The VFS always creates `/config` and `/sys/config`. Recovery may leave the first
without a provider and the second empty at generation zero. A deployment
candidate supplies a nonzero generation and a strictly sorted set of canonical
relative paths. Construction enforces the limits and rules in
[`config-projection-v1.md`](../formats/config-projection-v1.md), creates parents
in a staged namespace, and swaps the full view only after every entry validates.
Failure preserves both the old bytes and the old generation identity.

`/sys/config` files are immutable through ordinary filesystem operations. The
projection contains no secret values; services receive secrets through separate
capabilities. Updating `/config` alone does not change a running service. The
deployment lifecycle validates desired state, constructs a new immutable
generation projection, activates it transactionally, and can select the prior
projection during rollback.

## Consequences

- Desired edits and active runtime inputs have explicit, inspectable meanings.
- Package activation never copies arbitrary `/config` bytes directly into a
  running service's authority.
- Rollback selects a complete predecessor generation instead of attempting to
  reverse individual configuration writes.
- Software written only for `/etc` is not compatible until its package declares
  and consumes the TROE configuration projection explicitly.
- Secrets and provider mounting remain separate responsibilities. Schema
  migration, health checks, and durable active-generation selection are
  implemented by the hosted reference in [ADR 0044](0044-transactional-system-lifecycle.md),
  not silently by this namespace boundary.

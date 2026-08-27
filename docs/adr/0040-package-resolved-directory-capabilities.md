# ADR 0040: Package-resolved directory capabilities

Status: accepted; portable root-resolution and confinement foundation
implemented, 2026-08-27. Package-schema encoding and native service grant
composition are completed with the Stage 9 package activation work.

## Context

The ABI 1.1 filesystem services currently resolve a request from the launching
shell's working directory and also accept absolute paths. KCAP declares only
that a package needs the read or mutation interface; it cannot say which part
of the namespace the package needs. That compatibility grant is suitable for
the immutable recovery command environment, but it must not become the normal
installed-package authority contract.

An absolute path is a name, not authority. Granting one broad namespace handle
and asking applications to stay under a documented prefix would not prevent
parent traversal, symbolic-link escape, later mount replacement, or stale
generation use.

## Decision

Installed package manifests declare at most eight named roots. Each declaration
selects one closed role and access mode:

| Role | Activation source | Allowed access |
| --- | --- | --- |
| `assets` | immutable package data directory | read |
| `data` | exact package-owned persistent directory | read or read-mutate |
| `config` | active generation's resolved non-secret configuration | read |

Names contain 1–32 lowercase ASCII identifier bytes and are unique within one
package. A declaration is not a path. Generation activation resolves every
declaration through the locked package plan and deployment policy to an exact
existing directory object. Any absent, ambiguous, wrong-kind, or over-capacity
root rejects the generation before a task or handle becomes live.

The resolved object retains:

- its canonical absolute composition root, which is not exposed as authority;
- the immutable generation identity;
- read-only or read-mutate rights; and
- the exact mounted-provider boundary, if the root belongs to one.

The application receives one typed directory service handle for each resolved
root. Requests carry only nonempty relative paths. Absolute paths and a `..`
at the capability root fail before namespace or provider access. Normalization
may remove `.` and may consume `..` only within the retained root.

Every operation revalidates the active generation and current provider boundary.
A path cannot enter a mount created beneath an internal root or cross from one
provider to another. The initial scoped service does not follow symbolic links:
every intermediate or final link fails normal metadata, read, list, and mutation
operations. A read-link operation may inspect an exact final link without
following it. Scoped mutation does not create symbolic links. This closed rule
preserves confinement without relying on a provider-specific open-beneath race;
a later link-following revision requires provider object identities and an
explicit measured need.

Read, mutation, mount, provider, block, and device authority remain different
types. Mutation never implies mount or provider administration. Directory
handles are owner- and generation-checked through the ordinary dispatch table;
cancellation, task teardown, and generation replacement revoke them in the
existing order.

## Compatibility transition

The immutable recovery image and existing shell-launched ABI 1.1 packages keep
the current cwd-based filesystem service while package schemas and installed
generation activation are introduced. That service is named compatibility
authority in source and diagnostics. It is never emitted by the installed
package resolver.

Each in-tree command migrates atomically to declared roots when its package
manifest moves to the Stage 9 schema. Commands whose documented purpose is to
inspect the interactive recovery namespace remain recovery packages rather than
silently receiving an installed-system root grant. No absolute pathname alone
is converted into a capability.

## Consequences and verification

The portable VFS owns relative-beneath normalization, generation/right checks,
provider-boundary retention, and no-follow validation. Providers with symbolic
links expose final-component metadata without following it. Host tests cover
absolute input, parent escape, stale generations, read/mutation separation,
missing parents, final links, and a mount inserted beneath an already granted
root.

Native acceptance must additionally prove manifest resolution, per-handle root
selection, stale generation and owner rejection, cancellation, exact handle and
frame reclamation, and behavior-equivalent recovery commands on both
architectures. The package and lock schemas specify declarations and resolved
objects; they do not duplicate the VFS confinement algorithm.

This decision adds no ambient filesystem handle, global descriptor namespace,
mount-by-path authority, provider control, block access, device access, symlink
following, current-directory mutation, or cross-root rename/link operation.

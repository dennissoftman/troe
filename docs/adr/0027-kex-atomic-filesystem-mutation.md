# ADR 0027: KEX atomic filesystem mutation

Status: accepted and implemented for the Stage 9 mutation command migration,
2026-08-25.

## Decision

A KEX package may request optional interface 7, version 1.0, with the
`filesystem-mutate` capability. It is distinct from ADR 0026's read-only
interface: mutation authority does not imply read, list, metadata, provider,
mount, block, or device access. Packages may request both interfaces when a
larger application genuinely requires both.

The mutation interface exposes one complete-file replacement transaction and
atomic regular-file removal. `begin-replace` resolves paths relative to the
immutable startup cwd and returns an opaque nonzero token. `append` accepts
only the exact next offset, carries at most 4,086 bytes per copied call, and
stages at most 64 KiB total. `commit-replace` consumes the transaction and
publishes through `Namespace::write_file`; `abort-replace` consumes it without
publication. Commit is terminal even on provider failure, and application
teardown discards every unfinished transaction. `remove` is rejected while a
replacement is pending and otherwise delegates to the namespace's atomic
regular-file removal.

Only one transaction exists per granted handle. The kernel reserves its fixed
64 KiB staging ceiling before returning a token, checks every sequential offset
and size with checked arithmetic, and never exposes the staging allocation or
provider internals. The namespace retains authority, quota, object-type,
provider atomicity, and durability policy. Immutable KEFS, FAT, and ext4 paths
therefore reject mutation; writable RAMFS and the selected STFS provider keep
their existing atomic contracts.

The SDK supplies a streaming `FileReplacement` client whose `commit` and
`abort` consume the token. `write.kex` streams argv or stdin without a whole-file
application buffer; `rm.kex` receives the same mutation capability but cannot
read. Both targets exercise pipeline writes, immutable denial, 128-node quota
exhaustion and recovery, repeated create/remove teardown, and stable heap
accounting.

## Security and sequencing consequences

There is no partial visible write, seek, append-to-existing-file, rename,
directory mutation, permission change, mount operation, or raw persistence
primitive. A fault, lease expiry, invalid offset, or forgotten commit leaves no
published prefix. Fixed staging does temporarily duplicate bytes during the
namespace/provider commit, but both copies have explicit 64 KiB ceilings and
are reclaimed before the shell resumes.

This is sufficient for current `write` and `rm` behavior and for small runtime
state files. Larger-runtime packaging, module loading, and durable multi-file
transactions remain separate designs. Timer, diagnostics, and typed network
application services are the next command-migration boundaries before TCP,
Lua, or Python.

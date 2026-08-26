# ADR 0027: KEX atomic filesystem mutation

Status: accepted and implemented for the Stage 9 mutation command migration,
2026-08-25.

## Decision

A KEX package may request optional interface 7, version 1.3, with the
`filesystem-mutate` capability. It is distinct from ADR 0026's read-only
interface: mutation authority does not imply read, list, metadata, provider,
mount, block, or device access. Packages may request both interfaces when a
larger application genuinely requires both.

The mutation interface exposes one complete-file replacement transaction,
atomic regular-file or symbolic-link removal, empty-directory creation,
symbolic-link creation, and same-provider regular-file hard-link creation.
`begin-replace` resolves paths
relative to the immutable startup cwd and returns an opaque nonzero token.
`append` accepts
only the exact next offset, carries at most 4,086 bytes per copied call, and
stages at most 1 MiB total. `commit-replace` consumes the transaction and
publishes through `Namespace::write_file`; `abort-replace` consumes it without
publication. Commit is terminal even on provider failure, and application
teardown discards every unfinished transaction. `remove` is rejected while a
replacement is pending and otherwise delegates to the namespace's atomic
non-directory removal. Link requests carry two independently length-bounded
UTF-8 strings in one copied call and are rejected while a replacement is
pending. Absolute symbolic targets are provider-root-relative, relative targets
are link-parent-relative, and hard links may not cross providers.

Only one transaction exists per granted handle. The kernel reserves its fixed
1 MiB staging ceiling before returning a token, checks every sequential offset
and size with checked arithmetic, and never exposes the staging allocation or
provider internals. The namespace retains authority, quota, object-type,
provider atomicity, and durability policy. Immutable KEFS paths reject
mutation. FAT32 and constrained ext4 accept it only when mount policy granted a
writable provider backed by a durable block capability; their read-only mounts
still reject it. RAMFS and STFS retain their existing atomic contracts.

The SDK supplies a streaming `FileReplacement` client whose `commit` and
`abort` consume the token plus bounded directory, symbolic-, and hard-link methods.
`write.kex` streams argv or stdin without a whole-file application buffer;
`rm.kex` and `ln.kex` receive the same mutation capability but cannot read.
Both targets exercise pipeline writes, immutable denial, 128-node quota
exhaustion and recovery, repeated create/remove teardown, and stable heap
accounting.

## Security and sequencing consequences

There is no partial visible write, seek, append-to-existing-file, rename,
directory removal/rename, permission change, mount operation, or raw persistence
primitive. Link creation delegates one complete operation to the selected
provider and never exposes inode identifiers. A fault, lease expiry, invalid
offset, or forgotten commit leaves no published prefix. Fixed staging does
temporarily duplicate bytes during the namespace/provider commit, but both
copies have explicit 1 MiB ceilings and are reclaimed before the shell resumes.

This is sufficient for current `write`, `rm`, `ln`, and uncompressed `tar`
behavior and for bounded runtime state files. Larger-runtime packaging, module loading, and durable
multi-file transactions remain separate designs.

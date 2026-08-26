# ADR 0027: KEX streamed filesystem mutation

Status: accepted and implemented for the Stage 9 mutation command migration,
2026-08-25; amended for scalable streaming, 2026-08-26.

## Decision

A KEX package may request optional interface 7, version 2.0, with the
`filesystem-mutate` capability. It is distinct from ADR 0026's read-only
interface: mutation authority does not imply read, list, metadata, provider,
mount, block, or device access. Packages may request both interfaces when a
larger application genuinely requires both.

The mutation interface exposes one sequential regular-file replacement,
regular-file or symbolic-link removal, empty-directory creation, symbolic-link
creation, and same-provider regular-file hard-link creation. `begin-replace`
resolves paths relative to the immutable startup cwd, truncates or creates the
file, and returns an opaque nonzero token. `append` accepts only the exact next
64-bit offset and carries at most one dispatcher-sized payload. The kernel
aggregates calls in a 16 KiB buffer by default; before writing, an application
may select a power-of-two size from 4 KiB through 1 MiB. There is no aggregate
transaction or file-size limit in the ABI.

`commit-replace` flushes the final buffer, asks the namespace/provider to order
durability, and consumes the token. `abort-replace` consumes it without flushing
the final buffer. Truncation and previously flushed chunks remain visible after
abort, fault, lease expiry, or teardown; this intentionally matches ordinary
streamed write semantics rather than rollback. `remove` and link/directory
operations are rejected while a replacement is pending. Link requests carry
two independently length-bounded UTF-8 strings in one copied call. Absolute
symbolic targets are provider-root-relative, relative targets are
link-parent-relative, and hard links may not cross providers.

Only one streamed replacement exists per granted handle. The kernel checks
every offset and size with checked arithmetic and never exposes its bounded
working buffer or provider internals. `Namespace` routes truncate, append, and
sync independently. FAT32 grows cluster chains incrementally; ext4 grows data
extents and checksummed depth-one extent metadata incrementally. Neither
retains a complete payload or enumerates a complete large allocation chain.
Immutable KEFS paths reject mutation, and read-only FAT32/ext4 mounts still
reject it. RAMFS payload allocation is the file's own backing store. STFS is an
intentional bounded exception: its single state object must fit its dual-slot
transaction format, so it retains that complete fixed-capacity payload until
sync.

The SDK supplies a `FileReplacement` client whose `commit` and `abort` consume
the token plus bounded directory, symbolic-, and hard-link methods. KEX standard
streams are forwarded directly instead of being retained by the runner. Shell
`>` and `>>` use a 16 KiB namespace-backed output stream; `tar.kex` requests
1 MiB for archive creation and member extraction. `rm.kex` and `ln.kex` receive
mutation capability but cannot read. Host tests model a 2 GiB streamed file,
and explicit real-image stress tests write and fsck 128 MiB files on both ext4
and FAT32.

## Security and sequencing consequences

The interface deliberately has partial visible writes and provider-level
sequential append, but no seek, rename, directory removal/rename, permission
change, mount operation, or raw persistence primitive. Shell `>>` does not read
or duplicate the existing file. Link creation delegates one operation to the
selected provider and never exposes inode identifiers. File length is limited
only by the selected provider profile, inherent format representation, free
media, RAMFS/STFS quota, or checked arithmetic—not by a shell or ABI staging
ceiling. The 1 MiB maximum controls working memory and I/O aggregation only.

This is sufficient for current shell redirection, `rm`, `ln`, uncompressed
`tar`, future `dd`-style block-size selection, and bounded runtime state files.
Durable atomic replacement, rename, multi-file transactions, larger-runtime
packaging, and module loading remain separate designs.

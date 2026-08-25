# ADR 0026: KEX read-only filesystem service

Status: accepted and implemented for the Stage 9 read-only command migration,
2026-08-25.

## Decision

A KEX package may request the optional `filesystem-read` capability. If the
launching shell owns a live VFS namespace, the kernel grants interface 6,
version 1.0, rooted at that namespace and resolving relative paths from the
command's immutable startup cwd. The interface exposes only `open`, offset
`read`, `close`, `metadata`, and paginated `list`; it grants no mutation,
mount, provider, block, device, or raw kernel authority.

Requests and replies use the allocation-free codecs in `troe-abi` and remain
inside the 4 KiB dispatcher message ceiling. Paths are at most 256 bytes.
Each launch owns at most eight generation-checked open-file tokens. Reads are
bounded by the caller's reply capacity. Directory pages are lexical, carry an
opaque continuation cursor, and contain at most 64 entries, 64 bytes per name,
and 3,072 aggregate name bytes. Metadata identifies only object kind and byte
count. Exact decoding rejects unknown versions/opcodes, trailing bytes,
invalid paths or cursors, wrong object kinds, stale tokens, and overflow.

The service borrows the shell's live namespace only for the isolated launch.
It revalidates the object through VFS operations, never returns kernel pointers
or provider internals, and drops all open slots with the dispatcher before the
shell resumes. The manifest remains least-authority: packages without
`filesystem-read` receive no filesystem handle, and a missing, malformed,
unsupported, or unavailable requirement rejects launch.

The repo-local SDK exposes typed read-only operations and errors. `cat`,
`grep`, `hexdump`, `ls`, and `man` are the first migrated consumers; their KEX
artifacts execute on both targets while the static implementations remain only
as absent-artifact recovery fallbacks.

## Security and sequencing consequences

Opening a path does not snapshot or widen authority: every token is scoped to
one launch and generation reuse rejects stale values. Pagination prevents an
untrusted or large provider directory from causing unbounded allocation, and
lexical ordering makes repeated pages deterministic without exposing provider
enumeration order. Apps must still bound whole-file and line processing and
close successful opens on every exit path.

This interface deliberately cannot implement `write` or `rm`; mutation needs a
separate capability with provider-specific atomicity and durability semantics.
Timer, diagnostics, and typed network services also remain separate. Those
boundaries and their command migrations precede TCP and larger runtimes such as
Lua or Python.

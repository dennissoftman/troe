# ADR 0026: KEX read-only filesystem service

Status: accepted and implemented for the Stage 9 read-only command migration,
2026-08-25; open-table capacity amended by ADR 0046.

## Decision

A KEX package may request the optional `filesystem-read` capability. If the
launching shell owns a live VFS namespace, the kernel grants interface 6,
version 1.2, rooted at that namespace and resolving relative paths from the
command's immutable startup cwd. The interface exposes only `open`, offset
`read`, `close`, `metadata`, paginated `list`, and final-component `readlink`;
it grants no mutation,
mount, provider, block, device, or raw kernel authority.

Requests and replies use the allocation-free codecs in `troe-abi` and remain
inside the 4 KiB dispatcher message ceiling. Paths are at most 256 bytes.
Each launch owns a fallibly growing table of at most 4,096 generation-checked
open-file tokens. Reads are
bounded by the caller's reply capacity. Directory pages are lexical, carry an
opaque continuation cursor, and contain at most 64 entries, 64 bytes per name,
and 3,072 aggregate name bytes. Listings distinguish regular files,
directories, and provider-owned symbolic links; metadata and open follow a
link to its bounded provider-root target. `readlink` returns at most 256 UTF-8
target bytes without following the final component. Metadata identifies only resolved
object kind and byte count. Exact decoding rejects unknown versions/opcodes,
trailing bytes,
invalid paths or cursors, wrong object kinds, stale tokens, and overflow.

The service borrows the shell's live namespace only for the isolated launch.
It revalidates the object through VFS operations, never returns kernel pointers
or provider internals, and drops all open slots with the dispatcher before the
shell resumes. The manifest remains least-authority: packages without
`filesystem-read` receive no filesystem handle, and a missing, malformed,
unsupported, or unavailable requirement rejects launch.

The repo-local SDK exposes typed read-only operations and errors. `cat`,
`grep`, `hexdump`, `ls`, `man`, and later `tar` are migrated consumers and their
KEX artifacts execute on both targets. ADR 0030 later removed the temporary
absent-artifact fallbacks.

## Security and sequencing consequences

Opening a path does not snapshot or widen authority: every token is scoped to
one launch and generation reuse rejects stale values. Pagination prevents an
untrusted or large provider directory from causing unbounded allocation, and
lexical ordering makes repeated pages deterministic without exposing provider
enumeration order. Apps must still bound whole-file and line processing and
close successful opens on every exit path.

This interface deliberately cannot implement `write` or `rm`; ADR 0027 adds a
separate capability while retaining provider-specific atomicity and durability
semantics. Timer, diagnostics, and typed network services also remain separate.
Those boundaries and their command migrations precede TCP and larger runtimes
such as Lua or Python.

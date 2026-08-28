# ADR 0047: KEX filesystem tools and user-space runtime

Status: accepted and implemented, 2026-08-28.

## Decision

TROE keeps filesystem policy and algorithms in isolated user space. The kernel
exposes typed read and mutation capabilities: bounded metadata/list/read/link
calls, streamed file replacement, link/directory creation, unlink, empty
directory removal, and atomic same-provider rename. It does not implement copy,
recursive traversal, recursive deletion, destination-name policy, or
cross-provider move emulation.

The `no_std` `troe-kex-runtime` crate is the first POSIX-like facade above the
raw `troe-kex` SDK. It provides path joining, bounded streamed file copy,
iterative no-follow traversal, recursive copy, recursive post-order deletion,
and same-provider move helpers. Traversal retains fallibly grown `Vec` metadata
up to 4,096 objects and 1 MiB of aggregate path bytes. These ceilings are
backstops, not preallocated tables; file content is never aggregated into the
traversal metadata. Arbitrary trees never consume the Rust call stack.

`cp`, `mv`, recursive `rm`, and `rmdir` share this behavior. Symlinks encountered
during recursion are reproduced or removed as links and are never followed.
`mv` uses rename and fails explicitly with `CrossDevice`; it does not claim a
safe cross-provider copy/sync/remove transaction that the current primitives
cannot guarantee. Commands return stable nonzero statuses and path-specific
diagnostics for typed failures.

## Scope and future libc roadmap

This facade is not libc. It has no C ABI, global `errno`, integer file
descriptors, POSIX `stat`, `open`/`read`/`write`, `DIR`/`readdir`, allocator ABI,
or `FILE` streams. A future libc effort should add those in layers: define the
C ABI and stable errno mapping; introduce descriptor tables over typed handles;
add stat/open/read/write and directory iteration; standardize allocator
integration; then build buffered `FILE` streams. Each layer must preserve
capability attenuation and bounded, fallible metadata growth rather than
introducing ambient kernel namespace authority.

## Consequences

The raw typed ABI stays small and auditable while commands share one tested
implementation. Allocation-using commands initialize the existing growable TLSF
heap through a serialized global adapter, and `Vec::try_reserve` exposes memory
failure as a command error. Cross-provider moves remain deliberately absent
until a durable temporary-name, sync, cleanup, and recovery contract exists.

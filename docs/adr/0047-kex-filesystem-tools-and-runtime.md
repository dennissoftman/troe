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
and same-provider move helpers. Its allocation-free modules also provide
immutable environment/default lookup and inheritance, direct-command parsing
and child cleanup, stable POSIX-style error translation, UTC calendar
conversion and bounded C-locale date formatting, decimal parsing and libm
entry points, ASCII classification, and non-cryptographic seed mixing.
Traversal retains fallibly grown `Vec` metadata up to 4,096 objects and 1 MiB
of aggregate path bytes. These ceilings are backstops, not preallocated tables;
file content is never aggregated into the traversal metadata. Arbitrary trees
never consume the Rust call stack. The allocation-backed surface is feature
gated so language runtimes with their own allocator can use the other modules.

`cp`, `mv`, recursive `rm`, and `rmdir` share this behavior. Symlinks encountered
during recursion are reproduced or removed as links and are never followed.
`mv` uses rename and fails explicitly with `CrossDevice`; it does not claim a
safe cross-provider copy/sync/remove transaction that the current primitives
cannot guarantee. Commands return stable nonzero statuses and path-specific
diagnostics for typed failures.

## Scope and future libc roadmap

This facade is not libc. It now exposes a deliberately small static C ABI for
pointer-free math/calendar/seed operations plus one checked bounded calendar
formatter, and an SDK-owned C source core provides the unavoidable standard
symbol wrappers used by Lua. Stable errno numbers exist and typed callback
failures reach them. There is still no general integer descriptor table, POSIX
`stat`, `open`/`read`/`write`, `DIR`/`readdir`, allocator ABI, shared-object
loader, or reusable `FILE` implementation.

A future libc effort should add those in layers: freeze a documented C ABI and
errno contract; introduce capability-scoped descriptor tables; add
stat/open/read/write and directory iteration; standardize allocator integration;
then move the current app-local buffered `FILE` machinery behind that shared
interface and add complete `FILE` streams. C string/memory pointer primitives,
varargs formatting, Lua's upstream C sources, and stateful `FILE` buffering stay
in C today: rewriting them as Rust raw-pointer exports would add unsafe shims
without improving ownership. Each later layer must preserve capability
attenuation and bounded, fallible metadata growth rather than introduce ambient
kernel namespace authority.

## Consequences

The raw typed ABI stays small and auditable while commands share one tested
implementation. Allocation-using commands initialize the existing growable TLSF
heap through a serialized global adapter, and `Vec::try_reserve` exposes memory
failure as a command error. Cross-provider moves remain deliberately absent
until a durable temporary-name, sync, cleanup, and recovery contract exists.
Lua hard-compiles the same Rust implementation and the SDK C core today; future
dynamic linking can change code distribution without changing the capability
boundary.

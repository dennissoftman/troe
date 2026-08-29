# ADR 0046: Owner-scoped process launch and scalable resource tables

Status: accepted and implemented, 2026-08-28.

Supersession note, 2026-08-28: ADR 0050 extends package selection to an exact
relative or absolute path when `argv[0]` contains `/`. Bare-name lookup,
capability attenuation, owner-scoped lifecycle tokens, and teardown are
unchanged.

Supersession note, 2026-08-29: the interactive shell now evaluates bounded
left-associative `&&` and `||` lists. Moving a broader command language into
`sh.kex` remains future work.

## Context

The resident-process and observation work left command evaluation split across
two worlds. The interactive shell could resolve KEX packages, but an ordinary
application such as `sh.kex` could not launch another application. Small fixed
tables also capped the scheduler, dispatcher, waits, jobs, and observation at
8–32 records even when memory was available. Raising those array lengths would
preallocate scarce kernel memory without solving ownership or stale-token
problems.

The kernel must provide mechanisms and resource authority; command grammar and
policy belong in an unprivileged shell application. That requires a complete
launch/lifecycle boundary before the shell parser grows POSIX control syntax.

## Decision

KEX interface 20, `process-launch` 1.0, grants owner-scoped child admission and
lifecycle operations. `SPAWN` accepts canonical cwd, argv, environment, and
stdin/stdout/stderr selections. The kernel resolves only the exact
`/bin/<argv[0]>.kex` package, validates its executable and KCAP manifest, creates
a fresh address space, and returns both a read-only global `ProcessId` and an
unforgeable `ChildToken`. `POLL`, blocking `WAIT`, `CANCEL`, and terminal-only
`REAP` require that token and preserve the complete `u32` application status.

A child manifest must be an attenuation of the launcher's own grants. Nested
launch never manufactures authority merely because a package requests it.
`shell-script` and privileged `clock-control` cannot be delegated through this
interface. A future broker may implement a separately named policy, but it
must not silently weaken this boundary.

The child token is a 64-bit generation/slot capability and is deliberately
separate from the 64-bit monotonic process ID. The slot half is 32-bit because
the implemented hard ceiling is 65,536 objects; the other 32 bits prevent stale
slot reuse. Making the slot index 64-bit would enlarge metadata without adding
usable capacity, while using a plain PID would make observation identity into
control authority.

KEX interface 21, `pipe` 1.0, creates owner-scoped byte pipes. A pipe has
explicit reader and writer closure, blocking reads, complete bounded writes,
backpressure, EOF, and generation-checked endpoints. A launch may inherit a
standard stream, attach a null endpoint, or attach the corresponding end of an
owned pipe. Child stream services retain endpoint references until teardown;
parent closure and child exit therefore produce deterministic EOF and broken
pipe behavior.

Parent teardown recursively cancels and reaps every retained descendant before
revoking the parent's handles and memory. TROE does not adopt or orphan a child
in this increment. A child can itself receive attenuated launch/pipe handles,
so nesting is recursive without adding a kernel shell or parser.

Resource registries now use fallibly growing `Vec` storage with small initial
reservations instead of maximum-sized arrays. The scheduler and process
registry, wait and pending-call tables, dispatch ports, resident records,
owner child table, and owner pipe table grow on demand. Current hard ceilings
are:

| Resource | Hard ceiling | Initial reservation |
| --- | ---: | ---: |
| tasks and process records | 65,536 | 64 |
| wait registrations and pending calls | 65,536 each | 64 and 8 |
| dispatcher ports | 65,536 | 64 |
| dispatcher handles | 262,144 | 64 |
| retained children per launch authority | 65,536 | 64 |
| pipes per pipe authority | 65,536 | 64 |
| aggregate pipe capacity per owner | 256 MiB | zero bytes |
| read-only open files per application | 4,096 | 64 |
| UDP bindings | 16,384 | 64 |
| ARP neighbor cache | 256 | zero records |

Growth failure and ceiling exhaustion are explicit and atomic. Counters and
slot fields were widened so the public accounting can represent the ceiling
without saturating at 255 or 65,535. The immutable hard ceilings are safety
backstops, not promises to reserve that many objects.

KCAP now permits 128 sorted requirements. Command invocation and environment
tables permit 128 entries each within the existing 4 KiB copied-message
boundary. The shell's already dynamic argv and pipeline vectors are bounded at
128 arguments and 255 stages, the maximum useful stage count under its current
512-byte command-line limit.

This scaling rule applies to runtime object registries. It does not blindly
multiply format geometry, path/symlink safety budgets, hardware-topology arrays,
or one-reply batch sizes; those bounds need pagination or a format/version
decision before they change. The legacy 16-record observation reply is one such
case, so 1.1 adds pagination instead of allocating a giant reply.

The initial diagnostic consumer is `spawn.kex`. It proves inherited streams,
captured pipe output, nested package resolution, full nonzero child status,
wait, and reap on both architectures. It is not a substitute for moving command
evaluation into `sh.kex`.

## Configuration direction

The constants above are system hard ceilings. A later typed system
configuration may set lower boot-wide and per-process soft limits, analogous to
`ulimit`, and privileged policy may raise those soft limits up to the compiled
hard ceiling. Raising the compiled ceiling remains possible after reviewing
token width, memory accounting, and worst-case scan costs; it must not require
changing the application ABI.

## Consequences

The kernel now exposes process, wait, cancellation, environment, standard
stream, and pipe mechanisms without knowing shell syntax. `sh.kex` can later
become the evaluator for `&&`, `||`, conditionals, loops, and eventually a
larger POSIX grammar while the kernel remains grammar-free.

This increment did not implement `fork`, shared address spaces, POSIX signals,
process groups, descriptor duplication, command substitution, or a POSIX
conformance claim. ADR 0050 subsequently added explicit KEX paths. Pipes are concurrent across
resident processes, but the existing interactive shell's own pipeline executor
remains unchanged until `sh.kex` adopts the new APIs.

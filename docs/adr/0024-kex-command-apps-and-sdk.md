# ADR 0024: KEX command applications and build SDK

Status: accepted and implemented for the Stage 9 application vertical slice,
2026-08-25.

## Decision

TROE command applications are immutable KEX v1 files installed at
`/bin/<architecture>/<command>.kex`. A command is a lowercase ASCII name with
digits, `_`, or `-`; applications do not receive arbitrary filesystem paths as
implicit authority. `cd`, `poweroff`, and `reboot` remain non-shadowable shell
intrinsics. For every other name the shell tries the KEX resolver first. An
absent artifact permits the current static recovery built-in; an artifact that
exists but is malformed, exceeds policy, or faults fails closed and never
falls back.

The first command ABI is synchronous and capability-only. Startup supplies
exactly four ABI 1.0 call handles:

- command invocation: returns one bounded, versioned `cwd` and `argv` record;
- standard input: bounded reads from the current pipeline stream;
- standard output and standard error: bounded writes to distinct streams.

All request and reply sizes remain within the existing 4 KiB dispatcher
message ceiling. Invocation encoding accepts at most 32 arguments, a 256-byte
working directory, and 512 aggregate argument bytes. The kernel stages input
and output under the existing 64 KiB pipeline ceiling. Unknown opcodes,
versions, handles, trailing bytes, and over-capacity output are deterministic
errors. EOF is a successful zero-byte input reply.

Application artifacts are sized with VFS metadata and copied through bounded
offset reads into a fresh owned buffer before parsing. Runtime loading retains
the KEX transaction, W^X rules, per-application page tables, guarded stack,
dispatcher ownership, lease, fault containment, and ordered teardown from ADRs
0011, 0014, and 0015. The cooperative shell task is logically yielded while
the application owns the CPU and is made runnable again only after application
handles and pages are reclaimed. This first increment permits one foreground
application at a time; it does not claim jobs, shared memory, threads, or
preemption.

`crates/troe-abi` is the allocation-free wire contract. The repo-local Rust SDK
in `sdk/rust/troe-kex` owns startup validation and architecture call gates, and
applications use its `entry!` macro instead of defining raw syscalls. The
dependency-free Rust `troe-kex-tool` command builds both pinned `*-unknown-none`
targets with `sdk/kex.ld`, passes the resulting ELF through its strict converter,
and can byte-check or inspect installed output. Example source lives
under `apps/`; canonical generated artifacts are committed under `rootfs/bin`
until the signed content-store packaging decision replaces that bootstrap
distribution path.

## Security and efficiency consequences

Authority comes only from startup handles. The SDK exposes no ambient POSIX
environment, dynamic linker, TLS, filesystem, network, clock, allocator, or
machine-control interface. Apps are `no_std`, abort on panic, use a fixed image
base, request explicit stack/heap pages, and are statically linked. The hosted
builder rejects dynamic metadata, relocations, TLS, W+X, noncanonical layout,
wrong targets, residual bytes, and artifacts outside Standard KEX ceilings.

Resolution performs no directory search and never executes from writable
state. Only `NotFound` selects a recovery built-in, preventing a corrupt or
hostile installed application from silently changing the executed code path.
Pipeline bytes are copied at the service boundary in this synchronous version;
that is bounded and simple, but a future concurrent pipeline design will need
an explicit ring/wakeup contract rather than silently widening this ABI.

## Sequencing consequence

The four command/stream handles and end-to-end `echo` replacement must pass on
both native targets before application networking is designed. Networking then
starts as a separate bounded datagram/service capability over the already
implemented UDP substrate. TCP follows only after app-visible port ownership,
wait/cancellation, timer, receive-backpressure, teardown, and adversarial
service tests exist. TCP, DNS, TLS, and a general socket API are therefore not
part of this ADR.

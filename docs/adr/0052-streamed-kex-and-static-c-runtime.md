# ADR 0052: Streamed KEX loading and the static C runtime boundary

Status: accepted and implemented, 2026-08-29.

## Context

The KEX format permits a 32 MiB executable, while the owned kernel heap is
smaller. Retaining a complete external package in kernel heap made the format
ceiling unusable for substantial statically linked language runtimes. Such
runtimes also need one audited freestanding C target and process-local services
without acquiring a host libc ABI or ambient POSIX authority.

Large optional executables must remain independently deployable from shared
media. Embedding them in KEFS or EFI would couple the recovery image to runtime
payload size and would remove the clear missing-media failure boundary.

## Decision

Every VFS-backed direct, background, service, and owner-scoped nested KEX launch
uses a coherent multi-pass offset reader. The format layer retains one 4 KiB
prefix, one 4 KiB replay buffer, and at most one 16 KiB completion-validation
buffer. It validates complete package and executable geometry, fingerprints the
complete source and relocation bytes, and returns a pointer-free plan. The
native loader allocates a provisional inactive root,
zeros image frames, streams only segment file bytes into those frames, applies
the validated relative relocations, and requires both fingerprints to match
again before activation. All earlier W^X, randomized placement, startup,
capability attenuation, transaction rollback, zeroized teardown, and exact
page accounting remain common to the new path. The loader rejects source
mutation, no-progress or over-reported reads, malformed and oversized input,
and sink failures without activating the root.

Optional runtime KEX packages are installed only below the versioned
`/vol/shared/runtime/v1/<architecture>/bin` tree. Its canonical manifest binds
the exact sorted path set, byte lengths, and SHA-256 digests. Deterministic host
tooling builds, verifies, and installs mounted or detached shared media. Rootfs,
KEFS, and EFI builds do not consume runtime trees, and no embedded fallback is
provided.

The SDK owns one LP64 freestanding C sysroot for x86-64 and AArch64. It is built
with `-nostdlibinc`, exports `lib/libtroe_c.a`, and defines the target types,
layouts, constants, errno values, setjmp state, UTF-8/wide behavior, C locale,
and symbol ownership used by statically linked runtimes. The library and its
Rust host bridge expose the hybrid allocator, bounded process-local descriptors,
buffered `FILE` and directory streams, filesystem and link operations,
argv/environment, exit processing, clocks, UTC conversion, secure randomness,
single-execution-thread locks, and TSS. Lua consumes the shared headers,
setjmp implementation, compatibility core, and nanoprintf source.

The facade is an application library, not a kernel POSIX subsystem. It can use
only typed capabilities present in the package manifest. Missing authority
returns `EACCES`; unsupported flags and facilities return explicit errors.
Thread creation, signals, fork/exec, executable private mappings, networking,
dynamic linking, additional locales, and timezone databases are absent.

## Consequences

A maximum-size canonical KEX package no longer requires a similarly sized
kernel-heap allocation. A substantial C runtime can be compiled against one
reproducible cross-target SDK, linked statically, stored on shared media, and
launched with the normal application isolation and teardown contract.

The static archive belongs in the build sysroot's architecture `lib`
directory. TROE still has no guest `/lib`: an executable carries the symbols it
uses, and `/vol/shared/runtime/v1/<architecture>/bin` contains runnable KEX
packages rather than link-time objects.

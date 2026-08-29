# Third-party software

Portable policy crates have no third-party runtime dependencies.

The firmware application uses `uefi` 0.39 from the rust-osdev project under
MIT OR Apache-2.0. Cargo.lock pins its complete transitive dependency graph.
It is confined to the UEFI bootstrap boundary and is not used after
ExitBootServices.

The owned machine heap and the bounded KEX application heap adapter use `rlsf`
0.2.3 under MIT OR Apache-2.0. Its build graph uses `cfg-if`, `const-default`,
and the build-time `rustversion` macro; the lockfile also records its optional
Unix `libc` edge. The project supplies each fixed memory pool, synchronization
where needed, ownership transition, and exact requested-byte accounting.

`lua.kex` vendors the official Lua 5.5.1 source release under MIT. TROE builds
the interpreter as freestanding C for both KEX targets, supplies the allocator,
math, formatting, non-local-jump, stream, and filesystem boundaries, and omits
ambient host access from the capability-backed `io`, `os`, `package`, and
`debug` library surface. Exact archive URL, hash, license, and the one
conditional upstream-source change are recorded in `apps/lua/vendor/UPSTREAM.md`.

Lua number formatting uses nanoprintf 0.6.1 under Unlicense OR 0BSD. The source,
license, archive hash, and configuration are vendored once under
`sdk/c/troe-kex-runtime/vendor` and shared with Lua. Lua's
transcendental C symbols are backed by the pinned pure-Rust `libm` 0.2.16 crate
under MIT OR Apache-2.0; its default architecture support uses baseline
hardware floating-point instructions without requiring a hosted C library.

Audit status: APIs, licenses, target isolation, allocation/handoff contracts,
and the Lua C/Rust boundary are reviewed under repository policy. The complete
lockfile is also checked by pinned
`cargo-audit` against the committed RustSec database revision; no claim is made
that this is a formal security audit.

The optional `cargo alpine` development command downloads the official Alpine
Linux 3.24.1 virtual ISO for x86-64 or AArch64. Those images remain external
development inputs under Alpine's constituent package licenses and are not
redistributed by TROE. Exact filenames, lengths, release URL, and SHA-256
digests are pinned in `tools/alpine-profile.json`.

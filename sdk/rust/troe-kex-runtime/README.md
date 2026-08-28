# TROE KEX runtime

`troe-kex-runtime` is TROE's small `no_std` POSIX-like user-space layer over the
raw typed `troe-kex` SDK. It does not add kernel authority and is not a complete
libc.

The default `alloc` feature provides streamed and recursive filesystem
algorithms with iterative no-follow traversal and fallibly grown metadata.
Disable default features to retain the allocation-free environment, stable
errno, direct-process, UTC calendar/formatting, C-locale ASCII, and seed
helpers; enable the independent `math` feature for decimal/libm support. Lua
uses `math` without `alloc` because its TLSF heap is owned by the embedded
interpreter rather than a Rust global allocator.

The small exported C surface is intentionally limited to operations whose ABI
can remain direct or whose pointer span can be validated once. The companion
[`sdk/c/troe-kex-runtime`](../../c/troe-kex-runtime) source supplies standard C
symbols that inherently operate on C pointers or varargs.

Planned layers are a frozen C ABI and errno contract, capability-scoped file
descriptors, `stat`/`open`/`read`/`write`, bounded `DIR` iteration, allocator
integration, and finally reusable buffered `FILE` streams. Until those exist,
this crate must not be described as libc.

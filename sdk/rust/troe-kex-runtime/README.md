# TROE KEX runtime

`troe-kex-runtime` is TROE's small `no_std` POSIX-like user-space layer over the
raw typed `troe-kex` SDK. It does not add kernel authority and is not a complete
libc.

The default `alloc` feature provides streamed and recursive filesystem
algorithms with iterative no-follow traversal and fallibly grown metadata.
Disable default features to retain the allocation-free environment, stable
errno, direct-process, UTC calendar/formatting, C-locale ASCII, typed CSPRNG
reads, and POSIX-shaped private-memory helpers; enable the independent `math`
feature for decimal/libm support. The memory facade supports zeroed anonymous
private data, read/read-write/inaccessible protection changes, and owned
unmapping. It deliberately rejects fixed replacement, sharing, file/device
backing, and executable mappings. Lua uses `math` without `alloc` because its
TLSF/private-mapping hybrid heap is owned by the embedded interpreter rather
than a Rust global allocator.

The small exported C surface is intentionally limited to operations whose ABI
can remain direct or whose pointer span can be validated once. The companion
[`sdk/c/troe-kex-runtime`](../../c/troe-kex-runtime) source supplies standard C
symbols that inherently operate on C pointers or varargs.

The current surface does not include a frozen general C ABI, capability-scoped
file descriptors, `stat`/`open`/`read`/`write`, bounded `DIR` iteration, a shared
allocator ABI, or reusable buffered `FILE` streams. This crate must therefore
not be described as libc. Reusable-runtime and optional compatibility direction
is tracked in GitHub issues #10 and #11.

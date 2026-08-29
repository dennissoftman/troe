# TROE freestanding C runtime

This directory implements the C symbols declared by the sibling
`troe-kex-sysroot`. `tools/build_c_sysroot.py` cross-compiles the sources with
`-nostdlibinc` and publishes the deterministic static archive
`<architecture>/lib/libtroe_c.a`; applications link that archive into their KEX
image. There is no dynamic linker or guest `/lib` dependency.

The allocation-free binary64 formatter in `troe_printf_double.h` provides
correctly rounded `%f`, `%e`, and `%g` conversions across the finite double
range. Integer, pointer, string, and character conversions use the vendored
nanoprintf implementation.

The runtime owns:

- allocation, zeroed allocation, reallocation, alignment, and release through
  the `troe_runtime_host` allocator callback;
- memory, strings, conversion, sorting/searching, math/decimal adapters,
  UTF-8/wide-character conversion, C/POSIX locale behavior, and target-native
  `setjmp`/`longjmp` state;
- 64 bounded descriptors, 16 directory streams, 16 buffered `FILE` objects,
  standard streams, read-only file access, sequential replacement and
  provider-backed preserved-append writes, metadata, cwd, directories,
  rename/removal, and hard/symbolic links;
- immutable argv/environment, 32 atexit callbacks, process termination, clocks,
  UTC calendar conversion, secure random reads, and 32 coherent TSS keys; and
- single-execution-thread mutex, once, and TSS behavior with explicit
  `ENOTSUP` thread-creation stubs.

The callback table is capability scoped. Missing file, mutation, timer,
wall-clock, or random authority fails at the attempted operation; it is never
replaced by ambient access. Without private-memory authority, allocation remains
inside the growable TLSF heap and reports normal allocation failure at its
limit. Unsupported access modes,
random writes, process creation, signals, executable mappings, networking,
dynamic linking, additional locales, and timezone databases fail explicitly.

Nanoprintf 0.6.1 is vendored once below `vendor/` and shared by this runtime and
Lua. Lua also consumes these headers, compatibility symbols, and setjmp source;
application-specific Lua state and pipe-backed extensions remain in the Lua
application.

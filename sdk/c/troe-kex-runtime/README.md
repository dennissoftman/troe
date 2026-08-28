# TROE freestanding C compatibility core

`troe_libc_core.c` is a small SDK-owned source component that KEX language
runtimes may hard-compile while TROE has no dynamic linker. It supplies the
standard C symbols that still inherently need C pointer or varargs semantics:
memory/string operations, `strerror`, C locale data, `strtod` dispatch, the
floating-point ABI adapters (including the `frexp` pointer wrapper), and bounded
nanoprintf formatting.

Safe generic algorithms live in the sibling Rust `troe-kex-runtime` crate.
Lua-specific state, upstream Lua C sources, allocator callbacks, and its
temporary buffered `FILE` implementation remain under `apps/lua`. This core is
not a complete libc and does not provide descriptors, directory streams,
allocator ownership, or ambient filesystem access.

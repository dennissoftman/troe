# Vendored runtime sources

`lua-5.5.1/src` is the unmodified `src` directory from the official Lua
5.5.1 release archive:

- URL: <https://www.lua.org/ftp/lua-5.5.1.tar.gz>
- SHA-256: `1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce`
- License: MIT; see `lua-5.5.1/LICENSE`

TROE carries one small conditional change in `lbaselib.c`: `dofile` and
`loadfile` are not registered when `TROE_LUA` is defined. The KEX executable
loads its initial file through the bounded filesystem capability instead of
exposing an ambient libc `FILE` API.

The shared C SDK owns the nanoprintf source and license used by this runtime;
see `sdk/c/troe-kex-runtime/vendor/nanoprintf-0.6.1`.

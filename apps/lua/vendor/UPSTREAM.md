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

`nanoprintf-0.6.1/nanoprintf.h` and its license come from the nanoprintf v0.6.1
release archive:

- URL: <https://github.com/charlesnicholson/nanoprintf/archive/refs/tags/v0.6.1.tar.gz>
- SHA-256: `81d4dc86e40fa80cf64b6f3bb8d2fbbaf6d54bbf971a0ccb48cf414d32f51e4f`
- License: Unlicense or 0BSD; see `nanoprintf-0.6.1/LICENSE`

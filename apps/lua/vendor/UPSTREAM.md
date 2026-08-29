# Vendored runtime sources

`lua-5.5.1/src` is the unmodified `src` directory from the official Lua
5.5.1 release archive:

- URL: <https://www.lua.org/ftp/lua-5.5.1.tar.gz>
- SHA-256: `1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce`
- License: MIT; see `lua-5.5.1/LICENSE`

TROE supplies its platform integration in `apps/lua/c` and compiles these
upstream sources without modifying them. Its bounded `FILE` facade exposes
`dofile`, `loadfile`, and Lua module reads through typed KEX filesystem
capabilities.

The shared C SDK owns the nanoprintf source and license used by this runtime;
see `sdk/c/troe-kex-runtime/vendor/nanoprintf-0.6.1`.

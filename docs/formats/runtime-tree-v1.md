# Shared runtime tree v1

The shared runtime tree is the canonical location for optional, large,
architecture-specific KEX executables. One installed tree begins at
`/vol/shared/runtime/v1` and has this exact shape:

```text
runtime/v1/
├── MANIFEST.sha256
├── aarch64/bin/<name>.kex
└── x86_64/bin/<name>.kex
```

Runtime executables are not rootfs, KEFS, EFI, or guest `/lib` contents. A
missing `/vol/shared` medium or missing version tree is a terminal unavailable
artifact condition; launch does not fall back to an embedded copy.

## Manifest

`MANIFEST.sha256` is ASCII and begins with exactly:

```text
TROE-RUNTIME-TREE 1
```

Each following line is:

```text
<lowercase-sha256> <decimal-byte-count> <architecture>/bin/<name>.kex
```

Records are strictly increasing by path. The architecture is `aarch64` or
`x86_64`; the middle component is exactly `bin`; and a path has exactly three
components. Names are portable ASCII letters, digits, `_`, `-`, or `.`, occupy
at most 64 UTF-8 bytes before the `.kex` suffix, and do not contain path
separators. The tree contains 1 through 128 artifacts. Each artifact is nonempty
and no larger than the KEX package v1 ceiling of 33,571,904 bytes.

The listed regular files and manifest are the complete file set. Symbolic
links, duplicate paths, unmanifested files, missing files, noncanonical
records, unsupported schemas, and length or digest mismatches are invalid.

## Tooling

`tools/mkruntime.py build` copies exact inputs into a temporary sibling,
orders records canonically, writes the manifest, verifies the result, and
atomically publishes the requested output directory. `verify` performs the
same exact-tree checks without mutation. `install` requires an available
mounted shared-media directory and publishes below `runtime/v1`.
`install-image` requires a valid detached TROE GPT/FAT32 shared image and
`mtools`, refuses to replace an installed v1 tree, copies every file, extracts
the result again, and verifies it byte-for-byte. `verify-image` performs the
same extraction and comparison without installation.

The manifest authenticates deterministic population and detects accidental
media changes; it is not a signature or package-trust record. Every selected
file still passes complete KEX package, KCAP, target, executable, relocation,
and capability validation at launch.

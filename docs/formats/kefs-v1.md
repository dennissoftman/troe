# KEFS version 1

All integers are little-endian. The format has no alignment padding.

Header (16 bytes):

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 8 | `4b 45 46 53 76 31 00 00` (`KEFSv1`, then two zero bytes) |
| 8 | 2 | record count |
| 10 | 2 | reserved, zero |
| 12 | 4 | exact total image length |

Each record is `kind:u8`, `path_len:u16`, `data_len:u32`, UTF-8 path bytes,
then file data. Kind 1 is a file and kind 2 is a directory. Directory data must
be empty. Paths are absolute, normalized, non-root, strictly byte-lexically
increasing, and must obey the global path bounds. Parents precede children in
the source image used by 0.1.

The reader checks every addition and slice boundary before access, requires
exact end-of-image consumption, parses into temporary owned records, and only
then mutates the namespace. A malformed image therefore cannot cause an
out-of-bounds read or partial mount.

The magic identifies the KEFS format and version only. It intentionally embeds
no product, repository, or vendor name, so a project rename does not change the
filesystem contract.

`tools/mkefs.py` is the canonical builder. It rejects symlinks and unsupported
filesystem objects so host-specific link behavior cannot enter an image. Its
verification path independently decodes the artifact, validates every record
and exact end-of-image consumption, and compares the resulting ordered paths,
kinds, and payloads with the normalized source tree. A byte-for-byte rebuild is
therefore not the sole round-trip check.

For boot roots, `--architecture` selects one target-qualified source
`/bin/<architecture>` directory, projects its children into runtime `/bin`, and
excludes all other architecture directories. The KEFS wire format itself stays
architecture-neutral.

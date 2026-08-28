# KEX package v1

KEX package v1 is the canonical single-file application artifact. Installed
bare commands live at `/bin/<command>.kex`; the same canonical package may be
selected through an explicit VFS path. It binds one KCAP v1 capability manifest
to one architecture-specific KEX v1 executable and optional CMPL v1 descriptor,
so launch and completion never depend on adjacent sidecars. The kernel validates
the complete envelope and manifest before it
constructs optional services, then validates the embedded executable before
allocating or mapping application pages.

All integers are unsigned little-endian. The header is exactly 48 bytes:

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `KEXPKG`, two zero bytes |
| 8 | 2 | package major | 1 |
| 10 | 2 | package minor | 0 |
| 12 | 2 | header bytes | 48 |
| 14 | 2 | flags | bit 0 means an embedded CMPL artifact is present |
| 16 | 4 | manifest offset | 48 |
| 20 | 4 | manifest bytes | exact canonical KCAP v1 length |
| 24 | 4 | executable offset | `48 + manifest_bytes` |
| 28 | 4 | completion offset | zero without bit 0; otherwise exact executable end |
| 32 | 8 | executable bytes | nonzero and at most 16 MiB |
| 40 | 8 | package bytes | exact input length |

The KCAP bytes immediately follow the header. The KEX executable immediately
follows KCAP. When flag bit 0 is set, one nonempty canonical CMPL v1 artifact
immediately follows the executable and consumes the remainder of the package.
Gaps, padding, reordered members, unbound trailing bytes, unknown flags, and
unsupported versions are noncanonical. A complete package is at most
16,793,792 bytes: a 48-byte header, the 144-byte maximum manifest, the 16 MiB
maximum executable, and the 16 KiB maximum completion artifact.

KCAP and CMPL remain independently versioned encodings, but neither is
installed as a separate file. KCAP inclusion proves that an empty
manifest is intentional rather than missing. KEX v1 likewise remains the
strict executable subformat and continues to reject capabilities, signatures,
and unrelated metadata inside its load image. CMPL is metadata rather than
authority and is validated separately from KCAP.

The hosted builder emits one package file and removes any adjacent `.kcap`
sidecar. Check mode rejects such sidecars. Package
identity, content hashes, and signatures belong to the separate package-model
and trust formats; they are not inferred from reserved bytes in this envelope.

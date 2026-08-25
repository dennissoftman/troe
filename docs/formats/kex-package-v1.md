# KEX package v1

KEX package v1 is the canonical single-file application artifact installed as
`/bin/<command>.kex`. It binds one KCAP v1 capability manifest to one
architecture-specific KEX v1 executable so launch never depends on an adjacent
sidecar. The kernel validates the complete envelope and manifest before it
constructs optional services, then validates the embedded executable before
allocating or mapping application pages.

All integers are unsigned little-endian. The header is exactly 48 bytes:

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `KEXPKG`, two zero bytes |
| 8 | 2 | package major | 1 |
| 10 | 2 | package minor | 0 |
| 12 | 2 | header bytes | 48 |
| 14 | 2 | flags | zero |
| 16 | 4 | manifest offset | 48 |
| 20 | 4 | manifest bytes | exact canonical KCAP v1 length |
| 24 | 4 | executable offset | `48 + manifest_bytes` |
| 28 | 4 | reserved | zero |
| 32 | 8 | executable bytes | nonzero and at most 16 MiB |
| 40 | 8 | package bytes | exact input length |

The KCAP bytes immediately follow the header. The KEX executable immediately
follows KCAP. Gaps, padding, reordered members, trailing bytes, unknown flags,
and unsupported versions are noncanonical. A complete package is at most
16,777,408 bytes: a 48-byte header, the 144-byte maximum manifest, and the
16 MiB maximum executable.

KCAP remains an independently versioned allocation-free record encoding, but
it is never installed as a separate file. Its inclusion proves that an empty
manifest is intentional rather than missing. KEX v1 likewise remains the
strict executable subformat and continues to reject capabilities, signatures,
and unrelated metadata inside its load image.

The hosted builder emits one package file and removes an adjacent legacy
`.kcap` left by an older build. Check mode rejects such sidecars. Package
identity, content hashes, and signatures may wrap or version this envelope in a
future publication design; they are not inferred from reserved bytes.

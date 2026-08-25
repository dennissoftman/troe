# KCAP v1 capability manifest

KCAP v1 is the canonical package-side declaration of optional startup
authorities for one KEX command. KEX remains an architecture-specific static
executable with no embedded capabilities; the adjacent manifest is validated
before any optional service is registered or any application page is mapped.

All integers are unsigned little-endian. The 16-byte header is:

| Offset | Bytes | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `KCAPv1`, two zero bytes |
| 8 | 2 | record count | 0–16 |
| 10 | 2 | reserved | zero |
| 12 | 4 | encoded bytes | exactly `16 + count * 8` |

Each eight-byte record contains interface identifier (`u32`), required major
(`u16`), and required minor (`u16`). Records are strictly ascending by nonzero
interface identifier; duplicates and major version zero are invalid. There are
no rights bits: KCAP declares which typed startup interface is required, while
the kernel grants only that interface's fixed call right and exact version.

The repo-local builder reads the closed capability names from:

```toml
[package.metadata.troe-kex]
capabilities = ["datagram"]
```

It writes `<command>.kex` and `<command>.kcap` together under the selected
source architecture. KEFS projects both into flat runtime `/bin`. A missing
artifact or malformed, unknown, unsupported, or unavailable requirement rejects
launch and never selects privileged fallback behavior. The four command/standard-stream handles
are mandatory ABI context and therefore are not repeated in KCAP.

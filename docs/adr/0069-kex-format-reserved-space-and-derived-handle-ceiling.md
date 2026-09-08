# ADR 0069: KEX format reserved space and derived handle ceiling

Status: accepted and implemented, 2026-09-08. The ABI 1.3 extension in
[ADR 0035, Phase B](https://github.com/dennissoftman/troe/issues/8) supersedes the
single-prefix startup calculation below: ABI 1.3 uses an 80-byte prefix and
167 handles; ABI 1.0–1.2 retain 64 bytes and 168 handles. The SDK subtracts the
versioned IPC extent as well as the startup region when deriving image span.
Container, package, and KCAP versions in this decision are unchanged.

## Context

TROE keeps its canonical KEX executable and host-side ELF converter. Native ELF
loading is outside the current contract in CORE-SPEC and
[issue #10](https://github.com/dennissoftman/troe/issues/10): the system has no
Unix syscall ABI, uses a freestanding runtime, and validates a canonical
monotone stream with a fixed working set. These pre-release formats have no
installed compatibility obligation.

The previous service, loader, manifest, and startup descriptor limits disagreed.
Package offsets also used narrower fields than package lengths, while headers
and capability records lacked space for explicit fail-closed reservations.

## Decision

KEX container 1.2 has a 96-byte header. Every existing field keeps its offset;
a reserved-zero `u64` occupies byte 88. Flag bit 0 is reserved for a block-mappable
image, bit 1 for a TLS template, and load permission value 4 for a TLS template.
These reservations are not supported features: the parser rejects all of them.
The exact layout is [KEX v1](../formats/kex-v1.md).

KEXPKG 1.1 has an 80-byte header, 64-bit executable and completion offsets and
lengths, an explicit completion byte count, and 16 reserved-zero bytes. Manifest
offset and length remain 32-bit because the canonical manifest is bounded.
Members remain tightly concatenated. An absent completion requires zero offset
and length; a present completion consumes exactly the package remainder. The
complete ceiling is 2,147,502,184 bytes: 80 + 2,072 + 2 GiB + 16 KiB. See
[KEX package v1](../formats/kex-package-v1.md).

KCAP 1.1 has a 24-byte header with an exact minor and reserved-zero `u64`, plus
16-byte records. Each record retains the interface and exact version, adds
`kind = 0` for `KIND_INTERFACE`, and requires its remaining six bytes to be zero.
The maximum remains 128 requirements, for 2,072 encoded bytes. Unknown kinds,
minors, and nonzero reserved bytes fail closed. See [KCAP v1](../formats/kcap-v1.md).

`troe_abi::startup` owns the page and region geometry, 64-byte header, 24-byte
handle descriptor, and four mandatory command/stream handles. Initial capacity
is `(REGION_BYTES - HEADER_BYTES) / HANDLE_BYTES`: 168 handles in the current
one-page region. The loader, SDK, and SCFG derive their limits from this value;
the hosted package model mirrors it and derives total plan capacity from the
128-package limit. The format-codec dependency rule admits `troe-abi` as leaf
wire vocabulary and enforces that it has no shipped crate dependencies. A compile-time assertion ensures all 128 optional requirements
plus mandatory handles fit. Admission still requires supported interfaces and
authorized capabilities; a larger budget grants no new authority.

The SDK validates the supplied mapped region length and derives the image span
from the heap address minus that length and image base. The kernel asserts its
one-frame allocation matches the ABI region. Widening the region requires
updating both physical allocation and machine mapping, as well as respecting
SCFG's one-byte budget representation.

## Deliberately unchanged

- Relative relocations stay 16 bytes with two `u64` offsets. Shrinking them to
  `u32` would impose a 4 GiB span limit; a relocation kind remains speculative
  until the linking requirements in issue #10 are defined.
- Compression is absent because it would break the current fixed-working-set,
  direct replay contract for the canonical stream.
- KEXPKG has no self-digest. A field hashing its own complete envelope would
  break the canonical bijection between members and package bytes; identity,
  integrity, and signatures belong to the surrounding trust formats.
- Redundant exact fields such as header bytes and record bytes remain canonical
  assertions, validated before allocation. They are not implicit extension
  lengths.
- The closed KCAP interface kinds, SCFG capability mask, 128-requirement ceiling,
  executable image-span and encoded-byte limits, and W^X boundary remain intact.

## Verification

Rust tests compare complete, header-only completion, and streamed package
validation for reserved bytes, full-width geometry, and inconsistent completion
lengths. Manifest and SDK tests check exact kinds, reserved fields, and startup
capacity. SCFG and hosted-plan tests cover the shared handle budget. The
generated rejection corpus covers the executable header reservation on both
architectures. All committed commands, service probes, and KEFS images are
rebuilt, and the exhaustive `python3 scripts/test.py` gate verifies formatting,
lints, tests, deterministic artifacts, and both QEMU architecture paths.

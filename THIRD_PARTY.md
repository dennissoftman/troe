# Third-party software

Portable policy crates have no third-party runtime dependencies.

The firmware application uses `uefi` 0.39 from the rust-osdev project under
MIT OR Apache-2.0. Cargo.lock pins its complete transitive dependency graph.
It is confined to the UEFI bootstrap boundary and is not used after
ExitBootServices.

The owned machine heap uses `rlsf` 0.2.3 under MIT OR Apache-2.0. Its UEFI build
graph uses `cfg-if`, `const-default`, and the build-time `rustversion` macro;
the lockfile also records its optional Unix `libc` edge. The project supplies
the fixed memory pool, synchronization, ownership transition, and accounting
adapter.

Audit status: APIs, licenses, target isolation, and allocation/handoff contracts
were reviewed for Stage 2. The complete lockfile is also checked by pinned
`cargo-audit` against the committed RustSec database revision; no claim is made
that this is a formal security audit.

# ADR 0049: kernel CSPRNG, readable random capability, and KEX ASLR

Status: accepted and implemented, 2026-08-28.

## Context

Private virtual memory makes address placement a security-relevant kernel
decision. Clock values, addresses, device identifiers, and emulator defaults
are not entropy. Lua also needs a real seed source, and future archive,
cryptographic, protocol, and package tools need random bytes without each
application inventing a platform shim.

Random output is not privileged merely because it is random. One process
reading its own bytes must neither predict another process's output nor reveal
the generator state. The authority boundary is therefore an auditable typed
read capability, not an artificial lifetime quota or an entropy-depletion
counter.

## Decision

Before exiting boot services, the kernel obtains a 40-byte seed from the UEFI
RNG protocol. It prefers the raw algorithm and falls back to the protocol's
selected default. Missing service, read failure, or an all-zero catastrophic
source check aborts boot; TROE never silently substitutes clocks or addresses.
The seed is moved into owned memory and erased from the handoff record.

The `troe-random` `no_std` crate implements a ChaCha20 CSPRNG with a 256-bit key,
64-bit nonce, checked 64-bit block counter, unbiased bounded `u64` selection,
and fast key erasure after every nonempty public draw. The kernel owns the only
generator instance. Placement draws and application reads share it through
checked exclusive borrowing, so no state can be cloned or concurrently reused.

ABI 1.1 adds the typed `random` interface 1.0. A canonical request names a
nonzero reply length up to 4,096 bytes. The kernel copies only that many fresh
bytes into the caller-owned reply and exposes neither seed, counters, device,
nor generator state. SDK/runtime `fill`, `next_u32`, and `next_u64` helpers
chunk larger buffers. The capability remains explicit in the immutable KEX
manifest and launcher attenuation chain. There is no cumulative byte cap;
normal call scheduling and the per-call bound provide fairness.

KEX container 1.1 is position-independent. The SDK links ELF64 `ET_DYN` at
base zero and the converter accepts only target-relative dynamic relocations.
KEX stores each relocation as a 16-byte pair of image-relative target and value
offsets. The parser requires sorted, unique eight-byte target spans inside the
mapped image and values inside the image. Targets may begin at unaligned byte
offsets because prebuilt target libraries can pack pointer constants and may
place address literals in code. Relocation happens only in fresh private
backing before publication. This supports the target's prebuilt Rust
`core`/`alloc` without a custom sysroot: the loader applies
`selected_image_base + value_offset` before mapping the final RX/R/RW pages, so
no executable or read-only runtime page is temporarily writable and no
writable-executable alias is created.

For every launch, the kernel uniformly selects:

- a 2 MiB-aligned image base in the 4 GiB–64 TiB window; and
- a separately randomized 2 MiB-aligned stack placement in the 96–128 TiB
  window.

Heap and startup addresses derive from the selected image base. Anonymous
private mappings use unbiased selection across all aligned free slots in the
process's dynamic arena, not merely a randomized first-fit start. Checked
placement rejects every overlap or architectural boundary failure before frame
ownership changes.

QEMU profiles attach `rng-random` backed by `/dev/urandom`; the Cloud
Hypervisor profile attaches its equivalent virtio RNG. Hosted CSPRNG tests use
explicit deterministic seeds. Guest acceptance reads the typed capability and
requires independently launched KEX images to occupy different bases.

## Consequences

Applications can read secure random values, Lua no longer synthesizes seeds,
and user image/stack/private-map layouts are randomized without weakening the
capability or W^X model. A boot environment that cannot provide approved
entropy is unsupported rather than deceptively "random."

This decision does not provide kernel ASLR, demand paging, swap, shared
libraries, executable anonymous memory, JIT transitions, `fork`, or a general
dynamic linker. Executable private memory remains a separate future decision
requiring provenance, W^X transitions, instruction-cache synchronization, and
revocation semantics.

# ADR 0048: capability-scoped private memory and configurable resource policy

Status: accepted and implemented, 2026-08-28.

Amendment, 2026-08-31: [ADR 0060](0060-extent-backed-launch-reservation.md)
applies this decision's `operation_quantum_pages` substep bound and extent-based
backing to the initial launch reservation as well, so the quantum is no longer
specific to dynamic private mappings. Its meaning here is unchanged.

## Context

KEX ABI 1.1 gives each application an initially bounded heap whose mapped
prefix can grow upward. That is sufficient for ordinary commands, but it is not
a complete private-memory substrate for language runtimes, streaming archive
and compression programs, or allocators that need to return large freed
objects to the system. There is no anonymous mapping, inaccessible reservation,
range protection, or partial unmapping operation.

The missing mechanism must not turn the kernel into a POSIX implementation.
The kernel should validate and apply typed, caller-private page-table changes;
address selection, allocation policy, compatibility flags, and higher-level
algorithms belong in a reusable `no_std` user-space runtime. It must also
preserve TROE's existing page ownership, global W^X, bounded kernel work,
explicit capability, and exact teardown rules.

Several existing narrow or fixed implementation choices are not suitable
resource policy. In particular, application TLSF geometry currently prevents a
single allocation larger than approximately 32 MiB even when virtual and
physical memory are available. Conversely, removing every bound would let
sparse reservations or deliberately fragmented mappings consume unaccounted
kernel metadata. TROE needs configurable limits with sane defaults, not tiny
legacy tables or unbounded metadata.

## Decision

Keep the application ABI at 1.1 and add a typed `private-memory` interface 1.0
over the existing capability-handle call gate. An application receives the
interface only when its immutable manifest requests it and its launcher can
delegate it. The handle affects only the caller's dynamic private arena. It
never accepts a physical address, another task identity, a kernel pointer, or a
file/device handle.

The raw interface provides these mechanisms:

- reserve a page-aligned private virtual range without backing frames;
- map a new zeroed private range read-only or read-write;
- change a complete or partial owned range between inaccessible, read-only, and
  read-write states;
- unmap a complete or partial owned range and return its zeroed frames; and
- query the caller's granted limits, current use, and high-water accounting.

Requests and replies use exact canonical records. Addresses, byte lengths, page
counts, alignments, limits, use counters, and high-water counters are unsigned
64-bit quantities with checked conversions at architecture and collection
boundaries. Opcodes, closed protection values, flags, and page-table indices
remain narrow because their domains are intrinsically narrow.

Protection is deliberately limited to inaccessible, read-only, and read-write
private data. Write-only input is normalized to read-write by the POSIX facade.
Executable, shared, device, and file-backed mappings are unsupported. Normal
Lua, Deflate/ZIP, and zstd do not require executable memory. A future executable
mapping interface must arrive with an authenticated loader or JIT consumer and
separately resolve W^X transitions, physical aliases, instruction-cache
synchronization, code provenance, and revocation.

The heap continues to grow upward. Private mappings are selected from the high
end of a dedicated dynamic arena below the guarded stack and grow downward.
One application-owned virtual-region ledger prevents heap and mapping overlap.
Advisory address hints may improve deterministic reuse, but no operation can
replace the image, startup page, heap, guarded stack, or another live mapping.
An inaccessible reservation consumes address space and charged metadata but no
data frames.

Mapping metadata uses initially empty, fallibly grown storage. Adjacent regions
with identical logical state and compatible backing are merged. Per-process
mapping-record and metadata-byte limits plus a boot-wide metadata budget bound
fragmentation attacks and protect the owned kernel heap. The limits do not
preallocate their maximum and do not limit the byte size of one mapping.

Large backing allocations are acquired and zeroed in configured page quanta so
no contiguous-allocation search or zeroing substep scales to the total request.
The quantum is a kernel work/allocation tuning value, not a total mapping-size
limit. The current single-core call transaction remains externally atomic;
future scheduler-interleaved VM transactions may reuse the same quantum without
changing the ABI. Before publishing a successful change, the kernel reserves
required metadata and page-table resources. Ordinary allocation failure rolls
a map back to its previous externally visible state. An impossible failure
after a destructive page-table mutation terminalizes the task and follows the
complete teardown path rather than resuming a partially changed address space.

The reusable Rust runtime exposes POSIX-shaped anonymous `mmap`, `mprotect`, and
`munmap` behavior over the typed SDK without hiding the raw capability model.
It rejects unknown flags and unsupported executable, shared, fixed-replacement,
device, and file-backed requests with stable errno mappings. Safe ownership
types cover whole mappings; pointer-invalidating range operations remain
explicitly unsafe.

Application allocation uses full-width TLSF geometry on the 64-bit KEX targets.
Small and medium allocations continue to use the reusable growable heap. Large
allocations use page-aligned private mappings so freeing them can return frames
during the process lifetime. The selection threshold and heap growth quantum
are tuning values rather than functional ceilings. Allocation statistics use
explicit 64-bit byte and operation counters.

## Resource configuration

The desired operator policy lives at
`/config/system/resources/memory.toml`. Activation parses a deliberately
restricted TOML schema, rejects unknown or duplicate input, validates every
quantity as `u64`, and emits both:

1. the typed memory-policy record carried by the immutable SCFG generation and
   consumed by the kernel; and
2. deterministic normalized TOML at
   `/sys/config/system/resources/memory.toml` for inspection.

The kernel never parses TOML or trusts the projection as enforcement input.
Generation construction proves that the typed record and normalized projection
describe identical policy. Editing `/config` does not affect a running
generation.

Optional numeric limits use an explicit boolean. `limited = false` requires the
`maximum` field to be absent; `limited = true` requires a nonzero `maximum`.
There are no zero, string, or missing-field sentinels for infinity. Mandatory
fragmentation and metadata safety bounds always require a nonzero maximum.

The effective authority chain is:

```text
architectural and compiled safety boundary
    -> active system policy
        -> package resource request
            -> launcher attenuation
                -> process-private memory capability
```

Every transition may reduce authority and none may increase it. A child launch
cannot manufacture memory authority absent from its parent. Active defaults
and ceilings are visible below `/sys/config`; process-specific grants, current
use, and high-water values belong to typed process observation and `mem`.

The policy includes at least:

- a minimum free-frame reserve protected from application commitment;
- an optional boot-wide application commitment limit;
- optional default per-process committed and reserved page limits;
- mandatory default per-process mapping-record and metadata-byte limits;
- a mandatory boot-wide VM-metadata budget; and
- a nonzero page-operation work quantum.

The compiled ceilings remain reviewed safety backstops derived from virtual
address geometry, token width, metadata arithmetic, and worst-case scan cost.
They are not eagerly reserved resources and do not require an application ABI
change when raised. Initial image, stack, and heap format limits remain
separate admission bounds; their memory quantities use 64-bit representation
in the revised pre-release format.

## Failure and teardown

Policy exhaustion, global metadata exhaustion, physical-frame exhaustion,
invalid or unowned ranges, unsupported protections, checked-arithmetic
overflow, and malformed records remain distinguishable stable results. The
runtime maps them to memory-appropriate values such as `ENOMEM`, `EINVAL`,
`EACCES`, `ENOTSUP`, and `EOVERFLOW`; it does not reuse file-size errors for
memory limits.

Every committed data frame is zeroed before first visibility and before return
to the system allocator. Sparse reservations, page-table frames, backing
extents, metadata, current/high-water accounting, and pending transactions are
charged to one process owner. Cancellation, faults, normal exit, and parent
teardown revoke handles, discard pending replies, zero private frames and page
tables, and return all resources exactly once.

## Consequences

Applications can use gigabytes when address space, physical memory, and active
policy permit it without forcing the kernel to reserve gigabytes at boot.
Configuration can deliberately sandbox a process or preserve system headroom.
Mapping-count limits constrain fragmentation rather than useful byte capacity.

The kernel retains typed capability-scoped primitives and no POSIX parser,
descriptor table, allocator, or filesystem algorithm. The raw SDK remains
distinct from the higher-level runtime. This increment is a complete private
data-memory facility, not a claim of complete libc, demand paging, shared
memory, general dynamic linking, executable allocation, threads, `fork`, or
swap. The kernel CSPRNG, position-independent KEX relocation, randomized
image/stack placement, and randomized private-gap selection are implemented by
[ADR 0049](0049-kernel-csprng-and-kex-aslr.md).

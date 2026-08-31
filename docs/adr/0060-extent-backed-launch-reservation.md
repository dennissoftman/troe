# ADR 0060: extent-backed launch reservation

Status: accepted and implemented, 2026-08-31.

## Context

[ADR 0059](0059-declared-image-span-and-scaled-launch-admission.md) removed the
declared ceilings on a KEX launch and recorded the one scaling limit it
deliberately left in place: a launch reserved its image, startup page, heap, and
stack as **one physically contiguous run**. A large application therefore needed
a single long free span and could be refused under fragmentation even when
enough total frames remained. Heap growth and the
[ADR 0048](0048-capability-scoped-private-memory-and-resource-policy.md) private
mappings were already extent-based; only the initial reservation was not.

Contiguity is not something the application can observe. Its image, heap, and
stack are described by page tables the kernel owns, and every byte it addresses
is virtual. The requirement was an artifact of how the reservation was written,
not a property anything depended on.

## Decision

Reserve a launch as an ordered sequence of physical extents covering the same
logical page sequence the contiguous run produced: image pages, the startup
page, heap pages, then stack pages. Consumers keep addressing frames by logical
page or byte offset; only physical contiguity is given up.

`troe_memory::PhysicalExtents` owns the addressing rule, so it is unit tested in
the crate that owns `PhysicalRange` rather than inside the kernel binary, which
has no test harness. It offers three primitives and no closures: `run_at` for
the first contiguous run of a logical page range, `byte_run_at` for the same in
bytes, and `push`, which appends one reserved run and coalesces a physically
adjacent tail. The kernel keeps only the hardware calls and the transaction:
one loop maps a region across however many runs back it, another copies bytes
across whatever boundaries they cross.

Three bounds make the split safe rather than merely possible:

- **Extent count.** Every extent costs at least one record in a mapping plan
  bounded to `troe_memory::MAX_MAPPINGS` across kernel and application mappings
  together. A reservation is refused above `MAX_APPLICATION_EXTENTS`, so "too
  fragmented to describe" becomes the same fail-closed refusal as "not enough
  frames" instead of a failure discovered while building the plan.
- **Coalescing.** The frame allocator returns first fit, so consecutive quanta
  are usually adjacent and fold back into one extent. An unfragmented machine
  reserves exactly one extent and builds exactly the records the contiguous
  reservation built.
- **Shrink on failure.** When no run of the requested size is free, the request
  halves rather than failing, down to a single page. A launch needs only as much
  contiguity as the machine still has.

Zeroing happens as each quantum is taken, so no substep scales with the total
request and no derived range is ever published over frames that still hold a
previous owner's bytes.

Two invariants that assumed one record per region are restated in terms that
survive the split:

- **User regions describe the address space the application sees.** Every ABI
  call validates its request and reply buffers against that region list, and the
  check requires a buffer to lie wholly inside one region. Building one region
  per mapping record therefore refused a buffer that straddled a split even
  though it lay inside one mapped, uniformly permitted range. Virtually adjacent
  records with identical permissions now merge into the one region the
  application sees, and `troe_machine::planned_user_regions` applies that same
  rule so the kernel's expectation and the builder's output come from one
  definition rather than two that can drift.
  Merging also preserves the property
  [ADR 0014](0014-unprivileged-task-isolation-and-teardown.md) states, that the
  shared address-space mechanism retains at most 19 user regions: a region is
  virtually contiguous by construction, so however many extents back it, it
  merges back into one.
- **Launch admission checks coverage, not a record formula.** The expected
  record count was `segments + fixed regions`, which is no longer a function of
  the segment count. Admission now requires the built address space to reproduce
  the plan's coalesced regions exactly *and* the plan to cover exactly the
  charged private pages. Coverage is the stronger property: it catches a lost or
  duplicated page, which the record formula never did.

## Consequences

A launch now needs enough free frames, not one long free span, so an
application sized like a language runtime starts on a machine whose free memory
is fragmented. The contiguous case is unchanged in both behavior and record
count, so nothing is paid for on a machine that does not need it.

The fragmented path is exercised on every acceptance run rather than only when
memory happens to be fragmented. Production coalesces and uses the configured
operation quantum; the acceptance image takes tiny non-coalescing steps, so
every command launch is backed by several extents and drives the split mapping,
payload-copy, straddling-relocation, and buffer-validation paths. That
configuration is what found the region-validation defect above: it appeared only
once a region spanned three extents, which on an unfragmented machine never
happened.

Payload writes are bounded to their own segment. The contiguous reservation got
that bound for free, because it handed `copy_to_physical` the segment's own
physical range; addressing the whole reservation would otherwise let an overrun
spill into the next segment, the startup page, or the heap.

Physical fragmentation is now visible in the mapping plan, so a machine that
stays fragmented spends more of the bounded record budget per launch. Reducing
that pressure — a buddy allocator with order-indexed free lists in place of the
current first-fit scan, and separating single-page kernel metadata from
application extents so it stops perforating long runs — is deferred and belongs
with its own measurements.

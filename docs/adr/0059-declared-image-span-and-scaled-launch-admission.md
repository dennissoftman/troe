# ADR 0059: declared image span and scaled launch admission

Status: accepted and implemented, 2026-08-31.

## Context

Application ABI 1.1 gave every artifact the same fixed 128 MiB image window and
held its mapped image to 8,192 pages. Both numbers were launch safety maxima
chosen when the loader copied a whole artifact into kernel-owned staging, and
neither describes a resource the kernel actually owns:

- The startup page sat at `image_base + 128 MiB` for every application, so a
  four-page command reserved the same image address space as the largest
  runtime the format could express, and the guest SDK asserted that exact
  offset rather than a structural relationship.
- The 8,192-page ceiling capped a mapped image at 32 MiB. Language runtimes
  already approach that: the built CPython artifacts are roughly 7.5 MiB of
  image with a 32 MiB initial heap.
- The 32 MiB encoded-byte ceiling protected kernel staging memory that
  [ADR 0052](0052-streamed-kex-and-static-c-runtime.md) removed. Every
  production launch now streams inside a fixed working set, and the whole-slice
  parser survives only behind the `acceptance-probes` feature.
- The pre-admission charge added a flat 512 page-table pages and compared the
  total against a `resident_pages` constant that encoded the same 8,192-page
  image assumption. The native launch path already computes the exact table
  requirement from the built mapping plan and already charges it against the
  configured minimum-free reserve, so the flat figure was a second, looser
  estimate of a quantity the kernel measures anyway.

The fixed values could not simply be raised. A larger image makes the flat
table charge unsound, and it turns the single launch-time zeroing pass into a
substep that scales with the whole request, which the bounded-kernel-work rule
in [ADR 0048](0048-capability-scoped-private-memory-and-resource-policy.md)
already rejected for private mappings.

## Decision

Raise the application ABI to 1.2 and make the image span a property of the
artifact rather than of the format.

An ABI 1.2 artifact declares its image span in the previously reserved 32-bit
header field at offset 36, as a page count. The span must be nonzero, a
multiple of the 2 MiB image alignment, no greater than the 1 GiB standard
maximum, and **exactly** the image end rounded up to that alignment. An upper
bound would let an artifact reserve image address space it never maps; the
exact rule keeps the startup page directly above the image and keeps the
virtual layout derivable from the artifact alone.

ABI 1.0 and 1.1 artifacts keep the fixed 128 MiB implied span. For them the
field remains reserved and must be zero, and the canonical-span rule does not
apply, so existing artifacts continue to load unchanged.

The declared span replaces the separate mapped-image ceiling. Segments are
ordered and non-overlapping and each must end within the span, so the span
bounds the mapped page count without a second constant. `ImagePagesExceeded`
is withdrawn and `InvalidImageSpan` is added.

Both remaining aggregate charges are derived rather than fixed:

- the pre-admission page-table charge is computed from the mapped layout. One
  page-table page describes 512 entries, so each of the three levels below the
  root costs at most one page per that level's coverage, rounded up, plus one
  page per launch region for a run that does not begin on that level's
  boundary, over a shared root. The bound must hold for the largest expressible
  launch, not only for typical ones: an optimistic estimate would admit a
  launch that then fails at the exact reservation the kernel computes from the
  built mapping plan; and
- the resident-page ceiling is the maximum private page count the format can
  express plus that bound applied to it.

The guest SDK stops asserting one fixed startup offset. It recovers the
declared span from the startup page and checks that it is nonzero, aligned, and
within the standard maximum. The span itself is not independently knowable by
the guest, so this replaces an unverifiable constant with the structural
relationship and the policy bound, and keeps every other startup-page check.

Launch zeroing is bounded by the same `operation_quantum_pages` policy value
ADR 0048 applies to private mappings. Frames are zeroed in quanta at reservation
time, before any derived range is published, so no zeroing substep scales with
the total request. The preparation steps inherit zeroed frames; the streamed
loader already delivers payload bytes in fixed-size reads, so its copy work was
already bounded.

## Consequences

An artifact may now map up to 1 GiB of image, thirty-two times the former
mapped-image ceiling, and the encoded ceiling follows the span at two spans.
The binding constraint on a launch becomes available frames measured against
the configured minimum-free reserve, which the kernel already enforced.

Small applications get tighter, not looser. Every command in `/bin` declared a
128 MiB image window under ABI 1.1 and declares 2 MiB under ABI 1.2, so the
change reduces per-application image address space by a factor of sixty-four
while removing the ceiling for large ones.

Every KEX artifact is rebuilt, because the header field and the ABI minor both
change. In the shared corpus, `standard-max-span` now declares the full maximum
span in a few hundred bytes instead of sitting at the old fixed one, and
`standard-minimum-span`, `standard-large-image`, and five span rejection cases
join it. `standard-max-encoded`, `standard-max-pages`, `header-reserved32`, and
`image-pages-exceeded` are withdrawn: the encoded ceiling is no longer a
boundary worth materializing, offset 36 is no longer reserved, and the page
ceiling no longer exists. Dropping the two 32 MiB boundary artifacts takes the
corpus from 64 MB to 8.5 MB and moves its only Git LFS entry beyond the `.kefs`
assets onto the smaller `standard-large-image` pair.

One scaling limit was deliberately left in place by this decision and resolved
separately. A launch reserved its image, startup page, heap, and stack as one
physically contiguous run, so a large application needed a large contiguous
extent and could be refused under fragmentation even when enough total frames
were free. [ADR 0060](0060-extent-backed-launch-reservation.md) replaces that
reservation with coalesced physical extents and settles how many mapping-plan
records one launch may consume.

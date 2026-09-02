# ADR 0019: bounded modern virtio block transport

Status: accepted and both QEMU transports implemented, 2026-08-24. The shared
core, AArch64 `virtio-mmio`, and x86-64 q35 modern virtio PCI transports are
active and feed the same storage-activation layer. The completion bound and the
error an expiry reports are stated below as they are implemented today; an
earlier poll-count bound reported an expiry as an ordinary device failure.

## Context

Stage 8 needs a native block path after UEFI boot services end. The existing
`troe-block`, GPT, BMNT, FAT32, and ext4 crates deliberately know nothing about
device buses. The pinned QEMU profiles expose the same virtio block device model
through different transports: MMIO on AArch64 `virt` and PCI on x86-64 q35.

Virtio DMA also creates a stronger lifetime obligation than ordinary bounded
polling. If a request times out while its descriptor still names a caller's
buffer, returning from the request would let the device write after the Rust
borrow expires. A request timeout therefore cannot be treated as an ordinary
I/O error until the queue is proven dead.

## Decision

`troe-virtio` is a safe, `no_std`, transport-independent block profile based on
the [OASIS Virtio 1.3 specification](https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html).
It validates feature negotiation, immutable geometry, 512-byte sector
translation, request headers, completion status, and split-queue layout before
a bus driver receives them.

The initial profile is deliberately narrow:

- modern non-transitional devices with mandatory `VIRTIO_F_VERSION_1`;
- request virtqueue zero, an eight-entry split ring, and exactly one request in
  flight;
- direct descriptor chains containing header, optional data, and status;
- read, write, and flush requests only;
- optional device read-only, logical-block-size, segment, and flush features;
- at most 1 MiB in the single data segment; and
- no packed rings, indirect descriptors, event-index optimization, multiqueue,
  topology enforcement, discard, write-zeroes, secure erase, zoned operation,
  or force-unit-access claim.

Virtio request sectors remain 512 bytes even when the exported logical block is
4 KiB. Capacity and every request are checked for exact conversion. A device
offering flush is modeled as supporting explicit cache flush but never FUA.
Write support in this transport is mechanism only: persistent filesystem policy
continues to expose read-only mounts until mutation, dirty-state, and recovery
rules are implemented.

The first bus implementation scans only the bounded MMIO aperture supplied by
the pinned AArch64 `virt` profile. Discovery order has no mount-role meaning.
It validates magic, modern version, block device ID, stable configuration
generation, `FEATURES_OK`, queue capacity/readiness, and `DRIVER_OK` in the
required order.

The q35 implementation scans only PCI bus zero's bounded 32-by-8 function
space and accepts the modern block device identifier. It detects capability
loops and duplicates, ignores unrelated vendor capabilities, sizes referenced
memory BARs with decode disabled and exact state restoration, maps only the
page-rounded common/notify/ISR/device regions, and validates every capability
offset and length against its BAR. Initialization enables memory decode and bus
mastering, disables MSI-X vectors for the polling profile, and uses the same
feature, queue, completion, timeout, and reset contracts as MMIO.

One page-aligned allocation retains each split queue, request header, and status
for the complete initialized-device lifetime. Payloads are exclusively borrowed
identity-mapped kernel buffers; an IOMMU or non-identity DMA profile will require
an explicit mapping capability. Outer-shareable store/load barriers surround
queue publication and completion observation.

Completion polling is bounded by elapsed monotonic milliseconds, shared by both
transports, and not by a poll count. A poll count bounds guest instructions
rather than time, and under emulation nothing ties the two together: the
completion is produced by a separate host thread, so on a contended host the
vCPU can burn its whole count before that thread is scheduled at all, and a
device that was only slow is declared dead. The architected counter advances
whether or not the vCPU is scheduled, and it is established before any block
device is initialized, so a poll count remains only the fallback bound for a
boot that reports no counter.

An expiry is its own block error, not the device-reported I/O failure. The two
are different facts: a reported failure is a completed request the device says
failed, while an expiry leaves the request's outcome unknown. Filesystem
providers keep the distinction to their own callers, so an application and a
serial log can tell a slow or dead transport from a media read that failed.
On expiry, the driver resets the device and confirms reset before returning.
If reset cannot be confirmed, the kernel parks permanently because no safe
return can revoke the outstanding DMA pointer.

## Consequences

- Filesystem and partition crates remain independent of virtio and QEMU.
- MMIO and PCI share request, geometry, completion, and storage-policy
  validation while keeping discovery and register layouts separate.
- Both QEMU production images now prove native post-handoff GPT/BMNT/ext4
  selection and a read-only provider read.
- The synchronous profile is simple enough to audit but does not yet offer
  interrupt-driven throughput.
- The completion bound is a real interval, so an overloaded host slows a request
  instead of failing it. An expiry now means the queue did not answer for the
  whole budget, which is a device verdict rather than a statement about how much
  CPU the guest received.
- Enabling an IOMMU, packed queues, multiple in-flight requests, or untrusted
  device isolation requires a new DMA ownership and teardown review.

# ADR 0023: bounded virtio network and minimal protocol profile

Status: accepted for Stage 8, 2026-08-24; native transports in progress.

The first supported NIC is modern virtio-net on the existing AArch64 MMIO and
x86-64 PCI buses. The initial device profile negotiates no checksum, segment,
mergeable-buffer, control-queue, multiqueue, packed-ring, or guest-offload
features. It owns one receive and one transmit split queue, uses fixed complete
Ethernet-frame buffers, bounds every completion wait, and resets before
revoking any outstanding DMA memory.

The first configured protocol set is untagged Ethernet II, Ethernet/IPv4 ARP,
IPv4 without options or fragments, and UDP. Static address policy is sufficient
for the deterministic QEMU acceptance peer; DHCP, IPv6, ICMP, TCP, DNS, VLANs,
reassembly, routing tables, and forwarding remain later explicit increments.
Unknown protocols and features fail or are ignored within bounded work rather
than widening the parser.

Receive admission has independent frame-count, retained-byte, and per-frame
ceilings and drops newest input at capacity. Parsing checks every length before
borrowing payload bytes, verifies IPv4 and present UDP checksums, rejects
fragments and nonzero padding, and never allocates from packet-declared sizes.
Host tests include every short-frame boundary, checksum corruption, and 10,000
back-to-back frames while asserting constant retained count and bytes.

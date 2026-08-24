# ADR 0023: bounded virtio network and minimal protocol profile

Status: accepted and implemented for Stage 8; amended by the networking
usability increment, 2026-08-24.

The first supported NIC is modern virtio-net on the existing AArch64 MMIO and
x86-64 PCI buses. The initial device profile negotiates no checksum, segment,
mergeable-buffer, control-queue, multiqueue, packed-ring, or guest-offload
features. It owns one receive and one transmit split queue, uses fixed complete
Ethernet-frame buffers, bounds every completion wait, and resets before
revoking any outstanding DMA memory.

The modern transport uses the 12-byte virtio-net v1 header, including the
buffer-count field even though mergeable receive buffers are not negotiated.
Both queues contain eight entries but expose only one fixed 1,514-byte frame
buffer at a time, so a device can never create an allocation from packet data.
The AArch64 frontend uses the pinned modern virtio-MMIO aperture; q35 uses the
validated PCI common, notify, ISR, and device capabilities with bus mastering
enabled only after owned mappings become active.

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

Acceptance boots attach one architecture-private QEMU user-network NIC, resolve
the slirp gateway by ARP, and exchange a checksummed UDP request/reply with a
loopback host peer. The peer sends unrelated datagrams first. Five independent
guest processes per architecture must complete the exchange alongside durable
rollback/state recovery, and the host independently requires exactly five
requests.

The networking usability increment promotes the same device boundary into the
ordinary QEMU composition. A bounded DHCP discover/request exchange supplies
one IPv4 address, subnet mask, router, and lease; ARP replies and ICMP echo are
accepted; and a small hardware-independent capability backs replaceable
`net`, `dhcp`, `ping`, and `udp` shell commands.

The runtime-service amendment moves NIC polling behind a shared single-CPU
service checkpoint. Each checkpoint processes at most eight frames. The
service retains eight least-recently-observed ARP entries, eight persistent UDP
port bindings, and at most four datagrams/4 KiB per port, dropping newest input
at capacity. It answers local ARP and ICMP echo requests during prompt idle and
cooperative command waits. `udp send --source-port`, `udp listen`, `net stats`,
and `arp` expose that state without adding background jobs or shell loops.
Command waits use a boot-relative monotonic clock and observe Ctrl-C only at
explicit checkpoints. TCP, TLS, DNS, background jobs, and general sockets
remain explicitly deferred.

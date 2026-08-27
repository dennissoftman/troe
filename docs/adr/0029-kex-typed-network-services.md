# ADR 0029: KEX typed network services

Status: accepted and implemented for the Stage 9 network-command migration,
2026-08-25; neighbor-table capacity amended by ADR 0046.

## Decision

Network authority is split into three least-authority KEX interfaces. Interface
10 version 1.0, requested as `network-observe`, exposes only current link/IPv4
status, eleven fixed counters, and the complete cache of at most 256 typed
IPv4-to-Ethernet neighbors. Its exact canonical replies are 24 bytes for status,
88 bytes for counters, and 8 to 2,568 bytes for the bounded neighbor list.

Interface 11 version 1.0, requested as `network-configure`, performs one bounded
and cancellable DHCP discover/request exchange. Its successful reply reuses the
canonical observation status record. Interface 12 version 1.0, requested as
`icmp-echo`, performs one bounded and cancellable echo exchange from an exact
four-byte destination request and returns an exact eight-byte typed reply.

`net.kex` and `arp.kex` request observation only, `dhcp.kex` requests
configuration only, and `ping.kex` requests ICMP echo only. The kernel adapters
reuse the existing bounded ambient network state and protocol implementations;
they do not expose their internals to applications. Missing hardware reports
not-found, malformed protocol replies have a distinct status, and owner-wide
handle revocation remains the teardown boundary.

## Security and sequencing consequences

No network capability implies another. None grants raw Ethernet, packet
injection, arbitrary routes, UDP, devices, memory mapping, or machine control.
Observation cannot mutate state; DHCP and echo cannot inspect unrelated state
or persist a background operation. All request/reply sizes and retained counts
are fixed, waits contain cancellation checkpoints, and application input cannot
select a device or expand authority.

These services complete the lower-level command migration needed before TCP.
TCP remains a separate decision requiring a bounded connection state machine,
retransmission/timer policy, ownership and teardown rules, receive
backpressure, and adversarial portable tests. DNS, TLS, IPv6, raw sockets,
background jobs, and general sockets are not implied.

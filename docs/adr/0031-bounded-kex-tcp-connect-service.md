# ADR 0031: Bounded KEX TCP connect service

Status: accepted and implemented for the first Stage 9 TCP slice, 2026-08-25.

## Decision

Interface 13 version 1.0, requested as `tcp-connect`, grants one outbound TCP
connection attempt during one KEX launch. `CONNECT` accepts exactly one literal
unicast IPv4 address and one nonzero destination port and returns the selected
nonzero local port. A successful connect consumes the handle's connection
slot. `WRITE`, `READ`, and `CLOSE` then operate only on that connection; there
is no address-family, protocol, option, descriptor, or generic socket argument.

The SDK reflects that state transition. `CommandContext::tcp_connect` returns
an optional connect authority, consuming `connect` returns a typed
`TcpConnection`, and graceful `close` consumes the connection. Application
teardown aborts and removes any live connection even if the application never
closes it. Missing authority remains authoritative.

The initial wire profile is deliberately small: Ethernet II, IPv4 without
options or fragmentation, and option-free emitted TCP. For interoperability,
the private parser accepts and discards only a well-formed MSS option on SYN
segments; option values never cross the KEX boundary. It accepts only SYN, ACK,
PSH, FIN, and RST from an exact four-tuple. TCP checksums are mandatory. The
portable state machine uses exact next-sequence admission, ignores future
segments, acknowledges duplicates without redelivering bytes, rejects future
or partial acknowledgements, handles active, passive, and simultaneous close,
and treats an in-window reset as terminal.

Resource bounds are part of interface 1.0:

- at most four live TCP connections system-wide and one per `tcp-connect`
  handle;
- one at-most-1,460-byte unacknowledged transmit segment per connection;
- one 4 KiB receive FIFO per connection, with no out-of-order queue;
- a four-attempt retransmission schedule of 250, 500, 1,000, and 1,000 ms;
- a four-second cancellable bound for connect, write, read, and graceful close;
- no application-controlled or negotiated TCP options, urgent data, IP
  fragmentation, window scaling, selective acknowledgement, keepalive,
  background operation, or connection persistence after owner teardown.

The receive window is the remaining FIFO capacity. A segment that is ahead of
the exact next sequence or does not fit is not retained and elicits a current
acknowledgement. Reads reopen the window and cause an acknowledgement. Writes
respect the peer's unscaled advertised window and complete through bounded
single-segment acknowledgements. Exhaustion drops no retained application data
and cannot grow a queue.

Initial sequence values are supplied by the kernel from boot-relative time,
the device address, and a per-boot connection generation. This is sufficient
for the current bounded emulator profile but is not cryptographic entropy;
deployment on hostile routed networks requires a separately reviewed entropy
source before TCP is treated as spoof-resistant.

## Security and sequencing consequences

`tcp-connect` grants neither `datagram`, `network-observe`,
`network-configure`, nor `icmp-echo`, and none of those grants TCP. The service
does not expose Ethernet addresses, ARP, routes, raw IPv4/TCP headers, device
selection, packet injection, or DMA state. It performs neighbor resolution and
packet construction inside the kernel and copies only bounded byte streams
across the existing call gate.

Names are not accepted, so this interface grants no DNS authority. Bytes are
not interpreted as HTTP or TLS, and the service grants no certificate, secret,
or clock authority. It is a typed TCP byte-stream service, not a TLS service.

Inbound bind/listen/accept is intentionally absent. It requires a distinct
`tcp-listen` authority, explicit local-port ownership, SYN-backlog and accept
queue bounds, and a separate denial-of-service review. Adding it later must not
widen interface 13 into a general socket API.

Portable adversarial tests are the acceptance gate for sequence, flag,
duplicate, reset, close, retransmission/timeout, tuple-isolation, and
receive-window transitions. ABI tests gate every truncation, trailing byte,
reserved field, zero port, non-unicast address, and payload ceiling. Native
QEMU verification must additionally prove connect, transfer, cancellation, and
zero live connections after application teardown before a command relies on
this service.

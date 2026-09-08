# TCP listener interface v1.0

KCAP capability `tcp-listen` selects interface 29, major 1, minor 0, with
CALL rights. It is application-facing and independent of `tcp-connect`,
`datagram`, and network configuration authority. Foreground, background, and
resident application launches grant it only when declared. Child launches
must attenuate their parent's capabilities.

One handle owns one local IPv4 port on the configured interface. Port zero
selects an unclaimed ephemeral port in 49152 through 65535. An existing
listener or connection, including a retained tuple, prevents another owner
from claiming its port. A handle cannot listen twice. There is no wildcard
address, DNS, TLS, raw packet access, route control, or generic socket API.

All integers below are little-endian; IPv4 addresses are four bytes in display
order. Requests and replies have exact sizes unless explicitly variable.
Malformed fields, trailing bytes, zero connection IDs, and unknown opcodes
return `InvalidRequest`. Unknown or retired IDs return `NotFound`.

| Opcode | Request | Successful reply |
| --- | --- | --- |
| 1 LISTEN | u16 port, u8 backlog, u8 reserved zero | u16 resolved nonzero port |
| 2 ACCEPT | empty | u16 connection ID, four-byte peer IPv4, u16 peer port |
| 3 WRITE | u16 connection ID, 1–1460 payload bytes | empty, after acknowledgement |
| 4 READ | u16 connection ID, u16 nonzero requested count | up to the requested count; zero is orderly EOF |
| 5 CLOSE | u16 connection ID | empty, after graceful close |

READ is bounded by `MAX_SERVICE_PAYLOAD_BYTES`. ACCEPT and stream operations
have a four-second cancellable deadline. A timed-out ACCEPT leaves the
listener bound. An occupied requested port returns `Conflict`; unavailable
capacity returns `Exhausted`; absent IPv4 configuration returns
`NotConfigured`. Transport failures use the common network reply statuses.
Receiving peer EOF leaves the sending half available for a response.
CLOSE retires the identifier even on failure. Connection IDs are scoped to
one handle and monotonically allocated without wraparound.

The system permits two listeners, backlog 1 through 4 per listener, and eight
accepted streams per handle. The shared sixteen-connection limit includes
active connections, half-open and completed backlog entries, accepted streams,
and retained tuples. Full capacity drops new SYNs while existing handshakes
continue. Each connection has one 1460-byte unacknowledged segment and a 4 KiB
receive FIFO. Retransmission and exact tuple/sequence admission follow the
portable TCP state machine.

Runtime checkpoints process pending emissions and retained-tuple expiry.
An active closer retains its tuple for four seconds; passive close can reclaim
it immediately. Teardown aborts live accepted streams and releases the
listener and its backlog. Previously gracefully closed connections remain in
the ambient table until their protocol state permits reclamation.

The Rust SDK exposes `CommandContext::tcp_listen()` and `TcpListen` methods
`listen`, `accept`, `write`, `read`, and `close`. ACCEPT returns the connection
identifier and peer record used by subsequent stream calls.

Verification uses the ABI exact-encoding tests, SDK startup-authority tests,
portable TCP state-machine tests, native kernel compilation/lint, and the
changed-file gate's network acceptance scenario. The existing QEMU scenario
exercises outbound TCP and shared stream operations; inbound host-to-guest
listener acceptance is not covered by that scenario.

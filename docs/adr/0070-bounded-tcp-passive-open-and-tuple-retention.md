# ADR 0070: bounded TCP passive open and tuple retention

Status: accepted and implemented. Application access is defined by the
[TCP listener v1 contract](../formats/tcp-listen-v1.md). Interface 29 grants
independent `tcp-listen` authority; statements below about an absent KEX
listener describe the original state-machine-only decision.

## Context

[ADR 0031](0031-bounded-kex-tcp-connect-service.md) implemented one bounded
outbound TCP byte stream and named the reason inbound service was left out:
"Inbound bind/listen/accept is intentionally absent. It requires a distinct
`tcp-listen` authority, explicit local-port ownership, SYN-backlog and accept
queue bounds, and a separate denial-of-service review."

Two of those prerequisites are protocol decisions rather than authority
decisions, and neither belongs in the kernel binary, which has no test harness:

- **The passive handshake itself.** `TcpConnection` had one constructor,
  `connect`, and its state set began at `SynSent`. There was no state in which
  an admitted inbound SYN has been answered and awaits the peer's final
  acknowledgement, so no inbound connection could exist to grant authority
  over.
- **Tuple reuse safety.** The active closer transitioned straight to `Closed`
  once the peer's FIN arrived. A server is normally the side that closes, so a
  connection's four-tuple became immediately reusable while the peer could
  still retransmit a FIN into it. Outbound-only use hid this: the client
  selected a fresh ephemeral port for each connection, and the four-connection
  ceiling made reuse within one boot unlikely.

Both are adversarial state-machine problems with exact sequence, flag, and
duplicate rules. They are decided and tested here, in `troe-net`, before any
authority is granted.

## Decision

### Passive open

`TcpConnection::accept` answers one admitted inbound SYN. The connection starts
in the new `SynReceived` state with a pending SYN+ACK on the existing bounded
retransmission schedule, so a silent client expires through the same four
attempts and 2,750 ms as any other unacknowledged segment. It reaches
`Established` only on a segment that has ACK without SYN, acknowledges exactly
the SYN+ACK, and carries exactly the next expected sequence.

Two adversarial cases are decided explicitly:

- A **retransmitted inbound SYN** for a queued tuple is a duplicate answered by
  the pending SYN+ACK. It never opens a second connection, and a SYN reusing
  the tuple with a different sequence is refused rather than rebinding the
  connection.
- A **final acknowledgement carrying payload or FIN** is retained. The
  handshake completes and the same segment is then processed through the
  established path, so a client that pipelines its complete request onto the
  final ACK loses no bytes. This is the common HTTP request shape, not an edge
  case.

### Listener ownership

`TcpListener` owns one local endpoint and every connection between an admitted
SYN and its acceptance. Placing the queue here, rather than in the kernel's
connection table, keeps the complete passive handshake portable and adversarially
testable without a kernel.

The queue is the denial-of-service containment point. A full backlog drops
further inbound SYNs rather than growing anything, and one client's reset,
malformed segment, or silence terminates only its own connection: a listener
never fails because a client misbehaved. `poll_accept` returns the oldest
connection whose handshake completed, including one whose peer already sent its
request and FIN, and never returns a half-open, reset, or timed-out connection.

The listener deliberately does not emit RST. The profile accepts RST from a
peer but has never transmitted one, and a listener that answered stray segments
with RST would become a reflection amplifier. An unmatched segment is ignored,
so a closed port is silent.

### Bounds

- at most `MAX_TCP_LISTENERS` (2) owned listening endpoints;
- at most `MAX_TCP_BACKLOG` (4) passive opens queued per listener, refused at
  the ceiling rather than queued;
- `MAX_TCP_CONNECTIONS` raised from 4 to 16, now spanning accepted connections,
  half-open passive opens, and tuples still retained after close together. The
  previous ceiling could not hold even one full backlog, and 2 listeners times
  4 queued opens plus 8 accepted connections fits within it. Worst-case
  preallocation is 16 receive FIFOs, 64 KiB, against the 32 MiB kernel metadata
  budget in `config/system/resources/memory.toml`;
- `TCP_TIME_WAIT_MILLISECONDS` is 4,000.

The system-wide ceiling spans listeners and accepted connections together, but
`TcpListener` sees only its own endpoint. Its owner enforces the total; this
crate enforces the per-listener bound.

### Tuple retention

The active closer enters the new `TimeWait` state instead of `Closed`, from
`FinWaitTwo` on the peer's FIN and from `Closing` on the acknowledgement of its
own FIN. The passive closer still reclaims immediately from `LastAck`, which is
correct: it is not the side that can have a delayed FIN arrive.

`TimeWait` retains the tuple, still acknowledges a retransmitted FIN, reports
orderly end of stream to a reader, and admits no further application
operation. The interval begins at the first emission poll after the transition
and ends by reclaiming the tuple.

The interval is 4,000 ms, not the conventional two maximum segment lifetimes.
This is a deliberate bounded-profile deviation with a stated basis: it covers
the complete 2,750 ms retransmission schedule, which is the longest a peer's
delayed final FIN can take in this profile, so no delayed segment can arrive
after the tuple has been reused. A conventional 60-second interval would hold
tuples for fifteen times the longest possible retransmission and would exhaust
the sixteen-connection budget under ordinary serving. The deviation is sound
only because every retransmission bound here is fixed and small; it would not
be sound on a general routed network with unbounded segment lifetime.

## Security and sequencing consequences

This ADR grants no authority. It raises no application ceiling other than the
outbound connection count, adds no interface, and changes no manifest
capability. An application still cannot bind, listen, or accept, because no KEX
interface exposes `TcpListener`.

Passive open widens the attack surface of the protocol layer specifically: a
listener admits segments from peers this machine never contacted, whereas
`tcp-connect` only ever admitted an exact tuple it had itself chosen. The
containment answer is the bounded backlog, per-connection failure isolation,
silence rather than RST, and the same exact-tuple and next-sequence admission
the outbound profile already enforced. Initial sequence values are still
supplied by the owner, and ADR 0031's caveat is unchanged and now more
load-bearing: they are derived from boot-relative time, the device address, and
a per-boot generation, which is not cryptographic entropy. A listening service
on a hostile routed network needs the separately reviewed entropy source that
ADR named before it can be treated as spoof-resistant.

Portable adversarial tests are the acceptance gate for passive establishment,
retransmitted and tuple-reusing SYNs, handshake-carried payload and FIN,
backlog exhaustion and slot reuse, per-connection reset and SYN+ACK timeout
isolation, active close, simultaneous close, passive close, and the retention
interval's start, refusal, and expiry.

Granting an application listen authority remains a separate decision. It must
add a distinct interface with explicit local-port ownership, an accept queue
whose depth an application cannot expand, a resident-process lifetime for a
server that outlives one shell dispatch, and its own denial-of-service review.
DNS, TLS, IPv6, raw sockets, and general sockets remain out of scope.

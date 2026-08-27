# ADR 0025: KEX owned datagram service

Status: accepted and implemented for the Stage 9 application-networking slice,
2026-08-25; binding-table capacity amended by ADR 0046.

## Decision

An application may receive one optional ABI 1.0 datagram handle in addition to
the four command/stream handles from ADR 0024. Absence is authoritative: the
SDK reports missing authority and the app cannot discover or access the network
device by another path. Interface 5 exposes only synchronous IPv4/UDP `send`
and cancellable `receive`; it is not a POSIX socket or raw-packet interface.

Every request and reply is allocation-free at the ABI boundary and canonical.
`send` carries an optional source port, destination IPv4 address and nonzero
port, and at most 1,472 payload bytes; its exact reply is the selected nonzero
source port. `receive` carries one nonzero local port and returns the source
address, source port, and bounded payload. A receive has a four-second hard
deadline and returns the stable timeout status if neither a datagram nor
cancellation arrives. General service statuses distinguish invalid input,
exhaustion, absent configuration, cancellation, timeout, ownership conflict,
and oversize input.

The per-launch service exclusively claims each requested or selected local port
before use. A second owner cannot reuse an existing binding. Claims are bounded
by the platform's 16,384-port ceiling and reuse the existing four-datagram/4 KiB
per-port drop-newest queues. `receive` waits through the existing cooperative
runtime checkpoint so network interrupts make progress, Ctrl-C returns the
stable cancelled status, and the hard deadline is observed. Dropping the launch
dispatcher unbinds every claimed port and discards retained datagrams before
the shell resumes.

The repo-local SDK exposes `CommandContext::datagram`, fixed receive storage,
and typed `send`/`receive` methods. `apps/udp` is the first replacement app.
Both native targets must prove an application send, cancellable receive, and a
zero live-port count after each command. ADR 0030 later removed the temporary
absent-artifact fallback.

## Security and sequencing consequences

Applications receive no MAC address, ARP cache, DHCP control, raw frames, route
mutation, device registers, DMA memory, or ambient global socket namespace.
The service copies bounded messages, validates exact encodings, resolves ARP
inside the kernel, and tears ownership down with the isolated launch. The
single foreground-app model means synchronous waiting does not imply a general
blocking-thread contract.

This closes the datagram ownership, backpressure, wait/cancellation, and
teardown prerequisites identified by ADR 0024. TCP is still a separate design:
it must add bounded connection state, retransmission and timer rules, sequence
validation, listen/accept ownership, half-close semantics, and adversarial
state-machine tests without widening this datagram handle into a generic socket
escape hatch. DNS, TLS, IPv6, background jobs, and asynchronous polling remain
out of scope.

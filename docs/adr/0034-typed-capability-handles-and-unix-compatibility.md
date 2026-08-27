# ADR 0034: typed capability handles

Status: accepted and implemented for current KEX services, 2026-08-26.

## Context

Traditional Unix places files, pipes, terminals, sockets, devices, and event
sources behind integer descriptors. That vocabulary is compact, but it erases
object type and encourages generic escape hatches and ambient discovery. TROE's
implemented services already use versioned interfaces, opaque tokens, explicit
grants, and owner-scoped teardown.

## Decision

TROE unifies handle mechanics, not unrelated object semantics. Shared mechanics
include:

- opaque slot-plus-generation identity;
- interface type and version validation;
- explicit owner and authority provenance;
- bounded resource charging;
- close, cancellation, wakeup, and terminal transitions;
- exact revocation and teardown; and
- no kernel pointers or provider-private representation in application memory.

The native ABI preserves each object class's semantics:

| Object | Native semantic surface |
| --- | --- |
| byte stream | ordered reads and writes, EOF, and type-specific close rules |
| regular file | offset reads, metadata, and separately granted mutation |
| directory | relative lookup and bounded lexical enumeration |
| datagram endpoint | message-preserving send and receive with endpoint metadata |
| timer or wait source | typed completion or wake reason |
| system control | explicit versioned operations, never stream I/O by convention |

Only genuine byte streams share stream operations. The native ABI has no
universal file-descriptor syscall family, generic socket constructor, or
open-ended `ioctl`, `fcntl`, or socket-option channel. A new operation receives
a typed interface version, bounded canonical encoding, explicit authority, and
its own lifecycle and adversarial review.

Current filesystem, mutation, UDP, TCP-connect, timer, diagnostics,
network-observation, DHCP, and ICMP services follow this rule. Their common
ownership and teardown machinery does not make their protocols interchangeable.

## Consequences

- SDK types reject many wrong-object operations before an ABI call.
- Package manifests describe actual authority rather than entry into a generic
  descriptor namespace.
- Shared lifecycle and wait machinery does not require one universal operation
  table.
- The current command filesystem service remains a command-environment grant,
  not a general package-scoped directory contract.
- Scoped package roots are tracked in
  [GitHub issue #6](https://github.com/dennissoftman/troe/issues/6).
- An optional userspace BSD/POSIX facade is not implemented; its value and cost
  are tracked in
  [GitHub issue #11](https://github.com/dennissoftman/troe/issues/11).

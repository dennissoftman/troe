# ADR 0034: Typed capability handles and optional Unix compatibility

Status: accepted direction, 2026-08-26. Existing KEX filesystem, datagram, TCP,
timer, diagnostics, and network-control services conform to the typed-interface
rule. Scoped directory roots, heterogeneous waits, listeners, and any Unix
compatibility facade remain later work under their own acceptance gates.

## Context

Traditional Unix gives files, pipes, terminals, sockets, devices, and many
event sources integer file descriptors. This makes a small set of operations
composable, but erases object type and tends to accumulate generic escape
hatches such as `ioctl`, `fcntl`, socket option namespaces, and ambient path or
network discovery.

TROE already has a different foundation: startup grants versioned interfaces,
operations use opaque generation-checked tokens, and owner teardown revokes the
objects created for one application. The filesystem, UDP, TCP, diagnostics,
timer, and network-control ABIs deliberately remain separate. That repeated
choice needs one architectural rule so future listeners, files, timers, waits,
devices, and compatibility work do not accidentally introduce a universal
descriptor ABI.

## Decision

TROE unifies **handle mechanics**, not unrelated object semantics.

Common mechanics may include:

- opaque slot-plus-generation identity;
- interface type and version validation;
- explicit owner and authority provenance;
- bounded resource charging;
- close or consuming state transitions;
- cancellation, wakeup, and terminal status;
- exact revocation and teardown; and
- no exposure of kernel pointers or provider-private representation.

The native ABI preserves the semantics of each object class:

| Object | Native semantic surface |
| --- | --- |
| byte stream | ordered reads and writes, EOF, and type-specific close rules |
| regular file | offset reads, metadata, and separately granted mutation |
| directory | relative lookup and bounded lexical enumeration |
| datagram endpoint | message-preserving send and receive with endpoint metadata |
| listener | bounded accept producing a new typed stream capability |
| timer or wait source | typed completion or wake reason |
| system control | explicit versioned operations, never stream I/O by convention |

Only objects that are genuinely byte streams share stream operations. A
datagram is not flattened into bytes, a directory is not read as an encoded
buffer, and system control does not become a magic file operation.

The native ABI will not add a universal integer file-descriptor syscall family,
generic `socket(domain, type, protocol)` creation, or open-ended `ioctl`,
`fcntl`, or `setsockopt`-style extension channels. A new operation receives a
typed interface version, a bounded canonical encoding, explicit authority, and
its own lifecycle and adversarial review.

### Filesystem authority

Package-managed applications should receive scoped directory capabilities for
declared roots such as `assets`, `data`, or one resolved configuration view.
Lookup and mutation are relative to those roots. An absolute path names an
object in a namespace but does not by itself grant authority to reach it.

ADR 0026's current `filesystem-read` service borrows the launching shell's live
namespace and roots relative resolution at the startup working directory. That
is an implemented command-environment slice, not a promise that every future
package receives ambient access to the complete namespace. Package activation
must resolve each declared filesystem grant to explicit roots before launch.
Read, mutation, mount, provider, block, and device authority remain separable.

### Network authority

Byte-stream connection, datagram ownership, inbound listening, observation,
configuration, ICMP, DNS, TLS, and raw-packet access remain distinct grants.
For example, a TCP connection may implement the byte-stream surface after a
typed connect operation, but possession of it grants neither UDP nor network
configuration. A future listener returns owned connection capabilities and
does not widen the outbound-connect interface into a generic socket.

### Waiting and compatibility

A bounded wait mechanism may observe heterogeneous handles because waiting,
cancellation, and teardown are common mechanics. Wake conditions and results
remain closed and typed for each registered object; a wait facility does not
turn those objects into one semantic type. ADR 0032 continues to own the
unsettled scheduler-visible wait contract.

A documented BSD/POSIX subset may later be supplied as an optional userspace
SDK or runtime facade. It may map familiar descriptor, `read`, `write`, socket,
and polling calls onto native typed capabilities, but it is not the kernel ABI
and cannot manufacture authority absent from the package manifest. Unsupported
operations fail explicitly. Compatibility cost is charged to packages that
select it rather than every application or the recovery system.

## Inspiration boundary

TROE selectively borrows:

- Linux's common VFS object and `*at`-style directory-relative operation ideas;
- BSD's compact stream/socket vocabulary and `kqueue` event-notification
  lessons; and
- FreeBSD Capsicum's capability-oriented scoped and rights-reduced handles.

These are design inputs, not compatibility claims. Native interfaces remain
TROE-specific, typed, bounded, versioned, and capability-granted.

## Consequences

- SDK types can prevent many wrong-object operations before an ABI call.
- Package manifests describe real authority instead of permission to enter a
  generic descriptor or socket namespace.
- Shared lifecycle and wait machinery can be implemented once without placing
  every object behind one operation table.
- Ported software may require an explicit compatibility runtime and may not
  receive every historical Unix operation.
- The current broad command filesystem capability must evolve into scoped roots
  before it is treated as the general package filesystem contract.

## Rejected alternatives

- **A Linux/POSIX-style universal descriptor ABI:** compact at first, but loses
  type and authority information and encourages generic extension channels.
- **The BSD socket API as the native kernel contract:** useful compatibility
  vocabulary, but address families, protocol selection, options, and control
  operations would collapse TROE's independent network authorities.
- **Everything represented as files:** namespace composition is useful, but
  encoding datagrams, listeners, timers, and control protocols as byte files
  obscures their invariants.
- **Entirely unrelated lifecycle machinery per object:** preserves type but
  duplicates ownership, generation, cancellation, accounting, and teardown
  rules that must remain consistent system-wide.

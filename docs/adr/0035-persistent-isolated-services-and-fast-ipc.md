# ADR 0035: Persistent isolated services and fast protected IPC

Status: proposed implementation contract, 2026-08-27. Nothing in this ADR is
implemented or accepted merely because the document exists. Acceptance requires
every phase and gate below, including the dependency-removal and native
performance gates.

## Context

TROE has reached the point where its portable components are service-shaped but
its native composition is not yet a microkernel boundary. The kernel image still
links the VFS namespace, KEFS/RAMFS, FAT32, ext4, StateFS, volume activation,
identity/content policy, and the complete ARP/IPv4/UDP/DHCP/ICMP/TCP state. A
fault in any of that Rust code therefore retains kernel privilege even though
applications can reach it only through typed capabilities.

ADR 0032 established blocked tasks, pending calls, owned suspended contexts,
timer/UDP wakeups, and one isolated diagnostics server. That server is launched
for one request and exits. The protected measurement path currently performs
two request-payload copies and two reply-payload copies per nonempty fragment,
reloads task roots with full TLB invalidation, and programs a fresh execution
lease for every user execution segment. Those costs are explicit and safe, but
they are not an acceptable steady-state design for storage and networking.

This ADR defines the complete transition to persistent, independently scheduled
servers while retaining copied message isolation. It intentionally separates
format and protocol policy from device mechanism:

```text
applications and kernel clients
             |
             | typed synchronous capabilities
             v
      VFS/storage server -------------------- network server
             |                                      |
             | exact block-region handles           | packet-device handle
             v                                      v
      kernel block broker                    kernel packet broker
             |                                      |
             v                                      v
         virtio-block                           virtio-net
```

The initial storage migration may put namespace, volume selection, and all
filesystem providers in one server so removing privileged parsers does not first
depend on nested service IPC. The accepted end state permits a VFS/volume server
and per-mount provider servers, using the same bounded call mechanism.

## Goals

This decision has six inseparable goals:

1. remove filesystem formats, namespace policy, and network protocols from the
   privileged kernel address space;
2. retain typed, generation-checked, least-authority application interfaces;
3. make the common protected call path allocation-free with one payload copy in
   each direction and no full TLB invalidation;
4. support persistent servers, service-to-service calls, blocking device events,
   exact cancellation, and contained server faults;
5. preserve the existing single-CPU, bounded-resource, W^X, execution-lease,
   and transactional-teardown guarantees; and
6. prove that the protection boundary does not become the limiting factor for
   the accepted virtio storage and network profiles.

## Non-goals

This ADR does not add SMP, general preemption, demand paging, arbitrary shared
memory, universal file descriptors, capability transfer inside arbitrary
messages, dynamic linking, a general socket API, an IOMMU, or userspace DMA
drivers. It does not weaken the 50 ms execution lease. It does not promise that
a crashed writable filesystem operation is rolled back or transparently
retried.

Driver isolation is deliberately later. A userspace process that can program an
unrestricted DMA descriptor is able to address physical memory unless an IOMMU
or an equally strong kernel-controlled mapping discipline prevents it. Until a
separate DMA ADR is accepted, virtio queue programming, interrupt
acknowledgement, reset, and DMA-buffer lifetime remain kernel mechanisms.

## Target kernel boundary

After this ADR closes, the kernel may contain only:

- boot entry, platform discovery, interrupt and timer mechanisms;
- physical memory, page tables, address-space tags, W^X, and task contexts;
- the scheduler, waits, endpoints, capability tables, and copied IPC fast path;
- KEX/package validation, mapping, execution, and exact teardown;
- immutable boot-artifact lookup by fixed role, without filesystem parsing;
- bounded block and packet device brokers over kernel-owned virtio DMA queues;
- console/input mechanisms, machine lifecycle, and allocation-free fatal output;
  and
- narrow kernel-client continuations required by the current native shell and
  loader until those policies are separately moved to user processes.

The kernel must not link or instantiate `troe-vfs`, `troe-ext4`, `troe-fat`,
`troe-statefs`, `troe-storage`, `troe-gpt`, `troe-mount`, `troe-persist`,
`troe-config`, `troe-content`, `troe-identity`, or `troe-net`. It must not parse
a filesystem superblock, resolve a path, maintain a mount table, interpret a
partition/mount/generation format, parse an Ethernet/IP packet, own a port or
TCP connection, or perform DHCP/ARP policy.

`troe-block`, the transport-independent virtio mechanism, application/ABI
validation, dispatch/task/memory code, and `troe-machine` may remain kernel
dependencies. GPT, BMNT, PRGN, persistence, content-generation, configuration,
and identity policy move to the storage service by the final phase.

## Standard bounded runtime

The first implementation uses one immutable Standard profile. Construction
must reserve all steady-state metadata before any server becomes ready.

| Resource | Standard hard ceiling |
| --- | ---: |
| Live scheduler records | 16 |
| Persistent isolated servers | 8 |
| Live service endpoints | 16 |
| Live capability handles system-wide | 256 |
| Handles owned by one task | 32 |
| Live endpoint-scoped client badges | 256 |
| Client badges at one endpoint | 32 |
| Simultaneous pending synchronous calls | 32 |
| Pending calls queued at one endpoint | 8 |
| Retained queued request bytes system-wide | 128 KiB |
| Request or reply payload | 4 KiB |
| Nested user call-chain members | 4 |
| Wait sources in one immutable wait set | 4 |
| Published waits system-wide | 32 |
| Private IPC pages per isolated task | 2 |
| Preallocated kernel IPC clients | 4 |
| Maximum client call lifetime | 4,000 ms |
| Boot-service roles | 4 |
| Encoded package bytes per boot service | 4 MiB |
| Aggregate encoded boot-service bytes | 8 MiB |
| Aggregate persistent-server resident pages | 8,192 (32 MiB) |

An endpoint may select a smaller queue, retained-byte, or deadline ceiling at
construction. It may not enlarge a ceiling after publication. Capacity failure
is atomic and returns a typed exhausted result before service delivery.

The 32 queued payload slots account for the complete 128 KiB maximum. Direct
handoff does not consume a queued payload slot. Queue storage is zeroed before
reuse; its allocation and zeroing cost is outside the direct fast path.

Each boot service record also fixes a resident-page/heap-growth ceiling that the
ordinary unbounded-until-physical-exhaustion application policy cannot widen.
The initial network server is limited to 1,024 resident pages (4 MiB), the
combined VFS/storage server to 4,096 pages (16 MiB), and a later provider server
to 2,048 pages (8 MiB). Code, data, startup, IPC, heap, stack, and page-table
ownership are all charged. The aggregate 8,192-page ceiling applies before any
server starts. Exceeding a service quota returns heap exhaustion without
affecting another task; an internal partial mapping failure remains terminal.

## Task IPC pages

Application ABI 1.2 adds two private 4 KiB IPC pages to every isolated task:

- `ipc_tx`: user RW/NX, containing the exact outbound payload; and
- `ipc_rx`: user RW/NX, receiving the exact inbound payload.

For ABI 1.2 layouts, the two pages follow the immutable startup page and precede
the heap. The heap base moves upward by two pages only for an artifact requiring
ABI minor 2. ABI 1.0 and 1.1 layouts and calls remain valid and retain their
existing addresses. The ABI 1.2 startup header grows in a versioned form and
publishes both IPC addresses. It never publishes a physical address.

The ABI 1.2 startup page has this exact fixed prefix; initial 24-byte handle
records begin at byte 80 rather than byte 64:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | exact encoded startup bytes |
| 4 | 2 | ABI major, still 1 |
| 6 | 2 | ABI minor, exactly 2 |
| 8 | 4 | base page bytes, exactly 4,096 |
| 12 | 2 | flags/reserved, zero |
| 14 | 2 | initial handle count |
| 16 | 8 | KEX image base |
| 24 | 8 | heap base |
| 32 | 8 | initially mapped heap bytes |
| 40 | 8 | stack bottom |
| 48 | 8 | stack top |
| 56 | 8 | nonzero task identity |
| 64 | 8 | `ipc_tx` virtual address |
| 72 | 8 | `ipc_rx` virtual address |

If `startup` is the existing image-base-plus-128-MiB address, `ipc_tx` is
`startup + 4 KiB`, `ipc_rx` is `startup + 8 KiB`, and the ABI 1.2 heap begins at
`startup + 12 KiB`. Every addition and the complete heap/guard/stack layout are
checked exactly as for ABI 1.1. The encoded length is `80 + 24 * handle_count`;
all remaining startup-page bytes are zero. ABI 1.0/1.1 retain their 64-byte
prefix and handle offset.

The two IPC frames come from a permanently reserved pool of 32 pages in the
owned boot arena: two pages for each of the 16 task slots. They are mapped once
through the boot arena's existing supervisor-only identity mapping in every
task root and mapped user-accessible only at the owning task's two IPC virtual
addresses. No task receives a user mapping for another slot. Consequently, the
kernel can copy between any two IPC pages using supervisor aliases while
remaining under either task root; the peers never share a user mapping.

Adding the contiguous two-page IPC mapping raises the retained user-region
ceiling from 19 to 20: sixteen KEX load records plus startup, IPC, heap, and
stack regions. The compile-time equality between the loader maximum and native
region storage must be updated and tested. The IPC aliases are RW/NX normal
memory on both sides and must pass the existing global W^X alias checks.

IPC pages are zeroed before first publication, after terminal task transition,
before task-slot reuse, and in every partial launch rollback. They are retained
by the task record until handles, pending calls, waits, and address-space state
have been revoked. A stale task or address-space generation can therefore
neither address nor receive data from a reused slot.

The four kernel IPC clients each own a separate preallocated TX/RX pair in the
boot arena. Those pages have no user mapping and are not part of the 32-page
isolated-task pool. The complete IPC reservation is therefore 40 pages
(160 KiB). A kernel client retains a typed enum continuation and scalar offsets,
never a suspended Rust frame, borrow, trait-object reference, or raw pointer.

## ABI 1.2 calls

ABI 1.2 adds two calls without changing ABI 1.0/1.1 operations.

### `ipc_call`

Call number 4 is:

```text
ipc_call(handle, opcode, request_bytes, reply_capacity, deadline_millis,
         object_parameter)
    -> (service_status, reply_bytes)
```

The request is the first `request_bytes` of `ipc_tx`; a successful reply is
written to the first `reply_bytes` of `ipc_rx`. Both lengths may be zero and may
not exceed 4 KiB. The deadline is an absolute boot-relative monotonic value and
must not exceed the endpoint's ceiling or 4,000 ms from admission. Ordinary
clients may not request an unbounded deadline.

The kernel validates the handle owner, call right, endpoint generation,
interface version, opcode scalar, both lengths, deadline, call-chain depth, and
available pending-call accounting before copying or publishing any state.
`object_parameter` must be zero for a user service endpoint. Kernel object
interfaces may assign it one exact scalar meaning, such as a relative block LBA
or immutable blob offset, so a complete 4 KiB data payload does not lose bytes
to a transport header.

Noncanonical lengths/scalars, a forged or foreign handle, wrong rights, an
illegal object parameter, and an impossible reply capacity retain the existing
contained invalid-call fate. A valid live call that encounters queue/system
capacity, a detected call cycle, or a deadline returns the typed transport
result without delivery. Service opcode/payload rejection remains an ordinary
typed service reply.

### `ipc_reply_wait`

Call number 5 is available only to a server that owns the wait-set handle and
the receive/reply handle for every endpoint source in that wait set:

```text
ipc_reply_wait(wait_set, token, status, reply_bytes, deadline_millis)
    -> receive event
```

When `token` is nonzero, the first `reply_bytes` of the server's `ipc_tx` is the
reply to that exact delivered call. The kernel validates and consumes the token
exactly once. `token == 0` is valid only when the task owns no delivered inbound
call; `status` and `reply_bytes` must then be zero. This form performs the
server's initial wait or waits after a one-way device event.

`deadline_millis` applies to the newly published wait, never retroactively to
the reply identified by `token`. `u64::MAX` means that the resident server has
no idle-wait deadline; ordinary client calls may not use that value. A finite
deadline at or before the current monotonic value produces an immediate
deadline event without publishing a blocked task.

Reply completion and wait publication are one atomic kernel transition. A
client can never observe a completed reply while the server still appears busy,
and an event becoming ready during publication cannot be lost.

The returned event uses six architecture result registers. ABI 1.2 documents
these call-specific clobbers; every other application-visible register remains
preserved. The fields are:

1. closed event kind: endpoint call, resource ready, deadline, closed, or
   revoked;
2. generation-checked call token, or zero for a non-call event;
3. packed immutable wait-set source index and endpoint-scoped client badge;
4. packed interface and opcode for a call event;
5. exact request payload bytes; and
6. maximum reply payload bytes accepted by that client.

For a call event, the kernel has copied the request into `ipc_rx` before the
server resumes. Metadata does not consume payload bytes, so the complete 4 KiB
service payload remains available. The server SDK exposes a typed event rather
than raw registers.

Event kinds are fixed as zero-invalid, 1 endpoint-call, 2 resource-ready,
3 deadline, 4 closed, 5 revoked, and 6 client-closed. In the third result word,
bits 0–15 contain the source index, bits 16–31 are zero, and bits 32–63 contain
the client badge; non-client events carry badge zero. In the fourth word, bits
0–31 contain the interface ID, bits 32–47 contain the opcode, and bits 48–63 are
zero. Non-call events carry zero interface, opcode, request bytes, and reply
capacity.

On x86-64, `ipc_reply_wait` returns those six words in `RAX`, `RDX`, `RDI`,
`RSI`, `R8`, and `R9`. On AArch64 it returns them in `X0` through `X5`. The new
call preserves every other ABI-visible register. `ipc_call` retains the normal
two-result `RAX`/`RDX` or `X0`/`X1` convention.

ABI 1.2 adds three terminal transport results after the existing stable reply
values: 20 `closed`, 21 `peer-died`, and 22 `deadlock`. Queue capacity uses the
existing 4 `exhausted` result, and call deadlines use 7 `timeout`. These results
describe the transport fate and cannot be emitted by an ordinary service as a
forged successful completion. Legacy ABI calls map an unrepresentable new
transport fate to their existing failure/cancelled behavior.

## Internal interface registry and rights

Application-facing interface IDs 1 through 15 retain their current meanings;
the existing server-endpoint interface 15 remains valid at major 1 for the
compatibility transport. Persistent boot services use this closed internal
registry:

| Interface | ID | Version | Operations |
| --- | ---: | ---: | --- |
| persistent server endpoint | 15 | 2.0 | `ipc_reply_wait` only |
| immutable wait set | 16 | 1.0 | wait through `ipc_reply_wait` |
| packet device | 17 | 1.0 | info, transmit, receive, supervisor reset |
| block region | 18 | 1.0 | geometry, read, write, flush, derive |
| immutable boot blob | 19 | 1.0 | metadata, offset read |
| service lifecycle | 20 | 1.0 | initialize, shutdown |

Common rights bits are fixed as call bit 0, receive bit 1, reply bit 2, wait bit
3, read bit 4, write bit 5, flush bit 6, derive bit 7, and reset bit 8. An
interface rejects meaningless bits even if they are set in a malformed startup
record. Derivation intersects these bits and can never add one.

Packet transmit consumes the exact 1–1,514-byte `ipc_tx` prefix; receive writes
one exact frame to `ipc_rx`. Block read/write use `object_parameter` as the
region-relative logical-block address. The payload length must be a nonzero
logical-block multiple no larger than 4 KiB: read has an empty request and exact
reply capacity, while write has the exact TX payload and zero reply capacity.
Geometry is a fixed canonical reply; flush has no payload. Derive uses a fixed
start/count/rights request and requires derive authority. Boot-blob read uses
`object_parameter` as byte offset and returns at most 4 KiB.

KCAP gains the closed boot-only requirement names `wait-set`, `packet-device`,
`block-region`, `block-delegate`, `boot-blob`, and `service-lifecycle`.
Repository builders reject those names for ordinary `/bin` packages. Only a
fixed boot-service role may receive them, and artifact requirements are still
intersected with supervisor policy rather than granting authority themselves.

Legacy `handle_call` remains the ABI 1.0 compatibility path. It may reach an
isolated endpoint through the bounded slow path, but it is not eligible for the
one-copy direct fast path. Repository-provided servers and service clients must
use ABI 1.2 before filesystem or network migration is accepted.

## Endpoint and call state

Each endpoint is bound to exactly one server task incarnation and a closed set
of typed interfaces. Client handles name the endpoint slot and generation plus
one interface/version and call right. The server owns a distinct receive/reply
handle. Possession of an endpoint identifier or wait-set source index grants no
call, receive, or reply authority.

Opening the first client handle for one `(endpoint, task owner)` creates a
nonzero endpoint-scoped client badge. Every call event carries that opaque badge
so a persistent server can bind open-file tokens, UDP ports, and TCP connections
to one client lifetime without learning or trusting a global task ID. Additional
handles for the same owner and endpoint reuse the badge while retaining their
own interface and rights. Closing the last handle publishes one mandatory
`client-closed` control event. The event consumes no payload slot, cannot be
dropped because the ordinary call queue is full, and is represented by a
preallocated pending bit in the badge table. Server code must release all
badge-owned state when it consumes the event. The kernel cannot inspect
server-private cleanup; quotas bound a faulty server that retains it. Task
teardown does not wait for service cleanup before reclaiming the dead client,
and the badge contains no client pointer or mapping.

Badge values use slot-plus-generation identity. Reusing a badge slot advances
its generation, and the slot retires rather than wrapping at the maximum. A
stale badge in server-private state can therefore never identify a later client.

A pending call has exactly these states:

```text
admitted -> queued -> delivered -> replied
                         |            |
                         +-> cancelled+
queued -> timed-out | cancelled | peer-died
delivered -> timed-out | cancelled | peer-died
```

Every terminal state has one consumer. Request identity is consumed once the
server observes it, even if reply validation later fails. No terminal state is
converted into success by restart or retry.

Portable tables retain only task IDs, endpoint/capability generations, lengths,
deadlines, closed state, counters, and opaque slot identities. They retain no
user or kernel pointers. Native composition owns the saved contexts and the
fixed IPC/queue slots.

## Direct protected-call fast path

The common synchronous path is eligible only when all of these are true:

- caller and server are live isolated tasks on the sole CPU;
- the caller uses ABI 1.2 IPC pages;
- the handle resolves to the current endpoint incarnation;
- the server is blocked in `ipc_reply_wait` on a wait set containing that
  endpoint;
- no older request is queued at the endpoint;
- request/reply bounds and call accounting are available;
- the server is not already a member of the caller's call chain;
- adding it stays within the four-member chain bound; and
- no pending cancellation, terminal event, or higher-priority kernel work
  requires the slow path.

With interrupts masked for the bounded transition, the kernel performs this
ordering:

1. validate every scalar, generation, authority, deadline, and chain rule;
2. reserve and initialize one pending-call record without allocating;
3. copy exactly the request prefix from the caller's supervisor IPC alias to
   the server's supervisor IPC alias;
4. freeze the caller as blocked on that call and make the server the active
   member of the donated execution chain;
5. switch directly to the tagged server root without selecting through the
   round-robin scan; and
6. resume the server with the canonical receive metadata.

On `ipc_reply_wait`, the kernel validates the active token and status, copies
exactly one reply prefix from server `ipc_tx` to caller `ipc_rx`, publishes the
server wait, marks the caller ready, unwinds one call-chain member, and switches
directly to the immediate caller. The replied caller wins this handoff even if
another endpoint request is queued; the server is then ready from its published
wait and will be selected again normally. This prevents one busy server from
silently monopolizing the CPU.

The steady direct path has the following mandatory structural result per
nonempty request/reply:

| Event | Required count |
| --- | ---: |
| Request payload copies | 1 |
| Reply payload copies | 1 |
| Owned-heap allocation calls | 0 |
| Queue payload slots consumed | 0 |
| Round-robin scheduler scans | 0 |
| User-root handoffs | 2 |
| Full TLB invalidations | 0 |
| Targeted TLB invalidations | 0 |
| Additional execution-lease programs | 0 |

Zero-length directions count no payload copy. Fixed metadata writes are counted
separately from payload copies.

## Queued slow path and backpressure

If the server is not waiting, admission copies the complete request atomically
from client `ipc_tx` into one preallocated queue payload slot before blocking
the client. Delivery later copies that slot once into server `ipc_rx` and zeros
the complete queue slot before reuse. The reply still copies once from server to
client. Thus a nonempty queued request has exactly two request copies and one
reply copy.

Endpoint queues are FIFO. Direct handoff may not bypass an older queued call.
Queue-full and system-call-capacity exhaustion are distinct typed results and
have no service-visible effect. There is no partial admission, overwrite,
priority insertion, unbounded sender list, or shared mutable queue payload.

This FIFO is not a general mailbox. Every entry is one synchronous call whose
caller remains blocked, whose lifetime is bounded by that caller and deadline,
and which must produce one reply or terminal fate. There is no send-only
operation, independently persistent message, application-visible dequeue, or
message ownership after caller teardown. Endpoint major 2 makes this behavior
an explicit new contract rather than silently widening ADR 0011's port.

A caller remains unable to execute while its call is queued or delivered, so
its IPC pages cannot change on the accepted single-CPU system. The kernel still
uses the copied queue slot rather than depending on that fact; this preserves
ADR 0032's copied-pending-request rule and leaves a valid path to later SMP.

## Wait sets and device events

A persistent server must wait for both client calls and service-specific event
sources without polling. A wait set is an immutable, generation-checked object
owned by one server and constructed before that server becomes ready. It names
at most four sources. Initial server code cannot add, remove, duplicate, or
retarget a source at runtime.

Supported sources in this ADR are:

- one or more receive-capable service endpoints;
- one packet-device receive-ready source;
- one block-device completion source if later asynchronous block transport is
  accepted; and
- one boot-relative monotonic deadline supplied to `ipc_reply_wait`.

Endpoint sources also report the mandatory `client-closed` control event. A
close racing with a delivered call marks that call cancelled first and then
publishes closure. The server can never receive another call for the closed
badge after observing the event.

Readiness and wait publication use the existing observe-or-publish discipline.
If a source is already ready, `ipc_reply_wait` returns it without publishing a
blocked task. If no source is ready, the task, wait registration, complete
context, and optional call deadline are published before idle can be entered.
Close, revoke, cancellation, deadline, and resource readiness each wake exactly
once with their typed reason.

Closed/revoked sources and an already expired deadline are selected before
ordinary readiness. Otherwise, an immutable wait-set cursor selects ready
sources round-robin beginning after the last delivered source. The cursor moves
only after successful delivery. Endpoint-local calls remain FIFO, and a
`client-closed` event for a badge precedes any subsequently observable event for
that badge. This prevents a continuously ready NIC or client endpoint from
starving the other source.

The wait mechanism unifies lifecycle only. An endpoint call, packet readiness,
and timer deadline remain different event kinds and expose different typed
operations, consistent with ADR 0034.

## Nested service calls and deadlock

A server may synchronously call another server. The caller's execution chain is
donated directly so a provider needed to complete the original request runs
without waiting for an unrelated scheduler turn. There are no priorities in the
accepted single-CPU scheduler, so this direct handoff is the complete initial
priority-donation policy.

The kernel retains a bounded ordered chain of at most four user task identities.
Calling any task already present in the chain is rejected as `deadlock` before
delivery. Exceeding the depth is rejected as `exhausted`. A task may own at most
one outbound synchronous call and one currently delivered inbound call. A
server is non-reentrant: another caller queues rather than entering the same
server concurrently.

The intended deepest initial path is:

```text
application -> VFS server -> filesystem provider -> kernel block broker
```

The kernel broker is not a user chain member. Four members leave one bounded
future mediation step without admitting arbitrary recursion.

## Tagged address spaces and root switching

Copy reduction alone is insufficient if every call flushes translations. The
same implementation phase must add retained task address-space tags.

On x86-64, the kernel uses PCID when CPUID reports PCID and the required
invalidation mechanism. PCID 0 is reserved for the kernel root; task slots use
PCIDs 1 through 16. A normal direct handoff loads the destination CR3 with the
no-flush rule. Before an address-space slot/PCID is reused, the kernel performs a
targeted invalidation for that PCID after the old task is terminal and before
the new root can run. Page additions invalidate only the changed virtual range
for that task. If the required feature is absent, the existing full-flush path
remains a correctness fallback and is reported as such; that platform does not
satisfy the fast-profile acceptance claim.

On AArch64, task slots use ASIDs 1 through 16 in TTBR0; ASID 0 is reserved for
the kernel root. The implemented ASID width is validated from architectural
feature registers before task publication. Slot reuse executes a targeted ASID
invalidation with the required barriers. Page additions invalidate only the
changed address and ASID. A full `TLBI VMALLE1` is forbidden on the steady IPC
path.

The fast gate executes kernel code under the current task root. This is safe
only because every task root contains identical supervisor-only kernel image,
device, boot-arena, kernel-stack, exception, and IPC-pool mappings. The fast path
touches no general free-RAM identity mapping. Fault handling, root mutation,
teardown, and any operation needing mappings absent from a task root first
switch to the kernel root and use the slow path.

Tagged translations are an optimization with explicit invalidation proofs, not
a change to address-space ownership. A generation mismatch, unconfirmed
invalidation, unsupported feature state, or root/tag accounting failure is
terminal for the affected task or kernel initialization; it never falls through
to a stale tagged mapping.

## Execution leases and scheduling charge

Removing lease programs must not remove lease enforcement. A direct synchronous
call chain retains the caller's already armed absolute 50 ms execution deadline.
The kernel changes only the active task identity as it hands execution between
chain members. It does not extend or reprogram the deadline at each hop. User
CPU time spent in a server is therefore charged to the initiating execution
segment.

If the lease expires, the currently executing unprivileged task is terminated.
If that task is a server, its current caller receives `peer-died`, the remaining
chain unwinds, and the supervisor applies the server restart policy. The caller
does not receive a successful reply and the operation is not retried.

When a server blocks on a device or deadline, the execution lease is quiesced
only after the wait and pending-call state are fully published. The call's
absolute service deadline remains armed through the kernel wait mechanism. A
later server resume receives a fresh bounded execution segment, but the original
call deadline is never extended. This slow blocking case may program timers and
is counted separately from direct steady IPC.

Background device events have no donating client. Scheduling such a server arms
its ordinary fresh 50 ms lease. A server that never reaches an ABI boundary is
contained by the existing lease rather than requiring general preemption.

A kernel IPC client likewise has no donated user lease. Direct entry into the
server arms a fresh 50 ms server lease while the independent 4,000 ms call
deadline remains retained by the pending-call table. Completion resumes the
owned kernel continuation under the kernel root.

## Capability and security rules

The following rules are mandatory:

- client, server, wait-set, packet, block, and supervisor handles have distinct
  typed interfaces and rights;
- a server cannot mint handles or widen rights; the kernel or an explicitly
  authorized supervisor derives only equal-or-narrower authority;
- restart always advances endpoint and task generations; old client handles are
  revoked and never silently retarget a replacement process;
- general capability transfer in message payloads is rejected;
- request and reply pages are never mapped into both peers at user privilege;
- the kernel copies before the destination task resumes and only after the
  source task has trapped and stopped;
- reply tokens are opaque, generation checked, single use, and bound to the
  exact server task, client task, endpoint incarnation, and pending call;
- a server reply may carry only service statuses 0 through 19; transport
  statuses 20 through 22 are synthesized only by the kernel;
- wrong, stale, duplicate, oversized, late, foreign, or transport-status replies
  fault the offending server task through the contained invalid-call fate,
  complete its client with `peer-died`, and never write client memory;
- client cancellation removes an undelivered call atomically or marks a
  delivered call cancelled; it never manufactures rollback of prior service
  effects;
- server teardown cancels inbound/outbound calls and waits before handles,
  pages, or address-space tags are reclaimed; and
- fatal diagnostics, interrupt acknowledgement, and DMA reset do not depend on
  a user server or IPC allocation.

Copying through supervisor IPC aliases avoids SMAP/PAN relaxation over arbitrary
user pointers on the fast path. Legacy pointer-based calls retain their current
complete-range validation and copied slow path.

The containment claim is architectural integrity, authority confinement, and
bounded availability: a malicious server cannot write kernel or peer memory,
forge a capability, escape its block/packet authority, retain reclaimed task
resources, or run past its lease. Isolation cannot make that server preserve
data it is explicitly authorized to mutate or tell the truth in a syntactically
valid service reply. Clients continue to validate canonical typed replies, and
durable storage recovery remains provider policy. Cache/timing, speculative
execution, and other microarchitectural side channels are unchanged from the
current threat model and require a separate hardware policy if they become a
deployment requirement.

## Persistent server lifecycle

A configured server has these supervisor-visible states:

```text
Absent -> Starting -> Ready <-> Blocked
                    |    |
                    v    v
                 Exited | Faulted -> Restarting -> Starting
                                      |
                                      v
                                    Offline
```

`Ready` is published only after the artifact, package requirements, address
space, IPC pages, handles, wait set, endpoint binding, and server initialization
reply have all committed. Clients cannot obtain handles to `Starting` or
`Restarting` incarnations.

Initialization uses service-lifecycle opcode 1. The newly entered server first
publishes its wait; the supervisor is the only client allowed to send this call.
All boot-blob, broker, endpoint, and wait-set handles are already present in the
startup page. The server validates and opens its state, then replies success
with an empty payload within 4,000 ms. Any other status, payload, timeout, exit,
or fault rejects the incarnation and runs complete teardown without publishing
ordinary client handles. Service-lifecycle opcode 2 requests shutdown; a clean
server replies success, quiesces owned state, and exits. An unsolicited clean
exit is still recorded distinctly and is never treated as an acknowledged
shutdown.

Server exit, fault, lease expiry, initialization rejection, and supervisor
shutdown are distinct recorded fates. Teardown order is:

1. make the server terminal and prevent new endpoint admission;
2. revoke the receive/reply handle and advance endpoint generation;
3. complete the delivered caller and every queued caller exactly once with
   `closed` for a clean exit or `peer-died` for a fault/revocation;
4. cancel the server's outbound call, wait set, and device waits;
5. revoke server-owned block, packet, timer, namespace, and control handles;
6. reset a brokered device when policy requires it and confirm reset before DMA
   storage can be reused;
7. reap, zero, invalidate the address-space tag, and return every ordinary task
   frame; and
8. zero the retained IPC pair before its task slot may be reused.

Restart policy is part of each boot service record, not server preference. The
initial policies are:

- network server: restart after a fault, at most three starts in any 60-second
  boot-relative window, then remain offline;
- VFS/storage server: at most one automatic restart after a fault, reopen every
  persistent provider through its normal validation/recovery path, and keep a
  volume offline or read-only if validation is uncertain; and
- clean core-service exit: remain offline unless the supervisor explicitly
  requested shutdown/replacement.

Restart never preserves TCP connections, UDP ports, open-file tokens, pending
mutations, `/tmp` contents, or client handles. Network restart resets the packet
broker generation and repeats configuration policy. Storage restart does not
replay the failed request; StateFS/TXSLOT may recover a committed predecessor,
and FAT/ext4 dirty-state rules decide whether a volume can reopen.

## Bootstrapping

The VFS server cannot be loaded from a filesystem that only it can parse. The
kernel image therefore contains a small immutable boot-service capsule with
fixed roles, initially `storage-server` and `network-server`, using the same
architecture-specific KEX-package validation as applications. Role lookup is a
bounded compile-time table, not a path namespace or general archive.

Capsule bytes are part of the kernel/EFI image trust unit and cannot be replaced
by an attached disk or network response. Initially, updating a core server
updates that image. Stage 9 signatures may later authorize an external capsule,
but this ADR does not introduce an unauthenticated early loader or fallback to a
disk artifact after capsule validation fails.

The capsule's 8 MiB aggregate ceiling does not widen the Core Specification's
16 MiB release-image ceiling; kernel, capsule, boot data, and embedded recovery
bytes must fit it together.

The existing KEFS root, BMNT/PRGN selectors, activation pointer, and other boot
policy artifacts become opaque immutable boot blobs. A typed read-only
`boot-blob` capability exposes only a fixed role, exact byte count, and bounded
offset reads. The kernel does not interpret filesystem or storage-policy bytes.
Core servers may copy these blobs during initialization; this is boot-time work
and is excluded from steady IPC claims.

The order is:

1. establish kernel memory, protection, interrupts, console, timer, and device
   brokers;
2. validate and start the storage server with boot-blob and authorized block
   handles;
3. wait for its explicit ready result and publish its VFS endpoint;
4. validate and start the network server with one packet-device handle;
5. publish application-facing service handles only after server readiness; and
6. start the native shell/session task.

Recovery mode is a separately embedded storage-server artifact plus the opaque
KEFS recovery blob, not a privileged kernel KEFS parser. If no storage server
can start, fatal output reports the failure without filesystem access and the
machine follows the configured recovery/halt policy.

The current kernel-resident shell and KEX loader become explicit kernel clients.
They use preallocated IPC slots and heap-owned enum continuations; no user-server
wait may retain an arbitrary Rust frame, borrow, trait object reference, or raw
pointer. Artifact staging is a bounded state machine of metadata plus offset
reads. A later shell/supervisor userspace migration may reuse these protocols
but is not required to remove filesystem code from kernel privilege.

## Network server split

The first production persistent service is the network server. It owns:

- Ethernet, ARP, IPv4, UDP, DHCP, ICMP, and TCP parsing/construction;
- address, neighbor, route, port, datagram, connection, retransmission, and
  protocol counters;
- all application-facing datagram, observation, configuration, echo, and
  outbound TCP interfaces; and
- protocol timers, receive admission, cancellation, and per-client resource
  ownership.

The kernel packet broker owns only:

- the validated virtio-net device and fixed DMA queues;
- MAC/link metadata obtained from the accepted device profile;
- bounded transmit of one complete frame up to 1,514 bytes;
- bounded receive of one complete frame up to 1,514 bytes;
- interrupt acknowledge/mask/unmask, a coalesced receive-ready bit, counters,
  and confirmed reset; and
- one generation-checked packet handle granted only to the network server.

Transmit copies the complete frame into the broker's fixed DMA buffer before
publishing a descriptor; receive copies from a completed fixed DMA buffer into
the server's `ipc_rx`. A completion that is not immediate becomes a broker-owned
pending operation and blocks the server without retaining its user pointer or a
kernel Rust frame. The shared device interrupt wakes bounded main-context
completion work. Timeout or permanent queue error follows the existing
mask/unpublish/reset/confirm rule before completing the call with failure.

The network server's immutable wait set contains its client endpoint and packet
receive-ready source; `ipc_reply_wait` supplies the nearest protocol deadline.
The ISR never parses or allocates. A receive event wakes the server, which pulls
at most the existing eight-frame budget through the packet handle and then
returns to `ipc_reply_wait`.

No raw packet, packet-device, route-control, DMA, MMIO, or interrupt handle is
given to applications. A network-server compromise can emit or consume frames
through its granted NIC and destroy its protocol state, but it cannot map kernel
memory, program descriptors, select another device, or survive handle
revocation/reset.

## Filesystem and storage server split

Before isolation, `troe-shell` must stop owning `Rc<RefCell<Namespace>>`.
Filesystem error, metadata, listing, stream, and revision types used by clients
move to an implementation-independent client/protocol crate backed by
`troe-abi`. Host tests retain a direct adapter; native composition uses an IPC
adapter. No shell or loader code may downcast or borrow a provider.

The first isolated storage server owns:

- `Namespace`, KEFS, RAMFS, FAT32, ext4, and StateFS;
- GPT/BMNT/PRGN discovery and exact mount activation;
- content generation, activation/rollback, identity snapshots, and mount policy;
- `/tmp`, `/vol`, `/config`, and generated VFS node state; and
- the existing filesystem-read, filesystem-mutate, volume-control, and command
  catalog/revision protocols.

The kernel block broker owns the native virtio devices and enforces each handle's
logical-block geometry, base, length, access, alignment, 4 KiB transfer maximum,
flush right, and one-request synchronous queue. The server never receives DMA
memory or a device mapping. Deriving a child region requires an explicit
delegate right and can only narrow the parent's range and access. Overlapping
writable child regions are rejected by the broker.

"Synchronous queue" means one request in flight and one eventual reply to the
calling server; it does not authorize polling with the CPU unavailable. Phase E
adds an interrupt-driven deferred completion to the accepted virtio block
profile. Write data is copied from `ipc_tx` into fixed DMA storage before queue
publication. Read data is copied from fixed DMA storage into `ipc_rx` only after
validated completion. The server is blocked on a broker-owned pending operation,
and no user pointer, IPC-page borrow, block-device borrow, or ordinary kernel
frame spans the wait. Timeout retains ADR 0019's reset-and-confirm requirement;
an unconfirmed reset remains terminal rather than releasing live DMA memory.

The initial combined server may receive the broad disk authority required to
reproduce current boot policy; that authority can corrupt authorized disks but
not kernel memory. Before provider separation is accepted, a volume-manager
role must derive exact per-volume block handles and give each provider only its
selected region. The intended final path is:

```text
client -> VFS/volume server -> provider server -> kernel block broker
```

KEFS and RAMFS remain server implementations. The kernel sees the embedded KEFS
image only as bytes handed through `boot-blob`. KEX loading reads `/bin` through
the VFS protocol into the kernel's bounded package staging transaction; it does
not restore an in-kernel root parser.

Provider failure takes only that provider/mount offline after the split. VFS
must not redirect the same call to another provider, retry a mutation, or reuse
an old provider token. Mount and open-token generations advance before any
replacement becomes visible.

## No mutable shared-memory fast path

The task IPC pages are private, and their supervisor aliases are kernel-only.
They are not shared-memory grants. This ADR rejects mapping a client payload
page directly into a server because revocation, concurrent mutation, partial
visibility, pin accounting, cache maintenance, and server-fault cleanup would
become part of every filesystem and network call.

The accepted 4 KiB copy is small relative to a filesystem block and larger than
the complete network frame profile. Larger file operations retain streamed
chunks. A future read-only immutable object mapping or page-loan protocol needs
two measured consumers and a separate ownership ADR; poor implementation of
this fast path is not justification for weakening isolation.

## Performance contract

Performance acceptance combines deterministic structural gates with relative
latency/throughput gates. QEMU proves counters and ordering, not publishable
nanosecond claims. Named real hardware is required before claiming absolute
latency.

### IPC microbenchmarks

The existing 0, 64, 256, and 4,096-byte matrix gains three protected rows:

- current compatibility slow path;
- persistent server with an immediately waiting endpoint; and
- persistent server with one deliberately queued request.

Each row retains 64 native warmups and at least 256 native samples. The direct
row must reproduce the structural fast-path table exactly on x86-64 and
AArch64. It also records trap entries, root writes, PCID/ASID hits, targeted and
full invalidations, scheduler scans, queue operations, lease programs, payload
copies, allocation calls, chain depth, and completed calls.

In the same boot image and on the same machine, the persistent direct-path p95
must be no more than 60% of the compatibility isolated-server p95 for 0, 64,
and 256 bytes. The 4 KiB direct p95 must be no more than 70%. A failure blocks
service migration even when structural counters pass. These same-image QEMU
ratios are an engineering regression gate, not a hardware latency claim.
Real-hardware evidence on one named machine per architecture is required only
before publishing absolute or architecture-level performance claims; lack of a
physical TROE platform does not waive or block the QEMU ratio gate.

### End-to-end regression budgets

Before moving either subsystem, record its current in-kernel acceptance image.
After migration, using identical media, peer, commands, payloads, and QEMU
platform configuration:

| Workload | Minimum retained throughput | Maximum p95 latency multiplier |
| --- | ---: | ---: |
| 4 KiB sequential ext4 reads | 80% | 1.25x |
| 4 KiB sequential ext4 writes plus declared sync | 75% | 1.35x |
| FAT32 4 KiB sequential reads/writes | 75% | 1.35x |
| 1,472-byte UDP request/reply | 85% | 1.25x |
| bounded TCP stream transfer | 80% | 1.30x |

No workload may add steady owned-heap allocation in the IPC interval, lose a
frame/handle/wait, widen a device or volume right, or exceed the existing
provider/network retained-state bounds. A throughput pass cannot waive a
security or structural failure.

Boot through an unchanged platform profile may take at most 1.15 times the
pre-migration median ticks from post-handoff entry to shell prompt, measured
over five fresh boots with identical firmware and disks. Serial formatting is
excluded using internal markers.

During Phases D and E, acceptance builds retain the old in-kernel implementation
behind `acceptance-probes` only and run old/new workload pairs in one boot. This
keeps firmware, QEMU scheduling, disks, peer, and host load as close as possible.
Production builders must reject the old implementation after its migration
phase closes. The final same-image results and exact QEMU/toolchain identifiers
are committed in a machine-readable baseline fixture; prose tables are not the
comparison oracle.

## Observability

Diagnostics add fixed counters for:

- direct and queued protected calls;
- request/reply payload bytes and copy counts;
- direct-handoff eligibility failures by closed reason;
- live/high-water endpoints, handles, pending calls, queued bytes, chains, and
  wait sets;
- queue-full, deadline, cancellation, peer-death, deadlock, and stale-token
  events;
- PCID/ASID hits, root writes, targeted invalidations, full invalidations, and
  tag reuse;
- server starts, readiness, clean exits, faults, lease deaths, restarts, and
  offline transitions; and
- packet/block broker requests, bytes, errors, resets, and generation changes.

Counters saturate or fail closed under the same policy as existing accounting;
they never wrap silently. An application receives only its typed/authorized
snapshot. Fatal output prints a minimal allocation-free server/task fate without
depending on VFS or network services.

## Repository decomposition

Implementation must reduce the composition root instead of adding another
subsystem to `kernel/src/main.rs`:

- `troe-abi` owns ABI 1.2 scalars, startup fields, interface IDs, rights, event
  packing, and canonical broker/lifecycle codecs;
- `troe-dispatch` owns portable endpoint, handle, badge, pending-call, FIFO, and
  structural-counter models, with payload storage injected by composition;
- `troe-task` owns task states, immutable wait sets, call-chain donation,
  wake/cancel ordering, and server lifecycle transitions;
- `troe-machine` owns boot-arena IPC slots, supervisor aliases, PCID/ASID and
  invalidation mechanisms, context gates, and interrupt-backed broker
  completions;
- a small new `troe-service` crate owns boot-service records, readiness,
  restart-window policy, and pointer-free kernel continuation enums;
- an implementation-independent namespace client crate owns shell/loader-facing
  filesystem traits and types without depending on `troe-vfs`;
- `services/network` and `services/storage` are ordinary freestanding KEX
  packages; later provider packages live beside them under `services/`; and
- native kernel integration is split into `kernel/src/ipc.rs`,
  `kernel/src/supervisor.rs`, `kernel/src/client.rs`, and
  `kernel/src/broker/{block,packet}.rs`, leaving `main.rs` as composition and
  boot ordering.

The boot-service record is a kernel-build-time Rust value, not a new disk
format. It contains the fixed role, embedded artifact bytes, endpoint/interface
set, initial handle derivations, immutable wait-set sources, resident-page
ceiling, initialization deadline, and restart policy. A serialized/updateable
capsule requires a later versioned format and trust decision.

## Implementation sequence and phase gates

Implementation is deliberately vertical. A later phase may not start by
weakening an earlier gate.

### Phase A: freeze baselines and portable models

- Extend the IPC benchmark schema and capture the current compatibility,
  filesystem, UDP, and TCP baselines.
- Add portable endpoint, pending-call, call-chain, wait-set, server-lifecycle,
  restart-window, and kernel-continuation models.
- Exhaustively test every state transition and capacity before native behavior
  changes.

Gate: host tests cover all legal transitions, every stale generation, queue
wraparound, deadline/cancel/fault race, depth/cycle rejection, and rollback
failpoint. Existing QEMU output remains byte-for-byte compatible outside new
diagnostic records.

### Phase B: ABI 1.2 IPC pages and tagged roots

- Add the versioned startup layout, two-page boot-arena pool, supervisor aliases,
  SDK ownership, and exact teardown.
- Add PCID/ASID allocation, targeted invalidation, safe fallback, and counters.
- Implement `ipc_call` and `ipc_reply_wait` against a synthetic persistent echo
  task in the acceptance harness, without yet adding general restart policy or
  migrating a product service.

Gate: both architectures pass direct/queued structural matrices, W^X and user
mapping tests, slot reuse with stale-tag rejection, zeroization probes, legacy
ABI 1.0/1.1 compatibility, and the IPC latency ratio.

### Phase C: persistent supervision and kernel clients

- Add multiple simultaneously live KEX contexts, immutable wait sets, direct
  call-chain handoff, bounded queues, exact cancellation, and restart policy.
- Replace the one-shot diagnostics server with a persistent instance.
- Convert native shell/loader service use to pointer-free kernel continuation
  records; no Rust frame or borrow spans a server wait.

Gate: fault the server before receive, after receive, during nested call, before
reply, after reply validation, while queued, and while blocked. Every case must
produce one client fate, exact endpoint/handle/wait/frame cleanup, successful
bounded restart, and a subsequent normal call.

### Phase D: network server

- Add the packet broker and move all `troe-net` state plus application adapters
  into the persistent network server.
- Preserve the existing application service interface versions.
- Remove `troe-net` from the kernel dependency graph.

Gate: all host parser/state-machine tests, all four QEMU profiles, repeated DHCP,
ARP, ICMP, UDP and TCP operations, interrupt-idle wakeup, cancellation,
server-fault/reset/restart, structural IPC counts, and end-to-end budgets pass.

### Phase E: combined VFS/storage server

- Split shell/loader namespace clients from the concrete `Namespace` type.
- Move KEFS, RAMFS, FAT32, ext4, StateFS, GPT/mount, generation, content, and
  identity code into one isolated storage server.
- Load core service artifacts from the boot capsule and expose current boot data
  only through immutable boot-blob and block handles.
- Remove all named filesystem/storage implementation crates from the kernel
  dependency graph.

Gate: boot/recovery, command discovery and launch, redirection, large streamed
files, links, manual mounts, StateFS recovery, generation rollback, filesystem
server faults at every mutation boundary, block interrupt idle/wakeup without
poll spinning, all four QEMU profiles, and storage performance budgets pass.
The kernel source and dependency audit rejects path, mount, provider,
filesystem-format, and GPT parser imports.

### Phase F: provider fault domains

- Add service-to-service VFS/provider protocols over the already accepted IPC
  path.
- Move selected ext4, FAT32, and StateFS instances into per-mount servers with
  exact block-region handles.
- Keep KEFS/RAMFS in the namespace server unless measurement and recovery policy
  justify another split.

Gate: a fault in one provider leaves kernel, network, VFS, and unrelated mounts
alive; the failed mount advances generation and becomes offline/read-only under
policy; nested call depth/copy counters are exact; no write crosses its granted
region; and aggregate storage remains within the regression budget.

### Phase G: closure audit

- Update architecture, roadmap, testing contract, ADR ledger, threat model, and
  recovery documentation to describe only implemented behavior.
- Reject forbidden kernel dependencies and service implementations through
  repository policy tests.
- Run the full local maintainer gate and all four QEMU suites from clean images.

Gate: the target kernel boundary and every verification item in this ADR are
true simultaneously. Only then may this ADR become accepted and implemented.

## Verification matrix

Portable tests must include:

- exact IPC/startup codecs, every truncation, reserved field, length, opcode,
  status, deadline, and result-register boundary;
- direct eligibility and each closed rejection reason;
- FIFO order, full queue, global retained-byte exhaustion, wraparound, and
  zeroization;
- stale task/endpoint/handle/token/wait/tag generations and maximum generation
  retirement;
- caller cancellation before admission, queued, delivered, replying, and after
  completion;
- server clean exit, fault, lease expiry, restart exhaustion, and offline fate;
- call-chain depth, direct nested reply order, cycle/self-call rejection, and
  unwind after middle-server fault;
- observe-before-publish readiness and every wait/deadline race;
- PCID/ASID allocation, targeted invalidation, fallback, slot reuse, heap growth,
  and accounting failpoints;
- IPC-page mapping ownership, supervisor-only peer aliases, W^X, zeroization,
  rollback, and exact frame return; and
- block/packet right narrowing, bounds, resets, and post-revocation rejection.

Native acceptance on x86-64 and AArch64 must additionally inject:

- invalid IPC virtual access to another task slot;
- stale translation use after task/tag reuse;
- server faults in translation, write, execute, illegal instruction, invalid
  call, and unexpected return paths;
- lease expiry in the client, first server, and nested server;
- interrupt arrival before wait publication, during direct copy, while the
  server runs, and immediately after reply;
- cancellation and deadline races with packet and block completion;
- network reset failure, which must preserve the existing terminal DMA safety
  rule; and
- persistent-storage faults before/after dirty markers, block writes, flushes,
  provider sync, and client reply.

Every native scenario asserts one terminal fate, zero partial IPC reply, no
unowned live handle/wait/call, exact ordinary frame return, IPC-page zeroization,
correct tag invalidation, no DMA release before reset, survival of unrelated
servers, and a successful subsequent operation when restart policy permits.

## Rejected alternatives

- **Keep service-shaped code linked into the kernel:** typed APIs limit
  authority but do not contain parser or memory-safety faults.
- **Map client pages directly into servers:** removes a copy by adding shared
  mutation, pinning, revocation, partial visibility, and teardown complexity to
  every call.
- **Copy through transient heap buffers:** safe but recreates allocation and
  extra-copy costs already visible in the isolated baseline.
- **Flush the complete TLB on every handoff:** correct fallback, unacceptable as
  the claimed steady service path.
- **Remove or refresh the execution lease at every hop:** removal weakens
  containment; refreshing lets a bounded nested chain multiply CPU time.
- **Move virtio drivers to userspace immediately:** without IOMMU-enforced DMA
  authority, process isolation would not protect physical memory.
- **One thread/kernel stack per endpoint or handler:** wastes fixed memory and
  retains arbitrary native frames instead of scheduler-owned contexts.
- **Unbounded asynchronous mailboxes:** unnecessary for synchronous typed
  services and incompatible with exact retained-byte accounting.
- **Transparent service restart and request replay:** duplicates mutations,
  writes, sends, and connection effects whose completion may be uncertain.
- **A universal descriptor or ioctl ABI:** erases the typed authority boundaries
  fixed by ADR 0034.

## Relationship to earlier decisions

This proposal extends ADRs 0014, 0015, 0032, and 0034. If accepted, it supersedes
ADR 0032's one-server/one-request composition ceiling and ADR 0009's statement
that the kernel permanently owns the VFS object model. It does not supersede
their bounded copying, task teardown, provider-region, typed-handle, or DMA
safety rules.

Until every closure gate passes, current architecture and ADR implementation
status remain authoritative: services other than diagnostics are in-process,
diagnostics is one-shot, the kernel owns VFS/network state, and full TLB
invalidation remains measured rather than silently described as optimized.

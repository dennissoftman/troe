# Thread and synchronization codec v1

`troe_abi::threading` implements allocation-free, little-endian codecs for
interfaces 30 (`THREAD_CONTROL`) and 31 (`THREAD_SYNC`), both version 1.0.
These are assigned contracts, not executable native services. The active
application ABI remains 1.3; the kernel and SDK reject ABI 1.4, and current
startup encoding/decoding rejects both thread interfaces. No KCAP builder name
grants them. Native loaders reject the separately encoded
[KEX static TLS container](kex-static-tls-v1.md); its reader supports offline
inspection and conversion only. Native composition is governed by
[ADR 0071](../adr/0071-native-threads-and-owned-synchronization.md).

## Identity, authority and call framing

A token is one `u64`: bits 0–23 contain slot + 1, bits 24–31 contain a closed
kind (thread 1, mutex 2, condition 3, permit 4), and bits 32–63 contain a
nonzero generation. Slots range from 0 through 16,777,214. Zero slot fields,
zero generations and unknown kinds are rejected. This representational bound
does not grant storage. Tokens contain no process identifier or authority;
decoding proves only shape. Generation exhaustion must retire a native slot.

Every operation requires `CALL` (bit 0). Interface 30 additionally uses create
(bit 9), start/abort (10), join (11), detach (12), stop (13), and observe/current
(14). Exit and sleep need only `CALL`. Interface 31 accepts only `CALL`.
Bits 0–8 keep their existing meanings; bit 15 is unassigned. Rights are checked
against trusted capability state, not the startup copy or payload. Shared
process memory means handles cannot isolate mutually hostile siblings.

The `Call` codec assigns entry 6 with six words:
`[handle, 64, 32, 0, 0, 0]`. The handle is nonzero; lengths are exact full-width
values. There are no user pointers. The request and response occupy prefixes
of the calling thread's already-owned TX/RX pages. `Completion` encodes exactly
`[0, 32]` for an operation response or `[1, 0]` for a rejected call with no
exposed RX prefix. All other completion pairs are invalid. These codecs do not
alter the current dispatcher's rejection of entry 6.

## Requests

Each request is exactly 64 bytes. Truncated and trailing bytes are rejected.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 2 | interface major, 1 |
| 2 | 2 | operation number |
| 4 | 4 | interface ID, matching the trusted handle |
| 8 | 56 | seven `u64` argument words |

Unused words are zero. Unknown operations, flags, versions and token kinds fail
decoding. Encoders validate directly constructed values before returning bytes.
`Request::required_rights` supplies the operation mask without authenticating it.

| Interface 30 operation | Arguments in order | Additional right |
| --- | --- | --- |
| 1 prepare | image entry offset, opaque argument, committed stack pages | create |
| 2 start | thread token | start |
| 3 abort | thread token | start |
| 4 join | thread token, wait flags, deadline | join |
| 5 detach | thread token | detach |
| 6 request stop | thread token | stop |
| 7 observe | thread token | observe |
| 8 current | none | observe |
| 9 exit | scalar result | none |
| 10 sleep | wait flags, deadline | none |

Prepare's offset is below 1 GiB and its stack count is 1 through 2^32 pages.
These structural ceilings are not an admission policy or proof of an executable
entry. The kernel-selected trampoline and native budget checks are separate.
A successful exit has no returning response.

| Interface 31 operation | Arguments in order |
| --- | --- |
| 1 create mutex | owner death policy: poison 0, fail process 1 |
| 2 create condition | none |
| 3 create permit | initial count, nonzero maximum; both fit `u32`, initial ≤ maximum |
| 4 lock | mutex token, wait flags, deadline |
| 5 unlock | mutex token |
| 6 condition wait | condition token, mutex token, wait flags, deadline |
| 7 notify | condition token, broadcast flag exactly 0 or 1 |
| 8 acquire permit | permit token, wait flags, deadline |
| 9 release permit | permit token, nonzero count fitting `u32` |
| 10 destroy mutex | mutex token |
| 11 destroy condition | condition token |
| 12 destroy permit | permit token |

Wait flags use bits 0–1: 0 means an immediate try, 1 an indefinite wait, 2 an
absolute monotonic deadline; 3 is invalid. Bit 8 opts into observing the caller's
sticky cooperative stop request. All other bits are zero. Try requires both
flags and deadline zero. Indefinite wait requires deadline zero. Tagged
deadlines use boot-relative milliseconds; zero and `u64::MAX` are real values,
not sentinels. Condition wait and sleep reject try mode. Stop observation is
cooperative and cannot asynchronously unwind a thread.

## Responses

Each response is exactly 32 bytes and is decoded against a validated request.
Matching interface and opcode are necessary but do not establish a live pending
operation or protect a caller from its own shared-memory siblings.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | echoed interface |
| 4 | 2 | interface major, 1 |
| 6 | 2 | echoed operation |
| 8 | 2 | outcome |
| 10 | 1 | observation state, otherwise zero |
| 11 | 1 | observation flags, otherwise zero |
| 12 | 4 | reserved zero |
| 16 | 8 | success value, otherwise zero |
| 24 | 8 | reserved zero |

Outcomes are success 0, would block 1, timed out 2, stopped 3, poisoned 4, busy
5, deadlock 6, stale 7, not mutex owner 8, different condition mutex 9,
exhausted 10, invalid state 11, process stopping 12, invalid request 13,
unsupported 14, denied 15, and permit overflow 16. Unknown values fail.
These are independent of IPC transport status codes.
Stale covers both a missing generation and a token outside the authenticated
process; the wire contract exposes no separate cross-process ownership error.

Success carries a correctly typed token for prepare/current and object creation,
an unrestricted scalar result for join, or zero for other operations. Only
successful observe carries a snapshot. Failure carries neither value nor snapshot.
Would-block requires try mode; timeout requires a tagged deadline; stopped
requires stop observation. Poison is valid only for lock/condition wait,
deadlock for join/lock, not-owner for unlock/condition wait, different-mutex for
condition wait, and overflow for permit release.

Observation states are prepared 1, ready 2, running 3, blocked 4, exiting 5,
completed 6 and revoked 7. Flags are stop-requested bit 0, detached bit 1 and
resources-released bit 2. No other bits are accepted. Released resources require
completed or revoked state. A snapshot grants no right to recycle backing.

For an admitted condition wait, success, timeout and cooperative stop mean the
original mutex has been reacquired. Deadline/stop apply to the condition phase;
reacquisition has no deadline or stop cancellation. Poison grants no ownership.
The codecs enforce representation and outcome compatibility; actual ownership,
linearization and resource release belong to the scheduler model and native
composition.

## Immutable per-thread startup descriptor

`StartupReference` encodes a standalone 16-byte ABI 1.4 extension: at process
header offset 80, the initial descriptor's page-aligned address; at offset 88,
the exact descriptor prefix size, 128. The assigned header is 96 bytes, giving
166 initial-handle slots. ABI 1.0–1.2 retain 64 bytes/168 slots and ABI 1.3
retains 80 bytes/167 slots. The current startup encoder does not publish ABI 1.4.

`StartupDescriptor` encodes an exact 128-byte prefix of a dedicated 4 KiB
read-only/NX page. `decode_page` also requires every trailing byte to be zero.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | magic `TTHRv1`, two zero bytes |
| 8 | 2 | descriptor major, 1 |
| 10 | 2 | descriptor minor, 0 |
| 12 | 4 | prefix bytes, 128 |
| 16 | 8 | thread token |
| 24 | 8 | shared process startup address |
| 32 | 8 | process startup mapped bytes, 4,096 |
| 40 | 8 | committed stack bottom |
| 48 | 8 | exclusive committed stack top |
| 56 | 8 | TLS allocation base |
| 64 | 8 | complete page-rounded TLS bytes |
| 72 | 8 | thread pointer |
| 80 | 8 | private TX address |
| 88 | 8 | private RX address, exactly TX + 4,096 |
| 96 | 8 | resolved worker entry, zero for initial thread |
| 104 | 8 | worker argument, zero for initial thread |
| 112 | 4 | initial-thread flag exactly 0 or 1 |
| 116 | 4 | reserved zero |
| 120 | 8 | self-address of descriptor mapping |

Process startup, stack including its two guards, TLS, IPC pair, and descriptor
must be nonempty, page aligned, disjoint, exclude page zero and remain within
the lower 48-bit user half. Arithmetic is checked. The thread pointer is
8-byte aligned inside TLS. Worker entry is a nonzero user address outside
these data/guard ranges; native RX and compiler-layout checks remain necessary.
An initial descriptor has zero entry and argument. A byte codec cannot prove
that an address is mapped, immutable, owned or actually contains these bytes.

`troe-application::thread_memory` includes and charges the descriptor page.
Its typed regions specify RW/NX stack, TLS and IPC, followed by read-only/NX
startup. Geometry tests compose its outputs with both compiler TLS layouts and
this descriptor codec. No mapping or thread is published by either component.

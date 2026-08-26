# IPC baseline and measurement contract

This records both the pre-scheduler synchronous in-process dispatcher and the
first protected diagnostics-server path. It measures mechanisms that exist in
the tree; QEMU validates counters and bounds, while publishable latency claims
still require named real hardware.

## Reproducing the host matrix

Run the release-mode example from the repository root:

```sh
cargo run -q -p troe-dispatch --example ipc_baseline --release
```

The fixed matrix is 0, 64, 256, and 4096 payload bytes. Each row performs
10,000 unreported warmup calls followed by 50,000 measured calls. Optional
`--warmup N` and `--samples N` arguments change only those counts. The clock is
`std::time::Instant`; the reported unit is monotonic nanoseconds, not CPU
cycles. Measurement begins immediately before `Dispatcher::call` and ends
after the owned reply has returned and been checked, but before its buffer is
dropped.

The example verifies its structural counters before printing a row. In the
current path a request is borrowed directly, so the dispatcher performs no
request copy or request allocation. A non-empty echo reply performs exactly one
bounded payload copy into one owned allocation. There is no privilege or
address-space transition, TLB invalidation, or timer program in this path.

## Recorded host result

Collected on 2026-08-26 with macOS 26.5.2 arm64, repository commit `f04de1a`
plus the baseline instrumentation in this change:

| Payload | p50 ns | p95 ns | p99 ns | max ns | Calls | Request copies / allocs | Reply copies / allocs | AS switches / TLB / timer |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 41 | 42 | 42 | 1,416 | 50,000 | 0 / 0 | 0 / 0 | 0 / 0 / 0 |
| 64 | 41 | 42 | 42 | 250 | 50,000 | 0 / 0 | 50,000 / 50,000 | 0 / 0 / 0 |
| 256 | 41 | 42 | 42 | 3,417 | 50,000 | 0 / 0 | 50,000 / 50,000 | 0 / 0 / 0 |
| 4096 | 83 | 84 | 125 | 8,584 | 50,000 | 0 / 0 | 50,000 / 50,000 | 0 / 0 / 0 |

The maxima are recorded for completeness, not treated as stable performance
claims on a non-realtime host. The percentile shape and structural events are
the useful baseline.

## Native acceptance matrix

Acceptance images run the same payload matrix during boot with 64 warmup calls
and 256 measured calls per row. They print `ipc-baseline` records containing
the architecture counter frequency, p50/p95/p99/max ticks, bytes, copies,
allocations, address-space switches, TLB invalidations, timer programs, and
completed calls. x86-64 uses ordered TSC reads; AArch64 uses the architected
physical counter. Boot fails if the deterministic structural event totals do
not match the current in-process contract.

QEMU validates the counter plumbing and event-count regression. Its latency is
not a hardware performance claim. Publishable latency comparisons require the
unchanged acceptance image and matrix on named real x86-64 and AArch64 machines.

## Isolated diagnostics matrix

The acceptance kernel runs the same 0, 64, 256, and 4096-byte logical payload
matrix through a least-authority EL0/ring-3 diagnostics transport server. Each
row uses 64 warmup requests and 256 measured requests. The interval begins when
the server endpoint starts delivering the first fragment and ends when it
accepts that request's final generation-checked reply. It therefore includes
the copied handoff, protected execution, reply gate, address-space switches,
TLB work, and lease programming, but excludes process construction, teardown,
and serial formatting.

The v1 server envelope carries a token, interface, opcode, bounds, and reserved
bytes inside the 4 KiB call limit. A 4096-byte logical payload consequently
uses two bounded fragments; smaller rows use one. The matrix reports this
rather than silently reducing the 4 KiB payload. Reply tokens change for every
fragment, and a logical sample completes only after every fragment is echoed
and validated.

The kernel now uses a fixed 4 KiB request buffer and a caller-owned fixed reply
buffer for server-endpoint calls. `Service::call_into` lets the endpoint encode
directly into that reply buffer. No payload alias crosses the protection
boundary: the server still receives a copy and the kernel still validates and
copies its reply. General services retain the owned-reply API.

The owned heap records successful allocation and deallocation calls. Every
measured receive-to-reply interval snapshots that counter and boot fails unless
the delta is exactly zero. This is stronger than checking live bytes or a
high-water mark, either of which can miss transient allocation. Construction
and final client-reply ownership remain bounded setup/teardown work outside the
steady interval.

The first server composition has hard ceilings of one retained request and one
suspended server context. The ordinary command step limit remains 1024; only
the acceptance benchmark uses a 1536-step ceiling so 320 two-fragment warmup
and measured exchanges fit in one server lifetime.

## Deterministic native structural result

Both QEMU architecture gates require these totals for each 256-request row:

| Logical payload | Wire fragments | Request copies | Reply copies | Reply allocations | Address-space switches | TLB invalidations | Timer programs |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 256 | 0 | 0 | 0 | 512 | 512 | 256 |
| 64 | 256 | 512 | 512 | 0 | 512 | 512 | 256 |
| 256 | 256 | 512 | 512 | 0 | 512 | 512 | 256 |
| 4096 | 512 | 1024 | 1024 | 0 | 1536 | 1536 | 768 |

The zero-byte row counts payload copies, not fixed envelope writes. x86-64
currently reloads CR3 in each direction; AArch64 changes TTBR0 and executes a
full `TLBI VMALLE1`. Thus the measured full-invalidation cost is explicit.
ASID/PCID retention is a justified future optimization, but it is not assumed
or simulated here. Likewise, one lease is deliberately programmed for every
user-execution segment; removing that safety boundary was not an acceptable
latency optimization.

The optimization made in this slice is therefore narrow and measured: two
transient kernel allocations were removed from the server transport path, and
the endpoint now performs a direct copy into caller-owned bounded storage.
Reply ownership, token generation checks, server-fault fate, and teardown are
unchanged.

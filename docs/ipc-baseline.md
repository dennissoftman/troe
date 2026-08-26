# IPC baseline and measurement contract

This is the pre-scheduler-change baseline for the synchronous in-process
dispatcher. It deliberately measures the mechanism that exists today rather
than projecting the cost of deferred calls or an isolated user server.

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
The isolated diagnostics path introduced later must emit the identical schema,
so its extra copies and protection transitions can be compared directly.

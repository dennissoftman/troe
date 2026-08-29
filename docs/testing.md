# Testing and impact selection

TROE has one authoritative exhaustive gate and one conservative development
selector. Focused testing shortens feedback loops; it never replaces the full
gate before merge or release.

## Commands

Run the complete repository surface, including every named platform and every
QEMU scenario group:

```console
python3 scripts/test.py
```

Run only gates affected by committed, staged, unstaged, and untracked changes
relative to `HEAD`:

```console
python3 scripts/test_changed.py --explain
```

On a feature branch, compare the entire branch with its known base:

```console
python3 scripts/test_changed.py --base main --explain
```

Inspect the decision without executing it:

```console
python3 scripts/test_changed.py --base main --dry-run --explain
```

The selector uses Cargo's workspace dependency graph plus reviewed rules for
apps, Python tools, generated artifacts, and runtime behavior. A library change
selects that package and all transitive workspace consumers. Shared KEX SDK or
tool changes select every app on both targets. An unknown path, dependency
policy change, workflow change, or test-runner change fails closed to
`python3 scripts/test.py`.

The exhaustive runner gives image generation a single owner. Production and
acceptance variants use `scripts/build.py --all-variants`, which creates shared
KEFS, configuration, content, and storage inputs once before building both
kernel variants. Focused groups that do not execute destructive fault probes
build only production images.

`--skip-qemu` is only an environment escape hatch. It does not mean that QEMU
coverage is unnecessary; the full pinned gate must still run on the merge
runner. `--require-filesystem-tools` makes absence of the exact external FAT32
and ext4 interoperability tools an error.

## QEMU scenario groups

`scripts/test-qemu.py` accepts a repeatable `--scenario` option. Omitting it is
the exhaustive default and selects every group. Multiple selected groups run in
their canonical order during the same primary guest boot where possible.

| Group | Runtime contract exercised |
| --- | --- |
| `boot` | Owned boot, production activation, StateFS diagnostics, packaged KEX launch |
| `network` | Link and IPv4 state, DHCP, ICMP, ARP, cancellation, UDP, bounded TCP streams |
| `shell-terminal` | Editing, completion, history, manuals, parsing, CRLF, and clear-screen behavior |
| `filesystem` | KEFS/ext4/FAT32 reads and writes, shared-media restart persistence, paths, logical lists, pipelines, bounded `sh.kex` scripts, RAMFS mutation, read-only and error behavior, plus repeated direct and nested launches of the large shared-media C runtime probe |
| `lua` | Lua inline/stdin/file loading, the portable compute/allocation benchmark, consolidated language/numeric/system examples, script argument/`-l` compatibility, exact binary64 formatting, complete pipe reads, buffering modes, protected errors, shared-runtime math/calendar/environment/process/random behavior, typed filesystem errno failures, OS-shim clock and exit behavior, timer preemption, fragmentation, a 48 MiB private allocation beyond the former narrow TLSF geometry, and bounded OOM recovery |
| `quota-memory` | 128-entry quota, recovery, repeated transient workloads, exact initial/heap/private commitment accounting, zeroed private mappings, partial protect/unmap and recoalescing, typed CSPRNG reads, and independently randomized KEX image bases |
| `persistence` | A second boot and native cold-reset termination after the baseline durable boot |
| `fault-isolation` | Write, execute, guard, exception, and fatal probes with rollback validation |
| `framebuffer-keyboard` | Owned framebuffer activation and native x86 PS/2 input; selecting it enables both device checks |

Examples:

```console
# One focused group on the normal x86 development platform.
python3 scripts/test-qemu.py \
  --platform x86_64-q35-uefi --environment qemu \
  --scenario network

# Related groups can be repeated; images are rebuilt from current sources.
python3 scripts/test-qemu.py \
  --platform x86_64-q35-uefi --environment qemu \
  --scenario shell-terminal --scenario filesystem

# Low-level changes should widen to every platform.
python3 scripts/test-qemu.py \
  --platform all --environment qemu \
  --scenario boot --scenario fault-isolation

# The exhaustive default remains unchanged.
python3 scripts/test-qemu.py \
  --platform all --environment qemu \
  --framebuffer-console --native-keyboard
```

`fault-isolation` automatically causes production and acceptance-probe images
to be built. Other focused groups build only production images. `--skip-build`
is safe only when the required current-source images and cloud bundles were
already produced; it must not be used merely to hide stale artifacts.

The filesystem group builds `tests/runtime-probe` for both targets outside the
production application catalog, publishes a canonical runtime tree, installs
it only on the shared FAT32 acceptance media, and launches the architecture
path twice directly and once through owner-scoped nested launch. The probe has
an 8 MiB file-backed payload and exercises large allocator mappings and
reallocation, rollback/reclamation, buffered stdio, descriptor and directory
bounds, cwd and link mutation, UTF-8/wide conversion, UTC/C locale time,
randomness, setjmp, single-execution-thread locks/TSS, explicit thread and flag
rejection, missing capabilities, missing runtime files, repeated launch, ASLR,
and zero retained allocator/private-map state. The rootfs and EFI inputs never
contain the probe.

Host-only C and runtime-tree contracts are independently reproducible with:

```console
python3 -m unittest tests.test_c_sysroot tests.test_mkruntime
python3 tools/build_c_sysroot.py /tmp/troe-c-sysroot \
  --architecture all --check
```

`--smoke` is a fixed quick terminal scenario and is intentionally mutually
exclusive with `--scenario`. It remains useful for interactive console work,
but it is not an exhaustive or impact-selected gate.

## Instructions for coding agents and LLMs

After changing code or tests:

1. Run `python3 scripts/test_changed.py --dry-run --explain` and inspect both
   the changed paths and the reasons printed for each gate.
2. Run `python3 scripts/test_changed.py --explain`. Do not manually remove a
   selected package, app, Python test, QEMU group, or platform.
3. If a changed path widens to the full gate, accept the widening. Add a narrow
   rule only when repository ownership and runtime reachability prove it sound,
   and add selector regression tests with that rule.
4. Use an individual `--scenario` while diagnosing or iterating inside one
   known subsystem. Return to the selector after the change is complete.
5. Before declaring a branch merge-ready, run `python3 scripts/test.py` in the
   pinned local environment and retain the result in the maintainer's local
   release notes or terminal log.

Never infer that an unchanged file makes its tests irrelevant. Tests may be
selected through reverse dependencies, generated inputs, package formats, or
runtime integration even when their own source files did not change.

## Native trap-entry contract

Every native gate that can call Rust after firmware services are released is
part of this current implementation contract. It applies to the single-CPU
x86-64 and AArch64 backends; it is not a generic ABI for other machines.

### Shared rules

- Application entry and resume run with the owned IRQ class masked, publish the
  complete kernel root and return stack, switch address spaces, and enable user
  interrupt delivery only through the final architectural return.
- A gate that can resume interrupted application code saves every documented
  application-visible register class before calling Rust and restores it before
  returning. A terminal gate may omit user-state preservation because it must
  restore the previously published kernel context instead.
- Rust is entered on a 16-byte-aligned kernel stack with nested delivery masked.
  No application pointer is dereferenced before complete mapping validation.
- An exception is contained only when its saved origin is application privilege
  and the published run kind permits that fate. Kernel-origin faults are fatal.
- Completion restores the kernel address space and CPU state before Rust regains
  control. The active run is then unpublished before IRQ delivery is re-enabled.
- Native assembly addresses retained data symbols without depending on image
  size. AArch64 uses `ADRP` plus the low-12-bit relocation for kernel roots,
  saved contexts, and emergency-stack state; `ADR` cannot safely name data once
  an image crosses its ±1 MiB reach.

### x86-64 gates

| Gate | User fate | Required entry work |
| --- | --- | --- |
| `x86_isolated_syscall_entry` | suspend or terminate | hardware RSP0 stack, save all GPRs and FXSAVE state, clear DF/AC, validate active run |
| `x86_execution_timer_entry` | preempt a user timeslice or resume kernel deadline wait | inspect saved CS before selecting the path; user origin saves every GPR and FXSAVE class, clears DF/AC, disarms and acknowledges the timer, and publishes a resumable context; kernel origin saves/restores every GPR and FXSAVE class, clears DF/AC, records the runtime deadline, and returns with `iretq` |
| `x86_input_interrupt_entry` | resume | save all GPRs and FXSAVE state, clear DF/AC, service bounded input, restore state, `iretq` |
| `x86_exception_no_error_entry` | contain or fatal | clear DF/AC, pass saved CS origin, restore kernel context only for a contained user fault |
| `x86_exception_error_entry` | contain or fatal | clear DF/AC, account for hardware error code, pass saved CS origin |
| `x86_page_fault_entry` | contain or fatal | clear DF/AC, pass CR2, error code, and saved CS origin |
| `x86_spurious_interrupt_entry` | resume | calls no Rust and returns without LAPIC EOI |

All Rust-calling x86 gates execute `cld` and clear `RFLAGS.AC` before the call.
The original user RFLAGS remains in the hardware/application frame and is
restored only when that user continuation is deliberately resumed.

### AArch64 gates

| Vector path | User fate | Required entry work |
| --- | --- | --- |
| `troe_aarch64_exception_entry` | fatal | mask DAIF, switch to the dedicated 16 KiB mapped emergency stack, pass ESR/FAR, never return |
| `troe_aarch64_lower_sync_entry` | suspend or terminate | mask DAIF, save X0-X30, Q0-Q31, FPCR/FPSR, ELR/SPSR, SP_EL0, and TPIDR_EL0; distinguish `SVC #0` from faults |
| `troe_aarch64_irq_entry` | resume, complete a kernel deadline, or preempt a user timeslice | mask IRQ and save X0-X30, Q0-Q31, FPCR/FPSR, ELR/SPSR, SP_EL0, and TPIDR_EL0; an active EL0 application timer publishes that complete resumable context, while a kernel deadline records its wake and returns through the saved IRQ frame |
| current/lower FIQ or SError vector | fatal | route to the common fatal exception entry |

Application entry resets `TPIDR_EL0`; every syscall suspension and timer
preemption preserves it in the complete resumable application context.

### Behavioral evidence

The acceptance image exercises successful and invalid syscalls, translation,
write-permission, execute-permission, illegal-instruction, unexpected-entry,
page-return, execution-timer, external input/network IRQ, heap-growth-limit,
and AArch64 thread-pointer preservation paths. Terminal fault sessions exercise
kernel-origin write, execute, synchronous-exception, and task-stack-guard paths.
The acceptance image exceeds 1 MiB and therefore also exercises the
page-relative data-symbol relocations used by AArch64 entry and completion.
The source contract test pins assembly ordering that cannot be probabilistically
inferred from one emulator timing interleaving. Both target lints and all four
exhaustive QEMU profiles remain mandatory after a gate change.

## IPC baseline and measurement contract

This section defines repeatable measurements for the current synchronous
in-process dispatcher and protected diagnostics-server path. QEMU validates
counters and bounds; publishable latency claims require named real hardware.

### Reproducing the host matrix

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

### Native acceptance matrix

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

### Isolated diagnostics matrix

The acceptance kernel runs the same logical payload matrix through a
least-authority EL0/ring-3 diagnostics transport server. Each row uses 64 warmup
requests and 256 measured requests. The interval begins when the server
endpoint starts delivering the first fragment and ends when it accepts that
request's final generation-checked reply. It includes the copied handoff,
protected execution, reply gate, address-space switches, TLB work, and lease
programming, but excludes process construction, teardown, and serial formatting.

The v1 server envelope carries a token, interface, opcode, bounds, and reserved
bytes inside the 4 KiB call limit. A 4096-byte logical payload consequently uses
two bounded fragments; smaller rows use one. Reply tokens change for every
fragment, and a logical sample completes only after every fragment is echoed
and validated.

The kernel uses fixed 4 KiB request and caller-owned reply buffers for
server-endpoint calls. `Service::call_into` encodes directly into the reply
buffer. No payload alias crosses the protection boundary: the server receives
a copy and the kernel validates and copies its reply. Every measured
receive-to-reply interval must have exactly zero owned-heap allocation calls.
Construction and final client-reply ownership remain bounded setup/teardown
outside that steady interval.

The current diagnostics-server composition has hard ceilings of one retained request and one
suspended server context. The acceptance-probe build permits 1536 isolated
service calls so 320 two-fragment warmup and measured exchanges fit in one
server lifetime.

### Deterministic native structural result

Both QEMU architecture gates require these totals for each 256-request row:

| Logical payload | Wire fragments | Request copies | Reply copies | Reply allocations | Address-space switches | TLB invalidations | Timer programs |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 256 | 0 | 0 | 0 | 512 | 512 | 256 |
| 64 | 256 | 512 | 512 | 0 | 512 | 512 | 256 |
| 256 | 256 | 512 | 512 | 0 | 512 | 512 | 256 |
| 4096 | 512 | 1024 | 1024 | 0 | 1536 | 1536 | 768 |

The zero-byte row counts payload copies, not fixed envelope writes. x86-64
currently reloads CR3 in each direction; AArch64 changes TTBR0 and executes a
full `TLBI VMALLE1`. No ASID/PCID retention is implemented or simulated; the
protected-IPC design that would add it is tracked in
[GitHub issue #8](https://github.com/dennissoftman/troe/issues/8). One lease is
deliberately programmed for every user-execution segment; removing that safety
boundary is not an acceptable latency optimization.

The isolated path performs no transient kernel allocation in its measured
receive-to-reply interval and copies directly into caller-owned bounded storage.
Reply ownership, token generation checks, server-fault fate, and teardown remain
part of the current contract.

## Maintainer merge and release gates

The repository intentionally has no GitHub Actions workflow. The maintainer
runs `python3 scripts/test.py --require-filesystem-tools` locally before a
merge. This exhaustive behavioral gate accepts QEMU `8.x` through `11.x`,
structurally valid matching distribution UEFI firmware, and e2fsprogs `1.47.x`;
the ext4 byte verifier and all guest scenarios remain unchanged.

Release-grade reproducibility evidence uses
`python3 scripts/test.py --strict-tool-versions --require-filesystem-tools`.
That strict environment must provide Rust 1.97.1, QEMU 11.1.0, the committed
`edk2-stable202605-r1` firmware bytes, `cargo-audit` 0.22.1, e2fsprogs 1.47.4,
dosfstools, and mtools. The focused selector is a development aid and does not
replace the maintainer-owned exhaustive gate.

The non-QEMU production gate is separate because it requires a Linux x86-64
host with KVM and a pre-created isolated TAP. It verifies the exact v53.0
Cloud Hypervisor and `ch-remote` static assets, `CLOUDHV.fd` release
`ch-f308d878a6`, a production-identity bundle, process reopen, rollback, reboot,
and corrupted-StateFS recovery. Run it only as documented in
[`cloud-hypervisor-production.md`](cloud-hypervisor-production.md). A dry-run,
host-only test, QEMU result, or fixture-identity bundle is not production
acceptance evidence.

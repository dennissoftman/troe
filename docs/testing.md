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

The exhaustive runner executes one gate at a time and emulates one named
platform at a time. It invokes `scripts/test-qemu.py` once per named platform
instead of once for all of them, so a single guest competes for host memory,
cores, and local ports even when other checkouts run their own gate. Coverage
is unchanged: every named platform and every scenario group still runs. The
concurrent multi-platform path stays available by invoking
`scripts/test-qemu.py --platform all` directly.

The runner prints its numbered gate plan before the first command, then reports
each gate's start time, exact argv, and duration. While a gate runs it repeats a
liveness line every `--progress-interval` seconds, sixty by default, so a long
silent platform is distinguishable from a stalled one. `--progress-interval 0`
suppresses those lines. A failing gate is named on standard error with its
elapsed time and the number of gates that already passed.

`--skip-qemu` is only an environment escape hatch. It does not mean that QEMU
coverage is unnecessary; the full pinned gate must still run on the merge
runner. `--require-filesystem-tools` makes absence of the exact external FAT32
and ext4 interoperability tools an error. `--require-python-tools` does the
same for the Python format and lint gates.

## Portable thread and synchronization models

`cargo test -p troe-task --lib thread::` exercises the process-owned lifecycle
policy: transactional admission, per-process/global charges, stale generations,
join/detach and timeout claims, creator exit, sticky stop, and reclamation only
after native acknowledgement. The corpus includes 10,000 short transition
schedules, each followed by complete model teardown and accounting checks.

The paired synchronization model covers FIFO grants, self-lock/non-owner errors,
expired and stopped waiters, stale events, condition binding/reacquisition,
notification cohorts, both owner-death policies, ownerless permits, quotas and
resource-release interlocks. It also enumerates 3,125 five-event schedules over
notification, timeout, stop, unlock and exit. Each step checks queue membership,
exact ownership, pending-completion references and unchanged vector capacities;
each schedule ends with teardown and resource-baseline checks.

Metadata checks compare the compiled inline/array layouts with retained vector
capacities, test exact-byte and one-byte-short budgets, reject invalid counts
before allocation, and ensure retirement does not refund reserved backing.
`cargo test -p troe-task --lib thread::admission::` checks the combined table
budget, protected IPC headroom and the enforced per-process ceiling. Its
two-process case blocks every admitted thread simultaneously, then times out
and consumes every wait without changing the retained metadata charge.
The maximum-capacity calculation is compared with exhaustive candidate
validation over varied object counts, context limits and metadata budgets.

These tests verify the portable policy; they do not execute application threads
or establish machine-level TLS, isolation, pthread, or physical-reclamation
support. Changes to the crate also select its consumers and native regression
scenarios through the normal impact selector.

## Static TLS layout and compiler probes

`cargo test -p troe-application --lib static_tls::` checks both architecture
layouts, empty and zero-filled templates, alignment padding, complete page
charges, displacement ceilings, overflow, virtual-range boundaries, independent
thread storage, and unchanged destination bytes after rejected initialization.
Successful initialization must overwrite every byte, including reused padding.

`python3 -m unittest discover -s tests -p test_kex_tool.py -k StaticTls -v`
compiles and links eighteen C11 local-exec fixtures for x86-64 and AArch64. It
reads the ELF TLS geometry and symbols, decodes the actual address-return
instructions, and compares their thread-pointer offsets with the Rust planner
through `cargo kex tls-layout`. The fixtures cover sub-word and over-page
alignment, BSS-only templates, odd lengths, and both halves of AArch64's
24-bit relocation. Unexpected instruction sequences require explicit review;
they are not silently interpreted as equivalent. Ordinary conversion rejects
these inputs; explicit `convert --threaded` must emit canonical container 1.3
with matching geometry and initializer bytes and pass reproducibility checks.
The test linker uses separate loadable pages and an explicit full-page `.text`
extent so target trap padding is described, preserving strict unexplained-byte
rejection. Additional compiled fixtures check empty TLS, pointer-fixup rejection,
malformed headers/sections/symbols, trampoline identity, and unchanged output
after failed conversion.

`cargo test -p troe-application --lib tls_artifact::` checks exact extension
versions, reserved bytes, all truncations, source/suffix agreement, relocation
overlap, file-backed entries, and empty/BSS-only templates on both targets.
Native and streaming package loaders must reject this format even when their
caller supplies a higher ABI ceiling. Inspection produces no native load plan.

The probes require `clang` and `ld.lld` and fail if either is unavailable.
`TROE_TLS_CC` and `TROE_TLS_LD` select explicit executables; compiler/linker
versions are printed with the results. Missing tools do not skip this check.
Changes to `troe-application` select these probes as well as Rust and native
regression checks. These are host compiler/layout checks, not evidence of
thread-pointer switching or TLS execution inside a guest.

The shared recipe in `tools/thread_profile.py` selects explicit target CPU/TLS
options, Clang builtin headers and the TROE sysroot, and excludes ambient
compiler configuration and include-path variables. The C ABI probe checks
freestanding LP64/LE, type widths, lock-free word atomics and separate TLS
storage. It also verifies that ABI-1 `errno` is still a non-TLS declaration.

Pin qualification uses the exact Clang/LLD releases in
`sdk/c/thread-profile-v1.json`. Select explicit executable paths where required:

```console
python3 tools/thread_profile.py --cc /path/to/clang --ld /path/to/ld.lld \
  --output /tmp/troe-thread-profile.json
python3 tools/thread_profile.py --compatible-tools
python3 -m unittest discover -s tests -p test_thread_profile.py
```

Both tool families are checked. Strict mode rejects other releases before
qualification; compatible mode records whether each pin matches. The report
binds tool binaries, builtin/sysroot headers, compiler recipe, linker script,
probe and format-decoder sources, Cargo lock and Rust toolchain specification
by SHA-256. Inputs are fingerprinted before and after the run. Required probes
must be present and pass without skips or expected failures; zero selected tests
cannot produce success. A failed qualification leaves an existing report
untouched. Report publication is an atomic replacement in its destination
directory; the directory must already exist.

This is regression/provenance evidence, not a signed toolchain attestation or
native admission credential. Reports always state `qualification_only: true`
and `native_admission: false`. The recipe's disabled stack protector and RELRO
apply to layout qualification only. The selected runtime ownership and native
hardening prerequisites are recorded in [ADR 0071](adr/0071-native-threads-and-owned-synchronization.md).

## Thread memory planning

`cargo test -p troe-application --lib thread_memory::` verifies complete guarded
windows, TLS initializer agreement, sparse alignment gaps, page-zero and user
range exclusion, overflow, and independent mapped-page, resident-page,
reserved-page, ordinary-frame and IPC-pair budgets. Checked sums include all
retained plans and reject overflow in derived byte counts. IPC pages count toward logical
resident charges without also consuming ordinary-frame allowances. The immutable
startup descriptor consumes a mapped page and an ordinary frame. Tests check
its read-only region kind and compose complete descriptor bytes from both
compiler TLS layouts without overlapping stack guards or private IPC.

An independent oracle enumerates mapped pages and collects their parent-table
identities. The constant-work table calculation must match it across 512
generated layouts and explicit 2 MiB, 1 GiB and 512 GiB boundary cases. A 1 TiB
stack case exercises planning without allocating or walking its pages. These
tests verify geometry and accounting only; they do not reserve memory, validate
collision against live mappings, or establish native guard-fault/teardown behavior.

`cargo test -p troe-application --lib process_memory::` checks whole-process
placement and peak memory charges. It verifies disjoint shared/initial-thread
reservations on either side of the image, image holes, reserved heap growth,
guard-only collisions, zero heap and empty/BSS/initialized TLS, image permission
preservation, and complete initial-descriptor round trips. Every independent
budget is tested at its exact boundary and one unit below it. A page-enumerating
oracle checks the combined table count across 512 layouts with sparse images,
all sixteen load records, large TLS alignments and table-boundary crossings.
Maximum 16 TiB heap and stack requests exercise bounded work without allocating
their backing. Tests account for architecture-specific empty-TLS padding and
prove native loaders continue to reject the artifact after successful preflight.

`cargo test -p troe-application tls_owner::` checks owned staging and immutable
initializer lifetimes, reservation-before-allocation, malformed input and injected
allocation failure, actual-capacity rejection/charges, failed-update rollback,
overflow and competing retained owners. Stop is permanent and refunds nothing
until drop. Both compiler layouts initialize from the original template after
staging release and after other image/TLS copies change; bad destinations remain
untouched. The tests distinguish zero initialized bytes from a nonempty compiler
TLS mapping and verify cleared destination slack. Compile-fail examples reject
releasing staging with a live artifact borrow and sharing the account as `Sync`.
These are portable buffer-lifetime checks, not native frame-reuse or context
quiescence evidence.

`cargo test -p troe-abi --lib threading::` checks every operation, exact wire
lengths and reserved bytes, typed token/generation boundaries, deadline tags,
response correlation and ownership-sensitive outcomes. Adversarial bit mutations
must be rejected or reproduce identical canonical bytes. Startup tests reject
overlap, arithmetic overflow and nonzero page slack. Application encoder and SDK
tests also prove ABI 1.0–1.3 cannot gain threading from newly assigned interface
IDs, and that ABI 1.4 stays rejected. These checks do not execute native threads.

## Python tooling gates

The repository's own Python is formatted and linted by one tool. `ruff` is both
the formatter and the linter, configured in `pyproject.toml`, which exists for
no other purpose: TROE ships no Python package. The exhaustive gate runs

```console
ruff format --check .
ruff check .
```

immediately after the Rust format gates, and `scripts/test_changed.py` runs the
same two commands over exactly the Python files that changed. A changed
`pyproject.toml` widens the focused selector to the full gate, because a lint
policy change has no bounded impact.

`line-length` is 88 and `target-version` follows `MINIMUM_PYTHON` in
`scripts/repository_policy.py`. `extend-exclude` names only vendored and
generated trees: `apps/lua/vendor`, `apps/python/patches`, `build`, and
`**/target`. Every other Python file in the repository is in scope, including
the CPython guest probes under `tests/fixtures/cpython`. The selected rule set
and each disabled rule's rationale live in `pyproject.toml`. A rule that is
wrong for the repository is disabled there rather than with a scattered `noqa`;
nineteen per-line directives survive where the reverse is true, and the same
file inventories them. `RUF100` is enabled, so a directive that no longer
suppresses anything fails the gate.

The guest probes are the one tree these gates cannot prove correct: they are
copied into the image and executed by the shipped interpreter inside the TROE
guest, so only the QEMU `cpython` group runs them. `ruff format` is safe there
because it preserves the parsed tree exactly. `ANN201`, `I001`, and `N813` are
disabled for that tree because satisfying them would rewrite what the guest
executes -- an annotation evaluated at definition time, the order the probe
imports the standard library in, and the form its `xml.etree` import takes.
Run the QEMU `cpython` group before merging any change to those files that
`ruff format` did not make.

`ruff` is resolved from `PATH` by name, exactly like the host image utilities.
Absence skips both gates with a notice on standard error;
`--require-python-tools` makes that absence a failure. Install it with
`brew install ruff`, `cargo install ruff`, or the distribution package.
`tests/test_repository_policy.py` asserts that the configuration exists, that
the excluded paths are exactly the vendored and generated ones, that both
runners execute the two commands, that both runners skip them when `ruff` is
absent and fail under `--require-python-tools`, and that linting with
suppressions ignored raises exactly the nineteen inventoried findings, so an
uninventoried `noqa` fails the gate.

## Application and service gates

`apps/` and `services/` are each one Cargo workspace with one committed
`Cargo.lock`. Their members inherit `[workspace.package]` and
`[workspace.lints]` and declare neither a workspace root nor a release profile
of their own, so the shipped commands and services are inside the format, lint,
and test gates rather than beside them.

The exhaustive runner covers them with five kinds of gate:

- `cargo fmt (applications)` and `cargo fmt (services)` check the whole tree.
- `clippy app (<command>)` and `clippy service (<name>)` lint one package at a
  time for `x86_64-unknown-none` and `aarch64-unknown-none` at `-D warnings`.
  One package at a time is required, not tidier: Cargo unifies features across
  everything it builds together, and `ls` and `mem` take `troe-kex-runtime`
  without the `alloc` feature that `cp`, `mv`, and `rm` enable. A single
  workspace-wide build would lint those two against a feature set they never
  ship with, and would fail to compile for want of a global allocator.
- `clippy applications (host unit tests)` lints the library test modules on the
  host, which is where they run.
- `cargo test applications` runs the 31 library unit tests in `awk`, `grep`,
  `printf`, `sed`, `tar`, `timesync`, and `wc`. A command binary is
  `#![no_main]` and declares `test = false`, so `--tests` and `--lib` reach the
  library targets only; the binaries cannot host a test harness on either a bare
  target or the host.
- `kex shared app (lua)` builds the one shared-volume deliverable the gate can
  build. A shared-volume application ships no committed `.kex`, so there is no
  `kex app (<command>)` byte-for-byte `--check` for it and nothing short of a
  QEMU acceptance run would otherwise compile it. Building it here keeps
  `cargo kex build` covered for every member it can reach.

`python` is excluded from the lint, test, and build gates. Its build script
consumes the CPython tree that `tools/build_cpython.py` generates outside the
repository, so reaching it would make an out-of-tree build a prerequisite of
`cargo clippy`; its Rust bridge is covered by `test_cpython_integration.py`
instead. `lua` is included: the Python suite already compiles its vendored C
runtime.

That exclusion is a real hole, not a technicality: `unsafe_code = "deny"` and
the `unwrap_used`, `expect_used`, and `panic` denies are declared for the whole
tree but never compiled against `apps/python/src/main.rs` or
`apps/python/build.rs`, and the `#![allow(...)]` in that build script is
therefore inert. Two policy tests substitute for the missing compiler pass:
`test_the_unlinted_member_keeps_the_denied_constructs_out` fails if a shipped
`python` source grows an `unwrap`, `expect`, or explicit panic, and
`test_every_unsafe_opt_in_is_named_at_its_crate_root` holds its undocumented
`unsafe` count to a shrink-only ceiling. Neither substitutes for
`clippy::pedantic`; `python` alone is held to a lower standard than the other
38 applications. That build script keeps its `#![allow(...)]` header even
though nothing compiles it: the header states why a build script may panic, it
is identical to the one in `apps/lua/build.rs` that clippy does enforce, and
`test_panicking_allowance_stays_inside_build_scripts` names both files, so the
day `python` re-enters the lint gate the exemption is already correct rather
than a new finding.

Both trees start from the root workspace's lint levels and deviate in two ways,
each recorded in the workspace manifest next to the setting:

- `unsafe_code` is `deny` rather than `forbid`. Four members genuinely need
  `unsafe` -- the Lua and CPython FFI bridges, `mem` reading pages it mapped for
  itself, and the fault-injection service trapping on purpose -- and `forbid`
  cannot be lifted. Each of the four opts in with one crate-level
  `#![allow(unsafe_code)]` and a stated reason.
- `missing_docs` and seventeen named `clippy` lints are `allow`. Each is a lint
  the shipped sources violate today. A panic location records the file and line
  of its call site, so every `.kex` package embeds the line numbers of its own
  sources: fixing any of these findings moves a line and rewrites a committed
  binary artifact. Every other lint in `clippy::all` and `clippy::pedantic`
  stays on, and `unwrap_used`, `expect_used`, and `panic` stay `deny`.

`scripts/test_changed.py` selects the same gates for a changed application:
formatting, both bare-metal clippy targets, and, when the package has a library,
its host lint and unit tests. A changed command is checked byte-for-byte against
its committed artifact; a changed shared-volume application is built instead,
because it has no committed artifact to compare against. Changing
`apps/Cargo.toml`, `apps/Cargo.lock`, or either services counterpart widens to
the full gate, and changing `apps/common.rs`, which 33 commands include, widens
to every application gate and every QEMU scenario.

## QEMU scenario groups

`scripts/test-qemu.py` accepts a repeatable `--scenario` option. Omitting it
selects the default groups; Lua and CPython require explicit selection. Multiple
selected groups run in their canonical order during the same primary guest boot
where possible.

| Group | Runtime contract exercised |
| --- | --- |
| `boot` | Owned boot, production activation, StateFS diagnostics, packaged KEX launch |
| `network` | Link and IPv4 state, DHCP, ICMP, ARP, cancellation, UDP including a terminal-supplied datagram payload, bounded TCP streams |
| `shell-terminal` | Editing, completion, history, manuals, parsing, CRLF, clear-screen behavior, and the foreground session terminal-input loan: typed lines, end of input, cancellation, background and nested end-of-input, resident-job and service coexistence, and unchanged redirection and pipelines |
| `filesystem` | KEFS/ext4/FAT32 reads and writes, shared-media restart persistence, paths, logical lists, pipelines, bounded `sh.kex` scripts, RAMFS mutation, read-only and error behavior, explicit-path `.kex` fallback for direct and nested launches with consent and exact-file precedence, bare-name isolation from the current directory, plus repeated direct and nested launches of the large shared-media C runtime probe |
| `system-baseline` | Compatibility IPC samples and structural counters, 1,472-byte UDP round trips, 16 KiB TCP transfers, and five internally timed boots from identical media |
| `storage-baseline` | Fresh-media ext4/FAT32 4 KiB read and write-plus-sync timing, exact payload checks, and frozen fixture validation |
| `lua` | Explicit-path execution of the optional shared-media runtime, Lua inline/stdin/file loading, the portable compute/allocation benchmark, consolidated language/numeric/system examples, script argument/`-l` compatibility, exact binary64 formatting, complete pipe reads, buffering modes, protected errors, shared-runtime math/calendar/environment/process/random behavior, typed filesystem errno failures, OS-shim clock and exit behavior, timer preemption, fragmentation, a 48 MiB private allocation beyond the former narrow TLSF geometry, and bounded OOM recovery. Not selected by default: it consumes the shared runtime tree, which the `filesystem` group also installs |
| `cpython` | Version-addressable and default interpreters, explicit-path execution consent, `-c`, arguments after `--`, scripts, `-m`, redirected stdin, an interactive REPL that retains state and ends on end of input, upstream Unicode/GC/weakref/traceback semantics, the shipped library profile plus a full shipped-module import sweep, TROE-backed filesystem/temporary-file/clock/entropy behavior, excluded modules and explicit thread-creation failure, withheld random and mutation authority, and kernel-frame reclamation across repeated successful and failing launches. Not selected by default: it consumes the separately built interpreter package (see below) |
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

## CPython acceptance inputs

The `cpython` group runs against the authenticated interpreter package rather
than rebuilding it, so build the package and the capability-negative
interpreters into `build/` first. The package build fetches, digest-checks, and
Sigstore-verifies each pinned upstream release, so it needs the `sigstore` CLI
and an exact build Python for every pinned series.

```console
python3 tools/build_cpython.py build build/cpython-package --version all \
  --source-cache "$TROE_CPYTHON_CACHE" --work-directory "$TROE_CPYTHON_WORK"

python3 tools/build_cpython.py variants build/cpython-diagnostics \
  --work-directory "$TROE_CPYTHON_WORK"

python3 scripts/test-qemu.py \
  --platform all --environment qemu --scenario cpython
```

One command repopulates a recreated shared medium with every optional runtime.
It cross-builds each named application for both architectures, publishes them
into `/vol/shared/bin/<architecture>`, and installs an already-built CPython
package alongside them:

```console
python3 tools/mkruntime.py provision \
  --image build/troe-shared-fat32.img \
  --app lua --cpython-package build/cpython-package --reset
```

Drop `--reset` to add runtimes to an existing medium, and repeat `--app` for
each additional application. The CPython package is installed rather than
rebuilt, because building it is the slow authenticated step above.

`python` is not a valid `--app` name. `apps/python` links against a generated
CPython tree, so it only builds when `tools/build_cpython.py` supplies
`TROE_CPYTHON_BUILD`, `TROE_CPYTHON_SOURCE`, `TROE_CPYTHON_SYSROOT`,
`TROE_CPYTHON_VERSION`, `TROE_CPYTHON_SERIES`, and
`TROE_CPYTHON_ARCHITECTURE`. Passing `--app python` runs a bare
`cargo kex build apps/python`, and its build script fails with
`TROE_CPYTHON_BUILD must name a generated CPython path`. Build the
authenticated package once with the command above and install it through
`--cpython-package` instead:

```console
# Wrong: the interpreter has no CPython build environment here.
python3 tools/mkruntime.py provision --image build/troe-shared-fat32.img \
  --app python --cpython-package build/cpython-package

# Right: the package supplies the interpreter; --app is for other runtimes.
python3 tools/mkruntime.py provision --image build/troe-shared-fat32.img \
  --cpython-package build/cpython-package
```

`--check` builds the package twice in independent directories and compares
every output byte. Reuse the retained work directory for `variants`: the
capability-negative interpreters relink the already-built library rather than
rebuilding CPython.

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
Syscall and user-timer frames save FS/GS/DS/ES selectors and the independent
full FS base. Before Rust, gates clear FS/GS selectors and FS base and restore
the fixed kernel DS/ES selectors; input IRQs also save, normalize and restore
this state. Terminal exception gates normalize it before dispatch. Kernel
timer IRQs enter with the fixed kernel profile. Each resumed user context
restores selectors before FS base. The owned flat GDT, disabled LDT and
disabled FSGSBASE keep GS base zero. Acceptance handlers observe all four
selectors, both FS/GS bases and LDTR before doing their work; loader probes
also check this kernel profile after every native return, including faults
and final exit.

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
and both architecture thread-pointer preservation paths. The x86 probe binds
only a validated writable nonexecutable user word, checks that all four data
selectors start at zero, then installs a nonzero user data selector in each.
It rejects null, executable and overflowing TLS addresses without modifying
the saved context, then verifies FS:0 and all four selectors after yield and
actual timer preemption. A separate native isolation probe attempts to load
GS from the disabled LDT and requires a contained fault and full reclamation.
A 1 ms initial TLS probe slice forces the preemption;
subsequent slices use the ordinary 50 ms limit. Read-only checks
verify the retained base and selectors before each resume, without repairing
them. The loop and accepted preemption count are bounded. Terminal fault
sessions exercise kernel-origin write, execute, synchronous-exception, and
task-stack-guard paths.
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

The acceptance-only compatibility diagnostics composition retains one request
and one suspended server context. The acceptance-probe build permits 1536 isolated
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

The zero-byte row counts payload copies separately from fixed envelope writes.
This compatibility path reloads CR3 in each direction on x86-64; AArch64 changes
TTBR0 and executes `TLBI VMALLE1`. Each compatibility execution segment retains
its existing lease program. The private-page path below uses retained tags and
donates one absolute lease across handoffs.

The isolated path performs no transient kernel allocation in its measured
receive-to-reply interval and copies directly into caller-owned bounded storage.
Reply ownership, token generation checks, server-fault fate, and teardown remain
part of the current contract.

## Private-page IPC and tagged-root gate

`kernel/src/ipc.rs` runs ABI 1.3 client and persistent echo artifacts in the same
acceptance image and boot as the compatibility matrix. Each payload (0, 64,
256, 4,096 bytes) has direct and queued rows, each with 64 warmup calls followed
by 256 measured calls. One lease covers the complete measured batch. Timing
begins at kernel call admission and ends after validated reply completion and
the root handoff; construction, teardown, and diagnostic output are excluded.
The unsorted `ipc-phase-b-samples` records use the same counter/frequency as
`ipc-samples`; frozen fixtures in `tests/fixtures/adr-0035` are never rewritten.

Measurements are grouped by payload: compatibility, Phase B direct and queued,
then Phase C general-direct. Each group uses one compatibility sample array.
Its serial transcript is emitted after all paths finish, including observations
collected before a failure. Native fault probes run after the latency groups.
This keeps comparisons close in time without changing clocks, sample counts,
warmups, timing boundaries, or thresholds; host scheduling can still affect
the results. The release build optimizes the machine, service, task and dispatch
crates for speed while retaining the workspace's size profile elsewhere.
Scalar call/reply decoding can inline into the native checked path. Phase B
reply/wait saves the server context before publishing its next event, then
restores the caller directly; it does not copy the updated server context
through the trap frame before restoring that caller. The native deadline and
queued-delivery case verifies that the published server event survives.
Phase B recognizes the explicit infinite-wait sentinel before reading the
monotonic clock. Finite waits, call deadlines and the execution lease retain
their checks, including the native expired-wait and call-timeout cases.

For each nonempty direct round trip the gate requires one request copy, one
reply copy, two user-root handoffs, zero heap allocations, zero queue slots,
zero scheduler scans, zero targeted/full invalidations, and zero additional
lease programs. Queued requests copy into and out of one preallocated slot,
which is fully zeroed on delivery; replies still copy once. Zero-length
payloads cause zero payload copies. The measured batch includes 512 direct
traps or 768 queued traps, plus its final client yield. Scheduler snapshots,
actual allocation/timer counters, native tag/root counters, and payload counters
must agree before a row is emitted.

`scripts/ipc_phase_b.py` independently recomputes nearest-rank p95 values from
both arrays. Direct p95 divided by same-boot compatibility p95 must be at most
0.70 at every payload size. A queued ratio is reported without a
latency threshold. All rows must use one clock and feature mode. Evidence is
written to `build/ipc-phase-b-<platform>-<tagged|fallback>.json`, including raw
samples, structural counts, host, QEMU command, and acceptance-image SHA-256.
Hosted acceptance uploads those files as artifacts.

The general runtime is separately measured by `kernel/src/supervisor/benchmark.rs`
using the same native client and same-boot compatibility samples. Its
`general-direct` rows must meet the same copy, root, trap, allocation, scheduler,
and lease requirements. The Phase C p95 budget is 0.70 at every payload size;
its records encode that limit as 700/1000 using
`ratio_scale=1000`. Phase B encodes the same cap as 70/100. The performance
follow-up is tracked in [issue #211](https://github.com/dennissoftman/troe/issues/211).
`scripts/ipc_phase_c.py` also requires seven native
fault rows: before receive, after receive, in a nested call, before reply, after
reply validation, while queued, and while blocked. Each row proves one fate per
client, exact transport/wait/frame cleanup before replacement, a new incarnation,
and a successful subsequent normal call. The queued and blocked cases also
exercise an independent live caller. Evidence is retained in
`build/ipc-phase-c-<platform>-<tagged|fallback>.json` with raw timings and the same
machine/image identity as the Phase B evidence. Latency failures require
investigation; retries must be disclosed and thresholds must not be reduced.

AArch64 profiles require real ASID use in the emulated architecture. x86 TCG
reports the full-flush fallback and cannot satisfy a tagged-profile claim. The
two x86 hosted profiles also run `qemu-kvm` with `-cpu host -accel kvm`, require
PCID plus INVPCID, and fail if hardware tagging is unavailable. There is no
silent accelerator fallback.
The KVM virtio-PCI runner uses the same QEMU cloud-bundle format and compiled
guest probe port; its output directory and recorded command identify KVM.
Local SBSA acceptance uses the pinned firmware:

```console
python3 scripts/test-qemu.py --platform aarch64-sbsa-ref --environment qemu
python3 scripts/test-qemu.py --platform x86_64-q35-uefi --environment qemu-kvm --scenario fault-isolation
```

The native safety matrix checks all 20 pool slots and atomic exhaustion,
zeroization on provisional release and terminal reuse, stale tag rejection
across root reincarnation, and native ABI 1.0/1.1/1.2 compatibility calls. The
adversarial persistent task exercises clean exit, server lease expiry, repeated
handoffs until the original lease expires, stale token, oversized reply,
zero-token reply while owning a call, supervisor-alias access, NX execution, and
server exit with an undelivered queued request.
Client probes exercise illegal object parameters and past/oversized deadlines.
Each terminal case has one caller fate, no replay, and exact frame/handle/page
cleanup. The general lifecycle models remain covered by host tests; the native
IPC composition is the synthetic two-task endpoint.

## Storage baseline capture

The default QEMU gate includes `storage-baseline`. This scenario measures the
current application filesystem path on fresh disposable ext4 and FAT32 media.
Cloud profiles copy the verified bundle system disk before each baseline
scenario; guest writes never modify the pristine bundle. Split profiles reset
their separate root disk. Platforms run sequentially to avoid competing
measurement guests. Run just
this scenario with:

```console
python3 scripts/test-qemu.py --platform all --environment qemu --scenario storage-baseline
```

The harness builds `tests/storage-baseline` as a standalone KEX package on the
shared disk. It uses an acceptance-only timer diagnostic to sample the same
architecture counter as the IPC matrix. The SDK `acceptance-probes` feature
exposes this hook; production kernels reject its payload, and the production
image verifier rejects its marker. No baseline executable is installed into the
production rootfs.

Each volume runs 64 unreported warmups followed by 256 timed 4 KiB writes, then
64 warmups and 256 timed 4 KiB reads from that file. A write interval includes
`begin_append`, the complete 4 KiB `write_all`, and `commit` (including the
provider sync). The current ABI splits both a 4 KiB write and read across two
bounded data calls. Read intervals cover the loop that receives all 4 KiB at
consecutive offsets; open/close and
byte-for-byte payload validation are outside the interval. The payload is
4096 bytes of `0x5a` with its first eight bytes replaced by the little-endian
chunk index; a repeated or reordered chunk therefore fails verification. Every
operation yields outside its measured interval, and
all serial formatting occurs after the samples for a row have completed.

Elapsed ticks include kernel execution and device waits. Each interval also
includes the return half of the first timer call and entry half of the second;
no timer-overhead subtraction is applied. The fixture retains every sample,
nearest-rank p50/p95, and throughput calculated as total measured bytes divided
by total elapsed time. These are QEMU engineering measurements, with no absolute
hardware latency claim.

Frozen fixtures live under `tests/fixtures/adr-0035/storage-*.json`. Capture
requires a fresh build and an explicit output directory; it refuses
`--skip-build` and existing output files:

```console
python3 scripts/test-qemu.py --platform all --environment qemu --scenario storage-baseline --record-storage-baseline /tmp/troe-storage-capture
```

Capture records the QEMU command and version, verbose Rust version, host,
source/base revision, probe hash, and hashes of firmware and disk inputs before
boot. The ordinary gate validates the frozen contract and recomputes its
statistics from the raw samples, then writes fresh observations separately to
`build/storage-baseline-results`. It does not treat another run's timing as an
absolute pass threshold. The subsystem migration and same-image ratio gates
are specified by [issue #8](https://github.com/dennissoftman/troe/issues/8).

## IPC, network, and boot baseline capture

The default `system-baseline` scenario freezes current-path
measurements in `tests/fixtures/adr-0035/system-*.json`, one file per platform.
It runs sequentially when multiple platforms are selected:

```console
python3 scripts/test-qemu.py --platform all --environment qemu --scenario system-baseline
python3 scripts/test-qemu.py --platform all --environment qemu --scenario system-baseline --record-system-baseline /tmp/troe-system-capture
```

Explicit capture requires a fresh build and refuses existing destination files.
Ordinary verification validates the frozen fixture, recomputes every statistic,
and saves fresh observations in `build/system-baseline-results`. Timings from
different runs are not absolute pass thresholds.

Each IPC row preserves all 256 samples in measurement order, alongside the
existing p50/p95/p99 and exact structural counters, for both current paths and
all four payload sizes. The new `ipc-samples` diagnostic is emitted after the
timed calls. A zero-tick individual IPC sample is valid counter quantization;
negative samples and runs with no total elapsed ticks are rejected.

The harness installs `tests/network-baseline` only on the disposable shared
volume. Each transport runs 64 warmups and 256 samples against a loopback-bound
host peer reached through QEMU's `10.0.2.2` gateway. UDP sends and receives one
1,472-byte datagram per sample on one owned port. TCP uses one established
connection, writing 16 KiB and reading its complete echo per sample through the
SDK's bounded partial calls; connection setup and close are outside the timed
interval. The peer enables `TCP_NODELAY`. Both sides check the exact payload:
`0x5a` bytes with an eight-byte little-endian sample index. The fixture records
the peer ports and policy. Network throughput counts the request and echoed
payload bytes together; headers are excluded. Guest yields, payload comparison,
and serial result formatting occur outside the intervals. Timer-call overhead
is included, as in the storage measurements.

Boot samples use five fresh QEMU processes with identical command, firmware
state, and disk bytes. The harness snapshots mutable inputs once, restores them
before each boot, and verifies their hashes again. Acceptance-only internal
markers sample entry to `post_handoff` and readiness to print the first shell
prompt. The dedicated IPC benchmark interval, including its diagnostic output,
is subtracted; ordinary boot initialization remains inside the interval. The
boot record is formatted and transmitted only after the ending counter sample,
so host serial arrival time and measurement-record formatting are excluded.

Each boot retains its start, end, excluded interval, and calibrated counter
frequency. Its elapsed ticks are normalized to integer nanoseconds before
computing the five-boot median; calibration can differ slightly between fresh
x86 guests. These normalized ticks remain QEMU engineering evidence, not an
absolute hardware latency claim. The first boot also supplies the IPC and
network rows, which must agree on their counter frequency. The fixture includes
QEMU/Rust identifiers and hashes of probe, source, firmware, and disk inputs.
Production image builders reject both the boot and IPC-sample diagnostic
markers.

## Maintainer merge and release gates

The merge gate runs on GitHub Actions, in `.github/workflows/gate.yml`. It
runs the same gates as a local invocation and accepts the same compatible tool
policy: QEMU `8.x` through `11.x`, structurally valid matching distribution
UEFI firmware, and e2fsprogs `1.47.x`. The ext4 byte verifier and all guest
scenarios are unchanged.

The e2fsprogs range is narrower in practice than its version check states. The
byte verifier requires every active inode's timestamps to equal the fixed epoch
in `tools/mkstorage.py`, which only a `mke2fs` that honours
`E2FSPROGS_FAKE_TIME` can produce. `1.47.4`, the pinned version, is verified.
`1.47.0`, which Ubuntu 24.04 ships, passes the `1.47.x` check and then fails
the verifier with `ext4 inode timestamps are not deterministic`. Which release
between them gained the variable is not established here, so treat the pinned
version as the requirement and build it from source when a distribution
package is older — `.github/actions/pinned-e2fsprogs` does exactly that, and
proves the variable is honoured before the gate runs rather than letting the
failure surface minutes later. `MINIMUM_E2FSPROGS_VERSION` still admits
`1.47.0`, so the version check alone does not reject a tool that cannot satisfy
the verifier.

The hosted run covers all four named platforms. SBSA uses
`.github/actions/pinned-sbsa` to build SHA-256-pinned QEMU 11.1.0 and the firmware
commits in `tools/sbsa-firmware-sources.lock.json`. The other hosted runners use
the compatible distribution tools; both x86 profiles also require real KVM
PCID/INVPCID coverage. Local SBSA release evidence still uses strict tool pins.

Two properties are specific to the hosted run. Each hosted platform gets its own
runner, so the fixed acceptance UDP ports cannot collide the way two overlapping
runs on one machine do. And the work is selected by `scripts/test_changed.py`
from the changed paths rather than always running everything, so a
documentation-only change runs one policy test instead of rebuilding the kernel
and booting four VMs. The selector owns that mapping; the workflow does not
restate it. A change under `.github/workflows/` escalates to the exhaustive
gate, so the workflow cannot weaken its own coverage unobserved.

`aarch64-sbsa-ref` has no distribution firmware, so a local run builds the pinned
edk2 and Trusted Firmware-A banks and caches them against
`tools/sbsa-firmware-sources.lock.json`. A restored cache is still verified
against the `MANIFEST.sha256` its builder wrote.

Running the gate locally remains supported and is unchanged:
`python3 scripts/test.py --require-filesystem-tools`. Prefer the hosted run for
routine verification; a local run is the faster answer when iterating on a
failure that reproduces on the developer's own machine.

Release-grade reproducibility evidence uses

```console
python3 scripts/test.py --strict-tool-versions --require-filesystem-tools --require-python-tools
```

That strict environment must provide Rust 1.97.1, QEMU 11.1.0, the committed
`edk2-stable202605-r1` firmware bytes, `cargo-audit` 0.22.1, e2fsprogs 1.47.4,
dosfstools, mtools, and `ruff`. The focused selector is a development aid and does not
replace the maintainer-owned exhaustive gate.

The non-QEMU production gate is separate because it requires a Linux x86-64
host with KVM and a pre-created isolated TAP. It verifies the exact v53.0
Cloud Hypervisor and `ch-remote` static assets, `CLOUDHV.fd` release
`ch-f308d878a6`, a production-identity bundle, process reopen, rollback, reboot,
and corrupted-StateFS recovery. Run it only as documented in
[`cloud-hypervisor-production.md`](cloud-hypervisor-production.md). A dry-run,
host-only test, QEMU result, or fixture-identity bundle is not production
acceptance evidence.

# Historical Stage 3 strict security review and remediation handoff

Date: 2026-08-23
Repository baseline: `b3a0cd0` plus the uncommitted Stage 3 worktree
Historical disposition: **GO for Stage 4**

Status: archived evaluation. The remediation was finalized in `3b0762c`; Stages
4 and 5 have since landed. Findings, locations, counts, and instructions below
describe the reviewed Stage 3 worktree and are retained as review evidence, not
as current repository guidance. For current status use
[../roadmap.md](../roadmap.md), and for the live unsafe count use
[../security/unsafe-inventory.md](../security/unsafe-inventory.md).

Remediation status, 2026-08-23: all findings below received implementation
changes in the reviewed worktree. The complete non-emulator gate, pinned RustSec audit,
production probe-string exclusion, and the x86_64/AArch64 acceptance matrix pass
with QEMU 11.1.0. The reviewed unsafe inventory contains exactly 80 authored
tokens. Stage 3 therefore satisfies the completion rule below.

## Purpose

This document was the portable handoff for finishing and re-reviewing Stage 3:
MMU-owned mappings and W^X. The automated gate passed on the pinned QEMU
profiles, but review found three architecture-level blockers and six additional
security or verification gaps. At that baseline, Stage 4 was blocked until
every P1 item was fixed and the complete gate passed again. The P2 items also
needed resolution before Stage 3 could be called polished or release-ready.

The referenced worktree was not committed when this review was written. Its
final remediated form is preserved by commit `3b0762c`. At review time, moving
the work to another machine required transferring modified and untracked files,
especially:

- `crates/troe-machine/src/mmu.rs`
- `docs/adr/0008-owned-page-tables-and-wx.md`
- all modified files reported by `git status --short`

Line numbers below refer to the reviewed 2026-08-23 worktree and may move as
fixes are applied.

## Verified baseline

The following command completed successfully on the reviewed tree:

```text
python3 scripts/test.py
```

It covered:

- `cargo fmt --all -- --check`;
- workspace and both UEFI-target Clippy gates with warnings denied;
- 39 workspace unit tests;
- deterministic KEFS validation;
- the project-authored unsafe inventory at exactly 67 tokens;
- both optimized UEFI image builds;
- complete x86_64 and AArch64 QEMU acceptance;
- deliberate write-to-read-only and execute-from-NX faults on both targets.

Passing this gate proves the pinned emulator paths work. It does not prove the
one-way firmware handoff, live-stack ownership, interrupt state, physical-alias
W^X, or portability properties described below.

## Required remediation order

1. Make successful `ExitBootServices()` a non-returning control-flow boundary.
2. Establish an explicitly owned kernel stack before reclaiming firmware stack
   pages.
3. Take explicit ownership of interrupt and exception state.
4. Repair the global mapping/W^X model and add regression tests.
5. Harden architecture address validation and unsafe PE-image bounds.
6. Isolate destructive acceptance probes from production dispatch.
7. Add a reproducible dependency advisory gate.
8. Run all verification and review the resulting unsafe inventory and ADR text.

## P1 — stage-blocking findings

### 1. Never return after `ExitBootServices()` succeeds

Location: `kernel/src/main.rs:118-156`

The call at line 118 is an irreversible ownership transition. After it succeeds,
normalization, mapping-plan construction, frame allocation, native writes,
exception-vector setup, MMU installation, and address conversion can still
return `Err(())`. That error reaches `main`, which returns `Status::ABORTED` to
firmware at lines 101-104.

UEFI states that after `ExitBootServices()` the OS loader owns continued system
operation and EFI does not regain control until reset:

- <https://uefi.org/specs/UEFI/2.10/04_EFI_System_Table.html>
- <https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html>

Required fix:

- split the preparation path into pre-handoff fallible work and a post-handoff
  path that cannot return to firmware;
- make every post-handoff failure emit a bounded native diagnostic and park or
  reset through an explicitly owned mechanism;
- do not use a `Result` path that can reach the UEFI entry return after the
  successful transition;
- add a testable model or structural assertion for the one-way boundary.

Acceptance criteria:

- no control-flow path after successful `ExitBootServices()` reaches a UEFI
  `Status` return;
- representative post-handoff failures reach stable native fatal output and a
  terminal state;
- no post-handoff diagnostic allocates through firmware or calls a boot service.

### 2. Do not expose the live firmware stack through the frame allocator

Location: `kernel/src/main.rs:282-303` and
`crates/troe-memory/src/lib.rs:779-823`

`EfiBootServicesCode` and `EfiBootServicesData` are reclassified as usable, and
`NormalizedMemoryMap::build(&regions, &[])` supplies no reservations. The frame
allocator then marks every usable frame free. Execution is still using the UEFI
dispatcher stack, so its physical pages can be returned by later allocations.

The Stage 3 ADR already acknowledges the dispatcher stack at
`docs/adr/0008-owned-page-tables-and-wx.md:41-45`. EDK2 identifies DXE stack
memory as `EfiBootServicesData` in its stack handoff implementation:

- <https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Core/DxeIplPeim/DxeLoad.c>

This is an immediate prerequisite for Stage 4, which introduces task stacks and
will start consuming physical frames.

Required fix:

- allocate an explicitly owned boot/kernel stack before the final reclaimable
  map is exposed to the frame allocator;
- switch stack using a small reviewed architecture boundary;
- reserve both the old live stack and new owned stack while switching;
- only release the old stack after execution is provably off it;
- ensure stack bounds are explicit, page-aligned, mapped RW/NX, and accounted;
- update the ADR and memory accounting so “free” means genuinely allocatable.

Acceptance criteria:

- the current stack pointer always falls within an owned, reserved stack range;
- no allocator call can return a frame from the active stack;
- both architectures boot and fault correctly after the stack switch;
- a regression test proves stack reservations are excluded from free-frame
  accounting.

### 3. Own x86 interrupt state before installing the minimal IDT

Location: `crates/troe-machine/src/mmu.rs:556-603`

The replacement IDT is zero-initialized and only vector 14 is installed. Nothing
clears `RFLAGS.IF` before `lidt`. The UEFI x64 execution environment enters with
interrupts enabled:

- <https://uefi.org/specs/UEFI/2.10_A/02_Overview.html>

An IRQ, NMI-related path, or unexpected exception that reaches an absent gate
can escalate through an absent double-fault path to a triple fault and reset.
Successful permission-fault tests only prove vector 14 under the pinned OVMF
environment.

Required fix:

- execute `cli` before replacing firmware interrupt/exception state;
- install terminal handlers for all architecturally relevant exceptions,
  including double fault, general protection, invalid opcode, and stack faults;
- keep maskable interrupts disabled until the project owns interrupt-controller
  routing and handlers;
- document NMI and machine-check assumptions separately;
- make the terminal park implementation consistent with the chosen interrupt
  state.

Acceptance criteria:

- no maskable interrupt can reach an absent IDT entry;
- unexpected exceptions reach bounded native diagnostics rather than resetting;
- the QEMU gate covers at least one non-page-fault exception or an explicit IDT
  structure test;
- interrupt-state ownership is recorded in the unsafe inventory.

## P2 — security and hardening findings

### 4. Enforce W^X across physical aliases

Location: `crates/troe-memory/src/lib.rs:350-403`

`MappingPlan::insert` rejects virtual overlap only. `enforces_w_xor_x()` checks
each mapping independently. Two disjoint virtual ranges can therefore map the
same physical page as RW/NX and RX, while the function returns `true`. This
defeats the advertised global W^X invariant once non-identity or remappable
mappings are introduced.

Required fix:

- define the intended physical-alias policy explicitly;
- reject physical overlap with conflicting permissions, or maintain a
  page-granular aggregate permission invariant;
- define whether same-permission aliases are allowed and how memory type, owner,
  lifetime, and remappability must agree;
- rename `enforces_w_xor_x` if it remains only a per-entry check;
- add regression tests for RW/RX aliases in both insertion orders and for
  partially overlapping physical ranges.

Acceptance criteria:

- no accepted plan can expose a physical byte as both writable and executable;
- the backend validates the same invariant immediately before activation;
- the unsafe inventory no longer overstates the mapping-plan guarantee.

### 5. Do not assume firmware uses selector `0x38`

Location: `crates/troe-machine/src/mmu.rs:556-591`

The new GDT initializes only entries 6 and 7, corresponding to selectors `0x30`
and `0x38`. The page-fault gate copies the current CS selector without proving
that it refers to entry 7 in the replacement GDT. A compliant environment with
a different flat selector would install a gate referencing a null descriptor.

Required fix:

- either install descriptors at the selector indices actually observed, after
  validating table bounds and selector properties;
- or load a project-owned fixed code/data selector pair and use the fixed code
  selector in every gate;
- add a pure descriptor/gate construction test that varies the incoming
  selector.

Acceptance criteria:

- every installed gate references a present 64-bit code descriptor in the
  active GDT;
- correctness does not depend on a selector value observed only in pinned OVMF.

### 6. Match AArch64 address validation to `TCR_EL1.IPS`

Location: `crates/troe-machine/src/mmu.rs:650-742`

The page mapper accepts physical addresses below `2^48`, but `TCR_EL1.IPS` is
hard-coded to `0b010`, which describes a 40-bit/1 TiB output space. The backend
can therefore accept and encode addresses that its active translation regime
does not support.

Arm architecture register references:

- <https://developer.arm.com/documentation/ddi0601/2026-03/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1->
- <https://developer.arm.com/documentation/ddi0601/2026-03/AArch64-Registers/ID-AA64MMFR0-EL1--AArch64-Memory-Model-Feature-Register-0>

Required fix:

- either reject addresses at or above `2^40` for the current fixed profile;
- or read `ID_AA64MMFR0_EL1.PARange`, select a supported IPS encoding, and
  validate every table and leaf physical address against it;
- verify that the selected 4 KiB granule and EL1 translation features are
  supported;
- add boundary tests around the selected physical-address limit.

Acceptance criteria:

- accepted physical addresses and table bases are representable under the
  installed TCR;
- unsupported CPU configurations fail before page-table activation.

### 7. Establish every `slice::from_raw_parts` safety precondition

Location: `crates/troe-machine/src/mmu.rs:249-263`

`loaded_image_layout` checks non-null and non-zero length, but does not check
that `byte_count <= isize::MAX` or that `base + byte_count` does not wrap the
address space. Both are explicit preconditions of `slice::from_raw_parts`:

- <https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html>

The subsequent PE parser also rounds the reported image length upward to a page
boundary. It should prove that the rounded range remains within the live image
allocation rather than silently extending the view.

Required fix:

- validate the maximum slice size and checked pointer/range end before the
  unsafe conversion;
- validate page alignment and rounded image bounds against the allocation or PE
  `SizeOfImage` contract;
- make the `SAFETY` comment state how every Rust precondition is established;
- add malformed maximum-size and overflow regression tests around a safe helper.

Acceptance criteria:

- the unsafe block has a locally checkable proof for every documented
  `from_raw_parts` requirement;
- malformed protocol metadata fails closed without constructing a Rust slice.

### 8. Keep destructive MMU probes out of production command dispatch

Location: `kernel/src/main.rs:332-342` and `scripts/test-qemu.py:469-481`

The undocumented `mmu-probe write` and `mmu-probe execute` inputs deliberately
crash the kernel and are recognized before normal shell parsing or capability
checks. Leaving them in the production image creates an availability hazard and
will bypass Stage 4 capability-scoped dispatch.

Required fix:

- compile probes only in an explicit acceptance-test profile or feature;
- keep production images free of the magic command strings and trigger code;
- ensure the acceptance script boots the test-profile artifact deliberately;
- after observing the diagnostic, also verify that the CPU remains terminal and
  the machine does not reboot into another successful prompt.

Acceptance criteria:

- production shell input cannot invoke permission-fault probes;
- acceptance builds still prove both permission violations on both
  architectures;
- the test distinguishes a parked fatal state from a reboot after the marker.

### 9. Add a reproducible dependency advisory gate

Location: `scripts/test.py:35-98`

The current verification command checks formatting, linting, tests, unsafe
count, images, and QEMU, but does not check `Cargo.lock` against a vulnerability
database. The reviewed repository did not invoke a pinned `cargo audit` or
`cargo deny` gate. Search did not surface a specific advisory for the direct
`uefi` or `rlsf` versions, but search is not a reproducible lockfile audit.

RustSec tooling guidance:

- <https://rustsec.org/>

Required fix:

- add a documented, version-pinned `cargo-audit` or `cargo-deny` invocation;
- define how withdrawn, unmaintained, unsound, and vulnerability advisories are
  treated;
- pin or otherwise make the advisory database snapshot reproducible for release
  evidence;
- keep license/source policy aligned with `THIRD_PARTY.md` and the release gate
  in `CORE-SPEC.md:729-739`.

Acceptance criteria:

- one documented command audits the complete lockfile and fails according to an
  explicit policy;
- the result and database revision can be recorded for a release candidate;
- exceptions require a reviewed, time-bounded rationale in the repository.

## Re-verification checklist

After remediation, run at minimum:

```text
python3 scripts/test.py
git diff --check
git status --short
```

Also verify manually:

- no post-`ExitBootServices()` path returns;
- the active stack is inside a reserved owned range before firmware stack pages
  become allocatable;
- x86 interrupt state is explicit and every reachable exception has a valid
  gate/descriptor path;
- AArch64 TCR, detected features, and accepted addresses agree;
- the mapping model rejects physical RW/RX aliases;
- production images contain no destructive probe command strings;
- unsafe-token changes have corresponding `SAFETY` comments and updates to
  `docs/security/unsafe-inventory.md`;
- ADR 0008 and `docs/architecture.md` describe actual behavior rather than the
  pre-fix design;
- both QEMU targets pass normal boot, write-fault, execute-fault, fatal-state,
  and halt scenarios.

## Completion rule

Stage 3 can be marked verified only when:

- all three P1 findings are fixed and reviewed;
- all P2 findings are either fixed or explicitly accepted with narrow,
  documented scope and evidence;
- the full verification gate and dependency audit pass on the final tree;
- no known failing ownership, memory-safety, W^X, or exception-state invariant
  remains.

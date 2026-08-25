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
| `filesystem` | KEFS/ext4 reads, paths, pipelines, RAMFS mutation, read-only and error behavior |
| `quota-memory` | 128-entry quota, recovery, repeated transient workloads, owned heap accounting |
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
5. Before declaring a branch merge-ready, require the successful `full-test`
   workflow or run `python3 scripts/test.py` in the pinned local environment.

Never infer that an unchanged file makes its tests irrelevant. Tests may be
selected through reverse dependencies, generated inputs, package formats, or
runtime integration even when their own source files did not change.

## Merge gate

`.github/workflows/full-test.yml` runs the exhaustive command on a self-hosted
macOS runner labelled `troe-qemu-11-1`. That runner must provide Rust 1.97.1,
QEMU 11.1.0, the committed `edk2-stable202605-r1` firmware bytes,
`cargo-audit` 0.22.1, e2fsprogs 1.47.4, dosfstools, and mtools. Repository branch
protection should require the `exhaustive pinned gate` check.

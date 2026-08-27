# Implementation roadmap

This page tracks landed stages and the work that is still intentionally open.
It is not a second architecture specification: current mechanics belong in
[the architecture guide](architecture.md), serialized contracts belong in
[formats](formats), and design rationale belongs in [ADRs](adr).

Status words are used narrowly:

- **complete** means the stage's stated exit is implemented and covered by its
  named host or QEMU gate;
- **in progress** means useful slices have landed but the stage exit is still
  open; and
- **planned** means groundwork is retained here, but the repository does not
  claim the capability.

## Landed foundation

| Stage | Status | Durable outcome |
| --- | --- | --- |
| 0–1: portable model and UEFI | complete | One bounded shell/VFS model runs on the host and in x86-64 and AArch64 UEFI images. Deterministic KEFS generation, parser/filesystem tests, and serial acceptance are established. |
| 2–3: owned machine and MMU | complete | The kernel exits boot services, owns allocation and native diagnostics, installs owned page tables, enforces W^X, and contains deliberate permission faults on both architectures. See [ADR 0005](adr/0005-memory-ownership-direction.md) and [ADR 0008](adr/0008-owned-page-tables-and-wx.md). |
| 4–5: cooperative tasks and dispatch | complete | Bounded task records, guarded stacks, typed capabilities, synchronous copied request/reply, and exact teardown are implemented. See [ADR 0010](adr/0010-cooperative-tasks-and-guarded-stacks.md) and [ADR 0011](adr/0011-bounded-in-process-message-dispatch.md). |
| 5.1–5.2: terminal and interrupt input | complete | The owned text console, bounded editor/history/completion, interrupt resources, input queues, native idle, x86 keyboard, and both serial paths are accepted. See [ADR 0012](adr/0012-native-text-console-and-editor-policy.md) and [ADR 0013](adr/0013-interrupt-driven-input-and-driver-resources.md). |
| 6: task isolation | complete | Fresh ring-3/EL0 address spaces, copied-message validation, contained user faults, owner-scoped handle revocation, zeroization, and exact frame reclamation pass on both architectures. See [ADR 0014](adr/0014-unprivileged-task-isolation-and-teardown.md). |
| 7: loadable applications | complete | Static KEX v1 applications run through ABI 1.1 with bounded leases, explicit handles, scheduler-controlled resume, fail-closed loading, and transactional teardown. See [ADR 0015](adr/0015-kex-application-abi-and-execution-bounds.md) and the [KEX format](formats/kex-v1.md). |
| 7.5: platform separation | Phases A and B complete | CPU mechanisms are separated from named VM platforms. Pinned q35/`virt` profiles and two discoverable QEMU ACPI/FDT contracts pass the complete acceptance matrix. No real provider-cloud environment is accepted. See [ADR 0016](adr/0016-hardware-targets-and-emulator-role.md) and [cloud platform support](cloud-platform-support.md). |
| 8: networking and persistence | complete | Bounded virtio block/network transports, stable volume selection, FAT32/ext4 providers, immutable generations, crash-consistent activation/rollback, StateFS mutation, identity metadata, UDP, DHCP, ICMP, and bounded outbound TCP are host- and QEMU-verified. The exact disk contracts remain in [formats](formats). |

The detailed closure classification for all accepted decisions is maintained in
the [ADR implementation ledger](adr/implementation-status.md). Completed stages
remain listed here so their ordering and architectural dependencies are not
lost, but their old patch-by-patch narratives are intentionally omitted.

## Stage 9: production usability — in progress

The first product-facing vertical slice is complete:

- every ordinary shell command is an immutable KEX application; only `cd`,
  `poweroff`, and `reboot` remain privileged intrinsics;
- the repo-local Rust SDK, linker contract, `cargo kex` build/inspect workflow,
  single-file KEX/KCAP packages, examples, and authoring skill are present;
- typed filesystem, mutation, timer, diagnostics, datagram, observation, DHCP,
  ICMP, and outbound-TCP services preserve least authority; and
- command discovery and completion use the immutable `/bin` catalog, while
  corrupt, absent, or faulting artifacts fail closed.

This is not yet a production release. Stage 9 remains open until one named
deployment can be installed, operated, updated, diagnosed, and recovered using
supported procedures. The remaining exit work is:

1. define registry trust roots, artifact signatures, revocation, provenance,
   target locks, and stable machine-readable tooling schemas;
2. ship supported install, update, rollback, garbage-collection,
   crash-diagnostic, reproducible-release, and bounded data-migration flows;
3. implement ADR 0033's writable desired configuration at `/config` and
   generation-bound active projection at `/sys/config`, then deliberately
   migrate the recovery-only KEFS `/etc` layout;
4. document deployment-class threat models, hardening profiles, operational
   limits, and a minimal recovery image; and
5. decide whether an optional userspace BSD/POSIX facade materially improves
   portability without replacing the typed native interfaces fixed by
   [ADR 0034](adr/0034-typed-capability-handles-and-unix-compatibility.md).

## Runtime and service evolution

[ADR 0032](adr/0032-bounded-wait-channels-and-asynchronous-mailboxes.md) remains
a staged decision, but its first six execution slices are complete. Portable
wait/pending-call models, native deferred timer and UDP waits, bounded suspended
contexts, an isolated diagnostics server, server-fault cleanup, and the
in-process/isolated IPC counter matrix are implemented. The exact trap rules
and measurement contract are preserved in [testing](testing.md).

Still open:

- add preallocated FIFO mailboxes only after two named non-test consumers need
  queued complete messages;
- support multiple independently scheduled live KEX applications and define
  persistent-server and restart policy before moving a device-owning service
  out of the kernel; and
- consider ASID/PCID retention, priority donation, shared-memory grants,
  preemption, SMP, background jobs, or concurrent pipelines only through
  separate measurements and ownership decisions.

The existing synchronous service `PortId` remains a service endpoint. A future
queued object is a mailbox, not a silent semantic expansion of that endpoint.

[ADR 0035](adr/0035-persistent-isolated-services-and-fast-ipc.md) is the
proposed end-to-end contract for this open work. It fixes a copied direct
handoff fast path, persistent lifecycle/restart rules, tagged address spaces,
kernel block/packet brokers, and staged network/filesystem migrations with
structural and end-to-end performance gates. It makes no implementation claim
until every named phase closes.

## Dynamic linking and reusable runtimes — planned

KEX applications are self-contained static images. Dynamic linking is a named
milestone because importing an ambient ELF loader would weaken the current
single-file and bounded-validation properties.

Any accepted design must:

- permit one self-contained package with pinned shared objects while allowing
  immutable content-addressed deduplication;
- make architecture, ABI, dependency, and symbol versions explicit and bound
  depth, object, symbol, relocation, and byte counts;
- preserve W^X and read-only-after-relocation state, grant libraries no
  authority independent of their application, and reclaim every page exactly;
- define reviewed x86-64 and AArch64 relocation subsets with negative corpora
  and native teardown/reuse gates; and
- let the SDK reproduce and inspect a package without ambient host libraries
  or paths.

A future decision must choose the KEX container revision and whether relocation
belongs in a small userspace runtime, hosted packaging, or a narrowly scoped
kernel mechanism. Until then, libc and Lua components remain statically linked.

## Platform expansion — planned per environment

TROE support is an exact `(platform, environment)` claim. The accepted runtime
matrix currently contains only the four named QEMU contracts documented in
[cloud platform support](cloud-platform-support.md). QEMU with KVM and provider
clouds remain unaccepted until their exact firmware, storage/network drivers,
image-import contract, and real-instance lifecycle evidence exist. Physical
boards, USB/SD bring-up, and no-MMU targets are outside the current product
roadmap.

## Tooling and packaging — planned beyond the bootstrap SDK

[The tooling and packaging specification](../TOOLING-PACKAGING-SPEC.md) is
forward-looking design, not a list of commands that work today. Cargo,
repository scripts, the KEX SDK, KCAP manifests, and deterministic image tools
are the current bootstrap surface. A public package registry, trusted
generation publication, native `troe` package CLI, and package-managed
configuration remain Stage 9 work and must reuse the implemented content,
identity, rollback, and typed-authority boundaries rather than invent parallel
ones.

General FAT12/16 and exFAT, NTFS, journal replay, repair, dynamic filesystem
providers, and broader authorization policy remain separately scoped storage
decisions. Read/write FAT32, the constrained ext4 profile, and StateFS are the
implemented providers; their presence does not imply the broader formats.

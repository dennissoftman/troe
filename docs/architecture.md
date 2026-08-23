# Initial architecture

The same portable graph is linked into two composition roots:

```text
host stdin/stdout ─┐                 ┌─ hosted process
                   ├─ shell ─ VFS ──┤
native UART ───────┘                 └─ owned-machine kernel
```

The graph is intentionally direct today. Interfaces are shaped so a later
dispatcher can replace calls without exposing implementation pointers.

Repository `scripts` and Cargo commands are bootstrap developer tooling, not a
package manager or a privileged system-control plane. The future CLI described
in [../TOOLING-PACKAGING-SPEC.md](../TOOLING-PACKAGING-SPEC.md) must sit
above versioned libraries and service interfaces. It does not replace the
statically linked recovery shell.

## Input-to-output trace

1. A composition root owns line editing and enforces the 512-byte line bound.
2. The shell crate tokenizes iteratively. Quotes group bytes; no expansion,
   recursion, substitution, environment lookup, or globbing occurs.
3. The pipeline executor finds a statically linked command by name. Commands
   receive only stdin/stdout/stderr streams plus access mediated by `Shell`.
4. Each non-final command writes to a `BoundedOutput`. The next stage reads the
   frozen result through `SliceInput`; a stage cannot observe mutable internals.
5. Filesystem commands ask `Namespace` to canonicalize from the logical cwd.
   Immutable KEFS nodes and writable `/tmp` nodes share one object model.
6. The final output capability writes either host bytes or the polling native
   UART. UEFI text output is confined to the pre-handoff banner.

Pipelines are sequential in this single-task milestone. This makes backpressure
an explicit capacity error rather than requiring hidden scheduling. When tasks
arrive, the public byte-stream semantics can remain while the implementation
becomes a bounded ring with cooperative wakeups.

## Authority

There are no ambient device or reboot globals in portable crates. Only the UEFI
composition root and isolated machine mechanism import firmware/hardware APIs. `Shell` receives a boolean
machine-control grant; `halt` is denied without it. This is meaningful defense
against accidental coupling, but is not isolation while commands share an
address space.

## Allocation

Portable components use `alloc` but every untrusted growth path has a local
hard bound. Stage 1 obtained allocation from UEFI. Stage 2 installs a hybrid
adapter: it delegates only before the explicit arena exists, then routes all new
allocations to the owned TLSF heap. Once handoff completes, firmware fallback is
permanently disabled. Pre-arena loader allocations, if any, are retained rather
than passed to dead boot services.

Stage 2 begins with an architecture-independent memory-map model in
`kllm-memory`. It validates checked 4 KiB ranges, normalizes unordered firmware
descriptors, overlays bounded explicit reservations, and reports usable and
reserved bytes. It also models checked, aligned monotonic allocation over one
explicitly reserved boot arena, including padding, exhaustion, and sealing
accounting. The UEFI adapter and later pointer boundary consume these models;
firmware types do not enter the portable crate.

The final handoff reserves a 2,084-page LoaderData arena, carves and seals a
6 MiB general heap, dedicates 2 MiB to monotonic page-table construction, and
reserves 128 KiB/16 KiB kernel and emergency stacks. It installs polling
16550/PL011 and bounded native fatal paths, transfers to the owned stack, and
enters a non-returning `ExitBootServices` continuation. Interrupts are masked
before exception state changes. Only then does the kernel reclassify expired
boot-services code/data as usable and build a compact bitmap over genuinely
allocatable pages. `mem` and `/sys/memory` publish owned-map bytes, free/total
frames, and live heap use, capacity, high-water, and failure counts.

Stage 3 adds a pure, bounded mapping plan. The composition root identity-maps
only runtime RAM, PE-classified image sections, the boot arena, and the AArch64
PL011 page. Physical aliases are rejected. The native backend emits fresh 4 KiB
tables, validates CPU-reported physical-address limits, enables W^X, and replaces
firmware exception state with fixed x86-64 GDT/TSS/IDT state or an AArch64 VBAR.
Executable image pages are RX, immutable image pages are RO/NX, and writable
runtime/device pages are NX. Deliberate write and execute violations are
validated in fresh QEMU boots for both architectures.

The post-handoff shell invokes no firmware protocol or allocator and cannot
manipulate page tables or exception vectors. Authorized halt parks the CPU.
Per-task stacks and guard pages begin with the cooperative-task stage. The
Stage 3 dispatcher already uses an explicitly bounded owned RW/NX stack.

## Future persistent-storage boundary

Persistent storage preserves the same dependency direction. A transport
provides bounded block-region capabilities; partition discovery turns a whole
device into non-overlapping regions; independently selected filesystem
providers expose VFS objects. Format-specific structures do not enter the
machine backend, block transport, partition layer, or kernel composition root.

```text
block transport -> bounded region -> filesystem provider -> VFS namespace
                         ^
                  whole device or GPT
```

KEFS is the intentionally built-in recovery exception. The current FAT12 image
is read by firmware. General FAT12/16/32, exFAT, the default persistent ext4
profile, and later NTFS support are separate providers; before dynamic loading
they may be statically selected crates, and later writable providers should run
as capability-scoped services. An image does not carry providers it did not
select.

An external filesystem provider may be packaged under its own declared license,
but the module label alone is not a license boundary. Differently licensed
source and artifacts remain outside the Apache-licensed core and default image;
the service/module ABI, provenance, notices, and release treatment are reviewed
explicitly. Static linkage into the kernel image is not considered separation.

Initial partition support is discovery rather than management: accept a whole
device or validate a bounded GPT layout created by host/installer tooling. No
filesystem provider can address blocks outside its granted region. See
[ADR 0009](adr/0009-persistent-filesystems-and-partitions.md).

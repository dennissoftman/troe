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

The final handoff reserves an 8 MiB LoaderData arena, carves and seals a 6 MiB
general heap, installs polling 16550/PL011 and bounded native fatal paths, and
then captures and retains the final UEFI map while exiting boot services. The
kernel reclassifies expired boot-services code/data as usable, fails closed on
all other non-conventional types, and builds a compact bitmap only over usable
pages. `mem` and `/sys/memory` publish owned-map bytes, free/total frames, and
live heap use, capacity, high-water, and failure counts.

The post-handoff shell uses no firmware protocol or allocator. Authorized halt
parks the CPU. MMU replacement, W^X, and architecture exception vectors are the
next stage and are intentionally absent from this ownership patch.

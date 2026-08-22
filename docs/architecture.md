# Initial architecture

The same portable graph is linked into two composition roots:

```text
host stdin/stdout ─┐                 ┌─ hosted process
                   ├─ shell ─ VFS ──┤
UEFI text console ─┘                 └─ firmware application
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
6. The final output capability writes either host bytes or firmware text.

Pipelines are sequential in this single-task milestone. This makes backpressure
an explicit capacity error rather than requiring hidden scheduling. When tasks
arrive, the public byte-stream semantics can remain while the implementation
becomes a bounded ring with cooperative wakeups.

## Authority

There are no ambient device or reboot globals in portable crates. Only the UEFI
composition root imports firmware APIs. `Shell` receives a boolean
machine-control grant; `halt` is denied without it. This is meaningful defense
against accidental coupling, but is not isolation while commands share an
address space.

## Allocation

Portable components use `alloc` but every untrusted growth path has a local
hard bound. Stage 1 obtains allocation from UEFI boot services through the
maintained `uefi` crate. Exiting boot services is deliberately not attempted in
this slice: doing that safely requires the boot allocator, normalized memory
map, native console, exception path, and owned heap to land together.

Stage 2 begins with an architecture-independent memory-map model in
`kllm-memory`. It validates checked 4 KiB ranges, normalizes unordered firmware
descriptors, overlays bounded explicit reservations, and reports usable and
reserved bytes. It also models checked, aligned monotonic allocation over one
explicitly reserved boot arena, including padding, exhaustion, and sealing
accounting. The UEFI adapter and later pointer boundary consume these models;
firmware types do not enter the portable crate.

While boot services remain active, the kernel adapts a live UEFI map into this
model and supplies its checked usable/non-usable byte counts to `mem`. The
report labels the map as an advisory firmware snapshot: subsequent firmware
allocation makes its key stale, so it is diagnostic input rather than an
ownership claim or the final ExitBootServices map.

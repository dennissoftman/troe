# Initial architecture

The same portable graph is linked into two composition roots:

```text
host stdin/stdout ─┐                 ┌─ hosted process
                   ├─ shell ─ VFS ──┤
UEFI text console ─┘                 └─ firmware application
```

The graph is intentionally direct today. Interfaces are shaped so a later
dispatcher can replace calls without exposing implementation pointers.

## Input-to-output trace

1. A composition root owns line editing and enforces the 512-byte line bound.
2. `kllm-shell` tokenizes iteratively. Quotes group bytes; no expansion,
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


# ADR 0064: bounded cell-grid display surfaces and the display protocol

Status: proposed implementation contract, 2026-09-01. Nothing in this ADR is
implemented or accepted merely because the document exists. Acceptance requires
every gate below. Amends ADR 0012, which deferred "rich color, windowing" from
the first framebuffer renderer, and preserves that ADR's recovery-console
invariant unchanged.

Phase 1 of [#134]. Depends on no kernel or ABI change.

## Context

TROE renders normal shell output through `TextConsole`, a bounded cell grid on
an owned pixel surface with fixed 5x7 glyphs in 6x8 cells and exactly one
global foreground/background pair. There is no window, no z-order, no focus,
and no display client. The session owns one decoder pair and lends terminal
input to at most one foreground process.

A graphical stack ultimately needs shareable memory (#131), capability transfer
(#130), and an interactive scheduling class (#133). None of those exist, each
is a significant kernel change, and each is measurement-gated.

The display *protocol*, however, does not depend on any of them. Windows,
z-order, focus, input routing, damage, atomic commit, present, and client
teardown are policy questions whose shape can be fixed and proven before any
pixel or any kernel work exists — provided surface content is small enough to
cross the existing copied 4 KiB message.

A character cell with attributes is that content. It is also the one surface
representation that renders faithfully to *both* a pixel framebuffer and an
ANSI terminal, because a cell grid with attributes is precisely what ANSI SGR
expresses. Window management therefore becomes assertable from serial output
inside the existing QEMU acceptance gate, on all four platform profiles,
before a single pixel is drawn — and headless remote display, which matters for
a guest whose framebuffer is often not the display anyone looks at, is a
property of the design rather than a later feature.

This ADR takes that as the first increment. It is deliberately not a graphics
stack.

## Decision

### Placement

`troe-display` is an ordinary SCFG boot service in its own address space. The
kernel gains no display concept: no surface, no window, no cell, no pixel. It
already owns the framebuffer and console transports as device mechanisms, and
that is the only authority the service receives.

The service uses only existing mechanism: `SERVER_ENDPOINT` (interface 15) for
client requests, the ADR 0032 deferred-reply path for event delivery, ADR 0038
supervision for lifecycle, and the existing 4 KiB copied payload. It adds one
interface identifier and no kernel code.

### Cell encoding

One cell is exactly 8 bytes, fixed-width, with no bit packing:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | Unicode scalar value; surrogates and out-of-range values refused |
| 4 | 1 | foreground palette index |
| 5 | 1 | background palette index |
| 6 | 2 | attribute bits; unknown bits reserved and MUST be zero |

The palette is 256 entries owned by the server. A client selects indices and
never transmits a color. Server-owned palette entries are what later becomes
the token table in Phase 5, so client content does not change when theming
arrives.

An 80x25 surface is 2,000 cells and 16,000 bytes: four full-refresh messages.
One damaged row is 80 cells and 640 bytes, so ordinary updates are a single
message with header room to spare. Packing a cell into 4 bytes was rejected;
it forces either a BMP-only code point or a 16-color palette, and TROE's ABI
style is exact fixed-width fields with reserved zeros rather than bit games.

### Surfaces and authority

A client creates a surface with geometry fixed at creation. There is no
implicit resize. An explicit resize is a distinct operation that atomically
discards content, so no peer ever observes a surface whose extent changed under
a partially applied update.

The split of authority is the security core of this ADR:

- The client owns **content only**.
- The server owns position, z-order, focus, visibility, and decorations.

A client cannot set its own position, cannot raise itself, and cannot take
focus. Focus changes only from real user input or from a server-owned hotkey
table read from configuration. This makes focus stealing structurally
impossible rather than a matter of policy, and it is the property that must not
be traded away later for convenience.

A client cannot read any surface, including its own. The protocol is write-only
with respect to content. There is no read-back, no foreign-surface query, and
no capture operation.

### Commit and damage

A commit carries a bounded list of runs, each `(row, column, count)` with a
reserved zero field, followed by the cells for those runs. A commit applies in
full or not at all: a rejected run rejects the whole commit and mutates no
cell. Runs are validated against surface geometry before any application, and
overlapping runs within one commit are refused rather than resolved.

The server computes its own damage from the committed scene and never trusts
client-declared damage for bounds.

### Decorations

The server draws decorations in cells: a one-cell border and a title row.
This is minimal, but it is deliberately present in Phase 1 because it proves
the server-side-decoration decision at near-zero cost, and because it is what
guarantees a hung client's window stays movable and closable. The token table
that styles decorations is Phase 5; the *ownership* is settled here.

### Input and events

Phase 1 routes the existing decoded `KeyEvent` stream to the focused surface.
The `KeyStroke` split — physical key, modifiers, press/release — is Phase 2,
and until it lands display clients receive editor-intent events. That is
sufficient for text user interfaces and insufficient for anything else, which
is an accepted limitation of this increment rather than an oversight.

A client receives events through one outstanding blocking `NextEvent` call that
the server completes when input or a configuration change arrives. The reply
carries up to a bounded number of batched events, so an event burst does not
cost a round trip per event. This is the existing ADR 0032 mechanism and
requires nothing new.

Per ADR 0012, AArch64 has no native keyboard until a bounded virtio-input
transport exists. On that architecture Phase 1 input arrives over serial.

### Backends and the recovery invariant

The server holds one scene and renders it to configured backends:

- **serial**: ANSI SGR and cursor addressing, emitting only what changed;
- **framebuffer**: `TextConsole` extended from one global color pair to
  per-cell attributes.

ADR 0012 requires that graphical availability cannot hide a broken recovery
console. That invariant holds: **the primary UART recovery console is never a
valid display-server target.** The framebuffer is taken on start and returned on
exit or fault, with the text console resuming.

**Open question: how the serial backend gets a transport.** An earlier draft
said the acceptance profile assigns the service a second UART. That is not
currently implementable. `SBSA_REF_MMIO` pins exactly one `MmioRole::Pl011`, no
platform descriptor carries a second UART role, and every QEMU profile passes a
single `-serial stdio`. A second *driven* UART would need a new `MmioRole`,
descriptor entries and an interrupt route on all four platforms — far more than
a profile flag.

Two candidate resolutions, to be settled before the serial backend is built:

1. **Console handover.** The display server takes the single console on start
   and returns it on exit or fault, exactly as it does the framebuffer. The gate
   asserts the recovery console before and after the display window rather than
   during it. Smallest platform change, and it keeps ADR 0012's invariant as
   long as handover is explicit and reversible.
2. **Framebuffer-only gate assertions.** Assert window management through the
   framebuffer path and a headless scene dump, and treat the serial backend as
   a later remote-display feature rather than a Phase 1 gate mechanism.

Resolution 2 became more attractive after ADR 0063: every profile now has a
working GOP framebuffer — `bochs-display` on `aarch64-sbsa-ref`, `ramfb` on
`aarch64-uefi-virtio-mmio` — so the framebuffer backend is available everywhere
and is no longer the harder path to assert against.

### Bounds

| Resource | Initial candidate |
| --- | ---: |
| Live surfaces system-wide | 16 |
| Surfaces owned by one client | 4 |
| Cells per surface | 8,192 |
| Runs per commit | 64 |
| Cells per commit | 2,048 |
| Batched events per reply | 32 |
| Palette entries | 256 |

These are proposals and require measurement. Every ceiling is charged to the
owning client, not to the server, so a client cannot exhaust the system through
the server's quota. Exhaustion is atomic and typed.

## Verification

Portable tests cover canonical cell encoding and its rejections (surrogate and
out-of-range scalars, reserved attribute bits, palette range, reserved run
fields), run validation against geometry, overlapping-run refusal, commit
atomicity under a mid-list rejection, resize content discard, z-order and focus
transitions, refusal of client-initiated focus and raise, per-client ceiling
exhaustion, event batching at the reply bound, and surface teardown on client
death.

Negative corpora cover truncated and over-long commits, runs crossing the
geometry boundary, arithmetic at the cell-count boundary, and commits naming a
revoked surface.

Native acceptance runs on both architectures and every supported QEMU profile. It
launches the service, creates surfaces from two distinct clients, and asserts
composed output over the service's own serial transport including z-order,
focus routing, and decoration. It asserts that terminating one client revokes
its surface and leaves the other intact, that the framebuffer backend activates
on both architectures, and that the primary UART recovery console remains
driven and assertable throughout — the ADR 0012 gate, unchanged.

## Consequences

The protocol's shape is settled and proven before any kernel work begins.
Pixel surfaces in Phase 4 become an additional surface type on a protocol whose
window, focus, damage, commit, and teardown semantics already passed the gate,
rather than a redesign under schedule pressure.

Window management enters the acceptance gate immediately, on every platform,
using the serial transport the gate already drives. Remote display costs
nothing extra.

The limitations are real and are accepted for this increment: monospaced cells
only, no pixels, no pointer, editor-intent events rather than raw key events,
and no client-side drawing of any kind. Nothing here is a general display API.

`TextConsole` gains per-cell attributes and a 256-entry palette. The shell's
own console path is otherwise unchanged in Phase 1, and the shell does not
become a display client in this increment.

Documentation impact at acceptance: ADR 0012 gains a supersession note for its
"rich color, windowing" deferral, and README.md, CORE-SPEC.md section 5, and
`docs/architecture.md` all state that no graphics stack exists and must be
reviewed against whatever this increment actually lands.

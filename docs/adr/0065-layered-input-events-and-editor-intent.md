# ADR 0065: layered input events and the editor-intent split

Status: proposed implementation contract, 2026-09-01. Nothing in this ADR is
implemented or accepted merely because the document exists. Acceptance requires
every gate below. Refines the key-event contract of ADR 0012 without replacing
it, and preserves the input-loan behavior of ADR 0053 unchanged.

Phase 2 of #134. Depends on no kernel or ABI change.

## Context

ADR 0012 established architecture-independent key events. The serial ANSI
decoder and the x86-64 set-1 PS/2 decoder both produce `KeyEvent`, and the line
editor consumes it. `KeyEvent` is an *editor intent* type: `Character`, `Enter`,
`Backspace`, `Left`, `Up`, `Complete`, `Cancel`, `KillBefore`,
`DeletePreviousWord`, `EndOfInput`, and their siblings.

For a line editor that is exactly the right abstraction, and this ADR does not
change it. For anything else it is structurally insufficient. `KeyEvent` cannot
express a key release, a modifier state, a key that is pressed but bound to no
editor intent, an autorepeat, or a pointer at all. `Up` means "recall previous
history entry", not "the up key went down" — the intent has already been
applied and the physical event is gone.

ADR 0064 accepts this as a Phase 1 limitation and routes editor-intent events to
display clients, which is sufficient for text user interfaces and useless for
anything else. This ADR removes that limitation.

## Decision

Input becomes three distinct types with one direction of derivation, rather
than one type serving two purposes:

```text
transport  --->  KeyStroke  ---+---> TextInput ---+---> KeyEvent
                (physical)     |   (composed)     |   (editor intent)
                               |                  |
                        display clients    line editor, text clients
```

- **`KeyStroke`** is physical: a closed key identity, a fixed modifier bitmask
  with reserved zero bits, and `Press`, `Release`, or `Repeat`. Transports
  produce it. Key identity is a closed enumeration rather than an open scancode
  space, so no transport can inject an unbounded value.
- **`TextInput`** is composed: bounded UTF-8 produced from keystrokes by a
  layout policy. It is a separate channel because composition is not one-to-one
  with keystrokes — dead keys already break that, and an input method would
  break it further.
- **`KeyEvent`** is unchanged, and is now *derived* from the two above by an
  editor policy rather than produced directly by a transport.

The line editor continues to consume `KeyEvent` only. ADR 0012's editor
contract and ADR 0053's foreground input loan are therefore preserved exactly,
and no existing shell behavior changes.

Display clients consume `KeyStroke` and `TextInput`. A client that wants only
text may request the derived `KeyEvent` stream instead of implementing an
editor.

### Pointer events

`PointerEvent` carries a position in surface-local coordinates, a button
bitmask, `Press` or `Release`, and a bounded scroll delta. The display server
owns cursor position and clamps it to screen bounds; no transport and no client
owns cursor state.

### Serial is a degraded transport, and says so

An ANSI terminal cannot express key release, and encodes only a small subset of
modifier combinations. A serial transport therefore synthesizes a paired press
and release for each decoded key and reports only the modifiers its escape
sequence actually carries.

This is not a defect to be fixed later; it is a property of the transport. It
is stated here so that a display client can query transport fidelity rather
than discover it, and so that no future change pretends serial keystrokes are
equivalent to native ones.

### Bounds and authority

Autorepeat is never synthesized in interrupt context. It is a bounded policy
applied outside it, with validated configuration per ADR 0013.

A client receives events only for the surface the display server has focused.
There is no ambient input authority, no client-visible global input stream, and
no mechanism by which a client observes input directed elsewhere.

## Verification

Portable tests cover the full derivation chain, layout policy application,
modifier state tracked across press and release including release-without-press,
serial release synthesis, closed-enumeration rejection of unknown key
identities, reserved modifier bits, bounded `TextInput` length, and pointer
coordinate and button bounds.

A mandatory regression suite proves every existing `KeyEvent` is still produced
for the same input on both the serial and PS/2 paths, so the editor and shell
observe no behavior change.

Native acceptance on both architectures and every supported QEMU profile proves the
editor path is unchanged and that a display client observes press and release
with correct modifier state where the transport can express it.

## Consequences

ADR 0012's key-event contract is refined rather than replaced, and the editor
keeps its intent-shaped input.

Display clients written against ADR 0064 Phase 1 are rewritten when this lands,
because they move from editor-intent events to keystrokes. That cost is known
and accepted; Phase 1 exists to settle the protocol, not to ship clients.

Serial keystroke fidelity remains permanently lower than native. On AArch64,
where ADR 0012 deferred native keyboard entirely, every keystroke is degraded
until the transport work in ADR 0066 lands.

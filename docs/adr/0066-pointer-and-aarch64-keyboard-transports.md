# ADR 0066: bounded pointer and AArch64 keyboard transports

Status: proposed implementation contract, 2026-09-01. Nothing in this ADR is
implemented or accepted merely because the document exists. Acceptance requires
every gate below. Amends the queue record of ADR 0013 and closes the AArch64
keyboard deferral of ADR 0012.

Phase 2 of #134. Depends on no kernel or ABI change.

## Context

ADR 0013 pinned interrupt-driven input to a bounded queue of raw events, each
carrying one uninterpreted transport byte tagged with an `InputSource` of
`Serial` or `Keyboard`. Device handlers drain a configured number of bytes,
acknowledge the controller, and return; all decoding happens outside interrupt
context. That discipline is correct and this ADR keeps it.

Two gaps remain. ADR 0012 deferred AArch64 native keyboard input "until a
bounded virtio-input transport exists", and that deferral is still in force, so
neither AArch64 platform has a native keyboard at all. And no pointer transport
exists on either architecture, which blocks every phase of #134 beyond the cell grid.

## Platform dependency

AArch64 now has **two** platforms with **two different virtio transports**, and
this ADR must serve both. ADR 0063 replaced the pinned `aarch64-virt-uefi` with
`aarch64-sbsa-ref`, but left the discoverable `aarch64-uefi-virtio-mmio`
platform in place:

| Platform | Transport | Interrupt model | Framebuffer |
| --- | --- | --- | --- |
| `aarch64-sbsa-ref` | virtio over PCI Express | `VirtioTransportKind::PciGic` | `bochs-display` |
| `aarch64-uefi-virtio-mmio` | virtio-MMIO | MMIO slot interrupts | `ramfb` |

So virtio-input is **not** a single transport choice on AArch64. It is
virtio-PCI on the reference platform and virtio-MMIO on the discoverable one,
and both must work.

The PCI half carries a constraint x86-64 does not. On x86-64 a function's
platform interrupt is named in its configuration Interrupt Line byte; on Arm
that byte means nothing, and the pin reaches one of four consecutive shared
peripheral interrupts through the standard swizzle. ADR 0063 introduced
`VirtioTransportKind::PciGic` specifically so that every site resolving an
interrupt fails to compile until it handles both models. Adding a virtio-input
PCI function must therefore handle `Pci` and `PciGic` explicitly, and must not
reintroduce a shared path that silently confuses them.

Two things this ADR previously treated as prerequisites are now satisfied.
GICv3 exists, so an SBSA-class interrupt controller is no longer a blocker. And
`virtio_pci.rs` is now exercised on AArch64 rather than x86-64 only, so the PCI
half of this work builds on transport code that already runs on both
architectures instead of on the MMIO path alone.

USB HID remains **not** an alternative on either platform: CORE-SPEC section 5
excludes a USB stack, so a PCIe AArch64 platform attaches virtio input
functions rather than relying on an XHCI keyboard.

## Decision

### q35: the i8042 auxiliary port

Enable the existing i8042 controller's auxiliary port and route IRQ12. Decode
the standard three-byte packet, and the four-byte packet only after a wheel
enable sequence has been acknowledged — never inferred from packet content.
Motion is relative.

The handler drains a bounded number of bytes, acknowledges, and returns, with no
allocation, no formatting, and no unbounded loop, exactly as ADR 0013 requires.
Packet reassembly and desynchronization recovery happen outside interrupt
context.

### AArch64: bounded virtio-input over both transports

Add a bounded virtio-input transport providing keyboard and pointer on both
AArch64 platforms: over PCI Express on `aarch64-sbsa-ref`, and over virtio-MMIO
on `aarch64-uefi-virtio-mmio`. This closes ADR 0012's deferral and gives AArch64
native keyboard input for the first time.

The device model is shared; only the transport binding and interrupt resolution
differ. The PCI binding must handle `VirtioTransportKind::Pci` and
`VirtioTransportKind::PciGic` as distinct cases, per ADR 0063.

### Absolute and relative are declared, not inferred

A transport descriptor declares whether it reports absolute or relative motion.
The i8042 auxiliary device is relative; a virtio-input tablet is absolute.
Nothing infers this from observed values.

The display server owns cursor position and clamps to screen bounds. No
transport owns cursor state, so a misbehaving or desynchronized device cannot
place the cursor outside the screen or carry position across a mode change.

### Queue record amendment

ADR 0013's queue carries `(source, byte)`. virtio-input delivers structured
type/code/value triples over a virtqueue rather than a byte stream, and
flattening those into bytes would put reassembly logic where the ADR 0013
discipline says it must not go.

`InputEvent` therefore widens to a small fixed-size record carrying either one
transport byte or one structured device event. Capacity, per-interrupt drain
budget, and overflow policy remain validated configuration; overflow still drops
the newest event and saturates a visible dropped-event counter while continuing
to drain and acknowledge, so a full queue cannot livelock the CPU.

`InputSource` gains `Pointer`.

### Resources stay platform facts

MMIO ranges, port ranges, interrupt lines, and vectors continue to come from
validated `troe-platform` descriptors. No driver discovers or embeds an address,
and no new build profile is introduced. Hot-plug is out of scope: transports are
enumerated once at composition.

## Verification

Portable tests cover three-byte and four-byte packet decoding, refusal of
four-byte packets before a successful wheel enable, desynchronization recovery,
overlong and truncated packets, virtio-input descriptor validation and negative
corpora, the widened queue record, and overflow accounting at capacity.

Native acceptance on both architectures and every supported QEMU profile injects
pointer motion and button events and asserts they reach a display client with
correct coordinates after server clamping. It proves native AArch64 keyboard
input drives a shell command for the first time, mirroring the existing q35
i8042 assertion. ADR 0013's queue and interrupt counters must remain bounded and
observable, and existing serial, keyboard, idle, and fatal-path coverage remains
mandatory.

## Consequences

ADR 0012's AArch64 keyboard deferral closes, and `docs/architecture.md` and
README.md must stop describing AArch64 native keyboard as unavailable.

ADR 0013's queue record widens, which touches every producer and consumer of
`InputEvent`. The change is mechanical but not local.

The i8042 auxiliary port is x86-64 only. AArch64 pointer support therefore rests
entirely on virtio-input, across both transports, and an AArch64 profile without
a virtio-input function has no pointer — which must be an explicit refusal at
composition rather than a silently absent cursor.

Serving two AArch64 transports is more work than the single-transport version
this ADR originally assumed, and the PCI half is the unfamiliar one. It is not
optional: dropping either leaves one shipped platform without input.

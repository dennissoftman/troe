# ADR 0012: native text console and configurable editor policy

Status: accepted, 2026-08-23.

Stage 5.1 introduces a portable terminal input and line-editing core, then an
owned framebuffer-backed text console. UART remains the mandatory early, fatal,
headless, and acceptance-test transport. A graphical console is an additional
normal-output transport, not a replacement for the recovery path.

Terminal policy is supplied through validated configuration values. The kernel
must not encode editor history counts, retained-history bytes, escape-sequence
bounds, completion candidate counts, or completion byte budgets as unrelated
literals. Portable crates provide one named Standard default and public
constructors so a composition root can select stricter validated limits when
needed. Runtime state must enforce the supplied limits atomically.

Input transports produce architecture-independent key events. The serial
decoder consumes complete ANSI CSI/SS3 sequences and discards unknown sequences
without leaking their printable tails into the command line. The x86-64 q35
profile polls i8042 and decodes PC scan-code set 1 into the same events under a
selected US-layout policy. AArch64 native keyboard input is deferred until a
bounded virtio-input transport exists. The editor owns bounded cursor-aware
editing and session history; shell-aware completion remains in `troe-shell` so
it can use the authoritative command registry and VFS namespace without giving
the terminal ambient filesystem authority.

Session history is volatile. Persistent history is deferred until persistent
storage has a crash, corruption, privacy, and recovery policy. A zero-capacity
history configuration explicitly disables history.

The framebuffer descriptor is copied from UEFI GOP before boot services exit.
Only validated scalar metadata and the physical framebuffer range cross the
handoff; no firmware protocol reference survives it. The owned mapping is
RW/NX, bounds-checked, and typed as device memory unless an architecture ADR
later selects a stronger framebuffer memory attribute. VGA text mode is not
used because it does not preserve the x86-64/AArch64 design.

The first framebuffer renderer is deliberately a text console rather than a
general graphics stack: fixed bitmap glyphs, a cell grid, cursor, wrapping,
scrolling, UTF-8 decoding with a replacement glyph, and the small control/CSI
subset required by the shell and editor. Scrollback, font loading, rich color,
windowing, USB HID, and a general display API are outside this increment.

QEMU keeps a deterministic headless profile using serial stdio and has an
explicit graphical profile. Host tests cover terminal parsing, editor bounds,
history eviction, completion budgets, framebuffer arithmetic, pixel formats,
and rendering. QEMU acceptance continues to drive UART so graphical
availability cannot hide a broken recovery console; additional smoke checks
require framebuffer activation on both architectures and inject native PS/2
keys on x86-64.

Implementation amendment, 2026-08-24: the repository's mandatory QEMU gate in
`scripts/test.py` always passes `--framebuffer-console` and
`--native-keyboard`. Consequently all four named platform runs must report
activation of the owned framebuffer console, and the q35 x86-64 run must
additionally complete a shell command delivered exclusively through the i8042 path. The serial-only
recovery path remains part of the same runs and is still used for assertions.

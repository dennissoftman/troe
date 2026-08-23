# ADR 0013: interrupt-driven input and bounded driver resources

Status: accepted, 2026-08-23.

Stage 5.2 replaces the owned shell's busy input polling with interrupt-driven
delivery while retaining polling for bootstrap and fatal recovery. Interrupts
are a hardware notification mechanism; the portable consumer interface is a
bounded queue of typed raw input events. Device handlers drain bytes into that
queue, acknowledge the owned controller, and return. UTF-8, ANSI, keyboard,
editor, VFS, and shell work never executes in interrupt context.

The queue is allocated and completely initialized before interrupts are
enabled. Its selected capacity, maximum bytes drained per interrupt, and
overflow behavior come from validated configuration. The initial overflow
policy drops the newest event, saturating a visible dropped-event counter, while
still draining and acknowledging the device so a full queue cannot livelock the
CPU. Interrupt handlers allocate no memory, format no text, acquire no blocking
lock, and perform no unbounded loop.

The first implementation remains single-CPU and cooperative. Main-context
queue access temporarily masks the owned input interrupt class; interrupt
context enters with that class masked. A queue-empty wait performs the
architecture's enable-and-sleep transition atomically enough to exclude a lost
wakeup: `sti; hlt` on x86-64 and an IRQ-unmask plus `wfi` sequence on AArch64.
This increment does not add timer interrupts, preemption, nested interrupts, or
general task blocking. Scheduler-visible wait channels are deferred until more
than the shell consumes asynchronous events.

Drivers consume validated resources rather than discovering or embedding
ambient authority. The pinned q35 and `virt` composition profiles initially
supply MMIO/port ranges, interrupt lines, vectors, and controller topology.
Future ACPI MADT or device-tree discovery may produce the same descriptors
without changing device-driver behavior. Resource addresses are platform facts;
queue sizes, drain budgets, priorities, and other policy limits remain selected
profile configuration rather than unrelated kernel literals.

The x86-64 profile owns the local APIC and I/O APIC, masks the legacy PIC, and
routes q35 keyboard and COM1 receive interrupts to explicit IDT gates. The
AArch64 profile pins QEMU `virt` to GICv2, owns its distributor and CPU
interface, and routes PL011 receive interrupts through the IRQ vector. Interrupt
entry mechanisms preserve interrupted architectural state before calling Rust
and restore it before returning.

QEMU acceptance must prove that ordinary serial input is received after polling
has been disabled, that native x86 keyboard input still works, that both CPUs
enter and wake from their idle instruction, and that queue/interrupt counters
are bounded and observable. Existing exception, W^X, terminal, and polling
fatal-path tests remain mandatory.

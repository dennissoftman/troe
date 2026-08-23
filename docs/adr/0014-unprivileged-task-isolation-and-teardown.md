# ADR 0014: unprivileged task isolation and transactional teardown

Status: accepted, 2026-08-23.

## Decision

Stage 6 executes isolated tasks at x86-64 ring 3 or AArch64 EL0t. A task owns a
fresh page-table root, private code/data/stack frames, one guarded user stack,
and every capability handle minted for its monotonic task identity. Kernel
image, runtime, and device mappings remain present in each root only at
supervisor privilege. User mappings are normal RAM, bounded to eight regions,
and preserve W^X across every physical alias. Device memory is never exposed to
an isolated task.

The current tiny profile allocates one contiguous 2 MiB table arena, one code
page, one data page, and four stack pages per launch. Guard addresses adjacent
to the user stack are absent. These are composition limits, not a public
application ABI. Page-table construction is bounded and fallible before the
task root is activated. Both the allocation and opaque root are one-shot,
non-cloneable tokens; native execution consumes the root and reclamation
consumes the allocation. The production frame allocator is likewise
non-cloneable, preventing accidental duplicate allocation authority; tests may
clone it only to prove failure atomicity.

Unprivileged execution is synchronous and cooperative. Interrupts remain
masked while the test continuation runs; Stage 6 adds neither preemption nor a
claim that a non-yielding task cannot deny service. The native entry boundary
preserves every ABI callee-saved general and floating-point/SIMD register. x86
uses a DPL-3 interrupt gate and a TSS ring-0 stack. AArch64 uses the lower-EL
synchronous vector and SP_EL1. Both return to the saved kernel context only
after reinstalling the kernel root and invalidating stale translations.
x86 also restores kernel RFLAGS and disables inherited `SYSCALL`, `SYSENTER`,
FSGSBASE, and protection-key entry mechanisms. It enables CPUID-supported SMEP
and SMAP, clears user-controlled AC on entry, and raises it only for the exact
validated message load. Unsupported inherited five-level paging, CET, or
supervisor protection-key state fails before descriptor replacement. AArch64
restores DAIF, SP_EL0, and TPIDR_EL0 in addition to the ABI-visible state.

The sole Stage 6 task call is an internal exit-with-message gate. It is not the
Stage 7 application ABI. The kernel validates opcode, status, complete source
range, and the 4 KiB destination bound before copying any byte into preallocated
kernel memory. AArch64 uses unprivileged loads so PAN state cannot weaken the
copy boundary. The copied value is then owned independently of the task address
space and can enter ordinary handle-based dispatch.

User translation, write-permission, execute-permission, and illegal-instruction
exceptions terminate only the current isolated record. Unknown calls, invalid
pointers, oversized messages, and unrepresentable statuses become the same
contained invalid-call fate without partial delivery. A fault in kernel mode,
an exception without an active isolated record, corrupted scheduler state, or
failure to restore the kernel root remains a terminal kernel fault; attempting
to recover those cases would continue from an unproved kernel state.

Teardown is one ordered transaction:

1. terminate or fault the scheduler record;
2. revoke every handle owned by its monotonic identity and advance generations;
3. reap the exact stack and address-space resources;
4. zero code, data, stack, and every page-table byte;
5. atomically return the complete physical range to the frame bitmap.

Failures before spawn zero and return frames immediately. Failures after spawn
use the same rollback path, including cancellation of a ready task whose native
launch never began. Contiguous allocation and range-free validate the complete
operation before changing bitmap state, so fragmented allocation and partial or
double teardown fail without mutation.

## Verification

Portable tests cover safe/unsafe physical aliases, user ownership/lifetime,
contiguous allocation and atomic free, copied-message detachment, per-owner
handle revocation, isolated task fault accounting, cancellation, reaping, and
resource-slot reuse.

Every production boot on both architectures runs a successful copied-message
task, then independently exercises translation, write-permission,
execute-permission, illegal-instruction, disabled alternate-entry,
invalid-opcode, invalid-pointer, oversize-message, and invalid-status
termination. AArch64 additionally rejects a nonzero `SVC` call encoding. The
x86 success and invalid-opcode probes also enter with the direction and
alignment-check flags set. The matrix checks zero partial output, stale-handle
rejection, exact resource returns, zero net frame loss, and reuse of both the
same address-space slot and lowest physical allocation. It also calls the
unrelated retained kernel handle after every task owner has been revoked and a
final successful reuse task has completed, then continues into the shell.
Existing terminal kernel-fault images remain separate and prove that genuine
kernel faults still park rather than masquerade as task faults.

## Consequences

Stage 7 can add a validated executable container and application ABI without
changing the privilege, page ownership, copied-message, fault-fate, or teardown
boundaries. It must still decide executable format, register/startup contract,
system-call representation, application memory budgets, and policy for
non-yielding code. Completion of Stage 6 does not imply loadable applications,
preemption, SMP, asynchronous IPC, shared memory, or a stable userspace ABI.

"""Regression tests for native application entry and completion contracts."""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MMU_SOURCE = (REPO_ROOT / "crates/runtime/troe-machine/src/mmu.rs").read_text(
    encoding="utf-8"
)
KERNEL_SRC = REPO_ROOT / "kernel/src"


def kernel_module(relative: str) -> str:
    """Read one kernel module and fail clearly if the module tree moves."""
    return (KERNEL_SRC / relative).read_text(encoding="utf-8")


ARTIFACTS_SOURCE = kernel_module("artifacts.rs")
DEFERRED_SOURCE = kernel_module("deferred.rs")
INVOCATION_SOURCE = kernel_module("invocation.rs")
LAUNCH_MEMORY_SOURCE = kernel_module("memory/launch.rs")
GROWTH_MEMORY_SOURCE = kernel_module("memory/growth.rs")
CONTRACT_SOURCE = (REPO_ROOT / "docs/testing.md").read_text(encoding="utf-8")


def source_between(source: str, start: str, end: str) -> str:
    """Return a named source region and fail clearly if either boundary moves."""
    start_offset = source.index(start)
    end_offset = source.index(end, start_offset + len(start))
    return source[start_offset:end_offset]


def source_after(source: str, start: str) -> str:
    """Return a named source region that runs to the end of its module."""
    return source[source.index(start) :]


def require_order(test: unittest.TestCase, source: str, *tokens: str) -> None:
    """Require every token exactly after its predecessor."""
    offset = 0
    for token in tokens:
        next_offset = source.find(token, offset)
        test.assertNotEqual(next_offset, -1, f"missing ordered token: {token}")
        offset = next_offset + len(token)


class NativeExecutionContractTests(unittest.TestCase):
    """Pin the ordering properties that make native entry and exit sound."""

    def test_x86_input_irq_normalizes_user_controlled_cpu_flags(self) -> None:
        entry = source_between(
            MMU_SOURCE,
            'extern "C" fn x86_input_interrupt_entry()',
            'extern "C" fn x86_input_interrupt_handler()',
        )
        require_order(
            self,
            entry,
            '"fxsave64 [rsp]"',
            '"cld"',
            '"pushfq"',
            '"btr qword ptr [rsp], 18"',
            '"popfq"',
            '"call {handler}"',
        )

    def test_every_rust_calling_x86_gate_normalizes_df_and_ac(self) -> None:
        gates = (
            (
                'extern "C" fn x86_isolated_syscall_entry()',
                'extern "C" fn x86_isolated_syscall_handler(',
            ),
            (
                'extern "C" fn x86_execution_timer_entry()',
                'extern "C" fn x86_execution_timer_handler(',
            ),
            (
                'extern "C" fn x86_input_interrupt_entry()',
                'extern "C" fn x86_input_interrupt_handler()',
            ),
            (
                'extern "C" fn x86_exception_no_error_entry()',
                'extern "C" fn x86_exception_error_entry()',
            ),
            (
                'extern "C" fn x86_exception_error_entry()',
                'extern "C" fn x86_exception_dispatch(',
            ),
            (
                'extern "C" fn x86_page_fault_entry()',
                'extern "C" fn x86_page_fault_dispatch(',
            ),
        )
        for start, end in gates:
            with self.subTest(gate=start):
                entry = source_between(MMU_SOURCE, start, end)
                require_order(
                    self,
                    entry,
                    '"cld"',
                    '"pushfq"',
                    '"btr qword ptr [rsp], 18"',
                    '"popfq"',
                    '"call {',
                )

    def test_resumable_native_irq_frames_save_complete_visible_state(self) -> None:
        x86 = source_between(
            MMU_SOURCE,
            'extern "C" fn x86_input_interrupt_entry()',
            'extern "C" fn x86_input_interrupt_handler()',
        )
        require_order(
            self,
            x86,
            '"push rax"',
            '"push r15"',
            '"fxsave64 [rsp]"',
            '"call {handler}"',
            '"fxrstor64 [rsp]"',
            '"pop r15"',
            '"pop rax"',
            '"iretq"',
        )

        aarch64 = source_between(
            MMU_SOURCE,
            '"troe_aarch64_irq_entry:"',
            "isolated_complete = sym aarch64_isolated_complete",
        )
        require_order(
            self,
            aarch64,
            '"msr daifset, #2"',
            '"stp x0, x1, [sp, #0]"',
            '"str x30, [sp, #240]"',
            '"stp q0, q1, [sp, #256]"',
            '"stp q30, q31, [sp, #736]"',
            '"bl troe_aarch64_input_interrupt"',
            '"ldp q0, q1, [sp, #256]"',
            '"ldp q30, q31, [sp, #736]"',
            '"ldp x0, x1, [sp, #0]"',
            '"ldr x30, [sp, #240]"',
            '"eret"',
        )

    def test_x86_timer_has_distinct_user_lease_and_kernel_deadline_returns(
        self,
    ) -> None:
        entry = source_between(
            MMU_SOURCE,
            'extern "C" fn x86_execution_timer_entry()',
            'extern "C" fn x86_runtime_timer_handler()',
        )
        require_order(
            self,
            entry,
            '"test byte ptr [rsp + 8], 3"',
            '"jz 2f"',
            '"push r15"',
            '"fxsave64 [rsp]"',
            '"call {handler}"',
            '"jmp {complete}"',
            '"2:"',
            '"push rax"',
            '"push r15"',
            '"fxsave64 [rsp]"',
            '"call {runtime_handler}"',
            '"fxrstor64 [rsp]"',
            '"pop r15"',
            '"pop rax"',
            '"iretq"',
        )

    def test_aarch64_suspended_context_preserves_thread_pointer(self) -> None:
        context = source_between(
            MMU_SOURCE,
            "struct ArchitectureApplicationContext {",
            "pub struct ApplicationSession",
        )
        self.assertIn("thread_pointer: u64", context)
        self.assertIn("thread_pointer) == 808", context)

        lower_sync = source_between(
            MMU_SOURCE,
            '"troe_aarch64_lower_sync_entry:"',
            '"troe_aarch64_isolated_complete_entry:"',
        )
        require_order(
            self,
            lower_sync,
            '"mrs x9, tpidr_el0"',
            '"str x9, [sp, #808]"',
            '"bl troe_aarch64_isolated_syscall"',
        )
        resume = source_between(
            MMU_SOURCE,
            'unsafe extern "C" fn aarch64_resume_application(',
            'extern "C" fn aarch64_isolated_complete()',
        )
        require_order(
            self,
            resume,
            '"ldr x9, [x11, #808]"',
            '"msr tpidr_el0, x9"',
            '"eret"',
        )
        self.assertIn("native-thread-pointer-aarch64.kex", ARTIFACTS_SOURCE)

    def test_documented_matrix_enumerates_every_native_gate(self) -> None:
        for gate in (
            "x86_isolated_syscall_entry",
            "x86_execution_timer_entry",
            "x86_input_interrupt_entry",
            "x86_exception_no_error_entry",
            "x86_exception_error_entry",
            "x86_page_fault_entry",
            "x86_spurious_interrupt_entry",
            "troe_aarch64_exception_entry",
            "troe_aarch64_lower_sync_entry",
            "troe_aarch64_irq_entry",
        ):
            with self.subTest(gate=gate):
                self.assertIn(f"`{gate}`", CONTRACT_SOURCE)

    def test_aarch64_irq_passes_complete_context_to_timer_handler(self) -> None:
        vectors = source_between(
            MMU_SOURCE,
            '"troe_aarch64_irq_entry:"',
            "isolated_complete = sym aarch64_isolated_complete",
        )
        require_order(
            self,
            vectors,
            '"mrs x10, spsr_el1"',
            '"str x10, [sp, #792]"',
            '"mov x0, sp"',
            '"bl troe_aarch64_input_interrupt"',
        )
        handler = source_between(
            MMU_SOURCE,
            'extern "C" fn troe_aarch64_input_interrupt(',
            'extern "C" fn troe_aarch64_isolated_syscall(',
        )
        self.assertIn("status & AARCH64_SPSR_MODE_MASK == 0", handler)
        self.assertIn("preempt_application", handler)
        self.assertIn("ISOLATED_ACTIVE.load(Ordering::Acquire)", handler)

    def test_application_state_is_unpublished_before_irqs_are_reenabled(self) -> None:
        for function, end in (
            ("pub fn run_application(", "pub fn resume_application("),
            ("pub fn resume_application(", "fn decode_isolated_outcome("),
        ):
            with self.subTest(function=function):
                body = source_between(MMU_SOURCE, function, end)
                require_order(
                    self,
                    body,
                    "prepare_application_execution(",
                    "architecture_",
                    "quiesce_application_execution()",
                    "ISOLATED_ACTIVE.store(false, Ordering::Release)",
                    "finish_application_execution()",
                )

    def test_timeslices_and_local_service_budgets_do_not_cap_process_lifetime(
        self,
    ) -> None:
        runner = source_between(
            INVOCATION_SOURCE,
            "fn run_command_application(",
            "fn command_application_error(",
        )
        budget = source_between(runner, "let terminal = loop", "match outcome")
        self.assertIn("ApplicationOutcome::HandleCall", budget)
        self.assertIn("if service_call && let Some(service_call_limit)", budget)
        self.assertNotIn("monotonic_millis()", budget)
        self.assertNotIn("CommandRuntimeExpired", runner)
        for outcome in ("Yielded", "Preempted", "HeapGrow"):
            with self.subTest(outcome=outcome):
                self.assertNotIn(f"ApplicationOutcome::{outcome}", budget)
        require_order(
            self,
            budget,
            "service_calls.checked_add(1)",
            "service_calls > service_call_limit",
        )
        preemption = source_between(
            runner,
            "ApplicationOutcome::Preempted(application)",
            "ApplicationOutcome::Yielded(application)",
        )
        require_order(
            self,
            preemption,
            "scheduler.preempt_current(task_id)",
            "dispatch(task_id, Capabilities::SERVICE)",
            "ApplicationResume::Timeslice",
        )

    def test_deferred_calls_block_idle_wake_and_resume_in_owned_order(self) -> None:
        waiter = source_between(
            DEFERRED_SOURCE,
            "fn wait_for_deferred_call(",
            "fn complete_diagnostics_deferred_call(",
        )
        require_order(
            self,
            waiter,
            "checkpoint()",
            "wait_for_runtime_event_timeout(interval)",
            "pending.resolve(completion)",
            "wake_blocked(completion.owner(), completion.key())",
            "dispatch(task_id, Capabilities::SERVICE)",
            "suspended.take(operation)",
            "pending.finish(operation)",
        )

        deferred_resume = source_after(
            DEFERRED_SOURCE,
            "fn resume_deferred_application_call(",
        )
        require_order(
            self,
            deferred_resume,
            "state.pending.bind_wait(operation, wait)",
            "state.suspended.insert(",
            "scheduler.block_current(task_id, wait)",
            "wait_for_deferred_call(",
            "troe_machine::resume_application(",
        )

        deferred_state = source_between(
            DEFERRED_SOURCE,
            "impl CommandDeferredState {",
            "fn command_handle_interface(",
        )
        self.assertIn("cancel_owner(owner, WakeReason::Revoked)", deferred_state)
        self.assertIn("teardown_owner(owner, WakeReason::Revoked)", deferred_state)

        runner = source_between(
            INVOCATION_SOURCE,
            "fn run_command_application(",
            "fn command_application_error(",
        )
        self.assertIn("resume_deferred_application_call(", runner)
        self.assertIn("state.revoke_owner(task_id)", runner)

    def test_command_cleanup_failures_are_terminal(self) -> None:
        runner = source_between(
            INVOCATION_SOURCE,
            "fn run_command_application(",
            "fn command_application_error(",
        )
        self.assertIn("rollback_command_application_task(", runner)
        self.assertIn("reclaim_command_application(", runner)

        rollback = source_between(
            LAUNCH_MEMORY_SOURCE,
            "fn rollback_command_application_task(",
            "fn reclaim_command_application(",
        )
        reclaim = source_between(
            LAUNCH_MEMORY_SOURCE,
            "fn reclaim_command_application(",
            "fn clear_provisional_loader_ownership(",
        )
        self.assertIn('fatal(b"fatal: application rollback invariant failed', rollback)
        self.assertIn('fatal(b"fatal: application reclaim invariant failed', reclaim)

    def test_growth_rollback_retains_metadata_until_release_succeeds(self) -> None:
        release = source_between(
            GROWTH_MEMORY_SOURCE,
            "fn release_application_growth_suffix(",
            "fn application_growth_pages(",
        )
        for collection, free in (
            ("growth_ranges", "frames.free_range(range)"),
            ("growth_table_frames", "frames.free(frame)"),
        ):
            with self.subTest(collection=collection):
                require_order(
                    self,
                    release,
                    f"{collection}.last()",
                    "zero_physical_range",
                    free,
                    f"{collection}.pop()",
                )


if __name__ == "__main__":
    unittest.main()

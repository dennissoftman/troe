"""Regression tests for native application entry and completion contracts."""

from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MMU_SOURCE = (REPO_ROOT / "crates/troe-machine/src/mmu.rs").read_text(
    encoding="utf-8"
)
KERNEL_SOURCE = (REPO_ROOT / "kernel/src/main.rs").read_text(encoding="utf-8")
CONTRACT_SOURCE = (REPO_ROOT / "docs/native-trap-entry-contract.md").read_text(
    encoding="utf-8"
)


def source_between(source: str, start: str, end: str) -> str:
    """Return a named source region and fail clearly if either boundary moves."""
    start_offset = source.index(start)
    end_offset = source.index(end, start_offset + len(start))
    return source[start_offset:end_offset]


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
            '"stp q0, q1, [sp, #272]"',
            '"stp q30, q31, [sp, #752]"',
            '"stp x0, x1, [sp, #0]"',
            '"str x30, [sp, #240]"',
            '"bl troe_aarch64_input_interrupt"',
            '"ldp q0, q1, [sp, #272]"',
            '"ldp q30, q31, [sp, #752]"',
            '"ldp x0, x1, [sp, #0]"',
            '"ldr x30, [sp, #240]"',
            '"eret"',
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
            "unsafe extern \"C\" fn aarch64_resume_application(",
            "extern \"C\" fn aarch64_isolated_complete()",
        )
        require_order(
            self,
            resume,
            '"ldr x9, [x11, #808]"',
            '"msr tpidr_el0, x9"',
            '"eret"',
        )
        self.assertIn("native-thread-pointer-aarch64.kex", KERNEL_SOURCE)

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

    def test_aarch64_irq_passes_exception_origin_to_timer_handler(self) -> None:
        vectors = source_between(
            MMU_SOURCE,
            '"troe_aarch64_irq_entry:"',
            "isolated_complete = sym aarch64_isolated_complete",
        )
        require_order(
            self,
            vectors,
            '"mrs x0, spsr_el1"',
            '"bl troe_aarch64_input_interrupt"',
        )
        handler = source_between(
            MMU_SOURCE,
            'extern "C" fn troe_aarch64_input_interrupt(saved_program_status: u64)',
            'extern "C" fn troe_aarch64_isolated_syscall(',
        )
        self.assertIn("saved_program_status & AARCH64_SPSR_MODE_MASK == 0", handler)
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

    def test_every_resumable_application_outcome_is_charged(self) -> None:
        runner = source_between(
            KERNEL_SOURCE,
            "fn run_command_application(",
            "const fn task_fault(",
        )
        budget = source_between(runner, "let terminal = loop", "match outcome")
        for outcome in ("Yielded", "HandleCall", "HeapGrow"):
            with self.subTest(outcome=outcome):
                self.assertIn(f"ApplicationOutcome::{outcome}", budget)
        require_order(
            self,
            budget,
            "monotonic_millis()",
            "APPLICATION_COMMAND_RUNTIME_MILLISECONDS",
            "if resumable",
            "steps.checked_add(1)",
            "APPLICATION_COMMAND_STEP_LIMIT",
        )

    def test_command_cleanup_failures_are_terminal(self) -> None:
        runner = source_between(
            KERNEL_SOURCE,
            "fn run_command_application(",
            "const fn task_fault(",
        )
        self.assertIn("rollback_command_application_task(", runner)
        self.assertIn("reclaim_command_application(", runner)

        rollback = source_between(
            KERNEL_SOURCE,
            "fn rollback_command_application_task(",
            "fn reclaim_command_application(",
        )
        reclaim = source_between(
            KERNEL_SOURCE,
            "fn reclaim_command_application(",
            "fn clear_provisional_loader_ownership(",
        )
        self.assertIn('fatal(b"fatal: application rollback invariant failed', rollback)
        self.assertIn('fatal(b"fatal: application reclaim invariant failed', reclaim)

    def test_growth_rollback_retains_metadata_until_release_succeeds(self) -> None:
        release = source_between(
            KERNEL_SOURCE,
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

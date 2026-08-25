"""Host-only tests for conservative changed-path verification selection."""

from __future__ import annotations

import unittest
from pathlib import PurePosixPath
from unittest import mock

from scripts import test_changed


def package(
    name: str, root: str, *reverse_dependencies: str
) -> test_changed.WorkspacePackage:
    """Build one compact package-graph fixture."""
    return test_changed.WorkspacePackage(
        name,
        PurePosixPath(root),
        frozenset(reverse_dependencies),
    )


PACKAGES = {
    "troe-net": package("troe-net", "crates/troe-net", "troe-machine", "troe-kernel"),
    "troe-machine": package("troe-machine", "crates/troe-machine", "troe-kernel"),
    "troe-kernel": package("troe-kernel", "kernel"),
    "troe-kex": package("troe-kex", "sdk/rust/troe-kex"),
    "troe-kex-alloc": package("troe-kex-alloc", "sdk/rust/troe-kex-alloc"),
    "troe-kex-tool": package("troe-kex-tool", "tools/troe-kex-tool"),
}


class ChangedTestSelectionTests(unittest.TestCase):
    """Selection widens through dependencies and fails closed for uncertainty."""

    def test_rust_change_selects_reverse_dependency_closure_and_scenarios(self) -> None:
        path = PurePosixPath("crates/troe-net/src/lib.rs")
        plan = test_changed.build_plan((path,), PACKAGES)
        self.assertFalse(plan.full_reasons)
        self.assertEqual(
            plan.rust_packages, {"troe-net", "troe-machine", "troe-kernel"}
        )
        self.assertEqual(plan.qemu_scenarios, {"boot", "network"})
        self.assertFalse(plan.qemu_all_platforms)

    def test_git_collection_includes_deletions_and_both_sides_of_renames(self) -> None:
        with mock.patch.object(
            test_changed,
            "_git_lines",
            side_effect=(("removed.rs", "added.rs"), ("untracked.rs",)),
        ) as git_lines:
            paths = test_changed.changed_paths("main")
        self.assertEqual(
            paths,
            tuple(
                PurePosixPath(path)
                for path in ("added.rs", "removed.rs", "untracked.rs")
            ),
        )
        self.assertIn("--no-renames", git_lines.call_args_list[0].args)
        self.assertIn("--diff-filter=ACDMRTUXB", git_lines.call_args_list[0].args)

    def test_low_level_change_expands_qemu_to_every_platform(self) -> None:
        plan = test_changed.build_plan(
            (PurePosixPath("crates/troe-machine/src/mechanism.rs"),), PACKAGES
        )
        self.assertTrue(plan.qemu_all_platforms)
        self.assertIn("fault-isolation", plan.qemu_scenarios)
        self.assertIn("troe-kernel", plan.rust_packages)

    def test_one_app_selects_only_its_dual_target_build_and_behavior(self) -> None:
        plan = test_changed.build_plan(
            (PurePosixPath("apps/tcp/src/main.rs"),), PACKAGES
        )
        self.assertFalse(plan.full_reasons)
        self.assertEqual(plan.applications, {"tcp"})
        self.assertFalse(plan.all_applications)
        self.assertEqual(plan.qemu_scenarios, {"network"})

    def test_app_mapping_targets_the_group_that_executes_the_command(self) -> None:
        printf_plan = test_changed.build_plan(
            (PurePosixPath("apps/printf/src/lib.rs"),), PACKAGES
        )
        man_plan = test_changed.build_plan(
            (PurePosixPath("apps/man/src/main.rs"),), PACKAGES
        )
        self.assertEqual(printf_plan.qemu_scenarios, {"filesystem"})
        self.assertEqual(man_plan.qemu_scenarios, {"shell-terminal"})
        lua_plan = test_changed.build_plan(
            (PurePosixPath("apps/lua/src/main.rs"),), PACKAGES
        )
        self.assertEqual(lua_plan.qemu_scenarios, {"lua"})

    def test_allocator_sdk_selects_lua_build_and_runtime_scenario(self) -> None:
        plan = test_changed.build_plan(
            (PurePosixPath("sdk/rust/troe-kex-alloc/src/lib.rs"),), PACKAGES
        )
        self.assertEqual(plan.applications, {"lua"})
        self.assertEqual(plan.qemu_scenarios, {"lua"})

    def test_shared_sdk_selects_every_application_and_tool_regression(self) -> None:
        plan = test_changed.build_plan(
            (PurePosixPath("sdk/rust/troe-kex/src/lib.rs"),), PACKAGES
        )
        self.assertTrue(plan.all_applications)
        self.assertEqual(plan.applications, set())
        self.assertIn("test_kex_tool.py", plan.python_tests)

    def test_runtime_image_tool_selects_owned_host_and_boot_suites(self) -> None:
        plan = test_changed.build_plan((PurePosixPath("tools/mkcloud.py"),), PACKAGES)
        self.assertFalse(plan.full_reasons)
        self.assertEqual(plan.python_tests, {"test_cloud_artifacts.py"})
        self.assertEqual(plan.qemu_scenarios, {"boot", "filesystem", "persistence"})
        self.assertTrue(plan.qemu_all_platforms)

    def test_audit_policy_change_runs_audit_without_unknown_fallback(self) -> None:
        plan = test_changed.build_plan(
            (PurePosixPath("tools/rustsec-exceptions.json"),), PACKAGES
        )
        self.assertFalse(plan.full_reasons)
        self.assertTrue(plan.run_audit)
        self.assertIn("test_audit_policy.py", plan.python_tests)

    def test_global_and_unknown_changes_fail_closed_to_full(self) -> None:
        for path in ("Cargo.toml", "new-unmapped-format.bin"):
            with self.subTest(path=path):
                plan = test_changed.build_plan((PurePosixPath(path),), PACKAGES)
                self.assertTrue(plan.full_reasons)

    def test_qemu_command_repeats_selected_groups_and_honors_scope(self) -> None:
        plan = test_changed.TestPlan((PurePosixPath("crates/troe-net/src/lib.rs"),))
        plan.qemu_scenarios.update(("network", "boot"))
        commands = test_changed.commands_for_plan(
            plan, skip_qemu=False, require_filesystem_tools=False
        )
        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertIn(test_changed.X86_64_Q35_UEFI, command)
        self.assertEqual(command.count("--scenario"), 2)
        self.assertIn("boot", command)
        self.assertIn("network", command)

    def test_full_fallback_preserves_qemu_unless_explicitly_skipped(self) -> None:
        plan = test_changed.TestPlan((PurePosixPath("Cargo.toml"),))
        plan.require_full(PurePosixPath("Cargo.toml"), "global")
        full = test_changed.commands_for_plan(
            plan, skip_qemu=False, require_filesystem_tools=False
        )[0]
        skipped = test_changed.commands_for_plan(
            plan, skip_qemu=True, require_filesystem_tools=True
        )[0]
        self.assertNotIn("--skip-qemu", full)
        self.assertIn("--skip-qemu", skipped)
        self.assertIn("--require-filesystem-tools", skipped)

    def test_selector_and_qemu_scenario_catalogs_are_exactly_aligned(self) -> None:
        self.assertEqual(
            test_changed.ALL_QEMU_SCENARIOS,
            frozenset(
                (
                    "boot",
                    "network",
                    "shell-terminal",
                    "filesystem",
                    "lua",
                    "quota-memory",
                    "persistence",
                    "fault-isolation",
                    "framebuffer-keyboard",
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()

"""Host-only tests for conservative changed-path verification selection."""

from __future__ import annotations

import unittest
from pathlib import PurePosixPath
from unittest import mock

from scripts import test_changed, test_scenarios
from scripts.test import PLATFORM_PROFILES


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
    "troe-completion": package(
        "troe-completion", "crates/common/troe-completion", "troe-shell"
    ),
    "troe-shell": package(
        "troe-shell", "crates/shell/troe-shell", "troe-host", "troe-kernel"
    ),
    "troe-host": package("troe-host", "host"),
    "troe-net": package(
        "troe-net", "crates/net/troe-net", "troe-machine", "troe-kernel"
    ),
    "troe-machine": package(
        "troe-machine", "crates/runtime/troe-machine", "troe-kernel"
    ),
    "troe-kernel": package("troe-kernel", "kernel"),
    "troe-kex": package("troe-kex", "sdk/rust/troe-kex"),
    "troe-kex-alloc": package("troe-kex-alloc", "sdk/rust/troe-kex-alloc"),
    "troe-kex-c-runtime": package("troe-kex-c-runtime", "sdk/rust/troe-kex-c-runtime"),
    "troe-kex-tool": package("troe-kex-tool", "tools/troe-kex-tool"),
}


class ChangedTestSelectionTests(unittest.TestCase):
    """Selection widens through dependencies and fails closed for uncertainty."""

    def test_rust_change_selects_reverse_dependency_closure_and_scenarios(self) -> None:
        path = PurePosixPath("crates/net/troe-net/src/lib.rs")
        plan = test_changed.build_plan((path,), PACKAGES)
        self.assertFalse(plan.full_reasons)
        self.assertEqual(
            plan.rust_packages, {"troe-net", "troe-machine", "troe-kernel"}
        )
        self.assertEqual(plan.qemu_scenarios, {"boot", "network"})
        self.assertFalse(plan.qemu_all_platforms)

    def test_completion_policy_change_selects_shell_consumers_and_behavior(
        self,
    ) -> None:
        path = PurePosixPath("crates/common/troe-completion/src/lib.rs")
        plan = test_changed.build_plan((path,), PACKAGES)
        self.assertFalse(plan.full_reasons)
        self.assertEqual(
            plan.rust_packages,
            {"troe-completion", "troe-shell", "troe-host", "troe-kernel"},
        )
        self.assertEqual(plan.qemu_scenarios, {"boot", "shell-terminal", "filesystem"})

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
            (PurePosixPath("crates/runtime/troe-machine/src/mechanism.rs"),), PACKAGES
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
        wc_plan = test_changed.build_plan(
            (PurePosixPath("apps/wc/src/lib.rs"),), PACKAGES
        )
        tar_plan = test_changed.build_plan(
            (PurePosixPath("apps/tar/src/lib.rs"),), PACKAGES
        )
        self.assertEqual(wc_plan.qemu_scenarios, {"filesystem", "shell-terminal"})
        self.assertEqual(tar_plan.qemu_scenarios, {"filesystem"})
        self.assertEqual(man_plan.qemu_scenarios, {"shell-terminal"})
        cat_plan = test_changed.build_plan(
            (PurePosixPath("apps/cat/src/main.rs"),), PACKAGES
        )
        udp_plan = test_changed.build_plan(
            (PurePosixPath("apps/udp/src/main.rs"),), PACKAGES
        )
        # Standard-input readers exercise the foreground terminal loan as well
        # as the group that supplies their operands.
        self.assertEqual(cat_plan.qemu_scenarios, {"filesystem", "shell-terminal"})
        self.assertEqual(udp_plan.qemu_scenarios, {"network", "shell-terminal"})
        lua_plan = test_changed.build_plan(
            (PurePosixPath("apps/lua/src/main.rs"),), PACKAGES
        )
        self.assertEqual(lua_plan.python_tests, {"test_lua_app.py"})
        self.assertEqual(lua_plan.qemu_scenarios, {"lua", "filesystem"})

    def test_allocator_sdk_selects_lua_build_and_runtime_scenario(self) -> None:
        plan = test_changed.build_plan(
            (PurePosixPath("sdk/rust/troe-kex-alloc/src/lib.rs"),), PACKAGES
        )
        self.assertEqual(plan.applications, {"cp", "lua", "mv", "rm"})
        self.assertEqual(plan.qemu_scenarios, {"filesystem", "lua"})

    def test_c_runtime_bridge_selects_runtime_probe_scenario(self) -> None:
        plan = test_changed.build_plan(
            (PurePosixPath("sdk/rust/troe-kex-c-runtime/src/lib.rs"),),
            PACKAGES,
        )
        self.assertFalse(plan.full_reasons)
        self.assertEqual(plan.rust_packages, {"troe-kex-c-runtime"})
        self.assertEqual(plan.qemu_scenarios, {"filesystem"})

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
        self.assertEqual(
            plan.python_tests, {"test_cloud_artifacts.py", "test_setup_troe.py"}
        )
        self.assertEqual(plan.qemu_scenarios, {"boot", "filesystem", "persistence"})
        self.assertTrue(plan.qemu_all_platforms)

    def test_shared_media_tool_selects_builder_mount_and_qemu_coverage(self) -> None:
        plan = test_changed.build_plan((PurePosixPath("tools/mkshared.py"),), PACKAGES)
        self.assertFalse(plan.full_reasons)
        self.assertEqual(
            plan.python_tests,
            {"test_mkshared.py", "test_mkstorage.py", "test_qemu_profile.py"},
        )
        self.assertEqual(plan.qemu_scenarios, {"boot", "filesystem"})
        self.assertTrue(plan.qemu_all_platforms)

    def test_runtime_tree_and_c_sysroot_tools_select_owned_contracts(self) -> None:
        cases = {
            "tools/mkruntime.py": "test_mkruntime.py",
            "tools/build_c_sysroot.py": "test_c_sysroot.py",
        }
        for path, test in cases.items():
            with self.subTest(path=path):
                plan = test_changed.build_plan((PurePosixPath(path),), PACKAGES)
                self.assertFalse(plan.full_reasons)
                self.assertEqual(plan.python_tests, {test})
                self.assertEqual(plan.qemu_scenarios, {"filesystem"})
                self.assertTrue(plan.qemu_all_platforms)

    def test_qemu_plugin_paths_select_only_their_host_contract_test(self) -> None:
        for path in (
            "tools/build_qemu_plugin.py",
            "tools/qemu-plugin/troe_count.c",
        ):
            with self.subTest(path=path):
                plan = test_changed.build_plan((PurePosixPath(path),), PACKAGES)
                self.assertFalse(plan.full_reasons)
                self.assertEqual(plan.python_tests, {"test_qemu_plugin.py"})
                self.assertEqual(plan.qemu_scenarios, set())

    def test_package_model_and_cli_select_only_their_host_contract_tests(self) -> None:
        cases = {
            "tools/package_model.py": "test_package_model.py",
            "tools/troe.py": "test_package_model.py",
            "tools/package_trust.py": "test_package_trust.py",
            "tools/troe_trust.py": "test_package_trust.py",
        }
        for path, test in cases.items():
            with self.subTest(path=path):
                plan = test_changed.build_plan((PurePosixPath(path),), PACKAGES)
                self.assertFalse(plan.full_reasons)
                self.assertEqual(plan.python_tests, {test})
                self.assertEqual(plan.qemu_scenarios, set())

    def test_cloud_hypervisor_runner_selects_its_host_contract_tests(self) -> None:
        cases = {
            "scripts/cloud_hypervisor_profile.py": {
                "test_cloud_hypervisor_profile.py",
                "test_setup_troe.py",
            },
            "scripts/test-cloud-hypervisor.py": {"test_cloud_hypervisor_profile.py"},
            "tools/cloud-hypervisor-profile.json": {"test_cloud_hypervisor_profile.py"},
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                plan = test_changed.build_plan((PurePosixPath(path),), PACKAGES)
                self.assertFalse(plan.full_reasons)
                self.assertEqual(plan.python_tests, expected)
                self.assertEqual(plan.qemu_scenarios, set())

    def test_provisioning_boundary_selects_installer_and_harness_contracts(
        self,
    ) -> None:
        plan = test_changed.build_plan(
            (PurePosixPath("tools/setup_troe.py"),), PACKAGES
        )
        self.assertFalse(plan.full_reasons)
        self.assertEqual(
            plan.python_tests,
            {"test_setup_troe.py", "test_cloud_hypervisor_profile.py"},
        )
        self.assertEqual(plan.qemu_scenarios, set())

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

    def test_every_changed_python_file_is_formatted_and_linted(self) -> None:
        plan = test_changed.build_plan(
            (
                PurePosixPath("tools/mkefs.py"),
                PurePosixPath("tests/fixtures/cpython/language_probe.py"),
                PurePosixPath("crates/net/troe-net/src/lib.rs"),
            ),
            PACKAGES,
        )
        self.assertEqual(
            plan.python_lint_paths,
            {"tools/mkefs.py", "tests/fixtures/cpython/language_probe.py"},
        )
        commands = test_changed.commands_for_plan(
            plan, skip_qemu=True, require_filesystem_tools=False
        )
        self.assertEqual(
            [command for command in commands if command[0] == "ruff"],
            [
                (
                    "ruff",
                    "format",
                    "--check",
                    "tests/fixtures/cpython/language_probe.py",
                    "tools/mkefs.py",
                ),
                (
                    "ruff",
                    "check",
                    "tests/fixtures/cpython/language_probe.py",
                    "tools/mkefs.py",
                ),
            ],
        )
        rust_only = test_changed.build_plan(
            (PurePosixPath("crates/net/troe-net/src/lib.rs"),), PACKAGES
        )
        self.assertEqual(rust_only.python_lint_paths, set())

    def test_a_deleted_python_file_is_not_handed_to_the_lint_gates(self) -> None:
        """`changed_paths` reports deletions and, under `--no-renames`, the old
        side of every rename. `ruff` is given file names, and it exits 2 on a
        name that is not on disk, so selecting a deleted path would abort the
        focused run with `command exited with status 2` for any change that
        removed or renamed a Python file."""
        gone = (
            PurePosixPath("tests/test_a_removed_gate.py"),
            PurePosixPath("tests/fixtures/cpython/removed_probe.py"),
        )
        for path in gone:
            with self.subTest(path=path):
                self.assertFalse((test_changed.REPO_ROOT / path).exists())
        plan = test_changed.build_plan(gone, PACKAGES)
        self.assertFalse(plan.full_reasons)
        self.assertEqual(plan.python_lint_paths, set())
        commands = test_changed.commands_for_plan(
            plan, skip_qemu=True, require_filesystem_tools=False
        )
        self.assertEqual(
            [
                command
                for command in commands
                if command[0] == test_changed.RUFF_EXECUTABLE
            ],
            [],
        )

        surviving = PurePosixPath("tools/mkefs.py")
        self.assertTrue((test_changed.REPO_ROOT / surviving).is_file())
        mixed = test_changed.build_plan((*gone, surviving), PACKAGES)
        self.assertEqual(mixed.python_lint_paths, {"tools/mkefs.py"})

    def test_the_python_tooling_policy_widens_to_the_full_gate(self) -> None:
        plan = test_changed.build_plan((PurePosixPath("pyproject.toml"),), PACKAGES)
        self.assertTrue(plan.full_reasons)
        command = test_changed.commands_for_plan(
            plan,
            skip_qemu=True,
            require_filesystem_tools=False,
            require_python_tools=True,
        )[0]
        self.assertIn("--require-python-tools", command)

    def test_a_kernel_change_selects_every_per_platform_target_lint(self) -> None:
        """`scripts/test.py` wraps each gate in a labeled `Step`, and the
        selector renders argv. It iterated the `Step` itself, so every change
        that reached `troe-kernel` through the dependency closure aborted the
        focused run with `TypeError: 'Step' object is not iterable`."""
        plan = test_changed.TestPlan(
            (PurePosixPath("crates/runtime/troe-kernel/src/lib.rs"),)
        )
        plan.rust_packages.add("troe-kernel")
        commands = test_changed.commands_for_plan(
            plan, skip_qemu=True, require_filesystem_tools=False
        )
        target_lints = [
            command
            for command in commands
            if command[:2] == ("cargo", "clippy") and "--target" in command
        ]
        self.assertEqual(len(target_lints), len(PLATFORM_PROFILES))
        for command in target_lints:
            self.assertTrue(all(isinstance(argument, str) for argument in command))
            self.assertEqual(command[-3:], ("--", "-D", "warnings"))

    def test_qemu_command_repeats_selected_groups_and_honors_scope(self) -> None:
        plan = test_changed.TestPlan((PurePosixPath("crates/net/troe-net/src/lib.rs"),))
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

    def test_cpython_paths_select_their_own_gate_without_a_rootfs_kex_build(
        self,
    ) -> None:
        paths = (
            PurePosixPath("apps/python/src/main.rs"),
            PurePosixPath("tools/build_cpython.py"),
            PurePosixPath("tests/fixtures/cpython/language_probe.py"),
            PurePosixPath("tests/python-no-random/Cargo.toml"),
        )
        plan = test_changed.build_plan(paths, {})
        self.assertEqual(plan.full_reasons, [])
        # `python` is outside the clippy and test gates, so the policy suite's
        # textual `unwrap`/`expect`/`panic` scan is the only compiler-like check
        # a change to its sources gets. It is selected for every path under the
        # application, not only for its manifest.
        self.assertEqual(
            plan.python_tests,
            {"test_cpython_integration.py", "test_repository_policy.py"},
        )
        self.assertEqual(plan.qemu_scenarios, {"cpython"})
        self.assertEqual(plan.applications, {"python"})
        commands = test_changed.commands_for_plan(
            plan, skip_qemu=False, require_filesystem_tools=False
        )
        self.assertFalse(
            [command for command in commands if "kex" in command], commands
        )
        self.assertIn("cpython", test_scenarios.SCENARIO_IDS)
        self.assertNotIn("cpython", test_scenarios.DEFAULT_SCENARIOS)
        self.assertEqual(
            test_scenarios.OPTIONAL_SCENARIOS, frozenset({"cpython", "lua"})
        )

    def test_selector_and_qemu_scenario_catalogs_are_exactly_aligned(self) -> None:
        self.assertEqual(
            test_changed.ALL_QEMU_SCENARIOS,
            frozenset(
                (
                    "boot",
                    "network",
                    "shell-terminal",
                    "filesystem",
                    "quota-memory",
                    "persistence",
                    "fault-isolation",
                    "framebuffer-keyboard",
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()

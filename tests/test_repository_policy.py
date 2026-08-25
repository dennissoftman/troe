"""Regression tests for repository toolchain and dependency policy."""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from repository_policy import (  # noqa: E402
    AUDIT_EXCEPTIONS_FILE,
    load_audit_exceptions,
    require_supported_python,
)


class RepositoryPolicyTests(unittest.TestCase):
    """Exercise the closed repository policy at its exact boundaries."""

    def test_python_version_boundary(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "require Python 3.13"):
            require_supported_python((3, 12, 99))
        require_supported_python((3, 13, 0))
        require_supported_python((4, 0, 0))

    def test_committed_exception_policy_is_valid_and_empty(self) -> None:
        self.assertEqual(load_audit_exceptions(AUDIT_EXCEPTIONS_FILE), ())

    def test_exception_policy_requires_owner_rationale_and_future_expiry(self) -> None:
        valid = {
            "schema": 1,
            "exceptions": [
                {
                    "advisory": "RUSTSEC-2026-0001",
                    "owner": "security@example.invalid",
                    "rationale": "Temporary boundary dependency mitigation.",
                    "expires": "2026-08-25",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "exceptions.json"
            policy.write_text(json.dumps(valid), encoding="utf-8")
            today = datetime.date(2026, 8, 24)
            self.assertEqual(
                load_audit_exceptions(policy, today=today),
                ("RUSTSEC-2026-0001",),
            )

            valid["exceptions"][0]["expires"] = "2026-08-24"
            policy.write_text(json.dumps(valid), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expired"):
                load_audit_exceptions(policy, today=today)

            valid["exceptions"][0].pop("owner")
            policy.write_text(json.dumps(valid), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exactly"):
                load_audit_exceptions(policy, today=today)

    def test_workspace_metadata_has_only_approved_boundary_dependencies(self) -> None:
        output = subprocess.run(
            ("cargo", "metadata", "--no-deps", "--format-version", "1"),
            cwd=REPO_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        metadata = json.loads(output)
        actual: dict[str, set[tuple[str, str, bool]]] = {}
        for package in metadata["packages"]:
            external = {
                (dependency["name"], dependency["req"], dependency["uses_default_features"])
                for dependency in package["dependencies"]
                if dependency["source"] is not None
            }
            if external:
                actual[package["name"]] = external
            self.assertEqual(package["edition"], "2024")
            self.assertEqual(package["license"], "Apache-2.0")
        self.assertEqual(
            actual,
            {
                "troe-kernel": {("uefi", "=0.39.0", True)},
                "troe-machine": {
                    ("rlsf", "=0.2.3", False),
                    ("uefi", "=0.39.0", True),
                },
            },
        )

        toolchain = tomllib.loads(
            (REPO_ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(toolchain["toolchain"]["channel"], "1.97.1")
        self.assertEqual(
            toolchain["toolchain"]["targets"],
            [
                "x86_64-unknown-uefi",
                "aarch64-unknown-uefi",
                "x86_64-unknown-none",
                "aarch64-unknown-none",
            ],
        )

    def test_kex_authoring_skill_is_one_concise_repo_local_file(self) -> None:
        root = REPO_ROOT / "skills" / "write-kex-apps"
        files = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
        self.assertEqual(files, ["SKILL.md"])
        source = (root / "SKILL.md").read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 120)
        self.assertTrue(source.startswith("---\nname: write-kex-apps\ndescription: "))
        self.assertIn("cargo kex build", source)
        self.assertIn("troe_kex_sdk::entry!", source)
        self.assertIn("Do not infer POSIX behavior", source)

    def test_every_ordinary_command_is_kex_only_on_both_targets(self) -> None:
        ordinary = {
            "arp",
            "cat",
            "clear",
            "dhcp",
            "echo",
            "grep",
            "hexdump",
            "ls",
            "man",
            "mem",
            "net",
            "ping",
            "pwd",
            "rm",
            "sleep",
            "udp",
            "write",
        }
        apps = {
            path.name
            for path in (REPO_ROOT / "apps").iterdir()
            if path.is_dir() and (path / "Cargo.toml").is_file()
        }
        self.assertEqual(apps, ordinary)
        for architecture in ("x86_64", "aarch64"):
            installed = {
                path.stem
                for path in (REPO_ROOT / "rootfs/bin" / architecture).glob("*.kex")
            }
            self.assertEqual(installed, ordinary | {"kex-echo"})

        shell = (REPO_ROOT / "crates/troe-shell/src/lib.rs").read_text(
            encoding="utf-8"
        )
        self.assertEqual(shell.count("\n    fn command_"), 2)
        self.assertIn("fn command_cd", shell)
        self.assertIn("fn command_machine_action", shell)
        for forbidden in (
            "ReplaceableBuiltin",
            "NetworkControl",
            "set_network",
            "set_runtime",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, shell)

    def test_superseded_resource_profiles_cannot_reenter_source_apis(self) -> None:
        forbidden_rust = ("ResourceProfile", "ResourcePolicy", "::tiny()", "::full()")
        for root in (REPO_ROOT / "crates", REPO_ROOT / "kernel"):
            for path in root.rglob("*.rs"):
                source = path.read_text(encoding="utf-8")
                for token in forbidden_rust:
                    with self.subTest(path=path.relative_to(REPO_ROOT), token=token):
                        self.assertNotIn(token, source)

        for relative in (
            "scripts/build.py",
            "tools/elf2kex.py",
            "tools/gen_kex_corpus.py",
        ):
            source = (REPO_ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                self.assertNotIn("--profile", source)

    def test_platform_facts_and_virtio_transport_selection_stay_below_kernel(self) -> None:
        machine_sources = tuple((REPO_ROOT / "crates/troe-machine/src").glob("*.rs"))
        kernel_sources = tuple((REPO_ROOT / "kernel/src").glob("*.rs"))
        fixed_platform_literals = (
            "0xfee00000",
            "0xfec00000",
            "0x08000000",
            "0x09000000",
            "0x0a000000",
            "0x3f8",
            "0x604",
            "0xcf9",
        )
        for path in (*machine_sources, *kernel_sources):
            normalized = path.read_text(encoding="utf-8").lower().replace("_", "")
            for literal in fixed_platform_literals:
                with self.subTest(path=path.relative_to(REPO_ROOT), literal=literal):
                    self.assertNotIn(literal, normalized)

        kernel = (REPO_ROOT / "kernel/src/main.rs").read_text(encoding="utf-8")
        for transport_api in (
            "discover_virtio_mmio",
            "discover_virtio_pci",
            "virtio_mmio_device_ranges",
            "virtio_pci_device_ranges",
        ):
            with self.subTest(transport_api=transport_api):
                self.assertNotIn(transport_api, kernel)

        machine = (REPO_ROOT / "crates/troe-machine/src/lib.rs").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            machine.count("target_arch"),
            2,
            "target_arch may only guard platform/CPU compatibility, not select transport",
        )


if __name__ == "__main__":
    unittest.main()

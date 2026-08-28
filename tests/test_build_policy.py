"""Host-only checks for production EFI acceptance-payload exclusion."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

from scripts import build, test as verification


class ProductionBuildPolicyTests(unittest.TestCase):
    """Exercise the same marker gate used by the production build."""

    def test_clean_efi_is_accepted_without_qemu(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "kernel.efi"
            image.write_bytes(b"MZ\0canonical production image")
            build.verify_production_efi(image)

    def test_every_acceptance_marker_is_rejected_without_qemu(self) -> None:
        for marker in build.PRODUCTION_FORBIDDEN_MARKERS:
            with self.subTest(marker=marker):
                with tempfile.TemporaryDirectory() as temporary:
                    image = Path(temporary) / "kernel.efi"
                    image.write_bytes(b"MZ\0prefix" + marker + b"suffix")
                    with self.assertRaisesRegex(
                        RuntimeError, "acceptance probe marker"
                    ):
                        build.verify_production_efi(image)

    def test_platform_is_mandatory_and_architecture_alias_is_gone(self) -> None:
        parsed = build.parse_args(["--platform", "all", "--fixture-identities"])
        self.assertEqual(parsed.platform, "all")
        self.assertTrue(parsed.fixture_identities)
        self.assertFalse(parsed.acceptance_probes)
        self.assertFalse(parsed.all_variants)
        self.assertFalse(parsed.strict_tool_versions)
        self.assertEqual(parsed.volume_table, build.DEFAULT_VOLUME_TABLE)
        custom = build.parse_args(
            [
                "--platform",
                "all",
                "--fixture-identities",
                "--volume-table",
                "custom.toml",
            ]
        )
        self.assertEqual(custom.volume_table, Path("custom.toml"))
        all_variants = build.parse_args(
            ["--platform", "all", "--fixture-identities", "--all-variants"]
        )
        self.assertTrue(all_variants.all_variants)
        strict = build.parse_args(
            [
                "--platform",
                "all",
                "--fixture-identities",
                "--strict-tool-versions",
            ]
        )
        self.assertTrue(strict.strict_tool_versions)
        self.assertEqual(build.requested_variants(parsed), (False,))
        self.assertEqual(build.requested_variants(all_variants), (False, True))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                build.parse_args([])
            with self.assertRaises(SystemExit):
                build.parse_args(["--arch", "x86_64"])
            with self.assertRaises(SystemExit):
                build.parse_args(["--platform", "unknown"])
            with self.assertRaises(SystemExit):
                build.parse_args(["--platform", "all"])
            with self.assertRaises(SystemExit):
                build.parse_args(
                    [
                        "--platform",
                        "all",
                        "--fixture-identities",
                        "--acceptance-probes",
                        "--all-variants",
                    ]
                )

    def test_build_profiles_contain_no_execution_environment_facts(self) -> None:
        profile_fields = {
            field.name for field in fields(next(iter(build.PLATFORM_PROFILES.values())))
        }
        self.assertEqual(
            profile_fields,
            {
                "numeric_id",
                "identifier",
                "architecture",
                "firmware_discovery",
                "target",
                "kernel_feature",
                "virtio_transport",
            },
        )
        self.assertFalse(hasattr(build, "RUNNER_PROFILES"))

    def test_cargo_argv_uses_exact_platform_feature(self) -> None:
        for profile in build.PLATFORM_PROFILES.values():
            with self.subTest(platform=profile.identifier, acceptance=False):
                self.assertEqual(
                    build.cargo_build_command(profile, acceptance_probes=False),
                    (
                        "cargo",
                        "build",
                        "--locked",
                        "-p",
                        "troe-kernel",
                        "--release",
                        "--target",
                        profile.target,
                        "--features",
                        profile.kernel_feature,
                    ),
                )
            with self.subTest(platform=profile.identifier, acceptance=True):
                self.assertEqual(
                    build.cargo_build_command(profile, acceptance_probes=True),
                    (
                        "cargo",
                        "build",
                        "--locked",
                        "-p",
                        "troe-kernel",
                        "--release",
                        "--target",
                        profile.target,
                        "--features",
                        f"{profile.kernel_feature},acceptance-probes",
                    ),
                )

    def test_verification_target_gates_combine_platform_and_acceptance(self) -> None:
        expected = [
            (
                "cargo",
                "clippy",
                "-p",
                "troe-kernel",
                "--target",
                profile.target,
                "--features",
                f"{profile.kernel_feature},acceptance-probes",
                "--",
                "-D",
                "warnings",
            )
            for profile in build.PLATFORM_PROFILES.values()
        ]
        self.assertEqual(verification.target_clippy_commands(), expected)

    def test_full_gate_has_only_one_owner_for_both_image_variants(self) -> None:
        without_qemu = verification.image_and_qemu_commands(skip_qemu=True)
        with_qemu = verification.image_and_qemu_commands(skip_qemu=False)
        self.assertEqual(len(without_qemu), 1)
        self.assertIn("--all-variants", without_qemu[0])
        self.assertEqual(len(with_qemu), 1)
        self.assertIn("test-qemu.py", str(with_qemu[0][1]))
        self.assertNotIn("build.py", str(with_qemu[0][1]))
        strict_without_qemu = verification.image_and_qemu_commands(
            skip_qemu=True, strict_tool_versions=True
        )
        strict_with_qemu = verification.image_and_qemu_commands(
            skip_qemu=False, strict_tool_versions=True
        )
        self.assertIn("--strict-tool-versions", strict_without_qemu[0])
        self.assertIn("--strict-tool-versions", strict_with_qemu[0])

    def test_rootfs_image_is_selected_only_by_architecture(self) -> None:
        for architecture in ("x86_64", "aarch64"):
            self.assertEqual(
                build.rootfs_image_path(architecture),
                build.REPO_ROOT / "assets" / f"root-{architecture}.kefs",
            )


if __name__ == "__main__":
    unittest.main()

"""Hosted checks for the repo-local KEX application builder."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import kex


class KexToolTests(unittest.TestCase):
    """Keep application identity, target commands, and installed bytes stable."""

    def test_example_manifest_and_build_commands_are_exact(self) -> None:
        manifest = kex.read_manifest(kex.REPO_ROOT / "apps" / "echo")
        self.assertEqual(manifest.package, "troe-app-echo")
        self.assertEqual(manifest.binary, "troe-app-echo")
        self.assertEqual(manifest.command, "echo")
        for target, triple in kex.TARGETS.items():
            command = kex.cargo_command(manifest, target)
            self.assertEqual(command[:3], ("cargo", "build", "--locked"))
            self.assertEqual(command[-2:], ("--target", triple))

    def test_installed_example_artifacts_are_canonical_for_each_target(self) -> None:
        for command in ("echo", "udp"):
            for target in kex.TARGETS:
                with self.subTest(command=command, target=target):
                    report = kex.inspect(
                        kex.REPO_ROOT / "rootfs" / "bin" / target / f"{command}.kex"
                    )
                    self.assertEqual(report["format"], "KEX v1")
                    self.assertEqual(report["abi"], "1.0")
                    self.assertEqual(report["target"], target)
                    self.assertEqual(report["stack_pages"], 4)
                    self.assertEqual(report["heap_pages"], 0)

    def test_inspection_rejects_corruption_and_command_names_are_narrow(self) -> None:
        artifact = kex.REPO_ROOT / "rootfs" / "bin" / "x86_64" / "echo.kex"
        original = artifact.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            corrupt = Path(directory) / "corrupt.kex"
            corrupt.write_bytes(original[:-1])
            with self.assertRaisesRegex(ValueError, "payload|length"):
                kex.inspect(corrupt)
        self.assertIsNotNone(kex.COMMAND_NAME.fullmatch("http-get_2"))
        for invalid in ("", "Echo", "../echo", "echo.kex", "écho"):
            self.assertIsNone(kex.COMMAND_NAME.fullmatch(invalid))


if __name__ == "__main__":
    unittest.main()

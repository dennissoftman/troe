"""Hosted checks for the canonical repo-local Rust KEX application tool."""

from __future__ import annotations

import json
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
KEX_APPLICATION_NAMES = tuple(
    sorted(
        path.name
        for path in (REPO_ROOT / "apps").iterdir()
        if path.is_dir() and (path / "Cargo.toml").is_file()
    )
)


def cargo_kex(*arguments: object) -> subprocess.CompletedProcess[bytes]:
    """Run the repository's canonical Cargo alias without a shell."""
    return subprocess.run(
        ("cargo", "kex", *(str(argument) for argument in arguments)),
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
    )


class KexToolTests(unittest.TestCase):
    """Keep canonical build, inspection, and installed bytes stable."""

    def test_installed_example_artifacts_are_canonical_for_each_target(self) -> None:
        for command in KEX_APPLICATION_NAMES:
            for target in ("x86_64", "aarch64"):
                with self.subTest(command=command, target=target):
                    artifact = REPO_ROOT / "rootfs" / "bin" / target / f"{command}.kex"
                    inspected = cargo_kex("inspect", artifact, "--json")
                    self.assertEqual(inspected.returncode, 0, inspected.stderr.decode())
                    report = json.loads(inspected.stdout)
                    self.assertEqual(report["format"], "KEX v1")
                    self.assertEqual(report["abi"], "1.0")
                    self.assertEqual(report["target"], target)
                    self.assertEqual(report["stack_pages"], 4)
                    self.assertEqual(report["heap_pages"], 0)
                    capability_path = artifact.with_suffix(".kcap")
                    capability_bytes = capability_path.read_bytes()
                    self.assertEqual(capability_bytes[:8], b"KCAPv1\0\0")
                    count, reserved, encoded_bytes = struct.unpack_from(
                        "<HHI", capability_bytes, 8
                    )
                    self.assertEqual(reserved, 0)
                    self.assertEqual(encoded_bytes, len(capability_bytes))
                    records = [
                        struct.unpack_from("<IHH", capability_bytes, 16 + index * 8)
                        for index in range(count)
                    ]
                    expected = [(5, 1, 0)] if command == "udp" else []
                    self.assertEqual(records, expected)

    def test_build_check_uses_pinned_app_contract(self) -> None:
        checked = cargo_kex(
            "build", "apps/echo", "--target", "x86_64", "--check"
        )
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        self.assertIn(b"KEX app verified", checked.stdout)

    def test_inspection_rejects_corruption_and_command_names_are_narrow(self) -> None:
        artifact = REPO_ROOT / "rootfs" / "bin" / "x86_64" / "echo.kex"
        with tempfile.TemporaryDirectory() as directory:
            corrupt = Path(directory) / "corrupt.kex"
            corrupt.write_bytes(artifact.read_bytes()[:-1])
            inspected = cargo_kex("inspect", corrupt)
            self.assertNotEqual(inspected.returncode, 0)
            self.assertIn(b"invalid KEX artifact", inspected.stderr)
        for invalid in ("", "Echo", "../echo", "echo.kex", "écho"):
            with self.subTest(name=invalid):
                rejected = cargo_kex(
                    "build",
                    "apps/echo",
                    "--name",
                    invalid,
                    "--target",
                    "x86_64",
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(b"command name", rejected.stderr)


if __name__ == "__main__":
    unittest.main()

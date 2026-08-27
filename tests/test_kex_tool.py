"""Hosted checks for the canonical repo-local Rust KEX application tool."""

from __future__ import annotations

import json
import os
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
KEX_TOOL = Path(os.environ.get("CARGO_TARGET_DIR", REPO_ROOT / "target"))
if not KEX_TOOL.is_absolute():
    KEX_TOOL = REPO_ROOT / KEX_TOOL
KEX_TOOL = (
    KEX_TOOL / "debug" / ("troe-kex-tool.exe" if os.name == "nt" else "troe-kex-tool")
)


def cargo_kex(*arguments: object) -> subprocess.CompletedProcess[bytes]:
    """Run the already-built canonical CLI without one Cargo process per case."""
    return subprocess.run(
        (KEX_TOOL, *(str(argument) for argument in arguments)),
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
    )


class KexToolTests(unittest.TestCase):
    """Keep canonical build, inspection, and installed bytes stable."""

    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ("cargo", "build", "--quiet", "--package", "troe-kex-tool"),
            cwd=REPO_ROOT,
            check=True,
        )

    def test_installed_example_artifacts_are_canonical_for_each_target(self) -> None:
        for command in KEX_APPLICATION_NAMES:
            for target in ("x86_64", "aarch64"):
                with self.subTest(command=command, target=target):
                    artifact = REPO_ROOT / "rootfs" / "bin" / target / f"{command}.kex"
                    inspected = cargo_kex("inspect", artifact, "--json")
                    self.assertEqual(inspected.returncode, 0, inspected.stderr.decode())
                    report = json.loads(inspected.stdout)
                    self.assertEqual(report["format"], "KEX package v1")
                    self.assertEqual(report["executable_format"], "KEX v1")
                    self.assertEqual(report["abi"], "1.1")
                    self.assertEqual(report["target"], target)
                    expected_stack_pages = (
                        64
                        if command == "lua"
                        else 12
                        if command == "tar"
                        else 20
                        if command in {"awk", "grep", "sed"}
                        else 4
                    )
                    self.assertEqual(report["stack_pages"], expected_stack_pages)
                    self.assertEqual(
                        report["heap_pages"], 256 if command == "lua" else 0
                    )
                    package_bytes = artifact.read_bytes()
                    self.assertEqual(package_bytes[:8], b"KEXPKG\0\0")
                    (
                        major,
                        minor,
                        header_bytes,
                        flags,
                        capability_offset,
                        capability_bytes,
                        executable_offset,
                        reserved,
                        executable_bytes,
                        encoded_bytes,
                    ) = struct.unpack_from("<HHHHIIIIQQ", package_bytes, 8)
                    self.assertEqual((major, minor, header_bytes, flags), (1, 0, 48, 0))
                    self.assertEqual(capability_offset, header_bytes)
                    self.assertEqual(
                        executable_offset, capability_offset + capability_bytes
                    )
                    self.assertEqual(reserved, 0)
                    self.assertEqual(
                        executable_offset + executable_bytes, len(package_bytes)
                    )
                    self.assertEqual(encoded_bytes, len(package_bytes))
                    self.assertEqual(report["bytes"], len(package_bytes))
                    self.assertEqual(report["executable_bytes"], executable_bytes)
                    capability_bytes = package_bytes[
                        capability_offset:executable_offset
                    ]
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
                    if command == "udp":
                        expected = [(5, 1, 0)]
                    elif command == "tar":
                        expected = [(6, 1, 2), (7, 2, 0)]
                    elif command in {
                        "awk",
                        "cat",
                        "grep",
                        "hexdump",
                        "ls",
                        "man",
                        "sed",
                        "wc",
                    }:
                        expected = [(6, 1, 2)]
                    elif command == "lua":
                        expected = [(6, 1, 2), (8, 1, 0)]
                    elif command in {"ln", "rm"}:
                        expected = [(7, 2, 0)]
                    elif command == "sleep":
                        expected = [(8, 1, 0)]
                    elif command == "timesync":
                        expected = [(5, 1, 0), (8, 1, 0), (18, 1, 0)]
                    elif command == "mem":
                        expected = [(9, 1, 0)]
                    elif command == "ps":
                        expected = [(19, 1, 0)]
                    elif command == "top":
                        expected = [(8, 1, 0), (19, 1, 0)]
                    elif command in {"arp", "net"}:
                        expected = [(10, 1, 0)]
                    elif command == "dhcp":
                        expected = [(11, 1, 0)]
                    elif command == "ping":
                        expected = [(12, 1, 0)]
                    elif command == "tcp":
                        expected = [(13, 1, 0)]
                    elif command == "mount":
                        expected = [(14, 1, 0)]
                    elif command == "sh":
                        expected = [(6, 1, 2), (16, 1, 0)]
                    else:
                        expected = []
                    self.assertEqual(records, expected)
                    self.assertEqual(report["requirements"], len(expected))
                    self.assertFalse(artifact.with_suffix(".kcap").exists())

    def test_build_check_uses_pinned_app_contract(self) -> None:
        checked = cargo_kex("build", "apps/echo", "--target", "x86_64", "--check")
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        self.assertIn(b"KEX package verified", checked.stdout)
        self.assertNotIn(
            os.fsencode(REPO_ROOT),
            (REPO_ROOT / "rootfs/bin/x86_64/echo.kex").read_bytes(),
        )

    def test_inspection_rejects_corruption_and_command_names_are_narrow(self) -> None:
        artifact = REPO_ROOT / "rootfs" / "bin" / "x86_64" / "echo.kex"
        with tempfile.TemporaryDirectory() as directory:
            package_bytes = artifact.read_bytes()
            executable_offset = struct.unpack_from("<I", package_bytes, 24)[0]
            raw = Path(directory) / "raw.kex"
            raw.write_bytes(package_bytes[executable_offset:])
            raw_inspection = cargo_kex("inspect", raw, "--json")
            self.assertEqual(
                raw_inspection.returncode, 0, raw_inspection.stderr.decode()
            )
            raw_report = json.loads(raw_inspection.stdout)
            self.assertEqual(raw_report["format"], "KEX v1")
            self.assertEqual(raw_report["requirements"], 0)

            corrupt = Path(directory) / "corrupt.kex"
            corrupt.write_bytes(package_bytes[:-1])
            inspected = cargo_kex("inspect", corrupt)
            self.assertNotEqual(inspected.returncode, 0)
            self.assertIn(b"invalid KEX package", inspected.stderr)
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

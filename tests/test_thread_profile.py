"""Compiler qualification must fail closed and resist ambient driver inputs."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts import test_changed  # noqa: E402
from tools import thread_profile  # noqa: E402


class ThreadProfileTests(unittest.TestCase):
    """Exercise real compiler commands and atomic qualification publication."""

    def test_missing_or_skipped_probes_cannot_qualify(self) -> None:
        with (
            patch("sys.stderr", new_callable=io.StringIO),
            patch.object(
                unittest.defaultTestLoader,
                "loadTestsFromName",
                return_value=unittest.TestSuite(),
            ),
        ):
            self.assertNotEqual(thread_profile.run_probes(), 0)

        def unavailable(_: unittest.TestCase) -> None:
            pass

        skipped = type(
            "SkippedQualification",
            (unittest.TestCase,),
            {
                name: unittest.skip("compiler unavailable")(unavailable)
                for name in thread_profile.REQUIRED_PROBES
            },
        )
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(skipped)
        with (
            patch("sys.stderr", new_callable=io.StringIO),
            patch.object(
                unittest.defaultTestLoader, "loadTestsFromName", return_value=suite
            ),
        ):
            self.assertNotEqual(thread_profile.run_probes(), 0)

    def test_recipe_and_pin_select_compiler_and_rejection_checks(self) -> None:
        for path in (
            "tools/thread_profile.py",
            "sdk/c/thread-profile-v1.json",
            "sdk/c/thread-profile-v1.ld",
        ):
            plan = test_changed.build_plan([PurePosixPath(path)], {})
            self.assertFalse(plan.full_reasons)
            self.assertFalse(plan.qemu_scenarios)
            self.assertEqual(
                plan.python_tests, {"test_kex_tool.py", "test_thread_profile.py"}
            )

    def test_ambient_header_and_driver_injection_cannot_change_probe(self) -> None:
        source = """
#include <stdint.h>
#include <troe/runtime.h>
void _start(void) {}
void __troe_thread_start_v1(const void *p, unsigned long n) {}
"""
        with tempfile.TemporaryDirectory(prefix="troe-profile-env-") as directory:
            root = Path(directory)
            injected = root / "injected"
            injected.mkdir()
            (injected / "stdint.h").write_text("#error ambient header selected\n")
            clean = root / "clean"
            clean.mkdir()
            dirty = root / "dirty"
            dirty.mkdir()
            cc = os.environ.get("TROE_TLS_CC", "clang")
            linker = os.environ.get("TROE_TLS_LD", "ld.lld")
            first = thread_profile.compile_probe(clean, "x86_64", source, cc, linker)
            with patch.dict(
                os.environ,
                {
                    "CPATH": str(injected),
                    "C_INCLUDE_PATH": str(injected),
                    "CCC_OVERRIDE_OPTIONS": "+-D__STDC_HOSTED__=1",
                    "SOURCE_DATE_EPOCH": "123456789",
                },
            ):
                second = thread_profile.compile_probe(
                    dirty, "x86_64", source, cc, linker
                )
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_wrong_tool_does_not_replace_prior_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-profile-reject-") as directory:
            output = Path(directory) / "report.json"
            output.write_text("prior evidence\n")
            result = subprocess.run(
                [
                    sys.executable,
                    REPO_ROOT / "tools/thread_profile.py",
                    "--cc",
                    sys.executable,
                    "--output",
                    output,
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"requires clang", result.stderr)
            self.assertEqual(output.read_text(), "prior evidence\n")
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_qualification_binds_both_tools_and_does_not_grant_admission(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-profile-qualify-") as directory:
            output = Path(directory) / "report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    REPO_ROOT / "tools/thread_profile.py",
                    "--compatible-tools",
                    "--output",
                    output,
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            report = json.loads(output.read_text())
            self.assertTrue(report["checks_passed"])
            self.assertTrue(report["qualification_only"])
            self.assertFalse(report["native_admission"])
            for tool in ("clang", "lld"):
                self.assertEqual(len(report["inputs"][tool]["sha256"]), 64)
            self.assertEqual(
                report["inputs"]["profile_sha256"],
                thread_profile.file_digest(thread_profile.PROFILE_FILE),
            )
            self.assertEqual(list(output.parent.iterdir()), [output])


if __name__ == "__main__":
    unittest.main()

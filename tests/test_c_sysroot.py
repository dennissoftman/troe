"""Cross-target regression tests for the reusable freestanding C sysroot."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class CSysrootTests(unittest.TestCase):
    """Require deterministic, architecture-correct SDK output."""

    @unittest.skipUnless(
        shutil.which("clang") and shutil.which("rustc"), "cross compiler unavailable"
    )
    def test_both_targets_build_deterministically_without_host_headers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-c-sysroot-") as temporary:
            output = Path(temporary) / "sysroot"
            subprocess.run(
                [
                    sys.executable,
                    REPO_ROOT / "tools" / "build_c_sysroot.py",
                    output,
                    "--check",
                ],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            expected_machines = {"x86_64": 62, "aarch64": 183}
            for architecture, machine in expected_machines.items():
                target = output / architecture
                archive = (target / "lib" / "libtroe_c.a").read_bytes()
                self.assertEqual(archive[:8], b"!<arch>\n")
                elf = archive.index(b"\x7fELF")
                self.assertEqual(
                    struct.unpack_from("<H", archive, elf + 18)[0], machine
                )
                metadata = json.loads((target / "TARGET.json").read_text())
                self.assertEqual(metadata["abi"], 1)
                self.assertEqual(metadata["architecture"], architecture)
                self.assertEqual(metadata["library"], "lib/libtroe_c.a")
                self.assertTrue((target / "include" / "troe" / "runtime.h").is_file())
                self.assertTrue((target / "include" / "sys" / "random.h").is_file())


if __name__ == "__main__":
    unittest.main()

"""Host-only tests for the QEMU TCG guest-work counting plugin."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER = REPO_ROOT / "tools" / "build_qemu_plugin.py"
SOURCE = REPO_ROOT / "tools" / "qemu-plugin" / "troe_count.c"


def qemu_headers_available() -> bool:
    """Report whether any searched prefix provides the QEMU plugin header."""
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    try:
        import build_qemu_plugin  # type: ignore[import-not-found]

        build_qemu_plugin.find_qemu_include(None)
    except (ImportError, RuntimeError):
        return False
    finally:
        sys.path.pop(0)
    return True


class QemuPluginTests(unittest.TestCase):
    """Require a warning-free build that exports the QEMU plugin contract."""

    def test_source_is_licensed_apart_from_the_repository(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("SPDX-License-Identifier: GPL-2.0-or-later", text)

    @unittest.skipUnless(
        shutil.which("clang") and shutil.which("pkg-config") and qemu_headers_available(),
        "QEMU plugin headers or host compiler unavailable",
    )
    def test_builds_without_warnings_and_exports_the_plugin_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-qemu-plugin-") as temporary:
            output = Path(temporary) / "troe_count.so"
            subprocess.run(
                [sys.executable, str(BUILDER), str(output)],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue(output.is_file())
            symbols = subprocess.run(
                ["nm", "-g", str(output)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            for symbol in ("qemu_plugin_install", "qemu_plugin_version"):
                self.assertIn(symbol, symbols)


if __name__ == "__main__":
    unittest.main()

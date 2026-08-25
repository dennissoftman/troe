"""Focused tests for the pinned RustSec audit command."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import audit  # noqa: E402


class AuditPolicyTests(unittest.TestCase):
    """The dependency gate rejects tool drift and never fetches implicitly."""

    def test_exact_cargo_audit_version_is_required(self) -> None:
        with mock.patch.object(audit, "run", return_value="cargo-audit 0.22.1"):
            audit.verify_tool_version()
        with mock.patch.object(audit, "run", return_value="cargo-audit 0.22.0"):
            with self.assertRaisesRegex(RuntimeError, "expected cargo-audit 0.22.1"):
                audit.verify_tool_version()

    def test_audit_command_is_no_fetch_deny_warnings_and_documented_ignores(self) -> None:
        command = audit.audit_command(("RUSTSEC-2026-0001",))
        self.assertIn("--no-fetch", command)
        self.assertEqual(command[command.index("--deny") + 1], "warnings")
        self.assertEqual(
            command[command.index("--ignore") + 1],
            "RUSTSEC-2026-0001",
        )
        self.assertNotIn("--ignore", audit.audit_command(()))


if __name__ == "__main__":
    unittest.main()

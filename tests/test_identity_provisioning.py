"""Tests for deployment identity provisioning and fixture separation."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

from mkcontent import (  # noqa: E402
    DOMAIN_ID,
    GROUP_ID,
    USER_ID,
    IdentityIds,
    load_deployment_identities,
)
from mkidentity import encode_identities, generate_identities  # noqa: E402


class IdentityProvisioningTests(unittest.TestCase):
    """Deployment IDs come from the supplied CSPRNG and reject fixture values."""

    def test_generation_retries_zero_reserved_and_collisions(self) -> None:
        values = iter(
            (
                bytes(16),
                USER_ID,
                bytes.fromhex("10" * 16),
                bytes.fromhex("10" * 16),
                bytes.fromhex("20" * 16),
                bytes.fromhex("30" * 16),
            )
        )
        identities = generate_identities(lambda _length: next(values))
        self.assertEqual(
            identities,
            IdentityIds(
                bytes.fromhex("10" * 16),
                bytes.fromhex("20" * 16),
                bytes.fromhex("30" * 16),
            ),
        )

    def test_canonical_file_round_trips(self) -> None:
        identities = IdentityIds(
            bytes.fromhex("10" * 16),
            bytes.fromhex("20" * 16),
            bytes.fromhex("30" * 16),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            path.write_text(encode_identities(identities), encoding="utf-8")
            self.assertEqual(load_deployment_identities(path), identities)

    def test_deployment_mode_rejects_every_reserved_fixture_id(self) -> None:
        base = {
            "schema": 1,
            "user_id": (bytes.fromhex("10" * 16)).hex(),
            "group_id": (bytes.fromhex("20" * 16)).hex(),
            "domain_id": (bytes.fromhex("30" * 16)).hex(),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            for field, reserved in (
                ("user_id", USER_ID),
                ("group_id", GROUP_ID),
                ("domain_id", DOMAIN_ID),
            ):
                document = dict(base)
                document[field] = reserved.hex()
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "reserved"):
                    load_deployment_identities(path)

    def test_provisioner_creates_owner_only_file_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            command = (
                sys.executable,
                str(REPO_ROOT / "tools" / "mkidentity.py"),
                "--output",
                str(path),
            )
            first = subprocess.run(
                command,
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
            )
            self.assertEqual(first.returncode, 0)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            identities = load_deployment_identities(path)
            original = path.read_bytes()

            second = subprocess.run(
                command,
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
            )
            self.assertEqual(second.returncode, 2)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(load_deployment_identities(path), identities)


if __name__ == "__main__":
    unittest.main()

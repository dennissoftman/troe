"""Regression tests for the pinned Alpine comparison launcher."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import alpine_profile
from scripts.qemu_profile import RUNNER_PROFILES


class AlpineProfileTests(unittest.TestCase):
    """The Alpine image and matched-machine policy fail closed."""

    def test_manifest_is_canonical_complete_and_pinned(self) -> None:
        profile = alpine_profile.alpine_profile()
        self.assertEqual(profile.version, "3.24.1")
        self.assertEqual(set(profile.artifacts), {"x86_64", "aarch64"})
        encoded = (
            json.dumps(
                json.loads(
                    alpine_profile.ALPINE_PROFILE_PATH.read_text(encoding="utf-8")
                ),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        self.assertEqual(
            alpine_profile.ALPINE_PROFILE_PATH.read_text(encoding="utf-8"), encoded
        )

    def test_install_help_is_available_without_launching_qemu(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(alpine_profile.REPO_ROOT / "scripts" / "run-alpine.py"),
                "--platform",
                "aarch64-virt-uefi",
                "--environment",
                "qemu",
                "--gui",
                "--install-help",
            ],
            cwd=alpine_profile.REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("setup-alpine", result.stdout)
        self.assertIn("virtio-ALPINE_ROOT", result.stdout)
        self.assertIn("apk add lua5.5", result.stdout)
        self.assertIn("TROE\\x20SHARE", result.stdout)
        self.assertIn("--reset-root-disk", result.stdout)

    def test_invalid_manifest_shape_and_artifact_name_are_rejected(self) -> None:
        original = json.loads(
            alpine_profile.ALPINE_PROFILE_PATH.read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory(prefix="troe-alpine-profile-") as temporary:
            path = Path(temporary) / "profile.json"
            malformed = dict(original)
            malformed["extra"] = True
            path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "invalid Alpine profile"):
                alpine_profile.alpine_profile(path)

            original["artifacts"]["aarch64"]["filename"] = "../untrusted.iso"
            path.write_text(json.dumps(original), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "invalid Alpine aarch64"):
                alpine_profile.alpine_profile(path)

    def test_image_verifier_rejects_wrong_size_and_digest(self) -> None:
        payload = b"pinned Alpine image"
        artifact = alpine_profile.AlpineArtifact(
            architecture="x86_64",
            filename="alpine.iso",
            bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        with tempfile.TemporaryDirectory(prefix="troe-alpine-image-") as temporary:
            image = Path(temporary) / artifact.filename
            image.write_bytes(payload)
            alpine_profile.verify_alpine_image(image, artifact)

            image.write_bytes(payload + b"!")
            with self.assertRaisesRegex(RuntimeError, "size mismatch"):
                alpine_profile.verify_alpine_image(image, artifact)
            image.write_bytes(payload[:-1] + b"!")
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                alpine_profile.verify_alpine_image(image, artifact)

    def test_acquisition_downloads_atomically_and_reuses_verified_cache(self) -> None:
        payload = b"downloaded image"
        artifact = alpine_profile.AlpineArtifact(
            architecture="x86_64",
            filename="alpine.iso",
            bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        profile = alpine_profile.AlpineProfile(
            version="1.2.3",
            base_url="https://example.invalid/releases",
            artifacts={"x86_64": artifact},
        )
        with tempfile.TemporaryDirectory(prefix="troe-alpine-cache-") as temporary:
            cache = Path(temporary)
            downloader = mock.Mock(
                side_effect=lambda _url, destination: destination.write_bytes(payload)
            )
            with mock.patch.object(alpine_profile, "ALPINE_CACHE_DIR", cache):
                image = alpine_profile.acquire_alpine_image(
                    profile, "x86_64", downloader=downloader
                )
                self.assertEqual(image.read_bytes(), payload)
                self.assertEqual(downloader.call_count, 1)
                self.assertEqual(
                    alpine_profile.acquire_alpine_image(
                        profile, "x86_64", downloader=downloader
                    ),
                    image,
                )
                self.assertEqual(downloader.call_count, 1)

                image.write_bytes(b"corrupt")
                with self.assertRaisesRegex(RuntimeError, "pass --refresh"):
                    alpine_profile.acquire_alpine_image(
                        profile, "x86_64", downloader=downloader
                    )

    def test_root_image_is_sparse_preserved_and_reset_explicitly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-alpine-root-") as temporary:
            root = Path(temporary) / "root.raw"
            self.assertTrue(alpine_profile.ensure_alpine_root_image(root))
            self.assertEqual(root.stat().st_size, alpine_profile.ALPINE_ROOT_DISK_BYTES)
            self.assertTrue(alpine_profile.alpine_root_needs_install(root))
            root.write_bytes(b"installed")
            self.assertFalse(alpine_profile.alpine_root_needs_install(root))
            with self.assertRaisesRegex(RuntimeError, "--reset-root-disk"):
                alpine_profile.ensure_alpine_root_image(root)
            self.assertTrue(
                alpine_profile.ensure_alpine_root_image(root, reset=True)
            )
            self.assertEqual(root.stat().st_size, alpine_profile.ALPINE_ROOT_DISK_BYTES)

    def test_uefi_variables_are_preserved_until_reset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-alpine-vars-") as temporary:
            directory = Path(temporary)
            source = directory / "template.fd"
            destination = directory / "persistent.fd"
            source.write_bytes(b"template")
            alpine_profile.ensure_alpine_variables(source, destination)
            destination.write_bytes(b"changed!")
            alpine_profile.ensure_alpine_variables(source, destination)
            self.assertEqual(destination.read_bytes(), b"changed!")
            alpine_profile.ensure_alpine_variables(source, destination, reset=True)
            self.assertEqual(destination.read_bytes(), b"template")

    def test_qemu_arguments_match_troe_resources_and_attach_shared_disk(self) -> None:
        runner = RUNNER_PROFILES[("aarch64-virt-uefi", "qemu")]
        command = alpine_profile._alpine_qemu_arguments(
            runner,
            "/usr/bin/qemu-system-aarch64",
            Path("/firmware-code.fd"),
            Path("/firmware-vars.fd"),
            Path("/alpine.iso"),
            Path("/alpine-root.raw"),
            Path("/troe-shared.img"),
            graphical=False,
            memory="256M",
        )
        self.assertEqual(command[command.index("-machine") + 1], runner.machine)
        self.assertEqual(command[command.index("-cpu") + 1], runner.cpu)
        self.assertEqual(command[command.index("-smp") + 1], "1")
        self.assertEqual(command[command.index("-m") + 1], "256M")
        self.assertIn("id=alpine-boot", " ".join(command))
        self.assertIn("id=alpine-root", " ".join(command))
        self.assertIn("id=alpine-shared", " ".join(command))
        self.assertTrue(
            any("drive=alpine-root" in argument and "bootindex=1" in argument for argument in command)
        )
        self.assertTrue(
            any(argument.endswith("drive=alpine-boot,bootindex=2") for argument in command)
        )
        self.assertIn("serial=ALPINE_ROOT", " ".join(command))
        self.assertIn("serial=TROE_SHARED", " ".join(command))
        self.assertIn("-display", command)

    def test_graphical_mode_only_changes_display_policy(self) -> None:
        runner = RUNNER_PROFILES[("x86_64-q35-uefi", "qemu")]
        command = alpine_profile._alpine_qemu_arguments(
            runner,
            "qemu-system-x86_64",
            Path("code.fd"),
            Path("vars.fd"),
            Path("alpine.iso"),
            None,
            None,
            graphical=True,
            memory="256M",
        )
        self.assertNotIn("-display", command)
        self.assertNotIn("id=alpine-root", " ".join(command))
        self.assertNotIn("id=alpine-shared", " ".join(command))
        self.assertTrue(
            any(argument.endswith("drive=alpine-boot,bootindex=1") for argument in command)
        )


if __name__ == "__main__":
    unittest.main()

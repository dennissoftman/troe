"""Regression tests for versioned shared runtime-artifact trees."""

from __future__ import annotations

import tempfile
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from tools import mkruntime


class RuntimeTreeTests(unittest.TestCase):
    """Keep runtime trees deterministic, exact, and outside boot artifacts."""

    def test_artifact_ceiling_matches_the_complete_package_contract(self) -> None:
        self.assertEqual(
            mkruntime.MAX_ARTIFACT_BYTES,
            48 + (16 + 128 * 8) + 32 * 1024 * 1024 + 16 * 1024,
        )

    def _artifacts(self, root: Path) -> list[mkruntime.Artifact]:
        x86 = root / "probe-x86_64.kex"
        arm = root / "probe-aarch64.kex"
        x86.write_bytes(b"x86 package")
        arm.write_bytes(b"arm package")
        return mkruntime.collect_artifacts(
            [f"x86_64:runtime-probe={x86}", f"aarch64:runtime-probe={arm}"]
        )

    def test_build_is_deterministic_and_versioned_by_architecture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-runtime-") as temporary:
            root = Path(temporary)
            artifacts = self._artifacts(root)
            first = root / "first"
            second = root / "second"
            mkruntime.build_tree(first, artifacts)
            mkruntime.build_tree(second, list(reversed(artifacts)))
            mkruntime.verify_tree(first)
            mkruntime.verify_tree(second)
            self.assertEqual(
                (first / mkruntime.MANIFEST_NAME).read_bytes(),
                (second / mkruntime.MANIFEST_NAME).read_bytes(),
            )
            for architecture in mkruntime.ARCHITECTURES:
                self.assertTrue(
                    (first / architecture / "runtime-probe.kex").is_file()
                )
            self.assertEqual(
                mkruntime.RUNTIME_DIRECTORY.as_posix(), "bin"
            )

    def test_verifier_rejects_tampering_and_unmanifested_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-runtime-") as temporary:
            root = Path(temporary)
            tree = root / "tree"
            mkruntime.build_tree(tree, self._artifacts(root))
            artifact = tree / "x86_64" / "runtime-probe.kex"
            artifact.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "verification failed"):
                mkruntime.verify_tree(tree)
            mkruntime.build_tree(tree, self._artifacts(root))
            (tree / "extra").write_bytes(b"ambient")
            with self.assertRaisesRegex(ValueError, "unmanifested"):
                mkruntime.verify_tree(tree)

    def test_install_requires_present_media_and_verifies_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-runtime-") as temporary:
            root = Path(temporary)
            tree = root / "tree"
            mkruntime.build_tree(tree, self._artifacts(root))
            missing = root / "missing-shared-media"
            with self.assertRaisesRegex(ValueError, "media is unavailable"):
                mkruntime.install_tree(tree, missing)
            shared = root / "shared"
            shared.mkdir()
            destination = mkruntime.install_tree(tree, shared)
            self.assertEqual(destination, shared / "bin")
            mkruntime.verify_tree(destination)

    def test_provisioning_refuses_to_build_the_cpython_interpreter(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-runtime-") as temporary:
            image = Path(temporary) / "shared.img"
            with self.assertRaisesRegex(ValueError, "--cpython-package"):
                mkruntime.provision_image(image, ["python"], None, False)
            self.assertFalse(image.exists())

    def test_invalid_or_duplicate_artifact_specs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-runtime-") as temporary:
            root = Path(temporary)
            artifact = root / "probe.kex"
            artifact.write_bytes(b"package")
            with self.assertRaisesRegex(ValueError, "ARCH:NAME=PATH"):
                mkruntime.collect_artifacts([f"unknown:probe={artifact}"])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                mkruntime.collect_artifacts(
                    [f"x86_64:probe={artifact}", f"x86_64:probe={artifact}"]
                )

    @unittest.skipUnless(
        shutil.which("mcopy") and shutil.which("mmd") and shutil.which("mdir"),
        "mtools unavailable",
    )
    def test_detached_shared_image_install_is_verified(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-runtime-image-") as temporary:
            root = Path(temporary)
            tree = root / "tree"
            mkruntime.build_tree(tree, self._artifacts(root))
            image = root / "shared.img"
            subprocess.run(
                [
                    sys.executable,
                    Path(mkruntime.__file__).with_name("mkshared.py"),
                    "--output",
                    image,
                    "--reset",
                ],
                check=True,
                capture_output=True,
            )
            mkruntime.install_image(tree, image)
            mkruntime.verify_image(tree, image)
            with self.assertRaisesRegex(ValueError, "already contains"):
                mkruntime.install_image(tree, image)


if __name__ == "__main__":
    unittest.main()

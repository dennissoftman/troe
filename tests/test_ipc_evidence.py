"""A rejected native IPC boot keeps its raw evidence without passing the gate."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.test_ipc_phase_b import transcript as phase_b
from tests.test_ipc_phase_c import transcript as phase_c
from tests.test_qemu_profile import TEST_QEMU


class IpcEvidenceTests(unittest.TestCase):
    def test_failed_ratios_and_structural_failures_retain_raw_boots(self) -> None:
        phase_b_failure = phase_b(direct_ticks=910, compatibility_ticks=1000)
        phase_b_failure += "\n" + "\n".join(
            line for line in phase_c().splitlines() if line.startswith("ipc-phase-c")
        )
        observations = (
            (phase_b_failure, "Phase B IPC: direct IPC p95 ratio failed"),
            (phase_c(ticks=901), "Phase C IPC: direct IPC p95 ratio failed"),
            (
                phase_c().replace(
                    "additional_lease_programs=0", "additional_lease_programs=1", 1
                ),
                "Phase B IPC: invalid IPC structural",
            ),
        )
        with tempfile.TemporaryDirectory(prefix="troe-ipc-evidence-") as directory:
            root = Path(directory)
            (root / "build").mkdir()
            image = root / "acceptance.img"
            image.write_bytes(b"exact acceptance image")
            retained = {}
            for transcript, error in observations:
                session = SimpleNamespace(
                    platform_id="aarch64-sbsa-ref",
                    command_line=["qemu-system-aarch64", "-machine", "sbsa-ref"],
                    require_tagged=True,
                    transcript=lambda transcript=transcript: transcript,
                )
                with (
                    mock.patch.object(TEST_QEMU, "REPO_ROOT", root),
                    mock.patch.object(TEST_QEMU, "boot_image_path", return_value=image),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.subTest(error=error),
                    self.assertRaisesRegex(TEST_QEMU.AcceptanceError, error),
                ):
                    TEST_QEMU.assert_ipc_baseline(session)
                paths = set((root / "build").glob("ipc-observation-*.json"))
                new_paths = paths - retained.keys()
                self.assertEqual(len(new_paths), 1)
                path = new_paths.pop()
                data = json.loads(path.read_text())
                self.assertEqual(data["kind"], "unvalidated-native-ipc-observation")
                self.assertEqual(data["transcript"], transcript + "\n")
                self.assertEqual(data["command"], session.command_line)
                self.assertTrue(data["require_tagged"])
                self.assertEqual(
                    data["image_sha256"], hashlib.sha256(image.read_bytes()).hexdigest()
                )
                self.assertNotIn("passed", data)
                for previous, contents in retained.items():
                    self.assertEqual(previous.read_bytes(), contents)
                retained[path] = path.read_bytes()

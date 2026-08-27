"""Regression tests for the host shared-media mount lifecycle."""

from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import mount_shared


class SharedMediaMountTests(unittest.TestCase):
    """Keep host attachment dispatch bounded, exact, and fail-closed."""

    def state(
        self,
        image: Path,
        device: Path,
        mount_point: Path,
        *,
        read_only: bool = False,
    ) -> mount_shared.MountState:
        return mount_shared.MountState(
            schema=mount_shared.STATE_SCHEMA,
            image=str(image.resolve()),
            platform="test",
            backend="test",
            device=str(device),
            partition=f"{device}s1",
            mount_point=str(mount_point),
            read_only=read_only,
        )

    def test_state_round_trip_and_exact_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-mount-state-") as temporary:
            root = Path(temporary)
            state_path = root / "state.json"
            expected = self.state(root / "shared.img", root / "disk4", root / "volume")
            mount_shared.write_state(expected, state_path)
            self.assertEqual(mount_shared.load_state(state_path), expected)

            state_path.write_text('{"schema": 1, "extra": true}', encoding="utf-8")
            with self.assertRaisesRegex(mount_shared.MountError, "invalid shape"):
                mount_shared.load_state(state_path)

    def test_live_attachment_blocks_qemu_and_stale_state_is_reaped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-mount-state-") as temporary:
            root = Path(temporary)
            image = root / "shared.img"
            device = root / "disk4"
            mount_point = root / "volume"
            state_path = root / "state.json"
            image.touch()
            device.touch()
            mount_shared.write_state(
                self.state(image, device, mount_point), state_path
            )
            with self.assertRaisesRegex(mount_shared.MountError, "before QEMU"):
                mount_shared.require_detached(
                    image,
                    state_path,
                    platform="unsupported-test-host",
                )

            device.unlink()
            mount_shared.require_detached(
                image,
                state_path,
                platform="unsupported-test-host",
            )
            self.assertFalse(state_path.exists())

    def test_macos_plist_selects_whole_disk_partition_and_mount_point(self) -> None:
        image = Path("/tmp/shared.img")
        payload = plistlib.dumps(
            {
                "system-entities": [
                    {"dev-entry": "/dev/disk4"},
                    {
                        "dev-entry": "/dev/disk4s1",
                        "mount-point": "/Volumes/TROE SHARE",
                    },
                ]
            }
        )
        state = mount_shared.parse_macos_attach(payload, image, read_only=True)
        self.assertEqual(state.device, "/dev/disk4")
        self.assertEqual(state.partition, "/dev/disk4s1")
        self.assertEqual(state.mount_point, "/Volumes/TROE SHARE")
        self.assertTrue(state.read_only)

        with self.assertRaisesRegex(mount_shared.MountError, "mounted FAT32"):
            mount_shared.parse_macos_attach(
                plistlib.dumps({"system-entities": [{"dev-entry": "/dev/disk4"}]}),
                image,
                read_only=False,
            )

    def test_macos_parse_failure_detaches_the_provisional_disk(self) -> None:
        payload = plistlib.dumps(
            {"system-entities": [{"dev-entry": "/dev/disk9"}]}
        )
        attached = mount_shared.subprocess.CompletedProcess(
            args=(), returncode=0, stdout=payload, stderr=b""
        )
        with (
            mock.patch.object(mount_shared.shutil, "which", return_value="/usr/bin/hdiutil"),
            mock.patch.object(mount_shared, "_run", return_value=attached),
            mock.patch.object(mount_shared.subprocess, "run") as cleanup,
            self.assertRaisesRegex(mount_shared.MountError, "mounted FAT32"),
        ):
            mount_shared.mount_macos(Path("/tmp/shared.img"), read_only=False)
        cleanup.assert_called_once_with(
            ("/usr/bin/hdiutil", "detach", "/dev/disk9"),
            check=False,
            stdout=mount_shared.subprocess.DEVNULL,
            stderr=mount_shared.subprocess.DEVNULL,
        )

    def test_linux_parsers_do_not_depend_on_fixed_loop_number(self) -> None:
        self.assertEqual(
            mount_shared.parse_linux_loop(
                "Mapped file /work/shared.img as /dev/loop37.\n"
            ),
            "/dev/loop37",
        )
        with self.assertRaisesRegex(mount_shared.MountError, "loop device"):
            mount_shared.parse_linux_loop("no device allocated")
        self.assertEqual(
            mount_shared._decode_findmnt_path("/media/dev/TROE\\x20SHARE"),
            "/media/dev/TROE SHARE",
        )

    def test_linux_udisks_backend_owns_loop_mount_and_detach(self) -> None:
        loop = mount_shared.subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout="Mapped file /work/shared.img as /dev/loop37.\n",
            stderr="",
        )
        mounted = mount_shared.subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout="Mounted /dev/loop37p1 at /media/dev/TROE SHARE.\n",
            stderr="",
        )

        def executable(name: str) -> str | None:
            if name == "udisksctl":
                return "/usr/bin/udisksctl"
            return None

        with (
            mock.patch.object(mount_shared.shutil, "which", side_effect=executable),
            mock.patch.object(mount_shared, "_wait_for_path", return_value=True),
            mock.patch.object(mount_shared, "_run", side_effect=(loop, mounted)) as run,
        ):
            state = mount_shared._mount_linux_udisks(
                Path("/work/shared.img"), read_only=True
            )
        self.assertEqual(state.device, "/dev/loop37")
        self.assertEqual(state.partition, "/dev/loop37p1")
        self.assertEqual(state.mount_point, "/media/dev/TROE SHARE")
        self.assertTrue(state.read_only)
        self.assertEqual(run.call_args_list[0].args[0][-1], "--read-only")

        with (
            mock.patch.object(mount_shared.shutil, "which", side_effect=executable),
            mock.patch.object(mount_shared, "_run") as detach,
        ):
            mount_shared.unmount_image(state)
        self.assertEqual(detach.call_count, 2)
        self.assertIn("unmount", detach.call_args_list[0].args[0])
        self.assertIn("loop-delete", detach.call_args_list[1].args[0])

    def test_dispatch_supports_macos_and_linux_but_rejects_windows(self) -> None:
        image = Path("/tmp/shared.img")
        expected = self.state(image, Path("/dev/disk4"), Path("/Volumes/shared"))
        with mock.patch.object(
            mount_shared, "mount_macos", return_value=expected
        ) as macos:
            self.assertEqual(
                mount_shared.mount_image(image, read_only=False, platform="darwin"),
                expected,
            )
            macos.assert_called_once_with(image, read_only=False)

        with mock.patch.object(
            mount_shared, "mount_linux", return_value=expected
        ) as linux:
            self.assertEqual(
                mount_shared.mount_image(image, read_only=True, platform="linux"),
                expected,
            )
            linux.assert_called_once_with(image, read_only=True)

        with self.assertRaisesRegex(mount_shared.MountError, "macOS and Linux"):
            mount_shared.mount_image(image, read_only=False, platform="win32")

    @unittest.skipIf(mount_shared.os.name == "nt", "Unix lock semantics")
    def test_media_lock_rejects_a_concurrent_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-mount-lock-") as temporary:
            lock_path = Path(temporary) / "shared.lock"
            with mount_shared.SharedMediaLock(lock_path):
                with self.assertRaisesRegex(mount_shared.MountError, "busy"):
                    with mount_shared.SharedMediaLock(lock_path):
                        self.fail("a second owner acquired the shared-media lock")


if __name__ == "__main__":
    unittest.main()

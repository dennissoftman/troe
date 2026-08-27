"""Regression tests for the dependency-free KEFS and FAT16 image builders."""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools import mkefs, mkfat


class KefsBuilderTests(unittest.TestCase):
    """Exercise deterministic KEFS construction and independent decoding."""

    @staticmethod
    def make_tree(root: Path) -> None:
        """Create one small tree with directories, files, and an ignored sentinel."""
        (root / "etc").mkdir()
        (root / "empty").mkdir()
        (root / "etc" / "motd").write_bytes(b"hello\n")
        (root / "payload.bin").write_bytes(bytes(range(32)))
        (root / "empty" / mkefs.MOUNTPOINT_SENTINEL).write_bytes(b"")

    def test_double_build_and_independent_round_trip_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_tree(root)
            expected = mkefs.collect(root)
            first = mkefs.build(root)
            second = mkefs.build(root)

            self.assertEqual(first, second)
            self.assertEqual(mkefs.decode(first), expected)
            mkefs.verify_tree(first, expected)

    def test_every_truncation_and_malformed_metadata_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_tree(root)
            image = mkefs.build(root)

        for length in range(len(image)):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    mkefs.decode(image[:length])

        corruptions: list[bytes] = []
        corrupt = bytearray(image)
        corrupt[0] ^= 0xFF
        corruptions.append(bytes(corrupt))
        corrupt = bytearray(image)
        corrupt[10] = 1
        corruptions.append(bytes(corrupt))
        corrupt = bytearray(image)
        struct.pack_into("<I", corrupt, 12, len(corrupt) - 1)
        corruptions.append(bytes(corrupt))
        corrupt = bytearray(image)
        corrupt[16] = 3
        corruptions.append(bytes(corrupt))
        corruptions.append(image + b"\0")

        for index, corrupt in enumerate(corruptions):
            with self.subTest(corruption=index):
                with self.assertRaises(ValueError):
                    mkefs.decode(corrupt)

    def test_tree_mismatch_and_extra_valid_record_fail_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_tree(root)
            expected = mkefs.collect(root)
            image = mkefs.build(root)

            (root / "extra").write_bytes(b"not in the artifact")
            with self.assertRaises(ValueError):
                mkefs.verify_tree(image, mkefs.collect(root))

            extra_image = mkefs.encode([*expected, (1, "/z-extra", b"extra")])
            with self.assertRaises(ValueError):
                mkefs.verify_tree(extra_image, expected)

    def test_check_command_decodes_the_existing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            self.make_tree(root)
            output = Path(temporary) / "root.kefs"
            image = mkefs.build(root)
            output.write_bytes(image)
            command = (
                sys.executable,
                str(Path(mkefs.__file__).resolve()),
                str(root),
                str(output),
                "--check",
            )

            accepted = subprocess.run(command, check=False, capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())

            corrupt = bytearray(image)
            corrupt[-1] ^= 0xFF
            output.write_bytes(corrupt)
            rejected = subprocess.run(command, check=False, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)

    def test_architecture_selection_flattens_only_one_bin_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin" / "x86_64").mkdir(parents=True)
            (root / "bin" / "aarch64").mkdir()
            (root / "recovery").mkdir()
            (root / "bin" / "x86_64" / "tool.kex").write_bytes(b"x86")
            (root / "bin" / "aarch64" / "tool.kex").write_bytes(b"arm")
            (root / "recovery" / "motd").write_bytes(b"shared")

            x86 = mkefs.decode(mkefs.build(root, "x86_64"))
            arm = mkefs.decode(mkefs.build(root, "aarch64"))
            self.assertIn((1, "/bin/tool.kex", b"x86"), x86)
            self.assertIn((1, "/bin/tool.kex", b"arm"), arm)
            self.assertIn((1, "/recovery/motd", b"shared"), x86)
            for entries in (x86, arm):
                self.assertFalse(
                    any(
                        path == "/etc" or path.startswith("/etc/")
                        for _kind, path, _payload in entries
                    )
                )
            self.assertNotIn((2, "/bin/x86_64", b""), x86)
            self.assertNotIn((2, "/bin/aarch64", b""), x86)

    def test_architecture_selection_rejects_flat_bin_collisions(self) -> None:
        entries: list[mkefs.Entry] = [
            (2, "/bin", b""),
            (1, "/bin/tool.kex", b"generic"),
            (2, "/bin/x86_64", b""),
            (1, "/bin/x86_64/tool.kex", b"target"),
        ]
        with self.assertRaisesRegex(ValueError, "collides"):
            mkefs.select_architecture(entries, "x86_64")

    def test_non_normalized_path_is_rejected(self) -> None:
        path = b"/a/../b"
        record = struct.pack("<BHI", 1, len(path), 0) + path
        image = (
            mkefs.MAGIC
            + struct.pack("<HHI", 1, 0, mkefs.HEADER_SIZE + len(record))
            + record
        )
        with self.assertRaises(ValueError):
            mkefs.decode(image)


class FatBuilderTests(unittest.TestCase):
    """Exercise the exact fixed 8 MiB FAT16 UEFI container contract."""

    PAYLOAD = bytes(range(251)) * 5
    MANIFEST = b"BMNTv1\0\0" + bytes(range(32))

    def test_both_architectures_build_deterministically_and_verify(self) -> None:
        for architecture, boot_name in mkfat.BOOT_NAMES.items():
            with self.subTest(architecture=architecture):
                first = mkfat.build(self.PAYLOAD, boot_name)
                second = mkfat.build(self.PAYLOAD, boot_name)
                self.assertEqual(first, second)
                self.assertEqual(len(first), mkfat.IMAGE_SIZE)
                self.assertEqual(mkfat.extract(first, boot_name), self.PAYLOAD)
                mkfat.verify(first, boot_name, self.PAYLOAD)

    def test_optional_mount_manifest_round_trips_as_a_separate_boot_file(self) -> None:
        boot_name = mkfat.BOOT_NAMES["x86_64"]
        image = mkfat.build(self.PAYLOAD, boot_name, self.MANIFEST)
        self.assertEqual(mkfat.extract(image, boot_name), self.PAYLOAD)
        self.assertEqual(mkfat.extract_mount_manifest(image, boot_name), self.MANIFEST)
        mkfat.verify(image, boot_name, self.PAYLOAD, self.MANIFEST)

    def test_extra_entry_in_each_directory_is_rejected(self) -> None:
        boot_name = mkfat.BOOT_NAMES["x86_64"]
        image = mkfat.build(self.PAYLOAD, boot_name)
        extra = mkfat.directory_entry(b"EXTRA   BIN", 0x20, 4, 0)
        offsets = (
            mkfat.ROOT_OFFSET + 64,
            mkfat.cluster_offset(2) + 96,
            mkfat.cluster_offset(3) + 96,
        )
        for offset in offsets:
            with self.subTest(offset=offset):
                corrupt = bytearray(image)
                corrupt[offset : offset + 32] = extra
                with self.assertRaises(ValueError):
                    mkfat.extract(bytes(corrupt), boot_name)

    def test_truncation_geometry_fat_and_unused_data_corruption_fail(self) -> None:
        boot_name = mkfat.BOOT_NAMES["aarch64"]
        image = mkfat.build(self.PAYLOAD, boot_name)
        for truncated in (b"", image[:511], image[:-1]):
            with self.subTest(length=len(truncated)):
                with self.assertRaises(ValueError):
                    mkfat.extract(truncated, boot_name)

        geometry = bytearray(image)
        geometry[13] = 2
        with self.assertRaises(ValueError):
            mkfat.extract(bytes(geometry), boot_name)

        extra_fat = bytearray(image)
        fat = bytearray(
            extra_fat[mkfat.SECTOR : mkfat.SECTOR + mkfat.FAT_SECTORS * mkfat.SECTOR]
        )
        mkfat.set_fat16(fat, 100, mkfat.END_OF_CHAIN)
        extra_fat[mkfat.SECTOR : mkfat.SECTOR + len(fat)] = fat
        extra_fat[mkfat.SECTOR + len(fat) : mkfat.SECTOR + 2 * len(fat)] = fat
        with self.assertRaises(ValueError):
            mkfat.extract(bytes(extra_fat), boot_name)

        file_clusters = max(
            1,
            (len(self.PAYLOAD) + mkfat.CLUSTER_BYTES - 1)
            // mkfat.CLUSTER_BYTES,
        )
        unused_data = bytearray(image)
        unused_data[mkfat.cluster_offset(4 + file_clusters)] = 1
        with self.assertRaises(ValueError):
            mkfat.extract(bytes(unused_data), boot_name)

    def test_payload_and_architecture_filename_must_match_exactly(self) -> None:
        x86_name = mkfat.BOOT_NAMES["x86_64"]
        arm_name = mkfat.BOOT_NAMES["aarch64"]
        image = mkfat.build(self.PAYLOAD, x86_name)

        with self.assertRaises(ValueError):
            mkfat.extract(image, arm_name)
        with self.assertRaises(ValueError):
            mkfat.verify(image, x86_name, self.PAYLOAD + b"different")

        corrupt = bytearray(image)
        corrupt[mkfat.cluster_offset(4)] ^= 0xFF
        with self.assertRaises(ValueError):
            mkfat.verify(bytes(corrupt), x86_name, self.PAYLOAD)


if __name__ == "__main__":
    unittest.main()

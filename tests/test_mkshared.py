"""Regression tests for the persistent 1 GiB GPT/FAT32 shared medium."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from tools import mkshared, mkstorage


class SharedFat32ImageTests(unittest.TestCase):
    """Keep shared-media creation sparse, exact, and non-destructive by default."""

    def test_identifiers_match_the_default_mount_policy(self) -> None:
        shared = [
            entry
            for entry in mkstorage.default_mount_specs()
            if entry.name == "shared"
        ]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0].disk_guid, mkshared.DISK_GUID)
        self.assertEqual(shared[0].partition_guid, mkshared.PARTITION_GUID)
        self.assertEqual(
            shared[0].filesystem_identity,
            mkshared.FAT32_VOLUME_ID.to_bytes(4, "little") + bytes(12),
        )

    def test_create_verify_preserve_and_explicit_reset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-shared-") as temporary:
            image = Path(temporary) / "shared.img"
            self.assertTrue(mkshared.ensure_image(image))
            self.assertEqual(image.stat().st_size, mkshared.DISK_BYTES)
            mkshared.verify_image(image)

            layout = mkshared.fat32_layout()
            retained_offset = (
                mkshared.PARTITION_START + layout.data_start
            ) * mkshared.SECTOR_BYTES + mkshared.FAT32_SECTORS_PER_CLUSTER * mkshared.SECTOR_BYTES
            with image.open("r+b") as output:
                output.seek(retained_offset)
                output.write(b"persistent-unused-cluster-bytes")
            self.assertFalse(mkshared.ensure_image(image))
            with image.open("rb") as source:
                source.seek(retained_offset)
                self.assertEqual(
                    source.read(len(b"persistent-unused-cluster-bytes")),
                    b"persistent-unused-cluster-bytes",
                )

            self.assertTrue(mkshared.ensure_image(image, reset=True))
            mkshared.verify_image(image)
            with image.open("rb") as source:
                source.seek(retained_offset)
                self.assertEqual(
                    source.read(len(b"persistent-unused-cluster-bytes")),
                    bytes(len(b"persistent-unused-cluster-bytes")),
                )

    def test_corruption_is_rejected_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-shared-") as temporary:
            image = Path(temporary) / "shared.img"
            mkshared.ensure_image(image)
            with image.open("r+b") as output:
                output.seek(510)
                output.write(b"\0\0")
            with self.assertRaisesRegex(ValueError, "protective MBR"):
                mkshared.ensure_image(image)
            with image.open("rb") as source:
                source.seek(510)
                self.assertEqual(source.read(2), b"\0\0")

    def test_valid_primary_and_stale_backup_fsinfo_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-shared-") as temporary:
            image = Path(temporary) / "shared.img"
            mkshared.ensure_image(image)
            primary_fsinfo = (
                mkshared.PARTITION_START + mkshared.FAT32_FSINFO_SECTOR
            ) * mkshared.SECTOR_BYTES
            with image.open("r+b") as output:
                output.seek(primary_fsinfo + 488)
                output.write(
                    struct.pack("<I", mkshared.fat32_layout().cluster_count - 2)
                )
            mkshared.verify_image(image)


if __name__ == "__main__":
    unittest.main()

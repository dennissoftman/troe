"""Regression tests for the pinned constrained-ext4 storage-image builder."""

from __future__ import annotations

import re
import shutil
import struct
import tempfile
import textwrap
import unittest
import unittest.mock
import zlib
from pathlib import Path

from tools import mkstorage

REPO_ROOT = Path(__file__).resolve().parents[1]


class MountManifestTests(unittest.TestCase):
    """Keep the shipped persistent root role explicitly writable."""

    def test_default_policy_includes_optional_writable_shared_fat32(self) -> None:
        root, shared = mkstorage.default_mount_specs()
        self.assertEqual((root.name, shared.name), ("root", "shared"))
        self.assertEqual(shared.filesystem, "fat32")
        self.assertEqual(shared.access, "read-write")
        self.assertEqual(shared.availability, "optional")
        self.assertEqual(shared.activation, "auto")
        self.assertEqual(shared.disk_guid, mkstorage.SHARED_DISK_GUID)
        self.assertEqual(shared.partition_guid, mkstorage.SHARED_PARTITION_GUID)
        self.assertEqual(
            shared.filesystem_identity,
            mkstorage.SHARED_FAT32_VOLUME_ID.to_bytes(4, "little") + bytes(12),
        )

    def test_root_role_is_required_read_write_ext4(self) -> None:
        manifest = mkstorage.build_manifest()
        mkstorage.verify_manifest(manifest)
        record = manifest[
            mkstorage.BMNT_HEADER_BYTES : mkstorage.BMNT_HEADER_BYTES
            + mkstorage.BMNT_RECORD_BYTES
        ]
        self.assertEqual(record[:4], bytes((2, 2, 2, 2)))

    def test_repository_volume_table_reproduces_the_default_policy(self) -> None:
        table = Path(__file__).resolve().parents[1] / "config" / "volumes.toml"
        self.assertEqual(
            mkstorage.build_manifest(mkstorage.load_volume_table(table)),
            mkstorage.build_manifest(),
        )

    def test_manual_acceptance_fixture_keeps_the_canonical_root(self) -> None:
        table = Path(__file__).resolve().parent / "fixtures" / "volumes-manual.toml"
        entries = mkstorage.load_volume_table(table)
        mkstorage.require_fixture_root(entries)
        self.assertEqual([entry.name for entry in entries], ["archive", "root"])
        self.assertEqual(entries[0].activation, "manual")

    def compile_table(self, source: str) -> tuple[mkstorage.MountSpec, ...]:
        with tempfile.TemporaryDirectory(prefix="troe-volumes-") as directory:
            path = Path(directory) / "volumes.toml"
            path.write_text(textwrap.dedent(source), encoding="utf-8")
            return mkstorage.load_volume_table(path)

    def test_custom_ext4_and_fat32_entries_compile_canonically(self) -> None:
        entries = self.compile_table(
            """
            version = 1

            [[volumes]]
            name = "media"
            selector = "gpt"
            filesystem = "fat32"
            disk_guid = "11111111-2222-3333-4444-555555555555"
            partition_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            volume_id = "a1b2c3d4"
            access = "read-write"
            availability = "optional"
            activation = "auto"

            [[volumes]]
            name = "archive"
            selector = "whole-device"
            filesystem = "ext4-v1"
            filesystem_uuid = "99999999-8888-7777-6666-555555555555"
            access = "read-only"
            availability = "optional"
            activation = "auto"
            """
        )
        manifest = mkstorage.build_manifest(entries)
        self.assertEqual(
            [entry.name for entry in mkstorage.decode_manifest(manifest)],
            ["archive", "media"],
        )
        media = mkstorage.decode_manifest(manifest)[1]
        self.assertEqual(media.filesystem_identity[:4], bytes.fromhex("d4c3b2a1"))
        self.assertEqual(media.filesystem_identity[4:], bytes(12))

    def test_custom_table_accepts_manual_and_rejects_ambiguous_mounts(self) -> None:
        manual = self.compile_table(
            """
            version = 1
            [[volumes]]
            name = "archive"
            selector = "whole-device"
            filesystem = "ext4-v1"
            filesystem_uuid = "99999999-8888-7777-6666-555555555555"
            access = "read-only"
            availability = "optional"
            activation = "manual"
            """
        )
        self.assertEqual(manual[0].activation, "manual")
        self.assertEqual(
            mkstorage.decode_manifest(mkstorage.build_manifest(manual)), manual
        )

        old_minor = bytearray(mkstorage.build_manifest(manual))
        struct.pack_into("<H", old_minor, 10, 0)
        old_minor[
            mkstorage.BMNT_CHECKSUM_OFFSET : mkstorage.BMNT_CHECKSUM_OFFSET + 4
        ] = bytes(4)
        struct.pack_into(
            "<I",
            old_minor,
            mkstorage.BMNT_CHECKSUM_OFFSET,
            zlib.crc32(old_minor),
        )
        with self.assertRaisesRegex(ValueError, "invalid BMNT header"):
            mkstorage.decode_manifest(bytes(old_minor))

        with self.assertRaisesRegex(
            ValueError, "root volume must activate automatically"
        ):
            self.compile_table(
                """
                version = 1
                [[volumes]]
                name = "root"
                selector = "whole-device"
                filesystem = "ext4-v1"
                filesystem_uuid = "99999999-8888-7777-6666-555555555555"
                access = "read-write"
                availability = "required"
                activation = "manual"
                """
            )

        duplicate = mkstorage.default_mount_specs()[0]
        with self.assertRaisesRegex(ValueError, "duplicates another stable selector"):
            mkstorage.build_manifest(
                (
                    duplicate,
                    mkstorage.MountSpec(
                        name="second",
                        selector=duplicate.selector,
                        filesystem=duplicate.filesystem,
                        access=duplicate.access,
                        availability="optional",
                        disk_guid=duplicate.disk_guid,
                        partition_guid=duplicate.partition_guid,
                        filesystem_identity=duplicate.filesystem_identity,
                    ),
                )
            )


class E2fsprogsPolicyTests(unittest.TestCase):
    """Keep compatible development and strict release policies explicit."""

    def test_strict_version_banner_is_pinned(self) -> None:
        for name, expected in mkstorage.PINNED_E2FSPROGS_OUTPUT.items():
            with self.subTest(name=name):
                mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                    name, "\n".join(expected) + "\n", strict=True
                )
                wrong = "\n".join(expected).replace(
                    mkstorage.PINNED_E2FSPROGS_VERSION, "1.47.5"
                )
                with self.assertRaises(ValueError):
                    mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                        name, wrong, strict=True
                    )
                with self.assertRaises(ValueError):
                    mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                        name,
                        "\n".join(expected) + "\nunreviewed wrapper\n",
                        strict=True,
                    )

    def test_compatible_policy_accepts_only_the_147_feature_line(self) -> None:
        for version in ("1.47", "1.47.0", "1.47.9"):
            with self.subTest(version=version):
                output = (
                    f"mke2fs {version} (distribution build)\n"
                    f"Using EXT2FS Library version {version}\n"
                )
                self.assertEqual(
                    mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                        "mke2fs", output
                    )[:2],
                    (1, 47),
                )
        for version in ("1.46.6", "1.48.0", "2.0.0"):
            with self.subTest(version=version):
                output = (
                    f"e2fsck {version} (distribution build)\n"
                    f"Using EXT2FS Library version {version}, distribution build\n"
                )
                with self.assertRaisesRegex(ValueError, "1.47.x"):
                    mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                        "e2fsck", output
                    )

    def test_compatible_policy_rejects_mixed_libraries_and_extra_output(self) -> None:
        with self.assertRaisesRegex(ValueError, "different versions"):
            mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                "mke2fs",
                "mke2fs 1.47.0 (distribution)\nUsing EXT2FS Library version 1.47.1\n",
            )
        with self.assertRaisesRegex(ValueError, "invalid mke2fs version banner"):
            mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                "mke2fs",
                "mke2fs 1.47.0 (distribution)\n"
                "Using EXT2FS Library version 1.47.0\n"
                "wrapper output\n",
            )


class Ext4JournalCapacityTests(unittest.TestCase):
    """Check the pinned log against the provider's transaction ceiling."""

    def test_pinned_journal_outsizes_the_worst_admissible_transaction(self) -> None:
        source = (REPO_ROOT / "crates" / "troe-ext4" / "src" / "journal.rs").read_text(
            encoding="utf-8"
        )
        declaration = re.search(
            r"pub\(crate\) const MAX_TRANSACTION_BLOCKS: usize = ([0-9_]+);", source
        )
        self.assertIsNotNone(
            declaration, "troe-ext4 must declare a transaction ceiling"
        )
        assert declaration is not None
        ceiling = int(declaration.group(1).replace("_", ""))

        # `encode_transaction` writes one descriptor block, one image per staged
        # block, and one commit record, and refuses the transaction unless every
        # one of them fits between the journal superblock and the log's end.
        footprint = ceiling + 2
        usable = mkstorage.EXT4_JOURNAL_BLOCKS - mkstorage.EXT4_JOURNAL_FIRST_BLOCK
        self.assertGreaterEqual(
            usable,
            footprint,
            f"the pinned {mkstorage.EXT4_JOURNAL_BLOCKS}-block journal leaves "
            f"{usable} usable blocks, below the {footprint} a worst-case "
            f"transaction needs; raise EXT4_JOURNAL_MEBIBYTES or lower "
            f"MAX_TRANSACTION_BLOCKS",
        )


class Ext4StorageBuilderTests(unittest.TestCase):
    """Exercise deterministic formatting and independent post-format parsing."""

    CONTENT = b"CSPKv1\0bounded storage test payload\n"

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("mke2fs") is None or shutil.which("e2fsck") is None:
            raise unittest.SkipTest("pinned e2fsprogs tools are unavailable")
        cls.first = mkstorage.create_ext4(cls.CONTENT)
        cls.second = mkstorage.create_ext4(cls.CONTENT)

    @staticmethod
    def refresh_superblock(image: bytearray) -> None:
        """Refresh the ext4 superblock checksum after one semantic mutation."""
        start = 1024
        checksum = mkstorage._crc32c(  # noqa: SLF001 - focused format regression
            0xFFFF_FFFF, memoryview(image)[start : start + 1020]
        )
        struct.pack_into("<I", image, start + 1020, checksum)

    @staticmethod
    def checksum_seed(image: bytearray) -> int:
        """Return the UUID-derived metadata_csum seed."""
        return mkstorage._crc32c(  # noqa: SLF001 - focused format regression
            0xFFFF_FFFF, memoryview(image)[1024 + 104 : 1024 + 120]
        )

    @classmethod
    def refresh_group_descriptor(cls, image: bytearray) -> None:
        """Refresh group zero's low 16-bit metadata_csum checksum."""
        offset = mkstorage.EXT4_BLOCK_BYTES
        descriptor = bytearray(
            image[offset : offset + mkstorage.EXT4_GROUP_DESCRIPTOR_BYTES]
        )
        descriptor[30:32] = b"\0\0"
        checksum = mkstorage._crc32c(  # noqa: SLF001 - focused format regression
            mkstorage._crc32c(  # noqa: SLF001 - focused format regression
                cls.checksum_seed(image), (0).to_bytes(4, "little")
            ),
            descriptor,
        )
        struct.pack_into("<H", image, offset + 30, checksum & 0xFFFF)

    @classmethod
    def refresh_block_bitmap(cls, image: bytearray) -> None:
        """Refresh group zero's block-bitmap checksum and descriptor checksum."""
        descriptor_offset = mkstorage.EXT4_BLOCK_BYTES
        bitmap_block = struct.unpack_from("<I", image, descriptor_offset)[0]
        bitmap_offset = bitmap_block * mkstorage.EXT4_BLOCK_BYTES
        checksum = mkstorage._crc32c(  # noqa: SLF001 - focused format regression
            cls.checksum_seed(image),
            memoryview(image)[
                bitmap_offset : bitmap_offset + mkstorage.EXT4_BLOCK_BYTES
            ],
        )
        struct.pack_into("<H", image, descriptor_offset + 24, checksum & 0xFFFF)
        cls.refresh_group_descriptor(image)

    @classmethod
    def refresh_inode_bitmap(cls, image: bytearray) -> None:
        """Refresh group zero's inode-bitmap checksum and descriptor checksum."""
        descriptor_offset = mkstorage.EXT4_BLOCK_BYTES
        bitmap_block = struct.unpack_from("<I", image, descriptor_offset + 4)[0]
        bitmap_offset = bitmap_block * mkstorage.EXT4_BLOCK_BYTES
        checksum = mkstorage._crc32c(  # noqa: SLF001 - focused format regression
            cls.checksum_seed(image),
            memoryview(image)[
                bitmap_offset : bitmap_offset + mkstorage.EXT4_INODES_PER_GROUP // 8
            ],
        )
        struct.pack_into("<H", image, descriptor_offset + 26, checksum & 0xFFFF)
        cls.refresh_group_descriptor(image)

    @classmethod
    def inode_offset(cls, image: bytearray, number: int) -> int:
        """Locate one inode in the single canonical group."""
        table = struct.unpack_from("<I", image, mkstorage.EXT4_BLOCK_BYTES + 8)[0]
        return (
            table * mkstorage.EXT4_BLOCK_BYTES
            + (number - 1) * mkstorage.EXT4_INODE_BYTES
        )

    @classmethod
    def refresh_inode(cls, image: bytearray, number: int) -> None:
        """Refresh both halves of one active inode checksum."""
        offset = cls.inode_offset(image, number)
        raw = bytearray(image[offset : offset + mkstorage.EXT4_INODE_BYTES])
        generation = struct.unpack_from("<I", raw, 100)[0]
        raw[124:126] = b"\0\0"
        raw[130:132] = b"\0\0"
        checksum = mkstorage._crc32c(  # noqa: SLF001 - focused format regression
            mkstorage._crc32c(  # noqa: SLF001 - focused format regression
                mkstorage._crc32c(  # noqa: SLF001 - focused format regression
                    cls.checksum_seed(image), number.to_bytes(4, "little")
                ),
                generation.to_bytes(4, "little"),
            ),
            raw,
        )
        struct.pack_into("<H", image, offset + 124, checksum & 0xFFFF)
        struct.pack_into("<H", image, offset + 130, checksum >> 16)

    @classmethod
    def journal_superblock_offset(cls, image: bytearray) -> int:
        """Locate the journal superblock through inode 8's first extent."""
        inode = cls.inode_offset(image, mkstorage.EXT4_JOURNAL_INODE)
        return (
            struct.unpack_from("<I", image, inode + 60)[0] * mkstorage.EXT4_BLOCK_BYTES
        )

    def test_double_build_is_identical_and_independently_validated(self) -> None:
        self.assertEqual(self.first, self.second)
        self.assertEqual(
            len(self.first), mkstorage.PARTITION_SECTORS * mkstorage.SECTOR_BYTES
        )
        mkstorage.verify_ext4(self.first, self.CONTENT)

    def test_journal_is_the_pinned_length_and_starts_where_expected(self) -> None:
        image = bytearray(self.first)
        offset = self.journal_superblock_offset(image)
        self.assertEqual(
            struct.unpack_from(">I", image, offset + 16)[0],
            mkstorage.EXT4_JOURNAL_BLOCKS,
        )
        self.assertEqual(
            struct.unpack_from(">I", image, offset + 20)[0],
            mkstorage.EXT4_JOURNAL_FIRST_BLOCK,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", image, self.inode_offset(image, mkstorage.EXT4_JOURNAL_INODE) + 4
            )[0],
            mkstorage.EXT4_JOURNAL_BLOCKS * mkstorage.EXT4_BLOCK_BYTES,
        )

        # This profile emits no journal checksums, so the declared length is
        # editable in place: an image that claims any other log size is refused
        # even though it stays self-consistent everywhere else.
        for field, value in ((16, mkstorage.EXT4_JOURNAL_BLOCKS * 2), (20, 2)):
            with self.subTest(field=field):
                altered = bytearray(self.first)
                struct.pack_into(">I", altered, offset + field, value)
                with self.assertRaisesRegex(
                    ValueError, "journal is not the pinned length"
                ):
                    mkstorage.verify_ext4(bytes(altered), self.CONTENT)

    def test_a_differently_sized_journal_fails_the_verifier(self) -> None:
        # A recipe that asks mke2fs for another journal size still formats and
        # passes `e2fsck`; the independent verifier is what refuses it, so the
        # build fails instead of producing an accepted image.
        with (
            unittest.mock.patch.object(
                mkstorage,
                "EXT4_JOURNAL_MEBIBYTES",
                mkstorage.EXT4_JOURNAL_MEBIBYTES + 1,
            ),
            self.assertRaisesRegex(ValueError, "journal is not the pinned length"),
        ):
            mkstorage.create_ext4(self.CONTENT)

    def test_truncation_dirty_state_and_unknown_features_are_rejected(self) -> None:
        for truncated in (b"", self.first[:2048], self.first[:-1]):
            with self.subTest(length=len(truncated)):
                with self.assertRaises(ValueError):
                    mkstorage.verify_ext4(truncated, self.CONTENT)

        dirty = bytearray(self.first)
        struct.pack_into("<H", dirty, 1024 + 58, 0)
        self.refresh_superblock(dirty)
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(dirty), self.CONTENT)

        feature = bytearray(self.first)
        incompat = struct.unpack_from("<I", feature, 1024 + 96)[0]
        struct.pack_into("<I", feature, 1024 + 96, incompat | 0x80)
        self.refresh_superblock(feature)
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(feature), self.CONTENT)

    def test_block_bitmap_semantics_reject_extra_and_padding_allocations(self) -> None:
        extra = bytearray(self.first)
        descriptor_offset = mkstorage.EXT4_BLOCK_BYTES
        bitmap_block = struct.unpack_from("<I", extra, descriptor_offset)[0]
        free_block = 2000
        bitmap_byte = bitmap_block * mkstorage.EXT4_BLOCK_BYTES + free_block // 8
        self.assertEqual(extra[bitmap_byte] & (1 << (free_block % 8)), 0)
        extra[bitmap_byte] |= 1 << (free_block % 8)
        free_blocks = struct.unpack_from("<H", extra, descriptor_offset + 12)[0]
        struct.pack_into("<H", extra, descriptor_offset + 12, free_blocks - 1)
        super_free = struct.unpack_from("<I", extra, 1024 + 12)[0]
        struct.pack_into("<I", extra, 1024 + 12, super_free - 1)
        self.refresh_block_bitmap(extra)
        self.refresh_superblock(extra)
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(extra), self.CONTENT)

        missing = bytearray(self.first)
        hello_offset = self.inode_offset(missing, 12)
        hello_block = struct.unpack_from("<I", missing, hello_offset + 60)[0]
        bitmap_block = struct.unpack_from("<I", missing, descriptor_offset)[0]
        bitmap_byte = bitmap_block * mkstorage.EXT4_BLOCK_BYTES + hello_block // 8
        self.assertNotEqual(missing[bitmap_byte] & (1 << (hello_block % 8)), 0)
        missing[bitmap_byte] &= ~(1 << (hello_block % 8))
        free_blocks = struct.unpack_from("<H", missing, descriptor_offset + 12)[0]
        struct.pack_into("<H", missing, descriptor_offset + 12, free_blocks + 1)
        super_free = struct.unpack_from("<I", missing, 1024 + 12)[0]
        struct.pack_into("<I", missing, 1024 + 12, super_free + 1)
        self.refresh_block_bitmap(missing)
        self.refresh_superblock(missing)
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(missing), self.CONTENT)

        padding = bytearray(self.first)
        bitmap_block = struct.unpack_from("<I", padding, descriptor_offset)[0]
        padding_bit = mkstorage.PARTITION_SECTORS * mkstorage.SECTOR_BYTES // 4096
        bitmap_byte = bitmap_block * mkstorage.EXT4_BLOCK_BYTES + padding_bit // 8
        self.assertNotEqual(padding[bitmap_byte] & (1 << (padding_bit % 8)), 0)
        padding[bitmap_byte] &= ~(1 << (padding_bit % 8))
        self.refresh_block_bitmap(padding)
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(padding), self.CONTENT)

    def test_inode_bitmap_semantics_reject_allocated_empty_inode(self) -> None:
        corrupt = bytearray(self.first)
        descriptor_offset = mkstorage.EXT4_BLOCK_BYTES
        bitmap_block = struct.unpack_from("<I", corrupt, descriptor_offset + 4)[0]
        inode = 100
        bit = inode - 1
        bitmap_byte = bitmap_block * mkstorage.EXT4_BLOCK_BYTES + bit // 8
        self.assertEqual(corrupt[bitmap_byte] & (1 << (bit % 8)), 0)
        corrupt[bitmap_byte] |= 1 << (bit % 8)
        free_inodes = struct.unpack_from("<H", corrupt, descriptor_offset + 14)[0]
        struct.pack_into("<H", corrupt, descriptor_offset + 14, free_inodes - 1)
        struct.pack_into(
            "<H",
            corrupt,
            descriptor_offset + 28,
            mkstorage.EXT4_INODES_PER_GROUP - inode,
        )
        super_free = struct.unpack_from("<I", corrupt, 1024 + 16)[0]
        struct.pack_into("<I", corrupt, 1024 + 16, super_free - 1)
        self.refresh_inode_bitmap(corrupt)
        self.refresh_superblock(corrupt)
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(corrupt), self.CONTENT)

        referenced = bytearray(self.first)
        inode = 14
        bit = inode - 1
        bitmap_block = struct.unpack_from("<I", referenced, descriptor_offset + 4)[0]
        bitmap_byte = bitmap_block * mkstorage.EXT4_BLOCK_BYTES + bit // 8
        self.assertNotEqual(referenced[bitmap_byte] & (1 << (bit % 8)), 0)
        referenced[bitmap_byte] &= ~(1 << (bit % 8))
        free_inodes = struct.unpack_from("<H", referenced, descriptor_offset + 14)[0]
        struct.pack_into("<H", referenced, descriptor_offset + 14, free_inodes + 1)
        super_free = struct.unpack_from("<I", referenced, 1024 + 16)[0]
        struct.pack_into("<I", referenced, 1024 + 16, super_free + 1)
        self.refresh_inode_bitmap(referenced)
        self.refresh_superblock(referenced)
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(referenced), self.CONTENT)

    def test_extent_tree_directory_checksum_and_payload_deviations_fail(self) -> None:
        extent_tree = bytearray(self.first)
        inode_offset = self.inode_offset(extent_tree, 12)
        struct.pack_into("<H", extent_tree, inode_offset + 46, 1)
        self.refresh_inode(extent_tree, 12)
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(extent_tree), self.CONTENT)

        directory = bytearray(self.first)
        root_offset = self.inode_offset(directory, mkstorage.EXT4_ROOT_INODE)
        root_block = struct.unpack_from("<I", directory, root_offset + 60)[0]
        directory[root_block * mkstorage.EXT4_BLOCK_BYTES + 100] ^= 1
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(directory), self.CONTENT)

        payload = bytearray(self.first)
        hello_offset = self.inode_offset(payload, 12)
        hello_block = struct.unpack_from("<I", payload, hello_offset + 60)[0]
        payload[hello_block * mkstorage.EXT4_BLOCK_BYTES] ^= 1
        with self.assertRaises(ValueError):
            mkstorage.verify_ext4(bytes(payload), self.CONTENT)


if __name__ == "__main__":
    unittest.main()

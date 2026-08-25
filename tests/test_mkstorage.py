"""Regression tests for the pinned constrained-ext4 storage-image builder."""

from __future__ import annotations

import shutil
import struct
import unittest

from tools import mkstorage


class E2fsprogsPinTests(unittest.TestCase):
    """Keep the host formatter/checker version contract exact."""

    def test_exact_version_banner_is_pinned(self) -> None:
        for name, expected in mkstorage.PINNED_E2FSPROGS_OUTPUT.items():
            with self.subTest(name=name):
                mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                    name, "\n".join(expected) + "\n"
                )
                wrong = "\n".join(expected).replace(
                    mkstorage.PINNED_E2FSPROGS_VERSION, "1.47.5"
                )
                with self.assertRaises(ValueError):
                    mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                        name, wrong
                    )
                with self.assertRaises(ValueError):
                    mkstorage._verify_e2fsprogs_version_output(  # noqa: SLF001
                        name, "\n".join(expected) + "\nunreviewed wrapper\n"
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

    def test_double_build_is_identical_and_independently_validated(self) -> None:
        self.assertEqual(self.first, self.second)
        self.assertEqual(
            len(self.first), mkstorage.PARTITION_SECTORS * mkstorage.SECTOR_BYTES
        )
        mkstorage.verify_ext4(self.first, self.CONTENT)

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

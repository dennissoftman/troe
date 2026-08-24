#!/usr/bin/env python3
"""Create the deterministic BMNT policy and GPT/ext4 QEMU storage fixture."""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path


SECTOR_BYTES = 512
TOTAL_SECTORS = 36_864
PARTITION_START = 2_048
PARTITION_SECTORS = 32_768
PARTITION_END = PARTITION_START + PARTITION_SECTORS - 1
GPT_ENTRY_COUNT = 128
GPT_ENTRY_BYTES = 128
GPT_ARRAY_BYTES = GPT_ENTRY_COUNT * GPT_ENTRY_BYTES
GPT_ARRAY_SECTORS = GPT_ARRAY_BYTES // SECTOR_BYTES
BACKUP_HEADER_LBA = TOTAL_SECTORS - 1
BACKUP_ARRAY_LBA = BACKUP_HEADER_LBA - GPT_ARRAY_SECTORS
FIRST_USABLE_LBA = 34
LAST_USABLE_LBA = BACKUP_ARRAY_LBA - 1

# These are exact on-media bytes. BMNT deliberately uses the same byte order
# as GPT fields so boot policy matching never depends on display formatting.
DISK_GUID = bytes.fromhex("1032547698badcfe0123456789abcdef")
PARTITION_GUID = bytes.fromhex("21436587a9cbedff1032547698badcfe")
LINUX_FILESYSTEM_TYPE_GUID = bytes.fromhex("af3dc60f838472478e793d69d8477de4")
FILESYSTEM_UUID = bytes.fromhex("00112233445566778899aabbccddeeff")
FILESYSTEM_UUID_TEXT = "00112233-4455-6677-8899-aabbccddeeff"
FAKE_TIME = "1704067200"

BMNT_HEADER_BYTES = 64
BMNT_RECORD_BYTES = 96
BMNT_CHECKSUM_OFFSET = 20


def build_manifest() -> bytes:
    """Encode one required read-only `/vol/root` ext4 selector."""
    name = b"root"
    total_bytes = BMNT_HEADER_BYTES + BMNT_RECORD_BYTES + len(name)
    image = bytearray(total_bytes)
    image[:8] = b"BMNTv1\0\0"
    struct.pack_into(
        "<HHHHI", image, 8, 1, 0, BMNT_HEADER_BYTES, BMNT_RECORD_BYTES, total_bytes
    )
    struct.pack_into("<H", image, 24, 1)
    struct.pack_into("<I", image, 28, len(name))

    record = memoryview(image)[BMNT_HEADER_BYTES:BMNT_HEADER_BYTES + BMNT_RECORD_BYTES]
    record[0] = 2  # GPT partition
    record[1] = 2  # ext4 v1
    record[2] = 1  # read-only
    record[3] = 2  # required
    struct.pack_into("<IH", record, 4, 0, len(name))
    record[16:32] = DISK_GUID
    record[32:48] = PARTITION_GUID
    record[48:64] = FILESYSTEM_UUID
    image[-len(name):] = name

    checksum_image = bytearray(image)
    checksum_image[BMNT_CHECKSUM_OFFSET:BMNT_CHECKSUM_OFFSET + 4] = b"\0" * 4
    struct.pack_into("<I", image, BMNT_CHECKSUM_OFFSET, zlib.crc32(checksum_image))
    return bytes(image)


def gpt_header(current_lba: int, backup_lba: int, entry_lba: int, entry_crc: int) -> bytes:
    """Encode one canonical 92-byte GPT 1.0 header in a zeroed sector."""
    sector = bytearray(SECTOR_BYTES)
    sector[:8] = b"EFI PART"
    struct.pack_into("<III", sector, 8, 0x0001_0000, 92, 0)
    struct.pack_into(
        "<QQQQ", sector, 24, current_lba, backup_lba, FIRST_USABLE_LBA, LAST_USABLE_LBA
    )
    sector[56:72] = DISK_GUID
    struct.pack_into("<QIII", sector, 72, entry_lba, GPT_ENTRY_COUNT, GPT_ENTRY_BYTES, entry_crc)
    header = bytearray(sector[:92])
    header[16:20] = b"\0" * 4
    struct.pack_into("<I", sector, 16, zlib.crc32(header))
    return bytes(sector)


def build_gpt(filesystem: bytes) -> bytes:
    """Wrap one exact ext4 payload in primary/backup-consistent GPT metadata."""
    if len(filesystem) != PARTITION_SECTORS * SECTOR_BYTES:
        raise ValueError("ext4 payload has the wrong exact partition size")

    entries = bytearray(GPT_ARRAY_BYTES)
    entries[:16] = LINUX_FILESYSTEM_TYPE_GUID
    entries[16:32] = PARTITION_GUID
    struct.pack_into("<QQQ", entries, 32, PARTITION_START, PARTITION_END, 0)
    name = "root".encode("utf-16-le")
    entries[56:56 + len(name)] = name
    entry_crc = zlib.crc32(entries)

    image = bytearray(TOTAL_SECTORS * SECTOR_BYTES)
    protective = memoryview(image)[:SECTOR_BYTES]
    protective[446 + 4] = 0xEE
    struct.pack_into("<II", protective, 446 + 8, 1, TOTAL_SECTORS - 1)
    protective[510:512] = b"\x55\xaa"

    image[SECTOR_BYTES:2 * SECTOR_BYTES] = gpt_header(
        1, BACKUP_HEADER_LBA, 2, entry_crc
    )
    primary_entries = 2 * SECTOR_BYTES
    image[primary_entries:primary_entries + GPT_ARRAY_BYTES] = entries
    partition_offset = PARTITION_START * SECTOR_BYTES
    image[partition_offset:partition_offset + len(filesystem)] = filesystem
    backup_entries = BACKUP_ARRAY_LBA * SECTOR_BYTES
    image[backup_entries:backup_entries + GPT_ARRAY_BYTES] = entries
    backup_header = BACKUP_HEADER_LBA * SECTOR_BYTES
    image[backup_header:backup_header + SECTOR_BYTES] = gpt_header(
        BACKUP_HEADER_LBA, 1, BACKUP_ARRAY_LBA, entry_crc
    )
    return bytes(image)


def create_ext4() -> bytes:
    """Build a clean, bounded ext4 v1 filesystem using e2fsprogs."""
    mke2fs = shutil.which("mke2fs")
    e2fsck = shutil.which("e2fsck")
    if mke2fs is None or e2fsck is None:
        raise FileNotFoundError("mke2fs and e2fsck are required for the QEMU storage fixture")

    with tempfile.TemporaryDirectory(prefix="troe-storage-") as temporary:
        root = Path(temporary)
        source = root / "source"
        nested = source / "nested"
        nested.mkdir(parents=True)
        (source / "hello.txt").write_bytes(b"native ext4 mount\n")
        (nested / "state.txt").write_bytes(b"read-only activation complete\n")
        timestamp = int(FAKE_TIME)
        for path in (source / "hello.txt", nested / "state.txt", nested, source):
            os.utime(path, (timestamp, timestamp))

        filesystem = root / "root.ext4"
        with filesystem.open("wb") as output:
            output.truncate(PARTITION_SECTORS * SECTOR_BYTES)
        environment = os.environ.copy()
        environment.update(
            {
                "E2FSPROGS_FAKE_TIME": FAKE_TIME,
                "SOURCE_DATE_EPOCH": FAKE_TIME,
            }
        )
        subprocess.run(
            [
                mke2fs,
                "-q",
                "-F",
                "-t",
                "ext4",
                "-b",
                "4096",
                "-I",
                "256",
                "-U",
                FILESYSTEM_UUID_TEXT,
                "-L",
                "TROE_ROOT",
                "-O",
                "none,has_journal,ext_attr,extent,filetype,sparse_super,large_file,extra_isize,metadata_csum",
                "-E",
                f"lazy_itable_init=0,lazy_journal_init=0,hash_seed={FILESYSTEM_UUID_TEXT}",
                "-d",
                str(source),
                str(filesystem),
            ],
            check=True,
            env=environment,
        )
        subprocess.run([e2fsck, "-fn", str(filesystem)], check=True)
        return filesystem.read_bytes()


def verify_manifest(manifest: bytes) -> None:
    """Check exact BMNT size, checksum, and stable identities."""
    if len(manifest) != BMNT_HEADER_BYTES + BMNT_RECORD_BYTES + 4:
        raise ValueError("unexpected BMNT size")
    stored = struct.unpack_from("<I", manifest, BMNT_CHECKSUM_OFFSET)[0]
    checked = bytearray(manifest)
    checked[BMNT_CHECKSUM_OFFSET:BMNT_CHECKSUM_OFFSET + 4] = b"\0" * 4
    if zlib.crc32(checked) != stored:
        raise ValueError("BMNT checksum mismatch")
    record = manifest[BMNT_HEADER_BYTES:BMNT_HEADER_BYTES + BMNT_RECORD_BYTES]
    if record[16:32] != DISK_GUID or record[32:48] != PARTITION_GUID:
        raise ValueError("BMNT GPT identity mismatch")
    if record[48:64] != FILESYSTEM_UUID or manifest[-4:] != b"root":
        raise ValueError("BMNT filesystem identity mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="also create the GPT/ext4 disk image")
    args = parser.parse_args()
    try:
        manifest = build_manifest()
        verify_manifest(manifest)
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_bytes(manifest)
        print(f"BMNT v1: {len(manifest)} bytes -> {args.manifest}")
        if args.output is not None:
            disk = build_gpt(create_ext4())
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(disk)
            print(f"GPT/ext4 fixture: {len(disk)} bytes -> {args.output}")
        return 0
    except (FileNotFoundError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"mkstorage: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

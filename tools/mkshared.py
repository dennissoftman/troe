#!/usr/bin/env python3
"""Create or verify the persistent host-shared 1 GiB GPT/FAT32 medium."""

from __future__ import annotations

import argparse
import os
import struct
import sys
import tempfile
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path

try:
    from tools import mkstorage
except ImportError:  # Direct execution from tools/.
    import mkstorage  # type: ignore[no-redef]


SECTOR_BYTES = 512
DISK_BYTES = 1024 * 1024 * 1024
TOTAL_SECTORS = DISK_BYTES // SECTOR_BYTES
PARTITION_START = 2_048
BACKUP_HEADER_LBA = TOTAL_SECTORS - 1
BACKUP_ARRAY_LBA = BACKUP_HEADER_LBA - mkstorage.GPT_ARRAY_SECTORS
FIRST_USABLE_LBA = 34
LAST_USABLE_LBA = BACKUP_ARRAY_LBA - 1
PARTITION_END = LAST_USABLE_LBA
PARTITION_SECTORS = PARTITION_END - PARTITION_START + 1

DISK_GUID_TEXT = mkstorage.SHARED_DISK_GUID_TEXT
PARTITION_GUID_TEXT = mkstorage.SHARED_PARTITION_GUID_TEXT
DISK_GUID = uuid.UUID(DISK_GUID_TEXT).bytes_le
PARTITION_GUID = uuid.UUID(PARTITION_GUID_TEXT).bytes_le
MICROSOFT_BASIC_DATA_GUID = uuid.UUID(
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
).bytes_le

FAT32_SECTORS_PER_CLUSTER = 8
FAT32_RESERVED_SECTORS = 32
FAT32_FAT_COUNT = 2
FAT32_ROOT_CLUSTER = 2
FAT32_FSINFO_SECTOR = 1
FAT32_BACKUP_BOOT_SECTOR = 6
FAT32_BACKUP_FSINFO_SECTOR = FAT32_BACKUP_BOOT_SECTOR + FAT32_FSINFO_SECTOR
FAT32_MEDIA = 0xF8
FAT32_END_OF_CHAIN = 0x0FFF_FFFF
FAT32_CLEAN_SHUTDOWN = 0x0800_0000
FAT32_NO_HARD_ERROR = 0x0400_0000
FAT32_VOLUME_ID = mkstorage.SHARED_FAT32_VOLUME_ID
FAT32_VOLUME_LABEL = b"TROE SHARE "
FAT32_OEM_IDENTIFIER = b"TROEFAT "
FAT32_MIN_CLUSTERS = 65_525
FAT32_MAX_CLUSTERS = 0x0FFF_FFF5
DEFAULT_OUTPUT = Path("build/troe-shared-fat32.img")


@dataclass(frozen=True)
class Fat32Layout:
    """Exact mutable FAT32 geometry inside the shared GPT partition."""

    fat_sectors: int
    data_start: int
    cluster_count: int

    @property
    def fat_bytes(self) -> int:
        return self.fat_sectors * SECTOR_BYTES


def fat32_layout() -> Fat32Layout:
    """Solve the FAT length and return the canonical 4 KiB-cluster layout."""
    fat_sectors = 1
    for _ in range(32):
        data_sectors = (
            PARTITION_SECTORS
            - FAT32_RESERVED_SECTORS
            - FAT32_FAT_COUNT * fat_sectors
        )
        if data_sectors <= 0:
            raise ValueError("shared FAT32 partition has no data region")
        cluster_count = data_sectors // FAT32_SECTORS_PER_CLUSTER
        required = (
            (cluster_count + 2) * 4 + SECTOR_BYTES - 1
        ) // SECTOR_BYTES
        if required == fat_sectors:
            if not FAT32_MIN_CLUSTERS <= cluster_count < FAT32_MAX_CLUSTERS:
                raise ValueError("shared partition does not classify as FAT32")
            return Fat32Layout(
                fat_sectors=fat_sectors,
                data_start=FAT32_RESERVED_SECTORS
                + FAT32_FAT_COUNT * fat_sectors,
                cluster_count=cluster_count,
            )
        fat_sectors = required
    raise ValueError("shared FAT32 geometry did not converge")


def _gpt_entries() -> bytes:
    entries = bytearray(mkstorage.GPT_ARRAY_BYTES)
    entries[:16] = MICROSOFT_BASIC_DATA_GUID
    entries[16:32] = PARTITION_GUID
    struct.pack_into("<QQQ", entries, 32, PARTITION_START, PARTITION_END, 0)
    name = "TROE Shared".encode("utf-16-le")
    entries[56 : 56 + len(name)] = name
    return bytes(entries)


def _boot_sector(layout: Fat32Layout) -> bytes:
    sector = bytearray(SECTOR_BYTES)
    sector[0:3] = b"\xeb\x58\x90"
    sector[3:11] = FAT32_OEM_IDENTIFIER
    struct.pack_into(
        "<HBHBHHBHHHII",
        sector,
        11,
        SECTOR_BYTES,
        FAT32_SECTORS_PER_CLUSTER,
        FAT32_RESERVED_SECTORS,
        FAT32_FAT_COUNT,
        0,
        0,
        FAT32_MEDIA,
        0,
        63,
        255,
        PARTITION_START,
        PARTITION_SECTORS,
    )
    struct.pack_into("<I", sector, 36, layout.fat_sectors)
    struct.pack_into("<HHIHH", sector, 40, 0, 0, FAT32_ROOT_CLUSTER, 1, 6)
    sector[64] = 0x80
    sector[66] = 0x29
    struct.pack_into("<I", sector, 67, FAT32_VOLUME_ID)
    sector[71:82] = FAT32_VOLUME_LABEL
    sector[82:90] = b"FAT32   "
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _fsinfo(layout: Fat32Layout) -> bytes:
    sector = bytearray(SECTOR_BYTES)
    struct.pack_into("<I", sector, 0, 0x4161_5252)
    struct.pack_into("<I", sector, 484, 0x6141_7272)
    struct.pack_into("<I", sector, 488, layout.cluster_count - 1)
    struct.pack_into("<I", sector, 492, FAT32_ROOT_CLUSTER + 1)
    struct.pack_into("<I", sector, 508, 0xAA55_0000)
    return bytes(sector)


def _initial_fat(layout: Fat32Layout) -> bytes:
    fat = bytearray(layout.fat_bytes)
    struct.pack_into("<I", fat, 0, 0x0FFF_FF00 | FAT32_MEDIA)
    struct.pack_into("<I", fat, 4, FAT32_END_OF_CHAIN)
    struct.pack_into("<I", fat, 8, FAT32_END_OF_CHAIN)
    return bytes(fat)


def _write_at(output: object, offset: int, payload: bytes) -> None:
    if offset < 0 or offset + len(payload) > DISK_BYTES:
        raise ValueError("shared-image write is outside the disk")
    output.seek(offset)
    if output.write(payload) != len(payload):
        raise OSError("short shared-image write")


def create_image(path: Path) -> None:
    """Create one new sparse image without overwriting an existing path."""
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"shared image already exists: {path}")
    layout = fat32_layout()
    entries = _gpt_entries()
    entry_crc = zlib.crc32(entries)
    primary_header = mkstorage.gpt_header(
        1,
        BACKUP_HEADER_LBA,
        2,
        entry_crc,
        FIRST_USABLE_LBA,
        LAST_USABLE_LBA,
        DISK_GUID,
    )
    backup_header = mkstorage.gpt_header(
        BACKUP_HEADER_LBA,
        1,
        BACKUP_ARRAY_LBA,
        entry_crc,
        FIRST_USABLE_LBA,
        LAST_USABLE_LBA,
        DISK_GUID,
    )
    boot = _boot_sector(layout)
    fsinfo = _fsinfo(layout)
    fat = _initial_fat(layout)
    partition_offset = PARTITION_START * SECTOR_BYTES

    with path.open("xb") as output:
        output.truncate(DISK_BYTES)
        _write_at(output, 0, mkstorage.protective_mbr(TOTAL_SECTORS))
        _write_at(output, SECTOR_BYTES, primary_header)
        _write_at(output, 2 * SECTOR_BYTES, entries)
        _write_at(output, BACKUP_ARRAY_LBA * SECTOR_BYTES, entries)
        _write_at(output, BACKUP_HEADER_LBA * SECTOR_BYTES, backup_header)
        _write_at(output, partition_offset, boot)
        _write_at(
            output,
            partition_offset + FAT32_FSINFO_SECTOR * SECTOR_BYTES,
            fsinfo,
        )
        _write_at(
            output,
            partition_offset + FAT32_BACKUP_BOOT_SECTOR * SECTOR_BYTES,
            boot,
        )
        _write_at(
            output,
            partition_offset + FAT32_BACKUP_FSINFO_SECTOR * SECTOR_BYTES,
            fsinfo,
        )
        first_fat = partition_offset + FAT32_RESERVED_SECTORS * SECTOR_BYTES
        _write_at(output, first_fat, fat)
        _write_at(output, first_fat + layout.fat_bytes, fat)
        output.flush()
        os.fsync(output.fileno())


def _read_at(source: object, offset: int, count: int) -> bytes:
    if offset < 0 or count < 0 or offset + count > DISK_BYTES:
        raise ValueError("shared-image read is outside the disk")
    source.seek(offset)
    payload = source.read(count)
    if len(payload) != count:
        raise ValueError("shared image is truncated")
    return payload


def _validate_fsinfo(payload: bytes, layout: Fat32Layout) -> None:
    if (
        len(payload) != SECTOR_BYTES
        or struct.unpack_from("<I", payload, 0)[0] != 0x4161_5252
        or struct.unpack_from("<I", payload, 484)[0] != 0x6141_7272
        or struct.unpack_from("<I", payload, 508)[0] != 0xAA55_0000
    ):
        raise ValueError("shared FAT32 FSInfo signatures are invalid")
    free = struct.unpack_from("<I", payload, 488)[0]
    next_free = struct.unpack_from("<I", payload, 492)[0]
    if (free != 0xFFFF_FFFF and free > layout.cluster_count) or (
        next_free != 0xFFFF_FFFF
        and not FAT32_ROOT_CLUSTER <= next_free <= layout.cluster_count + 1
    ):
        raise ValueError("shared FAT32 FSInfo counters are invalid")


def verify_image(path: Path) -> None:
    """Verify immutable geometry and clean mutable FAT32 metadata in bounded reads."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size != DISK_BYTES:
        raise ValueError("shared image is not a regular exact 1 GiB file")
    layout = fat32_layout()
    entries = _gpt_entries()
    entry_crc = zlib.crc32(entries)
    partition_offset = PARTITION_START * SECTOR_BYTES
    with path.open("rb") as source:
        if _read_at(source, 0, SECTOR_BYTES) != mkstorage.protective_mbr(
            TOTAL_SECTORS
        ):
            raise ValueError("shared image protective MBR is invalid")
        if _read_at(source, SECTOR_BYTES, SECTOR_BYTES) != mkstorage.gpt_header(
            1,
            BACKUP_HEADER_LBA,
            2,
            entry_crc,
            FIRST_USABLE_LBA,
            LAST_USABLE_LBA,
            DISK_GUID,
        ):
            raise ValueError("shared image primary GPT header is invalid")
        if _read_at(source, 2 * SECTOR_BYTES, len(entries)) != entries:
            raise ValueError("shared image primary GPT entries are invalid")
        if _read_at(source, BACKUP_ARRAY_LBA * SECTOR_BYTES, len(entries)) != entries:
            raise ValueError("shared image backup GPT entries are invalid")
        if _read_at(
            source, BACKUP_HEADER_LBA * SECTOR_BYTES, SECTOR_BYTES
        ) != mkstorage.gpt_header(
            BACKUP_HEADER_LBA,
            1,
            BACKUP_ARRAY_LBA,
            entry_crc,
            FIRST_USABLE_LBA,
            LAST_USABLE_LBA,
            DISK_GUID,
        ):
            raise ValueError("shared image backup GPT header is invalid")

        boot = _read_at(source, partition_offset, SECTOR_BYTES)
        if boot != _boot_sector(layout):
            raise ValueError("shared FAT32 boot sector or identity is invalid")
        if _read_at(
            source,
            partition_offset + FAT32_BACKUP_BOOT_SECTOR * SECTOR_BYTES,
            SECTOR_BYTES,
        ) != boot:
            raise ValueError("shared FAT32 backup boot sector differs")
        fsinfo = _read_at(
            source,
            partition_offset + FAT32_FSINFO_SECTOR * SECTOR_BYTES,
            SECTOR_BYTES,
        )
        _validate_fsinfo(fsinfo, layout)
        backup_fsinfo = _read_at(
            source,
            partition_offset + FAT32_BACKUP_FSINFO_SECTOR * SECTOR_BYTES,
            SECTOR_BYTES,
        )
        _validate_fsinfo(backup_fsinfo, layout)

        first_fat = partition_offset + FAT32_RESERVED_SECTORS * SECTOR_BYTES
        primary = _read_at(source, first_fat, layout.fat_bytes)
        backup = _read_at(source, first_fat + layout.fat_bytes, layout.fat_bytes)
        if primary != backup:
            raise ValueError("shared FAT32 allocation tables differ")
        media, reserved, root = struct.unpack_from("<III", primary, 0)
        if (
            media & 0x0FFF_FFFF != 0x0FFF_FF00 | FAT32_MEDIA
            or reserved < 0x0FFF_FFF8
            or reserved & (FAT32_CLEAN_SHUTDOWN | FAT32_NO_HARD_ERROR)
            != FAT32_CLEAN_SHUTDOWN | FAT32_NO_HARD_ERROR
            or root < 0x0FFF_FFF8
        ):
            raise ValueError("shared FAT32 core allocation entries are invalid or dirty")


def ensure_image(path: Path, *, reset: bool = False) -> bool:
    """Preserve one valid image or atomically create/reset it; return whether created."""
    if path.is_symlink():
        raise ValueError("shared image path must not be a symbolic link")
    path = path.resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not reset:
        verify_image(path)
        return False
    with tempfile.NamedTemporaryFile(
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as staging:
        staging_path = Path(staging.name)
    staging_path.unlink()
    try:
        create_image(staging_path)
        verify_image(staging_path)
        staging_path.replace(path)
    finally:
        if staging_path.exists():
            staging_path.unlink()
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="replace existing shared media with a new empty filesystem",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="verify an existing image without creating it",
    )
    args = parser.parse_args()
    if args.reset and args.verify:
        parser.error("--reset and --verify are mutually exclusive")
    try:
        if args.verify:
            verify_image(args.output)
            action = "verified"
        else:
            created = ensure_image(args.output, reset=args.reset)
            action = "created" if created else "preserved"
        print(
            f"shared GPT/FAT32: {action} {DISK_BYTES} bytes -> "
            f"{args.output.resolve(strict=True)}"
        )
        return 0
    except (FileNotFoundError, OSError, ValueError) as error:
        print(f"mkshared: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

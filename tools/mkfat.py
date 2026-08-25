#!/usr/bin/env python3
"""Create and verify a deterministic 1.44 MiB FAT12 UEFI boot image."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

SECTOR = 512
TOTAL_SECTORS = 2880
FAT_SECTORS = 9
ROOT_ENTRIES = 224
ROOT_SECTORS = 14
FIRST_DATA_SECTOR = 1 + 2 * FAT_SECTORS + ROOT_SECTORS
IMAGE_SIZE = SECTOR * TOTAL_SECTORS
END_OF_CHAIN = 0xFFF
OEM_IDENTIFIER = b"UEFIBOOT"
VOLUME_IDENTIFIER = 0x5545_4649
VOLUME_LABEL = b"UEFI BOOT  "
BOOT_NAMES = {
    "x86_64": b"BOOTX64 EFI",
    "aarch64": b"BOOTAA64EFI",
}
DIRECTORY_ENTRY_BYTES = 32
ROOT_OFFSET = (1 + 2 * FAT_SECTORS) * SECTOR
MAX_DATA_CLUSTER = TOTAL_SECTORS - FIRST_DATA_SECTOR + 1


def directory_entry(name: bytes, attributes: int, cluster: int, size: int) -> bytes:
    if (
        len(name) != 11
        or not 0 <= cluster <= 0xFFFF
        or not 0 <= size <= 0xFFFF_FFFF
    ):
        raise ValueError("invalid FAT directory entry")
    entry = bytearray(32)
    entry[:11] = name
    entry[11] = attributes
    # Valid, deterministic FAT date: 1980-01-01 with a midnight timestamp.
    struct.pack_into("<H", entry, 16, 0x0021)
    struct.pack_into("<H", entry, 18, 0x0021)
    struct.pack_into("<H", entry, 24, 0x0021)
    struct.pack_into("<H", entry, 26, cluster)
    struct.pack_into("<I", entry, 28, size)
    return bytes(entry)


def set_fat12(fat: bytearray, cluster: int, value: int) -> None:
    offset = cluster + cluster // 2
    if offset + 1 >= len(fat) or not 0 <= value <= 0xFFF:
        raise ValueError("FAT12 cluster is outside the allocation table")
    if cluster % 2 == 0:
        fat[offset] = value & 0xFF
        fat[offset + 1] = (fat[offset + 1] & 0xF0) | ((value >> 8) & 0x0F)
    else:
        fat[offset] = (fat[offset] & 0x0F) | ((value << 4) & 0xF0)
        fat[offset + 1] = (value >> 4) & 0xFF


def get_fat12(fat: bytes, cluster: int) -> int:
    offset = cluster + cluster // 2
    if cluster < 0 or offset + 1 >= len(fat):
        raise ValueError("FAT12 cluster is outside the allocation table")
    pair = fat[offset] | (fat[offset + 1] << 8)
    return (pair >> 4) & 0xFFF if cluster % 2 else pair & 0xFFF


def cluster_offset(cluster: int) -> int:
    if not 2 <= cluster <= MAX_DATA_CLUSTER:
        raise ValueError("data cluster is outside the fixed FAT12 geometry")
    return (FIRST_DATA_SECTOR + cluster - 2) * SECTOR


def enumerate_directory(directory: bytes, label: str) -> list[bytes]:
    """Enumerate every live entry and reject noncanonical trailing metadata."""
    if len(directory) % DIRECTORY_ENTRY_BYTES != 0:
        raise ValueError(f"{label} directory length is invalid")
    entries: list[bytes] = []
    terminated = False
    for offset in range(0, len(directory), DIRECTORY_ENTRY_BYTES):
        entry = directory[offset:offset + DIRECTORY_ENTRY_BYTES]
        if entry == bytes(DIRECTORY_ENTRY_BYTES):
            terminated = True
            continue
        if entry[0] == 0 or terminated:
            raise ValueError(f"{label} directory has noncanonical trailing entries")
        entries.append(entry)
    return entries


def require_directory(directory: bytes, expected: list[bytes], label: str) -> None:
    """Require exactly the ordered canonical entries and no others."""
    if enumerate_directory(directory, label) != expected:
        raise ValueError(f"{label} directory does not have the canonical structure")


def file_cluster_count(byte_count: int) -> int:
    """Return the bounded number of sectors occupied by the sole file."""
    if not 0 <= byte_count <= 0xFFFF_FFFF:
        raise ValueError("EFI executable length is outside the FAT12 field")
    return max(1, (byte_count + SECTOR - 1) // SECTOR)


def build(efi: bytes, boot_name: bytes) -> bytes:
    if boot_name not in BOOT_NAMES.values():
        raise ValueError("UEFI fallback name is not architecture-native")
    file_clusters = file_cluster_count(len(efi))
    last_cluster = 3 + file_clusters
    if last_cluster > MAX_DATA_CLUSTER:
        raise ValueError("EFI executable does not fit in the FAT12 image")

    image = bytearray(IMAGE_SIZE)
    boot = memoryview(image)[:SECTOR]
    boot[0:3] = b"\xEB\x3C\x90"
    boot[3:11] = OEM_IDENTIFIER
    struct.pack_into("<HBHBHHBHHHII", boot, 11, SECTOR, 1, 1, 2, ROOT_ENTRIES,
                     TOTAL_SECTORS, 0xF0, FAT_SECTORS, 18, 2, 0, 0)
    boot[36] = 0
    boot[38] = 0x29
    struct.pack_into("<I", boot, 39, VOLUME_IDENTIFIER)
    boot[43:54] = VOLUME_LABEL
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xAA"

    fat = bytearray(FAT_SECTORS * SECTOR)
    fat[:3] = b"\xF0\xFF\xFF"
    set_fat12(fat, 2, END_OF_CHAIN)
    set_fat12(fat, 3, END_OF_CHAIN)
    first_file_cluster = 4
    for index in range(file_clusters):
        cluster = first_file_cluster + index
        following = END_OF_CHAIN if index + 1 == file_clusters else cluster + 1
        set_fat12(fat, cluster, following)
    first_fat = SECTOR
    image[first_fat:first_fat + len(fat)] = fat
    second_fat = first_fat + len(fat)
    image[second_fat:second_fat + len(fat)] = fat

    image[ROOT_OFFSET:ROOT_OFFSET + 32] = directory_entry(b"EFI        ", 0x10, 2, 0)

    efi_dir = cluster_offset(2)
    image[efi_dir:efi_dir + 32] = directory_entry(b".          ", 0x10, 2, 0)
    image[efi_dir + 32:efi_dir + 64] = directory_entry(b"..         ", 0x10, 0, 0)
    image[efi_dir + 64:efi_dir + 96] = directory_entry(b"BOOT       ", 0x10, 3, 0)

    boot_dir = cluster_offset(3)
    image[boot_dir:boot_dir + 32] = directory_entry(b".          ", 0x10, 3, 0)
    image[boot_dir + 32:boot_dir + 64] = directory_entry(b"..         ", 0x10, 2, 0)
    image[boot_dir + 64:boot_dir + 96] = directory_entry(
        boot_name, 0x20, first_file_cluster, len(efi)
    )

    for index in range(file_clusters):
        source = efi[index * SECTOR:(index + 1) * SECTOR]
        destination = cluster_offset(first_file_cluster + index)
        image[destination:destination + len(source)] = source
    return bytes(image)


def expected_fat(file_clusters: int) -> bytes:
    """Construct the only allocation table accepted by the fixed container."""
    if not 1 <= file_clusters <= MAX_DATA_CLUSTER - 3:
        raise ValueError("EFI executable cluster count is outside the FAT12 image")
    fat = bytearray(FAT_SECTORS * SECTOR)
    fat[:3] = b"\xF0\xFF\xFF"
    set_fat12(fat, 2, END_OF_CHAIN)
    set_fat12(fat, 3, END_OF_CHAIN)
    for index in range(file_clusters):
        cluster = 4 + index
        following = END_OF_CHAIN if index + 1 == file_clusters else cluster + 1
        set_fat12(fat, cluster, following)
    return bytes(fat)


def extract(image: bytes, boot_name: bytes) -> bytes:
    """Validate the complete canonical FAT12 tree and return its sole payload."""
    if boot_name not in BOOT_NAMES.values():
        raise ValueError("UEFI fallback name is not architecture-native")
    if len(image) != IMAGE_SIZE or image[510:512] != b"\x55\xAA":
        raise ValueError("invalid FAT12 image size or boot signature")
    if (
        image[:3] != b"\xEB\x3C\x90"
        or image[3:11] != OEM_IDENTIFIER
        or struct.unpack_from("<I", image, 39)[0] != VOLUME_IDENTIFIER
        or image[43:54] != VOLUME_LABEL
        or image[54:62] != b"FAT12   "
        or image[36:39] != b"\0\0\x29"
        or any(image[62:510])
    ):
        raise ValueError("unexpected FAT12 format identifiers")
    geometry = struct.unpack_from("<HBHBHHBHHHII", image, 11)
    if geometry != (
        SECTOR,
        1,
        1,
        2,
        ROOT_ENTRIES,
        TOTAL_SECTORS,
        0xF0,
        FAT_SECTORS,
        18,
        2,
        0,
        0,
    ):
        raise ValueError("unexpected FAT12 geometry")
    fat_start = SECTOR
    fat = image[fat_start:fat_start + FAT_SECTORS * SECTOR]
    second = image[fat_start + len(fat):fat_start + 2 * len(fat)]
    if fat != second:
        raise ValueError("FAT copies differ")

    root = image[ROOT_OFFSET:ROOT_OFFSET + ROOT_SECTORS * SECTOR]
    require_directory(
        root,
        [directory_entry(b"EFI        ", 0x10, 2, 0)],
        "root",
    )
    efi_dir = image[cluster_offset(2):cluster_offset(2) + SECTOR]
    require_directory(
        efi_dir,
        [
            directory_entry(b".          ", 0x10, 2, 0),
            directory_entry(b"..         ", 0x10, 0, 0),
            directory_entry(b"BOOT       ", 0x10, 3, 0),
        ],
        "EFI",
    )
    boot_dir = image[cluster_offset(3):cluster_offset(3) + SECTOR]
    entries = enumerate_directory(boot_dir, "BOOT")
    if len(entries) != 3:
        raise ValueError("BOOT directory does not contain exactly one fallback executable")
    entry = entries[2]
    cluster = struct.unpack_from("<H", entry, 26)[0]
    size = struct.unpack_from("<I", entry, 28)[0]
    require_directory(
        boot_dir,
        [
            directory_entry(b".          ", 0x10, 3, 0),
            directory_entry(b"..         ", 0x10, 2, 0),
            directory_entry(boot_name, 0x20, cluster, size),
        ],
        "BOOT",
    )
    if cluster != 4:
        raise ValueError("UEFI fallback executable has a noncanonical first cluster")
    file_clusters = file_cluster_count(size)
    if 3 + file_clusters > MAX_DATA_CLUSTER or fat != expected_fat(file_clusters):
        raise ValueError("FAT allocation table is not canonical")

    cluster = struct.unpack_from("<H", entry, 26)[0]
    payload = bytearray()
    for index in range(file_clusters):
        if cluster != 4 + index:
            raise ValueError("UEFI fallback executable chain is not canonical")
        offset = cluster_offset(cluster)
        payload += image[offset:offset + SECTOR]
        cluster = get_fat12(fat, cluster)
    if cluster != END_OF_CHAIN:
        raise ValueError("invalid FAT end-of-chain marker")
    if any(payload[size:]):
        raise ValueError("UEFI fallback executable has nonzero cluster padding")
    first_unused_cluster = 4 + file_clusters
    if first_unused_cluster <= MAX_DATA_CLUSTER:
        if any(image[cluster_offset(first_unused_cluster):]):
            raise ValueError("unused FAT12 data clusters are not zero")
    return bytes(payload[:size])


def verify(image: bytes, boot_name: bytes, expected_payload: bytes) -> None:
    """Require the complete canonical tree and exact fallback payload."""
    if extract(image, boot_name) != expected_payload:
        raise ValueError("round-trip verification did not reproduce the EFI executable")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--efi", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true", help="verify an existing image only")
    args = parser.parse_args()
    boot_name = BOOT_NAMES[args.arch]
    try:
        efi = args.efi.read_bytes()
        if args.verify:
            image = args.output.read_bytes()
        else:
            image = build(efi, boot_name)
        verify(image, boot_name, efi)
        if not args.verify:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(image)
        print(f"FAT12 {args.arch}: {len(efi)}-byte EFI, {len(image)}-byte image -> {args.output}")
        return 0
    except (OSError, ValueError) as error:
        print(f"mkfat: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

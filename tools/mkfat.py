#!/usr/bin/env python3
"""Create and verify a deterministic 1.44 MiB FAT12 UEFI boot image."""

from __future__ import annotations

import argparse
import math
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


def directory_entry(name: bytes, attributes: int, cluster: int, size: int) -> bytes:
    if len(name) != 11 or not 0 <= cluster <= 0xFFFF or not 0 <= size <= 0xFFFF_FFFF:
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
    pair = fat[offset] | (fat[offset + 1] << 8)
    return (pair >> 4) & 0xFFF if cluster % 2 else pair & 0xFFF


def cluster_offset(cluster: int) -> int:
    if cluster < 2:
        raise ValueError("data clusters start at 2")
    return (FIRST_DATA_SECTOR + cluster - 2) * SECTOR


def build(efi: bytes, boot_name: bytes) -> bytes:
    if len(boot_name) != 11:
        raise ValueError("UEFI fallback name must be an 8.3 FAT name")
    file_clusters = max(1, math.ceil(len(efi) / SECTOR))
    last_cluster = 3 + file_clusters
    maximum_cluster = TOTAL_SECTORS - FIRST_DATA_SECTOR + 1
    if last_cluster > maximum_cluster:
        raise ValueError("EFI executable does not fit in the FAT12 image")

    image = bytearray(IMAGE_SIZE)
    boot = memoryview(image)[:SECTOR]
    boot[0:3] = b"\xEB\x3C\x90"
    boot[3:11] = b"KLLMBOOT"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, SECTOR, 1, 1, 2, ROOT_ENTRIES,
                     TOTAL_SECTORS, 0xF0, FAT_SECTORS, 18, 2, 0, 0)
    boot[36] = 0
    boot[38] = 0x29
    struct.pack_into("<I", boot, 39, 0x4B4C4C4D)
    boot[43:54] = b"KLLM BOOT  "
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

    root_offset = (1 + 2 * FAT_SECTORS) * SECTOR
    image[root_offset:root_offset + 32] = directory_entry(b"EFI        ", 0x10, 2, 0)

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


def extract(image: bytes, boot_name: bytes) -> bytes:
    if len(image) != IMAGE_SIZE or image[510:512] != b"\x55\xAA":
        raise ValueError("invalid FAT12 image size or boot signature")
    expected_bpb = struct.unpack_from("<HBHBHHBHHHII", image, 11)
    if expected_bpb[:8] != (SECTOR, 1, 1, 2, ROOT_ENTRIES, TOTAL_SECTORS, 0xF0, FAT_SECTORS):
        raise ValueError("unexpected FAT12 geometry")
    fat_start = SECTOR
    fat = image[fat_start:fat_start + FAT_SECTORS * SECTOR]
    second = image[fat_start + len(fat):fat_start + 2 * len(fat)]
    if fat != second:
        raise ValueError("FAT copies differ")
    boot_dir = image[cluster_offset(3):cluster_offset(3) + SECTOR]
    entry = boot_dir[64:96]
    if entry[:11] != boot_name or entry[11] != 0x20:
        raise ValueError("UEFI fallback executable is missing")
    cluster = struct.unpack_from("<H", entry, 26)[0]
    size = struct.unpack_from("<I", entry, 28)[0]
    payload = bytearray()
    visited: set[int] = set()
    while cluster < 0xFF8:
        if cluster < 2 or cluster in visited:
            raise ValueError("invalid or cyclic FAT chain")
        visited.add(cluster)
        offset = cluster_offset(cluster)
        payload += image[offset:offset + SECTOR]
        cluster = get_fat12(fat, cluster)
    if cluster > END_OF_CHAIN:
        raise ValueError("invalid FAT end-of-chain marker")
    return bytes(payload[:size])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--efi", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true", help="verify an existing image only")
    args = parser.parse_args()
    boot_name = b"BOOTX64 EFI" if args.arch == "x86_64" else b"BOOTAA64EFI"
    try:
        efi = args.efi.read_bytes()
        if args.verify:
            image = args.output.read_bytes()
        else:
            image = build(efi, boot_name)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(image)
        if extract(image, boot_name) != efi:
            raise ValueError("round-trip verification did not reproduce the EFI executable")
        print(f"FAT12 {args.arch}: {len(efi)}-byte EFI, {len(image)}-byte image -> {args.output}")
        return 0
    except (OSError, ValueError) as error:
        print(f"mkfat: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

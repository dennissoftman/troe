#!/usr/bin/env python3
"""Create and verify a deterministic 8 MiB FAT16 UEFI boot image."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

SECTOR = 512
SECTORS_PER_CLUSTER = 1
CLUSTER_BYTES = SECTOR * SECTORS_PER_CLUSTER
TOTAL_SECTORS = 16_384
FAT_SECTORS = 64
ROOT_ENTRIES = 224
ROOT_SECTORS = 14
FIRST_DATA_SECTOR = 1 + 2 * FAT_SECTORS + ROOT_SECTORS
IMAGE_SIZE = SECTOR * TOTAL_SECTORS
END_OF_CHAIN = 0xFFFF
MEDIA = 0xF8
OEM_IDENTIFIER = b"UEFIBOOT"
VOLUME_IDENTIFIER = 0x5545_4649
VOLUME_LABEL = b"UEFI BOOT  "
BOOT_NAMES = {
    "x86_64": b"BOOTX64 EFI",
    "aarch64": b"BOOTAA64EFI",
}
MOUNT_MANIFEST_NAME = b"VOLUMES BMT"
DIRECTORY_ENTRY_BYTES = 32
ROOT_OFFSET = (1 + 2 * FAT_SECTORS) * SECTOR
MAX_DATA_CLUSTER = (TOTAL_SECTORS - FIRST_DATA_SECTOR) // SECTORS_PER_CLUSTER + 1


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


def set_fat16(fat: bytearray, cluster: int, value: int) -> None:
    offset = cluster * 2
    if cluster < 0 or offset + 2 > len(fat) or not 0 <= value <= 0xFFFF:
        raise ValueError("FAT16 cluster is outside the allocation table")
    struct.pack_into("<H", fat, offset, value)


def get_fat16(fat: bytes, cluster: int) -> int:
    offset = cluster * 2
    if cluster < 0 or offset + 2 > len(fat):
        raise ValueError("FAT16 cluster is outside the allocation table")
    return struct.unpack_from("<H", fat, offset)[0]


def cluster_offset(cluster: int) -> int:
    if not 2 <= cluster <= MAX_DATA_CLUSTER:
        raise ValueError("data cluster is outside the fixed FAT16 geometry")
    return (FIRST_DATA_SECTOR + (cluster - 2) * SECTORS_PER_CLUSTER) * SECTOR


def enumerate_directory(directory: bytes, label: str) -> list[bytes]:
    """Enumerate every live entry and reject noncanonical trailing metadata."""
    if len(directory) % DIRECTORY_ENTRY_BYTES != 0:
        raise ValueError(f"{label} directory length is invalid")
    entries: list[bytes] = []
    terminated = False
    for offset in range(0, len(directory), DIRECTORY_ENTRY_BYTES):
        entry = directory[offset : offset + DIRECTORY_ENTRY_BYTES]
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
    """Return the bounded number of clusters occupied by one file."""
    if not 0 <= byte_count <= 0xFFFF_FFFF:
        raise ValueError("EFI executable length is outside the FAT16 field")
    return max(1, (byte_count + CLUSTER_BYTES - 1) // CLUSTER_BYTES)


def build(efi: bytes, boot_name: bytes, mount_manifest: bytes | None = None) -> bytes:
    if boot_name not in BOOT_NAMES.values():
        raise ValueError("UEFI fallback name is not architecture-native")
    if mount_manifest is not None and not mount_manifest:
        raise ValueError("boot mount manifest must not be empty")
    file_clusters = file_cluster_count(len(efi))
    manifest_clusters = (
        file_cluster_count(len(mount_manifest)) if mount_manifest is not None else 0
    )
    last_cluster = 3 + file_clusters + manifest_clusters
    if last_cluster > MAX_DATA_CLUSTER:
        raise ValueError("EFI executable does not fit in the FAT16 image")

    image = bytearray(IMAGE_SIZE)
    boot = memoryview(image)[:SECTOR]
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = OEM_IDENTIFIER
    struct.pack_into(
        "<HBHBHHBHHHII",
        boot,
        11,
        SECTOR,
        SECTORS_PER_CLUSTER,
        1,
        2,
        ROOT_ENTRIES,
        TOTAL_SECTORS,
        MEDIA,
        FAT_SECTORS,
        32,
        2,
        0,
        0,
    )
    boot[36] = 0
    boot[38] = 0x29
    struct.pack_into("<I", boot, 39, VOLUME_IDENTIFIER)
    boot[43:54] = VOLUME_LABEL
    boot[54:62] = b"FAT16   "
    boot[510:512] = b"\x55\xaa"

    fat = bytearray(FAT_SECTORS * SECTOR)
    fat[:4] = bytes((MEDIA, 0xFF, 0xFF, 0xFF))
    set_fat16(fat, 2, END_OF_CHAIN)
    set_fat16(fat, 3, END_OF_CHAIN)
    first_file_cluster = 4
    for index in range(file_clusters):
        cluster = first_file_cluster + index
        following = END_OF_CHAIN if index + 1 == file_clusters else cluster + 1
        set_fat16(fat, cluster, following)
    first_manifest_cluster = first_file_cluster + file_clusters
    for index in range(manifest_clusters):
        cluster = first_manifest_cluster + index
        following = END_OF_CHAIN if index + 1 == manifest_clusters else cluster + 1
        set_fat16(fat, cluster, following)
    first_fat = SECTOR
    image[first_fat : first_fat + len(fat)] = fat
    second_fat = first_fat + len(fat)
    image[second_fat : second_fat + len(fat)] = fat

    image[ROOT_OFFSET : ROOT_OFFSET + 32] = directory_entry(VOLUME_LABEL, 0x08, 0, 0)
    image[ROOT_OFFSET + 32 : ROOT_OFFSET + 64] = directory_entry(
        b"EFI        ", 0x10, 2, 0
    )

    efi_dir = cluster_offset(2)
    image[efi_dir : efi_dir + 32] = directory_entry(b".          ", 0x10, 2, 0)
    image[efi_dir + 32 : efi_dir + 64] = directory_entry(b"..         ", 0x10, 0, 0)
    image[efi_dir + 64 : efi_dir + 96] = directory_entry(b"BOOT       ", 0x10, 3, 0)

    boot_dir = cluster_offset(3)
    image[boot_dir : boot_dir + 32] = directory_entry(b".          ", 0x10, 3, 0)
    image[boot_dir + 32 : boot_dir + 64] = directory_entry(b"..         ", 0x10, 2, 0)
    image[boot_dir + 64 : boot_dir + 96] = directory_entry(
        boot_name, 0x20, first_file_cluster, len(efi)
    )
    if mount_manifest is not None:
        image[boot_dir + 96 : boot_dir + 128] = directory_entry(
            MOUNT_MANIFEST_NAME,
            0x20,
            first_manifest_cluster,
            len(mount_manifest),
        )

    for index in range(file_clusters):
        source = efi[index * CLUSTER_BYTES : (index + 1) * CLUSTER_BYTES]
        destination = cluster_offset(first_file_cluster + index)
        image[destination : destination + len(source)] = source
    if mount_manifest is not None:
        for index in range(manifest_clusters):
            source = mount_manifest[index * CLUSTER_BYTES : (index + 1) * CLUSTER_BYTES]
            destination = cluster_offset(first_manifest_cluster + index)
            image[destination : destination + len(source)] = source
    return bytes(image)


def expected_fat(file_clusters: int, manifest_clusters: int = 0) -> bytes:
    """Construct the only allocation table accepted by the fixed container."""
    if not 1 <= file_clusters <= MAX_DATA_CLUSTER - 3:
        raise ValueError("EFI executable cluster count is outside the FAT16 image")
    fat = bytearray(FAT_SECTORS * SECTOR)
    fat[:4] = bytes((MEDIA, 0xFF, 0xFF, 0xFF))
    set_fat16(fat, 2, END_OF_CHAIN)
    set_fat16(fat, 3, END_OF_CHAIN)
    for index in range(file_clusters):
        cluster = 4 + index
        following = END_OF_CHAIN if index + 1 == file_clusters else cluster + 1
        set_fat16(fat, cluster, following)
    first_manifest_cluster = 4 + file_clusters
    for index in range(manifest_clusters):
        cluster = first_manifest_cluster + index
        following = END_OF_CHAIN if index + 1 == manifest_clusters else cluster + 1
        set_fat16(fat, cluster, following)
    return bytes(fat)


def extract_files(image: bytes, boot_name: bytes) -> tuple[bytes, bytes | None]:
    """Validate the canonical FAT16 tree and return EFI and optional BMNT bytes."""
    if boot_name not in BOOT_NAMES.values():
        raise ValueError("UEFI fallback name is not architecture-native")
    if len(image) != IMAGE_SIZE or image[510:512] != b"\x55\xaa":
        raise ValueError("invalid FAT16 image size or boot signature")
    if (
        image[:3] != b"\xeb\x3c\x90"
        or image[3:11] != OEM_IDENTIFIER
        or struct.unpack_from("<I", image, 39)[0] != VOLUME_IDENTIFIER
        or image[43:54] != VOLUME_LABEL
        or image[54:62] != b"FAT16   "
        or image[36:39] != b"\0\0\x29"
        or any(image[62:510])
    ):
        raise ValueError("unexpected FAT16 format identifiers")
    geometry = struct.unpack_from("<HBHBHHBHHHII", image, 11)
    if geometry != (
        SECTOR,
        SECTORS_PER_CLUSTER,
        1,
        2,
        ROOT_ENTRIES,
        TOTAL_SECTORS,
        MEDIA,
        FAT_SECTORS,
        32,
        2,
        0,
        0,
    ):
        raise ValueError("unexpected FAT16 geometry")
    fat_start = SECTOR
    fat = image[fat_start : fat_start + FAT_SECTORS * SECTOR]
    second = image[fat_start + len(fat) : fat_start + 2 * len(fat)]
    if fat != second:
        raise ValueError("FAT copies differ")

    root = image[ROOT_OFFSET : ROOT_OFFSET + ROOT_SECTORS * SECTOR]
    require_directory(
        root,
        [
            directory_entry(VOLUME_LABEL, 0x08, 0, 0),
            directory_entry(b"EFI        ", 0x10, 2, 0),
        ],
        "root",
    )
    efi_dir = image[cluster_offset(2) : cluster_offset(2) + CLUSTER_BYTES]
    require_directory(
        efi_dir,
        [
            directory_entry(b".          ", 0x10, 2, 0),
            directory_entry(b"..         ", 0x10, 0, 0),
            directory_entry(b"BOOT       ", 0x10, 3, 0),
        ],
        "EFI",
    )
    boot_dir = image[cluster_offset(3) : cluster_offset(3) + CLUSTER_BYTES]
    entries = enumerate_directory(boot_dir, "BOOT")
    if len(entries) not in (3, 4):
        raise ValueError("BOOT directory has an invalid canonical file count")
    entry = entries[2]
    cluster = struct.unpack_from("<H", entry, 26)[0]
    size = struct.unpack_from("<I", entry, 28)[0]
    manifest_entry = entries[3] if len(entries) == 4 else None
    manifest_cluster = (
        struct.unpack_from("<H", manifest_entry, 26)[0]
        if manifest_entry is not None
        else 0
    )
    manifest_size = (
        struct.unpack_from("<I", manifest_entry, 28)[0]
        if manifest_entry is not None
        else 0
    )
    require_directory(
        boot_dir,
        [
            directory_entry(b".          ", 0x10, 3, 0),
            directory_entry(b"..         ", 0x10, 2, 0),
            directory_entry(boot_name, 0x20, cluster, size),
            *(
                [
                    directory_entry(
                        MOUNT_MANIFEST_NAME,
                        0x20,
                        manifest_cluster,
                        manifest_size,
                    )
                ]
                if manifest_entry is not None
                else []
            ),
        ],
        "BOOT",
    )
    if cluster != 4:
        raise ValueError("UEFI fallback executable has a noncanonical first cluster")
    file_clusters = file_cluster_count(size)
    manifest_clusters = (
        file_cluster_count(manifest_size) if manifest_entry is not None else 0
    )
    if (
        3 + file_clusters + manifest_clusters > MAX_DATA_CLUSTER
        or (
            manifest_entry is not None
            and (manifest_size == 0 or manifest_cluster != 4 + file_clusters)
        )
        or fat != expected_fat(file_clusters, manifest_clusters)
    ):
        raise ValueError("FAT allocation table is not canonical")

    def extract_chain(first: int, clusters: int, byte_count: int, label: str) -> bytes:
        cluster = first
        payload = bytearray()
        for index in range(clusters):
            if cluster != first + index:
                raise ValueError(f"{label} chain is not canonical")
            offset = cluster_offset(cluster)
            payload += image[offset : offset + CLUSTER_BYTES]
            cluster = get_fat16(fat, cluster)
        if cluster != END_OF_CHAIN:
            raise ValueError("invalid FAT end-of-chain marker")
        if any(payload[byte_count:]):
            raise ValueError(f"{label} has nonzero cluster padding")
        return bytes(payload[:byte_count])

    efi = extract_chain(4, file_clusters, size, "UEFI fallback executable")
    mount_manifest = (
        extract_chain(
            manifest_cluster,
            manifest_clusters,
            manifest_size,
            "boot mount manifest",
        )
        if manifest_entry is not None
        else None
    )
    first_unused_cluster = 4 + file_clusters + manifest_clusters
    if first_unused_cluster <= MAX_DATA_CLUSTER and any(
        image[cluster_offset(first_unused_cluster) :]
    ):
        raise ValueError("unused FAT16 data clusters are not zero")
    return efi, mount_manifest


def extract(image: bytes, boot_name: bytes) -> bytes:
    """Validate the complete canonical FAT16 tree and return the EFI payload."""
    return extract_files(image, boot_name)[0]


def extract_mount_manifest(image: bytes, boot_name: bytes) -> bytes | None:
    """Validate the complete canonical tree and return its optional BMNT payload."""
    return extract_files(image, boot_name)[1]


def verify(
    image: bytes,
    boot_name: bytes,
    expected_payload: bytes,
    expected_manifest: bytes | None = None,
) -> None:
    """Require the complete canonical tree and exact boot payloads."""
    if extract_files(image, boot_name) != (expected_payload, expected_manifest):
        raise ValueError("round-trip verification did not reproduce the boot payloads")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--efi", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--verify", action="store_true", help="verify an existing image only"
    )
    args = parser.parse_args()
    boot_name = BOOT_NAMES[args.arch]
    try:
        efi = args.efi.read_bytes()
        mount_manifest = args.manifest.read_bytes()
        if args.verify:
            image = args.output.read_bytes()
        else:
            image = build(efi, boot_name, mount_manifest)
        verify(image, boot_name, efi, mount_manifest)
        if not args.verify:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(image)
        print(
            f"FAT16 {args.arch}: {len(efi)}-byte EFI, "
            f"{len(image)}-byte image -> {args.output}"
        )
        return 0
    except (OSError, ValueError) as error:
        print(f"mkfat: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

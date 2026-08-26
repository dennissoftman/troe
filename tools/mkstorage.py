#!/usr/bin/env python3
"""Create the deterministic BMNT policy and GPT/ext4 QEMU storage fixture."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import uuid
import zlib
from dataclasses import dataclass
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

# The formatter is part of the on-media format contract. Updating this pin
# requires regenerating the fixture and reviewing every check in verify_ext4().
PINNED_E2FSPROGS_VERSION = "1.47.4"
PINNED_E2FSPROGS_DATE = "6-Mar-2025"
PINNED_E2FSPROGS_OUTPUT = {
    "mke2fs": (
        f"mke2fs {PINNED_E2FSPROGS_VERSION} ({PINNED_E2FSPROGS_DATE})",
        f"Using EXT2FS Library version {PINNED_E2FSPROGS_VERSION}",
    ),
    "e2fsck": (
        f"e2fsck {PINNED_E2FSPROGS_VERSION} ({PINNED_E2FSPROGS_DATE})",
        (
            f"Using EXT2FS Library version {PINNED_E2FSPROGS_VERSION}, "
            f"{PINNED_E2FSPROGS_DATE}"
        ),
    ),
}

EXT4_BLOCK_BYTES = 4096
EXT4_INODE_BYTES = 256
EXT4_GROUP_DESCRIPTOR_BYTES = 32
EXT4_BLOCKS_PER_GROUP = 32_768
EXT4_INODES_PER_GROUP = 4096
EXT4_FIRST_NON_RESERVED_INODE = 11
EXT4_ROOT_INODE = 2
EXT4_JOURNAL_INODE = 8
EXT4_EXTENTS_FLAG = 0x0008_0000
EXT4_EXTENT_MAGIC = 0xF30A
EXT4_COMPAT_FEATURES = 0x0000_0004 | 0x0000_0008
EXT4_INCOMPAT_FEATURES = 0x0000_0002 | 0x0000_0040
EXT4_RO_COMPAT_FEATURES = 0x0000_0001 | 0x0000_0002 | 0x0000_0040 | 0x0000_0400
EXT4_DIRECTORY_TAIL_BYTES = 12
EXT4_MAX_GROUPS = 32
EXT4_MAX_ACTIVE_INODES = 64
EXT4_MAX_DIRECTORY_BLOCKS = 256
EXT4_MAX_DIRECTORY_ENTRIES = 4096
EXT4_MAX_FILE_BYTES = 1024 * 1024
EXT4_MAX_NAME_BYTES = 64
CRC32C_POLYNOMIAL = 0x82F6_3B78

TXSLOT_TOTAL_SECTORS = 4_096
TXSLOT_PARTITION_START = 2_048
TXSLOT_PARTITION_SECTORS = 4
TXSLOT_PARTITION_END = TXSLOT_PARTITION_START + TXSLOT_PARTITION_SECTORS - 1
TXSLOT_BACKUP_HEADER_LBA = TXSLOT_TOTAL_SECTORS - 1
TXSLOT_BACKUP_ARRAY_LBA = TXSLOT_BACKUP_HEADER_LBA - GPT_ARRAY_SECTORS
TXSLOT_LAST_USABLE_LBA = TXSLOT_BACKUP_ARRAY_LBA - 1
TXSLOT_DISK_GUID = bytes.fromhex("76543210fedcba9889abcdef01234567")
TXSLOT_PARTITION_GUID = bytes.fromhex("67452301efcdab8998badcfe10325476")
TXSLOT_TYPE_GUID = bytes.fromhex("8e5f0f3f1bde4fcbbf3d5d8a7ec96a21")
STATEFS_DISK_GUID = bytes.fromhex("112233445566778899aabbccddeeff00")
STATEFS_PARTITION_GUID = bytes.fromhex("2233445566778899aabbccddeeff0011")
STATEFS_TYPE_GUID = bytes.fromhex("33445566778899aabbccddeeff001122")

BMNT_HEADER_BYTES = 64
BMNT_RECORD_BYTES = 96
BMNT_CHECKSUM_OFFSET = 20
BMNT_MAX_BYTES = 4 * 1024
BMNT_MAX_ENTRIES = 16
BMNT_MAX_NAME_BYTES = 32
PRGN_BYTES = 80
PRGN_CHECKSUM_OFFSET = 20


@dataclass(frozen=True)
class MountSpec:
    """One canonical source entry for a BMNT `/vol/<name>` mount."""

    name: str
    selector: str
    filesystem: str
    access: str
    availability: str
    disk_guid: bytes
    partition_guid: bytes
    filesystem_identity: bytes
    activation: str = "auto"


def default_mount_specs() -> tuple[MountSpec, ...]:
    """Return the deterministic QEMU root policy used without a source table."""
    return (
        MountSpec(
            name="root",
            selector="gpt",
            filesystem="ext4-v1",
            access="read-write",
            availability="required",
            disk_guid=DISK_GUID,
            partition_guid=PARTITION_GUID,
            filesystem_identity=FILESYSTEM_UUID,
        ),
    )


def _canonical_uuid(value: object, label: str, *, gpt: bool) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a canonical UUID string")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as error:
        raise ValueError(f"{label} must be a canonical UUID string") from error
    if str(parsed) != value.lower() or parsed.int == 0:
        raise ValueError(f"{label} must be a canonical nonzero UUID string")
    return parsed.bytes_le if gpt else parsed.bytes


def _required_string(entry: dict[str, object], key: str, index: int) -> str:
    value = entry.get(key)
    if not isinstance(value, str):
        raise ValueError(f"volume {index} field {key!r} must be a string")
    return value


def _validated_mount_specs(entries: object) -> tuple[MountSpec, ...]:
    if not isinstance(entries, (list, tuple)) or not entries:
        raise ValueError("volume table must contain at least one [[volumes]] entry")
    if len(entries) > BMNT_MAX_ENTRIES:
        raise ValueError(f"volume table exceeds the {BMNT_MAX_ENTRIES}-entry limit")

    retained: list[MountSpec] = []
    for index, raw in enumerate(entries):
        if isinstance(raw, MountSpec):
            spec = raw
        elif isinstance(raw, dict):
            name = _required_string(raw, "name", index)
            selector = _required_string(raw, "selector", index)
            filesystem = _required_string(raw, "filesystem", index)
            access = _required_string(raw, "access", index)
            availability = _required_string(raw, "availability", index)
            activation = _required_string(raw, "activation", index)
            common = {
                "name",
                "selector",
                "filesystem",
                "access",
                "availability",
                "activation",
            }
            if selector == "gpt" and filesystem == "ext4-v1":
                expected = common | {"disk_guid", "partition_guid", "filesystem_uuid"}
                disk_guid = _canonical_uuid(raw.get("disk_guid"), "disk_guid", gpt=True)
                partition_guid = _canonical_uuid(
                    raw.get("partition_guid"), "partition_guid", gpt=True
                )
                filesystem_identity = _canonical_uuid(
                    raw.get("filesystem_uuid"), "filesystem_uuid", gpt=False
                )
            elif selector == "whole-device" and filesystem == "ext4-v1":
                expected = common | {"filesystem_uuid"}
                disk_guid = bytes(16)
                partition_guid = bytes(16)
                filesystem_identity = _canonical_uuid(
                    raw.get("filesystem_uuid"), "filesystem_uuid", gpt=False
                )
            elif selector == "gpt" and filesystem == "fat32":
                expected = common | {"disk_guid", "partition_guid", "volume_id"}
                disk_guid = _canonical_uuid(raw.get("disk_guid"), "disk_guid", gpt=True)
                partition_guid = _canonical_uuid(
                    raw.get("partition_guid"), "partition_guid", gpt=True
                )
                volume_id = raw.get("volume_id")
                if (
                    not isinstance(volume_id, str)
                    or re.fullmatch(r"[0-9a-fA-F]{8}", volume_id) is None
                ):
                    raise ValueError(
                        f"volume {name!r} FAT32 volume_id must contain exactly eight hex digits"
                    )
                numeric_volume_id = int(volume_id, 16)
                if numeric_volume_id == 0:
                    raise ValueError(f"volume {name!r} FAT32 volume_id must be nonzero")
                filesystem_identity = numeric_volume_id.to_bytes(4, "little") + bytes(
                    12
                )
            else:
                raise ValueError(
                    f"volume {name!r} has unsupported selector/filesystem combination"
                )
            if set(raw) != expected:
                missing = sorted(expected - set(raw))
                extra = sorted(set(raw) - expected)
                raise ValueError(
                    f"volume {name!r} fields do not match its profile; missing={missing} extra={extra}"
                )
            spec = MountSpec(
                name=name,
                selector=selector,
                filesystem=filesystem,
                access=access,
                availability=availability,
                disk_guid=disk_guid,
                partition_guid=partition_guid,
                filesystem_identity=filesystem_identity,
                activation=activation,
            )
        else:
            raise ValueError(f"volume {index} must be a TOML table")

        name_bytes = spec.name.encode("utf-8")
        if (
            not 1 <= len(name_bytes) <= BMNT_MAX_NAME_BYTES
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", spec.name) is None
        ):
            raise ValueError(
                f"volume name {spec.name!r} must use 1-{BMNT_MAX_NAME_BYTES} lowercase ASCII name bytes"
            )
        if spec.filesystem not in {"ext4-v1", "fat32"}:
            raise ValueError(f"volume {spec.name!r} has an unsupported filesystem")
        if spec.access not in {"read-only", "read-write"}:
            raise ValueError(f"volume {spec.name!r} has an invalid access policy")
        if spec.availability not in {"optional", "required"}:
            raise ValueError(f"volume {spec.name!r} has an invalid availability policy")
        if spec.activation not in {"auto", "manual"}:
            raise ValueError(f"volume {spec.name!r} has an invalid activation policy")
        if spec.selector not in {"gpt", "whole-device"}:
            raise ValueError(f"volume {spec.name!r} has an invalid selector")
        if spec.selector == "whole-device" and spec.filesystem != "ext4-v1":
            raise ValueError("whole-device selectors currently support only ext4-v1")
        if spec.name == "root" and spec.filesystem != "ext4-v1":
            raise ValueError("the reserved root volume must use ext4-v1")
        if spec.name == "root" and spec.activation != "auto":
            raise ValueError("the reserved root volume must activate automatically")
        if spec.name == "boot" and spec.filesystem != "fat32":
            raise ValueError("the reserved boot volume must use fat32")
        if any(
            len(identifier) != 16
            for identifier in (
                spec.disk_guid,
                spec.partition_guid,
                spec.filesystem_identity,
            )
        ):
            raise ValueError(f"volume {spec.name!r} has an invalid stable identifier")
        if not any(spec.filesystem_identity):
            raise ValueError(f"volume {spec.name!r} has a zero filesystem identity")
        if spec.selector == "gpt" and (
            not any(spec.disk_guid) or not any(spec.partition_guid)
        ):
            raise ValueError(f"volume {spec.name!r} has a zero GPT identity")
        if spec.selector == "whole-device" and (
            any(spec.disk_guid) or any(spec.partition_guid)
        ):
            raise ValueError(
                f"volume {spec.name!r} has GPT fields on a whole-device selector"
            )
        if spec.filesystem == "fat32" and any(spec.filesystem_identity[4:]):
            raise ValueError(f"volume {spec.name!r} has a noncanonical FAT32 identity")
        retained.append(spec)

    retained.sort(key=lambda entry: entry.name)
    for previous, current in zip(retained, retained[1:], strict=False):
        if previous.name == current.name:
            raise ValueError(f"duplicate volume name {current.name!r}")
    selectors: set[tuple[object, ...]] = set()
    for spec in retained:
        selector_key = (
            spec.selector,
            spec.filesystem,
            spec.disk_guid,
            spec.partition_guid,
            spec.filesystem_identity,
        )
        if selector_key in selectors:
            raise ValueError(f"volume {spec.name!r} duplicates another stable selector")
        selectors.add(selector_key)
    string_bytes = sum(len(spec.name.encode("utf-8")) for spec in retained)
    encoded_bytes = BMNT_HEADER_BYTES + len(retained) * BMNT_RECORD_BYTES + string_bytes
    if encoded_bytes > BMNT_MAX_BYTES:
        raise ValueError(
            f"compiled volume table exceeds the {BMNT_MAX_BYTES}-byte limit"
        )
    return tuple(retained)


def load_volume_table(path: Path) -> tuple[MountSpec, ...]:
    """Parse and strictly validate one human-editable volume table."""
    try:
        with path.open("rb") as source:
            document = tomllib.load(source)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"invalid volume table TOML: {error}") from error
    if (
        set(document) != {"version", "volumes"}
        or type(document.get("version")) is not int
        or document.get("version") != 1
    ):
        raise ValueError(
            "volume table must contain only version=1 and [[volumes]] entries"
        )
    return _validated_mount_specs(document["volumes"])


def require_fixture_root(entries: tuple[MountSpec, ...]) -> None:
    """Require a table used with `--output` to select the generated root disk."""
    root = [entry for entry in entries if entry.name == "root"]
    if root != list(default_mount_specs()):
        raise ValueError(
            "a generated QEMU root fixture requires the canonical root entry; "
            "custom entries may be added alongside it"
        )


def build_manifest(entries: object | None = None) -> bytes:
    """Compile canonical mount specifications into one checksummed BMNT v1 image."""
    specs = _validated_mount_specs(
        default_mount_specs() if entries is None else entries
    )
    names = [spec.name.encode("utf-8") for spec in specs]
    total_bytes = (
        BMNT_HEADER_BYTES
        + len(specs) * BMNT_RECORD_BYTES
        + sum(len(name) for name in names)
    )
    image = bytearray(total_bytes)
    image[:8] = b"BMNTv1\0\0"
    struct.pack_into(
        "<HHHHI", image, 8, 1, 1, BMNT_HEADER_BYTES, BMNT_RECORD_BYTES, total_bytes
    )
    struct.pack_into("<H", image, 24, len(specs))
    struct.pack_into("<I", image, 28, sum(len(name) for name in names))

    string_offset = 0
    string_start = BMNT_HEADER_BYTES + len(specs) * BMNT_RECORD_BYTES
    for index, (spec, name) in enumerate(zip(specs, names, strict=True)):
        start = BMNT_HEADER_BYTES + index * BMNT_RECORD_BYTES
        record = memoryview(image)[start : start + BMNT_RECORD_BYTES]
        record[0] = {"whole-device": 1, "gpt": 2}[spec.selector]
        record[1] = {"fat32": 1, "ext4-v1": 2}[spec.filesystem]
        record[2] = {"read-only": 1, "read-write": 2}[spec.access]
        record[3] = {"optional": 1, "required": 2}[spec.availability]
        record[10] = {"auto": 1, "manual": 2}[spec.activation]
        struct.pack_into("<IH", record, 4, string_offset, len(name))
        record[16:32] = spec.disk_guid
        record[32:48] = spec.partition_guid
        record[48:64] = spec.filesystem_identity
        image[
            string_start + string_offset : string_start + string_offset + len(name)
        ] = name
        string_offset += len(name)

    checksum_image = bytearray(image)
    checksum_image[BMNT_CHECKSUM_OFFSET : BMNT_CHECKSUM_OFFSET + 4] = b"\0" * 4
    struct.pack_into("<I", image, BMNT_CHECKSUM_OFFSET, zlib.crc32(checksum_image))
    return bytes(image)


def build_region_selector(
    disk_guid: bytes, partition_guid: bytes, type_guid: bytes
) -> bytes:
    """Encode one exact GPT persistence-region selector."""
    image = bytearray(PRGN_BYTES)
    image[:8] = b"PRGNv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, PRGN_BYTES, 0, PRGN_BYTES)
    image[24:40] = disk_guid
    image[40:56] = partition_guid
    image[56:72] = type_guid
    checked = bytearray(image)
    checked[PRGN_CHECKSUM_OFFSET : PRGN_CHECKSUM_OFFSET + 4] = b"\0" * 4
    struct.pack_into("<I", image, PRGN_CHECKSUM_OFFSET, zlib.crc32(checked))
    return bytes(image)


def gpt_header(
    current_lba: int,
    backup_lba: int,
    entry_lba: int,
    entry_crc: int,
    first_usable_lba: int,
    last_usable_lba: int,
    disk_guid: bytes,
) -> bytes:
    """Encode one canonical 92-byte GPT 1.0 header in a zeroed sector."""
    sector = bytearray(SECTOR_BYTES)
    sector[:8] = b"EFI PART"
    struct.pack_into("<III", sector, 8, 0x0001_0000, 92, 0)
    struct.pack_into(
        "<QQQQ", sector, 24, current_lba, backup_lba, first_usable_lba, last_usable_lba
    )
    sector[56:72] = disk_guid
    struct.pack_into(
        "<QIII", sector, 72, entry_lba, GPT_ENTRY_COUNT, GPT_ENTRY_BYTES, entry_crc
    )
    header = bytearray(sector[:92])
    header[16:20] = b"\0" * 4
    struct.pack_into("<I", sector, 16, zlib.crc32(header))
    return bytes(sector)


def protective_mbr(total_sectors: int) -> bytes:
    """Encode the UEFI 2.11 canonical GPT protective MBR sector."""
    if not 2 <= total_sectors <= 0x1_0000_0000:
        raise ValueError("disk sector count is outside protective-MBR bounds")
    sector = bytearray(SECTOR_BYTES)
    sector[446 + 1 : 446 + 4] = b"\x00\x02\x00"
    sector[446 + 4] = 0xEE
    sector[446 + 5 : 446 + 8] = b"\xff\xff\xff"
    struct.pack_into("<II", sector, 446 + 8, 1, min(total_sectors - 1, 0xFFFF_FFFF))
    sector[510:512] = b"\x55\xaa"
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
    entries[56 : 56 + len(name)] = name
    entry_crc = zlib.crc32(entries)

    image = bytearray(TOTAL_SECTORS * SECTOR_BYTES)
    image[:SECTOR_BYTES] = protective_mbr(TOTAL_SECTORS)

    image[SECTOR_BYTES : 2 * SECTOR_BYTES] = gpt_header(
        1, BACKUP_HEADER_LBA, 2, entry_crc, FIRST_USABLE_LBA, LAST_USABLE_LBA, DISK_GUID
    )
    primary_entries = 2 * SECTOR_BYTES
    image[primary_entries : primary_entries + GPT_ARRAY_BYTES] = entries
    partition_offset = PARTITION_START * SECTOR_BYTES
    image[partition_offset : partition_offset + len(filesystem)] = filesystem
    backup_entries = BACKUP_ARRAY_LBA * SECTOR_BYTES
    image[backup_entries : backup_entries + GPT_ARRAY_BYTES] = entries
    backup_header = BACKUP_HEADER_LBA * SECTOR_BYTES
    image[backup_header : backup_header + SECTOR_BYTES] = gpt_header(
        BACKUP_HEADER_LBA,
        1,
        BACKUP_ARRAY_LBA,
        entry_crc,
        FIRST_USABLE_LBA,
        LAST_USABLE_LBA,
        DISK_GUID,
    )
    return bytes(image)


def build_small_gpt(
    disk_guid: bytes, partition_guid: bytes, type_guid: bytes, name_text: str
) -> bytes:
    """Create an empty four-block TXSLOT partition inside strict GPT metadata."""
    entries = bytearray(GPT_ARRAY_BYTES)
    entries[:16] = type_guid
    entries[16:32] = partition_guid
    struct.pack_into(
        "<QQQ", entries, 32, TXSLOT_PARTITION_START, TXSLOT_PARTITION_END, 0
    )
    name = name_text.encode("utf-16-le")
    entries[56 : 56 + len(name)] = name
    entry_crc = zlib.crc32(entries)

    image = bytearray(TXSLOT_TOTAL_SECTORS * SECTOR_BYTES)
    image[:SECTOR_BYTES] = protective_mbr(TXSLOT_TOTAL_SECTORS)
    image[SECTOR_BYTES : 2 * SECTOR_BYTES] = gpt_header(
        1,
        TXSLOT_BACKUP_HEADER_LBA,
        2,
        entry_crc,
        FIRST_USABLE_LBA,
        TXSLOT_LAST_USABLE_LBA,
        disk_guid,
    )
    image[2 * SECTOR_BYTES : 2 * SECTOR_BYTES + GPT_ARRAY_BYTES] = entries
    backup_entries = TXSLOT_BACKUP_ARRAY_LBA * SECTOR_BYTES
    image[backup_entries : backup_entries + GPT_ARRAY_BYTES] = entries
    backup_header = TXSLOT_BACKUP_HEADER_LBA * SECTOR_BYTES
    image[backup_header : backup_header + SECTOR_BYTES] = gpt_header(
        TXSLOT_BACKUP_HEADER_LBA,
        1,
        TXSLOT_BACKUP_ARRAY_LBA,
        entry_crc,
        FIRST_USABLE_LBA,
        TXSLOT_LAST_USABLE_LBA,
        disk_guid,
    )
    return bytes(image)


def _crc32c(seed: int, data: bytes | bytearray | memoryview) -> int:
    """Compute the non-final-xor CRC32C form used by ext4 metadata_csum."""
    checksum = seed
    for value in data:
        checksum ^= value
        for _ in range(8):
            checksum = (checksum >> 1) ^ (CRC32C_POLYNOMIAL & -(checksum & 1))
    return checksum & 0xFFFF_FFFF


def _read_integer(data: bytes | bytearray | memoryview, offset: int, width: int) -> int:
    """Read one bounded little-endian integer from an ext4 structure."""
    end = offset + width
    if offset < 0 or width not in (1, 2, 4) or end > len(data):
        raise ValueError("truncated ext4 metadata field")
    return int.from_bytes(data[offset:end], "little")


def _bitmap_bit(bitmap: bytes | bytearray | memoryview, bit: int) -> bool:
    """Return one bounded ext4 allocation-bitmap bit."""
    if bit < 0 or bit >= len(bitmap) * 8:
        raise ValueError("ext4 bitmap index is outside the bitmap block")
    return bool(bitmap[bit // 8] & (1 << (bit % 8)))


def _verify_e2fsprogs_version_output(name: str, output: str) -> None:
    """Require the exact formatter/checker banner committed by ADR 0017."""
    expected = PINNED_E2FSPROGS_OUTPUT.get(name)
    if expected is None:
        raise ValueError(f"unsupported e2fsprogs tool name: {name}")
    actual = tuple(line.strip() for line in output.splitlines() if line.strip())
    if actual != expected:
        rendered = " | ".join(actual) if actual else "<empty output>"
        raise ValueError(
            f"{name} must be e2fsprogs {PINNED_E2FSPROGS_VERSION}; got {rendered}"
        )


def require_pinned_e2fsprogs() -> tuple[str, str]:
    """Resolve and version-check the exact e2fsprogs tools used by the builder."""
    resolved: dict[str, str] = {}
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    for name in ("mke2fs", "e2fsck"):
        executable = shutil.which(name)
        if executable is None:
            raise FileNotFoundError(
                "pinned mke2fs and e2fsck are required for the QEMU storage fixture"
            )
        result = subprocess.run(
            [executable, "-V"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if result.returncode != 0:
            raise ValueError(f"{name} -V failed with status {result.returncode}")
        _verify_e2fsprogs_version_output(name, result.stdout + result.stderr)
        resolved[name] = executable
    return resolved["mke2fs"], resolved["e2fsck"]


@dataclass(frozen=True)
class _Ext4Extent:
    logical: int
    physical: int
    blocks: int
    unwritten: bool


@dataclass(frozen=True)
class _Ext4Inode:
    number: int
    generation: int
    kind: str
    size: int
    extents: tuple[_Ext4Extent, ...]


@dataclass(frozen=True)
class _Ext4Group:
    block_bitmap: int
    inode_bitmap: int
    inode_table: int
    free_blocks: int
    free_inodes: int
    used_directories: int


class _Ext4ProfileVerifier:
    """Bounded, dependency-free decoder for the generated ext4 v1 fixture."""

    def __init__(self, image: bytes, content: bytes | None) -> None:
        self.image = memoryview(image)
        self.content = content
        self.blocks = 0
        self.inodes = 0
        self.blocks_per_group = 0
        self.inodes_per_group = 0
        self.groups = 0
        self.free_blocks = 0
        self.free_inodes = 0
        self.checksum_seed = 0
        self.group_records: list[_Ext4Group] = []
        self.allocated_blocks: set[int] = set()
        self.allocated_inodes: set[int] = set()
        self.referenced_blocks: set[int] = set()
        self.inode_records: dict[int, _Ext4Inode] = {}

    def verify(self) -> None:
        """Validate all fixed geometry, metadata, allocation, and tree invariants."""
        self._verify_superblock()
        self._verify_groups_and_bitmaps()
        self._verify_inodes_and_extents()
        if self.allocated_blocks != self.referenced_blocks:
            missing = sorted(self.referenced_blocks - self.allocated_blocks)
            extra = sorted(self.allocated_blocks - self.referenced_blocks)
            raise ValueError(
                "ext4 block bitmap does not exactly describe metadata and extents "
                f"(missing={missing[:4]}, extra={extra[:4]})"
            )
        self._verify_journal()
        self._verify_exact_tree()

    def _slice(self, offset: int, length: int) -> memoryview:
        end = offset + length
        if offset < 0 or length < 0 or end > len(self.image):
            raise ValueError("ext4 image is truncated")
        return self.image[offset:end]

    def _block(self, number: int) -> memoryview:
        if number < 0 or number >= self.blocks:
            raise ValueError("ext4 metadata references a block outside the volume")
        return self._slice(number * EXT4_BLOCK_BYTES, EXT4_BLOCK_BYTES)

    def _verify_superblock(self) -> None:
        expected_bytes = PARTITION_SECTORS * SECTOR_BYTES
        if len(self.image) != expected_bytes:
            raise ValueError("ext4 fixture has the wrong exact partition length")
        superblock = self._slice(1024, 1024)
        exact_fields = (
            (56, 2, 0xEF53, "magic"),
            (58, 2, 1, "clean state"),
            (72, 4, 0, "Linux creator OS"),
            (76, 4, 1, "dynamic revision"),
            (84, 4, EXT4_FIRST_NON_RESERVED_INODE, "first non-reserved inode"),
            (88, 2, EXT4_INODE_BYTES, "inode size"),
            (92, 4, EXT4_COMPAT_FEATURES, "compatible features"),
            (96, 4, EXT4_INCOMPAT_FEATURES, "incompatible features"),
            (100, 4, EXT4_RO_COMPAT_FEATURES, "read-only-compatible features"),
            (206, 2, 0, "reserved GDT blocks"),
            (224, 4, EXT4_JOURNAL_INODE, "internal journal inode"),
            (228, 4, 0, "external journal device"),
            (232, 4, 0, "orphan-list head"),
            (260, 4, 0, "meta_bg origin"),
            (336, 4, 0, "high block count"),
            (340, 4, 0, "high reserved-block count"),
            (344, 4, 0, "high free-block count"),
            (348, 2, 32, "minimum extra inode size"),
            (350, 2, 32, "desired extra inode size"),
            (373, 1, 1, "CRC32C checksum type"),
            (624, 4, 0, "explicit checksum seed"),
        )
        for offset, width, expected, label in exact_fields:
            if _read_integer(superblock, offset, width) != expected:
                raise ValueError(f"ext4 {label} is outside the constrained profile")
        if _read_integer(superblock, 254, 2) not in (0, EXT4_GROUP_DESCRIPTOR_BYTES):
            raise ValueError("ext4 group descriptors are not 32 bytes")
        if superblock[104:120].tobytes() != FILESYSTEM_UUID:
            raise ValueError("ext4 filesystem UUID does not match BMNT policy")
        if superblock[120:136].tobytes() != b"TROE_ROOT" + b"\0" * 7:
            raise ValueError("ext4 volume label is not canonical")
        if any(superblock[208:224]):
            raise ValueError("ext4 profile requires an internal, not external, journal")
        if superblock[236:252].tobytes() != FILESYSTEM_UUID:
            raise ValueError("ext4 directory hash seed is not deterministic")
        stored_checksum = _read_integer(superblock, 1020, 4)
        if stored_checksum != _crc32c(0xFFFF_FFFF, superblock[:1020]):
            raise ValueError("ext4 superblock checksum mismatch")

        self.inodes = _read_integer(superblock, 0, 4)
        self.blocks = _read_integer(superblock, 4, 4)
        self.free_blocks = _read_integer(superblock, 12, 4)
        self.free_inodes = _read_integer(superblock, 16, 4)
        self.blocks_per_group = _read_integer(superblock, 32, 4)
        clusters_per_group = _read_integer(superblock, 36, 4)
        self.inodes_per_group = _read_integer(superblock, 40, 4)
        if (
            _read_integer(superblock, 20, 4) != 0
            or _read_integer(superblock, 24, 4) != 2
            or _read_integer(superblock, 28, 4) != 2
            or self.blocks != expected_bytes // EXT4_BLOCK_BYTES
            or self.inodes != EXT4_INODES_PER_GROUP
            or self.blocks_per_group != EXT4_BLOCKS_PER_GROUP
            or clusters_per_group != self.blocks_per_group
            or self.inodes_per_group != EXT4_INODES_PER_GROUP
        ):
            raise ValueError("ext4 formatter produced unexpected fixed geometry")
        self.groups = (self.blocks + self.blocks_per_group - 1) // self.blocks_per_group
        inode_groups = (
            self.inodes + self.inodes_per_group - 1
        ) // self.inodes_per_group
        if (
            self.groups == 0
            or self.groups != inode_groups
            or self.groups > EXT4_MAX_GROUPS
        ):
            raise ValueError(
                "ext4 block-group count is outside the constrained profile"
            )
        if self.groups != 1:
            raise ValueError(
                "the fixed 16 MiB ext4 fixture must contain exactly one group"
            )
        self.checksum_seed = _crc32c(0xFFFF_FFFF, FILESYSTEM_UUID)

    def _verify_groups_and_bitmaps(self) -> None:
        descriptor_table = self._block(1)
        inode_table_blocks = (
            self.inodes_per_group * EXT4_INODE_BYTES + EXT4_BLOCK_BYTES - 1
        ) // EXT4_BLOCK_BYTES
        self.referenced_blocks.update((0, 1))
        group_free_blocks = 0
        group_free_inodes = 0
        for group in range(self.groups):
            offset = group * EXT4_GROUP_DESCRIPTOR_BYTES
            descriptor = descriptor_table[offset : offset + EXT4_GROUP_DESCRIPTOR_BYTES]
            if len(descriptor) != EXT4_GROUP_DESCRIPTOR_BYTES:
                raise ValueError("truncated ext4 group descriptor")
            checked = bytearray(descriptor)
            stored_descriptor_checksum = _read_integer(checked, 30, 2)
            checked[30:32] = b"\0\0"
            calculated = _crc32c(
                _crc32c(self.checksum_seed, group.to_bytes(4, "little")), checked
            )
            if stored_descriptor_checksum != calculated & 0xFFFF:
                raise ValueError("ext4 group-descriptor checksum mismatch")

            block_bitmap_number = _read_integer(descriptor, 0, 4)
            inode_bitmap_number = _read_integer(descriptor, 4, 4)
            inode_table_number = _read_integer(descriptor, 8, 4)
            free_blocks = _read_integer(descriptor, 12, 2)
            free_inodes = _read_integer(descriptor, 14, 2)
            used_directories = _read_integer(descriptor, 16, 2)
            flags = _read_integer(descriptor, 18, 2)
            if flags != 0x0004 or _read_integer(descriptor, 20, 4) != 0:
                raise ValueError(
                    "ext4 group is lazy, uninitialized, or uses an exclude bitmap"
                )
            group_start = group * self.blocks_per_group
            group_end = min(group_start + self.blocks_per_group, self.blocks)
            if not (
                group_start <= block_bitmap_number < group_end
                and group_start <= inode_bitmap_number < group_end
                and group_start <= inode_table_number
                and inode_table_number + inode_table_blocks <= group_end
            ):
                raise ValueError("ext4 group metadata is outside its owning group")
            metadata = {
                block_bitmap_number,
                inode_bitmap_number,
                *range(inode_table_number, inode_table_number + inode_table_blocks),
            }
            if len(metadata) != inode_table_blocks + 2:
                raise ValueError("ext4 group metadata blocks overlap")
            if self.referenced_blocks.intersection(metadata):
                raise ValueError("ext4 group metadata overlaps the superblock or GDT")
            self.referenced_blocks.update(metadata)

            block_bitmap = self._block(block_bitmap_number)
            inode_bitmap = self._block(inode_bitmap_number)
            stored_block_checksum = _read_integer(descriptor, 24, 2)
            stored_inode_checksum = _read_integer(descriptor, 26, 2)
            block_bitmap_bytes = self.blocks_per_group // 8
            inode_bitmap_bytes = self.inodes_per_group // 8
            if stored_block_checksum != (
                _crc32c(self.checksum_seed, block_bitmap[:block_bitmap_bytes]) & 0xFFFF
            ):
                raise ValueError("ext4 block-bitmap checksum mismatch")
            if stored_inode_checksum != (
                _crc32c(self.checksum_seed, inode_bitmap[:inode_bitmap_bytes]) & 0xFFFF
            ):
                raise ValueError("ext4 inode-bitmap checksum mismatch")
            if any(value != 0xFF for value in inode_bitmap[inode_bitmap_bytes:]):
                raise ValueError("ext4 inode-bitmap block has noncanonical padding")

            blocks_in_group = group_end - group_start
            actual_free_blocks = 0
            for bit in range(self.blocks_per_group):
                allocated = _bitmap_bit(block_bitmap, bit)
                if bit < blocks_in_group:
                    block = group_start + bit
                    if allocated:
                        self.allocated_blocks.add(block)
                    else:
                        actual_free_blocks += 1
                elif not allocated:
                    raise ValueError(
                        "ext4 block bitmap leaves an out-of-range bit free"
                    )
            first_inode = group * self.inodes_per_group + 1
            inodes_in_group = min(
                self.inodes_per_group, self.inodes - group * self.inodes_per_group
            )
            actual_free_inodes = 0
            for bit in range(self.inodes_per_group):
                allocated = _bitmap_bit(inode_bitmap, bit)
                if bit < inodes_in_group:
                    inode = first_inode + bit
                    if allocated:
                        self.allocated_inodes.add(inode)
                    else:
                        actual_free_inodes += 1
                elif not allocated:
                    raise ValueError(
                        "ext4 inode bitmap leaves an out-of-range bit free"
                    )
            trailing_unused = 0
            for bit in range(inodes_in_group - 1, -1, -1):
                if _bitmap_bit(inode_bitmap, bit):
                    break
                trailing_unused += 1
            if (
                actual_free_blocks != free_blocks
                or actual_free_inodes != free_inodes
                or trailing_unused != _read_integer(descriptor, 28, 2)
            ):
                raise ValueError("ext4 group counters disagree with allocation bitmaps")
            group_free_blocks += free_blocks
            group_free_inodes += free_inodes
            self.group_records.append(
                _Ext4Group(
                    block_bitmap_number,
                    inode_bitmap_number,
                    inode_table_number,
                    free_blocks,
                    free_inodes,
                    used_directories,
                )
            )
        if (
            group_free_blocks != self.free_blocks
            or group_free_inodes != self.free_inodes
        ):
            raise ValueError(
                "ext4 superblock free counters disagree with group descriptors"
            )
        if len(self.allocated_blocks) != self.blocks - self.free_blocks:
            raise ValueError("ext4 global block count disagrees with block bitmaps")
        if len(self.allocated_inodes) != self.inodes - self.free_inodes:
            raise ValueError("ext4 global inode count disagrees with inode bitmaps")
        required_reserved = set(range(1, EXT4_FIRST_NON_RESERVED_INODE))
        if not required_reserved.issubset(self.allocated_inodes):
            raise ValueError("ext4 reserved inode range is not fully allocated")

    def _raw_inode(self, number: int) -> memoryview:
        zero_based = number - 1
        group = zero_based // self.inodes_per_group
        index = zero_based % self.inodes_per_group
        table = self.group_records[group].inode_table
        offset = table * EXT4_BLOCK_BYTES + index * EXT4_INODE_BYTES
        return self._slice(offset, EXT4_INODE_BYTES)

    def _verify_inode_checksum(self, number: int, raw: memoryview) -> None:
        generation = _read_integer(raw, 100, 4)
        extra_isize = _read_integer(raw, 128, 2)
        checked = bytearray(raw)
        stored_low = _read_integer(checked, 124, 2)
        stored_high = _read_integer(checked, 130, 2)
        checked[124:126] = b"\0\0"
        checked[130:132] = b"\0\0"
        calculated = _crc32c(
            _crc32c(
                _crc32c(self.checksum_seed, number.to_bytes(4, "little")),
                generation.to_bytes(4, "little"),
            ),
            checked,
        )
        if stored_low != calculated & 0xFFFF:
            raise ValueError("ext4 inode checksum mismatch")
        if extra_isize >= 4 and stored_high != calculated >> 16:
            raise ValueError("ext4 inode high checksum mismatch")
        if extra_isize < 4 and stored_high != 0:
            raise ValueError("ext4 reserved inode has an out-of-range high checksum")

    def _parse_extents(
        self, raw: memoryview, kind: str, size: int
    ) -> tuple[_Ext4Extent, ...]:
        root = raw[40:100]
        if (
            _read_integer(root, 0, 2) != EXT4_EXTENT_MAGIC
            or _read_integer(root, 4, 2) != 4
            or _read_integer(root, 6, 2) != 0
            or _read_integer(root, 8, 4) != 0
        ):
            raise ValueError("ext4 inode does not use a depth-zero inline extent root")
        count = _read_integer(root, 2, 2)
        if count > 4:
            raise ValueError("ext4 inode has too many inline extents")
        extents: list[_Ext4Extent] = []
        previous_end = 0
        file_blocks = (size + EXT4_BLOCK_BYTES - 1) // EXT4_BLOCK_BYTES
        for index in range(count):
            offset = 12 + index * 12
            logical = _read_integer(root, offset, 4)
            encoded_blocks = _read_integer(root, offset + 4, 2)
            physical_high = _read_integer(root, offset + 6, 2)
            physical = _read_integer(root, offset + 8, 4)
            unwritten = encoded_blocks > 0x8000
            blocks = encoded_blocks - 0x8000 if unwritten else encoded_blocks
            logical_end = logical + blocks
            physical_end = physical + blocks
            if (
                blocks == 0
                or physical_high != 0
                or physical == 0
                or physical_end > self.blocks
                or logical_end > file_blocks
                or (index != 0 and logical < previous_end)
                or (kind == "directory" and unwritten)
            ):
                raise ValueError("ext4 extent is outside the constrained profile")
            for block in range(physical, physical_end):
                if block in self.referenced_blocks:
                    raise ValueError("ext4 extent overlaps metadata or another extent")
                self.referenced_blocks.add(block)
            extents.append(_Ext4Extent(logical, physical, blocks, unwritten))
            previous_end = logical_end
        if kind == "directory":
            next_logical = 0
            for extent in extents:
                if extent.logical != next_logical:
                    raise ValueError("ext4 directory contains a hole")
                next_logical += extent.blocks
            if next_logical != file_blocks:
                raise ValueError("ext4 directory extents do not cover its exact size")
        return tuple(extents)

    def _verify_inodes_and_extents(self) -> None:
        fake_time = int(FAKE_TIME)
        directory_counts = [0] * self.groups
        for number in range(1, self.inodes + 1):
            raw = self._raw_inode(number)
            if number not in self.allocated_inodes:
                if any(raw):
                    raise ValueError("ext4 unallocated inode table entry is not zeroed")
                continue
            self._verify_inode_checksum(number, raw)
            mode_type = _read_integer(raw, 0, 2) & 0xF000
            if mode_type == 0:
                if number >= EXT4_FIRST_NON_RESERVED_INODE or number in (
                    EXT4_ROOT_INODE,
                    EXT4_JOURNAL_INODE,
                ):
                    raise ValueError(
                        "ext4 inode bitmap allocates an empty ordinary inode"
                    )
                continue
            kind = {0x4000: "directory", 0x8000: "file"}.get(mode_type)
            if kind is None:
                raise ValueError("ext4 image contains a symlink or special inode")
            if _read_integer(raw, 128, 2) != 32:
                raise ValueError("ext4 active inode has unexpected extra_isize")
            if _read_integer(raw, 26, 2) == 0:
                raise ValueError("ext4 active inode has no links")
            if _read_integer(raw, 32, 4) != EXT4_EXTENTS_FLAG:
                raise ValueError("ext4 active inode has unsupported flags")
            if _read_integer(raw, 104, 4) != 0 or _read_integer(raw, 118, 2) != 0:
                raise ValueError("ext4 image contains an ACL or external xattr block")
            if any(raw[160:]):
                raise ValueError("ext4 image contains an inline xattr payload")
            if _read_integer(raw, 20, 4) != 0:
                raise ValueError("ext4 image contains a deleted active inode")
            if any(
                _read_integer(raw, offset, 4) != fake_time
                for offset in (8, 12, 16, 144)
            ):
                raise ValueError("ext4 inode timestamps are not deterministic")
            size = _read_integer(raw, 4, 4) | (_read_integer(raw, 108, 4) << 32)
            if (
                kind == "file"
                and number != EXT4_JOURNAL_INODE
                and size > EXT4_MAX_FILE_BYTES
            ):
                raise ValueError(
                    "ext4 regular file exceeds the production mount ceiling"
                )
            if kind == "directory":
                if size == 0 or size % EXT4_BLOCK_BYTES:
                    raise ValueError("ext4 directory size is not block aligned")
                if size // EXT4_BLOCK_BYTES > EXT4_MAX_DIRECTORY_BLOCKS:
                    raise ValueError(
                        "ext4 directory exceeds the production mount ceiling"
                    )
                directory_counts[(number - 1) // self.inodes_per_group] += 1
            extents = self._parse_extents(raw, kind, size)
            extent_blocks = sum(extent.blocks for extent in extents)
            sectors = _read_integer(raw, 28, 4) | (_read_integer(raw, 116, 2) << 32)
            if sectors != extent_blocks * (EXT4_BLOCK_BYTES // SECTOR_BYTES):
                raise ValueError("ext4 inode block count disagrees with its extents")
            self.inode_records[number] = _Ext4Inode(
                number, _read_integer(raw, 100, 4), kind, size, extents
            )
        if len(self.inode_records) > EXT4_MAX_ACTIVE_INODES:
            raise ValueError("ext4 image exceeds the active-inode mount ceiling")
        for group, count in enumerate(directory_counts):
            if count != self.group_records[group].used_directories:
                raise ValueError("ext4 used-directory counter is inconsistent")

    @staticmethod
    def _mapped_block(inode: _Ext4Inode, logical: int) -> tuple[int, bool] | None:
        for extent in inode.extents:
            if extent.logical <= logical < extent.logical + extent.blocks:
                return extent.physical + logical - extent.logical, extent.unwritten
        return None

    def _verify_journal(self) -> None:
        journal = self.inode_records.get(EXT4_JOURNAL_INODE)
        if journal is None or journal.kind != "file" or journal.size == 0:
            raise ValueError("ext4 internal journal inode is missing")
        journal_blocks = (journal.size + EXT4_BLOCK_BYTES - 1) // EXT4_BLOCK_BYTES
        next_logical = 0
        for extent in journal.extents:
            if extent.logical != next_logical or extent.unwritten:
                raise ValueError(
                    "ext4 internal journal contains a hole or unwritten extent"
                )
            next_logical += extent.blocks
        if next_logical != journal_blocks:
            raise ValueError("ext4 internal journal extent map is incomplete")
        mapped = self._mapped_block(journal, 0)
        if mapped is None:
            raise ValueError("ext4 internal journal has no superblock")
        journal_superblock = self._block(mapped[0])
        if (
            int.from_bytes(journal_superblock[0:4], "big") != 0xC03B_3998
            or int.from_bytes(journal_superblock[4:8], "big") != 4
            or int.from_bytes(journal_superblock[12:16], "big") != EXT4_BLOCK_BYTES
            or int.from_bytes(journal_superblock[16:20], "big") != journal_blocks
            or journal_superblock[48:64].tobytes() != FILESYSTEM_UUID
        ):
            raise ValueError("ext4 internal journal superblock is inconsistent")

    def _directory_entries(self, inode: _Ext4Inode) -> dict[str, tuple[int, str]]:
        entries: dict[str, tuple[int, str]] = {}
        block_count = inode.size // EXT4_BLOCK_BYTES
        for logical in range(block_count):
            mapped = self._mapped_block(inode, logical)
            if mapped is None or mapped[1]:
                raise ValueError("ext4 directory has an unmapped block")
            block = self._block(mapped[0])
            tail_offset = EXT4_BLOCK_BYTES - EXT4_DIRECTORY_TAIL_BYTES
            tail = block[tail_offset:]
            if (
                _read_integer(tail, 0, 4) != 0
                or _read_integer(tail, 4, 2) != EXT4_DIRECTORY_TAIL_BYTES
                or _read_integer(tail, 6, 1) != 0
                or _read_integer(tail, 7, 1) != 0xDE
            ):
                raise ValueError("ext4 directory checksum tail is malformed")
            inode_seed = _crc32c(
                _crc32c(self.checksum_seed, inode.number.to_bytes(4, "little")),
                inode.generation.to_bytes(4, "little"),
            )
            if _read_integer(tail, 8, 4) != _crc32c(inode_seed, block[:tail_offset]):
                raise ValueError("ext4 directory-block checksum mismatch")
            offset = 0
            while offset < tail_offset:
                entry_inode = _read_integer(block, offset, 4)
                record_bytes = _read_integer(block, offset + 4, 2)
                name_bytes = _read_integer(block, offset + 6, 1)
                file_type = _read_integer(block, offset + 7, 1)
                if (
                    record_bytes < 8
                    or record_bytes % 4
                    or offset + record_bytes > tail_offset
                    or name_bytes > record_bytes - 8
                ):
                    raise ValueError("ext4 directory entry has invalid bounds")
                if entry_inode == 0:
                    if name_bytes != 0 or file_type != 0:
                        raise ValueError("ext4 free directory record is not canonical")
                else:
                    if entry_inode not in self.allocated_inodes:
                        raise ValueError("ext4 directory references a free inode")
                    if not 0 < name_bytes <= EXT4_MAX_NAME_BYTES:
                        raise ValueError(
                            "ext4 directory name exceeds the mount ceiling"
                        )
                    raw_name = block[offset + 8 : offset + 8 + name_bytes].tobytes()
                    if b"\0" in raw_name or b"/" in raw_name:
                        raise ValueError("ext4 directory contains a noncanonical name")
                    try:
                        name = raw_name.decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise ValueError("ext4 directory name is not UTF-8") from error
                    kind = {1: "file", 2: "directory"}.get(file_type)
                    if kind is None:
                        raise ValueError(
                            "ext4 directory entry has an unsupported file type"
                        )
                    if name in entries:
                        raise ValueError("ext4 directory contains a duplicate name")
                    entries[name] = (entry_inode, kind)
                    if len(entries) > EXT4_MAX_DIRECTORY_ENTRIES:
                        raise ValueError(
                            "ext4 directory exceeds the entry mount ceiling"
                        )
                offset += record_bytes
            if offset != tail_offset:
                raise ValueError(
                    "ext4 directory records do not end at the checksum tail"
                )
        return entries

    def _read_file(self, inode: _Ext4Inode) -> bytes:
        if inode.size > EXT4_MAX_FILE_BYTES:
            raise ValueError("ext4 file exceeds the bounded verifier allocation")
        output = bytearray(inode.size)
        for extent in inode.extents:
            if extent.unwritten:
                continue
            for index in range(extent.blocks):
                logical = extent.logical + index
                start = logical * EXT4_BLOCK_BYTES
                if start >= inode.size:
                    break
                count = min(EXT4_BLOCK_BYTES, inode.size - start)
                output[start : start + count] = self._block(extent.physical + index)[
                    :count
                ]
        return bytes(output)

    def _verify_exact_tree(self) -> None:
        expected_files = {
            "/hello.txt": b"native ext4 mount\n",
            "/nested/state.txt": b"read-only activation complete\n",
        }
        if self.content is not None:
            expected_files["/system.cspk"] = self.content
        expected_children: dict[str, dict[str, str]] = {
            "/": {
                "hello.txt": "file",
                "lost+found": "directory",
                "nested": "directory",
            },
            "/lost+found": {},
            "/nested": {"state.txt": "file"},
        }
        if self.content is not None:
            expected_children["/"]["system.cspk"] = "file"

        root = self.inode_records.get(EXT4_ROOT_INODE)
        if root is None or root.kind != "directory":
            raise ValueError("ext4 root inode is not a directory")
        queue = [("/", EXT4_ROOT_INODE, EXT4_ROOT_INODE)]
        reached = {EXT4_ROOT_INODE}
        linked = {EXT4_ROOT_INODE}
        while queue:
            path, inode_number, parent_inode = queue.pop(0)
            inode = self.inode_records[inode_number]
            entries = self._directory_entries(inode)
            if entries.get(".") != (inode_number, "directory"):
                raise ValueError("ext4 directory has an invalid dot entry")
            if entries.get("..") != (parent_inode, "directory"):
                raise ValueError("ext4 directory has an invalid dot-dot entry")
            visible = {
                name: value
                for name, value in entries.items()
                if name not in (".", "..")
            }
            expected = expected_children[path]
            if {name: value[1] for name, value in visible.items()} != expected:
                raise ValueError(
                    f"ext4 directory {path} does not match the canonical tree"
                )
            for name, (child_number, kind) in visible.items():
                child = self.inode_records.get(child_number)
                if child is None or child.kind != kind:
                    raise ValueError(
                        "ext4 directory file type disagrees with its inode"
                    )
                if child_number in linked:
                    raise ValueError(
                        "ext4 canonical tree contains a hard link or directory cycle"
                    )
                linked.add(child_number)
                reached.add(child_number)
                child_path = f"/{name}" if path == "/" else f"{path}/{name}"
                if kind == "directory":
                    queue.append((child_path, child_number, inode_number))
                elif self._read_file(child) != expected_files[child_path]:
                    raise ValueError(f"ext4 payload mismatch at {child_path}")
        live = set(self.inode_records)
        if live != reached | {EXT4_JOURNAL_INODE}:
            raise ValueError("ext4 image contains an unreachable active inode")


def verify_ext4(image: bytes, content: bytes | None = None) -> None:
    """Independently decode and validate the exact constrained ext4 fixture."""
    _Ext4ProfileVerifier(image, content).verify()


def create_ext4(content: bytes | None = None) -> bytes:
    """Build a clean, bounded ext4 v1 filesystem using e2fsprogs."""
    if content is not None and len(content) > EXT4_MAX_FILE_BYTES:
        raise ValueError("system.cspk exceeds the production ext4 mount ceiling")
    mke2fs, e2fsck = require_pinned_e2fsprogs()

    with tempfile.TemporaryDirectory(prefix="troe-storage-") as temporary:
        root = Path(temporary)
        source = root / "source"
        nested = source / "nested"
        nested.mkdir(parents=True)
        (source / "hello.txt").write_bytes(b"native ext4 mount\n")
        (nested / "state.txt").write_bytes(b"read-only activation complete\n")
        if content is not None:
            (source / "system.cspk").write_bytes(content)
        timestamp = int(FAKE_TIME)
        paths = [source / "hello.txt", nested / "state.txt"]
        if content is not None:
            paths.append(source / "system.cspk")
        paths.extend((nested, source))
        for path in paths:
            os.utime(path, (timestamp, timestamp))

        filesystem = root / "root.ext4"
        with filesystem.open("wb") as output:
            output.truncate(PARTITION_SECTORS * SECTOR_BYTES)
        environment = os.environ.copy()
        environment.update(
            {
                "E2FSPROGS_FAKE_TIME": FAKE_TIME,
                "LC_ALL": "C",
                "SOURCE_DATE_EPOCH": FAKE_TIME,
                "TZ": "UTC",
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
        subprocess.run([e2fsck, "-fn", str(filesystem)], check=True, env=environment)
        image = filesystem.read_bytes()
        verify_ext4(image, content)
        return image


def decode_manifest(manifest: bytes) -> tuple[MountSpec, ...]:
    """Independently decode and validate one canonical BMNT v1 image."""
    if not BMNT_HEADER_BYTES <= len(manifest) <= BMNT_MAX_BYTES:
        raise ValueError("BMNT size is outside the format bounds")
    major, minor, header_bytes, record_bytes, total_bytes = struct.unpack_from(
        "<HHHHI", manifest, 8
    )
    if (
        manifest[:8] != b"BMNTv1\0\0"
        or major != 1
        or minor != 1
        or header_bytes != BMNT_HEADER_BYTES
        or record_bytes != BMNT_RECORD_BYTES
        or total_bytes != len(manifest)
        or struct.unpack_from("<H", manifest, 26)[0] != 0
        or any(manifest[32:BMNT_HEADER_BYTES])
    ):
        raise ValueError("invalid BMNT header")
    stored = struct.unpack_from("<I", manifest, BMNT_CHECKSUM_OFFSET)[0]
    checked = bytearray(manifest)
    checked[BMNT_CHECKSUM_OFFSET : BMNT_CHECKSUM_OFFSET + 4] = b"\0" * 4
    if zlib.crc32(checked) != stored:
        raise ValueError("BMNT checksum mismatch")

    count = struct.unpack_from("<H", manifest, 24)[0]
    string_bytes = struct.unpack_from("<I", manifest, 28)[0]
    if not 1 <= count <= BMNT_MAX_ENTRIES:
        raise ValueError("BMNT entry count is outside the format bounds")
    string_start = BMNT_HEADER_BYTES + count * BMNT_RECORD_BYTES
    if string_start + string_bytes != len(manifest):
        raise ValueError("BMNT record and string lengths are inconsistent")
    strings = manifest[string_start:]
    selector_names = {1: "whole-device", 2: "gpt"}
    filesystem_names = {1: "fat32", 2: "ext4-v1"}
    access_names = {1: "read-only", 2: "read-write"}
    availability_names = {1: "optional", 2: "required"}
    activation_names = {1: "auto", 2: "manual"}
    decoded: list[MountSpec] = []
    expected_name_offset = 0
    for index in range(count):
        start = BMNT_HEADER_BYTES + index * BMNT_RECORD_BYTES
        record = manifest[start : start + BMNT_RECORD_BYTES]
        if len(record) != BMNT_RECORD_BYTES or any(record[64:]):
            raise ValueError(f"BMNT record {index} uses reserved bytes")
        if any(record[11:16]):
            raise ValueError(f"BMNT record {index} uses reserved bytes")
        try:
            activation = activation_names[record[10]]
        except KeyError as error:
            raise ValueError(
                f"BMNT record {index} contains an unknown activation"
            ) from error
        try:
            selector = selector_names[record[0]]
            filesystem = filesystem_names[record[1]]
            access = access_names[record[2]]
            availability = availability_names[record[3]]
        except KeyError as error:
            raise ValueError(f"BMNT record {index} contains an unknown enum") from error
        name_offset, name_bytes = struct.unpack_from("<IH", record, 4)
        if (
            name_offset != expected_name_offset
            or not 1 <= name_bytes <= BMNT_MAX_NAME_BYTES
        ):
            raise ValueError(f"BMNT record {index} has a noncanonical name range")
        name_end = name_offset + name_bytes
        try:
            name = strings[name_offset:name_end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"BMNT record {index} name is not UTF-8") from error
        if name_end > len(strings):
            raise ValueError(f"BMNT record {index} name is truncated")
        expected_name_offset = name_end
        spec = MountSpec(
            name=name,
            selector=selector,
            filesystem=filesystem,
            access=access,
            availability=availability,
            disk_guid=bytes(record[16:32]),
            partition_guid=bytes(record[32:48]),
            filesystem_identity=bytes(record[48:64]),
            activation=activation,
        )
        decoded.append(spec)
    if expected_name_offset != len(strings):
        raise ValueError("BMNT string table contains trailing bytes")
    specs = _validated_mount_specs(decoded)
    if tuple(decoded) != specs or build_manifest(specs) != manifest:
        raise ValueError("BMNT image is not canonically ordered or encoded")
    return specs


def verify_manifest(manifest: bytes) -> None:
    """Check one complete BMNT image without trusting its source table."""
    decode_manifest(manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--volume-table",
        type=Path,
        help="compile this strict TOML volume table instead of the built-in fixture policy",
    )
    parser.add_argument(
        "--output", type=Path, help="also create the GPT/ext4 disk image"
    )
    parser.add_argument(
        "--content", type=Path, help="install CSPK bytes at /system.cspk"
    )
    parser.add_argument("--persistence-selector", type=Path)
    parser.add_argument("--txslot-output", type=Path)
    parser.add_argument("--state-selector", type=Path)
    parser.add_argument("--statefs-output", type=Path)
    args = parser.parse_args()
    try:
        entries = (
            load_volume_table(args.volume_table)
            if args.volume_table is not None
            else default_mount_specs()
        )
        if args.output is not None:
            require_fixture_root(entries)
        manifest = build_manifest(entries)
        verify_manifest(manifest)
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_bytes(manifest)
        print(f"BMNT v1: {len(manifest)} bytes -> {args.manifest}")
        if args.persistence_selector is not None:
            selector = build_region_selector(
                TXSLOT_DISK_GUID, TXSLOT_PARTITION_GUID, TXSLOT_TYPE_GUID
            )
            args.persistence_selector.parent.mkdir(parents=True, exist_ok=True)
            args.persistence_selector.write_bytes(selector)
            print(f"PRGN v1: {len(selector)} bytes -> {args.persistence_selector}")
        if args.output is not None:
            content = args.content.read_bytes() if args.content is not None else None
            disk = build_gpt(create_ext4(content))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(disk)
            print(f"GPT/ext4 fixture: {len(disk)} bytes -> {args.output}")
        if args.txslot_output is not None:
            txslot = build_small_gpt(
                TXSLOT_DISK_GUID, TXSLOT_PARTITION_GUID, TXSLOT_TYPE_GUID, "activation"
            )
            args.txslot_output.parent.mkdir(parents=True, exist_ok=True)
            args.txslot_output.write_bytes(txslot)
            print(f"GPT/TXSLOT fixture: {len(txslot)} bytes -> {args.txslot_output}")
        if args.state_selector is not None:
            selector = build_region_selector(
                STATEFS_DISK_GUID, STATEFS_PARTITION_GUID, STATEFS_TYPE_GUID
            )
            args.state_selector.parent.mkdir(parents=True, exist_ok=True)
            args.state_selector.write_bytes(selector)
            print(f"PRGN v1 statefs: {len(selector)} bytes -> {args.state_selector}")
        if args.statefs_output is not None:
            statefs = build_small_gpt(
                STATEFS_DISK_GUID, STATEFS_PARTITION_GUID, STATEFS_TYPE_GUID, "statefs"
            )
            args.statefs_output.parent.mkdir(parents=True, exist_ok=True)
            args.statefs_output.write_bytes(statefs)
            print(f"GPT/statefs fixture: {len(statefs)} bytes -> {args.statefs_output}")
        return 0
    except (
        FileNotFoundError,
        OSError,
        ValueError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"mkstorage: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

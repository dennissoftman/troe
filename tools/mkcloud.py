#!/usr/bin/env python3
"""Build and independently verify deterministic TROE cloud raw-disk bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import sys
import tempfile
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from tools import mkcontent, mkfat, mkstorage
except ImportError:  # Direct execution from tools/.
    import mkcontent  # type: ignore[no-redef]
    import mkfat  # type: ignore[no-redef]
    import mkstorage  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parents[1]
PLATFORM_MANIFEST_PATH = REPO_ROOT / "tools" / "platforms.json"
ENVIRONMENT_MATRIX_PATH = REPO_ROOT / "tools" / "cloud-environments.json"

SECTOR_BYTES = 512
GPT_REVISION = 0x0001_0000
GPT_HEADER_BYTES = 92
GPT_ENTRY_COUNT = 128
GPT_ENTRY_BYTES = 128
GPT_ARRAY_BYTES = GPT_ENTRY_COUNT * GPT_ENTRY_BYTES
GPT_ARRAY_SECTORS = GPT_ARRAY_BYTES // SECTOR_BYTES
FIRST_USABLE_LBA = 2 + GPT_ARRAY_SECTORS
PARTITION_ALIGNMENT_SECTORS = 2_048
MAX_DISK_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024

SYSTEM_TOTAL_SECTORS = 106_496
SYSTEM_ESP_START_LBA = 2_048
SYSTEM_ESP_SECTORS = 69_632
SYSTEM_ROOT_START_LBA = SYSTEM_ESP_START_LBA + SYSTEM_ESP_SECTORS
SYSTEM_ROOT_SECTORS = 32_768

# A GPT EFI System Partition is fixed media and therefore uses FAT32, not the
# FAT12 superfloppy used by the exact pinned-QEMU boot fixture. 34 MiB with
# one-sector clusters leaves 68,528 data clusters, safely above FAT32's 65,525
# cluster classification boundary while keeping the complete disk below 64 MiB.
FAT32_BYTES_PER_SECTOR = SECTOR_BYTES
FAT32_SECTORS_PER_CLUSTER = 1
FAT32_RESERVED_SECTORS = 32
FAT32_FAT_COUNT = 2
FAT32_FAT_SECTORS = 536
FAT32_FIRST_DATA_SECTOR = FAT32_RESERVED_SECTORS + FAT32_FAT_COUNT * FAT32_FAT_SECTORS
FAT32_CLUSTER_COUNT = (
    SYSTEM_ESP_SECTORS - FAT32_FIRST_DATA_SECTOR
) // FAT32_SECTORS_PER_CLUSTER
FAT32_MAX_CLUSTER = FAT32_CLUSTER_COUNT + 1
FAT32_MIN_CLUSTERS = 65_525
FAT32_MAX_CLUSTERS = 0x0FFF_FFF5
FAT32_ROOT_CLUSTER = 2
FAT32_EFI_CLUSTER = 3
FAT32_BOOT_CLUSTER = 4
FAT32_FIRST_FILE_CLUSTER = 5
FAT32_MEDIA = 0xF8
FAT32_END_OF_CHAIN = 0x0FFF_FFFF
FAT32_FSINFO_SECTOR = 1
FAT32_BACKUP_BOOT_SECTOR = 6
FAT32_BACKUP_FSINFO_SECTOR = 7
FAT32_VOLUME_IDENTIFIER = 0x5452_4F45
FAT32_OEM_IDENTIFIER = b"TROEFAT "
FAT32_VOLUME_LABEL = b"TROE ESP   "
FAT32_TYPE_LABEL = b"FAT32   "

PE_MACHINES = {"x86_64": 0x8664, "aarch64": 0xAA64}
PE32_PLUS_MAGIC = 0x020B
PE_SUBSYSTEM_EFI_APPLICATION = 10

# GPT stores the first three GUID components little-endian. These constants are
# exact on-media bytes, matching tools/mkstorage.py's identity convention.
ESP_TYPE_GUID = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
ESP_UNIQUE_GUID = bytes.fromhex("78563412bc9af0de123456789abcdef0")
LINUX_FILESYSTEM_TYPE_GUID = bytes.fromhex("af3dc60f838472478e793d69d8477de4")

BUNDLE_FORMAT = "troe-cloud-raw-bundle-v1"
BUNDLE_KIND_PRODUCTION = "production"
BUNDLE_KIND_DEVELOPMENT = "development"
BUNDLE_KIND_ACCEPTANCE = "acceptance"
BUNDLE_KINDS = (
    BUNDLE_KIND_PRODUCTION,
    BUNDLE_KIND_DEVELOPMENT,
    BUNDLE_KIND_ACCEPTANCE,
)
BUNDLE_FILENAMES = {
    "system": "system.raw",
    "activation": "activation.raw",
    "state": "state.raw",
}
BUNDLE_MANIFEST = "bundle.json"
PRODUCTION_FORBIDDEN_MARKERS = (
    b"mmu-probe",
    b"task-probe",
    b"probing read-only",
    b"probing non-executable",
    b"probing task stack guard",
    b"KEX-ACCEPTANCE-DESTRUCTIVE-v1\0",
)

_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_PARTITION_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,35}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class GptPartition:
    """One canonical GPT partition and its exact payload."""

    name: str
    type_guid: bytes
    unique_guid: bytes
    first_lba: int
    last_lba: int
    payload: bytes

    @property
    def sectors(self) -> int:
        return self.last_lba - self.first_lba + 1


@dataclass(frozen=True)
class GptDisk:
    """A fully checked canonical GPT disk."""

    disk_guid: bytes
    total_sectors: int
    partitions: tuple[GptPartition, ...]


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _read_bounded(path: Path, maximum: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValueError(f"cannot inspect {label} {path}: {error}") from error
    if not 0 < size <= maximum:
        raise ValueError(f"{label} length {size} is outside the 1..{maximum} bound")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read {label} {path}: {error}") from error
    if len(data) != size:
        raise ValueError(f"{label} changed while it was being read")
    return data


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_bundle_kind(bundle_kind: str) -> str:
    if bundle_kind not in BUNDLE_KINDS:
        raise ValueError(f"unsupported cloud bundle kind {bundle_kind!r}")
    return bundle_kind


def _verify_content_identity_policy(content: bytes, bundle_kind: str) -> None:
    """Separate deployment identities from deterministic test identities."""
    _validate_bundle_kind(bundle_kind)
    if not isinstance(content, bytes) or not content:
        raise ValueError("cloud root CSPK is not a nonempty byte string")
    reserved = frozenset(
        identity for identity in mkcontent.RESERVED_FIXTURE_IDS if identity in content
    )
    if bundle_kind == BUNDLE_KIND_PRODUCTION:
        if reserved:
            raise ValueError("production CSPK contains reserved fixture identities")
    elif reserved != mkcontent.RESERVED_FIXTURE_IDS:
        raise ValueError(
            f"{bundle_kind} CSPK does not contain all reserved fixture identities"
        )


def _guid_text(raw: bytes) -> str:
    if len(raw) != 16:
        raise ValueError("GPT GUID must contain exactly 16 bytes")
    return str(uuid.UUID(bytes_le=raw))


def _guid_bytes(text: str) -> bytes:
    try:
        parsed = uuid.UUID(text)
    except (AttributeError, ValueError) as error:
        raise ValueError(f"invalid GPT GUID {text!r}") from error
    if str(parsed) != text:
        raise ValueError(f"GPT GUID is not canonical lowercase text: {text!r}")
    return parsed.bytes_le


def _protective_mbr(total_sectors: int) -> bytes:
    if not 2 <= total_sectors <= 0x1_0000_0000:
        raise ValueError("disk sector count is outside protective-MBR bounds")
    sector = bytearray(SECTOR_BYTES)
    # UEFI 2.11 Table 5.4 requires CHS 0/0/2 for LBA 1. Virtio exposes no
    # meaningful legacy CHS geometry, so the unrepresentable ending address is
    # the specified FF/FF/FF sentinel rather than an all-zero placeholder.
    sector[446 + 1 : 446 + 4] = b"\x00\x02\x00"
    sector[446 + 4] = 0xEE
    sector[446 + 5 : 446 + 8] = b"\xff\xff\xff"
    struct.pack_into("<II", sector, 446 + 8, 1, min(total_sectors - 1, 0xFFFF_FFFF))
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _gpt_header(
    *,
    current_lba: int,
    backup_lba: int,
    first_usable_lba: int,
    last_usable_lba: int,
    disk_guid: bytes,
    entry_lba: int,
    entry_crc: int,
) -> bytes:
    if len(disk_guid) != 16 or disk_guid == bytes(16):
        raise ValueError("disk GUID must be a nonzero 16-byte value")
    sector = bytearray(SECTOR_BYTES)
    sector[:8] = b"EFI PART"
    struct.pack_into("<III", sector, 8, GPT_REVISION, GPT_HEADER_BYTES, 0)
    struct.pack_into(
        "<QQQQ",
        sector,
        24,
        current_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
    )
    sector[56:72] = disk_guid
    struct.pack_into(
        "<QIII",
        sector,
        72,
        entry_lba,
        GPT_ENTRY_COUNT,
        GPT_ENTRY_BYTES,
        entry_crc,
    )
    checked = bytearray(sector[:GPT_HEADER_BYTES])
    checked[16:20] = bytes(4)
    struct.pack_into("<I", sector, 16, zlib.crc32(checked))
    return bytes(sector)


def _partition_entry(partition: GptPartition) -> bytes:
    if (
        len(partition.type_guid) != 16
        or partition.type_guid == bytes(16)
        or len(partition.unique_guid) != 16
        or partition.unique_guid == bytes(16)
        or _PARTITION_NAME.fullmatch(partition.name) is None
        or partition.first_lba > partition.last_lba
    ):
        raise ValueError(f"invalid GPT partition {partition.name!r}")
    name = partition.name.encode("utf-16-le")
    if len(name) > 72:
        raise ValueError("GPT partition name exceeds the fixed entry field")
    entry = bytearray(GPT_ENTRY_BYTES)
    entry[:16] = partition.type_guid
    entry[16:32] = partition.unique_guid
    struct.pack_into("<QQQ", entry, 32, partition.first_lba, partition.last_lba, 0)
    entry[56 : 56 + len(name)] = name
    return bytes(entry)


def build_gpt(
    disk_guid: bytes,
    total_sectors: int,
    partitions: tuple[GptPartition, ...],
) -> bytes:
    """Build the exact canonical GPT encoding accepted by :func:`parse_gpt`."""
    if (
        total_sectors * SECTOR_BYTES > MAX_DISK_BYTES
        or total_sectors <= 2 * GPT_ARRAY_SECTORS + 2
    ):
        raise ValueError("GPT disk length is outside the cloud-artifact bound")
    if not partitions or len(partitions) > 16:
        raise ValueError("GPT partition count is outside the 1..16 bound")
    backup_header_lba = total_sectors - 1
    backup_array_lba = backup_header_lba - GPT_ARRAY_SECTORS
    last_usable_lba = backup_array_lba - 1

    names: set[str] = set()
    identities: set[bytes] = set()
    previous_end = FIRST_USABLE_LBA - 1
    entries = bytearray(GPT_ARRAY_BYTES)
    for index, partition in enumerate(partitions):
        expected_bytes = partition.sectors * SECTOR_BYTES
        if (
            partition.name in names
            or partition.unique_guid in identities
            or partition.first_lba % PARTITION_ALIGNMENT_SECTORS != 0
            or partition.first_lba <= previous_end
            or partition.first_lba < FIRST_USABLE_LBA
            or partition.last_lba > last_usable_lba
            or len(partition.payload) != expected_bytes
        ):
            raise ValueError(f"invalid GPT geometry or payload for {partition.name!r}")
        names.add(partition.name)
        identities.add(partition.unique_guid)
        previous_end = partition.last_lba
        offset = index * GPT_ENTRY_BYTES
        entries[offset : offset + GPT_ENTRY_BYTES] = _partition_entry(partition)

    entry_crc = zlib.crc32(entries)
    image = bytearray(total_sectors * SECTOR_BYTES)
    image[:SECTOR_BYTES] = _protective_mbr(total_sectors)
    image[SECTOR_BYTES : 2 * SECTOR_BYTES] = _gpt_header(
        current_lba=1,
        backup_lba=backup_header_lba,
        first_usable_lba=FIRST_USABLE_LBA,
        last_usable_lba=last_usable_lba,
        disk_guid=disk_guid,
        entry_lba=2,
        entry_crc=entry_crc,
    )
    image[2 * SECTOR_BYTES : 2 * SECTOR_BYTES + GPT_ARRAY_BYTES] = entries
    for partition in partitions:
        start = partition.first_lba * SECTOR_BYTES
        image[start : start + len(partition.payload)] = partition.payload
    backup_array_offset = backup_array_lba * SECTOR_BYTES
    image[backup_array_offset : backup_array_offset + GPT_ARRAY_BYTES] = entries
    backup_header_offset = backup_header_lba * SECTOR_BYTES
    image[backup_header_offset : backup_header_offset + SECTOR_BYTES] = _gpt_header(
        current_lba=backup_header_lba,
        backup_lba=1,
        first_usable_lba=FIRST_USABLE_LBA,
        last_usable_lba=last_usable_lba,
        disk_guid=disk_guid,
        entry_lba=backup_array_lba,
        entry_crc=entry_crc,
    )
    encoded = bytes(image)
    parsed = parse_gpt(encoded)
    if (
        parsed.disk_guid != disk_guid
        or parsed.total_sectors != total_sectors
        or parsed.partitions != partitions
    ):
        raise ValueError("independent GPT verification did not reproduce the input")
    return encoded


def _parse_header(image: bytes, lba: int, total_sectors: int) -> dict[str, Any]:
    offset = lba * SECTOR_BYTES
    sector = image[offset : offset + SECTOR_BYTES]
    if len(sector) != SECTOR_BYTES or sector[:8] != b"EFI PART":
        raise ValueError(f"missing GPT header at LBA {lba}")
    revision, header_bytes, stored_crc, reserved = struct.unpack_from(
        "<IIII", sector, 8
    )
    if (
        revision != GPT_REVISION
        or header_bytes != GPT_HEADER_BYTES
        or reserved != 0
        or any(sector[GPT_HEADER_BYTES:])
    ):
        raise ValueError(f"noncanonical GPT header at LBA {lba}")
    checked = bytearray(sector[:header_bytes])
    checked[16:20] = bytes(4)
    if zlib.crc32(checked) != stored_crc:
        raise ValueError(f"GPT header checksum mismatch at LBA {lba}")
    current, backup, first_usable, last_usable = struct.unpack_from("<QQQQ", sector, 24)
    disk_guid = sector[56:72]
    entry_lba, entry_count, entry_bytes, entry_crc = struct.unpack_from(
        "<QIII", sector, 72
    )
    if (
        current != lba
        or backup >= total_sectors
        or first_usable > last_usable
        or last_usable >= total_sectors
        or disk_guid == bytes(16)
        or entry_count != GPT_ENTRY_COUNT
        or entry_bytes != GPT_ENTRY_BYTES
    ):
        raise ValueError(f"invalid GPT header fields at LBA {lba}")
    return {
        "current": current,
        "backup": backup,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "disk_guid": disk_guid,
        "entry_lba": entry_lba,
        "entry_crc": entry_crc,
    }


def _decode_partition_name(raw: bytes) -> str:
    try:
        decoded = raw.decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise ValueError("GPT partition name is not valid UTF-16LE") from error
    name, separator, trailing = decoded.partition("\0")
    if separator and any(character != "\0" for character in trailing):
        raise ValueError("GPT partition name has nonzero trailing code units")
    if _PARTITION_NAME.fullmatch(name) is None:
        raise ValueError(f"GPT partition name is not canonical: {name!r}")
    return name


def parse_gpt(image: bytes) -> GptDisk:
    """Strictly parse a complete bounded GPT image and return owned payloads."""
    if not image or len(image) > MAX_DISK_BYTES or len(image) % SECTOR_BYTES != 0:
        raise ValueError("GPT image has an invalid bounded length")
    total_sectors = len(image) // SECTOR_BYTES
    if total_sectors <= 2 * GPT_ARRAY_SECTORS + 2:
        raise ValueError("GPT image is too small for primary and backup metadata")
    expected_mbr = _protective_mbr(total_sectors)
    if image[:SECTOR_BYTES] != expected_mbr:
        raise ValueError("protective MBR is not canonical")

    backup_header_lba = total_sectors - 1
    backup_array_lba = backup_header_lba - GPT_ARRAY_SECTORS
    last_usable_lba = backup_array_lba - 1
    primary = _parse_header(image, 1, total_sectors)
    backup = _parse_header(image, backup_header_lba, total_sectors)
    expected_primary = {
        "current": 1,
        "backup": backup_header_lba,
        "first_usable": FIRST_USABLE_LBA,
        "last_usable": last_usable_lba,
        "disk_guid": primary["disk_guid"],
        "entry_lba": 2,
        "entry_crc": primary["entry_crc"],
    }
    expected_backup = {
        "current": backup_header_lba,
        "backup": 1,
        "first_usable": FIRST_USABLE_LBA,
        "last_usable": last_usable_lba,
        "disk_guid": primary["disk_guid"],
        "entry_lba": backup_array_lba,
        "entry_crc": primary["entry_crc"],
    }
    if primary != expected_primary or backup != expected_backup:
        raise ValueError("primary and backup GPT headers are inconsistent")

    primary_offset = 2 * SECTOR_BYTES
    backup_offset = backup_array_lba * SECTOR_BYTES
    entries = image[primary_offset : primary_offset + GPT_ARRAY_BYTES]
    backup_entries = image[backup_offset : backup_offset + GPT_ARRAY_BYTES]
    if entries != backup_entries:
        raise ValueError("primary and backup GPT entry arrays differ")
    if zlib.crc32(entries) != primary["entry_crc"]:
        raise ValueError("GPT entry-array checksum mismatch")

    partitions: list[GptPartition] = []
    seen_empty = False
    names: set[str] = set()
    identities: set[bytes] = set()
    previous_end = FIRST_USABLE_LBA - 1
    for index in range(GPT_ENTRY_COUNT):
        offset = index * GPT_ENTRY_BYTES
        entry = entries[offset : offset + GPT_ENTRY_BYTES]
        if entry == bytes(GPT_ENTRY_BYTES):
            seen_empty = True
            continue
        if seen_empty or len(partitions) >= 16:
            raise ValueError("GPT live entries are sparse or exceed the bound")
        type_guid = entry[:16]
        unique_guid = entry[16:32]
        first_lba, last_lba, attributes = struct.unpack_from("<QQQ", entry, 32)
        name = _decode_partition_name(entry[56:128])
        if (
            type_guid == bytes(16)
            or unique_guid == bytes(16)
            or attributes != 0
            or name in names
            or unique_guid in identities
            or first_lba % PARTITION_ALIGNMENT_SECTORS != 0
            or first_lba <= previous_end
            or first_lba < FIRST_USABLE_LBA
            or last_lba < first_lba
            or last_lba > last_usable_lba
        ):
            raise ValueError(f"invalid GPT partition entry {index}")
        payload_start = first_lba * SECTOR_BYTES
        payload_end = (last_lba + 1) * SECTOR_BYTES
        partition = GptPartition(
            name=name,
            type_guid=type_guid,
            unique_guid=unique_guid,
            first_lba=first_lba,
            last_lba=last_lba,
            payload=image[payload_start:payload_end],
        )
        if entry != _partition_entry(partition):
            raise ValueError(f"GPT partition entry {index} is not canonical")
        partitions.append(partition)
        names.add(name)
        identities.add(unique_guid)
        previous_end = last_lba
    if not partitions:
        raise ValueError("GPT contains no partitions")

    cursor = FIRST_USABLE_LBA * SECTOR_BYTES
    for partition in partitions:
        start = partition.first_lba * SECTOR_BYTES
        if any(image[cursor:start]):
            raise ValueError("unused GPT sectors before a partition are not zero")
        cursor = (partition.last_lba + 1) * SECTOR_BYTES
    if any(image[cursor : (last_usable_lba + 1) * SECTOR_BYTES]):
        raise ValueError("unused GPT sectors after the partitions are not zero")
    return GptDisk(
        disk_guid=primary["disk_guid"],
        total_sectors=total_sectors,
        partitions=tuple(partitions),
    )


def _validate_string_list(
    value: object, field: str, *, may_be_empty: bool
) -> list[str]:
    if (
        not isinstance(value, list)
        or (not may_be_empty and not value)
        or len(value) > 16
        or any(
            not isinstance(item, str) or not item or len(item) > 256 for item in value
        )
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"invalid cloud environment {field}")
    return value


def load_platform_manifest(
    path: Path = PLATFORM_MANIFEST_PATH,
) -> dict[str, dict[str, object]]:
    """Load only the platform facts needed to bind cloud artifact metadata."""
    raw = _read_bounded(path, MAX_MANIFEST_BYTES, "platform manifest")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid platform manifest JSON: {error}") from error
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "platforms"}
        or manifest.get("schema") != 1
        or not isinstance(manifest.get("platforms"), list)
        or not manifest["platforms"]
        or raw != _canonical_json(manifest)
    ):
        raise ValueError("platform manifest is not canonical schema 1")
    result: dict[str, dict[str, object]] = {}
    numeric_ids: set[int] = set()
    for entry in manifest["platforms"]:
        if not isinstance(entry, dict) or set(entry) != {
            "id",
            "name",
            "architecture",
            "firmware_discovery",
            "target",
            "kernel_feature",
            "virtio_transport",
        }:
            raise ValueError("platform manifest entry has an invalid field set")
        numeric_id = entry["id"]
        name = entry["name"]
        architecture = entry["architecture"]
        firmware_discovery = entry["firmware_discovery"]
        transport = entry["virtio_transport"]
        if (
            not isinstance(numeric_id, int)
            or isinstance(numeric_id, bool)
            or not 1 <= numeric_id <= 0xFFFF
            or numeric_id in numeric_ids
            or not isinstance(name, str)
            or _IDENTIFIER.fullmatch(name) is None
            or name in result
            or architecture not in {"x86_64", "aarch64"}
            or firmware_discovery not in {"fixed", "acpi", "fdt"}
            or (architecture == "x86_64" and firmware_discovery == "fdt")
            or (architecture == "aarch64" and firmware_discovery == "acpi")
            or transport not in {"pci", "mmio"}
            or not isinstance(entry["target"], str)
            or not entry["target"]
            or not isinstance(entry["kernel_feature"], str)
            or not entry["kernel_feature"]
        ):
            raise ValueError("platform manifest entry is invalid")
        numeric_ids.add(numeric_id)
        result[name] = entry
    return result


_ENVIRONMENT_FIELDS = {
    "id",
    "environment",
    "provider",
    "platform",
    "architecture",
    "runtime_status",
    "artifact_status",
    "firmware",
    "boot_contract",
    "machine_contract",
    "required_cpu_features",
    "interrupt_model",
    "virtio_transport",
    "block_device",
    "network_device",
    "image_format",
    "required_disks",
    "acceptance_evidence",
    "missing_drivers",
    "gaps",
}


def validate_environment_matrix(
    matrix: object, platforms: dict[str, dict[str, object]]
) -> tuple[dict[str, object], ...]:
    """Fail closed on ambiguous support claims or incomplete matrix records."""
    if (
        not isinstance(matrix, dict)
        or set(matrix) != {"schema", "entries"}
        or matrix.get("schema") != 1
        or not isinstance(matrix.get("entries"), list)
        or not matrix["entries"]
        or len(matrix["entries"]) > 64
    ):
        raise ValueError("cloud environment matrix is not schema 1")
    identifiers: set[str] = set()
    supported_pairs: set[tuple[str, str]] = set()
    validated: list[dict[str, object]] = []
    for raw_entry in matrix["entries"]:
        if not isinstance(raw_entry, dict) or set(raw_entry) != _ENVIRONMENT_FIELDS:
            raise ValueError("cloud environment entry has an invalid field set")
        entry = raw_entry
        identifier = entry["id"]
        environment = entry["environment"]
        provider = entry["provider"]
        platform = entry["platform"]
        architecture = entry["architecture"]
        runtime_status = entry["runtime_status"]
        artifact_status = entry["artifact_status"]
        transport = entry["virtio_transport"]
        if (
            not isinstance(identifier, str)
            or _IDENTIFIER.fullmatch(identifier) is None
            or identifier in identifiers
            or not isinstance(environment, str)
            or _IDENTIFIER.fullmatch(environment) is None
            or not isinstance(provider, str)
            or _IDENTIFIER.fullmatch(provider) is None
            or architecture not in {"x86_64", "aarch64"}
            or runtime_status
            not in {"accepted", "compatible-unverified", "incompatible"}
            or artifact_status not in {"host-verified", "unavailable"}
            or not isinstance(entry["firmware"], str)
            or not entry["firmware"]
            or not isinstance(entry["boot_contract"], str)
            or not entry["boot_contract"]
            or not isinstance(entry["machine_contract"], str)
            or not entry["machine_contract"]
            or not isinstance(entry["interrupt_model"], str)
            or not entry["interrupt_model"]
            or not isinstance(entry["block_device"], str)
            or not entry["block_device"]
            or not isinstance(entry["network_device"], str)
            or not entry["network_device"]
        ):
            raise ValueError(f"invalid cloud environment entry {identifier!r}")
        required_disks = _validate_string_list(
            entry["required_disks"], "required_disks", may_be_empty=True
        )
        _validate_string_list(
            entry["required_cpu_features"],
            "required_cpu_features",
            may_be_empty=False,
        )
        evidence = _validate_string_list(
            entry["acceptance_evidence"], "acceptance_evidence", may_be_empty=True
        )
        missing = _validate_string_list(
            entry["missing_drivers"], "missing_drivers", may_be_empty=True
        )
        gaps = _validate_string_list(entry["gaps"], "gaps", may_be_empty=True)
        identifiers.add(identifier)

        if artifact_status == "host-verified":
            if (
                not isinstance(platform, str)
                or platform not in platforms
                or architecture != platforms[platform]["architecture"]
                or transport != platforms[platform]["virtio_transport"]
                or entry["image_format"] != "raw-gpt"
                or required_disks != ["system", "activation", "state"]
                or missing
            ):
                raise ValueError(
                    f"buildable matrix entry {identifier!r} is inconsistent"
                )
            pair = (platform, environment)
            if pair in supported_pairs:
                raise ValueError(
                    "cloud matrix contains a duplicate platform/environment"
                )
            supported_pairs.add(pair)
        else:
            if (
                platform is not None
                or transport is not None
                or entry["image_format"] != "unavailable"
                or required_disks
                or runtime_status != "incompatible"
                or not missing
            ):
                raise ValueError(
                    f"unavailable matrix entry {identifier!r} is inconsistent"
                )

        if runtime_status == "accepted":
            if artifact_status != "host-verified" or not evidence:
                raise ValueError(f"accepted matrix entry {identifier!r} lacks evidence")
            if gaps:
                raise ValueError(f"accepted matrix entry {identifier!r} still has gaps")
        elif evidence:
            raise ValueError(
                f"unaccepted matrix entry {identifier!r} cannot claim acceptance evidence"
            )
        if runtime_status != "accepted" and not gaps:
            raise ValueError(
                f"unaccepted matrix entry {identifier!r} must state its gaps"
            )
        validated.append(entry)
    return tuple(validated)


def load_environment_matrix(
    path: Path = ENVIRONMENT_MATRIX_PATH,
    platforms: dict[str, dict[str, object]] | None = None,
) -> tuple[dict[str, object], ...]:
    raw = _read_bounded(path, MAX_MANIFEST_BYTES, "cloud environment matrix")
    try:
        matrix = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid cloud environment matrix JSON: {error}") from error
    if raw != _canonical_json(matrix):
        raise ValueError("cloud environment matrix is not canonical JSON")
    if platforms is None:
        platforms = load_platform_manifest()
    return validate_environment_matrix(matrix, platforms)


def resolve_environment(
    entries: tuple[dict[str, object], ...], platform: str, environment: str
) -> dict[str, object]:
    matches = [
        entry
        for entry in entries
        if entry["platform"] == platform and entry["environment"] == environment
    ]
    if len(matches) != 1 or matches[0]["artifact_status"] != "host-verified":
        raise ValueError(
            f"no buildable cloud artifact for platform {platform!r} "
            f"and environment {environment!r}"
        )
    return matches[0]


def _fat32_boot_name(architecture: str) -> bytes:
    try:
        return mkfat.BOOT_NAMES[architecture]
    except KeyError as error:
        raise ValueError(f"unsupported ESP architecture {architecture!r}") from error


def _fat32_file_clusters(byte_count: int) -> int:
    if not 0 < byte_count <= 0xFFFF_FFFF:
        raise ValueError("EFI executable length is outside the FAT32 field")
    return (byte_count + SECTOR_BYTES - 1) // SECTOR_BYTES


def _fat32_cluster_offset(cluster: int) -> int:
    if not FAT32_ROOT_CLUSTER <= cluster <= FAT32_MAX_CLUSTER:
        raise ValueError("FAT32 cluster is outside the ESP data region")
    sector = (
        FAT32_FIRST_DATA_SECTOR
        + (cluster - FAT32_ROOT_CLUSTER) * FAT32_SECTORS_PER_CLUSTER
    )
    return sector * SECTOR_BYTES


def _fat32_directory_entry(
    name: bytes, attributes: int, cluster: int, size: int
) -> bytes:
    if (
        len(name) != 11
        or not 0 <= attributes <= 0xFF
        or not 0 <= cluster <= FAT32_MAX_CLUSTER
        or not 0 <= size <= 0xFFFF_FFFF
    ):
        raise ValueError("invalid FAT32 directory entry")
    entry = bytearray(32)
    entry[:11] = name
    entry[11] = attributes
    struct.pack_into("<H", entry, 16, 0x0021)
    struct.pack_into("<H", entry, 18, 0x0021)
    struct.pack_into("<H", entry, 20, cluster >> 16)
    struct.pack_into("<H", entry, 24, 0x0021)
    struct.pack_into("<H", entry, 26, cluster & 0xFFFF)
    struct.pack_into("<I", entry, 28, size)
    return bytes(entry)


def _set_fat32(fat: bytearray, cluster: int, value: int) -> None:
    offset = cluster * 4
    if cluster < 0 or offset + 4 > len(fat) or not 0 <= value <= FAT32_END_OF_CHAIN:
        raise ValueError("FAT32 entry is outside the allocation table")
    struct.pack_into("<I", fat, offset, value)


def _fat32_boot_sector() -> bytes:
    sector = bytearray(SECTOR_BYTES)
    sector[:3] = b"\xeb\x58\x90"
    sector[3:11] = FAT32_OEM_IDENTIFIER
    struct.pack_into(
        "<HBHBHHBHHHII",
        sector,
        11,
        FAT32_BYTES_PER_SECTOR,
        FAT32_SECTORS_PER_CLUSTER,
        FAT32_RESERVED_SECTORS,
        FAT32_FAT_COUNT,
        0,
        0,
        FAT32_MEDIA,
        0,
        63,
        255,
        SYSTEM_ESP_START_LBA,
        SYSTEM_ESP_SECTORS,
    )
    struct.pack_into(
        "<IHHIHH",
        sector,
        36,
        FAT32_FAT_SECTORS,
        0,
        0,
        FAT32_ROOT_CLUSTER,
        FAT32_FSINFO_SECTOR,
        FAT32_BACKUP_BOOT_SECTOR,
    )
    sector[64:67] = b"\x80\x00\x29"
    struct.pack_into("<I", sector, 67, FAT32_VOLUME_IDENTIFIER)
    sector[71:82] = FAT32_VOLUME_LABEL
    sector[82:90] = FAT32_TYPE_LABEL
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _fat32_fsinfo(file_clusters: int) -> bytes:
    allocated = 3 + file_clusters
    next_free = FAT32_FIRST_FILE_CLUSTER + file_clusters
    if next_free > FAT32_MAX_CLUSTER:
        next_free = 0xFFFF_FFFF
    sector = bytearray(SECTOR_BYTES)
    struct.pack_into("<I", sector, 0, 0x4161_5252)
    struct.pack_into("<I", sector, 484, 0x6141_7272)
    struct.pack_into("<I", sector, 488, FAT32_CLUSTER_COUNT - allocated)
    struct.pack_into("<I", sector, 492, next_free)
    struct.pack_into("<I", sector, 508, 0xAA55_0000)
    return bytes(sector)


def build_fat32_esp(efi: bytes, architecture: str) -> bytes:
    """Build the deterministic fixed-media FAT32 EFI System Partition."""
    boot_name = _fat32_boot_name(architecture)
    file_clusters = _fat32_file_clusters(len(efi))
    last_file_cluster = FAT32_FIRST_FILE_CLUSTER + file_clusters - 1
    if (
        not FAT32_MIN_CLUSTERS <= FAT32_CLUSTER_COUNT < FAT32_MAX_CLUSTERS
        or last_file_cluster > FAT32_MAX_CLUSTER
    ):
        raise ValueError("EFI executable does not fit the canonical FAT32 ESP")

    image = bytearray(SYSTEM_ESP_SECTORS * SECTOR_BYTES)
    boot = _fat32_boot_sector()
    fsinfo = _fat32_fsinfo(file_clusters)
    image[:SECTOR_BYTES] = boot
    fsinfo_offset = FAT32_FSINFO_SECTOR * SECTOR_BYTES
    image[fsinfo_offset : fsinfo_offset + SECTOR_BYTES] = fsinfo
    backup_boot = FAT32_BACKUP_BOOT_SECTOR * SECTOR_BYTES
    image[backup_boot : backup_boot + SECTOR_BYTES] = boot
    backup_fsinfo = FAT32_BACKUP_FSINFO_SECTOR * SECTOR_BYTES
    image[backup_fsinfo : backup_fsinfo + SECTOR_BYTES] = fsinfo

    fat = bytearray(FAT32_FAT_SECTORS * SECTOR_BYTES)
    _set_fat32(fat, 0, 0x0FFF_FF00 | FAT32_MEDIA)
    _set_fat32(fat, 1, FAT32_END_OF_CHAIN)
    for cluster in (FAT32_ROOT_CLUSTER, FAT32_EFI_CLUSTER, FAT32_BOOT_CLUSTER):
        _set_fat32(fat, cluster, FAT32_END_OF_CHAIN)
    for cluster in range(FAT32_FIRST_FILE_CLUSTER, last_file_cluster + 1):
        following = FAT32_END_OF_CHAIN if cluster == last_file_cluster else cluster + 1
        _set_fat32(fat, cluster, following)
    first_fat = FAT32_RESERVED_SECTORS * SECTOR_BYTES
    second_fat = first_fat + len(fat)
    image[first_fat : first_fat + len(fat)] = fat
    image[second_fat : second_fat + len(fat)] = fat

    root = _fat32_cluster_offset(FAT32_ROOT_CLUSTER)
    image[root : root + 32] = _fat32_directory_entry(FAT32_VOLUME_LABEL, 0x08, 0, 0)
    image[root + 32 : root + 64] = _fat32_directory_entry(
        b"EFI        ", 0x10, FAT32_EFI_CLUSTER, 0
    )
    efi_directory = _fat32_cluster_offset(FAT32_EFI_CLUSTER)
    image[efi_directory : efi_directory + 32] = _fat32_directory_entry(
        b".          ", 0x10, FAT32_EFI_CLUSTER, 0
    )
    image[efi_directory + 32 : efi_directory + 64] = _fat32_directory_entry(
        b"..         ", 0x10, FAT32_ROOT_CLUSTER, 0
    )
    image[efi_directory + 64 : efi_directory + 96] = _fat32_directory_entry(
        b"BOOT       ", 0x10, FAT32_BOOT_CLUSTER, 0
    )
    boot_directory = _fat32_cluster_offset(FAT32_BOOT_CLUSTER)
    image[boot_directory : boot_directory + 32] = _fat32_directory_entry(
        b".          ", 0x10, FAT32_BOOT_CLUSTER, 0
    )
    image[boot_directory + 32 : boot_directory + 64] = _fat32_directory_entry(
        b"..         ", 0x10, FAT32_EFI_CLUSTER, 0
    )
    image[boot_directory + 64 : boot_directory + 96] = _fat32_directory_entry(
        boot_name, 0x20, FAT32_FIRST_FILE_CLUSTER, len(efi)
    )
    file_offset = _fat32_cluster_offset(FAT32_FIRST_FILE_CLUSTER)
    image[file_offset : file_offset + len(efi)] = efi

    encoded = bytes(image)
    if _extract_fat32_efi(encoded, architecture) != efi:
        raise ValueError("independent FAT32 verification did not reproduce the EFI")
    return encoded


def _extract_fat32_efi(payload: bytes, architecture: str) -> bytes:
    """Independently parse the complete constrained FAT32 ESP."""
    if len(payload) != SYSTEM_ESP_SECTORS * SECTOR_BYTES:
        raise ValueError("ESP partition has the wrong exact length")
    if not FAT32_MIN_CLUSTERS <= FAT32_CLUSTER_COUNT < FAT32_MAX_CLUSTERS:
        raise ValueError("ESP data-cluster count does not classify as FAT32")
    boot_name = _fat32_boot_name(architecture)
    boot = payload[:SECTOR_BYTES]
    geometry = struct.unpack_from("<HBHBHHBHHHII", boot, 11)
    fat32_geometry = struct.unpack_from("<IHHIHH", boot, 36)
    if (
        boot[:3] != b"\xeb\x58\x90"
        or boot[3:11] != FAT32_OEM_IDENTIFIER
        or geometry
        != (
            FAT32_BYTES_PER_SECTOR,
            FAT32_SECTORS_PER_CLUSTER,
            FAT32_RESERVED_SECTORS,
            FAT32_FAT_COUNT,
            0,
            0,
            FAT32_MEDIA,
            0,
            63,
            255,
            SYSTEM_ESP_START_LBA,
            SYSTEM_ESP_SECTORS,
        )
        or fat32_geometry
        != (
            FAT32_FAT_SECTORS,
            0,
            0,
            FAT32_ROOT_CLUSTER,
            FAT32_FSINFO_SECTOR,
            FAT32_BACKUP_BOOT_SECTOR,
        )
        or boot[52:64] != bytes(12)
        or boot[64:67] != b"\x80\x00\x29"
        or struct.unpack_from("<I", boot, 67)[0] != FAT32_VOLUME_IDENTIFIER
        or boot[71:82] != FAT32_VOLUME_LABEL
        or boot[82:90] != FAT32_TYPE_LABEL
        or any(boot[90:510])
        or boot[510:512] != b"\x55\xaa"
    ):
        raise ValueError("ESP FAT32 boot sector is not canonical")

    def sector(number: int) -> bytes:
        offset = number * SECTOR_BYTES
        return payload[offset : offset + SECTOR_BYTES]

    if sector(FAT32_BACKUP_BOOT_SECTOR) != boot:
        raise ValueError("ESP FAT32 backup boot sector differs")
    fsinfo = sector(FAT32_FSINFO_SECTOR)
    if sector(FAT32_BACKUP_FSINFO_SECTOR) != fsinfo:
        raise ValueError("ESP FAT32 backup FSInfo sector differs")
    for number in range(2, FAT32_RESERVED_SECTORS):
        if number in (FAT32_BACKUP_BOOT_SECTOR, FAT32_BACKUP_FSINFO_SECTOR):
            continue
        if any(sector(number)):
            raise ValueError("ESP FAT32 reserved sectors are not zero")
    if (
        struct.unpack_from("<I", fsinfo, 0)[0] != 0x4161_5252
        or struct.unpack_from("<I", fsinfo, 484)[0] != 0x6141_7272
        or struct.unpack_from("<I", fsinfo, 508)[0] != 0xAA55_0000
        or any(fsinfo[4:484])
        or any(fsinfo[496:508])
    ):
        raise ValueError("ESP FAT32 FSInfo sector is not canonical")

    root_offset = _fat32_cluster_offset(FAT32_ROOT_CLUSTER)
    expected_root = bytearray(SECTOR_BYTES)
    expected_root[:32] = _fat32_directory_entry(FAT32_VOLUME_LABEL, 0x08, 0, 0)
    expected_root[32:64] = _fat32_directory_entry(
        b"EFI        ", 0x10, FAT32_EFI_CLUSTER, 0
    )
    if payload[root_offset : root_offset + SECTOR_BYTES] != expected_root:
        raise ValueError("ESP FAT32 root directory is not canonical")

    efi_offset = _fat32_cluster_offset(FAT32_EFI_CLUSTER)
    expected_efi = bytearray(SECTOR_BYTES)
    expected_efi[:32] = _fat32_directory_entry(
        b".          ", 0x10, FAT32_EFI_CLUSTER, 0
    )
    expected_efi[32:64] = _fat32_directory_entry(
        b"..         ", 0x10, FAT32_ROOT_CLUSTER, 0
    )
    expected_efi[64:96] = _fat32_directory_entry(
        b"BOOT       ", 0x10, FAT32_BOOT_CLUSTER, 0
    )
    if payload[efi_offset : efi_offset + SECTOR_BYTES] != expected_efi:
        raise ValueError("ESP FAT32 EFI directory is not canonical")

    boot_offset = _fat32_cluster_offset(FAT32_BOOT_CLUSTER)
    boot_directory = payload[boot_offset : boot_offset + SECTOR_BYTES]
    size = struct.unpack_from("<I", boot_directory, 64 + 28)[0]
    file_clusters = _fat32_file_clusters(size)
    last_file_cluster = FAT32_FIRST_FILE_CLUSTER + file_clusters - 1
    if last_file_cluster > FAT32_MAX_CLUSTER:
        raise ValueError("ESP FAT32 executable exceeds the data region")
    expected_boot = bytearray(SECTOR_BYTES)
    expected_boot[:32] = _fat32_directory_entry(
        b".          ", 0x10, FAT32_BOOT_CLUSTER, 0
    )
    expected_boot[32:64] = _fat32_directory_entry(
        b"..         ", 0x10, FAT32_EFI_CLUSTER, 0
    )
    expected_boot[64:96] = _fat32_directory_entry(
        boot_name, 0x20, FAT32_FIRST_FILE_CLUSTER, size
    )
    if boot_directory != expected_boot:
        raise ValueError("ESP FAT32 BOOT directory is not canonical")

    first_fat = FAT32_RESERVED_SECTORS * SECTOR_BYTES
    fat_bytes = FAT32_FAT_SECTORS * SECTOR_BYTES
    fat = payload[first_fat : first_fat + fat_bytes]
    second_fat = payload[first_fat + fat_bytes : first_fat + 2 * fat_bytes]
    if fat != second_fat:
        raise ValueError("ESP FAT32 allocation tables differ")
    for cluster in range(len(fat) // 4):
        if cluster == 0:
            expected = 0x0FFF_FF00 | FAT32_MEDIA
        elif cluster in (1, FAT32_ROOT_CLUSTER, FAT32_EFI_CLUSTER, FAT32_BOOT_CLUSTER):
            expected = FAT32_END_OF_CHAIN
        elif FAT32_FIRST_FILE_CLUSTER <= cluster <= last_file_cluster:
            expected = (
                FAT32_END_OF_CHAIN if cluster == last_file_cluster else cluster + 1
            )
        else:
            expected = 0
        if struct.unpack_from("<I", fat, cluster * 4)[0] != expected:
            raise ValueError("ESP FAT32 allocation table is not canonical")

    allocated = 3 + file_clusters
    expected_next = FAT32_FIRST_FILE_CLUSTER + file_clusters
    if expected_next > FAT32_MAX_CLUSTER:
        expected_next = 0xFFFF_FFFF
    if (
        struct.unpack_from("<I", fsinfo, 488)[0] != FAT32_CLUSTER_COUNT - allocated
        or struct.unpack_from("<I", fsinfo, 492)[0] != expected_next
    ):
        raise ValueError("ESP FAT32 FSInfo allocation accounting is inconsistent")

    file_offset = _fat32_cluster_offset(FAT32_FIRST_FILE_CLUSTER)
    allocation_bytes = file_clusters * SECTOR_BYTES
    allocation = payload[file_offset : file_offset + allocation_bytes]
    if any(allocation[size:]):
        raise ValueError("ESP FAT32 executable allocation padding is not zero")
    if expected_next <= FAT32_MAX_CLUSTER:
        unused = _fat32_cluster_offset(expected_next)
        if any(payload[unused:]):
            raise ValueError("ESP FAT32 unused data clusters are not zero")
    return allocation[:size]


def _verify_pe_coff_machine(efi: bytes, architecture: str) -> None:
    try:
        expected_machine = PE_MACHINES[architecture]
    except KeyError as error:
        raise ValueError(f"unsupported PE architecture {architecture!r}") from error
    if len(efi) < 64 or efi[:2] != b"MZ":
        raise ValueError("ESP fallback executable lacks a bounded DOS header")
    pe_offset = struct.unpack_from("<I", efi, 0x3C)[0]
    coff_end = pe_offset + 24
    if (
        pe_offset < 64
        or coff_end > len(efi)
        or efi[pe_offset : pe_offset + 4] != b"PE\0\0"
    ):
        raise ValueError("ESP fallback executable has an invalid PE signature offset")
    machine, sections = struct.unpack_from("<HH", efi, pe_offset + 4)
    optional_bytes, characteristics = struct.unpack_from("<HH", efi, pe_offset + 20)
    optional_start = coff_end
    optional_end = optional_start + optional_bytes
    section_table_end = optional_end + sections * 40
    if (
        machine != expected_machine
        or not 1 <= sections <= 96
        or not 70 <= optional_bytes <= 4_096
        or optional_end < optional_start
        or section_table_end < optional_end
        or section_table_end > len(efi)
        or characteristics & 0x0002 == 0
        or struct.unpack_from("<H", efi, optional_start)[0] != PE32_PLUS_MAGIC
        or struct.unpack_from("<H", efi, optional_start + 68)[0]
        != PE_SUBSYSTEM_EFI_APPLICATION
    ):
        raise ValueError("ESP fallback executable is not an architecture-native EFI PE")


def verify_esp_payload(
    payload: bytes,
    architecture: str,
    expected_platform: str | None = None,
    *,
    bundle_kind: str,
) -> bytes:
    """Validate the complete canonical FAT32 ESP and return its EFI executable."""
    _validate_bundle_kind(bundle_kind)
    efi = _extract_fat32_efi(payload, architecture)
    _verify_pe_coff_machine(efi, architecture)
    contains_acceptance = any(marker in efi for marker in PRODUCTION_FORBIDDEN_MARKERS)
    if bundle_kind == BUNDLE_KIND_ACCEPTANCE:
        if not contains_acceptance:
            raise ValueError("acceptance ESP lacks an acceptance-only executable")
    elif contains_acceptance:
        raise ValueError("ESP contains an acceptance-only executable")
    if expected_platform is not None:
        if _IDENTIFIER.fullmatch(expected_platform) is None:
            raise ValueError("expected platform identifier is invalid")
        marker = expected_platform.encode("ascii")
        if efi.count(marker) != 1:
            raise ValueError(
                "EFI executable does not contain exactly one selected platform identity"
            )
    return efi


def _verify_boot_root_binding(efi: bytes, disk: GptDisk, root: GptPartition) -> None:
    """Require the EFI-embedded BMNT selector to name the packaged root."""
    magic = b"BMNTv1\0\0"
    if efi.count(magic) != 1:
        raise ValueError("EFI executable does not contain exactly one BMNT manifest")
    offset = efi.index(magic)
    if offset + 20 > len(efi):
        raise ValueError("EFI-embedded BMNT header is truncated")
    total_bytes = struct.unpack_from("<I", efi, offset + 16)[0]
    if not mkstorage.BMNT_HEADER_BYTES <= total_bytes <= 4_096:
        raise ValueError("EFI-embedded BMNT length is outside the bound")
    end = offset + total_bytes
    if end > len(efi):
        raise ValueError("EFI-embedded BMNT payload is truncated")
    manifest = efi[offset:end]
    mkstorage.verify_manifest(manifest)
    roots = [
        entry for entry in mkstorage.decode_manifest(manifest) if entry.name == "root"
    ]
    if len(roots) != 1:
        raise ValueError("EFI-embedded BMNT does not contain exactly one root role")
    root_entry = roots[0]
    filesystem_uuid = root.payload[1024 + 104 : 1024 + 120]
    if (
        root_entry.selector != "gpt"
        or root_entry.filesystem != "ext4-v1"
        or root_entry.disk_guid != disk.disk_guid
        or root_entry.partition_guid != root.unique_guid
        or root_entry.filesystem_identity != filesystem_uuid
    ):
        raise ValueError("EFI-embedded BMNT does not select the packaged root")


def _extract_root_content(payload: bytes) -> bytes:
    """Extract `/system.cspk` only after bounded ext4 metadata validation."""
    # The existing verifier intentionally accepts an expected CSPK rather than
    # trusting media to define its own expected content. For a self-contained
    # cloud bundle, first use the same bounded decoder to locate the candidate,
    # then rerun its public complete-tree verifier with those exact bytes.
    verifier = mkstorage._Ext4ProfileVerifier(payload, None)  # noqa: SLF001
    verifier._verify_superblock()  # noqa: SLF001
    verifier._verify_groups_and_bitmaps()  # noqa: SLF001
    verifier._verify_inodes_and_extents()  # noqa: SLF001
    if verifier.allocated_blocks != verifier.referenced_blocks:
        raise ValueError("ext4 allocation does not match referenced metadata")
    verifier._verify_journal()  # noqa: SLF001
    root = verifier.inode_records.get(mkstorage.EXT4_ROOT_INODE)
    if root is None or root.kind != "directory":
        raise ValueError("ext4 root inode is not a directory")
    entries = verifier._directory_entries(root)  # noqa: SLF001
    selected = entries.get("system.cspk")
    if selected is None or selected[1] != "file":
        raise ValueError("cloud root does not contain /system.cspk")
    inode = verifier.inode_records.get(selected[0])
    if inode is None or inode.kind != "file":
        raise ValueError("cloud root CSPK entry does not match its inode")
    content = verifier._read_file(inode)  # noqa: SLF001
    if not content:
        raise ValueError("cloud root contains an empty /system.cspk")
    return content


def verify_root_payload(payload: bytes) -> bytes:
    """Validate constrained ext4 and return its exact installed CSPK bytes."""
    if len(payload) != SYSTEM_ROOT_SECTORS * SECTOR_BYTES:
        raise ValueError("root partition has the wrong exact length")
    content = _extract_root_content(payload)
    mkstorage.verify_ext4(payload, content)
    return content


def _expect_source_root(image: bytes) -> tuple[GptDisk, GptPartition, bytes]:
    disk = parse_gpt(image)
    if len(disk.partitions) != 1:
        raise ValueError("root source disk must contain exactly one partition")
    root = disk.partitions[0]
    if (
        root.name != "root"
        or root.type_guid != LINUX_FILESYSTEM_TYPE_GUID
        or root.sectors != SYSTEM_ROOT_SECTORS
    ):
        raise ValueError("root source partition does not match the installed profile")
    content = verify_root_payload(root.payload)
    return disk, root, content


def _expect_seed_disk(image: bytes, role: str) -> GptDisk:
    if role == "activation":
        expected = (
            mkstorage.TXSLOT_DISK_GUID,
            mkstorage.TXSLOT_PARTITION_GUID,
            mkstorage.TXSLOT_TYPE_GUID,
        )
    elif role == "state":
        expected = (
            mkstorage.STATEFS_DISK_GUID,
            mkstorage.STATEFS_PARTITION_GUID,
            mkstorage.STATEFS_TYPE_GUID,
        )
    else:
        raise ValueError(f"unknown seed-disk role {role!r}")
    disk = parse_gpt(image)
    if (
        disk.total_sectors != mkstorage.TXSLOT_TOTAL_SECTORS
        or disk.disk_guid != expected[0]
        or len(disk.partitions) != 1
    ):
        raise ValueError(f"{role} seed disk has invalid GPT identity or geometry")
    partition = disk.partitions[0]
    if (
        partition.name != ("activation" if role == "activation" else "statefs")
        or partition.type_guid != expected[2]
        or partition.unique_guid != expected[1]
        or partition.first_lba != mkstorage.TXSLOT_PARTITION_START
        or partition.sectors != mkstorage.TXSLOT_PARTITION_SECTORS
        or any(partition.payload)
    ):
        raise ValueError(f"{role} seed partition is not canonical and empty")
    return disk


def build_system_disk(
    esp_payload: bytes,
    root_disk_guid: bytes,
    root_partition_guid: bytes,
    root_payload: bytes,
) -> bytes:
    """Combine a canonical FAT32 ESP and immutable root into one GPT system disk."""
    if len(esp_payload) != SYSTEM_ESP_SECTORS * SECTOR_BYTES:
        raise ValueError("FAT32 ESP has the wrong exact length")
    partitions = (
        GptPartition(
            name="esp",
            type_guid=ESP_TYPE_GUID,
            unique_guid=ESP_UNIQUE_GUID,
            first_lba=SYSTEM_ESP_START_LBA,
            last_lba=SYSTEM_ESP_START_LBA + SYSTEM_ESP_SECTORS - 1,
            payload=esp_payload,
        ),
        GptPartition(
            name="root",
            type_guid=LINUX_FILESYSTEM_TYPE_GUID,
            unique_guid=root_partition_guid,
            first_lba=SYSTEM_ROOT_START_LBA,
            last_lba=SYSTEM_ROOT_START_LBA + SYSTEM_ROOT_SECTORS - 1,
            payload=root_payload,
        ),
    )
    return build_gpt(root_disk_guid, SYSTEM_TOTAL_SECTORS, partitions)


def verify_system_disk(
    image: bytes,
    architecture: str,
    expected_platform: str | None = None,
    *,
    bundle_kind: str,
) -> GptDisk:
    _validate_bundle_kind(bundle_kind)
    disk = parse_gpt(image)
    if disk.total_sectors != SYSTEM_TOTAL_SECTORS or len(disk.partitions) != 2:
        raise ValueError("system disk has invalid total or partition count")
    esp, root = disk.partitions
    if (
        esp.name != "esp"
        or esp.type_guid != ESP_TYPE_GUID
        or esp.unique_guid != ESP_UNIQUE_GUID
        or esp.first_lba != SYSTEM_ESP_START_LBA
        or esp.sectors != SYSTEM_ESP_SECTORS
        or root.name != "root"
        or root.type_guid != LINUX_FILESYSTEM_TYPE_GUID
        or root.first_lba != SYSTEM_ROOT_START_LBA
        or root.sectors != SYSTEM_ROOT_SECTORS
    ):
        raise ValueError("system disk partition contract is invalid")
    efi = verify_esp_payload(
        esp.payload,
        architecture,
        expected_platform,
        bundle_kind=bundle_kind,
    )
    content = verify_root_payload(root.payload)
    _verify_content_identity_policy(content, bundle_kind)
    _verify_boot_root_binding(efi, disk, root)
    return disk


def _partition_metadata(partition: GptPartition) -> dict[str, object]:
    return {
        "end_lba": partition.last_lba,
        "name": partition.name,
        "payload_sha256": _sha256(partition.payload),
        "start_lba": partition.first_lba,
        "type_guid": _guid_text(partition.type_guid),
        "unique_guid": _guid_text(partition.unique_guid),
    }


def _disk_metadata(
    role: str, filename: str, image: bytes, disk: GptDisk, *, writable: bool
) -> dict[str, object]:
    return {
        "bytes": len(image),
        "disk_guid": _guid_text(disk.disk_guid),
        "filename": filename,
        "partitions": [_partition_metadata(item) for item in disk.partitions],
        "role": role,
        "sha256": _sha256(image),
        "writable": writable,
    }


def _bundle_manifest(
    *,
    platform: dict[str, object],
    environment: dict[str, object],
    images: dict[str, bytes],
    disks: dict[str, GptDisk],
    bundle_kind: str,
) -> dict[str, object]:
    _validate_bundle_kind(bundle_kind)
    return {
        "architecture": platform["architecture"],
        "artifact_status": environment["artifact_status"],
        "disks": [
            _disk_metadata(
                role,
                BUNDLE_FILENAMES[role],
                images[role],
                disks[role],
                writable=True,
            )
            for role in ("system", "activation", "state")
        ],
        "environment": environment["environment"],
        "format": BUNDLE_FORMAT,
        "firmware_discovery": platform["firmware_discovery"],
        "kind": bundle_kind,
        "matrix_entry": environment["id"],
        "platform": platform["name"],
        "platform_id": platform["id"],
        "runtime_status": environment["runtime_status"],
        "schema": 1,
        "sector_bytes": SECTOR_BYTES,
    }


def assemble_bundle(
    *,
    platform: dict[str, object],
    environment: dict[str, object],
    boot_fat: bytes,
    root_source: bytes,
    bundle_kind: str,
) -> tuple[dict[str, bytes], dict[str, object]]:
    """Create all bundle bytes without consulting paths or ambient environment."""
    _validate_bundle_kind(bundle_kind)
    if environment["platform"] != platform["name"]:
        raise ValueError("environment/platform selection is inconsistent")
    if environment["architecture"] != platform["architecture"]:
        raise ValueError("environment/platform architecture is inconsistent")
    architecture = str(platform["architecture"])
    efi = mkfat.extract(boot_fat, _fat32_boot_name(architecture))
    esp_payload = build_fat32_esp(efi, architecture)
    verify_esp_payload(
        esp_payload,
        architecture,
        str(platform["name"]),
        bundle_kind=bundle_kind,
    )
    source_disk, source_root, content = _expect_source_root(root_source)
    _verify_content_identity_policy(content, bundle_kind)
    _verify_boot_root_binding(efi, source_disk, source_root)
    system = build_system_disk(
        esp_payload,
        source_disk.disk_guid,
        source_root.unique_guid,
        source_root.payload,
    )
    activation = mkstorage.build_small_gpt(
        mkstorage.TXSLOT_DISK_GUID,
        mkstorage.TXSLOT_PARTITION_GUID,
        mkstorage.TXSLOT_TYPE_GUID,
        "activation",
    )
    state = mkstorage.build_small_gpt(
        mkstorage.STATEFS_DISK_GUID,
        mkstorage.STATEFS_PARTITION_GUID,
        mkstorage.STATEFS_TYPE_GUID,
        "statefs",
    )
    images = {"system": system, "activation": activation, "state": state}
    disks = {
        "system": verify_system_disk(
            system,
            str(platform["architecture"]),
            str(platform["name"]),
            bundle_kind=bundle_kind,
        ),
        "activation": _expect_seed_disk(activation, "activation"),
        "state": _expect_seed_disk(state, "state"),
    }
    manifest = _bundle_manifest(
        platform=platform,
        environment=environment,
        images=images,
        disks=disks,
        bundle_kind=bundle_kind,
    )
    return images, manifest


def _validate_manifest_structure(manifest: object) -> dict[str, object]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "architecture",
        "artifact_status",
        "disks",
        "environment",
        "format",
        "firmware_discovery",
        "kind",
        "matrix_entry",
        "platform",
        "platform_id",
        "runtime_status",
        "schema",
        "sector_bytes",
    }:
        raise ValueError("bundle manifest has an invalid field set")
    if (
        manifest["schema"] != 1
        or manifest["format"] != BUNDLE_FORMAT
        or manifest["firmware_discovery"] not in {"fixed", "acpi", "fdt"}
        or manifest["kind"] not in BUNDLE_KINDS
        or manifest["sector_bytes"] != SECTOR_BYTES
        or not isinstance(manifest["disks"], list)
        or len(manifest["disks"]) != 3
    ):
        raise ValueError("bundle manifest has an invalid schema or disk count")
    expected_disk_fields = {
        "bytes",
        "disk_guid",
        "filename",
        "partitions",
        "role",
        "sha256",
        "writable",
    }
    expected_partition_fields = {
        "end_lba",
        "name",
        "payload_sha256",
        "start_lba",
        "type_guid",
        "unique_guid",
    }
    for disk in manifest["disks"]:
        if not isinstance(disk, dict) or set(disk) != expected_disk_fields:
            raise ValueError("bundle disk record has an invalid field set")
        if (
            not isinstance(disk["bytes"], int)
            or isinstance(disk["bytes"], bool)
            or not 0 < disk["bytes"] <= MAX_DISK_BYTES
            or not isinstance(disk["sha256"], str)
            or _SHA256.fullmatch(disk["sha256"]) is None
            or not isinstance(disk["writable"], bool)
            or not isinstance(disk["partitions"], list)
            or not disk["partitions"]
            or len(disk["partitions"]) > 16
        ):
            raise ValueError("bundle disk record has invalid bounded values")
        _guid_bytes(disk["disk_guid"])
        for partition in disk["partitions"]:
            if (
                not isinstance(partition, dict)
                or set(partition) != expected_partition_fields
            ):
                raise ValueError("bundle partition record has an invalid field set")
            if (
                not isinstance(partition["start_lba"], int)
                or isinstance(partition["start_lba"], bool)
                or not isinstance(partition["end_lba"], int)
                or isinstance(partition["end_lba"], bool)
                or partition["start_lba"] > partition["end_lba"]
                or not isinstance(partition["payload_sha256"], str)
                or _SHA256.fullmatch(partition["payload_sha256"]) is None
                or not isinstance(partition["name"], str)
                or _PARTITION_NAME.fullmatch(partition["name"]) is None
            ):
                raise ValueError("bundle partition record has invalid bounded values")
            _guid_bytes(partition["type_guid"])
            _guid_bytes(partition["unique_guid"])
    return manifest


def verify_bundle(
    directory: Path,
    *,
    platform_manifest_path: Path = PLATFORM_MANIFEST_PATH,
    environment_matrix_path: Path = ENVIRONMENT_MATRIX_PATH,
    allow_test_artifacts: bool = False,
) -> dict[str, object]:
    """Verify every byte, format relation, and metadata claim in one bundle."""
    expected_names = set(BUNDLE_FILENAMES.values()) | {BUNDLE_MANIFEST}
    try:
        actual_names = {entry.name for entry in directory.iterdir()}
    except OSError as error:
        raise ValueError(f"cannot enumerate bundle {directory}: {error}") from error
    if actual_names != expected_names:
        raise ValueError("bundle contains missing or unexpected files")
    raw_manifest = _read_bounded(
        directory / BUNDLE_MANIFEST, MAX_MANIFEST_BYTES, "bundle manifest"
    )
    try:
        decoded = json.loads(raw_manifest)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid bundle manifest JSON: {error}") from error
    if raw_manifest != _canonical_json(decoded):
        raise ValueError("bundle manifest is not canonical JSON")
    manifest = _validate_manifest_structure(decoded)
    bundle_kind = str(manifest["kind"])
    if bundle_kind != BUNDLE_KIND_PRODUCTION and not allow_test_artifacts:
        raise ValueError(
            "test-artifact bundle requires explicit verification authority"
        )

    platforms = load_platform_manifest(platform_manifest_path)
    entries = load_environment_matrix(environment_matrix_path, platforms)
    platform_name = manifest["platform"]
    environment_name = manifest["environment"]
    if not isinstance(platform_name, str) or platform_name not in platforms:
        raise ValueError("bundle references an unknown platform")
    if not isinstance(environment_name, str):
        raise ValueError("bundle environment is invalid")
    environment = resolve_environment(entries, platform_name, environment_name)
    platform = platforms[platform_name]

    images = {
        role: _read_bounded(directory / filename, MAX_DISK_BYTES, f"{role} disk")
        for role, filename in BUNDLE_FILENAMES.items()
    }
    disks = {
        "system": verify_system_disk(
            images["system"],
            str(platform["architecture"]),
            str(platform["name"]),
            bundle_kind=bundle_kind,
        ),
        "activation": _expect_seed_disk(images["activation"], "activation"),
        "state": _expect_seed_disk(images["state"], "state"),
    }
    expected = _bundle_manifest(
        platform=platform,
        environment=environment,
        images=images,
        disks=disks,
        bundle_kind=bundle_kind,
    )
    if manifest != expected:
        raise ValueError("bundle metadata does not exactly describe the verified disks")
    return manifest


def build_bundle(
    *,
    platform_name: str,
    environment_name: str,
    boot_path: Path,
    root_path: Path,
    output_directory: Path,
    bundle_kind: str,
    platform_manifest_path: Path = PLATFORM_MANIFEST_PATH,
    environment_matrix_path: Path = ENVIRONMENT_MATRIX_PATH,
) -> dict[str, object]:
    """Atomically publish a deterministic bundle after complete verification."""
    _validate_bundle_kind(bundle_kind)
    platforms = load_platform_manifest(platform_manifest_path)
    if platform_name not in platforms:
        raise ValueError(f"unknown platform {platform_name!r}")
    entries = load_environment_matrix(environment_matrix_path, platforms)
    environment = resolve_environment(entries, platform_name, environment_name)
    platform = platforms[platform_name]
    boot = _read_bounded(boot_path, mkfat.IMAGE_SIZE, "boot FAT image")
    if len(boot) != mkfat.IMAGE_SIZE:
        raise ValueError("boot FAT image has the wrong exact length")
    root = _read_bounded(root_path, MAX_DISK_BYTES, "root source disk")
    images, manifest = assemble_bundle(
        platform=platform,
        environment=environment,
        boot_fat=boot,
        root_source=root,
        bundle_kind=bundle_kind,
    )

    if output_directory.exists():
        raise ValueError(f"output directory already exists: {output_directory}")
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}-", dir=output_directory.parent
        )
    )
    try:
        for role, filename in BUNDLE_FILENAMES.items():
            (staging / filename).write_bytes(images[role])
        (staging / BUNDLE_MANIFEST).write_bytes(_canonical_json(manifest))
        verify_bundle(
            staging,
            platform_manifest_path=platform_manifest_path,
            environment_matrix_path=environment_matrix_path,
            allow_test_artifacts=bundle_kind != BUNDLE_KIND_PRODUCTION,
        )
        staging.rename(output_directory)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform-manifest", type=Path, default=PLATFORM_MANIFEST_PATH
    )
    parser.add_argument(
        "--environment-matrix", type=Path, default=ENVIRONMENT_MATRIX_PATH
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build and verify a new bundle")
    build.add_argument("--platform", required=True)
    build.add_argument("--environment", required=True)
    build.add_argument("--boot", type=Path, required=True)
    build.add_argument("--root", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--kind", choices=BUNDLE_KINDS, required=True)

    verify = subparsers.add_parser("verify", help="verify an existing bundle only")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--allow-test-artifacts", action="store_true")

    subparsers.add_parser("matrix", help="validate and print the support matrix")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "build":
            manifest = build_bundle(
                platform_name=args.platform,
                environment_name=args.environment,
                boot_path=args.boot,
                root_path=args.root,
                output_directory=args.output,
                bundle_kind=args.kind,
                platform_manifest_path=args.platform_manifest,
                environment_matrix_path=args.environment_matrix,
            )
            print(
                f"cloud bundle {manifest['platform']}/{manifest['environment']} "
                f"-> {args.output}"
            )
        elif args.command == "verify":
            manifest = verify_bundle(
                args.bundle,
                platform_manifest_path=args.platform_manifest,
                environment_matrix_path=args.environment_matrix,
                allow_test_artifacts=args.allow_test_artifacts,
            )
            print(
                f"verified cloud bundle {manifest['platform']}/"
                f"{manifest['environment']}: {args.bundle}"
            )
        else:
            platforms = load_platform_manifest(args.platform_manifest)
            entries = load_environment_matrix(args.environment_matrix, platforms)
            for entry in entries:
                platform = entry["platform"] or "none"
                print(
                    f"{entry['id']}: {entry['runtime_status']}; "
                    f"platform={platform}; artifact={entry['artifact_status']}"
                )
        return 0
    except (OSError, ValueError) as error:
        print(f"mkcloud: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

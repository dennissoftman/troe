#!/usr/bin/env python3
"""Create a canonical CSPK v1 pack from the deterministic SCFG fixture."""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path


USER_ID = bytes([1]) * 16
GROUP_ID = bytes([2]) * 16
DOMAIN_ID = bytes([3]) * 16


def checked(image: bytearray, offset: int) -> bytes:
    """Publish one CRC32 field after treating it as zero."""
    image[offset:offset + 4] = b"\0" * 4
    struct.pack_into("<I", image, offset, zlib.crc32(image))
    return bytes(image)


def build_registry(generation: int) -> bytes:
    """Encode the deterministic two-principal IREG v1 fixture."""
    labels = b"usergroup"
    image = bytearray(64 + 2 * 64 + len(labels))
    image[:8] = b"IREGv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 64, len(image))
    struct.pack_into("<IIIQ", image, 24, 2, 0, len(labels), generation)
    user = memoryview(image)[64:128]
    user[:16] = USER_ID
    user[16:19] = bytes((1, 1, 1))
    struct.pack_into("<IH", user, 24, 0, 4)
    group = memoryview(image)[128:192]
    group[:16] = GROUP_ID
    group[16:19] = bytes((2, 1, 2))
    struct.pack_into("<IH", group, 24, 4, 5)
    image[192:] = labels
    return checked(image, 20)


def build_mapping(version: int) -> bytes:
    """Encode a UID-0/GID-0 IMAP v1 snapshot for one domain."""
    image = bytearray(64 + 2 * 128)
    image[:8] = b"IMAPv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 128, len(image))
    struct.pack_into("<I", image, 24, 2)
    struct.pack_into("<Q", image, 32, version)
    image[40:56] = DOMAIN_ID
    for index, (kind, target) in enumerate(((1, USER_ID), (2, GROUP_ID))):
        record = memoryview(image)[64 + index * 128:192 + index * 128]
        struct.pack_into("<I", record, 0, 1)
        record[4:6] = bytes((kind, 4))
        record[8:24] = target
    return checked(image, 20)


def build_mount(version: int) -> bytes:
    """Encode the root role's explicit immutable mapping policy."""
    image = bytearray(192)
    image[:8] = b"IMNTv1\0\0"
    struct.pack_into("<HHHBB", image, 8, 1, 0, 192, 2, 1)
    struct.pack_into("<H", image, 20, 4)
    image[32:36] = b"root"
    image[64:80] = DOMAIN_ID
    struct.pack_into("<Q", image, 80, version)
    return checked(image, 16)


def build_acl() -> bytes:
    """Encode a canonical owner/group/other read-only IACL v1 root."""
    image = bytearray(64 + 3 * 32)
    image[:8] = b"IACLv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 32, len(image))
    struct.pack_into("<I", image, 24, 3)
    for index, tag in enumerate((1, 3, 6)):
        image[64 + index * 32:66 + index * 32] = bytes((tag, 4))
    return checked(image, 20)


def build_security_manifest(generation: int, objects: list[tuple[int, bytes]]) -> bytes:
    """Encode ISEC v1 over registry, mapping, mount, and ACL objects."""
    image = bytearray(192)
    image[:8] = b"ISECv1\0\0"
    struct.pack_into("<HHHHQ", image, 8, 1, 0, 192, 0, generation)
    for offset, (_, data) in zip((24, 56, 88, 120), objects, strict=True):
        image[offset:offset + 32] = hashlib.sha256(data).digest()
    return checked(image, 152)


def identity_objects(generation: int) -> tuple[bytes, list[tuple[int, bytes]]]:
    """Return one complete typed security snapshot and its root."""
    objects = [
        (5, build_registry(generation)),
        (6, build_mapping(generation)),
        (7, build_mount(generation)),
        (8, build_acl()),
    ]
    security = build_security_manifest(generation, objects)
    return security, [*objects, (9, security)]


def build_manifest(config: bytes, previous: bytes | None, security: bytes) -> bytes:
    """Encode one canonical GMAN v1 generation root."""
    image = bytearray(128)
    image[:8] = b"GMANv1\0\0"
    struct.pack_into("<HHH", image, 8, 1, 0, 128)
    flags = 2 | int(previous is not None)
    struct.pack_into("<H", image, 14, flags)
    generation = struct.unpack_from("<Q", config, 24)[0]
    struct.pack_into("<Q", image, 16, generation)
    image[24:56] = hashlib.sha256(config).digest()
    if previous is not None:
        image[56:88] = hashlib.sha256(previous).digest()
    image[96:128] = hashlib.sha256(security).digest()
    return checked(image, 88)


def build_pack(config: bytes, previous_config: bytes | None) -> bytes:
    """Encode digest-sorted SCFG and generation-manifest objects."""
    generation = struct.unpack_from("<Q", config, 24)[0]
    active_security, active_identity = identity_objects(generation)
    objects = [(1, config), *active_identity]
    if previous_config is not None:
        previous_generation = struct.unpack_from("<Q", previous_config, 24)[0]
        previous_security, previous_identity = identity_objects(previous_generation)
        previous_manifest = build_manifest(previous_config, None, previous_security)
        active_manifest = build_manifest(config, previous_manifest, active_security)
        objects.extend(
            (
                (1, previous_config),
                *previous_identity,
                (3, previous_manifest),
                (3, active_manifest),
            )
        )
    else:
        objects.append((3, build_manifest(config, None, active_security)))
    unique: dict[bytes, tuple[int, bytes]] = {}
    for kind, data in objects:
        digest = hashlib.sha256(data).digest()
        previous = unique.get(digest)
        if previous is not None and previous != (kind, data):
            raise ValueError("one content identity has conflicting object kinds")
        unique[digest] = (kind, data)
    addressed = sorted(
        ((digest, kind, data) for digest, (kind, data) in unique.items()),
        key=lambda item: item[0],
    )
    table_end = 64 + 64 * len(addressed)
    image = bytearray(table_end + sum(len(data) for _, _, data in addressed))
    image[:8] = b"CSPKv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 64, len(image))
    struct.pack_into("<H", image, 24, len(addressed))
    offset = table_end
    for index, (digest, kind, data) in enumerate(addressed):
        record = memoryview(image)[64 + index * 64:128 + index * 64]
        record[:32] = digest
        record[32] = kind
        struct.pack_into("<II", record, 40, offset, len(data))
        image[offset:offset + len(data)] = data
        offset += len(data)
    checked = bytearray(image)
    checked[20:24] = b"\0" * 4
    struct.pack_into("<I", image, 20, zlib.crc32(checked))
    return bytes(image)


def write_reference(image: bytearray, offset: int, config: bytes) -> None:
    """Write one SACT SCFG reference."""
    generation = struct.unpack_from("<Q", config, 24)[0]
    config_crc = struct.unpack_from("<I", config, 20)[0]
    struct.pack_into("<QII", image, offset, generation, len(config), config_crc)
    image[offset + 16:offset + 48] = hashlib.sha256(config).digest()


def build_activation(config: bytes, previous_config: bytes | None) -> bytes:
    """Encode the bootstrap SACT pointer for the pack's SCFG object."""
    if config[:8] != b"SCFGv1\0\0" or len(config) > 0xFFFF_FFFF:
        raise ValueError("configuration is not a bounded SCFG v1 image")
    image = bytearray(128)
    image[:8] = b"SACTv1\0\0"
    struct.pack_into("<HHH", image, 8, 1, 0, 128)
    if previous_config is not None:
        struct.pack_into("<H", image, 14, 1)
    write_reference(image, 16, config)
    if previous_config is not None:
        write_reference(image, 64, previous_config)
    checked = bytearray(image)
    checked[112:116] = b"\0" * 4
    struct.pack_into("<I", image, 112, zlib.crc32(checked))
    return bytes(image)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--previous-config", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--activation-output", type=Path)
    args = parser.parse_args()
    try:
        config = args.config.read_bytes()
        previous_config = (
            args.previous_config.read_bytes() if args.previous_config is not None else None
        )
        pack = build_pack(config, previous_config)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(pack)
        print(f"CSPK v1: {len(pack)} bytes -> {args.output}")
        if args.activation_output is not None:
            activation = build_activation(config, previous_config)
            args.activation_output.parent.mkdir(parents=True, exist_ok=True)
            args.activation_output.write_bytes(activation)
            print(f"SACT v1: {len(activation)} bytes -> {args.activation_output}")
        return 0
    except (OSError, ValueError) as error:
        print(f"mkcontent: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

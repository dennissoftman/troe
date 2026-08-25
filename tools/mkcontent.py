#!/usr/bin/env python3
"""Create canonical CSPK v1 content with explicit fixture or deployment identities."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path


USER_ID = bytes([1]) * 16
GROUP_ID = bytes([2]) * 16
DOMAIN_ID = bytes([3]) * 16
RESERVED_FIXTURE_IDS = frozenset((USER_ID, GROUP_ID, DOMAIN_ID))


@dataclass(frozen=True)
class IdentityIds:
    """Opaque principal and domain identifiers used by one content pack."""

    user: bytes
    group: bytes
    domain: bytes


FIXTURE_IDENTITIES = IdentityIds(USER_ID, GROUP_ID, DOMAIN_ID)


def load_deployment_identities(path: Path) -> IdentityIds:
    """Load a provisioned deployment identity file and reject fixture IDs."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read deployment identities {path}: {error}") from error
    expected = {"schema", "user_id", "group_id", "domain_id"}
    if not isinstance(document, dict) or set(document) != expected or document["schema"] != 1:
        raise ValueError("deployment identity file has an invalid schema")

    values: list[bytes] = []
    for field in ("user_id", "group_id", "domain_id"):
        encoded = document[field]
        if (
            not isinstance(encoded, str)
            or re.fullmatch(r"[0-9a-f]{32}", encoded) is None
        ):
            raise ValueError(f"deployment {field} must be 32 lowercase hexadecimal digits")
        try:
            value = bytes.fromhex(encoded)
        except ValueError as error:
            raise ValueError(f"deployment {field} is not hexadecimal") from error
        if value == bytes(16) or value in RESERVED_FIXTURE_IDS:
            raise ValueError(f"deployment {field} is zero or reserved for fixtures")
        values.append(value)
    if len(set(values)) != len(values):
        raise ValueError("deployment principal and domain identifiers must be distinct")
    return IdentityIds(*values)


def checked(image: bytearray, offset: int) -> bytes:
    """Publish one CRC32 field after treating it as zero."""
    image[offset:offset + 4] = b"\0" * 4
    struct.pack_into("<I", image, offset, zlib.crc32(image))
    return bytes(image)


def build_registry(
    generation: int, identities: IdentityIds = FIXTURE_IDENTITIES
) -> bytes:
    """Encode the selected two-principal IREG v1 snapshot."""
    labels = b"usergroup"
    image = bytearray(64 + 2 * 64 + len(labels))
    image[:8] = b"IREGv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 64, len(image))
    struct.pack_into("<IIIQ", image, 24, 2, 0, len(labels), generation)
    user = memoryview(image)[64:128]
    user[:16] = identities.user
    user[16:19] = bytes((1, 1, 1))
    struct.pack_into("<IH", user, 24, 0, 4)
    group = memoryview(image)[128:192]
    group[:16] = identities.group
    group[16:19] = bytes((2, 1, 2))
    struct.pack_into("<IH", group, 24, 4, 5)
    image[192:] = labels
    return checked(image, 20)


def build_mapping(
    version: int, identities: IdentityIds = FIXTURE_IDENTITIES
) -> bytes:
    """Encode a UID-0/GID-0 IMAP v1 snapshot for one domain."""
    image = bytearray(64 + 2 * 128)
    image[:8] = b"IMAPv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 128, len(image))
    struct.pack_into("<I", image, 24, 2)
    struct.pack_into("<Q", image, 32, version)
    image[40:56] = identities.domain
    for index, (kind, target) in enumerate(
        ((1, identities.user), (2, identities.group))
    ):
        record = memoryview(image)[64 + index * 128:192 + index * 128]
        struct.pack_into("<I", record, 0, 1)
        record[4:6] = bytes((kind, 4))
        record[8:24] = target
    return checked(image, 20)


def build_mount(version: int, identities: IdentityIds = FIXTURE_IDENTITIES) -> bytes:
    """Encode the root role's explicit immutable mapping policy."""
    image = bytearray(192)
    image[:8] = b"IMNTv1\0\0"
    struct.pack_into("<HHHBB", image, 8, 1, 0, 192, 2, 1)
    struct.pack_into("<H", image, 20, 4)
    image[32:36] = b"root"
    image[64:80] = identities.domain
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


def identity_objects(
    generation: int, identities: IdentityIds = FIXTURE_IDENTITIES
) -> tuple[bytes, list[tuple[int, bytes]]]:
    """Return one complete typed security snapshot and its root."""
    objects = [
        (5, build_registry(generation, identities)),
        (6, build_mapping(generation, identities)),
        (7, build_mount(generation, identities)),
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


def build_pack(
    config: bytes,
    previous_config: bytes | None,
    identities: IdentityIds = FIXTURE_IDENTITIES,
) -> bytes:
    """Encode digest-sorted SCFG and generation-manifest objects."""
    generation = struct.unpack_from("<Q", config, 24)[0]
    active_security, active_identity = identity_objects(generation, identities)
    objects = [(1, config), *active_identity]
    if previous_config is not None:
        previous_generation = struct.unpack_from("<Q", previous_config, 24)[0]
        previous_security, previous_identity = identity_objects(
            previous_generation, identities
        )
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
    identity_source = parser.add_mutually_exclusive_group(required=True)
    identity_source.add_argument(
        "--fixture-identities",
        action="store_true",
        help="use reserved deterministic acceptance-only identifiers",
    )
    identity_source.add_argument(
        "--identity-file",
        type=Path,
        help="use a deployment identity file created by mkidentity.py",
    )
    args = parser.parse_args()
    try:
        config = args.config.read_bytes()
        previous_config = (
            args.previous_config.read_bytes() if args.previous_config is not None else None
        )
        identities = (
            FIXTURE_IDENTITIES
            if args.fixture_identities
            else load_deployment_identities(args.identity_file)
        )
        pack = build_pack(config, previous_config, identities)
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

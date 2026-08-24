#!/usr/bin/env python3
"""Create a canonical CSPK v1 pack from the deterministic SCFG fixture."""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path


def build_manifest(config: bytes, previous: bytes | None) -> bytes:
    """Encode one canonical GMAN v1 generation root."""
    image = bytearray(128)
    image[:8] = b"GMANv1\0\0"
    struct.pack_into("<HHH", image, 8, 1, 0, 128)
    if previous is not None:
        struct.pack_into("<H", image, 14, 1)
    struct.pack_into("<Q", image, 16, struct.unpack_from("<Q", config, 24)[0])
    image[24:56] = hashlib.sha256(config).digest()
    if previous is not None:
        image[56:88] = hashlib.sha256(previous).digest()
    checked = bytearray(image)
    checked[88:92] = b"\0" * 4
    struct.pack_into("<I", image, 88, zlib.crc32(checked))
    return bytes(image)


def build_pack(config: bytes, previous_config: bytes | None) -> bytes:
    """Encode digest-sorted SCFG and generation-manifest objects."""
    objects = [(1, config)]
    if previous_config is not None:
        previous_manifest = build_manifest(previous_config, None)
        active_manifest = build_manifest(config, previous_manifest)
        objects.extend(((1, previous_config), (3, previous_manifest), (3, active_manifest)))
    else:
        objects.append((3, build_manifest(config, None)))
    addressed = sorted(
        ((hashlib.sha256(data).digest(), kind, data) for kind, data in objects),
        key=lambda item: item[0],
    )
    if len({digest for digest, _, _ in addressed}) != len(addressed):
        raise ValueError("content objects are not unique")
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

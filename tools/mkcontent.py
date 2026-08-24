#!/usr/bin/env python3
"""Create a canonical CSPK v1 pack from the deterministic SCFG fixture."""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path


def build_pack(config: bytes) -> bytes:
    """Encode one SHA-256-addressed system-configuration object."""
    table_end = 64 + 64
    image = bytearray(table_end + len(config))
    image[:8] = b"CSPKv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 64, len(image))
    struct.pack_into("<H", image, 24, 1)
    record = memoryview(image)[64:128]
    record[:32] = hashlib.sha256(config).digest()
    record[32] = 1  # SCFG object
    struct.pack_into("<II", record, 40, table_end, len(config))
    image[table_end:] = config
    checked = bytearray(image)
    checked[20:24] = b"\0" * 4
    struct.pack_into("<I", image, 20, zlib.crc32(checked))
    return bytes(image)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        pack = build_pack(args.config.read_bytes())
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(pack)
        print(f"CSPK v1: {len(pack)} bytes -> {args.output}")
        return 0
    except OSError as error:
        print(f"mkcontent: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

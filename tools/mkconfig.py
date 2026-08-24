#!/usr/bin/env python3
"""Create the deterministic minimal SCFG v1 QEMU activation fixture."""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path


def build_config() -> bytes:
    """Encode generation one with one required recovery-bounded shell service."""
    strings = b"shell/bin/shell.kex"
    image = bytearray(64 + 64 + len(strings))
    image[:8] = b"SCFGv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 64, len(image))
    struct.pack_into("<QQHBBII", image, 24, 1, 0, 1, 3, 2, 30_000, len(strings))

    record = memoryview(image)[64:128]
    struct.pack_into("<I", record, 0, 1)
    record[4] = 1  # boot required
    record[5] = 4  # recovery shell on failure
    record[7] = 2  # initial handle ceiling
    struct.pack_into("<H", record, 8, 50)
    struct.pack_into("<II", record, 12, 5_000, 60_000)
    struct.pack_into("<IH", record, 40, 0, 5)
    struct.pack_into("<IH", record, 48, 5, 14)
    image[128:] = strings

    checked = bytearray(image)
    checked[20:24] = b"\0" * 4
    struct.pack_into("<I", image, 20, zlib.crc32(checked))
    return bytes(image)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        image = build_config()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(image)
        print(f"SCFG v1: {len(image)} bytes -> {args.output}")
        return 0
    except OSError as error:
        print(f"mkconfig: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

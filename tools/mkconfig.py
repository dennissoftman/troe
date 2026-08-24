#!/usr/bin/env python3
"""Create the deterministic minimal SCFG v1 QEMU activation fixture."""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path


def build_config(generation: int, previous: int) -> bytes:
    """Encode one generation with one required recovery-bounded shell service."""
    if generation <= 0 or previous < 0 or previous >= generation:
        raise ValueError("invalid generation relationship")
    strings = b"shell/bin/shell.kex"
    image = bytearray(64 + 64 + len(strings))
    image[:8] = b"SCFGv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 0, 64, 64, len(image))
    flags = 2 | (1 if previous else 0)
    struct.pack_into(
        "<QQHBBII", image, 24, generation, previous, 1, 3, flags, 30_000, len(strings)
    )

    record = memoryview(image)[64:128]
    struct.pack_into("<I", record, 0, 1)
    record[4] = 1  # boot required
    record[5] = 3 if previous else 4  # predecessor, else static recovery shell
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
    parser.add_argument("--previous-output", type=Path)
    args = parser.parse_args()
    try:
        image = build_config(2, 1)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(image)
        print(f"SCFG v1: {len(image)} bytes -> {args.output}")
        if args.previous_output is not None:
            previous = build_config(1, 0)
            args.previous_output.parent.mkdir(parents=True, exist_ok=True)
            args.previous_output.write_bytes(previous)
            print(f"SCFG v1 predecessor: {len(previous)} bytes -> {args.previous_output}")
        return 0
    except (OSError, ValueError) as error:
        print(f"mkconfig: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

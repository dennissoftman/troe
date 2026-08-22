#!/usr/bin/env python3
"""Build or verify the deterministic, bounds-checkable KEFS v1 root image."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = b"KLLMFS1\0"
HEADER_SIZE = 16
MAX_ENTRIES = 0xFFFF
MAX_PATH = 256


def collect(root: Path) -> list[tuple[int, str, bytes]]:
    if not root.is_dir():
        raise ValueError(f"root is not a directory: {root}")
    entries: list[tuple[int, str, bytes]] = []
    for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if candidate.is_symlink():
            raise ValueError(f"symbolic links are forbidden: {candidate}")
        relative = candidate.relative_to(root).as_posix()
        encoded = ("/" + relative).encode("utf-8")
        if b"\0" in encoded or len(encoded) > MAX_PATH:
            raise ValueError(f"invalid or oversized path: {relative}")
        if candidate.is_dir():
            entries.append((2, "/" + relative, b""))
        elif candidate.is_file():
            entries.append((1, "/" + relative, candidate.read_bytes()))
        else:
            raise ValueError(f"unsupported filesystem object: {candidate}")
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"too many entries: {len(entries)}")
    entries.sort(key=lambda entry: entry[1].encode("utf-8"))
    return entries


def build(root: Path) -> bytes:
    entries = collect(root)
    records = bytearray()
    for kind, path, payload in entries:
        encoded_path = path.encode("utf-8")
        if len(payload) > 0xFFFF_FFFF:
            raise ValueError(f"file is too large: {path}")
        records += struct.pack("<BHI", kind, len(encoded_path), len(payload))
        records += encoded_path
        records += payload
    total = HEADER_SIZE + len(records)
    if total > 0xFFFF_FFFF:
        raise ValueError("image is too large")
    return MAGIC + struct.pack("<HHI", len(entries), 0, total) + records


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--check", action="store_true", help="fail unless output already matches"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        image = build(args.root.resolve())
        if args.check:
            existing = args.output.read_bytes()
            if existing != image:
                print(f"stale embedded filesystem: {args.output}", file=sys.stderr)
                return 1
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(image)
        print(f"KEFS v1: {len(image)} bytes -> {args.output}")
        return 0
    except (OSError, ValueError) as error:
        print(f"mkefs: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


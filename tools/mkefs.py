#!/usr/bin/env python3
"""Build or verify the deterministic, bounds-checkable KEFS v1 root image."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = b"KEFSv1\0\0"
HEADER_SIZE = 16
MAX_ENTRIES = 0xFFFF
MAX_PATH = 256
MOUNTPOINT_SENTINEL = ".mountpoint"
Entry = tuple[int, str, bytes]


def collect(root: Path) -> list[Entry]:
    if not root.is_dir():
        raise ValueError(f"root is not a directory: {root}")
    entries: list[Entry] = []
    for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if candidate.is_symlink():
            raise ValueError(f"symbolic links are forbidden: {candidate}")
        if candidate.is_file() and candidate.name == MOUNTPOINT_SENTINEL:
            continue
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


def encode(entries: list[Entry]) -> bytes:
    """Encode an already normalized source tree as canonical KEFS v1 bytes."""
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"too many entries: {len(entries)}")
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


def build(root: Path) -> bytes:
    """Collect and encode one normalized source tree."""
    return encode(collect(root))


def checked_slice(image: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    """Return one checked image slice and its exclusive end offset."""
    end = offset + length
    if length < 0 or offset < 0 or end > len(image):
        raise ValueError(f"truncated KEFS {label}")
    return image[offset:end], end


def decode(image: bytes) -> list[Entry]:
    """Independently decode and validate one canonical KEFS v1 image."""
    if len(image) < HEADER_SIZE or image[:8] != MAGIC:
        raise ValueError("invalid KEFS header or magic")
    count, reserved, declared_length = struct.unpack_from("<HHI", image, 8)
    if reserved != 0 or declared_length != len(image):
        raise ValueError("invalid KEFS reserved field or total length")

    entries: list[Entry] = []
    kinds: dict[str, int] = {}
    previous_path: bytes | None = None
    offset = HEADER_SIZE
    for _ in range(count):
        header, offset = checked_slice(image, offset, 7, "record header")
        kind, path_length, data_length = struct.unpack("<BHI", header)
        if kind not in (1, 2) or path_length == 0 or path_length > MAX_PATH:
            raise ValueError("invalid KEFS record kind or path length")
        raw_path, offset = checked_slice(image, offset, path_length, "path")
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("KEFS path is not valid UTF-8") from error
        components = path.split("/")
        if (
            not path.startswith("/")
            or path == "/"
            or "\0" in path
            or components[0] != ""
            or any(component in ("", ".", "..") for component in components[1:])
        ):
            raise ValueError("KEFS path is not normalized")
        if previous_path is not None and raw_path <= previous_path:
            raise ValueError("KEFS paths are not strictly byte-lexical")
        parent = path.rsplit("/", 1)[0] or "/"
        if parent != "/" and kinds.get(parent) != 2:
            raise ValueError("KEFS parent directory is absent or out of order")
        payload, offset = checked_slice(image, offset, data_length, "payload")
        if kind == 2 and payload:
            raise ValueError("KEFS directory contains payload bytes")
        entries.append((kind, path, payload))
        kinds[path] = kind
        previous_path = raw_path

    if offset != len(image):
        raise ValueError("KEFS image has trailing records or bytes")
    return entries


def verify_tree(image: bytes, expected: list[Entry]) -> None:
    """Require the decoded artifact to equal the exact normalized source tree."""
    if decode(image) != expected:
        raise ValueError("KEFS round-trip does not reproduce the exact source tree")


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
        expected = collect(args.root.resolve())
        if args.check:
            image = args.output.read_bytes()
        else:
            image = encode(expected)
        verify_tree(image, expected)
        if not args.check:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(image)
        print(f"KEFS v1: {len(image)} bytes -> {args.output}")
        return 0
    except (OSError, ValueError) as error:
        print(f"mkefs: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Report deterministic PE/COFF and boot-container size attribution."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


def pe_sections(image: bytes) -> list[tuple[str, int, int]]:
    if len(image) < 64 or image[:2] != b"MZ":
        raise ValueError("EFI executable has no DOS/PE header")
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if pe_offset + 24 > len(image) or image[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("EFI executable has no valid PE signature")
    section_count = struct.unpack_from("<H", image, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe_offset + 20)[0]
    table = pe_offset + 24 + optional_size
    end = table + section_count * 40
    if end > len(image):
        raise ValueError("PE section table exceeds the executable")
    sections: list[tuple[str, int, int]] = []
    for index in range(section_count):
        offset = table + index * 40
        raw_name = image[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", image, offset + 8)[0]
        raw_size = struct.unpack_from("<I", image, offset + 16)[0]
        raw_offset = struct.unpack_from("<I", image, offset + 20)[0]
        if raw_size and (raw_offset > len(image) or raw_size > len(image) - raw_offset):
            raise ValueError(f"PE section {name} exceeds the executable")
        sections.append((name, raw_size, virtual_size))
    return sections


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--efi", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    args = parser.parse_args()
    try:
        efi = args.efi.read_bytes()
        rootfs = args.rootfs.read_bytes()
        container = args.image.read_bytes()
        sections = pe_sections(efi)
        debug = sum(raw for name, raw, _ in sections if "debug" in name.lower())
        print(f"boot image size report ({args.arch})")
        print(f"  boot container:             {len(container):>8} bytes")
        print(f"  EFI executable:             {len(efi):>8} bytes")
        for name, raw_size, virtual_size in sections:
            print(
                f"    PE {name:<8} raw:         {raw_size:>8} bytes "
                f"(virtual {virtual_size})"
            )
        print(
            f"  embedded KEFS source:       {len(rootfs):>8} bytes "
            "(included in PE read-only data)"
        )
        print(
            f"  architecture boundary cap:  {len(efi):>8} bytes "
            "(conservative whole-EFI upper bound)"
        )
        print(
            f"  debug information:          {debug:>8} bytes in deployable PE sections"
        )
        print(f"  container overhead/padding: {len(container) - len(efi):>8} bytes")
        if len(container) > 16 * 1024 * 1024:
            raise ValueError("boot container exceeds the 16 MiB hard ceiling")
        return 0
    except (OSError, ValueError) as error:
        print(f"size_report: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

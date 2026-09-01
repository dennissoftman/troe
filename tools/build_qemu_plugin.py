#!/usr/bin/env python3
"""Build the host-side QEMU TCG guest-work counting plugin.

The plugin is GPL-2.0-or-later because it includes QEMU's plugin header. It is
a measurement tool loaded by QEMU and is never linked into a TROE artifact.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "tools" / "qemu-plugin" / "troe_count.c"
HEADER = "qemu-plugin.h"
INCLUDE_CANDIDATES = (
    Path("/opt/homebrew/include"),
    Path("/usr/local/include"),
    Path("/usr/include"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        default=REPO_ROOT / "build" / "qemu-plugin" / "troe_count.so",
        help="shared object to write",
    )
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument(
        "--qemu-include",
        type=Path,
        help=f"directory holding {HEADER} (auto-detected by default)",
    )
    return parser.parse_args()


def find_qemu_include(explicit: Path | None) -> Path:
    if explicit is not None:
        if not (explicit / HEADER).is_file():
            raise RuntimeError(f"{HEADER} is not in {explicit}")
        return explicit
    for candidate in INCLUDE_CANDIDATES:
        if (candidate / HEADER).is_file():
            return candidate
    raise RuntimeError(
        f"{HEADER} was not found; install QEMU development headers or pass "
        "--qemu-include"
    )


def glib_flags() -> list[str]:
    if shutil.which("pkg-config") is None:
        raise RuntimeError("pkg-config is required to locate glib-2.0 headers")
    completed = subprocess.run(
        ["pkg-config", "--cflags", "glib-2.0"],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError("pkg-config could not describe glib-2.0")
    return completed.stdout.split()


def link_flags() -> list[str]:
    # QEMU resolves the plugin API from its own executable at load time, so the
    # shared object deliberately leaves those symbols undefined.
    if platform.system() == "Darwin":
        return ["-Wl,-undefined,dynamic_lookup"]
    return []


def build(output: Path, cc: str, include: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        cc,
        "-std=c11",
        "-O2",
        "-shared",
        "-fPIC",
        "-fvisibility=hidden",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(include),
        *glib_flags(),
        str(SOURCE),
        "-o",
        str(output),
        *link_flags(),
    ]
    subprocess.run(command, check=True)


def main() -> int:
    args = parse_args()
    try:
        include = find_qemu_include(args.qemu_include)
        build(args.output, args.cc, include)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"QEMU plugin build failed: {error}", file=sys.stderr)
        return 1
    print(f"QEMU guest-work plugin ready: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

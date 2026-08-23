#!/usr/bin/env python3
"""Build and run a kllm boot image with QEMU 11.1.0."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

from qemu_profile import QEMU_EXECUTABLES, REPO_ROOT, prepare_qemu_command


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--architecture",
        "--arch",
        choices=tuple(QEMU_EXECUTABLES),
        default="x86_64",
        help="architecture to emulate (default: x86_64)",
    )
    parser.add_argument(
        "--firmware-code",
        type=Path,
        help="path to the read-only UEFI firmware code image (auto-detected by default)",
    )
    parser.add_argument(
        "--firmware-vars",
        type=Path,
        help="path to the UEFI variable-store template (auto-detected by default)",
    )
    parser.add_argument(
        "--skip-version-check",
        action="store_true",
        help="deliberately allow a QEMU version other than 11.1.0",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build the image and print the QEMU command without starting it",
    )
    parser.add_argument(
        "--graphical",
        action="store_true",
        help="open the owned framebuffer console while preserving serial stdio",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        command = prepare_qemu_command(
            args.architecture,
            args.firmware_code,
            args.firmware_vars,
            skip_version_check=args.skip_version_check,
            graphical=args.graphical,
        )
        if args.dry_run:
            print(shlex.join(command))
            return 0
        return subprocess.run(command, cwd=REPO_ROOT, check=False).returncode
    except (FileNotFoundError, OSError, RuntimeError) as error:
        print(f"QEMU launch failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"QEMU launch failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

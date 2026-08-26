#!/usr/bin/env python3
"""Build and run the boot image with QEMU 11.1.0."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

from platform_profile import PLATFORM_IDS, REPO_ROOT
from qemu_profile import ENVIRONMENT_IDS, prepare_qemu_command


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=PLATFORM_IDS,
        required=True,
        help="exact named platform to emulate",
    )
    parser.add_argument(
        "--environment",
        choices=ENVIRONMENT_IDS,
        required=True,
        help="exact execution environment runner",
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
        "--skip-build",
        action="store_true",
        help="run an existing image and storage fixtures without rebuilding",
    )
    parser.add_argument(
        "--graphical",
        action="store_true",
        help="open the owned framebuffer console while preserving serial stdio",
    )
    parser.add_argument(
        "--volume-table",
        type=Path,
        help="build with this strict TOML custom-volume policy",
    )
    parser.add_argument(
        "--data-disk",
        action="append",
        type=Path,
        default=[],
        help="attach one additional writable raw disk image (repeatable, maximum four)",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    try:
        command = prepare_qemu_command(
            args.platform,
            args.environment,
            args.firmware_code,
            args.firmware_vars,
            skip_version_check=args.skip_version_check,
            build=not args.skip_build,
            graphical=args.graphical,
            volume_table=args.volume_table,
            data_disks=tuple(args.data_disk),
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

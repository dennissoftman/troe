#!/usr/bin/env python3
"""Build and run the boot image with QEMU 11.1.0."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path

from platform_profile import PLATFORM_IDS, REPO_ROOT
from qemu_profile import ENVIRONMENT_IDS, prepare_qemu_command

sys.path.insert(0, str(REPO_ROOT))

from tools.mount_shared import SharedMediaLock, require_detached  # noqa: E402


SHARED_MEDIA_PATH = REPO_ROOT / "build" / "troe-shared-fat32.img"


def is_default_shared_disk(path: Path) -> bool:
    """Return whether one explicit path aliases the managed shared medium."""
    return path.resolve(strict=False) == SHARED_MEDIA_PATH.resolve(strict=False)


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
        help=(
            "attach one additional writable raw disk image "
            "(repeatable; maximum three while shared media is enabled)"
        ),
    )
    parser.add_argument(
        "--no-shared-disk",
        action="store_true",
        help="do not create or attach the default persistent 1 GiB FAT32 medium",
    )
    parser.add_argument(
        "--reset-shared-disk",
        action="store_true",
        help="replace the persistent shared FAT32 medium with an empty image",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    try:
        if args.no_shared_disk and args.reset_shared_disk:
            raise RuntimeError(
                "--no-shared-disk and --reset-shared-disk are mutually exclusive"
            )
        if any(is_default_shared_disk(path) for path in args.data_disk):
            raise RuntimeError(
                "the default shared image is managed automatically; "
                "do not pass it through --data-disk"
            )
        media_lock = nullcontext() if args.no_shared_disk else SharedMediaLock()
        with media_lock:
            data_disks = list(args.data_disk)
            if not args.no_shared_disk:
                require_detached(SHARED_MEDIA_PATH)
                subprocess.run(
                    [
                        sys.executable,
                        str(REPO_ROOT / "tools" / "mkshared.py"),
                        "--output",
                        str(SHARED_MEDIA_PATH),
                        *(("--reset",) if args.reset_shared_disk else ()),
                    ],
                    cwd=REPO_ROOT,
                    check=True,
                )
                data_disks.insert(0, SHARED_MEDIA_PATH)
            command = prepare_qemu_command(
                args.platform,
                args.environment,
                args.firmware_code,
                args.firmware_vars,
                skip_version_check=args.skip_version_check,
                build=not args.skip_build,
                graphical=args.graphical,
                volume_table=args.volume_table,
                data_disks=tuple(data_disks),
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

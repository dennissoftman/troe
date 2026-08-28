#!/usr/bin/env python3
"""Run pinned Alpine Linux under TROE's matched QEMU machine profile."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from contextlib import ExitStack, nullcontext
from pathlib import Path

from alpine_profile import (
    acquire_alpine_image,
    alpine_root_disk_path,
    alpine_root_needs_install,
    alpine_profile,
    ensure_alpine_root_image,
    prepare_alpine_command,
)
from platform_profile import PLATFORM_IDS, REPO_ROOT, resolve_platform
from qemu_profile import ENVIRONMENT_IDS, validate_memory_size

sys.path.insert(0, str(REPO_ROOT))

from tools.mount_shared import SharedMediaLock, require_detached  # noqa: E402


SHARED_MEDIA_PATH = REPO_ROOT / "build" / "troe-shared-fat32.img"
SHARED_MOUNT_COMMAND = (
    "mkdir -p /mnt/shared && mount -t vfat "
    "'/dev/disk/by-label/TROE\\x20SHARE' /mnt/shared"
)
ROOT_DEVICE_COMMAND = "readlink -f /dev/disk/by-id/virtio-ALPINE_ROOT"


def install_help(platform: str) -> str:
    """Return the first-install guide shown for an empty Alpine system disk."""
    root_path = alpine_root_disk_path(platform)
    return f"""\
Alpine persistent installation ({platform})
============================================
Host system image: {root_path}

1. At the live ISO login, enter `root` (there is no initial password).
2. Identify the dedicated Alpine system disk:

   ROOT_DISK="$({ROOT_DEVICE_COMMAND})"
   basename "$ROOT_DISK"

3. Run the interactive installer:

   setup-alpine

   Configure eth0 with DHCP and select an Alpine mirror. At the disk prompt,
   enter the basename printed above (for example `vda`) and select `sys` mode.
   Never select the disk whose virtio ID is `TROE_SHARED`.

4. When setup completes, reboot into the installed system:

   reboot

5. Log in with the root password selected during setup and install Lua 5.5:

   apk update
   apk add lua5.5
   lua5.5 -v

6. Mount the independent TROE benchmark-data disk when needed:

   {SHARED_MOUNT_COMMAND}

Optional installed-system MOTD:

   printf '%s\\n' 'TROE Alpine benchmark guest' \\
     "Shared data: {SHARED_MOUNT_COMMAND}" \\
     'Lua: lua5.5 -v' > /etc/motd

This guide is always available on the host with `cargo alpine --install-help`.
Reset only this platform's Alpine installation with
`cargo alpine --platform {platform} --reset-root-disk`.
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=PLATFORM_IDS,
        required=True,
        help="exact TROE platform whose QEMU resources Alpine should match",
    )
    parser.add_argument(
        "--environment",
        choices=ENVIRONMENT_IDS,
        required=True,
        help="exact execution environment runner",
    )
    parser.add_argument(
        "--install-help",
        action="store_true",
        help="print the persistent Alpine first-install guide and exit",
    )
    parser.add_argument(
        "--firmware-code",
        type=Path,
        help="path to the pinned read-only UEFI firmware code image",
    )
    parser.add_argument(
        "--firmware-vars",
        type=Path,
        help="path to the pinned UEFI variable-store template",
    )
    parser.add_argument(
        "--iso",
        type=Path,
        help="use this Alpine-compatible boot image instead of the pinned download",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="redownload and replace the cached pinned Alpine image",
    )
    parser.add_argument(
        "--skip-version-check",
        action="store_true",
        help="deliberately allow a QEMU version other than the pinned version",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="prepare images and print the QEMU command without starting it",
    )
    parser.add_argument(
        "--gui",
        "--graphical",
        dest="graphical",
        action="store_true",
        help=(
            "open a graphical display while preserving serial stdio; keyboard "
            "input goes to Alpine while the QEMU window is focused"
        ),
    )
    parser.add_argument(
        "--memory",
        default="256M",
        help="guest memory (default: 256M; use the same value with cargo qemu)",
    )
    parser.add_argument(
        "--no-root-disk",
        action="store_true",
        help="boot the live ISO without Alpine's persistent system disk",
    )
    parser.add_argument(
        "--reset-root-disk",
        action="store_true",
        help="replace this platform's persistent Alpine system disk and UEFI state",
    )
    parser.add_argument(
        "--no-shared-disk",
        action="store_true",
        help="do not create or attach TROE's persistent shared FAT32 medium",
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
        if args.install_help:
            print(install_help(args.platform))
            return 0
        validate_memory_size(args.memory)
        if args.no_shared_disk and args.reset_shared_disk:
            raise RuntimeError(
                "--no-shared-disk and --reset-shared-disk are mutually exclusive"
            )
        if args.no_root_disk and args.reset_root_disk:
            raise RuntimeError(
                "--no-root-disk and --reset-root-disk are mutually exclusive"
            )
        if args.iso is not None and args.refresh:
            raise RuntimeError("--iso and --refresh are mutually exclusive")

        profile = alpine_profile()
        platform = resolve_platform(args.platform)
        if args.iso is None:
            image = acquire_alpine_image(
                profile, platform.architecture, refresh=args.refresh
            )
        else:
            image = args.iso.expanduser().resolve(strict=True)

        root_disk = None
        root_created = False
        root_needs_install = False
        root_lock = nullcontext()
        if not args.no_root_disk:
            root_disk = alpine_root_disk_path(args.platform)
            root_lock = SharedMediaLock(
                root_disk.with_suffix(".lock"),
                busy_message=(
                    f"Alpine root disk for {args.platform} is busy; stop its other QEMU"
                ),
            )
        media_lock = nullcontext() if args.no_shared_disk else SharedMediaLock()
        with ExitStack() as stack:
            stack.enter_context(root_lock)
            stack.enter_context(media_lock)
            if root_disk is not None:
                root_created = ensure_alpine_root_image(
                    root_disk, reset=args.reset_root_disk
                )
                root_needs_install = alpine_root_needs_install(root_disk)
            shared_disk = None
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
                shared_disk = SHARED_MEDIA_PATH

            command = prepare_alpine_command(
                args.platform,
                args.environment,
                args.firmware_code,
                args.firmware_vars,
                image=image,
                root_disk=root_disk,
                shared_disk=shared_disk,
                reset_variables=root_created or args.reset_root_disk,
                skip_version_check=args.skip_version_check,
                graphical=args.graphical,
                memory=args.memory,
            )
            if args.dry_run:
                print(shlex.join(command))
                return 0
            if shared_disk is not None:
                print(
                    "Alpine shared disk: after logging in as root, run "
                    f"`{SHARED_MOUNT_COMMAND}`",
                    file=sys.stderr,
                )
            if root_disk is not None:
                print(
                    f"Alpine persistent root disk: {root_disk}",
                    file=sys.stderr,
                )
                if root_needs_install:
                    print(f"\n{install_help(args.platform)}", file=sys.stderr)
            return subprocess.run(command, cwd=REPO_ROOT, check=False).returncode
    except (FileNotFoundError, OSError, RuntimeError) as error:
        print(f"Alpine launch failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"Alpine launch failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

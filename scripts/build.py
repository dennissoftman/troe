#!/usr/bin/env python3
"""Build the KEFS root and bootable UEFI images."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
IMAGE_SIZE_LIMIT = 16 * 1024 * 1024
TARGETS = {
    "x86_64": "x86_64-unknown-uefi",
    "aarch64": "aarch64-unknown-uefi",
}


def run(*command: str | Path) -> None:
    """Run a build command from the repository root."""
    subprocess.run(
        [str(argument) for argument in command], cwd=REPO_ROOT, check=True
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--architecture",
        "--arch",
        choices=("all", *TARGETS),
        default="all",
        help="architecture to build (default: all)",
    )
    parser.add_argument(
        "--acceptance-probes",
        action="store_true",
        help="build a separate image containing terminal MMU acceptance probes",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    architectures = TARGETS if args.architecture == "all" else (args.architecture,)

    try:
        run(
            sys.executable,
            TOOLS_DIR / "mkefs.py",
            REPO_ROOT / "rootfs",
            REPO_ROOT / "assets" / "root.kefs",
        )
        run(
            sys.executable,
            TOOLS_DIR / "mkstorage.py",
            "--manifest",
            REPO_ROOT / "assets" / "boot.bmnt",
            "--persistence-selector",
            REPO_ROOT / "assets" / "persist.prgn",
        )
        run(
            sys.executable,
            TOOLS_DIR / "mkconfig.py",
            "--output",
            REPO_ROOT / "assets" / "system.scfg",
        )
        run(
            sys.executable,
            TOOLS_DIR / "mkcontent.py",
            "--config",
            REPO_ROOT / "assets" / "system.scfg",
            "--output",
            REPO_ROOT / "assets" / "system.cspk",
        )

        for architecture in architectures:
            target = TARGETS[architecture]
            cargo_command = [
                "cargo",
                "build",
                "--locked",
                "-p",
                "troe-kernel",
                "--release",
                "--target",
                target,
            ]
            if args.acceptance_probes:
                cargo_command.extend(("--features", "acceptance-probes"))
            run(*cargo_command)

            efi = REPO_ROOT / "target" / target / "release" / "kernel.efi"
            suffix = "-acceptance" if args.acceptance_probes else ""
            image = REPO_ROOT / "build" / f"boot-{architecture}{suffix}.img"
            if not args.acceptance_probes:
                efi_bytes = efi.read_bytes()
                forbidden = (
                    b"mmu-probe",
                    b"task-probe",
                    b"probing read-only",
                    b"probing non-executable",
                    b"probing task stack guard",
                )
                if any(marker in efi_bytes for marker in forbidden):
                    raise RuntimeError(f"production EFI contains acceptance probe marker: {efi}")
            run(
                sys.executable,
                TOOLS_DIR / "mkfat.py",
                "--arch",
                architecture,
                "--efi",
                efi,
                "--output",
                image,
            )
            run(
                sys.executable,
                TOOLS_DIR / "size_report.py",
                "--arch",
                architecture,
                "--efi",
                efi,
                "--rootfs",
                REPO_ROOT / "assets" / "root.kefs",
                "--image",
                image,
            )
            if image.stat().st_size > IMAGE_SIZE_LIMIT:
                raise RuntimeError(f"image exceeds the 16 MiB ceiling: {image}")
    except (FileNotFoundError, OSError, RuntimeError) as error:
        print(f"build failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"build failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

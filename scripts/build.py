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

        for architecture in architectures:
            target = TARGETS[architecture]
            run(
                "cargo",
                "build",
                "--locked",
                "-p",
                "kllm-kernel",
                "--release",
                "--target",
                target,
            )

            efi = REPO_ROOT / "target" / target / "release" / "kllm-kernel.efi"
            image = REPO_ROOT / "build" / f"kllm-{architecture}.img"
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

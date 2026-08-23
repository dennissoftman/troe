#!/usr/bin/env python3
"""Run formatting, lint, test, consistency, image, and QEMU boot gates."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-qemu",
        action="store_true",
        help="skip boot acceptance when the pinned QEMU/firmware pair is unavailable",
    )
    return parser.parse_args()


def run(*command: str | Path) -> None:
    """Run a verification command from the repository root."""
    subprocess.run(
        [str(argument) for argument in command], cwd=REPO_ROOT, check=True
    )


def main() -> int:
    args = parse_args()
    commands: list[tuple[str | Path, ...]] = [
        ("cargo", "fmt", "--all", "--", "--check"),
        (
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ),
        (
            "cargo",
            "clippy",
            "-p",
            "kllm-kernel",
            "--target",
            "x86_64-unknown-uefi",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ),
        (
            "cargo",
            "clippy",
            "-p",
            "kllm-kernel",
            "--target",
            "aarch64-unknown-uefi",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ),
        ("cargo", "test", "--workspace"),
        (sys.executable, REPO_ROOT / "scripts" / "audit.py"),
        (
            sys.executable,
            TOOLS_DIR / "mkefs.py",
            REPO_ROOT / "rootfs",
            REPO_ROOT / "assets" / "root.kefs",
            "--check",
        ),
        (
            sys.executable,
            TOOLS_DIR / "check_unsafe.py",
            REPO_ROOT,
            "--expected",
            "199",
        ),
        (
            "cargo",
            "run",
            "--quiet",
            "-p",
            "kllm-host",
            "--",
            "--script",
            REPO_ROOT / "tests" / "smoke.ksh",
        ),
        (sys.executable, REPO_ROOT / "scripts" / "build.py"),
        (
            sys.executable,
            REPO_ROOT / "scripts" / "build.py",
            "--acceptance-probes",
        ),
    ]
    if not args.skip_qemu:
        commands.append(
            (sys.executable, REPO_ROOT / "scripts" / "test-qemu.py", "--skip-build")
        )

    try:
        for command in commands:
            run(*command)
    except FileNotFoundError as error:
        print(f"verification failed: command not found: {error.filename}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"verification failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

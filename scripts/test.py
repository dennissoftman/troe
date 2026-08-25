#!/usr/bin/env python3
"""Run formatting, lint, test, consistency, image, and QEMU boot gates."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

if __package__:
    from .platform_profile import PLATFORM_PROFILES
    from .qemu_profile import QEMU_ENVIRONMENT
    from .repository_policy import require_supported_python
else:
    from platform_profile import PLATFORM_PROFILES
    from qemu_profile import QEMU_ENVIRONMENT
    from repository_policy import require_supported_python


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-qemu",
        action="store_true",
        help="skip boot acceptance when the pinned QEMU/firmware pair is unavailable",
    )
    parser.add_argument(
        "--require-filesystem-tools",
        action="store_true",
        help="require and run e2fsprogs, dosfstools, and mtools interoperability tests",
    )
    return parser.parse_args()


def run(*command: str | Path) -> None:
    """Run a verification command from the repository root."""
    subprocess.run(
        [str(argument) for argument in command], cwd=REPO_ROOT, check=True
    )


def target_clippy_commands() -> list[tuple[str | Path, ...]]:
    """Return one exact target gate per named platform."""
    return [
        (
            "cargo",
            "clippy",
            "-p",
            "troe-kernel",
            "--target",
            profile.target,
            "--features",
            f"{profile.kernel_feature},acceptance-probes",
            "--",
            "-D",
            "warnings",
        )
        for profile in PLATFORM_PROFILES.values()
    ]


def main() -> int:
    try:
        require_supported_python()
    except RuntimeError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    args = parse_args()
    if args.require_filesystem_tools:
        os.environ["TROE_REQUIRE_FS_TOOLS"] = "1"
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
        *target_clippy_commands(),
        ("cargo", "test", "--workspace"),
        (
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            REPO_ROOT / "tests",
            "-p",
            "test_*.py",
        ),
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
            "242",
        ),
        (
            "cargo",
            "run",
            "--quiet",
            "-p",
            "troe-host",
            "--",
            "--script",
            REPO_ROOT / "tests" / "smoke.sh",
        ),
        (
            sys.executable,
            REPO_ROOT / "scripts" / "build.py",
            "--platform",
            "all",
            "--fixture-identities",
        ),
        (
            sys.executable,
            REPO_ROOT / "scripts" / "build.py",
            "--platform",
            "all",
            "--fixture-identities",
            "--acceptance-probes",
        ),
    ]
    if not args.skip_qemu:
        commands.append(
            (
                sys.executable,
                REPO_ROOT / "scripts" / "test-qemu.py",
                "--platform",
                "all",
                "--environment",
                QEMU_ENVIRONMENT,
                "--skip-build",
                "--framebuffer-console",
                "--native-keyboard",
            )
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

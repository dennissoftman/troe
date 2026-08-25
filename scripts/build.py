#!/usr/bin/env python3
"""Build the KEFS root and bootable UEFI images."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

if __package__:
    from .platform_profile import (
        PLATFORM_IDS,
        PLATFORM_PROFILES,
        PlatformProfile,
        boot_image_path,
    )
else:
    from platform_profile import (
        PLATFORM_IDS,
        PLATFORM_PROFILES,
        PlatformProfile,
        boot_image_path,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
IMAGE_SIZE_LIMIT = 16 * 1024 * 1024
PRODUCTION_FORBIDDEN_MARKERS = (
    b"mmu-probe",
    b"task-probe",
    b"probing read-only",
    b"probing non-executable",
    b"probing task stack guard",
    b"KEX-ACCEPTANCE-DESTRUCTIVE-v1\0",
)


def run(*command: str | Path) -> None:
    """Run a build command from the repository root."""
    subprocess.run([str(argument) for argument in command], cwd=REPO_ROOT, check=True)


def verify_production_efi(path: Path) -> None:
    """Reject acceptance-only payloads embedded in a production EFI image."""
    image = path.read_bytes()
    for marker in PRODUCTION_FORBIDDEN_MARKERS:
        if marker in image:
            label = marker.rstrip(b"\0").decode("ascii", errors="replace")
            raise RuntimeError(
                f"production EFI contains acceptance probe marker {label!r}: {path}"
            )


def cargo_build_command(
    profile: PlatformProfile, *, acceptance_probes: bool
) -> tuple[str, ...]:
    """Return the exact kernel build command for one named platform."""
    features = profile.kernel_feature
    if acceptance_probes:
        features += ",acceptance-probes"
    return (
        "cargo",
        "build",
        "--locked",
        "-p",
        "troe-kernel",
        "--release",
        "--target",
        profile.target,
        "--features",
        features,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=("all", *PLATFORM_IDS),
        required=True,
        help="named platform to build, or explicit 'all'",
    )
    parser.add_argument(
        "--acceptance-probes",
        action="store_true",
        help="build a separate image containing terminal MMU acceptance probes",
    )
    identity_source = parser.add_mutually_exclusive_group(required=True)
    identity_source.add_argument(
        "--fixture-identities",
        action="store_true",
        help="use deterministic test identities; never a deployment artifact",
    )
    identity_source.add_argument(
        "--identity-file",
        type=Path,
        help="deployment identities created exclusively by tools/mkidentity.py",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    platform_ids = PLATFORM_IDS if args.platform == "all" else (args.platform,)

    try:
        identity_arguments: tuple[str | Path, ...] = (
            ("--fixture-identities",)
            if args.fixture_identities
            else ("--identity-file", args.identity_file)
        )
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
            "--state-selector",
            REPO_ROOT / "assets" / "state.prgn",
        )
        run(
            sys.executable,
            TOOLS_DIR / "mkconfig.py",
            "--output",
            REPO_ROOT / "assets" / "system.scfg",
            "--previous-output",
            REPO_ROOT / "assets" / "system-prev.scfg",
        )
        run(
            sys.executable,
            TOOLS_DIR / "mkcontent.py",
            "--config",
            REPO_ROOT / "assets" / "system.scfg",
            "--previous-config",
            REPO_ROOT / "assets" / "system-prev.scfg",
            "--output",
            REPO_ROOT / "assets" / "system.cspk",
            "--activation-output",
            REPO_ROOT / "assets" / "system.sact",
            *identity_arguments,
        )
        run(
            sys.executable,
            TOOLS_DIR / "mkstorage.py",
            "--manifest",
            REPO_ROOT / "assets" / "boot.bmnt",
            "--output",
            REPO_ROOT / "build" / "storage-root.img",
            "--content",
            REPO_ROOT / "assets" / "system.cspk",
        )

        for platform_id in platform_ids:
            profile = PLATFORM_PROFILES[platform_id]
            run(*cargo_build_command(profile, acceptance_probes=args.acceptance_probes))

            efi = REPO_ROOT / "target" / profile.target / "release" / "kernel.efi"
            image = boot_image_path(
                profile, acceptance_probes=args.acceptance_probes
            )
            if not args.acceptance_probes:
                verify_production_efi(efi)
            run(
                sys.executable,
                TOOLS_DIR / "mkfat.py",
                "--arch",
                profile.architecture,
                "--efi",
                efi,
                "--output",
                image,
            )
            run(
                sys.executable,
                TOOLS_DIR / "size_report.py",
                "--arch",
                profile.architecture,
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

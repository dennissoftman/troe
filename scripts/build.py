#!/usr/bin/env python3
"""Build the KEFS root and bootable UEFI images."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

if __package__:
    from .platform_profile import (
        PLATFORM_IDS,
        PLATFORM_PROFILES,
        PlatformProfile,
        boot_image_path,
        root_storage_image_path,
    )
else:
    from platform_profile import (
        PLATFORM_IDS,
        PLATFORM_PROFILES,
        PlatformProfile,
        boot_image_path,
        root_storage_image_path,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
DEFAULT_VOLUME_TABLE = REPO_ROOT / "config" / "volumes.toml"
IMAGE_SIZE_LIMIT = 16 * 1024 * 1024
PRODUCTION_FORBIDDEN_MARKERS = (
    b"mmu-probe",
    b"task-probe",
    b"probing read-only",
    b"probing non-executable",
    b"probing task stack guard",
    b"KEX-ACCEPTANCE-DESTRUCTIVE-v1\0",
)


def rootfs_image_path(architecture: str) -> Path:
    """Return the target-selected KEFS image embedded by one kernel build."""
    return REPO_ROOT / "assets" / f"root-{architecture}.kefs"


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
    variants = parser.add_mutually_exclusive_group()
    variants.add_argument(
        "--acceptance-probes",
        action="store_true",
        help="build a separate image containing terminal MMU acceptance probes",
    )
    variants.add_argument(
        "--all-variants",
        action="store_true",
        help="build production and acceptance images after generating shared inputs once",
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
    parser.add_argument(
        "--volume-table",
        type=Path,
        default=DEFAULT_VOLUME_TABLE,
        help="strict TOML source compiled into the boot mount manifest",
    )
    return parser.parse_args(argv)


def requested_variants(args: argparse.Namespace) -> tuple[bool, ...]:
    """Return production/acceptance variants after shared inputs are generated."""
    return (False, True) if args.all_variants else (args.acceptance_probes,)


def main() -> int:
    args = parse_args()
    platform_ids = PLATFORM_IDS if args.platform == "all" else (args.platform,)

    try:
        identity_arguments: tuple[str | Path, ...] = (
            ("--fixture-identities",)
            if args.fixture_identities
            else ("--identity-file", args.identity_file)
        )
        architectures = tuple(
            dict.fromkeys(
                PLATFORM_PROFILES[platform_id].architecture
                for platform_id in platform_ids
            )
        )
        for architecture in architectures:
            run(
                sys.executable,
                TOOLS_DIR / "mkefs.py",
                REPO_ROOT / "rootfs",
                rootfs_image_path(architecture),
                "--architecture",
                architecture,
            )
        run(
            sys.executable,
            TOOLS_DIR / "mkstorage.py",
            "--manifest",
            REPO_ROOT / "assets" / "boot.bmnt",
            "--volume-table",
            args.volume_table,
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
        root_source = REPO_ROOT / "build" / "storage-root.img"
        run(
            sys.executable,
            TOOLS_DIR / "mkstorage.py",
            "--manifest",
            REPO_ROOT / "assets" / "boot.bmnt",
            "--volume-table",
            args.volume_table,
            "--output",
            root_source,
            "--content",
            REPO_ROOT / "assets" / "system.cspk",
        )
        for platform_id in platform_ids:
            shutil.copyfile(
                root_source,
                root_storage_image_path(PLATFORM_PROFILES[platform_id]),
            )

        for acceptance_probes in requested_variants(args):
            for platform_id in platform_ids:
                profile = PLATFORM_PROFILES[platform_id]
                run(*cargo_build_command(profile, acceptance_probes=acceptance_probes))

                efi = REPO_ROOT / "target" / profile.target / "release" / "kernel.efi"
                image = boot_image_path(profile, acceptance_probes=acceptance_probes)
                if not acceptance_probes:
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
                    rootfs_image_path(profile.architecture),
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

#!/usr/bin/env python3
"""Environment-independent build-platform identities and artifact paths."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast


REPO_ROOT = Path(__file__).resolve().parents[1]
PLATFORM_MANIFEST_PATH = REPO_ROOT / "tools" / "platforms.json"


@dataclass(frozen=True)
class PlatformProfile:
    """Facts required to build one named platform."""

    numeric_id: int
    identifier: str
    architecture: str
    firmware_discovery: str
    target: str
    kernel_feature: str
    virtio_transport: str


def platform_manifest() -> dict[str, object]:
    """Load and strictly validate the canonical build-platform manifest."""
    try:
        manifest = json.loads(PLATFORM_MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"cannot read platform manifest {PLATFORM_MANIFEST_PATH}: {error}"
        ) from error
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "platforms"}
        or manifest.get("schema") != 1
        or not isinstance(manifest.get("platforms"), list)
        or not manifest["platforms"]
    ):
        raise RuntimeError(f"invalid platform manifest: {PLATFORM_MANIFEST_PATH}")

    names: set[str] = set()
    numeric_ids: set[int] = set()
    for entry in manifest["platforms"]:
        if not isinstance(entry, dict) or set(entry) != {
            "id",
            "name",
            "architecture",
            "firmware_discovery",
            "target",
            "kernel_feature",
            "virtio_transport",
        }:
            raise RuntimeError(f"invalid platform manifest entry: {entry!r}")
        numeric_id = entry["id"]
        name = entry["name"]
        architecture = entry["architecture"]
        firmware_discovery = entry["firmware_discovery"]
        target = entry["target"]
        kernel_feature = entry["kernel_feature"]
        virtio_transport = entry["virtio_transport"]
        if (
            not isinstance(numeric_id, int)
            or isinstance(numeric_id, bool)
            or not 1 <= numeric_id <= 0xFFFF
            or not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", name) is None
            or not isinstance(architecture, str)
            or architecture not in {"x86_64", "aarch64"}
            or firmware_discovery not in {"fixed", "acpi", "fdt"}
            or (architecture == "x86_64" and firmware_discovery == "fdt")
            or (architecture == "aarch64" and firmware_discovery == "acpi")
            or not isinstance(target, str)
            or not target
            or not isinstance(kernel_feature, str)
            or not kernel_feature
            or not isinstance(virtio_transport, str)
            or virtio_transport not in {"pci", "mmio"}
        ):
            raise RuntimeError(f"invalid platform manifest entry: {entry!r}")
        if name in names or numeric_id in numeric_ids:
            raise RuntimeError("platform manifest contains duplicate identities")
        names.add(name)
        numeric_ids.add(numeric_id)
    return manifest


def _load_platform_profiles() -> dict[str, PlatformProfile]:
    manifest = platform_manifest()
    entries = cast(list[dict[str, object]], manifest["platforms"])
    profiles = {}
    for entry in entries:
        profile = PlatformProfile(
            numeric_id=cast(int, entry["id"]),
            identifier=cast(str, entry["name"]),
            architecture=cast(str, entry["architecture"]),
            firmware_discovery=cast(str, entry["firmware_discovery"]),
            target=cast(str, entry["target"]),
            kernel_feature=cast(str, entry["kernel_feature"]),
            virtio_transport=cast(str, entry["virtio_transport"]),
        )
        profiles[profile.identifier] = profile
    return profiles


PLATFORM_PROFILES = _load_platform_profiles()
PLATFORM_IDS = tuple(PLATFORM_PROFILES)
X86_64_Q35_UEFI = "x86_64-q35-uefi"
AARCH64_SBSA_REF = "aarch64-sbsa-ref"
X86_64_UEFI_VIRTIO_PCI = "x86_64-uefi-virtio-pci"
AARCH64_UEFI_VIRTIO_MMIO = "aarch64-uefi-virtio-mmio"


def resolve_platform(platform_id: str) -> PlatformProfile:
    """Resolve one exact environment-independent build platform."""
    try:
        return PLATFORM_PROFILES[platform_id]
    except KeyError as error:
        raise RuntimeError(f"unknown platform {platform_id!r}") from error


def boot_image_path(
    profile: PlatformProfile, *, acceptance_probes: bool = False
) -> Path:
    """Return the platform-qualified boot artifact path."""
    suffix = "-acceptance" if acceptance_probes else ""
    return REPO_ROOT / "build" / f"boot-{profile.identifier}{suffix}.img"


def root_storage_image_path(profile: PlatformProfile) -> Path:
    """Return the platform-qualified mutable persistent-root path."""
    return REPO_ROOT / "build" / f"storage-root-{profile.identifier}.img"


def txslot_image_path(profile: PlatformProfile) -> Path:
    """Return the platform-qualified mutable activation-medium path."""
    return REPO_ROOT / "build" / f"storage-txslot-{profile.identifier}.img"


def statefs_image_path(profile: PlatformProfile) -> Path:
    """Return the platform-qualified mutable filesystem-medium path."""
    return REPO_ROOT / "build" / f"storage-statefs-{profile.identifier}.img"


def shared_test_image_path(profile: PlatformProfile) -> Path:
    """Return the platform-private disposable FAT32 acceptance medium."""
    return REPO_ROOT / "build" / f"storage-shared-{profile.identifier}.img"

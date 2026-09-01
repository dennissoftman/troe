#!/usr/bin/env python3
"""Canonical build platforms and explicit QEMU execution runners."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import fcntl
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .platform_profile import (
        AARCH64_SBSA_REF,
        AARCH64_UEFI_VIRTIO_MMIO,
        X86_64_Q35_UEFI,
        X86_64_UEFI_VIRTIO_PCI,
        PlatformProfile,
        boot_image_path,
        resolve_platform,
        root_storage_image_path,
        statefs_image_path,
        txslot_image_path,
    )
else:
    from platform_profile import (
        AARCH64_SBSA_REF,
        AARCH64_UEFI_VIRTIO_MMIO,
        X86_64_Q35_UEFI,
        X86_64_UEFI_VIRTIO_PCI,
        PlatformProfile,
        boot_image_path,
        resolve_platform,
        root_storage_image_path,
        statefs_image_path,
        txslot_image_path,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
# Table-of-contents magic beginning a Trusted Firmware package.
TRUSTED_FIRMWARE_PACKAGE_MAGIC = b"\x01\x00\x64\xaa"
# How far into a secure-world bank that package is searched for.
TRUSTED_FIRMWARE_SEARCH_BYTES = 1024 * 1024
EXPECTED_QEMU_VERSION = "11.1.0"
MINIMUM_QEMU_VERSION = (8, 0, 0)
MAXIMUM_QEMU_VERSION = (12, 0, 0)
FIRMWARE_PROFILE_PATH = REPO_ROOT / "tools" / "qemu-firmware-profile.json"
DEFAULT_VOLUME_TABLE = REPO_ROOT / "config" / "volumes.toml"
# Split-disk QEMU profiles already expose boot, root, activation, and state
# devices; four additions exactly preserve the native eight-device ceiling.
MAX_EXTRA_DATA_DISKS = 4


@dataclass(frozen=True)
class RunnerProfile:
    """One exact execution-environment runner for one named platform."""

    platform_id: str
    environment: str
    executable: str
    machine: str
    cpu: str
    memory: str
    virtual_cpus: int
    virtio_block_device: str
    virtio_network_device: str
    virtio_rng_device: str
    network_mac: str
    acceptance_udp_port: int
    firmware_architecture: str
    firmware_code_filenames: tuple[str, ...]
    firmware_vars_filenames: tuple[str, ...]
    disk_layout: str = "split"
    framebuffer_device: str | None = None
    extra_arguments: tuple[str, ...] = ()
    boot_media_device: str | None = None
    firmware_code_is_volume: bool = True
    firmware_build_command: str | None = None


QEMU_ENVIRONMENT = "qemu"

RUNNER_PROFILES = {
    (X86_64_Q35_UEFI, QEMU_ENVIRONMENT): RunnerProfile(
        platform_id=X86_64_Q35_UEFI,
        environment=QEMU_ENVIRONMENT,
        executable="qemu-system-x86_64",
        machine="q35",
        cpu="max",
        memory="128M",
        virtual_cpus=1,
        virtio_block_device="virtio-blk-pci,disable-legacy=on",
        virtio_network_device="virtio-net-pci,disable-legacy=on",
        virtio_rng_device="virtio-rng-pci,disable-legacy=on",
        network_mac="52:54:00:12:34:56",
        acceptance_udp_port=40123,
        firmware_architecture="x86_64",
        firmware_code_filenames=(
            "edk2-x86_64-code.fd",
            "OVMF_CODE.fd",
            "OVMF_CODE_4M.fd",
        ),
        firmware_vars_filenames=(
            "edk2-i386-vars.fd",
            "OVMF_VARS.fd",
            "OVMF_VARS_4M.fd",
        ),
    ),
    (AARCH64_SBSA_REF, QEMU_ENVIRONMENT): RunnerProfile(
        platform_id=AARCH64_SBSA_REF,
        environment=QEMU_ENVIRONMENT,
        executable="qemu-system-aarch64",
        machine="sbsa-ref",
        # The reference firmware draws its entropy from FEAT_RNG, which the
        # older cores QEMU offers on this machine do not implement.
        cpu="max",
        memory="128M",
        virtual_cpus=1,
        virtio_block_device="virtio-blk-pci,disable-legacy=on",
        virtio_network_device="virtio-net-pci,disable-legacy=on",
        virtio_rng_device="virtio-rng-pci,disable-legacy=on",
        network_mac="52:54:00:12:34:57",
        acceptance_udp_port=40124,
        firmware_architecture="aarch64",
        # Two 256 MiB flash banks: Trusted Firmware in the first, the UEFI
        # volume and its variable store in the second.
        firmware_code_filenames=("SBSA_FLASH0.fd",),
        firmware_vars_filenames=("SBSA_FLASH1.fd",),
        firmware_code_is_volume=False,
        # No distribution packages this pair, so the tree builds both banks.
        firmware_build_command="python3 tools/build_sbsa_firmware.py",
        # The reference firmware carries no virtio driver, so the boot volume
        # arrives on the machine's own AHCI controller. Everything the kernel
        # then drives itself stays on virtio, as it does everywhere else.
        boot_media_device="ide-hd,bus=ide.0",
        # No `ramfb`: that needs the `fw_cfg` interface the reference machine
        # deliberately omits. The firmware's QEMU video driver binds this.
        framebuffer_device="bochs-display",
    ),
    (X86_64_UEFI_VIRTIO_PCI, QEMU_ENVIRONMENT): RunnerProfile(
        platform_id=X86_64_UEFI_VIRTIO_PCI,
        environment=QEMU_ENVIRONMENT,
        executable="qemu-system-x86_64",
        machine="q35",
        cpu="max",
        memory="128M",
        virtual_cpus=1,
        virtio_block_device="virtio-blk-pci,disable-legacy=on",
        virtio_network_device="virtio-net-pci,disable-legacy=on",
        virtio_rng_device="virtio-rng-pci,disable-legacy=on",
        network_mac="52:54:00:12:34:58",
        acceptance_udp_port=40125,
        firmware_architecture="x86_64",
        firmware_code_filenames=(
            "edk2-x86_64-code.fd",
            "OVMF_CODE.fd",
            "OVMF_CODE_4M.fd",
        ),
        firmware_vars_filenames=(
            "edk2-i386-vars.fd",
            "OVMF_VARS.fd",
            "OVMF_VARS_4M.fd",
        ),
        disk_layout="cloud-bundle-v1",
    ),
    (AARCH64_UEFI_VIRTIO_MMIO, QEMU_ENVIRONMENT): RunnerProfile(
        platform_id=AARCH64_UEFI_VIRTIO_MMIO,
        environment=QEMU_ENVIRONMENT,
        executable="qemu-system-aarch64",
        machine="virt,gic-version=3,acpi=off",
        cpu="cortex-a72",
        memory="128M",
        virtual_cpus=1,
        virtio_block_device="virtio-blk-device",
        virtio_network_device="virtio-net-device",
        virtio_rng_device="virtio-rng-device",
        network_mac="52:54:00:12:34:59",
        acceptance_udp_port=40126,
        firmware_architecture="aarch64",
        firmware_code_filenames=(
            "edk2-aarch64-code.fd",
            "AAVMF_CODE.fd",
            "QEMU_EFI.fd",
        ),
        firmware_vars_filenames=("edk2-arm-vars.fd", "AAVMF_VARS.fd"),
        disk_layout="cloud-bundle-v1",
        framebuffer_device="ramfb",
        extra_arguments=("-global", "virtio-mmio.force-legacy=false"),
    ),
}
ENVIRONMENT_IDS = tuple(dict.fromkeys(key[1] for key in RUNNER_PROFILES))
FIRMWARE_ARCHITECTURES = tuple(
    dict.fromkeys(runner.firmware_architecture for runner in RUNNER_PROFILES.values())
)
_VERIFIED_FIRMWARE: set[tuple[Path, int, int, str, str, bool]] = set()
_COMPATIBILITY_NOTICE_SHOWN = False


def select_runner(
    runners: dict[tuple[str, str], RunnerProfile],
    platform_id: str,
    environment: str,
) -> RunnerProfile:
    """Select one exact pair from a supplied runner catalog."""
    resolve_platform(platform_id)
    try:
        runner = runners[(platform_id, environment)]
    except KeyError as error:
        raise RuntimeError(
            f"no runner for platform {platform_id!r} in environment {environment!r}"
        ) from error
    if runner.platform_id != platform_id or runner.environment != environment:
        raise RuntimeError("runner catalog key does not match its record")
    return runner


def resolve_runner(platform_id: str, environment: str) -> RunnerProfile:
    """Resolve one explicit platform/environment runner pair."""
    return select_runner(RUNNER_PROFILES, platform_id, environment)


def validate_memory_size(value: str) -> str:
    """Return one explicit QEMU memory size or reject ambiguous syntax."""
    if re.fullmatch(r"[1-9][0-9]*[MG]", value) is None:
        raise RuntimeError(
            "memory must be an integer number of MiB or GiB, such as 256M"
        )
    return value


def validate_runner_catalog(
    runners: dict[tuple[str, str], RunnerProfile],
) -> None:
    """Reject incomplete, ambiguous, or mismatched execution runner records."""
    ports: set[int] = set()
    for key, runner in runners.items():
        platform = resolve_platform(runner.platform_id)
        if key != (runner.platform_id, runner.environment):
            raise RuntimeError("runner catalog key does not match its record")
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", runner.environment) is None
            or not runner.executable
            or not runner.machine
            or not runner.cpu
            or not runner.memory
            or runner.virtual_cpus != 1
            or not runner.virtio_block_device
            or not runner.virtio_network_device
            or not runner.virtio_rng_device
            or re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", runner.network_mac)
            is None
            or not 1 <= runner.acceptance_udp_port <= 0xFFFF
            or runner.firmware_architecture != platform.architecture
            or not runner.firmware_code_filenames
            or not runner.firmware_vars_filenames
            or runner.disk_layout not in {"split", "cloud-bundle-v1"}
            or any(not filename for filename in runner.firmware_code_filenames)
            or any(not filename for filename in runner.firmware_vars_filenames)
            or runner.boot_media_device == ""
            or runner.firmware_build_command == ""
        ):
            raise RuntimeError(f"invalid runner record for {key!r}")
        if runner.acceptance_udp_port in ports:
            raise RuntimeError("runner acceptance UDP ports must be unique")
        ports.add(runner.acceptance_udp_port)


validate_runner_catalog(RUNNER_PROFILES)


def variable_store_path(profile: PlatformProfile) -> Path:
    """Return the platform-qualified disposable UEFI variable-store path."""
    return REPO_ROOT / "build" / f"qemu-vars-{profile.identifier}.fd"


def cloud_bundle_path(
    profile: PlatformProfile,
    environment: str,
    *,
    acceptance_probes: bool = False,
) -> Path:
    """Return the exact environment-qualified cloud bundle directory."""
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", environment) is None:
        raise RuntimeError(f"invalid environment identifier {environment!r}")
    suffix = "-acceptance" if acceptance_probes else ""
    return REPO_ROOT / "build" / (f"cloud-{profile.identifier}-{environment}{suffix}")


def build_cloud_bundle(
    profile: PlatformProfile,
    environment: str,
    *,
    acceptance_probes: bool = False,
) -> Path:
    """Rebuild and verify one immutable system bundle from current artifacts."""
    bundle = cloud_bundle_path(
        profile,
        environment,
        acceptance_probes=acceptance_probes,
    )
    bundle.parent.mkdir(parents=True, exist_ok=True)
    lock_path = bundle.with_name(f".{bundle.name}.lock")
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        staging_root = Path(
            tempfile.mkdtemp(prefix=f".{bundle.name}-", dir=bundle.parent)
        )
        candidate = staging_root / "candidate"
        previous = staging_root / "previous"
        try:
            subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "mkcloud.py"),
                    "build",
                    "--platform",
                    profile.identifier,
                    "--environment",
                    environment,
                    "--boot",
                    str(
                        boot_image_path(
                            profile,
                            acceptance_probes=acceptance_probes,
                        )
                    ),
                    "--root",
                    str(REPO_ROOT / "build" / "storage-root.img"),
                    "--output",
                    str(candidate),
                    "--kind",
                    "acceptance" if acceptance_probes else "development",
                ],
                cwd=REPO_ROOT,
                check=True,
            )
            if bundle.exists() or bundle.is_symlink():
                bundle.rename(previous)
            try:
                candidate.rename(bundle)
            except Exception:
                if previous.exists() or previous.is_symlink():
                    previous.rename(bundle)
                raise
        finally:
            shutil.rmtree(staging_root, ignore_errors=True)
    return bundle


def firmware_profile() -> dict[str, object]:
    """Load and validate the committed firmware provenance manifest."""
    try:
        profile = json.loads(FIRMWARE_PROFILE_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"cannot read QEMU firmware profile {FIRMWARE_PROFILE_PATH}: {error}"
        ) from error
    if (
        not isinstance(profile, dict)
        or set(profile) != {"schema", "qemu_version", "firmware_release", "artifacts"}
        or profile.get("schema") != 1
        or profile.get("qemu_version") != EXPECTED_QEMU_VERSION
        or profile.get("firmware_release") != "edk2-stable202605-r1"
        or not isinstance(profile.get("artifacts"), dict)
    ):
        raise RuntimeError(f"invalid QEMU firmware profile: {FIRMWARE_PROFILE_PATH}")
    artifacts = profile["artifacts"]
    if set(artifacts) != set(FIRMWARE_ARCHITECTURES):
        raise RuntimeError("QEMU firmware profile has an invalid architecture set")
    for architecture in FIRMWARE_ARCHITECTURES:
        entries = artifacts[architecture]
        if not isinstance(entries, dict) or set(entries) != {"code", "vars"}:
            raise RuntimeError(
                f"QEMU firmware profile has invalid {architecture} artifacts"
            )
        for kind in ("code", "vars"):
            entry = entries[kind]
            if not isinstance(entry, dict):
                raise RuntimeError(
                    f"QEMU firmware profile has invalid {architecture} {kind} metadata"
                )
            # Firmware taken from a distribution is pinned by digest. Firmware
            # no distribution packages is built here instead, and an edk2 image
            # records its own build time, so its provenance is the pinned
            # source rather than a byte-for-byte identity.
            if set(entry) == {"built_from"}:
                if not isinstance(entry["built_from"], str) or not (
                    REPO_ROOT / entry["built_from"]
                ).is_file():
                    raise RuntimeError(
                        f"QEMU firmware profile names no {architecture} {kind} source"
                    )
                continue
            if (
                set(entry) != {"bytes", "sha256"}
                or not isinstance(entry["bytes"], int)
                or entry["bytes"] <= 0
                or not isinstance(entry["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
            ):
                raise RuntimeError(
                    f"QEMU firmware profile has invalid {architecture} {kind} metadata"
                )
    return profile


def verify_file_digest(path: Path, expected_bytes: int, expected_sha256: str) -> None:
    """Require an exact file length and SHA-256 digest."""
    if path.stat().st_size != expected_bytes:
        raise RuntimeError(
            f"firmware size mismatch for {path}: expected {expected_bytes} bytes, "
            f"got {path.stat().st_size}"
        )
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise RuntimeError(
            f"firmware digest mismatch for {path}: expected {expected_sha256}, got {actual}"
        )


def verify_compatible_firmware(
    path: Path, architecture: str, kind: str, *, volume: bool = True
) -> None:
    """Require a regular, flash-aligned firmware image of the expected shape."""
    if architecture not in FIRMWARE_ARCHITECTURES or kind not in ("code", "vars"):
        raise RuntimeError(f"invalid firmware selection: {architecture} {kind}")
    if not path.is_file():
        raise FileNotFoundError(f"firmware is not a regular file: {path}")
    size = path.stat().st_size
    minimum_bytes = 256 * 1024
    image_alignment = 4 * 1024
    if size < minimum_bytes or size % image_alignment != 0:
        raise RuntimeError(
            f"firmware image must be at least 256 KiB and 4-KiB aligned: {path}"
        )
    if volume:
        with path.open("rb") as source:
            header = source.read(64 * 1024)
        if b"_FVH" not in header:
            raise RuntimeError(
                f"firmware image has no UEFI firmware-volume header: {path}"
            )
        return
    # A secure-world bank holds Trusted Firmware and its package rather than a
    # UEFI volume, so the package table of contents is what identifies it. Its
    # offset follows the first-stage loader's length and is not fixed, so the
    # search covers the whole region a loader could occupy.
    with path.open("rb") as source:
        header = source.read(TRUSTED_FIRMWARE_SEARCH_BYTES)
    if TRUSTED_FIRMWARE_PACKAGE_MAGIC not in header:
        raise RuntimeError(
            f"firmware image has no Trusted Firmware package header: {path}"
        )


def verify_built_firmware(path: Path, architecture: str, kind: str, source: str) -> None:
    """Verify one locally built bank against the manifest its builder wrote.

    A distribution artifact is evidence because its digest is committed here.
    A bank built from source cannot be, because the image records when it was
    built, so the evidence is instead that these bytes are the ones the pinned
    sources produced and have not changed since.
    """
    if not (REPO_ROOT / source).is_file():
        raise RuntimeError(f"the pinned {architecture} firmware source {source} is absent")
    manifest = path.parent / "MANIFEST.sha256"
    if not manifest.is_file():
        raise RuntimeError(
            f"{path.name} has no build manifest beside it; rebuild it from {source}"
        )
    recorded = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None or not name:
            raise RuntimeError(f"malformed firmware manifest entry: {line}")
        recorded[name] = digest
    if path.name not in recorded:
        raise RuntimeError(f"{path.name} is not recorded in {manifest}")
    verify_file_digest(path, path.stat().st_size, recorded[path.name])


def verify_firmware(
    path: Path,
    architecture: str,
    kind: str,
    *,
    strict: bool = False,
    volume: bool = True,
) -> None:
    """Verify selected firmware structurally or against the release profile."""
    stat = path.stat()
    cache_key = (path, stat.st_size, stat.st_mtime_ns, architecture, kind, strict)
    if cache_key in _VERIFIED_FIRMWARE:
        return
    if not strict:
        verify_compatible_firmware(path, architecture, kind, volume=volume)
        _VERIFIED_FIRMWARE.add(cache_key)
        return
    profile = firmware_profile()
    artifacts = profile["artifacts"]
    try:
        entry = artifacts[architecture][kind]
    except (KeyError, TypeError) as error:
        raise RuntimeError(
            f"firmware profile has no {architecture} {kind} artifact"
        ) from error
    if "built_from" in entry:
        verify_built_firmware(path, architecture, kind, entry["built_from"])
        _VERIFIED_FIRMWARE.add(cache_key)
        return
    try:
        expected_bytes = entry["bytes"]
        expected_sha256 = entry["sha256"]
    except (KeyError, TypeError) as error:
        raise RuntimeError(
            f"firmware profile has no {architecture} {kind} artifact"
        ) from error
    if (
        not isinstance(expected_bytes, int)
        or expected_bytes <= 0
        or not isinstance(expected_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise RuntimeError(f"invalid {architecture} {kind} firmware profile entry")
    verify_file_digest(path, expected_bytes, expected_sha256)
    _VERIFIED_FIRMWARE.add(cache_key)


def qemu_version(executable: str) -> str:
    """Return the first QEMU version line."""
    result = subprocess.run(
        [executable, "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.stdout.splitlines()[0] if result.stdout else "no version output"


def verify_qemu_version(
    version_output: str, *, strict: bool = False
) -> tuple[int, int, int]:
    """Validate QEMU's version line under compatible or strict policy."""
    match = re.search(r"\bversion ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b", version_output)
    if match is None:
        raise RuntimeError(f"could not parse QEMU version: {version_output}")
    version = (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3) or 0),
    )
    expected = tuple(int(component) for component in EXPECTED_QEMU_VERSION.split("."))
    if strict and version != expected:
        raise RuntimeError(
            f"strict tool policy requires QEMU {EXPECTED_QEMU_VERSION}; "
            f"got {'.'.join(str(component) for component in version)}"
        )
    if not strict and not MINIMUM_QEMU_VERSION <= version < MAXIMUM_QEMU_VERSION:
        raise RuntimeError(
            "compatible tool policy requires QEMU 8.x through 11.x; "
            f"got {'.'.join(str(component) for component in version)}"
        )
    return version


def announce_compatible_qemu(version: tuple[int, int, int]) -> None:
    """Explain once that a run is behavioral rather than strict evidence."""
    global _COMPATIBILITY_NOTICE_SHOWN  # noqa: PLW0603 - process-local notice
    if _COMPATIBILITY_NOTICE_SHOWN:
        return
    rendered = ".".join(str(component) for component in version)
    print(
        f"QEMU compatibility mode: {rendered}; firmware is structurally checked. "
        "Use --strict-tool-versions for pinned release evidence.",
        file=sys.stderr,
    )
    _COMPATIBILITY_NOTICE_SHOWN = True


def firmware_search_roots(executable: str) -> tuple[Path, ...]:
    """Return QEMU-adjacent and conventional system firmware directories."""
    executable_dir = Path(executable).resolve().parent
    roots = (
        # Firmware no distribution packages, built into the tree by
        # `tools/build_sbsa_firmware.py`, is found before any system copy.
        REPO_ROOT / "build" / "sbsa-firmware",
        executable_dir / "share",
        executable_dir.parent / "share" / "qemu",
        Path("/usr/share/qemu"),
        Path("/usr/share/OVMF"),
        Path("/usr/share/edk2/x64"),
        Path("/usr/share/AAVMF"),
        Path("/opt/homebrew/share/qemu"),
        Path("/usr/local/share/qemu"),
    )
    return tuple(dict.fromkeys(roots))


def discover_firmware(executable: str, runner: RunnerProfile, kind: str) -> Path:
    """Find firmware named by an already-selected QEMU runner."""
    if kind == "code":
        filenames = runner.firmware_code_filenames
    elif kind == "vars":
        filenames = runner.firmware_vars_filenames
    else:
        raise RuntimeError(f"invalid firmware kind {kind!r}")
    roots = firmware_search_roots(executable)
    for root in roots:
        for filename in filenames:
            candidate = root / filename
            if candidate.is_file():
                return candidate.resolve()

    flag = "--firmware-code" if kind == "code" else "--firmware-vars"
    searched = ", ".join(str(root) for root in roots)
    remedy = (
        f"build it with `{runner.firmware_build_command}`, or pass {flag} explicitly"
        if runner.firmware_build_command
        else f"pass {flag} explicitly"
    )
    raise FileNotFoundError(
        f"could not auto-detect {runner.firmware_architecture} UEFI firmware {kind}; "
        f"{remedy} (searched: {searched})"
    )


def resolve_firmware(
    supplied: Path | None,
    executable: str,
    runner: RunnerProfile,
    kind: str,
    *,
    strict: bool = False,
) -> Path:
    """Resolve and verify an explicit or distribution firmware artifact."""
    if supplied is not None:
        selected = supplied.expanduser().resolve(strict=True)
    else:
        selected = discover_firmware(executable, runner, kind)
    verify_firmware(
        selected,
        runner.firmware_architecture,
        kind,
        strict=strict,
        volume=kind != "code" or runner.firmware_code_is_volume,
    )
    return selected


def _qemu_arguments(
    runner: RunnerProfile,
    executable: str,
    firmware: Path,
    variables: Path,
    image: Path,
    storage: Path,
    txslot: Path,
    statefs: Path,
    *,
    graphical: bool,
    framebuffer: bool,
    memory: str | None = None,
    data_disks: tuple[Path, ...] = (),
) -> list[str]:
    """Return exact QEMU arguments from one already-resolved runner record."""
    command = [
        executable,
        "-machine",
        runner.machine,
        "-monitor",
        "none",
        "-serial",
        "stdio",
    ]
    if not graphical:
        command.extend(("-display", "none"))
    if (graphical or framebuffer) and runner.framebuffer_device is not None:
        command.extend(("-device", runner.framebuffer_device))
    command.extend(("-cpu", runner.cpu, "-smp", str(runner.virtual_cpus)))
    command.extend(runner.extra_arguments)
    command.extend(
        (
            "-m",
            runner.memory if memory is None else validate_memory_size(memory),
            "-drive",
            f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}",
            "-drive",
            f"if=pflash,format=raw,unit=1,file={variables}",
        )
    )
    if runner.disk_layout == "cloud-bundle-v1":
        command.extend(
            (
                "-drive",
                f"if=none,format=raw,cache=writeback,id=troe-system,file={image}",
                "-device",
                f"{runner.virtio_block_device},drive=troe-system,bootindex=1",
            )
        )
    elif runner.boot_media_device is None:
        command.extend(
            (
                "-drive",
                f"if=virtio,format=raw,file={image}",
                "-drive",
                f"if=none,format=raw,cache=writeback,id=troe-root,file={storage}",
                "-device",
                f"{runner.virtio_block_device},drive=troe-root",
            )
        )
    else:
        # Firmware that carries no virtio driver still has to read the boot
        # volume, so it arrives on the bus the machine gives the firmware.
        command.extend(
            (
                "-drive",
                f"if=none,format=raw,id=troe-boot,file={image}",
                "-device",
                f"{runner.boot_media_device},drive=troe-boot,bootindex=1",
                "-drive",
                f"if=none,format=raw,cache=writeback,id=troe-root,file={storage}",
                "-device",
                f"{runner.virtio_block_device},drive=troe-root",
            )
        )
    command.extend(
        (
            "-drive",
            f"if=none,format=raw,cache=writeback,id=troe-txslot,file={txslot}",
            "-device",
            f"{runner.virtio_block_device},drive=troe-txslot",
            "-drive",
            f"if=none,format=raw,cache=writeback,id=troe-statefs,file={statefs}",
            "-device",
            f"{runner.virtio_block_device},drive=troe-statefs",
        )
    )
    for index, data_disk in enumerate(data_disks):
        drive_id = f"troe-data-{index}"
        command.extend(
            (
                "-drive",
                f"if=none,format=raw,cache=writeback,id={drive_id},file={data_disk}",
                "-device",
                f"{runner.virtio_block_device},drive={drive_id}",
            )
        )
    command.extend(
        (
            "-netdev",
            "user,id=troe-net",
            "-device",
            f"{runner.virtio_network_device},netdev=troe-net,mac={runner.network_mac}",
            "-object",
            "rng-random,id=troe-rng,filename=/dev/urandom",
            "-device",
            f"{runner.virtio_rng_device},rng=troe-rng",
            "-no-reboot",
        )
    )
    return command


def qemu_discovered_x86_spcr_bytes() -> bytes:
    """Return the exact runner-owned ACPI SPCR for QEMU COM1."""
    table = bytearray(80)
    table[0:4] = b"SPCR"
    table[4:8] = len(table).to_bytes(4, "little")
    table[8] = 2
    table[10:16] = b"TROE  "
    table[16:24] = b"QEMUCOM1"
    table[24:28] = (1).to_bytes(4, "little")
    table[28:32] = b"TROE"
    table[32:36] = (1).to_bytes(4, "little")
    table[36] = 0  # 16550
    table[40:52] = bytes((1, 8, 0, 1)) + (0x3F8).to_bytes(8, "little")
    table[52] = 0b11  # legacy IRQ and I/O-APIC GSI
    table[53] = 4
    table[54:58] = (4).to_bytes(4, "little")
    table[58] = 7  # 115200 baud
    table[60] = 1  # one stop bit
    table[64:68] = b"\xff\xff\xff\xff"  # non-PCI UART
    table[9] = (-sum(table)) & 0xFF
    return bytes(table)


def qemu_discovered_x86_spcr_path() -> Path:
    """Publish the deterministic SPCR fixture atomically under build/."""
    destination = REPO_ROOT / "build" / "qemu-discovered-x86-spcr.bin"
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = qemu_discovered_x86_spcr_bytes()
    if destination.is_file() and destination.read_bytes() == payload:
        return destination
    with tempfile.NamedTemporaryFile(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        delete=False,
    ) as staging:
        staging.write(payload)
        staging.flush()
        staging_path = Path(staging.name)
    staging_path.replace(destination)
    return destination


def prepare_qemu_command(
    platform_id: str,
    environment: str,
    firmware_code: Path | None = None,
    firmware_vars: Path | None = None,
    *,
    skip_version_check: bool = False,
    strict_tool_versions: bool = False,
    build: bool = True,
    acceptance_probes: bool = False,
    graphical: bool = False,
    framebuffer: bool = False,
    memory: str | None = None,
    volume_table: Path | None = None,
    data_disks: tuple[Path, ...] = (),
) -> list[str]:
    """Build an image, copy a disposable variable store, and return QEMU arguments."""
    profile = resolve_platform(platform_id)
    runner = resolve_runner(platform_id, environment)
    executable_name = runner.executable
    executable = shutil.which(executable_name)
    if executable is None:
        raise FileNotFoundError(f"QEMU executable not found on PATH: {executable_name}")

    if skip_version_check and strict_tool_versions:
        raise RuntimeError(
            "--skip-version-check and --strict-tool-versions are mutually exclusive"
        )
    if not skip_version_check:
        version = verify_qemu_version(
            qemu_version(executable), strict=strict_tool_versions
        )
        if not strict_tool_versions:
            announce_compatible_qemu(version)

    firmware = resolve_firmware(
        firmware_code, executable, runner, "code", strict=strict_tool_versions
    )
    vars_source = resolve_firmware(
        firmware_vars, executable, runner, "vars", strict=strict_tool_versions
    )
    if len(data_disks) > MAX_EXTRA_DATA_DISKS:
        raise RuntimeError(
            f"at most {MAX_EXTRA_DATA_DISKS} additional data disks may be attached"
        )
    resolved_data_disks: list[Path] = []
    for supplied in data_disks:
        selected = supplied.expanduser().resolve(strict=True)
        if not selected.is_file():
            raise FileNotFoundError(
                f"custom data disk is not a regular file: {selected}"
            )
        if selected in resolved_data_disks:
            raise RuntimeError(
                f"custom data disk is attached more than once: {selected}"
            )
        resolved_data_disks.append(selected)
    if not build and volume_table is not None:
        raise RuntimeError("--volume-table requires a build; remove --skip-build")
    if build:
        selected_volume_table = (
            DEFAULT_VOLUME_TABLE if volume_table is None else volume_table.expanduser()
        ).resolve(strict=True)
        if not selected_volume_table.is_file():
            raise FileNotFoundError(
                f"volume table is not a regular file: {selected_volume_table}"
            )
        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build.py"),
                "--platform",
                profile.identifier,
                "--fixture-identities",
                "--volume-table",
                str(selected_volume_table),
                *(("--strict-tool-versions",) if strict_tool_versions else ()),
                *(("--acceptance-probes",) if acceptance_probes else ()),
            ],
            cwd=REPO_ROOT,
            check=True,
        )

        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "mkstorage.py"),
                "--manifest",
                str(REPO_ROOT / "assets" / "boot.bmnt"),
                "--volume-table",
                str(selected_volume_table),
                "--output",
                str(REPO_ROOT / "build" / "storage-root.img"),
                "--content",
                str(REPO_ROOT / "assets" / "system.cspk"),
                "--persistence-selector",
                str(REPO_ROOT / "assets" / "persist.prgn"),
                "--txslot-output",
                str(txslot_image_path(profile)),
                "--state-selector",
                str(REPO_ROOT / "assets" / "state.prgn"),
                "--statefs-output",
                str(statefs_image_path(profile)),
                *(("--strict-tool-versions",) if strict_tool_versions else ()),
            ],
            cwd=REPO_ROOT,
            check=True,
        )
        if runner.disk_layout == "cloud-bundle-v1":
            build_cloud_bundle(
                profile,
                environment,
                acceptance_probes=acceptance_probes,
            )

    image = boot_image_path(profile, acceptance_probes=acceptance_probes)
    if runner.disk_layout == "cloud-bundle-v1":
        bundle = cloud_bundle_path(
            profile,
            environment,
            acceptance_probes=acceptance_probes,
        )
        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "mkcloud.py"),
                "verify",
                "--bundle",
                str(bundle),
                "--allow-test-artifacts",
            ],
            cwd=REPO_ROOT,
            check=True,
        )
        image = bundle / "system.raw"
        if build or not txslot_image_path(profile).is_file():
            shutil.copyfile(bundle / "activation.raw", txslot_image_path(profile))
        if build or not statefs_image_path(profile).is_file():
            shutil.copyfile(bundle / "state.raw", statefs_image_path(profile))
    if not image.is_file():
        raise FileNotFoundError(f"boot image not found: {image}")
    storage = root_storage_image_path(profile)
    if runner.disk_layout == "split" and not storage.is_file():
        raise FileNotFoundError(f"storage fixture not found: {storage}")
    txslot = txslot_image_path(profile)
    if not txslot.is_file() or txslot.stat().st_size != 4_096 * 512:
        raise FileNotFoundError(f"TXSLOT fixture not found or invalid: {txslot}")
    statefs = statefs_image_path(profile)
    if not statefs.is_file() or statefs.stat().st_size != 4_096 * 512:
        raise FileNotFoundError(f"statefs fixture not found or invalid: {statefs}")
    reserved_disks = {
        image.resolve(),
        storage.resolve(),
        txslot.resolve(),
        statefs.resolve(),
    }
    for data_disk in resolved_data_disks:
        if data_disk in reserved_disks:
            raise RuntimeError(
                f"custom data disk duplicates a TROE system disk: {data_disk}"
            )
    variables = variable_store_path(profile)
    shutil.copyfile(vars_source, variables)
    command = _qemu_arguments(
        runner,
        executable,
        firmware,
        variables,
        image,
        storage,
        txslot,
        statefs,
        data_disks=tuple(resolved_data_disks),
        graphical=graphical,
        framebuffer=framebuffer,
        memory=memory,
    )
    if profile.identifier == X86_64_UEFI_VIRTIO_PCI:
        command.extend(
            (
                "-acpitable",
                f"file={qemu_discovered_x86_spcr_path()}",
            )
        )
    return command

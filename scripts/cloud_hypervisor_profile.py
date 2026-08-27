#!/usr/bin/env python3
"""Pinned Cloud Hypervisor production-runner profile and host checks."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform as host_platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from platform_profile import REPO_ROOT, resolve_platform

sys.path.insert(0, str(REPO_ROOT))

from tools import mkcloud  # noqa: E402


PROFILE_PATH = REPO_ROOT / "tools" / "cloud-hypervisor-profile.json"
ARTIFACT_READ_CHUNK = 1024 * 1024
TAP_NAME = re.compile(r"[a-zA-Z0-9_.-]{1,15}")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAC_ADDRESS = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")


@dataclass(frozen=True)
class PinnedArtifact:
    """One exact upstream release asset."""

    name: str
    release: str
    sha256: str
    size: int
    url: str


@dataclass(frozen=True)
class CpuProfile:
    """Fixed guest CPU topology and address-width contract."""

    boot: int
    maximum: int
    max_phys_bits: int


@dataclass(frozen=True)
class HostProfile:
    """Minimum Linux/KVM host resources required before launch."""

    architecture: str
    kernel: str
    kvm_device: Path
    minimum_available_memory_bytes: int
    minimum_runtime_free_bytes: int


@dataclass(frozen=True)
class NetworkProfile:
    """Exact guest/TAP addressing and virtio-net identity."""

    guest: ipaddress.IPv4Interface
    host: ipaddress.IPv4Interface
    mac: str
    peer_port: int


@dataclass(frozen=True)
class CloudHypervisorProfile:
    """One exact TROE platform and Cloud Hypervisor execution environment."""

    architecture: str
    control: PinnedArtifact
    cpus: CpuProfile
    disks: tuple[str, ...]
    environment: str
    firmware: PinnedArtifact
    guest_memory_bytes: int
    host: HostProfile
    network: NetworkProfile
    platform: str
    vmm: PinnedArtifact


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _artifact(value: object, label: str) -> PinnedArtifact:
    if not isinstance(value, dict) or set(value) != {
        "name",
        "release",
        "sha256",
        "size",
        "url",
    }:
        raise ValueError(f"Cloud Hypervisor {label} record is invalid")
    name = value["name"]
    release = value["release"]
    digest = value["sha256"]
    size = value["size"]
    url = value["url"]
    if (
        not isinstance(name, str)
        or not name
        or "/" in name
        or not isinstance(release, str)
        or not release
        or not isinstance(digest, str)
        or SHA256.fullmatch(digest) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(url, str)
        or not url.startswith("https://github.com/")
        or not url.endswith(f"/{name}")
    ):
        raise ValueError(f"Cloud Hypervisor {label} record is invalid")
    return PinnedArtifact(name, release, digest, size, url)


def validate_profile(raw: object) -> CloudHypervisorProfile:
    """Validate the complete profile without accepting schema extensions."""
    fields = {
        "architecture",
        "control",
        "cpus",
        "disks",
        "environment",
        "firmware",
        "guest_memory_bytes",
        "host",
        "network",
        "platform",
        "schema",
        "vmm",
    }
    if not isinstance(raw, dict) or set(raw) != fields or raw.get("schema") != 1:
        raise ValueError("Cloud Hypervisor profile is not schema 1")

    architecture = raw["architecture"]
    environment = raw["environment"]
    platform_name = raw["platform"]
    disks = raw["disks"]
    guest_memory = raw["guest_memory_bytes"]
    if (
        architecture != "x86_64"
        or not isinstance(environment, str)
        or IDENTIFIER.fullmatch(environment) is None
        or not isinstance(platform_name, str)
        or not isinstance(disks, list)
        or disks != ["system", "activation", "state"]
        or not isinstance(guest_memory, int)
        or isinstance(guest_memory, bool)
        or guest_memory != 128 * 1024 * 1024
    ):
        raise ValueError("Cloud Hypervisor platform or resource profile is invalid")
    platform_profile = resolve_platform(platform_name)
    if (
        platform_profile.architecture != architecture
        or platform_profile.firmware_discovery != "acpi"
        or platform_profile.virtio_transport != "pci"
    ):
        raise ValueError("Cloud Hypervisor platform does not select ACPI virtio-PCI")

    cpus = raw["cpus"]
    if not isinstance(cpus, dict) or set(cpus) != {"boot", "max", "max_phys_bits"}:
        raise ValueError("Cloud Hypervisor CPU profile is invalid")
    boot = cpus["boot"]
    maximum = cpus["max"]
    physical_bits = cpus["max_phys_bits"]
    if (boot, maximum, physical_bits) != (1, 1, 46):
        raise ValueError("Cloud Hypervisor CPU profile is invalid")

    host = raw["host"]
    if not isinstance(host, dict) or set(host) != {
        "architecture",
        "kernel",
        "kvm_device",
        "minimum_available_memory_bytes",
        "minimum_runtime_free_bytes",
    }:
        raise ValueError("Cloud Hypervisor host profile is invalid")
    host_memory = host["minimum_available_memory_bytes"]
    host_storage = host["minimum_runtime_free_bytes"]
    if (
        host["architecture"] != "x86_64"
        or host["kernel"] != "linux"
        or host["kvm_device"] != "/dev/kvm"
        or not isinstance(host_memory, int)
        or isinstance(host_memory, bool)
        or host_memory < 4 * guest_memory
        or not isinstance(host_storage, int)
        or isinstance(host_storage, bool)
        or host_storage < 4 * 64 * 1024 * 1024
    ):
        raise ValueError("Cloud Hypervisor host profile is invalid")

    network = raw["network"]
    if not isinstance(network, dict) or set(network) != {
        "guest",
        "host",
        "mac",
        "peer_port",
    }:
        raise ValueError("Cloud Hypervisor network profile is invalid")
    try:
        guest_address = ipaddress.IPv4Interface(cast(str, network["guest"]))
        host_address = ipaddress.IPv4Interface(cast(str, network["host"]))
    except (
        ipaddress.AddressValueError,
        ipaddress.NetmaskValueError,
        TypeError,
    ) as error:
        raise ValueError("Cloud Hypervisor network profile is invalid") from error
    mac = network["mac"]
    peer_port = network["peer_port"]
    if (
        guest_address.network != host_address.network
        or guest_address.ip == host_address.ip
        or not isinstance(mac, str)
        or MAC_ADDRESS.fullmatch(mac) is None
        or not isinstance(peer_port, int)
        or isinstance(peer_port, bool)
        or not 1 <= peer_port <= 0xFFFF
    ):
        raise ValueError("Cloud Hypervisor network profile is invalid")

    vmm = _artifact(raw["vmm"], "VMM")
    control = _artifact(raw["control"], "control")
    firmware = _artifact(raw["firmware"], "firmware")
    if (
        vmm.release != "v53.0"
        or control.release != vmm.release
        or firmware.release != "ch-f308d878a6"
    ):
        raise ValueError("Cloud Hypervisor release pins are inconsistent")

    return CloudHypervisorProfile(
        architecture=architecture,
        control=control,
        cpus=CpuProfile(boot, maximum, physical_bits),
        disks=tuple(cast(list[str], disks)),
        environment=environment,
        firmware=firmware,
        guest_memory_bytes=guest_memory,
        host=HostProfile(
            architecture=cast(str, host["architecture"]),
            kernel=cast(str, host["kernel"]),
            kvm_device=Path(cast(str, host["kvm_device"])),
            minimum_available_memory_bytes=host_memory,
            minimum_runtime_free_bytes=host_storage,
        ),
        network=NetworkProfile(guest_address, host_address, mac, peer_port),
        platform=platform_name,
        vmm=vmm,
    )


def load_profile(path: Path = PROFILE_PATH) -> CloudHypervisorProfile:
    """Read the canonical pinned profile."""
    try:
        encoded = path.read_bytes()
        decoded = json.loads(encoded)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"cannot read Cloud Hypervisor profile {path}: {error}"
        ) from error
    if encoded != _canonical_json(decoded):
        raise ValueError("Cloud Hypervisor profile JSON is not canonical")
    return validate_profile(decoded)


def verify_artifact(
    supplied: Path, expected: PinnedArtifact, *, executable: bool
) -> Path:
    """Require one regular non-symlink asset with exact size and SHA-256."""
    if supplied.is_symlink():
        raise ValueError(f"pinned artifact must not be a symlink: {supplied}")
    path = supplied.resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected.size:
        raise ValueError(
            f"{expected.name} size mismatch: expected {expected.size}, "
            f"got {metadata.st_size}"
        )
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(ARTIFACT_READ_CHUNK):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected.sha256:
        raise ValueError(
            f"{expected.name} SHA-256 mismatch: expected {expected.sha256}, got {actual}"
        )
    if executable and not os.access(path, os.X_OK):
        raise ValueError(f"pinned executable is not executable: {path}")
    return path


def verify_version(executable: Path, program: str, release: str) -> None:
    """Require the pinned executable to identify the exact release."""
    completed = subprocess.run(
        [str(executable), "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
    )
    output = completed.stdout.strip()
    if completed.returncode != 0 or output != f"{program} {release}":
        raise ValueError(
            f"expected {program} {release!s}, got status {completed.returncode}: "
            f"{output!r}"
        )


def verify_production_bundle(
    directory: Path, profile: CloudHypervisorProfile
) -> dict[str, object]:
    """Verify an immutable production seed for the exact platform/environment."""
    manifest = mkcloud.verify_bundle(directory.resolve(strict=True))
    if (
        manifest.get("kind") != mkcloud.BUNDLE_KIND_PRODUCTION
        or manifest.get("platform") != profile.platform
        or manifest.get("environment") != profile.environment
    ):
        raise ValueError("bundle does not select the pinned production environment")
    return manifest


def stage_runtime_bundle(bundle: Path, runtime: Path) -> dict[str, Path]:
    """Create per-machine writable copies without mutating the verified seeds."""
    if runtime.exists():
        raise ValueError(f"runtime directory already exists: {runtime}")
    runtime.mkdir(parents=True, mode=0o700)
    runtime.chmod(0o700)
    staged: dict[str, Path] = {}
    try:
        for role, filename in mkcloud.BUNDLE_FILENAMES.items():
            destination = runtime / filename
            shutil.copyfile(bundle / filename, destination)
            staged[role] = destination
        shutil.copyfile(
            bundle / mkcloud.BUNDLE_MANIFEST, runtime / mkcloud.BUNDLE_MANIFEST
        )
    except Exception:
        shutil.rmtree(runtime, ignore_errors=True)
        raise
    return staged


def validate_tap_name(tap: str) -> str:
    """Reject ambiguous, empty, or Linux-truncated interface names."""
    if TAP_NAME.fullmatch(tap) is None or tap in {".", ".."}:
        raise ValueError(f"invalid TAP interface name: {tap!r}")
    return tap


def cloud_hypervisor_command(
    profile: CloudHypervisorProfile,
    *,
    vmm: Path,
    firmware: Path,
    disks: dict[str, Path],
    tap: str,
    api_socket: Path,
    log_file: Path,
    event_file: Path,
) -> list[str]:
    """Return the fully explicit v53 command for one staged machine."""
    validate_tap_name(tap)
    if set(disks) != set(profile.disks):
        raise ValueError("runtime disk set does not match the pinned profile")
    memory_mib = profile.guest_memory_bytes // (1024 * 1024)
    command = [
        str(vmm),
        "--cpus",
        (
            f"boot={profile.cpus.boot},max={profile.cpus.maximum},"
            f"max_phys_bits={profile.cpus.max_phys_bits}"
        ),
        "--memory",
        f"size={memory_mib}M,mergeable=off,shared=off,hugepages=off,prefault=on",
        "--platform",
        "num_pci_segments=1",
        "--firmware",
        str(firmware),
    ]
    for role in profile.disks:
        command.extend(
            (
                "--disk",
                (
                    f"path={disks[role]},image_type=raw,readonly=off,direct=off,"
                    "num_queues=1,queue_size=128,sparse=off"
                ),
            )
        )
    command.extend(
        (
            "--net",
            (
                f"tap={tap},mac={profile.network.mac},num_queues=1,queue_size=256,"
                "offload_tso=off,offload_ufo=off,offload_csum=off"
            ),
            "--serial",
            "tty",
            "--console",
            "off",
            "--api-socket",
            f"path={api_socket}",
            "--event-monitor",
            f"path={event_file}",
            "--log-file",
            str(log_file),
            "--seccomp",
            "true",
            "--landlock",
            "-v",
        )
    )
    return command


def _mem_available(path: Path) -> int:
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "MemAvailable:" and fields[2] == "kB":
            return int(fields[1]) * 1024
    raise ValueError(f"cannot read MemAvailable from {path}")


def verify_host(
    profile: CloudHypervisorProfile,
    *,
    tap: str,
    runtime_parent: Path,
    system_name: str | None = None,
    machine_name: str | None = None,
    sys_class_net: Path = Path("/sys/class/net"),
    meminfo: Path = Path("/proc/meminfo"),
) -> None:
    """Fail before launch unless the exact Linux/KVM/TAP resource floor exists."""
    system_name = host_platform.system().lower() if system_name is None else system_name
    machine_name = (
        host_platform.machine().lower() if machine_name is None else machine_name
    )
    if system_name != profile.host.kernel or machine_name not in {"x86_64", "amd64"}:
        raise ValueError("Cloud Hypervisor production acceptance requires Linux x86_64")
    try:
        kvm = profile.host.kvm_device.stat()
    except OSError as error:
        raise ValueError(
            f"KVM device is unavailable: {profile.host.kvm_device}"
        ) from error
    if not stat.S_ISCHR(kvm.st_mode) or not os.access(
        profile.host.kvm_device, os.R_OK | os.W_OK
    ):
        raise ValueError(
            f"KVM device is not a readable/writable character device: {profile.host.kvm_device}"
        )
    if _mem_available(meminfo) < profile.host.minimum_available_memory_bytes:
        raise ValueError("host does not meet the pinned available-memory floor")
    if shutil.disk_usage(runtime_parent).free < profile.host.minimum_runtime_free_bytes:
        raise ValueError("runtime filesystem does not meet the pinned free-space floor")

    tap = validate_tap_name(tap)
    tap_directory = sys_class_net / tap
    if not tap_directory.is_dir() or not (tap_directory / "tun_flags").is_file():
        raise ValueError(f"required pre-created TAP interface is unavailable: {tap}")
    completed = subprocess.run(
        ["ip", "-j", "address", "show", "dev", tap],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    try:
        records = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"cannot inspect TAP interface {tap}: {completed.stderr.strip()}"
        ) from error
    expected = str(profile.network.host)
    addresses = {
        f"{address.get('local')}/{address.get('prefixlen')}"
        for record in records
        if isinstance(record, dict)
        for address in cast(list[dict[str, object]], record.get("addr_info", []))
        if address.get("family") == "inet"
    }
    if completed.returncode != 0 or expected not in addresses:
        raise ValueError(f"TAP interface {tap} does not own {expected}")

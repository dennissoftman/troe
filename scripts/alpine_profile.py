#!/usr/bin/env python3
"""Pinned Alpine image acquisition and matched QEMU command construction."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable

if __package__:
    from .qemu_profile import (
        EXPECTED_QEMU_VERSION,
        QEMU_ENVIRONMENT,
        RunnerProfile,
        qemu_version,
        resolve_firmware,
        resolve_runner,
        validate_memory_size,
    )
else:
    from qemu_profile import (
        EXPECTED_QEMU_VERSION,
        QEMU_ENVIRONMENT,
        RunnerProfile,
        qemu_version,
        resolve_firmware,
        resolve_runner,
        validate_memory_size,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
ALPINE_PROFILE_PATH = REPO_ROOT / "tools" / "alpine-profile.json"
ALPINE_CACHE_DIR = REPO_ROOT / "build" / "alpine"
ALPINE_ROOT_DISK_BYTES = 4 * 1024 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class AlpineArtifact:
    """One exact official Alpine virtual ISO."""

    architecture: str
    filename: str
    bytes: int
    sha256: str


@dataclass(frozen=True)
class AlpineProfile:
    """The pinned Alpine release and its architecture artifacts."""

    version: str
    base_url: str
    artifacts: dict[str, AlpineArtifact]


def alpine_profile(path: Path = ALPINE_PROFILE_PATH) -> AlpineProfile:
    """Load and strictly validate the committed Alpine release profile."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read Alpine profile {path}: {error}") from error
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema", "version", "base_url", "artifacts"}
        or raw.get("schema") != 1
        or not isinstance(raw.get("version"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", raw["version"]) is None
        or not isinstance(raw.get("base_url"), str)
        or not raw["base_url"].startswith("https://")
        or raw["base_url"].endswith("/")
        or not isinstance(raw.get("artifacts"), dict)
        or set(raw["artifacts"]) != {"x86_64", "aarch64"}
    ):
        raise RuntimeError(f"invalid Alpine profile: {path}")

    artifacts: dict[str, AlpineArtifact] = {}
    for architecture in ("x86_64", "aarch64"):
        entry = raw["artifacts"][architecture]
        if (
            not isinstance(entry, dict)
            or set(entry) != {"filename", "bytes", "sha256"}
            or not isinstance(entry["filename"], str)
            or re.fullmatch(
                rf"alpine-virt-{re.escape(raw['version'])}-{architecture}\.iso",
                entry["filename"],
            )
            is None
            or not isinstance(entry["bytes"], int)
            or entry["bytes"] <= 0
            or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
        ):
            raise RuntimeError(
                f"invalid Alpine {architecture} artifact in profile: {path}"
            )
        artifacts[architecture] = AlpineArtifact(
            architecture=architecture,
            filename=entry["filename"],
            bytes=entry["bytes"],
            sha256=entry["sha256"],
        )
    return AlpineProfile(
        version=raw["version"], base_url=raw["base_url"], artifacts=artifacts
    )


def verify_alpine_image(path: Path, artifact: AlpineArtifact) -> None:
    """Require the exact length and SHA-256 of one pinned Alpine image."""
    try:
        actual_bytes = path.stat().st_size
    except OSError as error:
        raise RuntimeError(f"cannot inspect Alpine image {path}: {error}") from error
    if actual_bytes != artifact.bytes:
        raise RuntimeError(
            f"Alpine image size mismatch for {path}: expected {artifact.bytes} bytes, "
            f"got {actual_bytes}"
        )
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(DOWNLOAD_CHUNK_BYTES), b""):
                digest.update(chunk)
    except OSError as error:
        raise RuntimeError(f"cannot read Alpine image {path}: {error}") from error
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != artifact.sha256:
        raise RuntimeError(
            f"Alpine image digest mismatch for {path}: expected {artifact.sha256}, "
            f"got {actual_sha256}"
        )


def _copy_download(source: BinaryIO, destination: BinaryIO) -> None:
    """Copy one bounded stream without trusting a remote content length."""
    while chunk := source.read(DOWNLOAD_CHUNK_BYTES):
        destination.write(chunk)


def download_alpine_image(url: str, destination: Path) -> None:
    """Download one HTTPS artifact with the system TLS client when available."""
    curl = shutil.which("curl")
    if curl is not None:
        try:
            subprocess.run(
                [
                    curl,
                    "--fail",
                    "--location",
                    "--progress-bar",
                    "--proto",
                    "=https",
                    "--tlsv1.2",
                    "--output",
                    str(destination),
                    url,
                ],
                check=True,
            )
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                f"Alpine image download exited with status {error.returncode}"
            ) from error
        return
    try:
        with urllib.request.urlopen(url, timeout=60) as source:
            with destination.open("wb") as output:
                _copy_download(source, output)
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError(f"Alpine image download failed: {error}") from error


def acquire_alpine_image(
    profile: AlpineProfile,
    architecture: str,
    *,
    refresh: bool = False,
    downloader: Callable[[str, Path], None] = download_alpine_image,
) -> Path:
    """Return a verified cached ISO, downloading it atomically when absent."""
    try:
        artifact = profile.artifacts[architecture]
    except KeyError as error:
        raise RuntimeError(f"Alpine has no pinned {architecture} image") from error
    destination = ALPINE_CACHE_DIR / artifact.filename
    if destination.exists() and not refresh:
        try:
            verify_alpine_image(destination, artifact)
        except RuntimeError as error:
            raise RuntimeError(f"{error}; pass --refresh to replace it") from error
        return destination

    ALPINE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    url = f"{profile.base_url}/{architecture}/{artifact.filename}"
    print(f"Downloading Alpine {profile.version} {architecture} from {url}", flush=True)
    staging_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=ALPINE_CACHE_DIR,
            prefix=f".{artifact.filename}.",
            delete=False,
        ) as staging:
            staging_path = Path(staging.name)
            staging.flush()
        downloader(url, staging_path)
        verify_alpine_image(staging_path, artifact)
        staging_path.replace(destination)
    except OSError as error:
        raise RuntimeError(f"Alpine image download failed: {error}") from error
    finally:
        if staging_path is not None:
            staging_path.unlink(missing_ok=True)
    return destination


def alpine_variables_path(platform_id: str) -> Path:
    """Return the Alpine-qualified persistent UEFI variable-store path."""
    return ALPINE_CACHE_DIR / f"qemu-vars-{platform_id}.fd"


def alpine_root_disk_path(platform_id: str) -> Path:
    """Return the platform-qualified persistent Alpine system-disk path."""
    return ALPINE_CACHE_DIR / f"root-{platform_id}.raw"


def ensure_alpine_root_image(path: Path, *, reset: bool = False) -> bool:
    """Preserve or atomically create one sparse raw Alpine system disk."""
    if path.is_symlink():
        raise RuntimeError("Alpine root image path must not be a symbolic link")
    selected = path.resolve(strict=False)
    selected.parent.mkdir(parents=True, exist_ok=True)
    if selected.exists() and not reset:
        if not selected.is_file():
            raise RuntimeError(f"Alpine root image is not a regular file: {selected}")
        actual_bytes = selected.stat().st_size
        if actual_bytes != ALPINE_ROOT_DISK_BYTES:
            raise RuntimeError(
                f"Alpine root image has {actual_bytes} bytes, expected "
                f"{ALPINE_ROOT_DISK_BYTES}; pass --reset-root-disk to replace it"
            )
        return False

    staging_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=selected.parent,
            prefix=f".{selected.name}.",
            delete=False,
        ) as staging:
            staging_path = Path(staging.name)
            staging.truncate(ALPINE_ROOT_DISK_BYTES)
            staging.flush()
        staging_path.replace(selected)
    except OSError as error:
        raise RuntimeError(f"cannot create Alpine root image {selected}: {error}") from error
    finally:
        if staging_path is not None:
            staging_path.unlink(missing_ok=True)
    return True


def alpine_root_needs_install(path: Path) -> bool:
    """Return whether a system image still has no partition or boot metadata."""
    try:
        with path.open("rb") as root:
            return not any(root.read(4096))
    except OSError as error:
        raise RuntimeError(f"cannot inspect Alpine root image {path}: {error}") from error


def ensure_alpine_variables(
    source: Path, destination: Path, *, reset: bool = False
) -> None:
    """Preserve installed UEFI state or atomically initialize it from a template."""
    if destination.is_symlink():
        raise RuntimeError("Alpine UEFI variable-store path must not be a symbolic link")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not reset:
        if not destination.is_file():
            raise RuntimeError(
                f"Alpine UEFI variable store is not a regular file: {destination}"
            )
        if destination.stat().st_size != source.stat().st_size:
            raise RuntimeError(
                "Alpine UEFI variable store has the wrong size; "
                "pass --reset-root-disk to replace it"
            )
        return

    staging_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as staging:
            staging_path = Path(staging.name)
        shutil.copyfile(source, staging_path)
        staging_path.replace(destination)
    except OSError as error:
        raise RuntimeError(
            f"cannot initialize Alpine UEFI variable store {destination}: {error}"
        ) from error
    finally:
        if staging_path is not None:
            staging_path.unlink(missing_ok=True)


def _alpine_qemu_arguments(
    runner: RunnerProfile,
    executable: str,
    firmware: Path,
    variables: Path,
    image: Path,
    root_disk: Path | None,
    shared_disk: Path | None,
    *,
    graphical: bool,
    memory: str,
) -> list[str]:
    """Return a QEMU command matching TROE's machine resources."""
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
    if graphical and runner.framebuffer_device is not None:
        command.extend(("-device", runner.framebuffer_device))
    command.extend(("-cpu", runner.cpu, "-smp", str(runner.virtual_cpus)))
    command.extend(runner.extra_arguments)
    command.extend(
        (
            "-m",
            validate_memory_size(memory),
            "-drive",
            f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}",
            "-drive",
            f"if=pflash,format=raw,unit=1,file={variables}",
        )
    )
    if root_disk is not None:
        command.extend(
            (
                "-drive",
                f"if=none,format=raw,cache=writeback,id=alpine-root,file={root_disk}",
                "-device",
                f"{runner.virtio_block_device},drive=alpine-root,"
                "serial=ALPINE_ROOT,bootindex=1",
            )
        )
    command.extend(
        (
            "-drive",
            f"if=none,format=raw,readonly=on,id=alpine-boot,file={image}",
            "-device",
            f"{runner.virtio_block_device},drive=alpine-boot,bootindex="
            f"{2 if root_disk is not None else 1}",
        )
    )
    if shared_disk is not None:
        command.extend(
            (
                "-drive",
                f"if=none,format=raw,cache=writeback,id=alpine-shared,file={shared_disk}",
                "-device",
                f"{runner.virtio_block_device},drive=alpine-shared,serial=TROE_SHARED",
            )
        )
    command.extend(
        (
            "-netdev",
            "user,id=alpine-net",
            "-device",
            f"{runner.virtio_network_device},netdev=alpine-net,mac={runner.network_mac}",
            "-no-reboot",
        )
    )
    return command


def prepare_alpine_command(
    platform_id: str,
    environment: str = QEMU_ENVIRONMENT,
    firmware_code: Path | None = None,
    firmware_vars: Path | None = None,
    *,
    image: Path,
    root_disk: Path | None,
    shared_disk: Path | None,
    reset_variables: bool = False,
    skip_version_check: bool = False,
    graphical: bool = False,
    memory: str = "256M",
) -> list[str]:
    """Resolve matched QEMU resources and return an Alpine launch command."""
    runner = resolve_runner(platform_id, environment)
    executable = shutil.which(runner.executable)
    if executable is None:
        raise FileNotFoundError(f"QEMU executable not found on PATH: {runner.executable}")
    if not skip_version_check:
        version = qemu_version(executable)
        if re.search(rf"\bversion {re.escape(EXPECTED_QEMU_VERSION)}\b", version) is None:
            raise RuntimeError(
                f"expected QEMU {EXPECTED_QEMU_VERSION}, got: {version} "
                "(use --skip-version-check deliberately)"
            )

    selected_image = image.expanduser().resolve(strict=True)
    if not selected_image.is_file():
        raise FileNotFoundError(f"Alpine image is not a regular file: {selected_image}")
    selected_root = None
    if root_disk is not None:
        selected_root = root_disk.expanduser().resolve(strict=True)
        if not selected_root.is_file():
            raise FileNotFoundError(
                f"Alpine root image is not a regular file: {selected_root}"
            )
        if selected_root == selected_image:
            raise RuntimeError("Alpine boot image and root image must be different")
    selected_shared = None
    if shared_disk is not None:
        selected_shared = shared_disk.expanduser().resolve(strict=True)
        if not selected_shared.is_file():
            raise FileNotFoundError(
                f"shared image is not a regular file: {selected_shared}"
            )
        if selected_shared in {selected_image, selected_root}:
            raise RuntimeError("Alpine boot, root, and shared images must be different")

    firmware = resolve_firmware(firmware_code, executable, runner, "code")
    vars_source = resolve_firmware(firmware_vars, executable, runner, "vars")
    ALPINE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    variables = alpine_variables_path(platform_id)
    ensure_alpine_variables(
        vars_source,
        variables,
        reset=reset_variables or selected_root is None,
    )
    return _alpine_qemu_arguments(
        runner,
        executable,
        firmware,
        variables,
        selected_image,
        selected_root,
        selected_shared,
        graphical=graphical,
        memory=memory,
    )

#!/usr/bin/env python3
"""Shared pinned QEMU profile and image preparation helpers."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_QEMU_VERSION = "11.1.0"
QEMU_EXECUTABLES = {
    "x86_64": "qemu-system-x86_64",
    "aarch64": "qemu-system-aarch64",
}
FIRMWARE_FILENAMES = {
    "x86_64": {
        "code": ("edk2-x86_64-code.fd", "OVMF_CODE.fd", "OVMF_CODE_4M.fd"),
        "vars": ("edk2-i386-vars.fd", "OVMF_VARS.fd", "OVMF_VARS_4M.fd"),
    },
    "aarch64": {
        "code": ("edk2-aarch64-code.fd", "AAVMF_CODE.fd", "QEMU_EFI.fd"),
        "vars": ("edk2-arm-vars.fd", "AAVMF_VARS.fd"),
    },
}


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


def firmware_search_roots(executable: str) -> tuple[Path, ...]:
    """Return QEMU-adjacent and conventional system firmware directories."""
    executable_dir = Path(executable).resolve().parent
    roots = (
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


def discover_firmware(executable: str, architecture: str, kind: str) -> Path:
    """Find a QEMU-distributed UEFI code or variable-store image."""
    filenames = FIRMWARE_FILENAMES[architecture][kind]
    roots = firmware_search_roots(executable)
    for root in roots:
        for filename in filenames:
            candidate = root / filename
            if candidate.is_file():
                return candidate.resolve()

    flag = "--firmware-code" if kind == "code" else "--firmware-vars"
    searched = ", ".join(str(root) for root in roots)
    raise FileNotFoundError(
        f"could not auto-detect {architecture} UEFI firmware {kind}; "
        f"pass {flag} explicitly (searched: {searched})"
    )


def resolve_firmware(
    supplied: Path | None, executable: str, architecture: str, kind: str
) -> Path:
    """Resolve an explicit firmware path or discover QEMU's bundled image."""
    if supplied is not None:
        return supplied.expanduser().resolve(strict=True)
    return discover_firmware(executable, architecture, kind)


def prepare_qemu_command(
    architecture: str,
    firmware_code: Path | None = None,
    firmware_vars: Path | None = None,
    *,
    skip_version_check: bool = False,
    build: bool = True,
    acceptance_probes: bool = False,
    graphical: bool = False,
    framebuffer: bool = False,
) -> list[str]:
    """Build an image, copy a disposable variable store, and return QEMU arguments."""
    executable_name = QEMU_EXECUTABLES[architecture]
    executable = shutil.which(executable_name)
    if executable is None:
        raise FileNotFoundError(f"QEMU executable not found on PATH: {executable_name}")

    if not skip_version_check:
        version = qemu_version(executable)
        expected_version = rf"\bversion {re.escape(EXPECTED_QEMU_VERSION)}\b"
        if re.search(expected_version, version) is None:
            raise RuntimeError(
                f"expected QEMU {EXPECTED_QEMU_VERSION}, got: {version} "
                "(use --skip-version-check deliberately)"
            )

    firmware = resolve_firmware(firmware_code, executable, architecture, "code")
    vars_source = resolve_firmware(firmware_vars, executable, architecture, "vars")
    if build:
        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build.py"),
                "--architecture",
                architecture,
                *(("--acceptance-probes",) if acceptance_probes else ()),
            ],
            cwd=REPO_ROOT,
            check=True,
        )

    suffix = "-acceptance" if acceptance_probes else ""
    image = REPO_ROOT / "build" / f"kllm-{architecture}{suffix}.img"
    if not image.is_file():
        raise FileNotFoundError(f"boot image not found: {image}")
    variables = REPO_ROOT / "build" / f"qemu-vars-{architecture}.fd"
    shutil.copyfile(vars_source, variables)

    command = [
        executable,
        "-machine",
        "q35" if architecture == "x86_64" else "virt",
        "-monitor",
        "none",
        "-serial",
        "stdio",
    ]
    if not graphical:
        command.extend(("-display", "none"))
    if (graphical or framebuffer) and architecture == "aarch64":
        command.extend(("-device", "ramfb"))
    if architecture == "aarch64":
        command.extend(("-cpu", "cortex-a72"))
    command.extend(
        (
            "-m",
            "64M" if architecture == "x86_64" else "128M",
            "-drive",
            f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}",
            "-drive",
            f"if=pflash,format=raw,unit=1,file={variables}",
            "-drive",
            f"if=virtio,format=raw,file={image}",
            "-no-reboot",
        )
    )
    return command

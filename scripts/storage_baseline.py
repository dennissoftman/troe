"""Capture and validate ADR 0035's application-visible storage measurements."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from platform_profile import (
    REPO_ROOT,
    PlatformProfile,
    resolve_platform,
    shared_test_image_path,
)
from qemu_profile import cloud_bundle_path, qemu_version, resolve_runner

PROBE_PACKAGES = REPO_ROOT / "build" / "storage-baseline-packages"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "adr-0035"
CONTRACT = {
    "version": 1,
    "chunk_bytes": 4096,
    "warmup": 64,
    "samples": 256,
    "payload": "5a-with-u64le-chunk-index",
    "timer": "architecture-counter",
    "sync": "per-chunk",
}
ROWS = {
    (volume, phase) for volume in ("ext4", "fat32") for phase in ("read", "write_sync")
}


def build_probe(*, skip_build: bool) -> None:
    """Build the standalone acceptance package for both bare-metal targets."""
    if not skip_build:
        subprocess.run(
            (
                "cargo",
                "kex",
                "build",
                REPO_ROOT / "tests" / "storage-baseline",
                "--target",
                "all",
                "--output",
                PROBE_PACKAGES,
            ),
            cwd=REPO_ROOT,
            check=True,
        )
    for architecture in ("x86_64", "aarch64"):
        if not (PROBE_PACKAGES / architecture / "storage-baseline.kex").is_file():
            raise FileNotFoundError(
                "build the storage baseline package before --skip-build"
            )


def install_probe(profile: PlatformProfile) -> None:
    """Place the probe on the disposable FAT32 partition, outside the rootfs."""
    subprocess.run(
        (
            "mcopy",
            "-i",
            f"{shared_test_image_path(profile)}@@1048576",
            PROBE_PACKAGES / profile.architecture / "storage-baseline.kex",
            "::/storage-baseline.kex",
        ),
        cwd=REPO_ROOT,
        check=True,
    )


def cloud_system_copy_path(platform_id: str) -> Path:
    """Return the disposable system disk shared by sequential baseline boots."""
    resolve_platform(platform_id)
    return REPO_ROOT / "build" / f"baseline-system-{platform_id}.raw"


def isolate_cloud_system_disk(
    platform_id: str, environment: str, command: list[str]
) -> list[str]:
    """Keep a verified cloud bundle pristine across mutating baseline scenarios."""
    if resolve_runner(platform_id, environment).disk_layout != "cloud-bundle-v1":
        return command
    source = (
        cloud_bundle_path(
            resolve_platform(platform_id), environment, acceptance_probes=True
        )
        / "system.raw"
    )
    destination = cloud_system_copy_path(platform_id)
    source_field = f"file={source}"
    if sum(argument.split(",").count(source_field) for argument in command) != 1:
        raise ValueError("baseline cloud system disk missing or duplicated")
    shutil.copyfile(source, destination)
    return [
        ",".join(
            f"file={destination}" if field == source_field else field
            for field in argument.split(",")
        )
        for argument in command
    ]


def digest(path: Path) -> str:
    """Hash the exact bytes without retaining entire disk images in memory."""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def command_output(*command: str) -> str:
    """Read a required provenance identifier; missing tools fail capture."""
    return subprocess.run(
        command, cwd=REPO_ROOT, check=True, text=True, capture_output=True
    ).stdout.strip()


def provenance(
    platform_id: str,
    environment: str,
    command: list[str],
    *,
    probe_name: str = "storage-baseline",
    extra_sources: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Record the actual runner, firmware, disks, probe and source before boot."""
    inputs = {}
    for index, argument in enumerate(command):
        if index and command[index - 1] in ("-bios", "-kernel"):
            inputs[f"argument-{index}"] = digest(Path(argument))
        for field in argument.split(","):
            if field.startswith("file="):
                path = Path(field.removeprefix("file="))
                inputs[f"argument-{index}"] = digest(path)
    sources = (
        "kernel/src/service/clock.rs",
        "sdk/rust/troe-kex/src/lib.rs",
        "sdk/rust/troe-kex/Cargo.toml",
        "tests/storage-baseline/src/main.rs",
        "tests/storage-baseline/Cargo.toml",
        "tests/storage-baseline/Cargo.lock",
        "tests/storage-baseline/completion.cmpl",
        "scripts/build.py",
        "scripts/storage_baseline.py",
        "scripts/test-qemu.py",
        "scripts/qemu_profile.py",
        "scripts/platform_profile.py",
        "rust-toolchain.toml",
    )
    profile = resolve_platform(platform_id)
    return {
        "platform": platform_id,
        "environment": environment,
        "qemu": qemu_version(command[0]),
        "rust": command_output("rustc", "--version", "--verbose"),
        "host": platform.platform(),
        "base_commit": command_output("git", "rev-parse", "HEAD"),
        "command": [argument.replace(str(REPO_ROOT), "$REPO") for argument in command],
        "input_sha256": inputs,
        "source_sha256": {
            name: digest(REPO_ROOT / name) for name in (*sources, *extra_sources)
        },
        "probe_sha256": digest(
            REPO_ROOT
            / "build"
            / f"{probe_name}-packages"
            / profile.architecture
            / f"{probe_name}.kex"
        ),
    }


def fields(line: str) -> dict[str, str]:
    """Decode an exact key/value record, rejecting duplicate or empty fields."""
    result = {}
    for field in line.split()[1:]:
        key, separator, value = field.partition("=")
        if not separator or not key or not value or key in result:
            raise ValueError(f"malformed storage record: {line!r}")
        result[key] = value
    return result


def summarize(ticks: list[int], frequency: int) -> dict[str, Any]:
    """Derive nearest-rank p95 and aggregate throughput from exact raw samples."""
    if type(frequency) is not int or not 0 < frequency < 1 << 64:
        raise ValueError("invalid storage counter frequency")
    if len(ticks) != CONTRACT["samples"] or any(
        type(value) is not int or not 0 < value < 1 << 64 for value in ticks
    ):
        raise ValueError("storage measurements require 256 positive integer samples")
    ordered = sorted(ticks)
    total = sum(ticks)
    return {
        "frequency_hz": frequency,
        "ticks": ticks,
        "total_ticks": total,
        "p50_ticks": ordered[127],
        "p95_ticks": ordered[math.ceil(0.95 * len(ticks)) - 1],
        "min_ticks": ordered[0],
        "max_ticks": ordered[-1],
        "bytes_per_second": len(ticks) * CONTRACT["chunk_bytes"] * frequency / total,
    }


def make_document(output: str, origin: dict[str, Any]) -> dict[str, Any]:
    """Require one complete matrix and derive its statistics on the host."""
    lines = output.splitlines()
    headers = [line for line in lines if line.startswith("STORAGE-BASELINE ")]
    if len(headers) != 1 or fields(headers[0]) != {
        key: str(value) for key, value in CONTRACT.items()
    }:
        raise ValueError("missing or changed storage measurement contract")
    if lines.count("END storage-baseline") != 1:
        raise ValueError("storage measurement did not finish exactly once")
    rows = {}
    for line in lines:
        if not line.startswith("STORAGE "):
            continue
        if (
            not lines.index(headers[0])
            < lines.index(line)
            < lines.index("END storage-baseline")
        ):
            raise ValueError("storage record outside completed measurement")
        row = fields(line)
        if set(row) != {"volume", "phase", "frequency_hz", "ticks"}:
            raise ValueError("unexpected storage measurement fields")
        key = (row["volume"], row["phase"])
        if key not in ROWS or "/".join(key) in rows:
            raise ValueError("unexpected or duplicate storage measurement row")
        rows["/".join(key)] = summarize(
            [int(value) for value in row["ticks"].split(",")], int(row["frequency_hz"])
        )
    if set(rows) != {"/".join(key) for key in ROWS}:
        raise ValueError("incomplete storage measurement matrix")
    if len({row["frequency_hz"] for row in rows.values()}) != 1:
        raise ValueError("storage counter frequency changed")
    return {"adr": 35, "contract": CONTRACT, "provenance": origin, "storage": rows}


def validate_document(document: dict[str, Any], platform_id: str) -> None:
    """Reject corrupt fixtures instead of treating their values as thresholds."""
    try:
        if (
            set(document) != {"adr", "contract", "provenance", "storage"}
            or document["adr"] != 35
            or document["contract"] != CONTRACT
        ):
            raise ValueError("storage fixture contract changed")
        origin = document["provenance"]
        if origin["platform"] != platform_id or origin["environment"] != "qemu":
            raise ValueError("storage fixture platform/environment mismatch")
        for key in ("qemu", "rust", "host", "base_commit", "command"):
            if not origin[key]:
                raise ValueError("storage fixture has incomplete provenance")
        hashes = [origin["probe_sha256"]]
        for key in ("source_sha256", "input_sha256"):
            if not origin[key]:
                raise ValueError("storage fixture has no source/image hashes")
            hashes.extend(origin[key].values())
        if any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
            for value in hashes
        ):
            raise ValueError("storage fixture has invalid hashes")
        rows = document["storage"]
        if set(rows) != {"/".join(key) for key in ROWS}:
            raise ValueError("storage fixture matrix changed")
        if len({row["frequency_hz"] for row in rows.values()}) != 1:
            raise ValueError("storage fixture counter frequency changed")
        for row in rows.values():
            if row != summarize(row["ticks"], row["frequency_hz"]):
                raise ValueError("storage fixture statistics disagree with samples")
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed storage fixture") from error


def settle(document: dict[str, Any], record_directory: Path | None) -> None:
    """Validate frozen evidence; write fresh observations separately from it."""
    platform_id = document["provenance"]["platform"]
    validate_document(document, platform_id)
    filename = f"storage-{platform_id}.json"
    encoded = json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if record_directory is not None:
        record_directory.mkdir(parents=True, exist_ok=True)
        with (record_directory / filename).open("x", encoding="utf-8") as destination:
            destination.write(encoded)
        print(f"storage baseline recorded -> {record_directory / filename}")
        return
    fixture = FIXTURES / filename
    validate_document(json.loads(fixture.read_text("utf-8")), platform_id)
    observed = REPO_ROOT / "build" / "storage-baseline-results"
    observed.mkdir(parents=True, exist_ok=True)
    (observed / filename).write_text(encoded, "utf-8")

#!/usr/bin/env python3
"""Create the deterministic minimal SCFG v1 QEMU activation fixture."""

from __future__ import annotations

import argparse
import struct
import sys
import tomllib
import zlib
from pathlib import Path

HEADER_BYTES = 144
RECORD_BYTES = 64
POLICY_PATH = (
    Path(__file__).resolve().parents[1] / "config/system/resources/memory.toml"
)
MAX_MAPPINGS = 1_048_576
MAX_PROCESS_METADATA = 64 * 1024 * 1024
MAX_GLOBAL_METADATA = 256 * 1024 * 1024
MAX_OPERATION_QUANTUM = 1_048_576


def _u64(value: object, name: str, *, maximum: int = (1 << 64) - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= maximum
    ):
        raise ValueError(f"invalid memory policy {name}")
    return value


def _optional_limit(table: object, name: str) -> int | None:
    if not isinstance(table, dict) or set(table) not in (
        {"limited"},
        {"limited", "maximum"},
    ):
        raise ValueError(f"invalid memory policy {name}")
    limited = table.get("limited")
    if not isinstance(limited, bool):
        raise ValueError(f"invalid memory policy {name}.limited")
    maximum = table.get("maximum")
    if not limited:
        if maximum is not None:
            raise ValueError(f"unlimited memory policy {name} has maximum")
        return None
    return _u64(maximum, f"{name}.maximum")


def read_memory_policy(path: Path = POLICY_PATH) -> tuple[int, ...]:
    """Read the repository's closed typed memory policy."""
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot read memory policy: {error}") from error
    if set(value) != {"schema", "system", "process", "kernel"} or value["schema"] != 1:
        raise ValueError("invalid memory policy schema")
    system = value["system"]
    process = value["process"]
    kernel = value["kernel"]
    if (
        not isinstance(system, dict)
        or set(system) != {"minimum_free_pages", "application_commit"}
        or not isinstance(process, dict)
        or set(process) != {"default"}
        or not isinstance(process["default"], dict)
        or set(process["default"])
        != {"committed_pages", "reserved_pages", "mappings", "metadata_bytes"}
        or not isinstance(kernel, dict)
        or set(kernel) != {"global_metadata_bytes", "operation_quantum_pages"}
    ):
        raise ValueError("unknown or missing memory policy field")
    defaults = process["default"]
    system_limit = _optional_limit(
        system["application_commit"], "system.application_commit"
    )
    committed_limit = _optional_limit(
        defaults["committed_pages"], "process.default.committed_pages"
    )
    reserved_limit = _optional_limit(
        defaults["reserved_pages"], "process.default.reserved_pages"
    )
    mappings = defaults["mappings"]
    metadata = defaults["metadata_bytes"]
    if not isinstance(mappings, dict) or set(mappings) != {"maximum"}:
        raise ValueError("invalid process mapping policy")
    if not isinstance(metadata, dict) or set(metadata) != {"maximum"}:
        raise ValueError("invalid process metadata policy")
    minimum_free = _u64(system["minimum_free_pages"], "system.minimum_free_pages")
    maximum_mappings = _u64(
        mappings["maximum"], "process.default.mappings.maximum", maximum=MAX_MAPPINGS
    )
    maximum_metadata = _u64(
        metadata["maximum"],
        "process.default.metadata_bytes.maximum",
        maximum=MAX_PROCESS_METADATA,
    )
    global_metadata = _u64(
        kernel["global_metadata_bytes"],
        "kernel.global_metadata_bytes",
        maximum=MAX_GLOBAL_METADATA,
    )
    quantum = _u64(
        kernel["operation_quantum_pages"],
        "kernel.operation_quantum_pages",
        maximum=MAX_OPERATION_QUANTUM,
    )
    if global_metadata < maximum_metadata or (
        system_limit is not None
        and committed_limit is not None
        and committed_limit > system_limit
    ):
        raise ValueError("inconsistent memory policy")
    flags = (
        int(system_limit is not None)
        | int(committed_limit is not None) << 1
        | int(reserved_limit is not None) << 2
    )
    return (
        flags,
        minimum_free,
        system_limit or 0,
        committed_limit or 0,
        reserved_limit or 0,
        maximum_mappings,
        maximum_metadata,
        global_metadata,
        quantum,
    )


def build_config(
    generation: int, previous: int, memory_policy: Path = POLICY_PATH
) -> bytes:
    """Encode one generation with one boot-resident SNTP service."""
    if generation <= 0 or previous < 0 or previous >= generation:
        raise ValueError("invalid generation relationship")
    strings = b"timesync/bin/timesync.kex"
    image = bytearray(HEADER_BYTES + RECORD_BYTES + len(strings))
    image[:8] = b"SCFGv1\0\0"
    struct.pack_into("<HHHHI", image, 8, 1, 1, HEADER_BYTES, RECORD_BYTES, len(image))
    flags = 2 | (1 if previous else 0)
    struct.pack_into(
        "<QQHBBII", image, 24, generation, previous, 1, 3, flags, 30_000, len(strings)
    )
    struct.pack_into("<9Q", image, 64, *read_memory_policy(memory_policy))

    record = memoryview(image)[HEADER_BYTES : HEADER_BYTES + RECORD_BYTES]
    struct.pack_into("<I", record, 0, 1)
    record[4] = 1  # boot required
    record[5] = 3 if previous else 4  # predecessor, else static recovery shell
    record[7] = 7  # command streams plus datagram, timer, and clock control
    struct.pack_into("<H", record, 8, 50)
    struct.pack_into("<II", record, 12, 5_000, 0)
    struct.pack_into("<I", record, 20, 0b111)
    struct.pack_into("<IH", record, 40, 0, 8)
    struct.pack_into("<IH", record, 48, 8, 17)
    image[HEADER_BYTES + RECORD_BYTES :] = strings

    checked = bytearray(image)
    checked[20:24] = b"\0" * 4
    struct.pack_into("<I", image, 20, zlib.crc32(checked))
    return bytes(image)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous-output", type=Path)
    parser.add_argument("--memory-policy", type=Path, default=POLICY_PATH)
    args = parser.parse_args()
    try:
        image = build_config(2, 1, args.memory_policy)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(image)
        print(f"SCFG v1: {len(image)} bytes -> {args.output}")
        if args.previous_output is not None:
            previous = build_config(1, 0, args.memory_policy)
            args.previous_output.parent.mkdir(parents=True, exist_ok=True)
            args.previous_output.write_bytes(previous)
            print(
                f"SCFG v1 predecessor: {len(previous)} bytes -> {args.previous_output}"
            )
        return 0
    except (OSError, ValueError) as error:
        print(f"mkconfig: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

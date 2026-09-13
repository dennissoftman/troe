"""Validate ABI 1.3 native IPC against compatibility samples from the same boot."""

from __future__ import annotations

import math
from typing import Any

PAYLOADS = (0, 64, 256, 4096)
PATHS = ("persistent-direct", "persistent-queued")
SAMPLES = 256


def fields(line: str) -> dict[str, str]:
    """Parse one exact diagnostic record without accepting duplicate fields."""
    result = {}
    for field in line.split()[1:]:
        key, separator, value = field.partition("=")
        if not separator or not key or not value or key in result:
            raise ValueError("malformed or duplicate IPC field")
        result[key] = value
    return result


def p95(ticks: list[int]) -> int:
    """Use the frozen baseline's nearest-rank percentile convention."""
    if len(ticks) != SAMPLES or any(not 0 <= tick < 1 << 64 for tick in ticks):
        raise ValueError("invalid IPC sample array")
    value = sorted(ticks)[math.ceil(SAMPLES * 0.95) - 1]
    if value == 0:
        raise ValueError("IPC p95 cannot be zero")
    return value


def validate(
    output: str,
    *,
    require_tagged: bool,
    paths: tuple[str, ...] = PATHS,
    record_prefix: str = "ipc-phase-b",
    sample_prefix: str = "ipc-phase-b-samples",
    small_limit: int = 70,
    large_limit: int = 70,
    ratio_scale: int = 100,
) -> dict[str, Any]:
    """Recompute every ratio and require actual direct/queued structural counts."""
    checks = [
        fields(line)
        for line in output.splitlines()
        if line.startswith("ipc-phase-b-checks ")
    ]
    if checks != [
        {
            "pool": "20",
            "fates": "12",
            "terminal_zeroization": "1",
            "stale_tags": "1",
            "lease_millis": "50",
        }
    ]:
        raise ValueError("incomplete native IPC safety checks")
    raw = {}
    rows = {}
    compatibility = {}
    for line in output.splitlines():
        if not line.startswith(
            (f"{record_prefix} ", f"{sample_prefix} ", "ipc-samples ")
        ):
            continue
        row = fields(line)
        key = (row.pop("path"), int(row.pop("payload")))
        if line.startswith(f"{record_prefix} "):
            destination = rows
        elif line.startswith(f"{sample_prefix} "):
            destination = raw
        elif key[0] == "isolated-diagnostics":
            destination = compatibility
        else:
            continue
        if key in destination:
            raise ValueError("duplicate IPC row")
        destination[key] = row
    expected = {(path, size) for path in paths for size in PAYLOADS}
    if (
        set(rows) != expected
        or set(raw) != expected
        or set(compatibility) != {("isolated-diagnostics", size) for size in PAYLOADS}
    ):
        raise ValueError("incomplete same-boot IPC matrix")
    result = {}
    frequencies = set()
    modes = set()
    for (path, size), row in rows.items():
        counts = {name: int(value) for name, value in row.items()}
        queued = path == "persistent-queued"
        tagged = counts["tagged"]
        if tagged not in (0, 1) or (require_tagged and tagged != 1):
            raise ValueError("required PCID/ASID fast profile unavailable")
        modes.add(tagged)
        ticks_row = raw[(path, size)]
        old_row = compatibility[("isolated-diagnostics", size)]
        if set(ticks_row) != {"counter_hz", "ticks"} or set(old_row) != {
            "counter_hz",
            "ticks",
        }:
            raise ValueError("invalid IPC sample fields")
        frequency = int(ticks_row["counter_hz"])
        if frequency <= 0 or frequency != int(old_row["counter_hz"]):
            raise ValueError("IPC counters came from different clocks")
        frequencies.add(frequency)
        ticks = [int(value) for value in ticks_row["ticks"].split(",")]
        old_ticks = [int(value) for value in old_row["ticks"].split(",")]
        measured = p95(ticks)
        old_p95 = p95(old_ticks)
        limit = large_limit if size == 4096 else small_limit
        passed = measured * ratio_scale <= old_p95 * limit
        expected_counts = {
            "warmup": 64,
            "samples": SAMPLES,
            "p95_ticks": measured,
            "compatibility_p95": old_p95,
            "ratio_limit": limit,
            "ratio_pass": int(passed),
            "tagged": tagged,
            "calls": SAMPLES,
            "request_copies": (2 if queued else 1) * SAMPLES if size else 0,
            "reply_copies": SAMPLES if size else 0,
            "root_writes": 2 * SAMPLES,
            "targeted_invalidations": 0,
            "full_invalidations": 0 if tagged else 2 * SAMPLES,
            "queue_slots": SAMPLES if queued else 0,
            "traps": (3 if queued else 2) * SAMPLES + 1,
            "tag_hits": 2 * SAMPLES if tagged else 0,
            "steady_allocations": 0,
            "scheduler_scans": 0,
            "additional_lease_programs": 0,
        }
        if ratio_scale != 100:
            expected_counts["ratio_scale"] = ratio_scale
        if counts != expected_counts:
            raise ValueError(f"invalid IPC structural or latency record: {path}/{size}")
        if tagged and not queued and not passed:
            raise ValueError(f"direct IPC p95 ratio failed for {size} bytes")
        result[f"{path}/{size}"] = {
            "ticks": ticks,
            "compatibility_ticks": old_ticks,
            "counter_hz": frequency,
            "counters": counts,
            "p95_ratio": measured / old_p95,
        }
    if len(frequencies) != 1 or len(modes) != 1:
        raise ValueError("IPC matrix mixes machines or feature modes")
    return {
        "schema_version": 1,
        "tagged": bool(modes.pop()),
        "checks": checks[0],
        "rows": result,
    }

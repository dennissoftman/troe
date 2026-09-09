"""Require exact native fault cleanup and the general runtime's same-boot ratios."""

from typing import Any

if __package__:
    from . import ipc_phase_b
else:
    import ipc_phase_b

FAULTS = (
    "before-receive",
    "after-receive",
    "nested-call",
    "before-reply",
    "after-reply-validation",
    "queued",
    "blocked",
)


def validate(output: str, *, require_tagged: bool) -> dict[str, Any]:
    """Validate native terminal fates, zero live ownership and bounded replacement."""
    faults = {}
    for line in output.splitlines():
        if not line.startswith("ipc-phase-c fault="):
            continue
        row = ipc_phase_b.fields(line)
        name = row.pop("fault")
        if name not in FAULTS or name in faults:
            raise ValueError("unknown or duplicate Phase C fault")
        clients = 2 if name in ("queued", "blocked") else 1
        expected = {
            "clients": clients,
            "fates": clients,
            "endpoints": 0,
            "handles": 0,
            "waits": 0,
            "calls": 0,
            "frames": 0,
            "restart": 1,
            "normal": 1,
            "rx_unchanged": 1,
        }
        counts = {key: int(value) for key, value in row.items()}
        if counts != expected:
            raise ValueError(f"Phase C ownership or restart mismatch: {name}: {counts}")
        faults[name] = counts
    if set(faults) != set(FAULTS):
        raise ValueError("incomplete native Phase C fault matrix")
    result = ipc_phase_b.validate(
        output,
        require_tagged=require_tagged,
        paths=("general-direct",),
        record_prefix="ipc-phase-c-latency",
        sample_prefix="ipc-phase-c-samples",
        small_limit=675,
        large_limit=700,
        ratio_scale=1000,
    )
    result["faults"] = faults
    return result

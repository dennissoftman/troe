"""The fast-profile gate must reject missing evidence and fabricated counters."""

from __future__ import annotations

import unittest

from scripts import ipc_phase_b


def transcript(
    *, tagged: bool = True, direct_ticks: int = 50, compatibility_ticks: int = 100
) -> str:
    lines = [
        "ipc-phase-b-checks pool=20 fates=12 terminal_zeroization=1 stale_tags=1 "
        "lease_millis=50"
    ]
    for size in ipc_phase_b.PAYLOADS:
        old = ",".join([str(compatibility_ticks)] * 256)
        lines.append(
            f"ipc-samples path=isolated-diagnostics payload={size} "
            f"counter_hz=1000000 ticks={old}"
        )
        for path in ipc_phase_b.PATHS:
            queued = path == "persistent-queued"
            ticks = 90 if queued else direct_ticks
            raw = ",".join([str(ticks)] * 256)
            lines.append(
                f"ipc-phase-b-samples path={path} payload={size} counter_hz=1000000 "
                f"ticks={raw}"
            )
            limit = 70 if size == 4096 else 60
            copies = (512 if queued else 256) if size else 0
            reply = 256 if size else 0
            full = 0 if tagged else 512
            hits = 512 if tagged else 0
            lines.append(
                f"ipc-phase-b path={path} payload={size} warmup=64 samples=256 "
                f"p95_ticks={ticks} "
                f"compatibility_p95={compatibility_ticks} ratio_limit={limit} "
                f"ratio_pass={int(ticks * 100 <= compatibility_ticks * limit)} "
                f"tagged={int(tagged)} "
                f"calls=256 request_copies={copies} reply_copies={reply} "
                f"root_writes=512 "
                f"targeted_invalidations=0 full_invalidations={full} "
                f"queue_slots={256 if queued else 0} "
                f"traps={769 if queued else 513} tag_hits={hits} "
                f"steady_allocations=0 scheduler_scans=0 additional_lease_programs=0"
            )
    return "\n".join(lines)


class IpcPhaseBTests(unittest.TestCase):
    def test_ratios_are_recomputed_and_bounds_are_inclusive(self) -> None:
        result = ipc_phase_b.validate(transcript(direct_ticks=60), require_tagged=True)
        self.assertTrue(result["tagged"])
        self.assertEqual(len(result["rows"]), 8)
        with self.assertRaisesRegex(ValueError, "ratio failed"):
            ipc_phase_b.validate(transcript(direct_ticks=61), require_tagged=True)

    def test_fallback_cannot_satisfy_the_tagged_gate(self) -> None:
        output = transcript(tagged=False, direct_ticks=90)
        self.assertFalse(ipc_phase_b.validate(output, require_tagged=False)["tagged"])
        with self.assertRaisesRegex(ValueError, "unavailable"):
            ipc_phase_b.validate(output, require_tagged=True)

    def test_tampered_or_missing_evidence_fails(self) -> None:
        output = transcript()
        for damaged in (
            output.replace(
                "additional_lease_programs=0", "additional_lease_programs=1", 1
            ),
            output.replace("targeted_invalidations=0", "targeted_invalidations=1", 1),
            output.replace("steady_allocations=0", "steady_allocations=1", 1),
            output.replace("compatibility_p95=100", "compatibility_p95=200", 1),
            output.replace("counter_hz=1000000", "counter_hz=2000000", 1),
            output.replace("root_writes=512", "root_writes=512 root_writes=0", 1),
            output + "\n" + output.splitlines()[1],
            "\n".join(output.splitlines()[1:]),
            "\n".join(output.splitlines()[:-1]),
        ):
            with self.subTest(damaged=damaged[-80:]), self.assertRaises(ValueError):
                ipc_phase_b.validate(damaged, require_tagged=True)

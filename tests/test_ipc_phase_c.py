"""Phase C preserves exact fault fates, hardware counts, and its approved budget."""

import unittest

from scripts import ipc_phase_b, ipc_phase_c
from tests.test_ipc_phase_b import transcript as phase_b


def transcript(
    *, ticks: int = 500, large_ticks: int | None = None, tagged: bool = True
) -> str:
    old = phase_b(tagged=tagged, direct_ticks=500, compatibility_ticks=1000)
    lines = [old]
    for line in old.splitlines():
        if "path=persistent-direct" not in line:
            continue
        row = ipc_phase_b.fields(line)
        row["path"] = "general-direct"
        size = int(row["payload"])
        measured = large_ticks if size == 4096 and large_ticks is not None else ticks
        if line.startswith("ipc-phase-b-samples "):
            prefix = "ipc-phase-c-samples"
            row["ticks"] = ",".join([str(measured)] * 256)
        else:
            prefix = "ipc-phase-c-latency"
            limit = 700
            row.update(
                p95_ticks=str(measured),
                ratio_limit=str(limit),
                ratio_scale="1000",
                ratio_pass=str(int(measured <= limit)),
            )
        lines.append(
            prefix + " " + " ".join(f"{key}={value}" for key, value in row.items())
        )
    for name in ipc_phase_c.FAULTS:
        clients = 2 if name in ("queued", "blocked") else 1
        lines.append(
            f"ipc-phase-c fault={name} clients={clients} fates={clients} "
            "endpoints=0 handles=0 waits=0 calls=0 frames=0 "
            "restart=1 normal=1 rx_unchanged=1"
        )
    return "\n".join(lines)


class PhaseCTests(unittest.TestCase):
    def test_complete_matrix_and_real_tagging(self) -> None:
        result = ipc_phase_c.validate(transcript(ticks=700), require_tagged=True)
        self.assertEqual(len(result["faults"]), 7)
        self.assertEqual(len(result["rows"]), 4)
        self.assertEqual(result["rows"]["general-direct/64"]["p95_ratio"], 0.70)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            ipc_phase_c.validate(transcript(tagged=False), require_tagged=True)

    def test_budget_is_exact_at_every_payload_and_phase_b_is_unchanged(self) -> None:
        ipc_phase_c.validate(
            transcript(ticks=653, large_ticks=700), require_tagged=True
        )
        for output in (transcript(ticks=701), transcript(large_ticks=701)):
            with self.assertRaisesRegex(ValueError, "ratio failed"):
                ipc_phase_c.validate(output, require_tagged=True)
        with self.assertRaisesRegex(ValueError, "ratio failed"):
            ipc_phase_b.validate(phase_b(direct_ticks=61), require_tagged=True)

    def test_limits_cannot_be_relaxed_or_fates_duplicated(self) -> None:
        output = transcript()
        for bad in (
            output.replace("ratio_limit=700", "ratio_limit=701", 1),
            output.replace("ratio_scale=1000", "ratio_scale=100", 1),
            output.replace("fates=1", "fates=2", 1),
            output.replace("frames=0", "frames=1", 1),
            output.replace("restart=1", "restart=0", 1),
            output.replace("normal=1", "normal=0", 1),
            "\n".join(output.splitlines()[:-1]),
            output + "\n" + output.splitlines()[-1],
            output.replace("ipc-phase-c-samples", "absent-samples", 1),
        ):
            with self.subTest(bad=bad[-100:]), self.assertRaises(ValueError):
                ipc_phase_c.validate(bad, require_tagged=True)

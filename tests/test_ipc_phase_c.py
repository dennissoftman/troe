"""Phase C must preserve every fault fate, hardware count, and ratio limit."""

import unittest

from scripts import ipc_phase_c
from tests.test_ipc_phase_b import transcript as phase_b


def transcript(*, ticks: int = 50, tagged: bool = True) -> str:
    old = phase_b(tagged=tagged, direct_ticks=ticks)
    lines = [old]
    lines.extend(
        line.replace("ipc-phase-b-samples", "ipc-phase-c-samples")
        .replace("ipc-phase-b ", "ipc-phase-c-latency ")
        .replace("path=persistent-direct", "path=general-direct")
        for line in old.splitlines()
        if "path=persistent-direct" in line
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
        result = ipc_phase_c.validate(transcript(ticks=60), require_tagged=True)
        self.assertEqual(len(result["faults"]), 7)
        self.assertEqual(len(result["rows"]), 4)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            ipc_phase_c.validate(transcript(tagged=False), require_tagged=True)

    def test_limits_cannot_be_relaxed_or_fates_duplicated(self) -> None:
        with self.assertRaisesRegex(ValueError, "ratio failed"):
            ipc_phase_c.validate(transcript(ticks=61), require_tagged=True)
        output = transcript()
        for bad in (
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

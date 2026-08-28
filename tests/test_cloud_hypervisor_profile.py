"""Exact Cloud Hypervisor production profile and launcher tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from cloud_hypervisor_profile import (  # noqa: E402
    PROFILE_PATH,
    PinnedArtifact,
    cloud_hypervisor_command,
    load_profile,
    stage_runtime_bundle,
    validate_profile,
    validate_tap_name,
    verify_artifact,
)


def load_acceptance_module():
    """Load the hyphenated live runner without executing its CLI."""
    path = SCRIPTS / "test-cloud-hypervisor.py"
    spec = importlib.util.spec_from_file_location("test_cloud_hypervisor_live", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


LIVE = load_acceptance_module()


class CloudHypervisorProfileTests(unittest.TestCase):
    """Keep the first non-QEMU target exact and fail closed."""

    def test_profile_pins_exact_v53_artifacts_and_resource_floor(self) -> None:
        profile = load_profile()
        self.assertEqual(profile.platform, "x86_64-uefi-virtio-pci")
        self.assertEqual(profile.environment, "cloud-hypervisor-kvm-v53")
        self.assertEqual(profile.vmm.release, "v53.0")
        self.assertEqual(profile.vmm.size, 7_062_256)
        self.assertEqual(
            profile.vmm.sha256,
            "448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc",
        )
        self.assertEqual(profile.control.size, 1_798_776)
        self.assertEqual(profile.firmware.release, "ch-f308d878a6")
        self.assertEqual(profile.firmware.size, 4_194_304)
        self.assertEqual(profile.guest_memory_bytes, 128 * 1024 * 1024)
        self.assertEqual(profile.cpus.max_phys_bits, 46)
        self.assertEqual(profile.disks, ("system", "activation", "state"))

    def test_profile_is_canonical_and_rejects_extensions_or_widening(self) -> None:
        raw = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            PROFILE_PATH.read_text(encoding="utf-8"),
            json.dumps(raw, indent=2, sort_keys=True) + "\n",
        )

        extended = dict(raw)
        extended["fallback_environment"] = "qemu"
        with self.assertRaisesRegex(ValueError, "schema 1"):
            validate_profile(extended)

        widened = json.loads(json.dumps(raw))
        widened["cpus"]["max"] = 2
        with self.assertRaisesRegex(ValueError, "CPU profile"):
            validate_profile(widened)

    def test_pinned_artifact_verifier_checks_size_digest_mode_and_symlinks(
        self,
    ) -> None:
        payload = b"pinned-cloud-hypervisor-test"
        artifact = PinnedArtifact(
            name="fixture",
            release="v1",
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
            url="https://github.com/example/releases/download/v1/fixture",
        )
        with tempfile.TemporaryDirectory(prefix="troe-ch-artifact-") as directory:
            path = Path(directory) / "fixture"
            path.write_bytes(payload)
            path.chmod(0o755)
            self.assertEqual(
                verify_artifact(path, artifact, executable=True), path.resolve()
            )

            wrong_size = PinnedArtifact(
                artifact.name,
                artifact.release,
                artifact.sha256,
                artifact.size + 1,
                artifact.url,
            )
            with self.assertRaisesRegex(ValueError, "size mismatch"):
                verify_artifact(path, wrong_size, executable=False)

            wrong_digest = PinnedArtifact(
                artifact.name,
                artifact.release,
                "0" * 64,
                artifact.size,
                artifact.url,
            )
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_artifact(path, wrong_digest, executable=False)

            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                verify_artifact(link, artifact, executable=False)

    def test_command_is_exact_hardened_and_has_no_qemu_or_probe_fallback(self) -> None:
        profile = load_profile()
        disks = {role: Path(f"/runtime/{role}.raw") for role in profile.disks}
        command = cloud_hypervisor_command(
            profile,
            vmm=Path("/opt/cloud-hypervisor-static"),
            firmware=Path("/opt/CLOUDHV.fd"),
            disks=disks,
            tap="troe0",
            api_socket=Path("/runtime/control.sock"),
            log_file=Path("/runtime/vmm.log"),
            event_file=Path("/runtime/events.json"),
        )
        joined = " ".join(command)
        self.assertEqual(command[0], "/opt/cloud-hypervisor-static")
        self.assertEqual(command.count("--disk"), 3)
        self.assertIn("boot=1,max=1,max_phys_bits=46", command)
        self.assertIn(
            "size=128M,mergeable=off,shared=off,hugepages=off,prefault=on", command
        )
        self.assertIn("num_queues=1,queue_size=128,sparse=off", joined)
        self.assertIn("offload_tso=off,offload_ufo=off,offload_csum=off", joined)
        self.assertIn("--seccomp", command)
        self.assertIn("--landlock", command)
        self.assertIn("--rng", command)
        self.assertEqual(command[command.index("--rng") + 1], "src=/dev/urandom")
        self.assertNotIn("qemu", joined)
        self.assertNotIn("acceptance-probe", joined)

    def test_runtime_staging_copies_only_exact_bundle_files_and_never_overwrites(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-ch-stage-") as directory:
            parent = Path(directory)
            bundle = parent / "bundle"
            bundle.mkdir()
            expected = {
                "system.raw": b"system",
                "activation.raw": b"activation",
                "state.raw": b"state",
                "bundle.json": b"{}\n",
            }
            for name, payload in expected.items():
                (bundle / name).write_bytes(payload)
            runtime = parent / "runtime"
            staged = stage_runtime_bundle(bundle, runtime)
            self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o700)
            self.assertEqual(set(staged), {"system", "activation", "state"})
            self.assertEqual(
                {path.name: path.read_bytes() for path in runtime.iterdir()}, expected
            )
            with self.assertRaisesRegex(ValueError, "already exists"):
                stage_runtime_bundle(bundle, runtime)

    def test_tap_names_are_bounded_and_linux_safe(self) -> None:
        self.assertEqual(validate_tap_name("troe-prod0"), "troe-prod0")
        for invalid in ("", "a" * 16, "../tap", "tap name"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "invalid TAP"):
                    validate_tap_name(invalid)

    def test_corruption_probe_invalidates_only_newest_state_slot(self) -> None:
        image = bytearray(4_096 * 512)
        for slot, generation in enumerate((4, 5)):
            base = LIVE.STATE_PARTITION_OFFSET + slot * LIVE.STATE_SLOT_BYTES
            image[base : base + 8] = b"TXDTv1\0\0"
            image[base + 8 : base + 16] = generation.to_bytes(8, "little")
            commit = base + LIVE.STATE_DATA_BYTES
            image[commit : commit + 8] = b"TXCMv1\0\0"
            image[commit + 8 : commit + 16] = generation.to_bytes(8, "little")
        with tempfile.TemporaryDirectory(prefix="troe-ch-state-") as directory:
            path = Path(directory) / "state.raw"
            path.write_bytes(image)
            self.assertEqual(LIVE.corrupt_latest_state_slot(path), 5)
            changed = path.read_bytes()
            first = LIVE.STATE_PARTITION_OFFSET + LIVE.STATE_PAYLOAD_OFFSET
            second = first + LIVE.STATE_SLOT_BYTES
            self.assertEqual(changed[first], image[first])
            self.assertEqual(changed[second], image[second] ^ 0x80)


if __name__ == "__main__":
    unittest.main()

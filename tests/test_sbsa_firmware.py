"""Host-only tests for the pinned SBSA reference firmware builder.

Building the firmware needs a network and about ten minutes, so these cover
the parts that decide whether such a build is trustworthy: the pinning, the
publishing and verification of what it produces, the host-tool requirements,
and the agreement between what the builder writes and what the QEMU runner
goes looking for.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_sbsa_firmware  # type: ignore[import-not-found]  # noqa: E402
import qemu_profile  # type: ignore[import-not-found]  # noqa: E402

AARCH64_SBSA_REF = "aarch64-sbsa-ref"


class SourceLockTests(unittest.TestCase):
    def test_every_source_is_pinned_to_a_complete_commit_identity(self) -> None:
        bank_bytes, repositories = build_sbsa_firmware.sources()
        self.assertEqual(bank_bytes, 256 * 1024 * 1024)
        self.assertEqual(
            sorted(item.name for item in repositories),
            ["edk2", "edk2-platforms", "trusted-firmware-a"],
        )
        for repository in repositories:
            self.assertRegex(repository.commit, r"\A[0-9a-f]{40}\Z")
            self.assertTrue(repository.url.startswith("https://"))
            self.assertTrue(repository.url.endswith(".git"))

    def test_only_edk2_carries_submodules_and_each_is_a_relative_path(self) -> None:
        _, repositories = build_sbsa_firmware.sources()
        by_name = {item.name: item for item in repositories}
        self.assertEqual(by_name["edk2-platforms"].submodules, ())
        self.assertEqual(by_name["trusted-firmware-a"].submodules, ())
        submodules = by_name["edk2"].submodules
        self.assertIn("CryptoPkg/Library/OpensslLib/openssl", submodules)
        for submodule in submodules:
            self.assertFalse(submodule.startswith("/"))
            self.assertNotIn("..", Path(submodule).parts)
        self.assertEqual(len(set(submodules)), len(submodules))

    def test_a_lock_of_another_schema_or_shape_is_refused(self) -> None:
        document = json.loads(
            build_sbsa_firmware.SOURCE_LOCK.read_text(encoding="utf-8")
        )
        for mutate in (
            lambda value: value.update({"schema": 2}),
            lambda value: value.update({"bank_bytes": 0}),
            lambda value: value["repositories"].pop(),
            lambda value: value["repositories"][0].update({"commit": "abc123"}),
        ):
            candidate = json.loads(json.dumps(document))
            mutate(candidate)
            with tempfile.TemporaryDirectory() as directory:
                lock = Path(directory) / "lock.json"
                lock.write_text(json.dumps(candidate), encoding="utf-8")
                original = build_sbsa_firmware.SOURCE_LOCK
                build_sbsa_firmware.SOURCE_LOCK = lock
                try:
                    with self.assertRaises(RuntimeError):
                        build_sbsa_firmware.sources()
                finally:
                    build_sbsa_firmware.SOURCE_LOCK = original


class PublishAndVerifyTests(unittest.TestCase):
    BANK_BYTES = 4096

    def _published(self, directory: Path) -> Path:
        built = directory / "built"
        built.mkdir()
        for index, name in enumerate(build_sbsa_firmware.FLASH_BANKS):
            (built / name).write_bytes(bytes([index + 1]) * 512)
        output = directory / "output"
        build_sbsa_firmware.publish(
            [built / name for name in build_sbsa_firmware.FLASH_BANKS],
            output,
            self.BANK_BYTES,
        )
        return output

    def test_publishing_pads_each_bank_and_records_what_it_wrote(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = self._published(Path(directory))
            for name in build_sbsa_firmware.FLASH_BANKS:
                bank = output / name
                self.assertEqual(bank.stat().st_size, self.BANK_BYTES)
                # Padding must extend the image, never replace it.
                self.assertEqual(
                    bank.read_bytes()[512:], b"\x00" * (self.BANK_BYTES - 512)
                )
            build_sbsa_firmware.verify(output, self.BANK_BYTES)

    def test_publishing_refuses_an_image_larger_than_one_bank(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            built = Path(directory) / "built"
            built.mkdir()
            oversized = built / build_sbsa_firmware.FLASH_BANKS[0]
            oversized.write_bytes(b"\xff" * (self.BANK_BYTES + 1))
            with self.assertRaises(RuntimeError):
                build_sbsa_firmware.publish(
                    [oversized], Path(directory) / "out", self.BANK_BYTES
                )

    def test_verification_rejects_every_way_a_bank_can_be_wrong(self) -> None:
        first, second = build_sbsa_firmware.FLASH_BANKS
        manifest_name = build_sbsa_firmware.MANIFEST_NAME
        for description, corrupt in (
            ("absent manifest", lambda out: (out / manifest_name).unlink()),
            (
                "malformed entry",
                lambda out: (out / manifest_name).write_text(
                    "nonsense\n", encoding="utf-8"
                ),
            ),
            (
                "unrecorded bank",
                lambda out: (out / manifest_name).write_text(
                    f"{'0' * 64}  {first}\n", encoding="utf-8"
                ),
            ),
            ("missing bank", lambda out: (out / second).unlink()),
            ("short bank", lambda out: _truncate(out / second, 512)),
            ("altered bank", lambda out: _overwrite_first_byte(out / second)),
        ):
            with self.subTest(description):
                with tempfile.TemporaryDirectory() as directory:
                    output = self._published(Path(directory))
                    corrupt(output)
                    with self.assertRaises(RuntimeError):
                        build_sbsa_firmware.verify(output, self.BANK_BYTES)


class HostToolTests(unittest.TestCase):
    def test_a_make_too_old_for_the_build_is_named_and_refused(self) -> None:
        original = build_sbsa_firmware.run
        for version, acceptable in (
            ("GNU Make 3.81", False),
            ("GNU Make 3.82", True),
            ("GNU Make 4.4.1", True),
            ("bmake 20240108", False),
        ):
            with self.subTest(version):
                build_sbsa_firmware.run = lambda *_args, reported=version, **_kwargs: (
                    reported
                )
                try:
                    if acceptable:
                        self.assertTrue(build_sbsa_firmware.gnu_make(sys.executable))
                    else:
                        with self.assertRaises(RuntimeError):
                            build_sbsa_firmware.gnu_make(sys.executable)
                finally:
                    build_sbsa_firmware.run = original

    def test_the_prefixed_toolchain_directory_must_hold_every_prefixed_tool(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            for tool in build_sbsa_firmware.PREFIXED_TOOLS[:-1]:
                (candidate / tool).write_text("", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                build_sbsa_firmware.find_llvm_bin(candidate)
            (candidate / build_sbsa_firmware.PREFIXED_TOOLS[-1]).write_text(
                "", encoding="utf-8"
            )
            self.assertEqual(
                build_sbsa_firmware.find_llvm_bin(candidate), candidate.resolve()
            )

    def test_the_linker_may_live_apart_from_the_rest_of_the_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            together = Path(directory) / "together"
            together.mkdir()
            (together / "ld.lld").write_text("", encoding="utf-8")
            self.assertEqual(build_sbsa_firmware.find_lld_bin(together), together)
            apart = Path(directory) / "apart"
            apart.mkdir()
            # Packagers do ship lld separately, so absence here is not fatal
            # as long as the linker is reachable some other way.
            self.assertNotEqual(build_sbsa_firmware.find_lld_bin(apart), apart)


class RunnerAgreementTests(unittest.TestCase):
    def test_the_runner_looks_for_exactly_the_banks_the_builder_publishes(self) -> None:
        runner = qemu_profile.RUNNER_PROFILES[
            (AARCH64_SBSA_REF, qemu_profile.QEMU_ENVIRONMENT)
        ]
        published = build_sbsa_firmware.FLASH_BANKS
        self.assertEqual(
            (runner.firmware_code_filenames[0], runner.firmware_vars_filenames[0]),
            published,
        )
        # The secure bank holds Trusted Firmware, which is not a UEFI volume.
        self.assertFalse(runner.firmware_code_is_volume)
        self.assertIn("build_sbsa_firmware.py", runner.firmware_build_command or "")

    def test_the_runner_searches_where_the_builder_writes(self) -> None:
        roots = qemu_profile.firmware_search_roots(sys.executable)
        self.assertIn(build_sbsa_firmware.DEFAULT_OUTPUT, roots)
        self.assertEqual(roots[0], build_sbsa_firmware.DEFAULT_OUTPUT)


class StrictEvidenceTests(unittest.TestCase):
    """A bank built here is evidence through its manifest, not a fixed digest."""

    def _staged(self, directory: Path) -> Path:
        built = directory / "built"
        built.mkdir()
        for name in build_sbsa_firmware.FLASH_BANKS:
            (built / name).write_bytes(name.encode("ascii") * 64)
        output = directory / "output"
        build_sbsa_firmware.publish(
            [built / name for name in build_sbsa_firmware.FLASH_BANKS],
            output,
            256 * 1024,
        )
        return output

    def test_the_profile_pins_a_source_for_aarch64_and_a_digest_for_x86(self) -> None:
        artifacts = qemu_profile.firmware_profile()["artifacts"]
        for kind in ("code", "vars"):
            self.assertEqual(set(artifacts["aarch64"][kind]), {"built_from"})
            self.assertEqual(set(artifacts["x86_64"][kind]), {"bytes", "sha256"})
        source = artifacts["aarch64"]["code"]["built_from"]
        self.assertEqual(
            (REPO_ROOT / source).resolve(),
            build_sbsa_firmware.SOURCE_LOCK.resolve(),
        )

    def test_strict_verification_accepts_a_bank_matching_its_build_manifest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = self._staged(Path(directory))
            qemu_profile.verify_built_firmware(
                output / build_sbsa_firmware.FLASH_BANKS[0],
                "aarch64",
                "tools/sbsa-firmware-sources.lock.json",
            )

    def test_strict_verification_rejects_an_altered_or_unrecorded_bank(self) -> None:
        source = "tools/sbsa-firmware-sources.lock.json"
        first = build_sbsa_firmware.FLASH_BANKS[0]
        for description, corrupt in (
            (
                "altered bank",
                lambda out: _overwrite_first_byte(out / first),
            ),
            (
                "manifest absent",
                lambda out: (out / build_sbsa_firmware.MANIFEST_NAME).unlink(),
            ),
            (
                "bank unrecorded",
                lambda out: (out / build_sbsa_firmware.MANIFEST_NAME).write_text(
                    f"{'0' * 64}  other.fd\n", encoding="utf-8"
                ),
            ),
        ):
            with self.subTest(description):
                with tempfile.TemporaryDirectory() as directory:
                    output = self._staged(Path(directory))
                    corrupt(output)
                    with self.assertRaises(RuntimeError):
                        qemu_profile.verify_built_firmware(
                            output / first, "aarch64", source
                        )


def _truncate(path: Path, size: int) -> None:
    with path.open("r+b") as image:
        image.truncate(size)


def _overwrite_first_byte(path: Path) -> None:
    with path.open("r+b") as image:
        image.write(b"\xa5")


if __name__ == "__main__":
    unittest.main()

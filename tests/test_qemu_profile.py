"""Regression tests for the pinned QEMU firmware profile."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from types import ModuleType
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import qemu_profile  # noqa: E402
from platform_profile import (  # noqa: E402
    AARCH64_SBSA_REF,
    AARCH64_UEFI_VIRTIO_MMIO,
    PLATFORM_IDS,
    PLATFORM_MANIFEST_PATH,
    PLATFORM_PROFILES,
    X86_64_Q35_UEFI,
    X86_64_UEFI_VIRTIO_PCI,
    boot_image_path,
    platform_manifest,
    resolve_platform,
    root_storage_image_path,
    shared_test_image_path,
    statefs_image_path,
    txslot_image_path,
)
from qemu_profile import (  # noqa: E402
    ENVIRONMENT_IDS,
    EXPECTED_QEMU_VERSION,
    FIRMWARE_PROFILE_PATH,
    QEMU_ENVIRONMENT,
    RUNNER_PROFILES,
    _qemu_arguments,
    cloud_bundle_path,
    firmware_profile,
    resolve_runner,
    select_runner,
    validate_runner_catalog,
    variable_store_path,
    verify_compatible_firmware,
    verify_file_digest,
    verify_qemu_version,
)


def load_script_module(name: str, filename: str) -> ModuleType:
    """Load a hyphenated CLI script so its pure argument parser can be tested."""
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "scripts" / filename
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load script module {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUN_QEMU = load_script_module("troe_run_qemu", "run-qemu.py")
TEST_QEMU = load_script_module("troe_test_qemu", "test-qemu.py")


class FirmwareProfileTests(unittest.TestCase):
    """The committed profile and byte verifier fail closed."""

    def test_discovered_x86_spcr_fixture_is_exact_and_checksummed(self) -> None:
        table = qemu_profile.qemu_discovered_x86_spcr_bytes()
        self.assertEqual(len(table), 80)
        self.assertEqual(table[:4], b"SPCR")
        self.assertEqual(int.from_bytes(table[4:8], "little"), len(table))
        self.assertEqual(sum(table) & 0xFF, 0)
        self.assertEqual(table[36], 0)
        self.assertEqual(
            table[40:52], bytes((1, 8, 0, 1)) + (0x3F8).to_bytes(8, "little")
        )
        self.assertEqual(table[52:58], bytes((3, 4, 4, 0, 0, 0)))
        self.assertEqual(table[64:68], b"\xff\xff\xff\xff")

    def test_manifest_is_canonical_and_complete(self) -> None:
        profile = firmware_profile()
        self.assertEqual(profile["qemu_version"], EXPECTED_QEMU_VERSION)
        self.assertEqual(profile["firmware_release"], "edk2-stable202605-r1")
        self.assertEqual(set(profile["artifacts"]), {"x86_64", "aarch64"})
        for architecture in ("x86_64", "aarch64"):
            self.assertEqual(set(profile["artifacts"][architecture]), {"code", "vars"})
        encoded = json.dumps(profile, indent=2, sort_keys=True) + "\n"
        self.assertEqual(FIRMWARE_PROFILE_PATH.read_text(encoding="utf-8"), encoded)

    def test_exact_digest_passes_and_size_or_content_mismatch_fails(self) -> None:
        payload = b"pinned firmware bytes"
        expected = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory(prefix="troe-firmware-test-") as directory:
            artifact = Path(directory) / "firmware.fd"
            artifact.write_bytes(payload)
            verify_file_digest(artifact, len(payload), expected)
            with self.assertRaisesRegex(RuntimeError, "size mismatch"):
                verify_file_digest(artifact, len(payload) + 1, expected)
            artifact.write_bytes(payload[:-1] + b"!")
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                verify_file_digest(artifact, len(payload), expected)

    def test_compatible_firmware_requires_flash_geometry_and_volume_header(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-firmware-test-") as directory:
            artifact = Path(directory) / "OVMF_CODE.fd"
            payload = bytearray(4 * 64 * 1024)
            payload[40:44] = b"_FVH"
            artifact.write_bytes(payload)
            verify_compatible_firmware(artifact, "x86_64", "code")
            artifact.write_bytes(payload[:-1])
            with self.assertRaisesRegex(RuntimeError, "4-KiB aligned"):
                verify_compatible_firmware(artifact, "x86_64", "code")
            artifact.write_bytes(bytes(len(payload)))
            with self.assertRaisesRegex(RuntimeError, "no UEFI firmware-volume"):
                verify_compatible_firmware(artifact, "x86_64", "code")

    def test_qemu_compatibility_range_and_strict_pin_are_separate(self) -> None:
        self.assertEqual(
            verify_qemu_version("QEMU emulator version 8.2.2 (Debian)"),
            (8, 2, 2),
        )
        self.assertEqual(
            verify_qemu_version("QEMU emulator version 11.1.0", strict=True),
            (11, 1, 0),
        )
        for version in ("7.2.0", "12.0.0"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(RuntimeError, "8.x through 11.x"):
                    verify_qemu_version(f"QEMU emulator version {version}")
        with self.assertRaisesRegex(RuntimeError, "requires QEMU 11.1.0"):
            verify_qemu_version("QEMU emulator version 8.2.2", strict=True)

    def test_platform_manifest_is_canonical_and_matches_rust_descriptors(self) -> None:
        manifest = platform_manifest()
        encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        self.assertEqual(PLATFORM_MANIFEST_PATH.read_text(encoding="utf-8"), encoded)

        source = (
            REPO_ROOT / "crates" / "device" / "troe-platform" / "src" / "lib.rs"
        ).read_text(encoding="utf-8")
        numeric_ids = {
            name: int(raw)
            for name, raw in re.findall(
                r"pub const ([A-Z0-9_]+): Self = Self\(([0-9]+)\);", source
            )
        }
        descriptors = re.findall(
            r"pub const ([A-Z0-9_]+): PlatformDescriptor<'static> = "
            r"PlatformDescriptor::new\(\n(.*?)\n\);",
            source,
            re.DOTALL,
        )
        architecture_names = {"X86_64": "x86_64", "Aarch64": "aarch64"}
        rust_platforms = set()
        for constant, body in descriptors:
            identity = re.search(r"PlatformId::([A-Z0-9_]+),", body)
            name = re.search(r'\n\s*"([a-z0-9_-]+)",', body)
            architecture = re.search(r"Architecture::([A-Za-z0-9_]+),", body)
            transport = re.search(r"VirtioTransportKind::(PciGic|Pci|Mmio)\s*\{", body)
            self.assertIsNotNone(identity)
            self.assertIsNotNone(name)
            self.assertIsNotNone(architecture)
            self.assertIsNotNone(transport)
            assert identity is not None
            assert name is not None
            assert architecture is not None
            assert transport is not None
            self.assertEqual(identity.group(1), constant)
            rust_platforms.add(
                (
                    numeric_ids[constant],
                    name.group(1),
                    architecture_names[architecture.group(1)],
                    # A GIC-routed PCI transport is still a PCI transport as
                    # far as the manifest's device model is concerned.
                    "pci"
                    if transport.group(1) == "PciGic"
                    else transport.group(1).lower(),
                )
            )
        manifest_platforms = {
            (
                entry["id"],
                entry["name"],
                entry["architecture"],
                entry["virtio_transport"],
            )
            for entry in manifest["platforms"]
        }
        self.assertEqual(manifest_platforms, rust_platforms)

    def test_build_platform_records_are_complete_environment_independent(self) -> None:
        self.assertEqual(
            PLATFORM_IDS,
            (
                X86_64_Q35_UEFI,
                AARCH64_SBSA_REF,
                X86_64_UEFI_VIRTIO_PCI,
                AARCH64_UEFI_VIRTIO_MMIO,
            ),
        )
        self.assertEqual(
            {field.name for field in fields(type(resolve_platform(X86_64_Q35_UEFI)))},
            {
                "numeric_id",
                "identifier",
                "architecture",
                "firmware_discovery",
                "target",
                "kernel_feature",
                "virtio_transport",
            },
        )
        x86 = resolve_platform(X86_64_Q35_UEFI)
        arm = resolve_platform(AARCH64_SBSA_REF)
        self.assertEqual(
            (
                x86.numeric_id,
                x86.architecture,
                x86.firmware_discovery,
                x86.target,
                x86.kernel_feature,
                x86.virtio_transport,
            ),
            (
                1,
                "x86_64",
                "fixed",
                "x86_64-unknown-uefi",
                "platform-x86_64-q35-uefi",
                "pci",
            ),
        )
        discovered_x86 = resolve_platform(X86_64_UEFI_VIRTIO_PCI)
        discovered_arm = resolve_platform(AARCH64_UEFI_VIRTIO_MMIO)
        self.assertEqual(
            (
                discovered_x86.numeric_id,
                discovered_x86.architecture,
                discovered_x86.firmware_discovery,
                discovered_x86.target,
                discovered_x86.kernel_feature,
                discovered_x86.virtio_transport,
            ),
            (
                3,
                "x86_64",
                "acpi",
                "x86_64-unknown-uefi",
                "platform-x86_64-uefi-virtio-pci",
                "pci",
            ),
        )
        self.assertEqual(
            (
                discovered_arm.numeric_id,
                discovered_arm.architecture,
                discovered_arm.firmware_discovery,
                discovered_arm.target,
                discovered_arm.kernel_feature,
                discovered_arm.virtio_transport,
            ),
            (
                4,
                "aarch64",
                "fdt",
                "aarch64-unknown-uefi",
                "platform-aarch64-uefi-virtio-mmio",
                "mmio",
            ),
        )
        self.assertEqual(
            (
                arm.numeric_id,
                arm.architecture,
                arm.firmware_discovery,
                arm.target,
                arm.kernel_feature,
                arm.virtio_transport,
            ),
            (
                2,
                "aarch64",
                "fixed",
                "aarch64-unknown-uefi",
                "platform-aarch64-sbsa-ref",
                "pci",
            ),
        )
        discovered_x86 = resolve_runner(X86_64_UEFI_VIRTIO_PCI, QEMU_ENVIRONMENT)
        discovered_arm = resolve_runner(AARCH64_UEFI_VIRTIO_MMIO, QEMU_ENVIRONMENT)
        self.assertEqual(
            (
                discovered_x86.machine,
                discovered_x86.memory,
                discovered_x86.virtio_block_device,
                discovered_x86.virtio_network_device,
                discovered_x86.virtio_rng_device,
                discovered_x86.acceptance_udp_port,
            ),
            (
                "q35",
                "128M",
                "virtio-blk-pci,disable-legacy=on",
                "virtio-net-pci,disable-legacy=on",
                "virtio-rng-pci,disable-legacy=on",
                40125,
            ),
        )
        self.assertEqual(
            (
                discovered_arm.machine,
                discovered_arm.virtio_block_device,
                discovered_arm.virtio_network_device,
                discovered_arm.virtio_rng_device,
                discovered_arm.acceptance_udp_port,
            ),
            (
                "virt,gic-version=3,acpi=off",
                "virtio-blk-device",
                "virtio-net-device",
                "virtio-rng-device",
                40126,
            ),
        )

    def test_qemu_runner_records_are_complete_and_exact(self) -> None:
        self.assertEqual(ENVIRONMENT_IDS, (QEMU_ENVIRONMENT,))
        x86 = resolve_runner(X86_64_Q35_UEFI, QEMU_ENVIRONMENT)
        arm = resolve_runner(AARCH64_SBSA_REF, QEMU_ENVIRONMENT)
        self.assertEqual(
            (
                x86.executable,
                x86.machine,
                x86.cpu,
                x86.memory,
                x86.virtual_cpus,
                x86.virtio_block_device,
                x86.virtio_network_device,
                x86.virtio_rng_device,
                x86.firmware_architecture,
                x86.acceptance_udp_port,
            ),
            (
                "qemu-system-x86_64",
                "q35",
                "max",
                "128M",
                1,
                "virtio-blk-pci,disable-legacy=on",
                "virtio-net-pci,disable-legacy=on",
                "virtio-rng-pci,disable-legacy=on",
                "x86_64",
                40123,
            ),
        )
        self.assertEqual(
            (
                arm.executable,
                arm.machine,
                arm.cpu,
                arm.memory,
                arm.virtual_cpus,
                arm.virtio_block_device,
                arm.virtio_network_device,
                arm.virtio_rng_device,
                arm.firmware_architecture,
                arm.acceptance_udp_port,
                arm.extra_arguments,
            ),
            (
                "qemu-system-aarch64",
                "sbsa-ref",
                "max",
                "128M",
                1,
                "virtio-blk-pci,disable-legacy=on",
                "virtio-net-pci,disable-legacy=on",
                "virtio-rng-pci,disable-legacy=on",
                "aarch64",
                40124,
                (),
            ),
        )

    def test_unknown_platform_and_runner_pair_fail_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unknown platform"):
            resolve_platform("x86_64-unknown-uefi")
        with self.assertRaisesRegex(RuntimeError, "no runner"):
            resolve_runner(X86_64_Q35_UEFI, "cloud-hypervisor")

    def test_two_execution_environments_can_share_one_build_platform(self) -> None:
        qemu = resolve_runner(X86_64_Q35_UEFI, QEMU_ENVIRONMENT)
        alternate = replace(
            qemu,
            environment="qemu-kvm",
            acceptance_udp_port=41123,
        )
        runners = {
            (qemu.platform_id, qemu.environment): qemu,
            (alternate.platform_id, alternate.environment): alternate,
        }
        validate_runner_catalog(runners)
        self.assertIs(select_runner(runners, X86_64_Q35_UEFI, QEMU_ENVIRONMENT), qemu)
        self.assertIs(select_runner(runners, X86_64_Q35_UEFI, "qemu-kvm"), alternate)

    def test_all_mutable_and_boot_artifacts_include_the_platform_id(self) -> None:
        for profile in PLATFORM_PROFILES.values():
            with self.subTest(platform=profile.identifier):
                self.assertEqual(
                    boot_image_path(profile),
                    REPO_ROOT / "build" / f"boot-{profile.identifier}.img",
                )
                self.assertEqual(
                    boot_image_path(profile, acceptance_probes=True),
                    REPO_ROOT / "build" / f"boot-{profile.identifier}-acceptance.img",
                )
                self.assertEqual(
                    root_storage_image_path(profile),
                    REPO_ROOT / "build" / f"storage-root-{profile.identifier}.img",
                )
                self.assertEqual(
                    shared_test_image_path(profile),
                    REPO_ROOT / "build" / f"storage-shared-{profile.identifier}.img",
                )
                self.assertEqual(
                    txslot_image_path(profile),
                    REPO_ROOT / "build" / f"storage-txslot-{profile.identifier}.img",
                )
                self.assertEqual(
                    statefs_image_path(profile),
                    REPO_ROOT / "build" / f"storage-statefs-{profile.identifier}.img",
                )
                self.assertEqual(
                    variable_store_path(profile),
                    REPO_ROOT / "build" / f"qemu-vars-{profile.identifier}.fd",
                )
                self.assertEqual(
                    cloud_bundle_path(profile, QEMU_ENVIRONMENT),
                    REPO_ROOT
                    / "build"
                    / f"cloud-{profile.identifier}-{QEMU_ENVIRONMENT}",
                )
                self.assertEqual(
                    cloud_bundle_path(
                        profile,
                        QEMU_ENVIRONMENT,
                        acceptance_probes=True,
                    ),
                    REPO_ROOT
                    / "build"
                    / f"cloud-{profile.identifier}-{QEMU_ENVIRONMENT}-acceptance",
                )

    def test_acceptance_shared_media_is_disposable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-shared-cleanup-") as temporary:
            root = Path(temporary)
            paths = {
                platform_id: root / f"{platform_id}.img" for platform_id in PLATFORM_IDS
            }
            for path in paths.values():
                path.write_bytes(b"acceptance-only")
            with mock.patch.object(
                TEST_QEMU,
                "shared_test_image_path",
                side_effect=lambda profile: paths[profile.identifier],
            ):
                TEST_QEMU.cleanup_shared_media(PLATFORM_IDS)
                TEST_QEMU.cleanup_shared_media(PLATFORM_IDS)
            self.assertTrue(all(not path.exists() for path in paths.values()))

    def test_cloud_rebuild_preserves_last_good_bundle_on_failure(self) -> None:
        profile = resolve_platform(X86_64_UEFI_VIRTIO_PCI)
        with tempfile.TemporaryDirectory(prefix="troe-cloud-swap-") as temporary:
            bundle = Path(temporary) / "bundle"
            bundle.mkdir()
            (bundle / "sentinel").write_text("last-good", encoding="utf-8")
            with (
                mock.patch.object(
                    qemu_profile, "cloud_bundle_path", return_value=bundle
                ),
                mock.patch.object(
                    qemu_profile.subprocess,
                    "run",
                    side_effect=RuntimeError("synthetic build failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic build failure"),
            ):
                qemu_profile.build_cloud_bundle(profile, QEMU_ENVIRONMENT)
            self.assertEqual(
                (bundle / "sentinel").read_text(encoding="utf-8"),
                "last-good",
            )

    def test_qemu_argv_is_an_exact_projection_of_each_platform(self) -> None:
        paths = {
            "firmware": Path("/firmware.fd"),
            "variables": Path("/variables.fd"),
            "image": Path("/boot.img"),
            "storage": Path("/root.img"),
            "txslot": Path("/txslot.img"),
            "statefs": Path("/statefs.img"),
        }
        common_tail = [
            "-drive",
            "if=pflash,format=raw,unit=0,readonly=on,file=/firmware.fd",
            "-drive",
            "if=pflash,format=raw,unit=1,file=/variables.fd",
            "-drive",
            "if=virtio,format=raw,file=/boot.img",
            "-drive",
            "if=none,format=raw,cache=writeback,id=troe-root,file=/root.img",
        ]
        x86 = _qemu_arguments(
            RUNNER_PROFILES[(X86_64_Q35_UEFI, QEMU_ENVIRONMENT)],
            "/qemu-x86_64",
            **paths,
            graphical=False,
            framebuffer=False,
        )
        self.assertEqual(
            x86,
            [
                "/qemu-x86_64",
                "-machine",
                "q35",
                "-monitor",
                "none",
                "-serial",
                "stdio",
                "-display",
                "none",
                "-cpu",
                "max",
                "-smp",
                "1",
                "-m",
                "128M",
                *common_tail,
                "-device",
                "virtio-blk-pci,disable-legacy=on,drive=troe-root",
                "-drive",
                "if=none,format=raw,cache=writeback,id=troe-txslot,file=/txslot.img",
                "-device",
                "virtio-blk-pci,disable-legacy=on,drive=troe-txslot",
                "-drive",
                "if=none,format=raw,cache=writeback,id=troe-statefs,file=/statefs.img",
                "-device",
                "virtio-blk-pci,disable-legacy=on,drive=troe-statefs",
                "-netdev",
                "user,id=troe-net",
                "-device",
                "virtio-net-pci,disable-legacy=on,netdev=troe-net,mac=52:54:00:12:34:56",
                "-object",
                "rng-random,id=troe-rng,filename=/dev/urandom",
                "-device",
                "virtio-rng-pci,disable-legacy=on,rng=troe-rng",
                "-no-reboot",
            ],
        )
        arm = _qemu_arguments(
            RUNNER_PROFILES[(AARCH64_SBSA_REF, QEMU_ENVIRONMENT)],
            "/qemu-aarch64",
            **paths,
            graphical=False,
            framebuffer=True,
        )
        self.assertEqual(
            arm,
            [
                "/qemu-aarch64",
                "-machine",
                "sbsa-ref",
                "-monitor",
                "none",
                "-serial",
                "stdio",
                "-display",
                "none",
                "-device",
                "bochs-display",
                "-cpu",
                "max",
                "-smp",
                "1",
                "-m",
                "128M",
                "-drive",
                "if=pflash,format=raw,unit=0,readonly=on,file=/firmware.fd",
                "-drive",
                "if=pflash,format=raw,unit=1,file=/variables.fd",
                # The reference firmware has no virtio driver, so the boot
                # volume arrives on the machine's own AHCI controller.
                "-drive",
                "if=none,format=raw,id=troe-boot,file=/boot.img",
                "-device",
                "ide-hd,bus=ide.0,drive=troe-boot,bootindex=1",
                "-drive",
                "if=none,format=raw,cache=writeback,id=troe-root,file=/root.img",
                "-device",
                "virtio-blk-pci,disable-legacy=on,drive=troe-root",
                "-drive",
                "if=none,format=raw,cache=writeback,id=troe-txslot,file=/txslot.img",
                "-device",
                "virtio-blk-pci,disable-legacy=on,drive=troe-txslot",
                "-drive",
                "if=none,format=raw,cache=writeback,id=troe-statefs,file=/statefs.img",
                "-device",
                "virtio-blk-pci,disable-legacy=on,drive=troe-statefs",
                "-netdev",
                "user,id=troe-net",
                "-device",
                "virtio-net-pci,disable-legacy=on,netdev=troe-net,"
                "mac=52:54:00:12:34:57",
                "-object",
                "rng-random,id=troe-rng,filename=/dev/urandom",
                "-device",
                "virtio-rng-pci,disable-legacy=on,rng=troe-rng",
                "-no-reboot",
            ],
        )
        cloud_x86 = _qemu_arguments(
            RUNNER_PROFILES[(X86_64_UEFI_VIRTIO_PCI, QEMU_ENVIRONMENT)],
            "/qemu-x86_64",
            **paths,
            graphical=False,
            framebuffer=False,
        )
        self.assertNotIn("if=virtio,format=raw,file=/boot.img", cloud_x86)
        self.assertNotIn(
            "if=none,format=raw,cache=writeback,id=troe-root,file=/root.img",
            cloud_x86,
        )
        self.assertIn(
            "if=none,format=raw,cache=writeback,id=troe-system,file=/boot.img",
            cloud_x86,
        )
        self.assertIn(
            "virtio-blk-pci,disable-legacy=on,drive=troe-system,bootindex=1",
            cloud_x86,
        )

        custom = _qemu_arguments(
            RUNNER_PROFILES[(X86_64_Q35_UEFI, QEMU_ENVIRONMENT)],
            "/qemu-x86_64",
            **paths,
            graphical=False,
            framebuffer=False,
            memory="256M",
            data_disks=(Path("/archive.raw"), Path("/media.raw")),
        )
        self.assertEqual(custom[custom.index("-m") + 1], "256M")
        self.assertIn(
            "if=none,format=raw,cache=writeback,id=troe-data-0,file=/archive.raw",
            custom,
        )
        self.assertIn(
            "virtio-blk-pci,disable-legacy=on,drive=troe-data-1",
            custom,
        )
        with self.assertRaisesRegex(RuntimeError, "integer number of MiB or GiB"):
            _qemu_arguments(
                RUNNER_PROFILES[(X86_64_Q35_UEFI, QEMU_ENVIRONMENT)],
                "/qemu-x86_64",
                **paths,
                graphical=False,
                framebuffer=False,
                memory="256",
            )

    def test_launcher_and_acceptance_clis_require_platform_and_environment(
        self,
    ) -> None:
        run_args = RUN_QEMU.parse_args(
            [
                "--platform",
                X86_64_Q35_UEFI,
                "--environment",
                QEMU_ENVIRONMENT,
                "--skip-build",
                "--memory",
                "256M",
            ]
        )
        self.assertEqual(run_args.platform, X86_64_Q35_UEFI)
        self.assertEqual(run_args.environment, QEMU_ENVIRONMENT)
        self.assertEqual(run_args.memory, "256M")
        self.assertFalse(run_args.no_shared_disk)
        self.assertFalse(run_args.reset_shared_disk)
        self.assertFalse(run_args.strict_tool_versions)
        gui_run_args = RUN_QEMU.parse_args(
            [
                "--platform",
                X86_64_Q35_UEFI,
                "--environment",
                QEMU_ENVIRONMENT,
                "--gui",
            ]
        )
        self.assertTrue(gui_run_args.graphical)
        custom_run_args = RUN_QEMU.parse_args(
            [
                "--platform",
                X86_64_Q35_UEFI,
                "--environment",
                QEMU_ENVIRONMENT,
                "--volume-table",
                "custom.toml",
                "--data-disk",
                "archive.raw",
                "--data-disk",
                "media.raw",
                "--no-shared-disk",
            ]
        )
        self.assertEqual(custom_run_args.volume_table, Path("custom.toml"))
        self.assertEqual(
            custom_run_args.data_disk, [Path("archive.raw"), Path("media.raw")]
        )
        self.assertTrue(custom_run_args.no_shared_disk)
        reset_run_args = RUN_QEMU.parse_args(
            [
                "--platform",
                X86_64_Q35_UEFI,
                "--environment",
                QEMU_ENVIRONMENT,
                "--reset-shared-disk",
            ]
        )
        self.assertTrue(reset_run_args.reset_shared_disk)
        self.assertTrue(
            RUN_QEMU.is_default_shared_disk(
                REPO_ROOT / "build" / "troe-shared-fat32.img"
            )
        )
        self.assertFalse(RUN_QEMU.is_default_shared_disk(Path("archive.raw")))
        test_args = TEST_QEMU.parse_args(
            ["--platform", "all", "--environment", QEMU_ENVIRONMENT]
        )
        self.assertEqual(test_args.platform, "all")
        self.assertEqual(test_args.environment, QEMU_ENVIRONMENT)
        self.assertFalse(test_args.strict_tool_versions)
        self.assertEqual(
            TEST_QEMU.selected_scenarios(test_args), TEST_QEMU.DEFAULT_SCENARIOS
        )
        focused_args = TEST_QEMU.parse_args(
            [
                "--platform",
                X86_64_Q35_UEFI,
                "--environment",
                QEMU_ENVIRONMENT,
                "--scenario",
                "network",
                "--scenario",
                "shell-terminal",
            ]
        )
        self.assertEqual(
            TEST_QEMU.selected_scenarios(focused_args),
            frozenset(("network", "shell-terminal")),
        )
        framebuffer_args = TEST_QEMU.parse_args(
            [
                "--platform",
                X86_64_Q35_UEFI,
                "--environment",
                QEMU_ENVIRONMENT,
                "--scenario",
                "framebuffer-keyboard",
            ]
        )
        framebuffer_groups = TEST_QEMU.selected_scenarios(framebuffer_args)
        TEST_QEMU.apply_scenario_requirements(framebuffer_args, framebuffer_groups)
        self.assertTrue(framebuffer_args.framebuffer_console)
        self.assertTrue(framebuffer_args.native_keyboard)
        self.assertFalse(TEST_QEMU.requires_acceptance_images(frozenset(("network",))))
        self.assertTrue(
            TEST_QEMU.requires_acceptance_images(frozenset(("boot", "fault-isolation")))
        )
        smoke_with_scenario = TEST_QEMU.parse_args(
            [
                "--platform",
                X86_64_Q35_UEFI,
                "--environment",
                QEMU_ENVIRONMENT,
                "--smoke",
                "--scenario",
                "network",
            ]
        )
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            TEST_QEMU.selected_scenarios(smoke_with_scenario)

        strict_run_args = RUN_QEMU.parse_args(
            [
                "--platform",
                X86_64_Q35_UEFI,
                "--environment",
                QEMU_ENVIRONMENT,
                "--strict-tool-versions",
            ]
        )
        self.assertTrue(strict_run_args.strict_tool_versions)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                RUN_QEMU.parse_args(
                    [
                        "--platform",
                        X86_64_Q35_UEFI,
                        "--environment",
                        QEMU_ENVIRONMENT,
                        "--strict-tool-versions",
                        "--skip-version-check",
                    ]
                )

        rejected_argv = (
            (RUN_QEMU, []),
            (RUN_QEMU, ["--platform", X86_64_Q35_UEFI]),
            (
                RUN_QEMU,
                [
                    "--platform",
                    X86_64_Q35_UEFI,
                    "--environment",
                    "native",
                ],
            ),
            (
                RUN_QEMU,
                ["--arch", "x86_64", "--environment", QEMU_ENVIRONMENT],
            ),
            (
                TEST_QEMU,
                ["--platform", "unknown", "--environment", QEMU_ENVIRONMENT],
            ),
        )
        for module, argv in rejected_argv:
            with self.subTest(script=module.__name__, argv=argv):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        module.parse_args(list(argv))

    def test_primary_scenario_dispatch_runs_only_selected_groups(self) -> None:
        session = mock.Mock()
        with (
            mock.patch.object(TEST_QEMU, "assert_owned_boot") as owned_boot,
            mock.patch.object(TEST_QEMU, "run_boot_group") as boot,
            mock.patch.object(TEST_QEMU, "run_network_group") as network,
            mock.patch.object(TEST_QEMU, "run_shell_terminal_group") as shell,
            mock.patch.object(TEST_QEMU, "run_filesystem_group") as filesystem,
            mock.patch.object(TEST_QEMU, "run_lua_group") as lua,
            mock.patch.object(TEST_QEMU, "run_quota_memory_group") as quota,
            mock.patch.object(TEST_QEMU, "request_poweroff") as poweroff,
        ):
            TEST_QEMU.run_scenario(
                session,
                30.0,
                10.0,
                40123,
                frozenset(("network", "filesystem")),
            )
        session.wait_for.assert_called_once_with(b"sh:/> ", 30.0)
        owned_boot.assert_called_once_with(session)
        boot.assert_not_called()
        network.assert_called_once_with(session, 10.0, 40123)
        shell.assert_not_called()
        filesystem.assert_called_once_with(session, 10.0)
        lua.assert_not_called()
        quota.assert_not_called()
        poweroff.assert_called_once_with(session, 10.0)


if __name__ == "__main__":
    unittest.main()

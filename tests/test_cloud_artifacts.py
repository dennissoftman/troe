"""Deterministic cloud-bundle, GPT, verifier, and support-matrix tests."""

from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from scripts import build as production_build
from tools import mkcloud, mkcontent, mkfat, mkstorage


def fake_efi(architecture: str, payload: bytes) -> bytes:
    """Build a bounded synthetic PE32+ EFI application for format tests."""
    image = bytearray(384)
    image[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    optional_bytes = 70
    struct.pack_into(
        "<HHIIIHH",
        image,
        pe_offset + 4,
        mkcloud.PE_MACHINES[architecture],
        1,
        0,
        0,
        0,
        optional_bytes,
        0x0002,
    )
    optional = pe_offset + 24
    struct.pack_into("<H", image, optional, mkcloud.PE32_PLUS_MAGIC)
    struct.pack_into("<H", image, optional + 68, mkcloud.PE_SUBSYSTEM_EFI_APPLICATION)
    return bytes(image) + payload


class CanonicalGptTests(unittest.TestCase):
    """Exercise build/parse independence and complete bounded geometry checks."""

    DISK_GUID = bytes.fromhex("00112233445566778899aabbccddeeff")
    PARTITION_GUID = bytes.fromhex("ffeeddccbbaa99887766554433221100")

    @classmethod
    def image(cls) -> bytes:
        payload = b"payload" + bytes(2 * mkcloud.SECTOR_BYTES - len(b"payload"))
        partition = mkcloud.GptPartition(
            name="test",
            type_guid=mkcloud.LINUX_FILESYSTEM_TYPE_GUID,
            unique_guid=cls.PARTITION_GUID,
            first_lba=mkcloud.PARTITION_ALIGNMENT_SECTORS,
            last_lba=mkcloud.PARTITION_ALIGNMENT_SECTORS + 1,
            payload=payload,
        )
        return mkcloud.build_gpt(cls.DISK_GUID, 8_192, (partition,))

    def test_double_build_is_identical_and_parser_reproduces_exact_payload(
        self,
    ) -> None:
        first = self.image()
        second = self.image()
        self.assertEqual(first, second)
        disk = mkcloud.parse_gpt(first)
        self.assertEqual(disk.disk_guid, self.DISK_GUID)
        self.assertEqual(disk.total_sectors, 8_192)
        self.assertEqual(len(disk.partitions), 1)
        self.assertEqual(disk.partitions[0].name, "test")
        self.assertEqual(
            disk.partitions[0].payload[:7],
            b"payload",
        )

        primary_entries = first[
            2 * mkcloud.SECTOR_BYTES : 2 * mkcloud.SECTOR_BYTES
            + mkcloud.GPT_ARRAY_BYTES
        ]
        stored_crc = struct.unpack_from("<I", first, mkcloud.SECTOR_BYTES + 88)[0]
        self.assertEqual(zlib.crc32(primary_entries), stored_crc)
        self.assertEqual(
            struct.unpack_from("<QQ", primary_entries, 32),
            (
                mkcloud.PARTITION_ALIGNMENT_SECTORS,
                mkcloud.PARTITION_ALIGNMENT_SECTORS + 1,
            ),
        )
        self.assertEqual(first[447:450], b"\x00\x02\x00")
        self.assertEqual(first[451:454], b"\xff\xff\xff")

    def test_truncation_metadata_corruption_and_nonzero_gaps_fail(self) -> None:
        image = self.image()
        for corrupt in (b"", image[:-1], image[: 40 * mkcloud.SECTOR_BYTES]):
            with self.subTest(length=len(corrupt)):
                with self.assertRaises(ValueError):
                    mkcloud.parse_gpt(corrupt)

        protective = bytearray(image)
        protective[510] ^= 1
        with self.assertRaisesRegex(ValueError, "protective MBR"):
            mkcloud.parse_gpt(bytes(protective))

        protective_chs = bytearray(image)
        protective_chs[447] ^= 1
        with self.assertRaisesRegex(ValueError, "protective MBR"):
            mkcloud.parse_gpt(bytes(protective_chs))

        primary_entry = bytearray(image)
        primary_entry[2 * mkcloud.SECTOR_BYTES] ^= 1
        with self.assertRaisesRegex(ValueError, "entry arrays differ"):
            mkcloud.parse_gpt(bytes(primary_entry))

        backup_header = bytearray(image)
        backup_header[-mkcloud.SECTOR_BYTES + 16] ^= 1
        with self.assertRaisesRegex(ValueError, "header checksum"):
            mkcloud.parse_gpt(bytes(backup_header))

        gap = bytearray(image)
        gap[100 * mkcloud.SECTOR_BYTES] = 1
        with self.assertRaisesRegex(ValueError, "unused GPT sectors"):
            mkcloud.parse_gpt(bytes(gap))

    def test_storage_images_use_the_same_canonical_protective_mbr(self) -> None:
        for total_sectors in (
            mkstorage.TOTAL_SECTORS,
            mkstorage.TXSLOT_TOTAL_SECTORS,
        ):
            with self.subTest(total_sectors=total_sectors):
                protective = mkstorage.protective_mbr(total_sectors)
                self.assertEqual(protective, mkcloud._protective_mbr(total_sectors))
                self.assertEqual(protective[447:450], b"\x00\x02\x00")
                self.assertEqual(protective[451:454], b"\xff\xff\xff")

    def test_overlap_unaligned_and_wrong_payload_length_are_rejected(self) -> None:
        base = mkcloud.GptPartition(
            name="one",
            type_guid=mkcloud.LINUX_FILESYSTEM_TYPE_GUID,
            unique_guid=self.PARTITION_GUID,
            first_lba=2_048,
            last_lba=2_048,
            payload=bytes(mkcloud.SECTOR_BYTES),
        )
        unaligned = mkcloud.GptPartition(
            name="bad",
            type_guid=mkcloud.ESP_TYPE_GUID,
            unique_guid=mkcloud.ESP_UNIQUE_GUID,
            first_lba=2_049,
            last_lba=2_049,
            payload=bytes(mkcloud.SECTOR_BYTES),
        )
        short = mkcloud.GptPartition(
            name="bad",
            type_guid=mkcloud.ESP_TYPE_GUID,
            unique_guid=mkcloud.ESP_UNIQUE_GUID,
            first_lba=4_096,
            last_lba=4_096,
            payload=b"short",
        )
        with self.assertRaises(ValueError):
            mkcloud.build_gpt(self.DISK_GUID, 8_192, (base, unaligned))
        with self.assertRaises(ValueError):
            mkcloud.build_gpt(self.DISK_GUID, 8_192, (base, short))


class CloudEnvironmentMatrixTests(unittest.TestCase):
    """Keep support claims exact, machine-readable, and fail-closed."""

    def setUp(self) -> None:
        self.platforms = mkcloud.load_platform_manifest()
        self.raw = json.loads(
            mkcloud.ENVIRONMENT_MATRIX_PATH.read_text(encoding="utf-8")
        )

    def test_matrix_distinguishes_acceptance_compatibility_and_incompatibility(
        self,
    ) -> None:
        entries = mkcloud.load_environment_matrix(platforms=self.platforms)
        by_id = {entry["id"]: entry for entry in entries}
        self.assertEqual(
            by_id["qemu-q35-x86_64"]["runtime_status"],
            "compatible-unverified",
        )
        self.assertEqual(
            by_id["qemu-kvm-q35-x86_64"]["runtime_status"],
            "compatible-unverified",
        )
        self.assertEqual(
            by_id["cloud-hypervisor-v53-x86_64"]["runtime_status"],
            "compatible-unverified",
        )
        self.assertEqual(
            by_id["cloud-hypervisor-v53-x86_64"]["environment"],
            "cloud-hypervisor-kvm-v53",
        )
        self.assertFalse(by_id["cloud-hypervisor-v53-x86_64"]["acceptance_evidence"])
        self.assertEqual(
            by_id["qemu-discoverable-virtio-pci-x86_64"]["runtime_status"],
            "accepted",
        )
        self.assertEqual(
            by_id["qemu-discoverable-virtio-mmio-aarch64"]["runtime_status"],
            "accepted",
        )
        self.assertTrue(
            by_id["qemu-discoverable-virtio-pci-x86_64"]["acceptance_evidence"]
        )
        self.assertTrue(
            by_id["qemu-discoverable-virtio-mmio-aarch64"]["acceptance_evidence"]
        )
        self.assertEqual(by_id["aws-nitro-x86_64"]["missing_drivers"], ["nvme", "ena"])
        self.assertEqual(
            by_id["azure-generation-2-x86_64"]["missing_drivers"],
            ["hyper-v-vmbus", "hyper-v-storage", "hyper-v-network"],
        )
        self.assertEqual(
            {entry["artifact_status"] for entry in entries},
            {"host-verified", "unavailable"},
        )

    def test_false_acceptance_and_inconsistent_platform_records_fail(self) -> None:
        no_evidence = copy.deepcopy(self.raw)
        no_evidence["entries"][0]["runtime_status"] = "accepted"
        no_evidence["entries"][0]["acceptance_evidence"] = []
        with self.assertRaisesRegex(ValueError, "lacks evidence"):
            mkcloud.validate_environment_matrix(no_evidence, self.platforms)

        unresolved_gap = copy.deepcopy(self.raw)
        unresolved_gap["entries"][0]["runtime_status"] = "accepted"
        unresolved_gap["entries"][0]["acceptance_evidence"] = ["exact command"]
        with self.assertRaisesRegex(ValueError, "still has gaps"):
            mkcloud.validate_environment_matrix(unresolved_gap, self.platforms)

        wrong_arch = copy.deepcopy(self.raw)
        wrong_arch["entries"][0]["architecture"] = "aarch64"
        with self.assertRaisesRegex(ValueError, "buildable matrix entry"):
            mkcloud.validate_environment_matrix(wrong_arch, self.platforms)

        unsupported_claim = copy.deepcopy(self.raw)
        unsupported = next(
            entry
            for entry in unsupported_claim["entries"]
            if entry["id"] == "aws-nitro-x86_64"
        )
        unsupported["artifact_status"] = "host-verified"
        with self.assertRaisesRegex(ValueError, "buildable matrix entry"):
            mkcloud.validate_environment_matrix(unsupported_claim, self.platforms)

        duplicated = copy.deepcopy(self.raw)
        duplicate = copy.deepcopy(duplicated["entries"][0])
        duplicate["id"] = "duplicate-qemu"
        duplicated["entries"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate platform/environment"):
            mkcloud.validate_environment_matrix(duplicated, self.platforms)

    def test_unknown_fields_and_noncanonical_json_fail(self) -> None:
        extra = copy.deepcopy(self.raw)
        extra["entries"][0]["marketing_claim"] = "runs everywhere"
        with self.assertRaisesRegex(ValueError, "field set"):
            mkcloud.validate_environment_matrix(extra, self.platforms)

        with tempfile.TemporaryDirectory(prefix="troe-cloud-matrix-") as directory:
            path = Path(directory) / "matrix.json"
            path.write_text(json.dumps(self.raw), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not canonical JSON"):
                mkcloud.load_environment_matrix(path, self.platforms)


class CloudBundleTests(unittest.TestCase):
    """Verify reproducibility, exact partition payloads, and bundle corruption."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.platforms = mkcloud.load_platform_manifest()
        cls.entries = mkcloud.load_environment_matrix(platforms=cls.platforms)
        cls.platform = cls.platforms["x86_64-q35-uefi"]
        cls.environment = mkcloud.resolve_environment(
            cls.entries, "x86_64-q35-uefi", "qemu"
        )
        cls.efi = fake_efi(
            "x86_64",
            b"deterministic cloud test EFI\0"
            + b"x86_64-q35-uefi\0"
            + mkstorage.build_manifest(),
        )
        cls.boot = mkfat.build(
            cls.efi,
            mkfat.BOOT_NAMES["x86_64"],
            mkstorage.build_manifest(),
        )
        root = bytearray(mkcloud.SYSTEM_ROOT_SECTORS * mkcloud.SECTOR_BYTES)
        root[:32] = b"synthetic-root-start".ljust(32, b"!")
        root[-32:] = b"root-payload-end".ljust(32, b"!")
        root[1024 + 104 : 1024 + 120] = mkstorage.FILESYSTEM_UUID
        cls.root_payload = bytes(root)
        cls.root_source = mkstorage.build_gpt(cls.root_payload)
        cls.fixture_cspk = b"CSPKv1\0\0" + b"".join(
            sorted(mkcontent.RESERVED_FIXTURE_IDS)
        )
        cls.deployment_cspk = b"CSPKv1\0\0deployment-identities"

    @classmethod
    def root_length_only(cls, payload: bytes) -> bytes:
        if len(payload) != mkcloud.SYSTEM_ROOT_SECTORS * mkcloud.SECTOR_BYTES:
            raise ValueError("test root length mismatch")
        return cls.fixture_cspk

    def assemble(self) -> tuple[dict[str, bytes], dict[str, object]]:
        with mock.patch.object(
            mkcloud, "verify_root_payload", side_effect=self.root_length_only
        ):
            return mkcloud.assemble_bundle(
                platform=self.platform,
                environment=self.environment,
                boot_fat=self.boot,
                root_source=self.root_source,
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            )

    @staticmethod
    def write_bundle(
        directory: Path, images: dict[str, bytes], manifest: dict[str, object]
    ) -> None:
        directory.mkdir()
        for role, filename in mkcloud.BUNDLE_FILENAMES.items():
            (directory / filename).write_bytes(images[role])
        (directory / mkcloud.BUNDLE_MANIFEST).write_bytes(
            mkcloud._canonical_json(manifest)
        )

    def test_bundle_is_reproducible_and_has_exact_partition_geometry(self) -> None:
        first_images, first_manifest = self.assemble()
        second_images, second_manifest = self.assemble()
        self.assertEqual(first_images, second_images)
        self.assertEqual(first_manifest, second_manifest)

        system = mkcloud.parse_gpt(first_images["system"])
        self.assertEqual(system.disk_guid, mkstorage.DISK_GUID)
        self.assertEqual(system.total_sectors, mkcloud.SYSTEM_TOTAL_SECTORS)
        self.assertEqual(
            [(item.name, item.first_lba, item.last_lba) for item in system.partitions],
            [
                (
                    "esp",
                    mkcloud.SYSTEM_ESP_START_LBA,
                    mkcloud.SYSTEM_ESP_START_LBA + mkcloud.SYSTEM_ESP_SECTORS - 1,
                ),
                (
                    "root",
                    mkcloud.SYSTEM_ROOT_START_LBA,
                    mkcloud.SYSTEM_ROOT_START_LBA + mkcloud.SYSTEM_ROOT_SECTORS - 1,
                ),
            ],
        )
        self.assertEqual(system.partitions[1].payload, self.root_payload)
        esp = system.partitions[0].payload
        self.assertEqual(
            mkcloud.verify_esp_payload(
                esp,
                "x86_64",
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            ),
            self.efi,
        )
        self.assertEqual(esp[82:90], b"FAT32   ")

        activation = mkcloud.parse_gpt(first_images["activation"])
        state = mkcloud.parse_gpt(first_images["state"])
        self.assertFalse(any(activation.partitions[0].payload))
        self.assertFalse(any(state.partitions[0].payload))
        self.assertTrue(first_manifest["disks"][1]["writable"])
        self.assertTrue(first_manifest["disks"][0]["writable"])

    def test_every_qemu_platform_matrix_entry_assembles_on_the_host(self) -> None:
        qemu_entries = [
            entry
            for entry in self.entries
            if entry["environment"] == "qemu"
            and entry["artifact_status"] == "host-verified"
        ]
        self.assertEqual(len(qemu_entries), 4)
        for environment in qemu_entries:
            platform = self.platforms[str(environment["platform"])]
            architecture = str(platform["architecture"])
            efi = fake_efi(
                architecture,
                str(platform["name"]).encode("ascii")
                + b"\0"
                + mkstorage.build_manifest(),
            )
            boot = mkfat.build(
                efi,
                mkfat.BOOT_NAMES[architecture],
                mkstorage.build_manifest(),
            )
            with (
                self.subTest(platform=platform["name"]),
                mock.patch.object(
                    mkcloud,
                    "verify_root_payload",
                    side_effect=self.root_length_only,
                ),
            ):
                images, manifest = mkcloud.assemble_bundle(
                    platform=platform,
                    environment=environment,
                    boot_fat=boot,
                    root_source=self.root_source,
                    bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
                )
                self.assertEqual(manifest["platform"], platform["name"])
                self.assertEqual(manifest["architecture"], architecture)
                self.assertEqual(len(images["system"]), 52 * 1024 * 1024)

    def test_bundle_verifier_recomputes_every_hash_and_rejects_extra_files(
        self,
    ) -> None:
        images, manifest = self.assemble()
        with tempfile.TemporaryDirectory(prefix="troe-cloud-bundle-") as temporary:
            bundle = Path(temporary) / "bundle"
            self.write_bundle(bundle, images, manifest)
            with mock.patch.object(
                mkcloud, "verify_root_payload", side_effect=self.root_length_only
            ):
                with self.assertRaisesRegex(ValueError, "explicit verification"):
                    mkcloud.verify_bundle(bundle)
                self.assertEqual(
                    mkcloud.verify_bundle(bundle, allow_test_artifacts=True),
                    manifest,
                )

                system = bundle / mkcloud.BUNDLE_FILENAMES["system"]
                corrupted = bytearray(system.read_bytes())
                root_offset = mkcloud.SYSTEM_ROOT_START_LBA * mkcloud.SECTOR_BYTES
                corrupted[root_offset + 123] ^= 1
                system.write_bytes(corrupted)
                with self.assertRaisesRegex(ValueError, "metadata does not exactly"):
                    mkcloud.verify_bundle(bundle, allow_test_artifacts=True)

                system.write_bytes(images["system"][:-1])
                with self.assertRaises(ValueError):
                    mkcloud.verify_bundle(bundle, allow_test_artifacts=True)

                system.write_bytes(images["system"])
                (bundle / "unexpected").write_bytes(b"surprise")
                with self.assertRaisesRegex(ValueError, "unexpected files"):
                    mkcloud.verify_bundle(bundle, allow_test_artifacts=True)

    def test_atomic_builder_refuses_overwrite_and_verifies_published_bundle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-cloud-build-") as temporary:
            base = Path(temporary)
            boot = base / "boot.img"
            root = base / "root.img"
            output = base / "bundle"
            boot.write_bytes(self.boot)
            root.write_bytes(self.root_source)
            with mock.patch.object(
                mkcloud, "verify_root_payload", side_effect=self.root_length_only
            ):
                manifest = mkcloud.build_bundle(
                    platform_name="x86_64-q35-uefi",
                    environment_name="qemu",
                    boot_path=boot,
                    root_path=root,
                    output_directory=output,
                    bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
                )
                self.assertEqual(
                    mkcloud.verify_bundle(output, allow_test_artifacts=True),
                    manifest,
                )
                with self.assertRaisesRegex(ValueError, "already exists"):
                    mkcloud.build_bundle(
                        platform_name="x86_64-q35-uefi",
                        environment_name="qemu",
                        boot_path=boot,
                        root_path=root,
                        output_directory=output,
                        bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
                    )

    def test_semantic_root_verification_uses_independent_ext4_parser(self) -> None:
        payload = bytes(mkcloud.SYSTEM_ROOT_SECTORS * mkcloud.SECTOR_BYTES)
        content = b"CSPKv1\0test"
        with (
            mock.patch.object(mkcloud, "_extract_root_content", return_value=content),
            mock.patch.object(mkcloud.mkstorage, "verify_ext4") as verifier,
        ):
            self.assertEqual(mkcloud.verify_root_payload(payload), content)
        verifier.assert_called_once_with(payload, content)

    def test_esp_corruption_and_wrong_architecture_fail(self) -> None:
        esp = mkcloud.build_fat32_esp(self.efi, "x86_64")
        self.assertEqual(
            mkcloud.verify_esp_payload(
                esp,
                "x86_64",
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            ),
            self.efi,
        )
        corrupt = bytearray(esp)
        corrupt[82] ^= 1
        with self.assertRaisesRegex(ValueError, "boot sector"):
            mkcloud.verify_esp_payload(
                bytes(corrupt),
                "x86_64",
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            )
        with self.assertRaises(ValueError):
            mkcloud.verify_esp_payload(
                esp,
                "aarch64",
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            )

        renamed = mkcloud.build_fat32_esp(self.efi, "aarch64")
        with self.assertRaisesRegex(ValueError, "architecture-native"):
            mkcloud.verify_esp_payload(
                renamed,
                "aarch64",
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            )

    def test_pe_header_bounds_signature_magic_and_subsystem_fail_closed(self) -> None:
        cases: list[tuple[str, bytes, str]] = []

        cases.append(("short DOS header", b"MZ", "bounded DOS header"))

        bad_offset = bytearray(self.efi)
        struct.pack_into("<I", bad_offset, 0x3C, len(bad_offset) - 4)
        cases.append(("unbounded e_lfanew", bytes(bad_offset), "signature offset"))

        bad_signature = bytearray(self.efi)
        bad_signature[0x80:0x84] = b"PX\0\0"
        cases.append(("PE signature", bytes(bad_signature), "signature offset"))

        bad_magic = bytearray(self.efi)
        struct.pack_into("<H", bad_magic, 0x80 + 24, 0x010B)
        cases.append(("optional magic", bytes(bad_magic), "architecture-native"))

        bad_subsystem = bytearray(self.efi)
        struct.pack_into("<H", bad_subsystem, 0x80 + 24 + 68, 3)
        cases.append(("subsystem", bytes(bad_subsystem), "architecture-native"))

        for label, efi, message in cases:
            with self.subTest(case=label):
                esp = mkcloud.build_fat32_esp(efi, "x86_64")
                with self.assertRaisesRegex(ValueError, message):
                    mkcloud.verify_esp_payload(
                        esp,
                        "x86_64",
                        bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
                    )

    def test_fat32_backup_allocation_directories_and_unused_space_fail_closed(
        self,
    ) -> None:
        esp = mkcloud.build_fat32_esp(self.efi, "x86_64")
        cases: list[tuple[str, bytearray, str]] = []

        backup_boot = bytearray(esp)
        backup_boot[mkcloud.FAT32_BACKUP_BOOT_SECTOR * mkcloud.SECTOR_BYTES + 82] ^= 1
        cases.append(("backup boot", backup_boot, "backup boot"))

        fsinfo = bytearray(esp)
        for sector in (
            mkcloud.FAT32_FSINFO_SECTOR,
            mkcloud.FAT32_BACKUP_FSINFO_SECTOR,
        ):
            offset = sector * mkcloud.SECTOR_BYTES + 488
            value = struct.unpack_from("<I", fsinfo, offset)[0]
            struct.pack_into("<I", fsinfo, offset, value - 1)
        cases.append(("FSInfo accounting", fsinfo, "allocation accounting"))

        second_fat = bytearray(esp)
        second_fat_offset = (
            mkcloud.FAT32_RESERVED_SECTORS + mkcloud.FAT32_FAT_SECTORS
        ) * mkcloud.SECTOR_BYTES
        second_fat[second_fat_offset + 4 * mkcloud.FAT32_FIRST_FILE_CLUSTER] ^= 1
        cases.append(("FAT copy", second_fat, "allocation tables differ"))

        chain = bytearray(esp)
        first_fat_offset = mkcloud.FAT32_RESERVED_SECTORS * mkcloud.SECTOR_BYTES
        fat_bytes = mkcloud.FAT32_FAT_SECTORS * mkcloud.SECTOR_BYTES
        for offset in (first_fat_offset, first_fat_offset + fat_bytes):
            struct.pack_into(
                "<I",
                chain,
                offset + 4 * mkcloud.FAT32_FIRST_FILE_CLUSTER,
                0,
            )
        cases.append(("FAT chain", chain, "allocation table is not canonical"))

        directory = bytearray(esp)
        directory[mkcloud._fat32_cluster_offset(mkcloud.FAT32_ROOT_CLUSTER) + 100] = 1
        cases.append(("directory", directory, "root directory"))

        unused = bytearray(esp)
        file_clusters = (
            len(self.efi) + mkcloud.SECTOR_BYTES - 1
        ) // mkcloud.SECTOR_BYTES
        next_cluster = mkcloud.FAT32_FIRST_FILE_CLUSTER + file_clusters
        unused[mkcloud._fat32_cluster_offset(next_cluster)] = 1
        cases.append(("unused cluster", unused, "unused data clusters"))

        for label, corrupt, message in cases:
            with self.subTest(case=label):
                with self.assertRaisesRegex(ValueError, message):
                    mkcloud.verify_esp_payload(
                        bytes(corrupt),
                        "x86_64",
                        bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
                    )

    def test_acceptance_only_efi_is_never_packaged_as_production(self) -> None:
        self.assertEqual(
            mkcloud.PRODUCTION_FORBIDDEN_MARKERS,
            production_build.PRODUCTION_FORBIDDEN_MARKERS,
        )
        for marker in mkcloud.PRODUCTION_FORBIDDEN_MARKERS:
            with self.subTest(marker=marker):
                boot = mkfat.build(
                    fake_efi("x86_64", marker), mkfat.BOOT_NAMES["x86_64"]
                )
                efi = mkfat.extract(boot, mkfat.BOOT_NAMES["x86_64"])
                esp = mkcloud.build_fat32_esp(efi, "x86_64")
                with self.assertRaisesRegex(ValueError, "acceptance-only"):
                    mkcloud.verify_esp_payload(
                        esp,
                        "x86_64",
                        bundle_kind=mkcloud.BUNDLE_KIND_PRODUCTION,
                    )

    def test_acceptance_bundle_requires_explicit_build_and_verify_authority(
        self,
    ) -> None:
        acceptance_efi = self.efi + mkcloud.PRODUCTION_FORBIDDEN_MARKERS[0]
        acceptance_boot = mkfat.build(
            acceptance_efi,
            mkfat.BOOT_NAMES["x86_64"],
            mkstorage.build_manifest(),
        )
        with mock.patch.object(
            mkcloud,
            "verify_root_payload",
            side_effect=self.root_length_only,
        ):
            images, manifest = mkcloud.assemble_bundle(
                platform=self.platform,
                environment=self.environment,
                boot_fat=acceptance_boot,
                root_source=self.root_source,
                bundle_kind=mkcloud.BUNDLE_KIND_ACCEPTANCE,
            )
        self.assertEqual(manifest["kind"], mkcloud.BUNDLE_KIND_ACCEPTANCE)
        with tempfile.TemporaryDirectory(prefix="troe-cloud-acceptance-") as temporary:
            bundle = Path(temporary) / "bundle"
            self.write_bundle(bundle, images, manifest)
            with mock.patch.object(
                mkcloud,
                "verify_root_payload",
                side_effect=self.root_length_only,
            ):
                with self.assertRaisesRegex(ValueError, "explicit verification"):
                    mkcloud.verify_bundle(bundle)
                self.assertEqual(
                    mkcloud.verify_bundle(
                        bundle,
                        allow_test_artifacts=True,
                    ),
                    manifest,
                )

    def test_bundle_kinds_enforce_fixture_identity_and_probe_separation(self) -> None:
        with (
            mock.patch.object(
                mkcloud,
                "verify_root_payload",
                return_value=self.fixture_cspk,
            ),
            self.assertRaisesRegex(ValueError, "reserved fixture identities"),
        ):
            mkcloud.assemble_bundle(
                platform=self.platform,
                environment=self.environment,
                boot_fat=self.boot,
                root_source=self.root_source,
                bundle_kind=mkcloud.BUNDLE_KIND_PRODUCTION,
            )

        with (
            mock.patch.object(
                mkcloud,
                "verify_root_payload",
                return_value=self.deployment_cspk,
            ),
            self.assertRaisesRegex(ValueError, "all reserved fixture identities"),
        ):
            mkcloud.assemble_bundle(
                platform=self.platform,
                environment=self.environment,
                boot_fat=self.boot,
                root_source=self.root_source,
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            )

        with mock.patch.object(
            mkcloud,
            "verify_root_payload",
            return_value=self.deployment_cspk,
        ):
            images, manifest = mkcloud.assemble_bundle(
                platform=self.platform,
                environment=self.environment,
                boot_fat=self.boot,
                root_source=self.root_source,
                bundle_kind=mkcloud.BUNDLE_KIND_PRODUCTION,
            )
        self.assertEqual(manifest["kind"], mkcloud.BUNDLE_KIND_PRODUCTION)
        with tempfile.TemporaryDirectory(prefix="troe-cloud-production-") as temporary:
            bundle = Path(temporary) / "bundle"
            self.write_bundle(bundle, images, manifest)
            with mock.patch.object(
                mkcloud,
                "verify_root_payload",
                return_value=self.deployment_cspk,
            ):
                self.assertEqual(mkcloud.verify_bundle(bundle), manifest)

    def test_selected_platform_and_boot_manifest_bind_the_root(self) -> None:
        wrong_platform_efi = fake_efi(
            "x86_64", b"aarch64-sbsa-ref\0" + mkstorage.build_manifest()
        )
        wrong_platform_boot = mkfat.build(
            wrong_platform_efi,
            mkfat.BOOT_NAMES["x86_64"],
            mkstorage.build_manifest(),
        )
        with (
            mock.patch.object(
                mkcloud, "verify_root_payload", side_effect=self.root_length_only
            ),
            self.assertRaisesRegex(ValueError, "platform identity"),
        ):
            mkcloud.assemble_bundle(
                platform=self.platform,
                environment=self.environment,
                boot_fat=wrong_platform_boot,
                root_source=self.root_source,
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            )

        source = mkcloud.parse_gpt(self.root_source)
        wrong_guid = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeef")
        wrong_root_source = mkcloud.build_gpt(
            wrong_guid, source.total_sectors, source.partitions
        )
        with (
            mock.patch.object(
                mkcloud, "verify_root_payload", side_effect=self.root_length_only
            ),
            self.assertRaisesRegex(ValueError, "does not select the packaged root"),
        ):
            mkcloud.assemble_bundle(
                platform=self.platform,
                environment=self.environment,
                boot_fat=self.boot,
                root_source=wrong_root_source,
                bundle_kind=mkcloud.BUNDLE_KIND_DEVELOPMENT,
            )


if __name__ == "__main__":
    unittest.main()

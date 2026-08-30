"""Hosted setup-troe provisioning policy, target safety, and record tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_cloud_artifacts import fake_efi
from tools import mkcloud, mkcontent, mkfat, mkstorage, setup_troe


def _synthetic_root() -> bytes:
    """Build one deterministic root payload of the exact profile length."""
    root = bytearray(mkcloud.SYSTEM_ROOT_SECTORS * mkcloud.SECTOR_BYTES)
    root[:32] = b"synthetic-root-start".ljust(32, b"!")
    root[-32:] = b"root-payload-end".ljust(32, b"!")
    root[1024 + 104 : 1024 + 120] = mkstorage.FILESYSTEM_UUID
    return bytes(root)


class SetupTroeTests(unittest.TestCase):
    """setup-troe verifies before it mutates and never reports a partial install."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.platforms = mkcloud.load_platform_manifest(mkcloud.PLATFORM_MANIFEST_PATH)
        cls.platform = cls.platforms["x86_64-q35-uefi"]
        cls.entries = mkcloud.load_environment_matrix(
            mkcloud.ENVIRONMENT_MATRIX_PATH, cls.platforms
        )
        cls.environment = mkcloud.resolve_environment(
            cls.entries, "x86_64-q35-uefi", "qemu"
        )
        cls.root_source = mkstorage.build_gpt(_synthetic_root())
        cls.fixture_cspk = b"CSPKv1\0\0" + b"".join(sorted(mkcontent.RESERVED_FIXTURE_IDS))
        cls.deployment_cspk = b"CSPKv1\0\0deployment-identities"
        cls.boot = {
            kind: cls.build_boot(kind) for kind in mkcloud.BUNDLE_KINDS
        }
        cls._assembled = {}

    @classmethod
    def build_boot(cls, bundle_kind: str) -> bytes:
        """Build the boot image whose ESP matches one bundle kind's policy."""
        payload = (
            b"deterministic cloud test EFI\0"
            + b"x86_64-q35-uefi\0"
            + mkstorage.build_manifest()
        )
        if bundle_kind == mkcloud.BUNDLE_KIND_ACCEPTANCE:
            payload += b"KEX-ACCEPTANCE-DESTRUCTIVE-v1\0"
        efi = fake_efi("x86_64", payload)
        return mkfat.build(efi, mkfat.BOOT_NAMES["x86_64"], mkstorage.build_manifest())

    def setUp(self) -> None:
        self.cspk = self.fixture_cspk
        self._patch = mock.patch.object(
            mkcloud, "verify_root_payload", side_effect=lambda payload: self.cspk
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    @classmethod
    def assembled(cls, kind: str) -> tuple[dict[str, bytes], dict[str, object]]:
        """Return the one immutable 56 MiB image set that defines one kind.

        Assembly is deterministic for a fixed platform, environment, boot image,
        and kind, and `test_cloud_artifacts` owns that reproducibility contract.
        Every test republishes these images into its own destination and then
        edits only the published files, so assembling once per class removes
        repeated work without weakening an assertion.
        """
        if kind not in cls._assembled:
            cls._assembled[kind] = mkcloud.assemble_bundle(
                platform=cls.platform,
                environment=cls.environment,
                boot_fat=cls.boot[kind],
                root_source=cls.root_source,
                bundle_kind=kind,
            )
        return cls._assembled[kind]

    def write_bundle(self, kind: str = mkcloud.BUNDLE_KIND_DEVELOPMENT, name: str = "bundle") -> Path:
        """Publish one synthetic bundle of the requested kind."""
        self.cspk = (
            self.deployment_cspk
            if kind == mkcloud.BUNDLE_KIND_PRODUCTION
            else self.fixture_cspk
        )
        images, manifest = self.assembled(kind)
        directory = self.root / name
        directory.mkdir()
        for role, filename in mkcloud.BUNDLE_FILENAMES.items():
            (directory / filename).write_bytes(images[role])
        (directory / mkcloud.BUNDLE_MANIFEST).write_bytes(
            mkcloud._canonical_json(manifest)  # noqa: SLF001 - format fixture
        )
        return directory

    def test_production_mode_refuses_test_artifact_bundles(self) -> None:
        for kind in (mkcloud.BUNDLE_KIND_DEVELOPMENT, mkcloud.BUNDLE_KIND_ACCEPTANCE):
            with self.subTest(kind=kind):
                bundle = self.write_bundle(kind, name=f"bundle-{kind}")
                destination = self.root / f"machine-{kind}"
                with self.assertRaises(setup_troe.SetupError) as raised:
                    setup_troe.install(bundle=bundle, runtime_dir=destination)
                self.assertEqual(raised.exception.code, "bundle-rejected")
                self.assertFalse(destination.exists())

    def test_install_verifies_every_target_byte_and_records_completion(self) -> None:
        bundle = self.write_bundle()
        destination = self.root / "machine"
        record = setup_troe.install(
            bundle=bundle, runtime_dir=destination, allow_test_artifacts=True
        )
        self.assertEqual(record["state"], setup_troe.STATE_VERIFIED)
        self.assertEqual(record["format"], setup_troe.RECORD_FORMAT)
        self.assertEqual(
            [entry["role"] for entry in record["targets"]], list(setup_troe.ROLES)
        )
        for entry in record["targets"]:
            installed = Path(str(entry["path"]))
            self.assertEqual(entry["installed_sha256"], entry["expected_sha256"])
            self.assertEqual(installed.stat().st_size, entry["image_bytes"])
            self.assertEqual(
                installed.read_bytes(),
                (bundle / installed.name).read_bytes(),
                "installed bytes must equal the verified seed bytes",
            )

    def test_published_seed_bundle_is_never_mutated(self) -> None:
        bundle = self.write_bundle()
        before = {
            path.name: path.read_bytes() for path in sorted(bundle.iterdir())
        }
        setup_troe.install(
            bundle=bundle, runtime_dir=self.root / "machine", allow_test_artifacts=True
        )
        after = {path.name: path.read_bytes() for path in sorted(bundle.iterdir())}
        self.assertEqual(before, after)

    def test_record_is_canonical_json_and_omits_no_declared_field(self) -> None:
        bundle = self.write_bundle()
        destination = self.root / "machine"
        record = setup_troe.install(
            bundle=bundle, runtime_dir=destination, allow_test_artifacts=True
        )
        raw = (destination / setup_troe.RECORD_FILENAME).read_bytes()
        self.assertEqual(raw, setup_troe.canonical_json(record))
        self.assertEqual(json.loads(raw), record)
        self.assertNotIn("key", raw.decode("utf-8").lower().replace("matrix_entry", ""))

    def test_corrupt_bundle_is_refused_before_any_destination_mutation(self) -> None:
        for filename in sorted(mkcloud.BUNDLE_FILENAMES.values()):
            with self.subTest(filename=filename):
                bundle = self.write_bundle(name=f"bundle-{filename}")
                payload = bytearray((bundle / filename).read_bytes())
                payload[-1] ^= 0xFF
                (bundle / filename).write_bytes(bytes(payload))
                destination = self.root / f"machine-{filename}"
                with self.assertRaises(setup_troe.SetupError) as raised:
                    setup_troe.install(
                        bundle=bundle,
                        runtime_dir=destination,
                        allow_test_artifacts=True,
                    )
                self.assertEqual(raised.exception.code, "bundle-rejected")
                self.assertFalse(destination.exists())

    def test_unexpected_bundle_file_is_refused(self) -> None:
        bundle = self.write_bundle()
        (bundle / "extra.raw").write_bytes(b"unexpected")
        with self.assertRaises(setup_troe.SetupError) as raised:
            setup_troe.install(
                bundle=bundle,
                runtime_dir=self.root / "machine",
                allow_test_artifacts=True,
            )
        self.assertEqual(raised.exception.code, "bundle-rejected")

    def test_existing_destination_is_never_reused(self) -> None:
        bundle = self.write_bundle()
        destination = self.root / "machine"
        setup_troe.install(
            bundle=bundle, runtime_dir=destination, allow_test_artifacts=True
        )
        with self.assertRaises(setup_troe.SetupError) as raised:
            setup_troe.install(
                bundle=bundle, runtime_dir=destination, allow_test_artifacts=True
            )
        self.assertEqual(raised.exception.code, "target-exists")

    def test_symlinked_destination_is_refused(self) -> None:
        bundle = self.write_bundle()
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(setup_troe.SetupError) as raised:
            setup_troe.install(
                bundle=bundle, runtime_dir=link, allow_test_artifacts=True
            )
        self.assertEqual(raised.exception.code, "target-symlink")

    def test_runtime_directory_is_private(self) -> None:
        bundle = self.write_bundle()
        destination = self.root / "machine"
        setup_troe.install(
            bundle=bundle, runtime_dir=destination, allow_test_artifacts=True
        )
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)

    def test_device_roles_require_explicit_assignment(self) -> None:
        for entries in (["/dev/one"], ["system=/dev/a", "system=/dev/b"], ["bogus=/dev/a"], ["system="]):
            with self.subTest(entries=entries):
                with self.assertRaises(setup_troe.SetupError):
                    setup_troe._parse_devices(entries)  # noqa: SLF001 - closed surface
        self.assertEqual(
            setup_troe._parse_devices(  # noqa: SLF001 - closed surface
                ["system=/dev/a", "activation=/dev/b", "state=/dev/c"]
            ),
            {"system": "/dev/a", "activation": "/dev/b", "state": "/dev/c"},
        )

    def test_incomplete_role_set_is_refused(self) -> None:
        bundle = self.write_bundle()
        with self.assertRaises(setup_troe.SetupError) as raised:
            setup_troe.install(
                bundle=bundle,
                device_targets={"system": "/dev/a"},
                record_path=self.root / "record.json",
                allow_test_artifacts=True,
            )
        self.assertEqual(raised.exception.code, "target-selection")

    def test_device_install_requires_a_durable_record_path(self) -> None:
        bundle = self.write_bundle()
        with self.assertRaises(setup_troe.SetupError) as raised:
            setup_troe.install(
                bundle=bundle,
                device_targets={
                    "system": "/dev/a",
                    "activation": "/dev/b",
                    "state": "/dev/c",
                },
                allow_test_artifacts=True,
            )
        self.assertEqual(raised.exception.code, "record-required")

    def test_exactly_one_destination_mode_is_accepted(self) -> None:
        bundle = self.write_bundle()
        with self.assertRaises(setup_troe.SetupError) as raised:
            setup_troe.install(bundle=bundle, allow_test_artifacts=True)
        self.assertEqual(raised.exception.code, "target-selection")
        with self.assertRaises(setup_troe.SetupError) as raised:
            setup_troe.install(
                bundle=bundle,
                runtime_dir=self.root / "machine",
                device_targets={"system": "/dev/a", "activation": "/dev/b", "state": "/dev/c"},
                allow_test_artifacts=True,
            )
        self.assertEqual(raised.exception.code, "target-selection")

    def test_missing_bundle_is_refused(self) -> None:
        with self.assertRaises(setup_troe.SetupError) as raised:
            setup_troe.install(
                bundle=self.root / "absent",
                runtime_dir=self.root / "machine",
                allow_test_artifacts=True,
            )
        self.assertEqual(raised.exception.code, "bundle-missing")

    def test_production_bundle_installs_without_test_artifact_authority(self) -> None:
        bundle = self.write_bundle(mkcloud.BUNDLE_KIND_PRODUCTION, name="production")
        destination = self.root / "production-machine"
        record = setup_troe.install(bundle=bundle, runtime_dir=destination)
        self.assertEqual(record["state"], setup_troe.STATE_VERIFIED)
        self.assertEqual(record["bundle"]["kind"], mkcloud.BUNDLE_KIND_PRODUCTION)
        for entry in record["targets"]:
            self.assertEqual(entry["installed_sha256"], entry["expected_sha256"])

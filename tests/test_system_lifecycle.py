"""Power-loss, migration, rollback, GC, trust, and CLI lifecycle tests."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools import package_model, package_trust, system_lifecycle


TARGET = "x86_64-unknown-uefi"
NOW = 2_000_000
REPO_ROOT = Path(__file__).resolve().parents[1]
SYSTEM_CLI = REPO_ROOT / "tools/troe_system.py"


class LifecycleFixtures:
    """Create one reusable root role and independently signed package releases."""

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("openssl") is None:
            raise unittest.SkipTest("OpenSSL unavailable")
        cls.key_directory = tempfile.TemporaryDirectory(prefix="troe-lifecycle-keys-")
        cls.keys_root = Path(cls.key_directory.name)
        cls.root_key = cls.make_key("root")
        cls.snapshot_key = cls.make_key("snapshot")
        cls.publisher_key = cls.make_key("publisher")
        cls.builder_one_key = cls.make_key("builder-one")
        cls.builder_two_key = cls.make_key("builder-two")
        cls.root_envelope = cls.make_root_envelope()
        cls.root_anchor = package_model.sha256(cls.root_envelope.payload)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.key_directory.cleanup()

    @classmethod
    def make_key(cls, name: str) -> Path:
        path = cls.keys_root / f"{name}.pem"
        subprocess.run(
            ("openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(path)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return path

    @classmethod
    def key_record(cls, key: Path) -> dict[str, str]:
        return package_trust.key_record(package_trust.public_key_der_from_private(key))

    @classmethod
    def make_root_envelope(cls) -> package_trust.Envelope:
        records = sorted(
            (
                cls.key_record(cls.root_key),
                cls.key_record(cls.snapshot_key),
                cls.key_record(cls.publisher_key),
                cls.key_record(cls.builder_one_key),
                cls.key_record(cls.builder_two_key),
            ),
            key=lambda record: record["key_id"],
        )
        document = {
            "expires": NOW + 100_000,
            "generation": 1,
            "issued_at": NOW - 100,
            "keys": records,
            "previous_root_sha256": None,
            "publishers": [
                {
                    "key_ids": [cls.key_record(cls.publisher_key)["key_id"]],
                    "package": "hello",
                    "threshold": 1,
                },
                {
                    "key_ids": [cls.key_record(cls.publisher_key)["key_id"]],
                    "package": "library",
                    "threshold": 1,
                },
            ],
            "recovery_packages": [],
            "revocations": [],
            "roles": {
                "provenance": {
                    "key_ids": sorted(
                        (
                            cls.key_record(cls.builder_one_key)["key_id"],
                            cls.key_record(cls.builder_two_key)["key_id"],
                        )
                    ),
                    "threshold": 2,
                },
                "root": {
                    "key_ids": [cls.key_record(cls.root_key)["key_id"]],
                    "threshold": 1,
                },
                "snapshot": {
                    "key_ids": [cls.key_record(cls.snapshot_key)["key_id"]],
                    "threshold": 1,
                },
            },
            "schema": 1,
            "type": "root",
        }
        return package_trust.sign_payload(document, [cls.root_key])

    @staticmethod
    def package_document(
        version: tuple[int, int, int], artifact: bytes
    ) -> dict[str, object]:
        return {
            "capabilities": ["timer.wait"],
            "dependencies": [],
            "directories": [{"name": "state", "rights": "read-mutate", "role": "data"}],
            "name": "hello",
            "resources": {
                "execution_ms": 50,
                "handles": 2,
                "heap_bytes": 1_048_576,
                "stack_bytes": 65_536,
            },
            "schema": 1,
            "services": [{"command": "hello", "name": "hello.service"}],
            "targets": [
                {
                    "abi": [1, 1],
                    "architecture": "x86_64",
                    "artifact_bytes": len(artifact),
                    "artifact_sha256": package_model.sha256(artifact),
                    "sdk_sha256": package_model.sha256(b"sdk"),
                    "target": TARGET,
                    "toolchain_sha256": package_model.sha256(b"toolchain"),
                }
            ],
            "version": list(version),
        }

    @classmethod
    def release(
        cls, version: tuple[int, int, int], sequence: int
    ) -> tuple[package_model.TargetLock, system_lifecycle.ReleaseInput]:
        artifact = f"hello-{version}".encode("ascii")
        manifest = package_model.parse_manifest(
            package_model.canonical_json(cls.package_document(version, artifact))
        )
        lock = package_model.resolve("hello", TARGET, [manifest])
        package = package_model.build_package(manifest, lock, artifact)
        return lock, cls.signed_release(manifest, lock, package, sequence)

    @classmethod
    def signed_release(
        cls,
        manifest: package_model.Manifest,
        lock: package_model.TargetLock,
        package: bytes,
        sequence: int,
    ) -> system_lifecycle.ReleaseInput:
        release_document = {
            "expires": NOW + 50_000,
            "lock_sha256": lock.digest(),
            "manifest_sha256": manifest.digest(),
            "name": manifest.name,
            "package_bytes": len(package),
            "package_sha256": package_model.sha256(package),
            "provenance": {
                "build_recipe_sha256": package_model.sha256(b"recipe"),
                "builder": "builder.production",
                "reproducible_sha256": package_model.sha256(package),
                "source_sha256": package_model.sha256(b"source"),
            },
            "published_at": NOW - 10,
            "schema": 1,
            "sequence": sequence,
            "target": TARGET,
            "type": "release",
            "version": manifest.version.json(),
        }
        envelope = package_trust.sign_payload(
            release_document,
            [cls.publisher_key, cls.builder_one_key, cls.builder_two_key],
        )
        return system_lifecycle.ReleaseInput(envelope.bytes(), package)

    @staticmethod
    def migration(
        from_version: tuple[int, int, int],
        to_version: tuple[int, int, int],
        mode: str = "reversible",
    ) -> system_lifecycle.Migration:
        document = {
            "from_version": list(from_version),
            "mode": mode,
            "operations": [{"op": "set", "path": ["schema"], "value": to_version[0]}],
            "package": "hello",
            "schema": 1,
            "to_version": list(to_version),
        }
        return system_lifecycle.parse_migration(package_model.canonical_json(document))

    @classmethod
    def deploy_release(
        cls,
        store: system_lifecycle.LifecycleStore,
        version: tuple[int, int, int],
        sequence: int,
        *,
        migrations: tuple[system_lifecycle.Migration, ...] = (),
        allow_downgrade: tuple[str, ...] = (),
    ) -> tuple[int, system_lifecycle.ReleaseInput]:
        lock, release = cls.release(version, sequence)
        generation = store.deploy(
            package_model.canonical_json(lock.json()),
            cls.root_envelope.bytes(),
            cls.root_anchor,
            [release],
            now=NOW,
            migrations=migrations,
            allow_downgrade=allow_downgrade,
        )
        return generation, release

    @staticmethod
    def write_data(root: Path, value: dict[str, object]) -> None:
        (root / "data/hello.json").write_bytes(package_model.canonical_json(value))

    @staticmethod
    def read_data(root: Path) -> dict[str, object]:
        return json.loads((root / "data/hello.json").read_bytes())


class ActivationTests(LifecycleFixtures, unittest.TestCase):
    """Exercise clean install, configuration identity, health, and verification."""

    def test_clean_install_is_verified_pending_then_healthy_and_reopenable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = system_lifecycle.LifecycleStore(root)
            projection = system_lifecycle.projection_bytes(
                (("hello/endpoint", b"https://service.invalid"),)
            )
            desired_digest = store.set_desired_configuration(projection)
            generation, _release = self.deploy_release(store, (1, 0, 0), 1)
            self.assertEqual(generation, 1)
            self.assertEqual(store.status()["status"], "pending")
            pointer = store.mark_health(generation, True)
            self.assertEqual(pointer["active"], 1)
            self.assertEqual(pointer["recovery"], 1)
            self.assertEqual(pointer["status"], "healthy")

            generation_root = root / "generations/00000000000000000001"
            self.assertEqual(
                (generation_root / "sys-config/hello/endpoint").read_bytes(),
                b"https://service.invalid",
            )
            self.assertEqual(
                json.loads((generation_root / "generation.json").read_bytes())[
                    "config_sha256"
                ],
                desired_digest,
            )
            reopened = system_lifecycle.LifecycleStore(root)
            self.assertEqual(reopened.status(), pointer)
            verification = reopened.verify(now=NOW)
            self.assertEqual(verification["generations"], [1])
            self.assertEqual(verification["verified_releases"], 1)

    def test_desired_edits_do_not_mutate_active_projection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = system_lifecycle.LifecycleStore(root)
            old = system_lifecycle.projection_bytes((("hello/value", b"old"),))
            new = system_lifecycle.projection_bytes((("hello/value", b"new"),))
            store.set_desired_configuration(old)
            first, _release = self.deploy_release(store, (1, 0, 0), 1)
            store.mark_health(first, True)
            store.set_desired_configuration(new)
            active_file = (
                root / "generations/00000000000000000001/sys-config/hello/value"
            )
            self.assertEqual(active_file.read_bytes(), b"old")
            second, _release = self.deploy_release(store, (1, 0, 1), 2)
            self.assertEqual(
                root.joinpath(
                    "generations", f"{second:020d}", "sys-config/hello/value"
                ).read_bytes(),
                b"new",
            )

    def test_generation_reopen_detects_configuration_or_object_corruption(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = system_lifecycle.LifecycleStore(root)
            store.set_desired_configuration(
                system_lifecycle.projection_bytes((("hello/value", b"exact"),))
            )
            generation, release = self.deploy_release(store, (1, 0, 0), 1)
            store.mark_health(generation, True)
            config = root / f"generations/{generation:020d}/sys-config/hello/value"
            config.write_bytes(b"altered")
            with self.assertRaisesRegex(
                package_model.ModelError, "configuration digest"
            ):
                system_lifecycle.LifecycleStore(root).verify()
            config.write_bytes(b"exact")
            package = (
                root
                / "objects/packages"
                / f"{package_model.sha256(release.package)}.tpkg"
            )
            package.write_bytes(release.package[:-1])
            with self.assertRaises(package_model.ModelError):
                system_lifecycle.LifecycleStore(root).verify()

    def test_incomplete_or_recovery_only_release_sets_fail_before_generation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = system_lifecycle.LifecycleStore(root)
            lock, release = self.release((1, 0, 0), 1)
            with self.assertRaisesRegex(package_model.ModelError, "incomplete-plan"):
                store.deploy(
                    package_model.canonical_json(lock.json()),
                    self.root_envelope.bytes(),
                    self.root_anchor,
                    [],
                    now=NOW,
                )
            corrupted = bytearray(release.package)
            corrupted[-2] ^= 1
            with self.assertRaises(package_model.ModelError):
                store.deploy(
                    package_model.canonical_json(lock.json()),
                    self.root_envelope.bytes(),
                    self.root_anchor,
                    [system_lifecycle.ReleaseInput(release.release, bytes(corrupted))],
                    now=NOW,
                )
            self.assertEqual(list((root / "generations").iterdir()), [])

    def test_complete_multi_package_plan_requires_and_verifies_every_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = system_lifecycle.LifecycleStore(root)
            library_artifact = b"library-1"
            library_document = self.package_document((1, 0, 0), library_artifact)
            library_document["name"] = "library"
            library_document["services"] = []
            library = package_model.parse_manifest(
                package_model.canonical_json(library_document)
            )
            hello_artifact = b"hello-with-library"
            hello_document = self.package_document((1, 0, 0), hello_artifact)
            hello_document["dependencies"] = [
                {
                    "name": "library",
                    "requirement": {
                        "maximum_exclusive": [2, 0, 0],
                        "minimum": [1, 0, 0],
                    },
                }
            ]
            hello = package_model.parse_manifest(
                package_model.canonical_json(hello_document)
            )
            lock = package_model.resolve("hello", TARGET, [hello, library])
            packages = (
                package_model.build_package(hello, lock, hello_artifact),
                package_model.build_package(library, lock, library_artifact),
            )
            releases = [
                self.signed_release(manifest, lock, package, 1)
                for manifest, package in zip((hello, library), packages)
            ]
            generation = store.deploy(
                package_model.canonical_json(lock.json()),
                self.root_envelope.bytes(),
                self.root_anchor,
                list(reversed(releases)),
                now=NOW,
            )
            store.mark_health(generation, True)
            self.assertEqual(store.verify(now=NOW)["verified_releases"], 2)

            second_root = Path(directory) / "incomplete"
            incomplete = system_lifecycle.LifecycleStore(second_root)
            with self.assertRaisesRegex(package_model.ModelError, "incomplete-plan"):
                incomplete.deploy(
                    package_model.canonical_json(lock.json()),
                    self.root_envelope.bytes(),
                    self.root_anchor,
                    releases[:1],
                    now=NOW,
                )


class FormatTests(unittest.TestCase):
    """Reject ambiguous projections and migration descriptors before mutation."""

    def test_projection_paths_base64_order_and_collisions_are_strict(self) -> None:
        valid = system_lifecycle.projection_bytes(
            (("app/one", b"one"), ("app/two", b"two"))
        )
        self.assertEqual(len(system_lifecycle.parse_projection(valid)), 2)
        for document, diagnostic in (
            (
                {
                    "files": [
                        {"data": "", "path": "app"},
                        {"data": "", "path": "app/child"},
                    ],
                    "schema": 1,
                },
                "config-collision",
            ),
            (
                {"files": [{"data": "***", "path": "app/value"}], "schema": 1},
                "invalid-config-data",
            ),
            (
                {"files": [{"data": "", "path": "../escape"}], "schema": 1},
                "invalid-config-path",
            ),
        ):
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaisesRegex(package_model.ModelError, diagnostic):
                    system_lifecycle.parse_projection(
                        package_model.canonical_json(document)
                    )
        with self.assertRaisesRegex(package_model.ModelError, "noncanonical-json"):
            system_lifecycle.parse_projection(json.dumps(json.loads(valid)).encode())

    def test_migrations_require_canonical_bounded_idempotent_operations(self) -> None:
        valid = {
            "from_version": [1, 0, 0],
            "mode": "reversible",
            "operations": [{"op": "delete", "path": ["obsolete"]}],
            "package": "hello",
            "schema": 1,
            "to_version": [2, 0, 0],
        }
        self.assertEqual(
            system_lifecycle.parse_migration(package_model.canonical_json(valid)).mode,
            "reversible",
        )
        invalid = dict(valid)
        invalid["operations"] = [{"op": "rename", "path": ["old"]}]
        with self.assertRaisesRegex(
            package_model.ModelError, "invalid-migration-operation"
        ):
            system_lifecycle.parse_migration(package_model.canonical_json(invalid))


class MigrationAndRollbackTests(LifecycleFixtures, unittest.TestCase):
    """Exercise reversible, forward-only, and explicit downgrade policy."""

    def healthy_v1(self, root: Path) -> system_lifecycle.LifecycleStore:
        store = system_lifecycle.LifecycleStore(root)
        first, _release = self.deploy_release(store, (1, 0, 0), 1)
        store.mark_health(first, True)
        self.write_data(root, {"schema": 1, "value": "retained"})
        return store

    def test_reversible_health_failure_restores_data_and_known_predecessor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = self.healthy_v1(root)
            migration = self.migration((1, 0, 0), (2, 0, 0))
            second, _release = self.deploy_release(
                store, (2, 0, 0), 2, migrations=(migration,)
            )
            self.assertEqual(self.read_data(root)["schema"], 2)
            pointer = store.mark_health(second, False)
            self.assertEqual(pointer["active"], 1)
            self.assertEqual(pointer["status"], "healthy")
            self.assertEqual(self.read_data(root), {"schema": 1, "value": "retained"})
            self.assertEqual(store.diagnostics()[-1]["code"], "health-rollback")

            third, _release = self.deploy_release(
                store, (2, 0, 0), 2, migrations=(migration,)
            )
            store.mark_health(third, True)
            self.assertEqual(store.rollback()["active"], 1)
            self.assertEqual(self.read_data(root)["schema"], 1)

    def test_forward_only_health_failure_enters_recovery_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = self.healthy_v1(root)
            migration = self.migration((1, 0, 0), (2, 0, 0), mode="forward-only")
            second, _release = self.deploy_release(
                store, (2, 0, 0), 2, migrations=(migration,)
            )
            pointer = store.mark_health(second, False)
            self.assertEqual(pointer["status"], "recovery-required")
            self.assertEqual(pointer["active"], second)
            self.assertEqual(self.read_data(root)["schema"], 2)
            self.assertEqual(system_lifecycle.LifecycleStore(root).recover(), pointer)
            recovered = store.mark_health(second, True)
            self.assertEqual(recovered["status"], "healthy")
            self.assertEqual(recovered["active"], second)
            self.assertEqual(self.read_data(root)["schema"], 2)

    def test_downgrade_requires_the_exact_package_authorization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = system_lifecycle.LifecycleStore(root)
            first, _release = self.deploy_release(store, (2, 0, 0), 1)
            store.mark_health(first, True)
            with self.assertRaisesRegex(package_model.ModelError, "downgrade-policy"):
                self.deploy_release(store, (1, 0, 0), 2)
            second, _release = self.deploy_release(
                store, (1, 0, 0), 2, allow_downgrade=("hello",)
            )
            self.assertEqual(second, 2)


class PowerLossTests(LifecycleFixtures, unittest.TestCase):
    """Reopen after every durable publish, migration, activation, and cleanup boundary."""

    def baseline(self, root: Path) -> None:
        store = system_lifecycle.LifecycleStore(root)
        first, _release = self.deploy_release(store, (1, 0, 0), 1)
        store.mark_health(first, True)
        self.write_data(root, {"schema": 1})

    def test_deploy_failpoints_reopen_to_the_old_valid_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            temporary = Path(directory)
            baseline = temporary / "baseline"
            self.baseline(baseline)
            lock, release = self.release((2, 0, 0), 2)
            migration = self.migration((1, 0, 0), (2, 0, 0))
            boundaries = (
                f"object.packages.{package_model.sha256(release.package)}",
                f"object.releases.{package_model.sha256(release.release)}",
                "generation.staged",
                "generation.published",
                "migration.intent",
                "activation.migrating",
                "migration.package.hello",
                "activation.pending",
            )
            for index, boundary in enumerate(boundaries):
                with self.subTest(boundary=boundary):
                    case = temporary / f"case-{index}"
                    shutil.copytree(baseline, case)
                    store = system_lifecycle.LifecycleStore(
                        case, system_lifecycle.FailAfter(boundary)
                    )
                    with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                        store.deploy(
                            package_model.canonical_json(lock.json()),
                            self.root_envelope.bytes(),
                            self.root_anchor,
                            [release],
                            now=NOW,
                            migrations=(migration,),
                        )
                    recovered = system_lifecycle.LifecycleStore(case).recover()
                    self.assertEqual(recovered["active"], 1)
                    self.assertEqual(recovered["status"], "healthy")
                    self.assertEqual(self.read_data(case)["schema"], 1)

    def test_health_and_cleanup_failpoints_reopen_to_the_new_valid_generation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            temporary = Path(directory)
            pending = temporary / "pending"
            self.baseline(pending)
            migration = self.migration((1, 0, 0), (2, 0, 0))
            second, _release = self.deploy_release(
                system_lifecycle.LifecycleStore(pending),
                (2, 0, 0),
                2,
                migrations=(migration,),
            )
            for index, boundary in enumerate(
                ("health.checked", "activation.committed", "cleanup.transaction")
            ):
                with self.subTest(boundary=boundary):
                    case = temporary / f"health-{index}"
                    shutil.copytree(pending, case)
                    store = system_lifecycle.LifecycleStore(
                        case, system_lifecycle.FailAfter(boundary)
                    )
                    with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                        store.mark_health(second, True)
                    recovered = system_lifecycle.LifecycleStore(case).recover()
                    self.assertEqual(recovered["active"], second)
                    self.assertEqual(recovered["status"], "healthy")
                    self.assertEqual(self.read_data(case)["schema"], 2)

    def test_forward_only_power_loss_after_migration_never_runs_old_code(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            self.baseline(root)
            migration = self.migration((1, 0, 0), (2, 0, 0), mode="forward-only")
            lock, release = self.release((2, 0, 0), 2)
            store = system_lifecycle.LifecycleStore(
                root, system_lifecycle.FailAfter("activation.pending")
            )
            with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                store.deploy(
                    package_model.canonical_json(lock.json()),
                    self.root_envelope.bytes(),
                    self.root_anchor,
                    [release],
                    now=NOW,
                    migrations=(migration,),
                )
            pointer = system_lifecycle.LifecycleStore(root).recover()
            self.assertEqual(pointer["status"], "recovery-required")
            self.assertNotEqual(pointer["active"], 1)
            self.assertEqual(self.read_data(root)["schema"], 2)

    def test_forward_only_operator_retry_survives_health_receipt_power_loss(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            self.baseline(root)
            migration = self.migration((1, 0, 0), (2, 0, 0), mode="forward-only")
            second, _release = self.deploy_release(
                system_lifecycle.LifecycleStore(root),
                (2, 0, 0),
                2,
                migrations=(migration,),
            )
            system_lifecycle.LifecycleStore(root).mark_health(second, False)

            store = system_lifecycle.LifecycleStore(
                root, system_lifecycle.FailAfter("health.checked")
            )
            with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                store.mark_health(second, True)

            pointer = system_lifecycle.LifecycleStore(root).recover()
            self.assertEqual(pointer["active"], second)
            self.assertEqual(pointer["status"], "healthy")
            self.assertEqual(self.read_data(root)["schema"], 2)

    def test_health_failure_outcome_boundaries_are_already_durable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            temporary = Path(directory)
            for mode, boundary, expected_status, expected_schema in (
                ("reversible", "rollback.restored", "healthy", 1),
                (
                    "forward-only",
                    "activation.recovery-required",
                    "recovery-required",
                    2,
                ),
            ):
                with self.subTest(mode=mode):
                    root = temporary / mode
                    self.baseline(root)
                    migration = self.migration((1, 0, 0), (2, 0, 0), mode=mode)
                    second, _release = self.deploy_release(
                        system_lifecycle.LifecycleStore(root),
                        (2, 0, 0),
                        2,
                        migrations=(migration,),
                    )
                    store = system_lifecycle.LifecycleStore(
                        root, system_lifecycle.FailAfter(boundary)
                    )
                    with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                        store.mark_health(second, False)
                    pointer = system_lifecycle.LifecycleStore(root).recover()
                    self.assertEqual(pointer["status"], expected_status)
                    self.assertEqual(self.read_data(root)["schema"], expected_schema)

    def test_staging_and_diagnostic_cleanup_failpoints_are_recoverable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            self.baseline(root)
            staging = root / "generations/.stage-00000000000000000002"
            staging.mkdir()
            store = system_lifecycle.LifecycleStore(
                root, system_lifecycle.FailAfter("cleanup.staging")
            )
            with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                store.recover()
            self.assertEqual(
                system_lifecycle.LifecycleStore(root).recover()["active"], 1
            )

            store = system_lifecycle.LifecycleStore(root)
            for index in range(64):
                store.record_diagnostic("power.event", f"event {index}", 1)
            interrupted = system_lifecycle.LifecycleStore(
                root, system_lifecycle.FailAfter("cleanup.diagnostic")
            )
            with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                interrupted.record_diagnostic("power.event", "event 64", 1)
            self.assertEqual(
                len(system_lifecycle.LifecycleStore(root).diagnostics()), 64
            )

    def test_manual_rollback_is_old_or_new_across_every_durable_boundary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            temporary = Path(directory)
            baseline = temporary / "baseline"
            self.baseline(baseline)
            migration = self.migration((1, 0, 0), (2, 0, 0))
            second, _release = self.deploy_release(
                system_lifecycle.LifecycleStore(baseline),
                (2, 0, 0),
                2,
                migrations=(migration,),
            )
            system_lifecycle.LifecycleStore(baseline).mark_health(second, True)
            for index, boundary in enumerate(
                (
                    "rollback.intent",
                    "rollback.migrating",
                    "rollback.package.hello",
                    "rollback.restored",
                    "cleanup.transaction",
                )
            ):
                with self.subTest(boundary=boundary):
                    case = temporary / f"rollback-{index}"
                    shutil.copytree(baseline, case)
                    store = system_lifecycle.LifecycleStore(
                        case, system_lifecycle.FailAfter(boundary)
                    )
                    with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                        store.rollback()
                    pointer = system_lifecycle.LifecycleStore(case).recover()
                    if boundary == "rollback.intent":
                        self.assertEqual(pointer["active"], second)
                        self.assertEqual(self.read_data(case)["schema"], 2)
                    else:
                        self.assertEqual(pointer["active"], 1)
                        self.assertEqual(self.read_data(case)["schema"], 1)
                    self.assertEqual(pointer["status"], "healthy")


class GarbageCollectionAndDiagnosticsTests(LifecycleFixtures, unittest.TestCase):
    """Keep reachability and persistent diagnostics bounded under interruption."""

    def test_gc_preserves_roots_and_diagnostics_keep_only_the_latest_64(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = system_lifecycle.LifecycleStore(root)
            first, _release = self.deploy_release(store, (1, 0, 0), 1)
            store.mark_health(first, True)
            second, _release = self.deploy_release(store, (2, 0, 0), 2)
            store.mark_health(second, False)
            for index in range(70):
                store.record_diagnostic("test.event", f"event {index}", 1)
            diagnostics = store.diagnostics()
            self.assertEqual(len(diagnostics), 64)
            self.assertEqual(diagnostics[0]["detail"], "event 6")
            removed = store.garbage_collect()
            self.assertIn(f"{second:020d}", removed["generations"])
            self.assertEqual(store.status()["active"], 1)
            self.assertEqual(store.verify(now=NOW)["verified_releases"], 1)

    def test_gc_preserves_pending_migration_roots_and_is_restartable_per_deletion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-") as directory:
            root = Path(directory) / "store"
            store = system_lifecycle.LifecycleStore(root)
            first, _release = self.deploy_release(store, (1, 0, 0), 1)
            store.mark_health(first, True)
            self.write_data(root, {"schema": 1})
            migration = self.migration((1, 0, 0), (2, 0, 0))
            second, _release = self.deploy_release(
                store, (2, 0, 0), 2, migrations=(migration,)
            )
            during = store.garbage_collect()
            self.assertEqual(during["generations"], [])
            self.assertTrue(root.joinpath("generations", f"{second:020d}").is_dir())
            store.mark_health(second, False)

            interrupted = system_lifecycle.LifecycleStore(
                root,
                system_lifecycle.FailAfter(f"gc.generation.{second:020d}"),
            )
            with self.assertRaises(system_lifecycle.SimulatedPowerLoss):
                interrupted.garbage_collect()
            reopened = system_lifecycle.LifecycleStore(root)
            self.assertEqual(reopened.status()["active"], 1)
            reopened.garbage_collect()
            self.assertEqual(reopened.verify(now=NOW)["verified_releases"], 1)


class LifecycleCliTests(LifecycleFixtures, unittest.TestCase):
    """Keep the command surface canonical and independent of argument order."""

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, str(SYSTEM_CLI), *arguments),
            cwd=REPO_ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_config_deploy_health_verify_and_status_commands(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-lifecycle-cli-") as directory:
            root = Path(directory)
            store = root / "store"
            lock, release = self.release((1, 0, 0), 1)
            lock_path = root / "lock.json"
            root_path = root / "root.json"
            release_path = root / "release.json"
            package_path = root / "hello.tpkg"
            projection_path = root / "projection.json"
            lock_path.write_bytes(package_model.canonical_json(lock.json()))
            root_path.write_bytes(self.root_envelope.bytes())
            release_path.write_bytes(release.release)
            package_path.write_bytes(release.package)
            projection_path.write_bytes(
                system_lifecycle.projection_bytes((("hello/value", b"ready"),))
            )

            configured = self.run_cli(
                "config-set",
                "--store",
                str(store),
                "--projection",
                str(projection_path),
            )
            self.assertEqual(configured.returncode, 0, configured.stdout)
            deployed = self.run_cli(
                "deploy",
                "--store",
                str(store),
                "--lock",
                str(lock_path),
                "--root",
                str(root_path),
                "--trusted-payload-sha256",
                self.root_anchor,
                "--release",
                str(release_path),
                "--package",
                str(package_path),
                "--now",
                str(NOW),
            )
            self.assertEqual(deployed.returncode, 0, deployed.stdout)
            self.assertEqual(json.loads(deployed.stdout)["data"]["generation"], 1)
            healthy = self.run_cli(
                "health",
                "--store",
                str(store),
                "--generation",
                "1",
                "--result",
                "passed",
            )
            self.assertEqual(healthy.returncode, 0, healthy.stdout)
            verified = self.run_cli("verify", "--store", str(store), "--now", str(NOW))
            self.assertEqual(verified.returncode, 0, verified.stdout)
            output = json.loads(verified.stdout)
            self.assertTrue(output["ok"])
            self.assertEqual(output["data"]["verified_releases"], 1)


if __name__ == "__main__":
    unittest.main()

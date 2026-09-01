"""Negative trust-root, release, freshness, revocation, and publication tests."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools import package_model, package_trust

TARGET = "x86_64-unknown-uefi"
NOW = 1_000_000
REPO_ROOT = Path(__file__).resolve().parents[1]
TRUST_CLI = REPO_ROOT / "tools" / "troe_trust.py"


def package_fixture(
    name: str = "hello", version: tuple[int, int, int] = (1, 0, 0)
) -> tuple[package_model.Manifest, package_model.TargetLock, bytes]:
    """Construct one canonical target package without trust metadata."""
    artifact = b"native-kex-artifact"
    digest = package_model.sha256
    document = {
        "capabilities": ["timer.wait"],
        "dependencies": [],
        "directories": [{"name": "assets", "rights": "read", "role": "assets"}],
        "name": name,
        "resources": {
            "execution_ms": 50,
            "handles": 2,
            "heap_bytes": 1_048_576,
            "stack_bytes": 65_536,
        },
        "schema": 1,
        "services": [{"command": name, "name": f"{name}.service"}],
        "targets": [
            {
                "abi": [1, 1],
                "architecture": "x86_64",
                "artifact_bytes": len(artifact),
                "artifact_sha256": digest(artifact),
                "sdk_sha256": digest(b"sdk"),
                "target": TARGET,
                "toolchain_sha256": digest(b"toolchain"),
            }
        ],
        "version": list(version),
    }
    manifest = package_model.parse_manifest(package_model.canonical_json(document))
    lock = package_model.resolve(name, TARGET, [manifest])
    return manifest, lock, package_model.build_package(manifest, lock, artifact)


class TrustFixtures:
    """Temporary Ed25519 roles and canonical trust metadata."""

    def setUp(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("OpenSSL unavailable")
        self.temporary = tempfile.TemporaryDirectory(prefix="troe-trust-")
        self.root = Path(self.temporary.name)
        self.root_key = self.make_key("root")
        self.snapshot_key = self.make_key("snapshot")
        self.publisher_key = self.make_key("publisher")
        self.builder_one_key = self.make_key("builder-one")
        self.builder_two_key = self.make_key("builder-two")
        self.attacker_key = self.make_key("attacker")
        self.manifest, self.lock, self.package = package_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_key(self, name: str) -> Path:
        path = self.root / f"{name}.pem"
        subprocess.run(
            ("openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(path)),
            check=True,
            capture_output=True,
        )
        return path

    def record(self, private_key: Path) -> dict[str, str]:
        return package_trust.key_record(
            package_trust.public_key_der_from_private(private_key)
        )

    def root_document(
        self,
        *,
        generation: int = 1,
        previous: str | None = None,
        root_key: Path | None = None,
        revocations: list[dict[str, object]] | None = None,
        recovery: bool = False,
    ) -> dict[str, object]:
        selected_root = self.root_key if root_key is None else root_key
        records = [
            self.record(selected_root),
            self.record(self.snapshot_key),
            self.record(self.publisher_key),
            self.record(self.builder_one_key),
            self.record(self.builder_two_key),
        ]
        records.sort(key=lambda record: record["key_id"])
        root_id = self.record(selected_root)["key_id"]
        snapshot_id = self.record(self.snapshot_key)["key_id"]
        publisher_id = self.record(self.publisher_key)["key_id"]
        builder_ids = sorted(
            (
                self.record(self.builder_one_key)["key_id"],
                self.record(self.builder_two_key)["key_id"],
            )
        )
        return {
            "expires": NOW + 10_000,
            "generation": generation,
            "issued_at": NOW - 100,
            "keys": records,
            "previous_root_sha256": previous,
            "publishers": [
                {"key_ids": [publisher_id], "package": "hello", "threshold": 1}
            ],
            "recovery_packages": [package_model.sha256(self.package)]
            if recovery
            else [],
            "revocations": [] if revocations is None else revocations,
            "roles": {
                "provenance": {"key_ids": builder_ids, "threshold": 2},
                "root": {"key_ids": [root_id], "threshold": 1},
                "snapshot": {"key_ids": [snapshot_id], "threshold": 1},
            },
            "schema": 1,
            "type": "root",
        }

    def verified_root(
        self, **kwargs: object
    ) -> tuple[package_trust.Envelope, dict[str, object]]:
        document = self.root_document(**kwargs)
        root_key = kwargs.get("root_key", self.root_key)
        envelope = package_trust.sign_payload(document, [root_key])
        return package_trust.verify_initial_root(
            envelope.bytes(), package_model.sha256(envelope.payload), NOW
        )

    def release_document(
        self,
        *,
        package: bytes | None = None,
        target: str = TARGET,
        sequence: int = 1,
        expires: int = NOW + 1000,
    ) -> dict[str, object]:
        selected = self.package if package is None else package
        return {
            "expires": expires,
            "lock_sha256": self.lock.digest(),
            "manifest_sha256": self.manifest.digest(),
            "name": self.manifest.name,
            "package_bytes": len(selected),
            "package_sha256": package_model.sha256(selected),
            "provenance": {
                "build_recipe_sha256": package_model.sha256(b"recipe"),
                "builder": "builder.production",
                "reproducible_sha256": package_model.sha256(selected),
                "source_sha256": package_model.sha256(b"source"),
            },
            "published_at": NOW - 10,
            "schema": 1,
            "sequence": sequence,
            "target": target,
            "type": "release",
            "version": self.manifest.version.json(),
        }

    def release_envelope(self, **kwargs: object) -> package_trust.Envelope:
        return package_trust.sign_payload(
            self.release_document(**kwargs),
            [self.publisher_key, self.builder_one_key, self.builder_two_key],
        )


class RootAndCryptoTests(TrustFixtures, unittest.TestCase):
    """Exercise root bootstrap, rotation, thresholds, and exact signature coverage."""

    def test_initial_root_is_anchored_self_signed_and_canonical(self) -> None:
        envelope, root = self.verified_root()
        self.assertEqual(root["generation"], 1)
        self.assertEqual(package_trust.parse_envelope(envelope.bytes()), envelope)
        with self.assertRaisesRegex(package_model.ModelError, "root-anchor-mismatch"):
            package_trust.verify_initial_root(envelope.bytes(), "0" * 64, NOW)

        altered = json.loads(envelope.payload)
        altered["expires"] += 1
        forged = package_trust.Envelope(
            package_model.canonical_json(altered), envelope.signatures
        )
        with self.assertRaisesRegex(package_model.ModelError, "signature-threshold"):
            package_trust.verify_initial_root(
                forged.bytes(), package_model.sha256(forged.payload), NOW
            )

    def test_consecutive_rotation_requires_old_and_new_root_authorization(self) -> None:
        old_envelope, old_root = self.verified_root()
        new_root_key = self.make_key("root-new")
        document = self.root_document(
            generation=2,
            previous=package_model.sha256(old_envelope.payload),
            root_key=new_root_key,
        )
        rotated = package_trust.sign_payload(document, [self.root_key, new_root_key])
        _envelope, new_root = package_trust.verify_root_rotation(
            old_root, rotated.bytes(), NOW
        )
        self.assertEqual(new_root["generation"], 2)

        only_new = package_trust.sign_payload(document, [new_root_key])
        with self.assertRaisesRegex(package_model.ModelError, "signature-threshold"):
            package_trust.verify_root_rotation(old_root, only_new.bytes(), NOW)

        skipped = dict(document)
        skipped["generation"] = 3
        skipped_envelope = package_trust.sign_payload(
            skipped, [self.root_key, new_root_key]
        )
        with self.assertRaisesRegex(package_model.ModelError, "invalid-rotation"):
            package_trust.verify_root_rotation(old_root, skipped_envelope.bytes(), NOW)

    def test_malformed_ambiguous_and_expired_roots_fail(self) -> None:
        document = self.root_document()
        document["ambient_trust"] = True
        envelope = package_trust.sign_payload(document, [self.root_key])
        with self.assertRaisesRegex(package_model.ModelError, "invalid-fields"):
            package_trust.verify_initial_root(
                envelope.bytes(), package_model.sha256(envelope.payload), NOW
            )

        document = self.root_document()
        document["expires"] = NOW - 1
        document["issued_at"] = NOW - 100
        envelope = package_trust.sign_payload(document, [self.root_key])
        with self.assertRaisesRegex(package_model.ModelError, "root-expired"):
            package_trust.verify_initial_root(
                envelope.bytes(), package_model.sha256(envelope.payload), NOW
            )


class ReleasePolicyTests(TrustFixtures, unittest.TestCase):
    """Exercise release identity, provenance, freshness, replay, target, and
    recovery."""

    def test_active_release_binds_every_package_and_provenance_identity(self) -> None:
        _root_envelope, root = self.verified_root()
        release = self.release_envelope()
        verified = package_trust.verify_release(
            root, release.bytes(), self.package, now=NOW
        )
        self.assertEqual(verified.status, "active")
        self.assertEqual(
            verified.payload["package_sha256"], package_model.sha256(self.package)
        )

        corrupted = bytearray(self.package)
        corrupted[-2] ^= 1
        with self.assertRaisesRegex(
            package_model.ModelError, "invalid-json|release-mismatch"
        ):
            package_trust.verify_release(
                root, release.bytes(), bytes(corrupted), now=NOW
            )

    def test_expiry_offline_freshness_replay_and_cross_target_fail_closed(self) -> None:
        _root_envelope, root = self.verified_root()
        expired = self.release_envelope(expires=NOW - 1)
        with self.assertRaisesRegex(package_model.ModelError, "release-expired"):
            package_trust.verify_release(root, expired.bytes(), self.package, now=NOW)
        verified = package_trust.verify_release(
            root,
            expired.bytes(),
            self.package,
            now=NOW,
            offline=True,
            offline_grace=60,
        )
        self.assertEqual(verified.status, "active")
        with self.assertRaisesRegex(package_model.ModelError, "offline-policy"):
            package_trust.verify_release(
                root,
                expired.bytes(),
                self.package,
                now=NOW,
                offline=True,
                offline_grace=package_trust.MAX_OFFLINE_STALENESS_SECONDS + 1,
            )

        release = self.release_envelope(sequence=2)
        with self.assertRaisesRegex(package_model.ModelError, "release-replay"):
            package_trust.verify_release(
                root, release.bytes(), self.package, now=NOW, minimum_sequence=3
            )

        cross_target = self.release_envelope(target="aarch64-unknown-uefi")
        with self.assertRaisesRegex(package_model.ModelError, "release-mismatch"):
            package_trust.verify_release(
                root, cross_target.bytes(), self.package, now=NOW
            )

    def test_revocation_blocks_activation_but_preserves_pinned_recovery(self) -> None:
        publisher_id = self.record(self.publisher_key)["key_id"]
        revocations = [
            {
                "key_id": publisher_id,
                "reason": "publisher key compromise",
                "revoked_at": NOW - 1,
            }
        ]
        _root_envelope, revoked = self.verified_root(revocations=revocations)
        release = self.release_envelope()
        with self.assertRaisesRegex(package_model.ModelError, "signature-threshold"):
            package_trust.verify_release(
                revoked, release.bytes(), self.package, now=NOW
            )

        _root_envelope, recovery = self.verified_root(
            revocations=revocations, recovery=True
        )
        verified = package_trust.verify_release(
            recovery, release.bytes(), self.package, now=NOW
        )
        self.assertEqual(verified.status, "recovery-only")

        forged = package_trust.sign_payload(
            self.release_document(), [self.attacker_key]
        )
        with self.assertRaisesRegex(package_model.ModelError, "signature-threshold"):
            package_trust.verify_release(
                recovery, forged.bytes(), self.package, now=NOW
            )

    def test_wrong_publisher_partial_provenance_and_replayed_signature_fail(
        self,
    ) -> None:
        _root_envelope, root = self.verified_root()
        wrong = package_trust.sign_payload(
            self.release_document(),
            [self.attacker_key, self.builder_one_key, self.builder_two_key],
        )
        with self.assertRaisesRegex(package_model.ModelError, "signature-threshold"):
            package_trust.verify_release(root, wrong.bytes(), self.package, now=NOW)

        one_builder = package_trust.sign_payload(
            self.release_document(), [self.publisher_key, self.builder_one_key]
        )
        with self.assertRaisesRegex(package_model.ModelError, "signature-threshold"):
            package_trust.verify_release(
                root, one_builder.bytes(), self.package, now=NOW
            )

        document = self.release_document()
        document["provenance"]["reproducible_sha256"] = "0" * 64
        malformed = package_trust.sign_payload(
            document, [self.publisher_key, self.builder_one_key, self.builder_two_key]
        )
        with self.assertRaisesRegex(package_model.ModelError, "provenance-mismatch"):
            package_trust.verify_release(root, malformed.bytes(), self.package, now=NOW)


class SnapshotAndPublicationTests(TrustFixtures, unittest.TestCase):
    """Prove snapshot monotonicity and all-or-old atomic registry publication."""

    def test_snapshot_threshold_freshness_and_replay(self) -> None:
        _root_envelope, root = self.verified_root()
        release = self.release_envelope()
        payload = package_trust.validate_release_payload(release.payload)
        snapshot = package_trust.snapshot_payload(
            2, NOW - 1, NOW + 100, [(payload, release.digest())]
        )
        envelope = package_trust.sign_payload(snapshot, [self.snapshot_key])
        _verified_envelope, verified = package_trust.verify_snapshot(
            root, envelope.bytes(), now=NOW, minimum_generation=2
        )
        self.assertEqual(verified["generation"], 2)
        with self.assertRaisesRegex(package_model.ModelError, "snapshot-replay"):
            package_trust.verify_snapshot(
                root, envelope.bytes(), now=NOW, minimum_generation=3
            )

        wrong = package_trust.sign_payload(snapshot, [self.publisher_key])
        with self.assertRaisesRegex(package_model.ModelError, "signature-threshold"):
            package_trust.verify_snapshot(root, wrong.bytes(), now=NOW)

    def test_publication_is_complete_before_pointer_and_independently_verified(
        self,
    ) -> None:
        _root_envelope, root = self.verified_root()
        release = self.release_envelope()
        registry = self.root / "registry"
        generation = package_trust.publish_release(
            registry,
            root,
            release.bytes(),
            self.package,
            [self.snapshot_key],
            now=NOW,
            snapshot_expires=NOW + 100,
        )
        self.assertEqual(generation, 1)
        self.assertEqual((registry / "current").read_text(encoding="ascii"), "1")
        directory = registry / "generations" / "00000000000000000001"
        snapshot = package_trust.verify_registry_generation(
            root, directory, now=NOW, minimum_generation=1
        )
        self.assertEqual(len(snapshot["releases"]), 1)

        unexpected = directory / "partial.tmp"
        unexpected.write_bytes(b"partial")
        with self.assertRaisesRegex(package_model.ModelError, "unexpected top-level"):
            package_trust.verify_registry_generation(root, directory, now=NOW)
        unexpected.unlink()

        release_file = next((directory / "releases").iterdir())
        original = release_file.read_bytes()
        release_file.write_bytes(original[:-1])
        with self.assertRaises(package_model.ModelError):
            package_trust.verify_registry_generation(root, directory, now=NOW)
        release_file.write_bytes(original)

    def test_second_publication_preserves_old_generation_and_moves_pointer_once(
        self,
    ) -> None:
        _root_envelope, root = self.verified_root()
        registry = self.root / "registry"
        first = self.release_envelope()
        package_trust.publish_release(
            registry,
            root,
            first.bytes(),
            self.package,
            [self.snapshot_key],
            now=NOW,
            snapshot_expires=NOW + 100,
        )
        self.manifest, self.lock, self.package = package_fixture(version=(1, 0, 1))
        second = self.release_envelope(sequence=2)
        generation = package_trust.publish_release(
            registry,
            root,
            second.bytes(),
            self.package,
            [self.snapshot_key],
            now=NOW + 1,
            snapshot_expires=NOW + 100,
        )
        self.assertEqual(generation, 2)
        self.assertEqual((registry / "current").read_text(encoding="ascii"), "2")
        self.assertTrue((registry / "generations" / "00000000000000000001").is_dir())
        self.assertTrue((registry / "generations" / "00000000000000000002").is_dir())


class TrustCliTests(TrustFixtures, unittest.TestCase):
    """Keep the operator CLI a stable presentation of the trust library."""

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, str(TRUST_CLI), *arguments),
            cwd=REPO_ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

    def test_key_release_publication_and_registry_commands(self) -> None:
        root_envelope, _root = self.verified_root()
        release = self.release_envelope()
        root_path = self.root / "root.json"
        release_path = self.root / "release.json"
        package_path = self.root / "hello.tpkg"
        root_path.write_bytes(root_envelope.bytes())
        release_path.write_bytes(release.bytes())
        package_path.write_bytes(self.package)
        anchor = package_model.sha256(root_envelope.payload)

        identify = self.run_cli("key-id", "--private-key", str(self.publisher_key))
        self.assertEqual(identify.returncode, 0, identify.stderr)
        self.assertEqual(
            json.loads(identify.stdout)["data"]["key_id"],
            self.record(self.publisher_key)["key_id"],
        )

        verify = self.run_cli(
            "verify-release",
            "--root",
            str(root_path),
            "--trusted-payload-sha256",
            anchor,
            "--release",
            str(release_path),
            "--package",
            str(package_path),
            "--now",
            str(NOW),
        )
        self.assertEqual(verify.returncode, 0, verify.stdout)
        self.assertEqual(json.loads(verify.stdout)["data"]["status"], "active")

        registry = self.root / "registry-cli"
        publish = self.run_cli(
            "publish",
            "--root",
            str(root_path),
            "--trusted-payload-sha256",
            anchor,
            "--release",
            str(release_path),
            "--package",
            str(package_path),
            "--snapshot-key",
            str(self.snapshot_key),
            "--registry",
            str(registry),
            "--now",
            str(NOW),
            "--snapshot-expires",
            str(NOW + 100),
        )
        self.assertEqual(publish.returncode, 0, publish.stdout)
        verify_registry = self.run_cli(
            "verify-registry",
            "--root",
            str(root_path),
            "--trusted-payload-sha256",
            anchor,
            "--registry",
            str(registry),
            "--now",
            str(NOW),
        )
        self.assertEqual(verify_registry.returncode, 0, verify_registry.stdout)
        self.assertEqual(json.loads(verify_registry.stdout)["data"]["releases"], 1)


if __name__ == "__main__":
    unittest.main()

"""Adversarial package-model, resolver, artifact, plan, and CLI tests."""

from __future__ import annotations

import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools import package_model

REPO_ROOT = Path(__file__).resolve().parents[1]
TROE = REPO_ROOT / "tools" / "troe.py"
TARGET = "x86_64-unknown-uefi"
OTHER_TARGET = "aarch64-unknown-uefi"
SDK = package_model.sha256(b"sdk")
TOOLCHAIN = package_model.sha256(b"toolchain")


def manifest_document(
    name: str,
    version: tuple[int, int, int],
    artifact: bytes,
    *,
    dependencies: tuple[
        tuple[str, tuple[int, int, int], tuple[int, int, int]], ...
    ] = (),
    both_targets: bool = False,
) -> dict[str, object]:
    """Return one canonical model fixture."""
    targets = [
        {
            "abi": [1, 1],
            "architecture": "x86_64",
            "artifact_bytes": len(artifact),
            "artifact_sha256": package_model.sha256(artifact),
            "sdk_sha256": SDK,
            "target": TARGET,
            "toolchain_sha256": TOOLCHAIN,
        }
    ]
    if both_targets:
        arm_artifact = artifact + b"-arm"
        targets.insert(
            0,
            {
                "abi": [1, 1],
                "architecture": "aarch64",
                "artifact_bytes": len(arm_artifact),
                "artifact_sha256": package_model.sha256(arm_artifact),
                "sdk_sha256": SDK,
                "target": OTHER_TARGET,
                "toolchain_sha256": TOOLCHAIN,
            },
        )
    return {
        "capabilities": ["fs.directory.read", "timer.wait"],
        "dependencies": [
            {
                "name": dependency,
                "requirement": {
                    "maximum_exclusive": list(maximum),
                    "minimum": list(minimum),
                },
            }
            for dependency, minimum, maximum in dependencies
        ],
        "directories": [
            {"name": "assets", "rights": "read", "role": "assets"},
            {"name": "state", "rights": "read-mutate", "role": "data"},
        ],
        "name": name,
        "resources": {
            "execution_ms": 50,
            "handles": 4,
            "heap_bytes": 1_048_576,
            "stack_bytes": 65_536,
        },
        "schema": 1,
        "services": [{"command": name, "name": f"{name}.service"}],
        "targets": targets,
        "version": list(version),
    }


def parse_fixture(*args: object, **kwargs: object) -> package_model.Manifest:
    """Build and parse a manifest fixture."""
    return package_model.parse_manifest(
        package_model.canonical_json(manifest_document(*args, **kwargs))
    )


class ManifestTests(unittest.TestCase):
    """Keep PMAN parsing strict, bounded, and canonical after construction."""

    def test_round_trip_and_two_target_binding(self) -> None:
        manifest = parse_fixture("hello", (1, 2, 3), b"x86", both_targets=True)
        self.assertEqual(
            package_model.parse_manifest(package_model.canonical_json(manifest.json())),
            manifest,
        )
        self.assertEqual(manifest.target(TARGET).architecture, "x86_64")
        self.assertEqual(manifest.target(OTHER_TARGET).architecture, "aarch64")
        self.assertEqual(len(manifest.digest()), 64)

    def test_unknown_duplicate_unsorted_and_ambiguous_fields_fail(self) -> None:
        document = manifest_document("hello", (1, 0, 0), b"artifact")
        document["ambient_authority"] = True
        with self.assertRaisesRegex(package_model.ModelError, "invalid-fields"):
            package_model.parse_manifest(package_model.canonical_json(document))

        duplicate = package_model.canonical_json(
            manifest_document("hello", (1, 0, 0), b"artifact")
        ).replace(b'"schema":1', b'"schema":1,"schema":1')
        with self.assertRaisesRegex(package_model.ModelError, "duplicate-field"):
            package_model.parse_manifest(duplicate)

        document = manifest_document("hello", (1, 0, 0), b"artifact")
        document["capabilities"].reverse()
        with self.assertRaisesRegex(package_model.ModelError, "noncanonical-order"):
            package_model.parse_manifest(package_model.canonical_json(document))

        document = manifest_document("hello", (1, 0, 0), b"artifact", both_targets=True)
        document["targets"][0]["target"] = TARGET
        document["targets"][0]["architecture"] = "x86_64"
        with self.assertRaisesRegex(package_model.ModelError, "noncanonical-order"):
            package_model.parse_manifest(package_model.canonical_json(document))

    def test_resources_capabilities_directories_and_counts_are_closed(self) -> None:
        cases: list[tuple[str, callable]] = [
            (
                "unknown-capability",
                lambda document: (
                    document["capabilities"].append("process.superuser"),
                    document["capabilities"].sort(),
                ),
            ),
            (
                "invalid-directory-rights",
                lambda document: document["directories"][0].update(
                    {"rights": "read-mutate"}
                ),
            ),
            (
                "invalid-limit",
                lambda document: document["resources"].update({"handles": 9}),
            ),
            (
                "invalid-array",
                lambda document: document["directories"].extend(
                    {"name": f"d{index}", "rights": "read", "role": "assets"}
                    for index in range(8)
                ),
            ),
        ]
        for message, mutate in cases:
            with self.subTest(message=message):
                document = manifest_document("hello", (1, 0, 0), b"artifact")
                mutate(document)
                with self.assertRaisesRegex(package_model.ModelError, message):
                    package_model.parse_manifest(package_model.canonical_json(document))


class ResolverTests(unittest.TestCase):
    """Prove deterministic target locks and fail-closed dependency handling."""

    def catalog(self) -> list[package_model.Manifest]:
        return [
            parse_fixture(
                "app",
                (1, 0, 0),
                b"app",
                dependencies=(("library", (1, 0, 0), (3, 0, 0)),),
            ),
            parse_fixture("library", (1, 0, 0), b"library-1"),
            parse_fixture("library", (2, 0, 0), b"library-2"),
        ]

    def test_catalog_order_cannot_change_highest_compatible_lock(self) -> None:
        locks = {
            package_model.canonical_json(
                package_model.resolve("app", TARGET, permutation).json()
            )
            for permutation in itertools.permutations(self.catalog())
        }
        self.assertEqual(len(locks), 1)
        lock = package_model.parse_lock(next(iter(locks)))
        self.assertEqual(
            [(package.name, package.version.text()) for package in lock.packages],
            [("app", "1.0.0"), ("library", "2.0.0")],
        )
        self.assertEqual(
            package_model.parse_lock(package_model.canonical_json(lock.json())), lock
        )

    def test_cycles_conflicts_missing_dependencies_and_wrong_targets_fail(self) -> None:
        cyclic = [
            parse_fixture(
                "one",
                (1, 0, 0),
                b"one",
                dependencies=(("two", (1, 0, 0), (2, 0, 0)),),
            ),
            parse_fixture(
                "two",
                (1, 0, 0),
                b"two",
                dependencies=(("one", (1, 0, 0), (2, 0, 0)),),
            ),
        ]
        with self.assertRaisesRegex(package_model.ModelError, "dependency-cycle"):
            package_model.resolve("one", TARGET, cyclic)

        missing = parse_fixture(
            "app",
            (1, 0, 0),
            b"app",
            dependencies=(("missing", (1, 0, 0), (2, 0, 0)),),
        )
        with self.assertRaisesRegex(package_model.ModelError, "missing-dependency"):
            package_model.resolve("app", TARGET, [missing])

        left = parse_fixture(
            "left",
            (1, 0, 0),
            b"left",
            dependencies=(("library", (1, 0, 0), (2, 0, 0)),),
        )
        right = parse_fixture(
            "right",
            (1, 0, 0),
            b"right",
            dependencies=(("library", (2, 0, 0), (3, 0, 0)),),
        )
        root = parse_fixture(
            "root",
            (1, 0, 0),
            b"root",
            dependencies=(
                ("left", (1, 0, 0), (2, 0, 0)),
                ("right", (1, 0, 0), (2, 0, 0)),
            ),
        )
        libraries = [
            parse_fixture("library", (1, 0, 0), b"library-1"),
            parse_fixture("library", (2, 0, 0), b"library-2"),
        ]
        with self.assertRaisesRegex(package_model.ModelError, "version-conflict"):
            package_model.resolve("root", TARGET, [root, left, right, *libraries])

        with self.assertRaisesRegex(package_model.ModelError, "unsupported-target"):
            package_model.resolve("app", OTHER_TARGET, self.catalog())

    def test_lock_rejects_noncanonical_graph_and_bytes(self) -> None:
        lock = package_model.resolve("app", TARGET, self.catalog())
        document = lock.json()
        document["packages"][0]["dependencies"][0]["version"] = [1, 0, 0]
        with self.assertRaisesRegex(package_model.ModelError, "lock-mismatch"):
            package_model.parse_lock(package_model.canonical_json(document))
        with self.assertRaisesRegex(package_model.ModelError, "noncanonical-json"):
            package_model.parse_lock(json.dumps(lock.json()).encode())

        orphaned = lock.json()
        orphaned["packages"].append(
            package_model.resolve(
                "orphan", TARGET, [parse_fixture("orphan", (1, 0, 0), b"orphan")]
            )
            .packages[0]
            .json()
        )
        orphaned["packages"].sort(key=lambda package: package["name"])
        with self.assertRaisesRegex(package_model.ModelError, "unreachable-package"):
            package_model.parse_lock(package_model.canonical_json(orphaned))

        cyclic = lock.json()
        cyclic["packages"][1]["dependencies"] = [{"name": "app", "version": [1, 0, 0]}]
        with self.assertRaisesRegex(package_model.ModelError, "dependency-cycle"):
            package_model.parse_lock(package_model.canonical_json(cyclic))

    def test_reselection_removes_constraints_from_the_replaced_version(self) -> None:
        root = parse_fixture(
            "root",
            (1, 0, 0),
            b"root",
            dependencies=(
                ("chooser", (1, 0, 0), (3, 0, 0)),
                ("pin", (1, 0, 0), (2, 0, 0)),
            ),
        )
        chooser_two = parse_fixture(
            "chooser",
            (2, 0, 0),
            b"chooser-two",
            dependencies=(("leaf", (2, 0, 0), (3, 0, 0)),),
        )
        chooser_one = parse_fixture(
            "chooser",
            (1, 0, 0),
            b"chooser-one",
            dependencies=(("leaf", (1, 0, 0), (2, 0, 0)),),
        )
        pin = parse_fixture(
            "pin",
            (1, 0, 0),
            b"pin",
            dependencies=(
                ("chooser", (1, 0, 0), (2, 0, 0)),
                ("leaf", (1, 0, 0), (2, 0, 0)),
            ),
        )
        leaf_one = parse_fixture("leaf", (1, 0, 0), b"leaf-one")
        leaf_two = parse_fixture("leaf", (2, 0, 0), b"leaf-two")
        lock = package_model.resolve(
            "root",
            TARGET,
            [root, chooser_two, chooser_one, pin, leaf_one, leaf_two],
        )
        versions = {package.name: package.version.text() for package in lock.packages}
        self.assertEqual(versions["chooser"], "1.0.0")
        self.assertEqual(versions["leaf"], "1.0.0")


class PackageAndPlanTests(unittest.TestCase):
    """Bind artifacts to locks and derive bounded plans without system mutation."""

    def test_package_round_trip_corruption_and_cross_target_fail(self) -> None:
        artifact = b"native-kex"
        manifest = parse_fixture("hello", (1, 0, 0), artifact)
        lock = package_model.resolve("hello", TARGET, [manifest])
        package = package_model.build_package(manifest, lock, artifact)
        self.assertEqual(
            package_model.parse_package(package), (manifest, lock, artifact)
        )

        document = json.loads(package)
        document["artifact"] = "bm90LXRoZS1hcnRpZmFjdA=="
        with self.assertRaisesRegex(package_model.ModelError, "artifact-mismatch"):
            package_model.parse_package(package_model.canonical_json(document))

        other = parse_fixture("hello", (1, 0, 0), artifact, both_targets=True)
        other_lock = package_model.resolve("hello", OTHER_TARGET, [other])
        with self.assertRaisesRegex(package_model.ModelError, "artifact-mismatch"):
            package_model.build_package(other, other_lock, artifact)

    def test_every_locked_dependency_can_be_packaged_against_the_same_plan(
        self,
    ) -> None:
        app = parse_fixture(
            "app",
            (1, 0, 0),
            b"app",
            dependencies=(("library", (1, 0, 0), (2, 0, 0)),),
        )
        library = parse_fixture("library", (1, 0, 0), b"library")
        lock = package_model.resolve("app", TARGET, [app, library])
        for manifest, artifact in ((app, b"app"), (library, b"library")):
            package = package_model.build_package(manifest, lock, artifact)
            parsed, embedded_lock, parsed_artifact = package_model.parse_package(
                package
            )
            self.assertEqual(parsed, manifest)
            self.assertEqual(embedded_lock, lock)
            self.assertEqual(parsed_artifact, artifact)

        outsider = parse_fixture("outsider", (1, 0, 0), b"outsider")
        with self.assertRaisesRegex(package_model.ModelError, "manifest-mismatch"):
            package_model.build_package(outsider, lock, b"outsider")

    def test_plan_reports_exact_authority_services_and_totals(self) -> None:
        manifest = parse_fixture("hello", (1, 0, 0), b"native-kex")
        lock = package_model.resolve("hello", TARGET, [manifest])
        result = package_model.plan(lock, {(manifest.name, manifest.version): manifest})
        self.assertEqual(result["root"], "hello")
        self.assertEqual(result["totals"]["handles"], 4)
        self.assertEqual(
            result["packages"][0]["directories"][1]["rights"], "read-mutate"
        )


class CliTests(unittest.TestCase):
    """Keep presentation derived from one stable result and writes fail-closed."""

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (sys.executable, str(TROE), *arguments),
            cwd=REPO_ROOT,
            check=False,
            text=True,
            capture_output=True,
        )

    def test_check_resolve_build_inspect_explain_plan_and_diagnostics(self) -> None:
        artifact = b"native-kex"
        document = manifest_document("hello", (1, 0, 0), artifact)
        with tempfile.TemporaryDirectory(prefix="troe-package-cli-") as directory:
            root = Path(directory)
            manifest = root / "package.json"
            manifest.write_bytes(package_model.canonical_json(document))
            lock = root / "package.lock"
            binary = root / "hello.kex"
            binary.write_bytes(artifact)
            package = root / "hello.tpkg"

            for command in ("check", "diagnostics"):
                result = self.run_cli("--format", "json", command, str(manifest))
                self.assertEqual(result.returncode, 0, result.stderr)
                output = json.loads(result.stdout)
                self.assertTrue(output["ok"])
                self.assertEqual(output["diagnostics"], [])

            result = self.run_cli(
                "--format",
                "json",
                "resolve",
                "--root",
                "hello",
                "--target",
                TARGET,
                "--manifest",
                str(manifest),
                "--output",
                str(lock),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(lock.is_file())

            result = self.run_cli(
                "build",
                "--manifest",
                str(manifest),
                "--lock",
                str(lock),
                "--artifact",
                str(binary),
                "--output",
                str(package),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(package.is_file())

            invocations = (
                ("inspect", "--manifest", str(manifest)),
                ("inspect", "--package", str(package)),
                ("explain", "--manifest", str(manifest)),
                ("plan", "--lock", str(lock), "--manifest", str(manifest)),
            )
            for invocation in invocations:
                result = self.run_cli("--format", "json", *invocation)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(json.loads(result.stdout)["ok"])

            replacement = self.run_cli(
                "build",
                "--manifest",
                str(manifest),
                "--lock",
                str(lock),
                "--artifact",
                str(binary),
                "--output",
                str(package),
            )
            self.assertEqual(replacement.returncode, 2)
            self.assertIn("output-exists", replacement.stderr)

    def test_human_and_machine_failures_share_the_same_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-package-cli-") as directory:
            invalid = Path(directory) / "package.json"
            invalid.write_text('{"schema":2}', encoding="utf-8")
            machine = self.run_cli("--format", "json", "check", str(invalid))
            human = self.run_cli("check", str(invalid))
            self.assertEqual(machine.returncode, 2)
            self.assertEqual(human.returncode, 2)
            diagnostic = json.loads(machine.stdout)["diagnostics"][0]
            self.assertEqual(diagnostic["code"], "invalid-fields")
            self.assertIn(diagnostic["code"], human.stderr)


if __name__ == "__main__":
    unittest.main()

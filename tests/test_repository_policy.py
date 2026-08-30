"""Regression tests for repository toolchain and dependency policy."""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from repository_policy import (  # noqa: E402
    AUDIT_EXCEPTIONS_FILE,
    SHARED_VOLUME_APPLICATIONS,
    application_directories,
    load_audit_exceptions,
    require_supported_python,
)


class RepositoryPolicyTests(unittest.TestCase):
    """Exercise the closed repository policy at its exact boundaries."""

    def test_python_version_boundary(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "require Python 3.13"):
            require_supported_python((3, 12, 99))
        require_supported_python((3, 13, 0))
        require_supported_python((4, 0, 0))

    def test_committed_exception_policy_is_valid_and_empty(self) -> None:
        self.assertEqual(load_audit_exceptions(AUDIT_EXCEPTIONS_FILE), ())

    def test_exception_policy_requires_owner_rationale_and_future_expiry(self) -> None:
        valid = {
            "schema": 1,
            "exceptions": [
                {
                    "advisory": "RUSTSEC-2026-0001",
                    "owner": "security@example.invalid",
                    "rationale": "Temporary boundary dependency mitigation.",
                    "expires": "2026-08-25",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "exceptions.json"
            policy.write_text(json.dumps(valid), encoding="utf-8")
            today = datetime.date(2026, 8, 24)
            self.assertEqual(
                load_audit_exceptions(policy, today=today),
                ("RUSTSEC-2026-0001",),
            )

            valid["exceptions"][0]["expires"] = "2026-08-24"
            policy.write_text(json.dumps(valid), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expired"):
                load_audit_exceptions(policy, today=today)

            valid["exceptions"][0].pop("owner")
            policy.write_text(json.dumps(valid), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exactly"):
                load_audit_exceptions(policy, today=today)

    def test_workspace_metadata_has_only_approved_boundary_dependencies(self) -> None:
        output = subprocess.run(
            ("cargo", "metadata", "--no-deps", "--format-version", "1"),
            cwd=REPO_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        metadata = json.loads(output)
        actual: dict[str, set[tuple[str, str, bool]]] = {}
        for package in metadata["packages"]:
            external = {
                (
                    dependency["name"],
                    dependency["req"],
                    dependency["uses_default_features"],
                )
                for dependency in package["dependencies"]
                if dependency["source"] is not None
            }
            if external:
                actual[package["name"]] = external
            self.assertEqual(package["edition"], "2024")
            self.assertEqual(package["license"], "Apache-2.0")
        self.assertEqual(
            actual,
            {
                "troe-kernel": {("uefi", "=0.39.0", True)},
                "troe-kex-alloc": {("rlsf", "=0.2.3", False)},
                "troe-kex-runtime": {("libm", "=0.2.16", True)},
                "troe-machine": {
                    ("rlsf", "=0.2.3", False),
                    ("uefi", "=0.39.0", True),
                },
            },
        )

        toolchain = tomllib.loads(
            (REPO_ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(toolchain["toolchain"]["channel"], "1.97.1")
        self.assertEqual(
            toolchain["toolchain"]["targets"],
            [
                "x86_64-unknown-uefi",
                "aarch64-unknown-uefi",
                "x86_64-unknown-none",
                "aarch64-unknown-none",
            ],
        )

    def test_kex_authoring_skill_is_one_concise_repo_local_file(self) -> None:
        root = REPO_ROOT / "skills" / "write-kex-apps"
        files = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
        self.assertEqual(files, ["SKILL.md"])
        source = (root / "SKILL.md").read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 120)
        self.assertTrue(source.startswith("---\nname: write-kex-apps\ndescription: "))
        self.assertIn("cargo kex build", source)
        self.assertIn("troe_kex_sdk::entry!", source)
        self.assertIn("Do not infer POSIX behavior", source)
        self.assertIn("scripts/test_changed.py", source)
        self.assertIn("docs/testing.md", source)

    def test_every_ordinary_command_is_kex_only_on_both_targets(self) -> None:
        ordinary = {
            "arp",
            "awk",
            "cat",
            "clear",
            "cp",
            "dhcp",
            "echo",
            "grep",
            "hexdump",
            "ln",
            "ls",
            "man",
            "mem",
            "mount",
            "mv",
            "net",
            "ping",
            "printf",
            "ps",
            "pwd",
            "rm",
            "rmdir",
            "sed",
            "sh",
            "sleep",
            "spawn",
            "tar",
            "tcp",
            "timesync",
            "top",
            "udp",
            "wc",
        }
        apps = {path.name for path in application_directories()}
        self.assertEqual(apps, ordinary | SHARED_VOLUME_APPLICATIONS)
        self.assertEqual(SHARED_VOLUME_APPLICATIONS, {"lua", "python"})
        self.assertFalse(ordinary & SHARED_VOLUME_APPLICATIONS)
        for architecture in ("x86_64", "aarch64"):
            root = REPO_ROOT / "rootfs" / "bin" / architecture
            installed = {path.stem for path in root.glob("*.kex")}
            self.assertEqual(installed, ordinary)
            self.assertEqual(list(root.glob("*.kcap")), [])

        shell = (REPO_ROOT / "crates/shell/troe-shell/src/lib.rs").read_text(encoding="utf-8")
        self.assertEqual(shell.count("\n    fn command_"), 2)
        self.assertIn("fn command_cd", shell)
        self.assertIn("fn command_machine_action", shell)
        for forbidden in (
            "ReplaceableBuiltin",
            "NetworkControl",
            "set_network",
            "set_runtime",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, shell)

    def test_completion_policy_is_portable_and_kcap_remains_authority_only(self) -> None:
        completion_root = REPO_ROOT / "crates" / "common" / "troe-completion"
        manifest = tomllib.loads(
            (completion_root / "Cargo.toml").read_text(encoding="utf-8")
        )
        self.assertNotIn("dependencies", manifest)
        source = (completion_root / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("#![no_std]", source)
        self.assertIn("pub enum Resolver", source)
        self.assertIn("Address(AddressConstraints)", source)
        self.assertIn("Integer(IntegerConstraints)", source)

        shell = (REPO_ROOT / "crates" / "shell" / "troe-shell" / "src" / "lib.rs").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("fn argument_completion", shell)
        registry = (
            REPO_ROOT / "crates" / "shell" / "troe-shell" / "src" / "recovery_completion.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("CompletionDescriptor", registry)
        self.assertIn("PackageCompletionRegistry", registry)
        self.assertIn("kex_package_completion_range", registry)

        apps = list(application_directories())
        self.assertEqual(len(apps), 34)
        for app in apps:
            descriptor = app / "completion.cmpl"
            self.assertTrue(descriptor.is_file(), app.name)
            source = descriptor.read_text(encoding="utf-8")
            self.assertTrue(source.endswith("\n"), app.name)
            self.assertEqual(source.splitlines()[0], f"CMPL\t1\t{app.name}")

        for root in (REPO_ROOT / "rootfs" / "bin").iterdir():
            self.assertEqual(list(root.glob("*.complete")), [])

        kcap = (REPO_ROOT / "docs" / "formats" / "kcap-v1.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("completion descriptor", kcap.lower())

    def test_superseded_resource_profiles_cannot_reenter_source_apis(self) -> None:
        forbidden_rust = ("ResourceProfile", "ResourcePolicy", "::tiny()", "::full()")
        for root in (REPO_ROOT / "crates", REPO_ROOT / "kernel"):
            for path in root.rglob("*.rs"):
                source = path.read_text(encoding="utf-8")
                for token in forbidden_rust:
                    with self.subTest(path=path.relative_to(REPO_ROOT), token=token):
                        self.assertNotIn(token, source)

        for relative in (
            "scripts/build.py",
            "tools/elf2kex.py",
            "tools/gen_kex_corpus.py",
        ):
            source = (REPO_ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                self.assertNotIn("--profile", source)

    def test_platform_facts_and_virtio_transport_selection_stay_below_kernel(
        self,
    ) -> None:
        machine_sources = tuple((REPO_ROOT / "crates/runtime/troe-machine/src").glob("*.rs"))
        kernel_sources = tuple((REPO_ROOT / "kernel/src").glob("*.rs"))
        fixed_platform_literals = (
            "0xfee00000",
            "0xfec00000",
            "0x08000000",
            "0x09000000",
            "0x0a000000",
            "0x3f8",
            "0x604",
            "0xcf9",
        )
        for path in (*machine_sources, *kernel_sources):
            normalized = path.read_text(encoding="utf-8").lower().replace("_", "")
            for literal in fixed_platform_literals:
                with self.subTest(path=path.relative_to(REPO_ROOT), literal=literal):
                    self.assertNotIn(literal, normalized)

        kernel = (REPO_ROOT / "kernel/src/main.rs").read_text(encoding="utf-8")
        for transport_api in (
            "discover_virtio_mmio",
            "discover_virtio_pci",
            "virtio_mmio_device_ranges",
            "virtio_pci_device_ranges",
        ):
            with self.subTest(transport_api=transport_api):
                self.assertNotIn(transport_api, kernel)

        machine = (REPO_ROOT / "crates/runtime/troe-machine/src/lib.rs").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            machine.count("target_arch"),
            2,
            "target_arch may only guard platform/CPU compatibility, not select transport",
        )

    def test_crate_domains_and_roles_stay_layered(self) -> None:
        """Directories name the domain, crate names name the role, and neither
        may depend upward. This is the layering ADR 0035 Phase E relies on: a
        provider must be linkable without a namespace, and a format codec must
        be linkable without either."""
        manifests = {
            path.parent.name: (path.parent.parent.name, tomllib.loads(path.read_text("utf-8")))
            for path in (REPO_ROOT / "crates").rglob("Cargo.toml")
        }
        self.assertEqual(
            {domain for domain, _ in manifests.values()},
            {"common", "storage", "net", "device", "runtime", "shell"},
        )

        # Two troe-fs-* crates are contracts rather than filesystems: the
        # provider contract and the client contract. Everything else carrying
        # that prefix is an implementation.
        contracts = {"troe-fs-api", "troe-fs-client"}

        def shipped_dependencies(manifest: dict) -> set[str]:
            """Dependencies that reach a built image.

            Tests must be free to compose a namespace out of real providers, so
            dev-dependencies are deliberately excluded: the layering claim is
            about what the kernel and the future storage server link, not about
            what a unit test constructs.
            """
            names: set[str] = set()
            for section in ("dependencies", "build-dependencies"):
                names.update(
                    name for name in manifest.get(section, {}) if name.startswith("troe-")
                )
            for target in manifest.get("target", {}).values():
                names.update(
                    name for name in target.get("dependencies", {}) if name.startswith("troe-")
                )
            return names

        for crate, (domain, manifest) in manifests.items():
            self.assertEqual(
                manifest["package"]["name"],
                crate,
                f"{crate} directory and package name must match",
            )
            dependencies = shipped_dependencies(manifest)
            if crate.startswith("troe-fmt-"):
                for dependency in dependencies:
                    self.assertTrue(
                        dependency in {"troe-block", "troe-checksum", "troe-fs-api"}
                        or dependency.startswith("troe-fmt-"),
                        f"{crate} is a format codec: {dependency} is not a leaf"
                        " vocabulary. A block-resident format may read through"
                        " troe-block, but no format may reach a provider,"
                        " namespace, or policy crate.",
                    )
            if crate.startswith("troe-fs-") and crate not in contracts:
                self.assertLessEqual(
                    dependencies,
                    {"troe-fs-api", "troe-block", "troe-txslot", "troe-core", "troe-checksum"},
                    f"{crate} is a provider: it may not reach past the filesystem"
                    " contract, and must never link the namespace",
                )
            if crate == "troe-fs-api":
                self.assertEqual(
                    dependencies, set(), "the provider contract must stay dependency-free"
                )
            if crate == "troe-fs-client":
                self.assertLessEqual(
                    dependencies,
                    {"troe-fs-api", "troe-core"},
                    "the client contract may name vocabulary only, never an"
                    " implementation, so a client can be served across a"
                    " protection boundary",
                )
            if crate == "troe-namespace":
                self.assertNotIn(
                    "troe-volume", dependencies, "the namespace may not depend on volume policy"
                )
                for dependency in dependencies:
                    self.assertFalse(
                        dependency.startswith(("troe-fs-", "troe-fmt-"))
                        and dependency not in contracts,
                        f"the namespace may not link the {dependency} implementation",
                    )

    def test_the_session_holds_no_filesystem_implementation(self) -> None:
        """The shell is a namespace client, not a namespace owner. ADR 0035
        Phase E requires this before the namespace can move into a server: a
        session that names a concrete namespace cannot be served across a
        protection boundary."""
        manifest = tomllib.loads(
            (REPO_ROOT / "crates/shell/troe-shell/Cargo.toml").read_text("utf-8")
        )
        shipped = {
            name for name in manifest.get("dependencies", {}) if name.startswith("troe-")
        }
        self.assertIn("troe-fs-client", shipped)
        self.assertNotIn("troe-namespace", shipped)
        source = (REPO_ROOT / "crates/shell/troe-shell/src/lib.rs").read_text("utf-8")
        self.assertIn("pub type SharedNamespace = Rc<RefCell<dyn NamespaceClient>>;", source)

    def test_kernel_storage_dependencies_are_recorded_for_phase_e(self) -> None:
        """The kernel still links every filesystem format and the network stack.
        Pin that list so ADR 0035 Phase D and E removals are a visible diff and
        cannot regress silently in the other direction."""
        manifest = tomllib.loads((REPO_ROOT / "kernel" / "Cargo.toml").read_text("utf-8"))
        linked = {name for name in manifest["dependencies"] if name.startswith("troe-")}
        self.assertEqual(
            linked & {
                "troe-fmt-bmnt", "troe-fmt-cspk", "troe-fmt-gpt", "troe-fmt-prgn",
                "troe-fmt-scfg", "troe-fs-ext4", "troe-fs-fat", "troe-fs-statefs",
                "troe-identity", "troe-net", "troe-txslot", "troe-namespace", "troe-volume",
            },
            {
                "troe-fmt-bmnt", "troe-fmt-cspk", "troe-fmt-gpt", "troe-fmt-prgn",
                "troe-fmt-scfg", "troe-fs-ext4", "troe-fs-fat", "troe-fs-statefs",
                "troe-identity", "troe-net", "troe-txslot", "troe-namespace", "troe-volume",
            },
            "kernel storage/network linkage changed: update this gate with the migration",
        )



if __name__ == "__main__":
    unittest.main()

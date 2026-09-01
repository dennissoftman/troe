"""Regression tests for repository toolchain and dependency policy."""

from __future__ import annotations

import argparse
import datetime
import json
import re
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
    KEX_TARGETS,
    SHARED_VOLUME_APPLICATIONS,
    UNLINTABLE_APPLICATIONS,
    application_directories,
    buildable_shared_volume_directories,
    lintable_application_directories,
    load_audit_exceptions,
    require_supported_python,
    rootfs_application_directories,
    rust_code_without_comments_or_literals,
    rust_source_outside_test_configuration,
    service_directories,
    shipped_troe_dependencies,
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
        # Agents that discover skills under `.claude/skills` read their own copy,
        # so the two must not drift into different authoring guidance.
        mirror = REPO_ROOT / ".claude" / "skills" / "write-kex-apps" / "SKILL.md"
        self.assertTrue(mirror.is_file(), f"{mirror} is missing")
        self.assertEqual(mirror.read_text(encoding="utf-8"), source)
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
            "date",
            "dhcp",
            "echo",
            "grep",
            "head",
            "hexdump",
            "ln",
            "ls",
            "man",
            "mem",
            "mkdir",
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
            "tail",
            "tar",
            "tcp",
            "timesync",
            "top",
            "touch",
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
        self.assertEqual(len(apps), 39)
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
        kernel_sources = tuple((REPO_ROOT / "kernel/src").rglob("*.rs"))
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

        kernel = "\n".join(
            path.read_text(encoding="utf-8") for path in sorted(kernel_sources)
        )
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
        be linkable without either.

        The shipped graph is a total order: `common` is vocabulary, `device` is
        hardware mechanism, `net` and `storage` are subsystems over a device,
        `runtime` schedules them, and `shell` is the session above. Nothing
        links `net` and `storage` in either direction, so their relative rank is
        the one position this order chooses rather than records; `net` is placed
        lower because it links no other crate at all, which leaves a
        network-backed filesystem as the edge the order still permits."""
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

        # The shipped cross-domain edges, recomputed from the manifests below:
        # device to common; storage to common and device; runtime to common,
        # device, net, and storage; shell to common, device, storage, and
        # runtime. net links nothing. Every edge points down this order.
        order = ("common", "device", "net", "storage", "runtime", "shell")

        # What reaches an image is `shipped_troe_dependencies`: normal, build,
        # and per-target dependencies, never dev-dependencies. Every gate over
        # linkage shares that one definition, so they cannot drift apart on what
        # "shipped" means.
        for crate, (domain, manifest) in manifests.items():
            self.assertEqual(
                manifest["package"]["name"],
                crate,
                f"{crate} directory and package name must match",
            )
            dependencies = shipped_troe_dependencies(manifest)
            for dependency in dependencies:
                self.assertTrue(
                    dependency in manifests,
                    f"{crate} ships {dependency}, which is not a crate under"
                    " crates/: give this gate a domain for it before linking it.",
                )
                above = manifests[dependency][0]
                self.assertLessEqual(
                    order.index(above),
                    order.index(domain),
                    f"{crate} ({domain}) ships {dependency} ({above}), which is"
                    " a higher layer. A crate may link its own domain or a lower"
                    f" one only, in the order {' < '.join(order)}. Move the code"
                    f" that needs {dependency} down, invert the edge behind a"
                    " trait the lower crate owns, or, when only a test needs it,"
                    " declare it under [dev-dependencies].",
                )
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
        shipped = shipped_troe_dependencies(manifest)
        self.assertIn("troe-fs-client", shipped)
        storage = {
            path.name
            for path in (REPO_ROOT / "crates" / "storage").iterdir()
            if path.is_dir()
        }
        self.assertLessEqual(
            shipped & storage,
            {"troe-fs-api", "troe-fs-client"},
            "the session ships the two filesystem contracts and nothing else"
            " from the storage domain: a namespace, a provider, or a format"
            " codec under [dependencies] is linked into every image carrying the"
            " shell, and a session naming a concrete implementation cannot be"
            " served across a protection boundary. A test that needs a real"
            " filesystem composes one through [dev-dependencies].",
        )
        source = (REPO_ROOT / "crates/shell/troe-shell/src/lib.rs").read_text("utf-8")
        self.assertIn("pub type SharedNamespace = Rc<RefCell<dyn NamespaceClient>>;", source)

    def test_no_crate_ships_a_dependency_only_its_tests_name(self) -> None:
        """`[dependencies]` is what a built image links. A dependency named only
        inside a `#[cfg(test)]` item is a test fixture, and shipping it claims
        linkage the crate does not have.

        The scan is textual, so it is sound only while a use cannot hide from
        the text, and only while the removal never takes more than the annotated
        item. Three properties hold that. No crate under `crates` defines a
        macro, and every `troe-` dependency of those crates is itself one of
        them, so no dependency can arrive through an expansion: both are
        asserted here. And the removal is one-sided by construction -- it keeps
        every predicate that a non-test build can satisfy and every item shape
        it cannot delimit -- so a crate can only be missed, never reported
        wrongly. A name absent from the crate's sources altogether is likewise
        not reported, which leaves a link-only use silent rather than wrong."""
        crates = {
            path.parent.name: path.parent
            for path in (REPO_ROOT / "crates").rglob("Cargo.toml")
        }
        for directory in sorted(crates.values()):
            for path in sorted(directory.rglob("*.rs")):
                with self.subTest(path=path.relative_to(REPO_ROOT)):
                    # Code only: a doc-comment example or a diagnostic string
                    # naming the construct is not a definition of it.
                    code = rust_code_without_comments_or_literals(path.read_text("utf-8"))
                    self.assertTrue(
                        "macro_rules!" not in code,
                        f"{path.relative_to(REPO_ROOT)} defines a macro, which"
                        " can reach a dependency without naming it; this gate"
                        " would read that dependency as unused. Give the gate a"
                        " way to see the expansion before adding one.",
                    )

        for crate, directory in sorted(crates.items()):
            manifest = tomllib.loads((directory / "Cargo.toml").read_text("utf-8"))
            declared = shipped_troe_dependencies(manifest)

            # Only the crate's own compiled sources count. An integration test
            # under tests/ is a test target like any other.
            paths = sorted((directory / "src").rglob("*.rs"))
            if (directory / "build.rs").is_file():
                paths.append(directory / "build.rs")
            sources = [path.read_text("utf-8") for path in paths]
            everywhere = "\n".join(sources)
            outside_tests = "\n".join(
                rust_source_outside_test_configuration(source) for source in sources
            )
            for dependency in sorted(declared):
                self.assertTrue(
                    dependency in crates,
                    f"{crate} ships {dependency}, which is not a crate under"
                    " crates/, so this scan cannot see how it is reached.",
                )
                identifier = dependency.replace("-", "_")
                if identifier not in everywhere:
                    continue
                with self.subTest(crate=crate, dependency=dependency):
                    self.assertTrue(
                        identifier in outside_tests,
                        f"{crate} ships {dependency} but names it only inside a"
                        " #[cfg(test)] item, so no built image that links"
                        f" {crate} reaches it. Declare {dependency} under"
                        " [dev-dependencies] instead.",
                    )

    def test_test_configuration_stripping_ignores_braces_in_literals(self) -> None:
        """The shipped-dependency scan above depends on removing exactly the
        annotated item, so a brace inside a literal or a comment must not end it
        early and a nested cfg predicate naming test must still be seen."""
        source = """\
use troe_shipped::Kept;
#[cfg(test)]
mod tests {
    use troe_fixture::Made;
    fn brace() -> &'static str { "}" /* } */ }
}
#[cfg(all(test, feature = "extra"))]
use troe_extra::Also;
#[cfg(target_arch = "aarch64")]
use troe_platform::Retained;
"""
        outside = rust_source_outside_test_configuration(source)
        self.assertIn("troe_shipped", outside)
        self.assertIn("troe_platform", outside)
        self.assertNotIn("troe_fixture", outside)
        self.assertNotIn("troe_extra", outside)

    def test_test_configuration_stripping_keeps_what_a_shipped_build_compiles(
        self,
    ) -> None:
        """Only a predicate that cannot hold outside a test build may be
        removed. `not(test)` and `any(test, ..)` are both satisfied by a shipped
        build, so removing them would delete shipped code and then instruct the
        author to move a live dependency to [dev-dependencies] -- the one
        failure direction of this gate that is worse than silence.

        The first three cases are idioms `crates/runtime/troe-machine` uses
        today. The last two are not written anywhere in the tree; they are the
        nesting shapes that would defeat a pattern-matched predicate, and pin
        the scan's answer to their meaning rather than to how deep they go."""
        for name, source in {
            "not(test)": '#[cfg(not(test))]\nuse troe_real::Thing;\n',
            "any(test, cfg)": (
                '#[cfg(any(test, target_os = "uefi"))]\nuse troe_uefi::Thing;\n'
            ),
            "any(test, all(cfg, cfg))": (
                '#[cfg(any(test, all(target_os = "uefi", target_arch = "x86_64")))]\n'
                "use troe_uefi::Thing;\n"
            ),
            # Three levels of nesting: recognized, and retained on its merits
            # rather than by failing to parse.
            "all(not(test), cfg)": '#[cfg(all(not(test), unix))]\nuse troe_unix::Thing;\n',
            "not(all(test, cfg))": (
                '#[cfg(not(all(test, unix)))]\nuse troe_unix::Thing;\n'
            ),
        }.items():
            with self.subTest(predicate=name):
                self.assertEqual(
                    rust_source_outside_test_configuration(source),
                    source,
                    f"a {name} item ships and must survive the removal",
                )

        # The real `mechanism.rs` shape: a test fixture and the platform the
        # image actually selects, guarded as each other's complement. Stripping
        # must take the fixture and leave the selection.
        paired = """\
pub(crate) fn route() -> Result<Self, Error> {
    #[cfg(test)]
    let platform = troe_platform::X86_64_Q35_UEFI.validate()?;
    #[cfg(not(test))]
    let platform = crate::selected_platform()?;
    let troe_platform::VirtioTransportKind::Pci { .. } = platform.virtio() else {
        return Err(Error);
    };
    Ok(Self { platform })
}
"""
        outside = rust_source_outside_test_configuration(paired)
        self.assertIn("troe_platform", outside)
        self.assertIn("crate::selected_platform()", outside)
        self.assertNotIn("X86_64_Q35_UEFI", outside)

    def test_test_configuration_stripping_fails_closed_on_unknown_shapes(self) -> None:
        """An item this scan cannot delimit must cost the removal, not the rest
        of the file. A statement ends at neither a balanced body nor a top-level
        semicolon, so the scan reaches a delimiter that belongs to the enclosing
        block; it has to stop there and retain what follows."""
        statement = """\
fn f() {
    #[cfg(test)]
    do_it()
}
use troe_after::Thing;
fn g() {}
"""
        outside = rust_source_outside_test_configuration(statement)
        self.assertIn("troe_after", outside)
        self.assertIn("fn g()", outside)
        self.assertNotIn("do_it", outside)

        field = """\
struct S {
    #[cfg(test)]
    probe: troe_fixture::Probe,
    shipped: troe_kept::Value,
}
use troe_after::Thing;
"""
        outside = rust_source_outside_test_configuration(field)
        self.assertIn("troe_kept", outside)
        self.assertIn("troe_after", outside)
        self.assertNotIn("troe_fixture", outside)

    def test_comment_and_literal_blanking_leaves_only_code(self) -> None:
        """The macro-soundness assertion searches source text, so a construct
        merely named in a doc comment or a diagnostic string must not read as a
        definition of it."""
        source = '''\
/// Expands like `macro_rules! example { () => {} }` does.
const MESSAGE: &str = "macro_rules! is not defined here";
fn shipped() -> u8 {
    /* macro_rules! neither */
    4
}
'''
        code = rust_code_without_comments_or_literals(source)
        self.assertNotIn("macro_rules!", code)
        self.assertIn("fn shipped()", code)
        self.assertIn("const MESSAGE", code)
        self.assertEqual(
            code.count("\n"), source.count("\n"), "line numbering must survive"
        )
        self.assertNotIn(
            "macro_rules!",
            rust_code_without_comments_or_literals("macro/* split */_rules!"),
            "a blanked span must keep the tokens it separated apart",
        )
        self.assertIn(
            "macro_rules!",
            rust_code_without_comments_or_literals("macro_rules! real { () => {} }"),
            "a real definition must still be visible",
        )

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

    def test_shipped_packages_are_members_of_one_workspace_per_tree(self) -> None:
        """`apps/` and `services/` are each one Cargo workspace, not 42 of them.
        A per-package workspace root is invisible to `cargo fmt --all`,
        `cargo clippy --workspace`, and `cargo test --workspace`, which is how
        11,804 lines of shipped Rust and 31 unit tests stayed outside the gate.
        Assert the exact member sets, the single lock per tree, and that no
        member reintroduces a root, a profile, or its own lint levels."""
        for tree, directories in (
            ("apps", application_directories()),
            ("services", service_directories()),
        ):
            root = REPO_ROOT / tree
            workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
            self.assertNotIn("package", workspace, tree)
            self.assertEqual(workspace["workspace"]["resolver"], "3", tree)
            self.assertEqual(
                sorted(workspace["workspace"]["members"]),
                sorted(path.name for path in directories),
                tree,
            )
            self.assertTrue((root / "Cargo.lock").is_file(), tree)
            for directory in directories:
                member = tomllib.loads(
                    (directory / "Cargo.toml").read_text(encoding="utf-8")
                )
                with self.subTest(member=directory.name):
                    self.assertNotIn("workspace", member)
                    self.assertNotIn("profile", member)
                    self.assertEqual(member["lints"], {"workspace": True})
                    for field in ("version", "edition", "rust-version", "license", "publish"):
                        self.assertEqual(
                            member["package"][field], {"workspace": True}, field
                        )
                    # A `#![no_main]` command has no test harness, and Cargo's
                    # default test target for it cannot build for either a bare
                    # target or the host. Declaring it away is what lets the
                    # gate reach the library test modules with `--tests`.
                    self.assertEqual(len(member["bin"]), 1)
                    self.assertIs(member["bin"][0]["test"], False)
                    self.assertIs(member["bin"][0]["bench"], False)
                    self.assertFalse((directory / "Cargo.lock").exists())

    def test_application_lint_levels_track_the_root_workspace(self) -> None:
        """Both trees start from the root workspace's lint levels. Two rust
        deviations are deliberate and every clippy deviation is an `allow` for a
        lint the shipped sources violate today, which cannot be fixed here
        because a moved line rewrites the panic locations inside a committed
        `.kex`. Pin the deviations so tightening them is a visible diff and
        loosening them further is a failure."""
        def lints(manifest: Path) -> dict[str, dict[str, object]]:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
            return document["workspace"]["lints"]

        root = lints(REPO_ROOT / "Cargo.toml")
        self.assertEqual(
            root["rust"], {"unsafe_code": "forbid", "missing_docs": "warn"}
        )
        strict_clippy = {
            "all": {"level": "warn", "priority": -1},
            "pedantic": {"level": "warn", "priority": -1},
            "unwrap_used": "deny",
            "expect_used": "deny",
            "panic": "deny",
        }
        self.assertEqual(root["clippy"], strict_clippy)

        deferred = {
            "cast_possible_truncation",
            "cast_sign_loss",
            "collapsible_if",
            "doc_markdown",
            "if_not_else",
            "ignored_unit_patterns",
            "large_stack_arrays",
            "large_types_passed_by_value",
            "manual_let_else",
            "match_same_arms",
            "missing_errors_doc",
            "needless_pass_by_value",
            "semicolon_if_nothing_returned",
            "single_match_else",
            "struct_excessive_bools",
            "too_many_arguments",
            "too_many_lines",
        }
        for tree, allowed in (("apps", deferred), ("services", set())):
            with self.subTest(tree=tree):
                table = lints(REPO_ROOT / tree / "Cargo.toml")
                # `deny` rather than `forbid`: `forbid` cannot be lifted, and
                # four members genuinely need `unsafe`. They opt in per crate.
                self.assertEqual(
                    table["rust"], {"unsafe_code": "deny", "missing_docs": "allow"}
                )
                self.assertEqual(
                    {name: table["clippy"][name] for name in strict_clippy},
                    strict_clippy,
                )
                extra = set(table["clippy"]) - set(strict_clippy)
                self.assertEqual(extra, allowed)
                for name in extra:
                    self.assertEqual(table["clippy"][name], "allow", name)

    def test_one_release_profile_owns_every_shipped_package(self) -> None:
        """One `[profile.release]` per tree replaces 42 identical copies. The two
        interpreters keep `opt-level = 2`; that is the only value that differed,
        and `opt-level` is the only one a per-package override may carry, so
        `panic`, `lto`, and `strip` must stay uniform to be expressible here."""
        shipped = {
            "codegen-units": 1,
            "lto": False,
            "opt-level": "z",
            "panic": "abort",
            "strip": "none",
        }
        for tree, overrides in (
            ("apps", {"troe-app-lua": 2, "troe-app-python": 2}),
            ("services", {}),
        ):
            with self.subTest(tree=tree):
                profile = tomllib.loads(
                    (REPO_ROOT / tree / "Cargo.toml").read_text(encoding="utf-8")
                )["profile"]["release"]
                package = profile.pop("package", {})
                self.assertEqual(profile, shipped)
                self.assertEqual(
                    {name: table["opt-level"] for name, table in package.items()},
                    overrides,
                )
                for table in package.values():
                    self.assertEqual(set(table), {"opt-level"})

    def test_every_unsafe_opt_in_is_named_at_its_crate_root(self) -> None:
        """`unsafe_code` is `deny`, so each of the four members that needs it
        carries one crate-level `#![allow(unsafe_code)]` with the reason directly
        above it. Pin that set, so a fifth opt-in has to be argued for in review
        rather than added quietly.

        Pin the `SAFETY:` coverage too, per block rather than per file.
        CONTRIBUTING.md asks every `unsafe` block to name its invariant, and
        two of the four opted-in files do. `apps/lua/src/main.rs` documents 12
        of 43, and its header names that gap; `apps/python/src/main.rs`
        documents 3 of 4. The allowance below is a ceiling on the undocumented
        blocks, so the debt can only shrink and a new bare block fails here."""
        undocumented_allowance = {
            "apps/lua/src/main.rs": 31,
            "apps/python/src/main.rs": 1,
        }
        opted_in = {}
        for tree in ("apps", "services"):
            for source in sorted((REPO_ROOT / tree).rglob("*.rs")):
                relative = source.relative_to(REPO_ROOT).as_posix()
                if relative.startswith(("apps/lua/vendor/", "apps/python/patches/")):
                    continue
                text = source.read_text(encoding="utf-8")
                if "#![allow(unsafe_code)]" in text:
                    opted_in[relative] = text
        self.assertEqual(
            sorted(opted_in),
            [
                "apps/lua/src/main.rs",
                "apps/mem/src/main.rs",
                "apps/python/src/main.rs",
                "services/diagnostics-fault/src/main.rs",
            ],
        )
        for relative, text in opted_in.items():
            with self.subTest(source=relative):
                lines = text.splitlines()
                index = lines.index("#![allow(unsafe_code)]")
                self.assertTrue(lines[index - 1].startswith("// "), relative)
                self.assertGreaterEqual(text.count("SAFETY:"), 1, relative)
                undocumented = [
                    number
                    for number, line in enumerate(lines, start=1)
                    if "unsafe {" in line
                    and not any(
                        "SAFETY:" in preceding
                        for preceding in lines[max(number - 5, 0) : number - 1]
                    )
                ]
                self.assertLessEqual(
                    len(undocumented),
                    undocumented_allowance.get(relative, 0),
                    f"{relative}: `unsafe` blocks with no `SAFETY:` note in the "
                    f"four lines above them, at {undocumented}",
                )

    def test_panicking_allowance_stays_inside_build_scripts(self) -> None:
        """`unwrap_used`, `expect_used`, and `panic` are `deny` for both trees.
        A build script is the one place that has to be allowed to panic: it has
        no caller to return an error to. Pin the exception to build scripts, so
        the allowance cannot migrate into a shipped source file, where a panic
        would abort a running command instead of a build."""
        allowance = re.compile(
            r"#!?\[allow\([^)]*clippy::(?:expect_used|panic|unwrap_used)"
        )
        allowed_in = []
        for tree in ("apps", "services"):
            for source in sorted((REPO_ROOT / tree).rglob("*.rs")):
                relative = source.relative_to(REPO_ROOT).as_posix()
                if relative.startswith(("apps/lua/vendor/", "apps/python/patches/")):
                    continue
                if allowance.search(source.read_text(encoding="utf-8")):
                    self.assertEqual(source.name, "build.rs", relative)
                    allowed_in.append(relative)
        self.assertEqual(allowed_in, ["apps/lua/build.rs", "apps/python/build.rs"])

    def test_shipped_locks_add_no_unaudited_external_crate(self) -> None:
        """`scripts/audit.py` audits the root `Cargo.lock` only. That is sound
        exactly while `apps/Cargo.lock` and `services/Cargo.lock` name no
        registry crate the root lock does not already pin at the same version.
        Assert it, so adding a boundary dependency to a command fails here
        instead of silently leaving the RustSec gate."""
        def registry_crates(lock: Path) -> dict[str, str]:
            pinned: dict[str, str] = {}
            for entry in lock.read_text(encoding="utf-8").split("[[package]]")[1:]:
                if "source = " not in entry:
                    continue
                name = re.search(r'name = "([^"]+)"', entry)
                version = re.search(r'version = "([^"]+)"', entry)
                self.assertIsNotNone(name)
                self.assertIsNotNone(version)
                if name is not None and version is not None:
                    pinned[name.group(1)] = version.group(1)
            return pinned

        audited = registry_crates(REPO_ROOT / "Cargo.lock")
        for tree in ("apps", "services"):
            with self.subTest(tree=tree):
                shipped = registry_crates(REPO_ROOT / tree / "Cargo.lock")
                self.assertEqual(
                    {
                        name: version
                        for name, version in shipped.items()
                        if audited.get(name) != version
                    },
                    {},
                )

    def test_the_lint_gate_reaches_every_shipped_package_it_can_compile(self) -> None:
        """The full gate lints one package at a time on both bare-metal targets,
        because Cargo unifies features across a workspace build and `ls` and
        `mem` take `troe-kex-runtime` without the `alloc` feature that `cp`,
        `mv`, and `rm` enable. `python` is the single exclusion: its build script
        needs the CPython tree generated outside the repository."""
        self.assertEqual(UNLINTABLE_APPLICATIONS, {"python"})
        self.assertEqual(KEX_TARGETS, ("x86_64-unknown-none", "aarch64-unknown-none"))
        lintable = {path.name for path in lintable_application_directories()}
        self.assertEqual(
            lintable, {path.name for path in application_directories()} - {"python"}
        )
        import test as full_gate  # noqa: PLC0415

        labels = [
            step.label
            for step in full_gate.verification_steps(
                argparse.Namespace(
                    skip_qemu=True,
                    strict_tool_versions=False,
                    build_sbsa_firmware=False,
                )
            )
        ]
        expected = [f"clippy app ({name})" for name in sorted(lintable)]
        expected += [
            f"clippy service ({path.name})" for path in service_directories()
        ]
        expected += [
            "cargo fmt (applications)",
            "cargo fmt (services)",
            "clippy applications (host unit tests)",
            "cargo test applications",
        ]
        self.assertEqual(sorted(set(labels) & set(expected)), sorted(expected))

    def test_the_gate_builds_the_member_it_cannot_byte_check(self) -> None:
        """A shared-volume deliverable ships no committed `.kex`, so `--check`
        has nothing to compare against and only a QEMU acceptance run would
        otherwise build one. That left `cargo kex build` unexercised for the two
        members whose sources are largest. `lua` is built by the full gate
        instead; `python` cannot be, because its build script consumes the
        out-of-tree CPython tree."""
        shared = {path.name for path in buildable_shared_volume_directories()}
        self.assertEqual(shared, SHARED_VOLUME_APPLICATIONS - UNLINTABLE_APPLICATIONS)
        self.assertEqual(shared, {"lua"})
        checked = {path.name for path in rootfs_application_directories()}
        self.assertEqual(checked & SHARED_VOLUME_APPLICATIONS, set())
        import test as full_gate  # noqa: PLC0415

        labels = {
            step.label
            for step in full_gate.verification_steps(
                argparse.Namespace(
                    skip_qemu=True,
                    strict_tool_versions=False,
                    build_sbsa_firmware=False,
                )
            )
        }
        self.assertEqual(
            {label for label in labels if label.startswith("kex shared app (")},
            {f"kex shared app ({name})" for name in shared},
        )

    def test_the_unlinted_member_keeps_the_denied_constructs_out(self) -> None:
        """`unwrap_used`, `expect_used`, and `panic` are `deny` for the whole
        tree, but `python` is outside the lint gate, so nothing compiles those
        denies against its shipped source. Substitute a textual check for the
        one member clippy cannot reach, so the guarantee the workspace declares
        is at least enforced for the constructs the denies name. `build.rs` is
        exempt: a build script has no caller to return an error to, which is
        what `test_panicking_allowance_stays_inside_build_scripts` pins."""
        denied = re.compile(r"\.unwrap\(|\.expect\(|\b(?:panic|unreachable|todo|unimplemented)!")
        checked = []
        for name in sorted(UNLINTABLE_APPLICATIONS):
            for source in sorted((REPO_ROOT / "apps" / name).rglob("*.rs")):
                relative = source.relative_to(REPO_ROOT).as_posix()
                if source.name == "build.rs" or relative.startswith(
                    "apps/python/patches/"
                ):
                    continue
                found = [
                    number
                    for number, line in enumerate(
                        source.read_text(encoding="utf-8").splitlines(), start=1
                    )
                    if denied.search(line)
                ]
                self.assertEqual(found, [], f"{relative}: denied construct at {found}")
                checked.append(relative)
        self.assertEqual(checked, ["apps/python/src/main.rs"])

    def test_the_shared_include_records_its_standalone_source_path(self) -> None:
        """33 commands pull `apps/common.rs` in with
        `#[path = "../../common.rs"]`, and rustc records that spelling relative
        to the crate root rather than normalising it, so a shipped package names
        the file `src/../../common.rs`. Six committed artifacts carry that
        string. A workspace build shortens it to
        `<member>/src/../../common.rs`, and the builder's member remapping
        strips the member prefix back off, which is why the include needs no
        remapping of its own and why membership did not regenerate those six
        packages. Assert the committed bytes, so a remapping that stopped
        covering the include is named here rather than only failing
        `cargo kex build --check`."""
        carriers = []
        for architecture in ("x86_64", "aarch64"):
            binaries = REPO_ROOT / "rootfs" / "bin" / architecture
            for artifact in sorted(binaries.glob("*.kex")):
                data = artifact.read_bytes()
                if b"common.rs" not in data:
                    continue
                relative = artifact.relative_to(REPO_ROOT).as_posix()
                self.assertIn(b"src/../../common.rs", data, relative)
                self.assertNotIn(
                    f"{artifact.stem}/src/../../common.rs".encode(), data, relative
                )
                self.assertNotIn(b"/troe/apps/common.rs", data, relative)
                carriers.append(artifact.stem)
        self.assertEqual(
            sorted(set(carriers)), ["cp", "grep", "head", "mv", "tail", "touch"]
        )


if __name__ == "__main__":
    unittest.main()

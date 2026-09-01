#!/usr/bin/env python3
"""Host-only contract tests for the versioned TROE CPython integration."""

from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import build_cpython

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "apps" / "python"


class CpythonIntegrationTests(unittest.TestCase):
    """Keep the authenticated build, static policy, and package layout explicit."""

    def test_release_lock_preserves_stabilization_order_and_authenticated_inputs(
        self,
    ) -> None:
        releases = build_cpython.releases()
        self.assertEqual(
            [release.version for release in releases],
            ["3.14.7", "3.13.15", "3.12.14"],
        )
        self.assertEqual(releases[0].version, build_cpython.DEFAULT_VERSION)
        self.assertEqual(len({release.sha256 for release in releases}), 3)
        for release in releases:
            self.assertRegex(release.sha256, r"^[0-9a-f]{64}$")
            self.assertEqual(
                release.url,
                f"https://www.python.org/ftp/python/{release.version}/{release.archive_name}",
            )
            self.assertEqual(release.sigstore_url, release.url + ".sigstore")
            self.assertTrue(release.certificate_identity.endswith("@python.org"))
            self.assertTrue(release.certificate_oidc_issuer.startswith("https://"))

    def test_authentication_is_offline_identity_bound_and_digest_pinned(self) -> None:
        release = build_cpython.releases()[0]
        with tempfile.TemporaryDirectory(prefix="troe-cpython-auth-") as temporary:
            cache = Path(temporary)
            archive = cache / release.archive_name
            bundle = cache / f"{release.archive_name}.sigstore"
            archive.write_bytes(b"wrong archive")
            bundle.write_bytes(b"bundle")
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                build_cpython.authenticate_source(release, cache, "sigstore", True)
            archive.unlink()
            with self.assertRaisesRegex(
                RuntimeError, "offline source cache entry is missing"
            ):
                build_cpython.authenticate_source(release, cache, "sigstore", True)

    def test_configure_and_builtin_policies_disable_forbidden_facilities(self) -> None:
        forbidden = {
            "_socket",
            "_ssl",
            "_sqlite3",
            "_ctypes",
            "_multiprocessing",
            "_posixsubprocess",
            "readline",
            "_curses",
            "_tkinter",
            "_signal",
        }
        for release in build_cpython.releases():
            options = build_cpython.configure_options(
                release, "x86_64", "/build/python"
            )
            self.assertIn("--disable-shared", options)
            self.assertIn("--without-ensurepip", options)
            self.assertIn("--disable-ipv6", options)
            self.assertIn("--disable-test-modules", options)
            self.assertIn("--without-readline", options)
            self.assertIn("--with-tzpath=", options)
            setup = build_cpython.setup_local(release).read_text(encoding="utf-8")
            static, disabled = setup.split("*disabled*", 1)
            self.assertTrue(forbidden.isdisjoint(static.split()))
            self.assertTrue(forbidden.issubset(set(disabled.split())))
        manifest = (APP_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn(
            'capabilities = ["filesystem-read", "filesystem-mutate", "timer", '
            '"wall-clock", "private-memory", "random"]',
            manifest,
        )
        for capability in ("tcp-connect", "datagram", "process-launch", "pipe"):
            self.assertNotIn(f'"{capability}"', manifest)

    def test_pyconfig_owns_identity_paths_and_isolation(self) -> None:
        launcher = (APP_ROOT / "c" / "troe_cpython.c").read_text(encoding="utf-8")
        for setting in (
            "PyPreConfig_InitIsolatedConfig",
            "PyConfig_InitIsolatedConfig",
            "config.use_environment = 0",
            "config.user_site_directory = 0",
            "config.site_import = 0",
            "config.write_bytecode = 0",
            "config.install_signal_handlers = 0",
            "config.safe_path = 1",
            "config.module_search_paths_set = 1",
            'SET_PATH(filesystem_encoding, "utf-8")',
            'SET_PATH(program_name, "python" TROE_CPYTHON_SERIES)',
            "TROE_CPYTHON_PACKAGES",
            "TROE_CPYTHON_SERIES_PACKAGES",
        ):
            self.assertIn(setting, launcher)
        self.assertNotIn("site-packages", launcher)
        self.assertNotIn('"site"', launcher)
        for convention in (
            "install_interactive_builtins",
            "builtins.exit = _TroeQuitter('exit')",
            "builtins.quit = _TroeQuitter('quit')",
        ):
            self.assertIn(convention, launcher)
        patch = (APP_ROOT / "patches" / "troe.patch").read_text(encoding="utf-8")
        self.assertIn("ac_sys_system=TROE", patch)
        builder = (REPO_ROOT / "tools" / "build_cpython.py").read_text(encoding="utf-8")
        self.assertIn('"MACHDEP": "troe"', builder)

    def test_command_line_paths_are_anchored_to_the_caller(self) -> None:
        argv = [
            "build_cpython.py",
            "build",
            "build/cpython-package",
            "--source-cache",
            "build/cpython-cache",
            "--work-directory",
            "build/cpython-work",
        ]
        with mock.patch.object(sys, "argv", argv):
            args = build_cpython.parse_args()
        self.assertEqual(args.output, Path.cwd() / "build" / "cpython-package")
        self.assertEqual(args.source_cache, Path.cwd() / "build" / "cpython-cache")
        self.assertEqual(args.work_directory, Path.cwd() / "build" / "cpython-work")

    def test_seeding_never_falls_back_from_capability_backed_entropy(self) -> None:
        self.assertEqual(build_cpython.PATCH, APP_ROOT / "patches" / "troe.patch")
        patch = build_cpython.PATCH.read_text(encoding="utf-8")
        sections = {
            block.split(" b/", 1)[0]: block
            for block in patch.split("diff --git a/")[1:]
        }
        patched = "\n".join(
            line[1:]
            for line in sections["Modules/_randommodule.c"].splitlines()
            if line.startswith((" ", "+")) and not line.startswith("+++")
        )
        for token in (
            "#ifdef __TROE__",
            "return random_seed_urandom(self);",
            "#else",
            "#endif",
        ):
            self.assertIn(token, patched)
        guard = patched.index("#ifdef __TROE__")
        direct = patched.index("return random_seed_urandom(self);")
        upstream = patched.index("#else")
        end = patched.index("#endif")
        self.assertLess(guard, direct)
        self.assertLess(direct, upstream)
        self.assertLess(upstream, end)
        self.assertNotIn("PyErr_Clear", patched[guard:upstream])
        self.assertNotIn("random_seed_time_pid", patched[guard:upstream])
        withheld = {
            "python-no-random": "random",
            "python-no-mutate": "filesystem-mutate",
            "python-no-clock": "wall-clock",
        }
        self.assertEqual(set(build_cpython.NEGATIVE_VARIANTS), set(withheld))
        declaration = next(
            line
            for line in (APP_ROOT / "Cargo.toml")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.startswith("capabilities = ")
        )
        granted = json.loads(declaration.split("=", 1)[1].strip())
        for name, capability in withheld.items():
            variant = (REPO_ROOT / "tests" / name / "Cargo.toml").read_text(
                encoding="utf-8"
            )
            self.assertNotIn(f'"{capability}"', variant)
            self.assertIn('path = "../../apps/python/src/main.rs"', variant)
            self.assertIn('build = "../../apps/python/build.rs"', variant)
            for retained in granted:
                if retained != capability:
                    self.assertIn(f'"{retained}"', variant)

    def test_stdlib_install_emits_machine_readable_included_and_excluded_manifests(
        self,
    ) -> None:
        release = build_cpython.releases()[0]
        policy = build_cpython.load_json(build_cpython.STDLIB_POLICY)
        with tempfile.TemporaryDirectory(prefix="troe-cpython-stdlib-") as temporary:
            root = Path(temporary)
            source = root / "source"
            build = root / "build"
            destination = root / "output"
            (source / "Lib" / "package").mkdir(parents=True)
            (source / "Lib" / "ensurepip").mkdir()
            (source / "Lib" / "json.py").write_text("VALUE = 1\n", encoding="utf-8")
            (source / "Lib" / "socket.py").write_text("VALUE = 2\n", encoding="utf-8")
            (source / "Lib" / "package" / "__init__.py").write_text(
                "VALUE = 3\n", encoding="utf-8"
            )
            (source / "Lib" / "ensurepip" / "__init__.py").write_text(
                "VALUE = 4\n", encoding="utf-8"
            )
            (build / "Modules").mkdir(parents=True)
            (build / "Modules" / "config.c").write_text(
                "struct _inittab _PyImport_Inittab[] = {\n"
                '    {"math", PyInit_math},\n'
                "    /* Sentinel */\n"
                "};\n",
                encoding="utf-8",
            )
            metrics = build_cpython.install_stdlib(
                release, source, build, destination, policy
            )
            self.assertTrue((destination / "json.py").is_file())
            self.assertTrue((destination / "package" / "__init__.py").is_file())
            self.assertFalse((destination / "socket.py").exists())
            self.assertFalse((destination / "ensurepip").exists())
            included = json.loads(
                (destination / "TROE-MODULES-INCLUDED.json").read_text(encoding="utf-8")
            )
            excluded = json.loads(
                (destination / "TROE-MODULES-EXCLUDED.json").read_text(encoding="utf-8")
            )
            included_by_name = {item["name"]: item for item in included["modules"]}
            excluded_by_name = {item["name"]: item for item in excluded["modules"]}
            self.assertEqual(included_by_name["math"]["kind"], "built-in")
            self.assertIn("json", included_by_name)
            self.assertIn("package", included_by_name)
            self.assertIn("socket", excluded_by_name)
            self.assertIn("ensurepip", excluded_by_name)
            self.assertGreater(metrics["included_modules"], 2)
            self.assertGreater(metrics["excluded_modules"], 2)
            self.assertGreater(metrics["stdlib_bytes"], 0)

    def test_kex_page_measurement_reads_exact_package_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="troe-cpython-kex-") as temporary:
            path = Path(temporary) / "python.kex"
            artifact = bytearray(48 + 88 + 2 * 40)
            artifact[:8] = b"KEXPKG\0\0"
            struct.pack_into("<I", artifact, 24, 48)
            struct.pack_into("<Q", artifact, 32, len(artifact) - 48)
            executable = memoryview(artifact)[48:]
            executable[:8] = b"KEX\0FMT\0"
            struct.pack_into("<HH", executable, 14, 88, 40)
            struct.pack_into("<H", executable, 32, 2)
            struct.pack_into("<Q", executable, 88 + 24, 3 * 4096)
            struct.pack_into("<Q", executable, 88 + 40 + 24, 5 * 4096)
            path.write_bytes(artifact)
            self.assertEqual(build_cpython.kex_image_pages(path), 8)

    def test_package_records_and_enforces_per_component_size_ceilings(self) -> None:
        policy = build_cpython.load_json(build_cpython.STDLIB_POLICY)
        self.assertEqual(
            set(policy["limits"]),
            {"kex_bytes", "image_mapped_pages", "stdlib_bytes"},
        )
        for ceiling in policy["limits"].values():
            self.assertGreater(ceiling, 0)
        release = build_cpython.releases()[0]
        with tempfile.TemporaryDirectory(prefix="troe-cpython-limits-") as temporary:
            root = Path(temporary)
            source = root / "source"
            build = root / "build"
            artifact = root / "input.kex"
            (source / "Lib").mkdir(parents=True)
            (build / "Modules").mkdir(parents=True)
            (build / "Modules" / "config.c").write_text(
                "struct _inittab _PyImport_Inittab[] = {\n    /* Sentinel */\n};\n",
                encoding="utf-8",
            )
            artifact.write_bytes(b"test artifact")
            inspect = json.dumps(
                {
                    "format": "KEX package v1",
                    "target": "x86_64",
                    "stack_pages": 128,
                    "heap_pages": 8192,
                }
            )
            narrowed = dict(policy)
            narrowed["limits"] = dict(policy["limits"], image_mapped_pages=6)
            with (
                mock.patch.object(build_cpython, "run", return_value=inspect),
                mock.patch.object(build_cpython, "kex_image_pages", return_value=7),
            ):
                with self.assertRaisesRegex(RuntimeError, "above the accepted ceiling"):
                    build_cpython.install_release(
                        root / "package",
                        release,
                        source,
                        build,
                        "x86_64",
                        artifact,
                        narrowed,
                    )
                build_cpython.install_release(
                    root / "accepted",
                    release,
                    source,
                    build,
                    "x86_64",
                    artifact,
                    policy,
                )
            record = json.loads(
                (
                    root
                    / "accepted"
                    / "lib"
                    / "x86_64"
                    / f"python{release.version}"
                    / "TROE-BUILD.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(record["image_mapped_pages"], 7)
            self.assertEqual(record["kex_bytes"], artifact.stat().st_size)
            self.assertEqual(record["limits"], policy["limits"])

    def test_default_aliases_exist_only_for_the_newest_release(self) -> None:
        policy = build_cpython.load_json(build_cpython.STDLIB_POLICY)
        with tempfile.TemporaryDirectory(prefix="troe-cpython-layout-") as temporary:
            root = Path(temporary)
            source = root / "source"
            build = root / "build"
            artifact = root / "input.kex"
            (source / "Lib").mkdir(parents=True)
            (build / "Modules").mkdir(parents=True)
            (build / "Modules" / "config.c").write_text(
                "struct _inittab _PyImport_Inittab[] = {\n    /* Sentinel */\n};\n",
                encoding="utf-8",
            )
            artifact.write_bytes(b"test artifact")
            inspect = json.dumps(
                {
                    "format": "KEX package v1",
                    "target": "x86_64",
                    "stack_pages": 128,
                    "heap_pages": 8192,
                }
            )
            with (
                mock.patch.object(build_cpython, "run", return_value=inspect),
                mock.patch.object(build_cpython, "kex_image_pages", return_value=7),
            ):
                for release in build_cpython.releases():
                    build_cpython.install_release(
                        root / "package",
                        release,
                        source,
                        build,
                        "x86_64",
                        artifact,
                        policy,
                    )
            binaries = {
                path.name
                for path in (root / "package" / "bin" / "x86_64").glob("*.kex")
            }
            self.assertEqual(
                binaries,
                {
                    "python.kex",
                    "python3.kex",
                    "python3.14.kex",
                    "python3.14.7.kex",
                    "python3.13.kex",
                    "python3.13.15.kex",
                    "python3.12.kex",
                    "python3.12.14.kex",
                },
            )


if __name__ == "__main__":
    unittest.main()

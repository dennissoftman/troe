"""Hosted checks for the canonical repo-local Rust KEX application tool."""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

from repository_policy import rootfs_application_directories  # noqa: E402

from tools import thread_profile  # noqa: E402

KEX_APPLICATION_NAMES = tuple(
    path.name for path in rootfs_application_directories(REPO_ROOT)
)
KEX_TOOL = Path(os.environ.get("CARGO_TARGET_DIR", REPO_ROOT / "target"))
if not KEX_TOOL.is_absolute():
    KEX_TOOL = REPO_ROOT / KEX_TOOL
KEX_TOOL = (
    KEX_TOOL / "debug" / ("troe-kex-tool.exe" if os.name == "nt" else "troe-kex-tool")
)


def cargo_kex(*arguments: object) -> subprocess.CompletedProcess[bytes]:
    """Run the already-built canonical CLI without one Cargo process per case."""
    return subprocess.run(
        (KEX_TOOL, *(str(argument) for argument in arguments)),
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
    )


class KexToolTests(unittest.TestCase):
    """Keep canonical build, inspection, and installed bytes stable."""

    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ("cargo", "build", "--quiet", "--package", "troe-kex-tool"),
            cwd=REPO_ROOT,
            check=True,
        )

    def test_installed_example_artifacts_are_canonical_for_each_target(self) -> None:
        for command in KEX_APPLICATION_NAMES:
            for target in ("x86_64", "aarch64"):
                with self.subTest(command=command, target=target):
                    artifact = REPO_ROOT / "rootfs" / "bin" / target / f"{command}.kex"
                    inspected = cargo_kex("inspect", artifact, "--json")
                    self.assertEqual(inspected.returncode, 0, inspected.stderr.decode())
                    report = json.loads(inspected.stdout)
                    self.assertEqual(report["format"], "KEX package v1")
                    self.assertEqual(report["executable_format"], "KEX v1")
                    self.assertEqual(report["abi"], "1.3")
                    # Every application declares the span its image needs
                    # rather than one fixed window.
                    self.assertEqual(report["image_span_bytes"] % (2 * 1024 * 1024), 0)
                    self.assertGreater(report["image_span_bytes"], 0)
                    self.assertEqual(report["target"], target)
                    expected_stack_pages = (
                        64
                        if command == "lua"
                        else 64
                        if command == "grep"
                        else 12
                        if command in {"cp", "mv", "rm", "spawn", "tar"}
                        else 8
                        if command in {"arp", "ps", "tail", "top"}
                        else 20
                        if command in {"awk", "sed"}
                        else 4
                    )
                    self.assertEqual(report["stack_pages"], expected_stack_pages)
                    expected_heap_pages = {
                        "cp": 16,
                        "lua": 256,
                        "mv": 4,
                        "rm": 16,
                    }.get(command, 0)
                    self.assertEqual(report["heap_pages"], expected_heap_pages)
                    package_bytes = artifact.read_bytes()
                    self.assertEqual(package_bytes[:8], b"KEXPKG\0\0")
                    (
                        major,
                        minor,
                        header_bytes,
                        flags,
                        capability_offset,
                        capability_bytes,
                        executable_offset,
                        executable_bytes,
                        completion_offset,
                        completion_bytes,
                        encoded_bytes,
                    ) = struct.unpack_from("<HHHHIIQQQQQ", package_bytes, 8)
                    self.assertEqual((major, minor, header_bytes, flags), (1, 1, 80, 1))
                    self.assertEqual(package_bytes[64:80], bytes(16))
                    self.assertEqual(
                        completion_bytes, len(package_bytes) - completion_offset
                    )
                    self.assertEqual(capability_offset, header_bytes)
                    self.assertEqual(
                        executable_offset, capability_offset + capability_bytes
                    )
                    self.assertEqual(
                        executable_offset + executable_bytes, completion_offset
                    )
                    self.assertLess(completion_offset, len(package_bytes))
                    self.assertEqual(encoded_bytes, len(package_bytes))
                    self.assertEqual(report["bytes"], len(package_bytes))
                    self.assertEqual(report["executable_bytes"], executable_bytes)
                    completion = package_bytes[completion_offset:]
                    self.assertEqual(
                        completion,
                        (REPO_ROOT / "apps" / command / "completion.cmpl").read_bytes(),
                    )
                    self.assertEqual(
                        completion.splitlines()[0], f"CMPL\t1\t{command}".encode()
                    )
                    capability_bytes = package_bytes[
                        capability_offset:executable_offset
                    ]
                    self.assertEqual(capability_bytes[:8], b"KCAPv1\0\0")
                    count, minor, encoded_bytes = struct.unpack_from(
                        "<HHI", capability_bytes, 8
                    )
                    self.assertEqual(minor, 1)
                    self.assertEqual(capability_bytes[16:24], bytes(8))
                    self.assertEqual(encoded_bytes, len(capability_bytes))
                    records = [
                        struct.unpack_from("<IHHHHI", capability_bytes, 24 + index * 16)
                        for index in range(count)
                    ]
                    if command == "udp":
                        expected = [(5, 1, 0)]
                    elif command == "tar" or command in {
                        "cp",
                        "mkdir",
                        "mv",
                        "rm",
                        "touch",
                    }:
                        expected = [(6, 1, 5), (7, 1, 5)]
                    elif command in {
                        "awk",
                        "cat",
                        "grep",
                        "head",
                        "hexdump",
                        "ls",
                        "man",
                        "sed",
                        "tail",
                        "wc",
                    }:
                        expected = [(6, 1, 5)]
                    elif command == "lua":
                        expected = [
                            (6, 1, 5),
                            (7, 1, 5),
                            (8, 1, 1),
                            (17, 1, 1),
                            (20, 1, 0),
                            (21, 1, 0),
                            (22, 1, 0),
                            (23, 1, 0),
                        ]
                    elif command in {"ln", "rmdir"}:
                        expected = [(7, 1, 5)]
                    elif command == "sleep":
                        expected = [(8, 1, 1)]
                    elif command == "date":
                        expected = [(17, 1, 1)]
                    elif command == "timesync":
                        expected = [(5, 1, 0), (8, 1, 1), (18, 1, 1)]
                    elif command == "mem":
                        expected = [(9, 1, 0), (22, 1, 0), (23, 1, 0)]
                    elif command == "ps":
                        expected = [(19, 1, 1)]
                    elif command == "top":
                        expected = [(8, 1, 1), (19, 1, 1)]
                    elif command in {"arp", "net"}:
                        expected = [(10, 1, 0)]
                    elif command == "dhcp":
                        expected = [(11, 1, 0)]
                    elif command == "ping":
                        expected = [(12, 1, 0)]
                    elif command == "tcp":
                        expected = [(13, 1, 0)]
                    elif command == "mount":
                        expected = [(14, 1, 0)]
                    elif command == "sh":
                        expected = [(6, 1, 5), (16, 1, 0)]
                    elif command == "spawn":
                        expected = [(6, 1, 5), (20, 1, 0), (21, 1, 0)]
                    else:
                        expected = []
                    self.assertEqual(
                        records, [(*record, 0, 0, 0) for record in expected]
                    )
                    self.assertEqual(report["requirements"], len(expected))
                    self.assertFalse(artifact.with_suffix(".kcap").exists())

    def test_build_check_uses_pinned_app_contract(self) -> None:
        checked = cargo_kex("build", "apps/echo", "--target", "x86_64", "--check")
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        self.assertIn(b"KEX package verified", checked.stdout)
        self.assertNotIn(
            os.fsencode(REPO_ROOT),
            (REPO_ROOT / "rootfs/bin/x86_64/echo.kex").read_bytes(),
        )

    def test_inspection_rejects_corruption_and_command_names_are_narrow(self) -> None:
        artifact = REPO_ROOT / "rootfs" / "bin" / "x86_64" / "echo.kex"
        with tempfile.TemporaryDirectory() as directory:
            package_bytes = artifact.read_bytes()
            executable_offset = struct.unpack_from("<Q", package_bytes, 24)[0]
            completion_offset = struct.unpack_from("<Q", package_bytes, 40)[0]
            raw = Path(directory) / "raw.kex"
            raw.write_bytes(package_bytes[executable_offset:completion_offset])
            raw_inspection = cargo_kex("inspect", raw, "--json")
            self.assertEqual(
                raw_inspection.returncode, 0, raw_inspection.stderr.decode()
            )
            raw_report = json.loads(raw_inspection.stdout)
            self.assertEqual(raw_report["format"], "KEX v1")
            self.assertEqual(raw_report["requirements"], 0)

            corrupt = Path(directory) / "corrupt.kex"
            corrupt.write_bytes(package_bytes[:-1])
            inspected = cargo_kex("inspect", corrupt)
            self.assertNotEqual(inspected.returncode, 0)
            self.assertIn(b"invalid KEX package", inspected.stderr)
        for invalid in ("", "Echo", "../echo", "echo.kex", "écho"):
            with self.subTest(name=invalid):
                rejected = cargo_kex(
                    "build",
                    "apps/echo",
                    "--name",
                    invalid,
                    "--target",
                    "x86_64",
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(b"command name", rejected.stderr)


class StaticTlsTests(unittest.TestCase):
    """Compare portable TLS policy with actual cross-target compiler output."""

    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ("cargo", "build", "--quiet", "--package", "troe-kex-tool"),
            cwd=REPO_ROOT,
            check=True,
        )

    def layout(
        self, target: str, file: int, memory: int, alignment: int, pages: int = 4097
    ) -> dict[str, int | str]:
        """Read the actual Rust planner rather than duplicating it in Python."""
        result = cargo_kex(
            "tls-layout",
            "--target",
            target,
            "--file-bytes",
            file,
            "--memory-bytes",
            memory,
            "--alignment",
            alignment,
            "--max-pages",
            pages,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def compile_probe(self, root: Path, target: str, source: str) -> Path:
        """Use the reviewed compiler recipe for every geometry/rejection fixture."""
        return thread_profile.compile_probe(
            root,
            target,
            source,
            os.environ.get("TROE_TLS_CC", "clang"),
            os.environ.get("TROE_TLS_LD", "ld.lld"),
        )

    def test_empty_tls_still_charges_a_control_block(self) -> None:
        for target, offset in (("x86_64", 0), ("aarch64", 16)):
            with self.subTest(target=target):
                layout = self.layout(target, 0, 0, 1, 1)
                self.assertEqual(layout["template_offset"], offset)
                self.assertEqual(layout["thread_pointer_offset"], 0)
                self.assertEqual(layout["mapped_bytes"], 4096)
                self.assertEqual(layout["pages"], 1)

    def test_c_profile_uses_troe_headers_lp64_and_local_exec_storage(self) -> None:
        source = """
#include <troe/runtime.h>
#include <stdatomic.h>
#if !defined(__ELF__) || defined(__linux__) || __STDC_HOSTED__ != 0
#error Wrong target personality
#endif
_Static_assert(__STDC_VERSION__ == 201112L, "C11 profile required");
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "little endian required");
_Static_assert(sizeof(int) == 4 && sizeof(float) == 4 && sizeof(double) == 8,
               "scalar ABI changed");
_Static_assert(_Alignof(void *) == 8, "pointer alignment changed");
_Static_assert(__atomic_always_lock_free(8, 0), "native word atomics required");
_Static_assert(TROE_C_RUNTIME_ABI == 1, "review runtime ownership on ABI change");
_Thread_local unsigned long observed[2];
void _start(const void *descriptor, unsigned long bytes) {
  observed[0] = (unsigned long)descriptor; observed[1] = bytes;
}
void __troe_thread_start_v1(const void *descriptor, unsigned long bytes) {
  observed[0] = (unsigned long)descriptor; observed[1] = bytes;
}
"""
        for target in ("x86_64", "aarch64"):
            with tempfile.TemporaryDirectory(prefix="troe-c-profile-") as directory:
                root = Path(directory)
                elf = self.compile_probe(root, target, source)
                output = root / "profile.kex"
                result = cargo_kex("convert", elf, output, "--threaded")
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                report = json.loads(cargo_kex("inspect", output, "--json").stdout)
                self.assertEqual(report["tls"]["file_bytes"], 0)
                self.assertEqual(report["tls"]["memory_bytes"], 16)
                # Runtime ABI 1 still exports global errno. A compiler profile
                # must not silently turn that declaration into a TLS ABI.
                with self.assertRaises(subprocess.CalledProcessError) as rejected:
                    self.compile_probe(
                        root, target, "#include <errno.h>\n_Thread_local int errno;\n"
                    )
                self.assertIn(b"thread-local", rejected.exception.stderr)

    def test_layout_rejects_malformed_or_underfunded_requests(self) -> None:
        valid = [
            "tls-layout",
            "--target",
            "x86_64",
            "--file-bytes",
            "3",
            "--memory-bytes",
            "37",
            "--alignment",
            "64",
            "--max-pages",
            "1",
        ]
        for flag, value in (
            ("--target", "arm"),
            ("--file-bytes", "38"),
            ("--file-bytes", "-1"),
            ("--memory-bytes", str(1 << 64)),
            ("--memory-bytes", str((1 << 24) + 1)),
            ("--alignment", "0"),
            ("--alignment", "3"),
            ("--max-pages", "0"),
        ):
            with self.subTest(flag=flag, value=value):
                arguments = valid.copy()
                arguments[arguments.index(flag) + 1] = value
                result = cargo_kex(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
        for extra in (("--alignment", "64"), ("--target", "aarch64"), ("--json",)):
            self.assertNotEqual(cargo_kex(*valid, *extra).returncode, 0)
        self.assertNotEqual(cargo_kex(*valid[:-2]).returncode, 0)

    def test_threaded_conversion_rejects_malformed_elf_without_replacing_output(
        self,
    ) -> None:
        source = """
_Thread_local unsigned char initialized[3] __attribute__((aligned(64))) = {19};
_Thread_local unsigned char zeroed[5];
void *address_initialized(void) { return initialized; }
void _start(void) {}
void __troe_thread_start_v1(const void *descriptor, unsigned long bytes) {}
"""
        for target in ("x86_64", "aarch64"):
            with tempfile.TemporaryDirectory(
                prefix="troe-tls-rejections-"
            ) as directory:
                root = Path(directory)
                elf = self.compile_probe(root, target, source)
                original = elf.read_bytes()
                phoff, shoff = struct.unpack_from("<QQ", original, 32)
                _, phcount, _, shcount = struct.unpack_from("<HHHH", original, 54)
                programs = {
                    struct.unpack_from("<I", original, at)[0]: at
                    for at in range(phoff, phoff + 56 * phcount, 56)
                }
                sections = [
                    struct.unpack_from("<IIQQQQIIQQ", original, shoff + index * 64)
                    for index in range(shcount)
                ]
                tls = programs[7]
                tls_sections = [i for i, s in enumerate(sections) if s[2] & 0x400]
                tdata = shoff + tls_sections[0] * 64
                tbss = shoff + tls_sections[1] * 64
                symtab_index = next(i for i, s in enumerate(sections) if s[1] == 2)
                symtab = sections[symtab_index]
                names_section = sections[symtab[6]]
                names = original[names_section[4] : names_section[4] + names_section[5]]
                symbols = {}
                for at in range(symtab[4], symtab[4] + symtab[5], 24):
                    name = struct.unpack_from("<I", original, at)[0]
                    symbols[names[name : names.index(b"\0", name)]] = at
                trampoline = symbols[b"__troe_thread_start_v1"]
                initialized = symbols[b"initialized"]
                output = root / "probe.kex"
                converted = cargo_kex("convert", elf, output, "--threaded")
                self.assertEqual(converted.returncode, 0, converted.stderr.decode())
                known_output = output.read_bytes()

                # Scalar mutations reach the real CLI and shared format reader.
                mutations = [
                    ("TLS writable", tls + 4, "I", 6),
                    ("TLS executable", tls + 4, "I", 5),
                    ("TLS unknown flags", tls + 4, "I", 0x80000004),
                    ("TLS non-power alignment", tls + 48, "Q", 3),
                    ("TLS excessive alignment", tls + 48, "Q", 1 << 25),
                    ("TLS file exceeds memory", tls + 32, "Q", 9),
                    ("TLS overflowing file", tls + 8, "Q", (1 << 64) - 1),
                    ("TLS address residue", tls + 16, "Q", 1),
                    ("TLS physical address", tls + 24, "Q", 1),
                    ("TLS excessive memory", tls + 40, "Q", 1 << 25),
                    ("TLS missing last extent", tls + 40, "Q", 9),
                    ("TLS section wrong kind", tdata + 4, "I", 3),
                    ("TLS section not allocated", tdata + 8, "Q", 0x401),
                    ("TLS section executable", tdata + 8, "Q", 0x407),
                    ("TLS section missing TLS flag", tdata + 8, "Q", 3),
                    ("TLS section wrong file", tdata + 24, "Q", 0),
                    ("TLS section starts before source", tdata + 16, "Q", 0),
                    ("TLS section excessive extent", tdata + 32, "Q", 9),
                    ("TLS section metadata", tdata + 56, "Q", 1),
                    (
                        "TLS BSS overlaps initializer",
                        tbss + 16,
                        "Q",
                        sections[tls_sections[0]][3],
                    ),
                    (
                        "TLS symbol outside template",
                        initialized + 8,
                        "Q",
                        (1 << 64) - 1,
                    ),
                    ("TLS symbol undefined", initialized + 6, "H", 0),
                    ("trampoline unnamed", trampoline, "I", 0),
                    ("symbol name outside table", trampoline, "I", len(names)),
                    ("trampoline weak", trampoline + 4, "B", 0x22),
                    ("trampoline local", trampoline + 4, "B", 0x02),
                    ("trampoline object", trampoline + 4, "B", 0x11),
                    ("trampoline undefined", trampoline + 6, "H", 0),
                    ("trampoline absolute", trampoline + 6, "H", 0xFFF1),
                    ("trampoline empty", trampoline + 16, "Q", 0),
                    ("trampoline overflow", trampoline + 16, "Q", (1 << 64) - 1),
                    ("trampoline hidden in TLS", trampoline + 6, "H", tls_sections[0]),
                    ("trampoline reserved visibility", trampoline + 5, "B", 0x80),
                    (
                        "symbol table entry width",
                        shoff + symtab_index * 64 + 56,
                        "Q",
                        25,
                    ),
                    ("symbol zero", symtab[4], "I", 1),
                ]
                if target == "aarch64":
                    entry = struct.unpack_from("<Q", original, trampoline + 8)[0]
                    mutations.append(
                        ("unaligned trampoline", trampoline + 8, "Q", entry + 1)
                    )
                bad_inputs = {}
                for name, offset, fmt, value in mutations:
                    bad = bytearray(original)
                    struct.pack_into("<" + fmt, bad, offset, value)
                    bad_inputs[name] = bad
                duplicate = bytearray(original)
                stack = programs[0x6474E551]
                duplicate[stack : stack + 56] = duplicate[tls : tls + 56]
                bad_inputs["duplicate TLS header"] = duplicate
                missing = bytearray(original)
                missing[tls : tls + 56] = bytes(56)
                bad_inputs["missing TLS header"] = missing
                duplicate_symbol = bytearray(original)
                duplicate_symbol[initialized : initialized + 24] = original[
                    trampoline : trampoline + 24
                ]
                bad_inputs["duplicate trampoline"] = duplicate_symbol
                alias = bytearray(original)
                dynamic_index = next(i for i, s in enumerate(sections) if s[1] == 6)
                struct.pack_into(
                    "<QQQ",
                    alias,
                    shoff + dynamic_index * 64 + 16,
                    sections[tls_sections[0]][3],
                    sections[tls_sections[0]][4],
                    1,
                )
                bad_inputs["initializer aliases ordinary data"] = alias
                bad_inputs["unattributed trailing byte"] = original + b"x"
                for name, bad in bad_inputs.items():
                    with self.subTest(target=target, corruption=name):
                        elf.write_bytes(bad)
                        result = cargo_kex("convert", elf, output, "--threaded")
                        self.assertNotEqual(
                            result.returncode, 0, result.stderr.decode()
                        )
                        self.assertNotIn(b"panicked", result.stderr)
                        self.assertEqual(output.read_bytes(), known_output)
                elf.write_bytes(original)
                self.assertNotEqual(
                    cargo_kex(
                        "convert", elf, output, "--threaded", "--threaded"
                    ).returncode,
                    0,
                )
                self.assertEqual(output.read_bytes(), known_output)

    def test_empty_template_and_pointer_initializer_policy(self) -> None:
        base = (
            "void _start(void) {}\n"
            "void __troe_thread_start_v1(const void *p, unsigned long n) {}\n"
        )
        for target in ("x86_64", "aarch64"):
            with tempfile.TemporaryDirectory(prefix="troe-empty-tls-") as directory:
                root = Path(directory)
                elf = self.compile_probe(root, target, base)
                output = root / "probe.kex"
                converted = cargo_kex("convert", elf, output, "--threaded")
                self.assertEqual(converted.returncode, 0, converted.stderr.decode())
                report = json.loads(cargo_kex("inspect", output, "--json").stdout)
                self.assertEqual(report["tls"]["file_bytes"], 0)
                self.assertEqual(report["tls"]["memory_bytes"], 0)
                self.assertEqual(report["tls"]["source_offset"], 0)
                elf = self.compile_probe(
                    root,
                    target,
                    base + "int shared;\n_Thread_local int *pointer = &shared;\n",
                )
                result = cargo_kex("convert", elf, output, "--threaded")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    b"TLS initializer requires unsupported pointer relocations",
                    result.stderr,
                )
                # A final ELF must not retain TLS relocation requests, even
                # though this malformed variant still has a valid RELA shape.
                image = bytearray(elf.read_bytes())
                shoff = struct.unpack_from("<Q", image, 40)[0]
                shcount = struct.unpack_from("<H", image, 60)[0]
                rela = next(
                    struct.unpack_from("<Q", image, at + 24)[0]
                    for at in range(shoff, shoff + shcount * 64, 64)
                    if struct.unpack_from("<I", image, at + 4)[0] == 4
                )
                struct.pack_into(
                    "<Q", image, rela + 8, 18 if target == "x86_64" else 1030
                )
                elf.write_bytes(image)
                self.assertNotEqual(
                    cargo_kex("convert", elf, output, "--threaded").returncode, 0
                )

    def read_probe(
        self, image: bytes, target: str
    ) -> tuple[tuple[int, int, int], dict[str, int], dict[str, bytes]]:
        """Read only fixture ELF headers and named symbols, not production input."""
        self.assertEqual(image[:7], b"\x7fELF\x02\x01\x01")
        self.assertEqual(struct.unpack_from("<H", image, 16)[0], 3)
        self.assertEqual(
            struct.unpack_from("<H", image, 18)[0],
            {"x86_64": 62, "aarch64": 183}[target],
        )
        phoff, shoff = struct.unpack_from("<QQ", image, 32)
        phsize, phcount, shsize, shcount = struct.unpack_from("<HHHH", image, 54)
        self.assertEqual((phsize, shsize), (56, 64))
        programs = [
            struct.unpack_from("<IIQQQQQQ", image, phoff + index * phsize)
            for index in range(phcount)
        ]
        tls = [header for header in programs if header[0] == 7]
        self.assertEqual(len(tls), 1)
        _, _, offset, address, _, file, memory, alignment = tls[0]
        self.assertEqual(address % alignment, 0)
        self.assertEqual(offset % alignment, 0)
        self.assertLessEqual(file, memory)
        sections = [
            struct.unpack_from("<IIQQQQIIQQ", image, shoff + index * shsize)
            for index in range(shcount)
        ]
        symbols: dict[str, int] = {}
        functions: dict[str, bytes] = {}
        for section in sections:
            if section[1] != 2:  # SHT_SYMTAB
                continue
            strings_section = sections[section[6]]
            strings = image[
                strings_section[4] : strings_section[4] + strings_section[5]
            ]
            self.assertEqual(section[9], 24)
            for position in range(section[4], section[4] + section[5], 24):
                name, info, _, index, value, size = struct.unpack_from(
                    "<IBBHQQ", image, position
                )
                name = strings[name : strings.index(b"\0", name)].decode()
                if name in {"initialized", "zeroed", "tail"}:
                    self.assertEqual(info & 15, 6)  # STT_TLS
                    symbols[name] = value
                elif name.startswith("address_"):
                    self.assertEqual(info & 15, 2)  # STT_FUNC
                    owner = sections[index]
                    start = owner[4] + value - owner[3]
                    functions[name.removeprefix("address_")] = image[
                        start : start + size
                    ]
        self.assertEqual(symbols.keys(), functions.keys())
        self.assertTrue(symbols)
        if "initialized" in symbols:
            start = offset + symbols["initialized"]
            self.assertEqual(image[start], 19)
        return (file, memory, alignment), symbols, functions

    def thread_pointer_displacement(self, target: str, code: bytes) -> int:
        """Decode the small address-return sequence emitted by the probe flags.

        Reject any other sequence so a compiler change needs deliberate review.
        These assertions verify use of FS:0 / TPIDR_EL0 as well as the offset.
        """
        if target == "x86_64":
            self.assertEqual(len(code), 17, code.hex())
            self.assertEqual(code[:12], bytes.fromhex("64488b042500000000488d80"))
            self.assertEqual(code[-1], 0xC3)
            return struct.unpack_from("<i", code, 12)[0]
        self.assertEqual(len(code), 16, code.hex())
        read_tp, high, low, ret = struct.unpack("<IIII", code)
        self.assertEqual(read_tp, 0xD53BD048)  # mrs x8, TPIDR_EL0
        immediate = 0xFFF << 10
        self.assertEqual(high & ~immediate, 0x91400108)  # add x8, x8, #hi, lsl #12
        self.assertEqual(low & ~immediate, 0x91000100)  # add x0, x8, #lo
        self.assertEqual(ret, 0xD65F03C0)
        return (((high >> 10) & 0xFFF) << 12) + ((low >> 10) & 0xFFF)

    def test_compiled_local_exec_addresses_match_explicit_tls_conversion(
        self,
    ) -> None:
        cc = os.environ.get("TROE_TLS_CC", "clang")
        linker = os.environ.get("TROE_TLS_LD", "ld.lld")
        self.assertIsNotNone(shutil.which(cc), f"TLS probes require {cc}")
        self.assertIsNotNone(shutil.which(linker), f"TLS probes require {linker}")
        versions = tuple(
            subprocess.run(
                (tool, "--version"), check=True, capture_output=True, text=True
            ).stdout.splitlines()[0]
            for tool in (cc, linker)
        )
        print(f"TLS compiler probes: {'; '.join(versions)}")
        for target in ("x86_64", "aarch64"):
            # initialized bytes/alignment, zero-filled bytes/alignment. Include
            # BSS-only, odd lengths, sub-word and over-page alignment, and offsets
            # which require both halves of the AArch64 24-bit relocation.
            for initialized, init_align, zeroed, zero_align in (
                (1, 1, 0, 1),
                (3, 2, 0, 1),
                (0, 1, 5, 1),
                (0, 1, 5, 64),
                (3, 64, 0, 1),
                (3, 8, 5, 32),
                (3, 64, 5, 32),
                (3, 64, 65537, 64),
                (3, 8192, 8193, 8192),
            ):
                with (
                    self.subTest(
                        target=target,
                        initialized=initialized,
                        init_align=init_align,
                        zeroed=zeroed,
                        zero_align=zero_align,
                        compilers=versions,
                    ),
                    tempfile.TemporaryDirectory(prefix="troe-static-tls-") as directory,
                ):
                    root = Path(directory)
                    declarations = []
                    for name, size, alignment, initializer in (
                        ("initialized", initialized, init_align, " = {19}"),
                        ("zeroed", zeroed, zero_align, ""),
                    ):
                        if size:
                            declarations.extend(
                                (
                                    f"_Thread_local unsigned char {name}[{size}] "
                                    f"__attribute__((aligned({alignment}))){initializer};",
                                    f"void *address_{name}(void) {{ return {name}; }}",
                                )
                            )
                    if zeroed:
                        # A separate symbol after BSS forces the linker to
                        # resolve a far offset, including nonzero high/low bits.
                        declarations.extend(
                            (
                                "_Thread_local unsigned char tail[1];",
                                "void *address_tail(void) { return tail; }",
                            )
                        )
                    elf = self.compile_probe(
                        root,
                        target,
                        "\n".join(
                            (
                                *declarations,
                                "void _start(void) {}",
                                "void __troe_thread_start_v1("
                                "const void *descriptor, unsigned long bytes) {}",
                            )
                        ),
                    )
                    geometry, symbols, functions = self.read_probe(
                        elf.read_bytes(), target
                    )
                    layout = self.layout(target, *geometry)
                    for name, symbol_offset in symbols.items():
                        actual = self.thread_pointer_displacement(
                            target, functions[name]
                        )
                        expected = (
                            layout["template_offset"]
                            + symbol_offset
                            - layout["thread_pointer_offset"]
                        )
                        self.assertEqual(actual, expected)
                    # Legacy conversion remains closed. Only explicit threaded
                    # conversion can emit the separate, non-admitted format.
                    output = root / "probe.kex"
                    result = cargo_kex("convert", elf, output)
                    self.assertNotEqual(result.returncode, 0)
                    if geometry[2] <= 4096:
                        self.assertIn(b"TLS", result.stderr)
                    else:
                        self.assertIn(b"PT_LOAD geometry", result.stderr)
                    self.assertFalse(output.exists())
                    converted = cargo_kex("convert", elf, output, "--threaded")
                    self.assertEqual(converted.returncode, 0, converted.stderr.decode())
                    inspected = cargo_kex("inspect", output, "--json")
                    self.assertEqual(inspected.returncode, 0, inspected.stderr.decode())
                    report = json.loads(inspected.stdout)
                    self.assertEqual(report["abi"], "1.4")
                    self.assertEqual(report["container_minor"], 3)
                    self.assertFalse(report["native_admission"])
                    metadata = report["tls"]
                    self.assertEqual(
                        (
                            metadata["file_bytes"],
                            metadata["memory_bytes"],
                            metadata["alignment"],
                        ),
                        geometry,
                    )
                    artifact = output.read_bytes()
                    self.assertEqual(
                        len(artifact), metadata["file_offset"] + geometry[0]
                    )
                    if geometry[0]:
                        self.assertEqual(artifact[metadata["file_offset"]], 19)
                    checked = cargo_kex("convert", elf, output, "--threaded", "--check")
                    self.assertEqual(checked.returncode, 0, checked.stderr.decode())


if __name__ == "__main__":
    unittest.main()

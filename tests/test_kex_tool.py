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

from repository_policy import rootfs_application_directories  # noqa: E402

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

    def test_empty_tls_still_charges_a_control_block(self) -> None:
        for target, offset in (("x86_64", 0), ("aarch64", 16)):
            with self.subTest(target=target):
                layout = self.layout(target, 0, 0, 1, 1)
                self.assertEqual(layout["template_offset"], offset)
                self.assertEqual(layout["thread_pointer_offset"], 0)
                self.assertEqual(layout["mapped_bytes"], 4096)
                self.assertEqual(layout["pages"], 1)

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

    def test_compiled_local_exec_addresses_match_layout_and_tls_stays_rejected(
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
                    source = root / "probe.c"
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
                    source.write_text(
                        "\n".join((*declarations, "void _start(void) {}"))
                    )
                    obj = root / "probe.o"
                    elf = root / "probe.elf"
                    subprocess.run(
                        (
                            cc,
                            f"--target={target}-unknown-none-elf",
                            "-std=c11",
                            "-O2",
                            "-fPIC",
                            "-ffreestanding",
                            "-fomit-frame-pointer",
                            "-fno-stack-protector",
                            "-ftls-model=local-exec",
                            "-c",
                            source,
                            "-o",
                            obj,
                        ),
                        check=True,
                        capture_output=True,
                    )
                    subprocess.run(
                        (
                            linker,
                            "-pie",
                            "-e",
                            "_start",
                            "--no-relax",
                            "--no-dynamic-linker",
                            "-z",
                            "separate-code",
                            "-z",
                            "norelro",
                            "-z",
                            "max-page-size=4096",
                            obj,
                            "-o",
                            elf,
                        ),
                        check=True,
                        capture_output=True,
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
                    # The canonical converter still refuses TLS. Over-page TLS
                    # alignment also produces PT_LOAD geometry outside today's
                    # input contract; the portable planner does not widen it.
                    output = root / "probe.kex"
                    result = cargo_kex("convert", elf, output)
                    self.assertNotEqual(result.returncode, 0)
                    if geometry[2] <= 4096:
                        self.assertIn(b"TLS", result.stderr)
                    else:
                        self.assertIn(b"PT_LOAD geometry", result.stderr)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

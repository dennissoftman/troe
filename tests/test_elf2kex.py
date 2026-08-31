"""Regression tests for the dependency-free hosted ELF64-to-KEX converter."""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools import elf2kex, gen_kex_corpus


REPO_ROOT = Path(__file__).resolve().parents[1]
KEX_TOOL = Path(os.environ.get("CARGO_TARGET_DIR", REPO_ROOT / "target"))
if not KEX_TOOL.is_absolute():
    KEX_TOOL = REPO_ROOT / KEX_TOOL
KEX_TOOL = (
    KEX_TOOL / "debug" / ("troe-kex-tool.exe" if os.name == "nt" else "troe-kex-tool")
)


class Elf2KexTests(unittest.TestCase):
    """Exercise both targets and the converter's closed ELF rejection surface."""

    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ("cargo", "build", "--quiet", "--package", "troe-kex-tool"),
            cwd=REPO_ROOT,
            check=True,
        )

    @staticmethod
    def make_elf(
        target: str = "x86_64",
        *,
        load_flags: int = elf2kex.ELF_PF_R | elf2kex.ELF_PF_X,
        virtual_address: int = elf2kex.KEX_IMAGE_BASE,
        extra_program_type: int | None = None,
        second_load: bool = False,
        section_type: int | None = None,
        section_flags: int = 0,
    ) -> bytes:
        """Synthesize one canonical sectionless static executable."""
        machine = {
            "x86_64": elf2kex.ELF_EM_X86_64,
            "aarch64": elf2kex.ELF_EM_AARCH64,
        }[target]
        code = (
            b"\x90\xc3" if target == "x86_64" else b"\x00\x00\x80\xd2\x01\x00\x00\xd4"
        )
        program_count = 2 + int(extra_program_type is not None) + int(second_load)
        code_offset = (
            elf2kex.ELF_HEADER_BYTES + program_count * elf2kex.ELF_PROGRAM_HEADER_BYTES
        )
        first_file_bytes = code_offset + len(code)
        second_offset = elf2kex.KEX_PAGE_BYTES
        second_payload = b"data"
        image_bytes = (
            second_offset + len(second_payload) if second_load else first_file_bytes
        )
        section_offset = 0
        section_count = 0
        section_record_bytes = 0
        if section_type is not None:
            section_offset = image_bytes
            section_count = 2
            section_record_bytes = elf2kex.ELF_SECTION_HEADER_BYTES
            image_bytes += section_count * section_record_bytes

        image = bytearray(image_bytes)
        image[:16] = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
        struct.pack_into(
            "<HHIQQQIHHHHHH",
            image,
            16,
            elf2kex.ELF_ET_EXEC,
            machine,
            1,
            virtual_address + code_offset,
            elf2kex.ELF_HEADER_BYTES,
            section_offset,
            0,
            elf2kex.ELF_HEADER_BYTES,
            elf2kex.ELF_PROGRAM_HEADER_BYTES,
            program_count,
            section_record_bytes,
            section_count,
            0,
        )
        header_offset = elf2kex.ELF_HEADER_BYTES
        struct.pack_into(
            "<IIQQQQQQ",
            image,
            header_offset,
            elf2kex.ELF_PT_LOAD,
            load_flags,
            0,
            virtual_address,
            virtual_address,
            first_file_bytes,
            first_file_bytes,
            elf2kex.KEX_PAGE_BYTES,
        )
        header_offset += elf2kex.ELF_PROGRAM_HEADER_BYTES
        if second_load:
            struct.pack_into(
                "<IIQQQQQQ",
                image,
                header_offset,
                elf2kex.ELF_PT_LOAD,
                elf2kex.ELF_PF_R | elf2kex.ELF_PF_W,
                second_offset,
                elf2kex.KEX_IMAGE_BASE + elf2kex.KEX_PAGE_BYTES,
                elf2kex.KEX_IMAGE_BASE + elf2kex.KEX_PAGE_BYTES,
                len(second_payload),
                2 * elf2kex.KEX_PAGE_BYTES,
                elf2kex.KEX_PAGE_BYTES,
            )
            header_offset += elf2kex.ELF_PROGRAM_HEADER_BYTES
        if extra_program_type is not None:
            struct.pack_into(
                "<IIQQQQQQ",
                image,
                header_offset,
                extra_program_type,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            header_offset += elf2kex.ELF_PROGRAM_HEADER_BYTES
        struct.pack_into(
            "<IIQQQQQQ",
            image,
            header_offset,
            elf2kex.ELF_PT_GNU_STACK,
            elf2kex.ELF_PF_R | elf2kex.ELF_PF_W,
            0,
            0,
            0,
            0,
            0,
            16,
        )
        image[code_offset : code_offset + len(code)] = code
        if second_load:
            image[second_offset : second_offset + len(second_payload)] = second_payload
        if section_type is not None:
            struct.pack_into(
                "<IIQQQQIIQQ",
                image,
                section_offset + elf2kex.ELF_SECTION_HEADER_BYTES,
                0,
                section_type,
                section_flags,
                0,
                section_offset,
                0,
                0,
                0,
                1,
                0,
            )
        return bytes(image)

    def test_both_targets_convert_deterministically_and_round_trip(self) -> None:
        for target in elf2kex.KEX_TARGETS:
            with self.subTest(target=target):
                elf = self.make_elf(target, second_load=True)
                first = elf2kex.convert_elf(elf, expected_target=target)
                second = elf2kex.convert_elf(elf, expected_target=target)
                self.assertEqual(first, second)
                elf2kex.verify_kex(first, target)
                self.assertEqual(
                    struct.unpack_from("<H", first, 12)[0], elf2kex.KEX_TARGETS[target]
                )
                self.assertEqual(struct.unpack_from("<H", first, 32)[0], 2)
                self.assertEqual(
                    struct.unpack_from("<I", first, elf2kex.KEX_HEADER_BYTES + 32)[0],
                    2,
                )
                second = elf2kex.KEX_HEADER_BYTES + elf2kex.KEX_RECORD_BYTES
                self.assertEqual(struct.unpack_from("<I", first, second + 32)[0], 3)
                self.assertEqual(struct.unpack_from("<Q", first, second + 24)[0], 8192)

    def test_rust_converter_rejects_legacy_static_oracle_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for target in elf2kex.KEX_TARGETS:
                with self.subTest(target=target):
                    source = root / f"{target}.elf"
                    output = root / f"{target}.kex"
                    image = self.make_elf(target, second_load=True)
                    source.write_bytes(image)
                    converted = subprocess.run(
                        (
                            str(KEX_TOOL),
                            "convert",
                            str(source),
                            str(output),
                            "--target",
                            target,
                        ),
                        cwd=Path(__file__).resolve().parents[1],
                        check=False,
                        capture_output=True,
                    )
                    self.assertNotEqual(converted.returncode, 0)
                    self.assertFalse(output.exists())

    def test_rust_converter_matches_closed_python_rejections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "rejected.elf"
            output = root / "rejected.kex"

            def assert_rust_rejects(image: bytes, *options: str) -> None:
                source.write_bytes(image)
                output.unlink(missing_ok=True)
                converted = subprocess.run(
                    (
                        str(KEX_TOOL),
                        "convert",
                        str(source),
                        str(output),
                        *options,
                    ),
                    cwd=Path(__file__).resolve().parents[1],
                    check=False,
                    capture_output=True,
                )
                self.assertNotEqual(converted.returncode, 0)
                self.assertFalse(output.exists())

            for kind in (
                elf2kex.ELF_PT_DYNAMIC,
                elf2kex.ELF_PT_INTERP,
                elf2kex.ELF_PT_TLS,
                elf2kex.ELF_PT_NOTE,
                elf2kex.ELF_PT_GNU_EH_FRAME,
                elf2kex.ELF_PT_GNU_RELRO,
                elf2kex.ELF_PT_GNU_PROPERTY,
            ):
                with self.subTest(program_type=kind):
                    assert_rust_rejects(self.make_elf(extra_program_type=kind))
            for kind, flags in (
                (elf2kex.ELF_SHT_REL, 0),
                (elf2kex.ELF_SHT_RELA, 0),
                (elf2kex.ELF_SHT_RELR, 0),
                (elf2kex.ELF_SHT_DYNAMIC, 0),
                (elf2kex.ELF_SHT_DYNSYM, 0),
                (elf2kex.ELF_SHT_NOTE, 0),
                (elf2kex.ELF_SHT_INIT_ARRAY, 0),
                (elf2kex.ELF_SHT_NOBITS, elf2kex.ELF_SHF_TLS),
            ):
                with self.subTest(section_type=kind, flags=flags):
                    assert_rust_rejects(
                        self.make_elf(section_type=kind, section_flags=flags)
                    )
            assert_rust_rejects(
                self.make_elf(
                    load_flags=(elf2kex.ELF_PF_R | elf2kex.ELF_PF_W | elf2kex.ELF_PF_X)
                )
            )
            assert_rust_rejects(self.make_elf() + b"\0")
            assert_rust_rejects(self.make_elf(), "--target", "aarch64")
            assert_rust_rejects(self.make_elf(), "--stack-pages", "3")
            assert_rust_rejects(
                self.make_elf(), "--heap-pages", str((1 << 32) + 1)
            )

    def test_dynamic_interpreter_tls_notes_relro_and_relocations_are_rejected(
        self,
    ) -> None:
        forbidden_programs = (
            elf2kex.ELF_PT_DYNAMIC,
            elf2kex.ELF_PT_INTERP,
            elf2kex.ELF_PT_TLS,
            elf2kex.ELF_PT_NOTE,
            elf2kex.ELF_PT_GNU_EH_FRAME,
            elf2kex.ELF_PT_GNU_RELRO,
            elf2kex.ELF_PT_GNU_PROPERTY,
        )
        for kind in forbidden_programs:
            with self.subTest(program_type=kind):
                with self.assertRaises(ValueError):
                    elf2kex.convert_elf(self.make_elf(extra_program_type=kind))
        for kind, flags in (
            (elf2kex.ELF_SHT_REL, 0),
            (elf2kex.ELF_SHT_RELA, 0),
            (elf2kex.ELF_SHT_RELR, 0),
            (elf2kex.ELF_SHT_DYNAMIC, 0),
            (elf2kex.ELF_SHT_DYNSYM, 0),
            (elf2kex.ELF_SHT_NOTE, 0),
            (elf2kex.ELF_SHT_INIT_ARRAY, 0),
            (elf2kex.ELF_SHT_NOBITS, elf2kex.ELF_SHF_TLS),
        ):
            with self.subTest(section_type=kind, flags=flags):
                with self.assertRaises(ValueError):
                    elf2kex.convert_elf(
                        self.make_elf(section_type=kind, section_flags=flags)
                    )

    def test_target_base_permissions_entry_and_layout_are_closed(self) -> None:
        x86 = self.make_elf()
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(x86, expected_target="aarch64")
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(
                self.make_elf(
                    virtual_address=elf2kex.KEX_IMAGE_BASE - elf2kex.KEX_PAGE_BYTES
                )
            )
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(
                self.make_elf(
                    load_flags=elf2kex.ELF_PF_R | elf2kex.ELF_PF_W | elf2kex.ELF_PF_X
                )
            )
        bad_entry = bytearray(x86)
        struct.pack_into("<Q", bad_entry, 24, elf2kex.KEX_IMAGE_BASE + len(bad_entry))
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(bytes(bad_entry))
        arm_bad_entry = bytearray(self.make_elf("aarch64"))
        entry = struct.unpack_from("<Q", arm_bad_entry, 24)[0]
        struct.pack_into("<Q", arm_bad_entry, 24, entry + 1)
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(bytes(arm_bad_entry))
        unaligned = bytearray(x86)
        struct.pack_into(
            "<Q", unaligned, elf2kex.ELF_HEADER_BYTES + 16, elf2kex.KEX_IMAGE_BASE + 1
        )
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(bytes(unaligned))
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(x86 + b"\0")

    def test_standard_stack_heap_record_and_image_bounds_are_enforced(self) -> None:
        elf = self.make_elf()
        for stack in (0, 3, (1 << 32) + 1):
            with self.subTest(stack=stack):
                with self.assertRaises(ValueError):
                    elf2kex.convert_elf(elf, stack_pages=stack)
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(elf, heap_pages=(1 << 32) + 1)
        # A sparse image below the maximum span is admitted and declares the
        # span that covers it exactly.
        sparse = self.make_elf(
            virtual_address=elf2kex.KEX_IMAGE_BASE + 128 * 1024 * 1024
        )
        artifact = elf2kex.convert_elf(sparse)
        span_pages = struct.unpack_from("<I", artifact, 36)[0]
        self.assertEqual(
            span_pages * elf2kex.KEX_PAGE_BYTES,
            128 * 1024 * 1024 + elf2kex.KEX_IMAGE_ALIGNMENT,
        )
        # One page past the maximum span is refused.
        beyond = self.make_elf(
            virtual_address=elf2kex.KEX_IMAGE_BASE + elf2kex.MAX_IMAGE_SPAN_BYTES
        )
        with self.assertRaises(ValueError):
            elf2kex.convert_elf(beyond)

    def test_kex_self_validation_rejects_corruption(self) -> None:
        artifact = elf2kex.convert_elf(self.make_elf())
        corruptions: list[bytes] = [artifact[:-1]]
        for offset in (
            0,
            22,
            60,
            elf2kex.KEX_HEADER_BYTES + 32,
            elf2kex.KEX_HEADER_BYTES + 36,
        ):
            corrupt = bytearray(artifact)
            corrupt[offset] ^= 1
            corruptions.append(bytes(corrupt))
        for offset, format_, value in (
            (32, "<H", 17),
            (40, "<Q", (1 << 32) + 1),
            (48, "<Q", (1 << 32) + 1),
            (elf2kex.KEX_HEADER_BYTES, "<Q", 128 * 1024 * 1024),
            (
                elf2kex.KEX_HEADER_BYTES + 24,
                "<Q",
                8193 * elf2kex.KEX_PAGE_BYTES,
            ),
        ):
            corrupt = bytearray(artifact)
            struct.pack_into(format_, corrupt, offset, value)
            corruptions.append(bytes(corrupt))
        for index, corrupt in enumerate(corruptions):
            with self.subTest(corruption=index):
                with self.assertRaises(ValueError):
                    elf2kex.verify_kex(corrupt, "x86_64")
        arm = bytearray(elf2kex.convert_elf(self.make_elf("aarch64")))
        struct.pack_into("<Q", arm, 24, struct.unpack_from("<Q", arm, 24)[0] + 1)
        with self.assertRaises(ValueError):
            elf2kex.verify_kex(bytes(arm), "aarch64")

    def test_cli_build_and_check_validate_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "app.elf"
            output = root / "app.kex"
            source.write_bytes(self.make_elf("aarch64"))
            command = (
                sys.executable,
                str(Path(elf2kex.__file__).resolve()),
                str(source),
                str(output),
                "--target",
                "aarch64",
            )
            subprocess.run(command, check=True, capture_output=True)
            expected = output.read_bytes()
            checked = subprocess.run(
                (*command, "--check"), check=False, capture_output=True
            )
            self.assertEqual(checked.returncode, 0, checked.stderr.decode())
            output.write_bytes(expected + b"\0")
            rejected = subprocess.run(
                (*command, "--check"), check=False, capture_output=True
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_committed_shared_corpus_is_exactly_generated(self) -> None:
        corpus = Path(__file__).resolve().parent / "kex-corpus"
        gen_kex_corpus.write_or_check(corpus, True)
        for target in elf2kex.KEX_TARGETS:
            calls = (corpus / f"native-calls-{target}.kex").read_bytes()
            self.assertNotIn(gen_kex_corpus.ACCEPTANCE_MARKER, calls)
            for probe in ("spin", "invalid-call", "unexpected-return"):
                artifact = (corpus / f"native-{probe}-{target}.kex").read_bytes()
                self.assertIn(gen_kex_corpus.ACCEPTANCE_MARKER, artifact)


if __name__ == "__main__":
    unittest.main()

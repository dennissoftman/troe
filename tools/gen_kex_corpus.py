#!/usr/bin/env python3
"""Generate the shared canonical KEX v1 acceptance and rejection corpus."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

if __package__:
    from . import elf2kex
else:
    import elf2kex


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "tests" / "kex-corpus"
ACCEPTANCE_MARKER = b"KEX-ACCEPTANCE-DESTRUCTIVE-v1\0"


def _aarch64_words(*words: int) -> bytes:
    """Encode a small reviewed AArch64 acceptance program."""
    return b"".join(struct.pack("<I", word) for word in words)


NATIVE_CODE = {
    "x86_64": {
        "calls": bytes.fromhex(
            "833f5875764881fe00100000756d4c8b6740bb78563412b801000000cd8085c0"
            "755985d275554881fb78563412754c4883ec2066c704240100c744240270696e67"
            "4c89e74889e6ba060000004c8d54241041b804000000b802000000cd8085c07519"
            "83fa047514817c241070696e67750a4883c42031ff31c0cd80bf0100000031c0cd"
            "800f0b"
        ),
        "spin": bytes.fromhex("ebfe"),
        "heap-growth-limit": bytes.fromhex(
            "b80300000048c7c7ffffffff31f631d24531d24531c0cd8031ff31c0cd800f0b"
        ),
        "invalid-call": bytes.fromhex("b803000000cd800f0b"),
        "unexpected-return": bytes.fromhex("c3"),
    },
    "aarch64": {
        "calls": bytes.fromhex(
            "090040b93f610171410400543f0440f101040054132040f9742480d2280080d2"
            "010000d4600300b5410300b59f8e04f101030054ff8300d129008052e9030079"
            "092e8d52c9edac72e92300b8e00313aae1030091c20080d2e3430091840080d2"
            "480080d2010000d4400100b53f1000f101010054ea1340b95f01096ba1000054"
            "ff830091000080d2080080d2010000d4200080d2080080d2010000d4000020d4"
        ),
        "spin": bytes.fromhex("00000014"),
        "heap-growth-limit": bytes.fromhex(
            "680080d200008092e1031faae2031faae3031faae4031faa010000d4"
            "000080d2080080d2010000d4000020d4"
        ),
        "thread-pointer": _aarch64_words(
            0xD28A_CF09,  # mov x9, #0x5678
            0xD51B_D049,  # msr tpidr_el0, x9
            0xD280_0028,  # mov x8, #1 (yield)
            0xD400_0001,  # svc #0
            0xD53B_D04A,  # mrs x10, tpidr_el0
            0xD28A_CF09,  # mov x9, #0x5678
            0xEB09_015F,  # cmp x10, x9
            0x5400_0081,  # b.ne failure
            0xD280_0000,  # mov x0, #0
            0xD280_0008,  # mov x8, #0 (exit)
            0xD400_0001,  # svc #0
            0xD280_0020,  # failure: mov x0, #1
            0xD280_0008,  # mov x8, #0 (exit)
            0xD400_0001,  # svc #0
            0xD420_0000,  # brk #0
        ),
        "invalid-call": bytes.fromhex("680080d2010000d4000020d4"),
        "unexpected-return": bytes.fromhex("c0035fd6"),
    },
}


def _put_u16(image: bytearray, offset: int, value: int) -> bytes:
    struct.pack_into("<H", image, offset, value)
    return bytes(image)


def _put_u32(image: bytearray, offset: int, value: int) -> bytes:
    struct.pack_into("<I", image, offset, value)
    return bytes(image)


def _put_u64(image: bytearray, offset: int, value: int) -> bytes:
    struct.pack_into("<Q", image, offset, value)
    return bytes(image)


def build_static_elf(
    target: str,
    code: bytes,
    *,
    segment_count: int = 1,
    first_virtual: int = elf2kex.KEX_IMAGE_BASE,
    first_memory_bytes: int = elf2kex.KEX_PAGE_BYTES,
    first_file_bytes: int | None = None,
) -> bytes:
    """Build the deterministic static ELF interchange fixture used by the corpus."""
    if not 1 <= segment_count <= 16:
        raise ValueError("corpus ELF segment count is out of range")
    machine = {
        "x86_64": elf2kex.ELF_EM_X86_64,
        "aarch64": elf2kex.ELF_EM_AARCH64,
    }[target]
    program_count = segment_count + 1
    code_offset = (
        elf2kex.ELF_HEADER_BYTES + program_count * elf2kex.ELF_PROGRAM_HEADER_BYTES
    )
    minimum_first_file = code_offset + len(code)
    first_file_bytes = (
        minimum_first_file if first_file_bytes is None else first_file_bytes
    )
    if first_file_bytes < minimum_first_file or first_memory_bytes < first_file_bytes:
        raise ValueError("corpus ELF first segment cannot contain its code")
    last_file_end = first_file_bytes
    if segment_count > 1:
        last_file_end = (segment_count - 1) * elf2kex.KEX_PAGE_BYTES + 1
    image = bytearray(last_file_end)
    image[:16] = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        image,
        16,
        elf2kex.ELF_ET_EXEC,
        machine,
        1,
        first_virtual + code_offset,
        elf2kex.ELF_HEADER_BYTES,
        0,
        0,
        elf2kex.ELF_HEADER_BYTES,
        elf2kex.ELF_PROGRAM_HEADER_BYTES,
        program_count,
        0,
        0,
        0,
    )
    for index in range(segment_count):
        header = elf2kex.ELF_HEADER_BYTES + index * elf2kex.ELF_PROGRAM_HEADER_BYTES
        if index == 0:
            file_offset = 0
            virtual = first_virtual
            file_bytes = first_file_bytes
            memory_bytes = first_memory_bytes
            flags = elf2kex.ELF_PF_R | elf2kex.ELF_PF_X
        else:
            file_offset = index * elf2kex.KEX_PAGE_BYTES
            virtual = elf2kex.KEX_IMAGE_BASE + index * elf2kex.KEX_PAGE_BYTES
            file_bytes = 1
            memory_bytes = elf2kex.KEX_PAGE_BYTES
            flags = (
                elf2kex.ELF_PF_R if index % 2 else elf2kex.ELF_PF_R | elf2kex.ELF_PF_W
            )
            image[file_offset] = index
        struct.pack_into(
            "<IIQQQQQQ",
            image,
            header,
            elf2kex.ELF_PT_LOAD,
            flags,
            file_offset,
            virtual,
            virtual,
            file_bytes,
            memory_bytes,
            elf2kex.KEX_PAGE_BYTES,
        )
    stack_header = (
        elf2kex.ELF_HEADER_BYTES + segment_count * elf2kex.ELF_PROGRAM_HEADER_BYTES
    )
    struct.pack_into(
        "<IIQQQQQQ",
        image,
        stack_header,
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
    return bytes(image)


def _canonical(target: str, code: bytes, **kwargs: int) -> bytes:
    elf = build_static_elf(target, code, **kwargs)
    return elf2kex.convert_elf(elf, expected_target=target)


def _rejections(target: str, base: bytes) -> dict[str, tuple[bytes, str]]:
    """Return mutation name to (bytes, exact ParseError variant)."""
    cases: dict[str, tuple[bytes, str]] = {}

    def add(name: str, image: bytes, error: str) -> None:
        cases[name] = (image, error)

    add("truncated-header", base[:63], "TruncatedHeader")
    invalid = bytearray(base)
    invalid[0] ^= 0xFF
    add("invalid-magic", bytes(invalid), "InvalidMagic")
    add(
        "container-major",
        _put_u16(bytearray(base), 8, 2),
        "UnsupportedContainerVersion",
    )
    add(
        "container-minor",
        _put_u16(bytearray(base), 10, 2),
        "UnsupportedContainerVersion",
    )
    other_target = 2 if target == "x86_64" else 1
    add("wrong-target", _put_u16(bytearray(base), 12, other_target), "WrongTarget")
    add("header-bytes", _put_u16(bytearray(base), 14, 65), "InvalidLayout")
    add("record-bytes", _put_u16(bytearray(base), 16, 41), "InvalidLayout")
    add("records-offset", _put_u32(bytearray(base), 56, 65), "InvalidLayout")
    add("payload-offset", _put_u32(bytearray(base), 60, 105), "InvalidLayout")
    invalid = bytearray(base)
    invalid[22] = 1
    add("header-flags", bytes(invalid), "NonzeroReserved")
    add("header-reserved16", _put_u16(bytearray(base), 34, 1), "NonzeroReserved")
    span_pages = struct.unpack_from("<I", base, 36)[0]
    add("image-span-zero", _put_u32(bytearray(base), 36, 0), "InvalidImageSpan")
    add(
        "image-span-unaligned",
        _put_u32(bytearray(base), 36, span_pages + 1),
        "InvalidImageSpan",
    )
    add(
        "image-span-above-maximum",
        _put_u32(
            bytearray(base),
            36,
            elf2kex.MAX_IMAGE_SPAN_PAGES + elf2kex.KEX_IMAGE_ALIGNMENT
            // elf2kex.KEX_PAGE_BYTES,
        ),
        "InvalidImageSpan",
    )
    add(
        "image-span-noncanonical",
        _put_u32(
            bytearray(base),
            36,
            span_pages + elf2kex.KEX_IMAGE_ALIGNMENT // elf2kex.KEX_PAGE_BYTES,
        ),
        "InvalidImageSpan",
    )
    add(
        "image-span-legacy-nonzero",
        _put_u16(bytearray(_put_u32(bytearray(base), 36, 1)), 20, 1),
        "NonzeroReserved",
    )
    add(
        "record-reserved",
        _put_u32(bytearray(base), elf2kex.KEX_HEADER_BYTES + 36, 1),
        "NonzeroReserved",
    )
    add("abi-major", _put_u16(bytearray(base), 18, 2), "UnsupportedAbi")
    add(
        "abi-minor",
        _put_u16(bytearray(base), 20, elf2kex.KEX_ABI_MINOR + 1),
        "UnsupportedAbi",
    )
    add(
        "length-mismatch",
        _put_u64(bytearray(base), 80, len(base) + 1),
        "LengthMismatch",
    )
    add("record-count-zero", _put_u16(bytearray(base), 32, 0), "InvalidRecordCount")
    add(
        "record-count-seventeen",
        _put_u16(bytearray(base), 32, 17),
        "InvalidRecordCount",
    )
    add(
        "arithmetic-overflow",
        _put_u64(
            bytearray(base), elf2kex.KEX_HEADER_BYTES, 0xFFFF_FFFF_FFFF_F000
        ),
        "ArithmeticOverflow",
    )
    add(
        "permissions-zero",
        _put_u32(bytearray(base), elf2kex.KEX_HEADER_BYTES + 32, 0),
        "InvalidPermissions",
    )
    add(
        "permissions-four",
        _put_u32(bytearray(base), elf2kex.KEX_HEADER_BYTES + 32, 4),
        "InvalidPermissions",
    )
    add(
        "image-unaligned",
        _put_u64(bytearray(base), elf2kex.KEX_HEADER_BYTES, 1),
        "InvalidSegmentRange",
    )
    add(
        "memory-zero",
        _put_u64(bytearray(base), elf2kex.KEX_HEADER_BYTES + 24, 0),
        "InvalidSegmentRange",
    )
    add(
        "memory-unaligned",
        _put_u64(bytearray(base), elf2kex.KEX_HEADER_BYTES + 24, 4095),
        "InvalidSegmentRange",
    )
    file_bytes = struct.unpack_from("<Q", base, elf2kex.KEX_HEADER_BYTES + 16)[0]
    add(
        "file-exceeds-memory",
        _put_u64(
            bytearray(base), elf2kex.KEX_HEADER_BYTES + 24, file_bytes - 1
        ),
        "InvalidSegmentRange",
    )
    two = _canonical(target, NATIVE_CODE[target]["calls"], segment_count=2)
    add(
        "segments-overlap",
        _put_u64(bytearray(two), elf2kex.KEX_HEADER_BYTES + elf2kex.KEX_RECORD_BYTES, 0),
        "OverlappingSegments",
    )
    first_payload = struct.unpack_from("<Q", base, elf2kex.KEX_HEADER_BYTES + 8)[0]
    add(
        "payload-gap",
        _put_u64(bytearray(base), elf2kex.KEX_HEADER_BYTES + 8, first_payload + 1),
        "NoncanonicalPayload",
    )
    trailing = bytearray(base)
    trailing.append(0)
    _put_u64(trailing, 80, len(trailing))
    add("payload-trailing", bytes(trailing), "NoncanonicalPayload")
    add(
        "image-span-exceeded",
        _put_u64(
            bytearray(base),
            elf2kex.KEX_HEADER_BYTES,
            span_pages * elf2kex.KEX_PAGE_BYTES,
        ),
        "ImageSpanExceeded",
    )
    add("stack-below-minimum", _put_u64(bytearray(base), 40, 3), "StackBudgetExceeded")
    add(
        "stack-above-maximum",
        _put_u64(bytearray(base), 40, (1 << 32) + 1),
        "StackBudgetExceeded",
    )
    add(
        "heap-above-maximum",
        _put_u64(bytearray(base), 48, (1 << 32) + 1),
        "HeapBudgetExceeded",
    )
    add(
        "missing-executable",
        _put_u32(bytearray(base), elf2kex.KEX_HEADER_BYTES + 32, 1),
        "MissingExecutableSegment",
    )
    add(
        "entry-at-segment-end",
        _put_u64(bytearray(base), 24, elf2kex.KEX_PAGE_BYTES),
        "InvalidEntryPoint",
    )
    return cases


def generate_corpus() -> dict[str, bytes]:
    """Return every generated corpus file keyed by its canonical relative name."""
    files: dict[str, bytes] = {}
    manifest = ["# file\ttarget\tresult"]
    valid_rows: list[str] = []
    rejection_rows: dict[str, list[str]] = {
        target: [] for target in elf2kex.KEX_TARGETS
    }
    for target in elf2kex.KEX_TARGETS:
        calls = _canonical(target, NATIVE_CODE[target]["calls"])
        calls_name = f"native-calls-{target}.kex"
        files[calls_name] = calls
        manifest.append(f"{calls_name}\t{target}\tok")
        valid_rows.append(
            f'    ("{calls_name}", include_bytes!("{calls_name}") as &[u8], '
            f"Target::{'X86_64' if target == 'x86_64' else 'Aarch64'}),"
        )
        for probe in (
            "spin",
            "heap-growth-limit",
            "invalid-call",
            "unexpected-return",
        ):
            artifact = _canonical(
                target, NATIVE_CODE[target][probe] + ACCEPTANCE_MARKER
            )
            name = f"native-{probe}-{target}.kex"
            files[name] = artifact
            manifest.append(f"{name}\t{target}\tok")
            valid_rows.append(
                f'    ("{name}", include_bytes!("{name}") as &[u8], '
                f"Target::{'X86_64' if target == 'x86_64' else 'Aarch64'}),"
            )

        if target == "aarch64":
            probe = "thread-pointer"
            artifact = _canonical(
                target, NATIVE_CODE[target][probe] + ACCEPTANCE_MARKER
            )
            name = f"native-{probe}-{target}.kex"
            files[name] = artifact
            manifest.append(f"{name}\t{target}\tok")
            valid_rows.append(
                f'    ("{name}", include_bytes!("{name}") as &[u8], '
                "Target::Aarch64),"
            )

        boundary_artifacts = {
            "standard-max-records": _canonical(
                target, NATIVE_CODE[target]["calls"], segment_count=16
            ),
            "standard-max-span": _canonical(
                target,
                NATIVE_CODE[target]["calls"],
                first_virtual=elf2kex.KEX_IMAGE_BASE
                + elf2kex.MAX_IMAGE_SPAN_BYTES
                - elf2kex.KEX_PAGE_BYTES,
            ),
            "standard-minimum-span": _canonical(
                target, NATIVE_CODE[target]["calls"]
            ),
            "standard-max-stack-heap": elf2kex.convert_elf(
                build_static_elf(target, NATIVE_CODE[target]["calls"]),
                expected_target=target,
                stack_pages=1 << 32,
                heap_pages=1 << 32,
            ),
            # The encoded ceiling is now two spans, far past anything worth
            # committing. This case instead exercises a multi-megabyte image
            # whose payload fills its declared span exactly.
            "standard-large-image": _canonical(
                target,
                NATIVE_CODE[target]["calls"],
                first_file_bytes=4 * 1024 * 1024
                - elf2kex.KEX_HEADER_BYTES
                - elf2kex.KEX_RECORD_BYTES,
                first_memory_bytes=4 * 1024 * 1024,
            ),
        }
        for label, artifact in boundary_artifacts.items():
            name = f"valid-{label}-{target}.kex"
            files[name] = artifact
            manifest.append(f"{name}\t{target}\tok")
            valid_rows.append(
                f'    ("{name}", include_bytes!("{name}") as &[u8], '
                f"Target::{'X86_64' if target == 'x86_64' else 'Aarch64'}),"
            )

        for label, (artifact, error) in _rejections(target, calls).items():
            name = f"reject-{label}-{target}.kex"
            files[name] = artifact
            manifest.append(f"{name}\t{target}\t{error}")
            rejection_rows[target].append(
                f'    ("{name}", include_bytes!("{name}") as &[u8], '
                f"ParseError::{error}),"
            )

    files["manifest.tsv"] = ("\n".join(manifest) + "\n").encode()
    files["valid.inc"] = ("[\n" + "\n".join(valid_rows) + "\n]\n").encode()
    for target, rows in rejection_rows.items():
        files[f"rejections-{target}.inc"] = ("[\n" + "\n".join(rows) + "\n]\n").encode()
    return files


def write_or_check(output: Path, check: bool) -> None:
    expected = generate_corpus()
    if check:
        actual_names = (
            {path.name for path in output.iterdir() if path.is_file()}
            if output.is_dir()
            else set()
        )
        if actual_names != set(expected):
            raise ValueError(
                "committed KEX corpus file set differs from generator output"
            )
        for name, content in expected.items():
            if (output / name).read_bytes() != content:
                raise ValueError(f"committed KEX corpus differs at {name}")
        return
    output.mkdir(parents=True, exist_ok=True)
    for name, content in expected.items():
        (output / name).write_bytes(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        write_or_check(args.output, args.check)
        action = "verified" if args.check else "generated"
        print(f"KEX corpus {action}: {len(generate_corpus())} files -> {args.output}")
        return 0
    except (FileNotFoundError, OSError, ValueError) as error:
        print(f"gen_kex_corpus: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

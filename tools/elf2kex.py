#!/usr/bin/env python3
"""Convert one strict freestanding static ELF64 executable into canonical KEX v1."""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


ELF_HEADER_BYTES = 64
ELF_PROGRAM_HEADER_BYTES = 56
ELF_SECTION_HEADER_BYTES = 64
ELF_MAX_BYTES = 64 * 1024 * 1024
ELF_MAX_PROGRAM_HEADERS = 64
ELF_MAX_SECTION_HEADERS = 4096

ELF_ET_EXEC = 2
ELF_EM_X86_64 = 62
ELF_EM_AARCH64 = 183
ELF_PT_NULL = 0
ELF_PT_LOAD = 1
ELF_PT_DYNAMIC = 2
ELF_PT_INTERP = 3
ELF_PT_NOTE = 4
ELF_PT_SHLIB = 5
ELF_PT_PHDR = 6
ELF_PT_TLS = 7
ELF_PT_GNU_EH_FRAME = 0x6474_E550
ELF_PT_GNU_STACK = 0x6474_E551
ELF_PT_GNU_RELRO = 0x6474_E552
ELF_PT_GNU_PROPERTY = 0x6474_E553
ELF_PF_X = 1
ELF_PF_W = 2
ELF_PF_R = 4

ELF_SHT_NULL = 0
ELF_SHT_PROGBITS = 1
ELF_SHT_SYMTAB = 2
ELF_SHT_STRTAB = 3
ELF_SHT_RELA = 4
ELF_SHT_HASH = 5
ELF_SHT_DYNAMIC = 6
ELF_SHT_NOTE = 7
ELF_SHT_NOBITS = 8
ELF_SHT_REL = 9
ELF_SHT_DYNSYM = 11
ELF_SHT_INIT_ARRAY = 14
ELF_SHT_FINI_ARRAY = 15
ELF_SHT_PREINIT_ARRAY = 16
ELF_SHT_GROUP = 17
ELF_SHT_SYMTAB_SHNDX = 18
ELF_SHT_RELR = 19
ELF_SHF_WRITE = 0x1
ELF_SHF_ALLOC = 0x2
ELF_SHF_EXECINSTR = 0x4
ELF_SHF_TLS = 0x400

KEX_MAGIC = b"KEX\0FMT\0"
KEX_HEADER_BYTES = 88
KEX_RECORD_BYTES = 40
KEX_RELOCATION_BYTES = 16
KEX_IMAGE_BASE = 0x0000_4000_0000_0000
KEX_PAGE_BYTES = 4096
KEX_ABI_MAJOR = 1
KEX_ABI_MINOR = 1
KEX_TARGETS = {"x86_64": 1, "aarch64": 2}
ELF_MACHINES = {ELF_EM_X86_64: "x86_64", ELF_EM_AARCH64: "aarch64"}
KEX_PERMISSIONS = {
    ELF_PF_R: 1,
    ELF_PF_R | ELF_PF_X: 2,
    ELF_PF_R | ELF_PF_W: 3,
}
STANDARD_LIMITS = {
    "encoded_bytes": 32 * 1024 * 1024,
    "records": 16,
    "image_span": 128 * 1024 * 1024,
    "image_pages": 8192,
    "stack_min": 4,
    "stack_max": 1 << 32,
    "heap_pages": 1 << 32,
    "table_pages": 512,
    "resident_pages": 2 * (1 << 32) + 8192 + 1 + 512,
}


@dataclass(frozen=True)
class ElfLoadSegment:
    """One validated ELF PT_LOAD entry."""

    file_offset: int
    virtual_address: int
    file_bytes: int
    memory_bytes: int
    flags: int


@dataclass(frozen=True)
class ParsedElf:
    """Validated target, entry, and ordered static load segments."""

    target: str
    entry: int
    segments: tuple[ElfLoadSegment, ...]


@dataclass(frozen=True)
class KexRecord:
    """One canonical KEX output record and its source payload."""

    image_offset: int
    file_bytes: bytes
    memory_bytes: int
    permissions: int


def _checked_range(total: int, offset: int, length: int, label: str) -> tuple[int, int]:
    if offset < 0 or length < 0 or offset > total or length > total - offset:
        raise ValueError(f"{label} is outside the ELF artifact")
    return offset, offset + length


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _round_up(value: int, alignment: int) -> int:
    if value < 0 or not _power_of_two(alignment):
        raise ValueError("invalid alignment")
    rounded = value + alignment - 1
    if rounded > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("ELF size arithmetic overflow")
    return rounded & -alignment


def _program_headers(
    image: bytes, offset: int, count: int
) -> list[tuple[int, int, int, int, int, int, int, int]]:
    _checked_range(
        len(image), offset, count * ELF_PROGRAM_HEADER_BYTES, "ELF program-header table"
    )
    return [
        struct.unpack_from(
            "<IIQQQQQQ", image, offset + index * ELF_PROGRAM_HEADER_BYTES
        )
        for index in range(count)
    ]


def _section_headers(
    image: bytes, offset: int, count: int
) -> list[tuple[int, int, int, int, int, int, int, int, int, int]]:
    _checked_range(
        len(image), offset, count * ELF_SECTION_HEADER_BYTES, "ELF section-header table"
    )
    return [
        struct.unpack_from(
            "<IIQQQQIIQQ", image, offset + index * ELF_SECTION_HEADER_BYTES
        )
        for index in range(count)
    ]


def _validate_sections(
    image: bytes,
    sections: list[tuple[int, int, int, int, int, int, int, int, int, int]],
    string_index: int,
    loads: list[ElfLoadSegment],
) -> list[tuple[int, int]]:
    if not sections:
        if string_index != 0:
            raise ValueError("section-name index exists without a section table")
        return []
    if any(sections[0]):
        raise ValueError("ELF section zero is not canonical")
    if string_index >= len(sections):
        raise ValueError("ELF section-name table index is out of range")
    string_table = b""
    if string_index != 0:
        string_section = sections[string_index]
        if string_section[1] != ELF_SHT_STRTAB or string_section[2] & ELF_SHF_ALLOC:
            raise ValueError(
                "ELF section-name table is not a non-allocating string table"
            )
        start, end = _checked_range(
            len(image), string_section[4], string_section[5], "ELF section-name table"
        )
        string_table = image[start:end]
        if not string_table or string_table[0] != 0 or string_table[-1] != 0:
            raise ValueError("ELF section-name table is noncanonical")

    described: list[tuple[int, int]] = []
    for index, section in enumerate(sections[1:], 1):
        (
            name_offset,
            kind,
            flags,
            address,
            offset,
            size,
            link,
            info,
            alignment,
            entry_size,
        ) = section
        if alignment not in (0, 1) and not _power_of_two(alignment):
            raise ValueError(f"ELF section {index} has invalid alignment")
        if alignment > 1 and address and address % alignment:
            raise ValueError(f"ELF section {index} address is misaligned")
        if kind in (ELF_SHT_RELA, ELF_SHT_REL, ELF_SHT_RELR):
            raise ValueError("ELF contains residual relocation records")
        if kind in (ELF_SHT_DYNAMIC, ELF_SHT_DYNSYM):
            raise ValueError("ELF contains dynamic-linker metadata")
        if kind in (
            ELF_SHT_HASH,
            ELF_SHT_NOTE,
            ELF_SHT_INIT_ARRAY,
            ELF_SHT_FINI_ARRAY,
            ELF_SHT_PREINIT_ARRAY,
            ELF_SHT_GROUP,
            ELF_SHT_SYMTAB_SHNDX,
        ):
            raise ValueError("ELF contains unsupported runtime or link metadata")
        if kind not in (
            ELF_SHT_PROGBITS,
            ELF_SHT_SYMTAB,
            ELF_SHT_STRTAB,
            ELF_SHT_NOBITS,
        ):
            raise ValueError(f"ELF section type {kind:#x} is unsupported")
        if flags & ELF_SHF_TLS:
            raise ValueError("ELF contains thread-local storage")
        if flags & ELF_SHF_WRITE and flags & ELF_SHF_EXECINSTR:
            raise ValueError("ELF section requests writable executable memory")
        if name_offset:
            if name_offset >= len(string_table):
                raise ValueError("ELF section name is outside the string table")
            terminator = string_table.find(b"\0", name_offset)
            if terminator < 0:
                raise ValueError("ELF section name is unterminated")
            name = string_table[name_offset:terminator]
            if name in (b".interp", b".dynamic", b".dynsym", b".tdata", b".tbss"):
                raise ValueError(
                    f"ELF contains unsupported section {name.decode('ascii')}"
                )
        if kind == ELF_SHT_NOBITS:
            if offset > len(image):
                raise ValueError("ELF NOBITS section offset is outside the artifact")
        else:
            start, end = _checked_range(
                len(image), offset, size, f"ELF section {index}"
            )
            if size:
                described.append((start, end))
        if flags & ELF_SHF_ALLOC:
            section_end = address + size
            if section_end > 0xFFFF_FFFF_FFFF_FFFF:
                raise ValueError("ELF allocated section address overflows")
            owner = next(
                (
                    load
                    for load in loads
                    if load.virtual_address <= address
                    and section_end <= load.virtual_address + load.memory_bytes
                ),
                None,
            )
            if owner is None:
                raise ValueError(
                    "ELF allocated section is outside every PT_LOAD segment"
                )
            required_flags = ELF_PF_R
            if flags & ELF_SHF_WRITE:
                required_flags |= ELF_PF_W
            if flags & ELF_SHF_EXECINSTR:
                required_flags |= ELF_PF_X
            if owner.flags & required_flags != required_flags:
                raise ValueError(
                    "ELF section permissions exceed its PT_LOAD permissions"
                )
            if kind != ELF_SHT_NOBITS and size:
                if offset - owner.file_offset != address - owner.virtual_address:
                    raise ValueError(
                        "ELF allocated section file/address mapping is inconsistent"
                    )
                if offset + size > owner.file_offset + owner.file_bytes:
                    raise ValueError(
                        "ELF allocated section exceeds file-backed PT_LOAD bytes"
                    )
        elif address != 0:
            raise ValueError("ELF non-allocating section has a virtual address")
        if link >= len(sections) and link != 0:
            raise ValueError("ELF section link index is out of range")
        if kind in (ELF_SHT_SYMTAB, ELF_SHT_DYNSYM) and entry_size == 0:
            raise ValueError("ELF symbol table has zero-sized entries")
        _ = info
    return described


def parse_elf(image: bytes, expected_target: str | None = None) -> ParsedElf:
    """Validate the closed freestanding static ELF64 input contract."""
    if len(image) < ELF_HEADER_BYTES:
        raise ValueError("ELF header is truncated")
    if len(image) > ELF_MAX_BYTES:
        raise ValueError("ELF artifact exceeds the hosted conversion ceiling")
    if image[:9] != b"\x7fELF\x02\x01\x01\x00\x00" or any(image[9:16]):
        raise ValueError(
            "ELF identification is not canonical 64-bit little-endian System V"
        )
    (
        file_type,
        machine,
        version,
        entry,
        program_offset,
        section_offset,
        flags,
        header_bytes,
        program_record_bytes,
        program_count,
        section_record_bytes,
        section_count,
        section_string_index,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", image, 16)
    target = ELF_MACHINES.get(machine)
    if target is None or expected_target is not None and target != expected_target:
        raise ValueError("ELF machine does not match a supported requested KEX target")
    if target == "aarch64" and entry % 4:
        raise ValueError("AArch64 ELF entry is not instruction aligned")
    if (
        file_type != ELF_ET_EXEC
        or version != 1
        or flags != 0
        or header_bytes != ELF_HEADER_BYTES
        or program_record_bytes != ELF_PROGRAM_HEADER_BYTES
        or program_offset != ELF_HEADER_BYTES
        or not 0 < program_count <= ELF_MAX_PROGRAM_HEADERS
    ):
        raise ValueError(
            "ELF executable header or program-table layout is noncanonical"
        )
    if section_count == 0:
        if (
            section_offset != 0
            or section_record_bytes != 0
            or section_string_index != 0
        ):
            raise ValueError("ELF absent section table has nonzero metadata")
    elif (
        section_record_bytes != ELF_SECTION_HEADER_BYTES
        or not 0 < section_count <= ELF_MAX_SECTION_HEADERS
    ):
        raise ValueError("ELF section-table layout is noncanonical")

    program_headers = _program_headers(image, program_offset, program_count)
    loads: list[ElfLoadSegment] = []
    file_ranges: list[tuple[int, int]] = []
    phdr_seen = False
    stack_seen = False
    forbidden_types = {
        ELF_PT_DYNAMIC,
        ELF_PT_INTERP,
        ELF_PT_NOTE,
        ELF_PT_SHLIB,
        ELF_PT_TLS,
        ELF_PT_GNU_EH_FRAME,
        ELF_PT_GNU_RELRO,
        ELF_PT_GNU_PROPERTY,
    }
    for index, header in enumerate(program_headers):
        (
            kind,
            segment_flags,
            offset,
            virtual,
            physical,
            file_bytes,
            memory_bytes,
            align,
        ) = header
        if kind == ELF_PT_NULL:
            if any(header[1:]):
                raise ValueError("ELF PT_NULL record has nonzero fields")
            continue
        if kind in forbidden_types:
            raise ValueError(
                "ELF requires an unsupported dynamic, TLS, note, or RELRO facility"
            )
        if kind == ELF_PT_PHDR:
            if phdr_seen:
                raise ValueError("ELF contains duplicate PT_PHDR records")
            phdr_seen = True
            expected_bytes = program_count * ELF_PROGRAM_HEADER_BYTES
            if (
                segment_flags != ELF_PF_R
                or offset != program_offset
                or file_bytes != expected_bytes
                or memory_bytes != expected_bytes
                or align not in (8, KEX_PAGE_BYTES)
                or physical not in (0, virtual)
            ):
                raise ValueError("ELF PT_PHDR record is inconsistent")
            continue
        if kind == ELF_PT_GNU_STACK:
            if stack_seen:
                raise ValueError("ELF contains duplicate PT_GNU_STACK records")
            stack_seen = True
            if (
                segment_flags != ELF_PF_R | ELF_PF_W
                or any((offset, virtual, physical, file_bytes, memory_bytes))
                or align not in (0, 16)
            ):
                raise ValueError("ELF GNU stack is executable or noncanonical")
            continue
        if kind != ELF_PT_LOAD:
            raise ValueError(f"ELF program-header type {kind:#x} is unsupported")
        if len(loads) >= 16:
            raise ValueError("ELF has more load segments than KEX v1 can encode")
        if segment_flags not in KEX_PERMISSIONS:
            raise ValueError("ELF PT_LOAD permissions are not R, RX, or RW")
        if (
            align != KEX_PAGE_BYTES
            or offset % KEX_PAGE_BYTES
            or virtual % KEX_PAGE_BYTES
            or physical not in (0, virtual)
            or memory_bytes == 0
            or file_bytes > memory_bytes
        ):
            raise ValueError(
                "ELF PT_LOAD geometry is outside the KEX conversion contract"
            )
        start, end = _checked_range(
            len(image), offset, file_bytes, f"ELF PT_LOAD {index}"
        )
        if file_bytes:
            if any(
                start < prior_end and prior_start < end
                for prior_start, prior_end in file_ranges
            ):
                raise ValueError("ELF PT_LOAD file ranges overlap")
            file_ranges.append((start, end))
        loads.append(
            ElfLoadSegment(offset, virtual, file_bytes, memory_bytes, segment_flags)
        )

    if not loads:
        raise ValueError("ELF contains no PT_LOAD segment")
    previous_end = KEX_IMAGE_BASE
    executable_entry = False
    for load in loads:
        if load.virtual_address < KEX_IMAGE_BASE:
            raise ValueError("ELF PT_LOAD is below the fixed KEX image base")
        memory_end = load.virtual_address + _round_up(load.memory_bytes, KEX_PAGE_BYTES)
        if memory_end > 0xFFFF_FFFF_FFFF_FFFF:
            raise ValueError("ELF PT_LOAD address overflows")
        if load.virtual_address < previous_end:
            raise ValueError(
                "ELF PT_LOAD records are unordered or overlap after page rounding"
            )
        previous_end = memory_end
        if (
            load.flags & ELF_PF_X
            and load.virtual_address <= entry < load.virtual_address + load.file_bytes
        ):
            executable_entry = True
    if not executable_entry:
        raise ValueError("ELF entry is not inside file-backed executable bytes")
    phdr_end = program_offset + program_count * ELF_PROGRAM_HEADER_BYTES
    if phdr_seen and not any(
        load.file_offset <= program_offset
        and phdr_end <= load.file_offset + load.file_bytes
        and load.virtual_address + program_offset - load.file_offset
        == next(header[3] for header in program_headers if header[0] == ELF_PT_PHDR)
        for load in loads
    ):
        raise ValueError("ELF PT_PHDR is not covered by a PT_LOAD segment")

    sections = (
        _section_headers(image, section_offset, section_count) if section_count else []
    )
    section_ranges = _validate_sections(image, sections, section_string_index, loads)
    described = [
        (0, ELF_HEADER_BYTES),
        (program_offset, phdr_end),
        *file_ranges,
        *section_ranges,
    ]
    if section_count:
        described.append(
            (section_offset, section_offset + section_count * ELF_SECTION_HEADER_BYTES)
        )
    merged: list[list[int]] = []
    for start, end in sorted(described):
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    cursor = 0
    for start, end in merged:
        if any(image[cursor:start]):
            raise ValueError("ELF has nonzero bytes outside described structures")
        cursor = max(cursor, end)
    if cursor != len(image):
        raise ValueError("ELF has trailing bytes outside described structures")
    return ParsedElf(target, entry, tuple(loads))


def _records(parsed: ParsedElf, image: bytes) -> tuple[KexRecord, ...]:
    return tuple(
        KexRecord(
            load.virtual_address - KEX_IMAGE_BASE,
            image[load.file_offset : load.file_offset + load.file_bytes],
            _round_up(load.memory_bytes, KEX_PAGE_BYTES),
            KEX_PERMISSIONS[load.flags],
        )
        for load in parsed.segments
    )


def verify_kex(
    artifact: bytes,
    target: str,
    records: tuple[KexRecord, ...] | None = None,
    *,
    entry_offset: int | None = None,
    stack_pages: int | None = None,
    heap_pages: int | None = None,
) -> None:
    """Independently decode canonical KEX bytes, optionally against expected records."""
    limits = STANDARD_LIMITS
    if len(artifact) < KEX_HEADER_BYTES:
        raise ValueError("KEX output header is truncated")
    if len(artifact) > limits["encoded_bytes"]:
        raise ValueError("KEX output exceeds the standard encoded-byte ceiling")
    if artifact[:8] != KEX_MAGIC:
        raise ValueError("KEX output magic is invalid")
    if struct.unpack_from("<HH", artifact, 8) != (1, 1):
        raise ValueError("KEX output container version is invalid")
    if struct.unpack_from("<H", artifact, 12)[0] != KEX_TARGETS[target]:
        raise ValueError("KEX output target is invalid")
    if struct.unpack_from("<HHHHH", artifact, 14) != (
        KEX_HEADER_BYTES,
        KEX_RECORD_BYTES,
        KEX_ABI_MAJOR,
        KEX_ABI_MINOR,
        0,
    ):
        raise ValueError("KEX output fixed header fields are noncanonical")
    encoded_entry = struct.unpack_from("<Q", artifact, 24)[0]
    count, reserved = struct.unpack_from("<HH", artifact, 32)
    reserved32 = struct.unpack_from("<I", artifact, 36)[0]
    encoded_stack, encoded_heap = struct.unpack_from("<QQ", artifact, 40)
    table_offset, payload_offset = struct.unpack_from("<II", artifact, 56)
    artifact_bytes = struct.unpack_from("<Q", artifact, 80)[0]
    relocation_offset, relocation_count, relocation_bytes, relocation_reserved16, relocation_reserved32 = struct.unpack_from(
        "<IIHHI", artifact, 64
    )
    if (
        count == 0
        or count > limits["records"]
        or reserved != 0
        or reserved32 != 0
        or table_offset != KEX_HEADER_BYTES
        or relocation_offset != KEX_HEADER_BYTES + count * KEX_RECORD_BYTES
        or relocation_count != 0
        or relocation_bytes != KEX_RELOCATION_BYTES
        or relocation_reserved16 != 0
        or relocation_reserved32 != 0
        or payload_offset != relocation_offset
        or artifact_bytes != len(artifact)
    ):
        raise ValueError("KEX output table or length is noncanonical")
    if entry_offset is not None and encoded_entry != entry_offset:
        raise ValueError("KEX output entry differs from ELF")
    if target == "aarch64" and encoded_entry % 4:
        raise ValueError("KEX output AArch64 entry is not instruction aligned")
    if not limits["stack_min"] <= encoded_stack <= limits["stack_max"]:
        raise ValueError("KEX output stack request exceeds the standard policy")
    if encoded_heap > limits["heap_pages"]:
        raise ValueError("KEX output heap request exceeds the standard policy")
    if stack_pages is not None and encoded_stack != stack_pages:
        raise ValueError("KEX output stack request differs from conversion policy")
    if heap_pages is not None and encoded_heap != heap_pages:
        raise ValueError("KEX output heap request differs from conversion policy")
    decoded: list[KexRecord] = []
    next_payload = payload_offset
    previous_end = 0
    image_pages = 0
    executable_entry = False
    for index in range(count):
        offset = KEX_HEADER_BYTES + index * KEX_RECORD_BYTES
        (
            image_offset,
            file_offset,
            file_bytes,
            memory_bytes,
            permissions,
            record_reserved,
        ) = struct.unpack_from("<QQQQII", artifact, offset)
        if (
            image_offset % KEX_PAGE_BYTES
            or memory_bytes == 0
            or memory_bytes % KEX_PAGE_BYTES
            or file_bytes > memory_bytes
            or permissions not in (1, 2, 3)
            or record_reserved != 0
            or file_offset != next_payload
            or file_offset > len(artifact)
            or file_bytes > len(artifact) - file_offset
            or image_offset < previous_end
        ):
            raise ValueError("KEX output load record is noncanonical")
        payload = artifact[file_offset : file_offset + file_bytes]
        decoded.append(KexRecord(image_offset, payload, memory_bytes, permissions))
        next_payload += file_bytes
        previous_end = image_offset + memory_bytes
        image_pages += memory_bytes // KEX_PAGE_BYTES
        if permissions == 2 and image_offset <= encoded_entry < previous_end:
            executable_entry = True
    if next_payload != len(artifact) or not executable_entry:
        raise ValueError("KEX output payload or executable entry is noncanonical")
    if previous_end > limits["image_span"]:
        raise ValueError("KEX output image span exceeds the standard policy")
    if image_pages > limits["image_pages"]:
        raise ValueError("KEX output image pages exceed the standard policy")
    resident_pages = (
        image_pages + 1 + encoded_stack + encoded_heap + limits["table_pages"]
    )
    if resident_pages > limits["resident_pages"]:
        raise ValueError("KEX output resident charge exceeds the standard policy")
    if records is not None and tuple(decoded) != records:
        raise ValueError("KEX output records or payloads differ from the validated ELF")


def convert_elf(
    image: bytes,
    *,
    expected_target: str | None = None,
    stack_pages: int = 4,
    heap_pages: int = 0,
) -> bytes:
    """Convert validated static ELF64 bytes into one canonical KEX v1 artifact."""
    parsed = parse_elf(image, expected_target)
    limits = STANDARD_LIMITS
    records = _records(parsed, image)
    image_pages = sum(record.memory_bytes // KEX_PAGE_BYTES for record in records)
    image_end = max(record.image_offset + record.memory_bytes for record in records)
    payload_bytes = sum(len(record.file_bytes) for record in records)
    artifact_bytes = KEX_HEADER_BYTES + len(records) * KEX_RECORD_BYTES + payload_bytes
    if len(records) > limits["records"]:
        raise ValueError("ELF load-record count exceeds the standard KEX policy")
    if image_end > limits["image_span"]:
        raise ValueError("ELF image span exceeds the standard KEX policy")
    if image_pages > limits["image_pages"]:
        raise ValueError("ELF mapped pages exceed the standard KEX policy")
    if not limits["stack_min"] <= stack_pages <= limits["stack_max"]:
        raise ValueError("requested KEX stack pages exceed the standard KEX policy")
    if not 0 <= heap_pages <= limits["heap_pages"]:
        raise ValueError("requested KEX heap pages exceed the standard KEX policy")
    resident = image_pages + 1 + stack_pages + heap_pages + limits["table_pages"]
    if resident > limits["resident_pages"]:
        raise ValueError(
            "KEX aggregate resident charge exceeds the standard KEX policy"
        )
    if artifact_bytes > limits["encoded_bytes"]:
        raise ValueError("KEX encoded bytes exceed the standard KEX policy")

    output = bytearray(artifact_bytes)
    output[:8] = KEX_MAGIC
    struct.pack_into(
        "<HHHHHHHHQHHIQQII",
        output,
        8,
        1,
        1,
        KEX_TARGETS[parsed.target],
        KEX_HEADER_BYTES,
        KEX_RECORD_BYTES,
        KEX_ABI_MAJOR,
        KEX_ABI_MINOR,
        0,
        parsed.entry - KEX_IMAGE_BASE,
        len(records),
        0,
        0,
        stack_pages,
        heap_pages,
        KEX_HEADER_BYTES,
        KEX_HEADER_BYTES + len(records) * KEX_RECORD_BYTES,
    )
    payload_offset = KEX_HEADER_BYTES + len(records) * KEX_RECORD_BYTES
    struct.pack_into(
        "<IIHHI",
        output,
        64,
        payload_offset,
        0,
        KEX_RELOCATION_BYTES,
        0,
        0,
    )
    struct.pack_into("<Q", output, 80, artifact_bytes)
    for index, record in enumerate(records):
        record_offset = KEX_HEADER_BYTES + index * KEX_RECORD_BYTES
        struct.pack_into(
            "<QQQQII",
            output,
            record_offset,
            record.image_offset,
            payload_offset,
            len(record.file_bytes),
            record.memory_bytes,
            record.permissions,
            0,
        )
        output[payload_offset : payload_offset + len(record.file_bytes)] = (
            record.file_bytes
        )
        payload_offset += len(record.file_bytes)
    artifact = bytes(output)
    verify_kex(
        artifact,
        parsed.target,
        records,
        entry_offset=parsed.entry - KEX_IMAGE_BASE,
        stack_pages=stack_pages,
        heap_pages=heap_pages,
    )
    return artifact


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="freestanding static ELF64 input")
    parser.add_argument("output", type=Path, help="canonical KEX v1 output")
    parser.add_argument(
        "--target", choices=tuple(KEX_TARGETS), help="require this ELF target"
    )
    parser.add_argument("--stack-pages", type=int, default=4)
    parser.add_argument("--heap-pages", type=int, default=0)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate that output already matches conversion",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        artifact = convert_elf(
            args.input.read_bytes(),
            expected_target=args.target,
            stack_pages=args.stack_pages,
            heap_pages=args.heap_pages,
        )
        if args.check:
            existing = args.output.read_bytes()
            if existing != artifact:
                raise ValueError(
                    "existing KEX output differs from canonical ELF conversion"
                )
            print(f"KEX v1 verified: {len(existing)} bytes -> {args.output}")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(artifact)
            print(f"KEX v1: {len(artifact)} bytes -> {args.output}")
        return 0
    except (FileNotFoundError, OSError, ValueError) as error:
        print(f"elf2kex: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

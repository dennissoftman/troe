//! Strict hosted ELF64 to KEX v1 conversion.

use std::ops::Range;

use troe_application::{
    ABI_MAJOR, ABI_MINOR, ApplicationLimits, KEX_V1_HEADER_BYTES, KEX_V1_LOAD_RECORD_BYTES,
    KEX_V1_MAGIC, KEX_V1_RELOCATION_RECORD_BYTES, MAX_LOAD_RECORDS, PAGE_SIZE, SegmentPermissions,
    Target, parse_kex,
};

use crate::{ToolError, ToolResult};

const ELF_HEADER_BYTES: usize = 64;
const ELF_PROGRAM_HEADER_BYTES: usize = 56;
const ELF_SECTION_HEADER_BYTES: usize = 64;
const ELF_MAX_BYTES: usize = 64 * 1024 * 1024;
const ELF_MAX_PROGRAM_HEADERS: usize = 64;
const ELF_MAX_SECTION_HEADERS: usize = 4096;

const ELF_ET_DYN: u16 = 3;
const ELF_EM_X86_64: u16 = 62;
const ELF_EM_AARCH64: u16 = 183;
const ELF_PT_NULL: u32 = 0;
const ELF_PT_LOAD: u32 = 1;
const ELF_PT_DYNAMIC: u32 = 2;
const ELF_PT_INTERP: u32 = 3;
const ELF_PT_NOTE: u32 = 4;
const ELF_PT_SHLIB: u32 = 5;
const ELF_PT_PHDR: u32 = 6;
const ELF_PT_TLS: u32 = 7;
const ELF_PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const ELF_PT_GNU_STACK: u32 = 0x6474_e551;
const ELF_PT_GNU_RELRO: u32 = 0x6474_e552;
const ELF_PT_GNU_PROPERTY: u32 = 0x6474_e553;
const ELF_PF_X: u32 = 1;
const ELF_PF_W: u32 = 2;
const ELF_PF_R: u32 = 4;

const ELF_SHT_PROGBITS: u32 = 1;
const ELF_SHT_SYMTAB: u32 = 2;
const ELF_SHT_STRTAB: u32 = 3;
const ELF_SHT_RELA: u32 = 4;
const ELF_SHT_HASH: u32 = 5;
const ELF_SHT_DYNAMIC: u32 = 6;
const ELF_SHT_NOTE: u32 = 7;
const ELF_SHT_NOBITS: u32 = 8;
const ELF_SHT_REL: u32 = 9;
const ELF_SHT_DYNSYM: u32 = 11;
const ELF_SHT_INIT_ARRAY: u32 = 14;
const ELF_SHT_FINI_ARRAY: u32 = 15;
const ELF_SHT_PREINIT_ARRAY: u32 = 16;
const ELF_SHT_GROUP: u32 = 17;
const ELF_SHT_SYMTAB_SHNDX: u32 = 18;
const ELF_SHT_RELR: u32 = 19;
const ELF_SHT_GNU_HASH: u32 = 0x6fff_fff6;
const ELF_SHF_WRITE: u64 = 0x1;
const ELF_SHF_ALLOC: u64 = 0x2;
const ELF_SHF_EXECINSTR: u64 = 0x4;
const ELF_SHF_TLS: u64 = 0x400;
const ELF_RELA_BYTES: u64 = 24;
const R_X86_64_RELATIVE: u32 = 8;
const R_AARCH64_RELATIVE: u32 = 1027;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ElfLoadSegment {
    file_offset: u64,
    virtual_address: u64,
    file_bytes: u64,
    memory_bytes: u64,
    flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedElf {
    target: Target,
    entry: u64,
    segments: Vec<ElfLoadSegment>,
    relocations: Vec<ElfRelativeRelocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ElfRelativeRelocation {
    target_offset: u64,
    value_offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_bytes: u64,
    memory_bytes: u64,
    alignment: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SectionHeader {
    name_offset: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KexRecord<'image> {
    image_offset: u64,
    file_bytes: &'image [u8],
    memory_bytes: u64,
    permissions: SegmentPermissions,
}

fn invalid(message: impl Into<String>) -> ToolError {
    ToolError::new(message)
}

fn checked_range(total: usize, offset: u64, length: u64, label: &str) -> ToolResult<Range<usize>> {
    let offset = usize::try_from(offset)
        .map_err(|_| invalid(format!("{label} is outside the ELF artifact")))?;
    let length = usize::try_from(length)
        .map_err(|_| invalid(format!("{label} is outside the ELF artifact")))?;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= total)
        .ok_or_else(|| invalid(format!("{label} is outside the ELF artifact")))?;
    Ok(offset..end)
}

fn read_array<const N: usize>(image: &[u8], offset: usize) -> ToolResult<[u8; N]> {
    image
        .get(offset..offset.saturating_add(N))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| invalid("ELF structure is truncated"))
}

fn read_u16(image: &[u8], offset: usize) -> ToolResult<u16> {
    Ok(u16::from_le_bytes(read_array(image, offset)?))
}

fn read_u32(image: &[u8], offset: usize) -> ToolResult<u32> {
    Ok(u32::from_le_bytes(read_array(image, offset)?))
}

fn read_u64(image: &[u8], offset: usize) -> ToolResult<u64> {
    Ok(u64::from_le_bytes(read_array(image, offset)?))
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn round_up(value: u64, alignment: u64) -> ToolResult<u64> {
    if !alignment.is_power_of_two() {
        return Err(invalid("invalid alignment"));
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or_else(|| invalid("ELF size arithmetic overflow"))
}

fn target_from_machine(machine: u16) -> Option<Target> {
    match machine {
        ELF_EM_X86_64 => Some(Target::X86_64),
        ELF_EM_AARCH64 => Some(Target::Aarch64),
        _ => None,
    }
}

fn permissions(flags: u32) -> Option<SegmentPermissions> {
    match flags {
        ELF_PF_R => Some(SegmentPermissions::ReadOnly),
        flags if flags == ELF_PF_R | ELF_PF_X => Some(SegmentPermissions::ReadExecute),
        flags if flags == ELF_PF_R | ELF_PF_W => Some(SegmentPermissions::ReadWrite),
        _ => None,
    }
}

fn program_headers(image: &[u8], offset: u64, count: usize) -> ToolResult<Vec<ProgramHeader>> {
    let bytes = count
        .checked_mul(ELF_PROGRAM_HEADER_BYTES)
        .ok_or_else(|| invalid("ELF program-header table is outside the ELF artifact"))?;
    let table = checked_range(
        image.len(),
        offset,
        u64::try_from(bytes).map_err(|_| invalid("ELF program-header table is too large"))?,
        "ELF program-header table",
    )?;
    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let at = table.start + index * ELF_PROGRAM_HEADER_BYTES;
        headers.push(ProgramHeader {
            kind: read_u32(image, at)?,
            flags: read_u32(image, at + 4)?,
            offset: read_u64(image, at + 8)?,
            virtual_address: read_u64(image, at + 16)?,
            physical_address: read_u64(image, at + 24)?,
            file_bytes: read_u64(image, at + 32)?,
            memory_bytes: read_u64(image, at + 40)?,
            alignment: read_u64(image, at + 48)?,
        });
    }
    Ok(headers)
}

fn section_headers(image: &[u8], offset: u64, count: usize) -> ToolResult<Vec<SectionHeader>> {
    let bytes = count
        .checked_mul(ELF_SECTION_HEADER_BYTES)
        .ok_or_else(|| invalid("ELF section-header table is outside the ELF artifact"))?;
    let table = checked_range(
        image.len(),
        offset,
        u64::try_from(bytes).map_err(|_| invalid("ELF section-header table is too large"))?,
        "ELF section-header table",
    )?;
    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let at = table.start + index * ELF_SECTION_HEADER_BYTES;
        headers.push(SectionHeader {
            name_offset: read_u32(image, at)?,
            kind: read_u32(image, at + 4)?,
            flags: read_u64(image, at + 8)?,
            address: read_u64(image, at + 16)?,
            offset: read_u64(image, at + 24)?,
            size: read_u64(image, at + 32)?,
            link: read_u32(image, at + 40)?,
            info: read_u32(image, at + 44)?,
            alignment: read_u64(image, at + 48)?,
            entry_size: read_u64(image, at + 56)?,
        });
    }
    Ok(headers)
}

fn section_name(string_table: &[u8], name_offset: u32) -> ToolResult<Option<&[u8]>> {
    if name_offset == 0 {
        return Ok(None);
    }
    let start = usize::try_from(name_offset).map_err(|_| invalid("invalid section name"))?;
    let suffix = string_table
        .get(start..)
        .ok_or_else(|| invalid("ELF section name is outside the string table"))?;
    let length = suffix
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("ELF section name is unterminated"))?;
    Ok(Some(&suffix[..length]))
}

fn validate_section_kind(kind: u32) -> ToolResult<()> {
    if matches!(kind, ELF_SHT_REL | ELF_SHT_RELR) {
        return Err(invalid("ELF contains unsupported relocation records"));
    }
    if matches!(
        kind,
        ELF_SHT_NOTE
            | ELF_SHT_INIT_ARRAY
            | ELF_SHT_FINI_ARRAY
            | ELF_SHT_PREINIT_ARRAY
            | ELF_SHT_GROUP
            | ELF_SHT_SYMTAB_SHNDX
    ) {
        return Err(invalid("ELF contains unsupported runtime or link metadata"));
    }
    if !matches!(
        kind,
        ELF_SHT_PROGBITS
            | ELF_SHT_SYMTAB
            | ELF_SHT_STRTAB
            | ELF_SHT_NOBITS
            | ELF_SHT_RELA
            | ELF_SHT_DYNAMIC
            | ELF_SHT_DYNSYM
            | ELF_SHT_HASH
            | ELF_SHT_GNU_HASH
    ) {
        return Err(invalid(format!(
            "ELF section type {kind:#x} is unsupported"
        )));
    }
    Ok(())
}

fn validate_alloc_section(
    section: SectionHeader,
    kind: u32,
    loads: &[ElfLoadSegment],
) -> ToolResult<()> {
    let section_end = section
        .address
        .checked_add(section.size)
        .ok_or_else(|| invalid("ELF allocated section address overflows"))?;
    let owner = loads.iter().find(|load| {
        let load_end = load.virtual_address.checked_add(load.memory_bytes);
        load.virtual_address <= section.address && load_end.is_some_and(|end| section_end <= end)
    });
    let owner = owner
        .copied()
        .ok_or_else(|| invalid("ELF allocated section is outside every PT_LOAD segment"))?;
    let mut required_flags = ELF_PF_R;
    if section.flags & ELF_SHF_WRITE != 0 {
        required_flags |= ELF_PF_W;
    }
    if section.flags & ELF_SHF_EXECINSTR != 0 {
        required_flags |= ELF_PF_X;
    }
    if owner.flags & required_flags != required_flags {
        return Err(invalid(
            "ELF section permissions exceed its PT_LOAD permissions",
        ));
    }
    if kind != ELF_SHT_NOBITS && section.size != 0 {
        let file_delta = section
            .offset
            .checked_sub(owner.file_offset)
            .ok_or_else(|| invalid("ELF allocated section file/address mapping is inconsistent"))?;
        let address_delta = section
            .address
            .checked_sub(owner.virtual_address)
            .ok_or_else(|| invalid("ELF allocated section file/address mapping is inconsistent"))?;
        if file_delta != address_delta {
            return Err(invalid(
                "ELF allocated section file/address mapping is inconsistent",
            ));
        }
        let section_file_end = section
            .offset
            .checked_add(section.size)
            .ok_or_else(|| invalid("ELF allocated section exceeds file-backed PT_LOAD bytes"))?;
        let load_file_end = owner
            .file_offset
            .checked_add(owner.file_bytes)
            .ok_or_else(|| invalid("ELF allocated section exceeds file-backed PT_LOAD bytes"))?;
        if section_file_end > load_file_end {
            return Err(invalid(
                "ELF allocated section exceeds file-backed PT_LOAD bytes",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_sections(
    image: &[u8],
    sections: &[SectionHeader],
    string_index: usize,
    loads: &[ElfLoadSegment],
) -> ToolResult<Vec<Range<usize>>> {
    if sections.is_empty() {
        if string_index != 0 {
            return Err(invalid("section-name index exists without a section table"));
        }
        return Ok(Vec::new());
    }
    if sections[0]
        != (SectionHeader {
            name_offset: 0,
            kind: 0,
            flags: 0,
            address: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            alignment: 0,
            entry_size: 0,
        })
    {
        return Err(invalid("ELF section zero is not canonical"));
    }
    let mut string_table = &[][..];
    if string_index >= sections.len() {
        return Err(invalid("ELF section-name table index is out of range"));
    }
    if string_index != 0 {
        let section = sections[string_index];
        if section.kind != ELF_SHT_STRTAB || section.flags & ELF_SHF_ALLOC != 0 {
            return Err(invalid(
                "ELF section-name table is not a non-allocating string table",
            ));
        }
        let range = checked_range(
            image.len(),
            section.offset,
            section.size,
            "ELF section-name table",
        )?;
        string_table = &image[range];
        if string_table.first() != Some(&0) || string_table.last() != Some(&0) {
            return Err(invalid("ELF section-name table is noncanonical"));
        }
    }

    let mut described = Vec::new();
    for (index, section) in sections.iter().copied().enumerate().skip(1) {
        if !matches!(section.alignment, 0 | 1) && !section.alignment.is_power_of_two() {
            return Err(invalid(format!(
                "ELF section {index} has invalid alignment"
            )));
        }
        if section.alignment > 1 && section.address != 0 && section.address % section.alignment != 0
        {
            return Err(invalid(format!(
                "ELF section {index} address is misaligned"
            )));
        }
        validate_section_kind(section.kind)?;
        if section.flags & ELF_SHF_TLS != 0 {
            return Err(invalid("ELF contains thread-local storage"));
        }
        if section.flags & ELF_SHF_WRITE != 0 && section.flags & ELF_SHF_EXECINSTR != 0 {
            return Err(invalid("ELF section requests writable executable memory"));
        }
        if let Some(name) = section_name(string_table, section.name_offset)?
            && matches!(name, b".interp" | b".tdata" | b".tbss")
        {
            return Err(invalid(format!(
                "ELF contains unsupported section {}",
                String::from_utf8_lossy(name)
            )));
        }
        if section.kind == ELF_SHT_NOBITS {
            if usize::try_from(section.offset).map_or(true, |offset| offset > image.len()) {
                return Err(invalid("ELF NOBITS section offset is outside the artifact"));
            }
        } else {
            let range = checked_range(
                image.len(),
                section.offset,
                section.size,
                &format!("ELF section {index}"),
            )?;
            if !range.is_empty() {
                described.push(range);
            }
        }
        if section.flags & ELF_SHF_ALLOC != 0 {
            validate_alloc_section(section, section.kind, loads)?;
        } else if section.address != 0 {
            return Err(invalid("ELF non-allocating section has a virtual address"));
        }
        if section.link != 0
            && usize::try_from(section.link).map_or(true, |link| link >= sections.len())
        {
            return Err(invalid("ELF section link index is out of range"));
        }
        if matches!(section.kind, ELF_SHT_SYMTAB | ELF_SHT_DYNSYM) && section.entry_size == 0 {
            return Err(invalid("ELF symbol table has zero-sized entries"));
        }
        if section.kind == ELF_SHT_RELA && section.entry_size != ELF_RELA_BYTES {
            return Err(invalid("ELF RELA entry size is noncanonical"));
        }
        let _ = section.info;
    }
    Ok(described)
}

fn parse_relative_relocations(
    image: &[u8],
    sections: &[SectionHeader],
    string_index: usize,
    loads: &[ElfLoadSegment],
    target: Target,
) -> ToolResult<Vec<ElfRelativeRelocation>> {
    if sections.is_empty() {
        return Ok(Vec::new());
    }
    let names = sections
        .get(string_index)
        .filter(|section| section.kind == ELF_SHT_STRTAB)
        .ok_or_else(|| invalid("ELF section-name table is unavailable"))?;
    let names = &image[checked_range(
        image.len(),
        names.offset,
        names.size,
        "ELF section-name table",
    )?];
    let expected_kind = match target {
        Target::X86_64 => R_X86_64_RELATIVE,
        Target::Aarch64 => R_AARCH64_RELATIVE,
    };
    let mut found = false;
    let mut relocations = Vec::new();
    for section in sections
        .iter()
        .copied()
        .filter(|section| section.kind == ELF_SHT_RELA)
    {
        let name = section_name(names, section.name_offset)?;
        if found || name != Some(b".rela.dyn".as_slice()) {
            return Err(invalid("ELF contains a noncanonical relocation section"));
        }
        found = true;
        if section.size % ELF_RELA_BYTES != 0 {
            return Err(invalid("ELF RELA table is truncated"));
        }
        let range = checked_range(image.len(), section.offset, section.size, "ELF RELA table")?;
        let count = usize::try_from(section.size / ELF_RELA_BYTES)
            .map_err(|_| invalid("ELF RELA count is not representable"))?;
        relocations
            .try_reserve_exact(count)
            .map_err(|_| invalid("ELF RELA metadata allocation failed"))?;
        let record_bytes = usize::try_from(ELF_RELA_BYTES)
            .map_err(|_| invalid("ELF RELA record size is not representable"))?;
        for record in image[range].chunks_exact(record_bytes) {
            let target_offset = read_u64(record, 0)?;
            let info = read_u64(record, 8)?;
            let addend = i64::from_le_bytes(read_array(record, 16)?);
            let relocation_kind = u32::try_from(info & u64::from(u32::MAX))
                .map_err(|_| invalid("ELF relocation kind is invalid"))?;
            let symbol = info >> 32;
            let value_offset = u64::try_from(addend)
                .map_err(|_| invalid("ELF relative relocation addend is negative"))?;
            let target_end = target_offset
                .checked_add(8)
                .ok_or_else(|| invalid("ELF relocation target overflows"))?;
            let target_mapped = loads.iter().any(|load| {
                load.virtual_address <= target_offset
                    && load
                        .virtual_address
                        .checked_add(load.memory_bytes)
                        .is_some_and(|end| target_end <= end)
            });
            let value_mapped = loads.iter().any(|load| {
                load.virtual_address <= value_offset
                    && load
                        .virtual_address
                        .checked_add(load.memory_bytes)
                        .is_some_and(|end| value_offset < end)
            });
            if symbol != 0 || relocation_kind != expected_kind {
                return Err(invalid("ELF contains a non-relative relocation"));
            }
            if !target_mapped {
                return Err(invalid(
                    "ELF relative relocation target is outside the image",
                ));
            }
            if !value_mapped {
                return Err(invalid(
                    "ELF relative relocation value is outside the image",
                ));
            }
            relocations.push(ElfRelativeRelocation {
                target_offset,
                value_offset,
            });
        }
    }
    relocations.sort_unstable_by_key(|relocation| relocation.target_offset);
    if relocations
        .windows(2)
        .any(|pair| pair[0].target_offset == pair[1].target_offset)
    {
        return Err(invalid(
            "ELF contains duplicate relative relocation targets",
        ));
    }
    Ok(relocations)
}

fn validate_identification(image: &[u8]) -> ToolResult<()> {
    const IDENT_PREFIX: &[u8; 9] = b"\x7fELF\x02\x01\x01\x00\x00";
    if image.get(..9) != Some(IDENT_PREFIX.as_slice())
        || image
            .get(9..16)
            .is_none_or(|tail| tail.iter().any(|byte| *byte != 0))
    {
        return Err(invalid(
            "ELF identification is not canonical 64-bit little-endian System V",
        ));
    }
    Ok(())
}

struct ValidatedLoads {
    loads: Vec<ElfLoadSegment>,
    file_ranges: Vec<Range<usize>>,
    phdr_virtual: Option<u64>,
}

#[allow(clippy::too_many_lines)]
fn validate_loads(
    image: &[u8],
    headers: &[ProgramHeader],
    program_offset: u64,
) -> ToolResult<ValidatedLoads> {
    let mut loads = Vec::new();
    let mut file_ranges: Vec<Range<usize>> = Vec::new();
    let mut phdr_virtual = None;
    let mut stack_seen = false;
    let mut dynamic = None;
    for (index, header) in headers.iter().copied().enumerate() {
        if header.kind == ELF_PT_NULL {
            if header.flags != 0
                || header.offset != 0
                || header.virtual_address != 0
                || header.physical_address != 0
                || header.file_bytes != 0
                || header.memory_bytes != 0
                || header.alignment != 0
            {
                return Err(invalid("ELF PT_NULL record has nonzero fields"));
            }
            continue;
        }
        if header.kind == ELF_PT_DYNAMIC {
            if dynamic.replace(header).is_some()
                || header.flags != ELF_PF_R | ELF_PF_W
                || header.file_bytes == 0
                || header.file_bytes != header.memory_bytes
                || header.alignment != 8
            {
                return Err(invalid("ELF PT_DYNAMIC record is noncanonical"));
            }
            continue;
        }
        if matches!(
            header.kind,
            ELF_PT_INTERP
                | ELF_PT_NOTE
                | ELF_PT_SHLIB
                | ELF_PT_TLS
                | ELF_PT_GNU_EH_FRAME
                | ELF_PT_GNU_RELRO
                | ELF_PT_GNU_PROPERTY
        ) {
            return Err(invalid(
                "ELF requires an unsupported dynamic, TLS, note, or RELRO facility",
            ));
        }
        if header.kind == ELF_PT_PHDR {
            if phdr_virtual.is_some() {
                return Err(invalid("ELF contains duplicate PT_PHDR records"));
            }
            let expected_bytes = u64::try_from(headers.len())
                .ok()
                .and_then(|count| count.checked_mul(ELF_PROGRAM_HEADER_BYTES as u64))
                .ok_or_else(|| invalid("ELF PT_PHDR size overflows"))?;
            if header.flags != ELF_PF_R
                || header.offset != program_offset
                || header.file_bytes != expected_bytes
                || header.memory_bytes != expected_bytes
                || !matches!(header.alignment, 8 | PAGE_SIZE)
                || !matches!(header.physical_address, 0)
                    && header.physical_address != header.virtual_address
            {
                return Err(invalid("ELF PT_PHDR record is inconsistent"));
            }
            phdr_virtual = Some(header.virtual_address);
            continue;
        }
        if header.kind == ELF_PT_GNU_STACK {
            if stack_seen {
                return Err(invalid("ELF contains duplicate PT_GNU_STACK records"));
            }
            stack_seen = true;
            if header.flags != ELF_PF_R | ELF_PF_W
                || header.offset != 0
                || header.virtual_address != 0
                || header.physical_address != 0
                || header.file_bytes != 0
                || header.memory_bytes != 0
                || !matches!(header.alignment, 0 | 16)
            {
                return Err(invalid("ELF GNU stack is executable or noncanonical"));
            }
            continue;
        }
        if header.kind != ELF_PT_LOAD {
            return Err(invalid(format!(
                "ELF program-header type {:#x} is unsupported",
                header.kind
            )));
        }
        if loads.len() >= MAX_LOAD_RECORDS {
            return Err(invalid("ELF has more load segments than KEX v1 can encode"));
        }
        if permissions(header.flags).is_none() {
            return Err(invalid("ELF PT_LOAD permissions are not R, RX, or RW"));
        }
        if header.alignment != PAGE_SIZE
            || header.offset % PAGE_SIZE != 0
            || header.virtual_address % PAGE_SIZE != 0
            || !matches!(header.physical_address, 0)
                && header.physical_address != header.virtual_address
            || header.memory_bytes == 0
            || header.file_bytes > header.memory_bytes
        {
            return Err(invalid(
                "ELF PT_LOAD geometry is outside the KEX conversion contract",
            ));
        }
        let range = checked_range(
            image.len(),
            header.offset,
            header.file_bytes,
            &format!("ELF PT_LOAD {index}"),
        )?;
        if !range.is_empty() {
            if file_ranges
                .iter()
                .any(|prior| range.start < prior.end && prior.start < range.end)
            {
                return Err(invalid("ELF PT_LOAD file ranges overlap"));
            }
            file_ranges.push(range);
        }
        loads.push(ElfLoadSegment {
            file_offset: header.offset,
            virtual_address: header.virtual_address,
            file_bytes: header.file_bytes,
            memory_bytes: header.memory_bytes,
            flags: header.flags,
        });
    }
    if loads.is_empty() {
        return Err(invalid("ELF contains no PT_LOAD segment"));
    }
    let dynamic = dynamic.ok_or_else(|| invalid("ELF contains no PT_DYNAMIC record"))?;
    let dynamic_end = dynamic
        .virtual_address
        .checked_add(dynamic.memory_bytes)
        .ok_or_else(|| invalid("ELF PT_DYNAMIC address overflows"))?;
    if !loads.iter().any(|load| {
        load.flags == ELF_PF_R | ELF_PF_W
            && load.virtual_address <= dynamic.virtual_address
            && load
                .virtual_address
                .checked_add(load.memory_bytes)
                .is_some_and(|end| dynamic_end <= end)
    }) {
        return Err(invalid("ELF PT_DYNAMIC is outside writable image data"));
    }
    Ok(ValidatedLoads {
        loads,
        file_ranges,
        phdr_virtual,
    })
}

fn validate_load_order_and_entry(loads: &[ElfLoadSegment], entry: u64) -> ToolResult<()> {
    let mut previous_end = 0_u64;
    let mut executable_entry = false;
    for load in loads {
        let memory_end = load
            .virtual_address
            .checked_add(round_up(load.memory_bytes, PAGE_SIZE)?)
            .ok_or_else(|| invalid("ELF PT_LOAD address overflows"))?;
        if load.virtual_address < previous_end {
            return Err(invalid(
                "ELF PT_LOAD records are unordered or overlap after page rounding",
            ));
        }
        previous_end = memory_end;
        let file_end = load
            .virtual_address
            .checked_add(load.file_bytes)
            .ok_or_else(|| invalid("ELF PT_LOAD address overflows"))?;
        if load.flags & ELF_PF_X != 0 && load.virtual_address <= entry && entry < file_end {
            executable_entry = true;
        }
    }
    if !executable_entry {
        return Err(invalid(
            "ELF entry is not inside file-backed executable bytes",
        ));
    }
    Ok(())
}

fn validate_phdr_coverage(
    loads: &[ElfLoadSegment],
    program_offset: u64,
    program_bytes: u64,
    phdr_virtual: Option<u64>,
) -> ToolResult<()> {
    let Some(phdr_virtual) = phdr_virtual else {
        return Ok(());
    };
    let program_end = program_offset
        .checked_add(program_bytes)
        .ok_or_else(|| invalid("ELF program-header range overflows"))?;
    let covered = loads.iter().any(|load| {
        let Some(file_end) = load.file_offset.checked_add(load.file_bytes) else {
            return false;
        };
        let Some(mapped) = load
            .virtual_address
            .checked_add(program_offset.saturating_sub(load.file_offset))
        else {
            return false;
        };
        load.file_offset <= program_offset && program_end <= file_end && mapped == phdr_virtual
    });
    if !covered {
        return Err(invalid("ELF PT_PHDR is not covered by a PT_LOAD segment"));
    }
    Ok(())
}

fn validate_described_bytes(image: &[u8], mut described: Vec<Range<usize>>) -> ToolResult<()> {
    described.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in described {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    let mut cursor = 0;
    for range in merged {
        if image[cursor..range.start].iter().any(|byte| *byte != 0) {
            return Err(invalid(
                "ELF has nonzero bytes outside described structures",
            ));
        }
        cursor = cursor.max(range.end);
    }
    if cursor != image.len() {
        return Err(invalid(
            "ELF has trailing bytes outside described structures",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn parse_elf(image: &[u8], expected_target: Option<Target>) -> ToolResult<ParsedElf> {
    if image.len() < ELF_HEADER_BYTES {
        return Err(invalid("ELF header is truncated"));
    }
    if image.len() > ELF_MAX_BYTES {
        return Err(invalid(
            "ELF artifact exceeds the hosted conversion ceiling",
        ));
    }
    validate_identification(image)?;
    let file_type = read_u16(image, 16)?;
    let machine = read_u16(image, 18)?;
    let version = read_u32(image, 20)?;
    let entry = read_u64(image, 24)?;
    let program_offset = read_u64(image, 32)?;
    let section_offset = read_u64(image, 40)?;
    let flags = read_u32(image, 48)?;
    let header_bytes = read_u16(image, 52)?;
    let program_record_bytes = read_u16(image, 54)?;
    let program_count = usize::from(read_u16(image, 56)?);
    let section_record_bytes = read_u16(image, 58)?;
    let section_count = usize::from(read_u16(image, 60)?);
    let section_string_index = usize::from(read_u16(image, 62)?);

    let target = target_from_machine(machine)
        .filter(|target| expected_target.is_none_or(|expected| expected == *target));
    let target = target
        .ok_or_else(|| invalid("ELF machine does not match a supported requested KEX target"))?;
    if target == Target::Aarch64 && entry % 4 != 0 {
        return Err(invalid("AArch64 ELF entry is not instruction aligned"));
    }
    if file_type != ELF_ET_DYN
        || version != 1
        || flags != 0
        || usize::from(header_bytes) != ELF_HEADER_BYTES
        || usize::from(program_record_bytes) != ELF_PROGRAM_HEADER_BYTES
        || usize::try_from(program_offset) != Ok(ELF_HEADER_BYTES)
        || !(1..=ELF_MAX_PROGRAM_HEADERS).contains(&program_count)
    {
        return Err(invalid(
            "ELF executable header or program-table layout is noncanonical",
        ));
    }
    if section_count == 0 {
        if section_offset != 0 || section_record_bytes != 0 || section_string_index != 0 {
            return Err(invalid("ELF absent section table has nonzero metadata"));
        }
    } else if usize::from(section_record_bytes) != ELF_SECTION_HEADER_BYTES
        || section_count > ELF_MAX_SECTION_HEADERS
    {
        return Err(invalid("ELF section-table layout is noncanonical"));
    }

    let headers = program_headers(image, program_offset, program_count)?;
    let validated = validate_loads(image, &headers, program_offset)?;
    let loads = validated.loads;
    validate_load_order_and_entry(&loads, entry)?;
    let program_bytes = u64::try_from(program_count)
        .ok()
        .and_then(|count| count.checked_mul(ELF_PROGRAM_HEADER_BYTES as u64))
        .ok_or_else(|| invalid("ELF program-header range overflows"))?;
    validate_phdr_coverage(
        &loads,
        program_offset,
        program_bytes,
        validated.phdr_virtual,
    )?;

    let sections = if section_count == 0 {
        Vec::new()
    } else {
        section_headers(image, section_offset, section_count)?
    };
    let section_ranges = validate_sections(image, &sections, section_string_index, &loads)?;
    let relocations =
        parse_relative_relocations(image, &sections, section_string_index, &loads, target)?;
    let mut described = vec![
        0..ELF_HEADER_BYTES,
        checked_range(
            image.len(),
            program_offset,
            program_bytes,
            "ELF program-header table",
        )?,
    ];
    described.extend(validated.file_ranges);
    described.extend(section_ranges);
    if section_count != 0 {
        let section_bytes = section_count
            .checked_mul(ELF_SECTION_HEADER_BYTES)
            .ok_or_else(|| invalid("ELF section-header range overflows"))?;
        described.push(checked_range(
            image.len(),
            section_offset,
            u64::try_from(section_bytes)
                .map_err(|_| invalid("ELF section-header range overflows"))?,
            "ELF section-header table",
        )?);
    }
    validate_described_bytes(image, described)?;
    Ok(ParsedElf {
        target,
        entry,
        segments: loads,
        relocations,
    })
}

fn records<'image>(parsed: &ParsedElf, image: &'image [u8]) -> ToolResult<Vec<KexRecord<'image>>> {
    parsed
        .segments
        .iter()
        .map(|load| {
            let range = checked_range(
                image.len(),
                load.file_offset,
                load.file_bytes,
                "ELF PT_LOAD",
            )?;
            Ok(KexRecord {
                image_offset: load.virtual_address,
                file_bytes: &image[range],
                memory_bytes: round_up(load.memory_bytes, PAGE_SIZE)?,
                permissions: permissions(load.flags)
                    .ok_or_else(|| invalid("ELF PT_LOAD permissions are invalid"))?,
            })
        })
        .collect()
}

fn validate_policy(
    records: &[KexRecord<'_>],
    relocations: &[ElfRelativeRelocation],
    stack_pages: u64,
    heap_pages: u64,
) -> ToolResult<usize> {
    let limits = ApplicationLimits::standard();
    let image_pages = records.iter().try_fold(0_u64, |pages, record| {
        pages
            .checked_add(record.memory_bytes / PAGE_SIZE)
            .ok_or_else(|| invalid("ELF mapped page count overflows"))
    })?;
    let image_end = records.iter().try_fold(0_u64, |end, record| {
        record
            .image_offset
            .checked_add(record.memory_bytes)
            .map(|record_end| end.max(record_end))
            .ok_or_else(|| invalid("ELF image span overflows"))
    })?;
    let payload_bytes = records.iter().try_fold(0_usize, |bytes, record| {
        bytes
            .checked_add(record.file_bytes.len())
            .ok_or_else(|| invalid("KEX encoded byte count overflows"))
    })?;
    let table_bytes = records
        .len()
        .checked_mul(KEX_V1_LOAD_RECORD_BYTES)
        .ok_or_else(|| invalid("KEX table byte count overflows"))?;
    let relocation_bytes = relocations
        .len()
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or_else(|| invalid("KEX relocation-table byte count overflows"))?;
    let artifact_bytes = KEX_V1_HEADER_BYTES
        .checked_add(table_bytes)
        .and_then(|bytes| bytes.checked_add(relocation_bytes))
        .and_then(|bytes| bytes.checked_add(payload_bytes))
        .ok_or_else(|| invalid("KEX encoded byte count overflows"))?;
    if records.len() > limits.load_records() {
        return Err(invalid(
            "ELF load-record count exceeds the standard KEX policy",
        ));
    }
    if image_end > limits.image_span_bytes() {
        return Err(invalid("ELF image span exceeds the standard KEX policy"));
    }
    if image_pages > limits.image_pages() {
        return Err(invalid("ELF mapped pages exceed the standard KEX policy"));
    }
    let (minimum_stack, maximum_stack) = limits.stack_pages();
    if !(minimum_stack..=maximum_stack).contains(&stack_pages) {
        return Err(invalid(
            "requested KEX stack pages exceed the standard KEX policy",
        ));
    }
    if heap_pages > limits.heap_pages() {
        return Err(invalid(
            "requested KEX heap pages exceed the standard KEX policy",
        ));
    }
    let resident = image_pages
        .checked_add(1)
        .and_then(|pages| pages.checked_add(stack_pages))
        .and_then(|pages| pages.checked_add(heap_pages))
        .and_then(|pages| pages.checked_add(limits.table_pages()))
        .ok_or_else(|| invalid("KEX aggregate resident charge overflows"))?;
    if resident > limits.resident_pages() {
        return Err(invalid(
            "KEX aggregate resident charge exceeds the standard KEX policy",
        ));
    }
    if artifact_bytes > limits.encoded_bytes() {
        return Err(invalid("KEX encoded bytes exceed the standard KEX policy"));
    }
    Ok(artifact_bytes)
}

fn verify_generated(
    artifact: &[u8],
    parsed: &ParsedElf,
    records: &[KexRecord<'_>],
    relocations: &[ElfRelativeRelocation],
    stack_pages: u64,
    heap_pages: u64,
) -> ToolResult<()> {
    let plan = parse_kex(artifact, parsed.target, ABI_MINOR)
        .map_err(|error| invalid(format!("generated KEX failed validation: {error}")))?;
    if plan.entry_address() != plan.image_base().saturating_add(parsed.entry)
        || plan.stack_pages() != stack_pages
        || plan.heap_pages() != heap_pages
        || plan.target() != parsed.target
        || plan.abi_minor() != ABI_MINOR
    {
        return Err(invalid("generated KEX header differs from the ELF policy"));
    }
    let decoded_relocations = plan.relocations().collect::<Vec<_>>();
    if decoded_relocations.len() != relocations.len()
        || decoded_relocations
            .iter()
            .zip(relocations)
            .any(|(decoded, encoded)| {
                decoded.target_offset() != encoded.target_offset
                    || decoded.value_offset() != encoded.value_offset
            })
    {
        return Err(invalid("generated KEX relocations differ from the ELF"));
    }
    let decoded = plan.segments().collect::<Vec<_>>();
    if decoded.len() != records.len() {
        return Err(invalid("generated KEX records differ from the ELF"));
    }
    for (segment, record) in decoded.iter().zip(records) {
        if segment.image_offset() != record.image_offset
            || segment.memory_bytes() != record.memory_bytes
            || segment.file_bytes() != record.file_bytes
            || segment.permissions() != record.permissions
        {
            return Err(invalid(
                "generated KEX records or payloads differ from the ELF",
            ));
        }
    }
    Ok(())
}

/// Convert one closed, static ELF64 input into canonical KEX v1 bytes.
///
/// # Errors
///
/// Rejects unsupported targets, dynamic or relocatable facilities, malformed
/// geometry, noncanonical padding, forbidden permissions, or policy overruns.
#[allow(clippy::too_many_lines)]
pub fn convert_elf(
    image: &[u8],
    expected_target: Option<Target>,
    stack_pages: u64,
    heap_pages: u64,
) -> ToolResult<Vec<u8>> {
    let parsed = parse_elf(image, expected_target)?;
    let records = records(&parsed, image)?;
    let artifact_bytes = validate_policy(&records, &parsed.relocations, stack_pages, heap_pages)?;
    let record_count = u16::try_from(records.len())
        .map_err(|_| invalid("KEX load-record count is not representable"))?;
    let relocations_offset = KEX_V1_HEADER_BYTES
        .checked_add(records.len() * KEX_V1_LOAD_RECORD_BYTES)
        .ok_or_else(|| invalid("KEX relocation offset overflows"))?;
    let payload_offset = relocations_offset
        .checked_add(parsed.relocations.len() * KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or_else(|| invalid("KEX payload offset overflows"))?;
    let entry_offset = parsed.entry;

    let mut output = vec![0_u8; artifact_bytes];
    output[..8].copy_from_slice(&KEX_V1_MAGIC);
    write_u16(&mut output, 8, 1);
    write_u16(&mut output, 10, 1);
    write_u16(&mut output, 12, parsed.target as u16);
    write_u16(
        &mut output,
        14,
        u16::try_from(KEX_V1_HEADER_BYTES)
            .map_err(|_| invalid("KEX header size is not representable"))?,
    );
    write_u16(
        &mut output,
        16,
        u16::try_from(KEX_V1_LOAD_RECORD_BYTES)
            .map_err(|_| invalid("KEX record size is not representable"))?,
    );
    write_u16(&mut output, 18, ABI_MAJOR);
    write_u16(&mut output, 20, ABI_MINOR);
    write_u16(&mut output, 22, 0);
    write_u64(&mut output, 24, entry_offset);
    write_u16(&mut output, 32, record_count);
    write_u16(&mut output, 34, 0);
    write_u32(&mut output, 36, 0);
    write_u64(&mut output, 40, stack_pages);
    write_u64(&mut output, 48, heap_pages);
    write_u32(
        &mut output,
        56,
        u32::try_from(KEX_V1_HEADER_BYTES)
            .map_err(|_| invalid("KEX records offset is not representable"))?,
    );
    write_u32(
        &mut output,
        60,
        u32::try_from(payload_offset)
            .map_err(|_| invalid("KEX payload offset is not representable"))?,
    );
    write_u32(
        &mut output,
        64,
        u32::try_from(relocations_offset)
            .map_err(|_| invalid("KEX relocation offset is not representable"))?,
    );
    write_u32(
        &mut output,
        68,
        u32::try_from(parsed.relocations.len())
            .map_err(|_| invalid("KEX relocation count is not representable"))?,
    );
    write_u16(
        &mut output,
        72,
        u16::try_from(KEX_V1_RELOCATION_RECORD_BYTES)
            .map_err(|_| invalid("KEX relocation record size is not representable"))?,
    );
    write_u64(
        &mut output,
        80,
        u64::try_from(artifact_bytes)
            .map_err(|_| invalid("KEX artifact size is not representable"))?,
    );

    for (index, relocation) in parsed.relocations.iter().enumerate() {
        let at = relocations_offset + index * KEX_V1_RELOCATION_RECORD_BYTES;
        write_u64(&mut output, at, relocation.target_offset);
        write_u64(&mut output, at + 8, relocation.value_offset);
    }

    let mut next_payload = payload_offset;
    for (index, record) in records.iter().enumerate() {
        let at = KEX_V1_HEADER_BYTES + index * KEX_V1_LOAD_RECORD_BYTES;
        write_u64(&mut output, at, record.image_offset);
        write_u64(
            &mut output,
            at + 8,
            u64::try_from(next_payload)
                .map_err(|_| invalid("KEX file offset is not representable"))?,
        );
        write_u64(
            &mut output,
            at + 16,
            u64::try_from(record.file_bytes.len())
                .map_err(|_| invalid("KEX file size is not representable"))?,
        );
        write_u64(&mut output, at + 24, record.memory_bytes);
        write_u32(&mut output, at + 32, record.permissions as u32);
        write_u32(&mut output, at + 36, 0);
        let end = next_payload
            .checked_add(record.file_bytes.len())
            .ok_or_else(|| invalid("KEX payload range overflows"))?;
        output[next_payload..end].copy_from_slice(record.file_bytes);
        next_payload = end;
    }
    verify_generated(
        &output,
        &parsed,
        &records,
        &parsed.relocations,
        stack_pages,
        heap_pages,
    )?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture(target: Target) -> Vec<u8> {
        let code: &[u8] = match target {
            Target::X86_64 => &[0x90, 0xc3],
            Target::Aarch64 => &[0x00, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4],
        };
        let code_offset = ELF_HEADER_BYTES + 4 * ELF_PROGRAM_HEADER_BYTES;
        let data_offset = usize::try_from(PAGE_SIZE).unwrap_or_else(|_| unreachable!());
        let file_bytes = data_offset + 16;
        let mut image = vec![0_u8; file_bytes];
        image[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        put_u16(&mut image, 16, ELF_ET_DYN);
        put_u16(
            &mut image,
            18,
            match target {
                Target::X86_64 => ELF_EM_X86_64,
                Target::Aarch64 => ELF_EM_AARCH64,
            },
        );
        put_u32(&mut image, 20, 1);
        put_u64(
            &mut image,
            24,
            u64::try_from(code_offset).unwrap_or_else(|_| unreachable!()),
        );
        put_u64(&mut image, 32, ELF_HEADER_BYTES as u64);
        put_u16(
            &mut image,
            52,
            u16::try_from(ELF_HEADER_BYTES).unwrap_or_else(|_| unreachable!()),
        );
        put_u16(
            &mut image,
            54,
            u16::try_from(ELF_PROGRAM_HEADER_BYTES).unwrap_or_else(|_| unreachable!()),
        );
        put_u16(&mut image, 56, 4);

        let load = ELF_HEADER_BYTES;
        put_u32(&mut image, load, ELF_PT_LOAD);
        put_u32(&mut image, load + 4, ELF_PF_R | ELF_PF_X);
        put_u64(&mut image, load + 16, 0);
        put_u64(&mut image, load + 24, 0);
        put_u64(
            &mut image,
            load + 32,
            u64::try_from(code_offset + code.len()).unwrap_or_else(|_| unreachable!()),
        );
        put_u64(&mut image, load + 40, PAGE_SIZE);
        put_u64(&mut image, load + 48, PAGE_SIZE);

        let data = load + ELF_PROGRAM_HEADER_BYTES;
        put_u32(&mut image, data, ELF_PT_LOAD);
        put_u32(&mut image, data + 4, ELF_PF_R | ELF_PF_W);
        put_u64(&mut image, data + 8, PAGE_SIZE);
        put_u64(&mut image, data + 16, PAGE_SIZE);
        put_u64(&mut image, data + 32, 16);
        put_u64(&mut image, data + 40, PAGE_SIZE);
        put_u64(&mut image, data + 48, PAGE_SIZE);

        let dynamic = data + ELF_PROGRAM_HEADER_BYTES;
        put_u32(&mut image, dynamic, ELF_PT_DYNAMIC);
        put_u32(&mut image, dynamic + 4, ELF_PF_R | ELF_PF_W);
        put_u64(&mut image, dynamic + 8, PAGE_SIZE);
        put_u64(&mut image, dynamic + 16, PAGE_SIZE);
        put_u64(&mut image, dynamic + 32, 16);
        put_u64(&mut image, dynamic + 40, 16);
        put_u64(&mut image, dynamic + 48, 8);

        let stack = dynamic + ELF_PROGRAM_HEADER_BYTES;
        put_u32(&mut image, stack, ELF_PT_GNU_STACK);
        put_u32(&mut image, stack + 4, ELF_PF_R | ELF_PF_W);
        put_u64(&mut image, stack + 48, 16);
        image[code_offset..code_offset + code.len()].copy_from_slice(code);
        image
    }

    #[test]
    fn canonical_targets_convert_deterministically() {
        for target in [Target::X86_64, Target::Aarch64] {
            let image = fixture(target);
            let first = convert_elf(&image, Some(target), 4, 0);
            let second = convert_elf(&image, Some(target), 4, 0);
            assert!(first.is_ok());
            assert_eq!(first, second);
            let artifact = first.unwrap_or_else(|_| unreachable!());
            assert!(parse_kex(&artifact, target, ABI_MINOR).is_ok());
        }
    }

    #[test]
    fn dynamic_writable_executable_and_residual_bytes_are_rejected() {
        let canonical = fixture(Target::X86_64);
        let mut dynamic = canonical.clone();
        put_u32(
            &mut dynamic,
            ELF_HEADER_BYTES + ELF_PROGRAM_HEADER_BYTES,
            ELF_PT_DYNAMIC,
        );
        assert!(convert_elf(&dynamic, None, 4, 0).is_err());

        let mut writable_executable = canonical.clone();
        put_u32(
            &mut writable_executable,
            ELF_HEADER_BYTES + 4,
            ELF_PF_R | ELF_PF_W | ELF_PF_X,
        );
        assert!(convert_elf(&writable_executable, None, 4, 0).is_err());

        let mut trailing = canonical;
        trailing.push(0);
        assert!(convert_elf(&trailing, None, 4, 0).is_err());
    }

    #[test]
    fn target_and_resource_policy_are_closed() {
        let image = fixture(Target::Aarch64);
        assert!(convert_elf(&image, Some(Target::X86_64), 4, 0).is_err());
        assert!(convert_elf(&image, Some(Target::Aarch64), 3, 0).is_err());
        assert!(convert_elf(&image, Some(Target::Aarch64), 4, (1 << 32) + 1).is_err());
    }
}

//! Closed static local-exec ELF profile. No native loader is enabled here.
use super::{
    ELF_PF_R, ELF_PF_X, ELF_PT_TLS, ELF_SHF_ALLOC, ELF_SHF_EXECINSTR, ELF_SHF_TLS, ELF_SHF_WRITE,
    ELF_SHT_NOBITS, ELF_SHT_PROGBITS, ELF_SHT_STRTAB, ELF_SHT_SYMTAB, ElfLoadSegment,
    ElfRelativeRelocation, KexRecord, ParsedElf, ProgramHeader, SectionHeader, Target, ToolResult,
    checked_range, invalid, read_u16, read_u32, read_u64,
};
use troe_application::{
    KEX_V1_IMAGE_ALIGNMENT, MAX_IMAGE_SPAN_BYTES, static_tls::StaticTlsLayout, tls_artifact,
};

const TRAMPOLINE: &[u8] = b"__troe_thread_start_v1\0";
const SYMBOL_BYTES: u64 = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Info {
    source_offset: u64,
    file_offset: u64,
    pub(super) file_bytes: u64,
    memory_bytes: u64,
    alignment: u64,
    trampoline_offset: u64,
}

impl Info {
    pub(super) fn metadata(self, suffix: u64) -> tls_artifact::Metadata {
        tls_artifact::Metadata {
            source_offset: self.source_offset,
            file_offset: suffix,
            file_bytes: self.file_bytes,
            memory_bytes: self.memory_bytes,
            alignment: self.alignment,
            trampoline_offset: self.trampoline_offset,
        }
    }

    pub(super) fn template(self, image: &[u8]) -> ToolResult<&[u8]> {
        Ok(&image[checked_range(
            image.len(),
            self.file_offset,
            self.file_bytes,
            "ELF TLS initializer",
        )?])
    }
}

pub(super) fn header(
    image: &[u8],
    headers: &[ProgramHeader],
    loads: &[ElfLoadSegment],
    target: Target,
) -> ToolResult<Option<ProgramHeader>> {
    let mut found = None;
    for header in headers
        .iter()
        .copied()
        .filter(|header| header.kind == ELF_PT_TLS)
    {
        if found.replace(header).is_some() {
            return Err(invalid("ELF contains duplicate PT_TLS records"));
        }
        let alignment = header.alignment.max(1);
        StaticTlsLayout::new(
            target,
            header.file_bytes,
            header.memory_bytes,
            alignment,
            u64::MAX,
        )
        .map_err(|error| invalid(format!("ELF TLS layout: {error}")))?;
        if header.flags != ELF_PF_R
            || header.virtual_address % alignment != 0
            || header.offset % alignment != 0
            || !matches!(header.physical_address, 0)
                && header.physical_address != header.virtual_address
            || header
                .virtual_address
                .checked_add(header.memory_bytes)
                .is_none_or(|end| end > MAX_IMAGE_SPAN_BYTES)
        {
            return Err(invalid(
                "ELF PT_TLS flags, alignment residue or range is unsupported",
            ));
        }
        checked_range(
            image.len(),
            header.offset,
            header.file_bytes,
            "ELF PT_TLS initializer",
        )?;
        if header.file_bytes != 0
            && !loads.iter().any(|load| {
                load.flags & ELF_PF_X == 0
                    && load.virtual_address <= header.virtual_address
                    && header.virtual_address - load.virtual_address <= load.file_bytes
                    && header.file_bytes
                        <= load.file_bytes - (header.virtual_address - load.virtual_address)
                    && header.offset.checked_sub(load.file_offset)
                        == header.virtual_address.checked_sub(load.virtual_address)
            })
        {
            return Err(invalid(
                "ELF PT_TLS initializer has no consistent nonexecutable PT_LOAD source",
            ));
        }
    }
    Ok(found)
}

pub(super) fn validate_section(
    image: &[u8],
    section: SectionHeader,
    header: Option<ProgramHeader>,
) -> ToolResult<()> {
    let header = header
        .ok_or_else(|| invalid("ELF contains TLS sections without an admitted PT_TLS profile"))?;
    if section.flags & (ELF_SHF_ALLOC | ELF_SHF_TLS) != ELF_SHF_ALLOC | ELF_SHF_TLS
        || section.flags & !(ELF_SHF_ALLOC | ELF_SHF_WRITE | ELF_SHF_TLS) != 0
        || !matches!(section.kind, ELF_SHT_PROGBITS | ELF_SHT_NOBITS)
        || section.alignment > header.alignment.max(1)
        || section.link != 0
        || section.info != 0
        || section.entry_size != 0
    {
        return Err(invalid(
            "ELF TLS section has unsupported type, flags or metadata",
        ));
    }
    let start = section
        .address
        .checked_sub(header.virtual_address)
        .ok_or_else(|| invalid("ELF TLS section precedes its template"))?;
    let end = start
        .checked_add(section.size)
        .filter(|end| *end <= header.memory_bytes)
        .ok_or_else(|| invalid("ELF TLS section exceeds its template"))?;
    if section.kind == ELF_SHT_PROGBITS {
        if end > header.file_bytes || section.offset.checked_sub(header.offset) != Some(start) {
            return Err(invalid(
                "ELF initialized TLS section does not match PT_TLS file geometry",
            ));
        }
        checked_range(image.len(), section.offset, section.size, "ELF TLS section")?;
    } else if start < header.file_bytes {
        return Err(invalid(
            "ELF zero-filled TLS overlaps initialized template bytes",
        ));
    }
    Ok(())
}

fn validate_extent(sections: &[SectionHeader], header: Option<ProgramHeader>) -> ToolResult<()> {
    let Some(header) = header else {
        return Ok(());
    };
    // ELF .tbss can share virtual addresses with ordinary image data, but its
    // initialized prefix must not also describe an ordinary allocated object.
    let initialized_end = header.virtual_address + header.file_bytes;
    if header.file_bytes != 0
        && sections.iter().any(|section| {
            section.flags & (ELF_SHF_ALLOC | ELF_SHF_TLS) == ELF_SHF_ALLOC
                && section.size != 0
                && section.address < initialized_end
                && header.virtual_address < section.address + section.size
        })
    {
        return Err(invalid(
            "ELF TLS initializer aliases an ordinary allocated section",
        ));
    }
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(sections.len())
        .map_err(|_| invalid("ELF TLS section metadata allocation failed"))?;
    let mut file_end = 0;
    for section in sections
        .iter()
        .filter(|section| section.flags & ELF_SHF_TLS != 0)
    {
        let start = section.address - header.virtual_address;
        let end = start + section.size;
        if section.kind == ELF_SHT_PROGBITS {
            file_end = file_end.max(end);
        }
        if section.size != 0 {
            extents.push(start..end);
        }
    }
    extents.sort_unstable_by_key(|extent| extent.start);
    if file_end != header.file_bytes
        || extents.last().map_or(0, |extent| extent.end) != header.memory_bytes
        || extents.first().is_some_and(|extent| extent.start != 0)
        || extents.windows(2).any(|pair| pair[0].end > pair[1].start)
    {
        return Err(invalid(
            "ELF TLS sections do not describe one exact nonoverlapping template",
        ));
    }
    Ok(())
}

fn symbol_entry(
    image: &[u8],
    sections: &[SectionHeader],
    header: Option<ProgramHeader>,
) -> ToolResult<u64> {
    let mut tables = sections
        .iter()
        .filter(|section| section.kind == ELF_SHT_SYMTAB);
    let table = tables
        .next()
        .ok_or_else(|| invalid("threaded ELF requires a complete symbol table"))?;
    if tables.next().is_some()
        || table.entry_size != SYMBOL_BYTES
        || table.size == 0
        || table.size % SYMBOL_BYTES != 0
    {
        return Err(invalid(
            "threaded ELF has an ambiguous or malformed symbol table",
        ));
    }
    let strings = sections
        .get(
            usize::try_from(table.link)
                .map_err(|_| invalid("ELF symbol string-table index overflows"))?,
        )
        .filter(|section| section.kind == ELF_SHT_STRTAB && section.flags & ELF_SHF_ALLOC == 0)
        .ok_or_else(|| invalid("ELF symbols have no nonallocating string table"))?;
    let names = &image[checked_range(
        image.len(),
        strings.offset,
        strings.size,
        "ELF symbol names",
    )?];
    if names.first() != Some(&0) || names.last() != Some(&0) {
        return Err(invalid("ELF symbol strings are noncanonical"));
    }
    let records = &image[checked_range(image.len(), table.offset, table.size, "ELF symbols")?];
    if records[..24] != [0; 24] {
        return Err(invalid("ELF symbol zero is not canonical"));
    }
    let mut entry = None;
    for record in records.chunks_exact(24).skip(1) {
        let name_offset = usize::try_from(read_u32(record, 0)?)
            .ok()
            .filter(|offset| *offset < names.len())
            .ok_or_else(|| invalid("ELF symbol name offset is outside its string table"))?;
        // The final NUL guarantees termination for every in-range name. Inspect
        // only the fixed trampoline prefix: scanning an attacker-selected long
        // name once per symbol would make validation quadratic in input bytes.
        let trampoline = names[name_offset..].starts_with(TRAMPOLINE);
        let kind = record[4] & 15;
        let index = usize::from(read_u16(record, 6)?);
        let value = read_u64(record, 8)?;
        let size = read_u64(record, 16)?;
        if kind == 6 {
            validate_tls_symbol(sections, header, index, value, size)?;
        }
        if trampoline {
            let section = sections
                .get(index)
                .filter(|section| {
                    section.kind == ELF_SHT_PROGBITS
                        && section.flags
                            & (ELF_SHF_ALLOC | ELF_SHF_EXECINSTR | ELF_SHF_WRITE | ELF_SHF_TLS)
                            == ELF_SHF_ALLOC | ELF_SHF_EXECINSTR
                })
                .ok_or_else(|| {
                    invalid("thread trampoline is not defined in an executable section")
                })?;
            if entry.replace(value).is_some()
                || record[4] != 0x12
                || !matches!(record[5], 0 | 2)
                || size == 0
                || value < section.address
                || value
                    .checked_add(size)
                    .is_none_or(|end| end > section.address + section.size)
            {
                return Err(invalid(
                    "thread trampoline must be one defined strong global function",
                ));
            }
        }
    }
    entry.ok_or_else(|| invalid("threaded ELF is missing __troe_thread_start_v1"))
}

fn validate_tls_symbol(
    sections: &[SectionHeader],
    header: Option<ProgramHeader>,
    index: usize,
    value: u64,
    size: u64,
) -> ToolResult<()> {
    let header = header.ok_or_else(|| invalid("ELF TLS symbol exists without PT_TLS"))?;
    let section = sections
        .get(index)
        .filter(|section| section.flags & ELF_SHF_TLS != 0)
        .ok_or_else(|| invalid("ELF TLS symbol is undefined or names a non-TLS section"))?;
    let section_start = section.address - header.virtual_address;
    if value < section_start
        || value
            .checked_add(size)
            .is_none_or(|end| end > section_start + section.size)
    {
        return Err(invalid("ELF TLS symbol lies outside its template section"));
    }
    Ok(())
}

pub(super) fn validate(
    image: &[u8],
    sections: &[SectionHeader],
    loads: &[ElfLoadSegment],
    relocations: &[ElfRelativeRelocation],
    header: Option<ProgramHeader>,
    target: Target,
) -> ToolResult<Info> {
    validate_extent(sections, header)?;
    // Large PT_LOAD alignment is permitted only for TLS placement. Ordinary
    // allocated objects must still tolerate KEX's actual image-base alignment.
    if sections.iter().any(|section| {
        section.flags & ELF_SHF_ALLOC != 0
            && section.flags & ELF_SHF_TLS == 0
            && section.alignment > KEX_V1_IMAGE_ALIGNMENT
    }) {
        return Err(invalid(
            "non-TLS ELF section alignment exceeds KEX image-base alignment",
        ));
    }
    let trampoline_offset = symbol_entry(image, sections, header)?;
    if (target == Target::Aarch64 && !trampoline_offset.is_multiple_of(4))
        || !loads.iter().any(|load| {
            load.flags == ELF_PF_R | ELF_PF_X
                && load.virtual_address <= trampoline_offset
                && trampoline_offset - load.virtual_address < load.file_bytes
        })
    {
        return Err(invalid(
            "thread trampoline is outside file-backed executable PT_LOAD bytes",
        ));
    }
    let Some(header) = header else {
        return Ok(Info {
            source_offset: 0,
            file_offset: 0,
            file_bytes: 0,
            memory_bytes: 0,
            alignment: 1,
            trampoline_offset,
        });
    };
    if header.file_bytes != 0
        && relocations.iter().any(|relocation| {
            relocation.target_offset < header.virtual_address + header.file_bytes
                && header.virtual_address < relocation.target_offset + 8
        })
    {
        return Err(invalid(
            "ELF TLS initializer requires unsupported pointer relocations",
        ));
    }
    Ok(Info {
        source_offset: if header.file_bytes == 0 {
            0
        } else {
            header.virtual_address
        },
        file_offset: header.offset,
        file_bytes: header.file_bytes,
        memory_bytes: header.memory_bytes,
        alignment: header.alignment.max(1),
        trampoline_offset,
    })
}

pub(super) fn verify_generated(
    output: &[u8],
    image: &[u8],
    parsed: &ParsedElf,
    records: &[KexRecord<'_>],
    stack_pages: u64,
    heap_pages: u64,
) -> ToolResult<()> {
    let artifact = tls_artifact::Artifact::parse(output, parsed.target)
        .map_err(|error| invalid(format!("generated TLS KEX failed validation: {error}")))?;
    let info = parsed
        .tls
        .ok_or_else(|| invalid("generated TLS KEX has no source profile"))?;
    let suffix = (output.len() as u64)
        .checked_sub(info.file_bytes)
        .ok_or_else(|| invalid("generated TLS KEX has a truncated suffix"))?;
    if artifact.target() != parsed.target
        || artifact.entry_offset() != parsed.entry
        || artifact.stack_pages() != stack_pages
        || artifact.heap_pages() != heap_pages
        || artifact.metadata() != info.metadata(suffix)
        || artifact.template() != info.template(image)?
        || !artifact
            .segments()
            .map(|s| {
                (
                    s.image_offset(),
                    s.memory_bytes(),
                    s.file_bytes(),
                    s.permissions(),
                )
            })
            .eq(records
                .iter()
                .map(|r| (r.image_offset, r.memory_bytes, r.file_bytes, r.permissions)))
        || !artifact
            .relocations()
            .map(|r| (r.target_offset(), r.value_offset()))
            .eq(parsed
                .relocations
                .iter()
                .map(|r| (r.target_offset, r.value_offset)))
    {
        return Err(invalid(
            "generated TLS KEX differs from its validated ELF source",
        ));
    }
    Ok(())
}

//! Static TLS container inspection, separate from native load admission.
//!
//! Container 1.3 explicitly requires application ABI 1.4. The native and
//! streaming loaders still accept only container 1.2. This reader reuses their
//! image grammar but produces no startup layout, native mappings or load plan.
//! The immutable TLS initializer is an exact suffix of the artifact; it must
//! never be reconstructed from writable application memory after execution starts.

use crate::bytes::{read_u32, read_u64, write_u32, write_u64};
use crate::executable::{
    HeaderFormat, ParsedHeader, parse_header_for_format, parse_relocations, parse_segments,
};
use crate::static_tls::{StaticTlsError, StaticTlsLayout};
use crate::{
    ApplicationLimits, KEX_V1_RELOCATION_RECORD_BYTES, LoadSegment, MAX_IMAGE_SPAN_BYTES,
    MAX_LOAD_RECORDS, ParseError, RelativeRelocation, Target,
};
use core::fmt;

/// Explicit TLS container revision; not the current native loader revision.
pub const CONTAINER_MINOR: u16 = 3;
/// Base header plus one exact TLS extension.
pub const HEADER_BYTES: usize = 160;
/// Exact TLS extension size, at bytes 96..160.
pub const EXTENSION_BYTES: usize = 64;
/// TLS flag in this container version; all other bits remain rejected.
pub const FLAG: u16 = 2;
/// Static local-exec template and two-argument thread bootstrap convention.
pub const PROFILE: u32 = 1;

/// Rejection before publishing any artifact inspection result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Shared KEX image grammar rejected the bytes.
    Image(ParseError),
    /// Compiler TLS geometry or its explicit page allowance is invalid.
    Layout(StaticTlsError),
    /// TLS extension, profile, bounds or canonical suffix is invalid.
    InvalidTemplate,
    /// Main or worker entry is outside file-backed immutable executable bytes.
    InvalidEntry,
    /// A relative relocation overlaps the initialized TLS source.
    RelocatedTemplate,
    /// The immutable suffix differs from its nonexecutable image source.
    InconsistentTemplate,
}

impl From<ParseError> for Error {
    fn from(error: ParseError) -> Self {
        Self::Image(error)
    }
}
impl From<StaticTlsError> for Error {
    fn from(error: StaticTlsError) -> Self {
        Self::Layout(error)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(error) => error.fmt(formatter),
            Self::Layout(error) => error.fmt(formatter),
            Self::InvalidTemplate => {
                formatter.write_str("KEX TLS extension or suffix is noncanonical")
            }
            Self::InvalidEntry => {
                formatter.write_str("KEX TLS entry is not file-backed executable code")
            }
            Self::RelocatedTemplate => {
                formatter.write_str("KEX TLS initializer requires unsupported relocations")
            }
            Self::InconsistentTemplate => {
                formatter.write_str("KEX TLS suffix differs from its image initializer")
            }
        }
    }
}

/// Explicit TLS header fields; encoding validates scalar geometry, while
/// [`Artifact::parse`] additionally validates the complete image relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    /// Image-relative initialized TLS source; exactly zero when file bytes are zero.
    pub source_offset: u64,
    /// Exact start of the immutable artifact suffix, after all image payloads.
    pub file_offset: u64,
    /// Initialized template bytes in the suffix.
    pub file_bytes: u64,
    /// Complete template extent, including zero-filled thread-local storage.
    pub memory_bytes: u64,
    /// Nonzero power-of-two template alignment with zero residue.
    pub alignment: u64,
    /// Image-relative worker trampoline using the thread descriptor convention.
    pub trampoline_offset: u64,
}

impl Metadata {
    /// Compute complete compiler TLS geometry with an explicit page allowance.
    ///
    /// # Errors
    /// Rejects unsupported geometry or insufficient pages, before allocation.
    pub fn layout(self, target: Target, max_pages: u64) -> Result<StaticTlsLayout, Error> {
        Ok(StaticTlsLayout::new(
            target,
            self.file_bytes,
            self.memory_bytes,
            self.alignment,
            max_pages,
        )?)
    }

    /// Decode the exact versioned extension without accepting trailing bytes.
    ///
    /// # Errors
    /// Rejects unknown profiles, reserved bytes, bad scalar bounds or TLS layout.
    pub fn decode(bytes: &[u8], target: Target) -> Result<Self, Error> {
        if bytes.len() != EXTENSION_BYTES
            || read_u32(bytes, 48)? != PROFILE
            || read_u32(bytes, 52)? != 0
            || read_u64(bytes, 56)? != 0
        {
            return Err(Error::InvalidTemplate);
        }
        let metadata = Self {
            source_offset: read_u64(bytes, 0)?,
            file_offset: read_u64(bytes, 8)?,
            file_bytes: read_u64(bytes, 16)?,
            memory_bytes: read_u64(bytes, 24)?,
            alignment: read_u64(bytes, 32)?,
            trampoline_offset: read_u64(bytes, 40)?,
        };
        metadata.validate(target)?;
        Ok(metadata)
    }

    /// Encode canonical extension bytes, with no partial destination writes.
    ///
    /// # Errors
    /// Rejects bad scalar bounds and unsupported TLS geometry.
    pub fn encode(self, target: Target) -> Result<[u8; EXTENSION_BYTES], Error> {
        self.validate(target)?;
        let mut bytes = [0; EXTENSION_BYTES];
        for (offset, value) in [
            (0, self.source_offset),
            (8, self.file_offset),
            (16, self.file_bytes),
            (24, self.memory_bytes),
            (32, self.alignment),
            (40, self.trampoline_offset),
        ] {
            write_u64(&mut bytes, offset, value);
        }
        write_u32(&mut bytes, 48, PROFILE);
        Ok(bytes)
    }

    fn validate(self, target: Target) -> Result<(), Error> {
        self.layout(target, u64::MAX)?; // Geometry only; this is no native admission grant.
        if self.file_offset < HEADER_BYTES as u64
            || self.file_offset.checked_add(self.file_bytes).is_none()
            || self
                .source_offset
                .checked_add(self.file_bytes)
                .is_none_or(|end| end > MAX_IMAGE_SPAN_BYTES)
            || (self.file_bytes == 0 && self.source_offset != 0)
            || self.trampoline_offset >= MAX_IMAGE_SPAN_BYTES
            || (target == Target::Aarch64 && !self.trampoline_offset.is_multiple_of(4))
        {
            return Err(Error::InvalidTemplate);
        }
        Ok(())
    }
}

/// Validated image/TLS bytes for offline inspection or conversion verification.
///
/// This type cannot encode startup or substitute for native resource admission.
/// Segment addresses use zero image base and are therefore image-relative.
pub struct Artifact<'a> {
    header: ParsedHeader,
    metadata: Metadata,
    segments: [Option<LoadSegment<'a>>; MAX_LOAD_RECORDS],
    relocations: &'a [u8],
    template: &'a [u8],
}

impl<'a> Artifact<'a> {
    /// Validate exact container/image/TLS geometry without allocating.
    ///
    /// # Errors
    /// Rejects malformed image metadata, unsupported versions, source/suffix
    /// mismatch, relocated TLS initializers and invalid main/worker entries.
    pub fn parse(bytes: &'a [u8], target: Target) -> Result<Self, Error> {
        let limits = ApplicationLimits::standard();
        if bytes.len() > limits.encoded_bytes() {
            return Err(ParseError::ArtifactTooLarge.into());
        }
        let header = parse_header_for_format(
            bytes,
            bytes.len(),
            target,
            troe_abi::startup::THREAD_ABI_MINOR,
            limits,
            HeaderFormat::StaticTls,
        )?;
        let metadata = Metadata::decode(&bytes[96..HEADER_BYTES], target)?;
        let file_offset =
            usize::try_from(metadata.file_offset).map_err(|_| Error::InvalidTemplate)?;
        if file_offset < header.payload_offset
            || metadata.file_offset.checked_add(metadata.file_bytes) != Some(bytes.len() as u64)
        {
            return Err(Error::InvalidTemplate);
        }
        let image = bytes.get(..file_offset).ok_or(Error::InvalidTemplate)?;
        let parsed = parse_segments(image, header, 0)?;
        let relocations = parse_relocations(image, header, &parsed)?;
        let template = &bytes[file_offset..];
        for entry in [header.entry_offset, metadata.trampoline_offset] {
            if (target == Target::Aarch64 && !entry.is_multiple_of(4))
                || !parsed.segments.iter().flatten().any(|segment| {
                    segment.permissions().executable()
                        && segment.image_offset() <= entry
                        && entry - segment.image_offset() < segment.file_bytes().len() as u64
                })
            {
                return Err(Error::InvalidEntry);
            }
        }
        if metadata.file_bytes != 0 {
            let source_end = metadata.source_offset + metadata.file_bytes;
            let source = parsed
                .segments
                .iter()
                .flatten()
                .find(|segment| {
                    !segment.permissions().executable()
                        && segment.image_offset() <= metadata.source_offset
                        && source_end - segment.image_offset() <= segment.file_bytes().len() as u64
                })
                .ok_or(Error::InconsistentTemplate)?;
            let offset = usize::try_from(metadata.source_offset - source.image_offset())
                .map_err(|_| Error::InvalidTemplate)?;
            if source.file_bytes().get(offset..offset + template.len()) != Some(template) {
                return Err(Error::InconsistentTemplate);
            }
            for record in relocations.chunks_exact(KEX_V1_RELOCATION_RECORD_BYTES) {
                let destination = read_u64(record, 0)?;
                if destination < source_end && metadata.source_offset < destination + 8 {
                    return Err(Error::RelocatedTemplate);
                }
            }
        }
        Ok(Self {
            header,
            metadata,
            segments: parsed.segments,
            relocations,
            template,
        })
    }

    /// Target architecture.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.header.target
    }
    /// Validated TLS extension.
    #[must_use]
    pub const fn metadata(&self) -> Metadata {
        self.metadata
    }
    /// Immutable initialized prefix, never a view of writable process memory.
    #[must_use]
    pub const fn template(&self) -> &'a [u8] {
        self.template
    }
    /// Complete executable bytes retained by a full-artifact staging path.
    #[must_use]
    pub const fn encoded_bytes(&self) -> u64 {
        // Parsing proves that the exact initializer suffix ends the artifact.
        self.metadata.file_offset + self.metadata.file_bytes
    }
    /// Main entry as an image-relative byte offset.
    #[must_use]
    pub const fn entry_offset(&self) -> u64 {
        self.header.entry_offset
    }
    /// Declared image reservation size; excludes thread-local allocations.
    #[must_use]
    pub const fn image_span_bytes(&self) -> u64 {
        self.header.image_span_bytes
    }
    /// Requested initial stack count; no backing has been admitted.
    #[must_use]
    pub const fn stack_pages(&self) -> u64 {
        self.header.stack_pages
    }
    /// Requested initial heap count; no backing has been admitted.
    #[must_use]
    pub const fn heap_pages(&self) -> u64 {
        self.header.heap_pages
    }
    /// Ordered image segments with a zero inspection base.
    pub fn segments(&self) -> impl Iterator<Item = LoadSegment<'a>> + '_ {
        self.segments.iter().flatten().copied()
    }
    /// Validated image-relative pointer fixups, never TLS module relocations.
    pub fn relocations(&self) -> impl Iterator<Item = RelativeRelocation> + '_ {
        self.relocations
            .chunks_exact(KEX_V1_RELOCATION_RECORD_BYTES)
            .map(|record| RelativeRelocation {
                target_offset: read_u64(record, 0).unwrap_or_else(|_| unreachable!()),
                value_offset: read_u64(record, 8).unwrap_or_else(|_| unreachable!()),
            })
    }
}

#[cfg(test)]
mod tests;

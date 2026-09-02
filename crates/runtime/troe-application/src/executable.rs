//! The KEX v1 executable container and its bounded parser.

use crate::bytes::{read_u16, read_u32, read_u64};
use crate::{
    ABI_MAJOR, ApplicationLayout, ApplicationLimits, CONTAINER_MAJOR, CONTAINER_MINOR,
    HEADER_ABI_MAJOR, HEADER_ABI_MINOR, HEADER_ARTIFACT_BYTES, HEADER_BYTES,
    HEADER_CONTAINER_MAJOR, HEADER_CONTAINER_MINOR, HEADER_ENTRY_OFFSET, HEADER_FLAGS,
    HEADER_HEAP_PAGES, HEADER_IMAGE_SPAN_PAGES, HEADER_PAYLOAD_OFFSET, HEADER_RECORD_BYTES,
    HEADER_RECORD_COUNT, HEADER_RECORDS_OFFSET, HEADER_RELOCATION_BYTES, HEADER_RELOCATION_COUNT,
    HEADER_RELOCATIONS_OFFSET, HEADER_RESERVED_RELOCATION16, HEADER_RESERVED_RELOCATION32,
    HEADER_RESERVED16, HEADER_STACK_PAGES, HEADER_TARGET, KEX_V1_DECLARED_SPAN_ABI_MINOR,
    KEX_V1_HEADER_BYTES, KEX_V1_IMAGE_ALIGNMENT, KEX_V1_IMAGE_BASE, KEX_V1_LEGACY_IMAGE_SPAN_BYTES,
    KEX_V1_LOAD_RECORD_BYTES, KEX_V1_MAGIC, KEX_V1_MIN_IMAGE_BASE, KEX_V1_RELOCATION_RECORD_BYTES,
    KEX_V1_USER_END, LoadCharges, LoadPlan, LoadSegment, MAX_LOAD_RECORDS, PAGE_SIZE,
    RECORD_FILE_BYTES, RECORD_FILE_OFFSET, RECORD_IMAGE_OFFSET, RECORD_MEMORY_BYTES,
    RECORD_PERMISSIONS, RECORD_RESERVED, RELOCATION_TARGET_OFFSET, RELOCATION_VALUE_OFFSET,
    STARTUP_PAGES, canonical_image_span_bytes, maximum_table_pages,
};
use core::fmt;

/// Architecture encoded by one KEX artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Target {
    /// 64-bit x86 application using the ABI v1 x86 call convention.
    X86_64 = 1,
    /// 64-bit Arm application using the ABI v1 `AArch64` call convention.
    Aarch64 = 2,
}

impl Target {
    const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::X86_64),
            2 => Some(Self::Aarch64),
            _ => None,
        }
    }
}

/// Closed page permission values representable by KEX v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SegmentPermissions {
    /// Immutable non-executable data.
    ReadOnly = 1,
    /// Immutable executable code.
    ReadExecute = 2,
    /// Mutable non-executable data.
    ReadWrite = 3,
}

/// Kernel-selected virtual placement for one independently isolated image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadPlacement {
    pub(crate) image_base: u64,
    stack_top: u64,
}

impl LoadPlacement {
    /// Construct an explicit image/stack placement.
    ///
    /// Full validation is performed together with the executable's requested
    /// heap and stack geometry by [`parse_kex_at`].
    #[must_use]
    pub const fn new(image_base: u64, stack_top: u64) -> Self {
        Self {
            image_base,
            stack_top,
        }
    }

    /// First virtual byte of the image window.
    #[must_use]
    pub const fn image_base(self) -> u64 {
        self.image_base
    }

    /// Exclusive top of the initially mapped stack.
    #[must_use]
    pub const fn stack_top(self) -> u64 {
        self.stack_top
    }

    pub(crate) const STANDARD: Self = Self {
        image_base: KEX_V1_IMAGE_BASE,
        stack_top: KEX_V1_USER_END - PAGE_SIZE,
    };
}

impl SegmentPermissions {
    pub(crate) const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::ReadOnly),
            2 => Some(Self::ReadExecute),
            3 => Some(Self::ReadWrite),
            _ => None,
        }
    }

    /// Whether instruction fetch is permitted.
    #[must_use]
    pub const fn executable(self) -> bool {
        matches!(self, Self::ReadExecute)
    }

    /// Whether writes are permitted.
    #[must_use]
    pub const fn writable(self) -> bool {
        matches!(self, Self::ReadWrite)
    }
}
/// Deterministic KEX rejection category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Input exceeds the standard staging ceiling.
    ArtifactTooLarge,
    /// Input is shorter than the fixed header.
    TruncatedHeader,
    /// Header magic is not KEX.
    InvalidMagic,
    /// Container major or minor is not implemented.
    UnsupportedContainerVersion,
    /// Target value is unknown or differs from the running target.
    WrongTarget,
    /// Fixed header, record, table, or payload offsets are noncanonical.
    InvalidLayout,
    /// A reserved field or flag is nonzero.
    NonzeroReserved,
    /// Application ABI major or minimum minor is unsupported.
    UnsupportedAbi,
    /// Declared artifact size differs from the bounded input.
    LengthMismatch,
    /// Load-record count is zero or exceeds the standard policy.
    InvalidRecordCount,
    /// Checked format, address, or page arithmetic overflowed.
    ArithmeticOverflow,
    /// A segment permission value is outside the v1 closed set.
    InvalidPermissions,
    /// A segment has empty, unaligned, or inconsistent file/memory bounds.
    InvalidSegmentRange,
    /// Segments are not ordered or their page ranges overlap.
    OverlappingSegments,
    /// File payload ranges are not exact, ordered, and canonical.
    NoncanonicalPayload,
    /// A segment ends beyond the image span the artifact declared.
    ImageSpanExceeded,
    /// The declared image span is zero, misaligned, or above the standard policy.
    InvalidImageSpan,
    /// Requested stack pages are outside the standard range.
    StackBudgetExceeded,
    /// Requested heap pages exceed the standard policy.
    HeapBudgetExceeded,
    /// Aggregate private plus table reservation exceeds the standard policy.
    ResidentBudgetExceeded,
    /// No executable segment exists.
    MissingExecutableSegment,
    /// Entry is outside all executable segments.
    InvalidEntryPoint,
    /// Kernel-selected image/heap/stack placement is noncanonical.
    InvalidPlacement,
    /// A relative relocation is malformed, unordered, or targets outside the image.
    InvalidRelocation,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArtifactTooLarge => "KEX artifact exceeds the encoded-size budget",
            Self::TruncatedHeader => "KEX header is truncated",
            Self::InvalidMagic => "KEX magic is invalid",
            Self::UnsupportedContainerVersion => "KEX container version is unsupported",
            Self::WrongTarget => "KEX target does not match the running architecture",
            Self::InvalidLayout => "KEX header or table layout is noncanonical",
            Self::NonzeroReserved => "KEX reserved field or flag is nonzero",
            Self::UnsupportedAbi => "KEX application ABI is unsupported",
            Self::LengthMismatch => "KEX declared length differs from its input length",
            Self::InvalidRecordCount => "KEX load-record count is invalid",
            Self::ArithmeticOverflow => "KEX checked arithmetic overflowed",
            Self::InvalidPermissions => "KEX segment permissions are invalid",
            Self::InvalidSegmentRange => "KEX segment range is invalid",
            Self::OverlappingSegments => "KEX segments overlap or are out of order",
            Self::NoncanonicalPayload => "KEX segment payload layout is noncanonical",
            Self::ImageSpanExceeded => "KEX segment ends beyond the declared image span",
            Self::InvalidImageSpan => "KEX declared image span is invalid",
            Self::StackBudgetExceeded => "KEX stack request exceeds the standard policy",
            Self::HeapBudgetExceeded => "KEX heap request exceeds the standard policy",
            Self::ResidentBudgetExceeded => "KEX resident-page charge exceeds the standard policy",
            Self::MissingExecutableSegment => "KEX has no executable segment",
            Self::InvalidEntryPoint => "KEX entry point is not executable",
            Self::InvalidPlacement => "KEX virtual placement is invalid",
            Self::InvalidRelocation => "KEX relative relocation is invalid",
        })
    }
}
/// Parse and validate a complete KEX v1 artifact without allocating.
///
/// `supported_abi_minor` is the highest ABI minor implemented by the caller.
/// The current kernel passes [`ABI_MINOR`].
///
/// # Errors
///
/// Returns one deterministic rejection category without producing a partial
/// plan. No artifact byte is interpreted as a native pointer or Rust layout.
pub fn parse_kex(
    artifact: &[u8],
    expected_target: Target,
    supported_abi_minor: u16,
) -> Result<LoadPlan<'_>, ParseError> {
    parse_with_limits(
        artifact,
        expected_target,
        supported_abi_minor,
        ApplicationLimits::standard(),
        LoadPlacement::STANDARD,
    )
}

/// Parse and validate a KEX artifact at one explicit randomized placement.
///
/// # Errors
///
/// Returns the same deterministic format errors as [`parse_kex`], plus
/// [`ParseError::InvalidPlacement`] for noncanonical or overlapping geometry.
pub fn parse_kex_at(
    artifact: &[u8],
    expected_target: Target,
    supported_abi_minor: u16,
    placement: LoadPlacement,
) -> Result<LoadPlan<'_>, ParseError> {
    parse_with_limits(
        artifact,
        expected_target,
        supported_abi_minor,
        ApplicationLimits::standard(),
        placement,
    )
}

pub(crate) fn parse_with_limits(
    artifact: &[u8],
    expected_target: Target,
    supported_abi_minor: u16,
    limits: ApplicationLimits,
    placement: LoadPlacement,
) -> Result<LoadPlan<'_>, ParseError> {
    if artifact.len() > limits.encoded_bytes {
        return Err(ParseError::ArtifactTooLarge);
    }
    let header = parse_header(artifact, expected_target, supported_abi_minor, limits)?;
    let parsed = parse_segments(artifact, header, placement.image_base)?;
    let relocations = parse_relocations(artifact, header, &parsed)?;
    let private_pages = parsed
        .image_pages
        .checked_add(header.stack_pages)
        .and_then(|pages| pages.checked_add(header.heap_pages))
        .and_then(|pages| pages.checked_add(STARTUP_PAGES))
        .ok_or(ParseError::ArithmeticOverflow)?;
    let reserved_resident_pages = maximum_table_pages(private_pages)
        .and_then(|tables| private_pages.checked_add(tables))
        .ok_or(ParseError::ArithmeticOverflow)?;
    if reserved_resident_pages > limits.resident_pages {
        return Err(ParseError::ResidentBudgetExceeded);
    }
    let layout = application_layout(
        header.stack_pages,
        header.heap_pages,
        header.abi_minor,
        header.image_span_bytes,
        limits,
        placement,
    )?;

    Ok(LoadPlan {
        target: header.target,
        abi_minor: header.abi_minor,
        image_base: placement.image_base,
        entry_offset: header.entry_offset,
        stack_pages: header.stack_pages,
        heap_pages: header.heap_pages,
        segments: parsed.segments,
        segment_count: header.record_count,
        relocations,
        relocation_count: header.relocation_count,
        charges: LoadCharges {
            staging_bytes: artifact.len(),
            image_pages: parsed.image_pages,
            stack_pages: header.stack_pages,
            heap_pages: header.heap_pages,
            private_pages,
            reserved_resident_pages,
        },
        layout,
    })
}

pub(crate) fn application_layout(
    stack_pages: u64,
    heap_pages: u64,
    abi_minor: u16,
    image_span_bytes: u64,
    limits: ApplicationLimits,
    placement: LoadPlacement,
) -> Result<ApplicationLayout, ParseError> {
    if placement.image_base < KEX_V1_MIN_IMAGE_BASE
        || !placement.image_base.is_multiple_of(KEX_V1_IMAGE_ALIGNMENT)
        || !placement.stack_top.is_multiple_of(PAGE_SIZE)
        || placement.stack_top >= KEX_V1_USER_END
    {
        return Err(ParseError::InvalidPlacement);
    }
    let startup_address = placement
        .image_base
        .checked_add(image_span_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let heap_address = startup_address
        .checked_add(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let heap_bytes = heap_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let stack_slot_bytes = limits
        .maximum_stack_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let (lower_guard_address, upper_guard_address) = if abi_minor == 0 {
        let heap_slot_bytes = limits
            .heap_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(ParseError::ArithmeticOverflow)?;
        let lower_guard_address = heap_address
            .checked_add(heap_slot_bytes)
            .ok_or(ParseError::ArithmeticOverflow)?;
        let upper_guard_address = lower_guard_address
            .checked_add(PAGE_SIZE)
            .and_then(|stack_slot| stack_slot.checked_add(stack_slot_bytes))
            .ok_or(ParseError::ArithmeticOverflow)?;
        (lower_guard_address, upper_guard_address)
    } else {
        let upper_guard_address = placement.stack_top;
        let lower_guard_address = upper_guard_address
            .checked_sub(stack_slot_bytes)
            .and_then(|stack_slot| stack_slot.checked_sub(PAGE_SIZE))
            .ok_or(ParseError::ArithmeticOverflow)?;
        (lower_guard_address, upper_guard_address)
    };
    let stack_bytes = stack_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let stack_bottom = upper_guard_address
        .checked_sub(stack_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let user_end = upper_guard_address
        .checked_add(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let initial_heap_end = heap_address
        .checked_add(heap_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    if initial_heap_end > lower_guard_address || user_end > KEX_V1_USER_END {
        return Err(ParseError::InvalidPlacement);
    }
    Ok(ApplicationLayout {
        startup_address,
        heap_address,
        heap_bytes,
        stack_bottom,
        stack_top: upper_guard_address,
        lower_guard_address,
        upper_guard_address,
    })
}

#[derive(Clone, Copy)]
pub(crate) struct ParsedHeader {
    pub(crate) target: Target,
    pub(crate) abi_minor: u16,
    pub(crate) image_span_bytes: u64,
    pub(crate) entry_offset: u64,
    pub(crate) record_count: usize,
    pub(crate) records_offset: usize,
    pub(crate) payload_offset: usize,
    pub(crate) stack_pages: u64,
    pub(crate) heap_pages: u64,
    pub(crate) relocations_offset: usize,
    pub(crate) relocation_count: usize,
}

fn parse_header(
    artifact: &[u8],
    expected_target: Target,
    supported_abi_minor: u16,
    limits: ApplicationLimits,
) -> Result<ParsedHeader, ParseError> {
    parse_header_with_len(
        artifact,
        artifact.len(),
        expected_target,
        supported_abi_minor,
        limits,
    )
}

/// Resolve one artifact's image span from its header.
///
/// ABI 1.2 and above declare the span as a page count in the field ABI 1.0 and
/// 1.1 reserve; those older artifacts leave it zero and take the fixed implied
/// span. The span must be nonzero, aligned, and within the standard maximum.
/// The segment parser separately requires it to be the exact canonical span.
fn parse_image_span(
    header: &[u8],
    abi_minor: u16,
    limits: ApplicationLimits,
) -> Result<u64, ParseError> {
    let declared_span_pages = read_u32(header, HEADER_IMAGE_SPAN_PAGES)?;
    let image_span_bytes = if abi_minor < KEX_V1_DECLARED_SPAN_ABI_MINOR {
        if declared_span_pages != 0 {
            return Err(ParseError::NonzeroReserved);
        }
        KEX_V1_LEGACY_IMAGE_SPAN_BYTES
    } else {
        u64::from(declared_span_pages)
            .checked_mul(PAGE_SIZE)
            .ok_or(ParseError::ArithmeticOverflow)?
    };
    if image_span_bytes == 0
        || image_span_bytes > limits.maximum_image_span_bytes
        || !image_span_bytes.is_multiple_of(KEX_V1_IMAGE_ALIGNMENT)
    {
        return Err(ParseError::InvalidImageSpan);
    }
    Ok(image_span_bytes)
}

pub(crate) fn parse_header_with_len(
    artifact_prefix: &[u8],
    artifact_len: usize,
    expected_target: Target,
    supported_abi_minor: u16,
    limits: ApplicationLimits,
) -> Result<ParsedHeader, ParseError> {
    let header = artifact_prefix
        .get(..KEX_V1_HEADER_BYTES)
        .ok_or(ParseError::TruncatedHeader)?;
    if header.get(..KEX_V1_MAGIC.len()) != Some(KEX_V1_MAGIC.as_slice()) {
        return Err(ParseError::InvalidMagic);
    }
    if read_u16(header, HEADER_CONTAINER_MAJOR)? != CONTAINER_MAJOR
        || read_u16(header, HEADER_CONTAINER_MINOR)? != CONTAINER_MINOR
    {
        return Err(ParseError::UnsupportedContainerVersion);
    }
    let target =
        Target::from_raw(read_u16(header, HEADER_TARGET)?).ok_or(ParseError::WrongTarget)?;
    if target != expected_target {
        return Err(ParseError::WrongTarget);
    }
    if usize::from(read_u16(header, HEADER_BYTES)?) != KEX_V1_HEADER_BYTES
        || usize::from(read_u16(header, HEADER_RECORD_BYTES)?) != KEX_V1_LOAD_RECORD_BYTES
    {
        return Err(ParseError::InvalidLayout);
    }
    let abi_major = read_u16(header, HEADER_ABI_MAJOR)?;
    let abi_minor = read_u16(header, HEADER_ABI_MINOR)?;
    if abi_major != ABI_MAJOR || abi_minor > supported_abi_minor {
        return Err(ParseError::UnsupportedAbi);
    }
    if read_u16(header, HEADER_FLAGS)? != 0
        || read_u16(header, HEADER_RESERVED16)? != 0
        || read_u16(header, HEADER_RESERVED_RELOCATION16)? != 0
        || read_u32(header, HEADER_RESERVED_RELOCATION32)? != 0
    {
        return Err(ParseError::NonzeroReserved);
    }
    let image_span_bytes = parse_image_span(header, abi_minor, limits)?;
    let declared_bytes = usize::try_from(read_u64(header, HEADER_ARTIFACT_BYTES)?)
        .map_err(|_| ParseError::ArithmeticOverflow)?;
    if declared_bytes != artifact_len {
        return Err(ParseError::LengthMismatch);
    }

    let record_count = usize::from(read_u16(header, HEADER_RECORD_COUNT)?);
    if record_count == 0 || record_count > limits.load_records || record_count > MAX_LOAD_RECORDS {
        return Err(ParseError::InvalidRecordCount);
    }
    let records_offset = usize::try_from(read_u32(header, HEADER_RECORDS_OFFSET)?)
        .map_err(|_| ParseError::ArithmeticOverflow)?;
    let payload_offset = usize::try_from(read_u32(header, HEADER_PAYLOAD_OFFSET)?)
        .map_err(|_| ParseError::ArithmeticOverflow)?;
    let relocations_offset = usize::try_from(read_u32(header, HEADER_RELOCATIONS_OFFSET)?)
        .map_err(|_| ParseError::ArithmeticOverflow)?;
    let relocation_count = usize::try_from(read_u32(header, HEADER_RELOCATION_COUNT)?)
        .map_err(|_| ParseError::ArithmeticOverflow)?;
    if usize::from(read_u16(header, HEADER_RELOCATION_BYTES)?) != KEX_V1_RELOCATION_RECORD_BYTES {
        return Err(ParseError::InvalidLayout);
    }
    let records_bytes = record_count
        .checked_mul(KEX_V1_LOAD_RECORD_BYTES)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let records_end = records_offset
        .checked_add(records_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let relocation_table_bytes = relocation_count
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let relocations_end = relocations_offset
        .checked_add(relocation_table_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    if records_offset != KEX_V1_HEADER_BYTES
        || relocations_offset != records_end
        || payload_offset != relocations_end
        || payload_offset > artifact_len
    {
        return Err(ParseError::InvalidLayout);
    }

    let entry_offset = read_u64(header, HEADER_ENTRY_OFFSET)?;
    let stack_pages = read_u64(header, HEADER_STACK_PAGES)?;
    let heap_pages = read_u64(header, HEADER_HEAP_PAGES)?;
    if stack_pages < limits.minimum_stack_pages || stack_pages > limits.maximum_stack_pages {
        return Err(ParseError::StackBudgetExceeded);
    }
    if heap_pages > limits.heap_pages {
        return Err(ParseError::HeapBudgetExceeded);
    }

    Ok(ParsedHeader {
        target,
        abi_minor,
        image_span_bytes,
        entry_offset,
        record_count,
        records_offset,
        payload_offset,
        stack_pages,
        heap_pages,
        relocations_offset,
        relocation_count,
    })
}

struct ParsedSegments<'artifact> {
    segments: [Option<LoadSegment<'artifact>>; MAX_LOAD_RECORDS],
    image_pages: u64,
}

fn parse_relocations<'artifact>(
    artifact: &'artifact [u8],
    header: ParsedHeader,
    parsed: &ParsedSegments<'artifact>,
) -> Result<&'artifact [u8], ParseError> {
    let byte_count = header
        .relocation_count
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let end = header
        .relocations_offset
        .checked_add(byte_count)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let records = artifact
        .get(header.relocations_offset..end)
        .ok_or(ParseError::InvalidLayout)?;
    let image_end = parsed
        .segments
        .iter()
        .flatten()
        .try_fold(0_u64, |end, segment| {
            segment
                .image_offset
                .checked_add(segment.memory_bytes)
                .map(|segment_end| end.max(segment_end))
        })
        .ok_or(ParseError::ArithmeticOverflow)?;
    let mut previous_target = None;
    for record in records.chunks_exact(KEX_V1_RELOCATION_RECORD_BYTES) {
        let target_offset = read_u64(record, RELOCATION_TARGET_OFFSET)?;
        let value_offset = read_u64(record, RELOCATION_VALUE_OFFSET)?;
        let target_end = target_offset
            .checked_add(8)
            .ok_or(ParseError::InvalidRelocation)?;
        if previous_target.is_some_and(|previous| target_offset <= previous)
            || value_offset >= image_end
            || !parsed.segments.iter().flatten().any(|segment| {
                let segment_end = segment.image_offset.checked_add(segment.memory_bytes);
                segment.image_offset <= target_offset
                    && segment_end.is_some_and(|end| target_end <= end)
            })
        {
            return Err(ParseError::InvalidRelocation);
        }
        previous_target = Some(target_offset);
    }
    Ok(records)
}

fn parse_segments(
    artifact: &[u8],
    header: ParsedHeader,
    image_base: u64,
) -> Result<ParsedSegments<'_>, ParseError> {
    let mut segments = [None; MAX_LOAD_RECORDS];
    let mut expected_file_offset = header.payload_offset;
    let mut previous_image_end = 0_u64;
    let mut image_pages = 0_u64;
    let mut executable = false;
    let mut entry_is_executable = false;

    for (index, destination) in segments[..header.record_count].iter_mut().enumerate() {
        let record_start = header
            .records_offset
            .checked_add(
                index
                    .checked_mul(KEX_V1_LOAD_RECORD_BYTES)
                    .ok_or(ParseError::ArithmeticOverflow)?,
            )
            .ok_or(ParseError::ArithmeticOverflow)?;
        let current_record_end = record_start
            .checked_add(KEX_V1_LOAD_RECORD_BYTES)
            .ok_or(ParseError::ArithmeticOverflow)?;
        let record = artifact
            .get(record_start..current_record_end)
            .ok_or(ParseError::InvalidLayout)?;
        let parsed = parse_record(
            artifact,
            record,
            expected_file_offset,
            previous_image_end,
            index != 0,
            header.image_span_bytes,
            image_base,
        )?;
        previous_image_end = parsed.image_end;
        expected_file_offset = parsed.file_end;

        image_pages = image_pages
            .checked_add(parsed.segment.memory_bytes / PAGE_SIZE)
            .ok_or(ParseError::ArithmeticOverflow)?;
        if parsed.segment.permissions.executable() {
            executable = true;
            let entry_end = header
                .entry_offset
                .checked_add(1)
                .ok_or(ParseError::ArithmeticOverflow)?;
            entry_is_executable |=
                header.entry_offset >= parsed.segment.image_offset && entry_end <= parsed.image_end;
        }
        *destination = Some(parsed.segment);
    }

    if expected_file_offset != artifact.len() {
        return Err(ParseError::NoncanonicalPayload);
    }
    if !executable {
        return Err(ParseError::MissingExecutableSegment);
    }
    if !entry_is_executable {
        return Err(ParseError::InvalidEntryPoint);
    }
    // Artifacts that declare their own span must declare the exact one. ABI
    // 1.0 and 1.1 artifacts have a fixed implied span and are held only to the
    // segment bound already checked above.
    if header.abi_minor >= KEX_V1_DECLARED_SPAN_ABI_MINOR
        && canonical_image_span_bytes(previous_image_end) != Some(header.image_span_bytes)
    {
        return Err(ParseError::InvalidImageSpan);
    }

    Ok(ParsedSegments {
        segments,
        image_pages,
    })
}

struct ParsedRecord<'artifact> {
    segment: LoadSegment<'artifact>,
    image_end: u64,
    file_end: usize,
}

fn parse_record<'artifact>(
    artifact: &'artifact [u8],
    record: &[u8],
    expected_file_offset: usize,
    previous_image_end: u64,
    has_predecessor: bool,
    image_span_bytes: u64,
    image_base: u64,
) -> Result<ParsedRecord<'artifact>, ParseError> {
    let image_offset = read_u64(record, RECORD_IMAGE_OFFSET)?;
    let file_offset = usize::try_from(read_u64(record, RECORD_FILE_OFFSET)?)
        .map_err(|_| ParseError::ArithmeticOverflow)?;
    let file_byte_count = read_u64(record, RECORD_FILE_BYTES)?;
    let file_bytes =
        usize::try_from(file_byte_count).map_err(|_| ParseError::ArithmeticOverflow)?;
    let memory_bytes = read_u64(record, RECORD_MEMORY_BYTES)?;
    let permissions = SegmentPermissions::from_raw(read_u32(record, RECORD_PERMISSIONS)?)
        .ok_or(ParseError::InvalidPermissions)?;
    if read_u32(record, RECORD_RESERVED)? != 0 {
        return Err(ParseError::NonzeroReserved);
    }
    if memory_bytes == 0
        || !image_offset.is_multiple_of(PAGE_SIZE)
        || !memory_bytes.is_multiple_of(PAGE_SIZE)
        || file_byte_count > memory_bytes
    {
        return Err(ParseError::InvalidSegmentRange);
    }
    let image_end = image_offset
        .checked_add(memory_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    image_base
        .checked_add(image_end)
        .ok_or(ParseError::ArithmeticOverflow)?;
    if has_predecessor && image_offset < previous_image_end {
        return Err(ParseError::OverlappingSegments);
    }
    if image_end > image_span_bytes {
        return Err(ParseError::ImageSpanExceeded);
    }
    if file_offset != expected_file_offset {
        return Err(ParseError::NoncanonicalPayload);
    }
    let file_end = file_offset
        .checked_add(file_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let payload = artifact
        .get(file_offset..file_end)
        .ok_or(ParseError::NoncanonicalPayload)?;

    Ok(ParsedRecord {
        segment: LoadSegment {
            image_base,
            image_offset,
            memory_bytes,
            file_offset: u64::try_from(file_offset).map_err(|_| ParseError::ArithmeticOverflow)?,
            file_byte_count,
            permissions,
            file_bytes: payload,
        },
        image_end,
        file_end,
    })
}

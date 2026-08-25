//! Bounded parser and load-plan policy for KEX application artifacts.
#![no_std]
#![forbid(unsafe_code)]

use core::fmt;

/// KEX v1 base page size in bytes.
pub const PAGE_SIZE: u64 = 4096;
/// KEX v1 base page size as a host slice length.
pub const PAGE_BYTES: usize = 4096;
/// Fixed virtual base of every separately isolated KEX v1 image.
pub const KEX_V1_IMAGE_BASE: u64 = 0x0000_4000_0000_0000;
/// Exclusive upper bound of the application half of the initial 48-bit roots.
pub const KEX_V1_USER_END: u64 = 0x0000_8000_0000_0000;
/// KEX v1 header length in bytes.
pub const KEX_V1_HEADER_BYTES: usize = 64;
/// KEX v1 load-record length in bytes.
pub const KEX_V1_LOAD_RECORD_BYTES: usize = 40;
/// Product-name-independent KEX v1 format identifier.
pub const KEX_V1_MAGIC: [u8; 8] = *b"KEX\0FMT\0";
/// Maximum load records accepted by the standard application policy.
pub const MAX_LOAD_RECORDS: usize = 16;
/// Application ABI major implemented by this parser.
pub const ABI_MAJOR: u16 = 1;
/// First application ABI minor implemented by this parser.
pub const ABI_MINOR: u16 = 0;

const CONTAINER_MAJOR: u16 = 1;
const CONTAINER_MINOR: u16 = 0;
const STARTUP_PAGES: u64 = 1;
const STARTUP_FIXED_BYTES: usize = 64;
const STARTUP_HANDLE_BYTES: usize = 24;

const HEADER_CONTAINER_MAJOR: usize = 8;
const HEADER_CONTAINER_MINOR: usize = 10;
const HEADER_TARGET: usize = 12;
const HEADER_BYTES: usize = 14;
const HEADER_RECORD_BYTES: usize = 16;
const HEADER_ABI_MAJOR: usize = 18;
const HEADER_ABI_MINOR: usize = 20;
const HEADER_FLAGS: usize = 22;
const HEADER_ENTRY_OFFSET: usize = 24;
const HEADER_RECORD_COUNT: usize = 32;
const HEADER_RESERVED16: usize = 34;
const HEADER_STACK_PAGES: usize = 36;
const HEADER_HEAP_PAGES: usize = 40;
const HEADER_RECORDS_OFFSET: usize = 44;
const HEADER_PAYLOAD_OFFSET: usize = 48;
const HEADER_RESERVED32: usize = 52;
const HEADER_ARTIFACT_BYTES: usize = 56;

const RECORD_IMAGE_OFFSET: usize = 0;
const RECORD_FILE_OFFSET: usize = 8;
const RECORD_FILE_BYTES: usize = 16;
const RECORD_MEMORY_BYTES: usize = 24;
const RECORD_PERMISSIONS: usize = 32;
const RECORD_RESERVED: usize = 36;

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

impl SegmentPermissions {
    const fn from_raw(raw: u32) -> Option<Self> {
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

/// Absolute application limits enforced by the standard policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLimits {
    encoded_bytes: usize,
    load_records: usize,
    image_span_bytes: u64,
    image_pages: u64,
    minimum_stack_pages: u64,
    maximum_stack_pages: u64,
    heap_pages: u64,
    table_pages: u64,
    resident_pages: u64,
    initial_handles: u16,
}

impl ApplicationLimits {
    const STANDARD: Self = Self {
        encoded_bytes: 16 * 1024 * 1024,
        load_records: 16,
        image_span_bytes: 128 * 1024 * 1024,
        image_pages: 8192,
        minimum_stack_pages: 4,
        maximum_stack_pages: 256,
        heap_pages: 4096,
        table_pages: 512,
        resident_pages: 16_384,
        initial_handles: 32,
    };

    /// Limits fixed by the standard application policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self::STANDARD
    }

    /// Maximum encoded artifact bytes staged by the kernel.
    #[must_use]
    pub const fn encoded_bytes(self) -> usize {
        self.encoded_bytes
    }

    /// Maximum load records.
    #[must_use]
    pub const fn load_records(self) -> usize {
        self.load_records
    }

    /// Maximum image-relative end address.
    #[must_use]
    pub const fn image_span_bytes(self) -> u64 {
        self.image_span_bytes
    }

    /// Maximum mapped image pages.
    #[must_use]
    pub const fn image_pages(self) -> u64 {
        self.image_pages
    }

    /// Inclusive permitted stack-page range.
    #[must_use]
    pub const fn stack_pages(self) -> (u64, u64) {
        (self.minimum_stack_pages, self.maximum_stack_pages)
    }

    /// Maximum initially mapped heap pages.
    #[must_use]
    pub const fn heap_pages(self) -> u64 {
        self.heap_pages
    }

    /// Maximum application page-table pages.
    #[must_use]
    pub const fn table_pages(self) -> u64 {
        self.table_pages
    }

    /// Maximum total resident pages including page tables.
    #[must_use]
    pub const fn resident_pages(self) -> u64 {
        self.resident_pages
    }

    /// Maximum initially granted handles.
    #[must_use]
    pub const fn initial_handles(self) -> u16 {
        self.initial_handles
    }
}

/// One validated KEX load segment borrowing its staged payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment<'artifact> {
    image_offset: u64,
    memory_bytes: u64,
    file_byte_count: u64,
    permissions: SegmentPermissions,
    file_bytes: &'artifact [u8],
}

impl<'artifact> LoadSegment<'artifact> {
    /// Image-relative first byte.
    #[must_use]
    pub const fn image_offset(self) -> u64 {
        self.image_offset
    }

    /// Absolute first virtual byte at the fixed KEX v1 base.
    #[must_use]
    pub const fn virtual_address(self) -> u64 {
        KEX_V1_IMAGE_BASE + self.image_offset
    }

    /// Mapped bytes, including the zero-filled suffix.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    /// Bytes copied from the staged artifact.
    #[must_use]
    pub const fn file_bytes(self) -> &'artifact [u8] {
        self.file_bytes
    }

    /// Validated closed permission value.
    #[must_use]
    pub const fn permissions(self) -> SegmentPermissions {
        self.permissions
    }

    /// Bytes zero-filled after the file payload.
    #[must_use]
    pub const fn zero_fill_bytes(self) -> u64 {
        self.memory_bytes - self.file_byte_count
    }
}

/// Exact and conservative page charges derived before native table building.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadCharges {
    staging_bytes: usize,
    image_pages: u64,
    stack_pages: u64,
    heap_pages: u64,
    private_pages: u64,
    reserved_resident_pages: u64,
}

/// Canonical KEX v1 virtual placement outside the standard image window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLayout {
    startup_address: u64,
    heap_address: u64,
    heap_bytes: u64,
    stack_bottom: u64,
    stack_top: u64,
    lower_guard_address: u64,
    upper_guard_address: u64,
}

impl ApplicationLayout {
    /// Address of the immutable one-page ABI startup record.
    #[must_use]
    pub const fn startup_address(self) -> u64 {
        self.startup_address
    }

    /// First byte of the application's fixed zeroed heap.
    #[must_use]
    pub const fn heap_address(self) -> u64 {
        self.heap_address
    }

    /// Number of initially mapped heap bytes.
    #[must_use]
    pub const fn heap_bytes(self) -> u64 {
        self.heap_bytes
    }

    /// First mapped byte of the initial stack.
    #[must_use]
    pub const fn stack_bottom(self) -> u64 {
        self.stack_bottom
    }

    /// Exclusive, 16-byte-aligned initial stack pointer.
    #[must_use]
    pub const fn stack_top(self) -> u64 {
        self.stack_top
    }

    /// Page immediately below the standard reserved stack slot.
    #[must_use]
    pub const fn lower_guard_address(self) -> u64 {
        self.lower_guard_address
    }

    /// Page immediately above the mapped initial stack.
    #[must_use]
    pub const fn upper_guard_address(self) -> u64 {
        self.upper_guard_address
    }
}

/// One explicit initial authority descriptor encoded into the startup page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialHandle {
    /// Opaque generation-checked handle value.
    pub value: u64,
    /// ABI-defined rights bits.
    pub rights: u32,
    /// ABI-defined service interface identifier.
    pub interface: u32,
    /// Required interface major version.
    pub major: u16,
    /// Required interface minor version.
    pub minor: u16,
}

/// Values placed in the immutable ABI 1.0 startup page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupInfo<'handles> {
    /// Monotonic nonzero task identity selected by the kernel.
    pub task_id: u64,
    /// Initial handles after loader-policy and launcher-authority intersection.
    pub handles: &'handles [InitialHandle],
}

/// Failure to encode a canonical ABI startup page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupPageError {
    /// The task identity is the reserved zero value.
    InvalidTaskId,
    /// More initial handles were supplied than the standard policy permits.
    TooManyHandles,
    /// A descriptor used the reserved zero opaque-handle value.
    InvalidHandle,
    /// Two descriptors expose the same opaque handle value.
    DuplicateHandle,
}

/// One provisional resource class acquired by the native loader transaction.
///
/// The order is part of the loader contract: bounded staging precedes frames,
/// inactive tables, the scheduler task record, and the initial handle owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LoaderResource {
    /// Kernel-owned copy of the encoded KEX artifact.
    Staging = 0,
    /// Zeroable private-frame allocation, including the table reservation.
    Frames = 1,
    /// Constructed but not yet active application page-table root.
    Tables = 2,
    /// Provisional scheduler task and its resource accounting record.
    Task = 3,
    /// Initial owner-scoped handle set.
    Handles = 4,
}

impl LoaderResource {
    const ALL: [Self; 5] = [
        Self::Staging,
        Self::Frames,
        Self::Tables,
        Self::Task,
        Self::Handles,
    ];

    const REVERSE: [Self; 5] = [
        Self::Handles,
        Self::Task,
        Self::Tables,
        Self::Frames,
        Self::Staging,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// Invalid transition in the provisional native loader transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderTransactionError {
    /// A resource was recorded other than in the fixed acquisition order.
    OutOfOrder,
    /// Commit was attempted before every provisional resource was acquired.
    Incomplete,
    /// A transition was attempted after the transaction committed.
    AlreadyCommitted,
}

/// Allocation-free ownership ledger for the native loader's pre-entry phase.
///
/// Native code performs each real acquisition, then records it here. Before
/// commit, rollback visits every recorded resource in strict reverse order.
/// Commit is possible only after the complete staging/frame/table/task/handle
/// sequence, and is the sole transition that marks the root eligible for
/// activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoaderTransaction {
    owned: u8,
    next: u8,
    committed: bool,
}

impl LoaderTransaction {
    const ALL_OWNED: u8 = (1 << LoaderResource::ALL.len()) - 1;

    /// Begin an empty transaction whose application root is inactive.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owned: 0,
            next: 0,
            committed: false,
        }
    }

    /// Record one successfully acquired provisional resource.
    ///
    /// # Errors
    ///
    /// Returns an error after commit or when `resource` is not the next member
    /// of the fixed acquisition sequence.
    pub fn acquire(&mut self, resource: LoaderResource) -> Result<(), LoaderTransactionError> {
        if self.committed {
            return Err(LoaderTransactionError::AlreadyCommitted);
        }
        if usize::from(self.next) >= LoaderResource::ALL.len()
            || LoaderResource::ALL[usize::from(self.next)] != resource
        {
            return Err(LoaderTransactionError::OutOfOrder);
        }
        self.owned |= resource.bit();
        self.next += 1;
        Ok(())
    }

    /// Release every provisional resource in reverse acquisition order.
    ///
    /// The callback performs or observes the concrete cleanup. This method
    /// clears a bit only after its callback returns, making exhaustive hosted
    /// failpoint tests use the same state machine as native loading.
    pub fn rollback(&mut self, mut release: impl FnMut(LoaderResource)) {
        if self.committed {
            return;
        }
        for resource in LoaderResource::REVERSE {
            if self.owned & resource.bit() != 0 {
                release(resource);
                self.owned &= !resource.bit();
            }
        }
        self.next = 0;
    }

    /// Transfer all provisional resources to the runnable task atomically.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction already committed or if any
    /// acquisition phase is missing.
    pub fn commit(&mut self) -> Result<(), LoaderTransactionError> {
        if self.committed {
            return Err(LoaderTransactionError::AlreadyCommitted);
        }
        if self.owned != Self::ALL_OWNED {
            return Err(LoaderTransactionError::Incomplete);
        }
        self.owned = 0;
        self.committed = true;
        Ok(())
    }

    /// Number of provisional resource classes still retained by this ledger.
    #[must_use]
    pub const fn provisional_resources(self) -> u32 {
        self.owned.count_ones()
    }

    /// Whether commit has made the constructed root eligible for activation.
    #[must_use]
    pub const fn mapping_active(self) -> bool {
        self.committed
    }
}

impl Default for LoaderTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadCharges {
    /// Exact staged artifact bytes.
    #[must_use]
    pub const fn staging_bytes(self) -> usize {
        self.staging_bytes
    }

    /// Exact mapped segment pages.
    #[must_use]
    pub const fn image_pages(self) -> u64 {
        self.image_pages
    }

    /// Exact guarded-stack payload pages.
    #[must_use]
    pub const fn stack_pages(self) -> u64 {
        self.stack_pages
    }

    /// Exact zeroed application-heap pages.
    #[must_use]
    pub const fn heap_pages(self) -> u64 {
        self.heap_pages
    }

    /// Exact image, startup, heap, and stack pages.
    #[must_use]
    pub const fn private_pages(self) -> u64 {
        self.private_pages
    }

    /// Conservative reservation including the standard table-page ceiling.
    #[must_use]
    pub const fn reserved_resident_pages(self) -> u64 {
        self.reserved_resident_pages
    }
}

/// Fully validated, allocation-free KEX load plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadPlan<'artifact> {
    target: Target,
    abi_minor: u16,
    entry_offset: u64,
    stack_pages: u64,
    heap_pages: u64,
    segments: [Option<LoadSegment<'artifact>>; MAX_LOAD_RECORDS],
    segment_count: usize,
    charges: LoadCharges,
    layout: ApplicationLayout,
}

impl<'artifact> LoadPlan<'artifact> {
    /// Artifact target.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// Minimum ABI minor required by the artifact.
    #[must_use]
    pub const fn abi_minor(&self) -> u16 {
        self.abi_minor
    }

    /// Fixed virtual entry address.
    #[must_use]
    pub const fn entry_address(&self) -> u64 {
        KEX_V1_IMAGE_BASE + self.entry_offset
    }

    /// Requested initial stack pages.
    #[must_use]
    pub const fn stack_pages(&self) -> u64 {
        self.stack_pages
    }

    /// Requested initial zeroed heap pages.
    #[must_use]
    pub const fn heap_pages(&self) -> u64 {
        self.heap_pages
    }

    /// Ordered validated load segments.
    pub fn segments(&self) -> impl Iterator<Item = LoadSegment<'artifact>> + '_ {
        self.segments[..self.segment_count]
            .iter()
            .flatten()
            .copied()
    }

    /// Preliminary staging and page charges.
    #[must_use]
    pub const fn charges(&self) -> LoadCharges {
        self.charges
    }

    /// Canonical startup, heap, guard, and stack virtual placement.
    #[must_use]
    pub const fn layout(&self) -> ApplicationLayout {
        self.layout
    }

    /// Encode the immutable ABI 1.0 startup page into a zeroed base page.
    ///
    /// # Errors
    ///
    /// Rejects a zero task identity, too many initial handles, or duplicate
    /// opaque values before modifying the destination.
    pub fn encode_startup_page(
        &self,
        info: StartupInfo<'_>,
        destination: &mut [u8; PAGE_BYTES],
    ) -> Result<(), StartupPageError> {
        if info.task_id == 0 {
            return Err(StartupPageError::InvalidTaskId);
        }
        let limits = ApplicationLimits::standard();
        if info.handles.len() > usize::from(limits.initial_handles) {
            return Err(StartupPageError::TooManyHandles);
        }
        for (index, handle) in info.handles.iter().enumerate() {
            if handle.value == 0 {
                return Err(StartupPageError::InvalidHandle);
            }
            if info.handles[..index]
                .iter()
                .any(|existing| existing.value == handle.value)
            {
                return Err(StartupPageError::DuplicateHandle);
            }
        }

        destination.fill(0);
        let encoded_bytes = STARTUP_FIXED_BYTES + info.handles.len() * STARTUP_HANDLE_BYTES;
        let encoded_bytes =
            u32::try_from(encoded_bytes).map_err(|_| StartupPageError::TooManyHandles)?;
        let handle_count =
            u16::try_from(info.handles.len()).map_err(|_| StartupPageError::TooManyHandles)?;
        write_u32(destination, 0, encoded_bytes);
        write_u16(destination, 4, ABI_MAJOR);
        write_u16(destination, 6, ABI_MINOR);
        write_u32(destination, 8, 4096);
        write_u16(destination, 12, 0);
        write_u16(destination, 14, handle_count);
        write_u64(destination, 16, KEX_V1_IMAGE_BASE);
        write_u64(destination, 24, self.layout.heap_address);
        write_u64(destination, 32, self.layout.heap_bytes);
        write_u64(destination, 40, self.layout.stack_bottom);
        write_u64(destination, 48, self.layout.stack_top);
        write_u64(destination, 56, info.task_id);
        for (index, handle) in info.handles.iter().enumerate() {
            let offset = STARTUP_FIXED_BYTES + index * STARTUP_HANDLE_BYTES;
            write_u64(destination, offset, handle.value);
            write_u32(destination, offset + 8, handle.rights);
            write_u32(destination, offset + 12, handle.interface);
            write_u16(destination, offset + 16, handle.major);
            write_u16(destination, offset + 18, handle.minor);
        }
        Ok(())
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
    /// The image-relative address span exceeds the standard policy.
    ImageSpanExceeded,
    /// Mapped image pages exceed the standard policy.
    ImagePagesExceeded,
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
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArtifactTooLarge => "KEX artifact exceeds the staging budget",
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
            Self::ImageSpanExceeded => "KEX image span exceeds the standard policy",
            Self::ImagePagesExceeded => "KEX image pages exceed the standard policy",
            Self::StackBudgetExceeded => "KEX stack request exceeds the standard policy",
            Self::HeapBudgetExceeded => "KEX heap request exceeds the standard policy",
            Self::ResidentBudgetExceeded => "KEX resident-page charge exceeds the standard policy",
            Self::MissingExecutableSegment => "KEX has no executable segment",
            Self::InvalidEntryPoint => "KEX entry point is not executable",
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
    )
}

fn parse_with_limits(
    artifact: &[u8],
    expected_target: Target,
    supported_abi_minor: u16,
    limits: ApplicationLimits,
) -> Result<LoadPlan<'_>, ParseError> {
    if artifact.len() > limits.encoded_bytes {
        return Err(ParseError::ArtifactTooLarge);
    }
    let header = parse_header(artifact, expected_target, supported_abi_minor, limits)?;
    let parsed = parse_segments(artifact, header, limits)?;
    let private_pages = parsed
        .image_pages
        .checked_add(header.stack_pages)
        .and_then(|pages| pages.checked_add(header.heap_pages))
        .and_then(|pages| pages.checked_add(STARTUP_PAGES))
        .ok_or(ParseError::ArithmeticOverflow)?;
    let reserved_resident_pages = private_pages
        .checked_add(limits.table_pages)
        .ok_or(ParseError::ArithmeticOverflow)?;
    if reserved_resident_pages > limits.resident_pages {
        return Err(ParseError::ResidentBudgetExceeded);
    }
    let layout = application_layout(header.stack_pages, header.heap_pages, limits)?;

    Ok(LoadPlan {
        target: header.target,
        abi_minor: header.abi_minor,
        entry_offset: header.entry_offset,
        stack_pages: header.stack_pages,
        heap_pages: header.heap_pages,
        segments: parsed.segments,
        segment_count: header.record_count,
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

fn application_layout(
    stack_pages: u64,
    heap_pages: u64,
    limits: ApplicationLimits,
) -> Result<ApplicationLayout, ParseError> {
    let startup_address = KEX_V1_IMAGE_BASE
        .checked_add(limits.image_span_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let heap_address = startup_address
        .checked_add(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let heap_bytes = heap_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let heap_slot_bytes = limits
        .heap_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let lower_guard_address = heap_address
        .checked_add(heap_slot_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let stack_slot_address = lower_guard_address
        .checked_add(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let stack_slot_bytes = limits
        .maximum_stack_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let upper_guard_address = stack_slot_address
        .checked_add(stack_slot_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let stack_bytes = stack_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let stack_bottom = upper_guard_address
        .checked_sub(stack_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let user_end = upper_guard_address
        .checked_add(PAGE_SIZE)
        .ok_or(ParseError::ArithmeticOverflow)?;
    if user_end > KEX_V1_USER_END {
        return Err(ParseError::ArithmeticOverflow);
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
struct ParsedHeader {
    target: Target,
    abi_minor: u16,
    entry_offset: u64,
    record_count: usize,
    records_offset: usize,
    payload_offset: usize,
    stack_pages: u64,
    heap_pages: u64,
}

fn parse_header(
    artifact: &[u8],
    expected_target: Target,
    supported_abi_minor: u16,
    limits: ApplicationLimits,
) -> Result<ParsedHeader, ParseError> {
    let header = artifact
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
        || read_u32(header, HEADER_RESERVED32)? != 0
    {
        return Err(ParseError::NonzeroReserved);
    }
    let declared_bytes = usize::try_from(read_u64(header, HEADER_ARTIFACT_BYTES)?)
        .map_err(|_| ParseError::ArithmeticOverflow)?;
    if declared_bytes != artifact.len() {
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
    let records_bytes = record_count
        .checked_mul(KEX_V1_LOAD_RECORD_BYTES)
        .ok_or(ParseError::ArithmeticOverflow)?;
    let records_end = records_offset
        .checked_add(records_bytes)
        .ok_or(ParseError::ArithmeticOverflow)?;
    if records_offset != KEX_V1_HEADER_BYTES
        || payload_offset != records_end
        || payload_offset > artifact.len()
    {
        return Err(ParseError::InvalidLayout);
    }

    let entry_offset = read_u64(header, HEADER_ENTRY_OFFSET)?;
    let stack_pages = u64::from(read_u32(header, HEADER_STACK_PAGES)?);
    let heap_pages = u64::from(read_u32(header, HEADER_HEAP_PAGES)?);
    if stack_pages < limits.minimum_stack_pages || stack_pages > limits.maximum_stack_pages {
        return Err(ParseError::StackBudgetExceeded);
    }
    if heap_pages > limits.heap_pages {
        return Err(ParseError::HeapBudgetExceeded);
    }

    Ok(ParsedHeader {
        target,
        abi_minor,
        entry_offset,
        record_count,
        records_offset,
        payload_offset,
        stack_pages,
        heap_pages,
    })
}

struct ParsedSegments<'artifact> {
    segments: [Option<LoadSegment<'artifact>>; MAX_LOAD_RECORDS],
    image_pages: u64,
}

fn parse_segments(
    artifact: &[u8],
    header: ParsedHeader,
    limits: ApplicationLimits,
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
            limits,
        )?;
        previous_image_end = parsed.image_end;
        expected_file_offset = parsed.file_end;

        image_pages = image_pages
            .checked_add(parsed.segment.memory_bytes / PAGE_SIZE)
            .ok_or(ParseError::ArithmeticOverflow)?;
        if image_pages > limits.image_pages {
            return Err(ParseError::ImagePagesExceeded);
        }
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
    limits: ApplicationLimits,
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
    KEX_V1_IMAGE_BASE
        .checked_add(image_end)
        .ok_or(ParseError::ArithmeticOverflow)?;
    if has_predecessor && image_offset < previous_image_end {
        return Err(ParseError::OverlappingSegments);
    }
    if image_end > limits.image_span_bytes {
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
            image_offset,
            memory_bytes,
            file_byte_count,
            permissions,
            file_bytes: payload,
        },
        image_end,
        file_end,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ParseError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ParseError::ArithmeticOverflow)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ParseError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ParseError::ArithmeticOverflow)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ParseError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(ParseError::ArithmeticOverflow)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    #[derive(Clone, Copy)]
    struct TestSegment<'bytes> {
        image_offset: u64,
        memory_bytes: u64,
        permissions: u32,
        payload: &'bytes [u8],
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn usize_u16(value: usize) -> u16 {
        u16::try_from(value).unwrap_or_else(|_| unreachable!())
    }

    fn usize_u32(value: usize) -> u32 {
        u32::try_from(value).unwrap_or_else(|_| unreachable!())
    }

    fn usize_u64(value: usize) -> u64 {
        u64::try_from(value).unwrap_or_else(|_| unreachable!())
    }

    fn artifact(target: Target, segments: &[TestSegment<'_>]) -> Vec<u8> {
        let payload_bytes = segments
            .iter()
            .map(|segment| segment.payload.len())
            .sum::<usize>();
        let payload_offset = KEX_V1_HEADER_BYTES + segments.len() * KEX_V1_LOAD_RECORD_BYTES;
        let artifact_bytes = payload_offset + payload_bytes;
        let mut bytes = vec![0_u8; artifact_bytes];
        bytes[..8].copy_from_slice(&KEX_V1_MAGIC);
        put_u16(&mut bytes, HEADER_CONTAINER_MAJOR, CONTAINER_MAJOR);
        put_u16(&mut bytes, HEADER_CONTAINER_MINOR, CONTAINER_MINOR);
        put_u16(&mut bytes, HEADER_TARGET, target as u16);
        put_u16(&mut bytes, HEADER_BYTES, usize_u16(KEX_V1_HEADER_BYTES));
        put_u16(
            &mut bytes,
            HEADER_RECORD_BYTES,
            usize_u16(KEX_V1_LOAD_RECORD_BYTES),
        );
        put_u16(&mut bytes, HEADER_ABI_MAJOR, ABI_MAJOR);
        put_u16(&mut bytes, HEADER_ABI_MINOR, ABI_MINOR);
        put_u64(&mut bytes, HEADER_ENTRY_OFFSET, 0);
        put_u16(&mut bytes, HEADER_RECORD_COUNT, usize_u16(segments.len()));
        put_u32(&mut bytes, HEADER_STACK_PAGES, 4);
        put_u32(&mut bytes, HEADER_HEAP_PAGES, 0);
        put_u32(
            &mut bytes,
            HEADER_RECORDS_OFFSET,
            usize_u32(KEX_V1_HEADER_BYTES),
        );
        put_u32(&mut bytes, HEADER_PAYLOAD_OFFSET, usize_u32(payload_offset));
        put_u64(&mut bytes, HEADER_ARTIFACT_BYTES, usize_u64(artifact_bytes));

        let mut file_offset = payload_offset;
        for (index, segment) in segments.iter().enumerate() {
            let start = KEX_V1_HEADER_BYTES + index * KEX_V1_LOAD_RECORD_BYTES;
            put_u64(
                &mut bytes,
                start + RECORD_IMAGE_OFFSET,
                segment.image_offset,
            );
            put_u64(
                &mut bytes,
                start + RECORD_FILE_OFFSET,
                usize_u64(file_offset),
            );
            put_u64(
                &mut bytes,
                start + RECORD_FILE_BYTES,
                usize_u64(segment.payload.len()),
            );
            put_u64(
                &mut bytes,
                start + RECORD_MEMORY_BYTES,
                segment.memory_bytes,
            );
            put_u32(&mut bytes, start + RECORD_PERMISSIONS, segment.permissions);
            let end = file_offset + segment.payload.len();
            bytes[file_offset..end].copy_from_slice(segment.payload);
            file_offset = end;
        }
        bytes
    }

    fn valid_artifact(target: Target) -> Vec<u8> {
        artifact(
            target,
            &[
                TestSegment {
                    image_offset: 0,
                    memory_bytes: PAGE_SIZE,
                    permissions: SegmentPermissions::ReadExecute as u32,
                    payload: &[0x90, 0xc3],
                },
                TestSegment {
                    image_offset: PAGE_SIZE,
                    memory_bytes: PAGE_SIZE,
                    permissions: SegmentPermissions::ReadWrite as u32,
                    payload: &[1, 2, 3],
                },
            ],
        )
    }

    fn parse_standard(bytes: &[u8], target: Target) -> Result<LoadPlan<'_>, ParseError> {
        parse_kex(bytes, target, ABI_MINOR)
    }

    #[test]
    fn valid_plan_is_ordered_bounded_and_exactly_charged() {
        for target in [Target::X86_64, Target::Aarch64] {
            let bytes = valid_artifact(target);
            let plan = parse_standard(&bytes, target).unwrap_or_else(|_| unreachable!());
            let segments = plan.segments().collect::<Vec<_>>();

            assert_eq!(plan.target(), target);
            assert_eq!(plan.abi_minor(), 0);
            assert_eq!(plan.entry_address(), KEX_V1_IMAGE_BASE);
            assert_eq!(segments.len(), 2);
            assert_eq!(segments[0].file_bytes(), [0x90, 0xc3]);
            assert_eq!(segments[0].zero_fill_bytes(), PAGE_SIZE - 2);
            assert_eq!(segments[1].virtual_address(), KEX_V1_IMAGE_BASE + PAGE_SIZE);
            assert!(segments[0].permissions().executable());
            assert!(segments[1].permissions().writable());
            assert_eq!(plan.charges().staging_bytes(), bytes.len());
            assert_eq!(plan.charges().image_pages(), 2);
            assert_eq!(plan.charges().private_pages(), 7);
            assert_eq!(plan.charges().reserved_resident_pages(), 519);
            let layout = plan.layout();
            assert_eq!(
                layout.startup_address(),
                KEX_V1_IMAGE_BASE + 128 * 1024 * 1024
            );
            assert_eq!(layout.heap_bytes(), 0);
            assert_eq!(layout.stack_top() - layout.stack_bottom(), 4 * PAGE_SIZE);
            assert_eq!(layout.upper_guard_address(), layout.stack_top());
            assert!(layout.lower_guard_address() < layout.stack_bottom());
        }
    }

    #[test]
    fn startup_page_is_canonical_and_rejections_are_atomic() {
        let bytes = valid_artifact(Target::X86_64);
        let plan = parse_standard(&bytes, Target::X86_64).unwrap_or_else(|_| unreachable!());
        let handles = [
            InitialHandle {
                value: 0x1000_0001,
                rights: 1,
                interface: 7,
                major: 1,
                minor: 0,
            },
            InitialHandle {
                value: 0x1000_0002,
                rights: 3,
                interface: 9,
                major: 2,
                minor: 4,
            },
        ];
        let mut page = [0xa5_u8; PAGE_BYTES];
        plan.encode_startup_page(
            StartupInfo {
                task_id: 42,
                handles: &handles,
            },
            &mut page,
        )
        .unwrap_or_else(|_| unreachable!());

        assert_eq!(read_u32(&page, 0), Ok(112));
        assert_eq!(read_u16(&page, 4), Ok(ABI_MAJOR));
        assert_eq!(read_u16(&page, 6), Ok(ABI_MINOR));
        assert_eq!(read_u32(&page, 8), Ok(4096));
        assert_eq!(read_u16(&page, 12), Ok(0));
        assert_eq!(read_u16(&page, 14), Ok(2));
        assert_eq!(read_u64(&page, 16), Ok(KEX_V1_IMAGE_BASE));
        assert_eq!(read_u64(&page, 24), Ok(plan.layout().heap_address()));
        assert_eq!(read_u64(&page, 40), Ok(plan.layout().stack_bottom()));
        assert_eq!(read_u64(&page, 48), Ok(plan.layout().stack_top()));
        assert_eq!(read_u64(&page, 56), Ok(42));
        assert_eq!(read_u64(&page, 64), Ok(handles[0].value));
        assert_eq!(read_u32(&page, 72), Ok(handles[0].rights));
        assert_eq!(read_u64(&page, 88), Ok(handles[1].value));
        assert!(page[112..].iter().all(|byte| *byte == 0));

        let original = [0x5a_u8; PAGE_BYTES];
        let mut rejected = original;
        assert_eq!(
            plan.encode_startup_page(
                StartupInfo {
                    task_id: 0,
                    handles: &[],
                },
                &mut rejected,
            ),
            Err(StartupPageError::InvalidTaskId)
        );
        assert_eq!(rejected, original);

        let zero = [InitialHandle {
            value: 0,
            ..handles[0]
        }];
        assert_eq!(
            plan.encode_startup_page(
                StartupInfo {
                    task_id: 1,
                    handles: &zero,
                },
                &mut rejected,
            ),
            Err(StartupPageError::InvalidHandle)
        );
        assert_eq!(rejected, original);

        let duplicate = [handles[0], handles[0]];
        assert_eq!(
            plan.encode_startup_page(
                StartupInfo {
                    task_id: 1,
                    handles: &duplicate,
                },
                &mut rejected,
            ),
            Err(StartupPageError::DuplicateHandle)
        );
        assert_eq!(rejected, original);

        let too_many = [handles[0]; 33];
        assert_eq!(
            plan.encode_startup_page(
                StartupInfo {
                    task_id: 1,
                    handles: &too_many,
                },
                &mut rejected,
            ),
            Err(StartupPageError::TooManyHandles)
        );
        assert_eq!(rejected, original);
    }

    #[test]
    fn standard_limits_match_adr_0015() {
        let standard = ApplicationLimits::standard();

        assert_eq!(standard.encoded_bytes(), 16 * 1024 * 1024);
        assert_eq!(standard.load_records(), 16);
        assert_eq!(standard.image_span_bytes(), 128 * 1024 * 1024);
        assert_eq!(standard.image_pages(), 8192);
        assert_eq!(standard.stack_pages(), (4, 256));
        assert_eq!(standard.heap_pages(), 4096);
        assert_eq!(standard.table_pages(), 512);
        assert_eq!(standard.resident_pages(), 16_384);
        assert_eq!(standard.initial_handles(), 32);
    }

    #[test]
    fn format_identifier_is_product_name_independent() {
        assert_eq!(KEX_V1_MAGIC, *b"KEX\0FMT\0");
    }

    #[test]
    fn rejects_staging_overflow() {
        let oversized = vec![0_u8; ApplicationLimits::STANDARD.encoded_bytes + 1];
        assert_eq!(
            parse_standard(&oversized, Target::X86_64),
            Err(ParseError::ArtifactTooLarge)
        );
    }

    #[test]
    fn rejects_truncated_magic_version_target_and_abi() {
        assert_eq!(
            parse_standard(&[0_u8; KEX_V1_HEADER_BYTES - 1], Target::X86_64),
            Err(ParseError::TruncatedHeader)
        );
        let valid = valid_artifact(Target::X86_64);
        for (offset, error) in [
            (0, ParseError::InvalidMagic),
            (
                HEADER_CONTAINER_MAJOR,
                ParseError::UnsupportedContainerVersion,
            ),
            (
                HEADER_CONTAINER_MINOR,
                ParseError::UnsupportedContainerVersion,
            ),
            (HEADER_TARGET, ParseError::WrongTarget),
            (HEADER_ABI_MAJOR, ParseError::UnsupportedAbi),
            (HEADER_ABI_MINOR, ParseError::UnsupportedAbi),
        ] {
            let mut bytes = valid.clone();
            bytes[offset] = bytes[offset].wrapping_add(1);
            assert_eq!(parse_standard(&bytes, Target::X86_64), Err(error));
        }
        assert_eq!(
            parse_standard(&valid, Target::Aarch64),
            Err(ParseError::WrongTarget)
        );
    }

    #[test]
    fn rejects_noncanonical_header_and_reserved_fields() {
        let valid = valid_artifact(Target::X86_64);
        for offset in [
            HEADER_BYTES,
            HEADER_RECORD_BYTES,
            HEADER_RECORDS_OFFSET,
            HEADER_PAYLOAD_OFFSET,
        ] {
            let mut bytes = valid.clone();
            bytes[offset] = bytes[offset].wrapping_add(1);
            assert_eq!(
                parse_standard(&bytes, Target::X86_64),
                Err(ParseError::InvalidLayout)
            );
        }
        for offset in [HEADER_FLAGS, HEADER_RESERVED16, HEADER_RESERVED32] {
            let mut bytes = valid.clone();
            bytes[offset] = 1;
            assert_eq!(
                parse_standard(&bytes, Target::X86_64),
                Err(ParseError::NonzeroReserved)
            );
        }
        let mut wrong_length = valid;
        let declared = usize_u64(wrong_length.len()) + 1;
        put_u64(&mut wrong_length, HEADER_ARTIFACT_BYTES, declared);
        assert_eq!(
            parse_standard(&wrong_length, Target::X86_64),
            Err(ParseError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_invalid_record_counts() {
        let mut empty = valid_artifact(Target::X86_64);
        put_u16(&mut empty, HEADER_RECORD_COUNT, 0);
        assert_eq!(
            parse_standard(&empty, Target::X86_64),
            Err(ParseError::InvalidRecordCount)
        );

        let segments = vec![
            TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[1],
            };
            ApplicationLimits::STANDARD.load_records + 1
        ];
        let too_many = artifact(Target::X86_64, &segments);
        assert_eq!(
            parse_standard(&too_many, Target::X86_64),
            Err(ParseError::InvalidRecordCount)
        );
    }

    #[test]
    fn rejects_invalid_permissions_and_segment_geometry() {
        for permissions in [0, 4, u32::MAX] {
            let bytes = artifact(
                Target::X86_64,
                &[TestSegment {
                    image_offset: 0,
                    memory_bytes: PAGE_SIZE,
                    permissions,
                    payload: &[1],
                }],
            );
            assert_eq!(
                parse_standard(&bytes, Target::X86_64),
                Err(ParseError::InvalidPermissions)
            );
        }

        for (image_offset, memory_bytes, payload) in [
            (1, PAGE_SIZE, &[1][..]),
            (0, 0, &[1][..]),
            (0, PAGE_SIZE - 1, &[1][..]),
            (0, PAGE_SIZE, &[0_u8; 4097][..]),
        ] {
            let bytes = artifact(
                Target::X86_64,
                &[TestSegment {
                    image_offset,
                    memory_bytes,
                    permissions: SegmentPermissions::ReadExecute as u32,
                    payload,
                }],
            );
            assert_eq!(
                parse_standard(&bytes, Target::X86_64),
                Err(ParseError::InvalidSegmentRange)
            );
        }
    }

    #[test]
    fn rejects_overlap_sparse_span_and_page_budget() {
        let overlap = artifact(
            Target::X86_64,
            &[
                TestSegment {
                    image_offset: PAGE_SIZE,
                    memory_bytes: PAGE_SIZE,
                    permissions: SegmentPermissions::ReadExecute as u32,
                    payload: &[1],
                },
                TestSegment {
                    image_offset: 0,
                    memory_bytes: PAGE_SIZE,
                    permissions: SegmentPermissions::ReadOnly as u32,
                    payload: &[2],
                },
            ],
        );
        assert_eq!(
            parse_standard(&overlap, Target::X86_64),
            Err(ParseError::OverlappingSegments)
        );

        let sparse = artifact(
            Target::X86_64,
            &[TestSegment {
                image_offset: ApplicationLimits::STANDARD.image_span_bytes,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[1],
            }],
        );
        assert_eq!(
            parse_standard(&sparse, Target::X86_64),
            Err(ParseError::ImageSpanExceeded)
        );

        let too_many_pages = artifact(
            Target::X86_64,
            &[TestSegment {
                image_offset: 0,
                memory_bytes: (ApplicationLimits::STANDARD.image_pages + 1) * PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[1],
            }],
        );
        assert_eq!(
            parse_standard(&too_many_pages, Target::X86_64),
            Err(ParseError::ImagePagesExceeded)
        );

        let mut overflowing = valid_artifact(Target::X86_64);
        put_u64(
            &mut overflowing,
            KEX_V1_HEADER_BYTES + RECORD_IMAGE_OFFSET,
            u64::MAX - (PAGE_SIZE - 1),
        );
        assert_eq!(
            parse_standard(&overflowing, Target::X86_64),
            Err(ParseError::ArithmeticOverflow)
        );
    }

    #[test]
    fn rejects_noncanonical_payload_and_record_reserved_bytes() {
        let valid = valid_artifact(Target::X86_64);
        let first_record = KEX_V1_HEADER_BYTES;

        let mut gap = valid.clone();
        let offset =
            read_u64(&gap[first_record..], RECORD_FILE_OFFSET).unwrap_or_else(|_| unreachable!());
        put_u64(&mut gap, first_record + RECORD_FILE_OFFSET, offset + 1);
        assert_eq!(
            parse_standard(&gap, Target::X86_64),
            Err(ParseError::NoncanonicalPayload)
        );

        let mut trailing = valid.clone();
        trailing.push(0);
        let length = usize_u64(trailing.len());
        put_u64(&mut trailing, HEADER_ARTIFACT_BYTES, length);
        assert_eq!(
            parse_standard(&trailing, Target::X86_64),
            Err(ParseError::NoncanonicalPayload)
        );

        let mut reserved = valid;
        put_u32(&mut reserved, first_record + RECORD_RESERVED, 1);
        assert_eq!(
            parse_standard(&reserved, Target::X86_64),
            Err(ParseError::NonzeroReserved)
        );
    }

    #[test]
    fn rejects_stack_heap_and_aggregate_resident_budgets() {
        let valid = valid_artifact(Target::X86_64);
        for stack_pages in [0, 3, 257] {
            let mut bytes = valid.clone();
            put_u32(&mut bytes, HEADER_STACK_PAGES, stack_pages);
            assert_eq!(
                parse_standard(&bytes, Target::X86_64),
                Err(ParseError::StackBudgetExceeded)
            );
        }
        let mut heap = valid.clone();
        put_u32(&mut heap, HEADER_HEAP_PAGES, 4097);
        assert_eq!(
            parse_standard(&heap, Target::X86_64),
            Err(ParseError::HeapBudgetExceeded)
        );

        let limits = ApplicationLimits {
            resident_pages: 70,
            ..ApplicationLimits::STANDARD
        };
        assert_eq!(
            parse_with_limits(&valid, Target::X86_64, ABI_MINOR, limits,),
            Err(ParseError::ResidentBudgetExceeded)
        );
    }

    #[test]
    fn rejects_missing_executable_and_nonexecuting_entry() {
        let missing = artifact(
            Target::X86_64,
            &[TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadOnly as u32,
                payload: &[1],
            }],
        );
        assert_eq!(
            parse_standard(&missing, Target::X86_64),
            Err(ParseError::MissingExecutableSegment)
        );

        let mut bad_entry = valid_artifact(Target::X86_64);
        put_u64(&mut bad_entry, HEADER_ENTRY_OFFSET, PAGE_SIZE);
        assert_eq!(
            parse_standard(&bad_entry, Target::X86_64),
            Err(ParseError::InvalidEntryPoint)
        );
        put_u64(&mut bad_entry, HEADER_ENTRY_OFFSET, u64::MAX);
        assert_eq!(
            parse_standard(&bad_entry, Target::X86_64),
            Err(ParseError::ArithmeticOverflow)
        );
    }

    #[test]
    fn generated_shared_corpus_covers_both_targets_and_exact_boundaries() {
        let valid = include!("../../../tests/kex-corpus/valid.inc");
        for (name, bytes, target) in valid {
            let parsed = parse_kex(bytes, target, ABI_MINOR);
            assert!(parsed.is_ok(), "{name}: {:?}", parsed.as_ref().err());
            let plan = parsed.unwrap_or_else(|_| unreachable!());
            let limits = ApplicationLimits::standard();
            let segments = plan.segments().collect::<Vec<_>>();
            let image_pages = segments
                .iter()
                .map(|segment| segment.memory_bytes() / PAGE_SIZE)
                .sum::<u64>();
            assert_eq!(plan.charges().staging_bytes(), bytes.len(), "{name}");
            assert_eq!(plan.charges().image_pages(), image_pages, "{name}");
            assert_eq!(
                plan.charges().private_pages(),
                image_pages + 1 + plan.stack_pages() + plan.heap_pages(),
                "{name}"
            );
            assert_eq!(
                plan.charges().reserved_resident_pages(),
                plan.charges().private_pages() + limits.table_pages(),
                "{name}"
            );
            for pair in segments.windows(2) {
                assert!(
                    pair[0].virtual_address() + pair[0].memory_bytes() <= pair[1].virtual_address(),
                    "{name}"
                );
            }
            assert!(segments.iter().all(|segment| {
                !(segment.permissions().writable() && segment.permissions().executable())
            }));
            if name.contains("max-encoded") {
                assert_eq!(bytes.len(), limits.encoded_bytes(), "{name}");
            }
            if name.contains("max-records") {
                assert_eq!(segments.len(), limits.load_records(), "{name}");
            }
            if name.contains("max-span") {
                let last = segments.last().unwrap_or_else(|| unreachable!());
                assert_eq!(
                    last.image_offset() + last.memory_bytes(),
                    limits.image_span_bytes(),
                    "{name}"
                );
            }
            if name.contains("max-pages") {
                assert_eq!(image_pages, limits.image_pages(), "{name}");
            }
            if name.contains("max-stack-heap") {
                assert_eq!(plan.stack_pages(), limits.stack_pages().1, "{name}");
                assert_eq!(plan.heap_pages(), limits.heap_pages(), "{name}");
            }
        }

        let x86_rejections = include!("../../../tests/kex-corpus/rejections-x86_64.inc");
        for (name, bytes, expected) in x86_rejections {
            assert_eq!(
                parse_kex(bytes, Target::X86_64, ABI_MINOR),
                Err(expected),
                "{name}"
            );
        }
        let arm_rejections = include!("../../../tests/kex-corpus/rejections-aarch64.inc");
        for (name, bytes, expected) in arm_rejections {
            assert_eq!(
                parse_kex(bytes, Target::Aarch64, ABI_MINOR),
                Err(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn deterministic_plan_properties_hold_across_varied_disjoint_segments() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for iteration in 0..256_u64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let count = usize::try_from(state % 16 + 1).unwrap_or_else(|_| unreachable!());
            let mut segments = Vec::new();
            let mut image_offset = 0_u64;
            for index in 0..count {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let pages = state % 4 + 1;
                let permissions = if index == 0 {
                    SegmentPermissions::ReadExecute
                } else {
                    match state % 3 {
                        0 => SegmentPermissions::ReadOnly,
                        1 => SegmentPermissions::ReadExecute,
                        _ => SegmentPermissions::ReadWrite,
                    }
                };
                let payload = match index % 3 {
                    0 => &[0x90, 0xc3][..],
                    1 => &[1, 2, 3][..],
                    _ => &[][..],
                };
                segments.push(TestSegment {
                    image_offset,
                    memory_bytes: pages * PAGE_SIZE,
                    permissions: permissions as u32,
                    payload,
                });
                image_offset += (pages + state % 3) * PAGE_SIZE;
            }
            let target = if iteration % 2 == 0 {
                Target::X86_64
            } else {
                Target::Aarch64
            };
            let mut bytes = artifact(target, &segments);
            let stack_pages = u32::try_from(4 + state % 253).unwrap_or_else(|_| unreachable!());
            let heap_pages = u32::try_from(state % 4097).unwrap_or_else(|_| unreachable!());
            put_u32(&mut bytes, HEADER_STACK_PAGES, stack_pages);
            put_u32(&mut bytes, HEADER_HEAP_PAGES, heap_pages);
            let plan = parse_standard(&bytes, target).unwrap_or_else(|_| unreachable!());
            let parsed = plan.segments().collect::<Vec<_>>();
            assert_eq!(parsed.len(), count);
            let mut exact_image_pages = 0_u64;
            let mut previous_end = 0_u64;
            for segment in parsed {
                assert!(segment.image_offset() >= previous_end);
                assert!(!(segment.permissions().writable() && segment.permissions().executable()));
                previous_end = segment.image_offset() + segment.memory_bytes();
                exact_image_pages += segment.memory_bytes() / PAGE_SIZE;
            }
            assert_eq!(plan.charges().staging_bytes(), bytes.len());
            assert_eq!(plan.charges().image_pages(), exact_image_pages);
            assert_eq!(
                plan.charges().private_pages(),
                exact_image_pages + 1 + u64::from(stack_pages) + u64::from(heap_pages)
            );
            assert_eq!(
                plan.charges().reserved_resident_pages(),
                plan.charges().private_pages() + ApplicationLimits::STANDARD.table_pages
            );
        }
    }

    #[test]
    fn loader_transaction_failpoints_release_every_provisional_owner() {
        for failed_index in 0..LoaderResource::ALL.len() {
            let mut transaction = LoaderTransaction::new();
            let mut live = [false; LoaderResource::ALL.len()];
            for (index, resource) in LoaderResource::ALL.iter().copied().enumerate() {
                if index == failed_index {
                    break;
                }
                live[index] = true;
                assert_eq!(transaction.acquire(resource), Ok(()));
            }
            assert!(!transaction.mapping_active());
            let mut released = [None; LoaderResource::ALL.len()];
            let mut release_count = 0;
            transaction.rollback(|resource| {
                let index = resource as usize;
                assert!(live[index]);
                live[index] = false;
                released[release_count] = Some(resource);
                release_count += 1;
            });
            assert!(live.iter().all(|owned| !owned));
            assert_eq!(transaction.provisional_resources(), 0);
            assert!(!transaction.mapping_active());
            let expected = LoaderResource::ALL[..failed_index]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>();
            let actual = released[..release_count]
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn loader_transaction_requires_complete_ordered_commit() {
        let mut transaction = LoaderTransaction::new();
        assert_eq!(
            transaction.acquire(LoaderResource::Frames),
            Err(LoaderTransactionError::OutOfOrder)
        );
        assert_eq!(
            transaction.commit(),
            Err(LoaderTransactionError::Incomplete)
        );
        for resource in LoaderResource::ALL {
            assert_eq!(transaction.acquire(resource), Ok(()));
        }
        assert_eq!(transaction.commit(), Ok(()));
        assert!(transaction.mapping_active());
        assert_eq!(transaction.provisional_resources(), 0);
        assert_eq!(
            transaction.acquire(LoaderResource::Staging),
            Err(LoaderTransactionError::AlreadyCommitted)
        );
        assert_eq!(
            transaction.commit(),
            Err(LoaderTransactionError::AlreadyCommitted)
        );
    }

    #[test]
    fn every_truncation_fails_without_a_plan() {
        let valid = valid_artifact(Target::X86_64);
        for length in 0..valid.len() {
            assert!(parse_standard(&valid[..length], Target::X86_64).is_err());
        }
    }
}

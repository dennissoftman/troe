//! Bounded package, executable, and load-plan policy for KEX application artifacts.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use troe_abi::requirements;
pub use troe_abi::{ABI_MAJOR, ABI_MINOR};

/// KEX v1 base page size in bytes.
pub const PAGE_SIZE: u64 = 4096;
/// KEX v1 base page size as a host slice length.
pub const PAGE_BYTES: usize = 4096;
/// Canonical deterministic KEX v1 image base used by hosted inspection/tests.
pub const KEX_V1_IMAGE_BASE: u64 = 0x0000_4000_0000_0000;
/// Lowest admitted randomized application image base.
pub const KEX_V1_MIN_IMAGE_BASE: u64 = 0x0000_0001_0000_0000;
/// Required image-base randomization granularity.
pub const KEX_V1_IMAGE_ALIGNMENT: u64 = 2 * 1024 * 1024;
/// Exclusive upper bound of the application half of the initial 48-bit roots.
pub const KEX_V1_USER_END: u64 = 0x0000_8000_0000_0000;
/// Image span assumed for ABI 1.0 and 1.1 artifacts, which do not declare one.
///
/// Those artifacts place the startup page at a fixed offset from the image
/// base, so their span is part of the ABI rather than the header.
pub const KEX_V1_LEGACY_IMAGE_SPAN_BYTES: u64 = 128 * 1024 * 1024;
/// Lowest application ABI minor whose artifacts declare their own image span.
pub const KEX_V1_DECLARED_SPAN_ABI_MINOR: u16 = 2;
/// KEX v1 header length in bytes.
pub const KEX_V1_HEADER_BYTES: usize = 88;
/// KEX v1 load-record length in bytes.
pub const KEX_V1_LOAD_RECORD_BYTES: usize = 40;
/// KEX v1 relative-relocation record length in bytes.
pub const KEX_V1_RELOCATION_RECORD_BYTES: usize = 16;
/// Product-name-independent KEX v1 format identifier.
pub const KEX_V1_MAGIC: [u8; 8] = *b"KEX\0FMT\0";
/// KEX package v1 header length in bytes.
pub const KEX_PACKAGE_V1_HEADER_BYTES: usize = 48;
/// Canonical single-file KEX package identifier.
pub const KEX_PACKAGE_V1_MAGIC: [u8; 8] = *b"KEXPKG\0\0";
/// Maximum load records accepted by the standard application policy.
pub const MAX_LOAD_RECORDS: usize = 16;
const CONTAINER_MAJOR: u16 = 1;
const CONTAINER_MINOR: u16 = 1;
const STARTUP_PAGES: u64 = 1;
const MAX_INITIAL_STACK_PAGES: u64 = 1 << 32;
const MAX_INITIAL_HEAP_PAGES: u64 = 1 << 32;
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
const HEADER_IMAGE_SPAN_PAGES: usize = 36;
const HEADER_STACK_PAGES: usize = 40;
const HEADER_HEAP_PAGES: usize = 48;
const HEADER_RECORDS_OFFSET: usize = 56;
const HEADER_PAYLOAD_OFFSET: usize = 60;
const HEADER_RELOCATIONS_OFFSET: usize = 64;
const HEADER_RELOCATION_COUNT: usize = 68;
const HEADER_RELOCATION_BYTES: usize = 72;
const HEADER_RESERVED_RELOCATION16: usize = 74;
const HEADER_RESERVED_RELOCATION32: usize = 76;
const HEADER_ARTIFACT_BYTES: usize = 80;

const RECORD_IMAGE_OFFSET: usize = 0;
const RECORD_FILE_OFFSET: usize = 8;
const RECORD_FILE_BYTES: usize = 16;
const RECORD_MEMORY_BYTES: usize = 24;
const RECORD_PERMISSIONS: usize = 32;
const RECORD_RESERVED: usize = 36;

const RELOCATION_TARGET_OFFSET: usize = 0;
const RELOCATION_VALUE_OFFSET: usize = 8;

const PACKAGE_MAJOR: u16 = 1;
const PACKAGE_MINOR: u16 = 0;
const PACKAGE_HEADER_MAJOR: usize = 8;
const PACKAGE_HEADER_MINOR: usize = 10;
const PACKAGE_HEADER_BYTES: usize = 12;
const PACKAGE_HEADER_FLAGS: usize = 14;
const PACKAGE_HEADER_MANIFEST_OFFSET: usize = 16;
const PACKAGE_HEADER_MANIFEST_BYTES: usize = 20;
const PACKAGE_HEADER_EXECUTABLE_OFFSET: usize = 24;
const PACKAGE_HEADER_COMPLETION_OFFSET: usize = 28;
const PACKAGE_HEADER_EXECUTABLE_BYTES: usize = 32;
const PACKAGE_HEADER_PACKAGE_BYTES: usize = 40;
const PACKAGE_FLAG_COMPLETION: u16 = 1;

/// Maximum complete package bytes admitted by the standard application policy.
pub const MAX_KEX_PACKAGE_BYTES: usize = KEX_PACKAGE_V1_HEADER_BYTES
    + requirements::MAX_MANIFEST_BYTES
    + ApplicationLimits::STANDARD.encoded_bytes
    + troe_completion::MAX_ARTIFACT_BYTES;

/// One validated single-file package borrowing its manifest and KEX executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KexPackage<'package> {
    manifest: requirements::Manifest<'package>,
    executable: &'package [u8],
    completion: Option<&'package [u8]>,
}

impl<'package> KexPackage<'package> {
    /// Optional startup interfaces required by this package.
    #[must_use]
    pub const fn requirements(self) -> requirements::Manifest<'package> {
        self.manifest
    }

    /// Complete canonical KEX v1 executable contained by this package.
    #[must_use]
    pub const fn executable(self) -> &'package [u8] {
        self.executable
    }

    /// Canonical package-owned CMPL artifact, when present.
    #[must_use]
    pub const fn completion(self) -> Option<&'package [u8]> {
        self.completion
    }
}

/// Deterministic single-file package rejection category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageError {
    /// Input exceeds the complete package admission ceiling.
    PackageTooLarge,
    /// Input is shorter than the fixed package header.
    TruncatedHeader,
    /// Header magic is not the KEX package identifier.
    InvalidMagic,
    /// Package major or minor version is unsupported.
    UnsupportedVersion,
    /// Fixed header or embedded ranges are noncanonical.
    InvalidLayout,
    /// An unsupported package flag or reserved field is nonzero.
    NonzeroReserved,
    /// Declared package size differs from the exact input length.
    LengthMismatch,
    /// Embedded capability requirements are malformed.
    InvalidManifest,
    /// Embedded package-owned completion metadata is malformed.
    InvalidCompletion,
}

impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PackageTooLarge => "KEX package exceeds the staging budget",
            Self::TruncatedHeader => "KEX package header is truncated",
            Self::InvalidMagic => "KEX package magic is invalid",
            Self::UnsupportedVersion => "KEX package version is unsupported",
            Self::InvalidLayout => "KEX package layout is noncanonical",
            Self::NonzeroReserved => "KEX package reserved field or unsupported flag is nonzero",
            Self::LengthMismatch => "KEX package declared length differs from its input length",
            Self::InvalidManifest => "KEX package capability manifest is invalid",
            Self::InvalidCompletion => "KEX package completion artifact is invalid",
        })
    }
}

/// Deterministic single-file package encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageEncodeError {
    /// The executable is empty or exceeds the KEX v1 ceiling.
    InvalidExecutable,
    /// The requirements are excessive, duplicate, unordered, or invalid.
    InvalidManifest,
    /// The supplied CMPL artifact is malformed or excessive.
    InvalidCompletion,
    /// Checked package layout arithmetic overflowed.
    ArithmeticOverflow,
    /// Exact output allocation failed.
    AllocationFailed,
}

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
    image_base: u64,
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

    const STANDARD: Self = Self {
        image_base: KEX_V1_IMAGE_BASE,
        stack_top: KEX_V1_USER_END - PAGE_SIZE,
    };
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

/// Largest image span one artifact may declare.
///
/// The declared span bounds every mapped image page, so it replaces the former
/// fixed image-page ceiling: an artifact is held to the span it asks for, and
/// no artifact maps more than this. The binding launch constraint is available
/// frames, which the kernel charges against the configured minimum-free
/// reserve once the mapping plan exists.
pub const MAX_IMAGE_SPAN_BYTES: u64 = 1024 * 1024 * 1024;
/// [`MAX_IMAGE_SPAN_BYTES`] as a page count.
pub const MAX_IMAGE_SPAN_PAGES: u64 = MAX_IMAGE_SPAN_BYTES / PAGE_SIZE;
/// [`MAX_IMAGE_SPAN_BYTES`] as a host slice length.
///
/// The KEX ABI is LP64, so the span is representable; a build whose pointers
/// are narrower than the format requires fails here rather than silently
/// truncating an admission ceiling.
const MAX_IMAGE_SPAN_USIZE: usize = {
    const {
        assert!(
            usize::BITS >= u64::BITS,
            "KEX requires 64-bit host pointers"
        );
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        MAX_IMAGE_SPAN_BYTES as usize
    }
};

/// Page-table entries described by one page-table page.
const TABLE_ENTRIES: u64 = 512;
/// Page-table levels below the shared root on both supported architectures.
const TABLE_LEVELS_BELOW_ROOT: u32 = 3;
/// Contiguous virtual regions in one launch layout: image, startup, heap, stack.
const LAUNCH_REGIONS: u64 = 4;
/// Largest private page count one launch may charge before its page tables.
const MAX_PRIVATE_PAGES: u64 =
    MAX_IMAGE_SPAN_PAGES + STARTUP_PAGES + MAX_INITIAL_STACK_PAGES + MAX_INITIAL_HEAP_PAGES;

/// Canonical declared span for one image that ends at `image_end`.
///
/// The span is the image end rounded up to [`KEX_V1_IMAGE_ALIGNMENT`]. It is
/// exact rather than an upper bound, so an artifact cannot reserve image
/// address space it never maps, and the startup page always sits directly
/// above the image.
///
/// Returns [`None`] when the rounded span is not representable.
#[must_use]
pub const fn canonical_image_span_bytes(image_end: u64) -> Option<u64> {
    let Some(rounded) = image_end.checked_add(KEX_V1_IMAGE_ALIGNMENT - 1) else {
        return None;
    };
    Some(rounded / KEX_V1_IMAGE_ALIGNMENT * KEX_V1_IMAGE_ALIGNMENT)
}

/// Upper bound on the page-table pages needed to map `mapped_pages`.
///
/// One page-table page describes [`TABLE_ENTRIES`] entries, so each of the
/// three levels below the root costs at most one page per that level's
/// coverage, rounded up, plus one page per launch region for a run that does
/// not begin on that level's boundary. The root is shared.
///
/// The kernel charges the exact requirement computed from the built mapping
/// plan, so this bound only has to hold beforehand, while admission is still
/// deciding whether to reserve anything at all. It must nonetheless be a true
/// upper bound: an optimistic estimate would admit a launch that then fails at
/// the exact reservation.
///
/// Returns [`None`] when the count is not representable.
#[must_use]
pub const fn maximum_table_pages(mapped_pages: u64) -> Option<u64> {
    let mut total = 1_u64;
    let mut coverage = TABLE_ENTRIES;
    let mut level = 0_u32;
    while level < TABLE_LEVELS_BELOW_ROOT {
        let Some(rounded) = mapped_pages.checked_add(coverage - 1) else {
            return None;
        };
        let Some(with_level) = total.checked_add(rounded / coverage) else {
            return None;
        };
        let Some(with_regions) = with_level.checked_add(LAUNCH_REGIONS) else {
            return None;
        };
        total = with_regions;
        let Some(wider) = coverage.checked_mul(TABLE_ENTRIES) else {
            return None;
        };
        coverage = wider;
        level += 1;
    }
    Some(total)
}

/// Absolute application limits enforced by the standard policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLimits {
    encoded_bytes: usize,
    load_records: usize,
    maximum_image_span_bytes: u64,
    minimum_stack_pages: u64,
    maximum_stack_pages: u64,
    heap_pages: u64,
    resident_pages: u64,
    initial_handles: u16,
}

impl ApplicationLimits {
    const STANDARD: Self = Self {
        // Payload bytes cannot exceed the mapped span, which the segment
        // parser enforces exactly. The remaining allowance bounds the
        // canonical header, load records, and relative-relocation table.
        encoded_bytes: 2 * MAX_IMAGE_SPAN_USIZE,
        load_records: 16,
        maximum_image_span_bytes: MAX_IMAGE_SPAN_BYTES,
        minimum_stack_pages: 4,
        maximum_stack_pages: MAX_INITIAL_STACK_PAGES,
        heap_pages: MAX_INITIAL_HEAP_PAGES,
        resident_pages: match maximum_table_pages(MAX_PRIVATE_PAGES) {
            Some(tables) => MAX_PRIVATE_PAGES + tables,
            None => panic!("maximum private pages must have a table bound"),
        },
        initial_handles: 32,
    };

    /// Limits fixed by the standard application policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self::STANDARD
    }

    /// Maximum encoded KEX bytes accepted by the standard policy.
    #[must_use]
    pub const fn encoded_bytes(self) -> usize {
        self.encoded_bytes
    }

    /// Maximum load records.
    #[must_use]
    pub const fn load_records(self) -> usize {
        self.load_records
    }

    /// Largest image span one artifact may declare.
    #[must_use]
    pub const fn maximum_image_span_bytes(self) -> u64 {
        self.maximum_image_span_bytes
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
    image_base: u64,
    image_offset: u64,
    memory_bytes: u64,
    file_offset: u64,
    file_byte_count: u64,
    permissions: SegmentPermissions,
    file_bytes: &'artifact [u8],
}

/// Pointer-free geometry for one validated KEX load segment.
///
/// Unlike [`LoadSegment`], this value does not borrow the complete artifact.
/// It is therefore suitable for a bounded streaming loader which retains only
/// format metadata while copying payload ranges directly into inactive frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegmentLayout {
    image_base: u64,
    image_offset: u64,
    memory_bytes: u64,
    file_offset: u64,
    file_byte_count: u64,
    permissions: SegmentPermissions,
}

impl LoadSegmentLayout {
    /// Absolute first virtual byte at the kernel-selected image base.
    #[must_use]
    pub const fn virtual_address(self) -> u64 {
        self.image_base + self.image_offset
    }

    /// Image-relative first byte.
    #[must_use]
    pub const fn image_offset(self) -> u64 {
        self.image_offset
    }

    /// Mapped bytes, including the zero-filled suffix.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    /// Executable-relative first payload byte.
    #[must_use]
    pub const fn file_offset(self) -> u64 {
        self.file_offset
    }

    /// Number of payload bytes copied from the artifact.
    #[must_use]
    pub const fn file_byte_count(self) -> u64 {
        self.file_byte_count
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

impl<'artifact> LoadSegment<'artifact> {
    /// Return the segment's pointer-free geometry.
    #[must_use]
    pub const fn layout(self) -> LoadSegmentLayout {
        LoadSegmentLayout {
            image_base: self.image_base,
            image_offset: self.image_offset,
            memory_bytes: self.memory_bytes,
            file_offset: self.file_offset,
            file_byte_count: self.file_byte_count,
            permissions: self.permissions,
        }
    }
    /// Image-relative first byte.
    #[must_use]
    pub const fn image_offset(self) -> u64 {
        self.image_offset
    }

    /// Absolute first virtual byte at the kernel-selected KEX v1 base.
    #[must_use]
    pub const fn virtual_address(self) -> u64 {
        self.image_base + self.image_offset
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

/// One validated image-relative pointer fixup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelativeRelocation {
    target_offset: u64,
    value_offset: u64,
}

impl RelativeRelocation {
    /// Image-relative writable address receiving one little-endian `u64`.
    #[must_use]
    pub const fn target_offset(self) -> u64 {
        self.target_offset
    }

    /// Image-relative value added to the selected image base.
    #[must_use]
    pub const fn value_offset(self) -> u64 {
        self.value_offset
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

    /// First byte of the application's initially mapped, growable zeroed heap.
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

/// Values placed in the immutable ABI 1.x startup page.
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
    /// Bounded kernel-owned format-verifier scratch storage.
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
    /// Peak source-staging bytes retained by the selected loading path.
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
    image_base: u64,
    entry_offset: u64,
    stack_pages: u64,
    heap_pages: u64,
    segments: [Option<LoadSegment<'artifact>>; MAX_LOAD_RECORDS],
    segment_count: usize,
    relocations: &'artifact [u8],
    relocation_count: usize,
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

    /// Kernel-selected image base.
    #[must_use]
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Fixed virtual entry address.
    #[must_use]
    pub const fn entry_address(&self) -> u64 {
        self.image_base + self.entry_offset
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

    /// Ordered validated image-relative pointer fixups.
    pub fn relocations(&self) -> impl Iterator<Item = RelativeRelocation> + '_ {
        self.relocations
            .chunks_exact(KEX_V1_RELOCATION_RECORD_BYTES)
            .take(self.relocation_count)
            .map(|record| RelativeRelocation {
                target_offset: u64::from_le_bytes(
                    record[RELOCATION_TARGET_OFFSET..RELOCATION_TARGET_OFFSET + 8]
                        .try_into()
                        .unwrap_or_else(|_| unreachable!()),
                ),
                value_offset: u64::from_le_bytes(
                    record[RELOCATION_VALUE_OFFSET..RELOCATION_VALUE_OFFSET + 8]
                        .try_into()
                        .unwrap_or_else(|_| unreachable!()),
                ),
            })
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

    /// Encode the immutable ABI 1.x startup page into a zeroed base page.
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
        encode_startup_page(
            self.abi_minor,
            self.image_base,
            self.layout,
            info,
            destination,
        )
    }
}

fn encode_startup_page(
    abi_minor: u16,
    image_base: u64,
    layout: ApplicationLayout,
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
    write_u16(destination, 6, abi_minor);
    write_u32(destination, 8, 4096);
    write_u16(destination, 12, 0);
    write_u16(destination, 14, handle_count);
    write_u64(destination, 16, image_base);
    write_u64(destination, 24, layout.heap_address);
    write_u64(destination, 32, layout.heap_bytes);
    write_u64(destination, 40, layout.stack_bottom);
    write_u64(destination, 48, layout.stack_top);
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

/// Encode one canonical package containing requirements and a KEX v1 executable.
///
/// # Errors
///
/// Rejects empty or excessive executables, invalid requirements, checked
/// arithmetic failure, and exact allocation failure without producing output.
pub fn encode_kex_package(
    executable: &[u8],
    required: &[requirements::Requirement],
) -> Result<Vec<u8>, PackageEncodeError> {
    encode_kex_package_with_completion(executable, required, None)
}

/// Encode one canonical package with an optional package-owned CMPL artifact.
///
/// # Errors
///
/// Rejects malformed completion bytes in addition to the ordinary package
/// encoder failures. Completion is appended after the executable and bound by
/// the package envelope; it is never installed as a loose sidecar.
pub fn encode_kex_package_with_completion(
    executable: &[u8],
    required: &[requirements::Requirement],
    completion: Option<&[u8]>,
) -> Result<Vec<u8>, PackageEncodeError> {
    if executable.is_empty() || executable.len() > ApplicationLimits::standard().encoded_bytes() {
        return Err(PackageEncodeError::InvalidExecutable);
    }
    if let Some(bytes) = completion {
        troe_completion::CompletionArtifact::parse(bytes)
            .map_err(|_| PackageEncodeError::InvalidCompletion)?;
    }
    let mut manifest = [0_u8; requirements::MAX_MANIFEST_BYTES];
    let manifest_bytes = requirements::encode(required, &mut manifest)
        .map_err(|_| PackageEncodeError::InvalidManifest)?;
    let executable_offset = KEX_PACKAGE_V1_HEADER_BYTES
        .checked_add(manifest_bytes)
        .ok_or(PackageEncodeError::ArithmeticOverflow)?;
    let executable_end = executable_offset
        .checked_add(executable.len())
        .ok_or(PackageEncodeError::ArithmeticOverflow)?;
    let package_bytes = executable_end
        .checked_add(completion.map_or(0, <[u8]>::len))
        .ok_or(PackageEncodeError::ArithmeticOverflow)?;
    if package_bytes > MAX_KEX_PACKAGE_BYTES {
        return Err(PackageEncodeError::InvalidExecutable);
    }
    let mut package = Vec::new();
    package
        .try_reserve_exact(package_bytes)
        .map_err(|_| PackageEncodeError::AllocationFailed)?;
    package.resize(package_bytes, 0);
    package[..8].copy_from_slice(&KEX_PACKAGE_V1_MAGIC);
    write_u16(&mut package, PACKAGE_HEADER_MAJOR, PACKAGE_MAJOR);
    write_u16(&mut package, PACKAGE_HEADER_MINOR, PACKAGE_MINOR);
    write_u16(
        &mut package,
        PACKAGE_HEADER_FLAGS,
        if completion.is_some() {
            PACKAGE_FLAG_COMPLETION
        } else {
            0
        },
    );
    write_u16(
        &mut package,
        PACKAGE_HEADER_BYTES,
        u16::try_from(KEX_PACKAGE_V1_HEADER_BYTES)
            .map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    write_u32(
        &mut package,
        PACKAGE_HEADER_MANIFEST_OFFSET,
        u32::try_from(KEX_PACKAGE_V1_HEADER_BYTES)
            .map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    write_u32(
        &mut package,
        PACKAGE_HEADER_MANIFEST_BYTES,
        u32::try_from(manifest_bytes).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    write_u32(
        &mut package,
        PACKAGE_HEADER_EXECUTABLE_OFFSET,
        u32::try_from(executable_offset).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    if completion.is_some() {
        write_u32(
            &mut package,
            PACKAGE_HEADER_COMPLETION_OFFSET,
            u32::try_from(executable_end).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
        );
    }
    write_u64(
        &mut package,
        PACKAGE_HEADER_EXECUTABLE_BYTES,
        u64::try_from(executable.len()).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    write_u64(
        &mut package,
        PACKAGE_HEADER_PACKAGE_BYTES,
        u64::try_from(package_bytes).map_err(|_| PackageEncodeError::ArithmeticOverflow)?,
    );
    package[KEX_PACKAGE_V1_HEADER_BYTES..executable_offset]
        .copy_from_slice(&manifest[..manifest_bytes]);
    package[executable_offset..executable_end].copy_from_slice(executable);
    if let Some(completion) = completion {
        package[executable_end..].copy_from_slice(completion);
    }
    Ok(package)
}

/// Parse one exact single-file KEX application package.
///
/// This validates the envelope and capability manifest. Call [`parse_kex`] on
/// [`KexPackage::executable`] before allocating or mapping application pages.
///
/// # Errors
///
/// Rejects every truncation, unsupported version, noncanonical range,
/// reserved value, length mismatch, and malformed capability manifest.
pub fn parse_kex_package(package: &[u8]) -> Result<KexPackage<'_>, PackageError> {
    if package.len() > MAX_KEX_PACKAGE_BYTES {
        return Err(PackageError::PackageTooLarge);
    }
    if package.len() < KEX_PACKAGE_V1_HEADER_BYTES {
        return Err(PackageError::TruncatedHeader);
    }
    if package[..8] != KEX_PACKAGE_V1_MAGIC {
        return Err(PackageError::InvalidMagic);
    }
    if read_package_u16(package, PACKAGE_HEADER_MAJOR)? != PACKAGE_MAJOR
        || read_package_u16(package, PACKAGE_HEADER_MINOR)? != PACKAGE_MINOR
    {
        return Err(PackageError::UnsupportedVersion);
    }
    let flags = read_package_u16(package, PACKAGE_HEADER_FLAGS)?;
    if flags & !PACKAGE_FLAG_COMPLETION != 0 {
        return Err(PackageError::NonzeroReserved);
    }
    let header_bytes = usize::from(read_package_u16(package, PACKAGE_HEADER_BYTES)?);
    let manifest_offset =
        usize::try_from(read_package_u32(package, PACKAGE_HEADER_MANIFEST_OFFSET)?)
            .map_err(|_| PackageError::InvalidLayout)?;
    let manifest_bytes = usize::try_from(read_package_u32(package, PACKAGE_HEADER_MANIFEST_BYTES)?)
        .map_err(|_| PackageError::InvalidLayout)?;
    let executable_offset =
        usize::try_from(read_package_u32(package, PACKAGE_HEADER_EXECUTABLE_OFFSET)?)
            .map_err(|_| PackageError::InvalidLayout)?;
    let executable_bytes =
        usize::try_from(read_package_u64(package, PACKAGE_HEADER_EXECUTABLE_BYTES)?)
            .map_err(|_| PackageError::InvalidLayout)?;
    let completion_offset =
        usize::try_from(read_package_u32(package, PACKAGE_HEADER_COMPLETION_OFFSET)?)
            .map_err(|_| PackageError::InvalidLayout)?;
    let package_bytes = usize::try_from(read_package_u64(package, PACKAGE_HEADER_PACKAGE_BYTES)?)
        .map_err(|_| PackageError::LengthMismatch)?;
    if package_bytes != package.len() {
        return Err(PackageError::LengthMismatch);
    }
    let manifest_end = manifest_offset
        .checked_add(manifest_bytes)
        .ok_or(PackageError::InvalidLayout)?;
    let executable_end = executable_offset
        .checked_add(executable_bytes)
        .ok_or(PackageError::InvalidLayout)?;
    if header_bytes != KEX_PACKAGE_V1_HEADER_BYTES
        || manifest_offset != KEX_PACKAGE_V1_HEADER_BYTES
        || manifest_bytes > requirements::MAX_MANIFEST_BYTES
        || executable_offset != manifest_end
        || executable_bytes == 0
        || executable_bytes > ApplicationLimits::standard().encoded_bytes()
        || (flags == 0 && (completion_offset != 0 || executable_end != package.len()))
        || (flags == PACKAGE_FLAG_COMPLETION
            && (completion_offset != executable_end
                || completion_offset >= package.len()
                || package.len() - completion_offset > troe_completion::MAX_ARTIFACT_BYTES))
    {
        return Err(PackageError::InvalidLayout);
    }
    let manifest = requirements::Manifest::parse(
        package
            .get(manifest_offset..manifest_end)
            .ok_or(PackageError::InvalidLayout)?,
    )
    .map_err(|_| PackageError::InvalidManifest)?;
    let executable = package
        .get(executable_offset..executable_end)
        .ok_or(PackageError::InvalidLayout)?;
    let completion = if flags == PACKAGE_FLAG_COMPLETION {
        let bytes = package
            .get(completion_offset..)
            .ok_or(PackageError::InvalidLayout)?;
        troe_completion::CompletionArtifact::parse(bytes)
            .map_err(|_| PackageError::InvalidCompletion)?;
        Some(bytes)
    } else {
        None
    };
    Ok(KexPackage {
        manifest,
        executable,
        completion,
    })
}

/// Locate an embedded CMPL artifact using only the fixed package header and
/// authoritative file length.
///
/// This is the bounded activation-registry path: callers can read 48 header
/// bytes and then only the small completion range instead of staging an entire
/// executable. Full application launch still uses [`parse_kex_package`].
///
/// # Errors
///
/// Rejects incomplete headers, unknown flags or versions, inconsistent file
/// lengths, and noncanonical completion placement.
pub fn kex_package_completion_range(
    header: &[u8],
    file_bytes: u64,
) -> Result<Option<(u64, usize)>, PackageError> {
    if header.len() != KEX_PACKAGE_V1_HEADER_BYTES {
        return Err(PackageError::TruncatedHeader);
    }
    if header[..8] != KEX_PACKAGE_V1_MAGIC {
        return Err(PackageError::InvalidMagic);
    }
    if read_package_u16(header, PACKAGE_HEADER_MAJOR)? != PACKAGE_MAJOR
        || read_package_u16(header, PACKAGE_HEADER_MINOR)? != PACKAGE_MINOR
    {
        return Err(PackageError::UnsupportedVersion);
    }
    if usize::from(read_package_u16(header, PACKAGE_HEADER_BYTES)?) != KEX_PACKAGE_V1_HEADER_BYTES {
        return Err(PackageError::InvalidLayout);
    }
    let flags = read_package_u16(header, PACKAGE_HEADER_FLAGS)?;
    if flags & !PACKAGE_FLAG_COMPLETION != 0 {
        return Err(PackageError::NonzeroReserved);
    }
    let declared = read_package_u64(header, PACKAGE_HEADER_PACKAGE_BYTES)?;
    if declared != file_bytes
        || file_bytes > u64::try_from(MAX_KEX_PACKAGE_BYTES).unwrap_or(u64::MAX)
    {
        return Err(PackageError::LengthMismatch);
    }
    let manifest_offset = u64::from(read_package_u32(header, PACKAGE_HEADER_MANIFEST_OFFSET)?);
    let manifest_bytes = u64::from(read_package_u32(header, PACKAGE_HEADER_MANIFEST_BYTES)?);
    let executable_offset = u64::from(read_package_u32(header, PACKAGE_HEADER_EXECUTABLE_OFFSET)?);
    let executable_bytes = read_package_u64(header, PACKAGE_HEADER_EXECUTABLE_BYTES)?;
    if manifest_offset != u64::try_from(KEX_PACKAGE_V1_HEADER_BYTES).unwrap_or(u64::MAX)
        || manifest_bytes > u64::try_from(requirements::MAX_MANIFEST_BYTES).unwrap_or(u64::MAX)
        || executable_offset != manifest_offset.saturating_add(manifest_bytes)
        || executable_bytes == 0
        || executable_bytes
            > u64::try_from(ApplicationLimits::standard().encoded_bytes()).unwrap_or(u64::MAX)
    {
        return Err(PackageError::InvalidLayout);
    }
    let executable_end = executable_offset
        .checked_add(executable_bytes)
        .ok_or(PackageError::InvalidLayout)?;
    let completion_offset = u64::from(read_package_u32(header, PACKAGE_HEADER_COMPLETION_OFFSET)?);
    if flags == 0 {
        if completion_offset != 0 || executable_end != file_bytes {
            return Err(PackageError::InvalidLayout);
        }
        return Ok(None);
    }
    let completion_bytes = file_bytes
        .checked_sub(completion_offset)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(PackageError::InvalidLayout)?;
    if flags != PACKAGE_FLAG_COMPLETION
        || completion_offset != executable_end
        || completion_bytes == 0
        || completion_bytes > troe_completion::MAX_ARTIFACT_BYTES
    {
        return Err(PackageError::InvalidLayout);
    }
    Ok(Some((completion_offset, completion_bytes)))
}

fn read_package_u16(bytes: &[u8], offset: usize) -> Result<u16, PackageError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(PackageError::InvalidLayout)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_package_u32(bytes: &[u8], offset: usize) -> Result<u32, PackageError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(PackageError::InvalidLayout)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_package_u64(bytes: &[u8], offset: usize) -> Result<u64, PackageError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(PackageError::InvalidLayout)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

/// Fixed prefix retained while parsing a streamed KEX package.
///
/// This covers the largest package header, capability manifest, executable
/// header, and sixteen load records. Relocations and payload bytes are never
/// retained as a whole.
pub const STREAM_PREFIX_BYTES: usize = PAGE_BYTES;
/// Peak byte buffers used by the format-side streaming verifier.
pub const STREAM_WORKING_SET_BYTES: usize = 2 * PAGE_BYTES + troe_completion::MAX_ARTIFACT_BYTES;

/// Failure while validating or replaying a bounded streamed package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError {
    /// Source length is empty, unrepresentable, or above the package ceiling.
    InvalidLength,
    /// The source reported an I/O or integrity failure.
    SourceFailed,
    /// The source ended early, made no progress, or over-reported a read.
    IncompleteRead,
    /// Bounded verifier scratch storage could not be allocated.
    AllocationFailed,
    /// The package envelope or capability manifest was rejected.
    Package(PackageError),
    /// The embedded executable was rejected.
    Executable(ParseError),
    /// A replay pass did not match the bytes used to construct the plan.
    SourceChanged,
    /// The inactive-frame or relocation consumer rejected a verified chunk.
    SinkFailed,
}

/// Owned, pointer-free KEX plan produced from a bounded streaming source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamedLoadPlan {
    target: Target,
    abi_minor: u16,
    image_base: u64,
    entry_offset: u64,
    stack_pages: u64,
    heap_pages: u64,
    segments: [Option<LoadSegmentLayout>; MAX_LOAD_RECORDS],
    segment_count: usize,
    relocations_offset: u64,
    relocation_count: usize,
    charges: LoadCharges,
    layout: ApplicationLayout,
}

impl StreamedLoadPlan {
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

    /// Kernel-selected image base.
    #[must_use]
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Absolute application entry address.
    #[must_use]
    pub const fn entry_address(&self) -> u64 {
        self.image_base + self.entry_offset
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

    /// Ordered validated load-segment geometry.
    pub fn segments(&self) -> impl Iterator<Item = LoadSegmentLayout> + '_ {
        self.segments[..self.segment_count]
            .iter()
            .flatten()
            .copied()
    }

    /// Preliminary bounded-staging and page charges.
    #[must_use]
    pub const fn charges(&self) -> LoadCharges {
        self.charges
    }

    /// Canonical startup, heap, guard, and stack virtual placement.
    #[must_use]
    pub const fn layout(&self) -> ApplicationLayout {
        self.layout
    }

    /// Encode the immutable ABI startup page.
    ///
    /// # Errors
    ///
    /// Rejects invalid task or handle metadata before modifying the page.
    pub fn encode_startup_page(
        &self,
        info: StartupInfo<'_>,
        destination: &mut [u8; PAGE_BYTES],
    ) -> Result<(), StartupPageError> {
        encode_startup_page(
            self.abi_minor,
            self.image_base,
            self.layout,
            info,
            destination,
        )
    }
}

/// Complete validated package identity and its streamed executable plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamedKexPackage {
    package_bytes: usize,
    executable_offset: u64,
    manifest: [u8; requirements::MAX_MANIFEST_BYTES],
    manifest_bytes: usize,
    executable: StreamedLoadPlan,
    digest: [u8; 32],
    relocation_digest: [u8; 32],
}

impl StreamedKexPackage {
    /// Validated optional startup interfaces required by this package.
    #[must_use]
    pub fn requirements(&self) -> requirements::Manifest<'_> {
        requirements::Manifest::parse(&self.manifest[..self.manifest_bytes])
            .unwrap_or_else(|_| unreachable!())
    }

    /// Owned pointer-free executable plan.
    #[must_use]
    pub const fn executable(&self) -> &StreamedLoadPlan {
        &self.executable
    }

    /// Exact package length replayed by the coherent verifier.
    #[must_use]
    pub const fn package_bytes(&self) -> usize {
        self.package_bytes
    }
}

/// Parse and fully validate one package through bounded random-access reads.
///
/// The first pass retains a fixed one-page prefix and fingerprints every
/// source byte. Relocations are then reread, validated, and fingerprinted
/// independently. Later materialization APIs require both fingerprints to
/// match before the inactive address space can be activated.
///
/// # Errors
///
/// Rejects source contract violations, every normal package/KEX format error,
/// and any source mutation observed between validation passes.
pub fn parse_streamed_kex_package(
    byte_len: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    expected_target: Target,
    supported_abi_minor: u16,
    placement: LoadPlacement,
) -> Result<StreamedKexPackage, StreamError> {
    let package_bytes = usize::try_from(byte_len).map_err(|_| StreamError::InvalidLength)?;
    if package_bytes == 0 || package_bytes > MAX_KEX_PACKAGE_BYTES {
        return Err(StreamError::InvalidLength);
    }
    let prefix_bytes = package_bytes.min(STREAM_PREFIX_BYTES);
    let mut prefix = [0_u8; STREAM_PREFIX_BYTES];
    read_stream_exact(&mut read_at, 0, &mut prefix[..prefix_bytes])?;

    let parsed = parse_stream_prefix(
        &prefix[..prefix_bytes],
        package_bytes,
        expected_target,
        supported_abi_minor,
        placement,
    )?;
    let relocation_start = usize::try_from(parsed.executable_offset)
        .ok()
        .and_then(|offset| {
            usize::try_from(parsed.executable.relocations_offset)
                .ok()
                .and_then(|relocation| offset.checked_add(relocation))
        })
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    let relocation_bytes = parsed
        .executable
        .relocation_count
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    let relocation_end = relocation_start
        .checked_add(relocation_bytes)
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;

    let mut package_hash = Sha256::new();
    package_hash.update(&prefix[..prefix_bytes]);
    let mut relocation_hash = Sha256::new();
    hash_overlap(
        &mut relocation_hash,
        0,
        &prefix[..prefix_bytes],
        relocation_start,
        relocation_end,
    );
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut offset = prefix_bytes;
    while offset < package_bytes {
        let count = (package_bytes - offset).min(buffer.len());
        read_stream_exact(
            &mut read_at,
            u64::try_from(offset).map_err(|_| StreamError::InvalidLength)?,
            &mut buffer[..count],
        )?;
        package_hash.update(&buffer[..count]);
        hash_overlap(
            &mut relocation_hash,
            offset,
            &buffer[..count],
            relocation_start,
            relocation_end,
        );
        offset = offset
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
    }
    let digest = package_hash.finish();
    let relocation_digest = relocation_hash.finish();
    if let Some((completion_offset, completion_bytes)) = parsed.completion {
        validate_streamed_completion(completion_offset, completion_bytes, &mut read_at)?;
    }
    validate_streamed_relocations(
        &parsed.executable,
        parsed.executable_offset,
        &mut read_at,
        relocation_digest,
    )?;

    Ok(StreamedKexPackage {
        package_bytes,
        executable_offset: parsed.executable_offset,
        manifest: parsed.manifest,
        manifest_bytes: parsed.manifest_bytes,
        executable: parsed.executable,
        digest,
        relocation_digest,
    })
}

fn validate_streamed_completion(
    offset: u64,
    byte_count: usize,
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
) -> Result<(), StreamError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(byte_count)
        .map_err(|_| StreamError::AllocationFailed)?;
    buffer.resize(byte_count, 0);
    read_stream_exact(read_at, offset, &mut buffer)?;
    troe_completion::CompletionArtifact::parse(&buffer)
        .map_err(|_| StreamError::Package(PackageError::InvalidCompletion))?;
    Ok(())
}

/// Replay a validated package and copy only its segment payload bytes.
///
/// `consume` receives a segment index, a byte offset within that segment, and
/// one bounded verified-source chunk. A fingerprint mismatch is reported after
/// the replay; callers must keep destination frames provisional until success.
///
/// # Errors
///
/// Reports source failures, mutation, or a rejected destination chunk.
pub fn stream_verified_segments(
    package: &StreamedKexPackage,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    mut consume: impl FnMut(usize, u64, &[u8]) -> Result<(), ()>,
) -> Result<(), StreamError> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut offset = 0_usize;
    while offset < package.package_bytes {
        let count = (package.package_bytes - offset).min(buffer.len());
        read_stream_exact(
            &mut read_at,
            u64::try_from(offset).map_err(|_| StreamError::InvalidLength)?,
            &mut buffer[..count],
        )?;
        hash.update(&buffer[..count]);
        let chunk_end = offset
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
        for (index, segment) in package.executable.segments().enumerate() {
            let start = usize::try_from(package.executable_offset)
                .ok()
                .and_then(|base| {
                    usize::try_from(segment.file_offset())
                        .ok()
                        .and_then(|relative| base.checked_add(relative))
                })
                .ok_or(StreamError::InvalidLength)?;
            let end = usize::try_from(segment.file_byte_count())
                .ok()
                .and_then(|bytes| start.checked_add(bytes))
                .ok_or(StreamError::InvalidLength)?;
            let overlap_start = offset.max(start);
            let overlap_end = chunk_end.min(end);
            if overlap_start < overlap_end {
                let source_start = overlap_start - offset;
                let source_end = overlap_end - offset;
                consume(
                    index,
                    u64::try_from(overlap_start - start).map_err(|_| StreamError::InvalidLength)?,
                    &buffer[source_start..source_end],
                )
                .map_err(|()| StreamError::SinkFailed)?;
            }
        }
        offset = chunk_end;
    }
    if hash.finish() != package.digest {
        return Err(StreamError::SourceChanged);
    }
    Ok(())
}

/// Replay and visit every validated relocation using bounded storage.
///
/// The relocation-table fingerprint is checked after visitation. Callers must
/// discard provisional frames on any returned error.
///
/// # Errors
///
/// Reports source failures, mutation, malformed replay bytes, or sink failure.
pub fn visit_verified_relocations(
    package: &StreamedKexPackage,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    mut consume: impl FnMut(RelativeRelocation) -> Result<(), ()>,
) -> Result<(), StreamError> {
    let start = package
        .executable_offset
        .checked_add(package.executable.relocations_offset)
        .ok_or(StreamError::InvalidLength)?;
    let byte_count = package
        .executable
        .relocation_count
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or(StreamError::InvalidLength)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut consumed = 0_usize;
    while consumed < byte_count {
        let count = (byte_count - consumed).min(buffer.len());
        let offset = start
            .checked_add(u64::try_from(consumed).map_err(|_| StreamError::InvalidLength)?)
            .ok_or(StreamError::InvalidLength)?;
        read_stream_exact(&mut read_at, offset, &mut buffer[..count])?;
        hash.update(&buffer[..count]);
        for record in buffer[..count].chunks_exact(KEX_V1_RELOCATION_RECORD_BYTES) {
            let relocation = RelativeRelocation {
                target_offset: read_u64(record, RELOCATION_TARGET_OFFSET)
                    .map_err(StreamError::Executable)?,
                value_offset: read_u64(record, RELOCATION_VALUE_OFFSET)
                    .map_err(StreamError::Executable)?,
            };
            consume(relocation).map_err(|()| StreamError::SinkFailed)?;
        }
        consumed = consumed
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
    }
    if hash.finish() != package.relocation_digest {
        return Err(StreamError::SourceChanged);
    }
    Ok(())
}

struct ParsedStreamPrefix {
    executable_offset: u64,
    completion: Option<(u64, usize)>,
    manifest: [u8; requirements::MAX_MANIFEST_BYTES],
    manifest_bytes: usize,
    executable: StreamedLoadPlan,
}

#[allow(clippy::too_many_lines)]
fn parse_stream_prefix(
    prefix: &[u8],
    package_bytes: usize,
    expected_target: Target,
    supported_abi_minor: u16,
    placement: LoadPlacement,
) -> Result<ParsedStreamPrefix, StreamError> {
    if prefix.len() < KEX_PACKAGE_V1_HEADER_BYTES {
        return Err(StreamError::Package(PackageError::TruncatedHeader));
    }
    if prefix[..8] != KEX_PACKAGE_V1_MAGIC {
        return Err(StreamError::Package(PackageError::InvalidMagic));
    }
    if read_package_u16(prefix, PACKAGE_HEADER_MAJOR).map_err(StreamError::Package)?
        != PACKAGE_MAJOR
        || read_package_u16(prefix, PACKAGE_HEADER_MINOR).map_err(StreamError::Package)?
            != PACKAGE_MINOR
    {
        return Err(StreamError::Package(PackageError::UnsupportedVersion));
    }
    let flags = read_package_u16(prefix, PACKAGE_HEADER_FLAGS).map_err(StreamError::Package)?;
    if flags & !PACKAGE_FLAG_COMPLETION != 0 {
        return Err(StreamError::Package(PackageError::NonzeroReserved));
    }
    let header_bytes =
        usize::from(read_package_u16(prefix, PACKAGE_HEADER_BYTES).map_err(StreamError::Package)?);
    let manifest_offset = usize::try_from(
        read_package_u32(prefix, PACKAGE_HEADER_MANIFEST_OFFSET).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let manifest_bytes = usize::try_from(
        read_package_u32(prefix, PACKAGE_HEADER_MANIFEST_BYTES).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let executable_offset = usize::try_from(
        read_package_u32(prefix, PACKAGE_HEADER_EXECUTABLE_OFFSET).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let completion_offset = usize::try_from(
        read_package_u32(prefix, PACKAGE_HEADER_COMPLETION_OFFSET).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let executable_bytes = usize::try_from(
        read_package_u64(prefix, PACKAGE_HEADER_EXECUTABLE_BYTES).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?;
    let declared_package_bytes = usize::try_from(
        read_package_u64(prefix, PACKAGE_HEADER_PACKAGE_BYTES).map_err(StreamError::Package)?,
    )
    .map_err(|_| StreamError::Package(PackageError::LengthMismatch))?;
    if declared_package_bytes != package_bytes {
        return Err(StreamError::Package(PackageError::LengthMismatch));
    }
    let manifest_end = manifest_offset
        .checked_add(manifest_bytes)
        .ok_or(StreamError::Package(PackageError::InvalidLayout))?;
    let executable_end = executable_offset
        .checked_add(executable_bytes)
        .ok_or(StreamError::Package(PackageError::InvalidLayout))?;
    if header_bytes != KEX_PACKAGE_V1_HEADER_BYTES
        || manifest_offset != KEX_PACKAGE_V1_HEADER_BYTES
        || manifest_bytes > requirements::MAX_MANIFEST_BYTES
        || executable_offset != manifest_end
        || executable_bytes == 0
        || executable_bytes > ApplicationLimits::standard().encoded_bytes()
    {
        return Err(StreamError::Package(PackageError::InvalidLayout));
    }
    let completion = if flags == 0 {
        if completion_offset != 0 || executable_end != package_bytes {
            return Err(StreamError::Package(PackageError::InvalidLayout));
        }
        None
    } else {
        let completion_bytes = package_bytes
            .checked_sub(completion_offset)
            .ok_or(StreamError::Package(PackageError::InvalidLayout))?;
        if completion_offset != executable_end
            || completion_bytes == 0
            || completion_bytes > troe_completion::MAX_ARTIFACT_BYTES
        {
            return Err(StreamError::Package(PackageError::InvalidLayout));
        }
        Some((
            u64::try_from(completion_offset)
                .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?,
            completion_bytes,
        ))
    };
    let manifest_source = prefix
        .get(manifest_offset..manifest_end)
        .ok_or(StreamError::Package(PackageError::InvalidLayout))?;
    requirements::Manifest::parse(manifest_source)
        .map_err(|_| StreamError::Package(PackageError::InvalidManifest))?;
    let executable_prefix = prefix
        .get(executable_offset..)
        .ok_or(StreamError::Executable(ParseError::TruncatedHeader))?;
    let header = parse_header_with_len(
        executable_prefix,
        executable_bytes,
        expected_target,
        supported_abi_minor,
        ApplicationLimits::standard(),
    )
    .map_err(StreamError::Executable)?;
    let parsed = parse_stream_segments(
        executable_prefix,
        executable_bytes,
        header,
        placement.image_base,
    )
    .map_err(StreamError::Executable)?;
    let layout = application_layout(
        header.stack_pages,
        header.heap_pages,
        header.abi_minor,
        header.image_span_bytes,
        ApplicationLimits::standard(),
        placement,
    )
    .map_err(StreamError::Executable)?;
    let private_pages = parsed
        .image_pages
        .checked_add(header.stack_pages)
        .and_then(|pages| pages.checked_add(header.heap_pages))
        .and_then(|pages| pages.checked_add(STARTUP_PAGES))
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    let reserved_resident_pages = maximum_table_pages(private_pages)
        .and_then(|tables| private_pages.checked_add(tables))
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    if reserved_resident_pages > ApplicationLimits::standard().resident_pages {
        return Err(StreamError::Executable(ParseError::ResidentBudgetExceeded));
    }
    let mut manifest = [0_u8; requirements::MAX_MANIFEST_BYTES];
    manifest[..manifest_bytes].copy_from_slice(manifest_source);
    Ok(ParsedStreamPrefix {
        executable_offset: u64::try_from(executable_offset)
            .map_err(|_| StreamError::Package(PackageError::InvalidLayout))?,
        completion,
        manifest,
        manifest_bytes,
        executable: StreamedLoadPlan {
            target: header.target,
            abi_minor: header.abi_minor,
            image_base: placement.image_base,
            entry_offset: header.entry_offset,
            stack_pages: header.stack_pages,
            heap_pages: header.heap_pages,
            segments: parsed.segments,
            segment_count: header.record_count,
            relocations_offset: u64::try_from(header.relocations_offset)
                .map_err(|_| StreamError::Executable(ParseError::ArithmeticOverflow))?,
            relocation_count: header.relocation_count,
            charges: LoadCharges {
                staging_bytes: STREAM_WORKING_SET_BYTES,
                image_pages: parsed.image_pages,
                stack_pages: header.stack_pages,
                heap_pages: header.heap_pages,
                private_pages,
                reserved_resident_pages,
            },
            layout,
        },
    })
}

struct ParsedStreamSegments {
    segments: [Option<LoadSegmentLayout>; MAX_LOAD_RECORDS],
    image_pages: u64,
}

#[allow(clippy::too_many_lines)]
fn parse_stream_segments(
    prefix: &[u8],
    executable_bytes: usize,
    header: ParsedHeader,
    image_base: u64,
) -> Result<ParsedStreamSegments, ParseError> {
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
        let record_end = record_start
            .checked_add(KEX_V1_LOAD_RECORD_BYTES)
            .ok_or(ParseError::ArithmeticOverflow)?;
        let record = prefix
            .get(record_start..record_end)
            .ok_or(ParseError::InvalidLayout)?;
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
        if index != 0 && image_offset < previous_image_end {
            return Err(ParseError::OverlappingSegments);
        }
        if image_end > header.image_span_bytes {
            return Err(ParseError::ImageSpanExceeded);
        }
        if file_offset != expected_file_offset {
            return Err(ParseError::NoncanonicalPayload);
        }
        let file_end = file_offset
            .checked_add(file_bytes)
            .ok_or(ParseError::ArithmeticOverflow)?;
        if file_end > executable_bytes {
            return Err(ParseError::NoncanonicalPayload);
        }
        image_pages = image_pages
            .checked_add(memory_bytes / PAGE_SIZE)
            .ok_or(ParseError::ArithmeticOverflow)?;
        if permissions.executable() {
            executable = true;
            let entry_end = header
                .entry_offset
                .checked_add(1)
                .ok_or(ParseError::ArithmeticOverflow)?;
            entry_is_executable |= header.entry_offset >= image_offset && entry_end <= image_end;
        }
        *destination = Some(LoadSegmentLayout {
            image_base,
            image_offset,
            memory_bytes,
            file_offset: u64::try_from(file_offset).map_err(|_| ParseError::ArithmeticOverflow)?,
            file_byte_count,
            permissions,
        });
        expected_file_offset = file_end;
        previous_image_end = image_end;
    }
    if expected_file_offset != executable_bytes {
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
    Ok(ParsedStreamSegments {
        segments,
        image_pages,
    })
}

fn validate_streamed_relocations(
    plan: &StreamedLoadPlan,
    executable_offset: u64,
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    expected_digest: [u8; 32],
) -> Result<(), StreamError> {
    let start = executable_offset
        .checked_add(plan.relocations_offset)
        .ok_or(StreamError::InvalidLength)?;
    let byte_count = plan
        .relocation_count
        .checked_mul(KEX_V1_RELOCATION_RECORD_BYTES)
        .ok_or(StreamError::InvalidLength)?;
    let image_end = plan
        .segments()
        .try_fold(0_u64, |end, segment| {
            segment
                .image_offset()
                .checked_add(segment.memory_bytes())
                .map(|segment_end| end.max(segment_end))
        })
        .ok_or(StreamError::Executable(ParseError::ArithmeticOverflow))?;
    let mut previous_target = None;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; PAGE_BYTES];
    let mut consumed = 0_usize;
    while consumed < byte_count {
        let count = (byte_count - consumed).min(buffer.len());
        let offset = start
            .checked_add(u64::try_from(consumed).map_err(|_| StreamError::InvalidLength)?)
            .ok_or(StreamError::InvalidLength)?;
        read_stream_exact(read_at, offset, &mut buffer[..count])?;
        hash.update(&buffer[..count]);
        for record in buffer[..count].chunks_exact(KEX_V1_RELOCATION_RECORD_BYTES) {
            let target_offset =
                read_u64(record, RELOCATION_TARGET_OFFSET).map_err(StreamError::Executable)?;
            let value_offset =
                read_u64(record, RELOCATION_VALUE_OFFSET).map_err(StreamError::Executable)?;
            let target_end = target_offset
                .checked_add(8)
                .ok_or(StreamError::Executable(ParseError::InvalidRelocation))?;
            if previous_target.is_some_and(|previous| target_offset <= previous)
                || value_offset >= image_end
                || !plan.segments().any(|segment| {
                    let segment_end = segment.image_offset().checked_add(segment.memory_bytes());
                    segment.image_offset() <= target_offset
                        && segment_end.is_some_and(|end| target_end <= end)
                })
            {
                return Err(StreamError::Executable(ParseError::InvalidRelocation));
            }
            previous_target = Some(target_offset);
        }
        consumed = consumed
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
    }
    if hash.finish() != expected_digest {
        return Err(StreamError::SourceChanged);
    }
    Ok(())
}

fn read_stream_exact(
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    offset: u64,
    destination: &mut [u8],
) -> Result<(), StreamError> {
    let mut filled = 0_usize;
    while filled < destination.len() {
        let current = offset
            .checked_add(u64::try_from(filled).map_err(|_| StreamError::InvalidLength)?)
            .ok_or(StreamError::InvalidLength)?;
        let available = destination.len() - filled;
        let count =
            read_at(current, &mut destination[filled..]).map_err(|()| StreamError::SourceFailed)?;
        if count == 0 || count > available {
            return Err(StreamError::IncompleteRead);
        }
        filled = filled
            .checked_add(count)
            .ok_or(StreamError::InvalidLength)?;
    }
    Ok(())
}

fn hash_overlap(
    hash: &mut Sha256,
    chunk_start: usize,
    chunk: &[u8],
    range_start: usize,
    range_end: usize,
) {
    let Some(chunk_end) = chunk_start.checked_add(chunk.len()) else {
        return;
    };
    let start = chunk_start.max(range_start);
    let end = chunk_end.min(range_end);
    if start < end {
        hash.update(&chunk[start - chunk_start..end - chunk_start]);
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

fn parse_with_limits(
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

fn application_layout(
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
struct ParsedHeader {
    target: Target,
    abi_minor: u16,
    image_span_bytes: u64,
    entry_offset: u64,
    record_count: usize,
    records_offset: usize,
    payload_offset: usize,
    stack_pages: u64,
    heap_pages: u64,
    relocations_offset: usize,
    relocation_count: usize,
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

fn parse_header_with_len(
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

// Incremental FIPS 180-4 SHA-256 used only to bind bounded validation and
// replay passes. It owns 168 bytes of fixed state and performs no allocation.
#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    buffered: usize,
    byte_len: u64,
}

impl Sha256 {
    const fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            block: [0; 64],
            buffered: 0,
            byte_len: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.byte_len = self
            .byte_len
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if self.buffered != 0 {
            let copied = (64 - self.buffered).min(bytes.len());
            self.block[self.buffered..self.buffered + copied].copy_from_slice(&bytes[..copied]);
            self.buffered += copied;
            bytes = &bytes[copied..];
            if self.buffered == 64 {
                Self::compress(&mut self.state, &self.block);
                self.block.fill(0);
                self.buffered = 0;
            }
        }
        while bytes.len() >= 64 {
            let block = <&[u8; 64]>::try_from(&bytes[..64]).unwrap_or_else(|_| unreachable!());
            Self::compress(&mut self.state, block);
            bytes = &bytes[64..];
        }
        self.block[..bytes.len()].copy_from_slice(bytes);
        self.buffered = bytes.len();
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_len = self.byte_len.saturating_mul(8);
        self.block[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.block[self.buffered..].fill(0);
            Self::compress(&mut self.state, &self.block);
            self.block.fill(0);
            self.buffered = 0;
        }
        self.block[self.buffered..56].fill(0);
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress(&mut self.state, &self.block);
        let mut output = [0_u8; 32];
        for (chunk, value) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        output
    }

    #[allow(clippy::many_single_char_names, clippy::unreadable_literal)]
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
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

    #[derive(Clone, Copy)]
    struct TestRelocation {
        target_offset: u64,
        value_offset: u64,
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

    #[allow(clippy::too_many_lines)]
    fn artifact_with_relocations(
        target: Target,
        segments: &[TestSegment<'_>],
        relocations: &[TestRelocation],
    ) -> Vec<u8> {
        let payload_bytes = segments
            .iter()
            .map(|segment| segment.payload.len())
            .sum::<usize>();
        let relocations_offset = KEX_V1_HEADER_BYTES + segments.len() * KEX_V1_LOAD_RECORD_BYTES;
        let payload_offset =
            relocations_offset + relocations.len() * KEX_V1_RELOCATION_RECORD_BYTES;
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
        let image_end = segments
            .iter()
            .map(|segment| segment.image_offset + segment.memory_bytes)
            .max()
            .unwrap_or(0);
        // Degenerate geometries under test can end at zero; keep the header
        // itself well formed so the property under test is what fails.
        let span_bytes =
            canonical_image_span_bytes(image_end.max(1)).unwrap_or_else(|| unreachable!());
        put_u32(
            &mut bytes,
            HEADER_IMAGE_SPAN_PAGES,
            u32::try_from(span_bytes / PAGE_SIZE).unwrap_or_else(|_| unreachable!()),
        );
        put_u64(&mut bytes, HEADER_ENTRY_OFFSET, 0);
        put_u16(&mut bytes, HEADER_RECORD_COUNT, usize_u16(segments.len()));
        put_u64(&mut bytes, HEADER_STACK_PAGES, 4);
        put_u64(&mut bytes, HEADER_HEAP_PAGES, 0);
        put_u32(
            &mut bytes,
            HEADER_RECORDS_OFFSET,
            usize_u32(KEX_V1_HEADER_BYTES),
        );
        put_u32(
            &mut bytes,
            HEADER_RELOCATIONS_OFFSET,
            usize_u32(relocations_offset),
        );
        put_u32(
            &mut bytes,
            HEADER_RELOCATION_COUNT,
            usize_u32(relocations.len()),
        );
        put_u16(
            &mut bytes,
            HEADER_RELOCATION_BYTES,
            usize_u16(KEX_V1_RELOCATION_RECORD_BYTES),
        );
        put_u32(&mut bytes, HEADER_PAYLOAD_OFFSET, usize_u32(payload_offset));
        put_u64(&mut bytes, HEADER_ARTIFACT_BYTES, usize_u64(artifact_bytes));

        for (index, relocation) in relocations.iter().enumerate() {
            let start = relocations_offset + index * KEX_V1_RELOCATION_RECORD_BYTES;
            put_u64(
                &mut bytes,
                start + RELOCATION_TARGET_OFFSET,
                relocation.target_offset,
            );
            put_u64(
                &mut bytes,
                start + RELOCATION_VALUE_OFFSET,
                relocation.value_offset,
            );
        }

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

    fn artifact(target: Target, segments: &[TestSegment<'_>]) -> Vec<u8> {
        artifact_with_relocations(target, segments, &[])
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
    fn package_round_trip_binds_manifest_and_executable() {
        let executable = valid_artifact(Target::X86_64);
        let required = [requirements::Requirement {
            interface: 6,
            major: 1,
            minor: 0,
        }];
        let bytes =
            encode_kex_package(&executable, &required).unwrap_or_else(|_| std::process::abort());
        let package = parse_kex_package(&bytes).unwrap_or_else(|_| std::process::abort());
        assert_eq!(package.executable(), executable);
        assert_eq!(package.requirements().iter().collect::<Vec<_>>(), required);
        assert!(parse_standard(package.executable(), Target::X86_64).is_ok());
        assert_eq!(
            bytes.len(),
            KEX_PACKAGE_V1_HEADER_BYTES
                + requirements::HEADER_BYTES
                + requirements::RECORD_BYTES
                + executable.len()
        );
    }

    #[test]
    fn package_round_trip_binds_and_locates_completion_without_staging_executable() {
        let executable = valid_artifact(Target::X86_64);
        let completion = b"CMPL\t1\techo\n";
        let bytes = encode_kex_package_with_completion(&executable, &[], Some(completion))
            .unwrap_or_else(|_| std::process::abort());
        let package = parse_kex_package(&bytes).unwrap_or_else(|_| std::process::abort());
        assert_eq!(package.completion(), Some(completion.as_slice()));
        let range = kex_package_completion_range(
            &bytes[..KEX_PACKAGE_V1_HEADER_BYTES],
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        )
        .unwrap_or_else(|_| std::process::abort())
        .unwrap_or_else(|| std::process::abort());
        assert_eq!(&bytes[usize::try_from(range.0).unwrap_or(0)..], completion);
        assert_eq!(range.1, completion.len());

        let streamed = parse_streamed_kex_package(
            bytes.len() as u64,
            |offset, destination| {
                let start = usize::try_from(offset).map_err(|_| ())?;
                let count = destination.len().min(bytes.len() - start);
                destination[..count].copy_from_slice(&bytes[start..start + count]);
                Ok(count)
            },
            Target::X86_64,
            ABI_MINOR,
            LoadPlacement::STANDARD,
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            streamed.executable().charges().staging_bytes(),
            STREAM_WORKING_SET_BYTES
        );

        let mut malformed = bytes.clone();
        *malformed.last_mut().unwrap_or_else(|| unreachable!()) = b'x';
        assert_eq!(
            parse_streamed_kex_package(
                malformed.len() as u64,
                |offset, destination| {
                    let start = usize::try_from(offset).map_err(|_| ())?;
                    let count = destination.len().min(malformed.len() - start);
                    destination[..count].copy_from_slice(&malformed[start..start + count]);
                    Ok(count)
                },
                Target::X86_64,
                ABI_MINOR,
                LoadPlacement::STANDARD,
            ),
            Err(StreamError::Package(PackageError::InvalidCompletion))
        );
    }

    #[test]
    fn streamed_package_plan_replays_payload_and_relocations_boundedly() {
        let executable = artifact_with_relocations(
            Target::X86_64,
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
                    payload: &[0; 16],
                },
            ],
            &[TestRelocation {
                target_offset: PAGE_SIZE,
                value_offset: 1,
            }],
        );
        let required = [requirements::Requirement {
            interface: 23,
            major: 1,
            minor: 0,
        }];
        let package =
            encode_kex_package(&executable, &required).unwrap_or_else(|_| std::process::abort());
        let placement = LoadPlacement::new(
            KEX_V1_MIN_IMAGE_BASE + KEX_V1_IMAGE_ALIGNMENT,
            KEX_V1_USER_END - KEX_V1_IMAGE_ALIGNMENT,
        );
        let streamed = parse_streamed_kex_package(
            package.len() as u64,
            |offset, destination| {
                let start = usize::try_from(offset).map_err(|_| ())?;
                let count = destination.len().min(37).min(package.len() - start);
                destination[..count].copy_from_slice(&package[start..start + count]);
                Ok(count)
            },
            Target::X86_64,
            ABI_MINOR,
            placement,
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(streamed.requirements().iter().collect::<Vec<_>>(), required);
        let conventional = parse_kex_at(&executable, Target::X86_64, ABI_MINOR, placement)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            streamed.executable().entry_address(),
            conventional.entry_address()
        );
        assert_eq!(
            streamed.executable().charges().private_pages(),
            conventional.charges().private_pages()
        );
        assert_eq!(
            streamed.executable().charges().staging_bytes(),
            STREAM_WORKING_SET_BYTES
        );
        let mut copied = [Vec::new(), Vec::new()];
        stream_verified_segments(
            &streamed,
            |offset, destination| {
                let start = usize::try_from(offset).map_err(|_| ())?;
                let count = destination.len().min(package.len() - start);
                destination[..count].copy_from_slice(&package[start..start + count]);
                Ok(count)
            },
            |segment, offset, bytes| {
                assert_eq!(usize::try_from(offset), Ok(copied[segment].len()));
                copied[segment].extend_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(copied[0], [0x90, 0xc3]);
        assert_eq!(copied[1], [0; 16]);
        let mut relocations = Vec::new();
        visit_verified_relocations(
            &streamed,
            |offset, destination| {
                let start = usize::try_from(offset).map_err(|_| ())?;
                let count = destination.len().min(package.len() - start);
                destination[..count].copy_from_slice(&package[start..start + count]);
                Ok(count)
            },
            |relocation| {
                relocations.push(relocation);
                Ok(())
            },
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(relocations.len(), 1);
        assert_eq!(relocations[0].target_offset(), PAGE_SIZE);
        assert_eq!(relocations[0].value_offset(), 1);
    }

    #[test]
    fn streamed_package_detects_payload_and_relocation_changes_before_activation() {
        let executable = artifact_with_relocations(
            Target::X86_64,
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
                    payload: &[0; 16],
                },
            ],
            &[TestRelocation {
                target_offset: PAGE_SIZE,
                value_offset: 1,
            }],
        );
        let mut package =
            encode_kex_package(&executable, &[]).unwrap_or_else(|_| std::process::abort());
        let placement = LoadPlacement::new(
            KEX_V1_MIN_IMAGE_BASE + KEX_V1_IMAGE_ALIGNMENT,
            KEX_V1_USER_END - KEX_V1_IMAGE_ALIGNMENT,
        );
        let streamed = parse_streamed_kex_package(
            package.len() as u64,
            |offset, destination| {
                let start = usize::try_from(offset).map_err(|_| ())?;
                let count = destination.len().min(package.len() - start);
                destination[..count].copy_from_slice(&package[start..start + count]);
                Ok(count)
            },
            Target::X86_64,
            ABI_MINOR,
            placement,
        )
        .unwrap_or_else(|_| std::process::abort());
        let payload = usize::try_from(streamed.executable_offset)
            .unwrap_or(0)
            .checked_add(
                usize::try_from(
                    streamed
                        .executable()
                        .segments()
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .file_offset(),
                )
                .unwrap_or(0),
            )
            .unwrap_or(0);
        package[payload] ^= 1;
        assert_eq!(
            stream_verified_segments(
                &streamed,
                |offset, destination| {
                    let start = usize::try_from(offset).map_err(|_| ())?;
                    let count = destination.len().min(package.len() - start);
                    destination[..count].copy_from_slice(&package[start..start + count]);
                    Ok(count)
                },
                |_segment, _offset, _bytes| Ok(()),
            ),
            Err(StreamError::SourceChanged)
        );
    }

    #[test]
    fn streamed_package_rejects_oversize_without_reading() {
        let mut reads = 0;
        assert_eq!(
            parse_streamed_kex_package(
                MAX_KEX_PACKAGE_BYTES as u64 + 1,
                |_offset, _destination| {
                    reads += 1;
                    Ok(0)
                },
                Target::X86_64,
                ABI_MINOR,
                LoadPlacement::STANDARD,
            ),
            Err(StreamError::InvalidLength)
        );
        assert_eq!(reads, 0);
    }

    #[test]
    fn package_parser_rejects_every_noncanonical_boundary() {
        let executable = valid_artifact(Target::Aarch64);
        let canonical =
            encode_kex_package(&executable, &[]).unwrap_or_else(|_| std::process::abort());
        for end in 0..canonical.len() {
            assert!(parse_kex_package(&canonical[..end]).is_err());
        }

        let mut invalid = canonical.clone();
        invalid[0] ^= 1;
        assert_eq!(parse_kex_package(&invalid), Err(PackageError::InvalidMagic));
        invalid = canonical.clone();
        put_u16(&mut invalid, PACKAGE_HEADER_MAJOR, 2);
        assert_eq!(
            parse_kex_package(&invalid),
            Err(PackageError::UnsupportedVersion)
        );
        invalid = canonical.clone();
        put_u16(&mut invalid, PACKAGE_HEADER_FLAGS, 2);
        assert_eq!(
            parse_kex_package(&invalid),
            Err(PackageError::NonzeroReserved)
        );
        invalid = canonical.clone();
        put_u32(&mut invalid, PACKAGE_HEADER_MANIFEST_OFFSET, 0);
        assert_eq!(
            parse_kex_package(&invalid),
            Err(PackageError::InvalidLayout)
        );
        invalid = canonical.clone();
        invalid[KEX_PACKAGE_V1_HEADER_BYTES] ^= 1;
        assert_eq!(
            parse_kex_package(&invalid),
            Err(PackageError::InvalidManifest)
        );
        invalid = canonical.clone();
        put_u64(
            &mut invalid,
            PACKAGE_HEADER_PACKAGE_BYTES,
            usize_u64(canonical.len() - 1),
        );
        assert_eq!(
            parse_kex_package(&invalid),
            Err(PackageError::LengthMismatch)
        );
        invalid = canonical.clone();
        invalid.push(0);
        assert_eq!(
            parse_kex_package(&invalid),
            Err(PackageError::LengthMismatch)
        );

        let executable_offset = usize::try_from(
            read_package_u32(&canonical, PACKAGE_HEADER_EXECUTABLE_OFFSET)
                .unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!());
        invalid = canonical;
        invalid[executable_offset] ^= 1;
        let package = parse_kex_package(&invalid).unwrap_or_else(|_| unreachable!());
        assert!(parse_standard(package.executable(), Target::Aarch64).is_err());
    }

    #[test]
    fn package_encoder_rejects_invalid_inputs_without_output() {
        assert_eq!(
            encode_kex_package(&[], &[]),
            Err(PackageEncodeError::InvalidExecutable)
        );
        let executable = valid_artifact(Target::X86_64);
        let duplicate = [
            requirements::Requirement {
                interface: 6,
                major: 1,
                minor: 0,
            },
            requirements::Requirement {
                interface: 6,
                major: 1,
                minor: 0,
            },
        ];
        assert_eq!(
            encode_kex_package(&executable, &duplicate),
            Err(PackageEncodeError::InvalidManifest)
        );
    }

    #[test]
    fn valid_plan_is_ordered_bounded_and_exactly_charged() {
        for target in [Target::X86_64, Target::Aarch64] {
            let bytes = valid_artifact(target);
            let plan = parse_standard(&bytes, target).unwrap_or_else(|_| unreachable!());
            let segments = plan.segments().collect::<Vec<_>>();

            assert_eq!(plan.target(), target);
            assert_eq!(plan.abi_minor(), ABI_MINOR);
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
            assert_eq!(
                plan.charges().reserved_resident_pages(),
                7 + maximum_table_pages(7).unwrap_or_else(|| unreachable!())
            );
            let layout = plan.layout();
            assert_eq!(
                layout.startup_address(),
                KEX_V1_IMAGE_BASE + KEX_V1_IMAGE_ALIGNMENT
            );
            assert_eq!(layout.heap_bytes(), 0);
            assert_eq!(layout.stack_top() - layout.stack_bottom(), 4 * PAGE_SIZE);
            assert_eq!(layout.upper_guard_address(), layout.stack_top());
            assert!(layout.lower_guard_address() < layout.stack_bottom());
        }
    }

    #[test]
    fn relative_relocations_and_randomized_placement_are_exact() {
        let segments = [
            TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[0x90, 0xc3],
            },
            TestSegment {
                image_offset: PAGE_SIZE,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadOnly as u32,
                payload: &[0; 16],
            },
        ];
        let relocation = [TestRelocation {
            target_offset: PAGE_SIZE,
            value_offset: 1,
        }];
        let artifact = artifact_with_relocations(Target::X86_64, &segments, &relocation);
        let placement = LoadPlacement::new(
            KEX_V1_MIN_IMAGE_BASE + 6 * KEX_V1_IMAGE_ALIGNMENT,
            0x0000_7000_1000_0000,
        );
        let plan = parse_kex_at(&artifact, Target::X86_64, ABI_MINOR, placement)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(plan.image_base(), placement.image_base());
        assert_eq!(plan.entry_address(), placement.image_base());
        assert_eq!(plan.layout().stack_top(), placement.stack_top());
        assert_eq!(
            plan.segments().nth(1).map(LoadSegment::virtual_address),
            Some(placement.image_base() + PAGE_SIZE)
        );
        assert_eq!(
            plan.relocations().collect::<Vec<_>>(),
            [RelativeRelocation {
                target_offset: PAGE_SIZE,
                value_offset: 1,
            }]
        );

        let mut invalid = artifact.clone();
        put_u64(
            &mut invalid,
            KEX_V1_HEADER_BYTES
                + segments.len() * KEX_V1_LOAD_RECORD_BYTES
                + RELOCATION_TARGET_OFFSET,
            2 * PAGE_SIZE,
        );
        assert_eq!(
            parse_kex_at(&invalid, Target::X86_64, ABI_MINOR, placement),
            Err(ParseError::InvalidRelocation)
        );
        assert_eq!(
            parse_kex_at(
                &artifact,
                Target::X86_64,
                ABI_MINOR,
                LoadPlacement::new(0, placement.stack_top())
            ),
            Err(ParseError::InvalidPlacement)
        );
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
    fn legacy_startup_page_retains_abi_and_layout() {
        let current_bytes = valid_artifact(Target::X86_64);
        let current =
            parse_standard(&current_bytes, Target::X86_64).unwrap_or_else(|_| unreachable!());
        let mut legacy_bytes = current_bytes.clone();
        put_u16(&mut legacy_bytes, HEADER_ABI_MINOR, 0);
        put_u32(&mut legacy_bytes, HEADER_IMAGE_SPAN_PAGES, 0);
        let legacy =
            parse_standard(&legacy_bytes, Target::X86_64).unwrap_or_else(|_| unreachable!());
        let mut legacy_page = [0_u8; PAGE_BYTES];
        legacy
            .encode_startup_page(
                StartupInfo {
                    task_id: 43,
                    handles: &[],
                },
                &mut legacy_page,
            )
            .unwrap_or_else(|_| unreachable!());

        assert_eq!(read_u16(&legacy_page, 6), Ok(0));
        assert_ne!(legacy.layout().stack_top(), current.layout().stack_top());
        assert_eq!(
            legacy.layout().lower_guard_address(),
            legacy.layout().heap_address() + ApplicationLimits::standard().heap_pages() * PAGE_SIZE
        );
    }

    #[test]
    fn standard_limits_match_current_policy() {
        let standard = ApplicationLimits::standard();

        assert_eq!(standard.encoded_bytes(), 2 * 1024 * 1024 * 1024);
        assert_eq!(standard.load_records(), 16);
        assert_eq!(standard.maximum_image_span_bytes(), 1024 * 1024 * 1024);
        assert_eq!(standard.stack_pages(), (4, 1 << 32));
        assert_eq!(standard.heap_pages(), 1 << 32);
        let maximum_private = 2 * (1 << 32) + MAX_IMAGE_SPAN_PAGES + 1;
        assert_eq!(
            standard.resident_pages(),
            maximum_private
                + maximum_table_pages(maximum_private).unwrap_or_else(|| unreachable!())
        );
        assert_eq!(standard.initial_handles(), 32);
    }

    #[test]
    fn format_identifier_is_product_name_independent() {
        assert_eq!(KEX_V1_MAGIC, *b"KEX\0FMT\0");
    }

    #[test]
    fn rejects_executable_above_the_encoded_ceiling_without_staging_it() {
        // The ceiling is far larger than any artifact worth materializing, so
        // this drives the streamed path, which decides from declared lengths
        // inside a fixed working set rather than from a staged copy.
        let executable = artifact(
            Target::X86_64,
            &[TestSegment {
                image_offset: 0,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[0x90, 0xc3],
            }],
        );
        let mut package =
            encode_kex_package(&executable, &[]).unwrap_or_else(|_| std::process::abort());
        let oversize = u64::try_from(ApplicationLimits::STANDARD.encoded_bytes)
            .unwrap_or_else(|_| unreachable!())
            + 1;
        write_u64(&mut package, PACKAGE_HEADER_EXECUTABLE_BYTES, oversize);
        let mut reads = 0;
        assert_eq!(
            parse_streamed_kex_package(
                package.len() as u64,
                |offset, destination| {
                    reads += 1;
                    let start = usize::try_from(offset).map_err(|_| ())?;
                    let count = destination.len().min(package.len() - start);
                    destination[..count].copy_from_slice(&package[start..start + count]);
                    Ok(count)
                },
                Target::X86_64,
                ABI_MINOR,
                LoadPlacement::STANDARD,
            )
            .err(),
            Some(StreamError::Package(PackageError::InvalidLayout))
        );
        assert!(reads <= 2);
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
        for offset in [HEADER_FLAGS, HEADER_RESERVED16] {
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

        // A sparse image is admitted, and its declared span covers it exactly.
        let mut sparse = artifact(
            Target::X86_64,
            &[TestSegment {
                image_offset: 64 * KEX_V1_IMAGE_ALIGNMENT,
                memory_bytes: PAGE_SIZE,
                permissions: SegmentPermissions::ReadExecute as u32,
                payload: &[1],
            }],
        );
        put_u64(
            &mut sparse,
            HEADER_ENTRY_OFFSET,
            64 * KEX_V1_IMAGE_ALIGNMENT,
        );
        let sparse_plan =
            parse_standard(&sparse, Target::X86_64).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            sparse_plan.layout().startup_address(),
            LoadPlacement::STANDARD.image_base + 65 * KEX_V1_IMAGE_ALIGNMENT
        );

        // Shrinking the declared span below the image rejects the segment.
        let mut shrunk = sparse.clone();
        put_u32(
            &mut shrunk,
            HEADER_IMAGE_SPAN_PAGES,
            u32::try_from(64 * KEX_V1_IMAGE_ALIGNMENT / PAGE_SIZE)
                .unwrap_or_else(|_| unreachable!()),
        );
        assert_eq!(
            parse_standard(&shrunk, Target::X86_64),
            Err(ParseError::ImageSpanExceeded)
        );

        // Growing it past the canonical span reserves unmapped address space.
        let mut padded = sparse.clone();
        put_u32(
            &mut padded,
            HEADER_IMAGE_SPAN_PAGES,
            u32::try_from(66 * KEX_V1_IMAGE_ALIGNMENT / PAGE_SIZE)
                .unwrap_or_else(|_| unreachable!()),
        );
        assert_eq!(
            parse_standard(&padded, Target::X86_64),
            Err(ParseError::InvalidImageSpan)
        );

        // A span above the standard policy is refused before any segment work.
        let mut oversize = sparse.clone();
        put_u32(
            &mut oversize,
            HEADER_IMAGE_SPAN_PAGES,
            u32::try_from(MAX_IMAGE_SPAN_PAGES + KEX_V1_IMAGE_ALIGNMENT / PAGE_SIZE)
                .unwrap_or_else(|_| unreachable!()),
        );
        assert_eq!(
            parse_standard(&oversize, Target::X86_64),
            Err(ParseError::InvalidImageSpan)
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
        for stack_pages in [0_u64, 3, (1 << 32) + 1] {
            let mut bytes = valid.clone();
            put_u64(&mut bytes, HEADER_STACK_PAGES, stack_pages);
            assert_eq!(
                parse_standard(&bytes, Target::X86_64),
                Err(ParseError::StackBudgetExceeded)
            );
        }
        let mut heap = valid.clone();
        put_u64(&mut heap, HEADER_HEAP_PAGES, (1 << 32) + 1);
        assert_eq!(
            parse_standard(&heap, Target::X86_64),
            Err(ParseError::HeapBudgetExceeded)
        );

        let limits = ApplicationLimits {
            resident_pages: 16,
            ..ApplicationLimits::STANDARD
        };
        assert_eq!(
            parse_with_limits(
                &valid,
                Target::X86_64,
                ABI_MINOR,
                limits,
                LoadPlacement::STANDARD,
            ),
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
        let valid = include!("../../../../tests/kex-corpus/valid.inc");
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
                plan.charges().private_pages()
                    + maximum_table_pages(plan.charges().private_pages())
                        .unwrap_or_else(|| unreachable!()),
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
            if name.contains("max-records") {
                assert_eq!(segments.len(), limits.load_records(), "{name}");
            }
            if name.contains("max-span") {
                let last = segments.last().unwrap_or_else(|| unreachable!());
                assert_eq!(
                    last.image_offset() + last.memory_bytes(),
                    limits.maximum_image_span_bytes(),
                    "{name}"
                );
            }
            if name.contains("minimum-span") {
                let last = segments.last().unwrap_or_else(|| unreachable!());
                assert!(
                    last.image_offset() + last.memory_bytes() <= KEX_V1_IMAGE_ALIGNMENT,
                    "{name}"
                );
            }
            if name.contains("max-stack-heap") {
                assert_eq!(plan.stack_pages(), limits.stack_pages().1, "{name}");
                assert_eq!(plan.heap_pages(), limits.heap_pages(), "{name}");
            }
        }

        let x86_rejections = include!("../../../../tests/kex-corpus/rejections-x86_64.inc");
        for (name, bytes, expected) in x86_rejections {
            assert_eq!(
                parse_kex(bytes, Target::X86_64, ABI_MINOR),
                Err(expected),
                "{name}"
            );
        }
        let arm_rejections = include!("../../../../tests/kex-corpus/rejections-aarch64.inc");
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
            put_u64(&mut bytes, HEADER_STACK_PAGES, u64::from(stack_pages));
            put_u64(&mut bytes, HEADER_HEAP_PAGES, u64::from(heap_pages));
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
                plan.charges().private_pages()
                    + maximum_table_pages(plan.charges().private_pages())
                        .unwrap_or_else(|| unreachable!())
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

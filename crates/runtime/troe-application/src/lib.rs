//! Bounded package, executable, and load-plan policy for KEX application artifacts.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod bytes;
mod executable;
mod limits;
mod package;
mod plan;
mod sha256;
mod startup;
mod stream;
#[cfg(test)]
mod tests;
mod transaction;

use troe_abi::requirements;
pub use troe_abi::{ABI_MAJOR, ABI_MINOR};

pub use executable::{
    LoadPlacement, ParseError, SegmentPermissions, Target, parse_kex, parse_kex_at,
};
pub use limits::{ApplicationLimits, canonical_image_span_bytes, maximum_table_pages};
pub use package::{
    KexPackage, PackageEncodeError, PackageError, encode_kex_package,
    encode_kex_package_with_completion, kex_package_completion_range, parse_kex_package,
};
pub use plan::{
    ApplicationLayout, LoadCharges, LoadPlan, LoadSegment, LoadSegmentLayout, RelativeRelocation,
};
pub use startup::{InitialHandle, StartupInfo, StartupPageError};
pub use stream::{
    StreamError, StreamedKexPackage, StreamedLoadPlan, parse_streamed_kex_package,
    stream_verified_segments, visit_verified_relocations,
};
pub use transaction::{LoaderResource, LoaderTransaction, LoaderTransactionError};

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
/// Fixed prefix retained while parsing a streamed KEX package.
///
/// This covers the largest package header, capability manifest, executable
/// header, and sixteen load records. Relocations and payload bytes are never
/// retained as a whole.
pub const STREAM_PREFIX_BYTES: usize = PAGE_BYTES;
/// Peak byte buffers used by the format-side streaming verifier.
pub const STREAM_WORKING_SET_BYTES: usize = 2 * PAGE_BYTES + troe_completion::MAX_ARTIFACT_BYTES;

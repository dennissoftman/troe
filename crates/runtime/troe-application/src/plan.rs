//! Load segments, relocations, charges, and the resulting load plan.

use crate::startup::encode_startup_page;
use crate::{
    KEX_V1_RELOCATION_RECORD_BYTES, MAX_LOAD_RECORDS, PAGE_BYTES, RELOCATION_TARGET_OFFSET,
    RELOCATION_VALUE_OFFSET, SegmentPermissions, StartupInfo, StartupPageError, Target,
};

/// One validated KEX load segment borrowing its staged payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment<'artifact> {
    pub(crate) image_base: u64,
    pub(crate) image_offset: u64,
    pub(crate) memory_bytes: u64,
    pub(crate) file_offset: u64,
    pub(crate) file_byte_count: u64,
    pub(crate) permissions: SegmentPermissions,
    pub(crate) file_bytes: &'artifact [u8],
}

/// Pointer-free geometry for one validated KEX load segment.
///
/// Unlike [`LoadSegment`], this value does not borrow the complete artifact.
/// It is therefore suitable for a bounded streaming loader which retains only
/// format metadata while copying payload ranges directly into inactive frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegmentLayout {
    pub(crate) image_base: u64,
    pub(crate) image_offset: u64,
    pub(crate) memory_bytes: u64,
    pub(crate) file_offset: u64,
    pub(crate) file_byte_count: u64,
    pub(crate) permissions: SegmentPermissions,
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
    pub(crate) target_offset: u64,
    pub(crate) value_offset: u64,
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
    pub(crate) staging_bytes: usize,
    pub(crate) image_pages: u64,
    pub(crate) stack_pages: u64,
    pub(crate) heap_pages: u64,
    pub(crate) private_pages: u64,
    pub(crate) reserved_resident_pages: u64,
}

/// Canonical KEX v1 virtual placement outside the standard image window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationLayout {
    pub(crate) startup_address: u64,
    pub(crate) heap_address: u64,
    pub(crate) heap_bytes: u64,
    pub(crate) stack_bottom: u64,
    pub(crate) stack_top: u64,
    pub(crate) lower_guard_address: u64,
    pub(crate) upper_guard_address: u64,
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
    pub(crate) target: Target,
    pub(crate) abi_minor: u16,
    pub(crate) image_base: u64,
    pub(crate) entry_offset: u64,
    pub(crate) stack_pages: u64,
    pub(crate) heap_pages: u64,
    pub(crate) segments: [Option<LoadSegment<'artifact>>; MAX_LOAD_RECORDS],
    pub(crate) segment_count: usize,
    pub(crate) relocations: &'artifact [u8],
    pub(crate) relocation_count: usize,
    pub(crate) charges: LoadCharges,
    pub(crate) layout: ApplicationLayout,
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

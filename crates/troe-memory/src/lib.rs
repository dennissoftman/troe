//! Bounded, architecture-independent physical-memory ownership models.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Size of one base physical page.
pub const BASE_PAGE_SIZE: u64 = 4096;
/// Maximum firmware descriptors accepted by the normalization boundary.
pub const MAX_FIRMWARE_REGIONS: usize = 256;
/// Maximum explicit reservations accepted during early boot.
pub const MAX_RESERVATIONS: usize = 64;
/// Maximum normalized ranges produced after reservation splitting.
pub const MAX_NORMALIZED_REGIONS: usize = 512;
/// Maximum mappings accepted by the initial single-address-space plan.
pub const MAX_MAPPINGS: usize = 512;
/// Maximum physical frames tracked by the initial bitmap (256 GiB at 4 KiB).
pub const MAX_MANAGED_FRAMES: u64 = 64 * 1024 * 1024;

/// Failures produced while validating and normalizing physical memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMapError {
    /// A range begins at an address that is not base-page aligned.
    Unaligned,
    /// A range has no pages.
    Empty,
    /// Address or accounting arithmetic overflowed.
    Overflow,
    /// Two firmware-provided ranges overlap.
    FirmwareOverlap,
    /// A reservation includes bytes absent from the firmware map.
    ReservationUnmapped,
    /// An input or normalized range count exceeds its explicit bound.
    TooManyRegions,
}

impl fmt::Display for MemoryMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unaligned => formatter.write_str("physical range is not page aligned"),
            Self::Empty => formatter.write_str("physical range is empty"),
            Self::Overflow => formatter.write_str("physical range arithmetic overflowed"),
            Self::FirmwareOverlap => formatter.write_str("firmware memory ranges overlap"),
            Self::ReservationUnmapped => {
                formatter.write_str("reservation is not fully covered by the firmware map")
            }
            Self::TooManyRegions => formatter.write_str("memory region bound exceeded"),
        }
    }
}

/// A checked, half-open, base-page-aligned physical address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    start: u64,
    end: u64,
}

/// A checked, half-open, base-page-aligned virtual address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualRange {
    start: u64,
    end: u64,
}

impl VirtualRange {
    /// Construct a virtual range from a base address and page count.
    ///
    /// # Errors
    ///
    /// Rejects an unaligned start, zero pages, or checked arithmetic overflow.
    pub fn from_pages(start: u64, page_count: u64) -> Result<Self, MappingPlanError> {
        if !start.is_multiple_of(BASE_PAGE_SIZE) {
            return Err(MappingPlanError::Unaligned);
        }
        if page_count == 0 {
            return Err(MappingPlanError::Empty);
        }
        let byte_count = page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(MappingPlanError::Overflow)?;
        let end = start
            .checked_add(byte_count)
            .ok_or(MappingPlanError::Overflow)?;
        Ok(Self { start, end })
    }

    /// First byte in the range.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// First byte after the range.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Number of bytes in the range.
    #[must_use]
    pub const fn byte_count(self) -> u64 {
        self.end - self.start
    }

    /// Number of base pages in the range.
    #[must_use]
    pub const fn page_count(self) -> u64 {
        self.byte_count() / BASE_PAGE_SIZE
    }
}

/// Access permissions for one virtual mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPermissions {
    /// Reads are permitted.
    pub read: bool,
    /// Writes are permitted.
    pub write: bool,
    /// Instruction fetches are permitted.
    pub execute: bool,
}

impl MappingPermissions {
    /// Read-only, non-executable memory.
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    /// Read/write, non-executable memory.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    /// Read/execute, immutable memory.
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}

/// Cache and ordering behavior required by a mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingMemoryType {
    /// Cacheable ordinary RAM or image memory.
    Normal,
    /// Strongly ordered, non-executable device registers.
    Device,
}

/// Component that owns the mapped bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingOwner {
    /// Immutable or executable bytes in the loaded kernel image.
    KernelImage,
    /// Runtime RAM owned by the kernel.
    KernelRuntime,
    /// Architecture-selected device registers.
    MachineDevice,
    /// Private pages retained by one isolated task address space.
    IsolatedTask,
}

/// Lifetime promised for a mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingLifetime {
    /// Required only while composing the owned machine.
    Boot,
    /// Required for the lifetime of the kernel address space.
    Kernel,
    /// Retained only until one isolated task is terminated and reaped.
    Task,
}

/// Least-privileged execution level allowed to traverse one mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPrivilege {
    /// Accessible only while executing in the kernel privilege level.
    Kernel,
    /// Accessible from the unprivileged task execution level.
    User,
}

/// One architecture-neutral virtual-to-physical mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mapping {
    virtual_range: VirtualRange,
    physical_range: PhysicalRange,
    permissions: MappingPermissions,
    memory_type: MappingMemoryType,
    owner: MappingOwner,
    lifetime: MappingLifetime,
    remappable: bool,
    privilege: MappingPrivilege,
}

impl Mapping {
    /// Construct a checked mapping record.
    ///
    /// # Errors
    ///
    /// Rejects unequal range lengths, unreadable mappings, writable executable
    /// mappings, and executable device memory.
    pub fn new(
        virtual_range: VirtualRange,
        physical_range: PhysicalRange,
        permissions: MappingPermissions,
        memory_type: MappingMemoryType,
        owner: MappingOwner,
        lifetime: MappingLifetime,
        remappable: bool,
    ) -> Result<Self, MappingPlanError> {
        if virtual_range.byte_count() != physical_range.byte_count() {
            return Err(MappingPlanError::LengthMismatch);
        }
        if !permissions.read {
            return Err(MappingPlanError::Unreadable);
        }
        if permissions.write && permissions.execute {
            return Err(MappingPlanError::WritableExecutable);
        }
        if memory_type == MappingMemoryType::Device && permissions.execute {
            return Err(MappingPlanError::ExecutableDevice);
        }
        Ok(Self {
            virtual_range,
            physical_range,
            permissions,
            memory_type,
            owner,
            lifetime,
            remappable,
            privilege: MappingPrivilege::Kernel,
        })
    }

    /// Construct a checked user-accessible mapping.
    ///
    /// Device memory cannot be exposed through this constructor. Stage 6 user
    /// tasks receive services through copied messages rather than ambient MMIO.
    ///
    /// # Errors
    ///
    /// Returns the ordinary mapping validation errors, or
    /// [`MappingPlanError::InvalidUserOwner`] for non-task ownership/lifetime.
    pub fn user(
        virtual_range: VirtualRange,
        physical_range: PhysicalRange,
        permissions: MappingPermissions,
        owner: MappingOwner,
        lifetime: MappingLifetime,
    ) -> Result<Self, MappingPlanError> {
        if owner != MappingOwner::IsolatedTask || lifetime != MappingLifetime::Task {
            return Err(MappingPlanError::InvalidUserOwner);
        }
        let mut mapping = Self::new(
            virtual_range,
            physical_range,
            permissions,
            MappingMemoryType::Normal,
            owner,
            lifetime,
            false,
        )?;
        mapping.privilege = MappingPrivilege::User;
        Ok(mapping)
    }

    /// Construct an identity mapping over one physical range.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::new`].
    pub fn identity(
        range: PhysicalRange,
        permissions: MappingPermissions,
        memory_type: MappingMemoryType,
        owner: MappingOwner,
        lifetime: MappingLifetime,
        remappable: bool,
    ) -> Result<Self, MappingPlanError> {
        let virtual_range = VirtualRange::from_pages(range.start(), range.page_count())?;
        Self::new(
            virtual_range,
            range,
            permissions,
            memory_type,
            owner,
            lifetime,
            remappable,
        )
    }

    /// Virtual range covered by this record.
    #[must_use]
    pub const fn virtual_range(self) -> VirtualRange {
        self.virtual_range
    }

    /// Physical range backing this record.
    #[must_use]
    pub const fn physical_range(self) -> PhysicalRange {
        self.physical_range
    }

    /// Access permissions enforced by the backend.
    #[must_use]
    pub const fn permissions(self) -> MappingPermissions {
        self.permissions
    }

    /// Cache and ordering classification.
    #[must_use]
    pub const fn memory_type(self) -> MappingMemoryType {
        self.memory_type
    }

    /// Mapping owner.
    #[must_use]
    pub const fn owner(self) -> MappingOwner {
        self.owner
    }

    /// Mapping lifetime.
    #[must_use]
    pub const fn lifetime(self) -> MappingLifetime {
        self.lifetime
    }

    /// Whether a later, explicitly authorized replacement may change it.
    #[must_use]
    pub const fn remappable(self) -> bool {
        self.remappable
    }

    /// Least-privileged execution level allowed to use the mapping.
    #[must_use]
    pub const fn privilege(self) -> MappingPrivilege {
        self.privilege
    }
}

/// Failures produced while constructing a virtual mapping plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPlanError {
    /// A range begins at an address that is not base-page aligned.
    Unaligned,
    /// A range contains no pages.
    Empty,
    /// Address or page-count arithmetic overflowed.
    Overflow,
    /// Virtual and physical ranges have different lengths.
    LengthMismatch,
    /// The requested access cannot be represented as a readable mapping.
    Unreadable,
    /// A mapping requested write and execute permission simultaneously.
    WritableExecutable,
    /// Device memory requested execute permission.
    ExecutableDevice,
    /// A user mapping did not carry isolated-task ownership and lifetime.
    InvalidUserOwner,
    /// Two virtual ranges overlap.
    VirtualOverlap,
    /// Two mappings refer to overlapping physical bytes.
    PhysicalOverlap,
    /// The explicit mapping-count bound was exceeded.
    TooManyMappings,
}

impl fmt::Display for MappingPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unaligned => formatter.write_str("mapping range is not page aligned"),
            Self::Empty => formatter.write_str("mapping range is empty"),
            Self::Overflow => formatter.write_str("mapping arithmetic overflowed"),
            Self::LengthMismatch => formatter.write_str("mapping range lengths differ"),
            Self::Unreadable => formatter.write_str("mapping is not readable"),
            Self::WritableExecutable => formatter.write_str("mapping is writable and executable"),
            Self::ExecutableDevice => formatter.write_str("device mapping is executable"),
            Self::InvalidUserOwner => {
                formatter.write_str("user mapping lacks isolated-task ownership")
            }
            Self::VirtualOverlap => formatter.write_str("virtual mappings overlap"),
            Self::PhysicalOverlap => formatter.write_str("physical mappings overlap"),
            Self::TooManyMappings => formatter.write_str("mapping plan bound exceeded"),
        }
    }
}

/// Sorted, virtually non-overlapping mappings for one address space.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MappingPlan {
    mappings: Vec<Mapping>,
}

impl MappingPlan {
    /// Construct an empty plan.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mappings: Vec::new(),
        }
    }

    /// Insert one mapping while preserving sorted, non-overlapping order.
    ///
    /// # Errors
    ///
    /// Rejects virtual overlap, unsafe physical aliases, and plans above
    /// [`MAX_MAPPINGS`]. Read-only aliases and RW/NX aliases are allowed; any
    /// physical alias that would combine write and execute permission is not.
    pub fn insert(&mut self, mapping: Mapping) -> Result<(), MappingPlanError> {
        if self.mappings.len() >= MAX_MAPPINGS {
            return Err(MappingPlanError::TooManyMappings);
        }
        let start = mapping.virtual_range.start;
        let index = self
            .mappings
            .partition_point(|existing| existing.virtual_range.start < start);
        if index > 0 && self.mappings[index - 1].virtual_range.end > start {
            return Err(MappingPlanError::VirtualOverlap);
        }
        if index < self.mappings.len()
            && mapping.virtual_range.end > self.mappings[index].virtual_range.start
        {
            return Err(MappingPlanError::VirtualOverlap);
        }
        for existing in &self.mappings {
            if ranges_overlap(existing.physical_range, mapping.physical_range)
                && !physical_alias_is_safe(*existing, mapping)
            {
                return Err(MappingPlanError::PhysicalOverlap);
            }
        }
        self.mappings
            .try_reserve(1)
            .map_err(|_| MappingPlanError::TooManyMappings)?;
        self.mappings.insert(index, mapping);
        Ok(())
    }

    /// Sorted mapping records.
    #[must_use]
    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }

    /// Number of base pages described by the plan.
    ///
    /// # Errors
    ///
    /// Returns [`MappingPlanError::Overflow`] if the sum cannot be represented.
    pub fn page_count(&self) -> Result<u64, MappingPlanError> {
        self.mappings.iter().try_fold(0_u64, |total, mapping| {
            total
                .checked_add(mapping.virtual_range.page_count())
                .ok_or(MappingPlanError::Overflow)
        })
    }

    /// Whether the complete plan preserves W^X across virtual and physical aliases.
    #[must_use]
    pub fn enforces_global_w_xor_x(&self) -> bool {
        for (index, mapping) in self.mappings.iter().enumerate() {
            if mapping.permissions.write && mapping.permissions.execute {
                return false;
            }
            for other in &self.mappings[index + 1..] {
                if ranges_overlap(mapping.physical_range, other.physical_range)
                    && !physical_alias_is_safe(*mapping, *other)
                {
                    return false;
                }
            }
        }
        true
    }
}

fn physical_alias_is_safe(left: Mapping, right: Mapping) -> bool {
    if left.memory_type != right.memory_type {
        return false;
    }
    let writable = left.permissions.write || right.permissions.write;
    let executable = left.permissions.execute || right.permissions.execute;
    !(writable && executable)
}

const fn ranges_overlap(left: PhysicalRange, right: PhysicalRange) -> bool {
    left.start < right.end && right.start < left.end
}

impl PhysicalRange {
    /// Construct a range from a base address and page count.
    ///
    /// # Errors
    ///
    /// Rejects an unaligned start, zero pages, or checked arithmetic overflow.
    pub fn from_pages(start: u64, page_count: u64) -> Result<Self, MemoryMapError> {
        if !start.is_multiple_of(BASE_PAGE_SIZE) {
            return Err(MemoryMapError::Unaligned);
        }
        if page_count == 0 {
            return Err(MemoryMapError::Empty);
        }
        let byte_count = page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(MemoryMapError::Overflow)?;
        let end = start
            .checked_add(byte_count)
            .ok_or(MemoryMapError::Overflow)?;
        Ok(Self { start, end })
    }

    /// First byte in the range.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// First byte after the range.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Number of bytes in the range.
    #[must_use]
    pub const fn byte_count(self) -> u64 {
        self.end - self.start
    }

    /// Number of base pages in the range.
    #[must_use]
    pub const fn page_count(self) -> u64 {
        self.byte_count() / BASE_PAGE_SIZE
    }

    /// Whether `address` lies within this half-open range.
    #[must_use]
    pub const fn contains(self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
}

/// Ownership classification needed by the initial physical allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionKind {
    /// RAM that firmware permits the kernel to own after handoff.
    Usable,
    /// Firmware, device, image, metadata, or otherwise unavailable memory.
    Reserved,
}

/// One classified physical address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    range: PhysicalRange,
    kind: RegionKind,
}

impl MemoryRegion {
    /// Construct a classified range.
    #[must_use]
    pub const fn new(range: PhysicalRange, kind: RegionKind) -> Self {
        Self { range, kind }
    }

    /// Physical range covered by this region.
    #[must_use]
    pub const fn range(self) -> PhysicalRange {
        self.range
    }

    /// Ownership classification of this region.
    #[must_use]
    pub const fn kind(self) -> RegionKind {
        self.kind
    }
}

/// Checked byte accounting over a normalized memory map.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryMapStats {
    usable_bytes: u64,
    reserved_bytes: u64,
}

impl MemoryMapStats {
    /// Bytes the physical allocator may eventually own.
    #[must_use]
    pub const fn usable_bytes(self) -> u64 {
        self.usable_bytes
    }

    /// Bytes retained by firmware, devices, or explicit reservations.
    #[must_use]
    pub const fn reserved_bytes(self) -> u64 {
        self.reserved_bytes
    }

    /// Bytes described by the complete normalized map.
    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.usable_bytes + self.reserved_bytes
    }
}

/// Sorted, non-overlapping physical regions with explicit reservations applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedMemoryMap {
    regions: Vec<MemoryRegion>,
    stats: MemoryMapStats,
}

impl NormalizedMemoryMap {
    /// Normalize firmware regions and overlay explicit reservations.
    ///
    /// Firmware ranges may be unordered but must not overlap. Adjacent ranges
    /// with the same ownership are coalesced. Reservations may overlap each
    /// other, but every reserved byte must be described by the firmware map.
    ///
    /// # Errors
    ///
    /// Rejects count-bound violations, overlapping firmware ranges, unmapped
    /// reservations, and checked accounting overflow.
    pub fn build(
        firmware_regions: &[MemoryRegion],
        reservations: &[PhysicalRange],
    ) -> Result<Self, MemoryMapError> {
        if firmware_regions.len() > MAX_FIRMWARE_REGIONS || reservations.len() > MAX_RESERVATIONS {
            return Err(MemoryMapError::TooManyRegions);
        }

        let firmware = normalize_firmware(firmware_regions)?;
        let reservations = normalize_reservations(reservations);
        for reservation in &reservations {
            if !range_is_covered(*reservation, &firmware) {
                return Err(MemoryMapError::ReservationUnmapped);
            }
        }

        let mut regions = Vec::new();
        for region in &firmware {
            overlay_region(*region, &reservations, &mut regions)?;
        }
        let stats = calculate_stats(&regions)?;
        Ok(Self { regions, stats })
    }

    /// Sorted normalized regions.
    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Checked ownership accounting.
    #[must_use]
    pub const fn stats(&self) -> MemoryMapStats {
        self.stats
    }
}

/// Failures produced by the early monotonic allocator model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootAllocationError {
    /// A zero-byte allocation was requested.
    Empty,
    /// Alignment was zero or not a power of two.
    InvalidAlignment,
    /// Checked address or accounting arithmetic overflowed.
    Overflow,
    /// The reserved boot arena cannot satisfy the request.
    Exhausted,
    /// Allocation was attempted after the arena was sealed.
    Sealed,
}

impl fmt::Display for BootAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("boot allocation is empty"),
            Self::InvalidAlignment => formatter.write_str("boot allocation alignment is invalid"),
            Self::Overflow => formatter.write_str("boot allocation arithmetic overflowed"),
            Self::Exhausted => formatter.write_str("boot allocation arena is exhausted"),
            Self::Sealed => formatter.write_str("boot allocation arena is sealed"),
        }
    }
}

/// One checked byte allocation within the reserved boot arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootAllocation {
    start: u64,
    byte_count: u64,
}

impl BootAllocation {
    /// First byte assigned to the allocation.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Payload bytes assigned to the allocation.
    #[must_use]
    pub const fn byte_count(self) -> u64 {
        self.byte_count
    }

    /// First byte after the allocation.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.start + self.byte_count
    }
}

/// Bounded monotonic allocator over one explicitly reserved physical range.
///
/// This is a pure ownership model: it returns checked addresses but never
/// constructs references or dereferences physical memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootAllocator {
    arena: PhysicalRange,
    cursor: u64,
    allocated_bytes: u64,
    sealed: bool,
}

impl BootAllocator {
    /// Construct an empty allocator over a previously reserved arena.
    #[must_use]
    pub const fn new(arena: PhysicalRange) -> Self {
        Self {
            arena,
            cursor: arena.start,
            allocated_bytes: 0,
            sealed: false,
        }
    }

    /// Allocate payload bytes with a power-of-two alignment.
    ///
    /// A failed request does not change the cursor or accounting.
    ///
    /// # Errors
    ///
    /// Rejects zero bytes, invalid alignment, checked overflow, exhaustion, or
    /// any request after the allocator has been sealed.
    pub fn allocate(
        &mut self,
        byte_count: u64,
        alignment: u64,
    ) -> Result<BootAllocation, BootAllocationError> {
        if self.sealed {
            return Err(BootAllocationError::Sealed);
        }
        if byte_count == 0 {
            return Err(BootAllocationError::Empty);
        }
        if !alignment.is_power_of_two() {
            return Err(BootAllocationError::InvalidAlignment);
        }

        let alignment_mask = alignment - 1;
        let start = self
            .cursor
            .checked_add(alignment_mask)
            .ok_or(BootAllocationError::Overflow)?
            & !alignment_mask;
        let end = start
            .checked_add(byte_count)
            .ok_or(BootAllocationError::Overflow)?;
        if end > self.arena.end {
            return Err(BootAllocationError::Exhausted);
        }
        let allocated_bytes = self
            .allocated_bytes
            .checked_add(byte_count)
            .ok_or(BootAllocationError::Overflow)?;

        self.cursor = end;
        self.allocated_bytes = allocated_bytes;
        Ok(BootAllocation { start, byte_count })
    }

    /// Prevent all subsequent allocations.
    pub const fn seal(&mut self) {
        self.sealed = true;
    }

    /// Reserved arena backing this allocator.
    #[must_use]
    pub const fn arena(self) -> PhysicalRange {
        self.arena
    }

    /// Payload bytes returned to callers, excluding alignment padding.
    #[must_use]
    pub const fn allocated_bytes(self) -> u64 {
        self.allocated_bytes
    }

    /// Arena bytes consumed, including alignment padding.
    #[must_use]
    pub const fn consumed_bytes(self) -> u64 {
        self.cursor - self.arena.start
    }

    /// Bytes after the cursor that remain available for future requests.
    #[must_use]
    pub const fn remaining_bytes(self) -> u64 {
        self.arena.end - self.cursor
    }

    /// Whether the allocator rejects all further requests.
    #[must_use]
    pub const fn is_sealed(self) -> bool {
        self.sealed
    }
}

/// Failures produced by the physical-frame bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameAllocationError {
    /// Frame-count or bitmap-size arithmetic overflowed.
    Overflow,
    /// The configured bitmap capacity would be exceeded.
    TooManyFrames,
    /// Bitmap metadata could not be allocated.
    MetadataExhausted,
    /// No free usable frame remains.
    Exhausted,
    /// The supplied address is unaligned, reserved, or absent from the map.
    InvalidFrame,
    /// A usable frame that was already free was released.
    DoubleFree,
}

impl fmt::Display for FrameAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => formatter.write_str("frame allocator arithmetic overflowed"),
            Self::TooManyFrames => formatter.write_str("frame bitmap capacity exceeded"),
            Self::MetadataExhausted => formatter.write_str("frame bitmap metadata exhausted"),
            Self::Exhausted => formatter.write_str("physical frames exhausted"),
            Self::InvalidFrame => formatter.write_str("physical frame is not allocator-owned"),
            Self::DoubleFree => formatter.write_str("physical frame was freed twice"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameSpan {
    range: PhysicalRange,
    first_frame: u64,
}

/// Compact ownership bitmap over the usable spans in a normalized map.
///
/// Only usable pages consume bitmap bits, so high device ranges do not inflate
/// metadata. A zero bit denotes a free frame and a one bit an allocated frame.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
pub struct FrameAllocator {
    spans: Vec<FrameSpan>,
    bitmap: Vec<u64>,
    total_frames: u64,
    free_frames: u64,
}

impl FrameAllocator {
    /// Build an empty frame allocator over every usable normalized region.
    ///
    /// # Errors
    ///
    /// Rejects checked arithmetic overflow, maps above the explicit bitmap
    /// capacity, and fallible metadata allocation failure.
    pub fn from_map(map: &NormalizedMemoryMap) -> Result<Self, FrameAllocationError> {
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(map.regions.len())
            .map_err(|_| FrameAllocationError::MetadataExhausted)?;
        let mut total_frames = 0_u64;
        for region in &map.regions {
            if region.kind != RegionKind::Usable {
                continue;
            }
            spans.push(FrameSpan {
                range: region.range,
                first_frame: total_frames,
            });
            total_frames = total_frames
                .checked_add(region.range.page_count())
                .ok_or(FrameAllocationError::Overflow)?;
            if total_frames > MAX_MANAGED_FRAMES {
                return Err(FrameAllocationError::TooManyFrames);
            }
        }

        let word_count = total_frames
            .checked_add(63)
            .ok_or(FrameAllocationError::Overflow)?
            / 64;
        let word_count = usize::try_from(word_count).map_err(|_| FrameAllocationError::Overflow)?;
        let mut bitmap = Vec::new();
        bitmap
            .try_reserve_exact(word_count)
            .map_err(|_| FrameAllocationError::MetadataExhausted)?;
        bitmap.resize(word_count, 0);

        Ok(Self {
            spans,
            bitmap,
            total_frames,
            free_frames: total_frames,
        })
    }

    /// Allocate the lowest-addressed currently free physical frame.
    ///
    /// # Errors
    ///
    /// Returns [`FrameAllocationError::Exhausted`] when no frame is free.
    pub fn allocate(&mut self) -> Result<u64, FrameAllocationError> {
        if self.free_frames == 0 {
            return Err(FrameAllocationError::Exhausted);
        }
        for frame_index in 0..self.total_frames {
            if !self.is_allocated(frame_index)? {
                self.set_allocated(frame_index, true)?;
                self.free_frames -= 1;
                return self
                    .address_for_index(frame_index)
                    .ok_or(FrameAllocationError::Overflow);
            }
        }
        Err(FrameAllocationError::Exhausted)
    }

    /// Allocate one physically contiguous, aligned frame range atomically.
    ///
    /// # Errors
    ///
    /// Rejects zero/non-power-of-two bounds, arithmetic overflow, or a lack of
    /// one free run wholly contained in a usable physical span. No bitmap bit
    /// changes unless the complete request can be satisfied.
    pub fn allocate_contiguous(
        &mut self,
        page_count: u64,
        alignment_pages: u64,
    ) -> Result<PhysicalRange, FrameAllocationError> {
        if page_count == 0 || alignment_pages == 0 || !alignment_pages.is_power_of_two() {
            return Err(FrameAllocationError::InvalidFrame);
        }
        if page_count > self.free_frames {
            return Err(FrameAllocationError::Exhausted);
        }
        for span in &self.spans {
            let span_pages = span.range.page_count();
            if span_pages < page_count {
                continue;
            }
            let last_start = span_pages
                .checked_sub(page_count)
                .ok_or(FrameAllocationError::Overflow)?;
            for local_start in 0..=last_start {
                let address = span
                    .range
                    .start
                    .checked_add(
                        local_start
                            .checked_mul(BASE_PAGE_SIZE)
                            .ok_or(FrameAllocationError::Overflow)?,
                    )
                    .ok_or(FrameAllocationError::Overflow)?;
                let alignment_bytes = alignment_pages
                    .checked_mul(BASE_PAGE_SIZE)
                    .ok_or(FrameAllocationError::Overflow)?;
                if !address.is_multiple_of(alignment_bytes) {
                    continue;
                }
                let first = span
                    .first_frame
                    .checked_add(local_start)
                    .ok_or(FrameAllocationError::Overflow)?;
                let end = first
                    .checked_add(page_count)
                    .ok_or(FrameAllocationError::Overflow)?;
                let mut free = true;
                for frame in first..end {
                    if self.is_allocated(frame)? {
                        free = false;
                        break;
                    }
                }
                if !free {
                    continue;
                }
                let next_free = self
                    .free_frames
                    .checked_sub(page_count)
                    .ok_or(FrameAllocationError::Overflow)?;
                for frame in first..end {
                    self.set_allocated(frame, true)?;
                }
                self.free_frames = next_free;
                return PhysicalRange::from_pages(address, page_count)
                    .map_err(|_| FrameAllocationError::Overflow);
            }
        }
        Err(FrameAllocationError::Exhausted)
    }

    /// Mark every currently free allocator-owned frame in `range` unavailable.
    ///
    /// Frames outside usable spans are ignored, and reserving the same range
    /// repeatedly is idempotent. The returned count is the number of frames
    /// newly removed from the free pool.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic error if the allocator's internal accounting
    /// cannot represent the reservation.
    pub fn reserve_range(&mut self, range: PhysicalRange) -> Result<u64, FrameAllocationError> {
        let mut reserved = 0_u64;
        for span_index in 0..self.spans.len() {
            let span = self.spans[span_index];
            let overlap_start = span.range.start.max(range.start);
            let overlap_end = span.range.end.min(range.end);
            if overlap_start >= overlap_end {
                continue;
            }

            let first = span
                .first_frame
                .checked_add((overlap_start - span.range.start) / BASE_PAGE_SIZE)
                .ok_or(FrameAllocationError::Overflow)?;
            let page_count = (overlap_end - overlap_start) / BASE_PAGE_SIZE;
            let end = first
                .checked_add(page_count)
                .ok_or(FrameAllocationError::Overflow)?;
            for frame_index in first..end {
                if self.is_allocated(frame_index)? {
                    continue;
                }
                let next_free = self
                    .free_frames
                    .checked_sub(1)
                    .ok_or(FrameAllocationError::Overflow)?;
                let next_reserved = reserved
                    .checked_add(1)
                    .ok_or(FrameAllocationError::Overflow)?;
                self.set_allocated(frame_index, true)?;
                self.free_frames = next_free;
                reserved = next_reserved;
            }
        }
        Ok(reserved)
    }

    /// Return one previously allocated physical frame to the bitmap.
    ///
    /// # Errors
    ///
    /// Rejects unaligned, reserved, unmapped, and already-free addresses.
    pub fn free(&mut self, address: u64) -> Result<(), FrameAllocationError> {
        let frame_index = self
            .index_for_address(address)
            .ok_or(FrameAllocationError::InvalidFrame)?;
        if !self.is_allocated(frame_index)? {
            return Err(FrameAllocationError::DoubleFree);
        }
        self.set_allocated(frame_index, false)?;
        self.free_frames = self
            .free_frames
            .checked_add(1)
            .ok_or(FrameAllocationError::Overflow)?;
        Ok(())
    }

    /// Return a complete previously allocated contiguous range atomically.
    ///
    /// Every page is validated before the bitmap is changed, so an invalid or
    /// partially free range cannot cause partial teardown.
    ///
    /// # Errors
    ///
    /// Rejects a range containing an unmanaged, reserved, or already-free page.
    pub fn free_range(&mut self, range: PhysicalRange) -> Result<(), FrameAllocationError> {
        for page in 0..range.page_count() {
            let address = range
                .start
                .checked_add(
                    page.checked_mul(BASE_PAGE_SIZE)
                        .ok_or(FrameAllocationError::Overflow)?,
                )
                .ok_or(FrameAllocationError::Overflow)?;
            let index = self
                .index_for_address(address)
                .ok_or(FrameAllocationError::InvalidFrame)?;
            if !self.is_allocated(index)? {
                return Err(FrameAllocationError::DoubleFree);
            }
        }
        let next_free = self
            .free_frames
            .checked_add(range.page_count())
            .ok_or(FrameAllocationError::Overflow)?;
        for page in 0..range.page_count() {
            let address = range.start + page * BASE_PAGE_SIZE;
            let index = self
                .index_for_address(address)
                .ok_or(FrameAllocationError::InvalidFrame)?;
            self.set_allocated(index, false)?;
        }
        self.free_frames = next_free;
        Ok(())
    }

    /// Number of usable frames represented by the bitmap.
    #[must_use]
    pub const fn total_frames(&self) -> u64 {
        self.total_frames
    }

    /// Number of frames currently available for allocation.
    #[must_use]
    pub const fn free_frames(&self) -> u64 {
        self.free_frames
    }

    /// Bitmap storage bytes, excluding the bounded span table.
    #[must_use]
    pub fn bitmap_bytes(&self) -> usize {
        self.bitmap.len() * core::mem::size_of::<u64>()
    }

    fn is_allocated(&self, frame_index: u64) -> Result<bool, FrameAllocationError> {
        let (word, mask) = self.bitmap_location(frame_index)?;
        Ok(self.bitmap[word] & mask != 0)
    }

    fn set_allocated(
        &mut self,
        frame_index: u64,
        allocated: bool,
    ) -> Result<(), FrameAllocationError> {
        let (word, mask) = self.bitmap_location(frame_index)?;
        if allocated {
            self.bitmap[word] |= mask;
        } else {
            self.bitmap[word] &= !mask;
        }
        Ok(())
    }

    fn bitmap_location(&self, frame_index: u64) -> Result<(usize, u64), FrameAllocationError> {
        if frame_index >= self.total_frames {
            return Err(FrameAllocationError::Overflow);
        }
        let word = usize::try_from(frame_index / 64).map_err(|_| FrameAllocationError::Overflow)?;
        Ok((word, 1_u64 << (frame_index % 64)))
    }

    fn address_for_index(&self, frame_index: u64) -> Option<u64> {
        for span in &self.spans {
            let page_count = span.range.page_count();
            if frame_index >= span.first_frame && frame_index - span.first_frame < page_count {
                let offset = (frame_index - span.first_frame).checked_mul(BASE_PAGE_SIZE)?;
                return span.range.start.checked_add(offset);
            }
        }
        None
    }

    fn index_for_address(&self, address: u64) -> Option<u64> {
        if !address.is_multiple_of(BASE_PAGE_SIZE) {
            return None;
        }
        for span in &self.spans {
            if address >= span.range.start && address < span.range.end {
                let offset = (address - span.range.start) / BASE_PAGE_SIZE;
                return span.first_frame.checked_add(offset);
            }
        }
        None
    }
}

fn normalize_firmware(regions: &[MemoryRegion]) -> Result<Vec<MemoryRegion>, MemoryMapError> {
    let mut sorted = regions.to_vec();
    sorted.sort_unstable_by_key(|region| region.range.start);

    let mut normalized: Vec<MemoryRegion> = Vec::new();
    for region in sorted {
        if let Some(previous) = normalized.last()
            && region.range.start < previous.range.end
        {
            return Err(MemoryMapError::FirmwareOverlap);
        }
        append_region(&mut normalized, region)?;
    }
    Ok(normalized)
}

fn normalize_reservations(reservations: &[PhysicalRange]) -> Vec<PhysicalRange> {
    let mut sorted = reservations.to_vec();
    sorted.sort_unstable_by_key(|range| range.start);

    let mut normalized: Vec<PhysicalRange> = Vec::new();
    for range in sorted {
        if let Some(previous) = normalized.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        normalized.push(range);
    }
    normalized
}

fn range_is_covered(range: PhysicalRange, regions: &[MemoryRegion]) -> bool {
    let mut cursor = range.start;
    for region in regions {
        if region.range.end <= cursor {
            continue;
        }
        if region.range.start > cursor {
            return false;
        }
        cursor = region.range.end.min(range.end);
        if cursor == range.end {
            return true;
        }
    }
    false
}

fn overlay_region(
    region: MemoryRegion,
    reservations: &[PhysicalRange],
    output: &mut Vec<MemoryRegion>,
) -> Result<(), MemoryMapError> {
    let mut cursor = region.range.start;
    for reservation in reservations {
        if reservation.end <= cursor || reservation.start >= region.range.end {
            continue;
        }
        if cursor < reservation.start {
            append_region(
                output,
                MemoryRegion::new(
                    PhysicalRange {
                        start: cursor,
                        end: reservation.start.min(region.range.end),
                    },
                    region.kind,
                ),
            )?;
        }
        let reserved_start = cursor.max(reservation.start);
        let reserved_end = region.range.end.min(reservation.end);
        if reserved_start < reserved_end {
            append_region(
                output,
                MemoryRegion::new(
                    PhysicalRange {
                        start: reserved_start,
                        end: reserved_end,
                    },
                    RegionKind::Reserved,
                ),
            )?;
            cursor = reserved_end;
        }
        if cursor == region.range.end {
            break;
        }
    }
    if cursor < region.range.end {
        append_region(
            output,
            MemoryRegion::new(
                PhysicalRange {
                    start: cursor,
                    end: region.range.end,
                },
                region.kind,
            ),
        )?;
    }
    Ok(())
}

fn append_region(
    output: &mut Vec<MemoryRegion>,
    region: MemoryRegion,
) -> Result<(), MemoryMapError> {
    if let Some(previous) = output.last_mut()
        && previous.kind == region.kind
        && previous.range.end == region.range.start
    {
        previous.range.end = region.range.end;
        return Ok(());
    }
    if output.len() >= MAX_NORMALIZED_REGIONS {
        return Err(MemoryMapError::TooManyRegions);
    }
    output.push(region);
    Ok(())
}

fn calculate_stats(regions: &[MemoryRegion]) -> Result<MemoryMapStats, MemoryMapError> {
    let mut stats = MemoryMapStats::default();
    for region in regions {
        let destination = match region.kind {
            RegionKind::Usable => &mut stats.usable_bytes,
            RegionKind::Reserved => &mut stats.reserved_bytes,
        };
        *destination = destination
            .checked_add(region.range.byte_count())
            .ok_or(MemoryMapError::Overflow)?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::{
        BASE_PAGE_SIZE, BootAllocation, BootAllocationError, BootAllocator, FrameAllocationError,
        FrameAllocator, MAX_FIRMWARE_REGIONS, Mapping, MappingLifetime, MappingMemoryType,
        MappingOwner, MappingPermissions, MappingPlan, MappingPlanError, MappingPrivilege,
        MemoryMapError, MemoryRegion, NormalizedMemoryMap, PhysicalRange, RegionKind, VirtualRange,
    };
    use alloc::vec;

    fn pages(start_page: u64, count: u64) -> PhysicalRange {
        let start = start_page * BASE_PAGE_SIZE;
        PhysicalRange {
            start,
            end: start + count * BASE_PAGE_SIZE,
        }
    }

    fn region(start_page: u64, count: u64, kind: RegionKind) -> MemoryRegion {
        MemoryRegion::new(pages(start_page, count), kind)
    }

    #[test]
    fn range_construction_checks_alignment_empty_and_overflow() {
        assert_eq!(
            PhysicalRange::from_pages(1, 1),
            Err(MemoryMapError::Unaligned)
        );
        assert_eq!(PhysicalRange::from_pages(0, 0), Err(MemoryMapError::Empty));
        assert_eq!(
            PhysicalRange::from_pages(!(BASE_PAGE_SIZE - 1), 2),
            Err(MemoryMapError::Overflow)
        );
    }

    #[test]
    fn unordered_adjacent_firmware_ranges_are_coalesced() -> Result<(), MemoryMapError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(4, 2, RegionKind::Reserved),
                region(2, 2, RegionKind::Usable),
                region(0, 2, RegionKind::Usable),
            ],
            &[],
        )?;

        assert_eq!(
            map.regions(),
            &[
                region(0, 4, RegionKind::Usable),
                region(4, 2, RegionKind::Reserved)
            ]
        );
        assert_eq!(map.stats().usable_bytes(), 4 * BASE_PAGE_SIZE);
        assert_eq!(map.stats().reserved_bytes(), 2 * BASE_PAGE_SIZE);
        assert_eq!(map.stats().total_bytes(), 6 * BASE_PAGE_SIZE);
        Ok(())
    }

    #[test]
    fn overlapping_firmware_ranges_are_rejected() {
        assert_eq!(
            NormalizedMemoryMap::build(
                &[
                    region(0, 3, RegionKind::Usable),
                    region(2, 2, RegionKind::Reserved)
                ],
                &[]
            ),
            Err(MemoryMapError::FirmwareOverlap)
        );
    }

    #[test]
    fn reservation_splits_usable_memory_and_updates_accounting() -> Result<(), MemoryMapError> {
        let map = NormalizedMemoryMap::build(&[region(0, 10, RegionKind::Usable)], &[pages(3, 2)])?;

        assert_eq!(
            map.regions(),
            &[
                region(0, 3, RegionKind::Usable),
                region(3, 2, RegionKind::Reserved),
                region(5, 5, RegionKind::Usable),
            ]
        );
        assert_eq!(map.stats().usable_bytes(), 8 * BASE_PAGE_SIZE);
        assert_eq!(map.stats().reserved_bytes(), 2 * BASE_PAGE_SIZE);
        Ok(())
    }

    #[test]
    fn overlapping_reservations_merge_across_firmware_boundaries() -> Result<(), MemoryMapError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(0, 4, RegionKind::Usable),
                region(4, 2, RegionKind::Reserved),
                region(6, 4, RegionKind::Usable),
            ],
            &[pages(2, 5), pages(5, 3)],
        )?;

        assert_eq!(
            map.regions(),
            &[
                region(0, 2, RegionKind::Usable),
                region(2, 6, RegionKind::Reserved),
                region(8, 2, RegionKind::Usable),
            ]
        );
        Ok(())
    }

    #[test]
    fn reservation_cannot_cross_an_unmapped_gap() {
        assert_eq!(
            NormalizedMemoryMap::build(
                &[
                    region(0, 2, RegionKind::Usable),
                    region(4, 2, RegionKind::Usable)
                ],
                &[pages(1, 4)]
            ),
            Err(MemoryMapError::ReservationUnmapped)
        );
    }

    #[test]
    fn firmware_input_count_is_bounded() {
        let regions = vec![region(0, 1, RegionKind::Reserved); MAX_FIRMWARE_REGIONS + 1];
        assert_eq!(
            NormalizedMemoryMap::build(&regions, &[]),
            Err(MemoryMapError::TooManyRegions)
        );
    }

    #[test]
    fn boot_allocator_aligns_and_accounts_padding() {
        let mut allocator = BootAllocator::new(pages(1, 2));
        assert_eq!(
            allocator.allocate(3, 1),
            Ok(BootAllocation {
                start: BASE_PAGE_SIZE,
                byte_count: 3
            })
        );
        assert_eq!(
            allocator.allocate(4, 8),
            Ok(BootAllocation {
                start: BASE_PAGE_SIZE + 8,
                byte_count: 4
            })
        );
        assert_eq!(allocator.allocated_bytes(), 7);
        assert_eq!(allocator.consumed_bytes(), 12);
        assert_eq!(allocator.remaining_bytes(), 2 * BASE_PAGE_SIZE - 12);
    }

    #[test]
    fn boot_allocator_rejects_invalid_requests_without_mutation() {
        let mut allocator = BootAllocator::new(pages(0, 1));
        assert_eq!(allocator.allocate(0, 1), Err(BootAllocationError::Empty));
        assert_eq!(
            allocator.allocate(1, 3),
            Err(BootAllocationError::InvalidAlignment)
        );
        assert_eq!(allocator.consumed_bytes(), 0);
        assert_eq!(allocator.allocated_bytes(), 0);
    }

    #[test]
    fn boot_allocator_exhaustion_is_atomic() {
        let mut allocator = BootAllocator::new(pages(0, 1));
        assert_eq!(allocator.allocate(BASE_PAGE_SIZE, 1).map(|_| ()), Ok(()));
        assert_eq!(
            allocator.allocate(1, 1),
            Err(BootAllocationError::Exhausted)
        );
        assert_eq!(allocator.consumed_bytes(), BASE_PAGE_SIZE);
        assert_eq!(allocator.remaining_bytes(), 0);
    }

    #[test]
    fn boot_allocator_checked_alignment_overflow_is_atomic() -> Result<(), MemoryMapError> {
        let arena_start = u64::MAX - (2 * BASE_PAGE_SIZE - 1);
        let mut allocator = BootAllocator::new(PhysicalRange::from_pages(arena_start, 1)?);
        assert_eq!(
            allocator.allocate(1, 1_u64 << 63),
            Err(BootAllocationError::Overflow)
        );
        assert_eq!(allocator.consumed_bytes(), 0);
        Ok(())
    }

    #[test]
    fn sealed_boot_allocator_rejects_requests() {
        let mut allocator = BootAllocator::new(pages(0, 1));
        allocator.seal();
        assert!(allocator.is_sealed());
        assert_eq!(allocator.allocate(1, 1), Err(BootAllocationError::Sealed));
    }

    #[test]
    fn frame_bitmap_tracks_discontiguous_usable_ranges() -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(1, 2, RegionKind::Usable),
                region(3, 2, RegionKind::Reserved),
                region(5, 1, RegionKind::Usable),
            ],
            &[],
        )
        .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;

        assert_eq!(allocator.total_frames(), 3);
        assert_eq!(allocator.bitmap_bytes(), 8);
        assert_eq!(allocator.allocate(), Ok(BASE_PAGE_SIZE));
        assert_eq!(allocator.allocate(), Ok(2 * BASE_PAGE_SIZE));
        assert_eq!(allocator.allocate(), Ok(5 * BASE_PAGE_SIZE));
        assert_eq!(allocator.free_frames(), 0);
        assert_eq!(allocator.allocate(), Err(FrameAllocationError::Exhausted));
        Ok(())
    }

    #[test]
    fn frame_bitmap_rejects_invalid_and_double_free() -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(1, 1, RegionKind::Usable),
                region(2, 1, RegionKind::Reserved),
            ],
            &[],
        )
        .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let frame = allocator.allocate()?;

        assert_eq!(allocator.free(frame), Ok(()));
        assert_eq!(allocator.free(frame), Err(FrameAllocationError::DoubleFree));
        assert_eq!(
            allocator.free(2 * BASE_PAGE_SIZE),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(
            allocator.free(BASE_PAGE_SIZE + 1),
            Err(FrameAllocationError::InvalidFrame)
        );
        Ok(())
    }

    #[test]
    fn frame_bitmap_reserves_overlapping_device_pages_idempotently()
    -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(&[region(1, 8, RegionKind::Usable)], &[])
            .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let device = PhysicalRange::from_pages(3 * BASE_PAGE_SIZE, 3)
            .map_err(|_| FrameAllocationError::Overflow)?;

        assert_eq!(allocator.reserve_range(device), Ok(3));
        assert_eq!(allocator.reserve_range(device), Ok(0));
        assert_eq!(allocator.free_frames(), 5);

        while let Ok(frame) = allocator.allocate() {
            assert!(!device.contains(frame));
        }
        Ok(())
    }

    #[test]
    fn frame_bitmap_capacity_arithmetic_is_checked() -> Result<(), MemoryMapError> {
        let huge = PhysicalRange::from_pages(0, super::MAX_MANAGED_FRAMES + 1)?;
        let map = NormalizedMemoryMap::build(&[MemoryRegion::new(huge, RegionKind::Usable)], &[])?;
        assert_eq!(
            FrameAllocator::from_map(&map),
            Err(FrameAllocationError::TooManyFrames)
        );
        Ok(())
    }

    #[test]
    fn contiguous_frame_allocation_and_teardown_are_atomic() -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(&[region(1, 16, RegionKind::Usable)], &[])
            .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let isolated = allocator.allocate_contiguous(4, 4)?;
        assert_eq!(isolated.start(), 4 * BASE_PAGE_SIZE);
        assert_eq!(allocator.free_frames(), 12);

        let middle = isolated.start() + BASE_PAGE_SIZE;
        allocator.free(middle)?;
        let before = allocator.clone();
        assert_eq!(
            allocator.free_range(isolated),
            Err(FrameAllocationError::DoubleFree)
        );
        assert_eq!(allocator, before);
        allocator.reserve_range(
            PhysicalRange::from_pages(middle, 1).map_err(|_| FrameAllocationError::Overflow)?,
        )?;
        allocator.free_range(isolated)?;
        assert_eq!(allocator.free_frames(), 16);
        Ok(())
    }

    #[test]
    fn contiguous_frame_bounds_fail_without_mutation() -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(1, 2, RegionKind::Usable),
                region(3, 1, RegionKind::Reserved),
                region(4, 2, RegionKind::Usable),
            ],
            &[],
        )
        .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let before = allocator.clone();
        assert_eq!(
            allocator.allocate_contiguous(3, 1),
            Err(FrameAllocationError::Exhausted)
        );
        assert_eq!(allocator, before);
        assert_eq!(
            allocator.allocate_contiguous(0, 1),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(
            allocator.allocate_contiguous(1, 3),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(
            allocator.allocate_contiguous(1, 1_u64 << 63),
            Err(FrameAllocationError::Overflow)
        );
        assert_eq!(
            allocator.free_range(pages(3, 1)),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(allocator, before);
        Ok(())
    }

    #[test]
    fn active_stack_reservation_is_never_allocatable() -> Result<(), FrameAllocationError> {
        let stack = pages(4, 2);
        let map = NormalizedMemoryMap::build(&[region(1, 8, RegionKind::Usable)], &[stack])
            .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;

        while let Ok(frame) = allocator.allocate() {
            assert!(!stack.contains(frame));
        }
        assert_eq!(allocator.total_frames(), 6);
        assert_eq!(allocator.free_frames(), 0);
        Ok(())
    }

    fn identity_mapping(
        start_page: u64,
        page_count: u64,
        permissions: MappingPermissions,
    ) -> Result<Mapping, MappingPlanError> {
        let range = PhysicalRange::from_pages(start_page * BASE_PAGE_SIZE, page_count)
            .map_err(|_| MappingPlanError::Overflow)?;
        Mapping::identity(
            range,
            permissions,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
            MappingLifetime::Kernel,
            false,
        )
    }

    #[test]
    fn mapping_plan_sorts_disjoint_ranges_and_counts_pages() -> Result<(), MappingPlanError> {
        let mut plan = MappingPlan::new();
        plan.insert(identity_mapping(8, 2, MappingPermissions::READ_WRITE)?)?;
        plan.insert(identity_mapping(2, 3, MappingPermissions::READ_EXECUTE)?)?;

        assert_eq!(
            plan.mappings()[0].virtual_range().start(),
            2 * BASE_PAGE_SIZE
        );
        assert_eq!(
            plan.mappings()[1].virtual_range().start(),
            8 * BASE_PAGE_SIZE
        );
        assert_eq!(plan.page_count(), Ok(5));
        assert!(plan.enforces_global_w_xor_x());
        Ok(())
    }

    #[test]
    fn mapping_plan_rejects_overlap_without_mutation() -> Result<(), MappingPlanError> {
        let mut plan = MappingPlan::new();
        plan.insert(identity_mapping(4, 4, MappingPermissions::READ_ONLY)?)?;
        assert_eq!(
            plan.insert(identity_mapping(6, 4, MappingPermissions::READ_WRITE)?),
            Err(MappingPlanError::VirtualOverlap)
        );
        assert_eq!(plan.mappings().len(), 1);
        Ok(())
    }

    fn aliased_mapping(
        virtual_page: u64,
        physical_page: u64,
        page_count: u64,
        permissions: MappingPermissions,
    ) -> Result<Mapping, MappingPlanError> {
        let virtual_range = VirtualRange::from_pages(virtual_page * BASE_PAGE_SIZE, page_count)?;
        let physical_range = PhysicalRange::from_pages(physical_page * BASE_PAGE_SIZE, page_count)
            .map_err(|_| MappingPlanError::Overflow)?;
        Mapping::new(
            virtual_range,
            physical_range,
            permissions,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
            MappingLifetime::Kernel,
            false,
        )
    }

    #[test]
    fn mapping_plan_rejects_write_execute_aliases_in_both_orders() -> Result<(), MappingPlanError> {
        for (first, second) in [
            (
                MappingPermissions::READ_WRITE,
                MappingPermissions::READ_EXECUTE,
            ),
            (
                MappingPermissions::READ_EXECUTE,
                MappingPermissions::READ_WRITE,
            ),
        ] {
            let mut plan = MappingPlan::new();
            plan.insert(aliased_mapping(1, 8, 2, first)?)?;
            assert_eq!(
                plan.insert(aliased_mapping(20, 8, 2, second)?),
                Err(MappingPlanError::PhysicalOverlap)
            );
            assert_eq!(plan.mappings().len(), 1);
        }
        Ok(())
    }

    #[test]
    fn mapping_plan_accepts_only_aliases_that_preserve_global_w_xor_x()
    -> Result<(), MappingPlanError> {
        let mut plan = MappingPlan::new();
        plan.insert(aliased_mapping(1, 8, 4, MappingPermissions::READ_ONLY)?)?;
        plan.insert(aliased_mapping(20, 10, 4, MappingPermissions::READ_ONLY)?)?;
        plan.insert(aliased_mapping(30, 30, 2, MappingPermissions::READ_WRITE)?)?;
        plan.insert(aliased_mapping(50, 30, 2, MappingPermissions::READ_WRITE)?)?;
        assert!(plan.enforces_global_w_xor_x());

        let virtual_range = VirtualRange::from_pages(40 * BASE_PAGE_SIZE, 1)?;
        let physical_range = PhysicalRange::from_pages(8 * BASE_PAGE_SIZE, 1)
            .map_err(|_| MappingPlanError::Overflow)?;
        let user = Mapping::user(
            virtual_range,
            physical_range,
            MappingPermissions::READ_ONLY,
            MappingOwner::IsolatedTask,
            MappingLifetime::Task,
        )?;
        assert_eq!(user.privilege(), MappingPrivilege::User);
        plan.insert(user)?;
        assert!(plan.enforces_global_w_xor_x());
        Ok(())
    }

    #[test]
    fn mapping_plan_rejects_aliases_with_conflicting_memory_types() -> Result<(), MappingPlanError>
    {
        let mut plan = MappingPlan::new();
        plan.insert(aliased_mapping(1, 8, 1, MappingPermissions::READ_WRITE)?)?;
        let device = Mapping::new(
            VirtualRange::from_pages(20 * BASE_PAGE_SIZE, 1)?,
            pages(8, 1),
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Device,
            MappingOwner::MachineDevice,
            MappingLifetime::Kernel,
            false,
        )?;
        assert_eq!(plan.insert(device), Err(MappingPlanError::PhysicalOverlap));
        assert_eq!(plan.mappings().len(), 1);
        Ok(())
    }

    #[test]
    fn user_mapping_requires_task_ownership_and_lifetime() -> Result<(), MappingPlanError> {
        let virtual_range = VirtualRange::from_pages(40 * BASE_PAGE_SIZE, 1)?;
        let physical_range = pages(8, 1);
        assert_eq!(
            Mapping::user(
                virtual_range,
                physical_range,
                MappingPermissions::READ_ONLY,
                MappingOwner::KernelRuntime,
                MappingLifetime::Task,
            ),
            Err(MappingPlanError::InvalidUserOwner)
        );
        assert_eq!(
            Mapping::user(
                virtual_range,
                physical_range,
                MappingPermissions::READ_ONLY,
                MappingOwner::IsolatedTask,
                MappingLifetime::Kernel,
            ),
            Err(MappingPlanError::InvalidUserOwner)
        );
        Ok(())
    }

    #[test]
    fn mapping_permissions_enforce_w_xor_x_and_device_nx() {
        let range = pages(1, 1);
        let writable_executable = MappingPermissions {
            read: true,
            write: true,
            execute: true,
        };
        assert_eq!(
            Mapping::identity(
                range,
                writable_executable,
                MappingMemoryType::Normal,
                MappingOwner::KernelImage,
                MappingLifetime::Kernel,
                false,
            ),
            Err(MappingPlanError::WritableExecutable)
        );
        assert_eq!(
            Mapping::identity(
                range,
                MappingPermissions::READ_EXECUTE,
                MappingMemoryType::Device,
                MappingOwner::MachineDevice,
                MappingLifetime::Kernel,
                false,
            ),
            Err(MappingPlanError::ExecutableDevice)
        );
    }

    #[test]
    fn mapping_range_arithmetic_and_lengths_are_checked() -> Result<(), MappingPlanError> {
        assert_eq!(
            VirtualRange::from_pages(1, 1),
            Err(MappingPlanError::Unaligned)
        );
        assert_eq!(VirtualRange::from_pages(0, 0), Err(MappingPlanError::Empty));
        assert_eq!(
            VirtualRange::from_pages(!(BASE_PAGE_SIZE - 1), 2),
            Err(MappingPlanError::Overflow)
        );
        let virtual_range = VirtualRange::from_pages(0, 2)?;
        assert_eq!(
            Mapping::new(
                virtual_range,
                pages(0, 1),
                MappingPermissions::READ_ONLY,
                MappingMemoryType::Normal,
                MappingOwner::KernelRuntime,
                MappingLifetime::Boot,
                true,
            ),
            Err(MappingPlanError::LengthMismatch)
        );
        Ok(())
    }
}

//! Bounded, architecture-independent physical-memory ownership models.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod boot;
mod extents;
mod frames;
mod map;
mod mapping;
mod range;

use core::fmt;

pub use boot::{BootAllocation, BootAllocationError, BootAllocator};
pub use extents::{ExtentError, PhysicalExtents};
pub use frames::{FrameAllocationError, FrameAllocator};
pub use map::{MemoryMapStats, MemoryRegion, NormalizedMemoryMap, RegionKind};
pub use mapping::{
    Mapping, MappingLifetime, MappingMemoryType, MappingOwner, MappingPermissions, MappingPlan,
    MappingPlanError, MappingPrivilege, VirtualRange,
};
pub use range::PhysicalRange;

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

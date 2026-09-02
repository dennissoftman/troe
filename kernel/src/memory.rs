//! Application address-space memory: the allocations a launch owns.
//!
//! `ApplicationAllocation` and `IsolatedAllocation` name every physical and
//! virtual resource one loaded program holds, so teardown can release exactly
//! what launch reserved.

pub(crate) mod growth;
pub(crate) mod isolated;
pub(crate) mod launch;
pub(crate) mod private;

use crate::memory::private::ApplicationPrivateMemory;
use alloc::vec::Vec;
use troe_memory::{PhysicalExtents, PhysicalRange};

pub(crate) struct IsolatedAllocation {
    pub(crate) complete: PhysicalRange,
    pub(crate) tables: PhysicalRange,
    code: PhysicalRange,
    data: PhysicalRange,
    stack: PhysicalRange,
}

pub(crate) struct ApplicationAllocation {
    pub(crate) extents: PhysicalExtents,
    pub(crate) tables: PhysicalRange,
    image_pages: u64,
    pub(crate) startup: PhysicalRange,
    heap_pages: u64,
    growth_ranges: Vec<PhysicalRange>,
    pub(crate) growth_table_frames: Vec<u64>,
    private_memory: ApplicationPrivateMemory,
}

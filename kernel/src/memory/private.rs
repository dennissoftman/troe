//! Private application memory: extents, mappings, and the growth policy.
//!
//! Application private memory is a set of physical extents rather than one
//! contiguous run, so a large application still launches on a fragmented
//! machine. This module chooses the virtual range, allocates and releases the
//! extents, enforces the per-application policy, and answers the private
//! memory ABI calls.

use crate::deferred::owned_reply_payload;
use crate::handles::SharedRandom;
use crate::machine::OwnedAccounting;
use crate::memory::ApplicationAllocation;
use crate::memory::growth::application_growth_pages;
use alloc::vec::Vec;
use troe_abi::private_memory;
use troe_dispatch::ReplyStatus;
use troe_fmt_scfg::MemoryPolicy;
use troe_memory::{
    BASE_PAGE_SIZE, FrameAllocationError, FrameAllocator, MappingPermissions, PhysicalExtents,
    PhysicalRange, VirtualRange,
};

/// Largest number of physical extents one launch reservation may use.
///
/// Every extent contributes at least one bounded mapping-plan record, and
/// one plan holds at most `troe_memory::MAX_MAPPINGS` records across kernel
/// and application mappings together. Refusing a more fragmented
/// reservation up front keeps the allocation loop bounded and turns "too
/// fragmented to describe" into the same fail-closed refusal as "not enough
/// frames", rather than a failure discovered while building the plan.
pub(crate) const MAX_APPLICATION_EXTENTS: usize = 256;

/// Pages the startup page occupies between the image and the heap.
pub(crate) const APPLICATION_STARTUP_PAGES: u64 = 1;

/// Whether a launch reservation coalesces physically adjacent quanta.
///
/// Production always coalesces, so an unfragmented machine reserves exactly
/// one extent and builds exactly the mapping records the former contiguous
/// reservation built. The acceptance image deliberately does not, so every
/// command launch exercises the multi-extent mapping, payload-copy, and
/// straddling-relocation paths that real fragmentation would otherwise
/// reach only rarely and nondeterministically.
pub(crate) const COALESCE_LAUNCH_EXTENTS: bool = !cfg!(feature = "acceptance-probes");

/// Pages reserved per launch step in the acceptance image.
///
/// Production reserves the configured operation quantum and coalesces, so an
/// unfragmented machine takes exactly one extent. The acceptance image takes
/// tiny non-coalescing steps instead, so every command launch is backed by
/// several extents and exercises the split mapping, payload-copy,
/// straddling-relocation, and buffer-validation paths on every run rather
/// than only when memory happens to be fragmented.
pub(crate) const ACCEPTANCE_LAUNCH_QUANTUM_PAGES: u64 = 4;

pub(crate) struct ApplicationPrivateMemory {
    pub(crate) mappings: Vec<ApplicationPrivateMapping>,
    arena_end: u64,
    pub(crate) maximum_committed_pages: Option<u64>,
    maximum_reserved_pages: Option<u64>,
    maximum_mappings: u64,
    maximum_metadata_bytes: u64,
    operation_quantum_pages: u64,
    reserved_pages: u64,
    pub(crate) committed_pages: u64,
    pub(crate) metadata_bytes: u64,
    high_water_reserved_pages: u64,
    high_water_committed_pages: u64,
    high_water_mappings: u64,
    high_water_metadata_bytes: u64,
}

pub(crate) struct ApplicationPrivateMapping {
    pub(crate) range: VirtualRange,
    protection: private_memory::Protection,
    pub(crate) backing: Vec<PhysicalRange>,
}

impl ApplicationPrivateMemory {
    pub(crate) fn new(policy: MemoryPolicy, arena_end: u64) -> Self {
        Self {
            mappings: Vec::new(),
            arena_end,
            maximum_committed_pages: policy.default_committed_pages().maximum(),
            maximum_reserved_pages: policy.default_reserved_pages().maximum(),
            maximum_mappings: policy.default_maximum_mappings(),
            maximum_metadata_bytes: policy.default_maximum_metadata_bytes(),
            operation_quantum_pages: policy.operation_quantum_pages(),
            reserved_pages: 0,
            committed_pages: 0,
            metadata_bytes: 0,
            high_water_reserved_pages: 0,
            high_water_committed_pages: 0,
            high_water_mappings: 0,
            high_water_metadata_bytes: 0,
        }
    }

    fn statistics(&self) -> private_memory::Statistics {
        private_memory::Statistics {
            flags: (u64::from(self.maximum_committed_pages.is_some())
                * private_memory::COMMITTED_LIMITED)
                | (u64::from(self.maximum_reserved_pages.is_some())
                    * private_memory::RESERVED_LIMITED),
            maximum_committed_pages: self.maximum_committed_pages.unwrap_or(0),
            maximum_reserved_pages: self.maximum_reserved_pages.unwrap_or(0),
            maximum_mappings: self.maximum_mappings,
            maximum_metadata_bytes: self.maximum_metadata_bytes,
            operation_quantum_pages: self.operation_quantum_pages,
            reserved_pages: self.reserved_pages,
            committed_pages: self.committed_pages,
            mappings: u64::try_from(self.mappings.len()).unwrap_or(u64::MAX),
            metadata_bytes: self.metadata_bytes,
            high_water_reserved_pages: self.high_water_reserved_pages,
            high_water_committed_pages: self.high_water_committed_pages,
            high_water_mappings: self.high_water_mappings,
            high_water_metadata_bytes: self.high_water_metadata_bytes,
        }
    }
}

pub(crate) struct ApplicationPrivateAllocation {
    pub(crate) extents: PhysicalExtents,
    pub(crate) image_pages: u64,
    pub(crate) startup: PhysicalRange,
    pub(crate) heap_pages: u64,
    pub(crate) stack_pages: u64,
}

pub(crate) enum ApplicationGrowth {
    Committed {
        stats: troe_machine::MmuStats,
        mapped_bytes: u64,
    },
    Exhausted,
}

pub(crate) enum PrivateMemoryError {
    Reply(ReplyStatus),
    Terminal,
}

pub(crate) struct PrivateMemoryReply {
    pub(crate) status: ReplyStatus,
    pub(crate) payload: Vec<u8>,
    pub(crate) resources_changed: bool,
}

pub(crate) fn private_permissions(
    protection: private_memory::Protection,
) -> Option<MappingPermissions> {
    match protection {
        private_memory::Protection::None => None,
        private_memory::Protection::Read => Some(MappingPermissions::READ_ONLY),
        private_memory::Protection::ReadWrite => Some(MappingPermissions::READ_WRITE),
    }
}

pub(crate) fn private_metadata_bytes(mappings: &[ApplicationPrivateMapping]) -> Option<u64> {
    let mapping_count = u64::try_from(mappings.len()).ok()?;
    let extent_count = mappings.iter().try_fold(0_u64, |total, mapping| {
        total.checked_add(u64::try_from(mapping.backing.len()).ok()?)
    })?;
    mapping_count
        .checked_mul(u64::try_from(core::mem::size_of::<ApplicationPrivateMapping>()).ok()?)?
        .checked_add(
            extent_count.checked_mul(u64::try_from(core::mem::size_of::<PhysicalRange>()).ok()?)?,
        )
}

pub(crate) fn private_heap_end(
    allocation: &ApplicationAllocation,
    heap_start: u64,
) -> Result<u64, PrivateMemoryError> {
    let pages = allocation
        .heap_pages
        .checked_add(
            application_growth_pages(allocation).map_err(|()| PrivateMemoryError::Terminal)?,
        )
        .ok_or(PrivateMemoryError::Terminal)?;
    heap_start
        .checked_add(
            pages
                .checked_mul(BASE_PAGE_SIZE)
                .ok_or(PrivateMemoryError::Terminal)?,
        )
        .ok_or(PrivateMemoryError::Terminal)
}

pub(crate) fn private_range_available(
    state: &ApplicationPrivateMemory,
    floor: u64,
    range: VirtualRange,
) -> bool {
    range.start() >= floor
        && range.end() <= state.arena_end
        && state.mappings.iter().all(|mapping| {
            mapping.range.end() <= range.start() || range.end() <= mapping.range.start()
        })
}

pub(crate) fn align_down(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    Some(value & !(alignment - 1))
}

pub(crate) fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .and_then(|rounded| align_down(rounded, alignment))
}

pub(crate) fn private_gap_slots(
    gap_start: u64,
    gap_end: u64,
    byte_count: u64,
    alignment: u64,
) -> Option<(u64, u64)> {
    let first = align_up(gap_start, alignment)?;
    let last = gap_end
        .checked_sub(byte_count)
        .and_then(|value| align_down(value, alignment))?;
    if first > last {
        return None;
    }
    let slots = last
        .checked_sub(first)?
        .checked_div(alignment)?
        .checked_add(1)?;
    Some((first, slots))
}

pub(crate) fn select_private_gap(
    gap_start: u64,
    gap_end: u64,
    byte_count: u64,
    alignment: u64,
    selected: &mut u64,
) -> Result<Option<u64>, PrivateMemoryError> {
    let Some((first, slots)) = private_gap_slots(gap_start, gap_end, byte_count, alignment) else {
        return Ok(None);
    };
    if *selected >= slots {
        *selected = selected
            .checked_sub(slots)
            .ok_or(PrivateMemoryError::Terminal)?;
        return Ok(None);
    }
    let offset = selected
        .checked_mul(alignment)
        .ok_or(PrivateMemoryError::Terminal)?;
    Ok(Some(
        first
            .checked_add(offset)
            .ok_or(PrivateMemoryError::Terminal)?,
    ))
}

pub(crate) fn choose_private_range(
    state: &ApplicationPrivateMemory,
    floor: u64,
    request: private_memory::MapRequest,
    random: &SharedRandom,
) -> Result<VirtualRange, PrivateMemoryError> {
    let byte_count = request
        .page_count
        .checked_mul(BASE_PAGE_SIZE)
        .ok_or(PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
    let alignment = request
        .alignment_pages
        .checked_mul(BASE_PAGE_SIZE)
        .ok_or(PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
    if request.address_hint != 0
        && request.address_hint.is_multiple_of(alignment)
        && let Ok(range) = VirtualRange::from_pages(request.address_hint, request.page_count)
        && private_range_available(state, floor, range)
    {
        return Ok(range);
    }
    let mut total_slots = 0_u64;
    let mut gap_start = floor;
    for mapping in &state.mappings {
        if let Some((_, slots)) =
            private_gap_slots(gap_start, mapping.range.start(), byte_count, alignment)
        {
            total_slots = total_slots
                .checked_add(slots)
                .ok_or(PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
        }
        gap_start = mapping.range.end().max(gap_start);
    }
    if let Some((_, slots)) = private_gap_slots(gap_start, state.arena_end, byte_count, alignment) {
        total_slots = total_slots
            .checked_add(slots)
            .ok_or(PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
    }
    if total_slots == 0 {
        return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
    }
    let mut selected = random
        .try_borrow_mut()
        .map_err(|_| PrivateMemoryError::Terminal)?
        .uniform_u64(total_slots)
        .map_err(|_| PrivateMemoryError::Terminal)?;
    gap_start = floor;
    let mut selected_start = None;
    for mapping in &state.mappings {
        if let Some(start) = select_private_gap(
            gap_start,
            mapping.range.start(),
            byte_count,
            alignment,
            &mut selected,
        )? {
            selected_start = Some(start);
            break;
        }
        gap_start = mapping.range.end().max(gap_start);
    }
    if selected_start.is_none() {
        selected_start = select_private_gap(
            gap_start,
            state.arena_end,
            byte_count,
            alignment,
            &mut selected,
        )?;
    }
    let range = VirtualRange::from_pages(
        selected_start.ok_or(PrivateMemoryError::Terminal)?,
        request.page_count,
    )
    .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
    Ok(range)
}

pub(crate) fn append_private_extent(
    extents: &mut Vec<PhysicalRange>,
    frame: u64,
) -> Result<(), PrivateMemoryError> {
    if let Some(last) = extents.last_mut()
        && last.end() == frame
    {
        *last = PhysicalRange::from_pages(
            last.start(),
            last.page_count()
                .checked_add(1)
                .ok_or(PrivateMemoryError::Terminal)?,
        )
        .map_err(|_| PrivateMemoryError::Terminal)?;
        return Ok(());
    }
    extents
        .try_reserve(1)
        .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
    extents.push(PhysicalRange::from_pages(frame, 1).map_err(|_| PrivateMemoryError::Terminal)?);
    Ok(())
}

pub(crate) fn release_private_extents(
    frames: &mut FrameAllocator,
    extents: &[PhysicalRange],
) -> Result<(), PrivateMemoryError> {
    for range in extents {
        troe_machine::zero_physical_range(*range).map_err(|_| PrivateMemoryError::Terminal)?;
        frames
            .free_range(*range)
            .map_err(|_| PrivateMemoryError::Terminal)?;
    }
    Ok(())
}

pub(crate) fn allocate_private_extents(
    frames: &mut FrameAllocator,
    page_count: u64,
    operation_quantum_pages: u64,
) -> Result<Vec<PhysicalRange>, PrivateMemoryError> {
    if operation_quantum_pages == 0 {
        return Err(PrivateMemoryError::Terminal);
    }
    let mut extents = Vec::new();
    let mut remaining = page_count;
    while remaining != 0 {
        let quantum = remaining.min(operation_quantum_pages);
        match frames.allocate_contiguous(quantum, 1) {
            Ok(range) => {
                if extents.try_reserve(1).is_err() {
                    frames
                        .free_range(range)
                        .map_err(|_| PrivateMemoryError::Terminal)?;
                    release_private_extents(frames, &extents)?;
                    return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
                }
                if troe_machine::zero_physical_range(range).is_err() {
                    frames
                        .free_range(range)
                        .map_err(|_| PrivateMemoryError::Terminal)?;
                    release_private_extents(frames, &extents)?;
                    return Err(PrivateMemoryError::Terminal);
                }
                extents.push(range);
            }
            Err(FrameAllocationError::Exhausted) => {
                for _ in 0..quantum {
                    let Ok(frame) = frames.allocate() else {
                        release_private_extents(frames, &extents)?;
                        return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
                    };
                    let range = PhysicalRange::from_pages(frame, 1)
                        .map_err(|_| PrivateMemoryError::Terminal)?;
                    if troe_machine::zero_physical_range(range).is_err() {
                        frames
                            .free(frame)
                            .map_err(|_| PrivateMemoryError::Terminal)?;
                        release_private_extents(frames, &extents)?;
                        return Err(PrivateMemoryError::Terminal);
                    }
                    if let Err(error) = append_private_extent(&mut extents, frame) {
                        frames
                            .free(frame)
                            .map_err(|_| PrivateMemoryError::Terminal)?;
                        release_private_extents(frames, &extents)?;
                        return Err(error);
                    }
                }
            }
            Err(_) => {
                release_private_extents(frames, &extents)?;
                return Err(PrivateMemoryError::Terminal);
            }
        }
        remaining = remaining
            .checked_sub(quantum)
            .ok_or(PrivateMemoryError::Terminal)?;
    }
    Ok(extents)
}

pub(crate) fn private_policy_allows(
    accounting: &OwnedAccounting,
    allocation: &ApplicationAllocation,
    reserved_pages: u64,
    committed_pages: u64,
    mappings: u64,
    metadata_bytes: u64,
) -> Result<(), PrivateMemoryError> {
    let state = &allocation.private_memory;
    let process_commit = allocation
        .extents
        .page_count()
        .checked_add(
            application_growth_pages(allocation).map_err(|()| PrivateMemoryError::Terminal)?,
        )
        .and_then(|pages| pages.checked_add(committed_pages))
        .ok_or(PrivateMemoryError::Terminal)?;
    if state
        .maximum_reserved_pages
        .is_some_and(|maximum| reserved_pages > maximum)
        || state
            .maximum_committed_pages
            .is_some_and(|maximum| process_commit > maximum)
        || mappings > state.maximum_mappings
        || metadata_bytes > state.maximum_metadata_bytes
    {
        return Err(PrivateMemoryError::Reply(ReplyStatus::ResourceLimit));
    }
    let global_metadata = accounting
        .private_metadata_bytes
        .checked_sub(state.metadata_bytes)
        .and_then(|value| value.checked_add(metadata_bytes))
        .ok_or(PrivateMemoryError::Terminal)?;
    let system_commit = accounting
        .application_committed_pages
        .checked_sub(state.committed_pages)
        .and_then(|value| value.checked_add(committed_pages))
        .ok_or(PrivateMemoryError::Terminal)?;
    if global_metadata > accounting.memory_policy.global_metadata_bytes()
        || accounting
            .memory_policy
            .system_application_commit()
            .maximum()
            .is_some_and(|maximum| system_commit > maximum)
    {
        return Err(PrivateMemoryError::Reply(ReplyStatus::ResourceLimit));
    }
    Ok(())
}

pub(crate) fn commit_private_accounting(
    accounting: &mut OwnedAccounting,
    state: &mut ApplicationPrivateMemory,
    reserved_pages: u64,
    committed_pages: u64,
    metadata_bytes: u64,
) -> Result<(), PrivateMemoryError> {
    accounting.private_metadata_bytes = accounting
        .private_metadata_bytes
        .checked_sub(state.metadata_bytes)
        .and_then(|value| value.checked_add(metadata_bytes))
        .ok_or(PrivateMemoryError::Terminal)?;
    accounting.application_committed_pages = accounting
        .application_committed_pages
        .checked_sub(state.committed_pages)
        .and_then(|value| value.checked_add(committed_pages))
        .ok_or(PrivateMemoryError::Terminal)?;
    state.reserved_pages = reserved_pages;
    state.committed_pages = committed_pages;
    state.metadata_bytes = metadata_bytes;
    state.high_water_reserved_pages = state.high_water_reserved_pages.max(reserved_pages);
    state.high_water_committed_pages = state.high_water_committed_pages.max(committed_pages);
    state.high_water_mappings = state
        .high_water_mappings
        .max(u64::try_from(state.mappings.len()).map_err(|_| PrivateMemoryError::Terminal)?);
    state.high_water_metadata_bytes = state.high_water_metadata_bytes.max(metadata_bytes);
    Ok(())
}

pub(crate) fn reserve_private_table_frames(
    frames: &mut FrameAllocator,
    allocation: &mut ApplicationAllocation,
    application: &troe_machine::ApplicationSession,
    virtual_start: u64,
    page_count: u64,
    minimum_free_pages: u64,
) -> Result<usize, PrivateMemoryError> {
    let range = VirtualRange::from_pages(virtual_start, page_count)
        .map_err(|_| PrivateMemoryError::Terminal)?;
    let required = troe_machine::maximum_additional_page_table_pages(range)
        .map_err(|_| PrivateMemoryError::Terminal)?;
    let retained = allocation
        .tables
        .page_count()
        .checked_add(
            u64::try_from(allocation.growth_table_frames.len())
                .map_err(|_| PrivateMemoryError::Terminal)?,
        )
        .ok_or(PrivateMemoryError::Terminal)?;
    let available = retained
        .checked_sub(application.stats().table_pages)
        .ok_or(PrivateMemoryError::Terminal)?;
    let deficit = usize::try_from(required.saturating_sub(available))
        .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
    allocation
        .growth_table_frames
        .try_reserve_exact(deficit)
        .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
    let needed = u64::try_from(deficit).map_err(|_| PrivateMemoryError::Terminal)?;
    if frames.free_frames().saturating_sub(minimum_free_pages) < needed {
        return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
    }
    let retained_len = allocation.growth_table_frames.len();
    for _ in 0..deficit {
        let Ok(frame) = frames.allocate() else {
            while allocation.growth_table_frames.len() > retained_len {
                let frame = allocation
                    .growth_table_frames
                    .pop()
                    .ok_or(PrivateMemoryError::Terminal)?;
                frames
                    .free(frame)
                    .map_err(|_| PrivateMemoryError::Terminal)?;
            }
            return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
        };
        allocation.growth_table_frames.push(frame);
    }
    Ok(retained_len)
}

pub(crate) fn insert_private_mapping(
    state: &mut ApplicationPrivateMemory,
    mapping: ApplicationPrivateMapping,
) -> Result<(), PrivateMemoryError> {
    state
        .mappings
        .try_reserve(1)
        .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
    let index = state
        .mappings
        .binary_search_by_key(&mapping.range.start(), |current| current.range.start())
        .unwrap_or_else(|index| index);
    state.mappings.insert(index, mapping);
    Ok(())
}

pub(crate) fn private_extent_slice(
    extents: &[PhysicalRange],
    start_page: u64,
    page_count: u64,
) -> Result<Vec<PhysicalRange>, PrivateMemoryError> {
    let wanted_end = start_page
        .checked_add(page_count)
        .ok_or(PrivateMemoryError::Terminal)?;
    let mut result = Vec::new();
    let mut logical_start = 0_u64;
    for extent in extents {
        let logical_end = logical_start
            .checked_add(extent.page_count())
            .ok_or(PrivateMemoryError::Terminal)?;
        let overlap_start = logical_start.max(start_page);
        let overlap_end = logical_end.min(wanted_end);
        if overlap_start < overlap_end {
            result
                .try_reserve(1)
                .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
            result.push(
                PhysicalRange::from_pages(
                    extent
                        .start()
                        .checked_add(
                            overlap_start
                                .checked_sub(logical_start)
                                .ok_or(PrivateMemoryError::Terminal)?
                                .checked_mul(BASE_PAGE_SIZE)
                                .ok_or(PrivateMemoryError::Terminal)?,
                        )
                        .ok_or(PrivateMemoryError::Terminal)?,
                    overlap_end
                        .checked_sub(overlap_start)
                        .ok_or(PrivateMemoryError::Terminal)?,
                )
                .map_err(|_| PrivateMemoryError::Terminal)?,
            );
        }
        logical_start = logical_end;
    }
    let represented = result.iter().try_fold(0_u64, |pages, extent| {
        pages.checked_add(extent.page_count())
    });
    if represented != Some(page_count) {
        return Err(PrivateMemoryError::Terminal);
    }
    Ok(result)
}

pub(crate) fn private_subrange(
    range: VirtualRange,
    start_page: u64,
    page_count: u64,
) -> Result<VirtualRange, PrivateMemoryError> {
    let byte_offset = start_page
        .checked_mul(BASE_PAGE_SIZE)
        .ok_or(PrivateMemoryError::Terminal)?;
    VirtualRange::from_pages(
        range
            .start()
            .checked_add(byte_offset)
            .ok_or(PrivateMemoryError::Terminal)?,
        page_count,
    )
    .map_err(|_| PrivateMemoryError::Terminal)
}

pub(crate) fn private_backing_slice(
    mapping: &ApplicationPrivateMapping,
    start_page: u64,
    page_count: u64,
) -> Result<Vec<PhysicalRange>, PrivateMemoryError> {
    if mapping.backing.is_empty() {
        Ok(Vec::new())
    } else {
        private_extent_slice(&mapping.backing, start_page, page_count)
    }
}

pub(crate) fn split_private_mapping(
    mapping: &ApplicationPrivateMapping,
    address: u64,
    page_count: u64,
    middle_protection: Option<private_memory::Protection>,
    new_middle_backing: Option<Vec<PhysicalRange>>,
) -> Result<(Vec<ApplicationPrivateMapping>, Vec<PhysicalRange>), PrivateMemoryError> {
    let request = VirtualRange::from_pages(address, page_count)
        .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
    if request.start() < mapping.range.start() || request.end() > mapping.range.end() {
        return Err(PrivateMemoryError::Reply(ReplyStatus::NotFound));
    }
    let before_pages = request
        .start()
        .checked_sub(mapping.range.start())
        .and_then(|bytes| bytes.checked_div(BASE_PAGE_SIZE))
        .ok_or(PrivateMemoryError::Terminal)?;
    let after_pages = mapping
        .range
        .page_count()
        .checked_sub(before_pages)
        .and_then(|pages| pages.checked_sub(page_count))
        .ok_or(PrivateMemoryError::Terminal)?;
    if new_middle_backing.is_some() && !mapping.backing.is_empty() {
        return Err(PrivateMemoryError::Terminal);
    }
    let mut replacements = Vec::new();
    replacements
        .try_reserve_exact(usize::from(before_pages != 0) + usize::from(after_pages != 0) + 1)
        .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
    if before_pages != 0 {
        replacements.push(ApplicationPrivateMapping {
            range: private_subrange(mapping.range, 0, before_pages)?,
            protection: mapping.protection,
            backing: private_backing_slice(mapping, 0, before_pages)?,
        });
    }
    let existing_middle = private_backing_slice(mapping, before_pages, page_count)?;
    let (middle_backing, removed) = if middle_protection.is_some() {
        (
            Some(new_middle_backing.unwrap_or(existing_middle)),
            Vec::new(),
        )
    } else {
        (None, existing_middle)
    };
    if let Some(protection) = middle_protection {
        replacements.push(ApplicationPrivateMapping {
            range: request,
            protection,
            backing: middle_backing.ok_or(PrivateMemoryError::Terminal)?,
        });
    }
    if after_pages != 0 {
        replacements.push(ApplicationPrivateMapping {
            range: private_subrange(
                mapping.range,
                before_pages
                    .checked_add(page_count)
                    .ok_or(PrivateMemoryError::Terminal)?,
                after_pages,
            )?,
            protection: mapping.protection,
            backing: private_backing_slice(
                mapping,
                before_pages
                    .checked_add(page_count)
                    .ok_or(PrivateMemoryError::Terminal)?,
                after_pages,
            )?,
        });
    }
    Ok((replacements, removed))
}

pub(crate) fn private_replacement_metadata(
    state: &ApplicationPrivateMemory,
    index: usize,
    replacements: &[ApplicationPrivateMapping],
) -> Result<(u64, u64), PrivateMemoryError> {
    let old = state
        .mappings
        .get(index)
        .ok_or(PrivateMemoryError::Terminal)?;
    let mapping_count = u64::try_from(state.mappings.len())
        .map_err(|_| PrivateMemoryError::Terminal)?
        .checked_sub(1)
        .and_then(|count| count.checked_add(u64::try_from(replacements.len()).ok()?))
        .ok_or(PrivateMemoryError::Terminal)?;
    let old_extent_bytes = u64::try_from(old.backing.len())
        .map_err(|_| PrivateMemoryError::Terminal)?
        .checked_mul(
            u64::try_from(core::mem::size_of::<PhysicalRange>())
                .map_err(|_| PrivateMemoryError::Terminal)?,
        )
        .ok_or(PrivateMemoryError::Terminal)?;
    let replacement_extent_count = replacements.iter().try_fold(0_u64, |count, mapping| {
        count.checked_add(u64::try_from(mapping.backing.len()).ok()?)
    });
    let replacement_extent_bytes = replacement_extent_count
        .ok_or(PrivateMemoryError::Terminal)?
        .checked_mul(
            u64::try_from(core::mem::size_of::<PhysicalRange>())
                .map_err(|_| PrivateMemoryError::Terminal)?,
        )
        .ok_or(PrivateMemoryError::Terminal)?;
    let mapping_bytes = mapping_count
        .checked_mul(
            u64::try_from(core::mem::size_of::<ApplicationPrivateMapping>())
                .map_err(|_| PrivateMemoryError::Terminal)?,
        )
        .ok_or(PrivateMemoryError::Terminal)?;
    let current_extent_bytes = state
        .metadata_bytes
        .checked_sub(
            u64::try_from(state.mappings.len())
                .map_err(|_| PrivateMemoryError::Terminal)?
                .checked_mul(
                    u64::try_from(core::mem::size_of::<ApplicationPrivateMapping>())
                        .map_err(|_| PrivateMemoryError::Terminal)?,
                )
                .ok_or(PrivateMemoryError::Terminal)?,
        )
        .ok_or(PrivateMemoryError::Terminal)?;
    let metadata_bytes = current_extent_bytes
        .checked_sub(old_extent_bytes)
        .and_then(|bytes| bytes.checked_add(replacement_extent_bytes))
        .and_then(|bytes| bytes.checked_add(mapping_bytes))
        .ok_or(PrivateMemoryError::Terminal)?;
    Ok((mapping_count, metadata_bytes))
}

pub(crate) fn install_private_replacements(
    state: &mut ApplicationPrivateMemory,
    index: usize,
    replacements: Vec<ApplicationPrivateMapping>,
) -> Result<(), PrivateMemoryError> {
    let additional = replacements.len().saturating_sub(1);
    state
        .mappings
        .try_reserve(additional)
        .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
    let _removed = state.mappings.remove(index);
    for (offset, replacement) in replacements.into_iter().enumerate() {
        state.mappings.insert(index + offset, replacement);
    }
    Ok(())
}

pub(crate) fn coalesce_private_mappings(
    state: &mut ApplicationPrivateMemory,
) -> Result<(), PrivateMemoryError> {
    let mut index = 1_usize;
    while index < state.mappings.len() {
        let left_index = index - 1;
        let compatible = {
            let left = &state.mappings[left_index];
            let right = &state.mappings[index];
            left.range.end() == right.range.start()
                && left.protection == right.protection
                && left.backing.is_empty() == right.backing.is_empty()
        };
        if !compatible {
            index = index.checked_add(1).ok_or(PrivateMemoryError::Terminal)?;
            continue;
        }
        let merged_range = {
            let left = &state.mappings[left_index];
            let right = &state.mappings[index];
            VirtualRange::from_pages(
                left.range.start(),
                left.range
                    .page_count()
                    .checked_add(right.range.page_count())
                    .ok_or(PrivateMemoryError::Terminal)?,
            )
            .map_err(|_| PrivateMemoryError::Terminal)?
        };
        let boundary_merges = state.mappings[left_index]
            .backing
            .last()
            .zip(state.mappings[index].backing.first())
            .is_some_and(|(left, right)| left.end() == right.start());
        let additional_extents = state.mappings[index]
            .backing
            .len()
            .saturating_sub(usize::from(boundary_merges));
        if state.mappings[left_index]
            .backing
            .try_reserve(additional_extents)
            .is_err()
        {
            index = index.checked_add(1).ok_or(PrivateMemoryError::Terminal)?;
            continue;
        }
        let right = state.mappings.remove(index);
        let left = &mut state.mappings[left_index];
        left.range = merged_range;
        let mut skip = 0_usize;
        if boundary_merges {
            let left_extent = left
                .backing
                .last_mut()
                .ok_or(PrivateMemoryError::Terminal)?;
            let right_extent = right.backing.first().ok_or(PrivateMemoryError::Terminal)?;
            *left_extent = PhysicalRange::from_pages(
                left_extent.start(),
                left_extent
                    .page_count()
                    .checked_add(right_extent.page_count())
                    .ok_or(PrivateMemoryError::Terminal)?,
            )
            .map_err(|_| PrivateMemoryError::Terminal)?;
            skip = 1;
        }
        left.backing.extend_from_slice(&right.backing[skip..]);
    }
    Ok(())
}

pub(crate) fn private_address_reply(address: u64) -> Result<Vec<u8>, PrivateMemoryError> {
    let encoded =
        private_memory::encode_address(address).map_err(|_| PrivateMemoryError::Terminal)?;
    owned_reply_payload(&encoded).map_err(|()| PrivateMemoryError::Reply(ReplyStatus::Exhausted))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn handle_private_memory_call(
    accounting: &mut OwnedAccounting,
    allocation: &mut ApplicationAllocation,
    application: &mut troe_machine::ApplicationSession,
    heap_start: u64,
    opcode: u16,
    payload: &[u8],
) -> Result<PrivateMemoryReply, PrivateMemoryError> {
    if opcode == private_memory::QUERY {
        if !payload.is_empty() {
            return Err(PrivateMemoryError::Reply(ReplyStatus::InvalidRequest));
        }
        let encoded = private_memory::encode_statistics(allocation.private_memory.statistics())
            .map_err(|_| PrivateMemoryError::Terminal)?;
        return Ok(PrivateMemoryReply {
            status: ReplyStatus::Success,
            payload: owned_reply_payload(&encoded)
                .map_err(|()| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?,
            resources_changed: false,
        });
    }

    if matches!(opcode, private_memory::RESERVE | private_memory::MAP_ZEROED) {
        let request = private_memory::decode_map_request(payload)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
        if opcode == private_memory::RESERVE
            && request.protection != private_memory::Protection::None
        {
            return Err(PrivateMemoryError::Reply(ReplyStatus::InvalidRequest));
        }
        let floor = private_heap_end(allocation, heap_start)?;
        let range = choose_private_range(
            &allocation.private_memory,
            floor,
            request,
            &accounting.random,
        )?;
        let address_reply = private_address_reply(range.start())?;
        allocation
            .private_memory
            .mappings
            .try_reserve(1)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
        let mut backing = Vec::new();
        if opcode == private_memory::MAP_ZEROED {
            let minimum_free = accounting.memory_policy.minimum_free_pages();
            let available = accounting.frames.free_frames().saturating_sub(minimum_free);
            if request.page_count > available {
                return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
            }
            backing = allocate_private_extents(
                &mut accounting.frames,
                request.page_count,
                accounting.memory_policy.operation_quantum_pages(),
            )?;
        }
        let retained_tables = if opcode == private_memory::MAP_ZEROED
            && request.protection != private_memory::Protection::None
        {
            match reserve_private_table_frames(
                &mut accounting.frames,
                allocation,
                application,
                range.start(),
                range.page_count(),
                accounting.memory_policy.minimum_free_pages(),
            ) {
                Ok(retained) => Some(retained),
                Err(error) => {
                    release_private_extents(&mut accounting.frames, &backing)?;
                    return Err(error);
                }
            }
        } else {
            None
        };
        let mapping = ApplicationPrivateMapping {
            range,
            protection: request.protection,
            backing,
        };
        insert_private_mapping(&mut allocation.private_memory, mapping)?;
        let reserved = allocation
            .private_memory
            .reserved_pages
            .checked_add(request.page_count)
            .ok_or(PrivateMemoryError::Terminal)?;
        let committed = allocation
            .private_memory
            .committed_pages
            .checked_add(u64::from(opcode == private_memory::MAP_ZEROED) * request.page_count)
            .ok_or(PrivateMemoryError::Terminal)?;
        let metadata = private_metadata_bytes(&allocation.private_memory.mappings)
            .ok_or(PrivateMemoryError::Terminal)?;
        let mapping_count = u64::try_from(allocation.private_memory.mappings.len())
            .map_err(|_| PrivateMemoryError::Terminal)?;
        if let Err(error) = private_policy_allows(
            accounting,
            allocation,
            reserved,
            committed,
            mapping_count,
            metadata,
        ) {
            let mapping = allocation.private_memory.mappings.remove(
                allocation
                    .private_memory
                    .mappings
                    .iter()
                    .position(|mapping| mapping.range == range)
                    .ok_or(PrivateMemoryError::Terminal)?,
            );
            release_private_extents(&mut accounting.frames, &mapping.backing)?;
            if let Some(retained) = retained_tables {
                while allocation.growth_table_frames.len() > retained {
                    let frame = allocation
                        .growth_table_frames
                        .pop()
                        .ok_or(PrivateMemoryError::Terminal)?;
                    accounting
                        .frames
                        .free(frame)
                        .map_err(|_| PrivateMemoryError::Terminal)?;
                }
            }
            return Err(error);
        }
        commit_private_accounting(
            accounting,
            &mut allocation.private_memory,
            reserved,
            committed,
            metadata,
        )?;
        if opcode == private_memory::MAP_ZEROED
            && request.protection != private_memory::Protection::None
        {
            let mapping = allocation
                .private_memory
                .mappings
                .iter()
                .find(|mapping| mapping.range == range)
                .ok_or(PrivateMemoryError::Terminal)?;
            application
                .replace_private_access(
                    range.start(),
                    &mapping.backing,
                    false,
                    private_permissions(request.protection),
                    &allocation.growth_table_frames,
                )
                .map_err(|_| PrivateMemoryError::Terminal)?;
        }
        return Ok(PrivateMemoryReply {
            status: ReplyStatus::Success,
            payload: address_reply,
            resources_changed: opcode == private_memory::MAP_ZEROED,
        });
    }

    if opcode == private_memory::PROTECT {
        let request = private_memory::decode_protect_request(payload)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
        let request_range = VirtualRange::from_pages(request.address, request.page_count)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
        let index = allocation
            .private_memory
            .mappings
            .iter()
            .position(|mapping| {
                mapping.range.start() <= request_range.start()
                    && request_range.end() <= mapping.range.end()
            })
            .ok_or(PrivateMemoryError::Reply(ReplyStatus::NotFound))?;
        let old_protection = allocation.private_memory.mappings[index].protection;
        if old_protection == request.protection {
            return Ok(PrivateMemoryReply {
                status: ReplyStatus::Success,
                payload: Vec::new(),
                resources_changed: false,
            });
        }
        let needs_backing = allocation.private_memory.mappings[index].backing.is_empty()
            && request.protection != private_memory::Protection::None;
        let (mut replacements, removed) = split_private_mapping(
            &allocation.private_memory.mappings[index],
            request.address,
            request.page_count,
            Some(request.protection),
            None,
        )?;
        if !removed.is_empty() {
            return Err(PrivateMemoryError::Terminal);
        }
        let middle = replacements
            .iter()
            .position(|mapping| mapping.range == request_range)
            .ok_or(PrivateMemoryError::Terminal)?;
        if needs_backing {
            let available = accounting
                .frames
                .free_frames()
                .saturating_sub(accounting.memory_policy.minimum_free_pages());
            if request.page_count > available {
                return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
            }
            replacements[middle].backing = allocate_private_extents(
                &mut accounting.frames,
                request.page_count,
                accounting.memory_policy.operation_quantum_pages(),
            )?;
        }
        let committed = allocation
            .private_memory
            .committed_pages
            .checked_add(u64::from(needs_backing) * request.page_count)
            .ok_or(PrivateMemoryError::Terminal)?;
        let (mapping_count, metadata) =
            private_replacement_metadata(&allocation.private_memory, index, &replacements)?;
        if let Err(error) = private_policy_allows(
            accounting,
            allocation,
            allocation.private_memory.reserved_pages,
            committed,
            mapping_count,
            metadata,
        ) {
            if needs_backing {
                release_private_extents(&mut accounting.frames, &replacements[middle].backing)?;
            }
            return Err(error);
        }
        let additional = replacements.len().saturating_sub(1);
        if allocation
            .private_memory
            .mappings
            .try_reserve(additional)
            .is_err()
        {
            if needs_backing {
                release_private_extents(&mut accounting.frames, &replacements[middle].backing)?;
            }
            return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
        }
        let retained_tables = if request.protection == private_memory::Protection::None {
            None
        } else {
            match reserve_private_table_frames(
                &mut accounting.frames,
                allocation,
                application,
                request.address,
                request.page_count,
                accounting.memory_policy.minimum_free_pages(),
            ) {
                Ok(retained) => Some(retained),
                Err(error) => {
                    if needs_backing {
                        release_private_extents(
                            &mut accounting.frames,
                            &replacements[middle].backing,
                        )?;
                    }
                    return Err(error);
                }
            }
        };
        if !replacements[middle].backing.is_empty()
            && application
                .replace_private_access(
                    request.address,
                    &replacements[middle].backing,
                    !allocation.private_memory.mappings[index].backing.is_empty()
                        && old_protection != private_memory::Protection::None,
                    private_permissions(request.protection),
                    &allocation.growth_table_frames,
                )
                .is_err()
        {
            if let Some(retained) = retained_tables {
                while allocation.growth_table_frames.len() > retained {
                    let frame = allocation
                        .growth_table_frames
                        .pop()
                        .ok_or(PrivateMemoryError::Terminal)?;
                    accounting
                        .frames
                        .free(frame)
                        .map_err(|_| PrivateMemoryError::Terminal)?;
                }
            }
            if needs_backing {
                release_private_extents(&mut accounting.frames, &replacements[middle].backing)?;
            }
            return Err(PrivateMemoryError::Terminal);
        }
        install_private_replacements(&mut allocation.private_memory, index, replacements)?;
        coalesce_private_mappings(&mut allocation.private_memory)?;
        let metadata = private_metadata_bytes(&allocation.private_memory.mappings)
            .ok_or(PrivateMemoryError::Terminal)?;
        let reserved = allocation.private_memory.reserved_pages;
        commit_private_accounting(
            accounting,
            &mut allocation.private_memory,
            reserved,
            committed,
            metadata,
        )?;
        return Ok(PrivateMemoryReply {
            status: ReplyStatus::Success,
            payload: Vec::new(),
            resources_changed: needs_backing,
        });
    }

    if opcode == private_memory::UNMAP {
        let request = private_memory::decode_unmap_request(payload)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
        let request_range = VirtualRange::from_pages(request.address, request.page_count)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
        let index = allocation
            .private_memory
            .mappings
            .iter()
            .position(|mapping| {
                mapping.range.start() <= request_range.start()
                    && request_range.end() <= mapping.range.end()
            })
            .ok_or(PrivateMemoryError::Reply(ReplyStatus::NotFound))?;
        let old_protection = allocation.private_memory.mappings[index].protection;
        let (replacements, removed_backing) = split_private_mapping(
            &allocation.private_memory.mappings[index],
            request.address,
            request.page_count,
            None,
            None,
        )?;
        let committed_removed = removed_backing
            .iter()
            .try_fold(0_u64, |total, range| total.checked_add(range.page_count()))
            .ok_or(PrivateMemoryError::Terminal)?;
        let reserved = allocation
            .private_memory
            .reserved_pages
            .checked_sub(request.page_count)
            .ok_or(PrivateMemoryError::Terminal)?;
        let committed = allocation
            .private_memory
            .committed_pages
            .checked_sub(committed_removed)
            .ok_or(PrivateMemoryError::Terminal)?;
        let (mapping_count, metadata) =
            private_replacement_metadata(&allocation.private_memory, index, &replacements)?;
        private_policy_allows(
            accounting,
            allocation,
            reserved,
            committed,
            mapping_count,
            metadata,
        )?;
        allocation
            .private_memory
            .mappings
            .try_reserve(replacements.len().saturating_sub(1))
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
        if !removed_backing.is_empty() && old_protection != private_memory::Protection::None {
            application
                .replace_private_access(
                    request.address,
                    &removed_backing,
                    true,
                    None,
                    &allocation.growth_table_frames,
                )
                .map_err(|_| PrivateMemoryError::Terminal)?;
        }
        install_private_replacements(&mut allocation.private_memory, index, replacements)?;
        release_private_extents(&mut accounting.frames, &removed_backing)?;
        coalesce_private_mappings(&mut allocation.private_memory)?;
        let metadata = private_metadata_bytes(&allocation.private_memory.mappings)
            .ok_or(PrivateMemoryError::Terminal)?;
        commit_private_accounting(
            accounting,
            &mut allocation.private_memory,
            reserved,
            committed,
            metadata,
        )?;
        return Ok(PrivateMemoryReply {
            status: ReplyStatus::Success,
            payload: Vec::new(),
            resources_changed: committed_removed != 0,
        });
    }

    Err(PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))
}

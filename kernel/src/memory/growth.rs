//! Heap growth: committing and releasing pages behind an application heap.
//!
//! A growth request is committed as whole pages appended to the private
//! reservation, charged against the application's totals, and rolled back as a
//! suffix if any part of it fails.

use crate::machine::OwnedAccounting;
use crate::memory::ApplicationAllocation;
use crate::memory::private::ApplicationGrowth;
use troe_memory::{BASE_PAGE_SIZE, FrameAllocationError, FrameAllocator, PhysicalRange};

pub(crate) fn application_resource_totals(
    allocation: &ApplicationAllocation,
    initial_private_pages: u64,
) -> Result<(u64, u64), ()> {
    let table_pages = allocation
        .tables
        .page_count()
        .checked_add(u64::try_from(allocation.growth_table_frames.len()).map_err(|_| ())?)
        .ok_or(())?;
    let private_pages = initial_private_pages
        .checked_add(application_growth_pages(allocation)?)
        .and_then(|value| value.checked_add(allocation.private_memory.committed_pages))
        .ok_or(())?;
    Ok((table_pages, private_pages))
}

#[allow(clippy::too_many_lines)]
pub(crate) fn commit_application_heap_growth(
    accounting: &mut OwnedAccounting,
    allocation: &mut ApplicationAllocation,
    application: &mut troe_machine::ApplicationSession,
    heap_start: u64,
    maximum_heap_pages: u64,
    minimum_pages: u64,
) -> Result<ApplicationGrowth, ()> {
    let initial_pages = allocation.heap_pages;
    let current_pages = initial_pages
        .checked_add(application_growth_pages(allocation)?)
        .ok_or(())?;
    let private_ceiling_pages = allocation
        .private_memory
        .mappings
        .first()
        .map_or(maximum_heap_pages, |mapping| {
            mapping.range.start().saturating_sub(heap_start) / BASE_PAGE_SIZE
        });
    let maximum_heap_pages = maximum_heap_pages.min(private_ceiling_pages);
    let remaining = maximum_heap_pages.checked_sub(current_pages).ok_or(())?;
    if minimum_pages == 0 || minimum_pages > remaining {
        return Ok(ApplicationGrowth::Exhausted);
    }
    if allocation.growth_ranges.try_reserve(1).is_err() {
        return Ok(ApplicationGrowth::Exhausted);
    }
    let heap_virtual_start = heap_start
        .checked_add(current_pages.checked_mul(BASE_PAGE_SIZE).ok_or(())?)
        .ok_or(())?;
    let required_new_tables = additional_table_pages(heap_virtual_start, minimum_pages)?;
    let retained_table_pages = allocation
        .tables
        .page_count()
        .checked_add(u64::try_from(allocation.growth_table_frames.len()).map_err(|_| ())?)
        .ok_or(())?;
    let available_table_pages = retained_table_pages
        .checked_sub(application.stats().table_pages)
        .ok_or(())?;
    let table_deficit = required_new_tables.saturating_sub(available_table_pages);
    let table_deficit = usize::try_from(table_deficit).map_err(|_| ())?;
    if allocation
        .growth_table_frames
        .try_reserve_exact(table_deficit)
        .is_err()
    {
        return Ok(ApplicationGrowth::Exhausted);
    }
    let needed_frames = minimum_pages
        .checked_add(u64::try_from(table_deficit).map_err(|_| ())?)
        .ok_or(())?;
    let application_commit = accounting
        .application_committed_pages
        .checked_add(minimum_pages)
        .ok_or(())?;
    let process_commit = allocation
        .extents
        .page_count()
        .checked_add(application_growth_pages(allocation)?)
        .and_then(|pages| pages.checked_add(allocation.private_memory.committed_pages))
        .and_then(|pages| pages.checked_add(minimum_pages))
        .ok_or(())?;
    if accounting
        .memory_policy
        .system_application_commit()
        .maximum()
        .is_some_and(|maximum| application_commit > maximum)
        || allocation
            .private_memory
            .maximum_committed_pages
            .is_some_and(|maximum| process_commit > maximum)
        || needed_frames
            > accounting
                .frames
                .free_frames()
                .saturating_sub(accounting.memory_policy.minimum_free_pages())
    {
        return Ok(ApplicationGrowth::Exhausted);
    }
    let start = allocation.growth_ranges.len();
    let table_start = allocation.growth_table_frames.len();
    for _ in 0..table_deficit {
        let Ok(frame) = accounting.frames.allocate() else {
            release_application_growth_suffix(
                &mut accounting.frames,
                allocation,
                start,
                table_start,
            )?;
            return Ok(ApplicationGrowth::Exhausted);
        };
        allocation.growth_table_frames.push(frame);
    }
    match accounting.frames.allocate_contiguous(minimum_pages, 1) {
        Ok(range) => {
            if troe_machine::zero_physical_range(range).is_err() {
                accounting.frames.free_range(range).map_err(|_| ())?;
                release_application_growth_suffix(
                    &mut accounting.frames,
                    allocation,
                    start,
                    table_start,
                )?;
                return Err(());
            }
            allocation.growth_ranges.push(range);
        }
        Err(FrameAllocationError::Exhausted) => {
            for _ in 0..minimum_pages {
                let Ok(frame) = accounting.frames.allocate() else {
                    release_application_growth_suffix(
                        &mut accounting.frames,
                        allocation,
                        start,
                        table_start,
                    )?;
                    return Ok(ApplicationGrowth::Exhausted);
                };
                let range = PhysicalRange::from_pages(frame, 1).map_err(|_| ())?;
                if troe_machine::zero_physical_range(range).is_err() {
                    accounting.frames.free(frame).map_err(|_| ())?;
                    release_application_growth_suffix(
                        &mut accounting.frames,
                        allocation,
                        start,
                        table_start,
                    )?;
                    return Err(());
                }
                if !append_application_growth_frame(allocation, start, frame)? {
                    accounting.frames.free(frame).map_err(|_| ())?;
                    release_application_growth_suffix(
                        &mut accounting.frames,
                        allocation,
                        start,
                        table_start,
                    )?;
                    return Ok(ApplicationGrowth::Exhausted);
                }
            }
        }
        Err(_) => {
            release_application_growth_suffix(
                &mut accounting.frames,
                allocation,
                start,
                table_start,
            )?;
            return Err(());
        }
    }
    let new_ranges = &allocation.growth_ranges[start..];
    let Ok(stats) =
        application.commit_heap_growth(heap_start, new_ranges, &allocation.growth_table_frames)
    else {
        release_application_growth_suffix(&mut accounting.frames, allocation, start, table_start)?;
        return Err(());
    };
    accounting.application_committed_pages = application_commit;
    let mapped_pages = current_pages.checked_add(minimum_pages).ok_or(())?;
    let mapped_bytes = mapped_pages.checked_mul(BASE_PAGE_SIZE).ok_or(())?;
    Ok(ApplicationGrowth::Committed {
        stats,
        mapped_bytes,
    })
}

pub(crate) fn release_application_growth_suffix(
    frames: &mut FrameAllocator,
    allocation: &mut ApplicationAllocation,
    retained: usize,
    retained_tables: usize,
) -> Result<(), ()> {
    while allocation.growth_ranges.len() > retained {
        let range = *allocation.growth_ranges.last().ok_or(())?;
        troe_machine::zero_physical_range(range).map_err(|_| ())?;
        frames.free_range(range).map_err(|_| ())?;
        allocation.growth_ranges.pop();
    }
    while allocation.growth_table_frames.len() > retained_tables {
        let frame = *allocation.growth_table_frames.last().ok_or(())?;
        let range = PhysicalRange::from_pages(frame, 1).map_err(|_| ())?;
        troe_machine::zero_physical_range(range).map_err(|_| ())?;
        frames.free(frame).map_err(|_| ())?;
        allocation.growth_table_frames.pop();
    }
    Ok(())
}

pub(crate) fn application_growth_pages(allocation: &ApplicationAllocation) -> Result<u64, ()> {
    allocation
        .growth_ranges
        .iter()
        .try_fold(0_u64, |pages, range| pages.checked_add(range.page_count()))
        .ok_or(())
}

pub(crate) fn append_application_growth_frame(
    allocation: &mut ApplicationAllocation,
    request_start: usize,
    frame: u64,
) -> Result<bool, ()> {
    if allocation.growth_ranges.len() > request_start {
        let last = allocation.growth_ranges.last_mut().ok_or(())?;
        if last.end() == frame {
            *last =
                PhysicalRange::from_pages(last.start(), last.page_count() + 1).map_err(|_| ())?;
            return Ok(true);
        }
    }
    if allocation.growth_ranges.try_reserve(1).is_err() {
        return Ok(false);
    }
    allocation
        .growth_ranges
        .push(PhysicalRange::from_pages(frame, 1).map_err(|_| ())?);
    Ok(true)
}

pub(crate) fn additional_table_pages(virtual_start: u64, page_count: u64) -> Result<u64, ()> {
    let start_page = virtual_start / BASE_PAGE_SIZE;
    let end_page = start_page.checked_add(page_count).ok_or(())?;
    if start_page == 0 || end_page <= start_page {
        return Err(());
    }
    [512_u64, 512 * 512, 512 * 512 * 512]
        .into_iter()
        .try_fold(0_u64, |total, coverage| {
            let before = (start_page - 1) / coverage;
            let after = (end_page - 1) / coverage;
            total.checked_add(after.checked_sub(before)?)
        })
        .ok_or(())
}

//! Allocation-free removal planning for inactive, exclusively owned roots.

use super::{MmuError, UserRegion};
use alloc::vec::Vec;
use troe_memory::{BASE_PAGE_SIZE, PhysicalRange, VirtualRange};

pub(super) const MAX_REGIONS: usize = 4;

/// Physical extents come from retained kernel ownership, never user pointers.
#[derive(Clone, Copy)]
pub(super) struct Backing<'a> {
    pub range: VirtualRange,
    pub physical: &'a [PhysicalRange],
    pub writable: bool,
}

/// Validate every target leaf and every remaining user alias before any write.
/// The extra metadata bound includes transient split records during compaction.
pub(super) fn preflight(
    regions: &[UserRegion],
    targets: &[Backing<'_>],
    capacity: usize,
    mut translate: impl FnMut(u64) -> Result<u64, MmuError>,
) -> Result<u64, MmuError> {
    if targets.is_empty() || targets.len() > MAX_REGIONS {
        return Err(MmuError::InvalidUserContext);
    }
    let mut pages = 0_u64;
    for (index, target) in targets.iter().enumerate() {
        let mut physical_pages = 0_u64;
        for (extent_index, extent) in target.physical.iter().enumerate() {
            if extent.start() == 0
                || target.physical[..extent_index]
                    .iter()
                    .chain(targets[..index].iter().flat_map(|old| old.physical))
                    .any(|old| old.start() < extent.end() && extent.start() < old.end())
            {
                return Err(MmuError::InvalidUserContext);
            }
            physical_pages = physical_pages
                .checked_add(extent.page_count())
                .ok_or(MmuError::InvalidUserContext)?;
        }
        if target.range.start() == 0
            || physical_pages == 0
            || physical_pages != target.range.page_count()
            || targets[..index]
                .iter()
                .any(|old| overlaps(old.range, target.range))
        {
            return Err(MmuError::InvalidUserContext);
        }
        pages = pages
            .checked_add(physical_pages)
            .ok_or(MmuError::InvalidUserContext)?;
        let mut cursor = target.range.start();
        for region in regions {
            if !overlaps(region.range, target.range) {
                continue;
            }
            if region.range.start() > cursor
                || !region.permissions.read
                || region.permissions.write != target.writable
                || region.permissions.execute
            {
                return Err(MmuError::InvalidUserContext);
            }
            cursor = region.range.end().min(target.range.end());
        }
        if cursor != target.range.end() {
            return Err(MmuError::InvalidUserContext);
        }
    }
    let mut required = regions.len();
    let mut previous_end = 0;
    for region in regions {
        if region.range.start() < previous_end {
            return Err(MmuError::InvalidUserContext);
        }
        previous_end = region.range.end();
        let mut fragments = 0_usize;
        fragments_of(*region, targets, |_| fragments += 1)?;
        required = required
            .checked_add(fragments.saturating_sub(1))
            .ok_or(MmuError::InvalidUserContext)?;
    }
    if required > capacity {
        return Err(MmuError::InvalidUserContext);
    }
    for region in regions {
        let mut address = region.range.start();
        while address < region.range.end() {
            let physical = translate(address)?;
            let expected = targets
                .iter()
                .find(|target| contains(target.range, address))
                .map(|target| physical_at(*target, address))
                .transpose()?;
            if let Some(expected) = expected {
                if physical != expected {
                    return Err(MmuError::InvalidUserContext);
                }
            } else if targets
                .iter()
                .flat_map(|target| target.physical)
                .any(|range| range.start() <= physical && physical < range.end())
            {
                return Err(MmuError::InvalidUserContext);
            }
            address += BASE_PAGE_SIZE;
        }
    }
    Ok(pages)
}

/// Call only after successful preflight under the same exclusive root borrow.
/// A failure can follow earlier writes; the native owner must stop on any error.
pub(super) fn unmap(
    targets: &[Backing<'_>],
    mut remove: impl FnMut(u64) -> Result<u64, MmuError>,
) -> Result<(), MmuError> {
    for target in targets {
        let mut address = target.range.start();
        for range in target.physical {
            let mut physical = range.start();
            while physical < range.end() {
                if remove(address)? != physical {
                    return Err(MmuError::InvalidUserContext);
                }
                address += BASE_PAGE_SIZE;
                physical += BASE_PAGE_SIZE;
            }
        }
    }
    Ok(())
}

/// Call only after preflight and successful unmapping under the same root borrow.
/// Failure is terminal; no caller may resume with a partially changed summary.
pub(super) fn remove_regions(
    regions: &mut Vec<UserRegion>,
    targets: &[Backing<'_>],
) -> Result<(), MmuError> {
    for index in (0..regions.len()).rev() {
        let region = regions[index];
        if !targets
            .iter()
            .any(|target| overlaps(target.range, region.range))
        {
            continue;
        }
        regions.remove(index);
        // Preflight counted the maximum transient length before any PTE write.
        // Keep the bound checked here too, so a bug cannot allocate in teardown.
        let mut exhausted = false;
        fragments_of(region, targets, |fragment| {
            if regions.len() == regions.capacity() {
                exhausted = true;
            } else {
                regions.push(fragment);
            }
        })?;
        if exhausted {
            return Err(MmuError::InvalidUserContext);
        }
    }
    regions.sort_unstable_by_key(|region| region.range.start());
    Ok(())
}

fn fragments_of(
    region: UserRegion,
    targets: &[Backing<'_>],
    mut emit: impl FnMut(UserRegion),
) -> Result<(), MmuError> {
    let mut cursor = region.range.start();
    while cursor < region.range.end() {
        let next = targets
            .iter()
            .filter(|target| {
                cursor < target.range.end() && target.range.start() < region.range.end()
            })
            .min_by_key(|target| target.range.start());
        let end = next.map_or(region.range.end(), |target| {
            target.range.start().max(cursor)
        });
        if cursor < end {
            emit(UserRegion {
                range: VirtualRange::from_pages(cursor, (end - cursor) / BASE_PAGE_SIZE)
                    .map_err(|_| MmuError::InvalidUserContext)?,
                permissions: region.permissions,
            });
        }
        cursor = next.map_or(region.range.end(), |target| {
            target.range.end().min(region.range.end())
        });
    }
    Ok(())
}

fn physical_at(target: Backing<'_>, address: u64) -> Result<u64, MmuError> {
    let mut offset = address - target.range.start();
    for range in target.physical {
        if offset < range.byte_count() {
            return Ok(range.start() + offset);
        }
        offset -= range.byte_count();
    }
    Err(MmuError::InvalidUserContext)
}

fn contains(range: VirtualRange, address: u64) -> bool {
    range.start() <= address && address < range.end()
}
fn overlaps(a: VirtualRange, b: VirtualRange) -> bool {
    a.start() < b.end() && b.start() < a.end()
}

#[cfg(test)]
mod tests;

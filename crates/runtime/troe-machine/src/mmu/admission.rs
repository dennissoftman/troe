//! Allocation-free preflight for new private mappings in an inactive root.

use super::{MmuError, UserRegion, retirement::Backing};
use alloc::vec::Vec;
use troe_memory::{BASE_PAGE_SIZE, MappingPermissions, PhysicalRange, VirtualRange};

/// Check all virtual/physical extents before any unpublished bytes or PTEs change.
pub(super) fn preflight(
    regions: &[UserRegion],
    window: VirtualRange,
    targets: &[Backing<'_>],
    tables: PhysicalRange,
    capacity: usize,
    mut translate: impl FnMut(u64) -> Result<u64, MmuError>,
) -> Result<u64, MmuError> {
    if window.start() == 0
        || window.end() > (1 << 47)
        || targets.len() != 4
        || regions
            .len()
            .checked_add(targets.len())
            .is_none_or(|n| n > capacity)
        || regions.iter().any(|region| overlaps(region.range, window))
    {
        return Err(MmuError::InvalidUserContext);
    }
    let mut pages = 0_u64;
    for (index, target) in targets.iter().enumerate() {
        let mut count = 0_u64;
        if target.range.start() < window.start()
            || target.range.end() > window.end()
            || targets[..index]
                .iter()
                .any(|old| overlaps(old.range, target.range))
        {
            return Err(MmuError::InvalidUserContext);
        }
        for (part, extent) in target.physical.iter().enumerate() {
            if extent.start() == 0
                || extent.start() < tables.end() && tables.start() < extent.end()
                || target.physical[..part]
                    .iter()
                    .chain(targets[..index].iter().flat_map(|old| old.physical))
                    .any(|old| old.start() < extent.end() && extent.start() < old.end())
            {
                return Err(MmuError::InvalidUserContext);
            }
            count = count
                .checked_add(extent.page_count())
                .ok_or(MmuError::InvalidUserContext)?;
        }
        if count == 0 || count != target.range.page_count() {
            return Err(MmuError::InvalidUserContext);
        }
        pages = pages
            .checked_add(count)
            .ok_or(MmuError::InvalidUserContext)?;
    }
    let mut previous = 0;
    for region in regions {
        if region.range.start() < previous {
            return Err(MmuError::InvalidUserContext);
        }
        previous = region.range.end();
    }
    // Check the whole reservation, including guards and alignment holes. An
    // absent summary entry alone does not prove that a stale leaf is absent.
    for address in (window.start()..window.end()).step_by(4096) {
        if translate(address) != Err(MmuError::InvalidUserContext) {
            return Err(MmuError::InvalidUserContext);
        }
    }
    for region in regions {
        for address in (region.range.start()..region.range.end()).step_by(4096) {
            let physical = translate(address)?;
            if targets
                .iter()
                .flat_map(|target| target.physical)
                .any(|extent| extent.start() <= physical && physical < extent.end())
            {
                return Err(MmuError::InvalidUserContext);
            }
        }
    }
    Ok(pages)
}

/// Mapping can partially change the root: any failure is terminal to its owner.
pub(super) fn map(
    targets: &[Backing<'_>],
    mut insert: impl FnMut(u64, u64, MappingPermissions) -> Result<(), MmuError>,
) -> Result<(), MmuError> {
    for target in targets {
        let mut address = target.range.start();
        for extent in target.physical {
            for physical in (extent.start()..extent.end()).step_by(4096) {
                insert(address, physical, permissions(*target))?;
                address += BASE_PAGE_SIZE;
            }
        }
    }
    Ok(())
}

/// Preflight reserves the complete addition; this path never grows the vector.
pub(super) fn add_regions(
    regions: &mut Vec<UserRegion>,
    targets: &[Backing<'_>],
) -> Result<(), MmuError> {
    if regions
        .len()
        .checked_add(targets.len())
        .is_none_or(|n| n > regions.capacity())
    {
        return Err(MmuError::InvalidUserContext);
    }
    for target in targets {
        regions.push(UserRegion {
            range: target.range,
            permissions: permissions(*target),
        });
    }
    regions.sort_unstable_by_key(|region| region.range.start());
    Ok(())
}

fn permissions(target: Backing<'_>) -> MappingPermissions {
    if target.writable {
        MappingPermissions::READ_WRITE
    } else {
        MappingPermissions::READ_ONLY
    }
}
fn overlaps(a: VirtualRange, b: VirtualRange) -> bool {
    a.start() < b.end() && b.start() < a.end()
}

#[cfg(test)]
mod tests;

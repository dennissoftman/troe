//! Root mapping mechanics shared by suspended execution owners.
//!
//! Call authentication and physical ownership remain with the enclosing owner.
//! A mapping error can follow a partial update: all referenced backing must
//! remain retained until that owner retires the inactive root.

use super::{
    BASE_PAGE_SIZE, MappingMemoryType, MappingPermissions, MappingPrivilege, MmuError, MmuStats,
    PhysicalRange, TableArena, UserAddressSpace, UserRegion, VirtualRange, architecture_map_page,
    architecture_mmu_capabilities, architecture_protect_page, architecture_translate_page,
    architecture_unmap_page, updated_user_regions,
};

impl UserAddressSpace {
    #[allow(clippy::too_many_lines)]
    pub(super) fn grow_heap(
        &mut self,
        heap_start: u64,
        minimum_pages: u64,
        physical_ranges: &[PhysicalRange],
        supplemental_table_pages: &[u64],
    ) -> Result<MmuStats, MmuError> {
        let page_count = physical_ranges
            .iter()
            .try_fold(0_u64, |pages, range| pages.checked_add(range.page_count()))
            .ok_or(MmuError::InvalidUserContext)?;
        if page_count < minimum_pages || physical_ranges.is_empty() {
            return Err(MmuError::InvalidUserContext);
        }
        let region_index = self
            .regions
            .iter()
            .position(|region| {
                region.range.start() <= heap_start
                    && heap_start < region.range.end()
                    && region.permissions.write
                    && !region.permissions.execute
            })
            .ok_or(MmuError::InvalidUserContext)?;
        let region = self.regions[region_index];
        let added_bytes = page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(MmuError::AddressUnsupported)?;
        let new_end = region
            .range
            .end()
            .checked_add(added_bytes)
            .ok_or(MmuError::AddressUnsupported)?;
        let grown =
            VirtualRange::from_pages(region.range.start(), region.range.page_count() + page_count)
                .map_err(|_| MmuError::InvalidUserContext)?;
        if grown.end() != new_end
            || self
                .regions
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != region_index)
                .map(|(_, region)| *region)
                .any(|other| heap_start < other.range.end() && other.range.start() < new_end)
        {
            return Err(MmuError::InvalidUserContext);
        }
        let mut virtual_address = region.range.end();
        for range in physical_ranges {
            if range.start() == 0 {
                return Err(MmuError::InvalidUserContext);
            }
            for _ in 0..range.page_count() {
                if architecture_translate_page(self.root, virtual_address).is_ok() {
                    return Err(MmuError::InvalidUserContext);
                }
                virtual_address = virtual_address
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(MmuError::AddressUnsupported)?;
            }
        }
        if virtual_address != new_end {
            return Err(MmuError::InvalidUserContext);
        }
        let capabilities = architecture_mmu_capabilities()?;
        let mut arena = TableArena::resume(
            self.table_arena,
            self.stats.table_pages,
            supplemental_table_pages,
        )?;
        let mut virtual_address = region.range.end();
        for range in physical_ranges {
            let mut physical = range.start();
            for _ in 0..range.page_count() {
                architecture_map_page(
                    &mut arena,
                    self.root,
                    virtual_address,
                    physical,
                    MappingPermissions::READ_WRITE,
                    MappingMemoryType::Normal,
                    MappingPrivilege::User,
                    capabilities,
                )?;
                virtual_address = virtual_address
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(MmuError::AddressUnsupported)?;
                physical = physical
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(MmuError::AddressUnsupported)?;
            }
        }
        if let Some(tag) = &self.tag {
            tag.invalidate_range(region.range.end(), page_count)?;
        }
        self.regions[region_index] = UserRegion {
            range: grown,
            permissions: region.permissions,
        };
        self.stats.mapped_pages = self
            .stats
            .mapped_pages
            .checked_add(page_count)
            .ok_or(MmuError::InvalidUserContext)?;
        self.stats.table_pages = arena.used_pages;
        Ok(self.stats)
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn replace_private(
        &mut self,
        virtual_start: u64,
        physical_ranges: &[PhysicalRange],
        was_mapped: bool,
        permissions: Option<MappingPermissions>,
        supplemental_table_pages: &[u64],
    ) -> Result<MmuStats, MmuError> {
        if virtual_start == 0
            || !virtual_start.is_multiple_of(BASE_PAGE_SIZE)
            || physical_ranges.is_empty()
            || permissions.is_some_and(|value| !value.read || value.execute)
        {
            return Err(MmuError::InvalidUserContext);
        }
        let page_count = physical_ranges
            .iter()
            .try_fold(0_u64, |total, range| {
                if range.start() == 0 {
                    return None;
                }
                total.checked_add(range.page_count())
            })
            .ok_or(MmuError::InvalidUserContext)?;
        if page_count == 0 {
            return Err(MmuError::InvalidUserContext);
        }
        let target = VirtualRange::from_pages(virtual_start, page_count)
            .map_err(|_| MmuError::InvalidUserContext)?;
        let updated_regions = updated_user_regions(&self.regions, target, permissions)?;
        let mut virtual_address = virtual_start;
        for range in physical_ranges {
            let mut physical = range.start();
            for _ in 0..range.page_count() {
                match (
                    was_mapped,
                    architecture_translate_page(self.root, virtual_address),
                ) {
                    (true, Ok(mapped)) if mapped == physical => {}
                    (false, Err(MmuError::InvalidUserContext)) => {}
                    _ => return Err(MmuError::InvalidUserContext),
                }
                virtual_address = virtual_address
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(MmuError::AddressUnsupported)?;
                physical = physical
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(MmuError::AddressUnsupported)?;
            }
        }
        if virtual_address != target.end() {
            return Err(MmuError::InvalidUserContext);
        }
        let capabilities = architecture_mmu_capabilities()?;
        let mut arena = TableArena::resume(
            self.table_arena,
            self.stats.table_pages,
            supplemental_table_pages,
        )?;
        let mut virtual_address = virtual_start;
        for range in physical_ranges {
            let mut physical = range.start();
            for _ in 0..range.page_count() {
                match (was_mapped, permissions) {
                    (false, Some(permissions)) => architecture_map_page(
                        &mut arena,
                        self.root,
                        virtual_address,
                        physical,
                        permissions,
                        MappingMemoryType::Normal,
                        MappingPrivilege::User,
                        capabilities,
                    )?,
                    (true, Some(permissions)) => {
                        let retained =
                            architecture_protect_page(self.root, virtual_address, permissions)?;
                        if retained != physical {
                            return Err(MmuError::InvalidUserContext);
                        }
                    }
                    (true, None) => {
                        let removed = architecture_unmap_page(self.root, virtual_address)?;
                        if removed != physical {
                            return Err(MmuError::InvalidUserContext);
                        }
                    }
                    (false, None) => return Err(MmuError::InvalidUserContext),
                }
                virtual_address = virtual_address
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(MmuError::AddressUnsupported)?;
                physical = physical
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(MmuError::AddressUnsupported)?;
            }
        }
        if let Some(tag) = &self.tag {
            tag.invalidate_range(target.start(), page_count)?;
        }
        self.regions = updated_regions;
        self.stats.mapped_pages = match (was_mapped, permissions.is_some()) {
            (false, true) => self
                .stats
                .mapped_pages
                .checked_add(page_count)
                .ok_or(MmuError::InvalidUserContext)?,
            (true, false) => self
                .stats
                .mapped_pages
                .checked_sub(page_count)
                .ok_or(MmuError::InvalidUserContext)?,
            _ => self.stats.mapped_pages,
        };
        self.stats.table_pages = arena.used_pages;
        Ok(self.stats)
    }
}

//! Bounded heap commits retain their backing before touching a shared root.

use super::{NativeMemory, reserve_zeroed_private_extents};
use crate::machine::OwnedAccounting;
use troe_machine::NativeHeapCall;
use troe_memory::BASE_PAGE_SIZE;

pub(super) const MAX_GROWTH_RECORDS: usize = 128;

impl NativeMemory {
    pub(crate) fn grow_heap(
        &mut self,
        accounting: &mut OwnedAccounting,
        call: NativeHeapCall,
    ) -> Result<(), ()> {
        let execution = self
            .native
            .as_mut()
            .ok_or(())?
            .claim_heap(call)
            .map_err(|_| ())?;
        let pages = call.minimum_pages();
        let permitted = self.can_grow(accounting, pages)?;
        let frames = if permitted {
            reserve_zeroed_private_extents(accounting, pages).ok()
        } else {
            None
        };
        let Some(frames) = frames else {
            return self
                .native
                .as_mut()
                .ok_or(())?
                .complete_heap_execution(execution, troe_abi::heap_growth::EXHAUSTED)
                .map_err(|_| ());
        };
        let metadata = u64::try_from(frames.buffer_bytes()).map_err(|_| ())?;
        if !self.can_charge_metadata(accounting, metadata) {
            self.release_unpublished(accounting, core::slice::from_ref(&frames))?;
            return self
                .native
                .as_mut()
                .ok_or(())?
                .complete_heap_execution(execution, troe_abi::heap_growth::EXHAUSTED)
                .map_err(|_| ());
        }
        self.heap_growth.push(frames);
        self.committed_pages += pages;
        self.metadata_bytes += metadata;
        accounting.application_committed_pages += pages;
        accounting.private_metadata_bytes += metadata;
        // Both failure and success keep this frame owner in heap_growth.
        let native = self.native.as_mut().ok_or(())?;
        native
            .commit_heap_execution(
                &execution,
                self.heap_growth.last().ok_or(())?.extents(),
                &[],
            )
            .map_err(|_| ())?;
        self.heap_pages += pages;
        native
            .complete_heap_execution(execution, troe_abi::heap_growth::SUCCESS)
            .map_err(|_| ())
    }

    fn can_grow(&self, accounting: &OwnedAccounting, pages: u64) -> Result<bool, ()> {
        if pages == 0
            || pages > super::MAX_NATIVE_BATCH_PAGES
            || self.heap_growth.len() >= MAX_GROWTH_RECORDS
            || self.heap_growth.len() == self.heap_growth.capacity()
        {
            return Ok(false);
        }
        let Some(heap_pages) = self.heap_pages.checked_add(pages) else {
            return Ok(false);
        };
        if heap_pages > self.tls.plan().heap_capacity_pages() {
            return Ok(false);
        }
        let Some(committed) = self.committed_pages.checked_add(pages) else {
            return Ok(false);
        };
        let Some(global) = accounting.application_committed_pages.checked_add(pages) else {
            return Ok(false);
        };
        let tables = self.tables.ok_or(())?.page_count();
        let resident = committed
            .checked_add(tables)
            .and_then(|pages| pages.checked_add(self.tls.backing_pages()))
            .ok_or(())?;
        let start = self
            .tls
            .plan()
            .heap_address()
            .checked_add(self.heap_pages.checked_mul(BASE_PAGE_SIZE).ok_or(())?)
            .ok_or(())?;
        let required_tables = crate::memory::growth::additional_table_pages(start, pages)?;
        Ok(committed <= self.limits.memory.mapped_pages
            && resident <= self.limits.memory.resident_pages
            && resident.saturating_sub(2 * self.threads.len() as u64)
                <= self.limits.memory.ordinary_frames
            && pages
                <= accounting
                    .frames
                    .free_frames()
                    .saturating_sub(accounting.memory_policy.minimum_free_pages())
            && accounting
                .memory_policy
                .default_committed_pages()
                .maximum()
                .is_none_or(|limit| committed <= limit)
            && accounting
                .memory_policy
                .system_application_commit()
                .maximum()
                .is_none_or(|limit| global <= limit)
            && self
                .native
                .as_ref()
                .ok_or(())?
                .stats()
                .table_pages
                .checked_add(required_tables)
                .is_some_and(|needed| needed <= tables))
    }
}

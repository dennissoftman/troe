//! Correlated heap requests and immutable process heap reservations.

use super::{NativeProcessBacking, NativeProcessContext, ThreadContext};
use crate::mmu::{ApplicationHeapGrowth, ApplicationPending, MmuError, MmuStats};
use troe_memory::{BASE_PAGE_SIZE, PhysicalRange, VirtualRange};
use troe_task::thread::ThreadId;

/// One captured heap request, without allocation or mapping authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHeapCall {
    caller: ThreadId,
    sequence: u64,
    pair_slot: usize,
    pair_generation: u64,
    request: ApplicationHeapGrowth,
}

impl NativeHeapCall {
    /// Original process-scoped caller incarnation.
    #[must_use]
    pub const fn caller(self) -> ThreadId {
        self.caller
    }

    /// Minimum additional base pages requested by the caller.
    #[must_use]
    pub const fn minimum_pages(self) -> u64 {
        self.request.minimum_pages()
    }
}

/// Unique execution claim retained until completion or process stop.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "Complete the owned heap request or stop its process"]
pub struct NativeHeapExecution {
    operation: NativeHeapCall,
}

impl NativeHeapExecution {
    /// Exact request identity, for trusted allocation and wait accounting.
    #[must_use]
    pub const fn operation(&self) -> NativeHeapCall {
        self.operation
    }
}

pub(super) struct PendingHeapCall {
    operation: NativeHeapCall,
    claimed: bool,
    mapped_bytes: Option<u64>,
}

pub(super) fn capture(
    backing: &NativeProcessBacking,
    context: &mut ThreadContext,
    sequence: u64,
    request: ApplicationHeapGrowth,
) -> Result<NativeHeapCall, MmuError> {
    if context.heap_operation.is_some()
        || context.handle_operation.is_some()
        || context.scheduler_operation.is_some()
        || request.minimum_pages() == 0
    {
        return Err(MmuError::InvalidUserContext);
    }
    let ipc = context.ipc.ok_or(MmuError::InvalidUserContext)?;
    let pair = backing
        .pairs
        .get(ipc.index)
        .filter(|pair| pair.is_live())
        .ok_or(MmuError::InvalidUserContext)?;
    if crate::mmu::architecture_translate_page(backing.address_space.root, ipc.tx)?
        != pair.range().start()
        || crate::mmu::architecture_translate_page(backing.address_space.root, ipc.tx + 4096)?
            != pair.range().start() + 4096
    {
        return Err(MmuError::InvalidUserContext);
    }
    let operation = NativeHeapCall {
        caller: context.id,
        sequence,
        pair_slot: pair.slot(),
        pair_generation: pair.generation(),
        request,
    };
    context.heap_operation = Some(PendingHeapCall {
        operation,
        claimed: false,
        mapped_bytes: None,
    });
    Ok(operation)
}

impl NativeProcessContext {
    /// Bind the complete heap reservation before any native thread starts.
    ///
    /// Composition supplies its validated process layout. The initial committed
    /// heap must be RW/NX and start at this reservation's first page. Uncommitted
    /// heap pages cannot overlap another mapping or any thread window/guard.
    /// Future thread admission also respects the entire immutable reservation.
    /// This does not reserve physical frames or grant additional process quota.
    ///
    /// # Errors
    /// Rejects replacement, stopped/started owners, invalid geometry and overlap.
    pub fn bind_heap(&mut self, reservation: VirtualRange) -> Result<(), MmuError> {
        let space = &self.backing.address_space;
        if self.stopped
            || self.heap.is_some()
            || reservation.start() == 0
            || reservation.end() > (1 << 47)
            || self.contexts.iter().any(|context| {
                context.started
                    || super::admission::conflicts(context.start, reservation)
                    || context
                        .window
                        .is_some_and(|window| super::overlaps(window, reservation))
                    || context.ipc.is_some_and(|ipc| {
                        ipc.tx < reservation.end() && reservation.start() < ipc.tx + 8192
                    })
            })
        {
            return Err(MmuError::InvalidUserContext);
        }
        let mut found = false;
        for region in &space.regions {
            if region.range.start() == reservation.start()
                && region.range.end() <= reservation.end()
                && region.permissions.read
                && region.permissions.write
                && !region.permissions.execute
            {
                found = true;
            } else if super::overlaps(region.range, reservation) {
                return Err(MmuError::InvalidUserContext);
            }
        }
        if !found {
            return Err(MmuError::InvalidUserContext);
        }
        self.heap = Some(reservation);
        Ok(())
    }

    /// Claim the retained request once, before allocating backing on its behalf.
    ///
    /// # Errors
    /// Rejects stale, foreign, completed and already-claimed requests.
    pub fn claim_heap(
        &mut self,
        operation: NativeHeapCall,
    ) -> Result<NativeHeapExecution, MmuError> {
        let index = self.heap_index(operation, false)?;
        self.contexts[index]
            .heap_operation
            .as_mut()
            .ok_or(MmuError::InvalidUserContext)?
            .claimed = true;
        Ok(NativeHeapExecution { operation })
    }

    /// Commit newly owned, zeroed frames once for the claimed heap request.
    ///
    /// Composition checks its process/system budgets before this synchronous
    /// operation and retains every supplied data/table frame until root retirement
    /// on error. Unique native-owner access prevents sibling execution throughout
    /// mutation. A mapping failure stops all continuations; no backing is freed.
    /// Successful mutation does not wake the caller, resume user code, or grant a
    /// dispatch. It records the result for the separate owned completion.
    ///
    /// # Errors
    /// Rejects stale/replayed claims, absent reservations, excess growth and invalid
    /// backing. Any error from the mapping mechanism stops the process.
    pub fn commit_heap_execution(
        &mut self,
        execution: &NativeHeapExecution,
        physical_ranges: &[PhysicalRange],
        supplemental_table_pages: &[u64],
    ) -> Result<MmuStats, MmuError> {
        let index = self.heap_index(execution.operation, true)?;
        let pending = self.contexts[index]
            .heap_operation
            .as_ref()
            .ok_or(MmuError::InvalidUserContext)?;
        if pending.mapped_bytes.is_some() {
            return Err(MmuError::InvalidUserContext);
        }
        let heap = self.heap.ok_or(MmuError::InvalidUserContext)?;
        let region = self
            .backing
            .address_space
            .regions
            .iter()
            .find(|region| region.range.start() == heap.start())
            .ok_or(MmuError::InvalidUserContext)?;
        let pages = physical_ranges
            .iter()
            .try_fold(0_u64, |pages, range| pages.checked_add(range.page_count()))
            .ok_or(MmuError::InvalidUserContext)?;
        let added = pages
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(MmuError::InvalidUserContext)?;
        let end = region
            .range
            .end()
            .checked_add(added)
            .filter(|end| *end <= heap.end())
            .ok_or(MmuError::InvalidUserContext)?;
        let stats = match self.backing.address_space.grow_heap(
            heap.start(),
            execution.operation.minimum_pages(),
            physical_ranges,
            supplemental_table_pages,
        ) {
            Ok(stats) => stats,
            Err(error) => {
                self.stop();
                return Err(error);
            }
        };
        self.contexts[index]
            .heap_operation
            .as_mut()
            .ok_or(MmuError::InvalidUserContext)?
            .mapped_bytes = Some(end - heap.start());
        Ok(stats)
    }

    /// Complete the claimed request without entering user code or waking it.
    ///
    /// Success is derived from this request's recorded mapping, never a supplied
    /// byte count. `EXHAUSTED` is valid only when it has not committed pages.
    ///
    /// # Errors
    /// Returns the execution owner on stale identity or an inconsistent status.
    pub fn complete_heap_execution(
        &mut self,
        execution: NativeHeapExecution,
        status: u32,
    ) -> Result<(), (MmuError, NativeHeapExecution)> {
        let result = (|| {
            let index = self.heap_index(execution.operation, true)?;
            let context = &mut self.contexts[index];
            let pending = context
                .heap_operation
                .as_ref()
                .ok_or(MmuError::InvalidUserContext)?;
            let bytes = match (status, pending.mapped_bytes) {
                (troe_abi::heap_growth::SUCCESS, Some(bytes)) => bytes,
                (troe_abi::heap_growth::EXHAUSTED, None) => 0,
                _ => return Err(MmuError::InvalidUserContext),
            };
            super::application_context_set_results(&mut context.registers, status, bytes);
            context.pending = ApplicationPending::Timeslice;
            context.heap_operation = None;
            Ok(())
        })();
        result.map_err(|error| (error, execution))
    }

    fn heap_index(&self, operation: NativeHeapCall, claimed: bool) -> Result<usize, MmuError> {
        if self.stopped || operation.caller.process() != self.process {
            return Err(MmuError::InvalidUserContext);
        }
        let pair = self
            .backing
            .pairs
            .iter()
            .find(|pair| {
                pair.slot() == operation.pair_slot
                    && pair.generation() == operation.pair_generation
                    && pair.is_live()
            })
            .ok_or(MmuError::InvalidUserContext)?;
        self.contexts
            .iter()
            .position(|context| {
                context.id == operation.caller
                    && context.ipc.is_some_and(|ipc| {
                        self.backing.pairs.get(ipc.index).is_some_and(|bound| {
                            bound.slot() == pair.slot() && bound.generation() == pair.generation()
                        })
                    })
                    && context.pending == ApplicationPending::HeapGrow(operation.request)
                    && context.heap_operation.as_ref().is_some_and(|pending| {
                        pending.operation == operation && pending.claimed == claimed
                    })
            })
            .ok_or(MmuError::InvalidUserContext)
    }
}

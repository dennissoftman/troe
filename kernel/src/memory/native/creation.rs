//! Worker backing stays in the process owner through publication and retirement.

use super::{
    NativeMemory, NativeThreadMemory, release, reserve_zeroed_private_extents, write_launch_bytes,
};
use crate::machine::OwnedAccounting;
use troe_abi::threading::{Kind, Request, StartupDescriptor, Token};
use troe_application::{
    Target,
    thread_memory::{ThreadMemoryBudget, ThreadMemoryPlan},
};
use troe_machine::{
    IpcPagePair, NativeSchedulerExecution, NativeThreadAdmission, NativeThreadAdmissionError,
};
use troe_memory::{BASE_PAGE_SIZE, PhysicalExtents};
use troe_service::threading::{Completion, PrepareFailure, Preparing, Retiring, Starting};
use troe_task::thread::{ThreadId, ThreadResources, ThreadTable};

impl NativeMemory {
    /// Reserve and initialize an unpublished worker for one already-claimed call.
    /// A terminal error retains any mapped backing for complete process teardown.
    #[allow(clippy::too_many_lines)] // Keep physical ownership and every rollback together.
    pub(crate) fn prepare_thread(
        &mut self,
        accounting: &mut OwnedAccounting,
        threads: &mut ThreadTable,
        execution: &NativeSchedulerExecution,
        mut action: Preparing,
        reservation_base: u64,
    ) -> Result<Completion, ()> {
        if execution.caller() != action.caller() || execution.request() != action.request() {
            return Err(());
        }
        let window = match self.worker_window(accounting, action.request(), reservation_base) {
            Ok(window) => window,
            Err(failure) => return action.reject(threads, failure).map_err(|_| ()),
        };
        let Ok(ipc) = IpcPagePair::allocate_application_thread() else {
            return action
                .reject(threads, PrepareFailure::Exhausted)
                .map_err(|_| ());
        };
        let mut backing = [
            PhysicalExtents::new(),
            PhysicalExtents::new(),
            PhysicalExtents::new(),
        ];
        let [stack, tls, _, startup] = window.regions();
        for (index, region) in [stack, tls, startup].into_iter().enumerate() {
            if let Ok(frames) = reserve_zeroed_private_extents(accounting, region.pages()) {
                backing[index] = frames;
            } else {
                self.release_unpublished(accounting, &backing)?;
                return action
                    .reject(threads, PrepareFailure::Exhausted)
                    .map_err(|_| ());
            }
        }
        let metadata = backing
            .iter()
            .try_fold(0_u64, |sum, frames| {
                sum.checked_add(u64::try_from(frames.buffer_bytes()).ok()?)
            })
            .ok_or(())?;
        let pages = window.charges().mapped_pages();
        if !self.can_charge_metadata(accounting, metadata) {
            self.release_unpublished(accounting, &backing)?;
            return action
                .reject(threads, PrepareFailure::Exhausted)
                .map_err(|_| ());
        }
        let Ok(target) = action.reserve(
            threads,
            ThreadResources {
                reservation: window.reservation_base(),
                pages,
            },
        ) else {
            self.release_unpublished(accounting, &backing)?;
            return action
                .reject(threads, PrepareFailure::Exhausted)
                .map_err(|_| ());
        };
        // Own and charge every frame before initializing or admitting mappings.
        // The descriptor is produced from the same checked window and request.
        let Ok(descriptor) = self.worker_descriptor(target, window, action.request()) else {
            let rollback = action
                .revoke(threads, PrepareFailure::InvalidRequest)
                .map_err(|_| ())?;
            self.release_unpublished(accounting, &backing)?;
            threads
                .release_resources(target.process(), target)
                .map_err(|_| ())?;
            return rollback.finish(threads).map_err(|_| ());
        };
        let [stack, tls, startup] = backing;
        self.threads.push(NativeThreadMemory {
            thread: target,
            descriptor,
            window,
            stack,
            tls,
            startup,
        });
        self.committed_pages = self.committed_pages.checked_add(pages).ok_or(())?;
        self.metadata_bytes = self.metadata_bytes.checked_add(metadata).ok_or(())?;
        accounting.application_committed_pages = accounting
            .application_committed_pages
            .checked_add(pages)
            .ok_or(())?;
        accounting.private_metadata_bytes = accounting
            .private_metadata_bytes
            .checked_add(metadata)
            .ok_or(())?;
        let child = self.threads.last().ok_or(())?;
        let mut page = [0; 4096];
        for offset in (0..descriptor.tls_bytes).step_by(4096) {
            if self
                .tls
                .initialize_chunk(descriptor.tls_base, offset, &mut page)
                .map_err(|_| ())?
                != descriptor.thread_pointer
            {
                return Err(());
            }
            write_launch_bytes(&child.tls, offset, &page)?;
        }
        let native = self.native.as_mut().ok_or(())?;
        match native.admit_prepared(
            threads,
            NativeThreadAdmission {
                thread: target,
                descriptor,
                entry: self.tls.plan().trampoline_address(),
                backing: child.backing(),
            },
            ipc,
        ) {
            Ok(()) => native
                .complete_preparation(
                    threads,
                    execution,
                    action,
                    self.tls.plan().shared_reservation().0,
                )
                .map_err(|_| ()),
            Err(NativeThreadAdmissionError::Stopped(_)) => Err(()),
            Err(NativeThreadAdmissionError::Rejected { .. }) => {
                let rollback = action
                    .revoke(threads, PrepareFailure::Exhausted)
                    .map_err(|_| ())?;
                self.release_thread_backing(accounting, target)?;
                threads
                    .release_resources(target.process(), target)
                    .map_err(|_| ())?;
                rollback.finish(threads).map_err(|_| ())
            }
        }
    }

    #[allow(clippy::too_many_lines)] // One preflight checks all simultaneous resource ceilings.
    fn worker_window(
        &self,
        accounting: &OwnedAccounting,
        request: Request,
        base: u64,
    ) -> Result<ThreadMemoryPlan, PrepareFailure> {
        let invalid = PrepareFailure::InvalidRequest;
        let exhausted = PrepareFailure::Exhausted;
        let Request::Prepare {
            entry_offset,
            stack_pages,
            ..
        } = request
        else {
            return Err(invalid);
        };
        if self.tls.creation_stopped()
            || self
                .native
                .as_ref()
                .is_none_or(troe_machine::NativeProcessContext::is_stopped)
        {
            return Err(exhausted);
        }
        if !self
            .executable
            .iter()
            .flatten()
            .any(|(start, end)| *start <= entry_offset && entry_offset < *end)
            || self.target == Target::Aarch64 && !entry_offset.is_multiple_of(4)
            || stack_pages == 0
        {
            return Err(invalid);
        }
        if self.threads.len() >= self.limits.contexts
            || self.threads.len() == self.threads.capacity()
        {
            return Err(exhausted);
        }
        let bounds = self.limits.memory;
        let retained_tables = self.tables.ok_or(exhausted)?.page_count();
        let resident = self
            .committed_pages
            .checked_add(retained_tables)
            .and_then(|pages| pages.checked_add(self.tls.backing_pages()))
            .ok_or(exhausted)?;
        let reserved = self
            .threads
            .iter()
            .try_fold(
                (self.tls.plan().shared_reservation().1 - self.tls.plan().shared_reservation().0)
                    / BASE_PAGE_SIZE,
                |sum, thread| sum.checked_add(thread.window.charges().reserved_pages()),
            )
            .ok_or(exhausted)?;
        // Table frames are already retained. This conservative plan also requires
        // headroom for a complete additional prefix set before any new leaf.
        let window =
            ThreadMemoryPlan::new(
                base,
                stack_pages,
                self.tls.plan().tls_layout(),
                ThreadMemoryBudget {
                    mapped_pages: bounds.mapped_pages.saturating_sub(self.committed_pages),
                    resident_pages: bounds.resident_pages.saturating_sub(resident),
                    reserved_pages: bounds.reserved_pages.saturating_sub(reserved),
                    ordinary_frames: accounting
                        .frames
                        .free_frames()
                        .saturating_sub(accounting.memory_policy.minimum_free_pages())
                        .min(bounds.ordinary_frames.saturating_sub(
                            resident.saturating_sub(2 * self.threads.len() as u64),
                        )),
                    ipc_pairs: bounds.ipc_pairs.saturating_sub(self.threads.len() as u64),
                },
            )
            .map_err(|_| exhausted)?;
        let shared = self.tls.plan().shared_reservation();
        if window.reservation_base() < shared.1 && shared.0 < window.reservation_end()
            || self.threads.iter().any(|thread| {
                window.reservation_base() < thread.window.reservation_end()
                    && thread.window.reservation_base() < window.reservation_end()
            })
        {
            return Err(invalid);
        }
        let pages = window.charges().mapped_pages();
        let committed = self.committed_pages.checked_add(pages).ok_or(exhausted)?;
        let global = accounting
            .application_committed_pages
            .checked_add(pages)
            .ok_or(exhausted)?;
        if pages > super::MAX_NATIVE_BATCH_PAGES
            || accounting
                .memory_policy
                .default_committed_pages()
                .maximum()
                .is_some_and(|limit| committed > limit)
            || accounting
                .memory_policy
                .system_application_commit()
                .maximum()
                .is_some_and(|limit| global > limit)
            || self
                .native
                .as_ref()
                .ok_or(exhausted)?
                .stats()
                .table_pages
                .checked_add(window.charges().table_pages())
                .is_none_or(|needed| needed > retained_tables)
            || self
                .tls
                .plan()
                .tls_layout()
                .pages()
                .checked_mul(self.threads.len() as u64 + 1)
                .is_none_or(|needed| needed > bounds.tls_pages)
        {
            return Err(exhausted);
        }
        Ok(window)
    }

    fn worker_descriptor(
        &self,
        thread: ThreadId,
        window: ThreadMemoryPlan,
        request: Request,
    ) -> Result<StartupDescriptor, ()> {
        let Request::Prepare {
            entry_offset,
            argument,
            ..
        } = request
        else {
            return Err(());
        };
        let [stack, tls, ipc, startup] = window.regions();
        let descriptor = StartupDescriptor {
            thread: Token::new(
                Kind::Thread,
                u32::try_from(thread.slot()).map_err(|_| ())?,
                thread.generation(),
            )
            .map_err(|_| ())?,
            process_startup: self.tls.plan().startup_address(),
            stack_bottom: stack.start(),
            stack_top: stack.end(),
            tls_base: tls.start(),
            tls_bytes: tls.pages() * BASE_PAGE_SIZE,
            thread_pointer: window.thread_pointer(),
            ipc_tx: ipc.start(),
            entry: self
                .tls
                .plan()
                .shared_reservation()
                .0
                .checked_add(entry_offset)
                .ok_or(())?,
            argument,
            initial: false,
            address: startup.start(),
        };
        descriptor.encode().map_err(|_| ())?;
        Ok(descriptor)
    }

    pub(super) fn can_charge_metadata(&self, accounting: &OwnedAccounting, bytes: u64) -> bool {
        self.metadata_bytes.checked_add(bytes).is_some_and(|total| {
            total <= self.limits.metadata_bytes as u64
                && total <= accounting.memory_policy.default_maximum_metadata_bytes()
        }) && accounting
            .private_metadata_bytes
            .checked_add(bytes)
            .is_some_and(|total| total <= accounting.memory_policy.global_metadata_bytes())
    }

    pub(crate) fn start_thread(
        &self,
        threads: &mut ThreadTable,
        execution: &NativeSchedulerExecution,
        action: Starting,
    ) -> Result<Completion, ()> {
        self.native
            .as_ref()
            .ok_or(())?
            .complete_start(threads, execution, action)
            .map_err(|_| ())
    }

    pub(crate) fn discard_thread(
        &mut self,
        accounting: &mut OwnedAccounting,
        threads: &mut ThreadTable,
        target: ThreadId,
    ) -> Result<(), ()> {
        let child = self
            .threads
            .iter()
            .find(|thread| thread.thread == target)
            .ok_or(())?;
        let receipt = self
            .native
            .as_mut()
            .ok_or(())?
            .discard_revoked(threads, target, child.backing())
            .map_err(|_| ())?;
        if receipt.thread() != target
            || receipt.ordinary_pages() + 2 != child.window.charges().mapped_pages()
        {
            return Err(());
        }
        self.release_thread_backing(accounting, target)?;
        threads
            .release_resources(target.process(), target)
            .map_err(|_| ())?;
        Ok(())
    }

    pub(crate) fn retire_thread(
        &mut self,
        accounting: &mut OwnedAccounting,
        threads: &mut ThreadTable,
        execution: NativeSchedulerExecution,
        action: Retiring,
    ) -> Result<(), ()> {
        let target = action.caller();
        if execution.caller() != target || execution.request() != action.request() {
            return Err(());
        }
        let child = self
            .threads
            .iter()
            .find(|thread| thread.thread == target)
            .ok_or(())?;
        let receipt = self
            .native
            .as_mut()
            .ok_or(())?
            .retire_thread(execution, child.backing())
            .map_err(|_| ())?;
        if receipt.thread() != target
            || receipt.ordinary_pages() + 2 != child.window.charges().mapped_pages()
        {
            return Err(());
        }
        action.complete_thread(threads).map_err(|_| ())?;
        self.release_thread_backing(accounting, target)?;
        threads
            .release_resources(target.process(), target)
            .map_err(|_| ())?;
        Ok(())
    }

    /// Remove the exact owner before freeing, so a failed free cannot be retried
    /// through process teardown. Its full charge remains quarantined on failure.
    fn release_thread_backing(
        &mut self,
        accounting: &mut OwnedAccounting,
        target: ThreadId,
    ) -> Result<(), ()> {
        if self.reclamation_failed {
            return Err(());
        }
        let index = self
            .threads
            .iter()
            .position(|thread| thread.thread == target)
            .ok_or(())?;
        let child = self.threads.swap_remove(index);
        let pages = child.window.charges().mapped_pages();
        let metadata = u64::try_from(
            child.stack.buffer_bytes() + child.tls.buffer_bytes() + child.startup.buffer_bytes(),
        )
        .map_err(|_| ())?;
        self.committed_pages = self.committed_pages.checked_sub(pages).ok_or(())?;
        self.metadata_bytes = self.metadata_bytes.checked_sub(metadata).ok_or(())?;
        self.reclamation_failed = true;
        for frames in [&child.stack, &child.tls, &child.startup] {
            release(accounting, frames)?;
        }
        accounting.application_committed_pages = accounting
            .application_committed_pages
            .checked_sub(pages)
            .ok_or(())?;
        accounting.private_metadata_bytes = accounting
            .private_metadata_bytes
            .checked_sub(metadata)
            .ok_or(())?;
        self.reclamation_failed = false;
        Ok(())
    }
}

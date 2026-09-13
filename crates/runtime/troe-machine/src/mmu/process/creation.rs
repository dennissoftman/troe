//! Native readiness checks for owned Prepare and Start publication.

use super::{NativeProcessContext, NativeSchedulerExecution};
use crate::{ApplicationResume, MmuError, NativeThreadStop, mmu};
use core::sync::atomic::{Ordering, fence};
use troe_abi::threading::{Request, STARTUP_BYTES, StartupDescriptor};
use troe_service::threading::{Completion, Preparing, Starting};
use troe_task::thread::{ThreadId, ThreadTable};

impl NativeProcessContext {
    /// Finish an owned Prepare only after this exact native worker is initialized.
    ///
    /// `image_base` comes from the retained validated process image, never from
    /// the caller's payload. The descriptor must reproduce the copied entry
    /// offset, scalar argument and complete stack size. The matching caller claim,
    /// admitted private window, fresh context and live IPC binding all remain
    /// retained. This neither publishes Ready nor writes the caller's reply.
    ///
    /// # Errors
    /// Returns the action without publication on identity, readiness or policy
    /// mismatch. No request replay or resource refund is implied.
    #[allow(clippy::result_large_err)]
    pub fn complete_preparation(
        &self,
        threads: &ThreadTable,
        execution: &NativeSchedulerExecution,
        action: Preparing,
        image_base: u64,
    ) -> Result<Completion, (MmuError, Preparing)> {
        let result = (|| {
            self.creation_call(execution, action.caller(), action.request())?;
            let descriptor =
                self.creation_target(action.target().ok_or(MmuError::InvalidUserContext)?)?;
            let Request::Prepare {
                entry_offset,
                argument,
                stack_pages,
            } = action.request()
            else {
                return Err(MmuError::InvalidUserContext);
            };
            if image_base.checked_add(entry_offset) != Some(descriptor.entry)
                || descriptor.argument != argument
                || (descriptor.stack_top - descriptor.stack_bottom) / 4096 != stack_pages
            {
                return Err(MmuError::InvalidUserContext);
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Err((error, action));
        }
        action
            .finish(threads)
            .map_err(|(_, action)| (MmuError::InvalidUserContext, action))
    }

    /// Publish one Prepared worker after matching its creator and native readiness.
    ///
    /// The captured Start claim remains borrowed through the policy transition.
    /// No allocation, mapping mutation, user execution or reply write occurs.
    /// Complete the original native claim before resuming its caller. Failure
    /// publishing that reply requires process stop before any further execution.
    ///
    /// # Errors
    /// Returns the owned action with no Ready publication if any check fails.
    #[allow(clippy::result_large_err)]
    pub fn complete_start(
        &self,
        threads: &mut ThreadTable,
        execution: &NativeSchedulerExecution,
        action: Starting,
    ) -> Result<Completion, (MmuError, Starting)> {
        let result = self
            .creation_call(execution, action.caller(), action.request())
            .and_then(|()| self.creation_target(action.target()).map(|_| ()));
        if let Err(error) = result {
            return Err((error, action));
        }
        action
            .finish(threads)
            .map_err(|(_, action)| (MmuError::InvalidUserContext, action))
    }

    fn creation_call(
        &self,
        execution: &NativeSchedulerExecution,
        caller: ThreadId,
        request: Request,
    ) -> Result<(), MmuError> {
        if execution.caller() != caller || execution.request() != request {
            return Err(MmuError::InvalidUserContext);
        }
        self.scheduler_index(execution.operation, true).map(|_| ())
    }

    fn creation_target(&self, target: ThreadId) -> Result<StartupDescriptor, MmuError> {
        let context = self
            .contexts
            .iter()
            .find(|context| context.id == target)
            .ok_or(MmuError::InvalidUserContext)?;
        if context.started
            || context.window.is_none()
            || context.scheduler_operation.is_some()
            || context.pending != mmu::ApplicationPending::Timeslice
        {
            return Err(MmuError::InvalidUserContext);
        }
        let (ipc, _) = self.bound_ipc(target)?;
        let private = context
            .start
            .private_startup
            .ok_or(MmuError::InvalidUserContext)?;
        let mut bytes = [0; STARTUP_BYTES];
        mmu::copy_user_from_physical(
            self.backing.address_space.root,
            &self.backing.address_space.regions,
            private.start(),
            &mut bytes,
        )?;
        let descriptor =
            StartupDescriptor::decode(&bytes).map_err(|_| MmuError::InvalidUserContext)?;
        if descriptor.initial
            || descriptor.thread.slot() as usize != target.slot()
            || descriptor.thread.generation() != target.generation()
            || Some(descriptor.process_startup) != self.process_startup
            || descriptor.address != private.start()
            || descriptor.address != context.start.startup
            || context.start.startup_bytes != STARTUP_BYTES
            || descriptor.ipc_tx != ipc.tx
            || descriptor.stack_bottom != context.start.stack.start()
            || descriptor.stack_top != context.start.stack.end()
            || descriptor.tls_base != context.start.tls.start()
            || descriptor.tls_bytes != context.start.tls.end() - context.start.tls.start()
            || descriptor.thread_pointer != context.start.thread_pointer
        {
            return Err(MmuError::InvalidUserContext);
        }
        Ok(descriptor)
    }

    /// Resume a Running policy record using its retained Yield/Timeslice state.
    ///
    /// Scheduler replies must already be completed, and other pending native
    /// operations need their own completion path. The remaining process slice
    /// is still supplied and debited by trusted scheduling; this grants no time.
    /// First entry acquires the initialization published by Start.
    ///
    /// # Errors
    /// Rejects unpublished/non-running policy records and unresolved native work.
    /// Native execution failures retain the process-wide stop behavior of resume.
    pub fn resume_scheduled(
        &mut self,
        threads: &ThreadTable,
        id: ThreadId,
        remaining_milliseconds: u32,
    ) -> Result<NativeThreadStop, MmuError> {
        threads
            .validate_running(self.process, id)
            .map_err(|_| MmuError::InvalidUserContext)?;
        let context = self
            .contexts
            .iter()
            .find(|context| context.id == id)
            .ok_or(MmuError::InvalidUserContext)?;
        let completion = match context.pending {
            mmu::ApplicationPending::Timeslice => ApplicationResume::Timeslice,
            mmu::ApplicationPending::Yield => ApplicationResume::Yield,
            _ => return Err(MmuError::InvalidUserContext),
        };
        if !context.started {
            fence(Ordering::Acquire);
        }
        self.resume(id, completion, remaining_milliseconds)
    }
}

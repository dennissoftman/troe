//! Narrow operations keep every context inside its ordinary frame owner.

use super::NativeMemory;
use crate::machine::OwnedAccounting;
use troe_abi::threading::Request;
use troe_machine::{
    NativeHandleCall, NativeHandleExecution, NativeSchedulerCall, NativeSchedulerExecution,
    NativeThreadStop,
};
use troe_service::threading::Completion;
use troe_task::thread::{ThreadId, ThreadTable, schedule::Dispatch};

impl NativeMemory {
    pub(crate) fn resource_totals(&self) -> Result<(u64, u64), ()> {
        Ok((self.tables.ok_or(())?.page_count(), self.committed_pages))
    }
    pub(crate) fn charge_resident_metadata(
        &mut self,
        accounting: &mut OwnedAccounting,
        bytes: usize,
    ) -> Result<(), ()> {
        let bytes = u64::try_from(bytes).map_err(|_| ())?;
        if !self.can_charge_metadata(accounting, bytes) {
            return Err(());
        }
        self.metadata_bytes += bytes;
        accounting.private_metadata_bytes += bytes;
        Ok(())
    }

    pub(crate) fn resume(
        &mut self,
        threads: &mut ThreadTable,
        dispatch: &mut Dispatch,
        caller: ThreadId,
    ) -> Result<NativeThreadStop, ()> {
        self.native
            .as_mut()
            .ok_or(())?
            .resume_dispatch(threads, dispatch, caller)
            .map_err(|_| ())
    }

    pub(crate) fn claim_scheduler(
        &mut self,
        call: NativeSchedulerCall,
        request: Request,
    ) -> Result<NativeSchedulerExecution, ()> {
        self.native
            .as_mut()
            .ok_or(())?
            .claim_scheduler(call, request)
            .map_err(|_| ())
    }

    pub(crate) fn reject_scheduler(&mut self, call: NativeSchedulerCall) -> Result<(), ()> {
        self.native
            .as_mut()
            .ok_or(())?
            .complete_scheduler(call, None)
            .map_err(|_| ())
    }

    #[allow(clippy::needless_pass_by_value)] // Consume the owned completion with its once-only claim.
    pub(crate) fn complete_scheduler(
        &mut self,
        execution: NativeSchedulerExecution,
        completion: Completion,
    ) -> Result<(), ()> {
        if execution.caller() != completion.caller() || execution.request() != completion.request()
        {
            return Err(());
        }
        self.native
            .as_mut()
            .ok_or(())?
            .complete_scheduler_execution(execution, completion.response())
            .map_err(|_| ())
    }

    /// Copy only the immutable kernel capture; no user TX borrow escapes.
    pub(crate) fn copy_handle_request(
        &self,
        call: NativeHandleCall,
        output: &mut [u8],
    ) -> Result<(), ()> {
        let request = self
            .native
            .as_ref()
            .ok_or(())?
            .handle_request(call)
            .map_err(|_| ())?;
        if output.len() != request.len() {
            return Err(());
        }
        output.copy_from_slice(request);
        Ok(())
    }

    pub(crate) fn claim_handle(
        &mut self,
        call: NativeHandleCall,
    ) -> Result<NativeHandleExecution, ()> {
        self.native
            .as_mut()
            .ok_or(())?
            .claim_handle(call)
            .map_err(|_| ())
    }

    pub(crate) fn complete_handle(
        &mut self,
        execution: NativeHandleExecution,
        status: u32,
        reply: &[u8],
    ) -> Result<(), ()> {
        self.native
            .as_mut()
            .ok_or(())?
            .complete_handle_execution(execution, status, reply)
            .map_err(|_| ())
    }
}

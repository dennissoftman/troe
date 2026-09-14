//! The threaded resident branch shares process accounting and capability owners.

use super::{
    Capabilities, CommandApplicationOutcome, IsolationResource, OwnedAccounting,
    ResidentApplication, Scheduler, command_handle_interface, task_fault,
};
use crate::resident::threading::NativeResident;
use troe_machine::NativeThreadStop;

impl ResidentApplication<'_> {
    #[allow(clippy::too_many_lines)]
    #[inline(never)]
    pub(super) fn run_native_slice(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        native: &mut NativeResident,
    ) -> Result<Option<CommandApplicationOutcome>, ()> {
        let mut io = native.take_io()?;
        let result = self.run_native_with_io(scheduler, accounting, native, &mut io);
        native.restore_io(io);
        result
    }

    #[allow(clippy::too_many_lines)]
    fn run_native_with_io(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        native: &mut NativeResident,
        io: &mut crate::resident::threading::io::NativeIo,
    ) -> Result<Option<CommandApplicationOutcome>, ()> {
        scheduler
            .dispatch(self.task_id, Capabilities::SERVICE)
            .map_err(|_| ())?;
        self.processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .dispatch(self.process_id)
            .map_err(|_| ())?;
        self.execute_accounted(|| {
            io.poll(
                native,
                self.deferred_services.as_ref(),
                accounting,
                self.diagnostics_generation,
            )
        })?;
        let mut request = [0; troe_abi::MAX_MESSAGE_BYTES];
        while let Some((caller, stop)) = self.execute_accounted(|| native.next())? {
            if matches!(
                stop,
                NativeThreadStop::SchedulerCall(_)
                    | NativeThreadStop::HandleCall(_)
                    | NativeThreadStop::HeapGrow(_)
            ) && !native.charge_kernel(caller, stop)?
            {
                break;
            }
            let terminal = match stop {
                NativeThreadStop::DispatchExpired | NativeThreadStop::Preempted => {
                    native.yielded(caller, true)?;
                    break;
                }
                NativeThreadStop::Yielded => {
                    native.yielded(caller, false)?;
                    None
                }
                NativeThreadStop::SchedulerCall(call) => {
                    let process = self
                        .processes
                        .try_borrow()
                        .map_err(|_| ())?
                        .snapshot_for_task(self.task_id)
                        .map_err(|_| ())?;
                    native.scheduler_call(accounting, &self.dispatcher, process, call)?
                }
                NativeThreadStop::HeapGrow(call) => {
                    native.grow_heap(accounting, call)?;
                    None
                }
                NativeThreadStop::HandleCall(call) => {
                    if call.request_bytes() < 2
                        || call.request_bytes() > request.len()
                        || command_handle_interface(&self.handles, call.handle()).is_none()
                    {
                        return Err(());
                    }
                    let bytes = &mut request[..call.request_bytes()];
                    let pending = native.suspend_handle(call, bytes)?;
                    let pending = if let Some(services) = &self.deferred_services {
                        let process = self
                            .processes
                            .try_borrow()
                            .map_err(|_| ())?
                            .snapshot_for_task(self.task_id)
                            .map_err(|_| ())?;
                        io.prepare(
                            native,
                            process,
                            command_handle_interface(&self.handles, call.handle()).ok_or(())?,
                            call,
                            pending,
                            bytes,
                            services,
                        )?
                    } else {
                        Some(pending)
                    };
                    let Some(pending) = pending else {
                        continue;
                    };
                    let opcode = u16::from_le_bytes([bytes[0], bytes[1]]);
                    // Native suspension owns its call and exact wait. No policy
                    // or native root borrow reaches this service callback.
                    let reply = self
                        .dispatcher
                        .call_owned_abi(self.owner, call.handle(), opcode, &bytes[2..])
                        .map_err(|_| ())?;
                    native.complete_handle(pending, reply.status().abi_value(), reply.payload())?;
                    None
                }
                NativeThreadStop::ProcessExited(status) => {
                    native.stop()?;
                    Some(CommandApplicationOutcome::Exited(status))
                }
                NativeThreadStop::ProcessFaulted(fault) => {
                    native.stop()?;
                    Some(CommandApplicationOutcome::Faulted(task_fault(fault)))
                }
            };
            let (tables, pages) = native.resource_totals()?;
            let isolation =
                IsolationResource::new(self.isolation.slot(), tables, pages, self.handle_count)
                    .map_err(|_| ())?;
            scheduler
                .resize_current_isolation(self.task_id, isolation)
                .map_err(|_| ())?;
            self.isolation = isolation;
            self.processes
                .try_borrow_mut()
                .map_err(|_| ())?
                .update_resources(self.process_id, tables, pages, self.handle_count)
                .map_err(|_| ())?;
            if let Some(outcome) = terminal {
                match outcome {
                    CommandApplicationOutcome::Exited(status) => scheduler
                        .exit_current(self.task_id, status)
                        .map_err(|_| ())?,
                    CommandApplicationOutcome::Faulted(fault) => scheduler
                        .fault_current(self.task_id, fault)
                        .map_err(|_| ())?,
                }
                return Ok(Some(outcome));
            }
        }
        scheduler.preempt_current(self.task_id).map_err(|_| ())?;
        self.processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .preempted(self.process_id)
            .map_err(|_| ())?;
        Ok(None)
    }
}

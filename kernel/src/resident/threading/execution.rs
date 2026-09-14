//! Resident turns retain owned native calls, never borrowed policy across services.

use super::{NativeThreads, SharedNativeThreads};
use crate::{
    invocation::CommandApplicationOutcome, machine::OwnedAccounting, memory::native::NativeMemory,
};
use alloc::vec::Vec;
use troe_dispatch::{Dispatcher, HandleOwner};
use troe_machine::{
    NativeHandleCall, NativeHandleExecution, NativeSchedulerCall, NativeSchedulerExecution,
    NativeThreadStop,
};
use troe_service::threading::{Operation, Progress, Waiting};
use troe_task::{
    MonotonicMillis, ProcessId, ProcessSnapshot,
    thread::{ThreadId, ThreadState, ThreadWait, schedule::Dispatch, sync::ExitEffect},
};

type SchedulerWait = (NativeSchedulerExecution, Waiting);

pub(crate) struct NativeResident {
    memory: NativeMemory,
    policy: SharedNativeThreads,
    process: ProcessId,
    turn: Option<Dispatch>,
    waits: Vec<SchedulerWait>,
    stops: Vec<(ThreadId, NativeThreadStop)>,
}

/// The service event and its exact policy wait are inseparable after suspension.
pub(crate) struct ResidentHandleCall {
    execution: NativeHandleExecution,
    wait: ThreadWait,
}

impl NativeResident {
    pub(crate) fn resource_totals(&self) -> Result<(u64, u64), ()> {
        self.memory.resource_totals()
    }

    pub(crate) fn grow_heap(
        &mut self,
        accounting: &mut OwnedAccounting,
        call: troe_machine::NativeHeapCall,
    ) -> Result<(), ()> {
        self.memory.grow_heap(accounting, call)?;
        self.yielded(call.caller(), false)
    }
    /// On failure return the complete memory owner for caller-controlled rollback.
    #[allow(clippy::result_large_err)]
    pub(crate) fn new(
        mut memory: NativeMemory,
        policy: SharedNativeThreads,
        process: ProcessId,
        accounting: &mut OwnedAccounting,
    ) -> Result<Self, NativeMemory> {
        let mut waits = Vec::new();
        let mut stops = Vec::new();
        if waits.try_reserve_exact(super::PROCESS_THREADS).is_err()
            || stops.try_reserve_exact(super::PROCESS_THREADS).is_err()
        {
            return Err(memory);
        }
        let metadata = core::mem::size_of::<Self>() - core::mem::size_of::<NativeMemory>()
            + waits.capacity() * core::mem::size_of::<SchedulerWait>()
            + stops.capacity() * core::mem::size_of::<(ThreadId, NativeThreadStop)>();
        if memory
            .charge_resident_metadata(accounting, metadata)
            .is_err()
        {
            return Err(memory);
        }
        Ok(Self {
            memory,
            policy,
            process,
            turn: None,
            waits,
            stops,
        })
    }

    /// No execution deadline is retained while an unrelated resident is visited.
    /// Every return of None has finished this owner's turn. A returned native
    /// stop still owns a Running policy record until its handler transitions it.
    pub(crate) fn next(&mut self) -> Result<Option<(ThreadId, NativeThreadStop)>, ()> {
        let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
        let NativeThreads { threads, sync } = &mut *policy;
        let now = monotonic_now()?;
        for (_, wait) in &mut self.waits {
            wait.observe(threads, sync, now).map_err(|_| ())?;
        }
        if self.turn.is_none() {
            if threads.next_dispatch_process().map_err(|_| ())? != Some(self.process) {
                return Ok(None);
            }
            self.turn = threads
                .begin_dispatch(
                    troe_machine::process_accounting_ticks(),
                    troe_machine::process_accounting_frequency_hz().ok_or(())?,
                    crate::limits::RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                    8,
                )
                .map_err(|_| ())?;
        }
        let turn = self.turn.as_mut().ok_or(())?;
        let Some(caller) = threads
            .dispatch_sibling(turn, troe_machine::process_accounting_ticks())
            .map_err(|_| ())?
        else {
            threads
                .finish_dispatch(
                    self.turn.take().ok_or(())?,
                    troe_machine::process_accounting_ticks(),
                )
                .map_err(|_| ())?;
            return Ok(None);
        };
        if let Some(index) = self
            .waits
            .iter()
            .position(|(_, wait)| wait.caller() == caller)
        {
            let (execution, wait) = self.waits.swap_remove(index);
            let completion = wait.finish(threads, sync).map_err(|_| ())?;
            self.memory.complete_scheduler(execution, completion)?;
        }
        let stop = if let Some(index) = self.stops.iter().position(|(id, _)| *id == caller) {
            self.stops.swap_remove(index).1
        } else {
            self.memory.resume(threads, turn, caller)?
        };
        Ok(Some((caller, stop)))
    }

    /// A captured request can outlive its turn, but never renew its budget.
    pub(crate) fn charge_kernel(
        &mut self,
        caller: ThreadId,
        stop: NativeThreadStop,
    ) -> Result<bool, ()> {
        let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
        if policy
            .threads
            .charge_dispatch_step(
                self.turn.as_mut().ok_or(())?,
                caller,
                troe_machine::process_accounting_ticks(),
            )
            .map_err(|_| ())?
            != 0
        {
            return Ok(true);
        }
        if self.stops.len() >= super::PROCESS_THREADS
            || self.stops.len() == self.stops.capacity()
            || self.stops.iter().any(|(id, _)| *id == caller)
        {
            return Err(());
        }
        self.stops.push((caller, stop));
        policy
            .threads
            .yield_running(self.process, caller)
            .map_err(|_| ())?;
        policy
            .threads
            .finish_dispatch(
                self.turn.take().ok_or(())?,
                troe_machine::process_accounting_ticks(),
            )
            .map_err(|_| ())?;
        Ok(false)
    }

    pub(crate) fn yielded(&mut self, caller: ThreadId, end_turn: bool) -> Result<(), ()> {
        let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
        policy
            .threads
            .yield_running(self.process, caller)
            .map_err(|_| ())?;
        if end_turn {
            policy
                .threads
                .finish_dispatch(
                    self.turn.take().ok_or(())?,
                    troe_machine::process_accounting_ticks(),
                )
                .map_err(|_| ())?;
        }
        Ok(())
    }

    /// Authenticate before claiming, then release all shared policy borrows on return.
    /// A terminal outcome requests process teardown; no accepted Exit is replied to.
    #[allow(clippy::too_many_lines)] // The closed action set keeps owned completion explicit.
    pub(crate) fn scheduler_call(
        &mut self,
        accounting: &mut OwnedAccounting,
        dispatcher: &Dispatcher<'_>,
        process: ProcessSnapshot,
        call: NativeSchedulerCall,
    ) -> Result<Option<CommandApplicationOutcome>, ()> {
        if process.id() != self.process || call.caller().process() != self.process {
            return Err(());
        }
        let owner = HandleOwner::isolated(process.task_id().get()).map_err(|_| ())?;
        let authority = call
            .call()
            .zip(call.request_bytes())
            .and_then(|(call, bytes)| {
                dispatcher
                    .authorize_scheduler_owned_abi(owner, call.handle, bytes)
                    .ok()
            });
        let Some(authority) = authority else {
            self.memory.reject_scheduler(call)?;
            self.yielded(call.caller(), false)?;
            return Ok(None);
        };
        let execution = self.memory.claim_scheduler(call, authority.request())?;
        let operation = Operation::bind(process, call.caller(), authority).map_err(|_| ())?;
        let progress = {
            let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
            let NativeThreads { threads, sync } = &mut *policy;
            operation
                .execute(threads, sync, monotonic_now()?)
                .map_err(|_| ())?
        };
        let completion = match progress {
            Progress::Complete(completion) => completion,
            Progress::Waiting(wait) => {
                if self.waits.len() >= super::PROCESS_THREADS
                    || self.waits.len() == self.waits.capacity()
                    || self
                        .waits
                        .iter()
                        .any(|(_, retained)| retained.caller() == wait.caller())
                {
                    return Err(());
                }
                self.waits.push((execution, wait));
                return Ok(None);
            }
            Progress::Preparing(action) => {
                let base =
                    crate::resident::launch::random_application_placement(&accounting.random)?
                        .stack_top();
                let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
                self.memory.prepare_thread(
                    accounting,
                    &mut policy.threads,
                    &execution,
                    action,
                    base,
                )?
            }
            Progress::Starting(action) => {
                let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
                self.memory
                    .start_thread(&mut policy.threads, &execution, action)?
            }
            Progress::Aborting(action) => {
                let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
                self.memory
                    .discard_thread(accounting, &mut policy.threads, action.target())?;
                action.finish(&mut policy.threads).map_err(|_| ())?
            }
            Progress::Retiring(action) => {
                if action.disposition() != ExitEffect::ThreadExiting {
                    self.stop()?;
                    return Ok(Some(CommandApplicationOutcome::Faulted(
                        troe_task::TaskFault::InvalidCall,
                    )));
                }
                let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
                self.memory
                    .retire_thread(accounting, &mut policy.threads, execution, action)?;
                // Creator exit revokes its unpublished workers. Remove their
                // native windows before releasing policy charges or Join readiness.
                loop {
                    let revoked = policy.threads.snapshots(self.process).find(|snapshot| {
                        snapshot.state == ThreadState::Revoked && !snapshot.resources_released
                    });
                    let Some(revoked) = revoked else {
                        break;
                    };
                    self.memory
                        .discard_thread(accounting, &mut policy.threads, revoked.id)?;
                    policy
                        .threads
                        .reap(self.process, revoked.id)
                        .map_err(|_| ())?;
                }
                let snapshot = policy
                    .threads
                    .snapshot(self.process, call.caller())
                    .map_err(|_| ())?;
                if snapshot.detached {
                    policy
                        .threads
                        .reap(self.process, snapshot.id)
                        .map_err(|_| ())?;
                }
                let live = policy.threads.snapshots(self.process).any(|snapshot| {
                    !matches!(
                        snapshot.state,
                        ThreadState::Completed | ThreadState::Revoked
                    )
                });
                if !live {
                    policy.stop(self.process)?;
                    self.memory.stop();
                    self.turn = None;
                    return Ok(Some(CommandApplicationOutcome::Exited(0)));
                }
                return Ok(None);
            }
        };
        self.memory.complete_scheduler(execution, completion)?;
        self.yielded(call.caller(), false)?;
        Ok(None)
    }

    pub(crate) fn suspend_handle(
        &mut self,
        call: NativeHandleCall,
        request: &mut [u8],
    ) -> Result<ResidentHandleCall, ()> {
        self.memory.copy_handle_request(call, request)?;
        let execution = self.memory.claim_handle(call)?;
        let wait = self
            .policy
            .try_borrow_mut()
            .map_err(|_| ())?
            .threads
            .block(self.process, call.caller())
            .map_err(|_| ())?;
        Ok(ResidentHandleCall { execution, wait })
    }

    pub(crate) fn complete_handle(
        &mut self,
        pending: ResidentHandleCall,
        status: u32,
        reply: &[u8],
    ) -> Result<(), ()> {
        let caller = pending.execution.operation().caller();
        let mut policy = self.policy.try_borrow_mut().map_err(|_| ())?;
        if policy
            .threads
            .snapshot(self.process, caller)
            .map_err(|_| ())?
            .state
            != ThreadState::Blocked
        {
            return Err(());
        }
        // Validate/consume the exact generation before publishing the response.
        // Exclusive ownership prevents any Ready caller executing between them.
        policy
            .threads
            .wake(self.process, pending.wait)
            .map_err(|_| ())?;
        self.memory
            .complete_handle(pending.execution, status, reply)
    }

    pub(crate) fn stop(&mut self) -> Result<(), ()> {
        self.memory.stop();
        self.policy
            .try_borrow_mut()
            .map_err(|_| ())?
            .stop(self.process)?;
        self.turn = None;
        self.waits.clear();
        self.stops.clear();
        Ok(())
    }

    pub(crate) fn reclaim(mut self, accounting: &mut OwnedAccounting) -> Result<(), ()> {
        self.stop()?;
        self.memory.reclaim(accounting)?;
        self.policy
            .try_borrow_mut()
            .map_err(|_| ())?
            .remove_reclaimed(self.process)
    }
}

fn monotonic_now() -> Result<MonotonicMillis, ()> {
    let frequency = troe_machine::process_accounting_frequency_hz().ok_or(())?;
    if frequency == 0 {
        return Err(());
    }
    let millis =
        u128::from(troe_machine::process_accounting_ticks()) * 1_000 / u128::from(frequency);
    Ok(MonotonicMillis::from_millis(
        u64::try_from(millis).map_err(|_| ())?,
    ))
}

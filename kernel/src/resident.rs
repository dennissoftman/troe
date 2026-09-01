//! The resident process registry: slots, jobs, owners, and their tables.
//!
//! A resident process is one loaded application the machine keeps stepping:
//! its control block, its execution state, its bounded log, and the job the
//! shell knows it by.

pub(crate) mod application;
pub(crate) mod launch;

use crate::deferred::{CommandDeferredServices, CommandDeferredState};
use crate::handles::{SharedChildTable, SharedPipeTable, SharedProcessTable, SharedResidentLog};
use crate::invocation::{CommandApplicationHandle, CommandApplicationOutcome};
use crate::limits::{
    INITIAL_RESIDENT_PROCESS_CAPACITY, RESIDENT_PROCESS_CAPACITY, RESIDENT_PROCESS_FIRST_SLOT,
};
use crate::machine::OwnedAccounting;
use crate::memory::ApplicationAllocation;
use crate::nested::{NestedChild, NestedLaunchContext};
use crate::requirements::BackgroundRequirements;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use troe_dispatch::{Dispatcher, HandleOwner};
use troe_process::OwnerId;
use troe_task::{Capabilities, IsolationResource, ProcessId, Scheduler, TaskFault, TaskId};

pub(crate) struct ResidentProcessControl<'service> {
    pub(crate) owner: OwnerId,
    pub(crate) depth: u32,
    pub(crate) grants: BackgroundRequirements,
    pub(crate) children: SharedChildTable,
    pub(crate) pipes: SharedPipeTable,
    pub(crate) launch: NestedLaunchContext<'service>,
    pub(crate) processes: Vec<NestedChild<'service>>,
}

pub(crate) enum ResidentExecution {
    Unstarted(Box<ResidentLaunch>),
    Pending(Box<troe_machine::ApplicationOutcome>),
    Blocked,
}

pub(crate) struct ResidentLaunch {
    address_space: troe_machine::UserAddressSpace,
    entry: u64,
    stack_top: u64,
    startup_address: u64,
}

pub(crate) struct ResidentApplication<'service> {
    pub(crate) task_id: TaskId,
    process_id: ProcessId,
    processes: SharedProcessTable,
    allocation: ApplicationAllocation,
    isolation: IsolationResource,
    owner: HandleOwner,
    handles: Vec<CommandApplicationHandle>,
    handle_count: u16,
    stack_pages: u64,
    heap_start: u64,
    maximum_heap_pages: u64,
    private_pages: u64,
    dispatcher: Dispatcher<'service>,
    deferred_services: Option<CommandDeferredServices>,
    deferred_state: Option<CommandDeferredState>,
    pub(crate) process_control: Option<ResidentProcessControl<'service>>,
    pub(crate) execution: Option<ResidentExecution>,
}

pub(crate) struct ResidentJob {
    pub(crate) id: u32,
    task_id: TaskId,
    pub(crate) command: String,
    pub(crate) owner: ResidentOwner,
    log: SharedResidentLog,
    pub(crate) process: Option<Box<ResidentApplication<'static>>>,
    pub(crate) outcome: Option<CommandApplicationOutcome>,
    pub(crate) cancel_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentOwner {
    Session,
    Service(u32),
}

pub(crate) struct ResidentProcessTable {
    pub(crate) jobs: Vec<ResidentJob>,
    next_id: u32,
}

impl ResidentProcessTable {
    pub(crate) fn new() -> Result<Self, ()> {
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(INITIAL_RESIDENT_PROCESS_CAPACITY)
            .map_err(|_| ())?;
        Ok(Self { jobs, next_id: 1 })
    }

    pub(crate) fn available_slot(&self) -> Option<u32> {
        (0..RESIDENT_PROCESS_CAPACITY).find_map(|offset| {
            let offset = u32::try_from(offset).ok()?;
            let slot = RESIDENT_PROCESS_FIRST_SLOT.checked_add(offset)?;
            (!self.jobs.iter().any(|job| {
                job.process
                    .as_ref()
                    .is_some_and(|process| process.isolation.slot() == slot)
            }))
            .then_some(slot)
        })
    }

    pub(crate) fn admit(
        &mut self,
        command: String,
        owner: ResidentOwner,
        log: SharedResidentLog,
        process: Box<ResidentApplication<'static>>,
    ) -> Result<u32, Box<ResidentApplication<'static>>> {
        if self.jobs.len() >= RESIDENT_PROCESS_CAPACITY {
            return Err(process);
        }
        if self.jobs.try_reserve(1).is_err() {
            return Err(process);
        }
        let (id, next_id) = match owner {
            ResidentOwner::Session => {
                let Some(next_id) = self.next_id.checked_add(1) else {
                    return Err(process);
                };
                (self.next_id, next_id)
            }
            ResidentOwner::Service(_) => (0, self.next_id),
        };
        self.jobs.push(ResidentJob {
            id,
            task_id: process.task_id,
            command,
            owner,
            log,
            process: Some(process),
            outcome: None,
            cancel_requested: false,
        });
        self.next_id = next_id;
        Ok(id)
    }

    pub(crate) fn pump(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        shell_id: TaskId,
        shell_capabilities: Capabilities,
    ) -> Result<(), ()> {
        scheduler.yield_current(shell_id).map_err(|_| ())?;
        self.pump_processes(scheduler, accounting)?;
        scheduler
            .dispatch(shell_id, shell_capabilities)
            .map_err(|_| ())?;
        Ok(())
    }

    pub(crate) fn pump_processes(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        for index in 0..self.jobs.len() {
            if self.jobs[index].outcome.is_some() {
                continue;
            }
            let cancelled = self.jobs[index].cancel_requested;
            let result = if cancelled {
                None
            } else {
                self.jobs[index]
                    .process
                    .as_mut()
                    .map(|process| process.step(scheduler, accounting))
            };
            let terminal = match result {
                Some(Ok(Some(outcome))) => Some((outcome, false)),
                Some(Ok(None)) => None,
                Some(Err(())) => Some((
                    CommandApplicationOutcome::Faulted(TaskFault::InvalidCall),
                    true,
                )),
                None => Some((
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                )),
            };
            if let Some((outcome, force_cancel)) = terminal {
                let process = self.jobs[index].process.take().ok_or(())?;
                self.jobs[index].outcome = Some(process.teardown(
                    scheduler,
                    accounting,
                    outcome,
                    cancelled || force_cancel,
                )?);
            }
        }
        Ok(())
    }

    pub(crate) fn has_runnable_process(&self) -> bool {
        self.jobs.iter().any(|job| {
            job.outcome.is_none()
                && !job.cancel_requested
                && job.process.as_ref().is_some_and(|process| {
                    !matches!(process.execution, Some(ResidentExecution::Blocked))
                })
        })
    }

    pub(crate) fn request_cancel(&mut self, job_id: u32) -> Result<(), ()> {
        let job = self
            .jobs
            .iter_mut()
            .find(|job| job.id == job_id && job.owner == ResidentOwner::Session)
            .ok_or(())?;
        if job.outcome.is_some() {
            return Ok(());
        }
        job.process.as_ref().ok_or(())?.request_stop()?;
        job.cancel_requested = true;
        Ok(())
    }

    pub(crate) fn is_terminal(&self, job_id: u32) -> Result<bool, ()> {
        self.jobs
            .iter()
            .find(|job| job.id == job_id && job.owner == ResidentOwner::Session)
            .map(|job| job.outcome.is_some())
            .ok_or(())
    }

    pub(crate) fn copy_log(&self, job_id: u32, destination: &mut [u8]) -> Result<(usize, u64), ()> {
        let job = self
            .jobs
            .iter()
            .find(|job| job.id == job_id && job.owner == ResidentOwner::Session)
            .ok_or(())?;
        let log = job.log.try_borrow().map_err(|_| ())?;
        Ok((log.copy_recent(destination), log.dropped()))
    }

    pub(crate) fn remove_terminal(&mut self, job_id: u32) -> Result<CommandApplicationOutcome, ()> {
        let index = self
            .jobs
            .iter()
            .position(|job| job.id == job_id && job.owner == ResidentOwner::Session)
            .ok_or(())?;
        let outcome = self.jobs[index].outcome.ok_or(())?;
        self.jobs.remove(index);
        Ok(outcome)
    }

    pub(crate) fn service_task(&self, service_id: u32) -> Option<TaskId> {
        self.jobs
            .iter()
            .find(|job| job.owner == ResidentOwner::Service(service_id))
            .and_then(|job| job.process.as_ref())
            .map(|process| process.task_id)
    }

    pub(crate) fn request_service_cancel(&mut self, service_id: u32) -> Result<(), ()> {
        let job = self
            .jobs
            .iter_mut()
            .find(|job| job.owner == ResidentOwner::Service(service_id))
            .ok_or(())?;
        if job.outcome.is_none() {
            job.process.as_ref().ok_or(())?.request_stop()?;
            job.cancel_requested = true;
        }
        Ok(())
    }

    pub(crate) fn copy_service_log(
        &self,
        service_id: u32,
        destination: &mut [u8],
    ) -> Option<(usize, u64)> {
        let job = self
            .jobs
            .iter()
            .find(|job| job.owner == ResidentOwner::Service(service_id))?;
        let log = job.log.try_borrow().ok()?;
        Some((log.copy_recent(destination), log.dropped()))
    }

    pub(crate) fn take_service_terminal(
        &mut self,
        service_id: u32,
    ) -> Option<(TaskId, CommandApplicationOutcome, SharedResidentLog)> {
        let index = self.jobs.iter().position(|job| {
            job.owner == ResidentOwner::Service(service_id) && job.outcome.is_some()
        })?;
        let job = self.jobs.remove(index);
        Some((job.task_id, job.outcome?, job.log))
    }
}

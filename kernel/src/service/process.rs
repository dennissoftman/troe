//! Process launch, process observation, and pipe services.
//!
//! An application spawns children, observes their lifecycle, and creates pipe
//! pairs through these endpoints. Each one is bounded by the owner's child and
//! pipe tables rather than by the machine's totals.

use crate::handles::{
    SharedChildTable, SharedPipeTable, SharedProcessOwner, SharedProcessTable, SharedRuntime,
};
use alloc::vec::Vec;
use troe_abi::{pipe, process_launch, process_observation};
use troe_dispatch::{ReplyStatus, Request, Service, ServiceReply};
use troe_process::{PipeDirection, PipeEndpoint, ProcessError as ChildProcessError};
use troe_task::{ProcessOrigin, ProcessState};

pub(crate) struct ApplicationProcessObservationService {
    pub(crate) processes: SharedProcessTable,
    pub(crate) runtime: SharedRuntime,
}

pub(crate) struct ApplicationProcessLaunchService {
    pub(crate) owner: SharedProcessOwner,
    pub(crate) children: SharedChildTable,
}

pub(crate) struct ApplicationPipeService {
    pub(crate) owner: SharedProcessOwner,
    pub(crate) pipes: SharedPipeTable,
}

pub(crate) struct ApplicationPipeInputService {
    pub(crate) pipes: SharedPipeTable,
    pub(crate) endpoint: PipeEndpoint,
}

pub(crate) struct ApplicationPipeOutputService {
    pub(crate) pipes: SharedPipeTable,
    pub(crate) endpoint: PipeEndpoint,
}

pub(crate) fn child_process_status(error: ChildProcessError) -> ReplyStatus {
    match error {
        ChildProcessError::CapacityExhausted | ChildProcessError::MetadataExhausted => {
            ReplyStatus::Exhausted
        }
        ChildProcessError::InvalidToken => ReplyStatus::NotFound,
        ChildProcessError::ForeignOwner | ChildProcessError::Closed => ReplyStatus::Conflict,
        ChildProcessError::WouldBlock => ReplyStatus::Failure,
        ChildProcessError::InvalidCapacity
        | ChildProcessError::InvalidOwner
        | ChildProcessError::InvalidProcess
        | ChildProcessError::InvalidState
        | ChildProcessError::InvalidMessage => ReplyStatus::InvalidRequest,
        ChildProcessError::GenerationExhausted | ChildProcessError::AccountingOverflow => {
            ReplyStatus::Failure
        }
    }
}

impl Service for ApplicationProcessLaunchService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        let Some(owner) = self.owner.get() else {
            return Ok(ServiceReply::empty(ReplyStatus::Conflict));
        };
        if request.opcode() == process_launch::SPAWN {
            // Admission needs scheduler and namespace authority and is
            // intercepted by ResidentApplication::step.
            return Ok(ServiceReply::empty(ReplyStatus::Failure));
        }
        let Ok(token) = process_launch::decode_token(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        match request.opcode() {
            process_launch::POLL | process_launch::WAIT => {
                let status = match self.children.try_borrow() {
                    Ok(children) => children.status(owner, token),
                    Err(_) => return Ok(ServiceReply::empty(ReplyStatus::Conflict)),
                };
                match status {
                    Ok(status) => ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &process_launch::encode_status(status)
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                    ),
                    Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                }
            }
            process_launch::CANCEL => {
                let status = match self.children.try_borrow_mut() {
                    Ok(mut children) => children
                        .request_cancel(owner, token)
                        .and_then(|_| children.status(owner, token)),
                    Err(_) => return Ok(ServiceReply::empty(ReplyStatus::Conflict)),
                };
                match status {
                    Ok(status) => ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &process_launch::encode_status(status)
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                    ),
                    Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                }
            }
            process_launch::REAP => {
                let result = match self.children.try_borrow_mut() {
                    Ok(mut children) => children.reap(owner, token),
                    Err(_) => return Ok(ServiceReply::empty(ReplyStatus::Conflict)),
                };
                match result {
                    Ok(_) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                }
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Service for ApplicationPipeService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        let Some(owner) = self.owner.get() else {
            return Ok(ServiceReply::empty(ReplyStatus::Conflict));
        };
        let Ok(mut pipes) = self.pipes.try_borrow_mut() else {
            return Ok(ServiceReply::empty(ReplyStatus::Conflict));
        };
        match request.opcode() {
            pipe::CREATE => {
                let Ok(capacity) = pipe::decode_create(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match pipes.create(owner, capacity) {
                    Ok(token) => {
                        ServiceReply::with_payload(ReplyStatus::Success, &pipe::encode_token(token))
                    }
                    Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                }
            }
            pipe::WRITE => {
                let Ok((token, payload)) = pipe::decode_write(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match pipes.write_owner(owner, token, payload) {
                    Ok(count) if count == payload.len() => {
                        Ok(ServiceReply::empty(ReplyStatus::Success))
                    }
                    Ok(_) => Ok(ServiceReply::empty(ReplyStatus::Failure)),
                    Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                }
            }
            pipe::READ => {
                let Ok((token, maximum)) = pipe::decode_read(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let mut bytes = [0_u8; pipe::MAX_IO_BYTES];
                match pipes.read_owner(owner, token, &mut bytes[..maximum]) {
                    Ok(count) => ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count]),
                    Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                }
            }
            pipe::CLOSE_WRITER | pipe::CLOSE_READER => {
                let Ok(token) = pipe::decode_token(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let direction = if request.opcode() == pipe::CLOSE_WRITER {
                    PipeDirection::Writer
                } else {
                    PipeDirection::Reader
                };
                match pipes.close_owner(owner, token, direction) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                }
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Service for ApplicationProcessObservationService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        let frequency = troe_machine::process_accounting_frequency_hz()
            .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
        let processes = self
            .processes
            .try_borrow()
            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(processes.snapshots().len())
            .map_err(|_| troe_dispatch::DispatchError::MetadataExhausted)?;
        for process in processes.snapshots() {
            records.push(process_observation::Process {
                id: process.id().get(),
                task_id: u64::from(process.task_id().get()),
                started_millis: process.started_millis(),
                cpu_ticks: process.cpu_ticks(),
                resident_pages: process.resident_pages(),
                table_pages: process.table_pages(),
                private_pages: process.private_pages(),
                dispatches: process.dispatches(),
                yields: process.yields(),
                preemptions: process.preemptions(),
                handles: process.handles(),
                state: match process.state() {
                    ProcessState::Ready => process_observation::State::Ready,
                    ProcessState::Running => process_observation::State::Running,
                    ProcessState::Blocked => process_observation::State::Blocked,
                    ProcessState::Stopping => process_observation::State::Stopping,
                },
                origin: match process.origin() {
                    ProcessOrigin::Foreground => process_observation::Origin::Foreground,
                    ProcessOrigin::Background => process_observation::Origin::Background,
                    ProcessOrigin::Service => process_observation::Origin::Service,
                    ProcessOrigin::Child => process_observation::Origin::Child,
                },
                name: process_observation::ProcessName::new(process.name().as_str())
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
            });
        }
        let observed_millis = self.runtime.borrow().now().as_millis();
        match request.opcode() {
            process_observation::GET_SNAPSHOT if request.payload().is_empty() => {
                let retained = records.len().min(process_observation::MAX_PROCESSES);
                let snapshot = process_observation::Snapshot::new(
                    observed_millis,
                    frequency,
                    &records[..retained],
                )
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(
                    ReplyStatus::Success,
                    &process_observation::encode_snapshot(snapshot)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                )
            }
            process_observation::GET_PAGE => {
                let Ok(after) = process_observation::decode_page_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let start = records.partition_point(|process| process.id <= after);
                let end = start
                    .saturating_add(process_observation::MAX_PAGE_PROCESSES)
                    .min(records.len());
                let page_records = &records[start..end];
                let next_cursor = if end < records.len() {
                    page_records.last().map_or(0, |process| process.id)
                } else {
                    0
                };
                let page = process_observation::Page::new(
                    observed_millis,
                    frequency,
                    next_cursor,
                    u32::try_from(records.len())
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                    page_records,
                )
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(
                    ReplyStatus::Success,
                    &process_observation::encode_page(page)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                )
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

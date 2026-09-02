//! Suspended application calls and the deferred-call continuation machine.
//!
//! A service call an application makes that cannot complete synchronously —
//! a terminal read, a datagram receive, a timer, a child wait — is parked here
//! with the wait it registered, and resumed when the wait fires. This is the
//! plumbing that lets one cooperative task block without stalling the loop.
//!
//! This is the native IPC integration ADR 0035 names `kernel/src/ipc.rs`:
//! the continuation machine stays in the kernel when the servers move out,
//! and folds into that module together with the dispatcher wiring in
//! `service`.

use crate::handles::{
    SharedApplicationDatagram, SharedChildTable, SharedDiagnosticsSnapshot, SharedPipeTable,
    SharedRuntime,
};
use crate::invocation::CommandApplicationHandle;
use crate::limits::{APPLICATION_DATAGRAM_WAIT_MILLISECONDS, APPLICATION_TIMESLICE_MILLISECONDS};
use crate::machine::OwnedAccounting;
use crate::network::ReceivedUdp;
use crate::service::diagnostics::run_diagnostics_server;
use crate::service::process::child_process_status;
use crate::session::{SESSION_TERMINAL_WAIT_IDENTITY, SharedSessionTerminal};
use alloc::rc::Rc;
use alloc::vec::Vec;
use troe_abi::{datagram, diagnostics, pipe, process_launch, stream, timer};
use troe_dispatch::ReplyStatus;
use troe_process::{OwnerId, PipeEndpoint, ProcessError as ChildProcessError};
use troe_task::{
    Capabilities, MonotonicMillis, PendingCallState, PendingCallTable, PendingOperationId,
    Scheduler, TaskId, WaitObservation, WaitRegistration, WaitResource, WaitSpec, WaitTable,
    WakeInterest, WakeReason,
};

pub(crate) struct CommandDeferredServices {
    pub(crate) runtime: SharedRuntime,
    pub(crate) datagram: Option<SharedApplicationDatagram>,
    pub(crate) diagnostics: Option<Rc<[u8; diagnostics::SNAPSHOT_BYTES]>>,
    pub(crate) process_owner: Option<OwnerId>,
    pub(crate) children: Option<SharedChildTable>,
    pub(crate) pipes: Option<SharedPipeTable>,
    pub(crate) pipe_streams: Vec<PipeStreamService>,
    pub(crate) terminal: Option<SharedSessionTerminal>,
}

#[derive(Clone)]
pub(crate) struct PipeStreamService {
    pub(crate) interface: u32,
    pub(crate) pipes: SharedPipeTable,
    pub(crate) endpoint: PipeEndpoint,
}

pub(crate) enum DeferredCallKind {
    Timer {
        deadline: MonotonicMillis,
    },
    Datagram {
        state: SharedApplicationDatagram,
        local_port: u16,
        deadline: MonotonicMillis,
        resource: WaitResource,
    },
    Diagnostics {
        resource: WaitResource,
    },
    Child {
        children: SharedChildTable,
        owner: OwnerId,
        token: process_launch::ChildToken,
        resource: WaitResource,
    },
    PipeRead {
        pipes: SharedPipeTable,
        target: DeferredPipeTarget,
        maximum: usize,
        resource: WaitResource,
    },
    PipeWrite {
        pipes: SharedPipeTable,
        target: DeferredPipeTarget,
        byte_count: usize,
        resource: WaitResource,
    },
    TerminalRead {
        terminal: SharedSessionTerminal,
        maximum: usize,
        resource: WaitResource,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum DeferredPipeTarget {
    Owner {
        owner: OwnerId,
        token: pipe::PipeToken,
    },
    Endpoint(PipeEndpoint),
}

pub(crate) struct SuspendedApplicationCall {
    pub(crate) operation: PendingOperationId,
    pub(crate) application: troe_machine::ApplicationSession,
    pub(crate) call: troe_machine::ApplicationCall,
    pub(crate) kind: DeferredCallKind,
}

pub(crate) struct SuspendedApplicationCalls {
    pub(crate) slots: Vec<SuspendedApplicationCall>,
    high_water: u8,
}

pub(crate) struct CommandDeferredState {
    pub(crate) pending: PendingCallTable,
    pub(crate) waits: WaitTable,
    pub(crate) suspended: SuspendedApplicationCalls,
    pub(crate) next_request_id: u64,
}

pub(crate) enum DeferredCallPreparation {
    NotDeferred,
    Immediate {
        status: ReplyStatus,
        payload: Vec<u8>,
    },
    Blocked {
        operation: PendingOperationId,
        spec: WaitSpec,
        kind: DeferredCallKind,
    },
}

impl SuspendedApplicationCalls {
    fn new() -> Result<Self, ()> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(1).map_err(|_| ())?;
        Ok(Self {
            slots,
            high_water: 0,
        })
    }

    pub(crate) fn insert(&mut self, call: SuspendedApplicationCall) -> Result<(), ()> {
        if !self.slots.is_empty() {
            return Err(());
        }
        self.slots.push(call);
        self.high_water = 1;
        Ok(())
    }

    pub(crate) fn get(
        &self,
        operation: PendingOperationId,
    ) -> Result<&SuspendedApplicationCall, ()> {
        self.slots
            .first()
            .filter(|call| call.operation == operation)
            .ok_or(())
    }

    pub(crate) fn take(
        &mut self,
        operation: PendingOperationId,
    ) -> Result<SuspendedApplicationCall, ()> {
        if self
            .slots
            .first()
            .is_none_or(|call| call.operation != operation)
        {
            return Err(());
        }
        Ok(self.slots.remove(0))
    }

    fn clear(&mut self) {
        self.slots.clear();
    }
}

impl CommandDeferredState {
    #[inline(never)]
    pub(crate) fn new() -> Result<Self, ()> {
        Ok(Self {
            pending: PendingCallTable::new(1, troe_task::MAX_PENDING_REQUEST_BYTES)
                .map_err(|_| ())?,
            waits: WaitTable::new(1).map_err(|_| ())?,
            suspended: SuspendedApplicationCalls::new()?,
            next_request_id: 1,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.stats().live == 0
            && self.pending.stats().retained_bytes == 0
            && self.waits.stats().live == 0
            && self.suspended.slots.is_empty()
    }

    pub(crate) fn respected_bounds(&self) -> bool {
        self.pending.stats().high_water <= 1
            && self.waits.stats().high_water <= 1
            && self.suspended.high_water <= 1
    }

    pub(crate) fn revoke_owner(&mut self, owner: TaskId) -> Result<(), ()> {
        self.waits
            .cancel_owner(owner, WakeReason::Revoked)
            .map_err(|_| ())?;
        self.pending
            .teardown_owner(owner, WakeReason::Revoked)
            .map_err(|_| ())?;
        self.suspended.clear();
        Ok(())
    }
}

pub(crate) fn command_handle_interface(
    handles: &[CommandApplicationHandle],
    value: u64,
) -> Option<u32> {
    handles
        .iter()
        .find(|handle| handle.value == value)
        .map(|handle| handle.interface)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_resource_wait(
    task_id: TaskId,
    handle: u64,
    opcode: u16,
    payload: &[u8],
    reply_capacity: usize,
    resource: WaitResource,
    kind: DeferredCallKind,
    pending: &mut PendingCallTable,
    next_request_id: &mut u64,
) -> Result<DeferredCallPreparation, ()> {
    let operation = pending
        .begin(
            task_id,
            *next_request_id,
            handle,
            opcode,
            payload,
            reply_capacity,
        )
        .map_err(|_| ())?;
    *next_request_id = (*next_request_id).checked_add(1).ok_or(())?;
    let spec = WaitSpec::new(
        task_id,
        operation,
        Some(resource),
        WakeInterest::RESOURCE_READY,
        None,
    )
    .map_err(|_| ())?;
    Ok(DeferredCallPreparation::Blocked {
        operation,
        spec,
        kind,
    })
}

pub(crate) fn owned_reply_payload(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let mut payload = Vec::new();
    payload.try_reserve_exact(bytes.len()).map_err(|_| ())?;
    payload.extend_from_slice(bytes);
    Ok(payload)
}

#[inline(never)]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn prepare_deferred_call(
    task_id: TaskId,
    interface: u32,
    handle: u64,
    opcode: u16,
    payload: &[u8],
    reply_capacity: usize,
    services: &CommandDeferredServices,
    pending: &mut PendingCallTable,
    next_request_id: &mut u64,
) -> Result<DeferredCallPreparation, ()> {
    if interface == troe_abi::interface::PROCESS_LAUNCH && opcode == process_launch::WAIT {
        let Some(owner) = services.process_owner else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::Conflict,
                payload: Vec::new(),
            });
        };
        let Some(children) = &services.children else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::NotFound,
                payload: Vec::new(),
            });
        };
        let Ok(token) = process_launch::decode_token(payload) else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::InvalidRequest,
                payload: Vec::new(),
            });
        };
        let status = match children.try_borrow() {
            Ok(children) => children.status(owner, token),
            Err(_) => {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Conflict,
                    payload: Vec::new(),
                });
            }
        };
        let status = match status {
            Ok(status) => status,
            Err(error) => {
                return Ok(DeferredCallPreparation::Immediate {
                    status: child_process_status(error),
                    payload: Vec::new(),
                });
            }
        };
        if status.state != process_launch::ChildState::Running {
            let encoded = process_launch::encode_status(status).map_err(|_| ())?;
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::Success,
                payload: owned_reply_payload(&encoded)?,
            });
        }
        let resource = WaitResource::new(token.value(), owner.get()).map_err(|_| ())?;
        return prepare_resource_wait(
            task_id,
            handle,
            opcode,
            payload,
            reply_capacity,
            resource,
            DeferredCallKind::Child {
                children: children.clone(),
                owner,
                token,
                resource,
            },
            pending,
            next_request_id,
        );
    }

    if interface == troe_abi::interface::PIPE && matches!(opcode, pipe::READ | pipe::WRITE) {
        let Some(owner) = services.process_owner else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::Conflict,
                payload: Vec::new(),
            });
        };
        let Some(pipes) = &services.pipes else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::NotFound,
                payload: Vec::new(),
            });
        };
        if opcode == pipe::READ {
            let Ok((token, maximum)) = pipe::decode_read(payload) else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::InvalidRequest,
                    payload: Vec::new(),
                });
            };
            let mut bytes = [0_u8; pipe::MAX_IO_BYTES];
            let result = pipes.try_borrow_mut().map_err(|_| ())?.read_owner(
                owner,
                token,
                &mut bytes[..maximum],
            );
            return match result {
                Ok(count) => Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Success,
                    payload: owned_reply_payload(&bytes[..count])?,
                }),
                Err(ChildProcessError::WouldBlock) => {
                    let resource = WaitResource::new(token.value(), owner.get()).map_err(|_| ())?;
                    prepare_resource_wait(
                        task_id,
                        handle,
                        opcode,
                        payload,
                        reply_capacity,
                        resource,
                        DeferredCallKind::PipeRead {
                            pipes: pipes.clone(),
                            target: DeferredPipeTarget::Owner { owner, token },
                            maximum,
                            resource,
                        },
                        pending,
                        next_request_id,
                    )
                }
                Err(error) => Ok(DeferredCallPreparation::Immediate {
                    status: child_process_status(error),
                    payload: Vec::new(),
                }),
            };
        }
        let Ok((token, bytes)) = pipe::decode_write(payload) else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::InvalidRequest,
                payload: Vec::new(),
            });
        };
        let result = pipes
            .try_borrow_mut()
            .map_err(|_| ())?
            .write_owner(owner, token, bytes);
        return match result {
            Ok(count) if count == bytes.len() => Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::Success,
                payload: Vec::new(),
            }),
            Ok(_) => Err(()),
            Err(ChildProcessError::WouldBlock) => {
                let resource = WaitResource::new(token.value(), owner.get()).map_err(|_| ())?;
                prepare_resource_wait(
                    task_id,
                    handle,
                    opcode,
                    payload,
                    reply_capacity,
                    resource,
                    DeferredCallKind::PipeWrite {
                        pipes: pipes.clone(),
                        target: DeferredPipeTarget::Owner { owner, token },
                        byte_count: bytes.len(),
                        resource,
                    },
                    pending,
                    next_request_id,
                )
            }
            Err(error) => Ok(DeferredCallPreparation::Immediate {
                status: child_process_status(error),
                payload: Vec::new(),
            }),
        };
    }

    if interface == troe_abi::interface::STANDARD_INPUT
        && opcode == stream::READ
        && let Some(terminal) = &services.terminal
    {
        let Ok(maximum) = stream::decode_read_request(payload) else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::InvalidRequest,
                payload: Vec::new(),
            });
        };
        let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
        let ready = {
            let mut borrowed = terminal.try_borrow_mut().map_err(|_| ())?;
            borrowed.pump();
            borrowed
                .read_ready()
                .then(|| borrowed.take(&mut bytes[..maximum]))
        };
        if let Some(count) = ready {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::Success,
                payload: owned_reply_payload(&bytes[..count])?,
            });
        }
        let resource =
            WaitResource::new(SESSION_TERMINAL_WAIT_IDENTITY, task_id.get()).map_err(|_| ())?;
        return prepare_resource_wait(
            task_id,
            handle,
            opcode,
            payload,
            reply_capacity,
            resource,
            DeferredCallKind::TerminalRead {
                terminal: Rc::clone(terminal),
                maximum,
                resource,
            },
            pending,
            next_request_id,
        );
    }

    if matches!(
        interface,
        troe_abi::interface::STANDARD_INPUT
            | troe_abi::interface::STANDARD_OUTPUT
            | troe_abi::interface::STANDARD_ERROR
    ) && let Some(binding) = services
        .pipe_streams
        .iter()
        .find(|binding| binding.interface == interface)
    {
        let resource =
            WaitResource::new(binding.endpoint.token().value(), task_id.get()).map_err(|_| ())?;
        if interface == troe_abi::interface::STANDARD_INPUT && opcode == stream::READ {
            let Ok(maximum) = stream::decode_read_request(payload) else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::InvalidRequest,
                    payload: Vec::new(),
                });
            };
            let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
            let result = binding
                .pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .read_endpoint(binding.endpoint, &mut bytes[..maximum]);
            return match result {
                Ok(count) => Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Success,
                    payload: owned_reply_payload(&bytes[..count])?,
                }),
                Err(ChildProcessError::WouldBlock) => prepare_resource_wait(
                    task_id,
                    handle,
                    opcode,
                    payload,
                    reply_capacity,
                    resource,
                    DeferredCallKind::PipeRead {
                        pipes: binding.pipes.clone(),
                        target: DeferredPipeTarget::Endpoint(binding.endpoint),
                        maximum,
                        resource,
                    },
                    pending,
                    next_request_id,
                ),
                Err(error) => Ok(DeferredCallPreparation::Immediate {
                    status: child_process_status(error),
                    payload: Vec::new(),
                }),
            };
        }
        if matches!(
            interface,
            troe_abi::interface::STANDARD_OUTPUT | troe_abi::interface::STANDARD_ERROR
        ) && opcode == stream::WRITE
            && !payload.is_empty()
        {
            let result = binding
                .pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .write_endpoint(binding.endpoint, payload);
            return match result {
                Ok(count) if count == payload.len() => Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Success,
                    payload: Vec::new(),
                }),
                Ok(_) => Err(()),
                Err(ChildProcessError::WouldBlock) => prepare_resource_wait(
                    task_id,
                    handle,
                    opcode,
                    payload,
                    reply_capacity,
                    resource,
                    DeferredCallKind::PipeWrite {
                        pipes: binding.pipes.clone(),
                        target: DeferredPipeTarget::Endpoint(binding.endpoint),
                        byte_count: payload.len(),
                        resource,
                    },
                    pending,
                    next_request_id,
                ),
                Err(error) => Ok(DeferredCallPreparation::Immediate {
                    status: child_process_status(error),
                    payload: Vec::new(),
                }),
            };
        }
    }

    if interface == troe_abi::interface::TIMER && opcode == timer::SLEEP_UNTIL {
        let Ok(deadline) = timer::decode_milliseconds(payload) else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::InvalidRequest,
                payload: Vec::new(),
            });
        };
        let deadline = MonotonicMillis::from_millis(deadline);
        let now = services.runtime.borrow().now();
        if deadline <= now {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::Success,
                payload: Vec::new(),
            });
        }
        let operation = pending
            .begin(
                task_id,
                *next_request_id,
                handle,
                opcode,
                payload,
                reply_capacity,
            )
            .map_err(|_| ())?;
        *next_request_id = (*next_request_id).checked_add(1).ok_or(())?;
        let spec = WaitSpec::new(
            task_id,
            operation,
            None,
            WakeInterest::DEADLINE,
            Some(deadline),
        )
        .map_err(|_| ())?;
        return Ok(DeferredCallPreparation::Blocked {
            operation,
            spec,
            kind: DeferredCallKind::Timer { deadline },
        });
    }
    if interface == troe_abi::interface::DIAGNOSTICS {
        if opcode != diagnostics::GET_SNAPSHOT || !payload.is_empty() {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::InvalidRequest,
                payload: Vec::new(),
            });
        }
        if services.diagnostics.is_none() {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::NotFound,
                payload: Vec::new(),
            });
        }
        let operation = pending
            .begin(
                task_id,
                *next_request_id,
                handle,
                opcode,
                payload,
                reply_capacity,
            )
            .map_err(|_| ())?;
        *next_request_id = (*next_request_id).checked_add(1).ok_or(())?;
        let resource = WaitResource::new(operation.abi_value(), task_id.get()).map_err(|_| ())?;
        let spec = WaitSpec::new(
            task_id,
            operation,
            Some(resource),
            WakeInterest::RESOURCE_READY,
            None,
        )
        .map_err(|_| ())?;
        return Ok(DeferredCallPreparation::Blocked {
            operation,
            spec,
            kind: DeferredCallKind::Diagnostics { resource },
        });
    }
    if interface != troe_abi::interface::DATAGRAM || opcode != datagram::RECEIVE {
        return Ok(DeferredCallPreparation::NotDeferred);
    }
    let Ok(local_port) = datagram::decode_receive_request(payload) else {
        return Ok(DeferredCallPreparation::Immediate {
            status: ReplyStatus::InvalidRequest,
            payload: Vec::new(),
        });
    };
    let Some(state) = &services.datagram else {
        return Ok(DeferredCallPreparation::Immediate {
            status: ReplyStatus::NotFound,
            payload: Vec::new(),
        });
    };
    let local_port = match state.borrow_mut().claim_port(Some(local_port)) {
        Ok(port) => port,
        Err(status) => {
            return Ok(DeferredCallPreparation::Immediate {
                status,
                payload: Vec::new(),
            });
        }
    };
    match state.borrow_mut().receive_now(local_port) {
        Ok(Some(received)) => {
            let payload = encode_received_datagram(&received)?;
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::Success,
                payload,
            });
        }
        Err(status) => {
            return Ok(DeferredCallPreparation::Immediate {
                status,
                payload: Vec::new(),
            });
        }
        Ok(None) => {}
    }
    let now = services.runtime.borrow().now();
    let deadline = now.saturating_add(APPLICATION_DATAGRAM_WAIT_MILLISECONDS);
    let operation = pending
        .begin(
            task_id,
            *next_request_id,
            handle,
            opcode,
            payload,
            reply_capacity,
        )
        .map_err(|_| ())?;
    *next_request_id = (*next_request_id).checked_add(1).ok_or(())?;
    let resource = WaitResource::new(u64::from(local_port), task_id.get()).map_err(|_| ())?;
    let spec = WaitSpec::new(
        task_id,
        operation,
        Some(resource),
        WakeInterest::RESOURCE_READY.union(WakeInterest::DEADLINE),
        Some(deadline),
    )
    .map_err(|_| ())?;
    Ok(DeferredCallPreparation::Blocked {
        operation,
        spec,
        kind: DeferredCallKind::Datagram {
            state: state.clone(),
            local_port,
            deadline,
            resource,
        },
    })
}

pub(crate) fn encode_received_datagram(received: &ReceivedUdp) -> Result<Vec<u8>, ()> {
    let mut encoded = [0_u8; datagram::MAX_RECEIVE_REPLY_BYTES];
    let count = datagram::encode_receive_reply(
        received.source,
        received.source_port,
        &received.payload,
        &mut encoded,
    )
    .map_err(|_| ())?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(count).map_err(|_| ())?;
    payload.extend_from_slice(&encoded[..count]);
    Ok(payload)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn deferred_reply(
    kind: DeferredCallKind,
    reason: WakeReason,
    received: Option<ReceivedUdp>,
    request: &[u8],
) -> Result<(ReplyStatus, Vec<u8>), ()> {
    match (kind, reason) {
        (DeferredCallKind::Timer { .. }, WakeReason::Deadline) => {
            Ok((ReplyStatus::Success, Vec::new()))
        }
        (DeferredCallKind::Datagram { .. }, WakeReason::ResourceReady) => Ok((
            ReplyStatus::Success,
            encode_received_datagram(&received.ok_or(())?)?,
        )),
        (DeferredCallKind::Datagram { .. }, WakeReason::Deadline) => {
            Ok((ReplyStatus::Timeout, Vec::new()))
        }
        (
            DeferredCallKind::Child {
                children,
                owner,
                token,
                ..
            },
            WakeReason::ResourceReady,
        ) => {
            let status = children
                .try_borrow()
                .map_err(|_| ())?
                .status(owner, token)
                .map_err(|_| ())?;
            if status.state == process_launch::ChildState::Running {
                return Err(());
            }
            let encoded = process_launch::encode_status(status).map_err(|_| ())?;
            Ok((ReplyStatus::Success, owned_reply_payload(&encoded)?))
        }
        (
            DeferredCallKind::PipeRead {
                pipes,
                target,
                maximum,
                ..
            },
            WakeReason::ResourceReady,
        ) => {
            let mut bytes = [0_u8; pipe::MAX_IO_BYTES];
            let count = match target {
                DeferredPipeTarget::Owner { owner, token } => pipes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .read_owner(owner, token, &mut bytes[..maximum]),
                DeferredPipeTarget::Endpoint(endpoint) => pipes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .read_endpoint(endpoint, &mut bytes[..maximum]),
            }
            .map_err(|_| ())?;
            Ok((ReplyStatus::Success, owned_reply_payload(&bytes[..count])?))
        }
        (
            DeferredCallKind::PipeWrite {
                pipes,
                target,
                byte_count,
                ..
            },
            WakeReason::ResourceReady,
        ) => {
            let bytes = match target {
                DeferredPipeTarget::Owner { token, .. } => {
                    let (encoded_token, bytes) = pipe::decode_write(request).map_err(|_| ())?;
                    if encoded_token != token {
                        return Err(());
                    }
                    bytes
                }
                DeferredPipeTarget::Endpoint(_) => request,
            };
            if bytes.len() != byte_count {
                return Err(());
            }
            let count = match target {
                DeferredPipeTarget::Owner { owner, token } => pipes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .write_owner(owner, token, bytes),
                DeferredPipeTarget::Endpoint(endpoint) => pipes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .write_endpoint(endpoint, bytes),
            }
            .map_err(|_| ())?;
            if count != bytes.len() {
                return Err(());
            }
            Ok((ReplyStatus::Success, Vec::new()))
        }
        (
            DeferredCallKind::TerminalRead {
                terminal, maximum, ..
            },
            WakeReason::ResourceReady,
        ) => {
            let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
            let count = terminal
                .try_borrow_mut()
                .map_err(|_| ())?
                .take(&mut bytes[..maximum]);
            Ok((ReplyStatus::Success, owned_reply_payload(&bytes[..count])?))
        }
        (_, WakeReason::Cancelled | WakeReason::Revoked) => {
            Ok((ReplyStatus::Cancelled, Vec::new()))
        }
        (_, WakeReason::Closed) => Ok((ReplyStatus::Conflict, Vec::new())),
        (
            DeferredCallKind::Timer { .. } | DeferredCallKind::Diagnostics { .. },
            WakeReason::ResourceReady,
        )
        | (
            DeferredCallKind::Diagnostics { .. }
            | DeferredCallKind::Child { .. }
            | DeferredCallKind::PipeRead { .. }
            | DeferredCallKind::PipeWrite { .. }
            | DeferredCallKind::TerminalRead { .. },
            WakeReason::Deadline,
        ) => Err(()),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn wait_for_deferred_call(
    scheduler: &mut Scheduler,
    task_id: TaskId,
    operation: PendingOperationId,
    runtime: &SharedRuntime,
    pending: &mut PendingCallTable,
    waits: &mut WaitTable,
    suspended: &mut SuspendedApplicationCalls,
) -> Result<
    (
        troe_machine::ApplicationSession,
        troe_machine::ApplicationCall,
        ReplyStatus,
        Vec<u8>,
    ),
    (),
> {
    let mut received = None;
    let completion = loop {
        let state = pending.call(operation).map_err(|_| ())?.state();
        let PendingCallState::Waiting(wait) = state else {
            return Err(());
        };
        let cancelled = runtime.borrow_mut().checkpoint().is_err();
        if cancelled {
            if let Some(completion) = waits
                .cancel_operation(operation, WakeReason::Cancelled)
                .map_err(|_| ())?
            {
                break completion;
            }
            return Err(());
        }
        let now = runtime.borrow().now();
        let suspended_call = suspended.get(operation)?;
        match &suspended_call.kind {
            DeferredCallKind::Timer { deadline } => {
                if now >= *deadline {
                    let batch = waits.expire(now).map_err(|_| ())?;
                    if let Some(completion) = batch.iter().next() {
                        break completion;
                    }
                }
            }
            DeferredCallKind::Datagram {
                state,
                local_port,
                deadline,
                resource,
            } => {
                if let Some(datagram) = state
                    .borrow_mut()
                    .receive_now(*local_port)
                    .map_err(|_| ())?
                {
                    received = Some(datagram);
                    let batch = waits
                        .wake_resource(*resource, WakeReason::ResourceReady)
                        .map_err(|_| ())?;
                    if let Some(completion) = batch.iter().next() {
                        break completion;
                    }
                    return Err(());
                }
                if now >= *deadline {
                    let batch = waits.expire(now).map_err(|_| ())?;
                    if let Some(completion) = batch.iter().next() {
                        break completion;
                    }
                }
            }
            DeferredCallKind::Diagnostics { .. }
            | DeferredCallKind::Child { .. }
            | DeferredCallKind::PipeRead { .. }
            | DeferredCallKind::PipeWrite { .. }
            | DeferredCallKind::TerminalRead { .. } => return Err(()),
        }
        let deadline = match &suspended_call.kind {
            DeferredCallKind::Timer { deadline } | DeferredCallKind::Datagram { deadline, .. } => {
                *deadline
            }
            DeferredCallKind::Diagnostics { .. }
            | DeferredCallKind::Child { .. }
            | DeferredCallKind::PipeRead { .. }
            | DeferredCallKind::PipeWrite { .. }
            | DeferredCallKind::TerminalRead { .. } => return Err(()),
        };
        let remaining = deadline.as_millis().saturating_sub(now.as_millis());
        if remaining == 0 {
            continue;
        }
        // A logical wait may span hours or days, while architecture
        // one-shot counters have a much smaller exact range. Re-arm in
        // bounded idle slices so hardware width never becomes a process
        // lifetime limit.
        let interval = u32::try_from(remaining.min(u64::from(APPLICATION_TIMESLICE_MILLISECONDS)))
            .map_err(|_| ())?;
        let _deadline_fired =
            troe_machine::wait_for_runtime_event_timeout(interval).map_err(|_| ())?;
        if pending.call(operation).map_err(|_| ())?.state() != PendingCallState::Waiting(wait) {
            return Err(());
        }
    };
    pending.resolve(completion).map_err(|_| ())?;
    scheduler
        .wake_blocked(completion.owner(), completion.key())
        .map_err(|_| ())?;
    scheduler
        .dispatch(task_id, Capabilities::SERVICE)
        .map_err(|_| ())?;
    let suspended_call = suspended.take(operation)?;
    let request = pending.request(operation).map_err(|_| ())?;
    let (status, payload) =
        deferred_reply(suspended_call.kind, completion.reason(), received, request)?;
    if payload.len() > suspended_call.call.reply_capacity() {
        return Err(());
    }
    pending.finish(operation).map_err(|_| ())?;
    Ok((
        suspended_call.application,
        suspended_call.call,
        status,
        payload,
    ))
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn complete_diagnostics_deferred_call(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    task_id: TaskId,
    operation: PendingOperationId,
    snapshot: SharedDiagnosticsSnapshot,
    resource: WaitResource,
    pending: &mut PendingCallTable,
    waits: &mut WaitTable,
    suspended: &mut SuspendedApplicationCalls,
) -> Result<
    (
        troe_machine::ApplicationSession,
        troe_machine::ApplicationCall,
        ReplyStatus,
        Vec<u8>,
    ),
    (),
> {
    let reply_capacity = pending.call(operation).map_err(|_| ())?.reply_capacity();
    let (reason, server_reply) =
        run_diagnostics_server(scheduler, accounting, operation, snapshot, reply_capacity)?;
    let completion = match reason {
        WakeReason::ResourceReady | WakeReason::Closed => {
            let batch = waits.wake_resource(resource, reason).map_err(|_| ())?;
            let completion = batch.iter().next().ok_or(())?;
            if batch.iter().nth(1).is_some() {
                return Err(());
            }
            completion
        }
        WakeReason::Revoked => waits
            .cancel_operation(operation, reason)
            .map_err(|_| ())?
            .ok_or(())?,
        WakeReason::Deadline | WakeReason::Cancelled => return Err(()),
    };
    pending.resolve(completion).map_err(|_| ())?;
    scheduler
        .wake_blocked(completion.owner(), completion.key())
        .map_err(|_| ())?;
    scheduler
        .dispatch(task_id, Capabilities::SERVICE)
        .map_err(|_| ())?;
    let suspended_call = suspended.take(operation)?;
    if !matches!(
        suspended_call.kind,
        DeferredCallKind::Diagnostics { resource: owned, .. } if owned == resource
    ) {
        return Err(());
    }
    let (status, payload) = match reason {
        WakeReason::ResourceReady => server_reply.ok_or(())?,
        WakeReason::Closed => (ReplyStatus::Conflict, Vec::new()),
        WakeReason::Revoked => (ReplyStatus::Cancelled, Vec::new()),
        WakeReason::Deadline | WakeReason::Cancelled => return Err(()),
    };
    if payload.len() > suspended_call.call.reply_capacity() {
        return Err(());
    }
    pending.finish(operation).map_err(|_| ())?;
    Ok((
        suspended_call.application,
        suspended_call.call,
        status,
        payload,
    ))
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn resume_deferred_application_call(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    task_id: TaskId,
    operation: PendingOperationId,
    spec: WaitSpec,
    kind: DeferredCallKind,
    application: troe_machine::ApplicationSession,
    call: troe_machine::ApplicationCall,
    runtime: &SharedRuntime,
    diagnostics_snapshot: Option<&SharedDiagnosticsSnapshot>,
    state: &mut CommandDeferredState,
) -> Result<troe_machine::ApplicationOutcome, ()> {
    let registration = state
        .waits
        .register(spec, WaitObservation::Pending, runtime.borrow().now())
        .map_err(|_| ())?;
    match registration {
        WaitRegistration::Ready(reason) => {
            state
                .pending
                .mark_ready(operation, reason)
                .map_err(|_| ())?;
            let (status, payload) = deferred_reply(kind, reason, None, &[])?;
            if payload.len() > call.reply_capacity() {
                return Err(());
            }
            state.pending.finish(operation).map_err(|_| ())?;
            troe_machine::resume_application(
                application,
                troe_machine::ApplicationResume::HandleReply {
                    status: status.abi_value(),
                    reply: &payload,
                },
                APPLICATION_TIMESLICE_MILLISECONDS,
            )
            .map_err(|_| ())
        }
        WaitRegistration::Blocked(wait) => {
            let diagnostics = match &kind {
                DeferredCallKind::Diagnostics { resource } => {
                    Some((Rc::clone(diagnostics_snapshot.ok_or(())?), *resource))
                }
                DeferredCallKind::Timer { .. }
                | DeferredCallKind::Datagram { .. }
                | DeferredCallKind::Child { .. }
                | DeferredCallKind::PipeRead { .. }
                | DeferredCallKind::PipeWrite { .. }
                | DeferredCallKind::TerminalRead { .. } => None,
            };
            state.pending.bind_wait(operation, wait).map_err(|_| ())?;
            state.suspended.insert(SuspendedApplicationCall {
                operation,
                application,
                call,
                kind,
            })?;
            scheduler.block_current(task_id, wait).map_err(|_| ())?;
            let (application, _call, status, payload) =
                if let Some((snapshot, resource)) = diagnostics {
                    complete_diagnostics_deferred_call(
                        scheduler,
                        accounting,
                        task_id,
                        operation,
                        snapshot,
                        resource,
                        &mut state.pending,
                        &mut state.waits,
                        &mut state.suspended,
                    )?
                } else {
                    wait_for_deferred_call(
                        scheduler,
                        task_id,
                        operation,
                        runtime,
                        &mut state.pending,
                        &mut state.waits,
                        &mut state.suspended,
                    )?
                };
            troe_machine::resume_application(
                application,
                troe_machine::ApplicationResume::HandleReply {
                    status: status.abi_value(),
                    reply: &payload,
                },
                APPLICATION_TIMESLICE_MILLISECONDS,
            )
            .map_err(|_| ())
        }
    }
}

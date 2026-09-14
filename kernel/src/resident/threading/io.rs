//! Owned service waits: one bounded observation per resident visit.

use super::{NativeResident, PROCESS_THREADS, execution::ResidentHandleCall};
use crate::{
    deferred::{
        CommandDeferredServices, DeferredCallKind, DeferredCallPreparation, DeferredPipeTarget,
        deferred_reply, prepare_deferred_call,
    },
    machine::OwnedAccounting,
    network::ReceivedUdp,
    supervisor::ClientKey,
};
use alloc::vec::Vec;
use troe_dispatch::ReplyStatus;
use troe_machine::NativeHandleCall;
use troe_process::ProcessError;
use troe_task::{
    PendingCallState, PendingCallTable, PendingCaller, PendingOperationId, ProcessSnapshot, TaskId,
    WaitObservation, WaitRegistration, WaitResource, WaitTable, WakeReason,
};

struct Suspended {
    operation: PendingOperationId,
    continuation: ResidentHandleCall,
    kind: DeferredCallKind,
    resource: Option<WaitResource>,
}

pub(crate) struct NativeIo {
    task: TaskId,
    pending: PendingCallTable,
    waits: WaitTable,
    next_request: u64,
    slots: Vec<Suspended>,
    cursor: usize,
}

impl NativeIo {
    #[cfg(feature = "acceptance-probes")]
    pub(crate) fn live(&self) -> u32 {
        self.waits.stats().live
    }

    #[cfg(feature = "acceptance-probes")]
    pub(crate) fn high_water(&self) -> u32 {
        self.waits.stats().high_water
    }

    pub(crate) fn new(task: TaskId) -> Result<Self, ()> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(PROCESS_THREADS).map_err(|_| ())?;
        Ok(Self {
            task,
            pending: PendingCallTable::new(
                PROCESS_THREADS,
                PROCESS_THREADS * troe_task::MAX_PENDING_REQUEST_BYTES,
            )
            .map_err(|_| ())?,
            waits: WaitTable::new(PROCESS_THREADS).map_err(|_| ())?,
            next_request: 1,
            slots,
            cursor: 0,
        })
    }

    /// Inline storage is already part of the resident owner's charge.
    pub(crate) fn buffer_bytes(&self) -> usize {
        self.pending.metadata_bytes() - core::mem::size_of::<PendingCallTable>()
            + self.waits.metadata_bytes()
            - core::mem::size_of::<WaitTable>()
            + self.slots.capacity() * core::mem::size_of::<Suspended>()
    }

    /// A returned continuation belongs to a synchronous ordinary service call.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        &mut self,
        native: &mut NativeResident,
        process: ProcessSnapshot,
        interface: u32,
        call: NativeHandleCall,
        continuation: ResidentHandleCall,
        request: &[u8],
        services: &CommandDeferredServices,
    ) -> Result<Option<ResidentHandleCall>, ()> {
        if process.task_id() != self.task || self.slots.len() >= PROCESS_THREADS {
            return Err(());
        }
        let caller = PendingCaller::threaded(process, call.caller()).map_err(|_| ())?;
        let opcode = u16::from_le_bytes([request[0], request[1]]);
        let preparation = prepare_deferred_call(
            caller,
            interface,
            call.handle(),
            opcode,
            &request[2..],
            call.reply_capacity(),
            services,
            &mut self.pending,
            &mut self.next_request,
        )?;
        match preparation {
            DeferredCallPreparation::NotDeferred => return Ok(Some(continuation)),
            DeferredCallPreparation::Immediate { status, payload } => {
                native.complete_handle(continuation, status.abi_value(), &payload)?;
            }
            DeferredCallPreparation::Blocked {
                operation,
                spec,
                kind,
            } => {
                if spec.caller() != caller
                    || self.pending.call(operation).map_err(|_| ())?.caller() != caller
                {
                    return Err(());
                }
                let now = services.runtime.try_borrow().map_err(|_| ())?.now();
                match self
                    .waits
                    .register(spec, WaitObservation::Pending, now)
                    .map_err(|_| ())?
                {
                    WaitRegistration::Ready(reason) => {
                        self.pending.mark_ready(operation, reason).map_err(|_| ())?;
                        let (status, payload) = deferred_reply(kind, reason, None, &request[2..])?;
                        native.complete_handle(continuation, status.abi_value(), &payload)?;
                        self.pending.finish(operation).map_err(|_| ())?;
                    }
                    WaitRegistration::Blocked(wait) => {
                        self.pending.bind_wait(operation, wait).map_err(|_| ())?;
                        self.slots.push(Suspended {
                            operation,
                            continuation,
                            kind,
                            resource: spec.resource(),
                        });
                    }
                }
            }
        }
        Ok(None)
    }

    /// Complete at most one owned call. Work is bounded per process visit,
    /// independent of its runnable sibling count, and separately CPU-accounted.
    /// No policy borrow or user request pointer reaches any service operation.
    pub(crate) fn poll(
        &mut self,
        native: &mut NativeResident,
        services: Option<&CommandDeferredServices>,
        accounting: &mut OwnedAccounting,
        diagnostics_generation: Option<u32>,
    ) -> Result<(), ()> {
        if self.slots.is_empty() {
            return Ok(());
        }
        let services = services.ok_or(())?;
        let index = self.cursor % self.slots.len();
        self.cursor = (index + 1) % self.slots.len();
        let suspended = &self.slots[index];
        let operation = suspended.operation;
        let PendingCallState::Waiting(wait) = self.pending.call(operation).map_err(|_| ())?.state()
        else {
            return Err(());
        };
        services
            .runtime
            .try_borrow_mut()
            .map_err(|_| ())?
            .service_ambient();
        let now = services.runtime.try_borrow().map_err(|_| ())?.now();
        let (observation, received, diagnostic_reply) = match &suspended.kind {
            DeferredCallKind::Diagnostics { deadline, .. } => {
                let key = ClientKey {
                    task: self.task,
                    operation,
                };
                let snapshot = services.diagnostics.as_ref().ok_or(())?;
                let capacity = self
                    .pending
                    .call(operation)
                    .map_err(|_| ())?
                    .reply_capacity();
                let immediate = crate::client::submit(
                    accounting,
                    key,
                    diagnostics_generation.ok_or(())?,
                    snapshot.as_ref(),
                    capacity,
                    deadline.as_millis(),
                )?;
                let fate = match immediate {
                    Some(fate) => Some(fate),
                    None => crate::client::consume(accounting, key)?,
                };
                let Some((reason, reply)) = fate else {
                    return Ok(());
                };
                let observation = match reason {
                    WakeReason::ResourceReady => WaitObservation::ResourceReady,
                    WakeReason::Closed => WaitObservation::ResourceClosed,
                    WakeReason::Revoked => WaitObservation::OwnerRevoked,
                    WakeReason::Cancelled => WaitObservation::Cancelled,
                    WakeReason::Deadline => WaitObservation::Pending,
                };
                (observation, None, Some((reason, reply)))
            }
            kind => {
                let (observation, received) = observe(kind)?;
                (observation, received, None)
            }
        };
        let completion = self
            .waits
            .observe_operation(operation, suspended.resource, observation, now)
            .map_err(|_| ())?;
        let Some(completion) = completion else {
            return Ok(());
        };
        if completion.key() != wait {
            return Err(());
        }
        self.pending.resolve(completion).map_err(|_| ())?;
        let suspended = self.slots.swap_remove(index);
        let (status, payload) = if let Some((reason, reply)) = diagnostic_reply {
            if reason != completion.reason() {
                return Err(());
            }
            match reason {
                WakeReason::ResourceReady => reply.ok_or(())?,
                WakeReason::Closed => (ReplyStatus::Conflict, Vec::new()),
                WakeReason::Revoked | WakeReason::Cancelled => (ReplyStatus::Cancelled, Vec::new()),
                WakeReason::Deadline => (ReplyStatus::Timeout, Vec::new()),
            }
        } else {
            deferred_reply(
                suspended.kind,
                completion.reason(),
                received,
                self.pending.request(operation).map_err(|_| ())?,
            )?
        };
        native.complete_handle(suspended.continuation, status.abi_value(), &payload)?;
        self.pending.finish(operation).map_err(|_| ())?;
        Ok(())
    }

    /// Called after native and logical process stop; invokes no service callback.
    pub(crate) fn revoke(&mut self) -> Result<(), ()> {
        self.waits
            .discard_owner(self.task, WakeReason::Revoked)
            .map_err(|_| ())?;
        self.pending
            .teardown_owner(self.task, WakeReason::Revoked)
            .map_err(|_| ())?;
        self.slots.clear();
        self.cursor = 0;
        Ok(())
    }
}

/// One resource observation; readiness is consumed before another waiter is polled.
fn observe(kind: &DeferredCallKind) -> Result<(WaitObservation, Option<ReceivedUdp>), ()> {
    let readiness = match kind {
        DeferredCallKind::Timer { .. } => return Ok((WaitObservation::Pending, None)),
        DeferredCallKind::Datagram {
            state, local_port, ..
        } => {
            let received = state
                .try_borrow_mut()
                .map_err(|_| ())?
                .receive_now(*local_port)
                .map_err(|_| ())?;
            let observation = if received.is_some() {
                WaitObservation::ResourceReady
            } else {
                WaitObservation::Pending
            };
            return Ok((observation, received));
        }
        DeferredCallKind::Child {
            children,
            owner,
            token,
            ..
        } => children
            .try_borrow()
            .map_err(|_| ())?
            .status(*owner, *token)
            .map(|status| status.state != troe_abi::process_launch::ChildState::Running),
        DeferredCallKind::PipeRead { pipes, target, .. } => match target {
            DeferredPipeTarget::Owner { owner, token } => pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .owner_read_ready(*owner, *token),
            DeferredPipeTarget::Endpoint(endpoint) => pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .endpoint_read_ready(*endpoint),
        },
        DeferredCallKind::PipeWrite {
            pipes,
            target,
            byte_count,
            ..
        } => match target {
            DeferredPipeTarget::Owner { owner, token } => pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .owner_write_ready(*owner, *token, *byte_count),
            DeferredPipeTarget::Endpoint(endpoint) => pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .endpoint_write_ready(*endpoint, *byte_count),
        },
        DeferredCallKind::TerminalRead { terminal, .. } => {
            let mut terminal = terminal.try_borrow_mut().map_err(|_| ())?;
            terminal.pump();
            Ok(terminal.read_ready())
        }
        DeferredCallKind::Diagnostics { .. } => return Err(()),
    };
    Ok((
        match readiness {
            Ok(true) => WaitObservation::ResourceReady,
            Ok(false) => WaitObservation::Pending,
            Err(ProcessError::Closed | ProcessError::InvalidToken) => {
                WaitObservation::ResourceClosed
            }
            Err(_) => return Err(()),
        },
        None,
    ))
}

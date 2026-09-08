//! Pointer-free kernel continuation records for native service clients.
//!
//! Submit copies a request and returns. A separate scheduler step runs the
//! server; consume resumes the exact original operation without retaining an
//! application borrow, callback, Rust frame or payload pointer in the client.

use crate::handles::DiagnosticsServerFate;
use crate::machine::OwnedAccounting;
use crate::supervisor::ClientKey;
use alloc::vec::Vec;
use troe_abi::{diagnostics, ipc::Call, reply};
use troe_dispatch::ReplyStatus;
use troe_service::KernelContinuation;
use troe_task::{TaskId, WakeReason};

pub(crate) fn submit(
    accounting: &mut OwnedAccounting,
    key: ClientKey,
    incarnation: u32,
    snapshot: &[u8],
    reply_capacity: usize,
    deadline: u64,
) -> Result<Option<DiagnosticsServerFate>, ()> {
    let supervisor = accounting.persistent_services.as_mut().ok_or(())?;
    if supervisor
        .clients
        .iter()
        .any(|client| client.key == Some(key))
    {
        return Ok(None);
    }
    if supervisor.generation() != Some(incarnation) {
        return Ok(Some((WakeReason::Revoked, None)));
    }
    let Some(index) = supervisor
        .clients
        .iter()
        .position(|client| client.key.is_none() && client.handle.is_none())
    else {
        return Ok(Some((
            WakeReason::ResourceReady,
            Some((ReplyStatus::Exhausted, Vec::new())),
        )));
    };
    let client = &mut supervisor.clients[index];
    let runtime = supervisor.runtime.as_mut().ok_or(())?;
    let endpoint = supervisor.instances[0].as_ref().ok_or(())?.endpoint;
    let request_bytes = u16::try_from(snapshot.len()).map_err(|_| ())?;
    let reply_capacity = u16::try_from(reply_capacity.min(4096)).map_err(|_| ())?;
    runtime
        .kernel_request(client.actor, snapshot)
        .map_err(|_| ())?;
    let handle = runtime
        .model()
        .open(
            client.actor,
            endpoint,
            troe_abi::interface::DIAGNOSTICS,
            1,
            0,
        )
        .map_err(|_| ())?;
    let Ok(next) = runtime.kernel_call(
        client.actor,
        Call {
            handle,
            opcode: diagnostics::GET_SNAPSHOT,
            request_bytes,
            reply_capacity,
            deadline_millis: deadline,
            object_parameter: 0,
        },
    ) else {
        runtime
            .model()
            .close(client.actor, handle)
            .map_err(|_| ())?;
        return Err(());
    };
    #[cfg(feature = "acceptance-probes")]
    if crate::service::diagnostics::DIAGNOSTICS_FAULT_PROBE_REQUESTED
        .swap(false, core::sync::atomic::Ordering::AcqRel)
    {
        let actor = supervisor.instances[0].as_ref().ok_or(())?.actor;
        runtime
            .inject(actor, troe_machine::FaultPoint::BeforeReply)
            .map_err(|_| ())?;
    }
    client.key = Some(key);
    client.handle = Some(handle);
    client.continuation = Some(KernelContinuation::Diagnostics {
        task: key.task.get(),
        operation: key.operation.abi_value(),
        incarnation,
        deadline_millis: deadline,
    });
    if next.is_some() {
        supervisor.next = next;
    }
    Ok(None)
}

pub(crate) fn consume(
    accounting: &mut OwnedAccounting,
    key: ClientKey,
) -> Result<Option<DiagnosticsServerFate>, ()> {
    let supervisor = accounting.persistent_services.as_mut().ok_or(())?;
    let Some(client) = supervisor
        .clients
        .iter_mut()
        .find(|client| client.key == Some(key))
    else {
        return Ok(None);
    };
    let Some(KernelContinuation::Diagnostics {
        task, operation, ..
    }) = client.continuation
    else {
        return Err(());
    };
    if task != key.task.get() || operation != key.operation.abi_value() {
        return Err(());
    }
    let runtime = supervisor.runtime.as_mut().ok_or(())?;
    let mut bytes = [0; diagnostics::SNAPSHOT_BYTES];
    let Some((status, length)) = runtime
        .kernel_reply(client.actor, &mut bytes)
        .map_err(|_| ())?
    else {
        return Ok(None);
    };
    if let Some(handle) = client.handle.take() {
        // Revoked endpoint handles have already been removed during teardown.
        if runtime.model().has_handle(client.actor, handle) {
            runtime
                .model()
                .close(client.actor, handle)
                .map_err(|_| ())?;
        }
    }
    client.key = None;
    client.continuation = None;
    let fate = match status {
        reply::CLOSED => (WakeReason::Closed, None),
        reply::PEER_DIED | reply::DEADLOCK => (WakeReason::Revoked, None),
        reply::TIMEOUT => (WakeReason::Deadline, None),
        reply::CANCELLED => (WakeReason::Cancelled, None),
        value => {
            let status = ReplyStatus::from_abi_value(value).ok_or(())?;
            let mut payload = Vec::new();
            payload.try_reserve_exact(length).map_err(|_| ())?;
            payload.extend_from_slice(&bytes[..length]);
            (WakeReason::ResourceReady, Some((status, payload)))
        }
    };
    Ok(Some(fate))
}

pub(crate) fn cancel(accounting: &mut OwnedAccounting, task: TaskId) -> Result<(), ()> {
    let Some(supervisor) = accounting.persistent_services.as_mut() else {
        return Ok(());
    };
    for client in &mut supervisor.clients {
        if client.key.is_some_and(|key| key.task == task) {
            let runtime = supervisor.runtime.as_mut().ok_or(())?;
            runtime.cancel(client.actor).map_err(|_| ())?;
            runtime.model().take_resume(client.actor).map_err(|_| ())?;
            if let Some(handle) = client.handle.take()
                && runtime.model().has_handle(client.actor, handle)
            {
                runtime
                    .model()
                    .close(client.actor, handle)
                    .map_err(|_| ())?;
            }
            client.key = None;
            client.continuation = None;
        }
    }
    Ok(())
}

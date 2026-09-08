//! Native ownership faults, bounded replacement, and independently live peers.
use super::{ServerSpec, Supervisor, now};
use crate::machine::OwnedAccounting;
use troe_abi::{interface, ipc::Call, reply};
use troe_machine::FaultPoint;
use troe_service::{RestartPolicy, ServiceEvent, ServiceRecord, ServiceRole};
use troe_task::Scheduler;

pub(super) fn artifact(relay: bool) -> &'static [u8] {
    #[cfg(target_arch = "aarch64")]
    {
        if relay {
            include_bytes!("../../../tests/kex-corpus/aarch64/ipc-relay-server.kex")
        } else {
            include_bytes!("../../../tests/kex-corpus/aarch64/ipc-persistent-server.kex")
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if relay {
            include_bytes!("../../../tests/kex-corpus/x86_64/ipc-relay-server.kex")
        } else {
            include_bytes!("../../../tests/kex-corpus/x86_64/ipc-persistent-server.kex")
        }
    }
}

fn ready(
    s: &mut Supervisor,
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
) -> Result<(), ()> {
    let deadline = now()?.checked_add(4000).ok_or(())?;
    while !(0..3).all(|index| s.lifecycle.accepts_clients(ServiceRole::Acceptance(index))) {
        if now()? >= deadline {
            let _ = troe_machine::write(
                alloc::format!(
                    "ipc-phase-c ready-timeout states={:?},{:?},{:?} stats={:?}\n",
                    s.lifecycle.state(ServiceRole::Acceptance(0)),
                    s.lifecycle.state(ServiceRole::Acceptance(1)),
                    s.lifecycle.state(ServiceRole::Acceptance(2)),
                    s.lifecycle.stats()
                )
                .as_bytes(),
            );
            return Err(());
        }
        s.step(scheduler, accounting).inspect_err(|()| {
            let _ = troe_machine::write(
                alloc::format!(
                    "ipc-phase-c ready-error states={:?},{:?},{:?} stats={:?}\n",
                    s.lifecycle.state(ServiceRole::Acceptance(0)),
                    s.lifecycle.state(ServiceRole::Acceptance(1)),
                    s.lifecycle.state(ServiceRole::Acceptance(2)),
                    s.lifecycle.stats()
                )
                .as_bytes(),
            );
        })?;
    }
    Ok(())
}

fn admit(s: &mut Supervisor, client: usize, target: usize, opcode: u16) -> Result<u64, ()> {
    let endpoint = s.instances[target].as_ref().ok_or(())?.endpoint;
    let actor = s.clients[client].actor;
    let runtime = s.runtime.as_mut().ok_or(())?;
    let handle = runtime
        .model()
        .open(actor, endpoint, interface::DIAGNOSTICS, 1, 0)
        .map_err(|_| ())?;
    let deadline = now()?.checked_add(4000).ok_or(())?;
    let mut payload = [0x5a; 64];
    if opcode == 3 {
        payload[..8].copy_from_slice(&deadline.to_le_bytes());
    }
    runtime.kernel_request(actor, &payload).map_err(|_| ())?;
    let next = runtime
        .kernel_call(
            actor,
            Call {
                handle,
                opcode,
                request_bytes: 64,
                reply_capacity: 64,
                deadline_millis: deadline,
                object_parameter: 0,
            },
        )
        .map_err(|_| ())?;
    s.clients[client].handle = Some(handle);
    if next.is_some() {
        s.next = next;
    }
    Ok(handle)
}

fn result(s: &mut Supervisor, client: usize, expected: u32) -> Result<bool, ()> {
    let actor = s.clients[client].actor;
    let runtime = s.runtime.as_mut().ok_or(())?;
    let mut payload = [0; 64];
    let Some((status, bytes)) = runtime.kernel_reply(actor, &mut payload).map_err(|_| ())? else {
        return Ok(false);
    };
    if status != expected
        || (status == 0 && (bytes != 64 || payload != [0x5a; 64]))
        || (status != 0 && bytes != 0)
        || runtime
            .kernel_reply(actor, &mut payload)
            .map_err(|_| ())?
            .is_some()
    {
        return Err(());
    }
    let handle = s.clients[client].handle.take().ok_or(())?;
    if runtime.model().has_handle(actor, handle) {
        runtime.model().close(actor, handle).map_err(|_| ())?;
    }
    Ok(true)
}

fn drive_result(
    s: &mut Supervisor,
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    client: usize,
    expected: u32,
) -> Result<(), ()> {
    let deadline = now()?.checked_add(4000).ok_or(())?;
    while !result(s, client, expected)? {
        if now()? >= deadline {
            return Err(());
        }
        s.step(scheduler, accounting)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn case(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    case: usize,
) -> Result<(), ()> {
    let free = accounting.frames.free_frames();
    let specs: [ServerSpec; 3] = core::array::from_fn(|index| ServerSpec {
        record: ServiceRecord::new(
            ServiceRole::Acceptance(u8::try_from(index).unwrap_or_else(|_| unreachable!())),
            256,
            4000,
            RestartPolicy::new(2, u64::MAX).unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!()),
        artifact: artifact(index != 0),
        nested: index.checked_sub(1),
    });
    let mut s = Supervisor::new(&specs)?;
    ready(&mut s, scheduler, accounting).inspect_err(|()| {
        let _ = troe_machine::write(b"ipc-phase-c stage=ready-failed\n");
    })?;
    let before = s.runtime.as_mut().ok_or(())?.model().live();
    if before.contexts != 7 || before.endpoints != 3 {
        return Err(());
    }
    let target = usize::from(case == 6);
    let instance = s.instances[target].as_ref().ok_or(())?;
    let actor = instance.actor;
    let old_endpoint = instance.endpoint;
    let old_ticket = instance.ticket;
    let ipc = instance.allocation.ipc.as_ref().ok_or(())?.range();
    let pages = instance.allocation.extents.page_count() + instance.allocation.tables.page_count();
    let tag = s
        .runtime
        .as_mut()
        .ok_or(())?
        .tag_identity(actor)
        .map_err(|_| ())?;
    // A busy leaf gives both the queued-client and blocked-relay cases actual
    // copied pending calls; yielding alone is never counted as a blocked call.
    if case >= 5 {
        admit(&mut s, 1, 0, 2)?;
        s.step(scheduler, accounting)?;
    }
    s.runtime
        .as_mut()
        .ok_or(())?
        .poison_kernel_rx(s.clients[0].actor)
        .map_err(|_| ())?;
    let handle = admit(
        &mut s,
        0,
        if case == 2 { 2 } else { target },
        if case == 2 || case == 6 {
            3
        } else if case == 1 {
            2
        } else {
            1
        },
    )?;
    let faults = [
        FaultPoint::BeforeReceive,
        FaultPoint::AfterReceive,
        FaultPoint::NestedCall,
        FaultPoint::BeforeReply,
        FaultPoint::AfterReplyValidation,
    ];
    if case < 5 {
        s.runtime
            .as_mut()
            .ok_or(())?
            .inject(actor, faults[case])
            .map_err(|_| ())?;
    } else if case == 6 {
        s.step(scheduler, accounting)?;
        if s.runtime.as_mut().ok_or(())?.model().live().calls != 3 {
            return Err(());
        }
    }
    let free_before = accounting.frames.free_frames();
    if case >= 5 {
        if s.runtime.as_mut().ok_or(())?.stats().queued == 0 {
            return Err(());
        }
        s.runtime
            .as_mut()
            .ok_or(())?
            .terminate(actor, false)
            .map_err(|_| ())?;
        s.reap(scheduler, accounting, actor, ServiceEvent::Faulted)?;
    } else {
        let deadline = now()?.checked_add(4000).ok_or(())?;
        while s.instances[target].is_some() {
            if now()? >= deadline {
                return Err(());
            }
            s.step(scheduler, accounting)?;
        }
    }
    let runtime = s.runtime.as_mut().ok_or(())?;
    if !runtime
        .kernel_rx_unchanged(s.clients[0].actor)
        .map_err(|_| ())?
        || tag.is_live()
        || !troe_machine::ipc_range_is_zero(ipc)
        || accounting.frames.free_frames() != free_before.checked_add(pages).ok_or(())?
        || runtime.model().is_live(actor)
        || runtime
            .model()
            .open(
                s.clients[0].actor,
                old_endpoint,
                interface::DIAGNOSTICS,
                1,
                0,
            )
            .is_ok()
        || (case != 2 && runtime.model().has_handle(s.clients[0].actor, handle))
        || runtime.model().live().dirty_queues != 0
        || s.waits.stats().live != 2
    {
        return Err(());
    }
    drive_result(
        &mut s,
        scheduler,
        accounting,
        0,
        if case == 2 {
            reply::CONFLICT
        } else {
            reply::PEER_DIED
        },
    )?;
    if case >= 5 {
        drive_result(
            &mut s,
            scheduler,
            accounting,
            1,
            if case == 5 {
                reply::PEER_DIED
            } else {
                reply::SUCCESS
            },
        )?;
    }
    ready(&mut s, scheduler, accounting)?;
    let replacement = s.instances[target].as_ref().ok_or(())?;
    if replacement.ticket.generation() != old_ticket.generation() + 1
        || replacement.task.get() == old_ticket.task()
        || replacement.endpoint == old_endpoint
        || s.lifecycle.stats().starts != 4
    {
        return Err(());
    }
    // A normal call addresses the replacement explicitly; old client handles
    // and failed requests are never retargeted or replayed.
    admit(&mut s, 0, target, 1)?;
    drive_result(&mut s, scheduler, accounting, 0, reply::SUCCESS)?;
    for index in 0..3 {
        let actor = s.instances[index].as_ref().ok_or(())?.actor;
        s.runtime
            .as_mut()
            .ok_or(())?
            .terminate(actor, true)
            .map_err(|_| ())?;
        s.reap(scheduler, accounting, actor, ServiceEvent::Exited)?;
    }
    let live = s.runtime.as_mut().ok_or(())?.model().live();
    if live.contexts != 4
        || live.endpoints != 0
        || live.handles != 0
        || live.calls != 0
        || live.waits != 0
        || live.dirty_queues != 0
        || s.waits.stats().live != 0
        || accounting.frames.free_frames() != free
    {
        return Err(());
    }
    drop(s);
    let name = [
        "before-receive",
        "after-receive",
        "nested-call",
        "before-reply",
        "after-reply-validation",
        "queued",
        "blocked",
    ][case];
    let clients = if case >= 5 { 2 } else { 1 };
    if !troe_machine::write(alloc::format!("ipc-phase-c fault={name} clients={clients} fates={clients} endpoints=0 handles=0 waits=0 calls=0 frames=0 restart=1 normal=1 rx_unchanged=1\n").as_bytes()) { return Err(()); }
    Ok(())
}

pub(crate) fn verify(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
) -> Result<(), ()> {
    for index in 0..7 {
        case(scheduler, accounting, index).inspect_err(|()| {
            let _ = troe_machine::write(
                alloc::format!("ipc-phase-c failure case={index}\n").as_bytes(),
            );
        })?;
    }
    Ok(())
}

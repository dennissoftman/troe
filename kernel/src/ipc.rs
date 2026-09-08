//! Native Phase B acceptance with an owned persistent echo and isolated client.

use crate::artifacts::native_application_target;
use crate::limits::{IPC_BASELINE_SAMPLES, IPC_BASELINE_WARMUP_CALLS};
use crate::machine::OwnedAccounting;
use crate::memory::ApplicationAllocation;
use crate::memory::launch::{
    allocate_application, prepare_application_memory, reclaim_application,
    terminate_revoke_and_reap_task, write_launch_bytes,
};
use crate::probes::{EchoService, emit_ipc_samples, ipc_percentile};
use alloc::boxed::Box;
use alloc::vec::Vec;
use troe_application::{InitialHandle, StartupInfo, parse_kex, parse_kex_package};
use troe_dispatch::{BadgeTable, Dispatcher, HandleOwner, PortId, Rights};
use troe_machine::{ApplicationOutcome, ApplicationSession, IpcPair, IpcStop};
use troe_task::{Capabilities, IsolationResource, Scheduler, StackResource, TaskId};

struct ProbeTask {
    allocation: ApplicationAllocation,
    task: TaskId,
    owner: HandleOwner,
    startup: u64,
    session: ApplicationSession,
}

fn artifact(server: bool) -> &'static [u8] {
    #[cfg(target_arch = "aarch64")]
    {
        if server {
            include_bytes!("../../tests/kex-corpus/aarch64/ipc-echo-server.kex")
        } else {
            include_bytes!("../../tests/kex-corpus/aarch64/ipc-client.kex")
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if server {
            include_bytes!("../../tests/kex-corpus/x86_64/ipc-echo-server.kex")
        } else {
            include_bytes!("../../tests/kex-corpus/x86_64/ipc-client.kex")
        }
    }
}

#[derive(Clone, Copy)]
struct ProbeRequest {
    bytes: usize,
    opcode: u16,
    argument: u64,
}

#[allow(clippy::too_many_lines)]
fn launch(
    accounting: &mut OwnedAccounting,
    scheduler: &mut Scheduler,
    dispatcher: &mut Dispatcher<'_>,
    port: PortId,
    server: bool,
    request: ProbeRequest,
) -> Result<ProbeTask, ()> {
    let ProbeRequest {
        bytes,
        opcode,
        argument,
    } = request;
    let package = parse_kex_package(artifact(server)).map_err(|_| ())?;
    let requirements: Vec<_> = package.requirements().iter().collect();
    let expected = if server {
        &[(15, 2, 0), (24, 1, 0)][..]
    } else {
        &[(9, 1, 0)][..]
    };
    if requirements.len() != expected.len()
        || requirements
            .iter()
            .zip(expected)
            .any(|(requirement, &(id, major, minor))| {
                (requirement.interface, requirement.major, requirement.minor) != (id, major, minor)
            })
    {
        return Err(());
    }
    // Identical virtual placement deliberately exercises retained translations
    // for different physical pages under the two hardware tags.
    let plan = parse_kex(package.executable(), native_application_target(), 3).map_err(|_| ())?;
    let (allocation, mapping) = allocate_application(accounting, &plan).inspect_err(|()| {
        let _ = troe_machine::write(b"ipc-probe failure=allocation\n");
    })?;
    let mut task_id = None;
    let mut live_owner = None;
    let setup = (|| {
        prepare_application_memory(&allocation, &plan)?;
        let mut root =
            troe_machine::build_user_address_space(&mapping, allocation.tables).map_err(|_| ())?;
        let pair = allocation.ipc.as_ref().ok_or(())?;
        root.bind_ipc(pair, plan.layout().ipc_addresses().ok_or(())?.0)
            .map_err(|error| {
                let _ = troe_machine::write(
                    alloc::format!("ipc-probe failure=bind error={error:?}\n").as_bytes(),
                );
            })?;
        let slot = u32::try_from(pair.slot()).map_err(|_| ())?;
        let isolation = IsolationResource::new(
            slot,
            root.stats().table_pages,
            plan.charges().private_pages(),
            1,
        )
        .map_err(|_| ())?;
        let stack = StackResource::new(slot, plan.stack_pages()).map_err(|_| ())?;
        let task = scheduler
            .spawn_isolated(Capabilities::SERVICE, stack, isolation)
            .map_err(|_| ())?;
        task_id = Some(task);
        let owner = HandleOwner::isolated(task.get()).map_err(|_| ())?;
        live_owner = Some(owner);
        let interfaces: &[(u32, u16, u16, Rights)] = if server {
            &[
                (
                    troe_abi::interface::SERVER_ENDPOINT,
                    2,
                    0,
                    Rights::RECEIVE.union(Rights::REPLY),
                ),
                (troe_abi::interface::WAIT_SET, 1, 0, Rights::WAIT),
            ]
        } else {
            &[
                (
                    troe_abi::interface::COMMAND,
                    troe_abi::command::MAJOR,
                    troe_abi::command::MINOR,
                    Rights::CALL,
                ),
                (
                    troe_abi::interface::STANDARD_INPUT,
                    troe_abi::stream::MAJOR,
                    troe_abi::stream::MINOR,
                    Rights::CALL,
                ),
                (
                    troe_abi::interface::STANDARD_OUTPUT,
                    troe_abi::stream::MAJOR,
                    troe_abi::stream::MINOR,
                    Rights::CALL,
                ),
                (
                    troe_abi::interface::STANDARD_ERROR,
                    troe_abi::stream::MAJOR,
                    troe_abi::stream::MINOR,
                    Rights::CALL,
                ),
                (troe_abi::interface::DIAGNOSTICS, 1, 0, Rights::CALL),
            ]
        };
        let mut handles = Vec::new();
        for &(interface, major, minor, rights) in interfaces {
            let handle = dispatcher.open_owned(port, rights, owner).map_err(|_| ())?;
            handles.push(InitialHandle {
                value: handle.abi_value(),
                rights: rights.bits(),
                interface,
                major,
                minor,
            });
        }
        let mut startup = [0; 4096];
        plan.encode_startup_page(
            StartupInfo {
                task_id: u64::from(task.get()),
                handles: &handles,
            },
            &mut startup,
        )
        .map_err(|_| ())?;
        troe_machine::copy_to_physical(allocation.startup, 0, &startup).map_err(|_| ())?;
        if server {
            root.authorize_persistent_ipc(plan.layout().startup_address())
                .map_err(|_| ())?;
        }
        if !server {
            let mut config = [0; 32];
            config[..8].copy_from_slice(&(bytes as u64).to_le_bytes());
            config[8..16].copy_from_slice(&u64::from(opcode).to_le_bytes());
            config[24..32].copy_from_slice(&argument.to_le_bytes());
            config[16..24].copy_from_slice(
                &troe_machine::monotonic_millis()
                    .ok_or(())?
                    .checked_add(4000)
                    .ok_or(())?
                    .to_le_bytes(),
            );
            write_launch_bytes(
                &allocation.extents,
                (plan.charges().image_pages() + 1) * 4096,
                &config,
            )?;
        }
        scheduler
            .dispatch(task, Capabilities::SERVICE)
            .map_err(|_| ())?;
        let outcome = troe_machine::run_application(
            root,
            plan.entry_address(),
            plan.layout().stack_top(),
            plan.layout().startup_address(),
            4096,
            50,
        )
        .map_err(|_| ())?;
        scheduler.yield_current(task).map_err(|_| ())?;
        let ApplicationOutcome::Yielded(session) = outcome else {
            let _ = troe_machine::write(
                alloc::format!("ipc-probe failure=launch server={server} outcome={outcome:?}\n")
                    .as_bytes(),
            );
            return Err(());
        };
        Ok((task, owner, session))
    })();
    if let Ok((task, owner, session)) = setup {
        Ok(ProbeTask {
            allocation,
            task,
            owner,
            startup: plan.layout().startup_address(),
            session,
        })
    } else {
        if let Some(task) = task_id {
            terminate_revoke_and_reap_task(scheduler, task, dispatcher, live_owner)?;
        }
        reclaim_application(accounting, allocation)?;
        Err(())
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn verify(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    compatibility_p95: [u64; 4],
) -> Result<(), ()> {
    troe_machine::verify_ipc_pool().map_err(|_| ())?;
    let mut stale_tags: Option<[troe_machine::TagIdentity; 2]> = None;
    for (index, bytes) in [0, 64, 256, 4096].into_iter().enumerate() {
        for queued in [false, true] {
            let free = accounting.frames.free_frames();
            let mut dispatcher = Dispatcher::new(1, 16).map_err(|_| ())?;
            let (port, root_handle) = dispatcher
                .register(Box::new(EchoService), Rights::CALL)
                .map_err(|_| ())?;
            let server = launch(
                accounting,
                scheduler,
                &mut dispatcher,
                port,
                true,
                ProbeRequest {
                    bytes,
                    opcode: if queued { 2 } else { 1 },
                    argument: 0,
                },
            )
            .inspect_err(|()| {
                let _ = troe_machine::write(b"ipc-probe failure=server-launch\n");
            })?;
            let Ok(client) = launch(
                accounting,
                scheduler,
                &mut dispatcher,
                port,
                false,
                ProbeRequest {
                    bytes,
                    opcode: if queued { 2 } else { 1 },
                    argument: 0,
                },
            ) else {
                terminate_revoke_and_reap_task(
                    scheduler,
                    server.task,
                    &mut dispatcher,
                    Some(server.owner),
                )?;
                drop(server.session);
                reclaim_application(accounting, server.allocation)?;
                return Err(());
            };
            if stale_tags
                .is_some_and(|tags| tags.into_iter().any(troe_machine::TagIdentity::is_live))
            {
                return Err(());
            }
            let identities = [
                client.session.tag_identity().ok_or(())?,
                server.session.tag_identity().ok_or(())?,
            ];
            if identities.iter().any(|tag| !tag.is_live()) {
                return Err(());
            }
            let mut badges = BadgeTable::new(1).map_err(|_| ())?;
            let badge = badges.open(0, client.owner).map_err(|_| ())?;
            let mut pair = IpcPair::new(
                client.session,
                server.session,
                client.startup,
                server.startup,
                u32::try_from(badge.event_value()).map_err(|_| ())?,
            )
            .map_err(|error| {
                let _ = troe_machine::write(
                    alloc::format!("ipc-probe failure=pair error={error:?}\n").as_bytes(),
                );
            })?;
            let (next, stop) = pair.run().map_err(|_| ())?;
            pair = next;
            if stop != IpcStop::Yielded
                || !pair.quiescent()
                || pair.samples().len() != IPC_BASELINE_WARMUP_CALLS
            {
                return Err(());
            }
            let before = pair.stats();
            let tags = troe_machine::tag_stats();
            let allocation_calls = troe_machine::heap_stats().allocation_calls;
            let execution = troe_machine::application_execution_stats();
            let tasks = scheduler.stats();
            let (next, stop) = pair.run().map_err(|_| ())?;
            pair = next;
            if stop != IpcStop::Yielded || !pair.quiescent() {
                let _ = troe_machine::write(
                    alloc::format!(
                        "ipc-probe failure=run stop={stop:?} stats={:?}\n",
                        pair.stats()
                    )
                    .as_bytes(),
                );
                return Err(());
            }
            let mut samples: [u64; IPC_BASELINE_SAMPLES] =
                pair.samples().try_into().map_err(|_| ())?;
            let after = pair.stats();
            let final_tags = troe_machine::tag_stats();
            let calls = IPC_BASELINE_SAMPLES as u64;
            let request_copies = after.request_copies - before.request_copies;
            let reply_copies = after.reply_copies - before.reply_copies;
            let roots = final_tags.root_writes - tags.root_writes;
            let full = final_tags.full_invalidations - tags.full_invalidations;
            let targeted = final_tags.targeted_invalidations - tags.targeted_invalidations;
            let additional_lease_programs =
                after.additional_lease_programs - before.additional_lease_programs;
            let traps = after.traps - before.traps;
            let hits = final_tags.hits - tags.hits;
            let queue_zeroes = after.queue_zeroes - before.queue_zeroes;
            if after.completed - before.completed != calls
                || after.direct - before.direct != if queued { 0 } else { calls }
                || after.queued - before.queued != if queued { calls } else { 0 }
                || request_copies
                    != if bytes == 0 {
                        0
                    } else {
                        calls * if queued { 2 } else { 1 }
                    }
                || reply_copies != if bytes == 0 { 0 } else { calls }
                || roots != calls * 2
                || targeted != 0
                || additional_lease_programs != 0
                || traps != calls * if queued { 3 } else { 2 } + 1
                || hits != if tags.supported { roots } else { 0 }
                || troe_machine::application_execution_stats().timer_programs
                    - execution.timer_programs
                    != 1
                || scheduler.stats() != tasks
                || full != if tags.supported { 0 } else { roots }
                || queue_zeroes != if queued { calls } else { 0 }
                || troe_machine::heap_stats().allocation_calls != allocation_calls
            {
                return Err(());
            }
            let path = if queued {
                "persistent-queued"
            } else {
                "persistent-direct"
            };
            emit_ipc_samples(
                path,
                bytes,
                troe_machine::benchmark_counter_frequency_hz().ok_or(())?,
                &samples,
            )?;
            samples.sort_unstable();
            let p95 = ipc_percentile(&samples, 95);
            let ratio_limit = if bytes == 4096 { 70 } else { 60 };
            let ratio_pass =
                p95.saturating_mul(100) <= compatibility_p95[index].saturating_mul(ratio_limit);
            let line = alloc::format!(
                "ipc-phase-b path={path} payload={bytes} warmup=64 samples=256 p95_ticks={p95} compatibility_p95={} ratio_limit={ratio_limit} ratio_pass={} tagged={} calls={calls} request_copies={request_copies} reply_copies={reply_copies} root_writes={roots} targeted_invalidations={targeted} full_invalidations={full} queue_slots={queue_zeroes} traps={traps} tag_hits={hits} steady_allocations=0 scheduler_scans=0 additional_lease_programs={additional_lease_programs}\n",
                compatibility_p95[index],
                u8::from(ratio_pass),
                u8::from(tags.supported)
            );
            if !troe_machine::write(line.as_bytes()) {
                return Err(());
            }
            let client_range = client.allocation.ipc.as_ref().ok_or(())?.range();
            let server_range = server.allocation.ipc.as_ref().ok_or(())?.range();
            terminate_revoke_and_reap_task(
                scheduler,
                client.task,
                &mut dispatcher,
                Some(client.owner),
            )?;
            terminate_revoke_and_reap_task(
                scheduler,
                server.task,
                &mut dispatcher,
                Some(server.owner),
            )?;
            drop(pair);
            if identities.iter().any(|tag| tag.is_live()) {
                return Err(());
            }
            stale_tags = Some(identities);
            reclaim_application(accounting, client.allocation)?;
            reclaim_application(accounting, server.allocation)?;
            if !troe_machine::ipc_range_is_zero(client_range)
                || !troe_machine::ipc_range_is_zero(server_range)
            {
                return Err(());
            }
            dispatcher.close(root_handle).map_err(|_| ())?;
            if accounting.frames.free_frames() != free {
                return Err(());
            }
            if tags.supported && !queued && !ratio_pass {
                return Err(());
            }
        }
    }
    verify_faults(scheduler, accounting)
}

/// Native fates are checked before all roots, handles, and pages are reclaimed.
#[allow(clippy::too_many_lines)]
fn verify_faults(scheduler: &mut Scheduler, accounting: &mut OwnedAccounting) -> Result<(), ()> {
    use troe_machine::IsolatedFault;
    for opcode in [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 16, 17] {
        let free = accounting.frames.free_frames();
        let mut dispatcher = Dispatcher::new(1, 16).map_err(|_| ())?;
        let (port, root_handle) = dispatcher
            .register(Box::new(EchoService), Rights::CALL)
            .map_err(|_| ())?;
        let server = launch(
            accounting,
            scheduler,
            &mut dispatcher,
            port,
            true,
            ProbeRequest {
                bytes: 8,
                opcode,
                argument: 0,
            },
        )?;
        let alias = server.allocation.ipc.as_ref().ok_or(())?.range().start();
        let client = launch(
            accounting,
            scheduler,
            &mut dispatcher,
            port,
            false,
            ProbeRequest {
                bytes: 8,
                opcode,
                argument: alias,
            },
        )?;
        let client_range = client.allocation.ipc.as_ref().ok_or(())?.range();
        let mut badges = BadgeTable::new(1).map_err(|_| ())?;
        let badge = badges.open(0, client.owner).map_err(|_| ())?;
        let pair = IpcPair::new(
            client.session,
            server.session,
            client.startup,
            server.startup,
            u32::try_from(badge.event_value()).map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let before = troe_machine::application_execution_stats();
        let started = troe_machine::monotonic_millis().ok_or(())?;
        let (mut pair, stop) = pair.run().map_err(|_| ())?;
        let elapsed = troe_machine::monotonic_millis()
            .ok_or(())?
            .saturating_sub(started);
        let valid = match opcode {
            3 => {
                stop == IpcStop::Faulted {
                    peer: 1,
                    fault: IsolatedFault::ExecutionLeaseExpired,
                }
            }
            4 | 17 => stop == IpcStop::Exited { peer: 1, status: 0 },
            5 | 6 | 13 => {
                stop == IpcStop::Faulted {
                    peer: 1,
                    fault: IsolatedFault::InvalidCall,
                }
            }
            7 | 8 => matches!(
                stop,
                IpcStop::Faulted {
                    peer: 1,
                    fault: IsolatedFault::Permission
                }
            ),
            9 | 11 => {
                stop == IpcStop::Faulted {
                    peer: 0,
                    fault: IsolatedFault::InvalidCall,
                }
            }
            10 => {
                stop == IpcStop::Exited { peer: 0, status: 0 }
                    && pair.stats().direct == 0
                    && pair.stats().timeouts == 1
            }
            16 => {
                matches!(
                    stop,
                    IpcStop::Faulted {
                        fault: IsolatedFault::ExecutionLeaseExpired,
                        ..
                    }
                ) && pair.stats().completed > 1
            }
            _ => false,
        };
        if !valid
            || (opcode == 17 && (pair.stats().queued != 1 || pair.stats().queue_zeroes != 1))
            || !pair.quiescent()
            || troe_machine::application_execution_stats().timer_programs - before.timer_programs
                != 1
            || (matches!(opcode, 3 | 16) && !(49..=250).contains(&elapsed))
        {
            let _ = troe_machine::write(alloc::format!("ipc-probe failure=fate opcode={opcode} stop={stop:?} elapsed={elapsed} stats={:?}\n", pair.stats()).as_bytes());
            return Err(());
        }
        if matches!(
            stop,
            IpcStop::Faulted { peer: 1, .. } | IpcStop::Exited { peer: 1, .. }
        ) {
            if pair.stats().peer_deaths != 1
                || !troe_machine::ipc_range_is_zero(
                    server.allocation.ipc.as_ref().ok_or(())?.range(),
                )
            {
                return Err(());
            }
            let (next, completion) = pair.run().map_err(|_| ())?;
            pair = next;
            if completion != (IpcStop::Exited { peer: 0, status: 0 }) {
                return Err(());
            }
        }
        terminate_revoke_and_reap_task(
            scheduler,
            client.task,
            &mut dispatcher,
            Some(client.owner),
        )?;
        terminate_revoke_and_reap_task(
            scheduler,
            server.task,
            &mut dispatcher,
            Some(server.owner),
        )?;
        let server_range = server.allocation.ipc.as_ref().ok_or(())?.range();
        drop(pair);
        reclaim_application(accounting, client.allocation)?;
        reclaim_application(accounting, server.allocation)?;
        dispatcher.close(root_handle).map_err(|_| ())?;
        if accounting.frames.free_frames() != free
            || !troe_machine::ipc_range_is_zero(client_range)
            || !troe_machine::ipc_range_is_zero(server_range)
        {
            return Err(());
        }
    }
    if !troe_machine::write(b"ipc-phase-b-checks pool=20 fates=12 terminal_zeroization=1 stale_tags=1 lease_millis=50\n") { return Err(()); }
    Ok(())
}

//! Two native roots compete for process turns with unequal sibling counts.

use super::{
    IsolatedAllocation, METADATA_LIMIT, USER_DATA_BASE, allocate_isolated, allocate_pairs, prepare,
    reclaim_isolated,
};
use crate::machine::OwnedAccounting;
use troe_machine::{
    NativeProcessBacking, NativeProcessContext, NativeThreadStart, NativeThreadStop,
};
use troe_task::{
    Capabilities, ProcessId, ProcessName, ProcessOrigin, ProcessRegistration, ProcessTable,
    Scheduler, StackResource,
    thread::{ThreadId, ThreadQuota, ThreadResources, ThreadTable},
};

mod program;

struct Peer {
    native: NativeProcessContext,
    starts: [NativeThreadStart; 2],
    ids: [Option<ThreadId>; 2],
    owner: ProcessId,
}
struct Reclaim {
    threads: ThreadTable,
    owners: [ProcessId; 2],
    ids: [[Option<ThreadId>; 2]; 2],
}

pub(super) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    let free = accounting.frames.free_frames();
    let first = allocate_isolated(&mut accounting.frames)?;
    let Ok(second) = allocate_isolated(&mut accounting.frames) else {
        reclaim_isolated(&mut accounting.frames, first)?;
        return Err(());
    };
    let allocations = [first, second];
    let mut stage = "root and policy construction";
    let result = run(accounting, &allocations, &mut stage);
    if result.is_err() {
        let _ = troe_machine::write(
            alloc::format!("native process dispatch failed: {stage}\n").as_bytes(),
        );
    }
    // Both native roots and every pair owner have dropped before these frames.
    for allocation in allocations {
        reclaim_isolated(&mut accounting.frames, allocation)?;
    }
    let Reclaim {
        mut threads,
        owners,
        ids,
    } = result?;
    for (owner, ids) in owners.into_iter().zip(ids) {
        for id in ids.into_iter().flatten() {
            threads.release_resources(owner, id).map_err(|_| ())?;
            threads.reap(owner, id).map_err(|_| ())?;
        }
        threads.remove_process(owner).map_err(|_| ())?;
    }
    if threads.committed_pages() != 0 || accounting.frames.free_frames() != free {
        return Err(());
    }
    Ok(())
}

fn peer(
    index: usize,
    accounting: &OwnedAccounting,
    allocation: &IsolatedAllocation,
    scheduler: &mut Scheduler,
    processes: &mut ProcessTable,
    threads: &mut ThreadTable,
) -> Result<Peer, ()> {
    let pairs = allocate_pairs()?;
    let (plan, starts) = prepare(allocation, &accounting.kernel_plan, &pairs, program::CODE)?;
    let root = troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
    let task_id = scheduler
        .spawn(
            Capabilities::SERVICE,
            StackResource::new(u32::try_from(index).map_err(|_| ())?, 1).map_err(|_| ())?,
        )
        .map_err(|_| ())?;
    let owner = processes
        .register(ProcessRegistration {
            task_id,
            name: ProcessName::new("process-dispatch-probe").map_err(|_| ())?,
            origin: ProcessOrigin::Foreground,
            started_millis: 0,
            table_pages: root.stats().table_pages,
            private_pages: 10,
            handles: 0,
        })
        .map_err(|_| ())?;
    let count = if index == 0 { 2 } else { 1 };
    threads
        .register_process(
            owner,
            ThreadQuota {
                records: count,
                pages: count as u64 * 4,
            },
        )
        .map_err(|_| ())?;
    let initial = threads
        .prepare_initial(
            owner,
            ThreadResources {
                reservation: index as u64 * 2 + 1,
                pages: 4,
            },
        )
        .map_err(|_| ())?;
    let mut native = NativeProcessContext::with_backing(
        owner,
        NativeProcessBacking::new(root, pairs),
        2,
        METADATA_LIMIT,
    )
    .map_err(|_| ())?;
    native.prepare(initial, starts[0]).map_err(|_| ())?;
    native
        .bind_thread_ipc(initial, 0, super::TX[0])
        .map_err(|_| ())?;
    threads.start(owner, initial).map_err(|_| ())?;
    let mut ids = [Some(initial), None];
    if index == 0 {
        threads.dispatch(owner, initial).map_err(|_| ())?;
        let worker = threads
            .prepare_worker(
                owner,
                initial,
                ThreadResources {
                    reservation: 2,
                    pages: 4,
                },
            )
            .map_err(|_| ())?;
        native.prepare(worker, starts[1]).map_err(|_| ())?;
        native
            .bind_thread_ipc(worker, 1, super::TX[1])
            .map_err(|_| ())?;
        threads
            .start_worker(owner, initial, worker)
            .map_err(|_| ())?;
        threads.yield_running(owner, initial).map_err(|_| ())?;
        ids[1] = Some(worker);
    }
    Ok(Peer {
        native,
        starts,
        ids,
        owner,
    })
}

#[allow(clippy::too_many_lines)] // Keep both unique root lifetimes through stop and reclamation.
fn run(
    accounting: &OwnedAccounting,
    allocations: &[IsolatedAllocation; 2],
    stage: &mut &'static str,
) -> Result<Reclaim, ()> {
    let mut scheduler = Scheduler::new(2).map_err(|_| ())?;
    let mut processes = ProcessTable::new(2).map_err(|_| ())?;
    let mut threads = ThreadTable::new(2, 3, 12, METADATA_LIMIT).map_err(|_| ())?;
    let mut peers = [
        peer(
            0,
            accounting,
            &allocations[0],
            &mut scheduler,
            &mut processes,
            &mut threads,
        )?,
        peer(
            1,
            accounting,
            &allocations[1],
            &mut scheduler,
            &mut processes,
            &mut threads,
        )?,
    ];
    let owners = [peers[0].owner, peers[1].owner];
    let ids = [peers[0].ids, peers[1].ids];
    let stats = [peers[0].native.stats(), peers[1].native.stats()];
    let metadata = [
        peers[0].native.metadata_bytes(),
        peers[1].native.metadata_bytes(),
    ];
    let frequency = troe_machine::process_accounting_frequency_hz().ok_or(())?;
    *stage = "timer preparation expiry restores root and continuation";
    let first = ids[0][0].ok_or(())?;
    threads.dispatch(owners[0], first).map_err(|_| ())?;
    let before = troe_machine::application_execution_stats();
    if peers[0]
        .native
        .probe_dispatch_preparation_expiry(&threads, first)
        .map_err(|_| ())?
        != NativeThreadStop::DispatchExpired
        || peers[0].native.stats() != stats[0]
        || peers[0].native.metadata_bytes() != metadata[0]
        || troe_machine::application_execution_stats().address_space_switches
            != before.address_space_switches
        || peers[0]
            .native
            .probe_word(peers[0].starts[0].thread_pointer + 16)
            .map_err(|_| ())?
            != 0
    {
        return Err(());
    }
    threads.yield_running(owners[0], first).map_err(|_| ())?;
    *stage = "expired preparation permits no first entry";
    // A deliberately old observation models work delayed beyond its process turn.
    let mut expired = threads
        .begin_dispatch(0, frequency, 1, 2)
        .map_err(|_| ())?
        .ok_or(())?;
    let initial = threads
        .dispatch_sibling(&mut expired, 0)
        .map_err(|_| ())?
        .ok_or(())?;
    if troe_machine::process_accounting_ticks() < expired.deadline_ticks() {
        return Err(());
    }
    let before = troe_machine::application_execution_stats();
    if peers[0]
        .native
        .resume_dispatch(&mut threads, &mut expired, initial)
        .map_err(|_| ())?
        != NativeThreadStop::DispatchExpired
        || peers[0].native.is_stopped()
        || troe_machine::application_execution_stats() != before
        || peers[0]
            .native
            .probe_word(peers[0].starts[0].thread_pointer + 16)
            .map_err(|_| ())?
            != 0
    {
        return Err(());
    }
    threads.yield_running(owners[0], initial).map_err(|_| ())?;
    threads
        .finish_dispatch(expired, troe_machine::process_accounting_ticks())
        .map_err(|_| ())?;

    *stage = "process rotation and bounded repeated yields";
    let mut yields = [[0_u64; 2]; 2];
    for turn in 0..8 {
        // The expired turn already advanced the cursor, so the one-thread peer goes first.
        let index = 1 - turn % 2;
        let mut dispatch = threads
            .begin_dispatch(troe_machine::process_accounting_ticks(), frequency, 20, 2)
            .map_err(|_| ())?
            .ok_or(())?;
        if dispatch.process() != owners[index] {
            return Err(());
        }
        let deadline = dispatch.deadline_ticks();
        for _ in 0..2 {
            let Some(id) = threads
                .dispatch_sibling(&mut dispatch, troe_machine::process_accounting_ticks())
                .map_err(|_| ())?
            else {
                break;
            };
            let sibling = peers[index]
                .ids
                .iter()
                .position(|candidate| *candidate == Some(id))
                .ok_or(())?;
            let other_before = peers[1 - index]
                .native
                .probe_word(USER_DATA_BASE + 16)
                .map_err(|_| ())?;
            match peers[index]
                .native
                .resume_dispatch(&mut threads, &mut dispatch, id)
                .map_err(|_| ())?
            {
                NativeThreadStop::Yielded => {
                    yields[index][sibling] += 1;
                    if peers[index]
                        .native
                        .probe_word(peers[index].starts[sibling].thread_pointer + 16)
                        .map_err(|_| ())?
                        != yields[index][sibling]
                    {
                        return Err(());
                    }
                }
                NativeThreadStop::Preempted | NativeThreadStop::DispatchExpired => {}
                _ => return Err(()),
            }
            threads.yield_running(owners[index], id).map_err(|_| ())?;
            if dispatch.deadline_ticks() != deadline
                || peers[1 - index]
                    .native
                    .probe_word(USER_DATA_BASE + 16)
                    .map_err(|_| ())?
                    != other_before
            {
                return Err(());
            }
        }
        if dispatch.steps_left() == 0 {
            let id = peers[index].ids[0].ok_or(())?;
            threads.dispatch(owners[index], id).map_err(|_| ())?;
            let before = troe_machine::application_execution_stats();
            if peers[index]
                .native
                .resume_dispatch(&mut threads, &mut dispatch, id)
                .map_err(|_| ())?
                != NativeThreadStop::DispatchExpired
                || troe_machine::application_execution_stats() != before
            {
                return Err(());
            }
            threads.yield_running(owners[index], id).map_err(|_| ())?;
        }
        threads
            .finish_dispatch(dispatch, troe_machine::process_accounting_ticks())
            .map_err(|_| ())?;
    }
    if yields[0].contains(&0) || yields[1][0] == 0 {
        return Err(());
    }
    *stage = "busy worker is preempted without process fault";
    // Cursor now selects the one-thread peer. Its shared flag switches the same
    // code to a busy loop; the process deadline still bounds this native entry.
    troe_machine::copy_to_physical(allocations[1].data, 24, &1_u64.to_le_bytes())
        .map_err(|_| ())?;
    let mut dispatch = threads
        .begin_dispatch(troe_machine::process_accounting_ticks(), frequency, 10, 4)
        .map_err(|_| ())?
        .ok_or(())?;
    if dispatch.process() != owners[1] {
        return Err(());
    }
    let id = threads
        .dispatch_sibling(&mut dispatch, troe_machine::process_accounting_ticks())
        .map_err(|_| ())?
        .ok_or(())?;
    if peers[1]
        .native
        .resume_dispatch(&mut threads, &mut dispatch, id)
        .map_err(|_| ())?
        != NativeThreadStop::Preempted
        || peers[1].native.is_stopped()
    {
        return Err(());
    }
    threads.yield_running(owners[1], id).map_err(|_| ())?;
    threads
        .finish_dispatch(dispatch, troe_machine::process_accounting_ticks())
        .map_err(|_| ())?;
    *stage = "stop and root accounting";
    for (index, peer) in peers.iter_mut().enumerate() {
        if peer.native.stats() != stats[index] || peer.native.metadata_bytes() != metadata[index] {
            return Err(());
        }
        peer.native.stop();
        threads.stop_process(peer.owner).map_err(|_| ())?;
    }
    drop(peers);
    Ok(Reclaim {
        threads,
        owners,
        ids,
    })
}

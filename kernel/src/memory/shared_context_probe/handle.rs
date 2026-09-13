//! Retained ordinary calls while another native sibling changes shared memory.

use super::{
    IsolatedAllocation, METADATA_LIMIT, PAGE, TX, allocate_isolated, allocate_pairs, prepare,
    reclaim_isolated, verify_rx_tail,
};
use crate::machine::OwnedAccounting;
use troe_machine::{
    ApplicationResume, NativeHandleCall, NativeHandleExecution, NativeProcessBacking,
    NativeProcessContext, NativeThreadStart, NativeThreadStop,
};
use troe_memory::PhysicalRange;
use troe_task::{
    Capabilities, ProcessId, ProcessName, ProcessOrigin, ProcessRegistration, ProcessTable,
    Scheduler, StackResource,
    thread::{ThreadId, ThreadQuota, ThreadResources, ThreadTable, ThreadWait},
};

mod program;

pub(super) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    for mode in 0..=6 {
        let free = accounting.frames.free_frames();
        let first = allocate_isolated(&mut accounting.frames)?;
        let Ok(second) = allocate_isolated(&mut accounting.frames) else {
            reclaim_isolated(&mut accounting.frames, first)?;
            return Err(());
        };
        let allocations = [first, second];
        let mut stage = "construction";
        let result = run(accounting, &allocations, mode, &mut stage);
        if result.is_err() {
            let _ = troe_machine::write(
                alloc::format!("native handle ownership failed: mode={mode} stage={stage}\n")
                    .as_bytes(),
            );
        }
        // Every native root drops before any of its ordinary backing is freed.
        for allocation in allocations {
            reclaim_isolated(&mut accounting.frames, allocation)?;
        }
        let (mut threads, owner, ids) = result?;
        for id in ids {
            threads.release_resources(owner, id).map_err(|_| ())?;
            threads.reap(owner, id).map_err(|_| ())?;
        }
        threads.remove_process(owner).map_err(|_| ())?;
        if threads.committed_pages() != 0 || accounting.frames.free_frames() != free {
            return Err(());
        }
    }
    Ok(())
}

fn root(
    index: u32,
    accounting: &OwnedAccounting,
    allocation: &IsolatedAllocation,
    scheduler: &mut Scheduler,
    processes: &mut ProcessTable,
) -> Result<(NativeProcessContext, ProcessId, [NativeThreadStart; 2]), ()> {
    let pairs = allocate_pairs()?;
    let (plan, starts) = prepare(allocation, &accounting.kernel_plan, &pairs, program::CODE)?;
    let root = troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
    let task_id = scheduler
        .spawn(
            Capabilities::SERVICE,
            StackResource::new(index, 1).map_err(|_| ())?,
        )
        .map_err(|_| ())?;
    let owner = processes
        .register(ProcessRegistration {
            task_id,
            name: ProcessName::new("native-handle-probe").map_err(|_| ())?,
            origin: ProcessOrigin::Foreground,
            started_millis: 0,
            table_pages: root.stats().table_pages,
            private_pages: 10,
            handles: 0,
        })
        .map_err(|_| ())?;
    Ok((
        NativeProcessContext::with_backing(
            owner,
            NativeProcessBacking::new(root, pairs),
            2,
            METADATA_LIMIT,
        )
        .map_err(|_| ())?,
        owner,
        starts,
    ))
}

fn policy(owner: ProcessId) -> Result<(ThreadTable, [ThreadId; 2]), ()> {
    let mut threads = ThreadTable::new(1, 2, 8, METADATA_LIMIT).map_err(|_| ())?;
    threads
        .register_process(
            owner,
            ThreadQuota {
                records: 2,
                pages: 8,
            },
        )
        .map_err(|_| ())?;
    let first = threads
        .prepare_initial(
            owner,
            ThreadResources {
                reservation: 1,
                pages: 4,
            },
        )
        .map_err(|_| ())?;
    threads.start(owner, first).map_err(|_| ())?;
    threads.dispatch(owner, first).map_err(|_| ())?;
    let second = threads
        .prepare_worker(
            owner,
            first,
            ThreadResources {
                reservation: 2,
                pages: 4,
            },
        )
        .map_err(|_| ())?;
    threads.start_worker(owner, first, second).map_err(|_| ())?;
    threads.yield_running(owner, first).map_err(|_| ())?;
    Ok((threads, [first, second]))
}

fn mode_word(allocation: &IsolatedAllocation, sibling: u64, mode: u64) -> Result<(), ()> {
    let tls = PhysicalRange::from_pages(allocation.stack.start() + (sibling + 2) * PAGE, 1)
        .map_err(|_| ())?;
    troe_machine::copy_to_physical(tls, 48, &mode.to_le_bytes()).map_err(|_| ())
}

/// Keep normal preemption resumable while imposing a finite acceptance work bound.
fn enter(
    native: &mut NativeProcessContext,
    threads: &mut ThreadTable,
    id: ThreadId,
) -> Result<(NativeThreadStop, Option<ThreadWait>), ()> {
    let owner = id.process();
    let frequency = troe_machine::process_accounting_frequency_hz().ok_or(())?;
    for _ in 0..16 {
        let mut dispatch = threads
            .begin_dispatch(troe_machine::process_accounting_ticks(), frequency, 20, 2)
            .map_err(|_| ())?
            .ok_or(())?;
        if dispatch.process() != owner {
            return Err(());
        }
        threads.dispatch(owner, id).map_err(|_| ())?;
        let Ok(stop) = native.resume_dispatch(threads, &mut dispatch, id) else {
            threads.stop_process(owner).map_err(|_| ())?;
            return Err(());
        };
        if matches!(
            stop,
            NativeThreadStop::ProcessFaulted(_) | NativeThreadStop::ProcessExited(_)
        ) {
            threads.stop_process(owner).map_err(|_| ())?;
            return Ok((stop, None));
        }
        let wait = if matches!(stop, NativeThreadStop::HandleCall(_)) {
            Some(threads.block(owner, id).map_err(|_| ())?)
        } else {
            threads.yield_running(owner, id).map_err(|_| ())?;
            None
        };
        threads
            .finish_dispatch(dispatch, troe_machine::process_accounting_ticks())
            .map_err(|_| ())?;
        if !matches!(
            stop,
            NativeThreadStop::Preempted | NativeThreadStop::DispatchExpired
        ) {
            return Ok((stop, wait));
        }
    }
    Err(())
}

fn capture(
    native: &mut NativeProcessContext,
    threads: &mut ThreadTable,
    id: ThreadId,
    round: u64,
    marker: u64,
    mode: u64,
) -> Result<(NativeHandleCall, NativeHandleExecution, ThreadWait), ()> {
    let (NativeThreadStop::HandleCall(call), Some(wait)) = enter(native, threads, id)? else {
        return Err(());
    };
    let mut expected = [0_u8; 24];
    expected[..8].copy_from_slice(&5_u64.to_le_bytes());
    expected[8..16].copy_from_slice(&marker.to_le_bytes());
    expected[16..].copy_from_slice(&round.to_le_bytes());
    if call.caller() != id
        || call.handle() != 0x0012_3456
        || call.request_bytes() != if mode == 4 { 4096 } else { 24 }
        || call.reply_capacity()
            != if mode == 4 {
                4096
            } else if mode == 5 {
                0
            } else {
                8
            }
        || native.handle_request(call).map_err(|_| ())?[..24] != expected
    {
        return Err(());
    }
    if mode == 4 {
        for (index, bytes) in native
            .handle_request(call)
            .map_err(|_| ())?
            .chunks_exact(8)
            .enumerate()
            .skip(3)
        {
            if bytes != (marker + round + index as u64).to_le_bytes() {
                return Err(());
            }
        }
    }
    // This fixture checks native ownership, not service-capability admission.
    let execution = native.claim_handle(call).map_err(|_| ())?;
    let before = troe_machine::application_execution_stats();
    if native.claim_handle(call).is_ok()
        || native
            .complete_handle(call, 0, &marker.to_le_bytes())
            .is_ok()
        || native
            .resume(
                id,
                ApplicationResume::HandleReply {
                    status: 0,
                    reply: &[],
                },
                20,
            )
            .is_ok()
        || native.is_stopped()
        || troe_machine::application_execution_stats() != before
    {
        return Err(());
    }
    Ok((call, execution, wait))
}

#[allow(clippy::too_many_lines)] // Keep root and call owners through complete stop/reclamation.
fn run(
    accounting: &OwnedAccounting,
    allocations: &[IsolatedAllocation; 2],
    mode: u64,
    stage: &mut &'static str,
) -> Result<(ThreadTable, ProcessId, [ThreadId; 2]), ()> {
    let mut scheduler = Scheduler::new(2).map_err(|_| ())?;
    let mut processes = ProcessTable::new(2).map_err(|_| ())?;
    let (mut native, owner, starts) = root(
        0,
        accounting,
        &allocations[0],
        &mut scheduler,
        &mut processes,
    )?;
    let (mut foreign, _, _) = root(
        1,
        accounting,
        &allocations[1],
        &mut scheduler,
        &mut processes,
    )?;
    let (mut threads, ids) = policy(owner)?;
    for (index, id) in ids.into_iter().enumerate() {
        native.prepare(id, starts[index]).map_err(|_| ())?;
        native
            .bind_thread_ipc(id, index, TX[index])
            .map_err(|_| ())?;
    }
    let baseline = native.stats();
    let metadata = native.metadata_bytes();
    if matches!(mode, 2 | 3) {
        *stage = "reject a valid user address outside the retained IPC prefix";
        mode_word(&allocations[0], 0, mode)?;
        if enter(&mut native, &mut threads, ids[0]).is_ok() || !native.is_stopped() {
            return Err(());
        }
    } else if mode == 6 {
        *stage = "unclaimed rejection publishes no payload or execution";
        mode_word(&allocations[0], 0, mode)?;
        let (NativeThreadStop::HandleCall(call), Some(wait)) =
            enter(&mut native, &mut threads, ids[0])?
        else {
            return Err(());
        };
        let before = troe_machine::application_execution_stats();
        native
            .complete_handle(call, troe_abi::reply::DENIED, &[])
            .map_err(|_| ())?;
        if native.claim_handle(call).is_ok()
            || troe_machine::application_execution_stats() != before
        {
            return Err(());
        }
        verify_rx_tail(&native, TX[0], 0)?;
        threads.wake(owner, wait).map_err(|_| ())?;
        if enter(&mut native, &mut threads, ids[0])?.0 != NativeThreadStop::Yielded {
            return Err(());
        }
    } else {
        if mode >= 4 {
            mode_word(&allocations[0], 0, mode)?;
            mode_word(&allocations[0], 1, mode)?;
        }
        let mut old = None;
        for round in 0..2 {
            *stage = "capture first caller";
            let (first, execution, first_wait) =
                capture(&mut native, &mut threads, ids[0], round, 11, mode)?;
            if let Some(old) = old
                && (native.claim_handle(old).is_ok() || native.complete_handle(old, 0, &[]).is_ok())
            {
                return Err(());
            }
            if mode == 1 && round == 1 {
                *stage = "fault with a sibling call retained";
                mode_word(&allocations[0], 1, 1)?;
                if !matches!(
                    enter(&mut native, &mut threads, ids[1])?.0,
                    NativeThreadStop::ProcessFaulted(_)
                ) || !native.is_stopped()
                {
                    return Err(());
                }
                let before = native.probe_word(TX[0] + PAGE).map_err(|_| ())?;
                let (_, execution) = native
                    .complete_handle_execution(execution, 0, &99_u64.to_le_bytes())
                    .err()
                    .ok_or(())?;
                if native.probe_word(TX[0] + PAGE).map_err(|_| ())? != before
                    || native.handle_request(first).is_ok()
                    || threads.wake(owner, first_wait).is_ok()
                {
                    return Err(());
                }
                drop(execution);
                break;
            }
            *stage = "sibling modifies TX while both calls are retained";
            let (second, second_execution, second_wait) =
                capture(&mut native, &mut threads, ids[1], round, 22, mode)?;
            if native.probe_word(TX[0] + 8).map_err(|_| ())? != 0x00ba_dbad {
                return Err(());
            }
            let mut copy = [0; 4096];
            let copy = &mut copy[..first.request_bytes()];
            native.copy_request(ids[0], copy).map_err(|_| ())?;
            if copy[8..16] != 11_u64.to_le_bytes()
                || native.handle_request(first).map_err(|_| ())? != copy
                || (mode == 4 && copy[4088..4096] != (11 + round + 511).to_le_bytes())
            {
                return Err(());
            }
            *stage = "recover foreign and malformed completions without publication";
            let before = troe_machine::application_execution_stats();
            let first_rx = native.probe_word(TX[0] + PAGE).map_err(|_| ())?;
            let foreign_rx = foreign.probe_word(TX[0] + PAGE).map_err(|_| ())?;
            let (_, execution) = foreign
                .complete_handle_execution(execution, 0, &11_u64.to_le_bytes())
                .err()
                .ok_or(())?;
            let (_, execution) = native
                .complete_handle_execution(execution, u32::MAX, &[])
                .err()
                .ok_or(())?;
            let (_, execution) = native
                .complete_handle_execution(execution, 0, &[0; 4097][..=first.reply_capacity()])
                .err()
                .ok_or(())?;
            if native.probe_word(TX[0] + PAGE).map_err(|_| ())? != first_rx
                || foreign.probe_word(TX[0] + PAGE).map_err(|_| ())? != foreign_rx
                || foreign.is_stopped()
                || native.is_stopped()
            {
                return Err(());
            }
            *stage = "reverse completion and independent native reply validation";
            let second_reply = (22 + round).to_le_bytes();
            let first_reply = (11 + round).to_le_bytes();
            native
                .complete_handle_execution(
                    second_execution,
                    0,
                    if mode == 5 { &[] } else { &second_reply },
                )
                .map_err(|_| ())?;
            native
                .complete_handle_execution(execution, 0, if mode == 5 { &[] } else { &first_reply })
                .map_err(|_| ())?;
            if troe_machine::application_execution_stats() != before
                || native.complete_handle(first, 0, &[]).is_ok()
                || native.complete_handle(second, 0, &[]).is_ok()
            {
                return Err(());
            }
            for (index, wait) in [first_wait, second_wait].into_iter().enumerate() {
                verify_rx_tail(&native, TX[index], if mode == 5 { 0 } else { 8 })?;
                threads.wake(owner, wait).map_err(|_| ())?;
                if enter(&mut native, &mut threads, ids[index])?.0 != NativeThreadStop::Yielded
                    || native
                        .probe_word(starts[index].thread_pointer + 16)
                        .map_err(|_| ())?
                        != round + 1
                {
                    return Err(());
                }
            }
            old = Some(first);
        }
    }
    *stage = "final stop and retained accounting";
    if native.stats() != baseline || native.metadata_bytes() != metadata {
        return Err(());
    }
    native.stop();
    foreign.stop();
    threads.stop_process(owner).map_err(|_| ())?;
    Ok((threads, owner, ids))
}

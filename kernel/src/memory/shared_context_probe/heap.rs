//! Native heap claims, sibling execution and partial mapping failure.

use super::{PAGE, TX, allocate_isolated, handle, reclaim_isolated};
use crate::machine::OwnedAccounting;
use crate::memory::IsolatedAllocation;
use troe_machine::{
    ApplicationResume, NativeHeapCall, NativeHeapExecution, NativeProcessContext, NativeThreadStop,
};
use troe_memory::{PhysicalRange, VirtualRange};
use troe_task::{
    ProcessTable, Scheduler,
    thread::{ThreadId, ThreadTable, ThreadWait},
};

// The third heap page crosses a page-table boundary. With an exact initial
// table arena, its first growth leaf succeeds and its second must fail.
const HEAP: u64 = crate::limits::USER_CODE_BASE + 0x1000_0000 - 2 * PAGE;

pub(super) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    for mode in 0..3 {
        let free = accounting.frames.free_frames();
        let allocation = allocate_isolated(&mut accounting.frames)?;
        let Ok(backing) = accounting.frames.allocate_contiguous(3, 1) else {
            reclaim_isolated(&mut accounting.frames, allocation)?;
            return Err(());
        };
        let result = run(accounting, &allocation, backing, mode);
        // run has dropped every native root before either range can be reused.
        troe_machine::zero_physical_range(backing).map_err(|_| ())?;
        accounting.frames.free_range(backing).map_err(|_| ())?;
        reclaim_isolated(&mut accounting.frames, allocation)?;
        result?;
        if accounting.frames.free_frames() != free {
            return Err(());
        }
    }
    Ok(())
}

fn capture(
    native: &mut NativeProcessContext,
    threads: &mut ThreadTable,
    id: ThreadId,
) -> Result<(NativeHeapCall, NativeHeapExecution, ThreadWait), ()> {
    let (NativeThreadStop::HeapGrow(call), Some(wait)) = handle::enter(native, threads, id)? else {
        return Err(());
    };
    if call.caller() != id || call.minimum_pages() != 1 {
        return Err(());
    }
    let execution = native.claim_heap(call).map_err(|_| ())?;
    let before = troe_machine::application_execution_stats();
    if native.claim_heap(call).is_ok()
        || native
            .resume(
                id,
                ApplicationResume::HeapGrowth {
                    status: 0,
                    mapped_bytes: PAGE,
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

#[allow(clippy::too_many_lines)]
fn run(
    accounting: &OwnedAccounting,
    allocation: &IsolatedAllocation,
    backing: PhysicalRange,
    mode: u64,
) -> Result<(), ()> {
    troe_machine::zero_physical_range(backing).map_err(|_| ())?;
    let heap = VirtualRange::from_pages(HEAP, 3).map_err(|_| ())?;
    let mut scheduler = Scheduler::new(1).map_err(|_| ())?;
    let mut processes = ProcessTable::new(1).map_err(|_| ())?;
    let (mut native, owner, starts) = handle::root(
        0,
        accounting,
        allocation,
        &mut scheduler,
        &mut processes,
        Some((heap, backing, mode == 2)),
    )?;
    let (mut threads, ids) = handle::policy(owner)?;
    native.bind_heap(heap).map_err(|_| ())?;
    if native.bind_heap(heap).is_ok() {
        return Err(());
    }
    for (index, id) in ids.into_iter().enumerate() {
        native.prepare(id, starts[index]).map_err(|_| ())?;
        native
            .bind_thread_ipc(id, index, TX[index])
            .map_err(|_| ())?;
        handle::mode_word(allocation, index as u64, if mode == 1 { 8 } else { 7 })?;
        let tls =
            PhysicalRange::from_pages(allocation.stack.start() + (index as u64 + 2) * PAGE, 1)
                .map_err(|_| ())?;
        troe_machine::copy_to_physical(tls, 56, &(HEAP + (index as u64 + 1) * PAGE).to_le_bytes())
            .map_err(|_| ())?;
        troe_machine::copy_to_physical(tls, 64, &((index as u64 + 2) * PAGE).to_le_bytes())
            .map_err(|_| ())?;
    }
    let (first, execution, wait) = capture(&mut native, &mut threads, ids[0])?;
    let execution = native
        .complete_heap_execution(execution, troe_abi::heap_growth::SUCCESS)
        .err()
        .ok_or(())?
        .1;
    let before = troe_machine::application_execution_stats();
    let baseline = native.stats();
    if mode == 2 {
        if native
            .commit_heap_execution(
                &execution,
                &[PhysicalRange::from_pages(backing.start() + PAGE, 2).map_err(|_| ())?],
                &[],
            )
            .is_ok()
            || !native.is_stopped()
            || native.probe_leaf(HEAP + PAGE).map_err(|_| ())? != backing.start() + PAGE
            || native.probe_leaf(HEAP + 2 * PAGE).is_ok()
            || native
                .complete_heap_execution(execution, troe_abi::heap_growth::EXHAUSTED)
                .is_ok()
            || troe_machine::application_execution_stats() != before
        {
            return Err(());
        }
    } else {
        let (second, other, other_wait) = capture(&mut native, &mut threads, ids[1])?;
        let mutation_counters = troe_machine::application_execution_stats();
        if mode == 0 {
            let one = PhysicalRange::from_pages(backing.start() + PAGE, 1).map_err(|_| ())?;
            native
                .commit_heap_execution(&execution, &[one], &[])
                .map_err(|_| ())?;
            if native
                .commit_heap_execution(&execution, &[one], &[])
                .is_ok()
            {
                return Err(());
            }
            native
                .commit_heap_execution(
                    &other,
                    &[PhysicalRange::from_pages(backing.start() + 2 * PAGE, 1).map_err(|_| ())?],
                    &[],
                )
                .map_err(|_| ())?;
            let other = native
                .complete_heap_execution(other, troe_abi::heap_growth::EXHAUSTED)
                .err()
                .ok_or(())?
                .1;
            native
                .complete_heap_execution(other, troe_abi::heap_growth::SUCCESS)
                .map_err(|_| ())?;
            native
                .complete_heap_execution(execution, troe_abi::heap_growth::SUCCESS)
                .map_err(|_| ())?;
            if native.stats().mapped_pages != baseline.mapped_pages + 2 {
                return Err(());
            }
        } else {
            native
                .complete_heap_execution(other, troe_abi::heap_growth::EXHAUSTED)
                .map_err(|_| ())?;
            native
                .complete_heap_execution(execution, troe_abi::heap_growth::EXHAUSTED)
                .map_err(|_| ())?;
            if native.stats() != baseline {
                return Err(());
            }
        }
        if native.claim_heap(first).is_ok()
            || native.claim_heap(second).is_ok()
            || troe_machine::application_execution_stats() != mutation_counters
        {
            return Err(());
        }
        threads.wake(owner, other_wait).map_err(|_| ())?;
        threads.wake(owner, wait).map_err(|_| ())?;
        for id in [ids[1], ids[0]] {
            if handle::enter(&mut native, &mut threads, id)? != (NativeThreadStop::Yielded, None) {
                return Err(());
            }
        }
        if mode == 0
            && (native.probe_word(HEAP + PAGE).map_err(|_| ())? != 11
                || native.probe_word(HEAP + 2 * PAGE).map_err(|_| ())? != 22)
        {
            return Err(());
        }
        native.stop();
    }
    threads.stop_process(owner).map_err(|_| ())?;
    drop(native);
    for id in ids {
        threads.release_resources(owner, id).map_err(|_| ())?;
        threads.reap(owner, id).map_err(|_| ())?;
    }
    threads.remove_process(owner).map_err(|_| ())?;
    if threads.committed_pages() != 0 {
        return Err(());
    }
    Ok(())
}

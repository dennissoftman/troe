//! Native shared-root acceptance with guarded stacks, TLS and owned IPC pairs.

use super::IsolatedAllocation;
use super::isolated::{allocate_isolated, build_isolated_plan, reclaim_isolated};
use crate::limits::{USER_CODE_BASE, USER_DATA_BASE, USER_STACK_BASE};
use crate::machine::OwnedAccounting;
use alloc::vec::Vec;
use troe_machine::{
    ApplicationResume, IpcPagePair, NativeProcessBacking, NativeProcessContext, NativeThreadStart,
    NativeThreadStop,
};
use troe_memory::{
    Mapping, MappingLifetime, MappingOwner, MappingPermissions, MappingPlan, PhysicalRange,
    VirtualRange,
};
use troe_task::thread::{ThreadQuota, ThreadResources, ThreadTable};
use troe_task::{
    Capabilities, ProcessName, ProcessOrigin, ProcessRegistration, ProcessTable, Scheduler,
    StackResource,
};

// Both programs spin through actual preemption, then validate their TLS marker,
// exchange distinct IPC markers, increment counters, and yield 16 times. A final
// illegal instruction must revoke both continuations. A mismatch exits with 1,
// a distinct result, so it cannot masquerade as the expected fault.
#[cfg(target_arch = "x86_64")]
const CODE: &[u8] = &[
    0x49, 0x89, 0xfc, 0xbb, 0x00, 0xe1, 0xf5, 0x05, 0xff, 0xcb, 0x75, 0xfc, 0x41, 0xbe, 0x10, 0x00,
    0x00, 0x00, 0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x49, 0x3b, 0x04, 0x24, 0x75,
    0x42, 0x64, 0x4c, 0x8b, 0x3c, 0x25, 0x18, 0x00, 0x00, 0x00, 0x49, 0x89, 0x07, 0x64, 0x48, 0x03,
    0x04, 0x25, 0x10, 0x00, 0x00, 0x00, 0x49, 0x3b, 0x87, 0x00, 0x10, 0x00, 0x00, 0x75, 0x24, 0x64,
    0x4c, 0x8b, 0x2c, 0x25, 0x08, 0x00, 0x00, 0x00, 0x49, 0xff, 0x45, 0x00, 0x64, 0x48, 0xff, 0x04,
    0x25, 0x10, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x41, 0xff, 0xce, 0x75,
    0xb1, 0x0f, 0x0b, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xcd, 0x80, 0x0f, 0x0b,
];
#[cfg(target_arch = "aarch64")]
const CODE: &[u8] = &[
    0xf3, 0x03, 0x00, 0xaa, 0x14, 0x20, 0x9c, 0x52, 0xb4, 0xbe, 0xa0, 0x72, 0x94, 0x06, 0x00, 0x71,
    0xe1, 0xff, 0xff, 0x54, 0x15, 0x02, 0x80, 0x52, 0x56, 0xd0, 0x3b, 0xd5, 0xc0, 0x02, 0x40, 0xf9,
    0x61, 0x02, 0x40, 0xf9, 0x1f, 0x00, 0x01, 0xeb, 0x81, 0x02, 0x00, 0x54, 0xd8, 0x0e, 0x40, 0xf9,
    0x00, 0x03, 0x00, 0xf9, 0xc1, 0x0a, 0x40, 0xf9, 0x00, 0x00, 0x01, 0x8b, 0x01, 0x03, 0x48, 0xf9,
    0x1f, 0x00, 0x01, 0xeb, 0xa1, 0x01, 0x00, 0x54, 0xd7, 0x06, 0x40, 0xf9, 0xe0, 0x02, 0x40, 0xf9,
    0x00, 0x04, 0x00, 0x91, 0xe0, 0x02, 0x00, 0xf9, 0xc0, 0x0a, 0x40, 0xf9, 0x00, 0x04, 0x00, 0x91,
    0xc0, 0x0a, 0x00, 0xf9, 0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xb5, 0x06, 0x00, 0x71,
    0x41, 0xfd, 0xff, 0x54, 0x00, 0x00, 0x20, 0xd4, 0x20, 0x00, 0x80, 0xd2, 0x08, 0x00, 0x80, 0xd2,
    0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x20, 0xd4,
];

const PAGE: u64 = 4096;
const METADATA_LIMIT: usize = 16 * 1024;
const TX: [u64; 2] = [USER_STACK_BASE + 12 * PAGE, USER_STACK_BASE + 15 * PAGE];

#[allow(clippy::too_many_lines)]
pub(crate) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    let free = accounting.frames.free_frames();
    let allocation = allocate_isolated(&mut accounting.frames)?;
    let result = (|| {
        let pairs = allocate_pairs()?;
        let (plan, _) = prepare(&allocation, &accounting.kernel_plan, &pairs)?;
        let root =
            troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
        let mut scheduler = Scheduler::new(2).map_err(|_| ())?;
        let mut processes = ProcessTable::new(2).map_err(|_| ())?;
        let mut register = |slot| {
            let task = scheduler
                .spawn(
                    Capabilities::SERVICE,
                    StackResource::new(slot, 1).map_err(|_| ())?,
                )
                .map_err(|_| ())?;
            processes
                .register(ProcessRegistration {
                    task_id: task,
                    name: ProcessName::new("native-context-probe").map_err(|_| ())?,
                    origin: ProcessOrigin::Foreground,
                    started_millis: 0,
                    table_pages: root.stats().table_pages,
                    private_pages: 10,
                    handles: 0,
                })
                .map_err(|_| ())
        };
        let owner = register(0)?;
        let other = register(1)?;
        let mut threads = ThreadTable::new(2, 3, 10, METADATA_LIMIT).map_err(|_| ())?;
        threads
            .register_process(
                owner,
                ThreadQuota {
                    records: 2,
                    pages: 8,
                },
            )
            .map_err(|_| ())?;
        threads
            .register_process(
                other,
                ThreadQuota {
                    records: 1,
                    pages: 2,
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
        threads.start(owner, second).map_err(|_| ())?;
        threads.yield_running(owner, first).map_err(|_| ())?;
        let foreign = threads
            .prepare_initial(
                other,
                ThreadResources {
                    reservation: 3,
                    pages: 2,
                },
            )
            .map_err(|_| ())?;
        if NativeProcessContext::new(owner, root, 2, 0).is_ok() {
            return Err(());
        }
        // The rejected owner never ran; its caller still owns the same frames.
        let root =
            troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
        let bare = NativeProcessContext::new(owner, root, 2, METADATA_LIMIT).map_err(|_| ())?;
        let bare_metadata = bare.metadata_bytes();
        drop(bare);
        let prior = pair_identities(&pairs);
        let root =
            troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
        // The allowance fits the context/root arrays but not the retained pair
        // vector capacity. Rejection must retire the root before releasing pairs.
        if NativeProcessContext::with_backing(
            owner,
            NativeProcessBacking::new(root, pairs),
            2,
            bare_metadata,
        )
        .is_ok()
            || prior
                .iter()
                .any(|(_, _, range)| !troe_machine::ipc_range_is_zero(*range))
        {
            return Err(());
        }
        let pairs = allocate_pairs()?;
        verify_reused(&pairs, prior)?;
        let pair_capacity = pairs.capacity();
        let identities = pair_identities(&pairs);
        let (plan, starts) = prepare(&allocation, &accounting.kernel_plan, &pairs)?;
        let root =
            troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
        let mut native = NativeProcessContext::with_backing(
            owner,
            NativeProcessBacking::new(root, pairs),
            2,
            METADATA_LIMIT,
        )
        .map_err(|_| ())?;
        if native.metadata_bytes()
            < bare_metadata + pair_capacity * core::mem::size_of::<IpcPagePair>()
        {
            return Err(());
        }
        let root_charges = native.stats();
        let metadata = native.metadata_bytes();
        let mut missing_guard = starts[0];
        missing_guard.stack = VirtualRange::from_pages(USER_DATA_BASE, 1).map_err(|_| ())?;
        if native.prepare(foreign, starts[0]).is_ok()
            || native.prepare(first, missing_guard).is_ok()
        {
            return Err(());
        }
        for address in [
            0,
            u64::MAX - 7,
            starts[0].thread_pointer + 1,
            USER_CODE_BASE,
        ] {
            let mut invalid_tls = starts[0];
            invalid_tls.thread_pointer = address;
            if native.prepare(first, invalid_tls).is_ok() {
                return Err(());
            }
        }
        native.prepare(first, starts[0]).map_err(|_| ())?;
        if native.prepare(first, starts[1]).is_ok() || native.prepare(second, starts[0]).is_ok() {
            return Err(());
        }
        if native.ipc_addresses(first).is_ok()
            || native.bind_thread_ipc(foreign, 0, TX[0]).is_ok()
            || native.bind_thread_ipc(first, 0, TX[0] + 1).is_ok()
            || native.bind_thread_ipc(first, 2, TX[0]).is_ok()
            || native.bind_thread_ipc(first, 1, TX[0]).is_ok()
            || native
                .bind_thread_ipc(first, 0, starts[0].tls.start())
                .is_ok()
        {
            return Err(());
        }
        native.bind_thread_ipc(first, 0, TX[0]).map_err(|_| ())?;
        let mut overlaps_ipc = starts[1];
        overlaps_ipc.tls = VirtualRange::from_pages(TX[0], 2).map_err(|_| ())?;
        overlaps_ipc.thread_pointer = TX[0];
        if native.prepare(second, overlaps_ipc).is_ok() {
            return Err(());
        }
        native.prepare(second, starts[1]).map_err(|_| ())?;
        if native.bind_thread_ipc(second, 0, TX[0]).is_ok()
            || native.bind_thread_ipc(first, 1, TX[1]).is_ok()
        {
            return Err(());
        }
        native.bind_thread_ipc(second, 1, TX[1]).map_err(|_| ())?;
        let mut oversized = [0xa5; 4097];
        let mut untouched = [0x5a; 8];
        if native.copy_thread_tx(first, &mut oversized).is_ok()
            || oversized != [0xa5; 4097]
            || native.copy_thread_tx(foreign, &mut untouched).is_ok()
            || untouched != [0x5a; 8]
            || native.publish_thread_rx(foreign, &[0xff; 8]).is_ok()
        {
            return Err(());
        }
        for (index, id) in [first, second].into_iter().enumerate() {
            if native.ipc_addresses(id).map_err(|_| ())? != (TX[index], TX[index] + PAGE) {
                return Err(());
            }
            native
                .publish_thread_rx(id, &[0xa5; 4096])
                .map_err(|_| ())?;
            if native.publish_thread_rx(id, &oversized).is_ok()
                || native.probe_word(TX[index] + PAGE).map_err(|_| ())? != 0xa5a5_a5a5_a5a5_a5a5
                || native
                    .probe_word(TX[index] + 2 * PAGE - 8)
                    .map_err(|_| ())?
                    != 0xa5a5_a5a5_a5a5_a5a5
            {
                return Err(());
            }
            native.publish_thread_rx(id, &[]).map_err(|_| ())?;
            verify_rx_tail(&native, TX[index], 0)?;
            native
                .publish_thread_rx(id, &(11 + index as u64 * 11).to_le_bytes())
                .map_err(|_| ())?;
            verify_rx_tail(&native, TX[index], 8)?;
        }
        if native
            .resume(foreign, ApplicationResume::Timeslice, 1)
            .is_ok()
            || native
                .resume(first, ApplicationResume::Timeslice, 0)
                .is_ok()
            || native
                .resume(first, ApplicationResume::Timeslice, 51)
                .is_ok()
        {
            return Err(());
        }
        let ids = [first, second];
        let mut preemptions = [0_u32; 2];
        // Switch to the sibling while the first context is timer-preempted,
        // before either reaches its first voluntary yield.
        for (index, id) in ids.into_iter().enumerate() {
            threads.dispatch(owner, id).map_err(|_| ())?;
            if native
                .resume(id, ApplicationResume::Timeslice, 1)
                .map_err(|_| ())?
                != NativeThreadStop::Preempted
            {
                return Err(());
            }
            threads.yield_running(owner, id).map_err(|_| ())?;
            preemptions[index] = 1;
        }
        for round in 0..16 {
            for (index, id) in ids.into_iter().enumerate() {
                let mut completion = if round == 0 {
                    ApplicationResume::Timeslice
                } else {
                    ApplicationResume::Yield
                };
                let milliseconds = 50;
                loop {
                    threads.dispatch(owner, id).map_err(|_| ())?;
                    let stop = native
                        .resume(id, completion, milliseconds)
                        .map_err(|_| ())?;
                    threads.yield_running(owner, id).map_err(|_| ())?;
                    match stop {
                        NativeThreadStop::Yielded => break,
                        NativeThreadStop::Preempted => {
                            preemptions[index] += 1;
                            if preemptions[index] > 128 {
                                return Err(());
                            }
                            completion = ApplicationResume::Timeslice;
                        }
                        _ => return Err(()),
                    }
                }
                let marker = 11 + index as u64 * 11;
                let mut tx = [0; 8];
                native.copy_thread_tx(id, &mut tx).map_err(|_| ())?;
                if u64::from_le_bytes(tx) != marker {
                    return Err(());
                }
                native
                    .publish_thread_rx(id, &(marker + round + 1).to_le_bytes())
                    .map_err(|_| ())?;
                if native
                    .probe_word(starts[index].thread_pointer + 16)
                    .map_err(|_| ())?
                    != round + 1
                {
                    return Err(());
                }
            }
            if native.probe_word(USER_DATA_BASE + 16).map_err(|_| ())? != (round + 1) * 2 {
                return Err(());
            }
        }
        if preemptions.contains(&0)
            || native.stats() != root_charges
            || native.metadata_bytes() != metadata
        {
            return Err(());
        }
        threads.dispatch(owner, first).map_err(|_| ())?;
        if native
            .resume(first, ApplicationResume::Yield, 50)
            .map_err(|_| ())?
            != NativeThreadStop::ProcessFaulted(troe_machine::IsolatedFault::IllegalInstruction)
            || !native.is_stopped()
            || native.resume(second, ApplicationResume::Yield, 50).is_ok()
            || native.prepare(second, starts[1]).is_ok()
            || native.bind_thread_ipc(second, 1, TX[1]).is_ok()
            || native.ipc_addresses(second).is_ok()
            || native.copy_thread_tx(second, &mut untouched).is_ok()
            || untouched != [0x5a; 8]
            || native.publish_thread_rx(second, &[0xff; 8]).is_ok()
            || native.probe_word(TX[1] + PAGE).map_err(|_| ())? != 38
            || native.probe_word(USER_DATA_BASE + 16).map_err(|_| ())? != 32
        {
            return Err(());
        }
        threads.stop_process(owner).map_err(|_| ())?;
        threads.stop_process(other).map_err(|_| ())?;
        // The foreign process was never given a native context or physical
        // reservation; it exists only to test cross-owner token rejection.
        threads.release_resources(other, foreign).map_err(|_| ())?;
        threads.reap(other, foreign).map_err(|_| ())?;
        threads.remove_process(other).map_err(|_| ())?;
        // Stopping contexts must not recycle buffers still mapped by the root.
        let spare = IpcPagePair::allocate().map_err(|_| ())?;
        if identities.iter().any(|(slot, _, _)| *slot == spare.slot()) {
            return Err(());
        }
        drop(spare);
        drop(native);
        if identities
            .iter()
            .any(|(_, _, range)| !troe_machine::ipc_range_is_zero(*range))
        {
            return Err(());
        }
        let reused = allocate_pairs()?;
        verify_reused(&reused, identities)?;
        drop(reused);
        Ok((threads, owner, ids))
    })();
    // Even a failed observation must retire the native owner before erasing
    // and freeing the sole frame allocation. Never acknowledge model release
    // while any root or native continuation could still reference it.
    let reclaimed = reclaim_isolated(&mut accounting.frames, allocation);
    let (mut threads, owner, ids) = result?;
    reclaimed?;
    for id in ids {
        if threads.release_resources(owner, id).map_err(|_| ())?.pages != 4 {
            return Err(());
        }
        threads.reap(owner, id).map_err(|_| ())?;
    }
    threads.remove_process(owner).map_err(|_| ())?;
    if accounting.frames.free_frames() != free || threads.committed_pages() != 0 {
        return Err(());
    }
    Ok(())
}

fn prepare(
    allocation: &IsolatedAllocation,
    kernel: &MappingPlan,
    pairs: &[IpcPagePair],
) -> Result<(MappingPlan, [NativeThreadStart; 2]), ()> {
    troe_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
    troe_machine::copy_to_physical(allocation.code, 0, CODE).map_err(|_| ())?;
    let base = build_isolated_plan(kernel, allocation)?;
    let mut plan = MappingPlan::new();
    for mapping in base.mappings() {
        if mapping.virtual_range().start() != USER_STACK_BASE {
            plan.insert(*mapping).map_err(|_| ())?;
        }
    }
    // Split the four already-owned payload frames into two guarded stacks and
    // two TLS pages. There is no physical alias or second page-table owner.
    for index in 0..4 {
        plan.insert(
            Mapping::user(
                VirtualRange::from_pages(USER_STACK_BASE + index * 3 * PAGE, 1).map_err(|_| ())?,
                PhysicalRange::from_pages(allocation.stack.start() + index * PAGE, 1)
                    .map_err(|_| ())?,
                MappingPermissions::READ_WRITE,
                MappingOwner::IsolatedTask,
                MappingLifetime::Task,
            )
            .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
    }
    for (index, pair) in pairs.iter().enumerate() {
        plan.insert(
            Mapping::user(
                VirtualRange::from_pages(TX[index], 2).map_err(|_| ())?,
                pair.range(),
                MappingPermissions::READ_WRITE,
                MappingOwner::IsolatedTask,
                MappingLifetime::Task,
            )
            .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        troe_machine::copy_to_physical(pair.range(), 0, &[0xa5; 4096]).map_err(|_| ())?;
        troe_machine::copy_to_physical(pair.range(), 4096, &[0xa5; 4096]).map_err(|_| ())?;
    }
    let start = |index: u64| -> Result<NativeThreadStart, ()> {
        let tls = VirtualRange::from_pages(USER_STACK_BASE + (index + 2) * 3 * PAGE, 1)
            .map_err(|_| ())?;
        Ok(NativeThreadStart {
            entry: USER_CODE_BASE,
            stack: VirtualRange::from_pages(USER_STACK_BASE + index * 3 * PAGE, 1)
                .map_err(|_| ())?,
            tls,
            thread_pointer: tls.start(),
            startup: USER_DATA_BASE + index * 8,
            startup_bytes: 8,
        })
    };
    let starts = [start(0)?, start(1)?];
    for index in 0..2 {
        let marker = 11_u64 + index * 11;
        troe_machine::copy_to_physical(
            allocation.data,
            usize::try_from(index * 8).map_err(|_| ())?,
            &marker.to_le_bytes(),
        )
        .map_err(|_| ())?;
        let tls = PhysicalRange::from_pages(allocation.stack.start() + (index + 2) * PAGE, 1)
            .map_err(|_| ())?;
        troe_machine::copy_to_physical(tls, 0, &marker.to_le_bytes()).map_err(|_| ())?;
        troe_machine::copy_to_physical(tls, 8, &(USER_DATA_BASE + 16).to_le_bytes())
            .map_err(|_| ())?;
        troe_machine::copy_to_physical(
            tls,
            24,
            &TX[usize::try_from(index).map_err(|_| ())?].to_le_bytes(),
        )
        .map_err(|_| ())?;
    }
    if !plan.enforces_global_w_xor_x() {
        return Err(());
    }
    Ok((plan, starts))
}

fn allocate_pairs() -> Result<Vec<IpcPagePair>, ()> {
    let mut pairs = Vec::new();
    // Spare capacity is deliberately charged even though only two pairs are live.
    pairs.try_reserve_exact(4).map_err(|_| ())?;
    for _ in 0..2 {
        pairs.push(IpcPagePair::allocate().map_err(|_| ())?);
    }
    Ok(pairs)
}

fn pair_identities(pairs: &[IpcPagePair]) -> [(usize, u64, PhysicalRange); 2] {
    core::array::from_fn(|index| {
        (
            pairs[index].slot(),
            pairs[index].generation(),
            pairs[index].range(),
        )
    })
}

fn verify_reused(pairs: &[IpcPagePair], prior: [(usize, u64, PhysicalRange); 2]) -> Result<(), ()> {
    for (pair, (slot, generation, range)) in pairs.iter().zip(prior) {
        if pair.slot() != slot
            || pair.generation() != generation + 1
            || pair.range() != range
            || !pair.is_live()
        {
            return Err(());
        }
    }
    Ok(())
}

fn verify_rx_tail(native: &NativeProcessContext, tx: u64, from: u64) -> Result<(), ()> {
    for offset in (from..PAGE).step_by(8) {
        if native.probe_word(tx + PAGE + offset).map_err(|_| ())? != 0 {
            return Err(());
        }
    }
    Ok(())
}

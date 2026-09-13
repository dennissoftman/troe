//! Native shared-root acceptance with two guarded stacks and distinct TLS words.

use super::IsolatedAllocation;
use super::isolated::{allocate_isolated, build_isolated_plan, reclaim_isolated};
use crate::limits::{USER_CODE_BASE, USER_DATA_BASE, USER_STACK_BASE};
use crate::machine::OwnedAccounting;
use troe_machine::{ApplicationResume, NativeProcessContext, NativeThreadStart, NativeThreadStop};
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
// increment shared and private counters, and yield 16 times. A final illegal
// instruction must revoke both continuations. A marker mismatch exits with 1,
// a distinct result, so it cannot masquerade as the expected fault.
#[cfg(target_arch = "x86_64")]
const CODE: &[u8] = &[
    0x49, 0x89, 0xfc, 0xbb, 0x00, 0xe1, 0xf5, 0x05, 0xff, 0xcb, 0x75, 0xfc, 0x41, 0xbe, 0x10, 0x00,
    0x00, 0x00, 0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x49, 0x3b, 0x04, 0x24, 0x75,
    0x24, 0x64, 0x4c, 0x8b, 0x2c, 0x25, 0x08, 0x00, 0x00, 0x00, 0x49, 0xff, 0x45, 0x00, 0x64, 0x48,
    0xff, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x41, 0xff,
    0xce, 0x75, 0xcf, 0x0f, 0x0b, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xcd, 0x80, 0x0f, 0x0b,
];
#[cfg(target_arch = "aarch64")]
const CODE: &[u8] = &[
    0xf3, 0x03, 0x00, 0xaa, 0x14, 0x20, 0x9c, 0x52, 0xb4, 0xbe, 0xa0, 0x72, 0x94, 0x06, 0x00, 0x71,
    0xe1, 0xff, 0xff, 0x54, 0x15, 0x02, 0x80, 0x52, 0x56, 0xd0, 0x3b, 0xd5, 0xc0, 0x02, 0x40, 0xf9,
    0x61, 0x02, 0x40, 0xf9, 0x1f, 0x00, 0x01, 0xeb, 0xa1, 0x01, 0x00, 0x54, 0xd7, 0x06, 0x40, 0xf9,
    0xe0, 0x02, 0x40, 0xf9, 0x00, 0x04, 0x00, 0x91, 0xe0, 0x02, 0x00, 0xf9, 0xc0, 0x0a, 0x40, 0xf9,
    0x00, 0x04, 0x00, 0x91, 0xc0, 0x0a, 0x00, 0xf9, 0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
    0xb5, 0x06, 0x00, 0x71, 0x21, 0xfe, 0xff, 0x54, 0x00, 0x00, 0x20, 0xd4, 0x20, 0x00, 0x80, 0xd2,
    0x08, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x20, 0xd4,
];

const PAGE: u64 = 4096;
const METADATA_LIMIT: usize = 16 * 1024;

#[allow(clippy::too_many_lines)]
pub(crate) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    let free = accounting.frames.free_frames();
    let allocation = allocate_isolated(&mut accounting.frames)?;
    let result = (|| {
        let (plan, starts) = prepare(&allocation, &accounting.kernel_plan)?;
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
                    private_pages: 6,
                    handles: 0,
                })
                .map_err(|_| ())
        };
        let owner = register(0)?;
        let other = register(1)?;
        let mut threads = ThreadTable::new(2, 3, 6, METADATA_LIMIT).map_err(|_| ())?;
        threads
            .register_process(
                owner,
                ThreadQuota {
                    records: 2,
                    pages: 4,
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
                    pages: 2,
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
                    pages: 2,
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
        let mut native =
            NativeProcessContext::new(owner, root, 2, METADATA_LIMIT).map_err(|_| ())?;
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
        native.prepare(second, starts[1]).map_err(|_| ())?;
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
        drop(native);
        Ok((threads, owner, ids))
    })();
    // Even a failed observation must retire the native owner before erasing
    // and freeing the sole frame allocation. Never acknowledge model release
    // while any root or native continuation could still reference it.
    let reclaimed = reclaim_isolated(&mut accounting.frames, allocation);
    let (mut threads, owner, ids) = result?;
    reclaimed?;
    for id in ids {
        if threads.release_resources(owner, id).map_err(|_| ())?.pages != 2 {
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
    }
    if !plan.enforces_global_w_xor_x() {
        return Err(());
    }
    Ok((plan, starts))
}

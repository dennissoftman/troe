//! Native Exit retirement, retained sibling claims and quiescence-gated Join.

use super::{
    IsolatedAllocation, METADATA_LIMIT, PAGE, ProbeScheduler, TX, allocate_isolated,
    allocate_pairs, pair_identities, prepare, reclaim_isolated, thread_token, verify_rx_tail,
};
use crate::{
    limits::{USER_DATA_BASE, USER_STACK_BASE},
    machine::OwnedAccounting,
};
use troe_abi::threading::{Kind, Outcome, Request, Response, Token, Wait, WaitMode};
use troe_machine::{
    ApplicationResume, IpcPagePair, IsolatedFault, NativeProcessBacking, NativeProcessContext,
    NativeSchedulerCall, NativeSchedulerExecution, NativeThreadBacking, NativeThreadStart,
    NativeThreadStop,
};
use troe_memory::{
    Mapping, MappingLifetime, MappingOwner, MappingPermissions, MappingPlan, PhysicalRange,
    VirtualRange,
};
use troe_service::threading::{Operation, Progress, Retiring, Waiting};
use troe_task::thread::{ThreadId, ThreadQuota, ThreadResources, ThreadTable, sync};
use troe_task::{
    Capabilities, MonotonicMillis, ProcessName, ProcessOrigin, ProcessRegistration, ProcessTable,
    Scheduler, StackResource,
};

mod abort;
mod program;
const STARTUP: u64 = USER_STACK_BASE + 18 * PAGE;
const ZERO: MonotonicMillis = MonotonicMillis::from_millis(0);
const _: () = assert!(
    2 * core::mem::size_of::<NativeSchedulerExecution>()
        + core::mem::size_of::<Operation>()
        + core::mem::size_of::<Retiring>()
        + core::mem::size_of::<Waiting>()
        <= 4096
);

#[derive(Clone, Copy)]
enum Scenario {
    Retire(u64),
    Alias,
    StartupReference,
    Partial,
    Essential,
    Abort(u64),
    AbortAlias,
    AbortReference,
    StartWins,
}

pub(super) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    for scenario in [
        Scenario::Retire(USER_STACK_BASE),
        Scenario::Retire(USER_STACK_BASE + 6 * PAGE),
        Scenario::Retire(TX[0]),
        Scenario::Retire(TX[0] + PAGE),
        Scenario::Retire(STARTUP),
        Scenario::Alias,
        Scenario::StartupReference,
        Scenario::Partial,
        Scenario::Essential,
        Scenario::Abort(USER_STACK_BASE),
        Scenario::Abort(USER_STACK_BASE + 6 * PAGE),
        Scenario::Abort(STARTUP),
        Scenario::Abort(TX[0]),
        Scenario::Abort(TX[0] + PAGE),
        Scenario::AbortAlias,
        Scenario::AbortReference,
        Scenario::StartWins,
    ] {
        let free = accounting.frames.free_frames();
        let allocation = allocate_isolated(&mut accounting.frames)?;
        let mut worker = None;
        let result = (|| {
            worker = Some(
                accounting
                    .frames
                    .allocate_contiguous(3, 1)
                    .map_err(|_| ())?,
            );
            run_case(accounting, &allocation, &mut worker, scenario)
        })();
        // Every local native root has dropped before either ordinary owner frees.
        if let Some(range) = worker {
            troe_machine::zero_physical_range(range).map_err(|_| ())?;
            accounting.frames.free_range(range).map_err(|_| ())?;
        }
        reclaim_isolated(&mut accounting.frames, allocation)?;
        result?.finish()?;
        if accounting.frames.free_frames() != free {
            return Err(());
        }
    }
    Ok(())
}

struct Policy {
    threads: ThreadTable,
    sync: sync::SyncTable,
    authority: ProbeScheduler,
    ids: [ThreadId; 2],
}

struct Reclamation {
    threads: ThreadTable,
    sync: sync::SyncTable,
    ids: [Option<ThreadId>; 2],
}
impl Reclamation {
    // Physical owners and root are gone before acknowledging the remaining records.
    fn finish(mut self) -> Result<(), ()> {
        let owner = self.ids[1].ok_or(())?.process();
        for id in self.ids.into_iter().flatten() {
            self.threads.release_resources(owner, id).map_err(|_| ())?;
            self.threads.reap(owner, id).map_err(|_| ())?;
        }
        // stop_process already deregistered the paired synchronization owner.
        // Verify it drained its objects/waits without attempting a second removal.
        if self.sync.usage(owner) != (0, 0) {
            return Err(());
        }
        self.threads.remove_process(owner).map_err(|_| ())?;
        if self.threads.committed_pages() != 0 {
            return Err(());
        }
        Ok(())
    }
}
impl Policy {
    fn stop_and_reclaim(mut self, worker_reaped: bool) -> Result<Reclamation, ()> {
        self.sync
            .stop_process(&mut self.threads, self.ids[1].process())
            .map_err(|_| ())?;
        self.authority.revoke()?;
        Ok(Reclamation {
            threads: self.threads,
            sync: self.sync,
            ids: [
                if worker_reaped {
                    None
                } else {
                    Some(self.ids[0])
                },
                Some(self.ids[1]),
            ],
        })
    }
    fn new(table_pages: u64, prepared_worker: bool, abort_authority: bool) -> Result<Self, ()> {
        let mut scheduler = Scheduler::new(1).map_err(|_| ())?;
        let task_id = scheduler
            .spawn(
                Capabilities::SERVICE,
                StackResource::new(0, 1).map_err(|_| ())?,
            )
            .map_err(|_| ())?;
        let mut processes = ProcessTable::new(1).map_err(|_| ())?;
        let owner = processes
            .register(ProcessRegistration {
                task_id,
                name: ProcessName::new("native-retirement-probe").map_err(|_| ())?,
                origin: ProcessOrigin::Foreground,
                started_millis: 0,
                table_pages,
                private_pages: 13,
                handles: 1,
            })
            .map_err(|_| ())?;
        let mut rights = troe_dispatch::Rights::CALL
            .union(troe_dispatch::Rights::THREAD_OBSERVE)
            .union(troe_dispatch::Rights::THREAD_JOIN);
        if abort_authority {
            rights = rights.union(troe_dispatch::Rights::THREAD_START);
        }
        let authority = ProbeScheduler::with_rights(&processes, owner, rights)?;
        let mut threads = ThreadTable::new(1, 2, 9, METADATA_LIMIT).map_err(|_| ())?;
        threads
            .register_process(
                owner,
                ThreadQuota {
                    records: 2,
                    pages: 9,
                },
            )
            .map_err(|_| ())?;
        let initial = threads
            .prepare_initial(
                owner,
                ThreadResources {
                    reservation: 1,
                    pages: 4,
                },
            )
            .map_err(|_| ())?;
        threads.start(owner, initial).map_err(|_| ())?;
        threads.dispatch(owner, initial).map_err(|_| ())?;
        let worker = threads
            .prepare_worker(
                owner,
                initial,
                ThreadResources {
                    reservation: 2,
                    pages: 5,
                },
            )
            .map_err(|_| ())?;
        if !prepared_worker {
            threads.start(owner, worker).map_err(|_| ())?;
        }
        threads.yield_running(owner, initial).map_err(|_| ())?;
        let mut sync = sync::SyncTable::new(1, 1, 1, METADATA_LIMIT).map_err(|_| ())?;
        sync.register_process(
            &mut threads,
            owner,
            sync::SyncQuota {
                objects: 1,
                waits: 1,
            },
        )
        .map_err(|_| ())?;
        // Put the worker first so retirement moves both the sibling context and its pair index.
        Ok(Self {
            threads,
            sync,
            authority,
            ids: [worker, initial],
        })
    }

    fn capture(
        &mut self,
        native: &mut NativeProcessContext,
        index: usize,
    ) -> Result<(NativeSchedulerCall, NativeSchedulerExecution, Operation), ()> {
        let caller = self.ids[index];
        let owner = caller.process();
        self.threads.dispatch(owner, caller).map_err(|_| ())?;
        let mut captured = None;
        for _ in 0..128 {
            match native
                .resume(caller, ApplicationResume::Timeslice, 50)
                .map_err(|_| ())?
            {
                NativeThreadStop::Preempted => {}
                NativeThreadStop::SchedulerCall(call) => {
                    captured = Some(call);
                    break;
                }
                _ => return Err(()),
            }
        }
        let call = captured.ok_or(())?;
        let authorization = self
            .authority
            .dispatcher
            .authorize_scheduler_owned_abi(
                self.authority.principal,
                call.call().ok_or(())?.handle,
                call.request_bytes().ok_or(())?,
            )
            .map_err(|_| ())?;
        let request = authorization.request();
        let operation =
            Operation::bind(self.authority.process, caller, authorization).map_err(|_| ())?;
        let execution = native.claim_scheduler(call, request).map_err(|_| ())?;
        Ok((call, execution, operation))
    }
}

fn mappings(
    allocation: &IsolatedAllocation,
    kernel: &MappingPlan,
    pairs: &[IpcPagePair],
    worker: PhysicalRange,
    scenario: Scenario,
) -> Result<(MappingPlan, [NativeThreadStart; 2]), ()> {
    let (base, mut starts) = prepare(allocation, kernel, pairs, program::CODE)?;
    let mut plan = MappingPlan::new();
    for mapping in base.mappings() {
        let replacement = if mapping.virtual_range() == starts[0].stack {
            Some(worker.start())
        } else if mapping.virtual_range() == starts[0].tls {
            Some(worker.start() + PAGE)
        } else {
            None
        };
        plan.insert(if let Some(address) = replacement {
            user(
                mapping.virtual_range(),
                PhysicalRange::from_pages(address, 1).map_err(|_| ())?,
                MappingPermissions::READ_WRITE,
            )?
        } else {
            *mapping
        })
        .map_err(|_| ())?;
    }
    let startup = VirtualRange::from_pages(STARTUP, 1).map_err(|_| ())?;
    plan.insert(user(
        startup,
        PhysicalRange::from_pages(worker.start() + 2 * PAGE, 1).map_err(|_| ())?,
        MappingPermissions::READ_ONLY,
    )?)
    .map_err(|_| ())?;
    starts[0].startup = STARTUP;
    starts[0].private_startup = Some(startup);
    if matches!(scenario, Scenario::Alias | Scenario::AbortAlias) {
        plan.insert(user(
            VirtualRange::from_pages(STARTUP + 3 * PAGE, 1).map_err(|_| ())?,
            PhysicalRange::from_pages(worker.start() + PAGE, 1).map_err(|_| ())?,
            MappingPermissions::READ_WRITE,
        )?)
        .map_err(|_| ())?;
    }
    if matches!(
        scenario,
        Scenario::StartupReference | Scenario::AbortReference
    ) {
        starts[1].startup = starts[0].tls.start();
    }
    Ok((plan, starts))
}

fn user(
    virtual_range: VirtualRange,
    physical: PhysicalRange,
    permissions: MappingPermissions,
) -> Result<Mapping, ()> {
    Mapping::user(
        virtual_range,
        physical,
        permissions,
        MappingOwner::IsolatedTask,
        MappingLifetime::Task,
    )
    .map_err(|_| ())
}

fn scripts(
    allocation: &IsolatedAllocation,
    worker: PhysicalRange,
    policy: &Policy,
    fault: u64,
    abort: bool,
    start_wins: bool,
) -> Result<(), ()> {
    troe_machine::zero_physical_range(worker).map_err(|_| ())?;
    let token = Token::new(
        Kind::Thread,
        u32::try_from(policy.ids[0].slot()).map_err(|_| ())?,
        policy.ids[0].generation(),
    )
    .map_err(|_| ())?;
    let join = if abort {
        Request::Abort(token)
    } else {
        Request::Join {
            thread: token,
            wait: WaitMode::Wait(Wait {
                deadline: None,
                observe_stop: true,
            }),
        }
    };
    let current = Response {
        outcome: Outcome::Success,
        value: thread_token(&policy.threads, policy.ids[1].process(), policy.ids[1])?,
        snapshot: None,
    };
    let joined = Response {
        outcome: if start_wins {
            Outcome::InvalidState
        } else {
            Outcome::Success
        },
        value: if abort { 0 } else { u64::MAX },
        snapshot: None,
    };
    let exit = Request::Exit(u64::MAX);
    for (offset, request, response) in [
        (0x100, exit, None),
        (0x200, Request::Current, Some(current)),
        (0x260, join, Some(joined)),
    ] {
        troe_machine::copy_to_physical(allocation.data, offset, &request.encode().map_err(|_| ())?)
            .map_err(|_| ())?;
        if let Some(response) = response {
            troe_machine::copy_to_physical(
                allocation.data,
                offset + 64,
                &response.encode(request).map_err(|_| ())?,
            )
            .map_err(|_| ())?;
        }
    }
    for (index, physical) in [worker.start() + PAGE, allocation.stack.start() + 3 * PAGE]
        .into_iter()
        .enumerate()
    {
        let tls = PhysicalRange::from_pages(physical, 1).map_err(|_| ())?;
        for (offset, value) in [
            (8, USER_DATA_BASE + if index == 0 { 0x100 } else { 0x200 }),
            (40, policy.authority.handle.abi_value()),
            (48, if index == 0 { 1 } else { 2 }),
            (24, TX[index]),
            (64, fault),
        ] {
            troe_machine::copy_to_physical(tls, offset, &value.to_le_bytes()).map_err(|_| ())?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One ownership fixture, including all rejection and cleanup paths.
fn run_case(
    accounting: &mut OwnedAccounting,
    allocation: &IsolatedAllocation,
    retained: &mut Option<PhysicalRange>,
    scenario: Scenario,
) -> Result<Reclamation, ()> {
    let worker = retained.ok_or(())?;
    let pairs = allocate_pairs()?;
    let identities = pair_identities(&pairs);
    let (plan, starts) = mappings(
        allocation,
        &accounting.kernel_plan,
        &pairs,
        worker,
        scenario,
    )?;
    let root = troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
    let is_abort = matches!(
        scenario,
        Scenario::Abort(_) | Scenario::AbortAlias | Scenario::AbortReference | Scenario::StartWins
    );
    let start_wins = matches!(scenario, Scenario::StartWins);
    let mut policy = Policy::new(root.stats().table_pages, is_abort && !start_wins, is_abort)?;
    let owner = policy.ids[0].process();
    let fault = if let Scenario::Retire(address) | Scenario::Abort(address) = scenario {
        address
    } else {
        STARTUP
    };
    scripts(allocation, worker, &policy, fault, is_abort, start_wins)?;
    let mut native = NativeProcessContext::with_backing(
        owner,
        NativeProcessBacking::new(root, pairs),
        2,
        METADATA_LIMIT,
    )
    .map_err(|_| ())?;
    let mut invalid = starts[0];
    invalid.private_startup = Some(invalid.tls);
    if native.prepare(policy.ids[0], invalid).is_ok() {
        return Err(());
    }
    invalid = starts[0];
    // Startup arguments can be shared independently of private descriptor ownership.
    // An unreadable argument is still rejected before publishing a context.
    invalid.startup = 0;
    if native.prepare(policy.ids[0], invalid).is_ok() {
        return Err(());
    }
    for index in 0..2 {
        native
            .prepare(policy.ids[index], starts[index])
            .map_err(|_| ())?;
        native
            .bind_thread_ipc(policy.ids[index], index, TX[index])
            .map_err(|_| ())?;
    }
    let charges = native.stats();
    let metadata = native.metadata_bytes();
    let stack = [PhysicalRange::from_pages(worker.start(), 1).map_err(|_| ())?];
    let tls = [PhysicalRange::from_pages(worker.start() + PAGE, 1).map_err(|_| ())?];
    let startup = [PhysicalRange::from_pages(worker.start() + 2 * PAGE, 1).map_err(|_| ())?];
    let backing = NativeThreadBacking {
        stack: &stack,
        tls: &tls,
        startup: &startup,
    };
    if is_abort {
        return abort::run(
            accounting,
            retained,
            abort::Fixture {
                native,
                policy,
                starts,
                identities,
                scenario,
            },
        );
    }
    let (peer_call, peer, current) = policy.capture(&mut native, 1)?;
    policy
        .threads
        .yield_running(owner, policy.ids[1])
        .map_err(|_| ())?;
    let (_, peer) = native.retire_thread(peer, backing).err().ok_or(())?;
    let (exit_call, exit, exit_operation) = policy.capture(&mut native, 0)?;
    if exit.request() != (Request::Exit(u64::MAX)) {
        return Err(());
    }
    let bad = NativeThreadBacking {
        stack: &tls,
        tls: &stack,
        startup: &startup,
    };
    let (_, exit) = native.retire_thread(exit, bad).err().ok_or(())?;
    if native.is_stopped() || native.stats() != charges {
        return Err(());
    }
    if matches!(scenario, Scenario::Essential) {
        let mutex = policy
            .sync
            .create_mutex(
                &mut policy.threads,
                owner,
                policy.ids[0],
                sync::OwnerDeath::FailProcess,
            )
            .map_err(|_| ())?;
        if policy
            .sync
            .lock(
                &mut policy.threads,
                owner,
                policy.ids[0],
                mutex,
                sync::WaitMode::Try,
                ZERO,
            )
            .map_err(|_| ())?
            != sync::SyncStart::Complete(sync::SyncOutcome::Acquired)
        {
            return Err(());
        }
    }
    let Progress::Retiring(retiring) = exit_operation
        .execute(&mut policy.threads, &mut policy.sync, ZERO)
        .map_err(|_| ())?
    else {
        return Err(());
    };
    if retiring.caller() != exit.caller()
        || retiring.request() != exit.request()
        || retiring.disposition()
            != if matches!(scenario, Scenario::Essential) {
                sync::ExitEffect::ProcessStopped
            } else {
                sync::ExitEffect::ThreadExiting
            }
    {
        return Err(());
    }
    if matches!(scenario, Scenario::Essential) {
        native.stop();
        if native.retire_thread(exit, backing).is_ok()
            || native.stats() != charges
            || native.probe_word(starts[0].stack.start()).is_err()
            || retiring.complete_thread(&mut policy.threads).is_ok()
        {
            return Err(());
        }
    } else if matches!(scenario, Scenario::Alias | Scenario::StartupReference) {
        let (_, exit) = native.retire_thread(exit, backing).err().ok_or(())?;
        if native.is_stopped()
            || native.stats() != charges
            || native.probe_word(starts[0].tls.start()).is_err()
        {
            return Err(());
        }
        drop(exit);
        native.stop();
    } else if matches!(scenario, Scenario::Partial) {
        let (_, exit) = native
            .probe_retirement_failure(exit, backing)
            .err()
            .ok_or(())?;
        if !native.is_stopped()
            || native.stats() != charges
            || native.probe_word(starts[0].stack.start()).is_ok()
            || native.probe_word(starts[0].tls.start()).is_err()
        {
            return Err(());
        }
        if native
            .complete_scheduler_execution(
                exit,
                Response {
                    outcome: Outcome::Success,
                    value: 0,
                    snapshot: None,
                },
            )
            .is_ok()
        {
            return Err(());
        }
    } else {
        let retired = native.retire_thread(exit, backing).map_err(|_| ())?;
        if retired.thread() != policy.ids[0]
            || retired.ordinary_pages() != 3
            || native.stats().mapped_pages != charges.mapped_pages - 5
            || native.stats().table_pages != charges.table_pages
            || native.metadata_bytes() != metadata
            || native.complete_scheduler(exit_call, None).is_ok()
            || native
                .claim_scheduler(exit_call, Request::Exit(u64::MAX))
                .is_ok()
            || native
                .resume(policy.ids[0], ApplicationResume::Timeslice, 50)
                .is_ok()
        {
            return Err(());
        }
        for range in [
            starts[0].stack,
            starts[0].tls,
            starts[0].private_startup.ok_or(())?,
            VirtualRange::from_pages(TX[0], 2).map_err(|_| ())?,
        ] {
            for offset in 0..range.page_count() {
                if native.probe_word(range.start() + offset * PAGE).is_ok() {
                    return Err(());
                }
            }
        }
        let replacement = IpcPagePair::allocate().map_err(|_| ())?;
        if (
            replacement.slot(),
            replacement.generation(),
            replacement.range(),
        ) != (identities[0].0, identities[0].1 + 1, identities[0].2)
            || !troe_machine::ipc_range_is_zero(replacement.range())
        {
            return Err(());
        }
        retiring
            .complete_thread(&mut policy.threads)
            .map_err(|_| ())?;
        policy
            .threads
            .dispatch(owner, policy.ids[1])
            .map_err(|_| ())?;
        let Progress::Complete(completion) = current
            .execute(&mut policy.threads, &mut policy.sync, ZERO)
            .map_err(|_| ())?
        else {
            return Err(());
        };
        native
            .complete_scheduler_execution(peer, completion.response())
            .map_err(|_| ())?;
        verify_rx_tail(&native, TX[1], 32)?;
        policy
            .threads
            .yield_running(owner, policy.ids[1])
            .map_err(|_| ())?;
        let (_, join, operation) = policy.capture(&mut native, 1)?;
        let Progress::Waiting(mut wait) = operation
            .execute(&mut policy.threads, &mut policy.sync, ZERO)
            .map_err(|_| ())?
        else {
            return Err(());
        };
        if wait
            .observe(&mut policy.threads, &mut policy.sync, ZERO)
            .map_err(|_| ())?
        {
            return Err(());
        }
        let free = accounting.frames.free_frames();
        troe_machine::zero_physical_range(worker).map_err(|_| ())?;
        accounting.frames.free_range(worker).map_err(|_| ())?;
        *retained = None;
        if accounting.frames.free_frames() != free + 3 {
            return Err(());
        }
        if policy
            .threads
            .release_resources(owner, retired.thread())
            .map_err(|_| ())?
            .pages
            != 5
        {
            return Err(());
        }
        if !wait
            .observe(&mut policy.threads, &mut policy.sync, ZERO)
            .map_err(|_| ())?
        {
            return Err(());
        }
        policy.threads.reap(owner, policy.ids[0]).map_err(|_| ())?;
        policy
            .threads
            .dispatch(owner, policy.ids[1])
            .map_err(|_| ())?;
        let completion = wait
            .finish(&mut policy.threads, &mut policy.sync)
            .map_err(|_| ())?;
        if completion.response().value != u64::MAX {
            return Err(());
        }
        native
            .complete_scheduler_execution(join, completion.response())
            .map_err(|_| ())?;
        verify_rx_tail(&native, TX[1], 32)?;
        let mut stop = NativeThreadStop::Preempted;
        for _ in 0..128 {
            stop = native
                .resume(policy.ids[1], ApplicationResume::Timeslice, 50)
                .map_err(|_| ())?;
            if stop != NativeThreadStop::Preempted {
                break;
            }
        }
        if stop != NativeThreadStop::ProcessFaulted(IsolatedFault::Translation)
            || native
                .probe_word(starts[1].tls.start() + 16)
                .map_err(|_| ())?
                != 2
            || !troe_machine::ipc_range_is_zero(replacement.range())
        {
            return Err(());
        }
        drop(replacement);
        policy
            .sync
            .stop_process(&mut policy.threads, owner)
            .map_err(|_| ())?;
        native.stop();
        drop(native);
        if identities
            .iter()
            .any(|identity| !troe_machine::ipc_range_is_zero(identity.2))
        {
            return Err(());
        }
        // Initial backing belongs to the outer complete allocation, so its
        // logical release remains after the outer physical reclamation.
        return policy.stop_and_reclaim(true);
    }
    if native
        .complete_scheduler_execution(
            peer,
            Response {
                outcome: Outcome::Success,
                value: thread_token(&policy.threads, owner, policy.ids[1])?,
                snapshot: None,
            },
        )
        .is_ok()
        || native.complete_scheduler(peer_call, None).is_ok()
    {
        return Err(());
    }
    let spare = IpcPagePair::allocate().map_err(|_| ())?;
    if identities.iter().any(|identity| identity.0 == spare.slot()) {
        return Err(());
    }
    drop(spare);
    policy
        .sync
        .stop_process(&mut policy.threads, owner)
        .map_err(|_| ())?;
    drop(native);
    if identities
        .iter()
        .any(|identity| !troe_machine::ipc_range_is_zero(identity.2))
    {
        return Err(());
    }
    policy.stop_and_reclaim(false)
}

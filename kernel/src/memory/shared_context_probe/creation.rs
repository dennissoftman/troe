//! Canonical C Prepare/Start/Abort/Join with retained native and physical owners.

use super::{
    IsolatedAllocation, METADATA_LIMIT, PAGE, ProbeScheduler,
    admission::{Memory, mappings},
    allocate_isolated, reclaim_isolated,
};
use crate::{
    limits::{USER_CODE_BASE, USER_DATA_BASE},
    machine::OwnedAccounting,
};
use alloc::vec::Vec;
use troe_abi::threading::{Request, StartupReference};
use troe_application::{Target, static_tls::StaticTlsLayout};
use troe_dispatch::Rights;
use troe_machine::{IpcPagePair, NativeProcessContext, NativeSchedulerExecution, NativeThreadStop};
use troe_memory::PhysicalRange;
use troe_service::threading::{
    Completion, Operation, PrepareFailure, Preparing, Progress, Waiting,
};
use troe_task::{
    Capabilities, MonotonicMillis, ProcessId, ProcessName, ProcessOrigin, ProcessRegistration,
    ProcessTable, Scheduler, StackResource,
    thread::{ThreadId, ThreadQuota, ThreadResources, ThreadState, ThreadTable, sync},
};

mod program;
const ZERO: MonotonicMillis = MonotonicMillis::from_millis(0);
const SHARED: u64 = USER_DATA_BASE + 2 * PAGE;
const _: () = assert!(
    core::mem::size_of::<NativeSchedulerExecution>()
        + core::mem::size_of::<Preparing>()
        + core::mem::size_of::<Waiting>()
        <= 4096
);

#[derive(Debug)]
struct Trace {
    stage: &'static str,
    caller: usize,
    request: Option<Request>,
}

pub(super) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    let free = accounting.frames.free_frames();
    let allocation = allocate_isolated(&mut accounting.frames)?;
    let mut frames = [None; 3];
    let mut trace = Trace {
        stage: "initial reservation",
        caller: 0,
        request: None,
    };
    let result = run(accounting, &allocation, &mut frames, &mut trace);
    if result.is_err() {
        let _ = troe_machine::write(
            alloc::format!("native creation verification failed: {trace:?}\n").as_bytes(),
        );
    }
    // run's unique native root has dropped before any remaining frame is reused.
    for range in frames.into_iter().flatten() {
        troe_machine::zero_physical_range(range).map_err(|_| ())?;
        accounting.frames.free_range(range).map_err(|_| ())?;
    }
    reclaim_isolated(&mut accounting.frames, allocation)?;
    let (mut threads, owner) = result?;
    threads.remove_process(owner).map_err(|_| ())?;
    if threads.committed_pages() != 0 || accounting.frames.free_frames() != free {
        return Err(());
    }
    Ok(())
}

struct Policy {
    threads: ThreadTable,
    sync: sync::SyncTable,
    authority: ProbeScheduler,
    ids: [Option<ThreadId>; 3],
}
impl Policy {
    fn new(table_pages: u64) -> Result<Self, ()> {
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
                name: ProcessName::new("native-creation-probe").map_err(|_| ())?,
                origin: ProcessOrigin::Foreground,
                started_millis: 0,
                table_pages,
                private_pages: 18,
                handles: 1,
            })
            .map_err(|_| ())?;
        let authority = ProbeScheduler::with_rights(
            &processes,
            owner,
            Rights::CALL
                .union(Rights::THREAD_CREATE)
                .union(Rights::THREAD_START)
                .union(Rights::THREAD_OBSERVE)
                .union(Rights::THREAD_JOIN),
        )?;
        let mut threads = ThreadTable::new(1, 3, 15, METADATA_LIMIT).map_err(|_| ())?;
        threads
            .register_process(
                owner,
                ThreadQuota {
                    records: 3,
                    pages: 15,
                },
            )
            .map_err(|_| ())?;
        let initial = threads
            .prepare_initial(
                owner,
                ThreadResources {
                    reservation: 1,
                    pages: 5,
                },
            )
            .map_err(|_| ())?;
        let mut sync = sync::SyncTable::new(1, 1, 3, METADATA_LIMIT).map_err(|_| ())?;
        sync.register_process(
            &mut threads,
            owner,
            sync::SyncQuota {
                objects: 1,
                waits: 3,
            },
        )
        .map_err(|_| ())?;
        Ok(Self {
            threads,
            sync,
            authority,
            ids: [Some(initial), None, None],
        })
    }
    fn owner(&self) -> ProcessId {
        self.authority.process.id()
    }
}

struct Fixture {
    // Native references retire before metadata; ordinary frames live in the outer owner.
    native: NativeProcessContext,
    policy: Policy,
    memory: [Option<Memory>; 3],
    tls: StaticTlsLayout,
    delayed_start: Option<(NativeSchedulerExecution, Completion)>,
    wait: Option<(NativeSchedulerExecution, Waiting)>,
    injected: bool,
    hold_worker: bool,
    joined: bool,
    revoked_children: usize,
    prepared: usize,
    rolled_back: Option<ThreadId>,
}

#[allow(clippy::too_many_lines)] // Keep root lifetime and the bounded scheduling script together.
fn run(
    accounting: &mut OwnedAccounting,
    allocation: &IsolatedAllocation,
    frames: &mut [Option<PhysicalRange>; 3],
    trace: &mut Trace,
) -> Result<(ThreadTable, ProcessId), ()> {
    if program::BODY_ENTRY >= program::CODE.len() as u64
        || program::WORKER_ENTRY >= program::CODE.len() as u64
    {
        return Err(());
    }
    frames[0] = Some(
        accounting
            .frames
            .allocate_contiguous(3, 1)
            .map_err(|_| ())?,
    );
    let plan = mappings(accounting, allocation, program::CODE)?;
    let root = troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
    let policy = Policy::new(root.stats().table_pages)?;
    let initial = policy.ids[0].ok_or(())?;
    let target = if cfg!(target_arch = "x86_64") {
        Target::X86_64
    } else {
        Target::Aarch64
    };
    let tls = StaticTlsLayout::new(target, 8, 24, 8, 1).map_err(|_| ())?;
    let first = Memory::new(0, initial, &policy.threads, frames[0].ok_or(())?, tls)?;
    for (offset, value) in [
        (0, 0x1234_5678_9abc_def0_u64),
        (104, SHARED),
        (120, policy.authority.handle.abi_value()),
    ] {
        troe_machine::copy_to_physical(allocation.data, offset, &value.to_le_bytes())
            .map_err(|_| ())?;
    }
    let reference = StartupReference {
        address: first.descriptor.address,
    }
    .encode()
    .map_err(|_| ())?;
    troe_machine::copy_to_physical(allocation.data, 80, &reference).map_err(|_| ())?;
    let mut native =
        NativeProcessContext::new(policy.owner(), root, 3, METADATA_LIMIT).map_err(|_| ())?;
    let baseline = native.stats();
    let metadata = native.metadata_bytes();
    trace.stage = "initial native admission";
    native
        .admit_prepared(
            &policy.threads,
            first.admission(initial),
            IpcPagePair::allocate().map_err(|_| ())?,
        )
        .map_err(|_| ())?;
    first.verify(&native, tls, 0)?;
    if native.resume_scheduled(&policy.threads, initial, 1).is_ok() {
        return Err(());
    }
    let mut f = Fixture {
        native,
        policy,
        memory: [Some(first), None, None],
        tls,
        delayed_start: None,
        wait: None,
        injected: false,
        hold_worker: false,
        joined: false,
        revoked_children: 0,
        prepared: 0,
        rolled_back: None,
    };
    f.policy
        .threads
        .start(f.policy.owner(), initial)
        .map_err(|_| ())?;
    let mut cursor = 0;
    for _ in 0..256 {
        trace.stage = "wait completion";
        f.finish_wait()?;
        if f.policy.ids.iter().all(Option::is_none) {
            break;
        }
        let index = (0..3)
            .map(|n| (cursor + n) % 3)
            .find(|index| {
                f.policy.ids[*index].is_some_and(|id| {
                    !(*index == 0 && f.delayed_start.is_some() || *index == 1 && f.hold_worker)
                        && f.policy
                            .threads
                            .snapshot(f.policy.owner(), id)
                            .is_ok_and(|s| s.state == ThreadState::Ready)
                })
            })
            .ok_or(())?;
        cursor = (index + 1) % 3;
        trace.caller = index;
        let id = f.policy.ids[index].ok_or(())?;
        f.policy
            .threads
            .dispatch(f.policy.owner(), id)
            .map_err(|_| ())?;
        trace.stage = "C execution";
        match f
            .native
            .resume_scheduled(&f.policy.threads, id, 50)
            .map_err(|_| ())?
        {
            NativeThreadStop::Preempted => f
                .policy
                .threads
                .yield_running(f.policy.owner(), id)
                .map_err(|_| ())?,
            NativeThreadStop::Yielded => {
                if index != 1 || f.delayed_start.is_none() {
                    return Err(());
                }
                f.memory[index]
                    .as_ref()
                    .ok_or(())?
                    .verify(&f.native, tls, 1)?;
                let (execution, completion) = f.delayed_start.take().ok_or(())?;
                f.publish(execution, completion)?;
                f.hold_worker = true;
                f.policy
                    .threads
                    .yield_running(f.policy.owner(), id)
                    .map_err(|_| ())?;
            }
            NativeThreadStop::SchedulerCall(call) => {
                let admitted = f
                    .policy
                    .authority
                    .dispatcher
                    .authorize_scheduler_owned_abi(
                        f.policy.authority.principal,
                        call.call().ok_or(())?.handle,
                        call.request_bytes().ok_or(())?,
                    )
                    .map_err(|_| ())?;
                trace.request = Some(admitted.request());
                let execution = f
                    .native
                    .claim_scheduler(call, admitted.request())
                    .map_err(|_| ())?;
                let operation =
                    Operation::bind(f.policy.authority.process, id, admitted).map_err(|_| ())?;
                trace.stage = "owned dispatch";
                let progress = operation
                    .execute(&mut f.policy.threads, &mut f.policy.sync, ZERO)
                    .map_err(|_| ())?;
                f.apply(index, progress, execution, accounting, frames, trace)?;
            }
            stop => {
                let _ = troe_machine::write(
                    alloc::format!("native creation unexpected stop: {stop:?}\n").as_bytes(),
                );
                return Err(());
            }
        }
    }
    trace.stage = "final resource accounting";
    if !f.policy.ids.iter().all(Option::is_none)
        || frames.iter().any(Option::is_some)
        || f.delayed_start.is_some()
        || f.wait.is_some()
        || !f.injected
        || !f.joined
        || f.prepared != 3
        || f.revoked_children != 1
        || f.native.stats().mapped_pages != baseline.mapped_pages
        || f.native.stats().table_pages != baseline.table_pages + 4
        || f.native.metadata_bytes() != metadata
        || f.policy.threads.committed_pages() != 0
    {
        return Err(());
    }
    f.native.stop();
    drop(f.native);
    let owner = f.policy.owner();
    f.policy
        .sync
        .stop_process(&mut f.policy.threads, owner)
        .map_err(|_| ())?;
    if f.policy.sync.usage(owner) != (0, 0) {
        return Err(());
    }
    f.policy.authority.revoke()?;
    Ok((f.policy.threads, owner))
}

impl Fixture {
    #[allow(clippy::needless_pass_by_value)] // Publication consumes the checked reply beside its claim.
    fn publish(
        &mut self,
        execution: NativeSchedulerExecution,
        completion: Completion,
    ) -> Result<(), ()> {
        if execution.caller() != completion.caller() || execution.request() != completion.request()
        {
            return Err(());
        }
        self.native
            .complete_scheduler_execution(execution, completion.response())
            .map_err(|_| ())
    }
    fn finish_wait(&mut self) -> Result<(), ()> {
        let Some((_, wait)) = &mut self.wait else {
            return Ok(());
        };
        if !wait
            .observe(&mut self.policy.threads, &mut self.policy.sync, ZERO)
            .map_err(|_| ())?
        {
            return Ok(());
        }
        let (execution, wait) = self.wait.take().ok_or(())?;
        let caller = wait.caller();
        let owner = self.policy.owner();
        self.policy
            .threads
            .dispatch(owner, caller)
            .map_err(|_| ())?;
        let completion = wait
            .finish(&mut self.policy.threads, &mut self.policy.sync)
            .map_err(|_| ())?;
        if completion.response().value != 0x7788 || self.revoked_children != 1 {
            return Err(());
        }
        let worker = self.policy.ids[1].ok_or(())?;
        self.policy.threads.reap(owner, worker).map_err(|_| ())?;
        self.policy.ids[1] = None;
        self.joined = true;
        self.publish(execution, completion)?;
        self.policy
            .threads
            .yield_running(owner, caller)
            .map_err(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        index: usize,
        progress: Progress,
        execution: NativeSchedulerExecution,
        accounting: &mut OwnedAccounting,
        frames: &mut [Option<PhysicalRange>; 3],
        trace: &mut Trace,
    ) -> Result<(), ()> {
        let owner = self.policy.owner();
        let caller = execution.caller();
        match progress {
            Progress::Complete(completion) => self.publish(execution, completion)?,
            Progress::Preparing(action) => {
                trace.stage = "native preparation";
                let completion = self.prepare(action, &execution, accounting, frames, trace)?;
                self.publish(execution, completion)?;
            }
            Progress::Starting(action) => {
                trace.stage = "native Start publication";
                if index != 0 || self.delayed_start.is_some() || self.prepared != 1 {
                    return Err(());
                }
                let completion = self
                    .native
                    .complete_start(&mut self.policy.threads, &execution, action)
                    .map_err(|_| ())?;
                self.delayed_start = Some((execution, completion));
            }
            Progress::Aborting(action) => {
                trace.stage = "creator Abort reclamation";
                if index != 1 || action.target() != self.policy.ids[2].ok_or(())? {
                    return Err(());
                }
                let (_, action) = action.finish(&mut self.policy.threads).err().ok_or(())?;
                self.discard(2, accounting, frames)?;
                let completion = action.finish(&mut self.policy.threads).map_err(|_| ())?;
                self.policy.ids[2] = None;
                self.publish(execution, completion)?;
            }
            Progress::Waiting(wait) => {
                if index != 0 || self.wait.is_some() || !self.hold_worker {
                    return Err(());
                }
                self.wait = Some((execution, wait));
                self.hold_worker = false;
                return Ok(());
            }
            Progress::Retiring(action) => {
                trace.stage = "thread Exit and revoked child reclamation";
                if action.disposition() != sync::ExitEffect::ThreadExiting || index == 2 {
                    return Err(());
                }
                let memory = self.memory[index].as_ref().ok_or(())?;
                memory.verify(&self.native, self.tls, 1)?;
                let receipt = self
                    .native
                    .retire_thread(execution, memory.backing())
                    .map_err(|_| ())?;
                if receipt.thread() != caller || receipt.ordinary_pages() != 3 {
                    return Err(());
                }
                action
                    .complete_thread(&mut self.policy.threads)
                    .map_err(|_| ())?;
                if index == 1 {
                    let (_, wait) = self.wait.as_mut().ok_or(())?;
                    if wait
                        .observe(&mut self.policy.threads, &mut self.policy.sync, ZERO)
                        .map_err(|_| ())?
                    {
                        return Err(());
                    }
                    let child = self.policy.ids[2].ok_or(())?;
                    if self
                        .policy
                        .threads
                        .snapshot(owner, child)
                        .map_err(|_| ())?
                        .state
                        != ThreadState::Revoked
                    {
                        return Err(());
                    }
                    self.memory[2]
                        .as_ref()
                        .ok_or(())?
                        .verify(&self.native, self.tls, 0)?;
                    self.discard(2, accounting, frames)?;
                    self.policy.threads.reap(owner, child).map_err(|_| ())?;
                    self.policy.ids[2] = None;
                    self.revoked_children += 1;
                }
                self.reclaim(index, accounting, frames)?;
                if index == 0 {
                    self.policy.threads.reap(owner, caller).map_err(|_| ())?;
                    self.policy.ids[index] = None;
                }
                return Ok(());
            }
        }
        self.policy
            .threads
            .yield_running(owner, caller)
            .map_err(|_| ())
    }

    fn discard(
        &mut self,
        index: usize,
        accounting: &mut OwnedAccounting,
        frames: &mut [Option<PhysicalRange>; 3],
    ) -> Result<(), ()> {
        let target = self.policy.ids[index].ok_or(())?;
        let memory = self.memory[index].as_ref().ok_or(())?;
        let receipt = self
            .native
            .discard_revoked(&self.policy.threads, target, memory.backing())
            .map_err(|_| ())?;
        if receipt.thread() != target || receipt.ordinary_pages() != 3 {
            return Err(());
        }
        self.reclaim(index, accounting, frames)
    }
    fn reclaim(
        &mut self,
        index: usize,
        accounting: &mut OwnedAccounting,
        frames: &mut [Option<PhysicalRange>; 3],
    ) -> Result<(), ()> {
        let range = frames[index].ok_or(())?;
        troe_machine::zero_physical_range(range).map_err(|_| ())?;
        accounting.frames.free_range(range).map_err(|_| ())?;
        frames[index] = None;
        self.memory[index] = None;
        let target = self.policy.ids[index].ok_or(())?;
        if self
            .policy
            .threads
            .release_resources(self.policy.owner(), target)
            .map_err(|_| ())?
            .pages
            != 5
        {
            return Err(());
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Keep provisional resources and rollback ordering explicit.
    fn prepare(
        &mut self,
        mut action: Preparing,
        execution: &NativeSchedulerExecution,
        accounting: &mut OwnedAccounting,
        frames: &mut [Option<PhysicalRange>; 3],
        trace: &mut Trace,
    ) -> Result<Completion, ()> {
        let Request::Prepare {
            entry_offset,
            argument,
            stack_pages,
        } = action.request()
        else {
            return Err(());
        };
        let owner = self.policy.owner();
        if entry_offset >= program::CODE.len() as u64 {
            return action
                .reject(&self.policy.threads, PrepareFailure::InvalidRequest)
                .map_err(|_| ());
        }
        if stack_pages != 1 || self.policy.threads.usage(owner).0 == 3 {
            return action
                .reject(&self.policy.threads, PrepareFailure::Exhausted)
                .map_err(|_| ());
        }
        let index = self.policy.ids.iter().position(Option::is_none).ok_or(())?;
        frames[index] = Some(
            accounting
                .frames
                .allocate_contiguous(3, 1)
                .map_err(|_| ())?,
        );
        let target = action
            .reserve(
                &mut self.policy.threads,
                ThreadResources {
                    reservation: index as u64 + 1,
                    pages: 5,
                },
            )
            .map_err(|_| ())?;
        self.policy.ids[index] = Some(target);
        let mut memory = Memory::new(
            index,
            target,
            &self.policy.threads,
            frames[index].ok_or(())?,
            self.tls,
        )?;
        memory.entry = USER_CODE_BASE + program::WORKER_ENTRY;
        memory.descriptor.entry = USER_CODE_BASE + entry_offset;
        memory.descriptor.argument = argument;
        self.memory[index] = Some(memory);
        trace.stage = "unmapped preparation cannot publish";
        let before = self.native.stats();
        let (_, retained) = self
            .native
            .complete_preparation(&self.policy.threads, execution, action, USER_CODE_BASE)
            .err()
            .ok_or(())?;
        action = retained;
        if self.native.stats() != before {
            return Err(());
        }
        if !self.injected {
            trace.stage = "IPC exhaustion and rollback";
            let mut held = Vec::new();
            held.try_reserve_exact(troe_machine::IPC_TASK_PAIRS)
                .map_err(|_| ())?;
            for _ in 0..troe_machine::IPC_TASK_PAIRS {
                match IpcPagePair::allocate() {
                    Ok(pair) => held.push(pair),
                    Err(_) => break,
                }
            }
            if held.len() + 1 != troe_machine::IPC_TASK_PAIRS || IpcPagePair::allocate().is_ok() {
                return Err(());
            }
            let rollback = action
                .revoke(&mut self.policy.threads, PrepareFailure::Exhausted)
                .map_err(|_| ())?;
            let (_, rollback) = rollback.finish(&mut self.policy.threads).err().ok_or(())?;
            if self.native.stats() != before
                || self
                    .native
                    .probe_leaf(
                        self.memory[index]
                            .as_ref()
                            .ok_or(())?
                            .descriptor
                            .stack_bottom,
                    )
                    .is_ok()
            {
                return Err(());
            }
            self.reclaim(index, accounting, frames)?;
            let completion = rollback.finish(&mut self.policy.threads).map_err(|_| ())?;
            self.policy.ids[index] = None;
            self.rolled_back = Some(target);
            self.injected = true;
            drop(held);
            return Ok(completion);
        }
        trace.stage = "prepared native mapping";
        if index == 1 {
            let old = self.rolled_back.ok_or(())?;
            if target.slot() != old.slot() || target.generation() != old.generation() + 1 {
                return Err(());
            }
        }
        let memory = self.memory[index].as_ref().ok_or(())?;
        self.native
            .admit_prepared(
                &self.policy.threads,
                memory.admission(target),
                IpcPagePair::allocate().map_err(|_| ())?,
            )
            .map_err(|_| ())?;
        memory.verify(&self.native, self.tls, 0)?;
        if self
            .native
            .resume_scheduled(&self.policy.threads, target, 1)
            .is_ok()
        {
            return Err(());
        }
        trace.stage = "copied entry correlation";
        let (_, action) = self
            .native
            .complete_preparation(
                &self.policy.threads,
                execution,
                action,
                USER_CODE_BASE + PAGE,
            )
            .err()
            .ok_or(())?;
        let completion = self
            .native
            .complete_preparation(&self.policy.threads, execution, action, USER_CODE_BASE)
            .map_err(|_| ())?;
        self.prepared += 1;
        Ok(completion)
    }
}

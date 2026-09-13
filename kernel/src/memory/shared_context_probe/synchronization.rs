//! Native synchronization requests, owned waits and faulted-wait retirement.

use super::{
    IsolatedAllocation, METADATA_LIMIT, PAGE, TX, allocate_isolated, allocate_pairs,
    pair_identities, prepare, reclaim_isolated, verify_reused, verify_rx_tail,
};
use crate::limits::USER_DATA_BASE;
use crate::machine::OwnedAccounting;
use troe_abi::threading::{Kind, Outcome, Request, Response, Token, Wait, WaitMode};
use troe_dispatch::{Dispatcher, Handle, HandleOwner, Rights, SchedulerInterface};
use troe_machine::{
    ApplicationResume, NativeProcessBacking, NativeProcessContext, NativeSchedulerExecution,
    NativeThreadStart, NativeThreadStop,
};
use troe_memory::PhysicalRange;
use troe_service::threading::Waiting;
use troe_service::threading::{Operation, Progress};
use troe_task::thread::ThreadState;
use troe_task::thread::{ThreadId, ThreadQuota, ThreadResources, ThreadTable, sync};
use troe_task::{
    Capabilities, ProcessName, ProcessOrigin, ProcessRegistration, ProcessTable, Scheduler,
    StackResource,
};
use troe_task::{MonotonicMillis, ProcessSnapshot};

// Each user program copies one 64-byte script request into its own TX, calls
// entry 6 and compares all 32 reply bytes against its expected record. It then
// increments a private TLS completion count. Failure exits with 1; only the
// explicit fault scenario traps after its final successful request.
#[cfg(target_arch = "x86_64")]
const SYNC_CODE: &[u8] = &[
    0x64, 0x4c, 0x8b, 0x24, 0x25, 0x08, 0x00, 0x00, 0x00, 0x64, 0x4c, 0x8b, 0x2c, 0x25, 0x18, 0x00,
    0x00, 0x00, 0x64, 0x4c, 0x8b, 0x34, 0x25, 0x30, 0x00, 0x00, 0x00, 0x31, 0xdb, 0x49, 0x8b, 0x04,
    0xdc, 0x49, 0x89, 0x44, 0xdd, 0x00, 0xff, 0xc3, 0x83, 0xfb, 0x08, 0x75, 0xf0, 0x64, 0x48, 0x8b,
    0x3c, 0x25, 0x28, 0x00, 0x00, 0x00, 0xbe, 0x40, 0x00, 0x00, 0x00, 0xba, 0x20, 0x00, 0x00, 0x00,
    0x45, 0x31, 0xd2, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9, 0xb8, 0x06, 0x00, 0x00, 0x00, 0xcd, 0x80,
    0x48, 0x85, 0xc0, 0x75, 0x52, 0x48, 0x83, 0xfa, 0x20, 0x75, 0x4c, 0x31, 0xdb, 0x49, 0x8b, 0x44,
    0xdc, 0x40, 0x49, 0x3b, 0x84, 0xdd, 0x00, 0x10, 0x00, 0x00, 0x75, 0x3b, 0xff, 0xc3, 0x83, 0xfb,
    0x04, 0x75, 0xea, 0x64, 0x48, 0xff, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, 0x49, 0x83, 0xc4, 0x60,
    0x49, 0xff, 0xce, 0x75, 0x96, 0x64, 0x48, 0xc7, 0x04, 0x25, 0x38, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x64, 0x48, 0x83, 0x3c, 0x25, 0x40, 0x00, 0x00, 0x00, 0x00, 0x75, 0x12, 0xb8, 0x01,
    0x00, 0x00, 0x00, 0xcd, 0x80, 0xeb, 0xf7, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xcd, 0x80,
    0x0f, 0x0b,
];
#[cfg(target_arch = "aarch64")]
const SYNC_CODE: &[u8] = &[
    0x56, 0xd0, 0x3b, 0xd5, 0xd4, 0x06, 0x40, 0xf9, 0xd5, 0x0e, 0x40, 0xf9, 0xd7, 0x1a, 0x40, 0xf9,
    0x8a, 0x2e, 0x40, 0xa9, 0xaa, 0x2e, 0x00, 0xa9, 0x8a, 0x2e, 0x41, 0xa9, 0xaa, 0x2e, 0x01, 0xa9,
    0x8a, 0x2e, 0x42, 0xa9, 0xaa, 0x2e, 0x02, 0xa9, 0x8a, 0x2e, 0x43, 0xa9, 0xaa, 0x2e, 0x03, 0xa9,
    0xc0, 0x16, 0x40, 0xf9, 0x01, 0x08, 0x80, 0xd2, 0x02, 0x04, 0x80, 0xd2, 0x03, 0x00, 0x80, 0xd2,
    0x04, 0x00, 0x80, 0xd2, 0x05, 0x00, 0x80, 0xd2, 0xc8, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
    0xa0, 0x03, 0x00, 0xb5, 0x3f, 0x80, 0x00, 0xf1, 0x61, 0x03, 0x00, 0x54, 0xb8, 0x06, 0x40, 0x91,
    0x8a, 0x2e, 0x44, 0xa9, 0x0c, 0x37, 0x40, 0xa9, 0x5f, 0x01, 0x0c, 0xeb, 0xc1, 0x02, 0x00, 0x54,
    0x7f, 0x01, 0x0d, 0xeb, 0x81, 0x02, 0x00, 0x54, 0x8a, 0x2e, 0x45, 0xa9, 0x0c, 0x37, 0x41, 0xa9,
    0x5f, 0x01, 0x0c, 0xeb, 0x01, 0x02, 0x00, 0x54, 0x7f, 0x01, 0x0d, 0xeb, 0xc1, 0x01, 0x00, 0x54,
    0xc9, 0x0a, 0x40, 0xf9, 0x29, 0x05, 0x00, 0x91, 0xc9, 0x0a, 0x00, 0xf9, 0x94, 0x82, 0x01, 0x91,
    0xf7, 0x06, 0x00, 0xf1, 0x61, 0xfb, 0xff, 0x54, 0x29, 0x00, 0x80, 0xd2, 0xc9, 0x1e, 0x00, 0xf9,
    0xc9, 0x22, 0x40, 0xf9, 0xe9, 0x00, 0x00, 0xb5, 0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
    0xfe, 0xff, 0xff, 0x17, 0x20, 0x00, 0x80, 0xd2, 0x08, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
    0x00, 0x00, 0x20, 0xd4,
];

const BLOCK: WaitMode = WaitMode::Wait(Wait {
    deadline: None,
    observe_stop: true,
});
const EXPIRED: Wait = Wait {
    deadline: Some(0),
    observe_stop: true,
};
const SCRIPT_OFFSETS: [usize; 2] = [0x100, 0x900];
const STEP_BYTES: usize = 96;
const MAX_STEPS: usize = 16;
const OPERATION_STORAGE_LIMIT: usize = 4096;
const _: () = {
    assert!(STEP_BYTES == troe_abi::threading::REQUEST_BYTES + troe_abi::threading::RESPONSE_BYTES);
    assert!(SCRIPT_OFFSETS[0] + MAX_STEPS * STEP_BYTES <= SCRIPT_OFFSETS[1]);
    assert!(SCRIPT_OFFSETS[1] + MAX_STEPS * STEP_BYTES <= 4096);
};

#[derive(Clone, Copy)]
struct Step {
    request: Request,
    outcome: Outcome,
}

struct Script {
    steps: [Option<Step>; MAX_STEPS],
    len: usize,
}
impl Script {
    fn new() -> Self {
        Self {
            steps: [None; MAX_STEPS],
            len: 0,
        }
    }
    fn push(&mut self, request: Request, outcome: Outcome) -> Result<(), ()> {
        *self.steps.get_mut(self.len).ok_or(())? = Some(Step { request, outcome });
        self.len += 1;
        Ok(())
    }
    fn get(&self, index: usize) -> Result<Step, ()> {
        self.steps.get(index).and_then(|step| *step).ok_or(())
    }
}

// Both values are owned and non-cloneable. No dispatcher/table borrow spans
// execution of the sibling; finishing the policy wait cannot replay its request.
struct Pending {
    execution: NativeSchedulerExecution,
    wait: Waiting,
}

struct Probe {
    process: ProcessSnapshot,
    threads: ThreadTable,
    sync: sync::SyncTable,
    dispatcher: Dispatcher<'static>,
    handle: Handle,
    ids: [ThreadId; 2],
}

impl Probe {
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
                name: ProcessName::new("native-sync-probe").map_err(|_| ())?,
                origin: ProcessOrigin::Foreground,
                started_millis: 0,
                table_pages,
                private_pages: 10,
                handles: 1,
            })
            .map_err(|_| ())?;
        let process = processes.snapshots().next().ok_or(())?;
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
        threads.start(owner, second).map_err(|_| ())?;
        let mut sync = sync::SyncTable::new(1, 3, 2, METADATA_LIMIT).map_err(|_| ())?;
        sync.register_process(
            &mut threads,
            owner,
            sync::SyncQuota {
                objects: 3,
                waits: 2,
            },
        )
        .map_err(|_| ())?;
        let mut dispatcher = Dispatcher::new(1, 1).map_err(|_| ())?;
        let principal = HandleOwner::isolated(task_id.get()).map_err(|_| ())?;
        let handle = dispatcher
            .open_scheduler_owned(SchedulerInterface::SyncV1, Rights::CALL, principal)
            .map_err(|_| ())?;
        Ok(Self {
            process,
            threads,
            sync,
            dispatcher,
            handle,
            ids: [first, second],
        })
    }

    #[allow(clippy::too_many_lines)]
    fn scripts(&mut self, fault: bool) -> Result<[Script; 2], ()> {
        let owner = self.process.id();
        let caller = self.ids[0];
        let mutex = self
            .sync
            .create_mutex(&mut self.threads, owner, caller, sync::OwnerDeath::Poison)
            .map_err(|_| ())?;
        let mutex = identity(Kind::Mutex, mutex.slot(), mutex.generation())?;
        let mut first = Script::new();
        let mut second = Script::new();
        first.push(
            Request::Lock {
                mutex,
                wait: WaitMode::Try,
            },
            Outcome::Success,
        )?;
        second.push(Request::Lock { mutex, wait: BLOCK }, Outcome::Success)?;
        if !fault {
            let condition = self
                .sync
                .create_condition(&mut self.threads, owner, caller)
                .map_err(|_| ())?;
            let condition = identity(Kind::Condition, condition.slot(), condition.generation())?;
            let permit = self
                .sync
                .create_permit(&mut self.threads, owner, caller, 0, 2)
                .map_err(|_| ())?;
            let permit = identity(Kind::Permit, permit.slot(), permit.generation())?;
            first.push(
                Request::ConditionWait {
                    condition,
                    mutex,
                    wait: Wait {
                        deadline: None,
                        observe_stop: true,
                    },
                },
                Outcome::Success,
            )?;
            first.push(Request::Unlock(mutex), Outcome::Success)?;
            first.push(
                Request::AcquirePermit {
                    permit,
                    wait: BLOCK,
                },
                Outcome::Success,
            )?;
            first.push(
                Request::ReleasePermit { permit, count: 2 },
                Outcome::Success,
            )?;
            first.push(
                Request::ReleasePermit { permit, count: 1 },
                Outcome::Overflow,
            )?;
            first.push(
                Request::AcquirePermit {
                    permit,
                    wait: WaitMode::Try,
                },
                Outcome::Success,
            )?;
            first.push(
                Request::AcquirePermit {
                    permit,
                    wait: WaitMode::Try,
                },
                Outcome::Success,
            )?;
            first.push(
                Request::AcquirePermit {
                    permit,
                    wait: WaitMode::Wait(EXPIRED),
                },
                Outcome::TimedOut,
            )?;
            first.push(
                Request::Lock {
                    mutex,
                    wait: WaitMode::Try,
                },
                Outcome::Success,
            )?;
            first.push(
                Request::ConditionWait {
                    condition,
                    mutex,
                    wait: EXPIRED,
                },
                Outcome::TimedOut,
            )?;
            first.push(Request::Unlock(mutex), Outcome::Success)?;
            first.push(Request::DestroyCondition(condition), Outcome::Success)?;
            first.push(Request::DestroyMutex(mutex), Outcome::Success)?;
            first.push(Request::DestroyPermit(permit), Outcome::Success)?;
            second.push(
                Request::Notify {
                    condition,
                    all: true,
                },
                Outcome::Success,
            )?;
            second.push(Request::Unlock(mutex), Outcome::Success)?;
            // This immediate timeout lets the sibling publish its permit wait
            // before release; there is no sleep or timing-dependent handoff.
            second.push(
                Request::AcquirePermit {
                    permit,
                    wait: WaitMode::Wait(EXPIRED),
                },
                Outcome::TimedOut,
            )?;
            second.push(
                Request::ReleasePermit { permit, count: 1 },
                Outcome::Success,
            )?;
        }
        self.threads.yield_running(owner, caller).map_err(|_| ())?;
        Ok([first, second])
    }

    #[allow(clippy::needless_pass_by_value)] // Publication consumes both owned records.
    fn publish(
        &self,
        native: &mut NativeProcessContext,
        execution: NativeSchedulerExecution,
        completion: troe_service::threading::Completion,
        index: usize,
        expected: Step,
    ) -> Result<(), ()> {
        if completion.caller() != self.ids[index]
            || completion.request() != expected.request
            || execution.caller() != completion.caller()
            || execution.request() != completion.request()
            || completion.response() != response(expected.outcome)
        {
            return Err(());
        }
        native
            .complete_scheduler_execution(execution, completion.response())
            .map_err(|_| ())?;
        verify_rx_tail(native, TX[index], 32)
    }

    #[allow(clippy::too_many_lines)]
    fn run(
        &mut self,
        native: &mut NativeProcessContext,
        starts: [NativeThreadStart; 2],
        scripts: &[Script; 2],
        fault: bool,
    ) -> Result<(), ()> {
        let owner = self.process.id();
        let principal = HandleOwner::isolated(self.process.task_id().get()).map_err(|_| ())?;
        let mut pending: [Option<Pending>; 2] = core::array::from_fn(|_| None);
        let mut calls = [0_usize; 2];
        let mut done = [false; 2];
        let mut waits = 0;
        for _ in 0..64 {
            for operation in pending.iter_mut().flatten() {
                operation
                    .wait
                    .observe(&mut self.threads, &mut self.sync, now()?)
                    .map_err(|_| ())?;
            }
            let mut progressed = false;
            for (index, id) in self.ids.into_iter().enumerate() {
                if done[index]
                    || self.threads.snapshot(owner, id).map_err(|_| ())?.state != ThreadState::Ready
                {
                    continue;
                }
                progressed = true;
                self.threads.dispatch(owner, id).map_err(|_| ())?;
                if let Some(operation) = pending[index].take() {
                    let completion = operation
                        .wait
                        .finish(&mut self.threads, &mut self.sync)
                        .map_err(|_| ())?;
                    self.publish(
                        native,
                        operation.execution,
                        completion,
                        index,
                        scripts[index].get(calls[index].checked_sub(1).ok_or(())?)?,
                    )?;
                }
                // Preemption does not reorder this deterministic operation
                // schedule; retries use a bounded fixture-only execution slice.
                let mut stop = None;
                for _ in 0..128 {
                    let result = native
                        .resume(id, ApplicationResume::Timeslice, 50)
                        .map_err(|_| ())?;
                    if result != NativeThreadStop::Preempted {
                        stop = Some(result);
                        break;
                    }
                }
                match stop.ok_or(())? {
                    NativeThreadStop::SchedulerCall(captured) => {
                        let expected = scripts[index].get(calls[index])?;
                        if captured.caller() != id
                            || captured
                                .request(troe_abi::interface::THREAD_SYNC)
                                .map_err(|_| ())?
                                != expected.request
                        {
                            return Err(());
                        }
                        let admitted = self
                            .dispatcher
                            .authorize_scheduler_owned_abi(
                                principal,
                                captured.call().ok_or(())?.handle,
                                captured.request_bytes().ok_or(())?,
                            )
                            .map_err(|_| ())?;
                        let execution = native
                            .claim_scheduler(captured, admitted.request())
                            .map_err(|_| ())?;
                        let operation =
                            Operation::bind(self.process, id, admitted).map_err(|_| ())?;
                        calls[index] += 1;
                        match operation
                            .execute(&mut self.threads, &mut self.sync, now()?)
                            .map_err(|_| ())?
                        {
                            Progress::Complete(completion) => {
                                self.publish(native, execution, completion, index, expected)?;
                                self.threads.yield_running(owner, id).map_err(|_| ())?;
                            }
                            Progress::Waiting(wait) => {
                                let before = native.probe_word(TX[index] + PAGE).map_err(|_| ())?;
                                if wait.caller() != id
                                    || pending[index].is_some()
                                    || self.threads.snapshot(owner, id).map_err(|_| ())?.state
                                        != ThreadState::Blocked
                                    || native.claim_scheduler(captured, expected.request).is_ok()
                                    || native.complete_scheduler(captured, None).is_ok()
                                    || native.probe_word(TX[index] + PAGE).map_err(|_| ())?
                                        != before
                                {
                                    return Err(());
                                }
                                pending[index] = Some(Pending { execution, wait });
                                waits += 1;
                            }
                        }
                    }
                    NativeThreadStop::Yielded => {
                        if fault
                            || calls[index] != scripts[index].len
                            || native
                                .probe_word(starts[index].thread_pointer + 16)
                                .map_err(|_| ())?
                                != calls[index] as u64
                            || native
                                .probe_word(starts[index].thread_pointer + 56)
                                .map_err(|_| ())?
                                != 1
                        {
                            return Err(());
                        }
                        self.threads.yield_running(owner, id).map_err(|_| ())?;
                        done[index] = true;
                    }
                    NativeThreadStop::ProcessFaulted(
                        troe_machine::IsolatedFault::IllegalInstruction,
                    ) if fault && index == 0 => {
                        if waits != 1
                            || calls != [1, 1]
                            || pending[0].is_some()
                            || native
                                .probe_word(starts[0].thread_pointer + 16)
                                .map_err(|_| ())?
                                != 1
                            || native
                                .probe_word(starts[1].thread_pointer + 16)
                                .map_err(|_| ())?
                                != 0
                        {
                            return Err(());
                        }
                        return self.retire_fault(native, pending[1].take().ok_or(())?);
                    }
                    _ => return Err(()),
                }
            }
            if done == [true; 2] {
                if waits != 3
                    || pending.iter().any(Option::is_some)
                    || self.sync.usage(owner) != (0, 0)
                {
                    return Err(());
                }
                native.stop();
                self.sync
                    .stop_process(&mut self.threads, owner)
                    .map_err(|_| ())?;
                return Ok(());
            }
            if !progressed {
                return Err(());
            }
        }
        Err(())
    }

    fn retire_fault(
        &mut self,
        native: &mut NativeProcessContext,
        mut pending: Pending,
    ) -> Result<(), ()> {
        if !native.is_stopped() || self.sync.usage(self.process.id()) != (1, 1) {
            return Err(());
        }
        let before = native.probe_word(TX[1] + PAGE).map_err(|_| ())?;
        self.sync
            .stop_process(&mut self.threads, self.process.id())
            .map_err(|_| ())?;
        if pending
            .wait
            .observe(&mut self.threads, &mut self.sync, now()?)
            .is_ok()
            || pending
                .wait
                .finish(&mut self.threads, &mut self.sync)
                .is_ok()
        {
            return Err(());
        }
        let (error, execution) = native
            .complete_scheduler_execution(pending.execution, response(Outcome::Success))
            .err()
            .ok_or(())?;
        if error != troe_machine::MmuError::InvalidUserContext
            || execution.caller() != self.ids[1]
            || native.probe_word(TX[1] + PAGE).map_err(|_| ())? != before
            || self.sync.usage(self.process.id()) != (0, 0)
            || self.threads.committed_pages() != 8
            || self
                .ids
                .into_iter()
                .any(|id| native.resume(id, ApplicationResume::Timeslice, 50).is_ok())
        {
            return Err(());
        }
        Ok(())
    }
}

pub(super) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    for fault in [false, true] {
        verify_case(accounting, fault)?;
    }
    Ok(())
}

fn verify_case(accounting: &mut OwnedAccounting, fault: bool) -> Result<(), ()> {
    let free = accounting.frames.free_frames();
    let allocation = allocate_isolated(&mut accounting.frames)?;
    let result = (|| {
        let pairs = allocate_pairs()?;
        let identities = pair_identities(&pairs);
        let (plan, starts) = prepare(&allocation, &accounting.kernel_plan, &pairs, SYNC_CODE)?;
        let root =
            troe_machine::build_user_address_space(&plan, allocation.tables).map_err(|_| ())?;
        let mut probe = Probe::new(root.stats().table_pages)?;
        let scripts = probe.scripts(fault)?;
        // Fixed pending slots include both owned native claims and policy waits;
        // fixture request/response scripts are also bounded in this explicit budget.
        if core::mem::size_of::<[Option<Pending>; 2]>() + core::mem::size_of_val(&scripts)
            > OPERATION_STORAGE_LIMIT
        {
            return Err(());
        }
        install_scripts(&allocation, &scripts, probe.handle, fault)?;
        let mut native = NativeProcessContext::with_backing(
            probe.process.id(),
            NativeProcessBacking::new(root, pairs),
            2,
            METADATA_LIMIT,
        )
        .map_err(|_| ())?;
        let baseline = (
            native.stats(),
            native.metadata_bytes(),
            probe.threads.metadata_bytes(),
            probe.sync.metadata_bytes(),
        );
        for (index, id) in probe.ids.into_iter().enumerate() {
            native.prepare(id, starts[index]).map_err(|_| ())?;
            native
                .bind_thread_ipc(id, index, TX[index])
                .map_err(|_| ())?;
            native.publish_thread_rx(id, &[]).map_err(|_| ())?;
        }
        probe.run(&mut native, starts, &scripts, fault)?;
        if !native.is_stopped()
            || baseline
                != (
                    native.stats(),
                    native.metadata_bytes(),
                    probe.threads.metadata_bytes(),
                    probe.sync.metadata_bytes(),
                )
        {
            return Err(());
        }
        let principal = HandleOwner::isolated(probe.process.task_id().get()).map_err(|_| ())?;
        if probe.dispatcher.close_owner(principal).map_err(|_| ())? != 1
            || probe.dispatcher.stats().live_handles != 0
            || probe.dispatcher.stats().live_ports != 0
        {
            return Err(());
        }
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
        Ok(probe)
    })();
    let reclaimed = reclaim_isolated(&mut accounting.frames, allocation);
    let mut probe = result?;
    reclaimed?;
    for id in probe.ids {
        if probe
            .threads
            .release_resources(probe.process.id(), id)
            .map_err(|_| ())?
            .pages
            != 4
        {
            return Err(());
        }
        probe.threads.reap(probe.process.id(), id).map_err(|_| ())?;
    }
    probe
        .threads
        .remove_process(probe.process.id())
        .map_err(|_| ())?;
    if probe.threads.committed_pages() != 0 || accounting.frames.free_frames() != free {
        return Err(());
    }
    Ok(())
}

fn install_scripts(
    allocation: &IsolatedAllocation,
    scripts: &[Script; 2],
    handle: Handle,
    fault: bool,
) -> Result<(), ()> {
    for (index, script) in scripts.iter().enumerate() {
        if script.len == 0 || script.len > MAX_STEPS {
            return Err(());
        }
        for step in 0..script.len {
            let record = script.get(step)?;
            let offset = SCRIPT_OFFSETS[index] + step * STEP_BYTES;
            troe_machine::copy_to_physical(
                allocation.data,
                offset,
                &record.request.encode().map_err(|_| ())?,
            )
            .map_err(|_| ())?;
            troe_machine::copy_to_physical(
                allocation.data,
                offset + 64,
                &response(record.outcome)
                    .encode(record.request)
                    .map_err(|_| ())?,
            )
            .map_err(|_| ())?;
        }
        let tls =
            PhysicalRange::from_pages(allocation.stack.start() + (index as u64 + 2) * PAGE, 1)
                .map_err(|_| ())?;
        for (offset, value) in [
            (8, USER_DATA_BASE + SCRIPT_OFFSETS[index] as u64),
            (40, handle.abi_value()),
            (48, script.len as u64),
            (64, u64::from(fault && index == 0)),
        ] {
            troe_machine::copy_to_physical(tls, offset, &value.to_le_bytes()).map_err(|_| ())?;
        }
    }
    Ok(())
}

fn identity(kind: Kind, slot: usize, generation: u32) -> Result<Token, ()> {
    Token::new(kind, u32::try_from(slot).map_err(|_| ())?, generation).map_err(|_| ())
}
fn response(outcome: Outcome) -> Response {
    Response {
        outcome,
        value: 0,
        snapshot: None,
    }
}
fn now() -> Result<MonotonicMillis, ()> {
    troe_machine::monotonic_millis()
        .map(MonotonicMillis::from_millis)
        .ok_or(())
}

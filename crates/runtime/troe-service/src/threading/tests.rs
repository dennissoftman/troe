use super::*;
use troe_dispatch::{Dispatcher, Handle, Rights, SchedulerInterface};
use troe_task::thread::{ThreadQuota, ThreadResources};
use troe_task::{
    Capabilities, ProcessName, ProcessOrigin, ProcessRegistration, ProcessTable, Scheduler,
    StackResource,
};

mod exit;

struct Harness {
    processes: [ProcessSnapshot; 2],
    threads: ThreadTable,
    sync: sync::SyncTable,
    dispatcher: Dispatcher<'static>,
    handles: [[Handle; 2]; 2],
    ids: [ThreadId; 4],
    now: u64,
}

impl Harness {
    #[allow(clippy::too_many_lines)]
    fn new() -> Result<Self, ()> {
        let mut scheduler = Scheduler::new(2).map_err(|_| ())?;
        let mut registry = ProcessTable::new(2).map_err(|_| ())?;
        for slot in 0..2 {
            let task_id = scheduler
                .spawn(
                    Capabilities::SERVICE,
                    StackResource::new(slot, 1).map_err(|_| ())?,
                )
                .map_err(|_| ())?;
            registry
                .register(ProcessRegistration {
                    task_id,
                    name: ProcessName::new("thread-call-test").map_err(|_| ())?,
                    origin: ProcessOrigin::Foreground,
                    started_millis: 0,
                    table_pages: 1,
                    private_pages: 1,
                    handles: 0,
                })
                .map_err(|_| ())?;
        }
        let mut snapshots = registry.snapshots();
        let processes = [snapshots.next().ok_or(())?, snapshots.next().ok_or(())?];
        let mut threads = ThreadTable::new(2, 6, 32, 16384).map_err(|_| ())?;
        let mut sync = sync::SyncTable::new(2, 8, 4, 16384).map_err(|_| ())?;
        let mut dispatcher = Dispatcher::new(1, 4).map_err(|_| ())?;
        let mut handles = std::vec::Vec::new();
        for (index, process) in processes.into_iter().enumerate() {
            let owner = process.id();
            threads
                .register_process(
                    owner,
                    ThreadQuota {
                        records: 3,
                        pages: 16,
                    },
                )
                .map_err(|_| ())?;
            sync.register_process(
                &mut threads,
                owner,
                sync::SyncQuota {
                    objects: if index == 0 { 6 } else { 2 },
                    waits: if index == 0 { 3 } else { 1 },
                },
            )
            .map_err(|_| ())?;
            let principal = HandleOwner::isolated(process.task_id().get()).map_err(|_| ())?;
            let control = dispatcher
                .open_scheduler_owned(
                    SchedulerInterface::ControlV1,
                    Rights::CALL
                        .union(Rights::THREAD_OBSERVE)
                        .union(Rights::THREAD_STOP)
                        .union(Rights::THREAD_CREATE)
                        .union(Rights::THREAD_START)
                        .union(Rights::THREAD_JOIN)
                        .union(Rights::THREAD_DETACH),
                    principal,
                )
                .map_err(|_| ())?;
            let synchronization = dispatcher
                .open_scheduler_owned(SchedulerInterface::SyncV1, Rights::CALL, principal)
                .map_err(|_| ())?;
            handles.push([control, synchronization]);
        }
        let owner = processes[0].id();
        let initial = threads
            .prepare_initial(
                owner,
                ThreadResources {
                    reservation: 1,
                    pages: 2,
                },
            )
            .map_err(|_| ())?;
        threads.start(owner, initial).map_err(|_| ())?;
        threads.dispatch(owner, initial).map_err(|_| ())?;
        let mut ids = [initial; 4];
        for (index, id) in ids.iter_mut().enumerate().take(3).skip(1) {
            *id = threads
                .prepare_worker(
                    owner,
                    initial,
                    ThreadResources {
                        reservation: index as u64 + 1,
                        pages: 2,
                    },
                )
                .map_err(|_| ())?;
            threads.start(owner, *id).map_err(|_| ())?;
        }
        let other = processes[1].id();
        ids[3] = threads
            .prepare_initial(
                other,
                ThreadResources {
                    reservation: 4,
                    pages: 2,
                },
            )
            .map_err(|_| ())?;
        threads.start(other, ids[3]).map_err(|_| ())?;
        Ok(Self {
            processes,
            threads,
            sync,
            dispatcher,
            handles: handles.try_into().map_err(|_| ())?,
            ids,
            now: 0,
        })
    }

    fn select(&mut self, index: usize) -> Result<(), ()> {
        for id in self.ids {
            if self
                .threads
                .snapshot(id.process(), id)
                .map_err(|_| ())?
                .state
                == ThreadState::Running
            {
                self.threads
                    .yield_running(id.process(), id)
                    .map_err(|_| ())?;
            }
        }
        let id = self.ids[index];
        self.threads.dispatch(id.process(), id).map_err(|_| ())
    }

    fn authorize(&self, index: usize, request: Request) -> Result<AuthorizedSchedulerCall, ()> {
        let process = self.processes[usize::from(index == 3)];
        let principal = HandleOwner::isolated(process.task_id().get()).map_err(|_| ())?;
        let handle = self.handles[usize::from(index == 3)]
            [usize::from(request.interface() == wire_interface_sync())];
        let mut bytes = request.encode().map_err(|_| ())?;
        let result = self
            .dispatcher
            .authorize_scheduler_owned_abi(principal, handle.abi_value(), &bytes)
            .map_err(|_| ())?;
        bytes.fill(0xa5);
        assert_eq!(result.request(), request);
        Ok(result)
    }

    fn operation(&self, index: usize, request: Request) -> Result<Operation, ()> {
        Operation::bind(
            self.processes[usize::from(index == 3)],
            self.ids[index],
            self.authorize(index, request)?,
        )
        .map_err(|_| ())
    }

    fn run(&mut self, index: usize, request: Request) -> Result<Progress, ()> {
        self.operation(index, request)?
            .execute(
                &mut self.threads,
                &mut self.sync,
                MonotonicMillis::from_millis(self.now),
            )
            .map_err(|_| ())
    }

    fn response(
        &mut self,
        index: usize,
        request: Request,
        outcome: Outcome,
    ) -> Result<Response, ()> {
        let Progress::Complete(result) = self.run(index, request)? else {
            return Err(());
        };
        assert_eq!(result.caller(), self.ids[index]);
        assert_eq!(result.request(), request);
        let response = result.response();
        assert_eq!(response.outcome, outcome);
        assert_eq!(
            Response::decode(request, &response.encode(request).map_err(|_| ())?),
            Ok(response)
        );
        Ok(response)
    }

    fn create(&mut self, index: usize, request: Request) -> Result<Token, ()> {
        Token::decode(self.response(index, request, Outcome::Success)?.value).map_err(|_| ())
    }

    fn wait(&mut self, index: usize, request: Request) -> Result<Waiting, ()> {
        let Progress::Waiting(wait) = self.run(index, request)? else {
            return Err(());
        };
        assert_eq!(wait.caller(), self.ids[index]);
        assert_eq!(
            self.threads
                .snapshot(self.ids[index].process(), self.ids[index])
                .map_err(|_| ())?
                .state,
            ThreadState::Blocked
        );
        Ok(wait)
    }

    fn finish(&mut self, index: usize, wait: Waiting, outcome: Outcome) -> Result<(), ()> {
        self.select(index)?;
        let result = wait
            .finish(&mut self.threads, &mut self.sync)
            .map_err(|_| ())?;
        assert_eq!(result.caller(), self.ids[index]);
        assert_eq!(result.response().outcome, outcome);
        assert!(result.response().encode(result.request()).is_ok());
        Ok(())
    }
}

const fn wire_interface_sync() -> u32 {
    troe_abi::interface::THREAD_SYNC
}
const WAIT: wire::Wait = wire::Wait {
    deadline: None,
    observe_stop: true,
};
const TRY: wire::WaitMode = wire::WaitMode::Try;
const BLOCK: wire::WaitMode = wire::WaitMode::Wait(WAIT);

#[test]
fn binding_rejects_foreign_principals_and_threads_without_effects() -> Result<(), ()> {
    let h = Harness::new()?;
    for (process, caller, principal) in [(0, 0, 3), (0, 3, 0), (1, 0, 3)] {
        assert_eq!(
            Operation::bind(
                h.processes[process],
                h.ids[caller],
                h.authorize(principal, Request::Current)?
            ),
            Err(Error::Binding)
        );
    }
    assert_eq!(h.sync.usage(h.processes[0].id()), (0, 0));
    Ok(())
}

#[test]
fn current_observe_and_stop_use_captured_caller_and_live_target() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let initial = h.create(0, Request::Current)?;
    let snapshot = h
        .response(0, Request::Observe(initial), Outcome::Success)?
        .snapshot
        .ok_or(())?;
    assert_eq!(snapshot.state, wire::State::Running);
    assert!(!snapshot.stop_requested);
    h.response(0, Request::RequestStop(initial), Outcome::Success)?;
    assert!(
        h.response(0, Request::Observe(initial), Outcome::Success)?
            .snapshot
            .ok_or(())?
            .stop_requested
    );
    h.select(1)?;
    let worker = h.create(1, Request::Current)?;
    assert_ne!(initial, worker);
    h.select(3)?;
    h.response(3, Request::Observe(initial), Outcome::Stale)?;
    h.response(3, Request::RequestStop(worker), Outcome::Stale)?;
    assert!(
        !h.threads
            .snapshot(h.ids[1].process(), h.ids[1])
            .map_err(|_| ())?
            .stop_requested
    );
    Ok(())
}

#[test]
fn unimplemented_lifecycle_operations_do_not_publish_or_change_state() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let token = h.create(0, Request::Current)?;
    let before = h
        .threads
        .snapshot(h.ids[0].process(), h.ids[0])
        .map_err(|_| ())?;
    for request in [
        Request::Prepare {
            entry_offset: 0,
            argument: u64::MAX,
            stack_pages: 1,
        },
        Request::Start(token),
        Request::Abort(token),
    ] {
        h.response(0, request, Outcome::Unsupported)?;
        assert_eq!(
            h.threads
                .snapshot(h.ids[0].process(), h.ids[0])
                .map_err(|_| ())?,
            before
        );
    }
    h.response(1, Request::CreateCondition, Outcome::InvalidState)?;
    assert_eq!(h.sync.usage(h.ids[0].process()), (0, 0));
    Ok(())
}

#[test]
fn mutex_wait_retains_authority_and_blocks_new_calls_until_consumed() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let mutex = h.create(0, Request::CreateMutex(wire::OwnerDeath::Poison))?;
    h.response(0, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
    h.response(0, Request::Lock { mutex, wait: TRY }, Outcome::Deadlock)?;
    h.select(1)?;
    h.response(1, Request::Unlock(mutex), Outcome::NotOwner)?;
    h.response(1, Request::Lock { mutex, wait: TRY }, Outcome::WouldBlock)?;
    let wait = h.wait(1, Request::Lock { mutex, wait: BLOCK })?;
    let (error, wait) = wait.finish(&mut h.threads, &mut h.sync).err().ok_or(())?;
    assert_eq!(
        error,
        Error::Sync(sync::SyncError::Thread(ThreadError::InvalidState))
    );
    h.select(0)?;
    h.response(0, Request::Unlock(mutex), Outcome::Success)?;
    h.response(0, Request::DestroyMutex(mutex), Outcome::Busy)?;
    h.select(1)?;
    h.response(1, Request::Current, Outcome::Busy)?;
    h.response(1, Request::Unlock(mutex), Outcome::Busy)?;
    let completion = wait.finish(&mut h.threads, &mut h.sync).map_err(|_| ())?;
    assert_eq!(completion.response().outcome, Outcome::Success);
    h.response(1, Request::Unlock(mutex), Outcome::Success)?;
    h.response(1, Request::DestroyMutex(mutex), Outcome::Success)?;
    h.response(1, Request::Lock { mutex, wait: TRY }, Outcome::Stale)?;
    Ok(())
}

#[test]
fn condition_timeout_reacquires_and_retains_destroy_reference() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let mutex = h.create(0, Request::CreateMutex(wire::OwnerDeath::Poison))?;
    let condition = h.create(0, Request::CreateCondition)?;
    h.response(0, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
    let mut wait = h.wait(
        0,
        Request::ConditionWait {
            condition,
            mutex,
            wait: wire::Wait {
                deadline: Some(5),
                observe_stop: true,
            },
        },
    )?;
    h.select(1)?;
    h.response(1, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
    h.now = 5;
    assert!(
        wait.observe(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(5))
            .map_err(|_| ())?
    );
    h.response(
        1,
        Request::Notify {
            condition,
            all: true,
        },
        Outcome::Success,
    )?;
    h.response(1, Request::DestroyCondition(condition), Outcome::Busy)?;
    assert_eq!(
        h.threads
            .snapshot(h.ids[0].process(), h.ids[0])
            .map_err(|_| ())?
            .state,
        ThreadState::Blocked
    );
    h.response(1, Request::Unlock(mutex), Outcome::Success)?;
    h.now = u64::MAX;
    assert!(
        !wait
            .observe(
                &mut h.threads,
                &mut h.sync,
                MonotonicMillis::from_millis(u64::MAX)
            )
            .map_err(|_| ())?
    );
    h.finish(0, wait, Outcome::TimedOut)?;
    h.response(0, Request::Unlock(mutex), Outcome::Success)?;
    h.response(0, Request::DestroyCondition(condition), Outcome::Success)?;
    h.response(0, Request::DestroyMutex(mutex), Outcome::Success)?;
    assert_eq!(h.sync.usage(h.ids[0].process()), (0, 0));
    Ok(())
}

#[test]
fn notification_and_stop_preserve_selected_condition_result() -> Result<(), ()> {
    for stopped in [false, true] {
        let mut h = Harness::new()?;
        let caller = h.create(0, Request::Current)?;
        let mutex = h.create(0, Request::CreateMutex(wire::OwnerDeath::Poison))?;
        let condition = h.create(0, Request::CreateCondition)?;
        h.response(0, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
        let mut wait = h.wait(
            0,
            Request::ConditionWait {
                condition,
                mutex,
                wait: WAIT,
            },
        )?;
        h.select(1)?;
        h.response(1, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
        if stopped {
            h.response(1, Request::RequestStop(caller), Outcome::Success)?;
        }
        h.response(
            1,
            Request::Notify {
                condition,
                all: false,
            },
            Outcome::Success,
        )?;
        h.response(1, Request::RequestStop(caller), Outcome::Success)?;
        assert!(
            !wait
                .observe(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(0))
                .map_err(|_| ())?
        );
        h.response(1, Request::Unlock(mutex), Outcome::Success)?;
        h.finish(
            0,
            wait,
            if stopped {
                Outcome::Stopped
            } else {
                Outcome::Success
            },
        )?;
        h.response(0, Request::Unlock(mutex), Outcome::Success)?;
    }
    Ok(())
}

#[test]
fn permit_batch_overflow_has_no_partial_grant_and_tokens_cannot_change_kind() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let permit = h.create(
        0,
        Request::CreatePermit {
            count: 0,
            maximum: 1,
        },
    )?;
    let wait = h.wait(
        0,
        Request::AcquirePermit {
            permit,
            wait: BLOCK,
        },
    )?;
    h.select(1)?;
    h.response(
        1,
        Request::ReleasePermit { permit, count: 3 },
        Outcome::Overflow,
    )?;
    assert_eq!(
        h.threads
            .snapshot(h.ids[0].process(), h.ids[0])
            .map_err(|_| ())?
            .state,
        ThreadState::Blocked
    );
    h.response(
        1,
        Request::AcquirePermit { permit, wait: TRY },
        Outcome::WouldBlock,
    )?;
    h.response(
        1,
        Request::ReleasePermit { permit, count: 2 },
        Outcome::Success,
    )?;
    h.response(
        1,
        Request::AcquirePermit { permit, wait: TRY },
        Outcome::Success,
    )?;
    h.response(1, Request::DestroyPermit(permit), Outcome::Busy)?;
    h.finish(0, wait, Outcome::Success)?;
    h.response(0, Request::DestroyPermit(permit), Outcome::Success)?;
    let condition = h.create(0, Request::CreateCondition)?;
    assert_eq!(condition.slot(), permit.slot());
    assert_ne!(condition.generation(), permit.generation());
    let forged =
        Token::new(Kind::Permit, condition.slot(), condition.generation()).map_err(|_| ())?;
    for token in [permit, forged] {
        h.response(
            0,
            Request::ReleasePermit {
                permit: token,
                count: 1,
            },
            Outcome::Stale,
        )?;
    }
    h.select(3)?;
    h.response(3, Request::DestroyCondition(condition), Outcome::Stale)?;
    Ok(())
}

#[test]
fn expired_or_stopped_wait_never_consumes_an_available_permit() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let caller = h.create(0, Request::Current)?;
    let permit = h.create(
        0,
        Request::CreatePermit {
            count: 1,
            maximum: 1,
        },
    )?;
    h.response(
        0,
        Request::AcquirePermit {
            permit,
            wait: wire::WaitMode::Wait(wire::Wait {
                deadline: Some(0),
                observe_stop: false,
            }),
        },
        Outcome::TimedOut,
    )?;
    h.response(0, Request::RequestStop(caller), Outcome::Success)?;
    h.response(
        0,
        Request::AcquirePermit {
            permit,
            wait: BLOCK,
        },
        Outcome::Stopped,
    )?;
    h.response(
        0,
        Request::AcquirePermit { permit, wait: TRY },
        Outcome::Success,
    )?;
    h.response(
        0,
        Request::AcquirePermit { permit, wait: TRY },
        Outcome::WouldBlock,
    )?;
    Ok(())
}

#[test]
fn quota_failure_preserves_foreign_process_capacity() -> Result<(), ()> {
    let mut h = Harness::new()?;
    for _ in 0..6 {
        h.create(0, Request::CreateCondition)?;
    }
    h.response(
        0,
        Request::CreateMutex(wire::OwnerDeath::FailProcess),
        Outcome::Exhausted,
    )?;
    h.select(3)?;
    h.create(3, Request::CreateMutex(wire::OwnerDeath::FailProcess))?;
    assert_eq!(h.sync.usage(h.processes[0].id()), (6, 0));
    assert_eq!(h.sync.usage(h.processes[1].id()), (1, 0));
    Ok(())
}

#[test]
fn poison_returns_no_ownership_and_essential_owner_death_retires_waits() -> Result<(), ()> {
    for essential in [false, true] {
        let mut h = Harness::new()?;
        let mutex = h.create(
            0,
            Request::CreateMutex(if essential {
                wire::OwnerDeath::FailProcess
            } else {
                wire::OwnerDeath::Poison
            }),
        )?;
        h.response(0, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
        h.select(1)?;
        let mut wait = h.wait(1, Request::Lock { mutex, wait: BLOCK })?;
        h.select(0)?;
        let owner = h.ids[0].process();
        let Progress::Retiring(retiring) = h.run(0, Request::Exit(42))? else {
            return Err(());
        };
        let effect = retiring.disposition();
        if essential {
            assert_eq!(effect, sync::ExitEffect::ProcessStopped);
            assert!(retiring.complete_thread(&mut h.threads).is_err());
            assert!(
                wait.observe(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(0))
                    .is_err()
            );
            assert!(wait.finish(&mut h.threads, &mut h.sync).is_err());
            h.response(1, Request::Current, Outcome::Stopping)?;
            assert_eq!(h.sync.usage(owner), (0, 0));
        } else {
            assert_eq!(effect, sync::ExitEffect::ThreadExiting);
            retiring.complete_thread(&mut h.threads).map_err(|_| ())?;
            h.finish(1, wait, Outcome::Poisoned)?;
            h.response(1, Request::Unlock(mutex), Outcome::NotOwner)?;
            h.response(1, Request::Lock { mutex, wait: TRY }, Outcome::Poisoned)?;
            h.response(1, Request::DestroyMutex(mutex), Outcome::Success)?;
        }
    }
    Ok(())
}

#[test]
fn authority_revocation_prevents_new_admission_but_preserves_owned_operation() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let operation = h.operation(0, Request::CreateCondition)?;
    let principal = HandleOwner::isolated(h.processes[0].task_id().get()).map_err(|_| ())?;
    assert_eq!(h.dispatcher.close_owner(principal).map_err(|_| ())?, 2);
    assert!(h.authorize(0, Request::CreateCondition).is_err());
    let Progress::Complete(completion) = operation
        .execute(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(0))
        .map_err(|_| ())?
    else {
        return Err(());
    };
    assert_eq!(completion.response().outcome, Outcome::Success);
    assert_eq!(h.sync.usage(h.ids[0].process()), (1, 0));
    Ok(())
}

#[test]
fn clock_regression_is_composition_failure_without_an_application_reply() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let permit = h.create(
        0,
        Request::CreatePermit {
            count: 0,
            maximum: 1,
        },
    )?;
    h.now = 10;
    h.response(
        0,
        Request::AcquirePermit { permit, wait: TRY },
        Outcome::WouldBlock,
    )?;
    let operation = h.operation(0, Request::ReleasePermit { permit, count: 1 })?;
    assert_eq!(
        operation.execute(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(9)),
        Err(Error::Sync(sync::SyncError::ClockRegressed))
    );
    h.response(
        0,
        Request::AcquirePermit { permit, wait: TRY },
        Outcome::WouldBlock,
    )?;
    Ok(())
}

#[test]
fn condition_binding_failure_preserves_the_callers_other_mutex() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let first = h.create(0, Request::CreateMutex(wire::OwnerDeath::Poison))?;
    let second = h.create(0, Request::CreateMutex(wire::OwnerDeath::Poison))?;
    let condition = h.create(0, Request::CreateCondition)?;
    h.response(
        0,
        Request::Lock {
            mutex: first,
            wait: TRY,
        },
        Outcome::Success,
    )?;
    let wait = h.wait(
        0,
        Request::ConditionWait {
            condition,
            mutex: first,
            wait: WAIT,
        },
    )?;
    h.select(1)?;
    h.response(
        1,
        Request::Lock {
            mutex: second,
            wait: TRY,
        },
        Outcome::Success,
    )?;
    h.response(
        1,
        Request::ConditionWait {
            condition,
            mutex: second,
            wait: WAIT,
        },
        Outcome::DifferentMutex,
    )?;
    h.response(1, Request::Unlock(second), Outcome::Success)?;
    h.response(
        1,
        Request::Notify {
            condition,
            all: false,
        },
        Outcome::Success,
    )?;
    h.finish(0, wait, Outcome::Success)?;
    h.response(0, Request::Unlock(first), Outcome::Success)?;
    Ok(())
}

#[test]
fn broadcast_grants_the_current_cohort_in_fifo_reacquisition_order() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let mutex = h.create(0, Request::CreateMutex(wire::OwnerDeath::Poison))?;
    let condition = h.create(0, Request::CreateCondition)?;
    h.response(0, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
    let first = h.wait(
        0,
        Request::ConditionWait {
            condition,
            mutex,
            wait: WAIT,
        },
    )?;
    h.select(1)?;
    h.response(1, Request::Lock { mutex, wait: TRY }, Outcome::Success)?;
    let second = h.wait(
        1,
        Request::ConditionWait {
            condition,
            mutex,
            wait: WAIT,
        },
    )?;
    h.select(2)?;
    h.response(
        2,
        Request::Notify {
            condition,
            all: true,
        },
        Outcome::Success,
    )?;
    assert_eq!(
        h.threads
            .snapshot(h.ids[0].process(), h.ids[0])
            .map_err(|_| ())?
            .state,
        ThreadState::Ready
    );
    assert_eq!(
        h.threads
            .snapshot(h.ids[1].process(), h.ids[1])
            .map_err(|_| ())?
            .state,
        ThreadState::Blocked
    );
    h.response(2, Request::DestroyCondition(condition), Outcome::Busy)?;
    h.finish(0, first, Outcome::Success)?;
    h.response(0, Request::Unlock(mutex), Outcome::Success)?;
    h.finish(1, second, Outcome::Success)?;
    h.response(1, Request::Unlock(mutex), Outcome::Success)?;
    h.response(1, Request::DestroyCondition(condition), Outcome::Success)?;
    Ok(())
}

#[test]
fn mismatched_table_configuration_fails_without_publishing_an_object() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let operation = h.operation(0, Request::CreateCondition)?;
    let mut unrelated = sync::SyncTable::new(1, 1, 1, 4096).map_err(|_| ())?;
    assert_eq!(
        operation.execute(
            &mut h.threads,
            &mut unrelated,
            MonotonicMillis::from_millis(0)
        ),
        Err(Error::Sync(sync::SyncError::UnknownProcess))
    );
    assert_eq!(unrelated.usage(h.ids[0].process()), (0, 0));
    assert_eq!(h.sync.usage(h.ids[0].process()), (0, 0));
    Ok(())
}

#[test]
fn owned_join_dispatch_waits_for_quiescence_and_returns_the_scalar_once() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let caller = h.create(0, Request::Current)?;
    h.response(
        0,
        Request::Join {
            thread: caller,
            wait: TRY,
        },
        Outcome::Deadlock,
    )?;
    h.select(1)?;
    let target = h.create(1, Request::Current)?;
    h.select(0)?;
    h.response(
        0,
        Request::Join {
            thread: target,
            wait: TRY,
        },
        Outcome::WouldBlock,
    )?;
    let mut wait = h.wait(
        0,
        Request::Join {
            thread: target,
            wait: BLOCK,
        },
    )?;
    h.select(2)?;
    h.response(2, Request::Detach(target), Outcome::Busy)?;
    h.response(
        2,
        Request::Join {
            thread: target,
            wait: TRY,
        },
        Outcome::Busy,
    )?;
    h.select(1)?;
    let owner = h.ids[1].process();
    h.sync
        .begin_exit(
            &mut h.threads,
            owner,
            h.ids[1],
            MonotonicMillis::from_millis(0),
        )
        .map_err(|_| ())?;
    h.threads
        .complete(owner, h.ids[1], u64::MAX)
        .map_err(|_| ())?;
    assert!(
        !wait
            .observe(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(1))
            .map_err(|_| ())?
    );
    h.threads
        .release_resources(owner, h.ids[1])
        .map_err(|_| ())?;
    assert!(
        wait.observe(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(2))
            .map_err(|_| ())?
    );
    h.select(0)?;
    h.response(0, Request::Current, Outcome::Busy)?;
    let result = wait.finish(&mut h.threads, &mut h.sync).map_err(|_| ())?;
    assert_eq!(
        result.request(),
        Request::Join {
            thread: target,
            wait: BLOCK
        }
    );
    assert_eq!(result.response(), reply(Outcome::Success, u64::MAX));
    assert!(result.response().encode(result.request()).is_ok());
    h.response(
        0,
        Request::Join {
            thread: target,
            wait: TRY,
        },
        Outcome::Busy,
    )?;
    Ok(())
}

#[test]
fn timed_join_releases_claim_and_a_later_try_can_consume_the_result() -> Result<(), ()> {
    let mut h = Harness::new()?;
    h.select(1)?;
    let target = h.create(1, Request::Current)?;
    h.select(0)?;
    let options = wire::Wait {
        deadline: Some(5),
        observe_stop: true,
    };
    let mut wait = h.wait(
        0,
        Request::Join {
            thread: target,
            wait: wire::WaitMode::Wait(options),
        },
    )?;
    h.select(1)?;
    let owner = h.ids[1].process();
    h.sync
        .begin_exit(
            &mut h.threads,
            owner,
            h.ids[1],
            MonotonicMillis::from_millis(0),
        )
        .map_err(|_| ())?;
    h.threads.complete(owner, h.ids[1], 42).map_err(|_| ())?;
    assert!(
        wait.observe(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(5))
            .map_err(|_| ())?
    );
    h.finish(0, wait, Outcome::TimedOut)?;
    h.response(
        0,
        Request::Join {
            thread: target,
            wait: TRY,
        },
        Outcome::WouldBlock,
    )?;
    h.threads
        .release_resources(owner, h.ids[1])
        .map_err(|_| ())?;
    assert_eq!(
        h.response(
            0,
            Request::Join {
                thread: target,
                wait: TRY
            },
            Outcome::Success
        )?
        .value,
        42
    );
    Ok(())
}

#[test]
fn sleep_dispatch_keeps_its_owned_wait_through_early_finish_and_stop() -> Result<(), ()> {
    let mut h = Harness::new()?;
    let caller = h.create(0, Request::Current)?;
    let request = Request::Sleep(wire::Wait {
        deadline: Some(10),
        observe_stop: true,
    });
    let wait = h.wait(0, request)?;
    let (error, mut wait) = wait.finish(&mut h.threads, &mut h.sync).err().ok_or(())?;
    assert_eq!(
        error,
        Error::Control(control::Error::Thread(ThreadError::InvalidState))
    );
    h.select(1)?;
    assert!(
        !wait
            .observe(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(5))
            .map_err(|_| ())?
    );
    h.response(1, Request::RequestStop(caller), Outcome::Success)?;
    assert!(
        wait.observe(&mut h.threads, &mut h.sync, MonotonicMillis::from_millis(6))
            .map_err(|_| ())?
    );
    assert!(
        !wait
            .observe(
                &mut h.threads,
                &mut h.sync,
                MonotonicMillis::from_millis(10)
            )
            .map_err(|_| ())?
    );
    h.select(0)?;
    h.response(0, Request::Exit(42), Outcome::Busy)?;
    h.finish(0, wait, Outcome::Stopped)?;
    Ok(())
}

#[test]
fn detached_and_foreign_join_targets_do_not_acquire_authority() -> Result<(), ()> {
    let mut h = Harness::new()?;
    h.select(1)?;
    let target = h.create(1, Request::Current)?;
    h.select(0)?;
    h.response(0, Request::Detach(target), Outcome::Success)?;
    h.response(
        0,
        Request::Join {
            thread: target,
            wait: TRY,
        },
        Outcome::Busy,
    )?;
    h.select(3)?;
    h.response(3, Request::Detach(target), Outcome::Stale)?;
    h.response(
        3,
        Request::Join {
            thread: target,
            wait: TRY,
        },
        Outcome::Stale,
    )?;
    Ok(())
}

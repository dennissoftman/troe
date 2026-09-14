use super::*;
use crate::{
    ProcessName, ProcessOrigin, ProcessRegistration, ProcessTable,
    thread::{ThreadQuota, ThreadResources, ThreadTable},
};

extern crate std;
fn checked<T, E>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|_| std::process::abort())
}

fn callers() -> (ProcessSnapshot, ProcessSnapshot, [PendingCaller; 2]) {
    let mut processes = checked(ProcessTable::new(2));
    for task in [TaskId(1), TaskId(2)] {
        checked(processes.register(ProcessRegistration {
            task_id: task,
            name: checked(ProcessName::new("wait-test")),
            origin: ProcessOrigin::Foreground,
            started_millis: 0,
            table_pages: 1,
            private_pages: 8,
            handles: 1,
        }));
    }
    let process = checked(processes.snapshot_for_task(TaskId(1)));
    let other = checked(processes.snapshot_for_task(TaskId(2)));
    let mut threads = checked(ThreadTable::new(1, 2, 16, usize::MAX));
    checked(threads.register_process(
        process.id(),
        ThreadQuota {
            records: 2,
            pages: 16,
        },
    ));
    let initial = checked(threads.prepare_initial(
        process.id(),
        ThreadResources {
            reservation: 1,
            pages: 2,
        },
    ));
    checked(threads.start(process.id(), initial));
    checked(threads.dispatch(process.id(), initial));
    let worker = checked(threads.prepare_worker(
        process.id(),
        initial,
        ThreadResources {
            reservation: 2,
            pages: 2,
        },
    ));
    (
        process,
        other,
        [
            checked(PendingCaller::threaded(process, initial)),
            checked(PendingCaller::threaded(process, worker)),
        ],
    )
}

#[test]
fn siblings_share_task_authority_but_not_pending_call_identity() {
    let (process, other, [first, second]) = callers();
    assert_eq!(
        PendingCaller::threaded(
            other,
            first.thread_id().unwrap_or_else(|| std::process::abort())
        ),
        Err(PendingCallError::InvalidCaller)
    );
    let mut pending = checked(PendingCallTable::new(2, 32));
    let a = checked(pending.begin_for(first, 1, 9, 1, b"first", 16));
    assert_eq!(
        pending.begin_for(first, 2, 9, 1, b"duplicate", 16),
        Err(PendingCallError::OwnerAlreadyPending)
    );
    assert_eq!(
        pending.begin(process.task_id(), 2, 9, 1, b"legacy", 16),
        Err(PendingCallError::OwnerAlreadyPending)
    );
    let b = checked(pending.begin_for(second, 2, 9, 1, b"second", 16));
    assert_ne!(a, b);
    assert_eq!(checked(pending.call(a)).caller(), first);
    assert_eq!(checked(pending.call(b)).owner(), process.task_id());
    assert_eq!(checked(pending.request(a)), b"first");
    assert_eq!(checked(pending.request(b)), b"second");
}

#[test]
fn one_resource_observation_cannot_complete_a_sibling_or_foreign_generation() {
    let (_, _, owners) = callers();
    let mut pending = checked(PendingCallTable::new(2, 32));
    let mut waits = checked(WaitTable::new(2));
    let metadata = (pending.metadata_bytes(), waits.metadata_bytes());
    let resource = checked(WaitResource::new(44, 1));
    let mut operations = [None; 2];
    for (index, owner) in owners.into_iter().enumerate() {
        let op = checked(pending.begin_for(owner, index as u64 + 1, 9, 1, b"request", 16));
        let spec = checked(WaitSpec::new_for(
            owner,
            op,
            Some(resource),
            WakeInterest::RESOURCE_READY,
            None,
        ));
        let WaitRegistration::Blocked(key) =
            checked(waits.register(spec, WaitObservation::Pending, MonotonicMillis(0)))
        else {
            std::process::abort()
        };
        checked(pending.bind_wait(op, key));
        operations[index] = Some(op);
    }
    let [a, b] = operations.map(|operation| operation.unwrap_or_else(|| std::process::abort()));
    assert_eq!(
        waits.observe_operation(
            a,
            Some(checked(WaitResource::new(44, 2))),
            WaitObservation::ResourceReady,
            MonotonicMillis(0)
        ),
        Err(WaitError::InvalidResource)
    );
    let completion = checked(waits.observe_operation(
        a,
        Some(resource),
        WaitObservation::ResourceReady,
        MonotonicMillis(0),
    ))
    .unwrap_or_else(|| std::process::abort());
    let mut wrong = completion;
    wrong.owner = owners[1];
    assert_eq!(
        pending.resolve(wrong),
        Err(PendingCallError::MismatchedWake)
    );
    checked(pending.resolve(completion));
    assert!(matches!(
        checked(pending.call(b)).state(),
        PendingCallState::Waiting(_)
    ));
    assert_eq!(
        checked(waits.observe_operation(
            b,
            Some(resource),
            WaitObservation::Pending,
            MonotonicMillis(0)
        )),
        None
    );
    checked(pending.finish(a));
    let fresh = checked(pending.begin_for(owners[0], 3, 9, 1, b"new", 16));
    assert_eq!(a.slot(), fresh.slot());
    assert_ne!(a.generation(), fresh.generation());
    assert_eq!(
        pending.resolve(completion),
        Err(PendingCallError::StaleOperation)
    );
    assert_eq!(metadata, (pending.metadata_bytes(), waits.metadata_bytes()));
}

#[test]
fn stopped_process_discards_all_sibling_waits_and_zeroes_requests_without_growth() {
    let (process, _, owners) = callers();
    let mut pending = checked(PendingCallTable::new(2, 32));
    let mut waits = checked(WaitTable::new(2));
    let metadata = (pending.metadata_bytes(), waits.metadata_bytes());
    let mut old = Vec::new();
    for (index, owner) in owners.into_iter().enumerate() {
        let op = checked(pending.begin_for(owner, index as u64 + 1, 9, 1, b"secret", 16));
        let spec = checked(WaitSpec::new_for(
            owner,
            op,
            None,
            WakeInterest::DEADLINE,
            Some(MonotonicMillis(10)),
        ));
        let WaitRegistration::Blocked(key) =
            checked(waits.register(spec, WaitObservation::Pending, MonotonicMillis(0)))
        else {
            std::process::abort()
        };
        checked(pending.bind_wait(op, key));
        old.push(op);
    }
    assert_eq!(
        checked(waits.discard_owner(process.task_id(), WakeReason::Revoked)),
        2
    );
    assert_eq!(
        checked(pending.teardown_owner(process.task_id(), WakeReason::Revoked)),
        2
    );
    assert_eq!(waits.stats().live, 0);
    assert_eq!(pending.stats().retained_bytes, 0);
    assert_eq!(pending.stats().zeroized_bytes, 12);
    assert!(
        pending
            .slots
            .iter()
            .all(|slot| slot.request.iter().all(|byte| *byte == 0))
    );
    for op in old {
        assert_eq!(
            waits.observe_operation(op, None, WaitObservation::Pending, MonotonicMillis(11)),
            Err(WaitError::StaleWait)
        );
    }
    assert_eq!(metadata, (pending.metadata_bytes(), waits.metadata_bytes()));
    // Legacy exclusive task ownership is available again after complete disposal.
    checked(pending.begin(process.task_id(), 3, 9, 1, b"legacy", 16));
    assert_eq!(
        pending.begin_for(owners[0], 4, 9, 1, b"thread", 16),
        Err(PendingCallError::OwnerAlreadyPending)
    );
}

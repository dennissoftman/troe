use super::*;
use crate::thread::{ThreadQuota, ThreadResources, sync};

const OWNER: ProcessId = ProcessId(1);
const WAIT: WaitOptions = WaitOptions {
    deadline: None,
    observe_stop: true,
};

fn at(millis: u64) -> MonotonicMillis {
    MonotonicMillis::from_millis(millis)
}
fn setup() -> Result<(ThreadTable, [ThreadId; 3]), ThreadError> {
    let mut table = ThreadTable::new(2, 4, 16, 16384)?;
    table.register_process(
        OWNER,
        ThreadQuota {
            records: 3,
            pages: 12,
        },
    )?;
    let first = table.prepare_initial(
        OWNER,
        ThreadResources {
            reservation: 1,
            pages: 2,
        },
    )?;
    table.start(OWNER, first)?;
    table.dispatch(OWNER, first)?;
    let second = table.prepare_worker(
        OWNER,
        first,
        ThreadResources {
            reservation: 2,
            pages: 2,
        },
    )?;
    let third = table.prepare_worker(
        OWNER,
        first,
        ThreadResources {
            reservation: 3,
            pages: 2,
        },
    )?;
    table.start(OWNER, second)?;
    table.start(OWNER, third)?;
    Ok((table, [first, second, third]))
}
fn select(table: &mut ThreadTable, chosen: ThreadId) -> Result<(), ThreadError> {
    let current = table
        .slots
        .iter()
        .filter_map(|slot| slot.record.as_ref())
        .find(|record| record.snapshot.state == ThreadState::Running)
        .map(|record| record.snapshot.id);
    if let Some(current) = current {
        table.yield_running(current.process(), current)?;
    }
    table.dispatch(chosen.process(), chosen)
}
fn pending(start: Start) -> Result<Waiting, Error> {
    match start {
        Start::Waiting(wait) => Ok(wait),
        Start::Complete(_) => Err(ThreadError::InvalidState.into()),
    }
}
fn finish(mut wait: Waiting, table: &mut ThreadTable) -> Result<Outcome, Error> {
    let outcome = wait.finish(table)?;
    assert_eq!(wait.deadline(), None);
    assert_eq!(wait.finish(table), Err(Error::Thread(ThreadError::Stale)));
    Ok(outcome)
}

#[test]
fn early_waits_and_unsuccessful_tries_have_no_claim_or_sequence_effects() -> Result<(), Error> {
    let (mut table, [caller, target, _]) = setup()?;
    let before = (
        table.next_join,
        table.record(OWNER, caller)?.wait_sequence,
        table.usage(OWNER),
    );
    assert_eq!(
        table.join(OWNER, caller, target, WaitMode::Try, at(0))?,
        Start::Complete(Outcome::WouldBlock)
    );
    let expired = WaitOptions {
        deadline: Some(at(0)),
        observe_stop: false,
    };
    assert_eq!(
        table.join(OWNER, caller, target, WaitMode::Wait(expired), at(0))?,
        Start::Complete(Outcome::TimedOut)
    );
    assert_eq!(
        table.sleep(OWNER, caller, expired, at(0))?,
        Start::Complete(Outcome::TimedOut)
    );
    table.request_stop(OWNER, caller)?;
    assert_eq!(
        table.sleep(
            OWNER,
            caller,
            WaitOptions {
                observe_stop: true,
                ..expired
            },
            at(0)
        )?,
        Start::Complete(Outcome::TimedOut)
    );
    assert_eq!(
        table.join(OWNER, caller, target, WaitMode::Wait(WAIT), at(0))?,
        Start::Complete(Outcome::Stopped)
    );
    assert_eq!(
        table.sleep(OWNER, caller, WAIT, at(0))?,
        Start::Complete(Outcome::Stopped)
    );
    assert_eq!(
        before,
        (
            table.next_join,
            table.record(OWNER, caller)?.wait_sequence,
            table.usage(OWNER)
        )
    );
    assert!(table.record(OWNER, target)?.incoming_join.is_none());
    assert!(!table.record(OWNER, caller)?.control_wait);
    Ok(())
}

#[test]
fn join_waits_for_physical_ack_and_retains_result_after_target_reuse() -> Result<(), Error> {
    let (mut table, [caller, target, helper]) = setup()?;
    let metadata = table.metadata_bytes();
    let mut wait = pending(table.join(OWNER, caller, target, WaitMode::Wait(WAIT), at(1))?)?;
    assert_eq!(wait.caller(), caller);
    assert!(!wait.observe(&mut table, at(2))?);
    select(&mut table, target)?;
    table.begin_exit(OWNER, target)?;
    table.complete(OWNER, target, u64::MAX)?;
    assert!(!wait.observe(&mut table, at(3))?);
    assert_eq!(table.snapshot(OWNER, caller)?.state, ThreadState::Blocked);
    table.release_resources(OWNER, target)?;
    assert!(wait.observe(&mut table, at(4))?);
    table.reap(OWNER, target)?;
    select(&mut table, helper)?;
    let replacement = table.prepare_worker(
        OWNER,
        helper,
        ThreadResources {
            reservation: 4,
            pages: 2,
        },
    )?;
    assert_eq!(replacement.slot(), target.slot());
    assert_ne!(replacement.generation(), target.generation());
    table.request_stop(OWNER, caller)?;
    assert!(!wait.observe(&mut table, at(u64::MAX))?);
    select(&mut table, caller)?;
    assert_eq!(
        table.validate_running(OWNER, caller),
        Err(ThreadError::Busy)
    );
    assert_eq!(finish(wait, &mut table)?, Outcome::Joined(u64::MAX));
    table.validate_running(OWNER, caller)?;
    assert_eq!(table.metadata_bytes(), metadata);
    Ok(())
}

#[test]
fn timeout_cancels_only_its_claim_and_leaves_quiescent_result_available() -> Result<(), Error> {
    let (mut table, [caller, target, _]) = setup()?;
    let mut wait = pending(table.join(
        OWNER,
        caller,
        target,
        WaitMode::Wait(WaitOptions {
            deadline: Some(at(5)),
            observe_stop: true,
        }),
        at(0),
    )?)?;
    assert_eq!(wait.deadline(), Some(at(5)));
    select(&mut table, target)?;
    table.begin_exit(OWNER, target)?;
    table.complete(OWNER, target, 91)?;
    table.release_resources(OWNER, target)?;
    // A target that became quiescent but whose result has not been committed
    // cannot beat an expired absolute deadline at the observation point.
    assert!(wait.observe(&mut table, at(5))?);
    assert_eq!(wait.deadline(), None);
    select(&mut table, caller)?;
    assert_eq!(finish(wait, &mut table)?, Outcome::TimedOut);
    assert_eq!(
        table.join(OWNER, caller, target, WaitMode::Try, at(6))?,
        Start::Complete(Outcome::Joined(91))
    );
    assert_eq!(
        table.join(OWNER, caller, target, WaitMode::Try, at(6)),
        Err(ThreadError::Busy)
    );
    Ok(())
}

#[test]
fn stop_and_detach_race_relinquishes_claim_without_consuming_completion() -> Result<(), Error> {
    let (mut table, [caller, target, helper]) = setup()?;
    let mut wait = pending(table.join(OWNER, caller, target, WaitMode::Wait(WAIT), at(0))?)?;
    assert_eq!(table.detach(OWNER, target), Err(ThreadError::Busy));
    select(&mut table, helper)?;
    assert_eq!(
        table.join(OWNER, helper, target, WaitMode::Try, at(0)),
        Err(ThreadError::Busy)
    );
    table.request_stop(OWNER, caller)?;
    assert!(wait.observe(&mut table, at(1))?);
    table.detach(OWNER, target)?;
    select(&mut table, caller)?;
    assert_eq!(finish(wait, &mut table)?, Outcome::Stopped);
    assert_eq!(
        table.join(OWNER, caller, target, WaitMode::Try, at(2)),
        Err(ThreadError::Busy)
    );
    Ok(())
}

#[test]
fn sleep_preserves_absolute_deadline_and_result_across_stop_and_early_finish() -> Result<(), Error>
{
    let (mut table, [caller, _, helper]) = setup()?;
    let mut wait = pending(table.sleep(
        OWNER,
        caller,
        WaitOptions {
            deadline: Some(at(u64::MAX)),
            observe_stop: false,
        },
        at(7),
    )?)?;
    let error = wait
        .finish(&mut table)
        .err()
        .ok_or(ThreadError::InvalidState)?;
    assert_eq!(error, Error::Thread(ThreadError::InvalidState));
    select(&mut table, helper)?;
    table.request_stop(OWNER, caller)?;
    assert!(!wait.observe(&mut table, at(u64::MAX - 1))?);
    assert_eq!(wait.deadline(), Some(at(u64::MAX)));
    assert!(wait.observe(&mut table, at(u64::MAX))?);
    assert_eq!(wait.deadline(), None);
    assert!(!wait.observe(&mut table, at(u64::MAX))?);
    select(&mut table, caller)?;
    assert_eq!(table.block(OWNER, caller), Err(ThreadError::Busy));
    assert_eq!(finish(wait, &mut table)?, Outcome::TimedOut);
    table.validate_running(OWNER, caller)?;
    Ok(())
}

#[test]
fn clock_regression_cannot_wake_cancel_or_consume_a_join() -> Result<(), Error> {
    let (mut table, [caller, target, _]) = setup()?;
    let mut wait = pending(table.join(OWNER, caller, target, WaitMode::Wait(WAIT), at(10))?)?;
    let claim = table.record(OWNER, target)?.incoming_join;
    table.request_stop(OWNER, caller)?;
    assert_eq!(wait.observe(&mut table, at(9)), Err(Error::ClockRegressed));
    assert_eq!(table.record(OWNER, target)?.incoming_join, claim);
    assert_eq!(table.snapshot(OWNER, caller)?.state, ThreadState::Blocked);
    assert!(wait.observe(&mut table, at(10))?);
    assert_eq!(wait.observe(&mut table, at(9)), Err(Error::ClockRegressed));
    select(&mut table, caller)?;
    assert_eq!(finish(wait, &mut table)?, Outcome::Stopped);
    Ok(())
}

#[test]
fn exhausted_wait_or_claim_identity_fails_before_join_publication() -> Result<(), Error> {
    for exhausted_wait in [false, true] {
        let (mut table, [caller, target, _]) = setup()?;
        if exhausted_wait {
            table.record_mut(OWNER, caller)?.wait_sequence = u64::MAX;
        } else {
            table.next_join = u64::MAX;
        }
        let before = (table.next_join, table.record(OWNER, caller)?.wait_sequence);
        assert_eq!(
            table.join(OWNER, caller, target, WaitMode::Wait(WAIT), at(0)),
            Err(ThreadError::Exhausted)
        );
        assert_eq!(
            before,
            (table.next_join, table.record(OWNER, caller)?.wait_sequence)
        );
        assert!(table.record(OWNER, target)?.incoming_join.is_none());
        assert!(!table.record(OWNER, caller)?.control_wait);
        assert_eq!(table.snapshot(OWNER, caller)?.state, ThreadState::Running);
    }
    Ok(())
}

#[test]
fn ordinary_wake_and_sync_exit_cannot_bypass_an_unconsumed_control_wait() -> Result<(), Error> {
    let (mut table, [caller, _, _]) = setup()?;
    let mut sync = sync::SyncTable::new(1, 1, 1, 4096).map_err(|_| ThreadError::InvalidState)?;
    sync.register_process(
        &mut table,
        OWNER,
        sync::SyncQuota {
            objects: 1,
            waits: 1,
        },
    )
    .map_err(|_| ThreadError::InvalidState)?;
    let mutex = sync
        .create_mutex(&mut table, OWNER, caller, sync::OwnerDeath::FailProcess)
        .map_err(|_| ThreadError::InvalidState)?;
    sync.lock(&mut table, OWNER, caller, mutex, WaitMode::Try, at(0))
        .map_err(|_| ThreadError::InvalidState)?;
    let mut wait = pending(table.sleep(
        OWNER,
        caller,
        WaitOptions {
            deadline: Some(at(1)),
            observe_stop: false,
        },
        at(0),
    )?)?;
    assert_eq!(table.wake(OWNER, wait.token), Err(ThreadError::Busy));
    assert!(wait.observe(&mut table, at(1))?);
    select(&mut table, caller)?;
    assert_eq!(
        sync.begin_exit(&mut table, OWNER, caller, at(1)),
        Err(sync::SyncError::Thread(ThreadError::Busy))
    );
    assert_eq!(table.snapshot(OWNER, caller)?.state, ThreadState::Running);
    assert_eq!(finish(wait, &mut table)?, Outcome::TimedOut);
    sync.unlock(&mut table, OWNER, caller, mutex, at(1))
        .map_err(|_| ThreadError::InvalidState)?;
    Ok(())
}

#[test]
fn process_stop_invalidates_owned_wait_and_allows_resource_retirement() -> Result<(), Error> {
    let (mut table, [caller, target, helper]) = setup()?;
    let mut wait = pending(table.join(OWNER, caller, target, WaitMode::Wait(WAIT), at(0))?)?;
    table.stop_process(OWNER)?;
    assert_eq!(
        wait.observe(&mut table, at(1)),
        Err(Error::Thread(ThreadError::Stopping))
    );
    let error = wait
        .finish(&mut table)
        .err()
        .ok_or(ThreadError::InvalidState)?;
    assert_eq!(error, Error::Thread(ThreadError::Stopping));
    for id in [caller, target, helper] {
        table.release_resources(OWNER, id)?;
        table.reap(OWNER, id)?;
    }
    table.remove_process(OWNER)?;
    assert!(wait.observe(&mut table, at(1)).is_err());
    assert_eq!(table.committed_pages(), 0);
    Ok(())
}

#[test]
fn self_foreign_and_initial_targets_cannot_acquire_join_claims() -> Result<(), Error> {
    let (mut table, [caller, target, _]) = setup()?;
    assert_eq!(
        table.join(OWNER, caller, caller, WaitMode::Try, at(0)),
        Err(ThreadError::SelfJoin)
    );
    let other = ProcessId(2);
    table.register_process(
        other,
        ThreadQuota {
            records: 1,
            pages: 1,
        },
    )?;
    let foreign = table.prepare_initial(
        other,
        ThreadResources {
            reservation: 4,
            pages: 1,
        },
    )?;
    assert_eq!(
        table.join(OWNER, caller, foreign, WaitMode::Try, at(0)),
        Err(ThreadError::WrongOwner)
    );
    select(&mut table, target)?;
    assert_eq!(
        table.join(OWNER, target, caller, WaitMode::Try, at(0)),
        Err(ThreadError::Busy)
    );
    Ok(())
}

#[test]
fn indefinite_sleep_without_stop_observation_requires_process_stop() -> Result<(), Error> {
    let (mut table, [caller, _, _]) = setup()?;
    let mut wait = pending(table.sleep(OWNER, caller, WaitOptions::default(), at(0))?)?;
    table.request_stop(OWNER, caller)?;
    assert_eq!(wait.deadline(), None);
    assert!(!wait.observe(&mut table, at(u64::MAX))?);
    assert_eq!(table.snapshot(OWNER, caller)?.state, ThreadState::Blocked);
    table.stop_process(OWNER)?;
    assert_eq!(
        wait.observe(&mut table, at(u64::MAX)),
        Err(Error::Thread(ThreadError::Stopping))
    );
    Ok(())
}

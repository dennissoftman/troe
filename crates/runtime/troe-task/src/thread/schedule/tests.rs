use super::*;
use crate::thread::{ThreadQuota, ThreadResources};

const A: ProcessId = ProcessId(1);
const B: ProcessId = ProcessId(2);
const HZ: u64 = 1_000_000;

fn resources(reservation: u64) -> ThreadResources {
    ThreadResources {
        reservation,
        pages: 1,
    }
}

fn fixture() -> Result<(ThreadTable, [ThreadId; 4]), ThreadError> {
    let mut table = ThreadTable::new(2, 6, 6, usize::MAX)?;
    table.register_process(
        A,
        ThreadQuota {
            records: 5,
            pages: 5,
        },
    )?;
    table.register_process(
        B,
        ThreadQuota {
            records: 1,
            pages: 1,
        },
    )?;
    let initial = table.prepare_initial(A, resources(1))?;
    table.start(A, initial)?;
    table.dispatch(A, initial)?;
    let worker = table.prepare_worker(A, initial, resources(2))?;
    let sibling = table.prepare_worker(A, initial, resources(3))?;
    table.start_worker(A, initial, worker)?;
    table.start_worker(A, initial, sibling)?;
    table.yield_running(A, initial)?;
    let other = table.prepare_initial(B, resources(4))?;
    table.start(B, other)?;
    Ok((table, [initial, worker, sibling, other]))
}

#[test]
fn process_turns_do_not_multiply_with_runnable_siblings() -> Result<(), Error> {
    let (mut table, ids) = fixture()?;
    let metadata = table.metadata_bytes();
    let mut selected = alloc::vec::Vec::new();
    for turn in 0..12 {
        let now = turn * 20_000;
        let mut dispatch = table.begin_dispatch(now, HZ, 10, 4)?.ok_or(Error::Stale)?;
        let owner = if turn % 2 == 0 { A } else { B };
        assert_eq!(dispatch.process(), owner);
        let id = table
            .dispatch_sibling(&mut dispatch, now)?
            .ok_or(Error::Stale)?;
        selected.push(id);
        assert_eq!(table.charge_dispatch_step(&mut dispatch, id, now)?, 10);
        table.yield_running(owner, id)?;
        table
            .finish_dispatch(dispatch, now + 1)
            .map_err(|(error, _)| error)?;
    }
    assert_eq!(
        selected,
        [
            ids[0], ids[3], ids[1], ids[3], ids[2], ids[3], ids[0], ids[3], ids[1], ids[3], ids[2],
            ids[3]
        ]
    );
    assert_eq!(table.metadata_bytes(), metadata);
    Ok(())
}

#[test]
fn trap_steps_keep_one_deadline_and_floor_fractional_milliseconds() -> Result<(), Error> {
    let (mut table, _) = fixture()?;
    let mut dispatch = table.begin_dispatch(0, HZ, 10, 8)?.ok_or(Error::Stale)?;
    let deadline = dispatch.deadline_ticks();
    for (now, expected) in [(0_u64, 10), (1, 9), (1_001, 8), (8_001, 1), (9_001, 0)] {
        let id = table.dispatch_sibling(&mut dispatch, now.saturating_sub(1))?;
        let Some(id) = id else {
            assert_eq!(expected, 0);
            break;
        };
        assert_eq!(
            table.charge_dispatch_step(&mut dispatch, id, now)?,
            expected
        );
        assert_eq!(dispatch.deadline_ticks(), deadline);
        table.yield_running(A, id)?;
    }
    assert_eq!(table.dispatch_sibling(&mut dispatch, 9_999)?, None);
    table
        .finish_dispatch(dispatch, 10_000)
        .map_err(|(error, _)| error)?;
    assert_eq!(
        table
            .begin_dispatch(10_000, HZ, 10, 8)?
            .ok_or(Error::Stale)?
            .process(),
        B
    );
    Ok(())
}

#[test]
fn equal_clock_and_repeated_failed_work_cannot_renew_a_turn() -> Result<(), Error> {
    let (mut table, ids) = fixture()?;
    let mut dispatch = table.begin_dispatch(0, HZ, 10, 3)?.ok_or(Error::Stale)?;
    assert_eq!(
        table.begin_dispatch(0, HZ, 10, 3),
        Err(ThreadError::Busy.into())
    );
    assert_eq!(table.dispatch(B, ids[3]), Err(ThreadError::Busy));
    for remaining_steps in (0..3).rev() {
        let id = table
            .dispatch_sibling(&mut dispatch, 0)?
            .ok_or(Error::Stale)?;
        assert_eq!(table.charge_dispatch_step(&mut dispatch, id, 0)?, 10);
        assert_eq!(dispatch.steps_left(), remaining_steps);
        // This administrative invalid transition models kernel work that failed.
        assert_eq!(
            table.abort_worker(A, id, id),
            Err(ThreadError::InvalidState)
        );
        table.yield_running(A, id)?;
    }
    assert_eq!(table.dispatch_sibling(&mut dispatch, 0)?, None);
    table
        .finish_dispatch(dispatch, 0)
        .map_err(|(error, _)| error)?;
    assert_eq!(
        table
            .begin_dispatch(0, HZ, 10, 3)?
            .ok_or(Error::Stale)?
            .process(),
        B
    );
    Ok(())
}

#[test]
fn stop_invalidates_retained_dispatch_without_closing_a_newer_one() -> Result<(), Error> {
    let (mut table, _) = fixture()?;
    let mut old = table.begin_dispatch(0, HZ, 10, 8)?.ok_or(Error::Stale)?;
    table.stop_process(A)?;
    let mut current = table.begin_dispatch(1, HZ, 10, 8)?.ok_or(Error::Stale)?;
    assert_eq!(current.process(), B);
    assert_eq!(table.dispatch_sibling(&mut old, 1), Err(Error::Stale));
    let (error, _) = table.finish_dispatch(old, 1).err().ok_or(Error::Stale)?;
    assert_eq!(error, Error::Stale);
    assert!(table.dispatch_sibling(&mut current, 1)?.is_some());
    Ok(())
}

#[test]
fn clock_regression_poisoning_requires_stop_and_frequency_never_changes() -> Result<(), Error> {
    let (mut table, _) = fixture()?;
    let mut dispatch = table.begin_dispatch(10, HZ, 10, 8)?.ok_or(Error::Stale)?;
    assert_eq!(
        table.dispatch_sibling(&mut dispatch, 9),
        Err(Error::ClockRegressed)
    );
    assert_eq!(
        table.dispatch_sibling(&mut dispatch, 11),
        Err(Error::ClockRegressed)
    );
    let (error, _) = table
        .finish_dispatch(dispatch, 11)
        .err()
        .ok_or(Error::Stale)?;
    assert_eq!(error, Error::ClockRegressed);
    table.stop_process(A)?;
    assert_eq!(
        table.begin_dispatch(9, HZ, 10, 8),
        Err(Error::ClockRegressed)
    );
    assert_eq!(
        table.begin_dispatch(11, HZ * 2, 10, 8),
        Err(Error::ClockFrequencyChanged)
    );
    assert_eq!(
        table
            .begin_dispatch(11, HZ, 10, 8)?
            .ok_or(Error::Stale)?
            .process(),
        B
    );
    Ok(())
}

#[test]
fn invalid_budgets_and_overflow_publish_no_dispatch_or_cursor_change() -> Result<(), Error> {
    let (mut table, _) = fixture()?;
    for (frequency, millis, steps) in [
        (0, 10, 8),
        (999, 10, 8),
        (HZ, 0, 8),
        (HZ, 51, 8),
        (HZ, 10, 0),
        (HZ, 10, 257),
    ] {
        assert_eq!(
            table.begin_dispatch(0, frequency, millis, steps),
            Err(Error::InvalidBudget)
        );
    }
    assert_eq!(
        table.begin_dispatch(u64::MAX, HZ, 10, 8),
        Err(Error::Exhausted)
    );
    let dispatch = table
        .begin_dispatch(0, u64::MAX, 50, 8)?
        .ok_or(Error::Stale)?;
    assert_eq!(dispatch.process(), A);
    assert!(dispatch.deadline_ticks() < u64::MAX);
    table
        .finish_dispatch(dispatch, 0)
        .map_err(|(error, _)| error)?;
    table.dispatch_sequence = u64::MAX;
    assert_eq!(
        table.begin_dispatch(0, u64::MAX, 50, 8),
        Err(Error::Exhausted)
    );
    assert_eq!(table.active_dispatch, None);
    Ok(())
}

#[test]
fn all_blocked_and_wake_storms_preserve_process_rotation() -> Result<(), Error> {
    let (mut table, ids) = fixture()?;
    let mut dispatch = table.begin_dispatch(0, HZ, 10, 8)?.ok_or(Error::Stale)?;
    let deadline = dispatch.deadline_ticks();
    let mut waits = alloc::vec::Vec::new();
    for expected in &ids[..3] {
        let id = table
            .dispatch_sibling(&mut dispatch, 0)?
            .ok_or(Error::Stale)?;
        assert_eq!(id, *expected);
        assert_eq!(table.charge_dispatch_step(&mut dispatch, id, 0)?, 10);
        waits.push(table.block(A, id)?);
    }
    assert_eq!(table.dispatch_sibling(&mut dispatch, 0)?, None);
    assert_eq!(dispatch.deadline_ticks(), deadline);
    table
        .finish_dispatch(dispatch, 1)
        .map_err(|(error, _)| error)?;
    let mut other = table.begin_dispatch(1, HZ, 10, 8)?.ok_or(Error::Stale)?;
    let id = table.dispatch_sibling(&mut other, 1)?.ok_or(Error::Stale)?;
    assert_eq!(id, ids[3]);
    let other_wait = table.block(B, id)?;
    table
        .finish_dispatch(other, 2)
        .map_err(|(error, _)| error)?;
    let sequence = table.dispatch_sequence;
    assert_eq!(table.begin_dispatch(2, HZ, 10, 8)?, None);
    assert_eq!(table.dispatch_sequence, sequence);
    table.wake(A, waits[0])?;
    let mut current = table.begin_dispatch(3, HZ, 10, 8)?.ok_or(Error::Stale)?;
    assert_eq!(current.process(), A);
    for wait in &waits[1..] {
        table.wake(A, *wait)?;
    }
    table.wake(B, other_wait)?;
    assert_eq!(
        table.begin_dispatch(3, HZ, 10, 8),
        Err(ThreadError::Busy.into())
    );
    assert_eq!(table.dispatch_sibling(&mut current, 3)?, Some(ids[0]));
    table.yield_running(A, ids[0])?;
    table
        .finish_dispatch(current, 4)
        .map_err(|(error, _)| error)?;
    assert_eq!(
        table
            .begin_dispatch(4, HZ, 10, 8)?
            .ok_or(Error::Stale)?
            .process(),
        B
    );
    Ok(())
}

#[test]
fn preparation_churn_and_stale_tokens_keep_the_existing_turn() -> Result<(), Error> {
    let (mut table, _) = fixture()?;
    let pages = table.committed_pages();
    let mut dispatch = table.begin_dispatch(0, HZ, 10, 8)?.ok_or(Error::Stale)?;
    let caller = table
        .dispatch_sibling(&mut dispatch, 0)?
        .ok_or(Error::Stale)?;
    let mut previous: Option<ThreadId> = None;
    for now in 1..=4 {
        let child = table.prepare_worker(A, caller, resources(5))?;
        if let Some(old) = previous {
            assert_eq!(child.slot(), old.slot());
            assert_ne!(child.generation(), old.generation());
            assert_eq!(
                table.charge_dispatch_step(&mut dispatch, old, now),
                Err(ThreadError::Stale.into())
            );
        }
        assert_eq!(table.charge_dispatch_step(&mut dispatch, caller, now)?, 9);
        table.abort_worker(A, caller, child)?;
        table.release_resources(A, child)?;
        table.reap(A, child)?;
        previous = Some(child);
        assert_eq!(table.committed_pages(), pages);
        assert_eq!(dispatch.deadline_ticks(), 10_000);
        assert_eq!(
            dispatch.steps_left(),
            8 - u16::try_from(now).map_err(|_| Error::Exhausted)?
        );
    }
    let (error, dispatch) = table
        .finish_dispatch(dispatch, 5)
        .err()
        .ok_or(Error::Stale)?;
    assert_eq!(error, ThreadError::Busy.into());
    table.yield_running(A, caller)?;
    table
        .finish_dispatch(dispatch, 5)
        .map_err(|(error, _)| error)?;
    assert_eq!(
        table
            .begin_dispatch(5, HZ, 10, 8)?
            .ok_or(Error::Stale)?
            .process(),
        B
    );
    Ok(())
}

#[test]
fn process_slot_reuse_cannot_revive_an_old_dispatch() -> Result<(), Error> {
    let (mut table, ids) = fixture()?;
    let old = table.begin_dispatch(0, HZ, 10, 8)?.ok_or(Error::Stale)?;
    table.stop_process(A)?;
    for id in &ids[..3] {
        table.release_resources(A, *id)?;
        table.reap(A, *id)?;
    }
    table.remove_process(A)?;
    let replacement = ProcessId(3);
    table.register_process(
        replacement,
        ThreadQuota {
            records: 1,
            pages: 1,
        },
    )?;
    let initial = table.prepare_initial(replacement, resources(1))?;
    table.start(replacement, initial)?;
    let next = table.begin_dispatch(1, HZ, 10, 8)?.ok_or(Error::Stale)?;
    assert_eq!(next.process(), B);
    assert_eq!(
        table.finish_dispatch(old, 1).err().ok_or(Error::Stale)?.0,
        Error::Stale
    );
    table.finish_dispatch(next, 1).map_err(|(error, _)| error)?;
    let mut next = table.begin_dispatch(2, HZ, 10, 8)?.ok_or(Error::Stale)?;
    assert_eq!(next.process(), replacement);
    assert_eq!(table.dispatch_sibling(&mut next, 2)?, Some(initial));
    assert_ne!(initial.generation(), ids[0].generation());
    Ok(())
}

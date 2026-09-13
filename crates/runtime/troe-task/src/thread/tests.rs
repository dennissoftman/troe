use super::*;

const OWNER: ProcessId = ProcessId(1);
const OTHER: ProcessId = ProcessId(2);

#[test]
fn compiled_metadata_covers_inline_owner_and_actual_backing() -> Result<(), ThreadError> {
    for (processes, threads) in [(1, 1), (2, 4), (7, 19), (32, 256)] {
        let requested = ThreadTable::metadata_layout(processes, threads)?;
        assert_eq!(requested.inline(), Layout::new::<ThreadTable>());
        assert_eq!(
            requested.buffers(),
            [
                Layout::array::<Option<Process>>(processes).unwrap_or_else(|_| unreachable!()),
                Layout::array::<Slot>(threads).unwrap_or_else(|_| unreachable!()),
            ]
        );
        assert_eq!(
            ThreadTable::new(processes, threads, 1, requested.bytes() - 1).err(),
            Some(ThreadError::MetadataBudget)
        );
        let table = ThreadTable::new(processes, threads, 1, requested.bytes())?;
        assert_eq!(
            table.metadata_bytes(),
            core::mem::size_of_val(&table)
                + table.processes.capacity() * core::mem::size_of::<Option<Process>>()
                + table.slots.capacity() * core::mem::size_of::<Slot>()
        );
        assert_eq!(table.metadata_bytes(), requested.bytes());
    }
    Ok(())
}

#[test]
fn metadata_validation_needs_no_large_allocation() {
    for (processes, threads) in [
        (0, 1),
        (2, 1),
        (1, 0),
        (1, MAX_TASKS + 1),
        (usize::MAX, usize::MAX),
    ] {
        assert_eq!(
            ThreadTable::metadata_layout(processes, threads),
            Err(ThreadError::InvalidLimit)
        );
    }
    assert!(ThreadTable::metadata_layout(MAX_TASKS, MAX_TASKS).is_ok());
    assert_eq!(
        ThreadTable::new(1, 1, 1, 0).err(),
        Some(ThreadError::MetadataBudget)
    );
    assert_eq!(
        ThreadTable::new(1, 1, 0, usize::MAX).err(),
        Some(ThreadError::InvalidLimit)
    );
}

#[test]
fn retired_records_do_not_refund_backing_metadata() -> Result<(), ThreadError> {
    let layout = ThreadTable::metadata_layout(1, 2)?;
    let mut table = ThreadTable::new(1, 2, 4, layout.bytes())?;
    for reservation in 1..=100 {
        table.register_process(
            OWNER,
            ThreadQuota {
                records: 2,
                pages: 4,
            },
        )?;
        let id = table.prepare_initial(OWNER, resources(reservation, 1))?;
        assert_eq!(table.metadata_bytes(), layout.bytes());
        table.abort_prepared(OWNER, id)?;
        table.release_resources(OWNER, id)?;
        table.reap(OWNER, id)?;
        table.remove_process(OWNER)?;
        assert_eq!(table.metadata_bytes(), layout.bytes());
    }
    Ok(())
}

fn resources(reservation: u64, pages: u64) -> ThreadResources {
    ThreadResources { reservation, pages }
}

fn setup() -> Result<(ThreadTable, ThreadId, ThreadId), ThreadError> {
    let mut table = ThreadTable::new(2, 4, 16, ThreadTable::metadata_layout(2, 4)?.bytes())?;
    table.register_process(
        OWNER,
        ThreadQuota {
            records: 3,
            pages: 8,
        },
    )?;
    let initial = table.prepare_initial(OWNER, resources(1, 2))?;
    table.start(OWNER, initial)?;
    table.dispatch(OWNER, initial)?;
    let worker = table.prepare_worker(OWNER, initial, resources(2, 2))?;
    Ok((table, initial, worker))
}

fn finish(table: &mut ThreadTable, worker: ThreadId, result: u64) -> Result<(), ThreadError> {
    table.start(OWNER, worker)?;
    table.dispatch(OWNER, worker)?;
    table.begin_exit(OWNER, worker)?;
    table.complete(OWNER, worker, result)
}

#[test]
fn preparation_failure_preserves_charges_and_publication() -> Result<(), ThreadError> {
    let (mut table, initial, worker) = setup()?;
    let before = table.usage(OWNER);
    assert_eq!(
        table.prepare_worker(OWNER, initial, resources(2, 1)),
        Err(ThreadError::ReservationInUse)
    );
    assert_eq!(
        table.prepare_worker(OWNER, initial, resources(3, u64::MAX)),
        Err(ThreadError::Exhausted)
    );
    assert_eq!(
        table.prepare_worker(OWNER, initial, resources(0, 1)),
        Err(ThreadError::InvalidLimit)
    );
    assert_eq!(table.usage(OWNER), before);
    assert_eq!(table.snapshot(OWNER, worker)?.state, ThreadState::Prepared);
    assert_eq!(
        table.release_resources(OWNER, worker),
        Err(ThreadError::InvalidState)
    );
    Ok(())
}

#[test]
fn initial_thread_is_unique_and_aborted_reservations_remain_charged() -> Result<(), ThreadError> {
    let mut table = ThreadTable::new(1, 2, 4, ThreadTable::metadata_layout(1, 2)?.bytes())?;
    table.register_process(
        OWNER,
        ThreadQuota {
            records: 2,
            pages: 4,
        },
    )?;
    let first = table.prepare_initial(OWNER, resources(1, 2))?;
    assert_eq!(
        table.prepare_initial(OWNER, resources(2, 2)),
        Err(ThreadError::InvalidState)
    );
    table.abort_prepared(OWNER, first)?;
    assert_eq!(table.usage(OWNER), (1, 2));
    let second = table.prepare_initial(OWNER, resources(2, 2))?;
    assert_eq!(table.usage(OWNER), (2, 4));
    table.release_resources(OWNER, first)?;
    table.reap(OWNER, first)?;
    table.start(OWNER, second)?;
    assert_eq!(
        table.abort_prepared(OWNER, second),
        Err(ThreadError::InvalidState)
    );
    Ok(())
}

#[test]
fn per_process_and_global_limits_are_independent() -> Result<(), ThreadError> {
    let mut table = ThreadTable::new(2, 4, 6, ThreadTable::metadata_layout(2, 4)?.bytes())?;
    table.register_process(
        OWNER,
        ThreadQuota {
            records: 2,
            pages: 4,
        },
    )?;
    table.register_process(
        OTHER,
        ThreadQuota {
            records: 2,
            pages: 4,
        },
    )?;
    let a = table.prepare_initial(OWNER, resources(1, 2))?;
    let b = table.prepare_initial(OTHER, resources(2, 2))?;
    table.start(OWNER, a)?;
    table.dispatch(OWNER, a)?;
    let child = table.prepare_worker(OWNER, a, resources(3, 2))?;
    assert_eq!(
        table.prepare_worker(OWNER, a, resources(4, 1)),
        Err(ThreadError::Exhausted)
    );
    table.yield_running(OWNER, a)?;
    table.start(OTHER, b)?;
    table.dispatch(OTHER, b)?;
    assert_eq!(
        table.prepare_worker(OTHER, b, resources(4, 1)),
        Err(ThreadError::Exhausted)
    );
    table.abort_prepared(OWNER, child)?;
    assert_eq!(table.committed_pages(), 6);
    table.release_resources(OWNER, child)?;
    assert!(table.prepare_worker(OTHER, b, resources(4, 2)).is_ok());
    assert_eq!(table.committed_pages(), 6);
    Ok(())
}

#[test]
fn tokens_cannot_cross_processes_or_survive_slot_reuse() -> Result<(), ThreadError> {
    let (mut table, initial, old) = setup()?;
    assert_eq!(table.start(OTHER, old), Err(ThreadError::UnknownProcess));
    table.register_process(
        OTHER,
        ThreadQuota {
            records: 1,
            pages: 2,
        },
    )?;
    assert_eq!(table.start(OTHER, old), Err(ThreadError::WrongOwner));
    assert_eq!(table.request_stop(OTHER, old), Err(ThreadError::WrongOwner));
    table.abort_prepared(OWNER, old)?;
    table.release_resources(OWNER, old)?;
    table.reap(OWNER, old)?;
    let new = table.prepare_worker(OWNER, initial, resources(2, 2))?;
    assert_ne!(new, old);
    assert_eq!(new.slot, old.slot);
    assert_eq!(table.request_stop(OWNER, old), Err(ThreadError::Stale));
    assert!(!table.snapshot(OWNER, new)?.stop_requested);
    Ok(())
}

#[test]
fn operation_generations_reject_delayed_and_duplicate_wakes() -> Result<(), ThreadError> {
    let (mut table, initial, _) = setup()?;
    let first = table.block(OWNER, initial)?;
    table.wake(OWNER, first)?;
    assert_eq!(table.wake(OWNER, first), Err(ThreadError::Stale));
    table.dispatch(OWNER, initial)?;
    let second = table.block(OWNER, initial)?;
    assert_eq!(table.wake(OWNER, first), Err(ThreadError::Stale));
    assert_eq!(table.snapshot(OWNER, initial)?.state, ThreadState::Blocked);
    table.request_stop(OWNER, initial)?;
    assert_eq!(table.snapshot(OWNER, initial)?.state, ThreadState::Blocked);
    table.wake(OWNER, second)?;
    assert!(table.snapshot(OWNER, initial)?.stop_requested);
    Ok(())
}

#[test]
fn joining_requires_quiescence_and_consumes_completion_once() -> Result<(), ThreadError> {
    let (mut table, initial, worker) = setup()?;
    table.start(OWNER, worker)?;
    let claim = table.claim_join(OWNER, initial, worker)?;
    assert_eq!(table.detach(OWNER, worker), Err(ThreadError::Busy));
    assert_eq!(table.join_result(OWNER, claim)?, None);
    table.yield_running(OWNER, initial)?;
    table.dispatch(OWNER, worker)?;
    table.begin_exit(OWNER, worker)?;
    table.complete(OWNER, worker, 42)?;
    assert_eq!(table.join_result(OWNER, claim)?, None);
    assert_eq!(table.reap(OWNER, worker), Err(ThreadError::Busy));
    table.release_resources(OWNER, worker)?;
    assert_eq!(table.join_result(OWNER, claim)?, Some(42));
    assert_eq!(table.join_result(OWNER, claim), Err(ThreadError::Stale));
    assert_eq!(table.cancel_join(OWNER, claim), Err(ThreadError::Stale));
    table.reap(OWNER, worker)?;
    assert_eq!(table.usage(OWNER), (1, 2));
    Ok(())
}

#[test]
fn timed_out_join_cannot_cancel_a_new_claim_or_lose_the_result() -> Result<(), ThreadError> {
    let (mut table, initial, worker) = setup()?;
    table.start(OWNER, worker)?;
    let first = table.claim_join(OWNER, initial, worker)?;
    table.cancel_join(OWNER, first)?;
    let second = table.claim_join(OWNER, initial, worker)?;
    assert_ne!(first, second);
    assert_eq!(table.cancel_join(OWNER, first), Err(ThreadError::Stale));
    table.yield_running(OWNER, initial)?;
    table.dispatch(OWNER, worker)?;
    table.begin_exit(OWNER, worker)?;
    table.complete(OWNER, worker, 7)?;
    table.release_resources(OWNER, worker)?;
    assert_eq!(table.join_result(OWNER, second)?, Some(7));
    Ok(())
}

#[test]
fn detach_and_join_race_has_one_winner_in_both_orders() -> Result<(), ThreadError> {
    for detach_first in [false, true] {
        let (mut table, initial, worker) = setup()?;
        table.start(OWNER, worker)?;
        if detach_first {
            table.detach(OWNER, worker)?;
            assert_eq!(
                table.claim_join(OWNER, initial, worker),
                Err(ThreadError::Busy)
            );
        } else {
            let claim = table.claim_join(OWNER, initial, worker)?;
            assert_eq!(table.detach(OWNER, worker), Err(ThreadError::Busy));
            table.cancel_join(OWNER, claim)?;
            table.detach(OWNER, worker)?;
        }
    }
    Ok(())
}

#[test]
fn creator_exit_aborts_only_unstarted_children_and_relinquishes_join() -> Result<(), ThreadError> {
    let (mut table, initial, unstarted) = setup()?;
    let started = table.prepare_worker(OWNER, initial, resources(3, 2))?;
    table.start(OWNER, started)?;
    let claim = table.claim_join(OWNER, initial, started)?;
    table.begin_exit(OWNER, initial)?;
    assert_eq!(
        table.snapshot(OWNER, unstarted)?.state,
        ThreadState::Revoked
    );
    assert_eq!(table.snapshot(OWNER, started)?.state, ThreadState::Ready);
    assert_eq!(table.cancel_join(OWNER, claim), Err(ThreadError::Stale));
    table.detach(OWNER, started)?;
    assert_eq!(table.usage(OWNER), (3, 6));
    Ok(())
}

#[test]
fn completed_unjoined_records_still_consume_quota() -> Result<(), ThreadError> {
    let (mut table, initial, first) = setup()?;
    let second = table.prepare_worker(OWNER, initial, resources(3, 2))?;
    table.yield_running(OWNER, initial)?;
    finish(&mut table, first, 1)?;
    table.release_resources(OWNER, first)?;
    finish(&mut table, second, 2)?;
    table.release_resources(OWNER, second)?;
    assert_eq!(table.usage(OWNER), (3, 2));
    table.dispatch(OWNER, initial)?;
    assert_eq!(
        table.prepare_worker(OWNER, initial, resources(4, 1)),
        Err(ThreadError::Exhausted)
    );
    assert_eq!(table.reap(OWNER, first), Err(ThreadError::Busy));
    let claim = table.claim_join(OWNER, initial, first)?;
    assert_eq!(table.join_result(OWNER, claim)?, Some(1));
    table.reap(OWNER, first)?;
    assert!(
        table
            .prepare_worker(OWNER, initial, resources(4, 1))
            .is_ok()
    );
    Ok(())
}

#[test]
fn process_stop_invalidates_waits_and_claims_but_keeps_resources() -> Result<(), ThreadError> {
    let (mut table, initial, worker) = setup()?;
    table.start(OWNER, worker)?;
    let claim = table.claim_join(OWNER, initial, worker)?;
    let wait = table.block(OWNER, initial)?;
    table.dispatch(OWNER, worker)?;
    table.stop_process(OWNER)?;
    table.stop_process(OWNER)?;
    assert_eq!(table.usage(OWNER), (2, 4));
    assert_eq!(table.wake(OWNER, wait), Err(ThreadError::Stale));
    assert_eq!(table.join_result(OWNER, claim), Err(ThreadError::Stale));
    assert_eq!(table.start(OWNER, worker), Err(ThreadError::Stopping));
    assert_eq!(table.dispatch(OWNER, worker), Err(ThreadError::Stopping));
    assert_eq!(table.remove_process(OWNER), Err(ThreadError::Busy));
    for id in [initial, worker] {
        assert_eq!(table.reap(OWNER, id), Err(ThreadError::Busy));
        table.release_resources(OWNER, id)?;
        assert_eq!(table.release_resources(OWNER, id), Err(ThreadError::Stale));
        table.reap(OWNER, id)?;
    }
    assert_eq!(table.committed_pages(), 0);
    table.remove_process(OWNER)?;
    Ok(())
}

#[test]
fn exhausted_generations_fail_closed_without_wrapping() -> Result<(), ThreadError> {
    let (mut table, initial, worker) = setup()?;
    table.abort_prepared(OWNER, worker)?;
    table.release_resources(OWNER, worker)?;
    table.reap(OWNER, worker)?;
    for slot in &mut table.slots {
        if slot.record.is_none() {
            slot.generation = u32::MAX;
        }
    }
    assert_eq!(
        table.prepare_worker(OWNER, initial, resources(3, 1)),
        Err(ThreadError::Exhausted)
    );
    table.record_mut(OWNER, initial)?.wait_sequence = u64::MAX;
    assert_eq!(table.block(OWNER, initial), Err(ThreadError::Exhausted));
    assert_eq!(table.snapshot(OWNER, initial)?.state, ThreadState::Running);
    assert_eq!(table.usage(OWNER), (1, 2));
    Ok(())
}

#[test]
fn short_adversarial_schedules_always_remain_reclaimable() -> Result<(), ThreadError> {
    // Enumerate 10,000 four-operation schedules, including invalid duplicates
    // and stop racing with every creation/completion boundary. Every prefix
    // must remain bounded, and forced teardown must return the same baseline.
    for encoded in 0_u32..10_000 {
        let (mut table, initial, worker) = setup()?;
        table.yield_running(OWNER, initial)?;
        let capacities = (table.slots.capacity(), table.processes.capacity());
        let mut schedule = encoded;
        for _ in 0..4 {
            let _ = match schedule % 10 {
                0 => table.start(OWNER, worker),
                1 => table.dispatch(OWNER, worker),
                2 => table.yield_running(OWNER, worker),
                3 => table.begin_exit(OWNER, worker),
                4 => table.complete(OWNER, worker, 42),
                5 => table.release_resources(OWNER, worker).map(|_| ()),
                6 => table.detach(OWNER, worker),
                7 => table.reap(OWNER, worker),
                8 => table.stop_process(OWNER),
                _ => table.abort_prepared(OWNER, worker),
            };
            schedule /= 10;
            assert!(table.usage(OWNER).0 <= 2);
            assert!(table.committed_pages() <= 4);
            assert_eq!(
                (table.slots.capacity(), table.processes.capacity()),
                capacities
            );
        }
        table.stop_process(OWNER)?;
        for id in [initial, worker] {
            if let Ok(snapshot) = table.snapshot(OWNER, id) {
                if !snapshot.resources_released {
                    table.release_resources(OWNER, id)?;
                }
                table.reap(OWNER, id)?;
            }
        }
        assert_eq!(table.usage(OWNER), (0, 0));
        table.remove_process(OWNER)?;
    }
    Ok(())
}

use super::*;
use crate::{
    MonotonicMillis, ProcessId,
    thread::{
        ThreadQuota, ThreadResources,
        sync::{SyncOutcome, SyncQuota, SyncStart, WaitMode, WaitOptions},
    },
};
use alloc::vec::Vec;

const LIMITS: ThreadAdmissionLimits = ThreadAdmissionLimits {
    processes: 2,
    threads: 4,
    objects: 8,
    threads_per_process: 2,
};
const BUDGET: ThreadAdmissionBudget = ThreadAdmissionBudget {
    task_ipc_pairs: 6,
    reserved_task_ipc_pairs: 2,
    metadata_bytes: usize::MAX,
};

#[test]
fn maximum_capacity_matches_exhaustive_candidate_validation() -> Result<(), ThreadAdmissionError> {
    for objects in [2, 8, 32] {
        for per_process in [1, 2, 5] {
            for contexts in [4, 7, 16] {
                for metadata_bytes in (0..12000).step_by(97) {
                    let budget = ThreadAdmissionBudget {
                        task_ipc_pairs: contexts,
                        metadata_bytes,
                        ..BUDGET
                    };
                    let expected = (1..=contexts)
                        .filter(|threads| {
                            ThreadAdmissionPlan::new(
                                ThreadAdmissionLimits {
                                    threads: *threads,
                                    objects,
                                    threads_per_process: per_process,
                                    ..LIMITS
                                },
                                budget,
                            )
                            .is_ok()
                        })
                        .max();
                    let actual =
                        ThreadAdmissionPlan::maximum_capacity(2, objects, per_process, budget);
                    assert_eq!(
                        actual.as_ref().ok().map(|plan| plan.limits().threads),
                        expected
                    );
                    if let Ok(plan) = actual {
                        assert!(plan.metadata_bytes() <= metadata_bytes);
                        assert!(plan.limits().threads <= contexts - BUDGET.reserved_task_ipc_pairs);
                    }
                }
            }
        }
    }
    let largest = ThreadAdmissionPlan::maximum_capacity(
        2,
        8,
        crate::MAX_TASKS / 2,
        ThreadAdmissionBudget {
            task_ipc_pairs: usize::MAX,
            ..BUDGET
        },
    )?;
    assert_eq!(largest.limits().threads, crate::MAX_TASKS);
    assert_eq!(
        ThreadAdmissionPlan::maximum_capacity(2, 8, usize::MAX, BUDGET),
        Err(ThreadAdmissionError::InvalidLimit)
    );
    Ok(())
}

#[test]
fn paired_tables_fit_the_combined_compiled_budget() -> Result<(), ThreadAdmissionError> {
    let plan = ThreadAdmissionPlan::new(LIMITS, BUDGET)?;
    let bytes = plan.metadata_bytes();
    assert_eq!(plan.limits(), LIMITS);
    assert_eq!(plan.available_contexts(), 4);
    assert_eq!(
        bytes,
        ThreadTable::metadata_layout(2, 4)?.bytes() + SyncTable::metadata_layout(2, 8, 4)?.bytes()
    );
    let exact = ThreadAdmissionPlan::new(
        LIMITS,
        ThreadAdmissionBudget {
            metadata_bytes: bytes,
            ..BUDGET
        },
    )?;
    let (threads, sync) = exact.create_tables(40)?;
    assert_eq!(threads.metadata_bytes() + sync.metadata_bytes(), bytes);
    assert_eq!(
        ThreadAdmissionPlan::new(
            LIMITS,
            ThreadAdmissionBudget {
                metadata_bytes: bytes - 1,
                ..BUDGET
            }
        ),
        Err(ThreadAdmissionError::MetadataBudget)
    );
    assert_eq!(
        exact.create_tables(0).err(),
        Some(ThreadAdmissionError::Thread(ThreadError::InvalidLimit))
    );
    Ok(())
}

#[test]
fn reserved_contexts_cannot_be_promised_to_application_records() {
    for (total, reserved) in [(5, 2), (2, 2), (1, 2), (0, usize::MAX)] {
        let budget = ThreadAdmissionBudget {
            task_ipc_pairs: total,
            reserved_task_ipc_pairs: reserved,
            ..BUDGET
        };
        assert_eq!(
            ThreadAdmissionPlan::new(LIMITS, budget),
            Err(ThreadAdmissionError::ContextBudget)
        );
    }
    assert_eq!(
        ThreadAdmissionPlan::new(
            LIMITS,
            ThreadAdmissionBudget {
                reserved_task_ipc_pairs: 0,
                ..BUDGET
            }
        ),
        Err(ThreadAdmissionError::InvalidLimit)
    );
    // A larger physical pool never bypasses the configured metadata allowance.
    assert_eq!(
        ThreadAdmissionPlan::new(
            LIMITS,
            ThreadAdmissionBudget {
                task_ipc_pairs: usize::MAX,
                metadata_bytes: 0,
                ..BUDGET
            }
        ),
        Err(ThreadAdmissionError::MetadataBudget)
    );
}

#[test]
fn malformed_capacity_and_per_process_limits_are_rejected() {
    assert_eq!(
        ThreadAdmissionPlan::new(
            ThreadAdmissionLimits {
                threads: 5,
                ..LIMITS
            },
            ThreadAdmissionBudget {
                task_ipc_pairs: 16,
                ..BUDGET
            }
        ),
        Err(ThreadAdmissionError::InvalidLimit)
    );
    for per_process in [0, LIMITS.threads, usize::MAX] {
        assert_eq!(
            ThreadAdmissionPlan::new(
                ThreadAdmissionLimits {
                    threads_per_process: per_process,
                    ..LIMITS
                },
                BUDGET
            ),
            Err(ThreadAdmissionError::InvalidLimit)
        );
    }
    assert_eq!(
        ThreadAdmissionPlan::new(
            ThreadAdmissionLimits {
                processes: 0,
                ..LIMITS
            },
            BUDGET
        ),
        Err(ThreadAdmissionError::InvalidLimit)
    );
    assert_eq!(
        ThreadAdmissionPlan::new(
            ThreadAdmissionLimits {
                objects: 1,
                ..LIMITS
            },
            BUDGET
        ),
        Err(ThreadAdmissionError::Sync(SyncError::InvalidLimit))
    );
}

#[test]
fn paired_constructor_enforces_the_process_ceiling_during_registration()
-> Result<(), ThreadAdmissionError> {
    let (mut threads, _) = ThreadAdmissionPlan::new(LIMITS, BUDGET)?.create_tables(40)?;
    let owner = ProcessId(1);
    for records in [3, 4] {
        assert_eq!(
            threads.register_process(owner, ThreadQuota { records, pages: 20 }),
            Err(ThreadError::InvalidLimit)
        );
    }
    threads.register_process(
        owner,
        ThreadQuota {
            records: 2,
            pages: 20,
        },
    )?;
    let initial = threads.prepare_initial(
        owner,
        ThreadResources {
            reservation: 1,
            pages: 1,
        },
    )?;
    threads.start(owner, initial)?;
    threads.dispatch(owner, initial)?;
    let worker = threads.prepare_worker(
        owner,
        initial,
        ThreadResources {
            reservation: 2,
            pages: 1,
        },
    )?;
    assert_eq!(
        threads.prepare_worker(
            owner,
            initial,
            ThreadResources {
                reservation: 3,
                pages: 1
            }
        ),
        Err(ThreadError::Exhausted)
    );
    threads.abort_prepared(owner, worker)?;
    threads.release_resources(owner, worker)?;
    // A released but unreaped completion still consumes its record reservation.
    assert_eq!(
        threads.prepare_worker(
            owner,
            initial,
            ThreadResources {
                reservation: 3,
                pages: 1
            }
        ),
        Err(ThreadError::Exhausted)
    );
    threads.reap(owner, worker)?;
    assert!(
        threads
            .prepare_worker(
                owner,
                initial,
                ThreadResources {
                    reservation: 3,
                    pages: 1
                }
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn every_admitted_thread_can_wait_without_growing_metadata() -> Result<(), ThreadAdmissionError> {
    let (mut threads, mut sync) = ThreadAdmissionPlan::new(LIMITS, BUDGET)?.create_tables(40)?;
    let bytes = threads.metadata_bytes() + sync.metadata_bytes();
    let mut participants = Vec::new();
    for process in 1..=2 {
        let owner = ProcessId(process);
        threads.register_process(
            owner,
            ThreadQuota {
                records: 2,
                pages: 20,
            },
        )?;
        sync.register_process(
            &mut threads,
            owner,
            SyncQuota {
                objects: 1,
                waits: 2,
            },
        )?;
        let initial = threads.prepare_initial(
            owner,
            ThreadResources {
                reservation: process * 2,
                pages: 1,
            },
        )?;
        threads.start(owner, initial)?;
        threads.dispatch(owner, initial)?;
        let permit = sync.create_permit(&mut threads, owner, initial, 0, 1)?;
        let worker = threads.prepare_worker(
            owner,
            initial,
            ThreadResources {
                reservation: process * 2 + 1,
                pages: 1,
            },
        )?;
        threads.start(owner, worker)?;
        threads.yield_running(owner, initial)?;
        participants.extend([(owner, initial, permit), (owner, worker, permit)]);
    }
    let mut waits = Vec::new();
    for (owner, id, permit) in participants {
        threads.dispatch(owner, id)?;
        let mode = WaitMode::Wait(WaitOptions {
            deadline: Some(MonotonicMillis::from_millis(5)),
            observe_stop: false,
        });
        let start = sync.acquire_permit(
            &mut threads,
            owner,
            id,
            permit,
            mode,
            MonotonicMillis::from_millis(1),
        )?;
        let SyncStart::Waiting(token) = start else {
            unreachable!()
        };
        waits.push((owner, id, token));
    }
    assert_eq!(sync.usage(ProcessId(1)), (1, 2));
    assert_eq!(sync.usage(ProcessId(2)), (1, 2));
    for (owner, id, token) in waits {
        assert!(sync.observe(&mut threads, owner, token, MonotonicMillis::from_millis(5))?);
        threads.dispatch(owner, id)?;
        assert_eq!(
            sync.finish_wait(&mut threads, owner, id, token)?,
            SyncOutcome::TimedOut
        );
        threads.yield_running(owner, id)?;
    }
    assert_eq!(sync.usage(ProcessId(1)), (1, 0));
    assert_eq!(sync.usage(ProcessId(2)), (1, 0));
    assert_eq!(threads.metadata_bytes() + sync.metadata_bytes(), bytes);
    Ok(())
}

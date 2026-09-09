use super::*;
use crate::thread::{ThreadQuota, ThreadResources};

const OWNER: ProcessId = ProcessId(1);
const OTHER: ProcessId = ProcessId(2);
const WAIT: WaitMode = WaitMode::Wait(WaitOptions {
    deadline: None,
    observe_stop: false,
});

fn time(value: u64) -> MonotonicMillis {
    MonotonicMillis::from_millis(value)
}
fn options(deadline: Option<u64>, observe_stop: bool) -> WaitOptions {
    WaitOptions {
        deadline: deadline.map(time),
        observe_stop,
    }
}

struct Harness {
    threads: ThreadTable,
    sync: SyncTable,
    ids: [ThreadId; 3],
}

impl Harness {
    fn new() -> Result<Self, SyncError> {
        let mut threads = ThreadTable::new(2, 6, 12)?;
        threads.register_process(
            OWNER,
            ThreadQuota {
                records: 3,
                pages: 6,
            },
        )?;
        let a = threads.prepare_initial(
            OWNER,
            ThreadResources {
                reservation: 1,
                pages: 2,
            },
        )?;
        threads.start(OWNER, a)?;
        threads.dispatch(OWNER, a)?;
        let b = threads.prepare_worker(
            OWNER,
            a,
            ThreadResources {
                reservation: 2,
                pages: 2,
            },
        )?;
        let c = threads.prepare_worker(
            OWNER,
            a,
            ThreadResources {
                reservation: 3,
                pages: 2,
            },
        )?;
        threads.start(OWNER, b)?;
        threads.start(OWNER, c)?;
        let mut sync = SyncTable::new(2, 8, 4)?;
        sync.register_process(
            &mut threads,
            OWNER,
            SyncQuota {
                objects: 6,
                waits: 3,
            },
        )?;
        Ok(Self {
            threads,
            sync,
            ids: [a, b, c],
        })
    }

    fn select(&mut self, id: ThreadId) -> Result<(), SyncError> {
        for slot in 0..self.threads.slots.len() {
            if let Some(record) = self.threads.slots[slot].record
                && record.snapshot.state == ThreadState::Running
            {
                if record.snapshot.id == id {
                    return Ok(());
                }
                self.threads
                    .yield_running(record.snapshot.id.process, record.snapshot.id)?;
            }
        }
        self.threads.dispatch(id.process, id)?;
        Ok(())
    }

    fn mutex(&mut self, policy: OwnerDeath) -> Result<MutexId, SyncError> {
        self.sync
            .create_mutex(&mut self.threads, OWNER, self.ids[0], policy)
    }
    fn lock(
        &mut self,
        id: ThreadId,
        mutex: MutexId,
        mode: WaitMode,
        now: u64,
    ) -> Result<SyncStart, SyncError> {
        self.select(id)?;
        self.sync
            .lock(&mut self.threads, id.process, id, mutex, mode, time(now))
    }
    fn unlock(&mut self, id: ThreadId, mutex: MutexId, now: u64) -> Result<(), SyncError> {
        self.select(id)?;
        self.sync
            .unlock(&mut self.threads, id.process, id, mutex, time(now))
    }
    fn finish(&mut self, token: SyncWait) -> Result<SyncOutcome, SyncError> {
        self.select(token.0.thread)?;
        self.sync
            .finish_wait(&mut self.threads, OWNER, token.0.thread, token)
    }
    fn teardown(&mut self) -> Result<(), SyncError> {
        self.sync.stop_process(&mut self.threads, OWNER)?;
        for id in self.ids {
            self.threads.release_resources(OWNER, id)?;
            self.threads.reap(OWNER, id)?;
        }
        self.threads.remove_process(OWNER)?;
        assert_eq!(self.threads.committed_pages(), 0);
        assert_eq!(self.sync.usage(OWNER), (0, 0));
        Ok(())
    }

    fn queue_membership(&self) -> Result<[usize; 4], SyncError> {
        // Each queue node appears exactly once; completion nodes appear nowhere.
        let mut seen = [0; 4];
        for object in self.sync.objects.iter().filter_map(|slot| slot.object) {
            let mut cursor = object.queue.head;
            let mut last = None;
            let mut length = 0;
            while let Some(index) = cursor {
                length += 1;
                assert!(length <= self.sync.waits.len(), "queue cycle");
                seen[index] += 1;
                let waiter = self.sync.waits[index].ok_or(SyncError::Stale)?;
                assert_eq!(waiter.previous, last);
                assert_eq!(waiter.queued_on, Some(object.id));
                assert!(!matches!(waiter.phase, Phase::Complete(_)));
                let expected = if matches!(waiter.phase, Phase::Reacquiring(_)) {
                    waiter.mutex.ok_or(SyncError::Stale)?.0
                } else {
                    waiter.source
                };
                assert_eq!(expected, object.id);
                last = Some(index);
                cursor = waiter.next;
            }
            assert_eq!(last, object.queue.tail);
            if let Kind::Permit { count, maximum } = object.kind {
                assert!(count <= maximum);
                if object.queue.head.is_some() {
                    assert_eq!(count, 0);
                }
            }
            if let Kind::Mutex {
                owner, poisoned, ..
            } = object.kind
            {
                if poisoned {
                    assert!(owner.is_none());
                }
                if object.queue.head.is_some() {
                    assert!(owner.is_some());
                }
            }
        }
        Ok(seen)
    }

    fn invariants(&self) -> Result<(), SyncError> {
        let seen = self.queue_membership()?;
        for (index, waiter) in self.sync.waits.iter().enumerate() {
            let Some(waiter) = waiter else {
                assert_eq!(seen[index], 0);
                continue;
            };
            let record = self.threads.record(OWNER, waiter.token.0.thread)?;
            assert!(record.sync_wait);
            assert_eq!(record.wait_sequence, waiter.token.0.sequence);
            if let Phase::Complete(outcome) = waiter.phase {
                assert_eq!(seen[index], 0);
                assert!(waiter.queued_on.is_none());
                assert!(waiter.previous.is_none());
                assert!(waiter.next.is_none());
                assert!(matches!(
                    record.snapshot.state,
                    ThreadState::Ready | ThreadState::Running
                ));
                let mutex = waiter.mutex.or_else(|| {
                    matches!(
                        self.sync.object(OWNER, waiter.source).ok()?.kind,
                        Kind::Mutex { .. }
                    )
                    .then_some(MutexId(waiter.source))
                });
                if let Some(mutex) = mutex {
                    if outcome == SyncOutcome::Poisoned {
                        assert!(matches!(
                            self.sync.object(OWNER, mutex.0)?.kind,
                            Kind::Mutex {
                                owner: None,
                                poisoned: true,
                                ..
                            }
                        ));
                    } else if waiter.mutex.is_some() || outcome == SyncOutcome::Acquired {
                        self.sync
                            .require_owner(OWNER, waiter.token.0.thread, mutex)?;
                    }
                }
            } else {
                assert_eq!(seen[index], 1);
                assert_eq!(record.snapshot.state, ThreadState::Blocked);
            }
        }
        for record in self.threads.slots.iter().filter_map(|slot| slot.record) {
            let held = self.sync.objects.iter().filter_map(|slot| slot.object).filter(|object| matches!(object.kind, Kind::Mutex { owner: Some(holder), .. } if holder == record.snapshot.id)).count();
            assert_eq!(record.owned_mutexes, held);
            assert_eq!(
                record.sync_wait,
                self.sync
                    .waits
                    .iter()
                    .flatten()
                    .any(|waiter| waiter.token.0.thread == record.snapshot.id)
            );
        }
        assert_eq!(
            self.threads.process(OWNER)?.sync_objects,
            self.sync.usage(OWNER).0
        );
        Ok(())
    }
}

fn pending(start: SyncStart) -> Result<SyncWait, SyncError> {
    if let SyncStart::Waiting(token) = start {
        Ok(token)
    } else {
        Err(SyncError::Busy)
    }
}

#[test]
fn fifo_handoff_prevents_stealing_and_wrong_owner_unlock() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, c] = h.ids;
    let mutex = h.mutex(OwnerDeath::Poison)?;
    assert_eq!(
        h.lock(a, mutex, WAIT, 0)?,
        SyncStart::Complete(SyncOutcome::Acquired)
    );
    assert_eq!(h.lock(a, mutex, WAIT, 0), Err(SyncError::Deadlock));
    assert_eq!(h.unlock(b, mutex, 0), Err(SyncError::NotOwner));
    let first = pending(h.lock(b, mutex, WAIT, 0)?)?;
    let second = pending(h.lock(c, mutex, WAIT, 0)?)?;
    h.unlock(a, mutex, 0)?;
    assert_eq!(
        h.lock(a, mutex, WaitMode::Try, 0)?,
        SyncStart::Complete(SyncOutcome::WouldBlock)
    );
    assert_eq!(h.threads.wake(OWNER, first.0), Err(ThreadError::Busy));
    h.select(b)?;
    assert_eq!(h.threads.block(OWNER, b), Err(ThreadError::Busy));
    assert_eq!(h.threads.begin_exit(OWNER, b), Err(ThreadError::Busy));
    assert_eq!(h.finish(first)?, SyncOutcome::Acquired);
    assert_eq!(h.finish(first), Err(SyncError::Stale));
    h.unlock(b, mutex, 0)?;
    assert_eq!(h.finish(second)?, SyncOutcome::Acquired);
    h.invariants()?;
    h.teardown()
}

#[test]
fn early_deadline_and_stop_do_not_acquire_or_release() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let a = h.ids[0];
    let mutex = h.mutex(OwnerDeath::Poison)?;
    let cond = h.sync.create_condition(&mut h.threads, OWNER, a)?;
    assert_eq!(
        h.lock(a, mutex, WaitMode::Wait(options(Some(5), false)), 5)?,
        SyncStart::Complete(SyncOutcome::TimedOut)
    );
    h.threads.request_stop(OWNER, a)?;
    assert_eq!(
        h.lock(a, mutex, WaitMode::Wait(options(None, true)), 5)?,
        SyncStart::Complete(SyncOutcome::Stopped)
    );
    assert_eq!(
        h.lock(a, mutex, WaitMode::Try, 5)?,
        SyncStart::Complete(SyncOutcome::Acquired)
    );
    for (opts, result) in [
        (options(Some(5), false), SyncOutcome::TimedOut),
        (options(None, true), SyncOutcome::Stopped),
    ] {
        assert_eq!(
            h.sync.condition_wait(
                &mut h.threads,
                OWNER,
                a,
                ConditionWait {
                    condition: cond,
                    mutex,
                    options: opts
                },
                time(5)
            )?,
            SyncStart::Complete(result)
        );
        h.sync.require_owner(OWNER, a, mutex)?;
        assert_eq!(h.sync.usage(OWNER).1, 0);
    }
    assert_eq!(h.unlock(a, mutex, 4), Err(SyncError::ClockRegressed));
    h.sync.require_owner(OWNER, a, mutex)?;
    h.invariants()?;
    h.teardown()
}

#[test]
fn expired_head_is_skipped_before_grant_without_timer_delivery() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, c] = h.ids;
    let mutex = h.mutex(OwnerDeath::Poison)?;
    h.lock(a, mutex, WAIT, 0)?;
    let expired = pending(h.lock(b, mutex, WaitMode::Wait(options(Some(1), false)), 0)?)?;
    let eligible = pending(h.lock(c, mutex, WAIT, 0)?)?;
    h.unlock(a, mutex, 1)?;
    assert_eq!(h.finish(expired)?, SyncOutcome::TimedOut);
    assert_eq!(h.finish(eligible)?, SyncOutcome::Acquired);
    h.invariants()?;
    h.teardown()
}

#[test]
fn grant_timeout_and_stop_orders_complete_exactly_once() -> Result<(), SyncError> {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut h = Harness::new()?;
        let [a, b, _] = h.ids;
        let mutex = h.mutex(OwnerDeath::Poison)?;
        h.lock(a, mutex, WAIT, 0)?;
        let token = pending(h.lock(b, mutex, WaitMode::Wait(options(Some(1), true)), 0)?)?;
        let mut now = 0;
        for action in order {
            match action {
                0 => h.unlock(a, mutex, now)?,
                1 => {
                    now = 1;
                    h.sync.observe(&mut h.threads, OWNER, token, time(now))?;
                }
                _ => {
                    h.threads.request_stop(OWNER, b)?;
                    h.sync.observe(&mut h.threads, OWNER, token, time(now))?;
                }
            }
            h.invariants()?;
        }
        let expected = match order[0] {
            0 => SyncOutcome::Acquired,
            1 => SyncOutcome::TimedOut,
            _ => SyncOutcome::Stopped,
        };
        assert_eq!(h.finish(token)?, expected);
        assert_eq!(
            h.sync.observe(&mut h.threads, OWNER, token, time(now)),
            Err(SyncError::Stale)
        );
        h.teardown()?;
    }
    Ok(())
}

#[test]
fn permit_grant_timeout_and_stop_orders_never_duplicate_a_permit() -> Result<(), SyncError> {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut h = Harness::new()?;
        let [a, b, _] = h.ids;
        let permit = h.sync.create_permit(&mut h.threads, OWNER, a, 0, 1)?;
        h.select(b)?;
        let token = pending(h.sync.acquire_permit(
            &mut h.threads,
            OWNER,
            b,
            permit,
            WaitMode::Wait(options(Some(1), true)),
            time(0),
        )?)?;
        let mut now = 0;
        for action in order {
            match action {
                0 => {
                    h.select(a)?;
                    h.sync
                        .release_permit(&mut h.threads, OWNER, a, permit, time(now))?;
                }
                1 => {
                    now = 1;
                    h.sync.observe(&mut h.threads, OWNER, token, time(now))?;
                }
                _ => {
                    h.threads.request_stop(OWNER, b)?;
                    h.sync.observe(&mut h.threads, OWNER, token, time(now))?;
                }
            }
            h.invariants()?;
        }
        let expected = match order[0] {
            0 => SyncOutcome::Acquired,
            1 => SyncOutcome::TimedOut,
            _ => SyncOutcome::Stopped,
        };
        assert_eq!(h.finish(token)?, expected);
        let Kind::Permit { count, .. } = h.sync.object(OWNER, permit.0)?.kind else {
            return Err(SyncError::Stale);
        };
        assert_eq!(count, u32::from(expected != SyncOutcome::Acquired));
        h.teardown()?;
    }
    Ok(())
}

#[test]
fn pending_completions_still_consume_wait_quota() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, c] = h.ids;
    h.sync.processes[0]
        .as_mut()
        .ok_or(SyncError::Stale)?
        .quota
        .waits = 1;
    let mutex = h.mutex(OwnerDeath::Poison)?;
    h.lock(a, mutex, WAIT, 0)?;
    let first = pending(h.lock(b, mutex, WAIT, 0)?)?;
    assert_eq!(h.lock(c, mutex, WAIT, 0), Err(SyncError::Exhausted));
    assert_eq!(h.threads.snapshot(OWNER, c)?.state, ThreadState::Running);
    h.unlock(a, mutex, 0)?;
    assert_eq!(h.lock(c, mutex, WAIT, 0), Err(SyncError::Exhausted));
    assert_eq!(h.finish(first)?, SyncOutcome::Acquired);
    let second = pending(h.lock(c, mutex, WAIT, 0)?)?;
    h.unlock(b, mutex, 0)?;
    assert_eq!(h.finish(second)?, SyncOutcome::Acquired);
    h.invariants()?;
    h.teardown()
}

#[test]
fn condition_timeout_reacquires_after_deadline_and_pins_both_objects() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, _] = h.ids;
    let mutex = h.mutex(OwnerDeath::Poison)?;
    let cond = h.sync.create_condition(&mut h.threads, OWNER, a)?;
    h.lock(a, mutex, WAIT, 0)?;
    let token = pending(h.sync.condition_wait(
        &mut h.threads,
        OWNER,
        a,
        ConditionWait {
            condition: cond,
            mutex,
            options: options(Some(1), true),
        },
        time(0),
    )?)?;
    h.lock(b, mutex, WAIT, 0)?;
    assert!(h.sync.observe(&mut h.threads, OWNER, token, time(1))?);
    assert_eq!(h.threads.snapshot(OWNER, a)?.state, ThreadState::Blocked);
    assert_eq!(
        h.sync.destroy_condition(&mut h.threads, OWNER, b, cond),
        Err(SyncError::Busy)
    );
    h.threads.request_stop(OWNER, a)?;
    assert!(!h.sync.observe(&mut h.threads, OWNER, token, time(2))?);
    h.unlock(b, mutex, 20)?;
    assert_eq!(
        h.sync.destroy_condition(&mut h.threads, OWNER, b, cond),
        Err(SyncError::Busy)
    );
    assert_eq!(
        h.sync.destroy_mutex(&mut h.threads, OWNER, b, mutex),
        Err(SyncError::Busy)
    );
    assert_eq!(h.finish(token)?, SyncOutcome::TimedOut);
    h.sync.require_owner(OWNER, a, mutex)?;
    h.sync.destroy_condition(&mut h.threads, OWNER, a, cond)?;
    h.invariants()?;
    h.teardown()
}

#[test]
fn notification_skips_ineligible_waiter_without_losing_signal() -> Result<(), SyncError> {
    for stop in [false, true] {
        let mut h = Harness::new()?;
        let [a, b, c] = h.ids;
        let mutex = h.mutex(OwnerDeath::Poison)?;
        let cond = h.sync.create_condition(&mut h.threads, OWNER, a)?;
        assert_eq!(
            h.sync
                .notify(&mut h.threads, OWNER, a, cond, false, time(0))?,
            0
        );
        h.lock(a, mutex, WAIT, 0)?;
        let first = pending(h.sync.condition_wait(
            &mut h.threads,
            OWNER,
            a,
            ConditionWait {
                condition: cond,
                mutex,
                options: options(if stop { None } else { Some(1) }, stop),
            },
            time(0),
        )?)?;
        h.lock(b, mutex, WAIT, 0)?;
        let second = pending(h.sync.condition_wait(
            &mut h.threads,
            OWNER,
            b,
            ConditionWait {
                condition: cond,
                mutex,
                options: options(None, false),
            },
            time(0),
        )?)?;
        h.lock(c, mutex, WAIT, 0)?;
        if stop {
            h.threads.request_stop(OWNER, a)?;
        }
        assert_eq!(
            h.sync
                .notify(&mut h.threads, OWNER, c, cond, false, time(1))?,
            1
        );
        h.unlock(c, mutex, 1)?;
        assert_eq!(
            h.finish(first)?,
            if stop {
                SyncOutcome::Stopped
            } else {
                SyncOutcome::TimedOut
            }
        );
        h.unlock(a, mutex, 1)?;
        assert_eq!(h.finish(second)?, SyncOutcome::Notified);
        h.invariants()?;
        h.teardown()?;
    }
    Ok(())
}

#[test]
fn notification_cohort_and_binding_survive_reacquisition() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, c] = h.ids;
    let mutex = h.mutex(OwnerDeath::Poison)?;
    let other = h.mutex(OwnerDeath::Poison)?;
    let cond = h.sync.create_condition(&mut h.threads, OWNER, a)?;
    h.lock(a, mutex, WAIT, 0)?;
    let first = pending(h.sync.condition_wait(
        &mut h.threads,
        OWNER,
        a,
        ConditionWait {
            condition: cond,
            mutex,
            options: options(Some(2), true),
        },
        time(0),
    )?)?;
    h.lock(b, other, WAIT, 0)?;
    assert_eq!(
        h.sync.condition_wait(
            &mut h.threads,
            OWNER,
            b,
            ConditionWait {
                condition: cond,
                mutex: other,
                options: options(None, false)
            },
            time(0)
        ),
        Err(SyncError::DifferentMutex)
    );
    h.sync.require_owner(OWNER, b, other)?;
    h.unlock(b, other, 0)?;
    h.lock(b, mutex, WAIT, 0)?;
    let second = pending(h.sync.condition_wait(
        &mut h.threads,
        OWNER,
        b,
        ConditionWait {
            condition: cond,
            mutex,
            options: options(None, false),
        },
        time(0),
    )?)?;
    h.lock(c, mutex, WAIT, 0)?;
    assert_eq!(
        h.sync
            .notify(&mut h.threads, OWNER, c, cond, true, time(1))?,
        2
    );
    h.threads.request_stop(OWNER, a)?;
    assert!(!h.sync.observe(&mut h.threads, OWNER, first, time(3))?);
    // A later waiter must not join the already selected broadcast cohort.
    let later = pending(h.sync.condition_wait(
        &mut h.threads,
        OWNER,
        c,
        ConditionWait {
            condition: cond,
            mutex,
            options: options(None, false),
        },
        time(3),
    )?)?;
    assert_eq!(h.finish(first)?, SyncOutcome::Notified);
    h.unlock(a, mutex, 3)?;
    assert_eq!(h.finish(second)?, SyncOutcome::Notified);
    h.unlock(b, mutex, 3)?;
    assert_eq!(h.threads.snapshot(OWNER, c)?.state, ThreadState::Blocked);
    assert_eq!(
        h.sync
            .notify(&mut h.threads, OWNER, b, cond, false, time(3))?,
        1
    );
    assert_eq!(h.finish(later)?, SyncOutcome::Notified);
    h.invariants()?;
    h.teardown()
}

#[test]
fn poison_completes_condition_queue_and_reacquire_without_ownership() -> Result<(), SyncError> {
    for selected in [false, true] {
        let mut h = Harness::new()?;
        let [a, b, c] = h.ids;
        let mutex = h.mutex(OwnerDeath::Poison)?;
        let cond = h.sync.create_condition(&mut h.threads, OWNER, a)?;
        h.lock(a, mutex, WAIT, 0)?;
        let condition_wait = pending(h.sync.condition_wait(
            &mut h.threads,
            OWNER,
            a,
            ConditionWait {
                condition: cond,
                mutex,
                options: options(None, false),
            },
            time(0),
        )?)?;
        h.lock(b, mutex, WAIT, 0)?;
        let lock_wait = pending(h.lock(c, mutex, WAIT, 0)?)?;
        h.select(b)?;
        if selected {
            h.sync
                .notify(&mut h.threads, OWNER, b, cond, false, time(0))?;
        }
        assert_eq!(h.threads.begin_exit(OWNER, b), Err(ThreadError::Busy));
        assert_eq!(
            h.sync.begin_exit(&mut h.threads, OWNER, b, time(0))?,
            ExitEffect::ThreadExiting
        );
        h.threads.complete(OWNER, b, 7)?;
        assert_eq!(h.finish(condition_wait)?, SyncOutcome::Poisoned);
        assert_eq!(h.unlock(a, mutex, 0), Err(SyncError::NotOwner));
        assert_eq!(
            h.lock(a, mutex, WAIT, 0)?,
            SyncStart::Complete(SyncOutcome::Poisoned)
        );
        assert_eq!(
            h.sync.destroy_mutex(&mut h.threads, OWNER, a, mutex),
            Err(SyncError::Busy)
        );
        assert_eq!(h.finish(lock_wait)?, SyncOutcome::Poisoned);
        h.sync.destroy_mutex(&mut h.threads, OWNER, c, mutex)?;
        h.sync.destroy_condition(&mut h.threads, OWNER, c, cond)?;
        h.invariants()?;
        h.teardown()?;
    }
    Ok(())
}

#[test]
fn essential_owner_death_revokes_all_execution_and_references() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, _] = h.ids;
    let mutex = h.mutex(OwnerDeath::FailProcess)?;
    h.lock(a, mutex, WAIT, 0)?;
    let token = pending(h.lock(b, mutex, WAIT, 0)?)?;
    h.select(a)?;
    assert_eq!(
        h.sync.begin_exit(&mut h.threads, OWNER, a, time(0))?,
        ExitEffect::ProcessStopped
    );
    assert_eq!(h.sync.usage(OWNER), (0, 0));
    assert_eq!(h.threads.committed_pages(), 6);
    for id in h.ids {
        assert_eq!(h.threads.snapshot(OWNER, id)?.state, ThreadState::Revoked);
    }
    assert_eq!(h.threads.wake(OWNER, token.0), Err(ThreadError::Stale));
    h.teardown()
}

#[test]
fn grant_is_owned_before_resume_and_permits_are_not_refunded_on_exit() -> Result<(), SyncError> {
    for mutex_case in [false, true] {
        let mut h = Harness::new()?;
        let [a, b, _] = h.ids;
        let mutex = h.mutex(OwnerDeath::Poison)?;
        let permit = h.sync.create_permit(&mut h.threads, OWNER, a, 0, 1)?;
        let token = if mutex_case {
            h.lock(a, mutex, WAIT, 0)?;
            let token = pending(h.lock(b, mutex, WAIT, 0)?)?;
            h.unlock(a, mutex, 0)?;
            token
        } else {
            h.select(b)?;
            let token =
                pending(
                    h.sync
                        .acquire_permit(&mut h.threads, OWNER, b, permit, WAIT, time(0))?,
                )?;
            h.select(a)?;
            h.sync
                .release_permit(&mut h.threads, OWNER, a, permit, time(0))?;
            token
        };
        h.invariants()?;
        h.select(b)?;
        // Captured retirement before result consumption must retain the committed effect.
        h.sync.begin_exit(&mut h.threads, OWNER, b, time(0))?;
        h.threads.complete(OWNER, b, 0)?;
        h.select(a)?;
        assert_eq!(
            h.sync.observe(&mut h.threads, OWNER, token, time(0)),
            Err(SyncError::Stale)
        );
        if mutex_case {
            assert_eq!(
                h.lock(a, mutex, WAIT, 0)?,
                SyncStart::Complete(SyncOutcome::Poisoned)
            );
        } else {
            assert_eq!(
                h.sync
                    .acquire_permit(&mut h.threads, OWNER, a, permit, WaitMode::Try, time(0))?,
                SyncStart::Complete(SyncOutcome::WouldBlock)
            );
        }
        h.invariants()?;
        h.teardown()?;
    }
    Ok(())
}

#[test]
fn permits_skip_expired_waiters_and_enforce_overflow_and_pending_references()
-> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, c] = h.ids;
    let permit = h.sync.create_permit(&mut h.threads, OWNER, a, 0, 1)?;
    h.select(b)?;
    let first = pending(h.sync.acquire_permit(
        &mut h.threads,
        OWNER,
        b,
        permit,
        WaitMode::Wait(options(Some(1), false)),
        time(0),
    )?)?;
    h.select(c)?;
    let second =
        pending(
            h.sync
                .acquire_permit(&mut h.threads, OWNER, c, permit, WAIT, time(0))?,
        )?;
    h.select(a)?;
    h.sync
        .release_permit(&mut h.threads, OWNER, a, permit, time(1))?;
    assert_eq!(
        h.sync.destroy_permit(&mut h.threads, OWNER, a, permit),
        Err(SyncError::Busy)
    );
    assert_eq!(h.finish(first)?, SyncOutcome::TimedOut);
    assert_eq!(h.finish(second)?, SyncOutcome::Acquired);
    h.sync
        .release_permit(&mut h.threads, OWNER, c, permit, time(1))?;
    assert_eq!(
        h.sync
            .release_permit(&mut h.threads, OWNER, c, permit, time(1)),
        Err(SyncError::Overflow)
    );
    h.sync
        .acquire_permit(&mut h.threads, OWNER, c, permit, WaitMode::Try, time(1))?;
    h.sync.destroy_permit(&mut h.threads, OWNER, c, permit)?;
    h.invariants()?;
    h.teardown()
}

#[test]
fn admission_and_generation_failures_preserve_mutex_ownership() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let a = h.ids[0];
    let mutex = h.mutex(OwnerDeath::Poison)?;
    let condition = h.sync.create_condition(&mut h.threads, OWNER, a)?;
    h.lock(a, mutex, WAIT, 0)?;
    for exhausted_sequence in [false, true] {
        if exhausted_sequence {
            h.sync.processes[0]
                .as_mut()
                .ok_or(SyncError::Stale)?
                .quota
                .waits = 3;
            h.threads.record_mut(OWNER, a)?.wait_sequence = u64::MAX;
        } else {
            h.sync.processes[0]
                .as_mut()
                .ok_or(SyncError::Stale)?
                .quota
                .waits = 0;
        }
        let result = h.sync.condition_wait(
            &mut h.threads,
            OWNER,
            a,
            ConditionWait {
                condition,
                mutex,
                options: options(None, false),
            },
            time(0),
        );
        assert_eq!(
            result,
            Err(if exhausted_sequence {
                SyncError::Thread(ThreadError::Exhausted)
            } else {
                SyncError::Exhausted
            })
        );
        h.sync.require_owner(OWNER, a, mutex)?;
        assert_eq!(h.sync.usage(OWNER).1, 0);
        h.invariants()?;
    }
    h.teardown()
}

#[test]
fn stale_wait_cannot_complete_a_later_operation() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, _] = h.ids;
    let mutex = h.mutex(OwnerDeath::Poison)?;
    h.lock(a, mutex, WAIT, 0)?;
    let first = pending(h.lock(b, mutex, WaitMode::Wait(options(Some(1), false)), 0)?)?;
    h.sync.observe(&mut h.threads, OWNER, first, time(1))?;
    assert_eq!(h.finish(first)?, SyncOutcome::TimedOut);
    let second = pending(h.lock(b, mutex, WAIT, 1)?)?;
    assert_ne!(first, second);
    assert_eq!(
        h.sync.observe(&mut h.threads, OWNER, first, time(1)),
        Err(SyncError::Stale)
    );
    assert_eq!(h.threads.wake(OWNER, first.0), Err(ThreadError::Busy));
    h.unlock(a, mutex, 1)?;
    assert_eq!(h.finish(second)?, SyncOutcome::Acquired);
    h.invariants()?;
    h.teardown()
}

#[test]
fn object_tokens_quota_and_process_pairing_cannot_be_bypassed() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let a = h.ids[0];
    let old = h.mutex(OwnerDeath::Poison)?;
    h.sync.destroy_mutex(&mut h.threads, OWNER, a, old)?;
    let new = h.mutex(OwnerDeath::Poison)?;
    assert_eq!(old.0.slot, new.0.slot);
    assert_ne!(old, new);
    assert_eq!(h.lock(a, old, WAIT, 0), Err(SyncError::Stale));
    h.threads.register_process(
        OTHER,
        ThreadQuota {
            records: 3,
            pages: 6,
        },
    )?;
    h.sync.register_process(
        &mut h.threads,
        OTHER,
        SyncQuota {
            objects: 2,
            waits: 1,
        },
    )?;
    let other = h.threads.prepare_initial(
        OTHER,
        ThreadResources {
            reservation: 4,
            pages: 2,
        },
    )?;
    h.threads.start(OTHER, other)?;
    assert_eq!(h.lock(other, new, WAIT, 0), Err(SyncError::WrongOwner));
    let mut wrong = SyncTable::new(1, 2, 1)?;
    assert_eq!(
        wrong.register_process(
            &mut h.threads,
            OWNER,
            SyncQuota {
                objects: 2,
                waits: 1
            }
        ),
        Err(SyncError::DuplicateProcess)
    );
    assert_eq!(
        wrong.stop_process(&mut h.threads, OWNER),
        Err(SyncError::UnknownProcess)
    );
    h.select(a)?;
    for _ in 1..6 {
        h.sync.create_condition(&mut h.threads, OWNER, a)?;
    }
    assert_eq!(
        h.sync.create_condition(&mut h.threads, OWNER, a),
        Err(SyncError::Exhausted)
    );
    h.sync.stop_process(&mut h.threads, OTHER)?;
    h.threads.release_resources(OTHER, other)?;
    h.threads.reap(OTHER, other)?;
    h.threads.remove_process(OTHER)?;
    h.invariants()?;
    h.teardown()
}

#[test]
fn object_generations_retire_instead_of_wrapping() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    for slot in &mut h.sync.objects {
        slot.generation = u32::MAX;
    }
    assert_eq!(h.mutex(OwnerDeath::Poison), Err(SyncError::Exhausted));
    assert_eq!(h.sync.usage(OWNER), (0, 0));
    h.teardown()
}

#[test]
fn lifecycle_cannot_release_resources_before_sync_drains() -> Result<(), SyncError> {
    let mut h = Harness::new()?;
    let [a, b, _] = h.ids;
    let mutex = h.mutex(OwnerDeath::Poison)?;
    h.lock(a, mutex, WAIT, 0)?;
    let token = pending(h.lock(b, mutex, WAIT, 0)?)?;
    h.threads.stop_process(OWNER)?;
    assert_eq!(
        h.threads.release_resources(OWNER, a),
        Err(ThreadError::Busy)
    );
    assert_eq!(
        h.threads.release_resources(OWNER, b),
        Err(ThreadError::Busy)
    );
    assert_eq!(
        h.sync.observe(&mut h.threads, OWNER, token, time(0)),
        Err(SyncError::Thread(ThreadError::Stopping))
    );
    h.teardown()
}

#[test]
fn bounded_event_schedules_preserve_queues_and_restore_resource_baseline() -> Result<(), SyncError>
{
    // Exhaust every length-five schedule over notify, timeout, stop, unlock and exit.
    for encoded in 0..3125_u32 {
        let mut h = Harness::new()?;
        let [a, b, c] = h.ids;
        let mutex = h.mutex(OwnerDeath::Poison)?;
        let condition = h.sync.create_condition(&mut h.threads, OWNER, a)?;
        h.lock(a, mutex, WAIT, 0)?;
        let first = pending(h.sync.condition_wait(
            &mut h.threads,
            OWNER,
            a,
            ConditionWait {
                condition,
                mutex,
                options: options(Some(1), true),
            },
            time(0),
        )?)?;
        h.lock(b, mutex, WAIT, 0)?;
        let second = pending(h.lock(c, mutex, WaitMode::Wait(options(Some(2), true)), 0)?)?;
        let capacities = (
            h.sync.processes.capacity(),
            h.sync.objects.capacity(),
            h.sync.waits.capacity(),
        );
        let mut code = encoded;
        let mut now = 0;
        for _ in 0..5 {
            let action = code % 5;
            code /= 5;
            match action {
                0 => {
                    if h.select(b).is_ok() {
                        let _ =
                            h.sync
                                .notify(&mut h.threads, OWNER, b, condition, false, time(now));
                    }
                }
                1 => {
                    now += 1;
                    let _ = h.sync.observe(&mut h.threads, OWNER, first, time(now));
                    let _ = h.sync.observe(&mut h.threads, OWNER, second, time(now));
                }
                2 => {
                    h.threads.request_stop(OWNER, a)?;
                    let _ = h.sync.observe(&mut h.threads, OWNER, first, time(now));
                }
                3 => {
                    let _ = h.unlock(b, mutex, now);
                }
                _ => {
                    if h.select(b).is_ok() {
                        let _ = h.sync.begin_exit(&mut h.threads, OWNER, b, time(now));
                    }
                }
            }
            h.invariants()?;
            assert_eq!(
                capacities,
                (
                    h.sync.processes.capacity(),
                    h.sync.objects.capacity(),
                    h.sync.waits.capacity()
                )
            );
        }
        h.teardown()?;
    }
    Ok(())
}

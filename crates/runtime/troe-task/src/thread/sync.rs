//! Bounded process-private synchronization policy, paired with [`ThreadTable`].
//!
//! This is a serialized portable model, not a native service or memory-ordering
//! implementation. One composition owns both tables and supplies authenticated
//! callers and boot-relative clock observations. Wait publication, release and
//! grant are one transition under that ownership. All storage is reserved at
//! construction; intrusive queues reuse the same node during reacquisition.
//! Completed waits retain references until consumed or retired, including when
//! ownership has been granted but the thread has not resumed.

use super::{ProcessId, ThreadError, ThreadId, ThreadState, ThreadTable, ThreadWait};
use crate::{MAX_TASKS, MonotonicMillis};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectId {
    process: ProcessId,
    slot: usize,
    generation: u32,
}

/// Opaque process-owned mutex lifetime, scoped to its originating table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutexId(ObjectId);

/// Opaque process-owned condition lifetime, scoped to its originating table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionId(ObjectId);

/// Opaque process-owned permit lifetime, scoped to its originating table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermitId(ObjectId);

/// One outstanding operation; duplicate and delayed events cannot reuse it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncWait(ThreadWait);

/// Immutable response to exit while owning a mutex.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerDeath {
    /// Permanently reject acquisition, without granting ownership to waiters.
    Poison,
    /// Revoke the entire process for loss of an essential runtime invariant.
    FailProcess,
}

/// Independent immutable metadata limits for one process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncQuota {
    /// Live objects, including poisoned ones.
    pub objects: usize,
    /// Queued, reacquiring and completed-but-unconsumed operations.
    pub waits: usize,
}

/// Native-model blocking options, after wire/clock validation by composition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitOptions {
    /// Absolute monotonic deadline; `None` means no deadline.
    pub deadline: Option<MonotonicMillis>,
    /// Observe the thread's sticky cooperative stop request.
    pub observe_stop: bool,
}

/// One condition operation, with its mutex and immutable wait options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionWait {
    /// Queue to join; notifications are not stored for future callers.
    pub condition: ConditionId,
    /// Mutex currently owned by the caller, also used for reacquisition.
    pub mutex: MutexId,
    /// Deadline and cooperative stop observation for the condition phase.
    pub options: WaitOptions,
}

/// Immediate availability and deadline-aware blocking have separate contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitMode {
    /// Test availability once without a deadline or a queue reservation.
    Try,
    /// Reject an already expired deadline/stop before acquiring anything.
    Wait(WaitOptions),
}

/// An operation result with explicit ownership semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncOutcome {
    /// The mutex or one permit was granted exactly once.
    Acquired,
    /// No immediate resource was available; no wait was admitted.
    WouldBlock,
    /// Condition notification won; the original mutex has been reacquired.
    Notified,
    /// Deadline won; a condition operation retains/reacquires its mutex.
    TimedOut,
    /// Cooperative stop won; a condition operation retains/reacquires its mutex.
    Stopped,
    /// The mutex is poisoned. This result NEVER grants mutex ownership.
    Poisoned,
}

/// An immediate result or an operation suspended in the paired thread table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStart {
    /// Returned without blocking.
    Complete(SyncOutcome),
    /// Consume the result after dispatch using [`SyncTable::finish_wait`].
    Waiting(SyncWait),
}

/// Logical result of orderly thread retirement; physical capture is separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitEffect {
    /// The thread is Exiting; normal completion/reclamation can follow.
    ThreadExiting,
    /// An essential mutex was abandoned; all process execution was revoked.
    ProcessStopped,
}

/// Rejected synchronization transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    /// Lifecycle validation failed; includes stale/non-running callers.
    Thread(ThreadError),
    /// Invalid constructor, quota or permit bounds.
    InvalidLimit,
    /// Initial metadata allocation failed.
    MetadataExhausted,
    /// The owner has no registration in this synchronization table.
    UnknownProcess,
    /// The owner is already paired with a synchronization table.
    DuplicateProcess,
    /// A process/global metadata limit or object generation is exhausted.
    Exhausted,
    /// A handle belongs to another process.
    WrongOwner,
    /// A handle or operation no longer denotes a retained lifetime.
    Stale,
    /// Ownership, waits or completion references prevent this operation.
    Busy,
    /// Unlock or condition wait requires the calling thread to own the mutex.
    NotOwner,
    /// Non-recursive self-lock would deadlock.
    Deadlock,
    /// A condition still references another mutex.
    DifferentMutex,
    /// Releasing a permit would exceed its immutable maximum.
    Overflow,
    /// Composition supplied a regressing monotonic observation.
    ClockRegressed,
}

impl From<ThreadError> for SyncError {
    fn from(value: ThreadError) -> Self {
        Self::Thread(value)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Queue {
    head: Option<usize>,
    tail: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Mutex {
        owner: Option<ThreadId>,
        poisoned: bool,
        policy: OwnerDeath,
    },
    Condition,
    Permit {
        count: u32,
        maximum: u32,
    },
}

#[derive(Clone, Copy, Debug)]
struct Object {
    id: ObjectId,
    kind: Kind,
    queue: Queue,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    generation: u32,
    object: Option<Object>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Queued,
    Reacquiring(SyncOutcome),
    Complete(SyncOutcome),
}

#[derive(Clone, Copy, Debug)]
struct Waiter {
    token: SyncWait,
    source: ObjectId,
    mutex: Option<MutexId>,
    phase: Phase,
    options: WaitOptions,
    queued_on: Option<ObjectId>,
    previous: Option<usize>,
    next: Option<usize>,
}

impl Waiter {
    fn references(self, object: ObjectId) -> bool {
        self.source == object || self.mutex.is_some_and(|mutex| mutex.0 == object)
    }
}

#[derive(Clone, Copy, Debug)]
struct Process {
    id: ProcessId,
    quota: SyncQuota,
}

/// Fixed-capacity FIFO queues and closed synchronization object kinds.
#[derive(Debug)]
pub struct SyncTable {
    processes: Vec<Option<Process>>,
    objects: Vec<Slot>,
    waits: Vec<Option<Waiter>>,
    last_now: MonotonicMillis,
}

impl SyncTable {
    /// Reserve all storage. No operation after construction allocates.
    ///
    /// # Errors
    /// Rejects zero/excessive bounds and failed allocation.
    pub fn new(processes: usize, objects: usize, waits: usize) -> Result<Self, SyncError> {
        if processes == 0
            || processes > objects
            || objects > MAX_TASKS
            || waits == 0
            || waits > MAX_TASKS
        {
            return Err(SyncError::InvalidLimit);
        }
        Ok(Self {
            processes: reserved(processes, None)?,
            objects: reserved(
                objects,
                Slot {
                    generation: 0,
                    object: None,
                },
            )?,
            waits: reserved(waits, None)?,
            last_now: MonotonicMillis::default(),
        })
    }

    /// Pair an admitted process with exactly one synchronization table.
    ///
    /// # Errors
    /// Rejects unknown/stopping/duplicate processes, invalid quotas or capacity.
    pub fn register_process(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        quota: SyncQuota,
    ) -> Result<(), SyncError> {
        let process = threads.process(owner)?;
        if process.stopping {
            return Err(ThreadError::Stopping.into());
        }
        if process.sync_registered
            || self
                .processes
                .iter()
                .flatten()
                .any(|process| process.id == owner)
        {
            return Err(SyncError::DuplicateProcess);
        }
        if quota.objects == 0
            || quota.objects > self.objects.len()
            || quota.waits > self.waits.len()
            || quota.waits > process.quota.records
        {
            return Err(SyncError::InvalidLimit);
        }
        let slot = self
            .processes
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(SyncError::Exhausted)?;
        *slot = Some(Process { id: owner, quota });
        threads.process_mut(owner)?.sync_registered = true;
        Ok(())
    }

    /// Remove an empty registration before removing the process lifetime.
    ///
    /// # Errors
    /// Rejects unknown owners and retained objects/operations.
    pub fn remove_process(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
    ) -> Result<(), SyncError> {
        self.process(owner)?;
        if self.usage(owner) != (0, 0) {
            return Err(SyncError::Busy);
        }
        threads.process_mut(owner)?.sync_registered = false;
        for slot in &mut self.processes {
            if slot.is_some_and(|process| process.id == owner) {
                *slot = None;
            }
        }
        Ok(())
    }

    /// Create a non-recursive mutex with immutable owner-death policy.
    ///
    /// # Errors
    /// Rejects invalid callers and exhausted admission before publication.
    pub fn create_mutex(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        policy: OwnerDeath,
    ) -> Result<MutexId, SyncError> {
        self.create(
            threads,
            owner,
            caller,
            Kind::Mutex {
                owner: None,
                poisoned: false,
                policy,
            },
        )
        .map(MutexId)
    }

    /// Create an unbound condition with no stored notifications.
    ///
    /// # Errors
    /// Rejects invalid callers and exhausted admission before publication.
    pub fn create_condition(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
    ) -> Result<ConditionId, SyncError> {
        self.create(threads, owner, caller, Kind::Condition)
            .map(ConditionId)
    }

    /// Create an ownerless counter with a nonzero immutable maximum.
    ///
    /// # Errors
    /// Rejects invalid bounds/callers and exhausted admission.
    pub fn create_permit(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        initial: u32,
        maximum: u32,
    ) -> Result<PermitId, SyncError> {
        if maximum == 0 || initial > maximum {
            return Err(SyncError::InvalidLimit);
        }
        self.create(
            threads,
            owner,
            caller,
            Kind::Permit {
                count: initial,
                maximum,
            },
        )
        .map(PermitId)
    }

    /// Acquire or queue for an owner-checked mutex.
    ///
    /// # Errors
    /// Rejects invalid callers/handles, self-lock, clock regression and exhausted waits.
    pub fn lock(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        mutex: MutexId,
        mode: WaitMode,
        now: MonotonicMillis,
    ) -> Result<SyncStart, SyncError> {
        self.caller(threads, owner, caller)?;
        let Kind::Mutex {
            owner: holder,
            poisoned,
            ..
        } = self.object(owner, mutex.0)?.kind
        else {
            return Err(SyncError::Stale);
        };
        if holder == Some(caller) {
            return Err(SyncError::Deadlock);
        }
        self.clock(now)?;
        if let Some(outcome) = Self::early(threads, caller, mode, now)? {
            return Ok(SyncStart::Complete(outcome));
        }
        if poisoned {
            return Ok(SyncStart::Complete(SyncOutcome::Poisoned));
        }
        if holder.is_none() {
            self.set_owner(threads, mutex, Some(caller))?;
            return Ok(SyncStart::Complete(SyncOutcome::Acquired));
        }
        self.wait_or_try(threads, caller, mutex.0, None, mode)
    }

    /// Release and directly hand ownership to the first eligible waiter.
    ///
    /// # Errors
    /// Rejects invalid callers/handles, non-owner unlock and clock regression.
    pub fn unlock(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        mutex: MutexId,
        now: MonotonicMillis,
    ) -> Result<(), SyncError> {
        self.caller(threads, owner, caller)?;
        self.require_owner(owner, caller, mutex)?;
        self.clock(now)?;
        self.set_owner(threads, mutex, None)?;
        self.grant_mutex(threads, mutex, now)
    }

    /// Publish a condition wait and release its owned mutex atomically.
    ///
    /// Ordinary completion retains/reacquires the mutex, even after a deadline.
    /// Poison is a separate failure without ownership. Binding and destruction
    /// references survive notification, reacquisition and pending completion.
    ///
    /// # Errors
    /// Validation, binding and admission errors leave the mutex owned by caller.
    pub fn condition_wait(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        request: ConditionWait,
        now: MonotonicMillis,
    ) -> Result<SyncStart, SyncError> {
        let ConditionWait {
            condition,
            mutex,
            options,
        } = request;
        self.caller(threads, owner, caller)?;
        self.object(owner, condition.0)?;
        self.require_owner(owner, caller, mutex)?;
        if self
            .waits
            .iter()
            .flatten()
            .any(|wait| wait.source == condition.0 && wait.mutex != Some(mutex))
        {
            return Err(SyncError::DifferentMutex);
        }
        self.clock(now)?;
        if let Some(outcome) = Self::due(threads, caller, options, now)? {
            return Ok(SyncStart::Complete(outcome));
        }
        let token = self.admit(threads, caller, condition.0, Some(mutex), options)?;
        self.set_owner(threads, mutex, None)?;
        self.grant_mutex(threads, mutex, now)?;
        Ok(SyncStart::Waiting(token))
    }

    /// Notify one eligible waiter, or the entire currently admitted cohort.
    ///
    /// Expired/stopped waiters reacquire with their existing cause and do not
    /// consume a notification. This atomic model bounds work by table capacity;
    /// native composition must also enforce its interrupt/work-quantum budget.
    ///
    /// # Errors
    /// Rejects invalid callers/handles and clock regression.
    pub fn notify(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        condition: ConditionId,
        all: bool,
        now: MonotonicMillis,
    ) -> Result<usize, SyncError> {
        self.caller(threads, owner, caller)?;
        self.object(owner, condition.0)?;
        self.clock(now)?;
        let mut notified = 0;
        while let Some(index) = self.pop(condition.0)? {
            let waiter = self.waits[index].ok_or(SyncError::Stale)?;
            let cause = Self::due(threads, waiter.token.0.thread, waiter.options, now)?
                .unwrap_or(SyncOutcome::Notified);
            self.reacquire(threads, index, cause, now)?;
            if cause == SyncOutcome::Notified {
                notified += 1;
                if !all {
                    break;
                }
            }
        }
        Ok(notified)
    }

    /// Consume one ownerless permit, or queue without inventing an owner.
    ///
    /// # Errors
    /// Rejects invalid callers/handles, clock regression and exhausted waits.
    pub fn acquire_permit(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        permit: PermitId,
        mode: WaitMode,
        now: MonotonicMillis,
    ) -> Result<SyncStart, SyncError> {
        self.caller(threads, owner, caller)?;
        let Kind::Permit { count, maximum } = self.object(owner, permit.0)?.kind else {
            return Err(SyncError::Stale);
        };
        self.clock(now)?;
        if let Some(outcome) = Self::early(threads, caller, mode, now)? {
            return Ok(SyncStart::Complete(outcome));
        }
        if count != 0 {
            self.object_mut(permit.0)?.kind = Kind::Permit {
                count: count - 1,
                maximum,
            };
            return Ok(SyncStart::Complete(SyncOutcome::Acquired));
        }
        self.wait_or_try(threads, caller, permit.0, None, mode)
    }

    /// Release one permit, transferring directly to an eligible waiter first.
    ///
    /// # Errors
    /// Rejects invalid callers/handles, overflow and clock regression.
    pub fn release_permit(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        permit: PermitId,
        now: MonotonicMillis,
    ) -> Result<(), SyncError> {
        self.caller(threads, owner, caller)?;
        let Kind::Permit { count, maximum } = self.object(owner, permit.0)?.kind else {
            return Err(SyncError::Stale);
        };
        if count == maximum {
            return Err(SyncError::Overflow);
        }
        self.clock(now)?;
        while let Some(index) = self.pop(permit.0)? {
            let waiter = self.waits[index].ok_or(SyncError::Stale)?;
            if let Some(outcome) = Self::due(threads, waiter.token.0.thread, waiter.options, now)? {
                self.complete_wait(threads, index, outcome)?;
            } else {
                self.complete_wait(threads, index, SyncOutcome::Acquired)?;
                return Ok(());
            }
        }
        self.object_mut(permit.0)?.kind = Kind::Permit {
            count: count + 1,
            maximum,
        };
        Ok(())
    }

    /// Observe deadline/stop for this exact wait generation.
    ///
    /// A committed grant or selected condition result wins over later events.
    /// `false` means no change, including while reacquiring after selection.
    ///
    /// # Errors
    /// Rejects stale/cross-owner operations, stopping and clock regression.
    pub fn observe(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        token: SyncWait,
        now: MonotonicMillis,
    ) -> Result<bool, SyncError> {
        self.active(threads, owner)?;
        let index = self.wait_index(owner, token)?;
        self.clock(now)?;
        let waiter = self.waits[index].ok_or(SyncError::Stale)?;
        if waiter.phase != Phase::Queued {
            return Ok(false);
        }
        let Some(cause) = Self::due(threads, token.0.thread, waiter.options, now)? else {
            return Ok(false);
        };
        self.unlink(waiter.source, index)?;
        if waiter.mutex.is_some() {
            self.reacquire(threads, index, cause, now)?;
        } else {
            self.complete_wait(threads, index, cause)?;
        }
        Ok(true)
    }

    /// Consume a completed operation once, after the waiting thread is dispatched.
    ///
    /// # Errors
    /// Rejects wrong callers, stale/non-completed operations and non-running threads.
    pub fn finish_wait(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        token: SyncWait,
    ) -> Result<SyncOutcome, SyncError> {
        self.active(threads, owner)?;
        if caller != token.0.thread {
            return Err(SyncError::NotOwner);
        }
        let record = threads.record(owner, caller)?;
        if record.snapshot.state != ThreadState::Running {
            return Err(ThreadError::InvalidState.into());
        }
        let index = self.wait_index(owner, token)?;
        let Phase::Complete(outcome) = self.waits[index].ok_or(SyncError::Stale)?.phase else {
            return Err(SyncError::Busy);
        };
        self.waits[index] = None;
        threads.record_mut(owner, caller)?.sync_wait = false;
        Ok(outcome)
    }

    /// Destroy an unowned mutex only after every operation reference drains.
    ///
    /// # Errors
    /// Rejects invalid callers/tokens and held or referenced objects.
    pub fn destroy_mutex(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        mutex: MutexId,
    ) -> Result<(), SyncError> {
        self.destroy(threads, owner, caller, mutex.0)
    }

    /// Destroy a condition only after queued/reacquiring/completed waits drain.
    ///
    /// # Errors
    /// Rejects invalid callers/tokens and referenced objects.
    pub fn destroy_condition(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        condition: ConditionId,
    ) -> Result<(), SyncError> {
        self.destroy(threads, owner, caller, condition.0)
    }

    /// Destroy a permit with no outstanding operations, regardless of count.
    ///
    /// Consumer quiescence is application policy: permits have no owner to prove it.
    ///
    /// # Errors
    /// Rejects invalid callers/tokens and referenced objects.
    pub fn destroy_permit(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        permit: PermitId,
    ) -> Result<(), SyncError> {
        self.destroy(threads, owner, caller, permit.0)
    }

    /// Retire a captured running thread after userspace cleanup has ended.
    ///
    /// Abandoned application mutexes poison every wait, including condition
    /// phases. Essential mutex abandonment revokes the whole process. A granted
    /// permit is never refunded. This method does not run user destructors.
    ///
    /// # Errors
    /// Rejects stale/non-running callers, stopping and clock regression.
    pub fn begin_exit(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        now: MonotonicMillis,
    ) -> Result<ExitEffect, SyncError> {
        self.active(threads, owner)?;
        if threads.record(owner, caller)?.snapshot.state != ThreadState::Running {
            return Err(ThreadError::InvalidState.into());
        }
        self.clock(now)?;
        if self.objects.iter().filter_map(|slot| slot.object).any(|object| matches!(object.kind, Kind::Mutex { owner: Some(holder), policy: OwnerDeath::FailProcess, .. } if holder == caller)) {
            self.stop_process(threads, owner)?;
            return Ok(ExitEffect::ProcessStopped);
        }
        for waiter in &mut self.waits {
            if waiter.is_some_and(|waiter| waiter.token.0.thread == caller) {
                *waiter = None;
            }
        }
        threads.record_mut(owner, caller)?.sync_wait = false;
        for index in 0..self.objects.len() {
            let Some(object) = self.objects[index].object else {
                continue;
            };
            if matches!(object.kind, Kind::Mutex { owner: Some(holder), .. } if holder == caller) {
                self.poison(threads, MutexId(object.id))?;
            }
        }
        threads.begin_exit(owner, caller)?;
        Ok(ExitEffect::ThreadExiting)
    }

    /// Revoke the process and drain logical synchronization references atomically.
    ///
    /// Native contexts, timers, callbacks and backing still require capture and
    /// reclamation before the lifecycle table's resource acknowledgement.
    ///
    /// # Errors
    /// Rejects unknown lifecycle processes. Repeated teardown is harmless.
    pub fn stop_process(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
    ) -> Result<(), SyncError> {
        // Validate pairing before altering a process that could belong to another table.
        if threads.process(owner)?.sync_registered {
            self.process(owner)?;
        }
        threads.stop_process(owner)?;
        for waiter in &mut self.waits {
            if waiter.is_some_and(|waiter| waiter.token.0.thread.process == owner) {
                *waiter = None;
            }
        }
        for slot in &mut self.objects {
            if slot.object.is_some_and(|object| object.id.process == owner) {
                slot.object = None;
            }
        }
        for record in threads
            .slots
            .iter_mut()
            .filter_map(|slot| slot.record.as_mut())
        {
            if record.snapshot.id.process == owner {
                record.sync_wait = false;
                record.owned_mutexes = 0;
            }
        }
        threads.process_mut(owner)?.sync_objects = 0;
        threads.process_mut(owner)?.sync_registered = false;
        for slot in &mut self.processes {
            if slot.is_some_and(|process| process.id == owner) {
                *slot = None;
            }
        }
        Ok(())
    }

    /// Exact live object and retained wait counts for one owner.
    #[must_use]
    pub fn usage(&self, owner: ProcessId) -> (usize, usize) {
        (
            self.objects
                .iter()
                .filter(|slot| slot.object.is_some_and(|object| object.id.process == owner))
                .count(),
            self.waits
                .iter()
                .flatten()
                .filter(|waiter| waiter.token.0.thread.process == owner)
                .count(),
        )
    }

    fn create(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        kind: Kind,
    ) -> Result<ObjectId, SyncError> {
        self.caller(threads, owner, caller)?;
        if self.usage(owner).0 >= self.process(owner)?.quota.objects {
            return Err(SyncError::Exhausted);
        }
        let (index, slot) = self
            .objects
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.object.is_none() && slot.generation < u32::MAX)
            .ok_or(SyncError::Exhausted)?;
        slot.generation += 1;
        let id = ObjectId {
            process: owner,
            slot: index,
            generation: slot.generation,
        };
        slot.object = Some(Object {
            id,
            kind,
            queue: Queue::default(),
        });
        threads.process_mut(owner)?.sync_objects += 1;
        Ok(id)
    }

    fn destroy(
        &mut self,
        threads: &mut ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
        id: ObjectId,
    ) -> Result<(), SyncError> {
        self.caller(threads, owner, caller)?;
        let object = self.object(owner, id)?;
        if matches!(object.kind, Kind::Mutex { owner: Some(_), .. })
            || self
                .waits
                .iter()
                .flatten()
                .any(|waiter| waiter.references(id))
        {
            return Err(SyncError::Busy);
        }
        self.objects[id.slot].object = None;
        threads.process_mut(owner)?.sync_objects -= 1;
        Ok(())
    }

    fn wait_or_try(
        &mut self,
        threads: &mut ThreadTable,
        caller: ThreadId,
        source: ObjectId,
        mutex: Option<MutexId>,
        mode: WaitMode,
    ) -> Result<SyncStart, SyncError> {
        match mode {
            WaitMode::Try => Ok(SyncStart::Complete(SyncOutcome::WouldBlock)),
            WaitMode::Wait(options) => self
                .admit(threads, caller, source, mutex, options)
                .map(SyncStart::Waiting),
        }
    }

    fn admit(
        &mut self,
        threads: &mut ThreadTable,
        caller: ThreadId,
        source: ObjectId,
        mutex: Option<MutexId>,
        options: WaitOptions,
    ) -> Result<SyncWait, SyncError> {
        if self.usage(caller.process).1 >= self.process(caller.process)?.quota.waits {
            return Err(SyncError::Exhausted);
        }
        let index = self
            .waits
            .iter()
            .position(Option::is_none)
            .ok_or(SyncError::Exhausted)?;
        let token = SyncWait(threads.block(caller.process, caller)?);
        threads.record_mut(caller.process, caller)?.sync_wait = true;
        self.waits[index] = Some(Waiter {
            token,
            source,
            mutex,
            phase: Phase::Queued,
            options,
            queued_on: None,
            previous: None,
            next: None,
        });
        self.push(source, index)?;
        Ok(token)
    }

    fn early(
        threads: &ThreadTable,
        caller: ThreadId,
        mode: WaitMode,
        now: MonotonicMillis,
    ) -> Result<Option<SyncOutcome>, SyncError> {
        match mode {
            WaitMode::Try => Ok(None),
            WaitMode::Wait(options) => Self::due(threads, caller, options, now),
        }
    }

    fn due(
        threads: &ThreadTable,
        caller: ThreadId,
        options: WaitOptions,
        now: MonotonicMillis,
    ) -> Result<Option<SyncOutcome>, SyncError> {
        if options.deadline.is_some_and(|deadline| now >= deadline) {
            return Ok(Some(SyncOutcome::TimedOut));
        }
        if options.observe_stop
            && threads
                .record(caller.process, caller)?
                .snapshot
                .stop_requested
        {
            return Ok(Some(SyncOutcome::Stopped));
        }
        Ok(None)
    }

    fn reacquire(
        &mut self,
        threads: &mut ThreadTable,
        index: usize,
        cause: SyncOutcome,
        now: MonotonicMillis,
    ) -> Result<(), SyncError> {
        let waiter = self.waits[index].as_mut().ok_or(SyncError::Stale)?;
        let mutex = waiter.mutex.ok_or(SyncError::Stale)?;
        waiter.phase = Phase::Reacquiring(cause);
        self.push(mutex.0, index)?;
        self.grant_mutex(threads, mutex, now)
    }

    fn grant_mutex(
        &mut self,
        threads: &mut ThreadTable,
        mutex: MutexId,
        now: MonotonicMillis,
    ) -> Result<(), SyncError> {
        let Kind::Mutex {
            owner, poisoned, ..
        } = self.object(mutex.0.process, mutex.0)?.kind
        else {
            return Err(SyncError::Stale);
        };
        if owner.is_some() {
            return Ok(());
        }
        while let Some(index) = self.pop(mutex.0)? {
            let waiter = self.waits[index].ok_or(SyncError::Stale)?;
            if poisoned {
                self.complete_wait(threads, index, SyncOutcome::Poisoned)?;
                continue;
            }
            let outcome = if let Phase::Reacquiring(cause) = waiter.phase {
                cause
            } else {
                if let Some(cause) = Self::due(threads, waiter.token.0.thread, waiter.options, now)?
                {
                    self.complete_wait(threads, index, cause)?;
                    continue;
                }
                SyncOutcome::Acquired
            };
            self.set_owner(threads, mutex, Some(waiter.token.0.thread))?;
            self.complete_wait(threads, index, outcome)?;
            break;
        }
        Ok(())
    }

    fn complete_wait(
        &mut self,
        threads: &mut ThreadTable,
        index: usize,
        outcome: SyncOutcome,
    ) -> Result<(), SyncError> {
        let waiter = self.waits[index].as_mut().ok_or(SyncError::Stale)?;
        let record = threads.record_mut(waiter.token.0.thread.process, waiter.token.0.thread)?;
        if !record.sync_wait
            || record.snapshot.state != ThreadState::Blocked
            || record.wait_sequence != waiter.token.0.sequence
        {
            return Err(SyncError::Stale);
        }
        record.snapshot.state = ThreadState::Ready;
        waiter.phase = Phase::Complete(outcome);
        waiter.next = None;
        Ok(())
    }

    fn poison(&mut self, threads: &mut ThreadTable, mutex: MutexId) -> Result<(), SyncError> {
        self.set_owner(threads, mutex, None)?;
        let Kind::Mutex { poisoned, .. } = &mut self.object_mut(mutex.0)?.kind else {
            return Err(SyncError::Stale);
        };
        *poisoned = true;
        for index in 0..self.waits.len() {
            let Some(waiter) = self.waits[index] else {
                continue;
            };
            if !waiter.references(mutex.0) || matches!(waiter.phase, Phase::Complete(_)) {
                continue;
            }
            let queued_on = if matches!(waiter.phase, Phase::Reacquiring(_)) {
                mutex.0
            } else {
                waiter.source
            };
            self.unlink(queued_on, index)?;
            self.complete_wait(threads, index, SyncOutcome::Poisoned)?;
        }
        Ok(())
    }

    fn set_owner(
        &mut self,
        threads: &mut ThreadTable,
        mutex: MutexId,
        new_owner: Option<ThreadId>,
    ) -> Result<(), SyncError> {
        let Kind::Mutex { owner, .. } = &mut self.object_mut(mutex.0)?.kind else {
            return Err(SyncError::Stale);
        };
        if let Some(previous) = *owner {
            threads
                .record_mut(previous.process, previous)?
                .owned_mutexes -= 1;
        }
        if let Some(next) = new_owner {
            threads.record_mut(next.process, next)?.owned_mutexes += 1;
        }
        *owner = new_owner;
        Ok(())
    }

    fn push(&mut self, object: ObjectId, index: usize) -> Result<(), SyncError> {
        if self.waits[index]
            .ok_or(SyncError::Stale)?
            .queued_on
            .is_some()
        {
            return Err(SyncError::Busy);
        }
        let tail = self.object_mut(object)?.queue.tail;
        if let Some(tail) = tail {
            self.waits[tail].as_mut().ok_or(SyncError::Stale)?.next = Some(index);
        } else {
            self.object_mut(object)?.queue.head = Some(index);
        }
        self.object_mut(object)?.queue.tail = Some(index);
        let waiter = self.waits[index].as_mut().ok_or(SyncError::Stale)?;
        waiter.queued_on = Some(object);
        waiter.previous = tail;
        waiter.next = None;
        Ok(())
    }

    fn pop(&mut self, object: ObjectId) -> Result<Option<usize>, SyncError> {
        let index = self.object_mut(object)?.queue.head;
        if let Some(index) = index {
            self.unlink(object, index)?;
        }
        Ok(index)
    }

    fn unlink(&mut self, object: ObjectId, index: usize) -> Result<(), SyncError> {
        let waiter = self.waits[index].ok_or(SyncError::Stale)?;
        if waiter.queued_on != Some(object) {
            return Err(SyncError::Stale);
        }
        if let Some(previous) = waiter.previous {
            self.waits[previous].as_mut().ok_or(SyncError::Stale)?.next = waiter.next;
        } else {
            self.object_mut(object)?.queue.head = waiter.next;
        }
        if let Some(next) = waiter.next {
            self.waits[next].as_mut().ok_or(SyncError::Stale)?.previous = waiter.previous;
        } else {
            self.object_mut(object)?.queue.tail = waiter.previous;
        }
        let waiter = self.waits[index].as_mut().ok_or(SyncError::Stale)?;
        waiter.queued_on = None;
        waiter.previous = None;
        waiter.next = None;
        Ok(())
    }

    fn require_owner(
        &self,
        owner: ProcessId,
        caller: ThreadId,
        mutex: MutexId,
    ) -> Result<(), SyncError> {
        if matches!(self.object(owner, mutex.0)?.kind, Kind::Mutex { owner: Some(holder), .. } if holder == caller)
        {
            Ok(())
        } else {
            Err(SyncError::NotOwner)
        }
    }
    fn clock(&mut self, now: MonotonicMillis) -> Result<(), SyncError> {
        if now < self.last_now {
            return Err(SyncError::ClockRegressed);
        }
        self.last_now = now;
        Ok(())
    }
    fn caller(
        &self,
        threads: &ThreadTable,
        owner: ProcessId,
        caller: ThreadId,
    ) -> Result<(), SyncError> {
        self.active(threads, owner)?;
        threads.require_running(owner, caller)?;
        Ok(())
    }
    fn active(&self, threads: &ThreadTable, owner: ProcessId) -> Result<(), SyncError> {
        self.process(owner)?;
        if threads.process(owner)?.stopping {
            return Err(ThreadError::Stopping.into());
        }
        Ok(())
    }
    fn process(&self, owner: ProcessId) -> Result<&Process, SyncError> {
        self.processes
            .iter()
            .flatten()
            .find(|process| process.id == owner)
            .ok_or(SyncError::UnknownProcess)
    }
    fn object(&self, owner: ProcessId, id: ObjectId) -> Result<&Object, SyncError> {
        if id.process != owner {
            return Err(SyncError::WrongOwner);
        }
        self.objects
            .get(id.slot)
            .and_then(|slot| slot.object.as_ref())
            .filter(|object| object.id == id)
            .ok_or(SyncError::Stale)
    }
    fn object_mut(&mut self, id: ObjectId) -> Result<&mut Object, SyncError> {
        self.objects
            .get_mut(id.slot)
            .and_then(|slot| slot.object.as_mut())
            .filter(|object| object.id == id)
            .ok_or(SyncError::Stale)
    }
    fn wait_index(&self, owner: ProcessId, token: SyncWait) -> Result<usize, SyncError> {
        if token.0.thread.process != owner {
            return Err(SyncError::WrongOwner);
        }
        self.waits
            .iter()
            .position(|waiter| waiter.is_some_and(|waiter| waiter.token == token))
            .ok_or(SyncError::Stale)
    }
}

fn reserved<T: Clone>(count: usize, value: T) -> Result<Vec<T>, SyncError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| SyncError::MetadataExhausted)?;
    values.resize(count, value);
    Ok(values)
}

#[cfg(test)]
mod tests;

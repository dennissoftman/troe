//! Process-owned thread lifecycle policy; this module does not execute threads.
//!
//! One composition-owned table serializes admission and lifecycle transitions.
//! Construction reserves every slot. All subsequent operations are allocation-
//! free. Native composition must supply the authenticated process/caller and
//! acknowledge physical quiescence before releasing resources. These model
//! tokens are not a wire ABI or a substitute for capability validation.

use super::{MAX_TASKS, ProcessId};
use alloc::vec::Vec;

pub mod sync;

/// A slot generation within this table and a non-reused process lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadId {
    process: ProcessId,
    slot: usize,
    generation: u32,
}

impl ThreadId {
    /// Process sharing the thread's address space and capabilities.
    #[must_use]
    pub const fn process(self) -> ProcessId {
        self.process
    }
}

/// One generation of a thread's blocking operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadWait {
    thread: ThreadId,
    sequence: u64,
}

/// Exclusive claim to consume a target's completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinClaim {
    caller: ThreadId,
    target: ThreadId,
    sequence: u64,
}

/// Owned preparation supplied after native memory admission succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadResources {
    /// Nonzero resource-owner identity, unique among retained reservations.
    pub reservation: u64,
    /// Exact committed pages charged by the native resource owner.
    pub pages: u64,
}

/// Immutable effective limits selected by composition for one process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadQuota {
    /// Prepared, live and completed-but-unreaped records, including the initial thread.
    pub records: usize,
    /// Aggregate unreleased native thread pages.
    pub pages: u64,
}

/// Portable execution state; physical ownership is tracked separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadState {
    /// Fully reserved but never published to the scheduler.
    Prepared,
    /// Eligible for dispatch.
    Ready,
    /// Composition selected this thread to execute.
    Running,
    /// Suspended on its unique current operation.
    Blocked,
    /// Userspace cleanup ended; composition is retiring the context.
    Exiting,
    /// Cleanup returned; native resources may still need reclamation.
    Completed,
    /// Process stop or preparation abort forbids further execution.
    Revoked,
}

/// A copied observation, never a reference into a mutable record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadSnapshot {
    /// Exact lifetime identity.
    pub id: ThreadId,
    /// Logical execution state.
    pub state: ThreadState,
    /// Sticky cooperative notification; it does not inject unwinding.
    pub stop_requested: bool,
    /// Whether completion can no longer be joined.
    pub detached: bool,
    /// Whether native composition acknowledged complete resource reclamation.
    pub resources_released: bool,
}

/// Failed transitions have no publication or resource-accounting side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadError {
    /// A configured bound or reservation is invalid.
    InvalidLimit,
    /// Construction could not reserve metadata.
    MetadataExhausted,
    /// A process, record, page or identity bound is exhausted.
    Exhausted,
    /// The process was never registered or has been removed.
    UnknownProcess,
    /// This process is already registered.
    DuplicateProcess,
    /// The caller's authenticated process does not own this token.
    WrongOwner,
    /// The token no longer denotes the same retained lifetime.
    Stale,
    /// The process has stopped accepting work.
    Stopping,
    /// The transition is incompatible with the current lifecycle.
    InvalidState,
    /// A record, join claim or physical resource is still in use.
    Busy,
    /// The caller attempted to join itself.
    SelfJoin,
    /// A reservation is already charged to another retained thread.
    ReservationInUse,
}

#[derive(Clone, Copy, Debug)]
struct Process {
    id: ProcessId,
    quota: ThreadQuota,
    stopping: bool,
    initial_admitted: bool,
    sync_objects: usize,
    sync_registered: bool,
}

#[derive(Clone, Copy, Debug)]
struct Record {
    snapshot: ThreadSnapshot,
    creator: Option<ThreadId>,
    resources: ThreadResources,
    wait_sequence: u64,
    result: u64,
    joined: bool,
    incoming_join: Option<JoinClaim>,
    outgoing_join: Option<JoinClaim>,
    sync_wait: bool,
    owned_mutexes: usize,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    generation: u32,
    record: Option<Record>,
}

/// Fixed metadata capacity with independently bounded process admission.
#[derive(Debug)]
pub struct ThreadTable {
    processes: Vec<Option<Process>>,
    slots: Vec<Slot>,
    page_limit: u64,
    next_join: u64,
}

impl ThreadTable {
    /// Reserve every process/thread metadata slot before publication.
    ///
    /// # Errors
    /// Rejects zero/excessive bounds or failed metadata allocation.
    pub fn new(processes: usize, threads: usize, pages: u64) -> Result<Self, ThreadError> {
        if processes == 0 || processes > threads || threads > MAX_TASKS || pages == 0 {
            return Err(ThreadError::InvalidLimit);
        }
        let mut process_slots = Vec::new();
        process_slots
            .try_reserve_exact(processes)
            .map_err(|_| ThreadError::MetadataExhausted)?;
        process_slots.resize(processes, None);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(threads)
            .map_err(|_| ThreadError::MetadataExhausted)?;
        slots.resize(
            threads,
            Slot {
                generation: 0,
                record: None,
            },
        );
        Ok(Self {
            processes: process_slots,
            slots,
            page_limit: pages,
            next_join: 1,
        })
    }

    /// Register an authenticated process with immutable effective quotas.
    ///
    /// # Errors
    /// Rejects duplicate processes, invalid quotas or exhausted process slots.
    pub fn register_process(
        &mut self,
        owner: ProcessId,
        quota: ThreadQuota,
    ) -> Result<(), ThreadError> {
        if quota.records == 0
            || quota.records > self.slots.len()
            || quota.pages == 0
            || quota.pages > self.page_limit
        {
            return Err(ThreadError::InvalidLimit);
        }
        if self
            .processes
            .iter()
            .flatten()
            .any(|process| process.id == owner)
        {
            return Err(ThreadError::DuplicateProcess);
        }
        let slot = self
            .processes
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ThreadError::Exhausted)?;
        *slot = Some(Process {
            id: owner,
            quota,
            stopping: false,
            initial_admitted: false,
            sync_objects: 0,
            sync_registered: false,
        });
        Ok(())
    }

    /// Admit the process's initial thread after native preparation.
    ///
    /// The initial thread is non-joinable; its completion belongs to process
    /// supervision. Abort before start permits another initial preparation.
    ///
    /// # Errors
    /// Rejects repeat initial admission, stopping, quota or reservation errors.
    pub fn prepare_initial(
        &mut self,
        owner: ProcessId,
        resources: ThreadResources,
    ) -> Result<ThreadId, ThreadError> {
        if self.process(owner)?.initial_admitted {
            return Err(ThreadError::InvalidState);
        }
        let id = self.prepare(owner, None, resources)?;
        self.process_mut(owner)?.initial_admitted = true;
        Ok(id)
    }

    /// Admit a worker owned by the current running creator.
    ///
    /// # Errors
    /// Rejects stale/wrong-owner/non-running creators, stopping or exhausted admission.
    pub fn prepare_worker(
        &mut self,
        owner: ProcessId,
        creator: ThreadId,
        resources: ThreadResources,
    ) -> Result<ThreadId, ThreadError> {
        self.require_running(owner, creator)?;
        self.prepare(owner, Some(creator), resources)
    }

    fn prepare(
        &mut self,
        owner: ProcessId,
        creator: Option<ThreadId>,
        resources: ThreadResources,
    ) -> Result<ThreadId, ThreadError> {
        let process = *self.process(owner)?;
        if process.stopping {
            return Err(ThreadError::Stopping);
        }
        if resources.reservation == 0 || resources.pages == 0 {
            return Err(ThreadError::InvalidLimit);
        }
        if self
            .slots
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| {
                !record.snapshot.resources_released
                    && record.resources.reservation == resources.reservation
            })
        {
            return Err(ThreadError::ReservationInUse);
        }
        let (records, pages) = self.usage(owner);
        if records >= process.quota.records
            || pages
                .checked_add(resources.pages)
                .is_none_or(|sum| sum > process.quota.pages)
            || self
                .committed_pages()
                .checked_add(resources.pages)
                .is_none_or(|sum| sum > self.page_limit)
        {
            return Err(ThreadError::Exhausted);
        }
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.record.is_none() && slot.generation < u32::MAX)
            .ok_or(ThreadError::Exhausted)?;
        slot.generation += 1;
        let id = ThreadId {
            process: owner,
            slot: index,
            generation: slot.generation,
        };
        slot.record = Some(Record {
            snapshot: ThreadSnapshot {
                id,
                state: ThreadState::Prepared,
                stop_requested: false,
                detached: creator.is_none(),
                resources_released: false,
            },
            creator,
            resources,
            wait_sequence: 0,
            result: 0,
            joined: false,
            incoming_join: None,
            outgoing_join: None,
            sync_wait: false,
            owned_mutexes: 0,
        });
        Ok(id)
    }

    /// Publish a prepared context once native initialization is complete.
    ///
    /// # Errors
    /// Rejects stopping, stale tokens or repeat starts.
    pub fn start(&mut self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        if self.process(owner)?.stopping {
            return Err(ThreadError::Stopping);
        }
        self.transition(owner, id, ThreadState::Prepared, ThreadState::Ready)
    }

    /// Revoke an unstarted preparation without prematurely releasing its pages.
    ///
    /// # Errors
    /// Rejects stale tokens and any context already started.
    pub fn abort_prepared(&mut self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        let initial = self.record(owner, id)?.creator.is_none();
        self.transition(owner, id, ThreadState::Prepared, ThreadState::Revoked)?;
        if initial {
            self.process_mut(owner)?.initial_admitted = false;
        }
        Ok(())
    }

    /// Select one ready context on the single CPU.
    ///
    /// # Errors
    /// Rejects stopping, stale/non-ready threads or another running context.
    pub fn dispatch(&mut self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        if self.process(owner)?.stopping {
            return Err(ThreadError::Stopping);
        }
        if self
            .slots
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| record.snapshot.state == ThreadState::Running)
        {
            return Err(ThreadError::Busy);
        }
        self.transition(owner, id, ThreadState::Ready, ThreadState::Running)
    }

    /// Record a captured timeslice or explicit yield without changing stop state.
    ///
    /// # Errors
    /// Rejects stale/non-running threads.
    pub fn yield_running(&mut self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        self.transition(owner, id, ThreadState::Running, ThreadState::Ready)
    }

    /// Suspend a running thread and allocate its next operation generation.
    ///
    /// # Errors
    /// Rejects stale/non-running threads, retained synchronization completions,
    /// or exhausted operation generations.
    pub fn block(&mut self, owner: ProcessId, id: ThreadId) -> Result<ThreadWait, ThreadError> {
        self.require_running(owner, id)?;
        let record = self.record_mut(owner, id)?;
        let sequence = record
            .wait_sequence
            .checked_add(1)
            .ok_or(ThreadError::Exhausted)?;
        record.wait_sequence = sequence;
        record.snapshot.state = ThreadState::Blocked;
        Ok(ThreadWait {
            thread: id,
            sequence,
        })
    }

    /// Consume exactly the currently blocked operation's completion.
    ///
    /// # Errors
    /// Rejects stale, duplicate or cross-owner completions. Synchronization
    /// waits must be completed through the paired synchronization table.
    pub fn wake(&mut self, owner: ProcessId, wait: ThreadWait) -> Result<(), ThreadError> {
        let record = self.record_mut(owner, wait.thread)?;
        if record.sync_wait {
            return Err(ThreadError::Busy);
        }
        if record.snapshot.state != ThreadState::Blocked || record.wait_sequence != wait.sequence {
            return Err(ThreadError::Stale);
        }
        record.snapshot.state = ThreadState::Ready;
        Ok(())
    }

    /// Publish a sticky stop notification without forcing unwinding or unlocking.
    ///
    /// # Errors
    /// Rejects stale or wrong-owner tokens. Completed notifications are harmless.
    pub fn request_stop(&mut self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        self.record_mut(owner, id)?.snapshot.stop_requested = true;
        Ok(())
    }

    /// Enter native retirement after userspace cleanup and abort unstarted children.
    ///
    /// Exiting records cannot execute userspace. The trampoline's orderly
    /// cleanup must have ended before this captured boundary. Composition
    /// retains native resources until `release_resources` acknowledges them.
    /// With retained mutexes/results, use the synchronization table's
    /// `begin_exit` to apply owner-death policy and drain references first.
    ///
    /// # Errors
    /// Rejects stale/non-running threads.
    pub fn begin_exit(&mut self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        self.require_running(owner, id)?;
        if self.record(owner, id)?.owned_mutexes != 0 {
            return Err(ThreadError::Busy);
        }
        if let Some(claim) = self.record(owner, id)?.outgoing_join {
            self.cancel_join(owner, claim)?;
        }
        self.transition(owner, id, ThreadState::Running, ThreadState::Exiting)?;
        for record in self
            .slots
            .iter_mut()
            .filter_map(|slot| slot.record.as_mut())
        {
            if record.creator == Some(id) && record.snapshot.state == ThreadState::Prepared {
                record.snapshot.state = ThreadState::Revoked;
            }
        }
        Ok(())
    }

    /// Publish a bounded scalar result after orderly cleanup has ended.
    ///
    /// # Errors
    /// Rejects stale tokens and duplicate or premature completion.
    pub fn complete(
        &mut self,
        owner: ProcessId,
        id: ThreadId,
        result: u64,
    ) -> Result<(), ThreadError> {
        self.transition(owner, id, ThreadState::Exiting, ThreadState::Completed)?;
        self.record_mut(owner, id)?.result = result;
        Ok(())
    }

    /// Reserve the unique right to consume a target completion.
    ///
    /// Composition can atomically pair this with `block` under its lifecycle
    /// lock. The claim survives waiting but may be explicitly cancelled.
    ///
    /// # Errors
    /// Rejects self/cross-owner/stale joins, detached or already claimed targets,
    /// a non-running caller, or exhausted claim identities.
    pub fn claim_join(
        &mut self,
        owner: ProcessId,
        caller: ThreadId,
        target: ThreadId,
    ) -> Result<JoinClaim, ThreadError> {
        self.require_running(owner, caller)?;
        if caller == target {
            return Err(ThreadError::SelfJoin);
        }
        if self.record(owner, caller)?.outgoing_join.is_some() {
            return Err(ThreadError::Busy);
        }
        let record = self.record(owner, target)?;
        if record.snapshot.detached || record.joined || record.incoming_join.is_some() {
            return Err(ThreadError::Busy);
        }
        if matches!(
            record.snapshot.state,
            ThreadState::Prepared | ThreadState::Revoked
        ) {
            return Err(ThreadError::InvalidState);
        }
        let next = self
            .next_join
            .checked_add(1)
            .ok_or(ThreadError::Exhausted)?;
        let claim = JoinClaim {
            caller,
            target,
            sequence: self.next_join,
        };
        self.next_join = next;
        self.record_mut(owner, caller)?.outgoing_join = Some(claim);
        self.record_mut(owner, target)?.incoming_join = Some(claim);
        Ok(claim)
    }

    /// Poll/consume a claimed completion after native resources have quiesced.
    ///
    /// Returning `None` consumes nothing. Wakeup policy belongs to composition;
    /// this operation never polls the CPU or bypasses the scheduler.
    ///
    /// # Errors
    /// Rejects stale or cross-owner claims.
    pub fn join_result(
        &mut self,
        owner: ProcessId,
        claim: JoinClaim,
    ) -> Result<Option<u64>, ThreadError> {
        self.validate_claim(owner, claim)?;
        let record = self.record(owner, claim.target)?;
        if record.snapshot.state != ThreadState::Completed || !record.snapshot.resources_released {
            return Ok(None);
        }
        let result = record.result;
        self.cancel_join(owner, claim)?;
        self.record_mut(owner, claim.target)?.joined = true;
        Ok(Some(result))
    }

    /// Relinquish a claim on timeout/stop without consuming the target result.
    ///
    /// # Errors
    /// Rejects stale/consumed or cross-owner claims.
    pub fn cancel_join(&mut self, owner: ProcessId, claim: JoinClaim) -> Result<(), ThreadError> {
        self.validate_claim(owner, claim)?;
        self.record_mut(owner, claim.caller)?.outgoing_join = None;
        self.record_mut(owner, claim.target)?.incoming_join = None;
        Ok(())
    }

    /// Relinquish joinability without changing process ownership.
    ///
    /// # Errors
    /// Rejects stale tokens, an admitted join, previous detach or consumed result.
    pub fn detach(&mut self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        let record = self.record_mut(owner, id)?;
        if record.snapshot.detached || record.joined || record.incoming_join.is_some() {
            return Err(ThreadError::Busy);
        }
        if record.snapshot.state == ThreadState::Revoked {
            return Err(ThreadError::InvalidState);
        }
        record.snapshot.detached = true;
        Ok(())
    }

    /// Revoke all logical execution and claims; native recapture/reaping remains required.
    ///
    /// # Errors
    /// Rejects unknown processes. Repeated stop is idempotent.
    pub fn stop_process(&mut self, owner: ProcessId) -> Result<(), ThreadError> {
        self.process_mut(owner)?.stopping = true;
        for record in self
            .slots
            .iter_mut()
            .filter_map(|slot| slot.record.as_mut())
        {
            if record.snapshot.id.process == owner {
                record.snapshot.state = ThreadState::Revoked;
                record.snapshot.stop_requested = true;
                record.incoming_join = None;
                record.outgoing_join = None;
            }
        }
        Ok(())
    }

    /// Acknowledge native quiescence and release this record's page charge once.
    ///
    /// The caller must first retire contexts, references, waits and mappings,
    /// zero/reclaim backing, and only then call this method. The model cannot
    /// establish physical quiescence on behalf of the machine boundary.
    ///
    /// # Errors
    /// Rejects nonterminal lifetimes, retained synchronization references, or
    /// duplicate acknowledgements.
    pub fn release_resources(
        &mut self,
        owner: ProcessId,
        id: ThreadId,
    ) -> Result<ThreadResources, ThreadError> {
        let record = self.record_mut(owner, id)?;
        if !matches!(
            record.snapshot.state,
            ThreadState::Completed | ThreadState::Revoked
        ) {
            return Err(ThreadError::InvalidState);
        }
        if record.snapshot.resources_released {
            return Err(ThreadError::Stale);
        }
        if record.sync_wait || record.owned_mutexes != 0 {
            return Err(ThreadError::Busy);
        }
        record.snapshot.resources_released = true;
        Ok(record.resources)
    }

    /// Reuse a slot only after resource reclamation and completion consumption.
    ///
    /// # Errors
    /// Rejects live/unquiesced records or retained joinable results.
    pub fn reap(&mut self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        let record = self.record(owner, id)?;
        if !record.snapshot.resources_released
            || record.incoming_join.is_some()
            || record.outgoing_join.is_some()
        {
            return Err(ThreadError::Busy);
        }
        if record.snapshot.state != ThreadState::Revoked
            && !(record.snapshot.state == ThreadState::Completed
                && (record.snapshot.detached || record.joined))
        {
            return Err(ThreadError::Busy);
        }
        self.slots[id.slot].record = None;
        Ok(())
    }

    /// Remove an owner only after every retained thread record has been reaped.
    ///
    /// # Errors
    /// Rejects unknown owners, outstanding records and synchronization registrations.
    pub fn remove_process(&mut self, owner: ProcessId) -> Result<(), ThreadError> {
        if self.usage(owner).0 != 0 || self.process(owner)?.sync_registered {
            return Err(ThreadError::Busy);
        }
        let slot = self
            .processes
            .iter_mut()
            .find(|slot| slot.is_some_and(|process| process.id == owner))
            .ok_or(ThreadError::UnknownProcess)?;
        *slot = None;
        Ok(())
    }

    /// Observe exact retained state after process/lifetime validation.
    ///
    /// # Errors
    /// Rejects stale or cross-owner tokens.
    pub fn snapshot(&self, owner: ProcessId, id: ThreadId) -> Result<ThreadSnapshot, ThreadError> {
        Ok(self.record(owner, id)?.snapshot)
    }

    /// Retained records and unreleased native page charges for one process.
    #[must_use]
    pub fn usage(&self, owner: ProcessId) -> (usize, u64) {
        self.slots
            .iter()
            .filter_map(|slot| slot.record)
            .filter(|record| record.snapshot.id.process == owner)
            .fold((0, 0), |(count, pages), record| {
                (
                    count + 1,
                    pages
                        + if record.snapshot.resources_released {
                            0
                        } else {
                            record.resources.pages
                        },
                )
            })
    }

    /// Global unreleased page charges, already checked at admission.
    #[must_use]
    pub fn committed_pages(&self) -> u64 {
        self.slots
            .iter()
            .filter_map(|slot| slot.record)
            .filter(|record| !record.snapshot.resources_released)
            .map(|record| record.resources.pages)
            .sum()
    }

    fn process(&self, owner: ProcessId) -> Result<&Process, ThreadError> {
        self.processes
            .iter()
            .flatten()
            .find(|process| process.id == owner)
            .ok_or(ThreadError::UnknownProcess)
    }
    fn process_mut(&mut self, owner: ProcessId) -> Result<&mut Process, ThreadError> {
        self.processes
            .iter_mut()
            .flatten()
            .find(|process| process.id == owner)
            .ok_or(ThreadError::UnknownProcess)
    }
    fn record(&self, owner: ProcessId, id: ThreadId) -> Result<&Record, ThreadError> {
        if id.process != owner {
            return Err(ThreadError::WrongOwner);
        }
        self.slots
            .get(id.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| record.snapshot.id == id)
            .ok_or(ThreadError::Stale)
    }
    fn record_mut(&mut self, owner: ProcessId, id: ThreadId) -> Result<&mut Record, ThreadError> {
        if id.process != owner {
            return Err(ThreadError::WrongOwner);
        }
        self.slots
            .get_mut(id.slot)
            .and_then(|slot| slot.record.as_mut())
            .filter(|record| record.snapshot.id == id)
            .ok_or(ThreadError::Stale)
    }
    fn require_running(&self, owner: ProcessId, id: ThreadId) -> Result<(), ThreadError> {
        let record = self.record(owner, id)?;
        if record.sync_wait {
            return Err(ThreadError::Busy);
        }
        if record.snapshot.state == ThreadState::Running {
            Ok(())
        } else {
            Err(ThreadError::InvalidState)
        }
    }
    fn transition(
        &mut self,
        owner: ProcessId,
        id: ThreadId,
        from: ThreadState,
        to: ThreadState,
    ) -> Result<(), ThreadError> {
        let record = self.record_mut(owner, id)?;
        if record.snapshot.state != from {
            return Err(ThreadError::InvalidState);
        }
        record.snapshot.state = to;
        Ok(())
    }
    fn validate_claim(&self, owner: ProcessId, claim: JoinClaim) -> Result<(), ThreadError> {
        if self.record(owner, claim.caller)?.outgoing_join != Some(claim)
            || self.record(owner, claim.target)?.incoming_join != Some(claim)
        {
            return Err(ThreadError::Stale);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

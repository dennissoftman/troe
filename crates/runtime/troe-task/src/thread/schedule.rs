//! Process-first selection and owned dispatch accounting for native composition.
//!
//! This policy does not program a timer or enter userspace. Composition must
//! enforce the retained bound at the native entry boundary, debit bounded kernel
//! work, and end a dispatch before selecting a different process. A copied
//! millisecond observation is not a reusable execution entitlement.

use super::{ProcessId, ThreadError, ThreadId, ThreadState, ThreadTable};

#[cfg(test)]
mod tests;

/// Maximum count of charged native entries or bounded kernel-work batches per turn.
pub const MAX_DISPATCH_STEPS: u16 = 256;

/// Rejected selection, identity, clock observation or dispatch configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Lifecycle state or retained identity does not permit this operation.
    Thread(ThreadError),
    /// Time/work bounds or clock resolution cannot represent this dispatch.
    InvalidBudget,
    /// A counter observation precedes the last accepted observation.
    ClockRegressed,
    /// One table cannot change its boot's raw-counter frequency.
    ClockFrequencyChanged,
    /// Deadline or nonreused dispatch identity arithmetic overflowed.
    Exhausted,
    /// The table no longer retains this exact dispatch.
    Stale,
}
impl From<ThreadError> for Error {
    fn from(error: ThreadError) -> Self {
        Self::Thread(error)
    }
}

/// One process turn, retained across sibling selection and copied kernel work.
///
/// Dropping this owner does not mint another turn: the table remains occupied
/// until explicit completion or process stop. This value must return to the
/// same composition-owned table that selected it. No table borrow, callback,
/// user pointer or allocation survives in the owner.
///
/// ```compile_fail
/// fn duplicate(dispatch: troe_task::thread::schedule::Dispatch) {
///     let second = dispatch.clone();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Dispatch {
    owner: ProcessId,
    sequence: u64,
    deadline: u64,
    frequency: u64,
    last_now: u64,
    steps: u16,
    failed: bool,
}
impl Dispatch {
    /// Selected process, independent of how many runnable threads it owns.
    #[must_use]
    pub const fn process(&self) -> ProcessId {
        self.owner
    }

    /// Immutable raw-counter deadline; not a wire-clock timestamp.
    #[must_use]
    pub const fn deadline_ticks(&self) -> u64 {
        self.deadline
    }

    /// Boot-counter frequency retained when this process turn was selected.
    #[must_use]
    pub const fn frequency_hz(&self) -> u64 {
        self.frequency
    }

    /// Finite work allowance, including when repeated clock readings are equal.
    #[must_use]
    pub const fn steps_left(&self) -> u16 {
        self.steps
    }
}

impl ThreadTable {
    /// Select a process fairly before selecting any of its runnable threads.
    ///
    /// Clock frequency is fixed by the first successful observation. A turn is
    /// at most 50 ms and `MAX_DISPATCH_STEPS` bounded batches. Thread wake, create,
    /// yield and slot reuse do not move the process cursor or replace the owner.
    /// No runnable process returns `None` without consuming a dispatch identity.
    ///
    /// # Errors
    /// Rejects another active turn/running thread, invalid or regressing clocks,
    /// arithmetic exhaustion and unrepresentable time/work bounds without selection.
    pub fn begin_dispatch(
        &mut self,
        now: u64,
        frequency: u64,
        milliseconds: u32,
        steps: u16,
    ) -> Result<Option<Dispatch>, Error> {
        if self.active_dispatch.is_some() || self.any_running() {
            return Err(ThreadError::Busy.into());
        }
        if !(1..=50).contains(&milliseconds)
            || !(1..=MAX_DISPATCH_STEPS).contains(&steps)
            || frequency < 1_000
        {
            return Err(Error::InvalidBudget);
        }
        if let Some((last, hz)) = self.dispatch_clock {
            if frequency != hz {
                return Err(Error::ClockFrequencyChanged);
            }
            if now < last {
                return Err(Error::ClockRegressed);
            }
        }
        let duration = u64::try_from(u128::from(frequency) * u128::from(milliseconds) / 1_000)
            .map_err(|_| Error::Exhausted)?;
        let deadline = now.checked_add(duration).ok_or(Error::Exhausted)?;
        // One scan of thread slots, rather than a thread scan for every process.
        // Private retained indices refer to fixed process slots, never user data.
        let selected = self
            .slots
            .iter()
            .filter_map(|slot| slot.record)
            .filter(|record| record.snapshot.state == ThreadState::Ready)
            .filter_map(|record| {
                self.processes[record.process_slot]
                    .filter(|process| !process.stopping)
                    .map(|process| (record.process_slot, process.id))
            })
            .min_by_key(|(index, _)| {
                (index + self.processes.len() - self.process_cursor) % self.processes.len()
            });
        let Some((index, owner)) = selected else {
            self.dispatch_clock = Some((now, frequency));
            return Ok(None);
        };
        let sequence = self
            .dispatch_sequence
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.dispatch_sequence = sequence;
        self.active_dispatch = Some((owner, sequence));
        self.process_cursor = (index + 1) % self.processes.len();
        self.dispatch_clock = Some((now, frequency));
        Ok(Some(Dispatch {
            owner,
            sequence,
            deadline,
            frequency,
            last_now: now,
            steps,
            failed: false,
        }))
    }

    /// Select the next Ready sibling while retaining the same process turn.
    ///
    /// The cursor changes only after successful selection. Ready records with a
    /// committed policy completion may be selected so composition can consume it;
    /// native resume still requires that completion to be consumed first.
    /// A zero time/work remainder or no Ready sibling returns `None`.
    ///
    /// # Errors
    /// Rejects stale/stopped dispatches, clock regression or another Running thread.
    pub fn dispatch_sibling(
        &mut self,
        dispatch: &mut Dispatch,
        now: u64,
    ) -> Result<Option<ThreadId>, Error> {
        self.validate_dispatch(dispatch)?;
        if self.any_running() {
            return Err(ThreadError::Busy.into());
        }
        if self.dispatch_remaining(dispatch, now)? == 0 {
            return Ok(None);
        }
        let cursor = self.process(dispatch.owner)?.thread_cursor;
        let Some(id) = self.ready_for(dispatch.owner, cursor) else {
            return Ok(None);
        };
        self.dispatch(dispatch.owner, id)?;
        self.process_mut(dispatch.owner)?.thread_cursor = (id.slot() + 1) % self.slots.len();
        Ok(Some(id))
    }

    /// Debit one native entry or bounded kernel-work batch before starting it.
    ///
    /// Equal clock readings still consume work. The returned whole milliseconds
    /// are floored and bounded by the unchanged deadline, not a fresh timeslice.
    /// A sub-millisecond remainder or exhausted work allowance returns zero.
    /// Call again for each batch; never hold a user lock or callback across work.
    ///
    /// # Errors
    /// Rejects stale/stopped dispatches, wrong/non-running callers or clock regression.
    pub fn charge_dispatch_step(
        &mut self,
        dispatch: &mut Dispatch,
        caller: ThreadId,
        now: u64,
    ) -> Result<u32, Error> {
        self.validate_dispatch(dispatch)?;
        if self.record(dispatch.owner, caller)?.snapshot.state != ThreadState::Running {
            return Err(ThreadError::InvalidState.into());
        }
        let remaining = self.dispatch_remaining(dispatch, now)?;
        if remaining != 0 {
            dispatch.steps -= 1;
        }
        Ok(remaining)
    }

    /// Release this exact turn after returning every Running thread to policy.
    ///
    /// No refund or deadline renewal occurs. A faulted clock observation requires
    /// process stop instead; stale completion cannot close a newer process turn.
    ///
    /// # Errors
    /// Returns the owner on stale, busy, stopped or regressing-clock failure.
    pub fn finish_dispatch(
        &mut self,
        mut dispatch: Dispatch,
        now: u64,
    ) -> Result<(), (Error, Dispatch)> {
        let result = (|| {
            self.validate_dispatch(&dispatch)?;
            if self.any_running() {
                return Err(ThreadError::Busy.into());
            }
            self.dispatch_remaining(&mut dispatch, now)?;
            self.active_dispatch = None;
            Ok(())
        })();
        result.map_err(|error| (error, dispatch))
    }

    fn validate_dispatch(&self, dispatch: &Dispatch) -> Result<(), Error> {
        if self.active_dispatch != Some((dispatch.owner, dispatch.sequence)) {
            return Err(Error::Stale);
        }
        if self.process(dispatch.owner)?.stopping {
            return Err(ThreadError::Stopping.into());
        }
        if dispatch.failed {
            return Err(Error::ClockRegressed);
        }
        Ok(())
    }

    fn dispatch_remaining(&mut self, dispatch: &mut Dispatch, now: u64) -> Result<u32, Error> {
        self.validate_dispatch(dispatch)?;
        if now < dispatch.last_now {
            dispatch.failed = true;
            return Err(Error::ClockRegressed);
        }
        dispatch.last_now = now;
        self.dispatch_clock = Some((now, dispatch.frequency));
        if dispatch.steps == 0 || now >= dispatch.deadline {
            return Ok(0);
        }
        let millis = u128::from(dispatch.deadline - now) * 1_000 / u128::from(dispatch.frequency);
        u32::try_from(millis).map_err(|_| Error::Exhausted)
    }

    fn ready_for(&self, owner: ProcessId, cursor: usize) -> Option<ThreadId> {
        (0..self.slots.len())
            .map(|offset| (cursor + offset) % self.slots.len())
            .filter_map(|index| self.slots[index].record)
            .find(|record| {
                record.snapshot.id.process() == owner && record.snapshot.state == ThreadState::Ready
            })
            .map(|record| record.snapshot.id)
    }

    fn any_running(&self) -> bool {
        self.slots
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| record.snapshot.state == ThreadState::Running)
    }
}

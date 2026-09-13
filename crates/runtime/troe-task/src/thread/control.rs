//! Owned join and sleep waits without allocation, user pointers or callbacks.
//!
//! One serialized composition owns the thread table and each returned wait. It
//! supplies boot-relative clock observations and dispatches a woken caller before
//! consuming its result. Dropping a wait does not cancel it: consume it or stop
//! the process. Native execution claims and physical quiescence remain separate.

use super::sync::{WaitMode, WaitOptions};
use super::{JoinClaim, ProcessId, ThreadError, ThreadId, ThreadState, ThreadTable, ThreadWait};
use crate::MonotonicMillis;

#[cfg(test)]
mod tests;

/// Selected result, retained unchanged until the caller consumes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// A quiescent target's scalar completion was consumed exactly once.
    Joined(u64),
    /// A try-join found no quiescent completion and retained no claim.
    WouldBlock,
    /// The absolute deadline expired before an operation result was committed.
    TimedOut,
    /// An opted-in sticky stop was observed before result commitment.
    Stopped,
}

/// Immediate result or one owned blocking operation.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub enum Start {
    /// No wait or join claim remains to retire.
    Complete(Outcome),
    /// Retain until completion consumption or process stop.
    Waiting(Waiting),
}

/// Rejected observation or completion of an owned control wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The table no longer admits this process, caller or operation generation.
    Thread(ThreadError),
    /// Composition supplied a timestamp before this operation's last observation.
    ClockRegressed,
}

impl From<ThreadError> for Error {
    fn from(error: ThreadError) -> Self {
        Self::Thread(error)
    }
}

/// One exact caller wait, its optional join claim and immutable wait options.
///
/// A selected result is stored here, so the joined target can be reaped before
/// this caller resumes. No identity token keeps physical thread backing alive.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Waiting {
    token: ThreadWait,
    join: Option<JoinClaim>,
    options: WaitOptions,
    last_now: MonotonicMillis,
    phase: Phase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Pending,
    Complete(Outcome),
    Consumed,
}

impl ThreadTable {
    /// Join a target, optionally retaining one exclusive claim while blocked.
    ///
    /// Already expired/stopped waits return before admission. A try with no
    /// quiescent result consumes neither a claim identity nor completion. Native
    /// resource acknowledgement is required even if the target has completed.
    ///
    /// # Errors
    /// Rejects invalid/stopping callers, invalid or already claimed targets,
    /// self-join and exhausted operation/claim generations before publication.
    pub fn join(
        &mut self,
        owner: ProcessId,
        caller: ThreadId,
        target: ThreadId,
        mode: WaitMode,
        now: MonotonicMillis,
    ) -> Result<Start, ThreadError> {
        self.validate_running(owner, caller)?;
        self.validate_join(owner, caller, target)?;
        if let WaitMode::Wait(options) = mode
            && let Some(outcome) = due(
                options,
                self.record(owner, caller)?.snapshot.stop_requested,
                now,
            )
        {
            return Ok(Start::Complete(outcome));
        }
        let target_record = self.record(owner, target)?;
        if target_record.snapshot.state == ThreadState::Completed
            && target_record.snapshot.resources_released
        {
            let claim = self.claim_join(owner, caller, target)?;
            let result = self
                .join_result(owner, claim)?
                .ok_or(ThreadError::InvalidState)?;
            return Ok(Start::Complete(Outcome::Joined(result)));
        }
        let WaitMode::Wait(options) = mode else {
            return Ok(Start::Complete(Outcome::WouldBlock));
        };
        // Check the caller operation counter before claiming the target. The
        // serialized claim does not change this caller's lifecycle or wait slot.
        let sequence = self
            .record(owner, caller)?
            .wait_sequence
            .checked_add(1)
            .ok_or(ThreadError::Exhausted)?;
        let claim = self.claim_join(owner, caller, target)?;
        self.admit_control(owner, caller, sequence, Some(claim), options, now)
    }

    /// Suspend until an absolute deadline or an opted-in cooperative stop.
    ///
    /// No deadline and no stop observation intentionally waits until process
    /// termination. A deadline selects `TimedOut`; it never restarts on resumption.
    ///
    /// # Errors
    /// Rejects invalid/stopping callers, retained waits and exhausted sequences.
    pub fn sleep(
        &mut self,
        owner: ProcessId,
        caller: ThreadId,
        options: WaitOptions,
        now: MonotonicMillis,
    ) -> Result<Start, ThreadError> {
        self.validate_running(owner, caller)?;
        let record = self.record(owner, caller)?;
        if let Some(outcome) = due(options, record.snapshot.stop_requested, now) {
            return Ok(Start::Complete(outcome));
        }
        let sequence = record
            .wait_sequence
            .checked_add(1)
            .ok_or(ThreadError::Exhausted)?;
        self.admit_control(owner, caller, sequence, None, options, now)
    }

    fn admit_control(
        &mut self,
        owner: ProcessId,
        caller: ThreadId,
        sequence: u64,
        join: Option<JoinClaim>,
        options: WaitOptions,
        now: MonotonicMillis,
    ) -> Result<Start, ThreadError> {
        let record = self.record_mut(owner, caller)?;
        record.wait_sequence = sequence;
        record.control_wait = true;
        record.snapshot.state = ThreadState::Blocked;
        Ok(Start::Waiting(Waiting {
            token: ThreadWait {
                thread: caller,
                sequence,
            },
            join,
            options,
            last_now: now,
            phase: Phase::Pending,
        }))
    }
}

impl Waiting {
    /// Captured caller to dispatch once observation makes it ready.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.token.thread
    }

    /// Original deadline while pending; a selected result needs no timer event.
    #[must_use]
    pub const fn deadline(&self) -> Option<MonotonicMillis> {
        if matches!(self.phase, Phase::Pending) {
            self.options.deadline
        } else {
            None
        }
    }

    /// Observe this exact operation once; a previously selected result wins.
    ///
    /// Check deadline/stop before consuming a quiescent join result. Waking the
    /// caller retains its operation interlock until finish consumes the result.
    /// Event delivery need not poll or run the target or waiting caller.
    ///
    /// # Errors
    /// Rejects stopping/retired/stale waits and regressing clocks without changes.
    pub fn observe(
        &mut self,
        threads: &mut ThreadTable,
        now: MonotonicMillis,
    ) -> Result<bool, Error> {
        self.validate(threads)?;
        if now < self.last_now {
            return Err(Error::ClockRegressed);
        }
        if !matches!(self.phase, Phase::Pending) {
            self.last_now = now;
            return Ok(false);
        }
        let owner = self.caller().process();
        let record = threads.record(owner, self.caller())?;
        if record.snapshot.state != ThreadState::Blocked {
            return Err(ThreadError::Stale.into());
        }
        let outcome = if let Some(outcome) = due(self.options, record.snapshot.stop_requested, now)
        {
            if let Some(claim) = self.join {
                threads.cancel_join(owner, claim)?;
            }
            Some(outcome)
        } else if let Some(claim) = self.join {
            threads.join_result(owner, claim)?.map(Outcome::Joined)
        } else {
            None
        };
        self.last_now = now;
        let Some(outcome) = outcome else {
            return Ok(false);
        };
        // Claim cancellation/result consumption cannot alter the validated
        // caller's blocked state or wait sequence under this exclusive borrow.
        threads.record_mut(owner, self.caller())?.snapshot.state = ThreadState::Ready;
        self.join = None;
        self.phase = Phase::Complete(outcome);
        Ok(true)
    }

    /// Consume a selected result after dispatching its captured caller.
    ///
    /// # Errors
    /// Leaves the wait unchanged on premature, stale or stopping errors. A
    /// successful consume clears its interlock and rejects subsequent attempts.
    pub fn finish(&mut self, threads: &mut ThreadTable) -> Result<Outcome, Error> {
        self.validate(threads)?;
        let record = threads.record(self.caller().process(), self.caller())?;
        if record.snapshot.state != ThreadState::Running {
            return Err(ThreadError::InvalidState.into());
        }
        let Phase::Complete(outcome) = self.phase else {
            return Err(ThreadError::Busy.into());
        };
        threads
            .record_mut(self.caller().process(), self.caller())?
            .control_wait = false;
        self.phase = Phase::Consumed;
        Ok(outcome)
    }

    fn validate(&self, threads: &ThreadTable) -> Result<(), ThreadError> {
        let owner = self.caller().process();
        if threads.process(owner)?.stopping {
            return Err(ThreadError::Stopping);
        }
        let record = threads.record(owner, self.caller())?;
        if !record.control_wait || record.sync_wait || record.wait_sequence != self.token.sequence {
            return Err(ThreadError::Stale);
        }
        Ok(())
    }
}

fn due(options: WaitOptions, stopped: bool, now: MonotonicMillis) -> Option<Outcome> {
    if options.deadline.is_some_and(|deadline| now >= deadline) {
        Some(Outcome::TimedOut)
    } else if options.observe_stop && stopped {
        Some(Outcome::Stopped)
    } else {
        None
    }
}

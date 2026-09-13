//! Couple one authenticated process turn to the final native timer boundary.

use super::{ApplicationExecutionBound, NativeProcessContext, NativeThreadStop};
use crate::{ApplicationResume, MmuError, mechanism::ExecutionDeadline, mmu};
use core::sync::atomic::{Ordering, fence};
use troe_task::thread::{ThreadId, ThreadTable, schedule::Dispatch};

impl NativeProcessContext {
    /// Acceptance-only injection of expiry at the native timer-preparation boundary.
    ///
    /// # Errors
    /// Rejects a non-running caller or native invariant failure.
    #[cfg(feature = "acceptance-probes")]
    pub fn probe_dispatch_preparation_expiry(
        &mut self,
        threads: &ThreadTable,
        id: ThreadId,
    ) -> Result<NativeThreadStop, MmuError> {
        threads
            .validate_running(self.process, id)
            .map_err(|_| MmuError::InvalidUserContext)?;
        let observed = crate::process_accounting_ticks();
        self.resume_bound(
            id,
            ApplicationResume::Timeslice,
            ApplicationExecutionBound::Dispatch(ExecutionDeadline {
                ticks: observed,
                observed,
                frequency: crate::process_accounting_frequency_hz()
                    .ok_or(MmuError::ExecutionTimerUnavailable)?,
            }),
        )
    }

    /// Debit this process turn and resume one Running sibling under its deadline.
    ///
    /// Only completed Yield/Timeslice states are eligible. Every call charges a
    /// bounded step before native preparation, using this boot's raw counter.
    /// The timer boundary rechecks time after controller preparation, so it cannot
    /// substitute a fresh process quantum for the retained deadline. Arm programs
    /// that absolute counter value; x86 floors the remainder for its calibrated
    /// LAPIC one-shot and rechecks before entry. This is not a hard real-time bound.
    ///
    /// `DispatchExpired` means no user entry occurred and preserves the native
    /// continuation. Composition returns its Running policy record to Ready and
    /// finishes the process turn. Owned calls/waits remain separate and may outlive
    /// a turn; they cannot grant execution time. No table callback crosses entry.
    ///
    /// # Errors
    /// Rejects mismatched roots/turns/clock frequencies and unresolved native or
    /// policy work. Clock or native invariant failure stops the process; a foreign
    /// process identity does not mutate this root.
    pub fn resume_dispatch(
        &mut self,
        threads: &mut ThreadTable,
        dispatch: &mut Dispatch,
        id: ThreadId,
    ) -> Result<NativeThreadStop, MmuError> {
        if id.process() != self.process || dispatch.process() != self.process {
            return Err(MmuError::InvalidUserContext);
        }
        let checked = (|| {
            threads
                .validate_running(self.process, id)
                .map_err(|_| MmuError::InvalidUserContext)?;
            let context = self
                .contexts
                .iter()
                .find(|context| context.id == id)
                .ok_or(MmuError::InvalidUserContext)?;
            let completion = match context.pending {
                mmu::ApplicationPending::Timeslice => ApplicationResume::Timeslice,
                mmu::ApplicationPending::Yield => ApplicationResume::Yield,
                _ => return Err(MmuError::InvalidUserContext),
            };
            if crate::process_accounting_frequency_hz() != Some(dispatch.frequency_hz()) {
                return Err(MmuError::ExecutionTimerUnavailable);
            }
            let now = crate::process_accounting_ticks();
            let remaining = threads
                .charge_dispatch_step(dispatch, id, now)
                .map_err(|_| MmuError::InvalidUserContext)?;
            Ok((completion, remaining, now, context.started))
        })();
        let (completion, remaining, now, started) = match checked {
            Ok(checked) => checked,
            Err(error) => {
                self.stop();
                return Err(error);
            }
        };
        if remaining == 0 {
            return Ok(NativeThreadStop::DispatchExpired);
        }
        if !started {
            fence(Ordering::Acquire);
        }
        self.resume_bound(
            id,
            completion,
            ApplicationExecutionBound::Dispatch(ExecutionDeadline {
                ticks: dispatch.deadline_ticks(),
                frequency: dispatch.frequency_hz(),
                observed: now,
            }),
        )
    }
}

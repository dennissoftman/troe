//! Owned completion of a prepared-thread Abort after physical reclamation.

use super::{
    Completion, Error, Operation, Outcome, Request, ThreadError, ThreadId, ThreadState,
    ThreadTable, reply,
};

/// One successful logical Abort whose target backing is still retained.
///
/// Keep this action beside the caller's separate native execution claim. The
/// target must remain retained until [`Self::finish`] reaps it. Composition
/// removes the revoked native context/mappings, zeros and reclaims its physical
/// owners, then acknowledges the target's resources before finishing this action.
/// Dropping the action does not reclaim its target or reply to its caller.
///
/// ```compile_fail
/// fn duplicate(abort: troe_service::threading::Aborting) {
///     let duplicate = abort.clone();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Aborting {
    operation: Operation,
    target: ThreadId,
}

impl Aborting {
    pub(super) const fn new(operation: Operation, target: ThreadId) -> Self {
        Self { operation, target }
    }

    /// Captured caller whose native claim must eventually receive the reply.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.operation.caller()
    }

    /// Exact prepared lifetime that won the serialized Abort transition.
    #[must_use]
    pub const fn target(&self) -> ThreadId {
        self.target
    }

    /// Original immutable Abort request, for native claim correlation.
    #[must_use]
    pub const fn request(&self) -> Request {
        self.operation.authority.request()
    }

    /// Reap the acknowledged target and produce the caller's checked reply.
    ///
    /// Requires the exact live revoked target after physical reclamation and
    /// resource acknowledgement. No page charge is refunded here. Composition
    /// must dispatch the caller before this step, and retain its matching native
    /// claim until publication. This does not run user code or renew a deadline.
    ///
    /// # Errors
    /// Returns the action on failure without replaying Abort. Not-running, busy
    /// or not-yet-reclaimed state may be resolved before finishing; stopping or
    /// a stale target requires process teardown without a late success reply.
    #[allow(clippy::result_large_err)] // Retain bounded ownership without allocation.
    pub fn finish(self, threads: &mut ThreadTable) -> Result<Completion, (Error, Self)> {
        let result = (|| {
            let owner = self.caller().process();
            threads
                .validate_running(owner, self.caller())
                .map_err(Error::Thread)?;
            let snapshot = threads
                .snapshot(owner, self.target)
                .map_err(Error::Thread)?;
            if snapshot.state != ThreadState::Revoked {
                return Err(Error::Thread(ThreadError::InvalidState));
            }
            if !snapshot.resources_released {
                return Err(Error::Thread(ThreadError::Busy));
            }
            let reply = self.operation.complete(reply(Outcome::Success, 0))?;
            threads.reap(owner, self.target).map_err(Error::Thread)?;
            Ok(reply)
        })();
        result.map_err(|error| (error, self))
    }
}

//! Owned preparation and start actions for native resource composition.

use super::{
    Completion, Error, Kind, Operation, Outcome, Request, ThreadError, ThreadId, ThreadState,
    ThreadTable, Token, reply,
};
use troe_task::thread::ThreadResources;

/// Expected native preparation failure, never a successful token publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrepareFailure {
    /// The image entry or native geometry is invalid.
    InvalidRequest,
    /// A simultaneous resource allowance or physical reservation is exhausted.
    Exhausted,
    /// The admitted native profile does not implement the requested preparation.
    Unsupported,
}
impl PrepareFailure {
    const fn outcome(self) -> Outcome {
        match self {
            Self::InvalidRequest => Outcome::InvalidRequest,
            Self::Exhausted => Outcome::Exhausted,
            Self::Unsupported => Outcome::Unsupported,
        }
    }
}

/// One copied Prepare request retaining its target through native initialization.
///
/// Native composition retains the matching execution claim and every physical
/// owner beside this action. Dropping it neither refunds resources nor replies.
/// No user request pointer, table borrow or callback crosses resource work.
///
/// ```compile_fail
/// fn duplicate(action: troe_service::threading::Preparing) {
///     let duplicate = action.clone();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Preparing {
    operation: Operation,
    target: Option<(ThreadId, ThreadResources)>,
}

/// An unpublished preparation revoked for rollback before a failure reply.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct PreparationRollback {
    operation: Operation,
    target: ThreadId,
    failure: PrepareFailure,
}

/// One authenticated Start, before native readiness and logical publication.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Starting {
    operation: Operation,
    target: ThreadId,
}

impl Preparing {
    pub(super) const fn new(operation: Operation) -> Self {
        Self {
            operation,
            target: None,
        }
    }

    /// Captured creator that must receive this operation's eventual completion.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.operation.caller()
    }

    /// Original copied Prepare, including its untrusted image-relative entry.
    #[must_use]
    pub const fn request(&self) -> Request {
        self.operation.authority.request()
    }

    /// Current reserved lifetime; absent before logical reservation succeeds.
    #[must_use]
    pub const fn target(&self) -> Option<ThreadId> {
        match self.target {
            Some((id, _)) => Some(id),
            None => None,
        }
    }

    /// Charge retained beside the target, not a physical ownership receipt.
    #[must_use]
    pub const fn resources(&self) -> Option<ThreadResources> {
        match self.target {
            Some((_, resources)) => Some(resources),
            None => None,
        }
    }

    /// Reserve the target once, after all native resource classes are reserved.
    ///
    /// Composition bounds the image entry, stack/TLS geometry and complete peak
    /// resource charge before this step. No native mapping or Ready publication
    /// occurs here. Failure leaves this action without a new logical target.
    ///
    /// # Errors
    /// Rejects duplicate reservation, invalid/stopped creators or exhausted tables.
    pub fn reserve(
        &mut self,
        threads: &mut ThreadTable,
        resources: ThreadResources,
    ) -> Result<ThreadId, Error> {
        if self.target.is_some() {
            return Err(Error::Thread(ThreadError::InvalidState));
        }
        let caller = self.caller();
        threads
            .validate_running(caller.process(), caller)
            .map_err(Error::Thread)?;
        let target = threads
            .prepare_worker(caller.process(), caller, resources)
            .map_err(Error::Thread)?;
        self.target = Some((target, resources));
        Ok(target)
    }

    /// Produce a token after native composition has validated complete readiness.
    ///
    /// This policy check does not prove native mappings or physical ownership.
    /// Native composition must keep the root exclusively borrowed across its
    /// matching-context/IPC/descriptor checks and this completion. Start remains
    /// a separate operation after the caller initializes userspace bookkeeping.
    ///
    /// # Errors
    /// Returns this action for missing, stale, stopped or no-longer-prepared state.
    #[allow(clippy::result_large_err)]
    pub fn finish(self, threads: &ThreadTable) -> Result<Completion, (Error, Self)> {
        let result = (|| {
            let (target, resources) = self
                .target
                .ok_or(Error::Thread(ThreadError::InvalidState))?;
            let owner = self.caller().process();
            threads
                .validate_prepared_child(owner, self.caller(), target)
                .map_err(Error::Thread)?;
            threads
                .validate_prepared(owner, target, false, resources.pages)
                .map_err(Error::Thread)?;
            let slot = u32::try_from(target.slot()).map_err(|_| Error::Encoding)?;
            let token =
                Token::new(Kind::Thread, slot, target.generation()).map_err(|_| Error::Encoding)?;
            self.operation
                .complete(reply(Outcome::Success, token.bits()))
        })();
        result.map_err(|error| (error, self))
    }

    /// Reject before logical reservation, after releasing any unpublished backing.
    ///
    /// # Errors
    /// Rejects a retained target or a caller that can no longer receive completion.
    #[allow(clippy::result_large_err)]
    pub fn reject(
        self,
        threads: &ThreadTable,
        failure: PrepareFailure,
    ) -> Result<Completion, (Error, Self)> {
        let result = (|| {
            if self.target.is_some() {
                return Err(Error::Thread(ThreadError::Busy));
            }
            threads
                .validate_running(self.caller().process(), self.caller())
                .map_err(Error::Thread)?;
            self.operation.complete(reply(failure.outcome(), 0))
        })();
        result.map_err(|error| (error, self))
    }

    /// Revoke a reserved target for complete rollback before a failure reply.
    ///
    /// Native partial mutation instead requires stopping and reclaiming the
    /// complete process. This transition alone neither unmaps nor refunds pages.
    ///
    /// # Errors
    /// Returns this action when creator/target state no longer permits rollback.
    #[allow(clippy::result_large_err)]
    pub fn revoke(
        self,
        threads: &mut ThreadTable,
        failure: PrepareFailure,
    ) -> Result<PreparationRollback, (Error, Self)> {
        let Some((target, _)) = self.target else {
            return Err((Error::Thread(ThreadError::InvalidState), self));
        };
        if let Err(error) = threads.abort_worker(self.caller().process(), self.caller(), target) {
            return Err((Error::Thread(error), self));
        }
        Ok(PreparationRollback {
            operation: self.operation,
            target,
            failure,
        })
    }
}

impl PreparationRollback {
    /// Original captured creator whose matching native claim remains retained.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.operation.caller()
    }
    /// Exact revoked incarnation, retained until physical reclamation and reaping.
    #[must_use]
    pub const fn target(&self) -> ThreadId {
        self.target
    }
    /// Copied Prepare request; rollback does not manufacture an Abort request.
    #[must_use]
    pub const fn request(&self) -> Request {
        self.operation.authority.request()
    }

    /// Reap only after native access and ordinary physical owners are reclaimed.
    ///
    /// # Errors
    /// Returns this action without a reply for unreclaimed, stale or stopped state.
    #[allow(clippy::result_large_err)]
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
            let reply = self.operation.complete(reply(self.failure.outcome(), 0))?;
            threads.reap(owner, self.target).map_err(Error::Thread)?;
            Ok(reply)
        })();
        result.map_err(|error| (error, self))
    }
}

impl Starting {
    pub(super) const fn new(operation: Operation, target: ThreadId) -> Self {
        Self { operation, target }
    }
    /// Captured creator whose native call remains claimed through publication.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.operation.caller()
    }
    /// Exact prepared worker that may become Ready after native validation.
    #[must_use]
    pub const fn target(&self) -> ThreadId {
        self.target
    }
    /// Original copied Start for correlation with its retained native execution.
    #[must_use]
    pub const fn request(&self) -> Request {
        self.operation.authority.request()
    }

    /// Publish Ready once after complete native readiness has been checked.
    ///
    /// Native composition retains exclusive root/table access and the caller's
    /// matching claim through this step. No allocation or user execution occurs.
    /// Prepare cannot be substituted for Start. A native reply failure following
    /// publication requires process stop before any further execution.
    ///
    /// # Errors
    /// Returns this action if the creator, target or process no longer permits Start.
    #[allow(clippy::result_large_err)]
    pub fn finish(self, threads: &mut ThreadTable) -> Result<Completion, (Error, Self)> {
        let result = (|| {
            let completion = self.operation.complete(reply(Outcome::Success, 0))?;
            threads
                .start_worker(self.caller().process(), self.caller(), self.target)
                .map_err(Error::Thread)?;
            Ok(completion)
        })();
        result.map_err(|error| (error, self))
    }
}

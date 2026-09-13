//! Owned execution of authenticated thread lifecycle and synchronization calls.
//!
//! One serialized composition supplies the live process snapshot, captured
//! caller and paired tables. Native composition must claim the matching native
//! operation once before execution, retain that claim beside any wait, and
//! charge this storage in its admission budget. No user pointer, table borrow,
//! callback or delegated IPC lease crosses a suspension here. Ordinary threaded
//! package admission is separate and remains disabled.

use troe_abi::threading::{self as wire, Kind, Outcome, Request, Response, Token};
use troe_dispatch::{AuthorizedSchedulerCall, HandleOwner};
use troe_task::thread::{ThreadError, ThreadId, ThreadState, ThreadTable, control, sync};
use troe_task::{MonotonicMillis, ProcessSnapshot};

mod abort;
pub use abort::Aborting;
mod creation;
pub use creation::{PreparationRollback, PrepareFailure, Preparing, Starting};

#[cfg(test)]
mod tests;

/// A composition failure, distinct from an expected application outcome.
///
/// Execution may already have changed policy state. Never execute the request
/// again after this error; native composition must stop the affected process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The captured process, thread and authenticated principal disagree.
    Binding,
    /// An impossible lifecycle/table configuration was encountered.
    Thread(ThreadError),
    /// An impossible synchronization state or regressing clock was supplied.
    Sync(sync::SyncError),
    /// An invalid retained lifecycle wait or regressing clock was supplied.
    Control(control::Error),
    /// Trusted identity/result metadata cannot satisfy the wire contract.
    Encoding,
}

/// One authenticated operation bound to a captured native caller.
///
/// This value is neither copyable nor clonable. Binding does not itself claim a
/// native execution or validate that the thread is still running.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Operation {
    caller: ThreadId,
    authority: AuthorizedSchedulerCall,
}

/// One checked reply; publication still requires the matching native claim.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Completion {
    caller: ThreadId,
    request: Request,
    response: Response,
}

/// A checked reply, exact wait or terminal action with retained ownership.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub enum Progress {
    /// No policy wait remains to consume.
    Complete(Completion),
    /// Retain this value and the native claim until completion or process stop.
    Waiting(Waiting),
    /// No success reply is possible; finish native retirement or process stop.
    Retiring(Retiring),
    /// Retain the caller's claim until the aborted preparation is reclaimed.
    Aborting(Aborting),
    /// Retain the caller and all resource owners through native initialization.
    Preparing(Preparing),
    /// Validate native readiness before publishing this creator's prepared child.
    Starting(Starting),
}

/// An admitted Exit after lifecycle and synchronization owner-death policy.
///
/// Retain this beside the matching native execution claim. Dropping it neither
/// completes the thread nor reclaims any resource. Composition must retire the
/// thread or stop and reclaim the process without returning to the caller.
///
/// ```compile_fail
/// fn duplicate(exit: troe_service::threading::Retiring) {
///     let duplicate = exit.clone();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Retiring {
    operation: Operation,
    disposition: sync::ExitEffect,
}

/// An admitted wait, including its immutable request and authenticated caller.
///
/// Dropping this record does not cancel policy state or release its references;
/// composition must consume the wait or stop the process and retire both tables.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Waiting {
    operation: Operation,
    wait: WaitKind,
}

#[derive(Debug, Eq, PartialEq)]
enum WaitKind {
    Sync(sync::SyncWait),
    Control(control::Waiting),
}

impl Operation {
    /// Bind an owned authorization to the process selected by trusted scheduling.
    ///
    /// # Errors
    /// Rejects a principal/caller mismatch without changing any table.
    pub fn bind(
        process: ProcessSnapshot,
        caller: ThreadId,
        authority: AuthorizedSchedulerCall,
    ) -> Result<Self, Error> {
        if caller.process() != process.id()
            || HandleOwner::isolated(process.task_id().get()) != Ok(authority.owner())
        {
            return Err(Error::Binding);
        }
        Ok(Self { caller, authority })
    }

    /// Captured execution identity, never supplied by the request payload.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.caller
    }

    /// Consume this operation under exclusive ownership of the paired tables.
    ///
    /// Supports identity/stop, lifecycle and synchronization operations. Prepare
    /// and Start return owned actions for native initialization/readiness checks.
    /// Abort retains an owned action until physical reclamation is acknowledged. An
    /// admitted Exit returns an owned terminal action, never a success reply.
    /// Absolute wire deadlines are boot-relative milliseconds; they are never
    /// restarted on resumption. Work and storage are bounded by table capacity.
    ///
    /// # Errors
    /// Composition failures require process termination, not request replay.
    pub fn execute(
        self,
        threads: &mut ThreadTable,
        sync: &mut sync::SyncTable,
        now: MonotonicMillis,
    ) -> Result<Progress, Error> {
        let result = threads
            .validate_running(self.caller.process(), self.caller)
            .map_err(sync::SyncError::from)
            .and_then(|()| self.apply(threads, sync, now));
        match result {
            Ok(Effect::Identity(kind, slot, generation)) => {
                let slot = u32::try_from(slot).map_err(|_| Error::Encoding)?;
                let token = Token::new(kind, slot, generation).map_err(|_| Error::Encoding)?;
                self.complete(reply(Outcome::Success, token.bits()))
                    .map(Progress::Complete)
            }
            Ok(Effect::Reply(response)) => self.complete(response).map(Progress::Complete),
            Ok(Effect::Wait(wait)) => Ok(Progress::Waiting(Waiting {
                operation: self,
                wait,
            })),
            Ok(Effect::Exit(disposition)) => Ok(Progress::Retiring(Retiring {
                operation: self,
                disposition,
            })),
            Ok(Effect::Abort(target)) => Ok(Progress::Aborting(Aborting::new(self, target))),
            Ok(Effect::Prepare) => Ok(Progress::Preparing(Preparing::new(self))),
            Ok(Effect::Start(target)) => Ok(Progress::Starting(Starting::new(self, target))),
            Err(error) => self
                .complete(reply(error_outcome(error)?, 0))
                .map(Progress::Complete),
        }
    }

    fn complete(&self, response: Response) -> Result<Completion, Error> {
        let request = self.authority.request();
        response.encode(request).map_err(|_| Error::Encoding)?;
        Ok(Completion {
            caller: self.caller,
            request,
            response,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn apply(
        &self,
        threads: &mut ThreadTable,
        table: &mut sync::SyncTable,
        now: MonotonicMillis,
    ) -> Result<Effect, sync::SyncError> {
        let caller = self.caller;
        let owner = caller.process();
        let response = match self.authority.request() {
            Request::Current => {
                return Ok(Effect::Identity(
                    Kind::Thread,
                    caller.slot(),
                    caller.generation(),
                ));
            }
            Request::Observe(token) => {
                let id = threads.resolve(owner, token.slot() as usize, token.generation())?;
                let snapshot = threads.snapshot(owner, id)?;
                Response {
                    outcome: Outcome::Success,
                    value: 0,
                    snapshot: Some(wire::Snapshot {
                        state: match snapshot.state {
                            ThreadState::Prepared => wire::State::Prepared,
                            ThreadState::Ready => wire::State::Ready,
                            ThreadState::Running => wire::State::Running,
                            ThreadState::Blocked => wire::State::Blocked,
                            ThreadState::Exiting => wire::State::Exiting,
                            ThreadState::Completed => wire::State::Completed,
                            ThreadState::Revoked => wire::State::Revoked,
                        },
                        stop_requested: snapshot.stop_requested,
                        detached: snapshot.detached,
                        resources_released: snapshot.resources_released,
                    }),
                }
            }
            Request::RequestStop(token) => {
                let id = threads.resolve(owner, token.slot() as usize, token.generation())?;
                threads.request_stop(owner, id)?;
                reply(Outcome::Success, 0)
            }
            Request::Join { thread, wait } => {
                let target = threads.resolve(owner, thread.slot() as usize, thread.generation())?;
                return threads
                    .join(owner, caller, target, mode(wait), now)
                    .map(control_start)
                    .map_err(Into::into);
            }
            Request::Detach(token) => {
                let id = threads.resolve(owner, token.slot() as usize, token.generation())?;
                threads.detach(owner, id)?;
                reply(Outcome::Success, 0)
            }
            Request::Sleep(wait) => {
                return threads
                    .sleep(owner, caller, options(wait), now)
                    .map(control_start)
                    .map_err(Into::into);
            }
            Request::Exit(_) => {
                return table
                    .begin_exit(threads, owner, caller, now)
                    .map(Effect::Exit);
            }
            Request::Abort(token) => {
                let target = threads.resolve(owner, token.slot() as usize, token.generation())?;
                threads.abort_worker(owner, caller, target)?;
                return Ok(Effect::Abort(target));
            }
            Request::Prepare { .. } => return Ok(Effect::Prepare),
            Request::Start(token) => {
                let target = threads.resolve(owner, token.slot() as usize, token.generation())?;
                threads.validate_prepared_child(owner, caller, target)?;
                return Ok(Effect::Start(target));
            }
            Request::CreateMutex(policy) => {
                let policy = match policy {
                    wire::OwnerDeath::Poison => sync::OwnerDeath::Poison,
                    wire::OwnerDeath::FailProcess => sync::OwnerDeath::FailProcess,
                };
                let id = table.create_mutex(threads, owner, caller, policy)?;
                return Ok(Effect::Identity(Kind::Mutex, id.slot(), id.generation()));
            }
            Request::CreateCondition => {
                let id = table.create_condition(threads, owner, caller)?;
                return Ok(Effect::Identity(
                    Kind::Condition,
                    id.slot(),
                    id.generation(),
                ));
            }
            Request::CreatePermit { count, maximum } => {
                let id = table.create_permit(threads, owner, caller, count, maximum)?;
                return Ok(Effect::Identity(Kind::Permit, id.slot(), id.generation()));
            }
            Request::Lock { mutex, wait } => {
                let id = table.resolve_mutex(owner, mutex.slot() as usize, mutex.generation())?;
                return table
                    .lock(threads, owner, caller, id, mode(wait), now)
                    .map(start);
            }
            Request::Unlock(token) => {
                let id = table.resolve_mutex(owner, token.slot() as usize, token.generation())?;
                table.unlock(threads, owner, caller, id, now)?;
                reply(Outcome::Success, 0)
            }
            Request::ConditionWait {
                condition,
                mutex,
                wait,
            } => {
                let condition = table.resolve_condition(
                    owner,
                    condition.slot() as usize,
                    condition.generation(),
                )?;
                let mutex =
                    table.resolve_mutex(owner, mutex.slot() as usize, mutex.generation())?;
                return table
                    .condition_wait(
                        threads,
                        owner,
                        caller,
                        sync::ConditionWait {
                            condition,
                            mutex,
                            options: options(wait),
                        },
                        now,
                    )
                    .map(start);
            }
            Request::Notify { condition, all } => {
                let id = table.resolve_condition(
                    owner,
                    condition.slot() as usize,
                    condition.generation(),
                )?;
                table.notify(threads, owner, caller, id, all, now)?;
                reply(Outcome::Success, 0)
            }
            Request::AcquirePermit { permit, wait } => {
                let id =
                    table.resolve_permit(owner, permit.slot() as usize, permit.generation())?;
                return table
                    .acquire_permit(threads, owner, caller, id, mode(wait), now)
                    .map(start);
            }
            Request::ReleasePermit { permit, count } => {
                let id =
                    table.resolve_permit(owner, permit.slot() as usize, permit.generation())?;
                table.release_permits(threads, owner, caller, id, count, now)?;
                reply(Outcome::Success, 0)
            }
            Request::DestroyMutex(token) => {
                let id = table.resolve_mutex(owner, token.slot() as usize, token.generation())?;
                table.destroy_mutex(threads, owner, caller, id)?;
                reply(Outcome::Success, 0)
            }
            Request::DestroyCondition(token) => {
                let id =
                    table.resolve_condition(owner, token.slot() as usize, token.generation())?;
                table.destroy_condition(threads, owner, caller, id)?;
                reply(Outcome::Success, 0)
            }
            Request::DestroyPermit(token) => {
                let id = table.resolve_permit(owner, token.slot() as usize, token.generation())?;
                table.destroy_permit(threads, owner, caller, id)?;
                reply(Outcome::Success, 0)
            }
        };
        Ok(Effect::Reply(response))
    }
}

impl Retiring {
    /// Exact caller that must never resume after this accepted Exit.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.operation.caller
    }

    /// Captured Exit and scalar result for matching the retained native claim.
    #[must_use]
    pub const fn request(&self) -> Request {
        self.operation.authority.request()
    }

    /// Whether native composition retires one thread or stops the entire process.
    #[must_use]
    pub const fn disposition(&self) -> sync::ExitEffect {
        self.disposition
    }

    /// Publish the retained scalar only after removing this native continuation.
    ///
    /// This acknowledges no resources and produces no wire response. Physical
    /// owners must still zero/reclaim frames before logical resource release or
    /// Join readiness. Initial-thread and last-thread process fate, including
    /// reclamation of revoked prepared children, remain composition obligations.
    ///
    /// # Errors
    /// Returns this action unchanged if process-wide stop was required or the
    /// lifecycle no longer permits completion. Never replay the original Exit.
    #[allow(clippy::result_large_err)] // Preserve bounded ownership without allocation.
    pub fn complete_thread(self, threads: &mut ThreadTable) -> Result<(), (Error, Self)> {
        let Request::Exit(result) = self.request() else {
            return Err((Error::Encoding, self));
        };
        if self.disposition != sync::ExitEffect::ThreadExiting {
            return Err((Error::Thread(ThreadError::InvalidState), self));
        }
        let caller = self.caller();
        threads
            .complete(caller.process(), caller, result)
            .map_err(|error| (Error::Thread(error), self))
    }
}

impl Completion {
    /// Captured caller whose native claim must receive this reply.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.caller
    }

    /// Immutable original request, for exact native completion correlation.
    #[must_use]
    pub const fn request(&self) -> Request {
        self.request
    }

    /// Canonical checked result; this is not permission to execute the request.
    #[must_use]
    pub const fn response(&self) -> Response {
        self.response
    }
}

impl Waiting {
    /// Captured thread to dispatch when its owned wait becomes runnable.
    #[must_use]
    pub const fn caller(&self) -> ThreadId {
        self.operation.caller
    }

    /// Observe deadline/stop for this exact operation without rerunning it.
    ///
    /// # Errors
    /// Rejects retired waits, stopping processes and regressing clocks.
    pub fn observe(
        &mut self,
        threads: &mut ThreadTable,
        sync: &mut sync::SyncTable,
        now: MonotonicMillis,
    ) -> Result<bool, Error> {
        let owner = self.caller().process();
        match &mut self.wait {
            WaitKind::Sync(wait) => sync
                .observe(threads, owner, *wait, now)
                .map_err(Error::Sync),
            WaitKind::Control(wait) => wait.observe(threads, now).map_err(Error::Control),
        }
    }

    /// Consume the result after dispatching the captured waiting thread.
    ///
    /// # Errors
    /// Returns the owned wait on failure. Non-running/not-complete rejection
    /// leaves it consumable after dispatch; other failures require process stop.
    /// Encoding failure may follow a consumed policy result and must not retry.
    #[allow(clippy::result_large_err)] // Return bounded ownership without allocation.
    pub fn finish(
        mut self,
        threads: &mut ThreadTable,
        sync: &mut sync::SyncTable,
    ) -> Result<Completion, (Error, Self)> {
        let caller = self.caller();
        let response = match &mut self.wait {
            WaitKind::Sync(wait) => sync
                .finish_wait(threads, caller.process(), caller, *wait)
                .map(|outcome| reply(outcome_code(outcome), 0))
                .map_err(Error::Sync),
            WaitKind::Control(wait) => wait
                .finish(threads)
                .map(control_response)
                .map_err(Error::Control),
        };
        match response {
            Ok(response) => match self.operation.complete(response) {
                Ok(completion) => Ok(completion),
                Err(error) => Err((error, self)),
            },
            Err(error) => Err((error, self)),
        }
    }
}

enum Effect {
    Reply(Response),
    Wait(WaitKind),
    Identity(Kind, usize, u32),
    Exit(sync::ExitEffect),
    Abort(ThreadId),
    Prepare,
    Start(ThreadId),
}

fn reply(outcome: Outcome, value: u64) -> Response {
    Response {
        outcome,
        value,
        snapshot: None,
    }
}

fn options(wait: wire::Wait) -> sync::WaitOptions {
    sync::WaitOptions {
        deadline: wait.deadline.map(MonotonicMillis::from_millis),
        observe_stop: wait.observe_stop,
    }
}

fn mode(wait: wire::WaitMode) -> sync::WaitMode {
    match wait {
        wire::WaitMode::Try => sync::WaitMode::Try,
        wire::WaitMode::Wait(wait) => sync::WaitMode::Wait(options(wait)),
    }
}

fn start(start: sync::SyncStart) -> Effect {
    match start {
        sync::SyncStart::Complete(outcome) => Effect::Reply(reply(outcome_code(outcome), 0)),
        sync::SyncStart::Waiting(wait) => Effect::Wait(WaitKind::Sync(wait)),
    }
}

fn control_start(start: control::Start) -> Effect {
    match start {
        control::Start::Complete(outcome) => Effect::Reply(control_response(outcome)),
        control::Start::Waiting(wait) => Effect::Wait(WaitKind::Control(wait)),
    }
}

fn control_response(outcome: control::Outcome) -> Response {
    match outcome {
        control::Outcome::Joined(value) => reply(Outcome::Success, value),
        control::Outcome::WouldBlock => reply(Outcome::WouldBlock, 0),
        control::Outcome::TimedOut => reply(Outcome::TimedOut, 0),
        control::Outcome::Stopped => reply(Outcome::Stopped, 0),
    }
}

fn outcome_code(outcome: sync::SyncOutcome) -> Outcome {
    match outcome {
        sync::SyncOutcome::Acquired | sync::SyncOutcome::Notified => Outcome::Success,
        sync::SyncOutcome::WouldBlock => Outcome::WouldBlock,
        sync::SyncOutcome::TimedOut => Outcome::TimedOut,
        sync::SyncOutcome::Stopped => Outcome::Stopped,
        sync::SyncOutcome::Poisoned => Outcome::Poisoned,
    }
}

fn error_outcome(error: sync::SyncError) -> Result<Outcome, Error> {
    use ThreadError as T;
    use sync::SyncError as S;
    Ok(match error {
        S::Thread(T::Stale | T::WrongOwner) | S::Stale | S::WrongOwner => Outcome::Stale,
        S::Thread(T::Busy) | S::Busy => Outcome::Busy,
        S::Thread(T::Exhausted) | S::Exhausted => Outcome::Exhausted,
        S::Thread(T::Stopping) => Outcome::Stopping,
        S::Thread(T::InvalidState) => Outcome::InvalidState,
        S::NotOwner => Outcome::NotOwner,
        S::Deadlock | S::Thread(T::SelfJoin) => Outcome::Deadlock,
        S::DifferentMutex => Outcome::DifferentMutex,
        S::Overflow => Outcome::Overflow,
        S::Thread(error) => return Err(Error::Thread(error)),
        error => return Err(Error::Sync(error)),
    })
}

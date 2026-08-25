//! Bounded, architecture-independent cooperative task policy.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Milliseconds elapsed on the machine's monotonic clock.
///
/// Values have no wall-clock meaning and may be compared only within one boot.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(u64);

impl MonotonicMillis {
    /// Construct a boot-relative monotonic timestamp.
    #[must_use]
    pub const fn from_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    /// Exact boot-relative millisecond count.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Form a deadline without wrapping at the representable ceiling.
    #[must_use]
    pub const fn saturating_add(self, milliseconds: u64) -> Self {
        Self(self.0.saturating_add(milliseconds))
    }
}

/// Cooperative execution was cancelled at an explicit checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cancelled;

/// Runtime hook shared by commands, services, and future applications.
///
/// Implementations must bound the work performed by one checkpoint. Sleeping
/// remains cooperative: ambient services and cancellation are checked until
/// the monotonic deadline is reached.
pub trait CooperativeRuntime: fmt::Debug {
    /// Read the boot-relative monotonic clock.
    fn now(&self) -> MonotonicMillis;

    /// Yield to bounded ambient work and observe cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`Cancelled`] after the active invocation receives a request.
    fn checkpoint(&mut self) -> Result<(), Cancelled>;

    /// Cooperatively wait until `deadline`.
    ///
    /// # Errors
    ///
    /// Returns [`Cancelled`] if cancellation is observed before the deadline.
    fn sleep_until(&mut self, deadline: MonotonicMillis) -> Result<(), Cancelled> {
        while self.now() < deadline {
            self.checkpoint()?;
            core::hint::spin_loop();
        }
        Ok(())
    }

    /// Cooperatively wait for a relative millisecond interval.
    ///
    /// # Errors
    ///
    /// Returns [`Cancelled`] if cancellation is observed before completion.
    fn sleep(&mut self, milliseconds: u64) -> Result<(), Cancelled> {
        let deadline = self.now().saturating_add(milliseconds);
        self.sleep_until(deadline)
    }
}

/// Maximum number of live or unreaped cooperative task records.
pub const MAX_TASKS: usize = 16;

/// Opaque identity allocated monotonically for one task lifetime.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TaskId(u32);

impl TaskId {
    /// Numeric identity used only for diagnostics and tests.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Typed authority carried by a task record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Capabilities(u32);

impl Capabilities {
    /// No authority.
    pub const NONE: Self = Self(0);
    /// May use the native console transport.
    pub const CONSOLE: Self = Self(1 << 0);
    /// May access the mounted filesystem namespace.
    pub const FILESYSTEM: Self = Self(1 << 1);
    /// May request terminal machine control such as poweroff or reboot.
    pub const MACHINE_CONTROL: Self = Self(1 << 2);
    /// May be dispatched as an internal cooperative service.
    pub const SERVICE: Self = Self(1 << 3);

    /// Combine two sets without exposing their representation.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether this set contains every requested authority bit.
    #[must_use]
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
}

/// A reusable guarded-stack slot owned by one task until it is reaped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackResource {
    slot: u8,
    mapped_pages: u16,
}

/// Address-space, frame, and handle ownership retained by one isolated task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsolationResource {
    slot: u8,
    table_pages: u64,
    private_pages: u64,
    handles: u16,
}

impl IsolationResource {
    /// Describe one externally validated isolated address space.
    ///
    /// # Errors
    ///
    /// Rejects resources without page tables or private user pages.
    pub const fn new(
        slot: u8,
        table_pages: u64,
        private_pages: u64,
        handles: u16,
    ) -> Result<Self, TaskError> {
        if table_pages == 0 || private_pages == 0 {
            return Err(TaskError::EmptyAddressSpace);
        }
        Ok(Self {
            slot,
            table_pages,
            private_pages,
            handles,
        })
    }

    /// Pool-local address-space slot.
    #[must_use]
    pub const fn slot(self) -> u8 {
        self.slot
    }

    /// Page-table frames retained until reaping.
    #[must_use]
    pub const fn table_pages(self) -> u64 {
        self.table_pages
    }

    /// Private code, data, and stack frames retained until reaping.
    #[must_use]
    pub const fn private_pages(self) -> u64 {
        self.private_pages
    }

    /// Capability handles that teardown must invalidate.
    #[must_use]
    pub const fn handles(self) -> u16 {
        self.handles
    }

    /// Total physical frames retained by the address space.
    #[must_use]
    pub const fn total_pages(self) -> u64 {
        self.table_pages.saturating_add(self.private_pages)
    }
}

/// Contained unprivileged failure category recorded without trusting task data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskFault {
    /// Instruction or data address was not mapped.
    Translation,
    /// A mapped page denied the requested access.
    Permission,
    /// The task executed an invalid or unsupported instruction.
    IllegalInstruction,
    /// The task invoked an unknown call or supplied an invalid message range.
    InvalidCall,
    /// The task exhausted its bounded uninterrupted execution lease.
    ExecutionLeaseExpired,
}

impl StackResource {
    /// Describe one externally validated stack slot.
    ///
    /// # Errors
    ///
    /// Rejects a stack with no mapped payload pages.
    pub const fn new(slot: u8, mapped_pages: u16) -> Result<Self, TaskError> {
        if mapped_pages == 0 {
            return Err(TaskError::EmptyStack);
        }
        Ok(Self { slot, mapped_pages })
    }

    /// Pool-local slot number.
    #[must_use]
    pub const fn slot(self) -> u8 {
        self.slot
    }

    /// Mapped payload pages, excluding guard pages.
    #[must_use]
    pub const fn mapped_pages(self) -> u16 {
        self.mapped_pages
    }
}

/// Observable lifecycle of one cooperative task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    /// Eligible for capability-scoped dispatch.
    Ready,
    /// Currently executing on the single CPU.
    Running,
    /// Finished and retaining resources until explicitly reaped.
    Exited,
    /// Faulted at unprivileged execution level and awaiting explicit reaping.
    Faulted,
}

/// Result returned by one explicit cooperative continuation step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TaskStep {
    /// Preserve task-owned state and return control to the scheduler.
    Yield = 0,
    /// Finish successfully and make the record reapable.
    ExitSuccess = 1,
    /// Finish unsuccessfully and make the record reapable.
    ExitFailure = 2,
}

/// Read-only task metadata exposed by the scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskSnapshot {
    id: TaskId,
    state: TaskState,
    capabilities: Capabilities,
    stack: StackResource,
    dispatches: u32,
    yields: u32,
    exit_status: Option<u32>,
    isolation: Option<IsolationResource>,
    fault: Option<TaskFault>,
}

impl TaskSnapshot {
    /// Task identity.
    #[must_use]
    pub const fn id(self) -> TaskId {
        self.id
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(self) -> TaskState {
        self.state
    }

    /// Authority granted at spawn time.
    #[must_use]
    pub const fn capabilities(self) -> Capabilities {
        self.capabilities
    }

    /// Stack resource retained by the task.
    #[must_use]
    pub const fn stack(self) -> StackResource {
        self.stack
    }

    /// Number of times selected for execution.
    #[must_use]
    pub const fn dispatches(self) -> u32 {
        self.dispatches
    }

    /// Number of explicit cooperative yields.
    #[must_use]
    pub const fn yields(self) -> u32 {
        self.yields
    }

    /// Stable process-style completion status, once exited.
    #[must_use]
    pub const fn exit_status(self) -> Option<u32> {
        self.exit_status
    }

    /// Isolated resources retained by this record, when applicable.
    #[must_use]
    pub const fn isolation(self) -> Option<IsolationResource> {
        self.isolation
    }

    /// Contained fault that terminated the task, when applicable.
    #[must_use]
    pub const fn fault(self) -> Option<TaskFault> {
        self.fault
    }
}

/// Resource returned after a completed task is reaped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReapedTask {
    /// Identity of the retired record.
    pub id: TaskId,
    /// Guarded-stack slot returned to its owner pool.
    pub stack: StackResource,
    /// Final task status.
    pub exit_status: u32,
    /// Isolated resources returned for zeroization, handle revocation, and
    /// physical-frame reclamation.
    pub isolation: Option<IsolationResource>,
    /// Contained fault, if the task did not exit normally.
    pub fault: Option<TaskFault>,
}

/// Aggregate scheduler and task-owned-resource counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaskStats {
    /// Records spawned since scheduler creation.
    pub spawned: u32,
    /// Records currently retained, including exited records.
    pub live_records: u16,
    /// Tasks successfully reaped.
    pub reaped: u32,
    /// Explicit cooperative yields observed.
    pub yields: u32,
    /// Mapped stack pages retained by live records.
    pub owned_stack_pages: u32,
    /// Isolated address spaces retained by live records.
    pub owned_address_spaces: u16,
    /// Page-table plus private frames retained by isolated records.
    pub owned_isolation_pages: u64,
    /// Handles awaiting invalidation during isolated-task teardown.
    pub owned_handles: u32,
    /// Unprivileged task faults contained since scheduler creation.
    pub contained_faults: u32,
}

/// Deterministic scheduler-policy failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskError {
    /// Configured record bound is zero or exceeds [`MAX_TASKS`].
    InvalidCapacity,
    /// Metadata reservation could not be satisfied.
    MetadataExhausted,
    /// No additional task record may be created.
    CapacityExhausted,
    /// Task identity allocation overflowed.
    IdentityExhausted,
    /// No payload page exists between the stack guards.
    EmptyStack,
    /// An isolated address space has no table or private pages.
    EmptyAddressSpace,
    /// A retained task already owns the supplied stack slot.
    StackInUse,
    /// A retained task already owns the supplied address-space slot.
    AddressSpaceInUse,
    /// The requested identity is not retained.
    UnknownTask,
    /// Another task is already marked running.
    TaskAlreadyRunning,
    /// The operation does not match the task lifecycle state.
    InvalidState,
    /// Dispatch or transition counters overflowed.
    AccountingOverflow,
}

impl fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("task capacity is invalid"),
            Self::MetadataExhausted => formatter.write_str("task metadata allocation failed"),
            Self::CapacityExhausted => formatter.write_str("task record capacity exhausted"),
            Self::IdentityExhausted => formatter.write_str("task identity space exhausted"),
            Self::EmptyStack => formatter.write_str("task stack has no mapped pages"),
            Self::EmptyAddressSpace => formatter.write_str("isolated address space is empty"),
            Self::StackInUse => formatter.write_str("task stack slot is already owned"),
            Self::AddressSpaceInUse => {
                formatter.write_str("isolated address-space slot is already owned")
            }
            Self::UnknownTask => formatter.write_str("task identity is unknown"),
            Self::TaskAlreadyRunning => {
                formatter.write_str("a cooperative task is already running")
            }
            Self::InvalidState => formatter.write_str("task lifecycle transition is invalid"),
            Self::AccountingOverflow => formatter.write_str("task accounting overflowed"),
        }
    }
}

/// Failure while performing the scheduler-owned portion of isolated teardown.
///
/// A task-transition failure occurs before external authority revocation. A
/// revocation failure leaves the record terminal and retained, so callers must
/// not zero or release its physical resources. A reaping failure likewise
/// leaves the terminal record retained after successful revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TeardownError<RevocationError> {
    /// Scheduler lookup, terminal transition, or reaping failed.
    Task(TaskError),
    /// The injected external-authority revoker failed.
    Revocation(RevocationError),
}

impl<RevocationError> From<TaskError> for TeardownError<RevocationError> {
    fn from(error: TaskError) -> Self {
        Self::Task(error)
    }
}

impl<RevocationError: fmt::Display> fmt::Display for TeardownError<RevocationError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Task(error) => write!(formatter, "isolated teardown task failure: {error}"),
            Self::Revocation(error) => {
                write!(formatter, "isolated teardown revocation failure: {error}")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskRecord {
    snapshot: TaskSnapshot,
}

/// Bounded single-CPU round-robin cooperative scheduler policy.
///
/// The scheduler owns records and resource accounting, but not native context
/// switching. At most one record can be `Running`; only an explicit yield or
/// exit returns it to scheduler control.
#[derive(Debug)]
pub struct Scheduler {
    records: Vec<TaskRecord>,
    capacity: usize,
    cursor: usize,
    current: Option<TaskId>,
    next_id: u32,
    spawned: u32,
    reaped: u32,
    total_yields: u32,
    contained_faults: u32,
}

impl Scheduler {
    /// Create a scheduler with an immutable task-record bound.
    ///
    /// # Errors
    ///
    /// Rejects invalid capacity or metadata allocation failure.
    pub fn new(capacity: usize) -> Result<Self, TaskError> {
        if capacity == 0 || capacity > MAX_TASKS {
            return Err(TaskError::InvalidCapacity);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(capacity)
            .map_err(|_| TaskError::MetadataExhausted)?;
        Ok(Self {
            records,
            capacity,
            cursor: 0,
            current: None,
            next_id: 1,
            spawned: 0,
            reaped: 0,
            total_yields: 0,
            contained_faults: 0,
        })
    }

    /// Retain a ready task and take ownership of its stack slot.
    ///
    /// # Errors
    ///
    /// Rejects capacity, identity, accounting, or duplicate-stack violations.
    pub fn spawn(
        &mut self,
        capabilities: Capabilities,
        stack: StackResource,
    ) -> Result<TaskId, TaskError> {
        self.spawn_with_isolation(capabilities, stack, None)
    }

    /// Retain a ready isolated task and all resources required for teardown.
    ///
    /// # Errors
    ///
    /// Rejects the ordinary spawn failures plus duplicate address-space slots.
    pub fn spawn_isolated(
        &mut self,
        capabilities: Capabilities,
        stack: StackResource,
        isolation: IsolationResource,
    ) -> Result<TaskId, TaskError> {
        self.spawn_with_isolation(capabilities, stack, Some(isolation))
    }

    fn spawn_with_isolation(
        &mut self,
        capabilities: Capabilities,
        stack: StackResource,
        isolation: Option<IsolationResource>,
    ) -> Result<TaskId, TaskError> {
        if self.records.len() == self.capacity {
            return Err(TaskError::CapacityExhausted);
        }
        if self
            .records
            .iter()
            .any(|record| record.snapshot.stack.slot == stack.slot)
        {
            return Err(TaskError::StackInUse);
        }
        if let Some(isolation) = isolation
            && self.records.iter().any(|record| {
                record
                    .snapshot
                    .isolation
                    .is_some_and(|owned| owned.slot == isolation.slot)
            })
        {
            return Err(TaskError::AddressSpaceInUse);
        }
        let id = TaskId(self.next_id);
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or(TaskError::IdentityExhausted)?;
        let spawned = self
            .spawned
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        self.records.push(TaskRecord {
            snapshot: TaskSnapshot {
                id,
                state: TaskState::Ready,
                capabilities,
                stack,
                dispatches: 0,
                yields: 0,
                exit_status: None,
                isolation,
                fault: None,
            },
        });
        self.next_id = next_id;
        self.spawned = spawned;
        Ok(id)
    }

    /// Select the next ready task possessing every required capability.
    ///
    /// # Errors
    ///
    /// Rejects selection while another cooperative task remains running or if
    /// dispatch accounting overflows.
    pub fn dispatch_next(&mut self, required: Capabilities) -> Result<Option<TaskId>, TaskError> {
        if self.current.is_some() {
            return Err(TaskError::TaskAlreadyRunning);
        }
        let count = self.records.len();
        for offset in 0..count {
            let index = (self.cursor + offset) % count;
            let snapshot = &mut self.records[index].snapshot;
            if snapshot.state != TaskState::Ready || !snapshot.capabilities.contains(required) {
                continue;
            }
            snapshot.dispatches = snapshot
                .dispatches
                .checked_add(1)
                .ok_or(TaskError::AccountingOverflow)?;
            snapshot.state = TaskState::Running;
            self.current = Some(snapshot.id);
            self.cursor = (index + 1) % count;
            return Ok(Some(snapshot.id));
        }
        Ok(None)
    }

    /// Record an explicit cooperative yield by the running task.
    ///
    /// # Errors
    ///
    /// Rejects an unknown, non-running, or non-current identity and checked
    /// counter overflow.
    pub fn yield_current(&mut self, id: TaskId) -> Result<(), TaskError> {
        if self.current != Some(id) {
            return Err(TaskError::InvalidState);
        }
        let total_yields = self
            .total_yields
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        let record = self.record_mut(id)?;
        if record.snapshot.state != TaskState::Running {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.yields = record
            .snapshot
            .yields
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        record.snapshot.state = TaskState::Ready;
        self.total_yields = total_yields;
        self.current = None;
        Ok(())
    }

    /// Replace the resource accounting of the running isolated task.
    ///
    /// This is used after an atomic address-space growth commit. The address-
    /// space slot and handle ownership cannot change through this operation.
    ///
    /// # Errors
    ///
    /// Rejects a non-current, non-running, non-isolated task, or a replacement
    /// that changes its address-space identity or handle ownership.
    pub fn resize_current_isolation(
        &mut self,
        id: TaskId,
        replacement: IsolationResource,
    ) -> Result<(), TaskError> {
        if self.current != Some(id) {
            return Err(TaskError::InvalidState);
        }
        let record = self.record_mut(id)?;
        if record.snapshot.state != TaskState::Running {
            return Err(TaskError::InvalidState);
        }
        let Some(current) = record.snapshot.isolation else {
            return Err(TaskError::InvalidState);
        };
        if current.slot != replacement.slot || current.handles != replacement.handles {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.isolation = Some(replacement);
        Ok(())
    }

    /// Finish the running task and retain its resources for explicit reaping.
    ///
    /// # Errors
    ///
    /// Rejects an unknown, non-running, or non-current identity.
    pub fn exit_current(&mut self, id: TaskId, status: u32) -> Result<(), TaskError> {
        if self.current != Some(id) {
            return Err(TaskError::InvalidState);
        }
        let record = self.record_mut(id)?;
        if record.snapshot.state != TaskState::Running {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.state = TaskState::Exited;
        record.snapshot.exit_status = Some(status);
        self.current = None;
        Ok(())
    }

    /// Cancel a ready isolated task whose native launch could not begin.
    ///
    /// This transition exists solely for transactional composition rollback:
    /// it cannot cancel a running task, a kernel task, or an already terminal
    /// record. Resources remain retained until the ordinary reap operation.
    ///
    /// # Errors
    ///
    /// Rejects unknown, non-ready, or non-isolated tasks.
    pub fn cancel_ready(&mut self, id: TaskId, status: u32) -> Result<(), TaskError> {
        let record = self.record_mut(id)?;
        if record.snapshot.state != TaskState::Ready || record.snapshot.isolation.is_none() {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.state = TaskState::Exited;
        record.snapshot.exit_status = Some(status);
        Ok(())
    }

    /// Terminate the running unprivileged task after a contained native fault.
    ///
    /// # Errors
    ///
    /// Rejects a non-current, non-running, or non-isolated task and checked
    /// fault-accounting overflow. State is unchanged on every error.
    pub fn fault_current(&mut self, id: TaskId, fault: TaskFault) -> Result<(), TaskError> {
        if self.current != Some(id) {
            return Err(TaskError::InvalidState);
        }
        let contained_faults = self
            .contained_faults
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        let record = self.record_mut(id)?;
        if record.snapshot.state != TaskState::Running || record.snapshot.isolation.is_none() {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.state = TaskState::Faulted;
        record.snapshot.exit_status = Some(128);
        record.snapshot.fault = Some(fault);
        self.current = None;
        self.contained_faults = contained_faults;
        Ok(())
    }

    /// Remove an exited record and return its task-owned stack resource.
    ///
    /// # Errors
    ///
    /// Rejects unknown or non-exited tasks and checked accounting overflow.
    pub fn reap(&mut self, id: TaskId) -> Result<ReapedTask, TaskError> {
        let index = self
            .records
            .iter()
            .position(|record| record.snapshot.id == id)
            .ok_or(TaskError::UnknownTask)?;
        let snapshot = self.records[index].snapshot;
        if !matches!(snapshot.state, TaskState::Exited | TaskState::Faulted) {
            return Err(TaskError::InvalidState);
        }
        let reaped = self
            .reaped
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        self.records.remove(index);
        self.reaped = reaped;
        if self.records.is_empty() {
            self.cursor = 0;
        } else if index < self.cursor {
            self.cursor -= 1;
        } else if self.cursor >= self.records.len() {
            self.cursor = 0;
        }
        Ok(ReapedTask {
            id,
            stack: snapshot.stack,
            exit_status: snapshot.exit_status.ok_or(TaskError::InvalidState)?,
            isolation: snapshot.isolation,
            fault: snapshot.fault,
        })
    }

    /// Terminalize one isolated record, revoke its external authority, then reap it.
    ///
    /// Ready records are cancelled and running records exit with
    /// `rollback_status`. Already exited or faulted records retain their original
    /// outcome. Only after the record is terminal is `revoke` invoked with its
    /// terminal snapshot, and reaping occurs only if revocation succeeds.
    /// Physical zeroization and frame release are intentionally left to the
    /// caller after this method returns successfully.
    ///
    /// # Errors
    ///
    /// Returns [`TeardownError::Task`] for an unknown or non-isolated record, an
    /// invalid lifecycle transition, or a reaping failure. Returns
    /// [`TeardownError::Revocation`] when the injected revoker fails. Revocation
    /// failure leaves the task terminal and unreaped; reaping failure leaves it
    /// terminal and retained after revocation.
    pub fn terminate_revoke_and_reap<RevocationError>(
        &mut self,
        id: TaskId,
        rollback_status: u32,
        revoke: impl FnOnce(TaskSnapshot) -> Result<(), RevocationError>,
    ) -> Result<ReapedTask, TeardownError<RevocationError>> {
        let snapshot = self.task(id)?;
        if snapshot.isolation().is_none() {
            return Err(TeardownError::Task(TaskError::InvalidState));
        }
        match snapshot.state() {
            TaskState::Ready => self.cancel_ready(id, rollback_status)?,
            TaskState::Running => self.exit_current(id, rollback_status)?,
            TaskState::Exited | TaskState::Faulted => {}
        }
        let terminal = self.task(id)?;
        revoke(terminal).map_err(TeardownError::Revocation)?;
        self.reap(id).map_err(TeardownError::Task)
    }

    /// Obtain one immutable task snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError::UnknownTask`] for an identity no longer retained.
    pub fn task(&self, id: TaskId) -> Result<TaskSnapshot, TaskError> {
        self.records
            .iter()
            .find(|record| record.snapshot.id == id)
            .map(|record| record.snapshot)
            .ok_or(TaskError::UnknownTask)
    }

    /// Snapshot lifecycle and stack-ownership accounting.
    #[must_use]
    pub fn stats(&self) -> TaskStats {
        let owned_stack_pages = self.records.iter().fold(0_u32, |total, record| {
            total.saturating_add(u32::from(record.snapshot.stack.mapped_pages))
        });
        let owned_address_spaces = self
            .records
            .iter()
            .filter(|record| record.snapshot.isolation.is_some())
            .count();
        let (owned_isolation_pages, owned_handles) =
            self.records
                .iter()
                .fold((0_u64, 0_u32), |(pages, handles), record| {
                    match record.snapshot.isolation {
                        Some(resource) => (
                            pages.saturating_add(resource.total_pages()),
                            handles.saturating_add(u32::from(resource.handles)),
                        ),
                        None => (pages, handles),
                    }
                });
        TaskStats {
            spawned: self.spawned,
            live_records: u16::try_from(self.records.len()).unwrap_or(u16::MAX),
            reaped: self.reaped,
            yields: self.total_yields,
            owned_stack_pages,
            owned_address_spaces: u16::try_from(owned_address_spaces).unwrap_or(u16::MAX),
            owned_isolation_pages,
            owned_handles,
            contained_faults: self.contained_faults,
        }
    }

    fn record_mut(&mut self, id: TaskId) -> Result<&mut TaskRecord, TaskError> {
        self.records
            .iter_mut()
            .find(|record| record.snapshot.id == id)
            .ok_or(TaskError::UnknownTask)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cancelled, Capabilities, CooperativeRuntime, IsolationResource, MAX_TASKS, MonotonicMillis,
        Scheduler, StackResource, TaskError, TaskFault, TaskSnapshot, TaskState, TeardownError,
    };

    #[derive(Debug)]
    struct FakeRuntime {
        now: u64,
        checkpoints: u8,
        cancel_at: Option<u8>,
    }

    impl CooperativeRuntime for FakeRuntime {
        fn now(&self) -> MonotonicMillis {
            MonotonicMillis::from_millis(self.now)
        }

        fn checkpoint(&mut self) -> Result<(), Cancelled> {
            self.checkpoints = self.checkpoints.saturating_add(1);
            if self.cancel_at == Some(self.checkpoints) {
                return Err(Cancelled);
            }
            self.now = self.now.saturating_add(1);
            Ok(())
        }
    }

    fn stack(slot: u8) -> Result<StackResource, TaskError> {
        StackResource::new(slot, 8)
    }

    #[test]
    fn cooperative_sleep_uses_monotonic_deadlines_and_cancellation() {
        let mut runtime = FakeRuntime {
            now: 40,
            checkpoints: 0,
            cancel_at: None,
        };
        assert_eq!(runtime.sleep(3), Ok(()));
        assert_eq!(runtime.now(), MonotonicMillis::from_millis(43));
        assert_eq!(runtime.checkpoints, 3);

        runtime.cancel_at = Some(5);
        assert_eq!(runtime.sleep(10), Err(Cancelled));
        assert_eq!(runtime.now(), MonotonicMillis::from_millis(44));
    }

    #[test]
    fn round_robin_yield_and_exit_are_deterministic() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(3)?;
        let first = scheduler.spawn(Capabilities::SERVICE, stack(0)?)?;
        let second = scheduler.spawn(Capabilities::SERVICE, stack(1)?)?;

        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(first))
        );
        assert_eq!(scheduler.yield_current(first), Ok(()));
        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(second))
        );
        assert_eq!(scheduler.yield_current(second), Ok(()));
        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(first))
        );
        assert_eq!(scheduler.exit_current(first, 0), Ok(()));
        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(second))
        );
        assert_eq!(scheduler.exit_current(second, 0x1_0007), Ok(()));
        assert_eq!(scheduler.dispatch_next(Capabilities::SERVICE), Ok(None));

        assert_eq!(scheduler.task(first).map(TaskSnapshot::yields), Ok(1));
        assert_eq!(
            scheduler.task(second).map(TaskSnapshot::exit_status),
            Ok(Some(0x1_0007))
        );
        assert_eq!(scheduler.stats().yields, 2);
        Ok(())
    }

    #[test]
    fn dispatch_is_capability_scoped() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(2)?;
        let unprivileged = scheduler.spawn(Capabilities::NONE, stack(0)?)?;
        let console = scheduler.spawn(Capabilities::CONSOLE, stack(1)?)?;

        assert_eq!(
            scheduler.dispatch_next(Capabilities::CONSOLE),
            Ok(Some(console))
        );
        assert_eq!(scheduler.exit_current(console, 0), Ok(()));
        assert_eq!(scheduler.dispatch_next(Capabilities::CONSOLE), Ok(None));
        assert_eq!(
            scheduler.task(unprivileged).map(TaskSnapshot::dispatches),
            Ok(0)
        );
        assert_eq!(
            scheduler.task(unprivileged).map(TaskSnapshot::state),
            Ok(TaskState::Ready)
        );
        Ok(())
    }

    #[test]
    fn reaping_releases_exact_stack_accounting_for_reuse() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(1)?;
        let first = scheduler.spawn(Capabilities::SERVICE, stack(3)?)?;
        assert_eq!(scheduler.stats().owned_stack_pages, 8);
        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(first))
        );
        assert_eq!(scheduler.exit_current(first, 0), Ok(()));
        let reclaimed = scheduler.reap(first)?;
        assert_eq!(reclaimed.stack, stack(3)?);
        assert_eq!(scheduler.stats().owned_stack_pages, 0);

        let second = scheduler.spawn(Capabilities::SERVICE, reclaimed.stack)?;
        assert_ne!(first, second);
        assert_eq!(scheduler.stats().owned_stack_pages, 8);
        assert_eq!(scheduler.stats().reaped, 1);
        Ok(())
    }

    #[test]
    fn record_and_stack_ownership_bounds_fail_closed() -> Result<(), TaskError> {
        assert_eq!(Scheduler::new(0).err(), Some(TaskError::InvalidCapacity));
        assert_eq!(
            Scheduler::new(MAX_TASKS + 1).err(),
            Some(TaskError::InvalidCapacity)
        );
        assert_eq!(StackResource::new(0, 0), Err(TaskError::EmptyStack));

        let mut scheduler = Scheduler::new(2)?;
        let first = scheduler.spawn(Capabilities::NONE, stack(0)?)?;
        assert_eq!(
            scheduler.spawn(Capabilities::NONE, stack(0)?),
            Err(TaskError::StackInUse)
        );
        assert_eq!(scheduler.reap(first), Err(TaskError::InvalidState));
        assert_eq!(scheduler.dispatch_next(Capabilities::NONE), Ok(Some(first)));
        assert_eq!(
            scheduler.dispatch_next(Capabilities::NONE),
            Err(TaskError::TaskAlreadyRunning)
        );
        Ok(())
    }

    #[test]
    fn isolated_fault_teardown_returns_every_owned_resource() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(2)?;
        let isolation = IsolationResource::new(3, 19, 6, 2)?;
        let id = scheduler.spawn_isolated(Capabilities::SERVICE, stack(0)?, isolation)?;
        let stats = scheduler.stats();
        assert_eq!(stats.owned_address_spaces, 1);
        assert_eq!(stats.owned_isolation_pages, 25);
        assert_eq!(stats.owned_handles, 2);
        assert_eq!(scheduler.dispatch_next(Capabilities::SERVICE), Ok(Some(id)));
        scheduler.fault_current(id, TaskFault::Translation)?;
        assert_eq!(
            scheduler.task(id).map(TaskSnapshot::state),
            Ok(TaskState::Faulted)
        );
        assert_eq!(
            scheduler.task(id).map(TaskSnapshot::fault),
            Ok(Some(TaskFault::Translation))
        );
        let reaped = scheduler.reap(id)?;
        assert_eq!(reaped.isolation, Some(isolation));
        assert_eq!(reaped.fault, Some(TaskFault::Translation));
        assert_eq!(reaped.exit_status, 128);
        let stats = scheduler.stats();
        assert_eq!(stats.owned_address_spaces, 0);
        assert_eq!(stats.owned_isolation_pages, 0);
        assert_eq!(stats.owned_handles, 0);
        assert_eq!(stats.contained_faults, 1);
        Ok(())
    }

    #[test]
    fn running_isolation_can_grow_without_changing_ownership() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(1)?;
        let initial = IsolationResource::new(2, 4, 12, 3)?;
        let grown = IsolationResource::new(2, 5, 28, 3)?;
        let id = scheduler.spawn_isolated(Capabilities::SERVICE, stack(0)?, initial)?;
        assert_eq!(scheduler.dispatch_next(Capabilities::SERVICE), Ok(Some(id)));
        scheduler.resize_current_isolation(id, grown)?;
        assert_eq!(scheduler.task(id)?.isolation(), Some(grown));
        assert_eq!(scheduler.stats().owned_isolation_pages, 33);
        assert_eq!(
            scheduler.resize_current_isolation(id, IsolationResource::new(3, 5, 28, 3)?,),
            Err(TaskError::InvalidState)
        );
        assert_eq!(
            scheduler.resize_current_isolation(id, IsolationResource::new(2, 5, 28, 4)?,),
            Err(TaskError::InvalidState)
        );
        scheduler.exit_current(id, 0)?;
        assert_eq!(scheduler.reap(id)?.isolation, Some(grown));
        Ok(())
    }

    #[test]
    fn ordered_teardown_terminalizes_before_revocation_and_reaps_afterward()
    -> Result<(), TeardownError<&'static str>> {
        for (slot, running) in [(0, false), (1, true)] {
            let mut scheduler = Scheduler::new(1)?;
            let isolation = IsolationResource::new(slot, 4, 6, 1)?;
            let id = scheduler.spawn_isolated(Capabilities::SERVICE, stack(slot)?, isolation)?;
            if running {
                assert_eq!(scheduler.dispatch_next(Capabilities::SERVICE), Ok(Some(id)));
            }

            let mut state_during_revocation = None;
            let reaped = scheduler.terminate_revoke_and_reap(id, 7, |terminal| {
                state_during_revocation = Some(terminal.state());
                Ok::<(), &'static str>(())
            })?;

            assert_eq!(state_during_revocation, Some(TaskState::Exited));
            assert_eq!(reaped.id, id);
            assert_eq!(reaped.exit_status, 7);
            assert_eq!(reaped.isolation, Some(isolation));
            assert_eq!(scheduler.task(id), Err(TaskError::UnknownTask));
            assert_eq!(scheduler.stats().live_records, 0);
            assert_eq!(scheduler.stats().reaped, 1);
        }

        let mut scheduler = Scheduler::new(1)?;
        let isolation = IsolationResource::new(2, 4, 6, 1)?;
        let id = scheduler.spawn_isolated(Capabilities::SERVICE, stack(2)?, isolation)?;
        assert_eq!(scheduler.dispatch_next(Capabilities::SERVICE), Ok(Some(id)));
        scheduler.fault_current(id, TaskFault::Permission)?;
        let reaped = scheduler.terminate_revoke_and_reap(id, 7, |terminal| {
            assert_eq!(terminal.state(), TaskState::Faulted);
            Ok::<(), &'static str>(())
        })?;
        assert_eq!(reaped.exit_status, 128);
        assert_eq!(reaped.fault, Some(TaskFault::Permission));
        Ok(())
    }

    #[test]
    fn teardown_failpoints_retain_terminal_resources() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(2)?;
        let isolation = IsolationResource::new(0, 4, 6, 1)?;
        let id = scheduler.spawn_isolated(Capabilities::SERVICE, stack(0)?, isolation)?;

        let failed = scheduler.terminate_revoke_and_reap(id, 9, |terminal| {
            assert_eq!(terminal.state(), TaskState::Exited);
            Err("injected revocation failure")
        });
        assert_eq!(
            failed,
            Err(TeardownError::Revocation("injected revocation failure"))
        );
        assert_eq!(
            scheduler.task(id).map(TaskSnapshot::state),
            Ok(TaskState::Exited)
        );
        assert_eq!(scheduler.stats().live_records, 1);
        assert_eq!(scheduler.stats().reaped, 0);

        scheduler.reaped = u32::MAX;
        let mut revoked = false;
        let failed = scheduler.terminate_revoke_and_reap(id, 10, |terminal| {
            assert_eq!(terminal.state(), TaskState::Exited);
            assert_eq!(terminal.exit_status(), Some(9));
            revoked = true;
            Ok::<(), &'static str>(())
        });
        assert_eq!(
            failed,
            Err(TeardownError::Task(TaskError::AccountingOverflow))
        );
        assert!(revoked);
        assert_eq!(
            scheduler.task(id).map(TaskSnapshot::state),
            Ok(TaskState::Exited)
        );
        assert_eq!(scheduler.stats().live_records, 1);

        let ordinary = scheduler.spawn(Capabilities::NONE, stack(1)?)?;
        let mut revoker_called = false;
        let failed = scheduler.terminate_revoke_and_reap(ordinary, 1, |_terminal| {
            revoker_called = true;
            Ok::<(), &'static str>(())
        });
        assert_eq!(failed, Err(TeardownError::Task(TaskError::InvalidState)));
        assert!(!revoker_called);
        assert_eq!(
            scheduler.task(ordinary).map(TaskSnapshot::state),
            Ok(TaskState::Ready)
        );
        Ok(())
    }

    #[test]
    fn isolated_resource_aliases_and_invalid_faults_fail_closed() -> Result<(), TaskError> {
        assert_eq!(
            IsolationResource::new(0, 0, 1, 0),
            Err(TaskError::EmptyAddressSpace)
        );
        assert_eq!(
            IsolationResource::new(0, 1, 0, 0),
            Err(TaskError::EmptyAddressSpace)
        );
        let mut scheduler = Scheduler::new(2)?;
        let resource = IsolationResource::new(1, 4, 2, 0)?;
        let first = scheduler.spawn_isolated(Capabilities::NONE, stack(0)?, resource)?;
        assert_eq!(
            scheduler.spawn_isolated(Capabilities::NONE, stack(1)?, resource),
            Err(TaskError::AddressSpaceInUse)
        );
        assert_eq!(
            scheduler.fault_current(first, TaskFault::Permission),
            Err(TaskError::InvalidState)
        );
        assert_eq!(
            scheduler.task(first).map(TaskSnapshot::state),
            Ok(TaskState::Ready)
        );
        scheduler.cancel_ready(first, 9)?;
        let reaped = scheduler.reap(first)?;
        assert_eq!(reaped.exit_status, 9);
        assert_eq!(reaped.isolation, Some(resource));
        Ok(())
    }
}

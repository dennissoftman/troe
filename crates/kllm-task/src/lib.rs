//! Bounded, architecture-independent cooperative task policy.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

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
    /// May request terminal machine control such as halt.
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
    exit_status: Option<u8>,
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
    pub const fn exit_status(self) -> Option<u8> {
        self.exit_status
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
    pub exit_status: u8,
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
    /// A retained task already owns the supplied stack slot.
    StackInUse,
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
            Self::StackInUse => formatter.write_str("task stack slot is already owned"),
            Self::UnknownTask => formatter.write_str("task identity is unknown"),
            Self::TaskAlreadyRunning => {
                formatter.write_str("a cooperative task is already running")
            }
            Self::InvalidState => formatter.write_str("task lifecycle transition is invalid"),
            Self::AccountingOverflow => formatter.write_str("task accounting overflowed"),
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

    /// Finish the running task and retain its resources for explicit reaping.
    ///
    /// # Errors
    ///
    /// Rejects an unknown, non-running, or non-current identity.
    pub fn exit_current(&mut self, id: TaskId, status: u8) -> Result<(), TaskError> {
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
        if snapshot.state != TaskState::Exited {
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
        })
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
        TaskStats {
            spawned: self.spawned,
            live_records: u16::try_from(self.records.len()).unwrap_or(u16::MAX),
            reaped: self.reaped,
            yields: self.total_yields,
            owned_stack_pages,
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
        Capabilities, MAX_TASKS, Scheduler, StackResource, TaskError, TaskSnapshot, TaskState,
    };

    fn stack(slot: u8) -> Result<StackResource, TaskError> {
        StackResource::new(slot, 8)
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
        assert_eq!(scheduler.exit_current(second, 7), Ok(()));
        assert_eq!(scheduler.dispatch_next(Capabilities::SERVICE), Ok(None));

        assert_eq!(scheduler.task(first).map(TaskSnapshot::yields), Ok(1));
        assert_eq!(
            scheduler.task(second).map(TaskSnapshot::exit_status),
            Ok(Some(7))
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
}

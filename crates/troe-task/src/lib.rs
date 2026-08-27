//! Bounded, architecture-independent cooperative task policy.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

mod wait;

pub use wait::{
    MAX_PENDING_CALLS, MAX_PENDING_REQUEST_BYTES, MAX_WAIT_REGISTRATIONS, PendingCallError,
    PendingCallSnapshot, PendingCallState, PendingCallStats, PendingCallTable, PendingOperationId,
    WaitCompletion, WaitError, WaitKey, WaitObservation, WaitRegistration, WaitResource, WaitSpec,
    WaitStats, WaitTable, WakeBatch, WakeInterest, WakeReason,
};

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

/// Maximum UTF-8 bytes retained for one observable process name.
pub const MAX_PROCESS_NAME_BYTES: usize = 32;

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

/// Monotonic, non-reused identity for one application-process lifetime.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessId(u64);

impl ProcessId {
    /// Numeric diagnostic identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Launcher-owned placement of one observable application process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOrigin {
    /// Command attached to the shell's foreground terminal.
    Foreground,
    /// Session-owned background command.
    Background,
    /// Supervised system service.
    Service,
}

/// Observable lifecycle state independent of scheduler implementation details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    /// Eligible for a future application execution slice.
    Ready,
    /// Currently executing at the unprivileged level.
    Running,
    /// Waiting for one typed completion.
    Blocked,
    /// Cancellation has been requested and teardown is pending.
    Stopping,
}

/// Bounded UTF-8 executable name retained without command arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessName {
    bytes: [u8; MAX_PROCESS_NAME_BYTES],
    len: u8,
}

impl ProcessName {
    /// Copy one nonempty bounded UTF-8 name.
    ///
    /// # Errors
    ///
    /// Rejects an empty name or one above [`MAX_PROCESS_NAME_BYTES`].
    pub fn new(name: &str) -> Result<Self, ProcessError> {
        if name.is_empty() || name.len() > MAX_PROCESS_NAME_BYTES {
            return Err(ProcessError::InvalidName);
        }
        let mut bytes = [0_u8; MAX_PROCESS_NAME_BYTES];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self {
            bytes,
            len: u8::try_from(name.len()).map_err(|_| ProcessError::InvalidName)?,
        })
    }

    /// Borrow the validated UTF-8 name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("invalid-process-name")
    }
}

/// Immutable process metadata suitable for capability-scoped observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessSnapshot {
    id: ProcessId,
    task_id: TaskId,
    name: ProcessName,
    origin: ProcessOrigin,
    state: ProcessState,
    started_millis: u64,
    cpu_ticks: u64,
    table_pages: u64,
    private_pages: u64,
    handles: u16,
    dispatches: u32,
    yields: u32,
    preemptions: u32,
}

impl ProcessSnapshot {
    /// Stable process identity.
    #[must_use]
    pub const fn id(self) -> ProcessId {
        self.id
    }

    /// Internal scheduler identity retained for diagnostics.
    #[must_use]
    pub const fn task_id(self) -> TaskId {
        self.task_id
    }

    /// Executable name without arguments.
    #[must_use]
    pub const fn name(self) -> ProcessName {
        self.name
    }

    /// Launch placement.
    #[must_use]
    pub const fn origin(self) -> ProcessOrigin {
        self.origin
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(self) -> ProcessState {
        self.state
    }

    /// Boot-relative launch time.
    #[must_use]
    pub const fn started_millis(self) -> u64 {
        self.started_millis
    }

    /// High-resolution execution ticks charged only around user entry.
    #[must_use]
    pub const fn cpu_ticks(self) -> u64 {
        self.cpu_ticks
    }

    /// Retained page-table pages.
    #[must_use]
    pub const fn table_pages(self) -> u64 {
        self.table_pages
    }

    /// Retained private image, startup, heap, and stack pages.
    #[must_use]
    pub const fn private_pages(self) -> u64 {
        self.private_pages
    }

    /// Total retained application pages.
    #[must_use]
    pub const fn resident_pages(self) -> u64 {
        self.table_pages.saturating_add(self.private_pages)
    }

    /// Live generation-checked handles owned by the process.
    #[must_use]
    pub const fn handles(self) -> u16 {
        self.handles
    }

    /// Scheduler dispatch selections.
    #[must_use]
    pub const fn dispatches(self) -> u32 {
        self.dispatches
    }

    /// Voluntary yields.
    #[must_use]
    pub const fn yields(self) -> u32 {
        self.yields
    }

    /// Timer-driven resumable preemptions.
    #[must_use]
    pub const fn preemptions(self) -> u32 {
        self.preemptions
    }
}

/// Process-table registration values supplied after transactional launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessRegistration {
    /// Scheduler task backing the process.
    pub task_id: TaskId,
    /// Executable name without arguments.
    pub name: ProcessName,
    /// Launcher placement.
    pub origin: ProcessOrigin,
    /// Boot-relative launch time.
    pub started_millis: u64,
    /// Initially retained page-table pages.
    pub table_pages: u64,
    /// Initially retained private pages.
    pub private_pages: u64,
    /// Initially granted handles.
    pub handles: u16,
}

/// Bounded process-registry failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessError {
    /// Configured capacity is zero or above [`MAX_TASKS`].
    InvalidCapacity,
    /// Process metadata could not be reserved.
    MetadataExhausted,
    /// The process table is full.
    CapacityExhausted,
    /// The monotonic identity space is exhausted.
    IdentityExhausted,
    /// The supplied name is empty or too long.
    InvalidName,
    /// The process identity is unknown.
    UnknownProcess,
    /// A task already backs another registered process.
    TaskInUse,
    /// The requested lifecycle transition is invalid.
    InvalidState,
    /// A checked counter overflowed.
    AccountingOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessRecord {
    snapshot: ProcessSnapshot,
}

/// Bounded registry shared by foreground commands, background jobs, and services.
#[derive(Debug)]
pub struct ProcessTable {
    records: Vec<ProcessRecord>,
    capacity: usize,
    next_id: u64,
}

impl ProcessTable {
    /// Create a registry with one immutable record bound.
    ///
    /// # Errors
    ///
    /// Rejects invalid capacity or metadata reservation failure.
    pub fn new(capacity: usize) -> Result<Self, ProcessError> {
        if capacity == 0 || capacity > MAX_TASKS {
            return Err(ProcessError::InvalidCapacity);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(capacity)
            .map_err(|_| ProcessError::MetadataExhausted)?;
        Ok(Self {
            records,
            capacity,
            next_id: 1,
        })
    }

    /// Register one successfully spawned application task.
    ///
    /// # Errors
    ///
    /// Rejects exhausted identity/record capacity, duplicate tasks, invalid
    /// resources, or invalid names.
    pub fn register(
        &mut self,
        registration: ProcessRegistration,
    ) -> Result<ProcessId, ProcessError> {
        if self.records.len() == self.capacity {
            return Err(ProcessError::CapacityExhausted);
        }
        if self
            .records
            .iter()
            .any(|record| record.snapshot.task_id == registration.task_id)
        {
            return Err(ProcessError::TaskInUse);
        }
        if registration.table_pages == 0 || registration.private_pages == 0 {
            return Err(ProcessError::InvalidState);
        }
        let id = ProcessId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ProcessError::IdentityExhausted)?;
        self.records.push(ProcessRecord {
            snapshot: ProcessSnapshot {
                id,
                task_id: registration.task_id,
                name: registration.name,
                origin: registration.origin,
                state: ProcessState::Ready,
                started_millis: registration.started_millis,
                cpu_ticks: 0,
                table_pages: registration.table_pages,
                private_pages: registration.private_pages,
                handles: registration.handles,
                dispatches: 0,
                yields: 0,
                preemptions: 0,
            },
        });
        Ok(id)
    }

    /// Mark one ready process as executing.
    ///
    /// # Errors
    ///
    /// Rejects an unknown process, invalid state, or counter overflow.
    pub fn dispatch(&mut self, id: ProcessId) -> Result<(), ProcessError> {
        let record = self.record_mut(id)?;
        if record.snapshot.state != ProcessState::Ready {
            return Err(ProcessError::InvalidState);
        }
        record.snapshot.dispatches = record
            .snapshot
            .dispatches
            .checked_add(1)
            .ok_or(ProcessError::AccountingOverflow)?;
        record.snapshot.state = ProcessState::Running;
        Ok(())
    }

    /// Charge ticks spent inside one unprivileged execution boundary.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/non-running process or counter overflow.
    pub fn charge_cpu(&mut self, id: ProcessId, ticks: u64) -> Result<(), ProcessError> {
        let record = self.record_mut(id)?;
        if record.snapshot.state != ProcessState::Running {
            return Err(ProcessError::InvalidState);
        }
        record.snapshot.cpu_ticks = record
            .snapshot
            .cpu_ticks
            .checked_add(ticks)
            .ok_or(ProcessError::AccountingOverflow)?;
        Ok(())
    }

    /// Record a voluntary yield and return the process to ready state.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/non-running process or counter overflow.
    pub fn yielded(&mut self, id: ProcessId) -> Result<(), ProcessError> {
        let record = self.record_mut(id)?;
        if record.snapshot.state != ProcessState::Running {
            return Err(ProcessError::InvalidState);
        }
        record.snapshot.yields = record
            .snapshot
            .yields
            .checked_add(1)
            .ok_or(ProcessError::AccountingOverflow)?;
        record.snapshot.state = ProcessState::Ready;
        Ok(())
    }

    /// Record timer preemption and return the process to ready state.
    ///
    /// # Errors
    ///
    /// Rejects an unknown/non-running process or counter overflow.
    pub fn preempted(&mut self, id: ProcessId) -> Result<(), ProcessError> {
        let record = self.record_mut(id)?;
        if record.snapshot.state != ProcessState::Running {
            return Err(ProcessError::InvalidState);
        }
        record.snapshot.preemptions = record
            .snapshot
            .preemptions
            .checked_add(1)
            .ok_or(ProcessError::AccountingOverflow)?;
        record.snapshot.state = ProcessState::Ready;
        Ok(())
    }

    /// Retain a typed wait for the running process.
    ///
    /// # Errors
    ///
    /// Rejects an unknown or non-running process.
    pub fn blocked(&mut self, id: ProcessId) -> Result<(), ProcessError> {
        let record = self.record_mut(id)?;
        if record.snapshot.state != ProcessState::Running {
            return Err(ProcessError::InvalidState);
        }
        record.snapshot.state = ProcessState::Blocked;
        Ok(())
    }

    /// Publish completion of one retained typed wait.
    ///
    /// # Errors
    ///
    /// Rejects an unknown or non-blocked process.
    pub fn woke(&mut self, id: ProcessId) -> Result<(), ProcessError> {
        let record = self.record_mut(id)?;
        if record.snapshot.state != ProcessState::Blocked {
            return Err(ProcessError::InvalidState);
        }
        record.snapshot.state = ProcessState::Ready;
        Ok(())
    }

    /// Mark cancellation without granting process-control authority to observers.
    ///
    /// # Errors
    ///
    /// Rejects an unknown process.
    pub fn stopping(&mut self, id: ProcessId) -> Result<(), ProcessError> {
        let record = self.record_mut(id)?;
        record.snapshot.state = ProcessState::Stopping;
        Ok(())
    }

    /// Replace retained resource accounting after committed heap growth.
    ///
    /// # Errors
    ///
    /// Rejects an unknown process or zero resource counts.
    pub fn update_resources(
        &mut self,
        id: ProcessId,
        table_pages: u64,
        private_pages: u64,
        handles: u16,
    ) -> Result<(), ProcessError> {
        if table_pages == 0 || private_pages == 0 {
            return Err(ProcessError::InvalidState);
        }
        let record = self.record_mut(id)?;
        record.snapshot.table_pages = table_pages;
        record.snapshot.private_pages = private_pages;
        record.snapshot.handles = handles;
        Ok(())
    }

    /// Remove one process after scheduler reaping and authority revocation.
    ///
    /// # Errors
    ///
    /// Rejects an unknown process identity.
    pub fn remove(&mut self, id: ProcessId) -> Result<ProcessSnapshot, ProcessError> {
        let index = self
            .records
            .iter()
            .position(|record| record.snapshot.id == id)
            .ok_or(ProcessError::UnknownProcess)?;
        Ok(self.records.remove(index).snapshot)
    }

    /// Iterate over a stable borrow of current records in registration order.
    #[must_use]
    pub fn snapshots(&self) -> impl ExactSizeIterator<Item = ProcessSnapshot> + '_ {
        self.records.iter().map(|record| record.snapshot)
    }

    fn record_mut(&mut self, id: ProcessId) -> Result<&mut ProcessRecord, ProcessError> {
        self.records
            .iter_mut()
            .find(|record| record.snapshot.id == id)
            .ok_or(ProcessError::UnknownProcess)
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
    /// The native machine boundary reported an unrecoverable execution lease.
    ExecutionLeaseExpired,
    /// The command exceeded its bounded application service-call count.
    ///
    /// This is reserved for explicitly bounded internal IPC probes. Ordinary
    /// applications have no cumulative lifetime service-call ceiling.
    ServiceCallLimitExceeded,
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
    /// Suspended at an owned ABI boundary on one generation-checked wait.
    Blocked(WaitKey),
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
    preemptions: u32,
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

    /// Published wait identity while the task is blocked.
    #[must_use]
    pub const fn wait_key(self) -> Option<WaitKey> {
        match self.state {
            TaskState::Blocked(wait) => Some(wait),
            TaskState::Ready | TaskState::Running | TaskState::Exited | TaskState::Faulted => None,
        }
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

    /// Number of timer-driven timeslice preemptions.
    #[must_use]
    pub const fn preemptions(self) -> u32 {
        self.preemptions
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
    /// Timer-driven timeslice preemptions observed.
    pub preemptions: u32,
    /// Running tasks transitioned to a scheduler-visible blocked state.
    pub blocks: u32,
    /// Blocked tasks returned to readiness through a matching wait key.
    pub wakes: u32,
    /// Tasks currently retained in a blocked state.
    pub blocked_tasks: u16,
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

/// Bounded single-CPU round-robin scheduler policy.
///
/// The scheduler owns records and resource accounting, but not native context
/// switching. At most one record can be `Running`; an explicit yield, timer
/// preemption, block, exit, or contained fault returns it to scheduler control.
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
    total_preemptions: u32,
    total_blocks: u32,
    total_wakes: u32,
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
            total_preemptions: 0,
            total_blocks: 0,
            total_wakes: 0,
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
                preemptions: 0,
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

    /// Select one exact ready task after checking its required authority.
    ///
    /// Composition code uses exact dispatch when it already owns the native
    /// continuation associated with `id`. This preserves the scheduler's
    /// single-running-task invariant without requiring continuations to live
    /// inside scheduler records.
    ///
    /// # Errors
    ///
    /// Rejects dispatch while another task is running, an unknown identity, a
    /// task that is not ready, insufficient capability, or counter overflow.
    pub fn dispatch(&mut self, id: TaskId, required: Capabilities) -> Result<TaskId, TaskError> {
        if self.current.is_some() {
            return Err(TaskError::TaskAlreadyRunning);
        }
        let index = self
            .records
            .iter()
            .position(|record| record.snapshot.id == id)
            .ok_or(TaskError::UnknownTask)?;
        let snapshot = &mut self.records[index].snapshot;
        if snapshot.state != TaskState::Ready || !snapshot.capabilities.contains(required) {
            return Err(TaskError::InvalidState);
        }
        snapshot.dispatches = snapshot
            .dispatches
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        snapshot.state = TaskState::Running;
        self.current = Some(id);
        self.cursor = (index + 1) % self.records.len();
        Ok(id)
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

    /// Return a timer-preempted running task to the ready queue.
    ///
    /// # Errors
    ///
    /// Rejects an unknown, non-running, or non-current identity and checked
    /// counter overflow.
    pub fn preempt_current(&mut self, id: TaskId) -> Result<(), TaskError> {
        if self.current != Some(id) {
            return Err(TaskError::InvalidState);
        }
        let total_preemptions = self
            .total_preemptions
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        let record = self.record_mut(id)?;
        if record.snapshot.state != TaskState::Running {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.preemptions = record
            .snapshot
            .preemptions
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        record.snapshot.state = TaskState::Ready;
        self.total_preemptions = total_preemptions;
        self.current = None;
        Ok(())
    }

    /// Suspend the running isolated task on one published wait registration.
    ///
    /// The native context and pending call are owned by composition tables,
    /// never by a suspended Rust frame in this scheduler.
    ///
    /// # Errors
    ///
    /// Rejects a non-current, non-running, or non-isolated task and checked
    /// transition-counter overflow.
    pub fn block_current(&mut self, id: TaskId, wait: WaitKey) -> Result<(), TaskError> {
        if self.current != Some(id) {
            return Err(TaskError::InvalidState);
        }
        let total_blocks = self
            .total_blocks
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        let record = self.record_mut(id)?;
        if record.snapshot.state != TaskState::Running || record.snapshot.isolation.is_none() {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.state = TaskState::Blocked(wait);
        self.current = None;
        self.total_blocks = total_blocks;
        Ok(())
    }

    /// Return one blocked task to readiness through its exact wait identity.
    ///
    /// # Errors
    ///
    /// Rejects unknown, stale, duplicated, or mismatched wakes and checked
    /// transition-counter overflow.
    pub fn wake_blocked(&mut self, id: TaskId, wait: WaitKey) -> Result<(), TaskError> {
        let total_wakes = self
            .total_wakes
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        let record = self.record_mut(id)?;
        if record.snapshot.state != TaskState::Blocked(wait) {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.state = TaskState::Ready;
        self.total_wakes = total_wakes;
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

    /// Terminalize a blocked isolated task after its wait and pending call have
    /// been cancelled by composition-owned tables.
    ///
    /// # Errors
    ///
    /// Rejects a non-blocked or non-isolated task.
    pub fn cancel_blocked(&mut self, id: TaskId, status: u32) -> Result<(), TaskError> {
        let record = self.record_mut(id)?;
        if !matches!(record.snapshot.state, TaskState::Blocked(_))
            || record.snapshot.isolation.is_none()
        {
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

    /// Terminalize a blocked isolated task after a contained asynchronous fault.
    ///
    /// # Errors
    ///
    /// Rejects a non-blocked or non-isolated task and checked fault-accounting
    /// overflow. State is unchanged on every error.
    pub fn fault_blocked(&mut self, id: TaskId, fault: TaskFault) -> Result<(), TaskError> {
        let contained_faults = self
            .contained_faults
            .checked_add(1)
            .ok_or(TaskError::AccountingOverflow)?;
        let record = self.record_mut(id)?;
        if !matches!(record.snapshot.state, TaskState::Blocked(_))
            || record.snapshot.isolation.is_none()
        {
            return Err(TaskError::InvalidState);
        }
        record.snapshot.state = TaskState::Faulted;
        record.snapshot.exit_status = Some(128);
        record.snapshot.fault = Some(fault);
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
    /// Ready and blocked records are cancelled and running records exit with
    /// `rollback_status`. Already exited or faulted records retain their
    /// original outcome. Only after the record is terminal is `revoke` invoked
    /// with its terminal snapshot, and reaping occurs only if revocation succeeds.
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
            TaskState::Blocked(_) => self.cancel_blocked(id, rollback_status)?,
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
        let blocked_tasks = self
            .records
            .iter()
            .filter(|record| matches!(record.snapshot.state, TaskState::Blocked(_)))
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
            preemptions: self.total_preemptions,
            blocks: self.total_blocks,
            wakes: self.total_wakes,
            blocked_tasks: u16::try_from(blocked_tasks).unwrap_or(u16::MAX),
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
    use alloc::vec::Vec;

    use super::{
        Cancelled, Capabilities, CooperativeRuntime, IsolationResource, MAX_TASKS, MonotonicMillis,
        PendingCallSnapshot, PendingCallState, PendingCallTable, ProcessError, ProcessName,
        ProcessOrigin, ProcessRegistration, ProcessState, ProcessTable, Scheduler, StackResource,
        TaskError, TaskFault, TaskId, TaskSnapshot, TaskState, TeardownError, WaitObservation,
        WaitRegistration, WaitSpec, WaitTable, WakeInterest, WakeReason,
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
    fn timer_preemption_is_accounted_separately_from_cooperative_yield() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(2)?;
        let first = scheduler.spawn(Capabilities::SERVICE, stack(0)?)?;
        let second = scheduler.spawn(Capabilities::SERVICE, stack(1)?)?;

        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(first))
        );
        scheduler.preempt_current(first)?;
        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(second))
        );
        scheduler.yield_current(second)?;

        assert_eq!(scheduler.task(first)?.preemptions(), 1);
        assert_eq!(scheduler.task(first)?.yields(), 0);
        assert_eq!(scheduler.task(second)?.preemptions(), 0);
        assert_eq!(scheduler.task(second)?.yields(), 1);
        assert_eq!(scheduler.stats().preemptions, 1);
        assert_eq!(scheduler.stats().yields, 1);
        Ok(())
    }

    #[test]
    fn blocked_lifecycle_runs_other_ready_work_and_rejects_stale_wakes() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(2)?;
        let isolation = IsolationResource::new(0, 4, 6, 1)?;
        let blocked = scheduler.spawn_isolated(Capabilities::SERVICE, stack(0)?, isolation)?;
        let ready = scheduler.spawn(Capabilities::SERVICE, stack(1)?)?;
        let mut pending = PendingCallTable::new(1, 16).map_err(|_| TaskError::InvalidState)?;
        let operation = pending
            .begin(blocked, 1, 7, 3, b"sleep", 8)
            .map_err(|_| TaskError::InvalidState)?;
        let spec = WaitSpec::new(
            blocked,
            operation,
            None,
            WakeInterest::DEADLINE,
            Some(MonotonicMillis::from_millis(10)),
        )
        .map_err(|_| TaskError::InvalidState)?;
        let mut waits = WaitTable::new(1).map_err(|_| TaskError::InvalidState)?;
        let wait = match waits
            .register(
                spec,
                WaitObservation::Pending,
                MonotonicMillis::from_millis(0),
            )
            .map_err(|_| TaskError::InvalidState)?
        {
            WaitRegistration::Blocked(wait) => wait,
            WaitRegistration::Ready(_) => return Err(TaskError::InvalidState),
        };
        pending
            .bind_wait(operation, wait)
            .map_err(|_| TaskError::InvalidState)?;

        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(blocked))
        );
        scheduler.block_current(blocked, wait)?;
        assert_eq!(scheduler.task(blocked)?.wait_key(), Some(wait));
        assert_eq!(scheduler.stats().blocked_tasks, 1);
        assert_eq!(scheduler.stats().blocks, 1);
        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(ready))
        );
        scheduler.exit_current(ready, 0)?;

        let batch = waits
            .expire(MonotonicMillis::from_millis(10))
            .map_err(|_| TaskError::InvalidState)?;
        let completion = batch.iter().next().ok_or(TaskError::InvalidState)?;
        pending
            .resolve(completion)
            .map_err(|_| TaskError::InvalidState)?;
        scheduler.wake_blocked(completion.owner(), completion.key())?;
        assert_eq!(
            scheduler.wake_blocked(completion.owner(), completion.key()),
            Err(TaskError::InvalidState)
        );
        assert_eq!(
            pending.call(operation).map(PendingCallSnapshot::state),
            Ok(PendingCallState::Ready(WakeReason::Deadline))
        );
        assert_eq!(scheduler.stats().blocked_tasks, 0);
        assert_eq!(scheduler.stats().wakes, 1);
        assert_eq!(
            scheduler.dispatch_next(Capabilities::SERVICE),
            Ok(Some(blocked))
        );
        scheduler.exit_current(blocked, 0)?;
        Ok(())
    }

    #[test]
    fn blocked_teardown_cancels_wait_and_pending_call_before_reap()
    -> Result<(), TeardownError<&'static str>> {
        let mut scheduler = Scheduler::new(1)?;
        let isolation = IsolationResource::new(0, 4, 6, 1)?;
        let id = scheduler.spawn_isolated(Capabilities::SERVICE, stack(0)?, isolation)?;
        let mut pending = PendingCallTable::new(1, 16)
            .map_err(|_| TeardownError::Task(TaskError::InvalidState))?;
        let operation = pending
            .begin(id, 1, 7, 3, b"receive", 8)
            .map_err(|_| TeardownError::Task(TaskError::InvalidState))?;
        let spec = WaitSpec::new(
            id,
            operation,
            None,
            WakeInterest::DEADLINE,
            Some(MonotonicMillis::from_millis(10)),
        )
        .map_err(|_| TeardownError::Task(TaskError::InvalidState))?;
        let mut waits =
            WaitTable::new(1).map_err(|_| TeardownError::Task(TaskError::InvalidState))?;
        let wait = match waits
            .register(
                spec,
                WaitObservation::Pending,
                MonotonicMillis::from_millis(0),
            )
            .map_err(|_| TeardownError::Task(TaskError::InvalidState))?
        {
            WaitRegistration::Blocked(wait) => wait,
            WaitRegistration::Ready(_) => {
                return Err(TeardownError::Task(TaskError::InvalidState));
            }
        };
        pending
            .bind_wait(operation, wait)
            .map_err(|_| TeardownError::Task(TaskError::InvalidState))?;
        assert_eq!(scheduler.dispatch_next(Capabilities::SERVICE), Ok(Some(id)));
        scheduler.block_current(id, wait)?;

        let reaped = scheduler.terminate_revoke_and_reap(id, 9, |terminal| {
            assert_eq!(terminal.state(), TaskState::Exited);
            let batch = waits
                .cancel_owner(id, WakeReason::Revoked)
                .map_err(|_| "wait cancellation failed")?;
            for completion in batch.iter() {
                pending
                    .resolve(completion)
                    .map_err(|_| "pending resolution failed")?;
            }
            if pending
                .teardown_owner(id, WakeReason::Revoked)
                .map_err(|_| "pending teardown failed")?
                != 1
            {
                return Err("pending teardown count mismatch");
            }
            Ok(())
        })?;

        assert_eq!(reaped.id, id);
        assert_eq!(reaped.exit_status, 9);
        assert_eq!(waits.stats().live, 0);
        assert_eq!(pending.stats().live, 0);
        assert_eq!(pending.stats().retained_bytes, 0);
        assert_eq!(pending.stats().zeroized_bytes, 7);
        assert_eq!(scheduler.stats().live_records, 0);
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
    fn exact_dispatch_selects_the_owned_continuation() -> Result<(), TaskError> {
        let mut scheduler = Scheduler::new(3)?;
        let first = scheduler.spawn(Capabilities::SERVICE, stack(0)?)?;
        let second = scheduler.spawn(Capabilities::SERVICE, stack(1)?)?;

        assert_eq!(
            scheduler.dispatch(second, Capabilities::SERVICE),
            Ok(second)
        );
        scheduler.yield_current(second)?;
        assert_eq!(scheduler.task(first)?.dispatches(), 0);
        assert_eq!(scheduler.task(second)?.dispatches(), 1);
        assert_eq!(
            scheduler.dispatch(first, Capabilities::CONSOLE),
            Err(TaskError::InvalidState)
        );
        assert_eq!(scheduler.dispatch(first, Capabilities::SERVICE), Ok(first));
        assert_eq!(
            scheduler.dispatch(second, Capabilities::SERVICE),
            Err(TaskError::TaskAlreadyRunning)
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

    #[test]
    fn unified_process_table_tracks_all_origins_and_exact_accounting() -> Result<(), ProcessError> {
        let mut processes = ProcessTable::new(3)?;
        let foreground = processes.register(ProcessRegistration {
            task_id: TaskId(7),
            name: ProcessName::new("top")?,
            origin: ProcessOrigin::Foreground,
            started_millis: 100,
            table_pages: 9,
            private_pages: 12,
            handles: 6,
        })?;
        let background = processes.register(ProcessRegistration {
            task_id: TaskId(8),
            name: ProcessName::new("sleep")?,
            origin: ProcessOrigin::Background,
            started_millis: 101,
            table_pages: 7,
            private_pages: 8,
            handles: 5,
        })?;
        let service = processes.register(ProcessRegistration {
            task_id: TaskId(9),
            name: ProcessName::new("timesync")?,
            origin: ProcessOrigin::Service,
            started_millis: 102,
            table_pages: 8,
            private_pages: 10,
            handles: 7,
        })?;
        assert_eq!(foreground.get(), 1);
        assert_eq!(background.get(), 2);
        assert_eq!(service.get(), 3);

        processes.dispatch(foreground)?;
        processes.charge_cpu(foreground, 41)?;
        processes.preempted(foreground)?;
        processes.dispatch(foreground)?;
        processes.charge_cpu(foreground, 1)?;
        processes.yielded(foreground)?;
        processes.dispatch(background)?;
        processes.blocked(background)?;
        processes.update_resources(service, 11, 18, 9)?;

        let snapshots = processes.snapshots().collect::<Vec<_>>();
        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots[0].origin(), ProcessOrigin::Foreground);
        assert_eq!(snapshots[0].state(), ProcessState::Ready);
        assert_eq!(snapshots[0].cpu_ticks(), 42);
        assert_eq!(snapshots[0].dispatches(), 2);
        assert_eq!(snapshots[0].yields(), 1);
        assert_eq!(snapshots[0].preemptions(), 1);
        assert_eq!(snapshots[1].state(), ProcessState::Blocked);
        assert_eq!(snapshots[2].resident_pages(), 29);
        assert_eq!(snapshots[2].handles(), 9);

        processes.woke(background)?;
        processes.stopping(background)?;
        assert_eq!(
            processes
                .snapshots()
                .nth(1)
                .map(super::ProcessSnapshot::state),
            Some(ProcessState::Stopping)
        );
        assert_eq!(processes.remove(background)?.name().as_str(), "sleep");
        assert_eq!(processes.snapshots().len(), 2);
        Ok(())
    }

    #[test]
    fn process_table_rejects_stale_duplicate_and_excess_records() -> Result<(), ProcessError> {
        assert_eq!(
            ProcessTable::new(0).err(),
            Some(ProcessError::InvalidCapacity)
        );
        assert_eq!(ProcessName::new(""), Err(ProcessError::InvalidName));
        assert_eq!(
            ProcessName::new("123456789012345678901234567890123"),
            Err(ProcessError::InvalidName)
        );
        let mut processes = ProcessTable::new(1)?;
        let registration = ProcessRegistration {
            task_id: TaskId(1),
            name: ProcessName::new("ps")?,
            origin: ProcessOrigin::Foreground,
            started_millis: 1,
            table_pages: 1,
            private_pages: 1,
            handles: 1,
        };
        let id = processes.register(registration)?;
        assert_eq!(
            processes.register(registration),
            Err(ProcessError::CapacityExhausted)
        );
        assert_eq!(processes.woke(id), Err(ProcessError::InvalidState));
        processes.remove(id)?;
        assert_eq!(processes.dispatch(id), Err(ProcessError::UnknownProcess));
        let next = processes.register(registration)?;
        assert!(next.get() > id.get());
        Ok(())
    }
}

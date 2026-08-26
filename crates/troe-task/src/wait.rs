//! Bounded portable wait registrations and copied pending-call ownership.

use super::{MonotonicMillis, TaskId};
use alloc::vec::Vec;
use core::fmt;

/// Maximum number of simultaneously published wait registrations.
pub const MAX_WAIT_REGISTRATIONS: usize = 16;
/// Maximum number of simultaneously retained pending calls.
pub const MAX_PENDING_CALLS: usize = 16;
/// Maximum bytes copied into one pending request.
pub const MAX_PENDING_REQUEST_BYTES: usize = 4 * 1024;

/// Opaque slot-plus-generation identity for one published wait.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WaitKey {
    slot: u16,
    generation: u32,
}

impl WaitKey {
    /// Pool-local slot used only by diagnostics and tests.
    #[must_use]
    pub const fn slot(self) -> u16 {
        self.slot
    }

    /// Slot generation used only by diagnostics and tests.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Opaque slot-plus-generation identity for one copied pending call.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PendingOperationId {
    slot: u16,
    generation: u32,
}

impl PendingOperationId {
    /// Pool-local slot used only by diagnostics and tests.
    #[must_use]
    pub const fn slot(self) -> u16 {
        self.slot
    }

    /// Slot generation used only by diagnostics and tests.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Generation-checked resource identity observed by one wait registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitResource {
    identity: u64,
    generation: u32,
}

impl WaitResource {
    /// Construct a nonzero resource identity and generation.
    ///
    /// # Errors
    ///
    /// Rejects a zero identity or generation.
    pub const fn new(identity: u64, generation: u32) -> Result<Self, WaitError> {
        if identity == 0 || generation == 0 {
            return Err(WaitError::InvalidResource);
        }
        Ok(Self {
            identity,
            generation,
        })
    }

    /// Stable resource-local identity.
    #[must_use]
    pub const fn identity(self) -> u64 {
        self.identity
    }

    /// Resource generation captured by the registration.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Non-terminal conditions selected by one wait registration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WakeInterest(u8);

impl WakeInterest {
    /// No non-terminal condition.
    pub const NONE: Self = Self(0);
    /// Wake when the generation-checked resource becomes ready.
    pub const RESOURCE_READY: Self = Self(1 << 0);
    /// Wake when the boot-relative deadline is reached.
    pub const DEADLINE: Self = Self(1 << 1);

    /// Combine two closed condition sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every requested condition is present.
    #[must_use]
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
}

/// Exact reason a published or prospective wait became ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeReason {
    /// The observed resource has work for this waiter.
    ResourceReady,
    /// The boot-relative deadline was reached.
    Deadline,
    /// The active invocation was explicitly cancelled.
    Cancelled,
    /// The generation-checked resource was closed.
    Closed,
    /// Owner teardown revoked the pending authority.
    Revoked,
}

impl WakeReason {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Closed | Self::Revoked)
    }
}

/// Resource state observed in the same operation that may publish a wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitObservation {
    /// No ready or terminal condition is currently visible.
    Pending,
    /// The exact resource generation is already ready.
    ResourceReady,
    /// The exact resource generation is already closed.
    ResourceClosed,
    /// Cancellation is already visible.
    Cancelled,
    /// Owner revocation is already visible.
    OwnerRevoked,
}

/// Complete portable metadata required to publish one wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitSpec {
    owner: TaskId,
    operation: PendingOperationId,
    resource: Option<WaitResource>,
    interests: WakeInterest,
    deadline: Option<MonotonicMillis>,
}

impl WaitSpec {
    /// Validate a wait specification before observation or publication.
    ///
    /// # Errors
    ///
    /// A resource-ready interest requires a resource; a deadline interest
    /// requires a deadline; and at least one must be selected.
    pub const fn new(
        owner: TaskId,
        operation: PendingOperationId,
        resource: Option<WaitResource>,
        interests: WakeInterest,
        deadline: Option<MonotonicMillis>,
    ) -> Result<Self, WaitError> {
        if interests.0 == 0
            || (interests.contains(WakeInterest::RESOURCE_READY) && resource.is_none())
            || (interests.contains(WakeInterest::DEADLINE) && deadline.is_none())
        {
            return Err(WaitError::InvalidSpec);
        }
        Ok(Self {
            owner,
            operation,
            resource,
            interests,
            deadline,
        })
    }

    /// Task that owns the suspended operation.
    #[must_use]
    pub const fn owner(self) -> TaskId {
        self.owner
    }

    /// Pending operation completed by the wake.
    #[must_use]
    pub const fn operation(self) -> PendingOperationId {
        self.operation
    }

    /// Generation-checked observed resource, if any.
    #[must_use]
    pub const fn resource(self) -> Option<WaitResource> {
        self.resource
    }

    /// Closed set of selected non-terminal conditions.
    #[must_use]
    pub const fn interests(self) -> WakeInterest {
        self.interests
    }

    /// Optional boot-relative deadline.
    #[must_use]
    pub const fn deadline(self) -> Option<MonotonicMillis> {
        self.deadline
    }

    const fn accepts(self, reason: WakeReason) -> bool {
        match reason {
            WakeReason::ResourceReady => {
                self.resource.is_some() && self.interests.contains(WakeInterest::RESOURCE_READY)
            }
            WakeReason::Deadline => {
                self.deadline.is_some() && self.interests.contains(WakeInterest::DEADLINE)
            }
            WakeReason::Cancelled | WakeReason::Revoked => true,
            WakeReason::Closed => self.resource.is_some(),
        }
    }
}

/// Result of the lost-wakeup-safe observe-or-publish operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitRegistration {
    /// A condition was observed and no registration was published.
    Ready(WakeReason),
    /// No condition was visible and this generation-checked wait was published.
    Blocked(WaitKey),
}

/// One exactly-once completion removed from the wait table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitCompletion {
    key: WaitKey,
    owner: TaskId,
    operation: PendingOperationId,
    reason: WakeReason,
}

impl WaitCompletion {
    /// Consumed wait identity.
    #[must_use]
    pub const fn key(self) -> WaitKey {
        self.key
    }

    /// Task that owns the suspended operation.
    #[must_use]
    pub const fn owner(self) -> TaskId {
        self.owner
    }

    /// Pending operation completed by this wake.
    #[must_use]
    pub const fn operation(self) -> PendingOperationId {
        self.operation
    }

    /// Exact reason selected by the first successful consumer.
    #[must_use]
    pub const fn reason(self) -> WakeReason {
        self.reason
    }
}

/// Fixed-capacity collection returned by multi-wait wake operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakeBatch {
    completions: [Option<WaitCompletion>; MAX_WAIT_REGISTRATIONS],
    len: usize,
}

impl WakeBatch {
    const fn new() -> Self {
        Self {
            completions: [None; MAX_WAIT_REGISTRATIONS],
            len: 0,
        }
    }

    fn push(&mut self, completion: WaitCompletion) {
        self.completions[self.len] = Some(completion);
        self.len += 1;
    }

    /// Number of exactly-once completions in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no registration was completed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate over copied completion records in slot order.
    pub fn iter(&self) -> impl Iterator<Item = WaitCompletion> + '_ {
        self.completions[..self.len].iter().flatten().copied()
    }
}

/// Wait-table resource and transition failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitError {
    /// Configured capacity is zero or exceeds [`MAX_WAIT_REGISTRATIONS`].
    InvalidCapacity,
    /// Metadata reservation failed during table construction.
    MetadataExhausted,
    /// No reusable registration slot remains.
    CapacityExhausted,
    /// A zero resource identity or generation was supplied.
    InvalidResource,
    /// Interests, resource, and deadline do not form a usable wait.
    InvalidSpec,
    /// This task already owns a published registration.
    OwnerAlreadyWaiting,
    /// This pending operation already owns a published registration.
    OperationAlreadyWaiting,
    /// A stale, consumed, or retired wait key was supplied.
    StaleWait,
    /// The wake reason was not selected or is invalid for this registration.
    UnexpectedWake,
    /// Checked event accounting overflowed.
    AccountingOverflow,
}

impl fmt::Display for WaitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("wait capacity is invalid"),
            Self::MetadataExhausted => formatter.write_str("wait metadata allocation failed"),
            Self::CapacityExhausted => formatter.write_str("wait registration capacity exhausted"),
            Self::InvalidResource => formatter.write_str("wait resource identity is invalid"),
            Self::InvalidSpec => formatter.write_str("wait specification is invalid"),
            Self::OwnerAlreadyWaiting => formatter.write_str("task already has a wait"),
            Self::OperationAlreadyWaiting => formatter.write_str("operation already has a wait"),
            Self::StaleWait => formatter.write_str("wait identity is stale"),
            Self::UnexpectedWake => formatter.write_str("wake reason is not registered"),
            Self::AccountingOverflow => formatter.write_str("wait accounting overflowed"),
        }
    }
}

/// Aggregate wait publication and completion accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitStats {
    /// Currently published registrations.
    pub live: u16,
    /// Maximum simultaneously published registrations.
    pub high_water: u16,
    /// Published registrations completed exactly once.
    pub wakes: u64,
    /// Conditions consumed before a registration was published.
    pub immediate_wakes: u64,
    /// Resource-ready completions.
    pub resource_wakes: u64,
    /// Deadline completions.
    pub timeouts: u64,
    /// Explicit cancellation completions.
    pub cancellations: u64,
    /// Resource-close completions.
    pub closes: u64,
    /// Owner-revocation completions.
    pub revocations: u64,
    /// Stale key or resource-generation wake attempts.
    pub stale_wakes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaitRecord {
    key: WaitKey,
    spec: WaitSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaitSlot {
    generation: u32,
    retired: bool,
    record: Option<WaitRecord>,
}

/// Preallocated single-CPU wait-registration table.
///
/// Construction allocates the complete slot vector. Registration and wake do
/// not allocate, and no raw kernel or user pointer is retained.
#[derive(Debug)]
pub struct WaitTable {
    slots: Vec<WaitSlot>,
    stats: WaitStats,
}

impl WaitTable {
    /// Construct a table with an immutable registration bound.
    ///
    /// # Errors
    ///
    /// Rejects invalid capacity or metadata allocation failure.
    pub fn new(capacity: usize) -> Result<Self, WaitError> {
        if capacity == 0 || capacity > MAX_WAIT_REGISTRATIONS {
            return Err(WaitError::InvalidCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| WaitError::MetadataExhausted)?;
        for _ in 0..capacity {
            slots.push(WaitSlot {
                generation: 1,
                retired: false,
                record: None,
            });
        }
        Ok(Self {
            slots,
            stats: WaitStats::default(),
        })
    }

    /// Observe the current condition and publish only if it remains pending.
    ///
    /// This is the portable lost-wakeup boundary: the caller supplies the
    /// observation made while it has exclusive access to the resource state
    /// and wait table. An already-ready, closed, cancelled, revoked, or expired
    /// wait returns immediately without consuming a slot.
    ///
    /// # Errors
    ///
    /// Rejects duplicate owners or operations, incompatible observations,
    /// exhausted capacity, and checked accounting overflow.
    pub fn register(
        &mut self,
        spec: WaitSpec,
        observation: WaitObservation,
        now: MonotonicMillis,
    ) -> Result<WaitRegistration, WaitError> {
        if self.slots.iter().any(|slot| {
            slot.record
                .is_some_and(|record| record.spec.owner == spec.owner)
        }) {
            return Err(WaitError::OwnerAlreadyWaiting);
        }
        if self.slots.iter().any(|slot| {
            slot.record
                .is_some_and(|record| record.spec.operation == spec.operation)
        }) {
            return Err(WaitError::OperationAlreadyWaiting);
        }
        let observed = match observation {
            WaitObservation::Pending => spec
                .deadline
                .filter(|deadline| *deadline <= now)
                .map(|_| WakeReason::Deadline),
            WaitObservation::ResourceReady => Some(WakeReason::ResourceReady),
            WaitObservation::ResourceClosed => Some(WakeReason::Closed),
            WaitObservation::Cancelled => Some(WakeReason::Cancelled),
            WaitObservation::OwnerRevoked => Some(WakeReason::Revoked),
        };
        if let Some(reason) = observed {
            if !spec.accepts(reason) {
                return Err(WaitError::UnexpectedWake);
            }
            self.record_reason(reason, true)?;
            return Ok(WaitRegistration::Ready(reason));
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.record.is_none() && !slot.retired)
            .ok_or(WaitError::CapacityExhausted)?;
        let key = WaitKey {
            slot: u16::try_from(index).map_err(|_| WaitError::AccountingOverflow)?,
            generation: self.slots[index].generation,
        };
        let live = self
            .stats
            .live
            .checked_add(1)
            .ok_or(WaitError::AccountingOverflow)?;
        self.slots[index].record = Some(WaitRecord { key, spec });
        self.stats.live = live;
        self.stats.high_water = self.stats.high_water.max(live);
        Ok(WaitRegistration::Blocked(key))
    }

    /// Complete one exact registration with the first admitted reason.
    ///
    /// # Errors
    ///
    /// Rejects stale keys and reasons not selected by the registration.
    pub fn wake(&mut self, key: WaitKey, reason: WakeReason) -> Result<WaitCompletion, WaitError> {
        let index = self.validate_key(key)?;
        let record = self.slots[index].record.ok_or(WaitError::StaleWait)?;
        if !record.spec.accepts(reason) {
            return Err(WaitError::UnexpectedWake);
        }
        self.resolve_index(index, reason)
    }

    /// Wake every waiter for one exact resource generation.
    ///
    /// A different generation never wakes the retained operation. If the
    /// identity matches but the generation is stale, the attempt is counted.
    ///
    /// # Errors
    ///
    /// Only resource-ready and resource-closed reasons are accepted.
    pub fn wake_resource(
        &mut self,
        resource: WaitResource,
        reason: WakeReason,
    ) -> Result<WakeBatch, WaitError> {
        if !matches!(reason, WakeReason::ResourceReady | WakeReason::Closed) {
            return Err(WaitError::UnexpectedWake);
        }
        let stale_generation = self.slots.iter().any(|slot| {
            slot.record.is_some_and(|record| {
                record.spec.resource.is_some_and(|retained| {
                    retained.identity == resource.identity
                        && retained.generation != resource.generation
                })
            })
        });
        let mut indices = [None; MAX_WAIT_REGISTRATIONS];
        let mut count = 0;
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.record.is_some_and(|record| {
                record.spec.resource == Some(resource) && record.spec.accepts(reason)
            }) {
                indices[count] = Some(index);
                count += 1;
            }
        }
        if count == 0 && stale_generation {
            self.stats.stale_wakes = self
                .stats
                .stale_wakes
                .checked_add(1)
                .ok_or(WaitError::AccountingOverflow)?;
        }
        let mut batch = WakeBatch::new();
        for index in indices[..count].iter().flatten().copied() {
            batch.push(self.resolve_index(index, reason)?);
        }
        Ok(batch)
    }

    /// Complete every published deadline at or before `now`.
    ///
    /// # Errors
    ///
    /// Returns checked accounting failures without publishing new waits.
    pub fn expire(&mut self, now: MonotonicMillis) -> Result<WakeBatch, WaitError> {
        let mut indices = [None; MAX_WAIT_REGISTRATIONS];
        let mut count = 0;
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.record.is_some_and(|record| {
                record.spec.interests.contains(WakeInterest::DEADLINE)
                    && record.spec.deadline.is_some_and(|deadline| deadline <= now)
            }) {
                indices[count] = Some(index);
                count += 1;
            }
        }
        let mut batch = WakeBatch::new();
        for index in indices[..count].iter().flatten().copied() {
            batch.push(self.resolve_index(index, WakeReason::Deadline)?);
        }
        Ok(batch)
    }

    /// Complete the wait owned by one pending operation, if published.
    ///
    /// # Errors
    ///
    /// Only cancellation, close, or revocation may force an operation wake.
    pub fn cancel_operation(
        &mut self,
        operation: PendingOperationId,
        reason: WakeReason,
    ) -> Result<Option<WaitCompletion>, WaitError> {
        if !reason.is_terminal() {
            return Err(WaitError::UnexpectedWake);
        }
        let Some(index) = self.slots.iter().position(|slot| {
            slot.record
                .is_some_and(|record| record.spec.operation == operation)
        }) else {
            return Ok(None);
        };
        self.resolve_index(index, reason).map(Some)
    }

    /// Complete every wait owned by one task during cancellation or teardown.
    ///
    /// # Errors
    ///
    /// Only cancellation or revocation is valid for an owner-wide wake.
    pub fn cancel_owner(
        &mut self,
        owner: TaskId,
        reason: WakeReason,
    ) -> Result<WakeBatch, WaitError> {
        if !matches!(reason, WakeReason::Cancelled | WakeReason::Revoked) {
            return Err(WaitError::UnexpectedWake);
        }
        let mut batch = WakeBatch::new();
        if let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.record.is_some_and(|record| record.spec.owner == owner))
        {
            batch.push(self.resolve_index(index, reason)?);
        }
        Ok(batch)
    }

    /// Snapshot wait accounting.
    #[must_use]
    pub const fn stats(&self) -> WaitStats {
        self.stats
    }

    fn validate_key(&mut self, key: WaitKey) -> Result<usize, WaitError> {
        let index = usize::from(key.slot);
        let valid = self.slots.get(index).is_some_and(|slot| {
            slot.generation == key.generation && slot.record.is_some_and(|record| record.key == key)
        });
        if !valid {
            self.stats.stale_wakes = self
                .stats
                .stale_wakes
                .checked_add(1)
                .ok_or(WaitError::AccountingOverflow)?;
            return Err(WaitError::StaleWait);
        }
        Ok(index)
    }

    fn resolve_index(
        &mut self,
        index: usize,
        reason: WakeReason,
    ) -> Result<WaitCompletion, WaitError> {
        let record = self.slots[index].record.ok_or(WaitError::StaleWait)?;
        let live = self
            .stats
            .live
            .checked_sub(1)
            .ok_or(WaitError::AccountingOverflow)?;
        self.record_reason(reason, false)?;
        self.slots[index].record = None;
        match self.slots[index].generation.checked_add(1) {
            Some(generation) => self.slots[index].generation = generation,
            None => self.slots[index].retired = true,
        }
        self.stats.live = live;
        Ok(WaitCompletion {
            key: record.key,
            owner: record.spec.owner,
            operation: record.spec.operation,
            reason,
        })
    }

    fn record_reason(&mut self, reason: WakeReason, immediate: bool) -> Result<(), WaitError> {
        let immediate_wakes = if immediate {
            self.stats
                .immediate_wakes
                .checked_add(1)
                .ok_or(WaitError::AccountingOverflow)?
        } else {
            self.stats.immediate_wakes
        };
        let wakes = if immediate {
            self.stats.wakes
        } else {
            self.stats
                .wakes
                .checked_add(1)
                .ok_or(WaitError::AccountingOverflow)?
        };
        let reason_counter = match reason {
            WakeReason::ResourceReady => self.stats.resource_wakes,
            WakeReason::Deadline => self.stats.timeouts,
            WakeReason::Cancelled => self.stats.cancellations,
            WakeReason::Closed => self.stats.closes,
            WakeReason::Revoked => self.stats.revocations,
        }
        .checked_add(1)
        .ok_or(WaitError::AccountingOverflow)?;
        self.stats.immediate_wakes = immediate_wakes;
        self.stats.wakes = wakes;
        match reason {
            WakeReason::ResourceReady => self.stats.resource_wakes = reason_counter,
            WakeReason::Deadline => self.stats.timeouts = reason_counter,
            WakeReason::Cancelled => self.stats.cancellations = reason_counter,
            WakeReason::Closed => self.stats.closes = reason_counter,
            WakeReason::Revoked => self.stats.revocations = reason_counter,
        }
        Ok(())
    }
}

/// Portable state of one copied pending call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingCallState {
    /// Copied but not yet registered on a wait.
    New,
    /// Bound to one published wait registration.
    Waiting(WaitKey),
    /// Completed exactly once and ready for reply or terminal disposal.
    Ready(WakeReason),
}

/// Read-only metadata for one copied pending call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingCallSnapshot {
    id: PendingOperationId,
    owner: TaskId,
    request_id: u64,
    handle: u64,
    opcode: u16,
    request_bytes: u16,
    reply_capacity: u16,
    state: PendingCallState,
}

impl PendingCallSnapshot {
    /// Generation-checked pending operation identity.
    #[must_use]
    pub const fn id(self) -> PendingOperationId {
        self.id
    }

    /// Task that owns the suspended call.
    #[must_use]
    pub const fn owner(self) -> TaskId {
        self.owner
    }

    /// Monotonic dispatcher request identity.
    #[must_use]
    pub const fn request_id(self) -> u64 {
        self.request_id
    }

    /// Opaque service handle supplied by the task.
    #[must_use]
    pub const fn handle(self) -> u64 {
        self.handle
    }

    /// Service-defined operation number.
    #[must_use]
    pub const fn opcode(self) -> u16 {
        self.opcode
    }

    /// Copied request payload length.
    #[must_use]
    pub const fn request_bytes(self) -> usize {
        self.request_bytes as usize
    }

    /// Maximum reply bytes accepted by the suspended caller.
    #[must_use]
    pub const fn reply_capacity(self) -> usize {
        self.reply_capacity as usize
    }

    /// Current portable pending-call state.
    #[must_use]
    pub const fn state(self) -> PendingCallState {
        self.state
    }
}

/// Pending-call capacity, identity, and transition failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingCallError {
    /// Configured call or byte capacity is invalid.
    InvalidCapacity,
    /// Complete slot allocation failed during construction.
    MetadataExhausted,
    /// No reusable pending-call slot remains.
    CapacityExhausted,
    /// Retaining this request would exceed the fixed byte ceiling.
    ByteCapacityExhausted,
    /// Request or reply capacity exceeds [`MAX_PENDING_REQUEST_BYTES`].
    MessageTooLarge,
    /// Request identities must be nonzero and strictly increasing.
    RequestIdentityNotMonotonic,
    /// This task already owns a pending call.
    OwnerAlreadyPending,
    /// A stale, completed, or retired pending operation was supplied.
    StaleOperation,
    /// The requested transition does not match the pending-call state.
    InvalidState,
    /// A wake completion belongs to another owner, operation, or wait.
    MismatchedWake,
    /// Checked byte or event accounting overflowed.
    AccountingOverflow,
}

impl fmt::Display for PendingCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("pending-call capacity is invalid"),
            Self::MetadataExhausted => {
                formatter.write_str("pending-call metadata allocation failed")
            }
            Self::CapacityExhausted => formatter.write_str("pending-call capacity exhausted"),
            Self::ByteCapacityExhausted => {
                formatter.write_str("pending-call retained-byte capacity exhausted")
            }
            Self::MessageTooLarge => formatter.write_str("pending-call message is too large"),
            Self::RequestIdentityNotMonotonic => {
                formatter.write_str("pending-call request identity is not monotonic")
            }
            Self::OwnerAlreadyPending => formatter.write_str("task already has a pending call"),
            Self::StaleOperation => formatter.write_str("pending-call identity is stale"),
            Self::InvalidState => formatter.write_str("pending-call transition is invalid"),
            Self::MismatchedWake => formatter.write_str("pending-call wake does not match"),
            Self::AccountingOverflow => formatter.write_str("pending-call accounting overflowed"),
        }
    }
}

/// Aggregate copied pending-call ownership accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PendingCallStats {
    /// Currently retained pending calls.
    pub live: u16,
    /// Maximum simultaneously retained calls.
    pub high_water: u16,
    /// Currently retained copied request bytes.
    pub retained_bytes: u32,
    /// Maximum simultaneously retained request bytes.
    pub retained_bytes_high_water: u32,
    /// Calls completed or terminally disposed exactly once.
    pub completed: u64,
    /// Calls disposed for cancellation, close, or revocation.
    pub terminal_completions: u64,
    /// Request bytes explicitly zeroed before slot reuse.
    pub zeroized_bytes: u64,
}

#[derive(Debug)]
struct PendingSlot {
    generation: u32,
    retired: bool,
    record: Option<PendingCallSnapshot>,
    request: [u8; MAX_PENDING_REQUEST_BYTES],
}

impl PendingSlot {
    const fn empty() -> Self {
        Self {
            generation: 1,
            retired: false,
            record: None,
            request: [0; MAX_PENDING_REQUEST_BYTES],
        }
    }
}

/// Preallocated owner of copied requests awaiting deferred completion.
///
/// All slot buffers are allocated by [`Self::new`]. Beginning, binding,
/// resolving, finishing, and tearing down calls perform no dynamic allocation.
#[derive(Debug)]
pub struct PendingCallTable {
    slots: Vec<PendingSlot>,
    retained_byte_capacity: u32,
    last_request_id: u64,
    stats: PendingCallStats,
}

impl PendingCallTable {
    /// Construct a fixed call table and system-wide retained-byte ceiling.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive call capacity, an impossible byte ceiling,
    /// or allocation failure while preallocating all slot buffers.
    pub fn new(capacity: usize, retained_byte_capacity: usize) -> Result<Self, PendingCallError> {
        let maximum_bytes = capacity
            .checked_mul(MAX_PENDING_REQUEST_BYTES)
            .ok_or(PendingCallError::InvalidCapacity)?;
        if capacity == 0
            || capacity > MAX_PENDING_CALLS
            || retained_byte_capacity > maximum_bytes
            || retained_byte_capacity > u32::MAX as usize
        {
            return Err(PendingCallError::InvalidCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| PendingCallError::MetadataExhausted)?;
        for _ in 0..capacity {
            slots.push(PendingSlot::empty());
        }
        Ok(Self {
            slots,
            retained_byte_capacity: u32::try_from(retained_byte_capacity)
                .map_err(|_| PendingCallError::InvalidCapacity)?,
            last_request_id: 0,
            stats: PendingCallStats::default(),
        })
    }

    /// Copy and retain one complete request without publishing a wait.
    ///
    /// # Errors
    ///
    /// Rejects capacity, byte-budget, message-size, owner, identity-order, and
    /// checked accounting violations without consuming the request identity.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &mut self,
        owner: TaskId,
        request_id: u64,
        handle: u64,
        opcode: u16,
        request: &[u8],
        reply_capacity: usize,
    ) -> Result<PendingOperationId, PendingCallError> {
        if request.len() > MAX_PENDING_REQUEST_BYTES || reply_capacity > MAX_PENDING_REQUEST_BYTES {
            return Err(PendingCallError::MessageTooLarge);
        }
        if request_id == 0 || request_id <= self.last_request_id {
            return Err(PendingCallError::RequestIdentityNotMonotonic);
        }
        if self
            .slots
            .iter()
            .any(|slot| slot.record.is_some_and(|record| record.owner == owner))
        {
            return Err(PendingCallError::OwnerAlreadyPending);
        }
        let request_bytes =
            u32::try_from(request.len()).map_err(|_| PendingCallError::AccountingOverflow)?;
        let retained_bytes = self
            .stats
            .retained_bytes
            .checked_add(request_bytes)
            .ok_or(PendingCallError::AccountingOverflow)?;
        if retained_bytes > self.retained_byte_capacity {
            return Err(PendingCallError::ByteCapacityExhausted);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.record.is_none() && !slot.retired)
            .ok_or(PendingCallError::CapacityExhausted)?;
        let live = self
            .stats
            .live
            .checked_add(1)
            .ok_or(PendingCallError::AccountingOverflow)?;
        let id = PendingOperationId {
            slot: u16::try_from(index).map_err(|_| PendingCallError::AccountingOverflow)?,
            generation: self.slots[index].generation,
        };
        self.slots[index].request[..request.len()].copy_from_slice(request);
        self.slots[index].record = Some(PendingCallSnapshot {
            id,
            owner,
            request_id,
            handle,
            opcode,
            request_bytes: u16::try_from(request.len())
                .map_err(|_| PendingCallError::AccountingOverflow)?,
            reply_capacity: u16::try_from(reply_capacity)
                .map_err(|_| PendingCallError::AccountingOverflow)?,
            state: PendingCallState::New,
        });
        self.last_request_id = request_id;
        self.stats.live = live;
        self.stats.high_water = self.stats.high_water.max(live);
        self.stats.retained_bytes = retained_bytes;
        self.stats.retained_bytes_high_water =
            self.stats.retained_bytes_high_water.max(retained_bytes);
        Ok(id)
    }

    /// Bind a new pending call to its published wait identity.
    ///
    /// # Errors
    ///
    /// Rejects stale operations or double/late binding.
    pub fn bind_wait(
        &mut self,
        operation: PendingOperationId,
        wait: WaitKey,
    ) -> Result<(), PendingCallError> {
        let record = self.record_mut(operation)?;
        if record.state != PendingCallState::New {
            return Err(PendingCallError::InvalidState);
        }
        record.state = PendingCallState::Waiting(wait);
        Ok(())
    }

    /// Complete a call that became ready before wait publication.
    ///
    /// # Errors
    ///
    /// Rejects stale operations or a call already bound or completed.
    pub fn mark_ready(
        &mut self,
        operation: PendingOperationId,
        reason: WakeReason,
    ) -> Result<(), PendingCallError> {
        let record = self.record_mut(operation)?;
        if record.state != PendingCallState::New {
            return Err(PendingCallError::InvalidState);
        }
        record.state = PendingCallState::Ready(reason);
        Ok(())
    }

    /// Apply one exactly-once wait completion to its matching pending call.
    ///
    /// # Errors
    ///
    /// Rejects stale operations and owner, operation, or wait mismatches.
    pub fn resolve(&mut self, completion: WaitCompletion) -> Result<(), PendingCallError> {
        let record = self.record_mut(completion.operation)?;
        if record.owner != completion.owner
            || record.state != PendingCallState::Waiting(completion.key)
        {
            return Err(PendingCallError::MismatchedWake);
        }
        record.state = PendingCallState::Ready(completion.reason);
        Ok(())
    }

    /// Snapshot one retained operation.
    ///
    /// # Errors
    ///
    /// Rejects a stale, completed, or retired identity.
    pub fn call(
        &self,
        operation: PendingOperationId,
    ) -> Result<PendingCallSnapshot, PendingCallError> {
        self.record(operation)
    }

    /// Borrow the immutable copied request owned by one live operation.
    ///
    /// # Errors
    ///
    /// Rejects a stale, completed, or retired identity.
    pub fn request(&self, operation: PendingOperationId) -> Result<&[u8], PendingCallError> {
        let index = self.validate_operation(operation)?;
        let record = self.slots[index]
            .record
            .ok_or(PendingCallError::StaleOperation)?;
        Ok(&self.slots[index].request[..record.request_bytes()])
    }

    /// Remove one ready operation and zero its copied request before reuse.
    ///
    /// # Errors
    ///
    /// Rejects stale or non-ready operations and accounting overflow.
    pub fn finish(
        &mut self,
        operation: PendingOperationId,
    ) -> Result<PendingCallSnapshot, PendingCallError> {
        let index = self.validate_operation(operation)?;
        let record = self.slots[index]
            .record
            .ok_or(PendingCallError::StaleOperation)?;
        let PendingCallState::Ready(reason) = record.state else {
            return Err(PendingCallError::InvalidState);
        };
        self.release_index(index, record, reason.is_terminal())?;
        Ok(record)
    }

    /// Terminally dispose every operation owned by a task during teardown.
    ///
    /// Calls are removed and their copied requests are zeroed. The caller must
    /// first consume matching wait registrations so no published wait retains
    /// an operation identity after this method returns.
    ///
    /// # Errors
    ///
    /// Only cancellation, close, or revocation is a terminal teardown reason.
    pub fn teardown_owner(
        &mut self,
        owner: TaskId,
        reason: WakeReason,
    ) -> Result<u16, PendingCallError> {
        if !reason.is_terminal() {
            return Err(PendingCallError::InvalidState);
        }
        let mut matching = 0_u16;
        let mut matching_bytes = 0_u32;
        for slot in &self.slots {
            if let Some(record) = slot.record.filter(|record| record.owner == owner) {
                matching = matching
                    .checked_add(1)
                    .ok_or(PendingCallError::AccountingOverflow)?;
                matching_bytes = matching_bytes
                    .checked_add(u32::from(record.request_bytes))
                    .ok_or(PendingCallError::AccountingOverflow)?;
            }
        }
        self.stats
            .live
            .checked_sub(matching)
            .ok_or(PendingCallError::AccountingOverflow)?;
        self.stats
            .retained_bytes
            .checked_sub(matching_bytes)
            .ok_or(PendingCallError::AccountingOverflow)?;
        self.stats
            .completed
            .checked_add(u64::from(matching))
            .ok_or(PendingCallError::AccountingOverflow)?;
        self.stats
            .terminal_completions
            .checked_add(u64::from(matching))
            .ok_or(PendingCallError::AccountingOverflow)?;
        self.stats
            .zeroized_bytes
            .checked_add(u64::from(matching_bytes))
            .ok_or(PendingCallError::AccountingOverflow)?;
        for index in 0..self.slots.len() {
            let Some(mut record) = self.slots[index].record else {
                continue;
            };
            if record.owner != owner {
                continue;
            }
            record.state = PendingCallState::Ready(reason);
            self.release_index(index, record, true)?;
        }
        Ok(matching)
    }

    /// Snapshot retained-call and zeroization accounting.
    #[must_use]
    pub const fn stats(&self) -> PendingCallStats {
        self.stats
    }

    fn validate_operation(&self, operation: PendingOperationId) -> Result<usize, PendingCallError> {
        let index = usize::from(operation.slot);
        let valid = self.slots.get(index).is_some_and(|slot| {
            slot.generation == operation.generation
                && slot.record.is_some_and(|record| record.id == operation)
        });
        valid
            .then_some(index)
            .ok_or(PendingCallError::StaleOperation)
    }

    fn record(
        &self,
        operation: PendingOperationId,
    ) -> Result<PendingCallSnapshot, PendingCallError> {
        let index = self.validate_operation(operation)?;
        self.slots[index]
            .record
            .ok_or(PendingCallError::StaleOperation)
    }

    fn record_mut(
        &mut self,
        operation: PendingOperationId,
    ) -> Result<&mut PendingCallSnapshot, PendingCallError> {
        let index = self.validate_operation(operation)?;
        self.slots[index]
            .record
            .as_mut()
            .ok_or(PendingCallError::StaleOperation)
    }

    fn release_index(
        &mut self,
        index: usize,
        record: PendingCallSnapshot,
        terminal: bool,
    ) -> Result<(), PendingCallError> {
        let request_bytes = u32::from(record.request_bytes);
        let live = self
            .stats
            .live
            .checked_sub(1)
            .ok_or(PendingCallError::AccountingOverflow)?;
        let retained_bytes = self
            .stats
            .retained_bytes
            .checked_sub(request_bytes)
            .ok_or(PendingCallError::AccountingOverflow)?;
        let completed = self
            .stats
            .completed
            .checked_add(1)
            .ok_or(PendingCallError::AccountingOverflow)?;
        let terminal_completions = if terminal {
            self.stats
                .terminal_completions
                .checked_add(1)
                .ok_or(PendingCallError::AccountingOverflow)?
        } else {
            self.stats.terminal_completions
        };
        let zeroized_bytes = self
            .stats
            .zeroized_bytes
            .checked_add(u64::from(request_bytes))
            .ok_or(PendingCallError::AccountingOverflow)?;
        self.slots[index].request[..record.request_bytes()].fill(0);
        self.slots[index].record = None;
        match self.slots[index].generation.checked_add(1) {
            Some(generation) => self.slots[index].generation = generation,
            None => self.slots[index].retired = true,
        }
        self.stats.live = live;
        self.stats.retained_bytes = retained_bytes;
        self.stats.completed = completed;
        self.stats.terminal_completions = terminal_completions;
        self.stats.zeroized_bytes = zeroized_bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{Capabilities, Scheduler, StackResource};

    fn task(slot: u8) -> TaskId {
        let capacity = usize::from(slot) + 1;
        let Ok(mut scheduler) = Scheduler::new(capacity) else {
            std::process::abort()
        };
        let mut selected = None;
        for owned_slot in 0..=slot {
            let Ok(stack) = StackResource::new(owned_slot, 1) else {
                std::process::abort()
            };
            selected = match scheduler.spawn(Capabilities::NONE, stack) {
                Ok(task) => Some(task),
                Err(_) => std::process::abort(),
            };
        }
        selected.unwrap_or_else(|| std::process::abort())
    }

    fn pending(
        table: &mut PendingCallTable,
        owner: TaskId,
        request_id: u64,
        request: &[u8],
    ) -> PendingOperationId {
        match table.begin(owner, request_id, 9, 3, request, 128) {
            Ok(operation) => operation,
            Err(_) => std::process::abort(),
        }
    }

    fn timer_spec(owner: TaskId, operation: PendingOperationId, deadline: u64) -> WaitSpec {
        match WaitSpec::new(
            owner,
            operation,
            None,
            WakeInterest::DEADLINE,
            Some(MonotonicMillis::from_millis(deadline)),
        ) {
            Ok(spec) => spec,
            Err(_) => std::process::abort(),
        }
    }

    fn resource_spec(
        owner: TaskId,
        operation: PendingOperationId,
        resource: WaitResource,
    ) -> WaitSpec {
        match WaitSpec::new(
            owner,
            operation,
            Some(resource),
            WakeInterest::RESOURCE_READY.union(WakeInterest::DEADLINE),
            Some(MonotonicMillis::from_millis(50)),
        ) {
            Ok(spec) => spec,
            Err(_) => std::process::abort(),
        }
    }

    #[test]
    fn observe_or_publish_consumes_ready_and_deadline_without_a_slot() {
        let owner = task(0);
        let Ok(mut pending_calls) = PendingCallTable::new(2, 32) else {
            std::process::abort()
        };
        let first = pending(&mut pending_calls, owner, 1, b"one");
        let Ok(mut waits) = WaitTable::new(1) else {
            std::process::abort()
        };
        assert_eq!(
            waits.register(
                timer_spec(owner, first, 10),
                WaitObservation::Pending,
                MonotonicMillis::from_millis(10),
            ),
            Ok(WaitRegistration::Ready(WakeReason::Deadline))
        );
        assert_eq!(waits.stats().live, 0);
        pending_calls
            .mark_ready(first, WakeReason::Deadline)
            .unwrap_or_else(|_| std::process::abort());
        pending_calls
            .finish(first)
            .unwrap_or_else(|_| std::process::abort());

        let second = pending(&mut pending_calls, owner, 2, b"two");
        let resource = WaitResource::new(7, 1).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            waits.register(
                resource_spec(owner, second, resource),
                WaitObservation::ResourceReady,
                MonotonicMillis::from_millis(1),
            ),
            Ok(WaitRegistration::Ready(WakeReason::ResourceReady))
        );
        assert_eq!(waits.stats().immediate_wakes, 2);
        assert_eq!(waits.stats().timeouts, 1);
        assert_eq!(waits.stats().resource_wakes, 1);
    }

    #[test]
    fn stale_generation_and_duplicate_publication_fail_closed() {
        let first_owner = task(0);
        let second_owner = task(1);
        let mut calls = PendingCallTable::new(2, 32).unwrap_or_else(|_| std::process::abort());
        let first = pending(&mut calls, first_owner, 1, b"one");
        let second = pending(&mut calls, second_owner, 2, b"two");
        let mut waits = WaitTable::new(1).unwrap_or_else(|_| std::process::abort());
        let Ok(WaitRegistration::Blocked(first_key)) = waits.register(
            timer_spec(first_owner, first, 10),
            WaitObservation::Pending,
            MonotonicMillis::from_millis(0),
        ) else {
            std::process::abort()
        };
        assert_eq!(
            waits.register(
                timer_spec(first_owner, second, 10),
                WaitObservation::Pending,
                MonotonicMillis::from_millis(0),
            ),
            Err(WaitError::OwnerAlreadyWaiting)
        );
        assert_eq!(
            waits.register(
                timer_spec(second_owner, first, 10),
                WaitObservation::Pending,
                MonotonicMillis::from_millis(0),
            ),
            Err(WaitError::OperationAlreadyWaiting)
        );
        waits
            .wake(first_key, WakeReason::Deadline)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            waits.wake(first_key, WakeReason::Deadline),
            Err(WaitError::StaleWait)
        );
        let Ok(WaitRegistration::Blocked(second_key)) = waits.register(
            timer_spec(second_owner, second, 20),
            WaitObservation::Pending,
            MonotonicMillis::from_millis(0),
        ) else {
            std::process::abort()
        };
        assert_eq!(first_key.slot(), second_key.slot());
        assert_ne!(first_key.generation(), second_key.generation());
        assert_eq!(waits.stats().stale_wakes, 1);
    }

    #[test]
    fn timeout_cancel_and_close_races_have_one_consumer() {
        let owner = task(0);
        let mut calls = PendingCallTable::new(1, 32).unwrap_or_else(|_| std::process::abort());
        let operation = pending(&mut calls, owner, 1, b"request");
        let resource = WaitResource::new(11, 4).unwrap_or_else(|_| std::process::abort());
        let mut waits = WaitTable::new(1).unwrap_or_else(|_| std::process::abort());
        let Ok(WaitRegistration::Blocked(key)) = waits.register(
            resource_spec(owner, operation, resource),
            WaitObservation::Pending,
            MonotonicMillis::from_millis(0),
        ) else {
            std::process::abort()
        };
        calls
            .bind_wait(operation, key)
            .unwrap_or_else(|_| std::process::abort());

        let expired = waits
            .expire(MonotonicMillis::from_millis(50))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(expired.len(), 1);
        let completion = expired
            .iter()
            .next()
            .unwrap_or_else(|| std::process::abort());
        calls
            .resolve(completion)
            .unwrap_or_else(|_| std::process::abort());
        assert!(
            waits
                .wake_resource(resource, WakeReason::Closed)
                .unwrap_or_else(|_| std::process::abort())
                .is_empty()
        );
        assert_eq!(
            waits.cancel_operation(operation, WakeReason::Cancelled),
            Ok(None)
        );
        assert_eq!(
            calls.call(operation).map(PendingCallSnapshot::state),
            Ok(PendingCallState::Ready(WakeReason::Deadline))
        );
        calls
            .finish(operation)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(waits.stats().wakes, 1);
        assert_eq!(waits.stats().timeouts, 1);
    }

    #[test]
    fn resource_generation_mismatch_never_wakes_a_waiter() {
        let owner = task(0);
        let mut calls = PendingCallTable::new(1, 8).unwrap_or_else(|_| std::process::abort());
        let operation = pending(&mut calls, owner, 1, b"x");
        let current = WaitResource::new(4, 8).unwrap_or_else(|_| std::process::abort());
        let stale = WaitResource::new(4, 7).unwrap_or_else(|_| std::process::abort());
        let mut waits = WaitTable::new(1).unwrap_or_else(|_| std::process::abort());
        assert!(matches!(
            waits.register(
                resource_spec(owner, operation, current),
                WaitObservation::Pending,
                MonotonicMillis::from_millis(0),
            ),
            Ok(WaitRegistration::Blocked(_))
        ));
        assert!(
            waits
                .wake_resource(stale, WakeReason::ResourceReady)
                .unwrap_or_else(|_| std::process::abort())
                .is_empty()
        );
        assert_eq!(waits.stats().live, 1);
        assert_eq!(waits.stats().stale_wakes, 1);
    }

    #[test]
    fn copied_pending_calls_are_bounded_monotonic_and_zeroized() {
        let owner = task(0);
        let mut source = [1_u8, 2, 3, 4];
        let mut calls = PendingCallTable::new(1, 4).unwrap_or_else(|_| std::process::abort());
        let operation = pending(&mut calls, owner, 1, &source);
        source.fill(9);
        assert_eq!(calls.request(operation), Ok(&[1_u8, 2, 3, 4][..]));
        assert_eq!(calls.stats().retained_bytes, 4);
        assert_eq!(
            calls.begin(owner, 2, 9, 3, b"x", 1),
            Err(PendingCallError::OwnerAlreadyPending)
        );
        calls
            .mark_ready(operation, WakeReason::ResourceReady)
            .unwrap_or_else(|_| std::process::abort());
        let completed = calls
            .finish(operation)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(completed.request_id(), 1);
        assert_eq!(calls.call(operation), Err(PendingCallError::StaleOperation));
        assert!(
            calls.slots[usize::from(operation.slot())]
                .request
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(calls.stats().retained_bytes, 0);
        assert_eq!(calls.stats().zeroized_bytes, 4);
        assert_eq!(
            calls.begin(owner, 1, 9, 3, b"reuse", 1),
            Err(PendingCallError::RequestIdentityNotMonotonic)
        );
    }

    #[test]
    fn pending_capacity_and_retained_byte_limits_are_atomic() {
        let first_owner = task(0);
        let second_owner = task(1);
        assert!(matches!(
            PendingCallTable::new(0, 0),
            Err(PendingCallError::InvalidCapacity)
        ));
        let mut calls = PendingCallTable::new(2, 4).unwrap_or_else(|_| std::process::abort());
        let first = pending(&mut calls, first_owner, 1, b"abc");
        assert_eq!(
            calls.begin(second_owner, 2, 9, 3, b"de", 1),
            Err(PendingCallError::ByteCapacityExhausted)
        );
        assert_eq!(calls.stats().live, 1);
        assert_eq!(calls.stats().retained_bytes, 3);
        calls
            .mark_ready(first, WakeReason::Cancelled)
            .unwrap_or_else(|_| std::process::abort());
        calls
            .finish(first)
            .unwrap_or_else(|_| std::process::abort());
        let oversized = [0_u8; MAX_PENDING_REQUEST_BYTES + 1];
        assert_eq!(
            calls.begin(second_owner, 2, 9, 3, &oversized, 1),
            Err(PendingCallError::MessageTooLarge)
        );
        assert_eq!(calls.stats().live, 0);
    }

    #[test]
    fn owner_teardown_removes_and_zeroizes_every_pending_state() {
        for state in [
            PendingCallState::New,
            PendingCallState::Waiting(WaitKey {
                slot: 0,
                generation: 1,
            }),
            PendingCallState::Ready(WakeReason::Deadline),
        ] {
            let owner = task(0);
            let mut calls = PendingCallTable::new(1, 16).unwrap_or_else(|_| std::process::abort());
            let operation = pending(&mut calls, owner, 1, b"owned");
            calls.slots[0]
                .record
                .as_mut()
                .unwrap_or_else(|| std::process::abort())
                .state = state;
            assert_eq!(calls.teardown_owner(owner, WakeReason::Revoked), Ok(1));
            assert_eq!(calls.teardown_owner(owner, WakeReason::Revoked), Ok(0));
            assert_eq!(calls.call(operation), Err(PendingCallError::StaleOperation));
            assert!(calls.slots[0].request.iter().all(|byte| *byte == 0));
            assert_eq!(calls.stats().terminal_completions, 1);
            assert_eq!(calls.stats().completed, 1);
        }
    }

    #[test]
    fn exact_slot_boundaries_reuse_only_with_a_new_generation() {
        let first_owner = task(0);
        let second_owner = task(1);
        let third_owner = task(2);
        let mut calls = PendingCallTable::new(2, 8).unwrap_or_else(|_| std::process::abort());
        let first = pending(&mut calls, first_owner, 1, b"one");
        let second = pending(&mut calls, second_owner, 2, b"two");
        assert_eq!(
            calls.begin(third_owner, 3, 9, 3, b"x", 1),
            Err(PendingCallError::CapacityExhausted)
        );
        calls
            .mark_ready(first, WakeReason::Cancelled)
            .unwrap_or_else(|_| std::process::abort());
        calls
            .finish(first)
            .unwrap_or_else(|_| std::process::abort());
        let replacement = pending(&mut calls, third_owner, 3, b"new");
        assert_eq!(replacement.slot(), first.slot());
        assert_ne!(replacement.generation(), first.generation());
        assert_eq!(calls.call(first), Err(PendingCallError::StaleOperation));
        assert_eq!(calls.stats().live, 2);
        assert_eq!(calls.stats().high_water, 2);

        let mut waits = WaitTable::new(2).unwrap_or_else(|_| std::process::abort());
        let Ok(WaitRegistration::Blocked(first_wait)) = waits.register(
            timer_spec(first_owner, first, 10),
            WaitObservation::Pending,
            MonotonicMillis::from_millis(0),
        ) else {
            std::process::abort()
        };
        let Ok(WaitRegistration::Blocked(second_wait)) = waits.register(
            timer_spec(second_owner, second, 10),
            WaitObservation::Pending,
            MonotonicMillis::from_millis(0),
        ) else {
            std::process::abort()
        };
        assert_eq!(
            waits.register(
                timer_spec(third_owner, replacement, 10),
                WaitObservation::Pending,
                MonotonicMillis::from_millis(0),
            ),
            Err(WaitError::CapacityExhausted)
        );
        let expired = waits
            .expire(MonotonicMillis::from_millis(10))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(expired.len(), 2);
        assert_eq!(waits.stats().live, 0);
        assert_eq!(waits.stats().high_water, 2);
        assert_eq!(waits.stats().wakes, 2);
        assert!(
            expired
                .iter()
                .any(|completion| completion.key() == first_wait)
        );
        assert!(
            expired
                .iter()
                .any(|completion| completion.key() == second_wait)
        );
    }

    #[test]
    fn cancellation_close_and_revocation_each_complete_once() {
        for (index, reason) in [
            WakeReason::Cancelled,
            WakeReason::Closed,
            WakeReason::Revoked,
        ]
        .into_iter()
        .enumerate()
        {
            let owner = task(u8::try_from(index).unwrap_or_default());
            let mut calls = PendingCallTable::new(1, 16).unwrap_or_else(|_| std::process::abort());
            let operation = pending(&mut calls, owner, 1, b"pending");
            let resource = WaitResource::new(20, 3).unwrap_or_else(|_| std::process::abort());
            let mut waits = WaitTable::new(1).unwrap_or_else(|_| std::process::abort());
            let Ok(WaitRegistration::Blocked(key)) = waits.register(
                resource_spec(owner, operation, resource),
                WaitObservation::Pending,
                MonotonicMillis::from_millis(0),
            ) else {
                std::process::abort()
            };
            calls
                .bind_wait(operation, key)
                .unwrap_or_else(|_| std::process::abort());
            let completion = match reason {
                WakeReason::Cancelled => waits
                    .cancel_operation(operation, reason)
                    .unwrap_or_else(|_| std::process::abort())
                    .unwrap_or_else(|| std::process::abort()),
                WakeReason::Closed => waits
                    .wake_resource(resource, reason)
                    .unwrap_or_else(|_| std::process::abort())
                    .iter()
                    .next()
                    .unwrap_or_else(|| std::process::abort()),
                WakeReason::Revoked => waits
                    .cancel_owner(owner, reason)
                    .unwrap_or_else(|_| std::process::abort())
                    .iter()
                    .next()
                    .unwrap_or_else(|| std::process::abort()),
                WakeReason::ResourceReady | WakeReason::Deadline => std::process::abort(),
            };
            calls
                .resolve(completion)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(
                calls.call(operation).map(PendingCallSnapshot::state),
                Ok(PendingCallState::Ready(reason))
            );
            assert_eq!(waits.cancel_operation(operation, reason), Ok(None));
            calls
                .finish(operation)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(calls.stats().terminal_completions, 1);
            assert_eq!(waits.stats().wakes, 1);
        }
    }

    #[test]
    fn accounting_failures_leave_waits_and_teardown_ownership_intact() {
        let owner = task(0);
        let mut calls = PendingCallTable::new(1, 16).unwrap_or_else(|_| std::process::abort());
        let operation = pending(&mut calls, owner, 1, b"owned");
        calls.stats.completed = u64::MAX;
        assert_eq!(
            calls.teardown_owner(owner, WakeReason::Revoked),
            Err(PendingCallError::AccountingOverflow)
        );
        assert_eq!(calls.request(operation), Ok(&b"owned"[..]));
        assert_eq!(calls.stats().live, 1);
        assert_eq!(calls.stats().retained_bytes, 5);

        let mut waits = WaitTable::new(1).unwrap_or_else(|_| std::process::abort());
        waits.stats.timeouts = u64::MAX;
        assert_eq!(
            waits.register(
                timer_spec(owner, operation, 1),
                WaitObservation::Pending,
                MonotonicMillis::from_millis(1),
            ),
            Err(WaitError::AccountingOverflow)
        );
        assert_eq!(waits.stats().live, 0);
        assert_eq!(waits.stats().immediate_wakes, 0);

        waits.stats.timeouts = 0;
        let Ok(WaitRegistration::Blocked(key)) = waits.register(
            timer_spec(owner, operation, 2),
            WaitObservation::Pending,
            MonotonicMillis::from_millis(0),
        ) else {
            std::process::abort()
        };
        waits.stats.wakes = u64::MAX;
        assert_eq!(
            waits.wake(key, WakeReason::Deadline),
            Err(WaitError::AccountingOverflow)
        );
        assert_eq!(waits.stats().live, 1);
        waits.stats.wakes = 0;
        assert!(waits.wake(key, WakeReason::Deadline).is_ok());
    }
}

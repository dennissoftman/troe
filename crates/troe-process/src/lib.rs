//! Bounded owner-scoped child-process and byte-pipe policy.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use troe_abi::{pipe, process_launch};

/// Maximum children retained by one launch capability.
pub const MAX_CHILDREN_PER_OWNER: usize = 65_536;
/// Maximum pipe objects retained by one pipe capability.
pub const MAX_PIPES_PER_OWNER: usize = 65_536;
/// Maximum aggregate reserved pipe bytes per owner.
pub const MAX_PIPE_BYTES_PER_OWNER: usize = 256 * 1024 * 1024;

const INITIAL_OBJECT_CAPACITY: usize = 64;

/// Stable nonzero identity of one process-launch/pipe owner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OwnerId(u32);

impl OwnerId {
    /// Construct one owner identity.
    ///
    /// # Errors
    ///
    /// Rejects zero, which is reserved.
    pub const fn new(value: u32) -> Result<Self, ProcessError> {
        if value == 0 {
            Err(ProcessError::InvalidOwner)
        } else {
            Ok(Self(value))
        }
    }

    /// Numeric identity used to bind kernel task ownership.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Terminal or live child state retained independently of global observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildLifecycle {
    /// Child is admitted and nonterminal.
    Running,
    /// Child exited normally with an application-provided status.
    Exited(u32),
    /// Child hit a contained execution fault.
    Faulted,
    /// Owner cancellation completed.
    Cancelled,
}

impl ChildLifecycle {
    /// Convert owner state to the stable process-launch ABI.
    #[must_use]
    pub const fn abi_state(self) -> (process_launch::ChildState, u32) {
        match self {
            Self::Running => (process_launch::ChildState::Running, 0),
            Self::Exited(status) => (process_launch::ChildState::Exited, status),
            Self::Faulted => (
                process_launch::ChildState::Faulted,
                process_launch::FAULT_EXIT_STATUS,
            ),
            Self::Cancelled => (
                process_launch::ChildState::Cancelled,
                troe_abi::exit::CANCELLED,
            ),
        }
    }

    /// Whether no additional child execution is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChildRecord {
    owner: OwnerId,
    process_id: u64,
    lifecycle: ChildLifecycle,
    cancel_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChildSlot {
    generation: u32,
    record: Option<ChildRecord>,
}

/// Bounded generation-checked child capability table.
#[derive(Debug)]
pub struct ChildTable {
    slots: Vec<ChildSlot>,
    capacity: usize,
    live: usize,
}

impl ChildTable {
    /// Reserve one immutable child-token capacity.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds or metadata allocation failure.
    pub fn new(capacity: usize) -> Result<Self, ProcessError> {
        if capacity == 0 || capacity > MAX_CHILDREN_PER_OWNER {
            return Err(ProcessError::InvalidCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity.min(INITIAL_OBJECT_CAPACITY))
            .map_err(|_| ProcessError::MetadataExhausted)?;
        Ok(Self {
            slots,
            capacity,
            live: 0,
        })
    }

    /// Admit one live child and return a new owner-scoped token.
    ///
    /// # Errors
    ///
    /// Rejects zero/duplicate process IDs, exhausted capacity, or generation
    /// exhaustion without retaining a partial record.
    pub fn admit(
        &mut self,
        owner: OwnerId,
        process_id: u64,
    ) -> Result<process_launch::ChildToken, ProcessError> {
        if process_id == 0
            || self
                .slots
                .iter()
                .filter_map(|slot| slot.record)
                .any(|record| record.process_id == process_id)
        {
            return Err(ProcessError::InvalidProcess);
        }
        let index = if let Some(index) = self.slots.iter().position(|slot| slot.record.is_none()) {
            index
        } else {
            if self.slots.len() == self.capacity {
                return Err(ProcessError::CapacityExhausted);
            }
            self.slots
                .try_reserve(1)
                .map_err(|_| ProcessError::MetadataExhausted)?;
            self.slots.push(ChildSlot {
                generation: 1,
                record: None,
            });
            self.slots.len() - 1
        };
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::AccountingOverflow)?;
        let token = encode_token(index, slot.generation)?;
        slot.record = Some(ChildRecord {
            owner,
            process_id,
            lifecycle: ChildLifecycle::Running,
            cancel_requested: false,
        });
        self.live = self
            .live
            .checked_add(1)
            .ok_or(ProcessError::AccountingOverflow)?;
        process_launch::ChildToken::new(token).map_err(|_| ProcessError::InvalidToken)
    }

    /// Read current owner-visible child status.
    ///
    /// # Errors
    ///
    /// Rejects stale, forged, or foreign tokens.
    pub fn status(
        &self,
        owner: OwnerId,
        token: process_launch::ChildToken,
    ) -> Result<process_launch::ChildStatus, ProcessError> {
        let record = self.record(owner, token)?;
        let (state, exit_status) = record.lifecycle.abi_state();
        Ok(process_launch::ChildStatus {
            token,
            process_id: record.process_id,
            exit_status,
            state,
        })
    }

    /// Request cancellation of one live child.
    ///
    /// Returns `true` exactly once when a new cancellation request is retained.
    ///
    /// # Errors
    ///
    /// Rejects stale, forged, or foreign tokens.
    pub fn request_cancel(
        &mut self,
        owner: OwnerId,
        token: process_launch::ChildToken,
    ) -> Result<bool, ProcessError> {
        let record = self.record_mut(owner, token)?;
        if record.lifecycle.is_terminal() || record.cancel_requested {
            return Ok(false);
        }
        record.cancel_requested = true;
        Ok(true)
    }

    /// Whether the kernel must deliver owner cancellation to this child.
    ///
    /// # Errors
    ///
    /// Rejects stale, forged, or foreign tokens.
    pub fn cancellation_requested(
        &self,
        owner: OwnerId,
        token: process_launch::ChildToken,
    ) -> Result<bool, ProcessError> {
        Ok(self.record(owner, token)?.cancel_requested)
    }

    /// Publish one terminal outcome exactly once.
    ///
    /// # Errors
    ///
    /// Rejects nonterminal outcomes, stale/foreign tokens, or duplicate
    /// completion.
    pub fn finish(
        &mut self,
        owner: OwnerId,
        token: process_launch::ChildToken,
        lifecycle: ChildLifecycle,
    ) -> Result<(), ProcessError> {
        if !lifecycle.is_terminal() {
            return Err(ProcessError::InvalidState);
        }
        let record = self.record_mut(owner, token)?;
        if record.lifecycle.is_terminal() {
            return Err(ProcessError::InvalidState);
        }
        record.lifecycle = lifecycle;
        Ok(())
    }

    /// Revoke one terminal token and return its process identity and outcome.
    ///
    /// # Errors
    ///
    /// Rejects live, stale, forged, or foreign tokens.
    pub fn reap(
        &mut self,
        owner: OwnerId,
        token: process_launch::ChildToken,
    ) -> Result<(u64, ChildLifecycle), ProcessError> {
        let (index, generation) = decode_token(token.value(), self.capacity)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::InvalidToken)?;
        if slot.generation != generation {
            return Err(ProcessError::InvalidToken);
        }
        let record = slot.record.ok_or(ProcessError::InvalidToken)?;
        if record.owner != owner {
            return Err(ProcessError::ForeignOwner);
        }
        if !record.lifecycle.is_terminal() {
            return Err(ProcessError::InvalidState);
        }
        let next = slot
            .generation
            .checked_add(1)
            .ok_or(ProcessError::GenerationExhausted)?;
        slot.record = None;
        slot.generation = next;
        self.live = self
            .live
            .checked_sub(1)
            .ok_or(ProcessError::AccountingOverflow)?;
        Ok((record.process_id, record.lifecycle))
    }

    /// Iterate current tokens owned by one parent.
    pub fn owned_tokens(
        &self,
        owner: OwnerId,
    ) -> impl Iterator<Item = process_launch::ChildToken> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(move |(index, slot)| {
                (slot.record.is_some_and(|record| record.owner == owner))
                    .then(|| encode_token(index, slot.generation).ok())
                    .flatten()
                    .and_then(|value| process_launch::ChildToken::new(value).ok())
            })
    }

    /// Number of retained live or terminal child tokens.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.live
    }

    /// Whether no child tokens are retained.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.live == 0
    }

    fn record(
        &self,
        owner: OwnerId,
        token: process_launch::ChildToken,
    ) -> Result<ChildRecord, ProcessError> {
        let (index, generation) = decode_token(token.value(), self.capacity)?;
        let slot = self.slots.get(index).ok_or(ProcessError::InvalidToken)?;
        if slot.generation != generation {
            return Err(ProcessError::InvalidToken);
        }
        let record = slot.record.ok_or(ProcessError::InvalidToken)?;
        if record.owner != owner {
            return Err(ProcessError::ForeignOwner);
        }
        Ok(record)
    }

    fn record_mut(
        &mut self,
        owner: OwnerId,
        token: process_launch::ChildToken,
    ) -> Result<&mut ChildRecord, ProcessError> {
        let (index, generation) = decode_token(token.value(), self.capacity)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::InvalidToken)?;
        if slot.generation != generation {
            return Err(ProcessError::InvalidToken);
        }
        let record = slot.record.as_mut().ok_or(ProcessError::InvalidToken)?;
        if record.owner != owner {
            return Err(ProcessError::ForeignOwner);
        }
        Ok(record)
    }
}

/// One kernel-held pipe endpoint reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipeEndpoint {
    token: pipe::PipeToken,
    direction: PipeDirection,
}

impl PipeEndpoint {
    /// Opaque pipe identity associated with this endpoint.
    #[must_use]
    pub const fn token(self) -> pipe::PipeToken {
        self.token
    }

    /// Endpoint direction.
    #[must_use]
    pub const fn direction(self) -> PipeDirection {
        self.direction
    }
}

/// Direction granted to one pipe endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeDirection {
    /// Read buffered bytes and observe EOF after all writers close.
    Reader,
    /// Append buffered bytes while readers remain open.
    Writer,
}

#[derive(Debug)]
struct PipeRecord {
    owner: OwnerId,
    capacity: usize,
    bytes: VecDeque<u8>,
    owner_reader_open: bool,
    owner_writer_open: bool,
    attached_readers: u32,
    attached_writers: u32,
}

impl PipeRecord {
    fn readers(&self) -> u32 {
        u32::from(self.owner_reader_open) + self.attached_readers
    }

    fn writers(&self) -> u32 {
        u32::from(self.owner_writer_open) + self.attached_writers
    }

    fn removable(&self) -> bool {
        self.readers() == 0 && self.writers() == 0
    }
}

#[derive(Debug)]
struct PipeSlot {
    generation: u32,
    record: Option<PipeRecord>,
}

/// Bounded generation-checked owner pipe table.
#[derive(Debug)]
pub struct PipeTable {
    slots: Vec<PipeSlot>,
    capacity: usize,
    reserved_bytes: usize,
}

impl PipeTable {
    /// Reserve one immutable pipe-object capacity.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds or metadata allocation failure.
    pub fn new(capacity: usize) -> Result<Self, ProcessError> {
        if capacity == 0 || capacity > MAX_PIPES_PER_OWNER {
            return Err(ProcessError::InvalidCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity.min(INITIAL_OBJECT_CAPACITY))
            .map_err(|_| ProcessError::MetadataExhausted)?;
        Ok(Self {
            slots,
            capacity,
            reserved_bytes: 0,
        })
    }

    /// Create one empty pipe owned in both directions by `owner`.
    ///
    /// # Errors
    ///
    /// Rejects object/byte capacity or allocation exhaustion atomically.
    pub fn create(
        &mut self,
        owner: OwnerId,
        capacity: usize,
    ) -> Result<pipe::PipeToken, ProcessError> {
        if !(pipe::MIN_CAPACITY..=pipe::MAX_CAPACITY).contains(&capacity)
            || self.reserved_bytes.saturating_add(capacity) > MAX_PIPE_BYTES_PER_OWNER
        {
            return Err(ProcessError::CapacityExhausted);
        }
        let index = if let Some(index) = self.slots.iter().position(|slot| slot.record.is_none()) {
            index
        } else {
            if self.slots.len() == self.capacity {
                return Err(ProcessError::CapacityExhausted);
            }
            self.slots
                .try_reserve(1)
                .map_err(|_| ProcessError::MetadataExhausted)?;
            self.slots.push(PipeSlot {
                generation: 1,
                record: None,
            });
            self.slots.len() - 1
        };
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::AccountingOverflow)?;
        let token = pipe::PipeToken::new(encode_token(index, slot.generation)?)
            .map_err(|_| ProcessError::InvalidToken)?;
        let mut bytes = VecDeque::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ProcessError::MetadataExhausted)?;
        slot.record = Some(PipeRecord {
            owner,
            capacity,
            bytes,
            owner_reader_open: true,
            owner_writer_open: true,
            attached_readers: 0,
            attached_writers: 0,
        });
        self.reserved_bytes = self
            .reserved_bytes
            .checked_add(capacity)
            .ok_or(ProcessError::AccountingOverflow)?;
        Ok(token)
    }

    /// Attach one kernel-held child endpoint.
    ///
    /// # Errors
    ///
    /// Rejects stale/foreign tokens, closed direction, or reference overflow.
    pub fn attach(
        &mut self,
        owner: OwnerId,
        token: pipe::PipeToken,
        direction: PipeDirection,
    ) -> Result<PipeEndpoint, ProcessError> {
        let record = self.record_mut(owner, token)?;
        match direction {
            PipeDirection::Reader if record.owner_reader_open => {
                record.attached_readers = record
                    .attached_readers
                    .checked_add(1)
                    .ok_or(ProcessError::AccountingOverflow)?;
            }
            PipeDirection::Writer if record.owner_writer_open => {
                record.attached_writers = record
                    .attached_writers
                    .checked_add(1)
                    .ok_or(ProcessError::AccountingOverflow)?;
            }
            PipeDirection::Reader | PipeDirection::Writer => {
                return Err(ProcessError::Closed);
            }
        }
        Ok(PipeEndpoint { token, direction })
    }

    /// Release one kernel-held child endpoint exactly once.
    ///
    /// # Errors
    ///
    /// Rejects stale endpoints or accounting underflow.
    pub fn detach(&mut self, endpoint: PipeEndpoint) -> Result<(), ProcessError> {
        let (index, generation) = decode_token(endpoint.token.value(), self.capacity)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::InvalidToken)?;
        if slot.generation != generation {
            return Err(ProcessError::InvalidToken);
        }
        let record = slot.record.as_mut().ok_or(ProcessError::InvalidToken)?;
        match endpoint.direction {
            PipeDirection::Reader => {
                record.attached_readers = record
                    .attached_readers
                    .checked_sub(1)
                    .ok_or(ProcessError::InvalidState)?;
            }
            PipeDirection::Writer => {
                record.attached_writers = record
                    .attached_writers
                    .checked_sub(1)
                    .ok_or(ProcessError::InvalidState)?;
            }
        }
        self.remove_if_closed(index)
    }

    /// Write as the owner endpoint.
    ///
    /// # Errors
    ///
    /// Rejects foreign/stale/closed pipes, missing readers, empty input, or
    /// insufficient current capacity without partial writes.
    pub fn write_owner(
        &mut self,
        owner: OwnerId,
        token: pipe::PipeToken,
        bytes: &[u8],
    ) -> Result<usize, ProcessError> {
        let record = self.record_mut(owner, token)?;
        if !record.owner_writer_open || record.readers() == 0 {
            return Err(ProcessError::Closed);
        }
        write_pipe(record, bytes)
    }

    /// Read as the owner endpoint.
    ///
    /// Returns zero only for EOF after all writers close.
    ///
    /// # Errors
    ///
    /// Rejects foreign/stale/closed pipes, empty destination, or a currently
    /// empty pipe that still has writers.
    pub fn read_owner(
        &mut self,
        owner: OwnerId,
        token: pipe::PipeToken,
        destination: &mut [u8],
    ) -> Result<usize, ProcessError> {
        let record = self.record_mut(owner, token)?;
        if !record.owner_reader_open {
            return Err(ProcessError::Closed);
        }
        read_pipe(record, destination)
    }

    /// Whether an owner read can complete now with data or EOF.
    ///
    /// # Errors
    ///
    /// Rejects a stale, foreign, or closed owner endpoint.
    pub fn owner_read_ready(
        &mut self,
        owner: OwnerId,
        token: pipe::PipeToken,
    ) -> Result<bool, ProcessError> {
        let record = self.record_mut(owner, token)?;
        if !record.owner_reader_open {
            return Err(ProcessError::Closed);
        }
        Ok(!record.bytes.is_empty() || record.writers() == 0)
    }

    /// Whether one complete owner write fits now and a reader remains.
    ///
    /// # Errors
    ///
    /// Rejects a stale, foreign, or closed owner endpoint.
    pub fn owner_write_ready(
        &mut self,
        owner: OwnerId,
        token: pipe::PipeToken,
        byte_count: usize,
    ) -> Result<bool, ProcessError> {
        let record = self.record_mut(owner, token)?;
        if !record.owner_writer_open || record.readers() == 0 {
            return Err(ProcessError::Closed);
        }
        Ok(byte_count != 0 && byte_count <= record.capacity.saturating_sub(record.bytes.len()))
    }

    /// Write through one attached kernel endpoint.
    ///
    /// # Errors
    ///
    /// Rejects a stale or wrong-direction endpoint, closed readers, empty
    /// input, or current backpressure.
    pub fn write_endpoint(
        &mut self,
        endpoint: PipeEndpoint,
        bytes: &[u8],
    ) -> Result<usize, ProcessError> {
        if endpoint.direction != PipeDirection::Writer {
            return Err(ProcessError::InvalidState);
        }
        let record = self.endpoint_record_mut(endpoint)?;
        if record.readers() == 0 {
            return Err(ProcessError::Closed);
        }
        write_pipe(record, bytes)
    }

    /// Read through one attached kernel endpoint.
    ///
    /// # Errors
    ///
    /// Rejects a stale or wrong-direction endpoint, empty output storage, or
    /// an empty live pipe.
    pub fn read_endpoint(
        &mut self,
        endpoint: PipeEndpoint,
        destination: &mut [u8],
    ) -> Result<usize, ProcessError> {
        if endpoint.direction != PipeDirection::Reader {
            return Err(ProcessError::InvalidState);
        }
        read_pipe(self.endpoint_record_mut(endpoint)?, destination)
    }

    /// Whether an attached reader can complete now with data or EOF.
    ///
    /// # Errors
    ///
    /// Rejects a stale or wrong-direction endpoint.
    pub fn endpoint_read_ready(&mut self, endpoint: PipeEndpoint) -> Result<bool, ProcessError> {
        if endpoint.direction != PipeDirection::Reader {
            return Err(ProcessError::InvalidState);
        }
        let record = self.endpoint_record_mut(endpoint)?;
        Ok(!record.bytes.is_empty() || record.writers() == 0)
    }

    /// Whether one complete attached write fits now and a reader remains.
    ///
    /// # Errors
    ///
    /// Rejects a stale or wrong-direction endpoint or a pipe without readers.
    pub fn endpoint_write_ready(
        &mut self,
        endpoint: PipeEndpoint,
        byte_count: usize,
    ) -> Result<bool, ProcessError> {
        if endpoint.direction != PipeDirection::Writer {
            return Err(ProcessError::InvalidState);
        }
        let record = self.endpoint_record_mut(endpoint)?;
        if record.readers() == 0 {
            return Err(ProcessError::Closed);
        }
        Ok(byte_count != 0 && byte_count <= record.capacity.saturating_sub(record.bytes.len()))
    }

    /// Close one owner direction and invalidate the object after every endpoint closes.
    ///
    /// # Errors
    ///
    /// Rejects a stale, foreign, or already closed owner endpoint.
    pub fn close_owner(
        &mut self,
        owner: OwnerId,
        token: pipe::PipeToken,
        direction: PipeDirection,
    ) -> Result<(), ProcessError> {
        let (index, generation) = decode_token(token.value(), self.capacity)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::InvalidToken)?;
        if slot.generation != generation {
            return Err(ProcessError::InvalidToken);
        }
        let record = slot.record.as_mut().ok_or(ProcessError::InvalidToken)?;
        if record.owner != owner {
            return Err(ProcessError::ForeignOwner);
        }
        let open = match direction {
            PipeDirection::Reader => &mut record.owner_reader_open,
            PipeDirection::Writer => &mut record.owner_writer_open,
        };
        if !*open {
            return Err(ProcessError::Closed);
        }
        *open = false;
        self.remove_if_closed(index)
    }

    /// Total reserved byte capacity across current pipes.
    #[must_use]
    pub const fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    fn record_mut(
        &mut self,
        owner: OwnerId,
        token: pipe::PipeToken,
    ) -> Result<&mut PipeRecord, ProcessError> {
        let (index, generation) = decode_token(token.value(), self.capacity)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::InvalidToken)?;
        if slot.generation != generation {
            return Err(ProcessError::InvalidToken);
        }
        let record = slot.record.as_mut().ok_or(ProcessError::InvalidToken)?;
        if record.owner != owner {
            return Err(ProcessError::ForeignOwner);
        }
        Ok(record)
    }

    fn endpoint_record_mut(
        &mut self,
        endpoint: PipeEndpoint,
    ) -> Result<&mut PipeRecord, ProcessError> {
        let (index, generation) = decode_token(endpoint.token.value(), self.capacity)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::InvalidToken)?;
        if slot.generation != generation {
            return Err(ProcessError::InvalidToken);
        }
        slot.record.as_mut().ok_or(ProcessError::InvalidToken)
    }

    fn remove_if_closed(&mut self, index: usize) -> Result<(), ProcessError> {
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProcessError::InvalidToken)?;
        let Some(record) = slot.record.as_ref() else {
            return Err(ProcessError::InvalidToken);
        };
        if !record.removable() {
            return Ok(());
        }
        let capacity = record.capacity;
        let next = slot
            .generation
            .checked_add(1)
            .ok_or(ProcessError::GenerationExhausted)?;
        slot.record = None;
        slot.generation = next;
        self.reserved_bytes = self
            .reserved_bytes
            .checked_sub(capacity)
            .ok_or(ProcessError::AccountingOverflow)?;
        Ok(())
    }
}

fn write_pipe(record: &mut PipeRecord, bytes: &[u8]) -> Result<usize, ProcessError> {
    if bytes.is_empty() {
        return Err(ProcessError::InvalidMessage);
    }
    let available = record.capacity.saturating_sub(record.bytes.len());
    if bytes.len() > available {
        return Err(ProcessError::WouldBlock);
    }
    record.bytes.extend(bytes.iter().copied());
    Ok(bytes.len())
}

fn read_pipe(record: &mut PipeRecord, destination: &mut [u8]) -> Result<usize, ProcessError> {
    if destination.is_empty() {
        return Err(ProcessError::InvalidMessage);
    }
    if record.bytes.is_empty() {
        return if record.writers() == 0 {
            Ok(0)
        } else {
            Err(ProcessError::WouldBlock)
        };
    }
    let count = destination.len().min(record.bytes.len());
    for byte in &mut destination[..count] {
        *byte = record
            .bytes
            .pop_front()
            .ok_or(ProcessError::AccountingOverflow)?;
    }
    Ok(count)
}

fn encode_token(index: usize, generation: u32) -> Result<u64, ProcessError> {
    let slot = u32::try_from(index)
        .map_err(|_| ProcessError::InvalidToken)?
        .checked_add(1)
        .ok_or(ProcessError::InvalidToken)?;
    if generation == 0 {
        return Err(ProcessError::InvalidToken);
    }
    Ok((u64::from(generation) << 32) | u64::from(slot))
}

fn decode_token(value: u64, capacity: usize) -> Result<(usize, u32), ProcessError> {
    let encoded_slot = value & u64::from(u32::MAX);
    let generation = value >> 32;
    if encoded_slot == 0
        || encoded_slot > u64::try_from(capacity).map_err(|_| ProcessError::InvalidToken)?
        || generation == 0
    {
        return Err(ProcessError::InvalidToken);
    }
    Ok((
        usize::try_from(encoded_slot - 1).map_err(|_| ProcessError::InvalidToken)?,
        u32::try_from(generation).map_err(|_| ProcessError::InvalidToken)?,
    ))
}

/// Bounded process/pipe policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessError {
    /// Configured table capacity is invalid.
    InvalidCapacity,
    /// Fallible metadata or byte reservation failed.
    MetadataExhausted,
    /// A bounded record or byte capacity is exhausted.
    CapacityExhausted,
    /// Owner identity is reserved or invalid.
    InvalidOwner,
    /// Process identity is zero or already retained.
    InvalidProcess,
    /// Token is malformed, stale, or already revoked.
    InvalidToken,
    /// Token belongs to another owner.
    ForeignOwner,
    /// Token generation cannot advance safely.
    GenerationExhausted,
    /// Lifecycle or endpoint direction is invalid.
    InvalidState,
    /// Checked resource accounting failed.
    AccountingOverflow,
    /// Pipe endpoint is closed.
    Closed,
    /// Pipe has no current space/data but may make progress later.
    WouldBlock,
    /// Pipe message is empty or otherwise invalid.
    InvalidMessage,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCapacity => "process capacity is invalid",
            Self::MetadataExhausted => "process metadata allocation failed",
            Self::CapacityExhausted => "process capacity exhausted",
            Self::InvalidOwner => "process owner is invalid",
            Self::InvalidProcess => "process identity is invalid",
            Self::InvalidToken => "process token is invalid or stale",
            Self::ForeignOwner => "process token has another owner",
            Self::GenerationExhausted => "process token generation exhausted",
            Self::InvalidState => "process lifecycle or endpoint state is invalid",
            Self::AccountingOverflow => "process accounting overflowed",
            Self::Closed => "pipe endpoint is closed",
            Self::WouldBlock => "pipe operation would block",
            Self::InvalidMessage => "pipe message is invalid",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChildLifecycle, ChildTable, MAX_CHILDREN_PER_OWNER, MAX_PIPE_BYTES_PER_OWNER, OwnerId,
        PipeDirection, PipeTable, ProcessError,
    };
    use alloc::vec;
    use troe_abi::pipe;

    #[test]
    fn child_tokens_are_owner_scoped_generation_checked_and_preserve_status()
    -> Result<(), ProcessError> {
        let owner = OwnerId::new(7)?;
        let foreign = OwnerId::new(8)?;
        let mut children = ChildTable::new(2)?;
        let first = children.admit(owner, 41)?;
        assert_eq!(
            children.status(owner, first)?.state,
            troe_abi::process_launch::ChildState::Running
        );
        assert_eq!(
            children.status(foreign, first),
            Err(ProcessError::ForeignOwner)
        );
        assert!(children.request_cancel(owner, first)?);
        assert!(!children.request_cancel(owner, first)?);
        children.finish(owner, first, ChildLifecycle::Exited(203))?;
        assert_eq!(children.status(owner, first)?.exit_status, 203);
        assert_eq!(
            children.reap(owner, first)?,
            (41, ChildLifecycle::Exited(203))
        );
        assert_eq!(
            children.status(owner, first),
            Err(ProcessError::InvalidToken)
        );

        let reused = children.admit(owner, 42)?;
        assert_ne!(reused, first);
        Ok(())
    }

    #[test]
    fn child_capacity_and_terminal_rules_fail_closed() -> Result<(), ProcessError> {
        const TEST_CAPACITY: usize = 1024;

        let owner = OwnerId::new(1)?;
        let mut children = ChildTable::new(TEST_CAPACITY)?;
        let mut tokens = vec![];
        for process_id in
            1..=u64::try_from(TEST_CAPACITY).map_err(|_| ProcessError::AccountingOverflow)?
        {
            tokens.push(children.admit(owner, process_id)?);
        }
        assert_eq!(
            children.admit(owner, u64::try_from(TEST_CAPACITY + 1).unwrap_or(u64::MAX)),
            Err(ProcessError::CapacityExhausted)
        );
        assert_eq!(
            children.reap(owner, tokens[0]),
            Err(ProcessError::InvalidState)
        );
        assert!(ChildTable::new(MAX_CHILDREN_PER_OWNER).is_ok());
        Ok(())
    }

    #[test]
    fn pipe_endpoints_stream_with_backpressure_eof_and_exact_reclamation()
    -> Result<(), ProcessError> {
        let owner = OwnerId::new(9)?;
        let mut pipes = PipeTable::new(2)?;
        let token = pipes.create(owner, pipe::MIN_CAPACITY)?;
        let reader = pipes.attach(owner, token, PipeDirection::Reader)?;
        let writer = pipes.attach(owner, token, PipeDirection::Writer)?;
        pipes.close_owner(owner, token, PipeDirection::Reader)?;
        pipes.close_owner(owner, token, PipeDirection::Writer)?;

        let block = vec![0x5a; pipe::MIN_CAPACITY];
        assert_eq!(pipes.write_endpoint(writer, &block)?, block.len());
        assert_eq!(
            pipes.write_endpoint(writer, b"x"),
            Err(ProcessError::WouldBlock)
        );
        let mut destination = vec![0; pipe::MIN_CAPACITY];
        assert_eq!(
            pipes.read_endpoint(reader, &mut destination)?,
            destination.len()
        );
        assert_eq!(destination, block);
        pipes.detach(writer)?;
        assert_eq!(pipes.read_endpoint(reader, &mut destination)?, 0);
        pipes.detach(reader)?;
        assert_eq!(pipes.reserved_bytes(), 0);
        const { assert!(MAX_PIPE_BYTES_PER_OWNER >= pipe::MIN_CAPACITY) };
        Ok(())
    }
}

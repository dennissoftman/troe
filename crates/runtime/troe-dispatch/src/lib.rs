//! Bounded handles, ports, and synchronous in-process request/reply dispatch.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;
use core::str;
use troe_abi::{MAX_SERVICE_PAYLOAD_BYTES, command, stream};
use troe_core::{BoundedOutput, Output, StreamError, write_all};

/// Hard ceiling for one request or reply payload.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
/// Hard ceiling for registered service ports.
pub const MAX_PORTS: usize = 65_536;
/// Hard ceiling for live client handles.
pub const MAX_HANDLES: usize = 262_144;

const INITIAL_DISPATCH_CAPACITY: usize = 64;

/// Opaque generation-checked service endpoint identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortId {
    slot: u32,
    generation: u32,
}

/// Opaque generation-checked authority to call one service port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    slot: u32,
    generation: u32,
}

impl Handle {
    /// Stable opaque value exported through the application ABI.
    ///
    /// The low 32 bits encode a one-based slot and the high bits encode its
    /// generation. Applications must treat the result as an indivisible token.
    #[must_use]
    pub const fn abi_value(self) -> u64 {
        ((self.generation as u64) << 32) | (self.slot as u64 + 1)
    }

    /// Decode a stable ABI token without granting or validating authority.
    ///
    /// # Errors
    ///
    /// Rejects zero, non-canonical high bits, a zero generation, or an encoded
    /// slot outside the dispatcher hard ceiling.
    pub fn from_abi_value(value: u64) -> Result<Self, DispatchError> {
        let encoded_slot = value & u64::from(u32::MAX);
        let generation = value >> 32;
        if encoded_slot == 0 || encoded_slot > MAX_HANDLES as u64 || generation == 0 {
            return Err(DispatchError::InvalidHandle);
        }
        let slot = u32::try_from(encoded_slot).map_err(|_| DispatchError::InvalidHandle)?;
        let generation = u32::try_from(generation).map_err(|_| DispatchError::InvalidHandle)?;
        Ok(Self {
            slot: slot - 1,
            generation,
        })
    }
}

/// Principal that owns one handle and must lose it during task teardown.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HandleOwner {
    /// Kernel-internal endpoint not tied to an isolated task lifetime.
    #[default]
    Kernel,
    /// Monotonic isolated-task identity supplied by the scheduler.
    IsolatedTask(u32),
}

impl HandleOwner {
    /// Construct an isolated owner from a nonzero monotonic task identity.
    ///
    /// # Errors
    ///
    /// Rejects zero, which is reserved and never assigned by the scheduler.
    pub const fn isolated(task_id: u32) -> Result<Self, DispatchError> {
        if task_id == 0 {
            return Err(DispatchError::InvalidOwner);
        }
        Ok(Self::IsolatedTask(task_id))
    }
}

/// Immutable, kernel-owned copy made at an untrusted address-space boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopiedMessage {
    bytes: Vec<u8>,
}

impl CopiedMessage {
    /// Copy a complete bounded message into kernel-owned storage.
    ///
    /// # Errors
    ///
    /// Rejects oversize input or allocation failure without retaining a
    /// partial message.
    pub fn copy_from_untrusted(bytes: &[u8]) -> Result<Self, DispatchError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(DispatchError::MessageTooLarge);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| DispatchError::MetadataExhausted)?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned })
    }

    /// Copied message bytes, independent of the source address space.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Rights attached to a client handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rights(u8);

impl Rights {
    /// No operation is authorized.
    pub const NONE: Self = Self(0);
    /// Synchronous request/reply calls are authorized.
    pub const CALL: Self = Self(1 << 0);

    /// Combine two rights sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every requested right is present.
    #[must_use]
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }

    /// Fixed ABI bit representation carried by an initial handle descriptor.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0 as u32
    }
}

/// Stable service-level result carried by every successful dispatch reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ReplyStatus {
    /// The requested operation completed.
    Success = 0,
    /// The opcode or payload is invalid for the service.
    InvalidRequest = 1,
    /// The requested service object does not exist.
    NotFound = 2,
    /// The service could not complete the operation.
    Failure = 3,
    /// A bounded service resource is exhausted.
    Exhausted = 4,
    /// Required network configuration is absent.
    NotConfigured = 5,
    /// Cooperative work was cancelled.
    Cancelled = 6,
    /// A bounded wait expired.
    Timeout = 7,
    /// The requested resource has another owner.
    Conflict = 8,
    /// A service-domain payload ceiling was exceeded.
    TooLarge = 9,
    /// A path or namespace request is syntactically invalid.
    InvalidPath = 10,
    /// A file was used as a directory or the reverse.
    WrongType = 11,
    /// Mutation targeted immutable filesystem content.
    ReadOnly = 12,
    /// A filesystem quota is exhausted.
    NoSpace = 13,
    /// A filesystem object already exists.
    Exists = 14,
    /// Filesystem metadata is corrupt.
    Corrupt = 15,
    /// The filesystem transport failed.
    Io = 16,
    /// The filesystem requires an unsupported feature.
    Unsupported = 17,
    /// Filesystem arithmetic overflowed.
    Overflow = 18,
    /// A network exchange returned an invalid protocol response.
    NetworkProtocol = 19,
    /// The caller lacks authority for the requested operation.
    Denied = 20,
    /// A directory still contains entries.
    NotEmpty = 21,
    /// A name operation crossed filesystem-provider boundaries.
    CrossDevice = 22,
    /// A configured resource-policy ceiling was reached.
    ResourceLimit = 23,
}

impl ReplyStatus {
    /// Stable fixed-width value returned by the application ABI.
    #[must_use]
    pub const fn abi_value(self) -> u32 {
        self as u32
    }

    /// Decode one stable application-ABI reply value.
    #[must_use]
    pub const fn from_abi_value(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::InvalidRequest),
            2 => Some(Self::NotFound),
            3 => Some(Self::Failure),
            4 => Some(Self::Exhausted),
            5 => Some(Self::NotConfigured),
            6 => Some(Self::Cancelled),
            7 => Some(Self::Timeout),
            8 => Some(Self::Conflict),
            9 => Some(Self::TooLarge),
            10 => Some(Self::InvalidPath),
            11 => Some(Self::WrongType),
            12 => Some(Self::ReadOnly),
            13 => Some(Self::NoSpace),
            14 => Some(Self::Exists),
            15 => Some(Self::Corrupt),
            16 => Some(Self::Io),
            17 => Some(Self::Unsupported),
            18 => Some(Self::Overflow),
            19 => Some(Self::NetworkProtocol),
            20 => Some(Self::Denied),
            21 => Some(Self::NotEmpty),
            22 => Some(Self::CrossDevice),
            23 => Some(Self::ResourceLimit),
            _ => None,
        }
    }
}

/// Borrowed request delivered synchronously to one service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'a> {
    id: u64,
    opcode: u16,
    payload: &'a [u8],
}

impl<'a> Request<'a> {
    /// Monotonic identity copied into the corresponding reply.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Service-defined operation number.
    #[must_use]
    pub const fn opcode(self) -> u16 {
        self.opcode
    }

    /// Immutable request bytes, valid only for this synchronous call.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// Service-produced bounded reply before request identity is attached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceReply {
    status: ReplyStatus,
    payload: Vec<u8>,
}

/// Bounded service completion written directly into caller-owned storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceReplyInfo {
    status: ReplyStatus,
    payload_bytes: usize,
    payload_copies: u64,
    payload_allocations: u64,
}

impl ServiceReplyInfo {
    /// Describe an empty completion without a copy or allocation.
    #[must_use]
    pub const fn empty(status: ReplyStatus) -> Self {
        Self {
            status,
            payload_bytes: 0,
            payload_copies: 0,
            payload_allocations: 0,
        }
    }

    /// Describe a non-empty completion copied once into caller-owned storage.
    ///
    /// The service must have initialized exactly `payload_bytes` bytes of the
    /// destination supplied to [`Service::call_into`].
    #[must_use]
    pub const fn copied(status: ReplyStatus, payload_bytes: usize) -> Self {
        Self {
            status,
            payload_bytes,
            payload_copies: if payload_bytes == 0 { 0 } else { 1 },
            payload_allocations: 0,
        }
    }

    /// Stable service-level result.
    #[must_use]
    pub const fn status(self) -> ReplyStatus {
        self.status
    }

    /// Initialized prefix length in the supplied destination.
    #[must_use]
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

impl ServiceReply {
    /// Construct an empty service reply.
    #[must_use]
    pub const fn empty(status: ReplyStatus) -> Self {
        Self {
            status,
            payload: Vec::new(),
        }
    }

    /// Stable service-level result.
    #[must_use]
    pub const fn status(&self) -> ReplyStatus {
        self.status
    }

    /// Owned bounded reply bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Copy bounded reply bytes into an owned response.
    ///
    /// # Errors
    ///
    /// Rejects the hard message bound or fallible allocation failure.
    pub fn with_payload(status: ReplyStatus, payload: &[u8]) -> Result<Self, DispatchError> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(DispatchError::MessageTooLarge);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(payload.len())
            .map_err(|_| DispatchError::MetadataExhausted)?;
        owned.extend_from_slice(payload);
        Ok(Self {
            status,
            payload: owned,
        })
    }
}

/// Complete bounded reply returned to a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    request_id: u64,
    status: ReplyStatus,
    payload: Vec<u8>,
}

/// Complete bounded reply retained in caller-owned storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyInfo {
    request_id: u64,
    status: ReplyStatus,
    payload_bytes: usize,
}

impl ReplyInfo {
    /// Identity of the request that produced this reply.
    #[must_use]
    pub const fn request_id(self) -> u64 {
        self.request_id
    }

    /// Stable service-level result.
    #[must_use]
    pub const fn status(self) -> ReplyStatus {
        self.status
    }

    /// Initialized prefix length in the caller-owned destination.
    #[must_use]
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

impl Reply {
    /// Identity of the request that produced this reply.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Stable service-level result.
    #[must_use]
    pub const fn status(&self) -> ReplyStatus {
        self.status
    }

    /// Owned reply bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// One synchronous in-process service endpoint.
pub trait Service {
    /// Handle a complete borrowed request and return one owned bounded reply.
    ///
    /// # Errors
    ///
    /// Returns a dispatcher error when reply construction cannot satisfy its
    /// resource bounds. Service-domain failures belong in [`ReplyStatus`].
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError>;

    /// Handle one request using bounded caller-owned reply storage.
    ///
    /// The default preserves compatibility with owned service replies. A
    /// service with a naturally caller-directed encoder can override this to
    /// remove the intermediate allocation and copy.
    ///
    /// # Errors
    ///
    /// Returns the same mechanism failures as [`Self::call`] and rejects a
    /// reply that does not fit `destination`.
    fn call_into(
        &mut self,
        request: Request<'_>,
        destination: &mut [u8],
    ) -> Result<ServiceReplyInfo, DispatchError> {
        let reply = self.call(request)?;
        if reply.payload.len() > destination.len() {
            return Err(DispatchError::MessageTooLarge);
        }
        let payload_bytes = reply.payload.len();
        destination[..payload_bytes].copy_from_slice(&reply.payload);
        let nonempty = u64::from(payload_bytes != 0);
        Ok(ServiceReplyInfo {
            status: reply.status,
            payload_bytes,
            payload_copies: nonempty
                .checked_mul(2)
                .ok_or(DispatchError::AccountingOverflow)?,
            payload_allocations: nonempty,
        })
    }
}

/// Dispatcher mechanism and resource failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError {
    /// A configured table bound is zero or exceeds its hard ceiling.
    InvalidCapacity,
    /// A zero or otherwise reserved task owner was supplied.
    InvalidOwner,
    /// Bounded metadata allocation failed.
    MetadataExhausted,
    /// No reusable port slot remains.
    PortCapacityExhausted,
    /// No reusable handle slot remains.
    HandleCapacityExhausted,
    /// A request or reply exceeds [`MAX_MESSAGE_BYTES`].
    MessageTooLarge,
    /// A stale, closed, or foreign handle was supplied.
    InvalidHandle,
    /// A stale, closed, or foreign port was supplied.
    InvalidPort,
    /// The handle lacks the requested operation right.
    PermissionDenied,
    /// A monotonic request or accounting counter overflowed.
    AccountingOverflow,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("dispatch capacity is invalid"),
            Self::InvalidOwner => formatter.write_str("handle owner is invalid"),
            Self::MetadataExhausted => formatter.write_str("dispatch metadata allocation failed"),
            Self::PortCapacityExhausted => formatter.write_str("service port capacity exhausted"),
            Self::HandleCapacityExhausted => {
                formatter.write_str("service handle capacity exhausted")
            }
            Self::MessageTooLarge => formatter.write_str("message payload exceeds its bound"),
            Self::InvalidHandle => formatter.write_str("service handle is invalid"),
            Self::InvalidPort => formatter.write_str("service port is invalid"),
            Self::PermissionDenied => formatter.write_str("service handle right denied"),
            Self::AccountingOverflow => formatter.write_str("dispatch accounting overflowed"),
        }
    }
}

struct PortSlot<'service> {
    generation: u32,
    retired: bool,
    service: Option<Box<dyn Service + 'service>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandleBinding {
    port: PortId,
    rights: Rights,
    owner: HandleOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandleSlot {
    generation: u32,
    retired: bool,
    binding: Option<HandleBinding>,
}

/// Aggregate live-resource and request/reply accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchStats {
    /// Currently registered service ports.
    pub live_ports: u32,
    /// Currently live client handles.
    pub live_handles: u32,
    /// Calls successfully delivered to a service.
    pub calls: u64,
    /// Replies successfully returned to clients.
    pub replies: u64,
    /// Bytes borrowed directly from callers for delivered requests.
    pub request_bytes: u64,
    /// Request payload copies performed by this in-process dispatcher.
    ///
    /// This remains zero because [`Request`] borrows the caller's payload.
    pub request_payload_copies: u64,
    /// Request payload allocations performed by this in-process dispatcher.
    ///
    /// This remains zero because [`Request`] borrows the caller's payload.
    pub request_payload_allocations: u64,
    /// Owned reply payload bytes successfully returned to clients.
    pub reply_bytes: u64,
    /// Non-empty reply payload copies completed by [`ServiceReply::with_payload`].
    pub reply_payload_copies: u64,
    /// Non-empty reply buffer allocations completed by
    /// [`ServiceReply::with_payload`].
    pub reply_payload_allocations: u64,
}

/// Bounded synchronous in-process service router.
///
/// Requests borrow their payload only for the duration of [`Self::call`]. A
/// call either returns one owned reply or a typed mechanism failure. There is no
/// queued or cancellable state: closing before delivery invalidates a handle,
/// while closing during a synchronous call is impossible through the exclusive
/// dispatcher borrow. Stage 6 additionally revokes handles by task owner.
pub struct Dispatcher<'service> {
    ports: Vec<PortSlot<'service>>,
    handles: Vec<HandleSlot>,
    port_capacity: usize,
    handle_capacity: usize,
    next_request_id: u64,
    calls: u64,
    replies: u64,
    request_bytes: u64,
    reply_bytes: u64,
    reply_payload_copies: u64,
    reply_payload_allocations: u64,
}

impl<'service> Dispatcher<'service> {
    /// Construct dispatcher tables with immutable capacities.
    ///
    /// # Errors
    ///
    /// Rejects zero or over-ceiling capacities and fallible allocation failure.
    pub fn new(port_capacity: usize, handle_capacity: usize) -> Result<Self, DispatchError> {
        if port_capacity == 0
            || port_capacity > MAX_PORTS
            || handle_capacity == 0
            || handle_capacity > MAX_HANDLES
        {
            return Err(DispatchError::InvalidCapacity);
        }
        let mut ports = Vec::new();
        ports
            .try_reserve_exact(port_capacity.min(INITIAL_DISPATCH_CAPACITY))
            .map_err(|_| DispatchError::MetadataExhausted)?;
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(handle_capacity.min(INITIAL_DISPATCH_CAPACITY))
            .map_err(|_| DispatchError::MetadataExhausted)?;
        Ok(Self {
            ports,
            handles,
            port_capacity,
            handle_capacity,
            next_request_id: 1,
            calls: 0,
            replies: 0,
            request_bytes: 0,
            reply_bytes: 0,
            reply_payload_copies: 0,
            reply_payload_allocations: 0,
        })
    }

    /// Register a service port and return its first client handle.
    ///
    /// # Errors
    ///
    /// Rejects exhausted port or handle tables.
    pub fn register(
        &mut self,
        service: Box<dyn Service + 'service>,
        rights: Rights,
    ) -> Result<(PortId, Handle), DispatchError> {
        let port = self.allocate_port(service)?;
        match self.open(port, rights) {
            Ok(handle) => Ok((port, handle)),
            Err(error) => {
                let _closed = self.close_port(port);
                Err(error)
            }
        }
    }

    /// Mint another explicitly scoped handle to a live port.
    ///
    /// # Errors
    ///
    /// Rejects a stale port or exhausted handle table.
    pub fn open(&mut self, port: PortId, rights: Rights) -> Result<Handle, DispatchError> {
        self.open_owned(port, rights, HandleOwner::Kernel)
    }

    /// Mint an explicitly owned handle to a live port.
    ///
    /// Isolated ownership lets teardown revoke every authority retained by one
    /// task even when copies of opaque handle values still exist.
    ///
    /// # Errors
    ///
    /// Rejects a stale port, invalid owner, or exhausted handle table.
    pub fn open_owned(
        &mut self,
        port: PortId,
        rights: Rights,
        owner: HandleOwner,
    ) -> Result<Handle, DispatchError> {
        if matches!(owner, HandleOwner::IsolatedTask(0)) {
            return Err(DispatchError::InvalidOwner);
        }
        self.validate_port(port)?;
        if let Some((index, slot)) = self
            .handles
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.binding.is_none() && !slot.retired)
        {
            slot.binding = Some(HandleBinding {
                port,
                rights,
                owner,
            });
            return Ok(Handle {
                slot: u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
                generation: slot.generation,
            });
        }
        if self.handles.len() == self.handle_capacity {
            return Err(DispatchError::HandleCapacityExhausted);
        }
        self.handles
            .try_reserve(1)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        let index = self.handles.len();
        self.handles.push(HandleSlot {
            generation: 1,
            retired: false,
            binding: Some(HandleBinding {
                port,
                rights,
                owner,
            }),
        });
        Ok(Handle {
            slot: u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
            generation: 1,
        })
    }

    /// Close one handle and invalidate every copy of its identity.
    ///
    /// # Errors
    ///
    /// Rejects a stale, closed, or foreign handle.
    pub fn close(&mut self, handle: Handle) -> Result<(), DispatchError> {
        let slot = self.handle_slot_mut(handle)?;
        slot.binding = None;
        match slot.generation.checked_add(1) {
            Some(generation) => slot.generation = generation,
            None => slot.retired = true,
        }
        Ok(())
    }

    /// Revoke every live handle owned by one isolated task.
    ///
    /// Each matching slot advances its generation before this method returns,
    /// so all outstanding copied values fail closed. Kernel-owned and other
    /// tasks' handles are unchanged.
    ///
    /// # Errors
    ///
    /// Rejects a non-task owner or a revocation count that cannot be represented.
    pub fn close_owner(&mut self, owner: HandleOwner) -> Result<u16, DispatchError> {
        if !matches!(owner, HandleOwner::IsolatedTask(id) if id != 0) {
            return Err(DispatchError::InvalidOwner);
        }
        let matching = self
            .handles
            .iter()
            .filter(|slot| slot.binding.is_some_and(|binding| binding.owner == owner))
            .count();
        let matching = u16::try_from(matching).map_err(|_| DispatchError::AccountingOverflow)?;
        for slot in &mut self.handles {
            if slot.binding.is_some_and(|binding| binding.owner == owner) {
                slot.binding = None;
                match slot.generation.checked_add(1) {
                    Some(generation) => slot.generation = generation,
                    None => slot.retired = true,
                }
            }
        }
        Ok(matching)
    }

    /// Close a service port and every handle bound to it.
    ///
    /// # Errors
    ///
    /// Rejects a stale, closed, or foreign port.
    pub fn close_port(&mut self, port: PortId) -> Result<(), DispatchError> {
        self.validate_port(port)?;
        for slot in &mut self.handles {
            if slot.binding.is_some_and(|binding| binding.port == port) {
                slot.binding = None;
                match slot.generation.checked_add(1) {
                    Some(generation) => slot.generation = generation,
                    None => slot.retired = true,
                }
            }
        }
        let index = usize::try_from(port.slot).map_err(|_| DispatchError::InvalidPort)?;
        let slot = self
            .ports
            .get_mut(index)
            .ok_or(DispatchError::InvalidPort)?;
        slot.service = None;
        match slot.generation.checked_add(1) {
            Some(generation) => slot.generation = generation,
            None => slot.retired = true,
        }
        Ok(())
    }

    /// Deliver one bounded request and synchronously return its matching reply.
    ///
    /// # Errors
    ///
    /// Rejects oversized payloads, invalid authority, stale endpoints, service
    /// reply construction failures, or checked accounting overflow.
    pub fn call(
        &mut self,
        handle: Handle,
        opcode: u16,
        payload: &[u8],
    ) -> Result<Reply, DispatchError> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(DispatchError::MessageTooLarge);
        }
        let binding = self.handle_binding(handle)?;
        if !binding.rights.contains(Rights::CALL) {
            return Err(DispatchError::PermissionDenied);
        }
        self.validate_port(binding.port)?;
        let request_id = self.next_request_id;
        let next_request_id = request_id
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let calls = self
            .calls
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let request_bytes = self
            .request_bytes
            .checked_add(
                u64::try_from(payload.len()).map_err(|_| DispatchError::AccountingOverflow)?,
            )
            .ok_or(DispatchError::AccountingOverflow)?;
        let request = Request {
            id: request_id,
            opcode,
            payload,
        };
        self.next_request_id = next_request_id;
        self.calls = calls;
        self.request_bytes = request_bytes;
        let port_index =
            usize::try_from(binding.port.slot).map_err(|_| DispatchError::InvalidPort)?;
        let service = self
            .ports
            .get_mut(port_index)
            .and_then(|slot| slot.service.as_mut())
            .ok_or(DispatchError::InvalidPort)?;
        let service_reply = service.call(request)?;
        if service_reply.payload.len() > MAX_MESSAGE_BYTES {
            return Err(DispatchError::MessageTooLarge);
        }
        let replies = self
            .replies
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let reply_bytes = self
            .reply_bytes
            .checked_add(
                u64::try_from(service_reply.payload.len())
                    .map_err(|_| DispatchError::AccountingOverflow)?,
            )
            .ok_or(DispatchError::AccountingOverflow)?;
        let reply_payload_copies = self
            .reply_payload_copies
            .checked_add(u64::from(!service_reply.payload.is_empty()))
            .ok_or(DispatchError::AccountingOverflow)?;
        let reply_payload_allocations = self
            .reply_payload_allocations
            .checked_add(u64::from(!service_reply.payload.is_empty()))
            .ok_or(DispatchError::AccountingOverflow)?;
        self.replies = replies;
        self.reply_bytes = reply_bytes;
        self.reply_payload_copies = reply_payload_copies;
        self.reply_payload_allocations = reply_payload_allocations;
        Ok(Reply {
            request_id,
            status: service_reply.status,
            payload: service_reply.payload,
        })
    }

    /// Deliver one ABI call and write its bounded reply into caller-owned
    /// storage only when the handle remains owned by the supplied task.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, foreign, or insufficient-rights handles,
    /// insufficient destination storage, service failures, and counter
    /// overflow before returning a partial completion.
    pub fn call_owned_abi_into(
        &mut self,
        owner: HandleOwner,
        value: u64,
        opcode: u16,
        payload: &[u8],
        destination: &mut [u8],
    ) -> Result<ReplyInfo, DispatchError> {
        if !matches!(owner, HandleOwner::IsolatedTask(id) if id != 0) {
            return Err(DispatchError::InvalidOwner);
        }
        let handle = Handle::from_abi_value(value)?;
        if self.handle_binding(handle)?.owner != owner {
            return Err(DispatchError::InvalidHandle);
        }
        self.call_into(handle, opcode, payload, destination)
    }

    /// Deliver one ABI call only when the opaque handle remains owned by the
    /// supplied isolated task.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, foreign, or insufficient-rights handles
    /// before service delivery, in addition to the ordinary call failures.
    pub fn call_owned_abi(
        &mut self,
        owner: HandleOwner,
        value: u64,
        opcode: u16,
        payload: &[u8],
    ) -> Result<Reply, DispatchError> {
        if !matches!(owner, HandleOwner::IsolatedTask(id) if id != 0) {
            return Err(DispatchError::InvalidOwner);
        }
        let handle = Handle::from_abi_value(value)?;
        if self.handle_binding(handle)?.owner != owner {
            return Err(DispatchError::InvalidHandle);
        }
        self.call(handle, opcode, payload)
    }

    /// Snapshot live endpoint and completed request/reply counters.
    #[must_use]
    pub fn stats(&self) -> DispatchStats {
        let live_ports = self
            .ports
            .iter()
            .filter(|slot| slot.service.is_some())
            .count();
        let live_handles = self
            .handles
            .iter()
            .filter(|slot| slot.binding.is_some())
            .count();
        DispatchStats {
            live_ports: u32::try_from(live_ports).unwrap_or(u32::MAX),
            live_handles: u32::try_from(live_handles).unwrap_or(u32::MAX),
            calls: self.calls,
            replies: self.replies,
            request_bytes: self.request_bytes,
            request_payload_copies: 0,
            request_payload_allocations: 0,
            reply_bytes: self.reply_bytes,
            reply_payload_copies: self.reply_payload_copies,
            reply_payload_allocations: self.reply_payload_allocations,
        }
    }

    fn call_into(
        &mut self,
        handle: Handle,
        opcode: u16,
        payload: &[u8],
        destination: &mut [u8],
    ) -> Result<ReplyInfo, DispatchError> {
        if payload.len() > MAX_MESSAGE_BYTES || destination.len() > MAX_MESSAGE_BYTES {
            return Err(DispatchError::MessageTooLarge);
        }
        let binding = self.handle_binding(handle)?;
        if !binding.rights.contains(Rights::CALL) {
            return Err(DispatchError::PermissionDenied);
        }
        self.validate_port(binding.port)?;
        let request_id = self.next_request_id;
        let next_request_id = request_id
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let calls = self
            .calls
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let request_bytes = self
            .request_bytes
            .checked_add(
                u64::try_from(payload.len()).map_err(|_| DispatchError::AccountingOverflow)?,
            )
            .ok_or(DispatchError::AccountingOverflow)?;
        let request = Request {
            id: request_id,
            opcode,
            payload,
        };
        self.next_request_id = next_request_id;
        self.calls = calls;
        self.request_bytes = request_bytes;
        let port_index =
            usize::try_from(binding.port.slot).map_err(|_| DispatchError::InvalidPort)?;
        let service = self
            .ports
            .get_mut(port_index)
            .and_then(|slot| slot.service.as_mut())
            .ok_or(DispatchError::InvalidPort)?;
        let service_reply = service.call_into(request, destination)?;
        if service_reply.payload_bytes > destination.len()
            || service_reply.payload_bytes > MAX_MESSAGE_BYTES
        {
            return Err(DispatchError::MessageTooLarge);
        }
        let replies = self
            .replies
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let reply_bytes = self
            .reply_bytes
            .checked_add(
                u64::try_from(service_reply.payload_bytes)
                    .map_err(|_| DispatchError::AccountingOverflow)?,
            )
            .ok_or(DispatchError::AccountingOverflow)?;
        let reply_payload_copies = self
            .reply_payload_copies
            .checked_add(service_reply.payload_copies)
            .ok_or(DispatchError::AccountingOverflow)?;
        let reply_payload_allocations = self
            .reply_payload_allocations
            .checked_add(service_reply.payload_allocations)
            .ok_or(DispatchError::AccountingOverflow)?;
        self.replies = replies;
        self.reply_bytes = reply_bytes;
        self.reply_payload_copies = reply_payload_copies;
        self.reply_payload_allocations = reply_payload_allocations;
        Ok(ReplyInfo {
            request_id,
            status: service_reply.status,
            payload_bytes: service_reply.payload_bytes,
        })
    }

    fn allocate_port(
        &mut self,
        service: Box<dyn Service + 'service>,
    ) -> Result<PortId, DispatchError> {
        if let Some((index, slot)) = self
            .ports
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.service.is_none() && !slot.retired)
        {
            slot.service = Some(service);
            return Ok(PortId {
                slot: u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
                generation: slot.generation,
            });
        }
        if self.ports.len() == self.port_capacity {
            return Err(DispatchError::PortCapacityExhausted);
        }
        self.ports
            .try_reserve(1)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        let index = self.ports.len();
        self.ports.push(PortSlot {
            generation: 1,
            retired: false,
            service: Some(service),
        });
        Ok(PortId {
            slot: u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
            generation: 1,
        })
    }

    fn validate_port(&self, port: PortId) -> Result<(), DispatchError> {
        let slot = self
            .ports
            .get(usize::try_from(port.slot).map_err(|_| DispatchError::InvalidPort)?)
            .ok_or(DispatchError::InvalidPort)?;
        if slot.generation != port.generation || slot.service.is_none() {
            return Err(DispatchError::InvalidPort);
        }
        Ok(())
    }

    fn handle_binding(&self, handle: Handle) -> Result<HandleBinding, DispatchError> {
        let slot = self
            .handles
            .get(usize::try_from(handle.slot).map_err(|_| DispatchError::InvalidHandle)?)
            .ok_or(DispatchError::InvalidHandle)?;
        if slot.generation != handle.generation {
            return Err(DispatchError::InvalidHandle);
        }
        slot.binding.ok_or(DispatchError::InvalidHandle)
    }

    fn handle_slot_mut(&mut self, handle: Handle) -> Result<&mut HandleSlot, DispatchError> {
        let slot = self
            .handles
            .get_mut(usize::try_from(handle.slot).map_err(|_| DispatchError::InvalidHandle)?)
            .ok_or(DispatchError::InvalidHandle)?;
        if slot.generation != handle.generation || slot.binding.is_none() {
            return Err(DispatchError::InvalidHandle);
        }
        Ok(slot)
    }
}

/// Immutable command-invocation service for one application launch.
///
/// Arguments are retained once as a flat UTF-8 table with a parallel length
/// table. That representation serves both the single-message record of
/// interface 1.1 and the paged reads of 1.2 without a second copy, and without
/// one owned `String` allocation per argument.
pub struct CommandInvocationService {
    invocation: Option<Vec<u8>>,
    environment: Vec<u8>,
    argument_bytes: Vec<u8>,
    argument_lengths: Vec<u16>,
}

impl CommandInvocationService {
    /// Encode one canonical current-directory and argument record.
    ///
    /// # Errors
    ///
    /// Rejects invocation-policy excess or bounded allocation failure.
    pub fn new<T: AsRef<str>>(cwd: &str, arguments: &[T]) -> Result<Self, DispatchError> {
        Self::new_with_environment(cwd, arguments, &[])
    }

    /// Encode one invocation and its immutable `NAME=VALUE` environment.
    ///
    /// An argument vector that exceeds the single-message bounds of interface
    /// 1.1 is still accepted and is readable only page by page. `GET_INVOCATION`
    /// then fails closed rather than returning a prefix of the operands.
    ///
    /// # Errors
    ///
    /// Rejects invocation/environment policy excess or bounded allocation failure.
    pub fn new_with_environment<T: AsRef<str>>(
        cwd: &str,
        arguments: &[T],
        environment: &[&str],
    ) -> Result<Self, DispatchError> {
        if !(1..=command::MAX_PAGED_ARGUMENTS).contains(&arguments.len()) {
            return Err(DispatchError::MessageTooLarge);
        }
        let mut argument_bytes = Vec::new();
        let mut argument_lengths = Vec::new();
        argument_lengths
            .try_reserve_exact(arguments.len())
            .map_err(|_| DispatchError::MetadataExhausted)?;
        let mut aggregate = 0_usize;
        for (index, argument) in arguments.iter().enumerate() {
            let value = argument.as_ref();
            if value.len() > command::MAX_SINGLE_ARGUMENT_BYTES || (index == 0 && value.is_empty())
            {
                return Err(DispatchError::MessageTooLarge);
            }
            aggregate = aggregate
                .checked_add(value.len())
                .ok_or(DispatchError::MessageTooLarge)?;
            if aggregate > command::MAX_PAGED_ARGUMENT_BYTES {
                return Err(DispatchError::MessageTooLarge);
            }
            argument_bytes
                .try_reserve(value.len())
                .map_err(|_| DispatchError::MetadataExhausted)?;
            argument_bytes.extend_from_slice(value.as_bytes());
            argument_lengths
                .push(u16::try_from(value.len()).map_err(|_| DispatchError::MessageTooLarge)?);
        }

        let mut encoded = [0_u8; command::MAX_INVOCATION_BYTES];
        let invocation = match command::encode(cwd, arguments, &mut encoded) {
            Ok(count) => {
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(count)
                    .map_err(|_| DispatchError::MetadataExhausted)?;
                owned.extend_from_slice(&encoded[..count]);
                Some(owned)
            }
            Err(command::EncodeError::LimitExceeded)
                if arguments.len() > command::MAX_ARGUMENTS =>
            {
                None
            }
            Err(command::EncodeError::LimitExceeded) if aggregate > command::MAX_ARGUMENT_BYTES => {
                None
            }
            Err(_) => return Err(DispatchError::MessageTooLarge),
        };

        let mut encoded_environment = [0_u8; command::MAX_ENCODED_ENVIRONMENT_BYTES];
        let environment_count = command::encode_environment(environment, &mut encoded_environment)
            .map_err(|_| DispatchError::MessageTooLarge)?;
        let mut owned_environment = Vec::new();
        owned_environment
            .try_reserve_exact(environment_count)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        owned_environment.extend_from_slice(&encoded_environment[..environment_count]);
        Ok(Self {
            invocation,
            environment: owned_environment,
            argument_bytes,
            argument_lengths,
        })
    }

    /// Borrow one retained argument by its absolute index.
    fn argument(&self, wanted: usize) -> Option<&str> {
        let mut cursor = 0_usize;
        for (index, length) in self.argument_lengths.iter().enumerate() {
            let end = cursor.checked_add(usize::from(*length))?;
            if index == wanted {
                return str::from_utf8(self.argument_bytes.get(cursor..end)?).ok();
            }
            cursor = end;
        }
        None
    }
}

impl Service for CommandInvocationService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        match request.opcode() {
            command::GET_INVOCATION if request.payload().is_empty() => match &self.invocation {
                Some(invocation) => ServiceReply::with_payload(ReplyStatus::Success, invocation),
                None => Ok(ServiceReply::empty(ReplyStatus::TooLarge)),
            },
            command::GET_ENVIRONMENT if request.payload().is_empty() => {
                ServiceReply::with_payload(ReplyStatus::Success, &self.environment)
            }
            command::GET_ARGUMENT_PAGE => {
                let Ok(start) = command::decode_argument_page_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                if start > self.argument_lengths.len() {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                }
                let mut page = [0_u8; command::MAX_ARGUMENT_PAGE_REPLY_BYTES];
                let count = command::encode_argument_page_with(
                    self.argument_lengths.len(),
                    start,
                    |index| self.argument(index),
                    &mut page,
                )
                .map_err(|_| DispatchError::MessageTooLarge)?;
                ServiceReply::with_payload(ReplyStatus::Success, &page[..count])
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

/// Read-only byte service backed by one owned, bounded input snapshot.
pub struct ByteInputService {
    bytes: Vec<u8>,
    offset: usize,
}

impl ByteInputService {
    /// Own the complete input made available to one application.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl Service for ByteInputService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        if request.opcode() != stream::READ {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(requested) = stream::decode_read_request(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        let available = self.bytes.len().saturating_sub(self.offset);
        let count = requested.min(available).min(MAX_SERVICE_PAYLOAD_BYTES);
        let end = self
            .offset
            .checked_add(count)
            .ok_or(DispatchError::AccountingOverflow)?;
        let reply =
            ServiceReply::with_payload(ReplyStatus::Success, &self.bytes[self.offset..end])?;
        self.offset = end;
        Ok(reply)
    }
}

/// Shared bounded bytes retained after an output service is registered.
#[derive(Clone)]
pub struct SharedOutput {
    output: Rc<RefCell<BoundedOutput>>,
}

impl SharedOutput {
    /// Construct an empty output with one hard aggregate byte ceiling.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            output: Rc::new(RefCell::new(BoundedOutput::new(limit))),
        }
    }

    /// Copy all retained bytes to a caller-supplied output.
    ///
    /// # Errors
    ///
    /// Reports a conflicting service borrow or destination stream failure.
    pub fn copy_to(&self, destination: &mut dyn Output) -> Result<(), StreamError> {
        let retained = self.output.try_borrow().map_err(|_| StreamError::Device)?;
        write_all(destination, retained.as_slice())
    }

    /// Number of retained bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.output
            .try_borrow()
            .map_or(0, |output| output.as_slice().len())
    }

    /// Whether no bytes were retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Write-only byte-stream service retaining output in [`SharedOutput`].
pub struct ByteOutputService {
    output: SharedOutput,
}

impl ByteOutputService {
    /// Bind a service to shared retained output.
    #[must_use]
    pub const fn new(output: SharedOutput) -> Self {
        Self { output }
    }
}

impl Service for ByteOutputService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        if request.opcode() != stream::WRITE
            || request.payload().is_empty()
            || request.payload().len() > MAX_SERVICE_PAYLOAD_BYTES
        {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(mut output) = self.output.output.try_borrow_mut() else {
            return Ok(ServiceReply::empty(ReplyStatus::Failure));
        };
        let status = if write_all(&mut *output, request.payload()).is_ok() {
            ReplyStatus::Success
        } else {
            ReplyStatus::Failure
        };
        Ok(ServiceReply::empty(status))
    }
}

/// Console-service opcode accepting raw bytes as the request payload.
pub const CONSOLE_WRITE: u16 = 1;

/// Service adapter exposing any [`Output`] implementation through dispatch.
pub struct ConsoleService<O> {
    output: O,
}

impl<O> ConsoleService<O> {
    /// Wrap a direct output implementation as a message-shaped service.
    #[must_use]
    pub const fn new(output: O) -> Self {
        Self { output }
    }
}

impl<O: Output> Service for ConsoleService<O> {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
        if request.opcode() != CONSOLE_WRITE {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let status = if write_all(&mut self.output, request.payload()).is_ok() {
            ReplyStatus::Success
        } else {
            ReplyStatus::Failure
        };
        Ok(ServiceReply::empty(status))
    }
}

/// Client adapter preserving the ordinary [`Output`] interface over dispatch.
pub struct DispatchedOutput<'dispatcher, 'service> {
    dispatcher: &'dispatcher mut Dispatcher<'service>,
    handle: Handle,
}

impl<'dispatcher, 'service> DispatchedOutput<'dispatcher, 'service> {
    /// Bind an output client to one explicitly supplied handle.
    #[must_use]
    pub const fn new(dispatcher: &'dispatcher mut Dispatcher<'service>, handle: Handle) -> Self {
        Self { dispatcher, handle }
    }
}

impl Output for DispatchedOutput<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = bytes.len().min(MAX_MESSAGE_BYTES);
        let reply = self
            .dispatcher
            .call(self.handle, CONSOLE_WRITE, &bytes[..count])
            .map_err(|_| StreamError::Device)?;
        if reply.status() != ReplyStatus::Success || !reply.payload().is_empty() {
            return Err(StreamError::Device);
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        ByteInputService, ByteOutputService, CommandInvocationService, ConsoleService,
        CopiedMessage, DispatchError, DispatchedOutput, Dispatcher, Handle, HandleOwner,
        MAX_MESSAGE_BYTES, ReplyStatus, Request, Rights, Service, ServiceReply, ServiceReplyInfo,
        SharedOutput as RetainedOutput,
    };
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use troe_abi::{command, stream};
    use troe_core::{BoundedOutput, Output, StreamError, write_all};

    struct EchoService;

    impl Service for EchoService {
        fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
            if request.opcode() == 7 {
                ServiceReply::with_payload(ReplyStatus::Success, request.payload())
            } else {
                Ok(ServiceReply::empty(ReplyStatus::InvalidRequest))
            }
        }
    }

    struct DirectEchoService;

    impl Service for DirectEchoService {
        fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
            ServiceReply::with_payload(ReplyStatus::Success, request.payload())
        }

        fn call_into(
            &mut self,
            request: Request<'_>,
            destination: &mut [u8],
        ) -> Result<ServiceReplyInfo, DispatchError> {
            if request.payload().len() > destination.len() {
                return Err(DispatchError::MessageTooLarge);
            }
            destination[..request.payload().len()].copy_from_slice(request.payload());
            Ok(ServiceReplyInfo::copied(
                ReplyStatus::Success,
                request.payload().len(),
            ))
        }
    }

    #[test]
    fn an_oversized_argument_record_is_paged_and_never_returned_in_part() {
        // An operand list far larger than one single-message record.
        let mut arguments = alloc::vec::Vec::new();
        arguments.push(alloc::string::String::from("rm"));
        for index in 0..1000 {
            arguments.push(alloc::format!("operand-{index:04}.txt"));
        }
        let mut dispatcher = Dispatcher::new(4, 4).unwrap_or_else(|_| std::process::abort());
        let (_port, handle) = dispatcher
            .register(
                Box::new(
                    CommandInvocationService::new("/work", &arguments)
                        .unwrap_or_else(|_| std::process::abort()),
                ),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());

        // The single-message operation fails closed rather than truncating.
        assert_eq!(
            dispatcher
                .call(handle, command::GET_INVOCATION, &[])
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::TooLarge
        );

        let mut seen = Vec::new();
        let mut start = 0_usize;
        loop {
            let mut request = [0_u8; command::ARGUMENT_PAGE_REQUEST_BYTES];
            let count = command::encode_argument_page_request(start, &mut request)
                .unwrap_or_else(|_| std::process::abort());
            let reply = dispatcher
                .call(handle, command::GET_ARGUMENT_PAGE, &request[..count])
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(reply.status(), ReplyStatus::Success);
            let page = command::ArgumentPage::parse(reply.payload())
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(page.total(), arguments.len());
            if page.is_empty() {
                break;
            }
            seen.extend(page.iter().map(alloc::string::ToString::to_string));
            start = page.next_start();
        }
        assert_eq!(seen, arguments);

        // A malformed or out-of-range page request is refused, not clamped.
        assert_eq!(
            dispatcher
                .call(handle, command::GET_ARGUMENT_PAGE, &[0])
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::InvalidRequest
        );
        let mut past = [0_u8; command::ARGUMENT_PAGE_REQUEST_BYTES];
        let count = command::encode_argument_page_request(arguments.len() + 1, &mut past)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            dispatcher
                .call(handle, command::GET_ARGUMENT_PAGE, &past[..count])
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::InvalidRequest
        );
    }

    #[test]
    fn a_record_within_the_single_message_bounds_serves_both_operations() {
        let mut dispatcher = Dispatcher::new(4, 4).unwrap_or_else(|_| std::process::abort());
        let (_port, handle) = dispatcher
            .register(
                Box::new(
                    CommandInvocationService::new("/work", &["cat", "alpha.txt"])
                        .unwrap_or_else(|_| std::process::abort()),
                ),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());
        let reply = dispatcher
            .call(handle, command::GET_INVOCATION, &[])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(reply.status(), ReplyStatus::Success);
        let mut request = [0_u8; command::ARGUMENT_PAGE_REQUEST_BYTES];
        let count = command::encode_argument_page_request(0, &mut request)
            .unwrap_or_else(|_| std::process::abort());
        let reply = dispatcher
            .call(handle, command::GET_ARGUMENT_PAGE, &request[..count])
            .unwrap_or_else(|_| std::process::abort());
        let page =
            command::ArgumentPage::parse(reply.payload()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            page.iter().collect::<Vec<_>>(),
            alloc::vec!["cat", "alpha.txt"]
        );
    }

    #[test]
    fn command_and_standard_stream_services_enforce_exact_protocols() {
        let mut dispatcher = Dispatcher::new(4, 4).unwrap_or_else(|_| std::process::abort());
        let (_command_port, command_handle) = dispatcher
            .register(
                Box::new(
                    CommandInvocationService::new("/work", &["echo", "ready"])
                        .unwrap_or_else(|_| std::process::abort()),
                ),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());
        let reply = dispatcher
            .call(command_handle, command::GET_INVOCATION, &[])
            .unwrap_or_else(|_| std::process::abort());
        let invocation =
            command::Invocation::parse(reply.payload()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(invocation.cwd(), "/work");
        assert_eq!(invocation.argument(1), Some("ready"));
        assert_eq!(
            dispatcher
                .call(command_handle, command::GET_INVOCATION, &[0])
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::InvalidRequest
        );

        let (_input_port, input_handle) = dispatcher
            .register(
                Box::new(ByteInputService::new(b"abcdef".to_vec())),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());
        let four = stream::encode_read_request(4).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            dispatcher
                .call(input_handle, stream::READ, &four)
                .unwrap_or_else(|_| std::process::abort())
                .payload(),
            b"abcd"
        );
        assert_eq!(
            dispatcher
                .call(input_handle, stream::READ, &four)
                .unwrap_or_else(|_| std::process::abort())
                .payload(),
            b"ef"
        );

        let retained = RetainedOutput::new(5);
        let (_output_port, output_handle) = dispatcher
            .register(
                Box::new(ByteOutputService::new(retained.clone())),
                Rights::CALL,
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            dispatcher
                .call(output_handle, stream::WRITE, b"hello")
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::Success
        );
        assert_eq!(
            dispatcher
                .call(output_handle, stream::WRITE, b"!")
                .unwrap_or_else(|_| std::process::abort())
                .status(),
            ReplyStatus::Failure
        );
        let mut copied = BoundedOutput::new(5);
        retained
            .copy_to(&mut copied)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(copied.as_slice(), b"hello");
    }

    struct FailOnceService {
        request_ids: Rc<RefCell<Vec<u64>>>,
    }

    impl Service for FailOnceService {
        fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
            let mut request_ids = self.request_ids.borrow_mut();
            request_ids.push(request.id());
            if request_ids.len() == 1 {
                Err(DispatchError::MetadataExhausted)
            } else {
                Ok(ServiceReply::empty(ReplyStatus::Success))
            }
        }
    }

    struct RecordingService {
        request_ids: Rc<RefCell<Vec<u64>>>,
    }

    impl Service for RecordingService {
        fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, DispatchError> {
            self.request_ids.borrow_mut().push(request.id());
            Ok(ServiceReply::empty(ReplyStatus::Success))
        }
    }

    #[derive(Clone)]
    struct SharedOutput(Rc<RefCell<Vec<u8>>>);

    impl Output for SharedOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    #[test]
    fn request_reply_ids_and_payloads_are_stable() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(2, 4)?;
        let (_port, handle) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        let first = dispatcher.call(handle, 7, b"alpha")?;
        let second = dispatcher.call(handle, 7, b"beta")?;

        assert_eq!(first.request_id(), 1);
        assert_eq!(first.status(), ReplyStatus::Success);
        assert_eq!(first.payload(), b"alpha");
        assert_eq!(second.request_id(), 2);
        assert_eq!(second.payload(), b"beta");
        let stats = dispatcher.stats();
        assert_eq!(stats.calls, 2);
        assert_eq!(stats.replies, 2);
        assert_eq!(stats.request_bytes, 9);
        assert_eq!(stats.request_payload_copies, 0);
        assert_eq!(stats.request_payload_allocations, 0);
        assert_eq!(stats.reply_bytes, 9);
        assert_eq!(stats.reply_payload_copies, 2);
        assert_eq!(stats.reply_payload_allocations, 2);
        Ok(())
    }

    #[test]
    fn empty_payloads_do_not_claim_a_copy_or_allocation() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (_port, handle) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;

        let reply = dispatcher.call(handle, 7, &[])?;

        assert!(reply.payload().is_empty());
        let stats = dispatcher.stats();
        assert_eq!(stats.calls, 1);
        assert_eq!(stats.replies, 1);
        assert_eq!(stats.request_bytes, 0);
        assert_eq!(stats.reply_bytes, 0);
        assert_eq!(stats.reply_payload_copies, 0);
        assert_eq!(stats.reply_payload_allocations, 0);
        Ok(())
    }

    #[test]
    fn caller_owned_reply_path_has_no_payload_allocation() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (_port, handle) = dispatcher.register(Box::new(DirectEchoService), Rights::CALL)?;
        let mut destination = [0_u8; 16];

        let reply = dispatcher.call_into(handle, 7, b"direct", &mut destination)?;

        assert_eq!(reply.status(), ReplyStatus::Success);
        assert_eq!(reply.payload_bytes(), 6);
        assert_eq!(&destination[..reply.payload_bytes()], b"direct");
        let stats = dispatcher.stats();
        assert_eq!(stats.calls, 1);
        assert_eq!(stats.replies, 1);
        assert_eq!(stats.reply_payload_copies, 1);
        assert_eq!(stats.reply_payload_allocations, 0);
        Ok(())
    }

    #[test]
    fn delivered_request_id_remains_consumed_after_service_error() -> Result<(), DispatchError> {
        let request_ids = Rc::new(RefCell::new(Vec::new()));
        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (_port, handle) = dispatcher.register(
            Box::new(FailOnceService {
                request_ids: Rc::clone(&request_ids),
            }),
            Rights::CALL,
        )?;

        assert_eq!(
            dispatcher.call(handle, 1, b"first"),
            Err(DispatchError::MetadataExhausted)
        );
        let reply = dispatcher.call(handle, 1, b"second")?;
        assert_eq!(reply.request_id(), 2);
        assert_eq!(&*request_ids.borrow(), &[1, 2]);
        assert_eq!(dispatcher.stats().calls, 2);
        assert_eq!(dispatcher.stats().replies, 1);
        Ok(())
    }

    #[test]
    fn application_handle_tokens_are_nonzero_and_generation_checked() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(1, 2)?;
        let (port, kernel) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        let owner = HandleOwner::isolated(9)?;
        let first = dispatcher.open_owned(port, Rights::CALL, owner)?;
        assert_ne!(first.abi_value(), 0);
        assert_eq!(Rights::CALL.bits(), 1);
        let reply = dispatcher.call_owned_abi(owner, first.abi_value(), 7, b"owned")?;
        assert_eq!(reply.payload(), b"owned");
        assert_eq!(
            dispatcher.call_owned_abi(HandleOwner::isolated(10)?, first.abi_value(), 7, b"foreign"),
            Err(DispatchError::InvalidHandle)
        );
        assert_eq!(
            dispatcher.call_owned_abi(owner, first.abi_value() | (1_u64 << 63), 7, b"bad"),
            Err(DispatchError::InvalidHandle)
        );
        dispatcher.close(first)?;
        let replacement = dispatcher.open_owned(port, Rights::CALL, owner)?;
        assert_ne!(replacement.abi_value(), first.abi_value());
        dispatcher.close(kernel)?;
        Ok(())
    }

    #[test]
    fn maximum_handle_generation_retires_slot_without_reuse() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (port, _initial) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        dispatcher.handles[0].generation = u32::MAX;
        let terminal = Handle {
            slot: 0,
            generation: u32::MAX,
        };

        dispatcher.close(terminal)?;

        assert_eq!(dispatcher.handles[0].generation, u32::MAX);
        assert!(dispatcher.handles[0].retired);
        assert_eq!(dispatcher.stats().live_handles, 0);
        assert_eq!(
            dispatcher.call(terminal, 7, b"stale"),
            Err(DispatchError::InvalidHandle)
        );
        assert_eq!(
            dispatcher.open(port, Rights::CALL),
            Err(DispatchError::HandleCapacityExhausted)
        );
        Ok(())
    }

    #[test]
    fn saturated_request_identity_fails_before_delivery() -> Result<(), DispatchError> {
        let request_ids = Rc::new(RefCell::new(Vec::new()));
        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (_port, handle) = dispatcher.register(
            Box::new(RecordingService {
                request_ids: Rc::clone(&request_ids),
            }),
            Rights::CALL,
        )?;
        dispatcher.next_request_id = u64::MAX;

        assert_eq!(
            dispatcher.call(handle, 1, b"request-overflow"),
            Err(DispatchError::AccountingOverflow)
        );
        assert!(request_ids.borrow().is_empty());
        assert_eq!(dispatcher.next_request_id, u64::MAX);
        assert_eq!(dispatcher.stats().calls, 0);
        assert_eq!(dispatcher.stats().replies, 0);
        Ok(())
    }

    #[test]
    fn saturated_call_counter_fails_before_delivery() -> Result<(), DispatchError> {
        let request_ids = Rc::new(RefCell::new(Vec::new()));
        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (_port, handle) = dispatcher.register(
            Box::new(RecordingService {
                request_ids: Rc::clone(&request_ids),
            }),
            Rights::CALL,
        )?;
        dispatcher.calls = u64::MAX;

        assert_eq!(
            dispatcher.call(handle, 1, b"call-overflow"),
            Err(DispatchError::AccountingOverflow)
        );
        assert!(request_ids.borrow().is_empty());
        assert_eq!(dispatcher.next_request_id, 1);
        assert_eq!(dispatcher.stats().calls, u64::MAX);
        assert_eq!(dispatcher.stats().replies, 0);
        Ok(())
    }

    #[test]
    fn reply_counter_failure_consumes_successfully_delivered_identity() -> Result<(), DispatchError>
    {
        let request_ids = Rc::new(RefCell::new(Vec::new()));
        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (_port, handle) = dispatcher.register(
            Box::new(RecordingService {
                request_ids: Rc::clone(&request_ids),
            }),
            Rights::CALL,
        )?;
        dispatcher.replies = u64::MAX;

        assert_eq!(
            dispatcher.call(handle, 1, b"reply-overflow"),
            Err(DispatchError::AccountingOverflow)
        );
        assert_eq!(&*request_ids.borrow(), &[1]);
        assert_eq!(dispatcher.next_request_id, 2);
        assert_eq!(dispatcher.stats().calls, 1);
        assert_eq!(dispatcher.stats().replies, u64::MAX);

        dispatcher.replies = 0;
        let reply = dispatcher.call(handle, 1, b"after-overflow")?;
        assert_eq!(reply.request_id(), 2);
        assert_eq!(&*request_ids.borrow(), &[1, 2]);
        assert_eq!(dispatcher.stats().calls, 2);
        assert_eq!(dispatcher.stats().replies, 1);
        Ok(())
    }

    #[test]
    fn bounds_and_rights_fail_before_service_delivery() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(1, 2)?;
        let (port, callable) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        let denied = dispatcher.open(port, Rights::NONE)?;
        let oversized = vec![0_u8; MAX_MESSAGE_BYTES + 1];

        assert_eq!(
            dispatcher.call(callable, 7, &oversized),
            Err(DispatchError::MessageTooLarge)
        );
        assert_eq!(
            dispatcher.call(denied, 7, b"no"),
            Err(DispatchError::PermissionDenied)
        );
        assert_eq!(dispatcher.stats().calls, 0);
        Ok(())
    }

    #[test]
    fn table_capacities_are_hard_and_explicit() -> Result<(), DispatchError> {
        assert!(matches!(
            Dispatcher::new(0, 1),
            Err(DispatchError::InvalidCapacity)
        ));
        assert!(matches!(
            Dispatcher::new(1, 0),
            Err(DispatchError::InvalidCapacity)
        ));

        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (port, _handle) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        assert_eq!(
            dispatcher.open(port, Rights::CALL),
            Err(DispatchError::HandleCapacityExhausted)
        );
        assert!(matches!(
            dispatcher.register(Box::new(EchoService), Rights::CALL),
            Err(DispatchError::PortCapacityExhausted)
        ));
        assert_eq!(dispatcher.stats().live_ports, 1);
        assert_eq!(dispatcher.stats().live_handles, 1);
        Ok(())
    }

    #[test]
    fn dispatcher_metadata_grows_beyond_legacy_slot_counts() -> Result<(), DispatchError> {
        const TEST_PORTS: usize = 1024;
        let mut dispatcher = Dispatcher::new(TEST_PORTS, TEST_PORTS)?;
        for _ in 0..TEST_PORTS {
            let _registered = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        }
        assert_eq!(dispatcher.stats().live_ports, 1024);
        assert_eq!(dispatcher.stats().live_handles, 1024);
        Ok(())
    }

    #[test]
    fn stale_handles_and_ports_stay_invalid_after_slot_reuse() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(1, 2)?;
        let (old_port, old_handle) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        dispatcher.close(old_handle)?;
        let replacement = dispatcher.open(old_port, Rights::CALL)?;
        assert_ne!(old_handle, replacement);
        assert_eq!(
            dispatcher.call(old_handle, 7, b"stale"),
            Err(DispatchError::InvalidHandle)
        );
        dispatcher.close_port(old_port)?;
        assert_eq!(
            dispatcher.call(replacement, 7, b"closed"),
            Err(DispatchError::InvalidHandle)
        );

        let (new_port, new_handle) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        assert_ne!(old_port, new_port);
        assert_eq!(dispatcher.call(new_handle, 7, b"live")?.payload(), b"live");
        Ok(())
    }

    #[test]
    fn console_can_switch_between_direct_and_dispatched_output() -> Result<(), DispatchError> {
        let direct_bytes = Rc::new(RefCell::new(Vec::new()));
        let dispatched_bytes = Rc::new(RefCell::new(Vec::new()));
        let payload = vec![b'x'; MAX_MESSAGE_BYTES + 17];

        let mut direct = SharedOutput(Rc::clone(&direct_bytes));
        if write_all(&mut direct, &payload).is_err() {
            return Err(DispatchError::MetadataExhausted);
        }

        let mut dispatcher = Dispatcher::new(1, 1)?;
        let (_port, handle) = dispatcher.register(
            Box::new(ConsoleService::new(SharedOutput(Rc::clone(
                &dispatched_bytes,
            )))),
            Rights::CALL,
        )?;
        let mut output = DispatchedOutput::new(&mut dispatcher, handle);
        if write_all(&mut output, &payload).is_err() {
            return Err(DispatchError::MetadataExhausted);
        }

        assert_eq!(*direct_bytes.borrow(), *dispatched_bytes.borrow());
        assert_eq!(dispatcher.stats().calls, 2);
        Ok(())
    }

    #[test]
    fn copied_messages_detach_from_untrusted_storage_atomically() -> Result<(), DispatchError> {
        let mut source = vec![1_u8, 2, 3, 4];
        let copied = CopiedMessage::copy_from_untrusted(&source)?;
        source.fill(9);
        assert_eq!(copied.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(
            CopiedMessage::copy_from_untrusted(&vec![0; MAX_MESSAGE_BYTES + 1]),
            Err(DispatchError::MessageTooLarge)
        );
        Ok(())
    }

    #[test]
    fn owner_teardown_revokes_only_one_tasks_handles() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(1, 4)?;
        let (port, kernel) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        let first_owner = HandleOwner::isolated(7)?;
        let second_owner = HandleOwner::isolated(8)?;
        let first = dispatcher.open_owned(port, Rights::CALL, first_owner)?;
        let second = dispatcher.open_owned(port, Rights::CALL, second_owner)?;

        assert_eq!(dispatcher.close_owner(first_owner), Ok(1));
        assert_eq!(
            dispatcher.call(first, 7, b"revoked"),
            Err(DispatchError::InvalidHandle)
        );
        assert_eq!(dispatcher.call(second, 7, b"second")?.payload(), b"second");
        assert_eq!(dispatcher.call(kernel, 7, b"kernel")?.payload(), b"kernel");
        assert_eq!(dispatcher.close_owner(first_owner), Ok(0));
        assert_eq!(
            dispatcher.close_owner(HandleOwner::Kernel),
            Err(DispatchError::InvalidOwner)
        );
        assert_eq!(HandleOwner::isolated(0), Err(DispatchError::InvalidOwner));
        Ok(())
    }
}

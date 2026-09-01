//! Handles, rights, and the request and reply values crossing the call gate.

use crate::{DispatchError, MAX_HANDLES, MAX_MESSAGE_BYTES};
use alloc::vec::Vec;

/// Opaque generation-checked service endpoint identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortId {
    pub(crate) slot: u32,
    pub(crate) generation: u32,
}

/// Opaque generation-checked authority to call one service port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    pub(crate) slot: u32,
    pub(crate) generation: u32,
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
    pub(crate) id: u64,
    pub(crate) opcode: u16,
    pub(crate) payload: &'a [u8],
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
    pub(crate) status: ReplyStatus,
    pub(crate) payload: Vec<u8>,
}

/// Bounded service completion written directly into caller-owned storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceReplyInfo {
    pub(crate) status: ReplyStatus,
    pub(crate) payload_bytes: usize,
    pub(crate) payload_copies: u64,
    pub(crate) payload_allocations: u64,
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
    pub(crate) request_id: u64,
    pub(crate) status: ReplyStatus,
    pub(crate) payload: Vec<u8>,
}

/// Complete bounded reply retained in caller-owned storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyInfo {
    pub(crate) request_id: u64,
    pub(crate) status: ReplyStatus,
    pub(crate) payload_bytes: usize,
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

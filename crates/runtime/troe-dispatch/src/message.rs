//! Handles, rights, and the request and reply values crossing the call gate.

use crate::{DispatchError, MAX_HANDLES, MAX_MESSAGE_BYTES};
use alloc::vec::Vec;
use troe_abi::interface::rights as abi_rights;

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

/// Rights attached to one capability handle.
///
/// The bit assignment is fixed by ADR 0035 and shared by every interface. An
/// interface still rejects the bits its operations have no meaning for, so
/// possession of a bit is necessary rather than sufficient; see
/// [`troe_abi::interface::allowed_rights`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rights(u16);

impl Rights {
    /// No operation is authorized.
    pub const NONE: Self = Self(0);
    /// Synchronous request/reply calls are authorized.
    pub const CALL: Self = Self(abi_rights::CALL);
    /// Receiving one delivered call at an endpoint is authorized.
    pub const RECEIVE: Self = Self(abi_rights::RECEIVE);
    /// Replying to one delivered call is authorized.
    pub const REPLY: Self = Self(abi_rights::REPLY);
    /// Waiting on one immutable wait set is authorized.
    pub const WAIT: Self = Self(abi_rights::WAIT);
    /// Reading bytes is authorized.
    pub const READ: Self = Self(abi_rights::READ);
    /// Writing bytes is authorized.
    pub const WRITE: Self = Self(abi_rights::WRITE);
    /// Explicit durability flush is authorized.
    pub const FLUSH: Self = Self(abi_rights::FLUSH);
    /// Deriving an equal-or-narrower child authority is authorized.
    pub const DERIVE: Self = Self(abi_rights::DERIVE);
    /// Supervisor device reset is authorized.
    pub const RESET: Self = Self(abi_rights::RESET);

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

    /// Whether no right at all is present.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Narrow to the bits both sets carry.
    ///
    /// This is the only derivation primitive: a child authority is the
    /// intersection of its parent and the request, so derivation can never add
    /// a bit the parent does not already hold.
    #[must_use]
    pub const fn intersect(self, requested: Self) -> Self {
        Self(self.0 & requested.0)
    }

    /// Fixed ABI bit representation carried by an initial handle descriptor.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0 as u32
    }

    /// Decode a fixed ABI bit representation, rejecting unassigned bits.
    ///
    /// # Errors
    ///
    /// Rejects any bit outside [`troe_abi::interface::rights::ASSIGNED`], so a
    /// malformed startup record cannot smuggle authority through a bit this
    /// ABI has given no meaning.
    pub fn from_bits(bits: u32) -> Result<Self, DispatchError> {
        let bits = u16::try_from(bits).map_err(|_| DispatchError::InvalidRights)?;
        if bits & !abi_rights::ASSIGNED != 0 {
            return Err(DispatchError::InvalidRights);
        }
        Ok(Self(bits))
    }

    /// Check every bit against the operations one interface defines.
    ///
    /// This validates rather than narrows. Silently dropping a bit would let a
    /// caller believe it received authority it did not, so a request naming an
    /// operation its interface has no meaning for is an error worth reporting.
    /// Narrowing is [`Self::intersect`], which is derivation, not validation.
    ///
    /// # Errors
    ///
    /// Rejects an unassigned interface and any bit outside the mask that
    /// interface allows.
    pub const fn for_interface(self, interface: u32) -> Result<Self, DispatchError> {
        let allowed = troe_abi::interface::allowed_rights(interface);
        if allowed == 0 || self.0 & !allowed != 0 {
            return Err(DispatchError::InvalidRights);
        }
        Ok(self)
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

#[cfg(test)]
mod tests {
    use super::Rights;
    use crate::DispatchError;
    use troe_abi::interface;

    #[test]
    fn the_nine_bits_match_the_abi_assignment() {
        for (right, expected) in [
            (Rights::CALL, interface::rights::CALL),
            (Rights::RECEIVE, interface::rights::RECEIVE),
            (Rights::REPLY, interface::rights::REPLY),
            (Rights::WAIT, interface::rights::WAIT),
            (Rights::READ, interface::rights::READ),
            (Rights::WRITE, interface::rights::WRITE),
            (Rights::FLUSH, interface::rights::FLUSH),
            (Rights::DERIVE, interface::rights::DERIVE),
            (Rights::RESET, interface::rights::RESET),
        ] {
            assert_eq!(right.bits(), u32::from(expected));
            assert!(!right.is_empty());
            assert!(right.contains(right));
        }
        assert!(Rights::NONE.is_empty());
        assert_eq!(Rights::NONE.bits(), 0);
    }

    #[test]
    fn derivation_intersects_and_can_never_add_a_bit() {
        let parent = Rights::CALL.union(Rights::READ);
        // A child asking for more than its parent holds receives only the
        // overlap, so authority strictly narrows down a derivation chain.
        let child = parent.intersect(Rights::READ.union(Rights::WRITE));
        assert_eq!(child, Rights::READ);
        assert!(parent.contains(child));
        assert!(!child.contains(parent));
        assert_eq!(
            parent.intersect(Rights::WRITE.union(Rights::RESET)),
            Rights::NONE,
            "a request sharing no bit with its parent derives no authority"
        );
        assert_eq!(parent.intersect(parent), parent);
        // Intersection is the only derivation primitive, so no sequence of
        // derivations can reach a bit the original parent lacked.
        assert!(!parent.intersect(Rights::WRITE).contains(Rights::WRITE));
    }

    #[test]
    fn decoding_rejects_every_unassigned_bit() {
        assert_eq!(
            Rights::from_bits(u32::from(interface::rights::ASSIGNED)),
            Ok(Rights(interface::rights::ASSIGNED))
        );
        assert_eq!(Rights::from_bits(0), Ok(Rights::NONE));
        for shift in 9..32 {
            assert_eq!(
                Rights::from_bits(1 << shift).err(),
                Some(DispatchError::InvalidRights),
                "bit {shift} has no assigned meaning and must not decode"
            );
        }
        assert_eq!(
            Rights::from_bits(u32::MAX).err(),
            Some(DispatchError::InvalidRights)
        );
    }

    #[test]
    fn an_interface_accepts_only_the_bits_its_operations_need() {
        // A block region is the one interface that can derive and flush.
        let block = Rights::CALL
            .union(Rights::READ)
            .union(Rights::WRITE)
            .union(Rights::FLUSH)
            .union(Rights::DERIVE);
        assert_eq!(
            block.for_interface(interface::BLOCK_REGION),
            Ok(block),
            "a block region carries every bit its operations define"
        );
        assert_eq!(
            block.for_interface(interface::BOOT_BLOB).err(),
            Some(DispatchError::InvalidRights),
            "an immutable blob has no write, flush, or derive operation"
        );
        assert_eq!(
            Rights::CALL
                .union(Rights::READ)
                .for_interface(interface::BOOT_BLOB),
            Ok(Rights::CALL.union(Rights::READ))
        );
        assert_eq!(
            Rights::WAIT.for_interface(interface::WAIT_SET),
            Ok(Rights::WAIT)
        );
        assert_eq!(
            Rights::WAIT.for_interface(interface::BLOCK_REGION).err(),
            Some(DispatchError::InvalidRights),
            "only a wait set is waited on"
        );
        assert_eq!(
            Rights::CALL.for_interface(interface::HIGHEST + 1).err(),
            Some(DispatchError::InvalidRights),
            "an unassigned interface grants nothing"
        );
    }
}

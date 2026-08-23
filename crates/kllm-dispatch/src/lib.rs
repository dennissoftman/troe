//! Bounded handles, ports, and synchronous in-process request/reply dispatch.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use kllm_core::{Output, StreamError, write_all};

/// Hard ceiling for one request or reply payload.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
/// Hard ceiling for registered service ports.
pub const MAX_PORTS: usize = 16;
/// Hard ceiling for live client handles.
pub const MAX_HANDLES: usize = 32;

/// Opaque generation-checked service endpoint identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortId {
    slot: u16,
    generation: u32,
}

/// Opaque generation-checked authority to call one service port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    slot: u16,
    generation: u32,
}

impl Handle {
    /// Stable opaque value exported through the application ABI.
    ///
    /// The low 16 bits encode a one-based slot and the high bits encode its
    /// generation. Applications must treat the result as an indivisible token.
    #[must_use]
    pub const fn abi_value(self) -> u64 {
        ((self.generation as u64) << 16) | (self.slot as u64 + 1)
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

impl ServiceReply {
    /// Construct an empty service reply.
    #[must_use]
    pub const fn empty(status: ReplyStatus) -> Self {
        Self {
            status,
            payload: Vec::new(),
        }
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

struct PortSlot {
    generation: u32,
    retired: bool,
    service: Option<Box<dyn Service>>,
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
    pub live_ports: u16,
    /// Currently live client handles.
    pub live_handles: u16,
    /// Calls successfully delivered to a service.
    pub calls: u64,
    /// Replies successfully returned to clients.
    pub replies: u64,
}

/// Bounded synchronous in-process service router.
///
/// Requests borrow their payload only for the duration of [`Self::call`]. A
/// call either returns one owned reply or a typed mechanism failure. There is no
/// queued or cancellable state: closing before delivery invalidates a handle,
/// while closing during a synchronous call is impossible through the exclusive
/// dispatcher borrow. Stage 6 additionally revokes handles by task owner.
pub struct Dispatcher {
    ports: Vec<PortSlot>,
    handles: Vec<HandleSlot>,
    port_capacity: usize,
    handle_capacity: usize,
    next_request_id: u64,
    calls: u64,
    replies: u64,
}

impl Dispatcher {
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
            .try_reserve_exact(port_capacity)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(handle_capacity)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        Ok(Self {
            ports,
            handles,
            port_capacity,
            handle_capacity,
            next_request_id: 1,
            calls: 0,
            replies: 0,
        })
    }

    /// Register a service port and return its first client handle.
    ///
    /// # Errors
    ///
    /// Rejects exhausted port or handle tables.
    pub fn register(
        &mut self,
        service: Box<dyn Service>,
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
                slot: u16::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
                generation: slot.generation,
            });
        }
        if self.handles.len() == self.handle_capacity {
            return Err(DispatchError::HandleCapacityExhausted);
        }
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
            slot: u16::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
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
        let index = usize::from(port.slot);
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
        let request = Request {
            id: request_id,
            opcode,
            payload,
        };
        self.next_request_id = next_request_id;
        self.calls = calls;
        let port_index = usize::from(binding.port.slot);
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
        self.replies = replies;
        Ok(Reply {
            request_id,
            status: service_reply.status,
            payload: service_reply.payload,
        })
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
            live_ports: u16::try_from(live_ports).unwrap_or(u16::MAX),
            live_handles: u16::try_from(live_handles).unwrap_or(u16::MAX),
            calls: self.calls,
            replies: self.replies,
        }
    }

    fn allocate_port(&mut self, service: Box<dyn Service>) -> Result<PortId, DispatchError> {
        if let Some((index, slot)) = self
            .ports
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.service.is_none() && !slot.retired)
        {
            slot.service = Some(service);
            return Ok(PortId {
                slot: u16::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
                generation: slot.generation,
            });
        }
        if self.ports.len() == self.port_capacity {
            return Err(DispatchError::PortCapacityExhausted);
        }
        let index = self.ports.len();
        self.ports.push(PortSlot {
            generation: 1,
            retired: false,
            service: Some(service),
        });
        Ok(PortId {
            slot: u16::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
            generation: 1,
        })
    }

    fn validate_port(&self, port: PortId) -> Result<(), DispatchError> {
        let slot = self
            .ports
            .get(usize::from(port.slot))
            .ok_or(DispatchError::InvalidPort)?;
        if slot.generation != port.generation || slot.service.is_none() {
            return Err(DispatchError::InvalidPort);
        }
        Ok(())
    }

    fn handle_binding(&self, handle: Handle) -> Result<HandleBinding, DispatchError> {
        let slot = self
            .handles
            .get(usize::from(handle.slot))
            .ok_or(DispatchError::InvalidHandle)?;
        if slot.generation != handle.generation {
            return Err(DispatchError::InvalidHandle);
        }
        slot.binding.ok_or(DispatchError::InvalidHandle)
    }

    fn handle_slot_mut(&mut self, handle: Handle) -> Result<&mut HandleSlot, DispatchError> {
        let slot = self
            .handles
            .get_mut(usize::from(handle.slot))
            .ok_or(DispatchError::InvalidHandle)?;
        if slot.generation != handle.generation || slot.binding.is_none() {
            return Err(DispatchError::InvalidHandle);
        }
        Ok(slot)
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
pub struct DispatchedOutput<'a> {
    dispatcher: &'a mut Dispatcher,
    handle: Handle,
}

impl<'a> DispatchedOutput<'a> {
    /// Bind an output client to one explicitly supplied handle.
    #[must_use]
    pub const fn new(dispatcher: &'a mut Dispatcher, handle: Handle) -> Self {
        Self { dispatcher, handle }
    }
}

impl Output for DispatchedOutput<'_> {
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
        ConsoleService, CopiedMessage, DispatchError, DispatchedOutput, Dispatcher, HandleOwner,
        MAX_MESSAGE_BYTES, ReplyStatus, Request, Rights, Service, ServiceReply,
    };
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use kllm_core::{Output, StreamError, write_all};

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
        assert_eq!(dispatcher.stats().calls, 2);
        assert_eq!(dispatcher.stats().replies, 2);
        Ok(())
    }

    #[test]
    fn application_handle_tokens_are_nonzero_and_generation_checked() -> Result<(), DispatchError> {
        let mut dispatcher = Dispatcher::new(1, 2)?;
        let (port, first) = dispatcher.register(Box::new(EchoService), Rights::CALL)?;
        assert_ne!(first.abi_value(), 0);
        assert_eq!(Rights::CALL.bits(), 1);
        dispatcher.close(first)?;
        let replacement = dispatcher.open(port, Rights::CALL)?;
        assert_ne!(replacement.abi_value(), first.abi_value());
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

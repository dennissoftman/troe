//! Synchronous in-process request and reply dispatch over bounded tables.

use crate::{
    DispatchError, Handle, HandleOwner, MAX_HANDLES, MAX_MESSAGE_BYTES, MAX_PORTS, PortId, Reply,
    ReplyInfo, Request, Rights, ServiceReply, ServiceReplyInfo,
};
use alloc::boxed::Box;
use alloc::vec::Vec;

const INITIAL_DISPATCH_CAPACITY: usize = 64;
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

#[cfg(test)]
mod tests {
    use crate::{
        CopiedMessage, DispatchError, Dispatcher, Handle, HandleOwner, MAX_MESSAGE_BYTES,
        ReplyStatus, Request, Rights, Service, ServiceReply, ServiceReplyInfo,
    };
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

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

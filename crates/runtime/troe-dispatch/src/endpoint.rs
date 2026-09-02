//! Persistent service endpoints bound to one server incarnation.
//!
//! ADR 0035 separates two things the ADR 0011 dispatcher keeps together. A
//! [`crate::Dispatcher`] port is a service object the kernel calls in process,
//! under an exclusive borrow, with no queue and no incarnation. An endpoint
//! here is the client-visible identity of a *server task*: it names the
//! incarnation that answers, the closed set of interfaces it accepts, and the
//! ceilings its callers are admitted under.
//!
//! Only the binding half lives in this module. Badges, the queue, and the
//! pending-call state machine bind to an endpoint slot and arrive separately.
//!
//! The one rule that shapes everything else is that restart always advances the
//! endpoint generation. A client handle names a slot *and* a generation, so a
//! handle to a dead incarnation is stale rather than silently retargeted at its
//! replacement. That is why closing and rebinding are distinct operations and
//! why a slot retires instead of wrapping.

use crate::{DispatchError, HandleOwner, Rights};
use alloc::vec::Vec;

/// Hard ceiling for live persistent endpoints, from ADR 0035's Standard profile.
pub const MAX_ENDPOINTS: usize = 16;
/// Hard ceiling for calls queued at one endpoint.
pub const MAX_QUEUED_CALLS_PER_ENDPOINT: u16 = 8;
/// Hard ceiling for retained queued request bytes at one endpoint.
pub const MAX_RETAINED_REQUEST_BYTES: u32 = 128 * 1024;
/// Hard ceiling for one client call's lifetime.
pub const MAX_CALL_DEADLINE_MILLIS: u32 = 4_000;
/// Hard ceiling for interfaces one endpoint accepts.
///
/// ADR 0035 fixes no cardinality here. Eight covers the largest initial server —
/// the network server's five application-facing interfaces — with headroom, and
/// keeps the accepted set small enough to scan without an index.
pub const MAX_ENDPOINT_INTERFACES: usize = 8;

/// Opaque generation-checked persistent endpoint identity.
///
/// Possession grants nothing. ADR 0035 is explicit that an endpoint identifier
/// conveys no call, receive, or reply authority; those live in a handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointId {
    slot: u32,
    generation: u32,
}

impl EndpointId {
    /// Slot this identity names, independent of incarnation.
    #[must_use]
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// Incarnation this identity names.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Ceilings one endpoint selects when it is bound.
///
/// An endpoint may select smaller values than the profile's hard ceilings, and
/// a published binding is immutable, so a ceiling can never be enlarged after
/// publication. [`Self::narrow`] composes two sets before publication and takes
/// the smaller of each pair, so composing can only reduce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointLimits {
    queued_calls: u16,
    retained_bytes: u32,
    deadline_millis: u32,
}

impl EndpointLimits {
    /// The profile's hard ceilings, the widest an endpoint may select.
    pub const STANDARD: Self = Self {
        queued_calls: MAX_QUEUED_CALLS_PER_ENDPOINT,
        retained_bytes: MAX_RETAINED_REQUEST_BYTES,
        deadline_millis: MAX_CALL_DEADLINE_MILLIS,
    };

    /// Select ceilings at or below the profile's.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-profile value. Zero is rejected rather than
    /// treated as "unlimited": an endpoint that can admit no call and an
    /// endpoint with no deadline are both states this profile has no
    /// representation for.
    pub const fn new(
        queued_calls: u16,
        retained_bytes: u32,
        deadline_millis: u32,
    ) -> Result<Self, DispatchError> {
        if queued_calls == 0
            || queued_calls > MAX_QUEUED_CALLS_PER_ENDPOINT
            || retained_bytes == 0
            || retained_bytes > MAX_RETAINED_REQUEST_BYTES
            || deadline_millis == 0
            || deadline_millis > MAX_CALL_DEADLINE_MILLIS
        {
            return Err(DispatchError::InvalidCapacity);
        }
        Ok(Self {
            queued_calls,
            retained_bytes,
            deadline_millis,
        })
    }

    /// Calls this endpoint may hold queued.
    #[must_use]
    pub const fn queued_calls(self) -> u16 {
        self.queued_calls
    }

    /// Request bytes this endpoint may retain across its queued calls.
    #[must_use]
    pub const fn retained_bytes(self) -> u32 {
        self.retained_bytes
    }

    /// Longest lifetime this endpoint admits a call for.
    #[must_use]
    pub const fn deadline_millis(self) -> u32 {
        self.deadline_millis
    }

    /// Reduce every ceiling to the smaller of the two sets.
    #[must_use]
    pub const fn narrow(self, requested: Self) -> Self {
        Self {
            queued_calls: if requested.queued_calls < self.queued_calls {
                requested.queued_calls
            } else {
                self.queued_calls
            },
            retained_bytes: if requested.retained_bytes < self.retained_bytes {
                requested.retained_bytes
            } else {
                self.retained_bytes
            },
            deadline_millis: if requested.deadline_millis < self.deadline_millis {
                requested.deadline_millis
            } else {
                self.deadline_millis
            },
        }
    }

    /// Whether a requested call deadline is inside this endpoint's ceiling.
    #[must_use]
    pub const fn admits_deadline(self, requested_millis: u32) -> bool {
        requested_millis != 0 && requested_millis <= self.deadline_millis
    }
}

/// The closed set of interfaces one endpoint accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceSet {
    interfaces: [u32; MAX_ENDPOINT_INTERFACES],
    len: u8,
}

impl InterfaceSet {
    /// Build a closed set from a bounded slice of distinct assigned interfaces.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized set, a duplicate, and any identifier this
    /// ABI assigns no rights to.
    pub fn new(interfaces: &[u32]) -> Result<Self, DispatchError> {
        if interfaces.is_empty() || interfaces.len() > MAX_ENDPOINT_INTERFACES {
            return Err(DispatchError::InvalidCapacity);
        }
        let mut stored = [0_u32; MAX_ENDPOINT_INTERFACES];
        for (index, interface) in interfaces.iter().enumerate() {
            if troe_abi::interface::allowed_rights(*interface) == 0 {
                return Err(DispatchError::InvalidInterface);
            }
            if interfaces[..index].contains(interface) {
                return Err(DispatchError::InvalidInterface);
            }
            stored[index] = *interface;
        }
        let len = u8::try_from(interfaces.len()).map_err(|_| DispatchError::InvalidCapacity)?;
        Ok(Self {
            interfaces: stored,
            len,
        })
    }

    /// Whether this set accepts one interface.
    #[must_use]
    pub fn accepts(&self, interface: u32) -> bool {
        self.interfaces[..self.len()].contains(&interface)
    }

    /// Interfaces in the set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the set is empty, which construction never produces.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Accepted interfaces in construction order.
    #[must_use]
    pub fn as_slice(&self) -> &[u32] {
        &self.interfaces[..self.len()]
    }
}

/// One published endpoint incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointBinding {
    server: HandleOwner,
    interfaces: InterfaceSet,
    limits: EndpointLimits,
}

impl EndpointBinding {
    /// Server incarnation that answers this endpoint.
    #[must_use]
    pub const fn server(&self) -> HandleOwner {
        self.server
    }

    /// Closed interface set this endpoint accepts.
    #[must_use]
    pub const fn interfaces(&self) -> &InterfaceSet {
        &self.interfaces
    }

    /// Ceilings callers are admitted under.
    #[must_use]
    pub const fn limits(&self) -> EndpointLimits {
        self.limits
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointSlot {
    generation: u32,
    retired: bool,
    binding: Option<EndpointBinding>,
}

/// Live and high-water endpoint accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EndpointStats {
    /// Endpoints currently bound to a server incarnation.
    pub live: u32,
    /// Greatest number of simultaneously bound endpoints.
    pub high_water: u32,
    /// Slots retired because their generation reached the maximum.
    pub retired: u32,
    /// Incarnations published, counting every bind and rebind.
    pub incarnations: u64,
}

/// Bounded table of persistent endpoints.
#[derive(Debug)]
pub struct EndpointTable {
    slots: Vec<EndpointSlot>,
    live: u32,
    high_water: u32,
    retired: u32,
    incarnations: u64,
}

impl EndpointTable {
    /// Reserve every slot before any endpoint can be published.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-ceiling capacity, and a failed reservation.
    /// Construction reserves the complete table so publication never allocates.
    pub fn new(capacity: usize) -> Result<Self, DispatchError> {
        if capacity == 0 || capacity > MAX_ENDPOINTS {
            return Err(DispatchError::InvalidCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        for _ in 0..capacity {
            slots.push(EndpointSlot {
                generation: 0,
                retired: false,
                binding: None,
            });
        }
        Ok(Self {
            slots,
            live: 0,
            high_water: 0,
            retired: 0,
            incarnations: 0,
        })
    }

    /// Publish one endpoint bound to a server incarnation.
    ///
    /// Which server may name a boot-only interface is a boot-service-record
    /// question, so this table does not answer it: it accepts any assigned
    /// interface and leaves the role check to whoever builds the set.
    ///
    /// # Errors
    ///
    /// Rejects a kernel owner and an exhausted table.
    pub fn bind(
        &mut self,
        server: HandleOwner,
        interfaces: InterfaceSet,
        limits: EndpointLimits,
    ) -> Result<EndpointId, DispatchError> {
        // An endpoint is the identity of a server task. Binding one to the
        // kernel would make the generation meaningless, because there is no
        // incarnation to advance when it restarts.
        let HandleOwner::IsolatedTask(_) = server else {
            return Err(DispatchError::InvalidOwner);
        };
        let slot = self
            .slots
            .iter()
            .position(|slot| !slot.retired && slot.binding.is_none())
            .ok_or(DispatchError::EndpointCapacityExhausted)?;
        let index = u32::try_from(slot).map_err(|_| DispatchError::AccountingOverflow)?;
        self.publish(index, server, interfaces, limits)
    }

    /// Replace a closed endpoint's incarnation in the same slot.
    ///
    /// Restart reuses the slot so a supervisor's record of the service stays
    /// stable, and advances the generation so every old client handle is stale.
    ///
    /// # Errors
    ///
    /// Rejects a slot that is still bound, retired, or out of range, and the
    /// same owner and interface failures as [`Self::bind`].
    pub fn rebind(
        &mut self,
        slot: u32,
        server: HandleOwner,
        interfaces: InterfaceSet,
        limits: EndpointLimits,
    ) -> Result<EndpointId, DispatchError> {
        let HandleOwner::IsolatedTask(_) = server else {
            return Err(DispatchError::InvalidOwner);
        };
        let record = self
            .slots
            .get(slot as usize)
            .ok_or(DispatchError::InvalidEndpoint)?;
        if record.retired || record.binding.is_some() {
            return Err(DispatchError::InvalidEndpoint);
        }
        self.publish(slot, server, interfaces, limits)
    }

    fn publish(
        &mut self,
        slot: u32,
        server: HandleOwner,
        interfaces: InterfaceSet,
        limits: EndpointLimits,
    ) -> Result<EndpointId, DispatchError> {
        let incarnations = self
            .incarnations
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let live = self
            .live
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let record = self
            .slots
            .get_mut(slot as usize)
            .ok_or(DispatchError::InvalidEndpoint)?;
        // A generation that cannot advance can no longer distinguish a stale
        // handle from a live one, so the slot retires rather than wrapping.
        let generation = record
            .generation
            .checked_add(1)
            .ok_or(DispatchError::EndpointCapacityExhausted)?;
        record.generation = generation;
        record.binding = Some(EndpointBinding {
            server,
            interfaces,
            limits,
        });
        self.incarnations = incarnations;
        self.live = live;
        self.high_water = self.high_water.max(live);
        Ok(EndpointId { slot, generation })
    }

    /// Close one endpoint incarnation, revoking every handle that names it.
    ///
    /// The generation advances here rather than at the next bind, so a handle
    /// is stale from the moment the incarnation ends and never during a window
    /// in which the slot is unbound but still answering its old generation. A
    /// slot whose generation has reached the maximum retires permanently.
    ///
    /// # Errors
    ///
    /// Rejects a stale, unbound, retired, or out-of-range identity.
    pub fn close(&mut self, endpoint: EndpointId) -> Result<(), DispatchError> {
        self.resolve(endpoint)?;
        let live = self
            .live
            .checked_sub(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let record = self
            .slots
            .get_mut(endpoint.slot as usize)
            .ok_or(DispatchError::InvalidEndpoint)?;
        record.binding = None;
        if record.generation == u32::MAX {
            record.retired = true;
            self.retired = self
                .retired
                .checked_add(1)
                .ok_or(DispatchError::AccountingOverflow)?;
        }
        self.live = live;
        Ok(())
    }

    /// Resolve one live endpoint incarnation.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range slot, a retired slot, an unbound slot, and a
    /// generation naming any incarnation but the current one.
    pub fn resolve(&self, endpoint: EndpointId) -> Result<&EndpointBinding, DispatchError> {
        let record = self
            .slots
            .get(endpoint.slot as usize)
            .ok_or(DispatchError::InvalidEndpoint)?;
        if record.retired || record.generation != endpoint.generation {
            return Err(DispatchError::InvalidEndpoint);
        }
        record
            .binding
            .as_ref()
            .ok_or(DispatchError::InvalidEndpoint)
    }

    /// Resolve one live endpoint and check that it accepts an interface and the
    /// rights a handle would carry.
    ///
    /// # Errors
    ///
    /// Rejects a stale identity, an interface outside the endpoint's closed
    /// set, an empty rights set, and rights the interface has no operation for.
    pub fn resolve_for(
        &self,
        endpoint: EndpointId,
        interface: u32,
        rights: Rights,
    ) -> Result<&EndpointBinding, DispatchError> {
        let binding = self.resolve(endpoint)?;
        if !binding.interfaces.accepts(interface) {
            return Err(DispatchError::InvalidInterface);
        }
        if rights.is_empty() {
            return Err(DispatchError::InvalidRights);
        }
        rights.for_interface(interface)?;
        Ok(binding)
    }

    /// Current live, high-water, retirement, and incarnation accounting.
    #[must_use]
    pub const fn stats(&self) -> EndpointStats {
        EndpointStats {
            live: self.live,
            high_water: self.high_water,
            retired: self.retired,
            incarnations: self.incarnations,
        }
    }

    /// Slots the table was constructed with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EndpointId, EndpointLimits, EndpointTable, InterfaceSet, MAX_CALL_DEADLINE_MILLIS,
        MAX_ENDPOINT_INTERFACES, MAX_ENDPOINTS, MAX_QUEUED_CALLS_PER_ENDPOINT,
        MAX_RETAINED_REQUEST_BYTES,
    };
    use crate::{DispatchError, HandleOwner, Rights};
    use troe_abi::interface;

    fn server(id: u32) -> HandleOwner {
        HandleOwner::isolated(id).unwrap_or_else(|_| unreachable!())
    }

    fn interfaces() -> InterfaceSet {
        InterfaceSet::new(&[interface::FILESYSTEM_READ, interface::FILESYSTEM_MUTATE])
            .unwrap_or_else(|_| unreachable!())
    }

    fn table() -> EndpointTable {
        EndpointTable::new(MAX_ENDPOINTS).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn a_table_reserves_every_slot_and_rejects_an_impossible_capacity() {
        assert_eq!(
            EndpointTable::new(0).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            EndpointTable::new(MAX_ENDPOINTS + 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        let table = table();
        assert_eq!(table.capacity(), MAX_ENDPOINTS);
        assert_eq!(table.stats().live, 0);
        assert_eq!(table.stats().incarnations, 0);
    }

    #[test]
    fn an_endpoint_names_a_server_incarnation_and_never_the_kernel() {
        let mut table = table();
        assert_eq!(
            table
                .bind(HandleOwner::Kernel, interfaces(), EndpointLimits::STANDARD)
                .err(),
            Some(DispatchError::InvalidOwner),
            "a kernel owner has no incarnation for the generation to track"
        );
        let endpoint = table
            .bind(server(7), interfaces(), EndpointLimits::STANDARD)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(endpoint.generation(), 1);
        let binding = table.resolve(endpoint).unwrap_or_else(|_| unreachable!());
        assert_eq!(binding.server(), server(7));
        assert_eq!(binding.limits(), EndpointLimits::STANDARD);
        assert_eq!(table.stats().live, 1);
        assert_eq!(table.stats().high_water, 1);
    }

    #[test]
    fn restart_advances_the_generation_so_an_old_handle_cannot_retarget() {
        let mut table = table();
        let first = table
            .bind(server(7), interfaces(), EndpointLimits::STANDARD)
            .unwrap_or_else(|_| unreachable!());
        table.close(first).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.resolve(first).err(),
            Some(DispatchError::InvalidEndpoint),
            "a closed incarnation must not resolve"
        );
        let second = table
            .rebind(
                first.slot(),
                server(9),
                interfaces(),
                EndpointLimits::STANDARD,
            )
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(second.slot(), first.slot(), "restart reuses the slot");
        assert_ne!(second.generation(), first.generation());
        assert_eq!(
            table.resolve(first).err(),
            Some(DispatchError::InvalidEndpoint),
            "the replacement must not answer the old generation"
        );
        assert_eq!(
            table
                .resolve(second)
                .unwrap_or_else(|_| unreachable!())
                .server(),
            server(9)
        );
        assert_eq!(table.stats().incarnations, 2);
        assert_eq!(table.stats().live, 1);
    }

    #[test]
    fn rebinding_a_live_or_unknown_slot_is_rejected() {
        let mut table = table();
        let endpoint = table
            .bind(server(7), interfaces(), EndpointLimits::STANDARD)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table
                .rebind(
                    endpoint.slot(),
                    server(9),
                    interfaces(),
                    EndpointLimits::STANDARD
                )
                .err(),
            Some(DispatchError::InvalidEndpoint),
            "a live incarnation must be closed before its slot is reused"
        );
        assert_eq!(
            table
                .rebind(u32::MAX, server(9), interfaces(), EndpointLimits::STANDARD)
                .err(),
            Some(DispatchError::InvalidEndpoint)
        );
        table.close(endpoint).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.close(endpoint).err(),
            Some(DispatchError::InvalidEndpoint),
            "closing twice must not double-count the live total"
        );
        assert_eq!(table.stats().live, 0);
    }

    #[test]
    fn a_slot_retires_at_the_maximum_generation_rather_than_wrapping() {
        let mut table = EndpointTable::new(1).unwrap_or_else(|_| unreachable!());
        let endpoint = table
            .bind(server(7), interfaces(), EndpointLimits::STANDARD)
            .unwrap_or_else(|_| unreachable!());
        // Drive the one slot to the last generation it can still distinguish,
        // so the next incarnation is the final one.
        table.slots[0].generation = u32::MAX - 1;
        let aged = EndpointId {
            slot: endpoint.slot(),
            generation: u32::MAX - 1,
        };
        table.close(aged).unwrap_or_else(|_| unreachable!());
        let last = table
            .rebind(
                aged.slot(),
                server(8),
                interfaces(),
                EndpointLimits::STANDARD,
            )
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(last.generation(), u32::MAX);
        table.close(last).unwrap_or_else(|_| unreachable!());
        assert_eq!(table.stats().retired, 1);
        assert_eq!(
            table
                .rebind(
                    last.slot(),
                    server(9),
                    interfaces(),
                    EndpointLimits::STANDARD
                )
                .err(),
            Some(DispatchError::InvalidEndpoint),
            "a retired slot must never be published again"
        );
        assert_eq!(
            table.resolve(last).err(),
            Some(DispatchError::InvalidEndpoint),
            "a retired slot must not answer its final generation either"
        );
    }

    #[test]
    fn a_full_table_reports_endpoint_exhaustion() {
        let mut table = EndpointTable::new(2).unwrap_or_else(|_| unreachable!());
        for id in 1..=2 {
            table
                .bind(server(id), interfaces(), EndpointLimits::STANDARD)
                .unwrap_or_else(|_| unreachable!());
        }
        assert_eq!(
            table
                .bind(server(3), interfaces(), EndpointLimits::STANDARD)
                .err(),
            Some(DispatchError::EndpointCapacityExhausted)
        );
        assert_eq!(table.stats().high_water, 2);
    }

    #[test]
    fn an_interface_set_is_closed_bounded_and_free_of_duplicates() {
        assert_eq!(
            InterfaceSet::new(&[]).err(),
            Some(DispatchError::InvalidCapacity)
        );
        let oversized = [interface::COMMAND; MAX_ENDPOINT_INTERFACES + 1];
        assert_eq!(
            InterfaceSet::new(&oversized).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            InterfaceSet::new(&[interface::COMMAND, interface::COMMAND]).err(),
            Some(DispatchError::InvalidInterface)
        );
        assert_eq!(
            InterfaceSet::new(&[interface::HIGHEST + 1]).err(),
            Some(DispatchError::InvalidInterface),
            "an unassigned identifier carries no rights and cannot be accepted"
        );
        let set = interfaces();
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert!(set.accepts(interface::FILESYSTEM_READ));
        assert!(!set.accepts(interface::DATAGRAM));
        assert_eq!(
            set.as_slice(),
            [interface::FILESYSTEM_READ, interface::FILESYSTEM_MUTATE]
        );
    }

    #[test]
    fn resolving_for_a_handle_checks_the_interface_and_its_meaningful_rights() {
        let mut table = table();
        let endpoint = table
            .bind(server(7), interfaces(), EndpointLimits::STANDARD)
            .unwrap_or_else(|_| unreachable!());
        assert!(
            table
                .resolve_for(endpoint, interface::FILESYSTEM_READ, Rights::CALL)
                .is_ok()
        );
        assert_eq!(
            table
                .resolve_for(endpoint, interface::DATAGRAM, Rights::CALL)
                .err(),
            Some(DispatchError::InvalidInterface),
            "an interface outside the closed set is not reachable"
        );
        assert_eq!(
            table
                .resolve_for(endpoint, interface::FILESYSTEM_READ, Rights::NONE)
                .err(),
            Some(DispatchError::InvalidRights),
            "a handle carrying no right authorizes nothing"
        );
        assert_eq!(
            table
                .resolve_for(endpoint, interface::FILESYSTEM_READ, Rights::RESET)
                .err(),
            Some(DispatchError::InvalidRights),
            "an interface rejects a bit it has no operation for"
        );
    }

    #[test]
    fn limits_may_narrow_and_never_widen() {
        assert_eq!(
            EndpointLimits::new(0, 1, 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            EndpointLimits::new(1, 0, 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            EndpointLimits::new(1, 1, 0).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            EndpointLimits::new(MAX_QUEUED_CALLS_PER_ENDPOINT + 1, 1, 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            EndpointLimits::new(1, MAX_RETAINED_REQUEST_BYTES + 1, 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            EndpointLimits::new(1, 1, MAX_CALL_DEADLINE_MILLIS + 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        let narrow = EndpointLimits::new(2, 4_096, 500).unwrap_or_else(|_| unreachable!());
        // Narrowing takes the smaller of each pair in both directions, so a
        // published ceiling can never be enlarged by narrowing against a wider
        // request.
        assert_eq!(narrow.narrow(EndpointLimits::STANDARD), narrow);
        assert_eq!(EndpointLimits::STANDARD.narrow(narrow), narrow);
        let mixed = EndpointLimits::new(8, 1_024, 4_000).unwrap_or_else(|_| unreachable!());
        let result = narrow.narrow(mixed);
        assert_eq!(result.queued_calls(), 2);
        assert_eq!(result.retained_bytes(), 1_024);
        assert_eq!(result.deadline_millis(), 500);
    }

    #[test]
    fn an_endpoint_admits_only_deadlines_inside_its_ceiling() {
        let limits = EndpointLimits::new(2, 4_096, 500).unwrap_or_else(|_| unreachable!());
        assert!(limits.admits_deadline(1));
        assert!(limits.admits_deadline(500));
        assert!(!limits.admits_deadline(501));
        assert!(
            !limits.admits_deadline(0),
            "an unbounded deadline is not available to an ordinary client"
        );
    }
}

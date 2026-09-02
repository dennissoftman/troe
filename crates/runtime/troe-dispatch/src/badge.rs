//! Endpoint-scoped client badges.
//!
//! A persistent server has to bind open-file tokens, ports, and connections to
//! one client's lifetime. It must not do that with a global task identity: ADR
//! 0035 is explicit that a server neither learns nor trusts one. A badge is the
//! substitute — an opaque identity scoped to one `(endpoint, owner)` pair, which
//! the server may use as a key and nothing else.
//!
//! Two properties carry the weight.
//!
//! A badge is created by the *first* handle for a pair and reused by every
//! later one, so it tracks the client rather than the capability. It ends when
//! the *last* handle closes, which is the moment the server must release
//! everything keyed by it. That transition cannot be delivered through the
//! ordinary call queue, because a full queue would drop it and leak the
//! server's state; it is a bit in the badge's own slot, reserved when the badge
//! is created and consumed exactly once.
//!
//! Identity is slot plus generation, and a slot retires rather than wrapping.
//! Server-private state outlives the kernel's view of a client, so a stale
//! badge held by a server must never name a later one.

use crate::{DispatchError, HandleOwner};
use alloc::vec::Vec;

/// Hard ceiling for live client badges, from ADR 0035's Standard profile.
pub const MAX_CLIENT_BADGES: usize = 256;
/// Hard ceiling for client badges at one endpoint.
pub const MAX_BADGES_PER_ENDPOINT: usize = 32;

/// Opaque endpoint-scoped client identity.
///
/// A server receives this on every call event and may use it only as a key.
/// It encodes no task identity, no address, and nothing a server could act on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientBadge {
    slot: u32,
    generation: u32,
}

impl ClientBadge {
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

    /// Stable nonzero opaque value carried in a call event.
    ///
    /// The low 32 bits encode a one-based slot and the high bits its
    /// generation, so no live badge is ever zero and a non-client event's zero
    /// badge cannot be confused with one.
    #[must_use]
    pub const fn event_value(self) -> u64 {
        ((self.generation as u64) << 32) | (self.slot as u64 + 1)
    }
}

/// What closing one handle did to its badge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BadgeClosure {
    /// Other handles for this client remain, so the badge stays open.
    Retained,
    /// The last handle closed, and one `client-closed` event is now pending.
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BadgeState {
    /// The slot holds no client.
    Free,
    /// The client holds this many live handles at its endpoint.
    Open { handles: u32 },
    /// The last handle closed and the server has not yet consumed the event.
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BadgeSlot {
    generation: u32,
    retired: bool,
    endpoint_slot: u32,
    owner: HandleOwner,
    state: BadgeState,
}

/// Live, high-water, and lifetime badge accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BadgeStats {
    /// Badges holding at least one live handle.
    pub open: u32,
    /// Badges whose `client-closed` event is not yet consumed.
    pub pending_closed: u32,
    /// Greatest number of simultaneously occupied slots, open or pending.
    pub high_water: u32,
    /// Slots retired because their generation reached the maximum.
    pub retired: u32,
    /// Badges created over this table's lifetime.
    pub created: u64,
    /// `client-closed` events consumed by a server.
    pub closures_consumed: u64,
}

/// Bounded table of endpoint-scoped client badges.
#[derive(Debug)]
pub struct BadgeTable {
    slots: Vec<BadgeSlot>,
    open: u32,
    pending_closed: u32,
    high_water: u32,
    retired: u32,
    created: u64,
    closures_consumed: u64,
}

impl BadgeTable {
    /// Reserve every slot before any badge can be created.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-ceiling capacity, and a failed reservation.
    /// The complete table is reserved here so creating a badge never allocates,
    /// which is what lets the `client-closed` bit be preallocated with it.
    pub fn new(capacity: usize) -> Result<Self, DispatchError> {
        if capacity == 0 || capacity > MAX_CLIENT_BADGES {
            return Err(DispatchError::InvalidCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        for _ in 0..capacity {
            slots.push(BadgeSlot {
                generation: 0,
                retired: false,
                endpoint_slot: 0,
                owner: HandleOwner::Kernel,
                state: BadgeState::Free,
            });
        }
        Ok(Self {
            slots,
            open: 0,
            pending_closed: 0,
            high_water: 0,
            retired: 0,
            created: 0,
            closures_consumed: 0,
        })
    }

    /// Open one handle for a client, creating its badge if this is the first.
    ///
    /// A pair that already holds an open badge receives the same identity with
    /// its handle count raised, so a client with several handles at one
    /// endpoint is still one client to the server.
    ///
    /// # Errors
    ///
    /// Rejects an exhausted table, an endpoint already holding its maximum
    /// badges, and a handle count that would overflow.
    pub fn open(
        &mut self,
        endpoint_slot: u32,
        owner: HandleOwner,
    ) -> Result<ClientBadge, DispatchError> {
        if let Some(index) = self.find_open(endpoint_slot, owner) {
            let record = self
                .slots
                .get_mut(index)
                .ok_or(DispatchError::InvalidBadge)?;
            let BadgeState::Open { handles } = record.state else {
                return Err(DispatchError::InvalidBadge);
            };
            let handles = handles
                .checked_add(1)
                .ok_or(DispatchError::AccountingOverflow)?;
            record.state = BadgeState::Open { handles };
            let slot = u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?;
            return Ok(ClientBadge {
                slot,
                generation: record.generation,
            });
        }
        // A pending closure still occupies its endpoint's allowance: the server
        // has not released the state keyed by it, so the client is not gone.
        if self.occupied_at(endpoint_slot) >= MAX_BADGES_PER_ENDPOINT {
            return Err(DispatchError::BadgeCapacityExhausted);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.retired && slot.state == BadgeState::Free)
            .ok_or(DispatchError::BadgeCapacityExhausted)?;
        let slot = u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?;
        let created = self
            .created
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let open = self
            .open
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let record = self
            .slots
            .get_mut(index)
            .ok_or(DispatchError::InvalidBadge)?;
        let generation = record
            .generation
            .checked_add(1)
            .ok_or(DispatchError::BadgeCapacityExhausted)?;
        record.generation = generation;
        record.endpoint_slot = endpoint_slot;
        record.owner = owner;
        record.state = BadgeState::Open { handles: 1 };
        self.created = created;
        self.open = open;
        self.high_water = self
            .high_water
            .max(open.saturating_add(self.pending_closed));
        Ok(ClientBadge { slot, generation })
    }

    /// Close one of a client's handles.
    ///
    /// Closing the last one publishes the `client-closed` event by leaving the
    /// slot occupied with its reserved bit set. The slot is not reusable until
    /// a server consumes it through [`Self::take_closed`], so the event cannot
    /// be lost to slot pressure any more than to queue pressure.
    ///
    /// # Errors
    ///
    /// Rejects a stale, retired, or already closed badge.
    pub fn close_handle(&mut self, badge: ClientBadge) -> Result<BadgeClosure, DispatchError> {
        let index = self.open_index(badge)?;
        let record = self
            .slots
            .get_mut(index)
            .ok_or(DispatchError::InvalidBadge)?;
        let BadgeState::Open { handles } = record.state else {
            return Err(DispatchError::InvalidBadge);
        };
        let remaining = handles
            .checked_sub(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        if remaining > 0 {
            record.state = BadgeState::Open { handles: remaining };
            return Ok(BadgeClosure::Retained);
        }
        let open = self
            .open
            .checked_sub(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let pending = self
            .pending_closed
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        record.state = BadgeState::Closed;
        self.open = open;
        self.pending_closed = pending;
        Ok(BadgeClosure::Closed)
    }

    /// Close every handle one owner holds, across every endpoint.
    ///
    /// Task teardown does not wait for a server to release the state keyed by a
    /// badge, so this publishes each closure and returns immediately. The badge
    /// retains no pointer or mapping into the dead task, so nothing it holds
    /// keeps that task's resources alive.
    ///
    /// Returns the number of badges moved to a pending closure.
    ///
    /// # Errors
    ///
    /// Returns an accounting failure without closing any badge.
    pub fn revoke_owner(&mut self, owner: HandleOwner) -> Result<u32, DispatchError> {
        let closing = u32::try_from(
            self.slots
                .iter()
                .filter(|slot| slot.owner == owner && matches!(slot.state, BadgeState::Open { .. }))
                .count(),
        )
        .map_err(|_| DispatchError::AccountingOverflow)?;
        let open = self
            .open
            .checked_sub(closing)
            .ok_or(DispatchError::AccountingOverflow)?;
        let pending = self
            .pending_closed
            .checked_add(closing)
            .ok_or(DispatchError::AccountingOverflow)?;
        for slot in &mut self.slots {
            if slot.owner == owner && matches!(slot.state, BadgeState::Open { .. }) {
                slot.state = BadgeState::Closed;
            }
        }
        self.open = open;
        self.pending_closed = pending;
        Ok(closing)
    }

    /// Consume one pending `client-closed` event at an endpoint.
    ///
    /// Delivery is in slot order so a server observes closures deterministically
    /// rather than in an order that depends on table history. Consuming frees
    /// the slot for a later client, or retires it when its generation can no
    /// longer advance.
    ///
    /// # Errors
    ///
    /// Returns an accounting failure without consuming an event.
    pub fn take_closed(
        &mut self,
        endpoint_slot: u32,
    ) -> Result<Option<ClientBadge>, DispatchError> {
        let Some(index) = self.slots.iter().position(|slot| {
            slot.endpoint_slot == endpoint_slot && slot.state == BadgeState::Closed
        }) else {
            return Ok(None);
        };
        let slot = u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?;
        let pending = self
            .pending_closed
            .checked_sub(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let consumed = self
            .closures_consumed
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let record = self
            .slots
            .get_mut(index)
            .ok_or(DispatchError::InvalidBadge)?;
        let generation = record.generation;
        record.state = BadgeState::Free;
        record.owner = HandleOwner::Kernel;
        record.endpoint_slot = 0;
        if generation == u32::MAX {
            record.retired = true;
            self.retired = self
                .retired
                .checked_add(1)
                .ok_or(DispatchError::AccountingOverflow)?;
        }
        self.pending_closed = pending;
        self.closures_consumed = consumed;
        Ok(Some(ClientBadge { slot, generation }))
    }

    /// Resolve one badge that may still receive calls.
    ///
    /// A badge whose last handle has closed resolves to an error even before
    /// its event is consumed, so a server can never be handed another call for
    /// a client it has been told is gone.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range, retired, free, closed, or stale badge.
    pub fn resolve(&self, badge: ClientBadge) -> Result<HandleOwner, DispatchError> {
        let index = self.open_index(badge)?;
        self.slots
            .get(index)
            .map(|slot| slot.owner)
            .ok_or(DispatchError::InvalidBadge)
    }

    /// Endpoint one badge belongs to, whether open or pending closure.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range, retired, free, or stale badge.
    pub fn endpoint_of(&self, badge: ClientBadge) -> Result<u32, DispatchError> {
        let record = self
            .slots
            .get(badge.slot as usize)
            .ok_or(DispatchError::InvalidBadge)?;
        if record.retired
            || record.generation != badge.generation
            || record.state == BadgeState::Free
        {
            return Err(DispatchError::InvalidBadge);
        }
        Ok(record.endpoint_slot)
    }

    /// Live handles one badge holds, or zero once its last handle closed.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range, retired, free, or stale badge.
    pub fn handles(&self, badge: ClientBadge) -> Result<u32, DispatchError> {
        let record = self
            .slots
            .get(badge.slot as usize)
            .ok_or(DispatchError::InvalidBadge)?;
        if record.retired || record.generation != badge.generation {
            return Err(DispatchError::InvalidBadge);
        }
        match record.state {
            BadgeState::Open { handles } => Ok(handles),
            BadgeState::Closed => Ok(0),
            BadgeState::Free => Err(DispatchError::InvalidBadge),
        }
    }

    /// Current open, pending, high-water, and lifetime accounting.
    #[must_use]
    pub const fn stats(&self) -> BadgeStats {
        BadgeStats {
            open: self.open,
            pending_closed: self.pending_closed,
            high_water: self.high_water,
            retired: self.retired,
            created: self.created,
            closures_consumed: self.closures_consumed,
        }
    }

    /// Slots the table was constructed with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn find_open(&self, endpoint_slot: u32, owner: HandleOwner) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.endpoint_slot == endpoint_slot
                && slot.owner == owner
                && matches!(slot.state, BadgeState::Open { .. })
        })
    }

    /// Slots one endpoint occupies, counting pending closures.
    ///
    /// Scanning the table costs at most [`MAX_CLIENT_BADGES`] comparisons and
    /// happens only when a client's first handle opens, so the per-endpoint
    /// allowance needs no index of its own.
    fn occupied_at(&self, endpoint_slot: u32) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.endpoint_slot == endpoint_slot && slot.state != BadgeState::Free)
            .count()
    }

    fn open_index(&self, badge: ClientBadge) -> Result<usize, DispatchError> {
        let index = badge.slot as usize;
        let record = self.slots.get(index).ok_or(DispatchError::InvalidBadge)?;
        if record.retired
            || record.generation != badge.generation
            || !matches!(record.state, BadgeState::Open { .. })
        {
            return Err(DispatchError::InvalidBadge);
        }
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BadgeClosure, BadgeTable, ClientBadge, MAX_BADGES_PER_ENDPOINT, MAX_CLIENT_BADGES,
    };
    use crate::{DispatchError, HandleOwner};

    fn owner(id: u32) -> HandleOwner {
        HandleOwner::isolated(id).unwrap_or_else(|_| unreachable!())
    }

    fn table() -> BadgeTable {
        BadgeTable::new(MAX_CLIENT_BADGES).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn a_table_reserves_every_slot_and_rejects_an_impossible_capacity() {
        assert_eq!(
            BadgeTable::new(0).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            BadgeTable::new(MAX_CLIENT_BADGES + 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        let table = table();
        assert_eq!(table.capacity(), MAX_CLIENT_BADGES);
        assert_eq!(table.stats().open, 0);
        assert_eq!(table.stats().created, 0);
    }

    #[test]
    fn one_client_keeps_one_badge_across_several_handles() {
        let mut table = table();
        let first = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        let second = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            first, second,
            "a client with two handles at one endpoint is one client"
        );
        assert_eq!(table.handles(first), Ok(2));
        assert_eq!(table.stats().open, 1);
        assert_eq!(table.stats().created, 1);
        // A different owner, and the same owner at a different endpoint, are
        // both different clients: the badge is scoped to the pair.
        let other_owner = table.open(3, owner(9)).unwrap_or_else(|_| unreachable!());
        let other_endpoint = table.open(4, owner(7)).unwrap_or_else(|_| unreachable!());
        assert_ne!(other_owner, first);
        assert_ne!(other_endpoint, first);
        assert_eq!(table.stats().created, 3);
    }

    #[test]
    fn only_the_last_handle_publishes_the_closure() {
        let mut table = table();
        let badge = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        assert_eq!(table.close_handle(badge), Ok(BadgeClosure::Retained));
        assert_eq!(table.stats().pending_closed, 0);
        assert_eq!(table.handles(badge), Ok(1));
        assert_eq!(table.close_handle(badge), Ok(BadgeClosure::Closed));
        assert_eq!(table.stats().pending_closed, 1);
        assert_eq!(table.stats().open, 0);
        assert_eq!(table.handles(badge), Ok(0));
    }

    #[test]
    fn a_closed_badge_can_never_receive_another_call() {
        let mut table = table();
        let badge = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        assert_eq!(table.resolve(badge), Ok(owner(7)));
        table.close_handle(badge).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.resolve(badge).err(),
            Some(DispatchError::InvalidBadge),
            "a closed client must not be reachable even before its event is consumed"
        );
        assert_eq!(
            table.close_handle(badge).err(),
            Some(DispatchError::InvalidBadge),
            "closing twice must not publish two events"
        );
        // The endpoint is still answerable while the closure is pending, so a
        // server can route the event it has not yet consumed.
        assert_eq!(table.endpoint_of(badge), Ok(3));
    }

    #[test]
    fn a_pending_closure_survives_until_a_server_consumes_it() {
        let mut table = BadgeTable::new(1).unwrap_or_else(|_| unreachable!());
        let badge = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        table.close_handle(badge).unwrap_or_else(|_| unreachable!());
        // The one slot is still occupied, so a new client cannot displace the
        // event. A full table refuses the client rather than dropping it.
        assert_eq!(
            table.open(3, owner(9)).err(),
            Some(DispatchError::BadgeCapacityExhausted),
            "an unconsumed closure must not be evicted by a later client"
        );
        assert_eq!(table.take_closed(3), Ok(Some(badge)));
        assert_eq!(table.stats().pending_closed, 0);
        assert_eq!(table.stats().closures_consumed, 1);
        assert_eq!(
            table.take_closed(3),
            Ok(None),
            "one closure is consumed exactly once"
        );
        // Only now is the slot reusable, and the new client is a new identity.
        let next = table.open(3, owner(9)).unwrap_or_else(|_| unreachable!());
        assert_eq!(next.slot(), badge.slot());
        assert_ne!(next.generation(), badge.generation());
        assert_eq!(
            table.resolve(badge).err(),
            Some(DispatchError::InvalidBadge),
            "a stale badge held by a server must never name the later client"
        );
    }

    #[test]
    fn closures_are_taken_only_from_their_own_endpoint() {
        let mut table = table();
        let here = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        let elsewhere = table.open(4, owner(7)).unwrap_or_else(|_| unreachable!());
        table.close_handle(here).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.take_closed(4),
            Ok(None),
            "an endpoint must not consume another endpoint's closure"
        );
        assert_eq!(table.take_closed(3), Ok(Some(here)));
        table
            .close_handle(elsewhere)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(table.take_closed(4), Ok(Some(elsewhere)));
    }

    #[test]
    fn teardown_revokes_every_badge_one_owner_holds() {
        let mut table = table();
        let first = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        let second = table.open(4, owner(7)).unwrap_or_else(|_| unreachable!());
        let survivor = table.open(3, owner(9)).unwrap_or_else(|_| unreachable!());
        table.open(4, owner(7)).unwrap_or_else(|_| unreachable!());
        assert_eq!(table.revoke_owner(owner(7)), Ok(2));
        assert_eq!(table.stats().pending_closed, 2);
        assert_eq!(table.stats().open, 1);
        for revoked in [first, second] {
            assert_eq!(
                table.resolve(revoked).err(),
                Some(DispatchError::InvalidBadge)
            );
        }
        assert_eq!(
            table.resolve(survivor),
            Ok(owner(9)),
            "another client's badge must survive an unrelated teardown"
        );
        // Each revoked client still owes exactly one event, however many
        // handles it held.
        assert_eq!(table.take_closed(3), Ok(Some(first)));
        assert_eq!(table.take_closed(3), Ok(None));
        assert_eq!(table.take_closed(4), Ok(Some(second)));
        assert_eq!(table.revoke_owner(owner(7)), Ok(0));
    }

    #[test]
    fn one_endpoint_cannot_exceed_its_badge_allowance() {
        let mut table = table();
        for client in 1..=MAX_BADGES_PER_ENDPOINT {
            let id = u32::try_from(client).unwrap_or_else(|_| unreachable!());
            table.open(3, owner(id)).unwrap_or_else(|_| unreachable!());
        }
        let overflow =
            u32::try_from(MAX_BADGES_PER_ENDPOINT + 1).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.open(3, owner(overflow)).err(),
            Some(DispatchError::BadgeCapacityExhausted)
        );
        assert_eq!(
            table.open(4, owner(overflow)).map(|badge| badge.slot() > 0),
            Ok(true),
            "another endpoint has its own allowance"
        );
    }

    #[test]
    fn a_full_table_reports_badge_exhaustion() {
        let mut table = BadgeTable::new(2).unwrap_or_else(|_| unreachable!());
        table.open(1, owner(7)).unwrap_or_else(|_| unreachable!());
        table.open(2, owner(7)).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.open(3, owner(7)).err(),
            Some(DispatchError::BadgeCapacityExhausted)
        );
        assert_eq!(table.stats().high_water, 2);
    }

    #[test]
    fn a_slot_retires_at_the_maximum_generation_rather_than_wrapping() {
        let mut table = BadgeTable::new(1).unwrap_or_else(|_| unreachable!());
        let badge = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        table.slots[0].generation = u32::MAX;
        let aged = ClientBadge {
            slot: badge.slot(),
            generation: u32::MAX,
        };
        table.close_handle(aged).unwrap_or_else(|_| unreachable!());
        assert_eq!(table.take_closed(3), Ok(Some(aged)));
        assert_eq!(table.stats().retired, 1);
        assert_eq!(
            table.open(3, owner(9)).err(),
            Some(DispatchError::BadgeCapacityExhausted),
            "a retired slot must never name a later client"
        );
        assert_eq!(table.resolve(aged).err(), Some(DispatchError::InvalidBadge));
    }

    #[test]
    fn an_event_value_is_nonzero_and_distinguishes_every_incarnation() {
        let mut table = table();
        let first = table.open(3, owner(7)).unwrap_or_else(|_| unreachable!());
        assert_ne!(
            first.event_value(),
            0,
            "zero is reserved for a non-client event"
        );
        table.close_handle(first).unwrap_or_else(|_| unreachable!());
        table.take_closed(3).unwrap_or_else(|_| unreachable!());
        let second = table.open(3, owner(9)).unwrap_or_else(|_| unreachable!());
        assert_eq!(second.slot(), first.slot());
        assert_ne!(
            second.event_value(),
            first.event_value(),
            "reusing a slot must produce a different opaque value"
        );
    }
}

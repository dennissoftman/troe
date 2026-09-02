//! Pending synchronous calls, endpoint queues, and their exact accounting.
//!
//! Every call in this table is one synchronous request whose caller is blocked
//! until it produces exactly one reply or one terminal fate. ADR 0035 is
//! emphatic that this is not a mailbox: there is no send-only operation, no
//! independently persistent message, no application-visible dequeue, and no
//! message ownership after the caller is gone. The queue exists only because a
//! server that is already busy cannot take a call immediately.
//!
//! Three rules do most of the work here.
//!
//! *Every terminal state has one consumer.* A call ends once, and the state it
//! ended in is the one its caller observes. Nothing converts a terminal state
//! into success later, so a restarted server never turns a `peer-died` into a
//! reply and a retried request is a new call rather than a resurrection.
//!
//! *Identity is consumed when the server observes it.* Delivery, not reply, is
//! the point of no return. A server that takes a call and then produces an
//! invalid reply has still consumed it; the call ends as `peer-died` and is not
//! delivered again to anyone.
//!
//! *A direct handoff may not bypass an older queued call.* Skipping the queue
//! is an optimization for an idle server, not a priority, so it is available
//! only when the endpoint has nothing waiting.
//!
//! Payload storage is injected by composition. This table owns lengths, slot
//! identities, deadlines, and counters, and never a byte of payload or a
//! pointer to one. A queue slot it hands back must be zeroed before it is
//! recycled, which is the only way the model can express ADR 0035's
//! zero-before-reuse rule without owning the bytes.

use crate::{ClientBadge, DispatchError, MAX_MESSAGE_BYTES, MAX_RETAINED_REQUEST_BYTES};
use alloc::vec::Vec;

/// Hard ceiling for simultaneous pending calls, from the Standard profile.
pub const MAX_PENDING_CALLS: usize = 32;
/// Hard ceiling for calls queued at one endpoint.
pub const MAX_QUEUED_PER_ENDPOINT: usize = 8;

/// Opaque generation-checked identity of one pending call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallId {
    slot: u32,
    generation: u32,
}

impl CallId {
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

/// Queue storage this table has reserved for one request.
///
/// Composition owns the bytes. A slot handed back by a delivery or a terminal
/// fate must be zeroed and then returned through [`PendingCallTable::recycle`];
/// until it is, the table will not allocate it again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueSlotId(u32);

impl QueueSlotId {
    /// Index of the reserved storage.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// How one admitted call reached its server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// The server was waiting and nothing older was queued, so the request is
    /// copied once, straight to the server.
    Direct,
    /// The server was busy or had older work, so the request is retained in a
    /// queue slot and copied a second time when it is delivered.
    Queued,
}

/// Terminal fate of one pending call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallOutcome {
    /// The server replied. This is the only successful fate.
    Replied,
    /// The caller withdrew the call, or its client was revoked.
    Cancelled,
    /// The call's absolute deadline passed before it completed.
    TimedOut,
    /// The server died, was revoked, or produced an invalid reply.
    PeerDied,
}

/// Portable state of one pending call.
///
/// ADR 0035 names an `admitted` state ahead of `queued`, but admission here is
/// one atomic transition: every scalar, capacity, and ordering rule is checked
/// before anything is written, and the record is then published already queued
/// or already delivered. There is no instant at which a caller or a server can
/// observe a call that has been admitted and is neither, so the model does not
/// offer a state that cannot be seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallState {
    /// Retained in a queue slot, waiting for the server to become free.
    Queued,
    /// Observed by the server, which now owns the call's identity.
    Delivered,
    /// Ended, exactly once, with this fate.
    Ended(CallOutcome),
}

/// One delivery handed to a waiting server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery {
    /// The call the server now owns.
    pub call: CallId,
    /// Queue storage the request must be copied from, then zeroed and recycled.
    ///
    /// `None` for a direct handoff, whose request was copied straight into the
    /// server and never occupied a queue slot.
    pub payload: Option<QueueSlotId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallSlot {
    generation: u32,
    retired: bool,
    occupied: bool,
    endpoint_slot: u32,
    badge: ClientBadge,
    interface: u32,
    opcode: u16,
    request_bytes: u16,
    reply_capacity: u16,
    deadline_millis: u64,
    sequence: u64,
    payload: Option<QueueSlotId>,
    state: CallState,
}

/// Exact structural accounting for the portable call path.
///
/// ADR 0035 requires a nonempty direct call to perform exactly one request copy
/// and one reply copy, and a nonempty queued call exactly two request copies and
/// one reply copy. These counters are how the portable model proves it; the
/// native counters for roots, invalidations, and leases belong to Phase B.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PendingCallStats {
    /// Calls currently admitted, queued, or delivered.
    pub live: u32,
    /// Greatest number of simultaneously live calls.
    pub high_water: u32,
    /// Request bytes currently retained in queue slots.
    pub retained_bytes: u32,
    /// Greatest number of simultaneously retained request bytes.
    pub retained_high_water: u32,
    /// Calls admitted straight to a waiting server.
    pub direct_admissions: u64,
    /// Calls admitted into an endpoint queue.
    pub queued_admissions: u64,
    /// Request payload copies this model requires.
    pub request_payload_copies: u64,
    /// Reply payload copies this model requires.
    pub reply_payload_copies: u64,
    /// Queue payload slots consumed by admissions.
    pub queue_slots_consumed: u64,
    /// Calls that ended by reply.
    pub replied: u64,
    /// Calls that ended by cancellation.
    pub cancelled: u64,
    /// Calls that ended by deadline.
    pub timed_out: u64,
    /// Calls that ended because their peer died.
    pub peer_died: u64,
}

/// Bounded table of pending synchronous calls and their endpoint queues.
#[derive(Debug)]
pub struct PendingCallTable {
    slots: Vec<CallSlot>,
    free_queue_slots: Vec<QueueSlotId>,
    loaned_queue_slots: u32,
    retained_ceiling: u32,
    next_sequence: u64,
    stats: PendingCallStats,
}

impl PendingCallTable {
    /// Reserve every call record and queue slot before any call is admitted.
    ///
    /// The queue slot count is the number of requests that may be retained at
    /// once; ADR 0035 fixes it at the pending-call ceiling so the complete
    /// retained-byte maximum is accounted for.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-ceiling capacity, a retained-byte ceiling above
    /// the profile's, and a failed reservation.
    pub fn new(capacity: usize, retained_ceiling: u32) -> Result<Self, DispatchError> {
        if capacity == 0
            || capacity > MAX_PENDING_CALLS
            || retained_ceiling == 0
            || retained_ceiling > MAX_RETAINED_REQUEST_BYTES
        {
            return Err(DispatchError::InvalidCapacity);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        let mut free_queue_slots = Vec::new();
        free_queue_slots
            .try_reserve_exact(capacity)
            .map_err(|_| DispatchError::MetadataExhausted)?;
        for index in 0..capacity {
            slots.push(CallSlot {
                generation: 0,
                retired: false,
                occupied: false,
                endpoint_slot: 0,
                badge: ClientBadge::none(),
                interface: 0,
                opcode: 0,
                request_bytes: 0,
                reply_capacity: 0,
                deadline_millis: 0,
                sequence: 0,
                payload: None,
                state: CallState::Queued,
            });
            let index = u32::try_from(index).map_err(|_| DispatchError::InvalidCapacity)?;
            free_queue_slots.push(QueueSlotId(index));
        }
        Ok(Self {
            slots,
            free_queue_slots,
            loaned_queue_slots: 0,
            retained_ceiling,
            next_sequence: 0,
            stats: PendingCallStats::default(),
        })
    }

    /// Admit one validated call, direct to a waiting server or into its queue.
    ///
    /// `server_waiting` is the composition's answer to whether the endpoint's
    /// server is blocked and ready to take a call now. Even then, an endpoint
    /// with older queued work takes the queue path: a direct handoff may not
    /// bypass an older call.
    ///
    /// # Errors
    ///
    /// Rejects an oversized request or reply capacity, a zero deadline, an
    /// exhausted call table, a full endpoint queue, and a request that would
    /// exceed the retained-byte ceiling. Queue-full and table-full are distinct
    /// results, and neither has any service-visible effect.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        endpoint_slot: u32,
        badge: ClientBadge,
        interface: u32,
        opcode: u16,
        request_bytes: usize,
        reply_capacity: usize,
        deadline_millis: u64,
        server_waiting: bool,
    ) -> Result<(CallId, Admission), DispatchError> {
        if request_bytes > MAX_MESSAGE_BYTES || reply_capacity > MAX_MESSAGE_BYTES {
            return Err(DispatchError::MessageTooLarge);
        }
        if deadline_millis == 0 {
            return Err(DispatchError::InvalidDeadline);
        }
        let request_bytes =
            u16::try_from(request_bytes).map_err(|_| DispatchError::MessageTooLarge)?;
        let reply_capacity =
            u16::try_from(reply_capacity).map_err(|_| DispatchError::MessageTooLarge)?;
        let direct = server_waiting && self.oldest_queued(endpoint_slot).is_none();
        if !direct && self.queued_at(endpoint_slot) >= MAX_QUEUED_PER_ENDPOINT {
            return Err(DispatchError::QueueFull);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.retired && !slot.occupied)
            .ok_or(DispatchError::CallCapacityExhausted)?;
        // Reserve the queue slot and its bytes before any mutation, so a
        // capacity failure leaves the table exactly as it was.
        let reservation = if direct {
            None
        } else {
            let retained = self
                .stats
                .retained_bytes
                .checked_add(u32::from(request_bytes))
                .ok_or(DispatchError::AccountingOverflow)?;
            if retained > self.retained_ceiling {
                return Err(DispatchError::RetainedBytesExhausted);
            }
            let slot = *self
                .free_queue_slots
                .last()
                .ok_or(DispatchError::QueueFull)?;
            Some((slot, retained))
        };
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let live = self
            .stats
            .live
            .checked_add(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let slot_index = u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?;
        let record = self
            .slots
            .get_mut(index)
            .ok_or(DispatchError::InvalidCall)?;
        let generation = record
            .generation
            .checked_add(1)
            .ok_or(DispatchError::CallCapacityExhausted)?;
        record.generation = generation;
        record.occupied = true;
        record.endpoint_slot = endpoint_slot;
        record.badge = badge;
        record.interface = interface;
        record.opcode = opcode;
        record.request_bytes = request_bytes;
        record.reply_capacity = reply_capacity;
        record.deadline_millis = deadline_millis;
        record.sequence = sequence;
        let nonempty_request = u64::from(request_bytes != 0);
        let (state, payload, admission) = match reservation {
            None => (CallState::Delivered, None, Admission::Direct),
            Some((slot, _)) => (CallState::Queued, Some(slot), Admission::Queued),
        };
        record.state = state;
        record.payload = payload;
        if let Some((slot, retained)) = reservation {
            self.free_queue_slots.retain(|free| *free != slot);
            self.loaned_queue_slots = self.loaned_queue_slots.saturating_add(1);
            self.stats.retained_bytes = retained;
            self.stats.retained_high_water = self.stats.retained_high_water.max(retained);
            self.stats.queued_admissions = self.stats.queued_admissions.saturating_add(1);
            self.stats.queue_slots_consumed = self.stats.queue_slots_consumed.saturating_add(1);
            // A queued request is copied into the slot now and out of it at
            // delivery: two copies for one nonempty request.
            self.stats.request_payload_copies = self
                .stats
                .request_payload_copies
                .saturating_add(nonempty_request.saturating_mul(2));
        } else {
            self.stats.direct_admissions = self.stats.direct_admissions.saturating_add(1);
            self.stats.request_payload_copies = self
                .stats
                .request_payload_copies
                .saturating_add(nonempty_request);
        }
        self.next_sequence = sequence;
        self.stats.live = live;
        self.stats.high_water = self.stats.high_water.max(live);
        Ok((
            CallId {
                slot: slot_index,
                generation,
            },
            admission,
        ))
    }

    /// Deliver the oldest queued call at one endpoint.
    ///
    /// Delivery consumes the call's identity: the server owns it from here, and
    /// no later failure returns it to the queue for another attempt.
    ///
    /// Returns `None` when the endpoint has nothing queued.
    ///
    /// # Errors
    ///
    /// Returns an accounting failure without delivering.
    pub fn deliver_next(&mut self, endpoint_slot: u32) -> Result<Option<Delivery>, DispatchError> {
        let Some(index) = self.oldest_queued(endpoint_slot) else {
            return Ok(None);
        };
        let record = self.slots.get(index).ok_or(DispatchError::InvalidCall)?;
        let released = u32::from(record.request_bytes);
        let payload = record.payload;
        let call = CallId {
            slot: u32::try_from(index).map_err(|_| DispatchError::AccountingOverflow)?,
            generation: record.generation,
        };
        let retained = self
            .stats
            .retained_bytes
            .checked_sub(released)
            .ok_or(DispatchError::AccountingOverflow)?;
        let record = self
            .slots
            .get_mut(index)
            .ok_or(DispatchError::InvalidCall)?;
        record.state = CallState::Delivered;
        // The bytes stop being retained the moment they reach the server, but
        // the slot itself stays loaned until composition zeroes and recycles it.
        record.payload = None;
        self.stats.retained_bytes = retained;
        Ok(Some(Delivery { call, payload }))
    }

    /// End one call with its single terminal fate.
    ///
    /// # Errors
    ///
    /// Rejects a stale or already ended call, a reply from a call the server
    /// never took, and an accounting failure. A call may only be replied to
    /// from [`CallState::Delivered`], because a reply to a call no server
    /// observed would be a forged completion.
    pub fn complete(
        &mut self,
        call: CallId,
        outcome: CallOutcome,
    ) -> Result<Option<QueueSlotId>, DispatchError> {
        let index = self.live_index(call)?;
        let record = self.slots.get(index).ok_or(DispatchError::InvalidCall)?;
        if outcome == CallOutcome::Replied && record.state != CallState::Delivered {
            return Err(DispatchError::InvalidCall);
        }
        let released = match record.payload {
            Some(_) => u32::from(record.request_bytes),
            None => 0,
        };
        let payload = record.payload;
        let retained = self
            .stats
            .retained_bytes
            .checked_sub(released)
            .ok_or(DispatchError::AccountingOverflow)?;
        let live = self
            .stats
            .live
            .checked_sub(1)
            .ok_or(DispatchError::AccountingOverflow)?;
        let nonempty_reply =
            u64::from(outcome == CallOutcome::Replied && record.reply_capacity > 0);
        let record = self
            .slots
            .get_mut(index)
            .ok_or(DispatchError::InvalidCall)?;
        record.state = CallState::Ended(outcome);
        record.payload = None;
        record.occupied = false;
        if record.generation == u32::MAX {
            record.retired = true;
        }
        self.stats.retained_bytes = retained;
        self.stats.live = live;
        self.stats.reply_payload_copies = self
            .stats
            .reply_payload_copies
            .saturating_add(nonempty_reply);
        match outcome {
            CallOutcome::Replied => self.stats.replied = self.stats.replied.saturating_add(1),
            CallOutcome::Cancelled => self.stats.cancelled = self.stats.cancelled.saturating_add(1),
            CallOutcome::TimedOut => self.stats.timed_out = self.stats.timed_out.saturating_add(1),
            CallOutcome::PeerDied => self.stats.peer_died = self.stats.peer_died.saturating_add(1),
        }
        Ok(payload)
    }

    /// Return one zeroed queue slot to the free list.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range slot and one that is not currently loaned, so a
    /// slot cannot be recycled twice into two simultaneous requests.
    pub fn recycle(&mut self, slot: QueueSlotId) -> Result<(), DispatchError> {
        if slot.index() as usize >= self.slots.len() {
            return Err(DispatchError::InvalidCall);
        }
        if self.free_queue_slots.contains(&slot) || self.loaned_queue_slots == 0 {
            return Err(DispatchError::InvalidCall);
        }
        self.free_queue_slots.push(slot);
        self.loaned_queue_slots = self.loaned_queue_slots.saturating_sub(1);
        Ok(())
    }

    /// The earliest-deadline call that is due at `now_millis`, if any.
    ///
    /// A deadline applies from admission through delivery, so a call the server
    /// is holding expires exactly as one still queued does.
    #[must_use]
    pub fn due(&self, now_millis: u64) -> Option<CallId> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| {
                slot.occupied
                    && !matches!(slot.state, CallState::Ended(_))
                    && slot.deadline_millis <= now_millis
            })
            .min_by_key(|(_, slot)| (slot.deadline_millis, slot.sequence))
            .and_then(|(index, slot)| {
                Some(CallId {
                    slot: u32::try_from(index).ok()?,
                    generation: slot.generation,
                })
            })
    }

    /// Current state of one live call.
    ///
    /// # Errors
    ///
    /// Rejects a stale, retired, or ended call.
    pub fn state(&self, call: CallId) -> Result<CallState, DispatchError> {
        let index = self.live_index(call)?;
        self.slots
            .get(index)
            .map(|slot| slot.state)
            .ok_or(DispatchError::InvalidCall)
    }

    /// Endpoint-scoped client that made one live call.
    ///
    /// # Errors
    ///
    /// Rejects a stale, retired, or ended call.
    pub fn badge(&self, call: CallId) -> Result<ClientBadge, DispatchError> {
        let index = self.live_index(call)?;
        self.slots
            .get(index)
            .map(|slot| slot.badge)
            .ok_or(DispatchError::InvalidCall)
    }

    /// Calls currently queued at one endpoint.
    #[must_use]
    pub fn queued_at(&self, endpoint_slot: u32) -> usize {
        self.slots
            .iter()
            .filter(|slot| {
                slot.occupied
                    && slot.endpoint_slot == endpoint_slot
                    && slot.state == CallState::Queued
            })
            .count()
    }

    /// Exact structural and lifetime accounting.
    #[must_use]
    pub const fn stats(&self) -> PendingCallStats {
        self.stats
    }

    /// Call records the table was constructed with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn oldest_queued(&self, endpoint_slot: u32) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| {
                slot.occupied
                    && slot.endpoint_slot == endpoint_slot
                    && slot.state == CallState::Queued
            })
            .min_by_key(|(_, slot)| slot.sequence)
            .map(|(index, _)| index)
    }

    fn live_index(&self, call: CallId) -> Result<usize, DispatchError> {
        let index = call.slot as usize;
        let record = self.slots.get(index).ok_or(DispatchError::InvalidCall)?;
        if record.retired || !record.occupied || record.generation != call.generation {
            return Err(DispatchError::InvalidCall);
        }
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Admission, CallOutcome, CallState, MAX_PENDING_CALLS, MAX_QUEUED_PER_ENDPOINT,
        PendingCallTable,
    };
    use crate::{ClientBadge, DispatchError, MAX_RETAINED_REQUEST_BYTES};

    const DEADLINE: u64 = 4_000;

    fn table() -> PendingCallTable {
        PendingCallTable::new(MAX_PENDING_CALLS, MAX_RETAINED_REQUEST_BYTES)
            .unwrap_or_else(|_| unreachable!())
    }

    /// Admit one 64-byte call, choosing the path the server's state implies.
    fn admit(
        table: &mut PendingCallTable,
        endpoint: u32,
        waiting: bool,
    ) -> Result<(super::CallId, Admission), DispatchError> {
        table.admit(
            endpoint,
            ClientBadge::none(),
            6,
            1,
            64,
            128,
            DEADLINE,
            waiting,
        )
    }

    #[test]
    fn a_table_reserves_every_record_and_rejects_an_impossible_capacity() {
        assert_eq!(
            PendingCallTable::new(0, 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            PendingCallTable::new(MAX_PENDING_CALLS + 1, 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            PendingCallTable::new(1, 0).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(
            PendingCallTable::new(1, MAX_RETAINED_REQUEST_BYTES + 1).err(),
            Some(DispatchError::InvalidCapacity)
        );
        assert_eq!(table().capacity(), MAX_PENDING_CALLS);
    }

    #[test]
    fn a_waiting_server_takes_one_copy_and_a_busy_one_takes_two() {
        let mut table = table();
        let (direct, admission) = admit(&mut table, 3, true).unwrap_or_else(|_| unreachable!());
        assert_eq!(admission, Admission::Direct);
        assert_eq!(table.state(direct), Ok(CallState::Delivered));
        assert_eq!(table.stats().request_payload_copies, 1);
        assert_eq!(table.stats().queue_slots_consumed, 0);
        assert_eq!(
            table.stats().retained_bytes,
            0,
            "a direct request is never retained"
        );

        let (queued, admission) = admit(&mut table, 4, false).unwrap_or_else(|_| unreachable!());
        assert_eq!(admission, Admission::Queued);
        assert_eq!(table.state(queued), Ok(CallState::Queued));
        assert_eq!(table.stats().request_payload_copies, 3, "one plus two");
        assert_eq!(table.stats().queue_slots_consumed, 1);
        assert_eq!(table.stats().retained_bytes, 64);
    }

    #[test]
    fn an_empty_direction_costs_no_copy() {
        let mut table = table();
        let (call, _) = table
            .admit(3, ClientBadge::none(), 6, 1, 0, 0, DEADLINE, true)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(table.stats().request_payload_copies, 0);
        table
            .complete(call, CallOutcome::Replied)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.stats().reply_payload_copies,
            0,
            "a zero-capacity reply copies nothing"
        );
    }

    #[test]
    fn a_direct_handoff_never_bypasses_an_older_queued_call() {
        let mut table = table();
        let (older, _) = admit(&mut table, 3, false).unwrap_or_else(|_| unreachable!());
        // The server is waiting now, but something older is already queued, so
        // the new call still queues behind it.
        let (newer, admission) = admit(&mut table, 3, true).unwrap_or_else(|_| unreachable!());
        assert_eq!(admission, Admission::Queued);
        let delivery = table
            .deliver_next(3)
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|| unreachable!());
        assert_eq!(delivery.call, older, "the queue is FIFO");
        // A different endpoint's queue does not hold this one back.
        let (other, admission) = admit(&mut table, 4, true).unwrap_or_else(|_| unreachable!());
        assert_eq!(admission, Admission::Direct);
        assert_eq!(table.state(other), Ok(CallState::Delivered));
        assert_eq!(table.state(newer), Ok(CallState::Queued));
    }

    #[test]
    fn delivery_releases_the_bytes_and_loans_the_slot_until_it_is_recycled() {
        let mut table =
            PendingCallTable::new(1, MAX_RETAINED_REQUEST_BYTES).unwrap_or_else(|_| unreachable!());
        let (call, _) = admit(&mut table, 3, false).unwrap_or_else(|_| unreachable!());
        assert_eq!(table.stats().retained_bytes, 64);
        let delivery = table
            .deliver_next(3)
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|| unreachable!());
        let slot = delivery.payload.unwrap_or_else(|| unreachable!());
        assert_eq!(
            table.stats().retained_bytes,
            0,
            "bytes stop being retained once they reach the server"
        );
        assert_eq!(table.state(call), Ok(CallState::Delivered));
        assert_eq!(
            table.deliver_next(3),
            Ok(None),
            "a delivered call is not delivered twice"
        );
        table
            .complete(call, CallOutcome::Replied)
            .unwrap_or_else(|_| unreachable!());
        // Until the slot is zeroed and recycled the table will not lend it out
        // again, so a later request cannot land on unzeroed storage.
        assert_eq!(
            admit(&mut table, 3, false).err(),
            Some(DispatchError::QueueFull)
        );
        table.recycle(slot).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.recycle(slot).err(),
            Some(DispatchError::InvalidCall),
            "a slot cannot be recycled twice into two live requests"
        );
        assert!(admit(&mut table, 3, false).is_ok());
    }

    #[test]
    fn every_call_ends_exactly_once() {
        for outcome in [
            CallOutcome::Replied,
            CallOutcome::Cancelled,
            CallOutcome::TimedOut,
            CallOutcome::PeerDied,
        ] {
            let mut table = table();
            let (call, _) = admit(&mut table, 3, true).unwrap_or_else(|_| unreachable!());
            table
                .complete(call, outcome)
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(
                table.complete(call, CallOutcome::Replied).err(),
                Some(DispatchError::InvalidCall),
                "{outcome:?} must not be reopened, least of all into a reply"
            );
            assert_eq!(table.state(call).err(), Some(DispatchError::InvalidCall));
            assert_eq!(table.stats().live, 0);
        }
    }

    #[test]
    fn only_a_delivered_call_may_be_replied_to() {
        let mut table = table();
        let (queued, _) = admit(&mut table, 3, false).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table.complete(queued, CallOutcome::Replied).err(),
            Some(DispatchError::InvalidCall),
            "a reply to a call no server observed would be forged"
        );
        // Every other fate is available from the queue.
        assert!(table.complete(queued, CallOutcome::Cancelled).is_ok());
    }

    #[test]
    fn queue_full_and_table_full_are_distinct_results() {
        let mut table = table();
        for _ in 0..MAX_QUEUED_PER_ENDPOINT {
            admit(&mut table, 3, false).unwrap_or_else(|_| unreachable!());
        }
        assert_eq!(
            admit(&mut table, 3, false).err(),
            Some(DispatchError::QueueFull),
            "one endpoint's queue fills before the table does"
        );
        // Other endpoints keep working until the shared table is exhausted.
        let mut endpoint = 4;
        while admit(&mut table, endpoint, false).is_ok() {
            endpoint += 1;
        }
        assert_eq!(
            admit(&mut table, endpoint, false).err(),
            Some(DispatchError::CallCapacityExhausted)
        );
        let ceiling = u32::try_from(MAX_PENDING_CALLS).unwrap_or_else(|_| unreachable!());
        assert_eq!(table.stats().live, ceiling);
        assert_eq!(table.stats().high_water, ceiling);
    }

    #[test]
    fn the_retained_byte_ceiling_refuses_a_request_it_cannot_hold() {
        let mut table = PendingCallTable::new(4, 128).unwrap_or_else(|_| unreachable!());
        table
            .admit(3, ClientBadge::none(), 6, 1, 100, 0, DEADLINE, false)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            table
                .admit(4, ClientBadge::none(), 6, 1, 29, 0, DEADLINE, false)
                .err(),
            Some(DispatchError::RetainedBytesExhausted)
        );
        // The refusal changed nothing, so a request that does fit still lands.
        assert_eq!(table.stats().retained_bytes, 100);
        assert!(
            table
                .admit(4, ClientBadge::none(), 6, 1, 28, 0, DEADLINE, false)
                .is_ok()
        );
        assert_eq!(table.stats().retained_bytes, 128);
        assert_eq!(table.stats().retained_high_water, 128);
    }

    #[test]
    fn a_deadline_expires_a_queued_and_a_delivered_call_alike() {
        let mut table = table();
        let (queued, _) = table
            .admit(3, ClientBadge::none(), 6, 1, 8, 8, 500, false)
            .unwrap_or_else(|_| unreachable!());
        let (delivered, _) = table
            .admit(4, ClientBadge::none(), 6, 1, 8, 8, 200, true)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(table.due(199), None);
        assert_eq!(
            table.due(200),
            Some(delivered),
            "the earliest deadline is due first, and delivery does not exempt it"
        );
        table
            .complete(delivered, CallOutcome::TimedOut)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(table.due(499), None);
        assert_eq!(table.due(500), Some(queued));
        assert_eq!(table.stats().timed_out, 1);
    }

    #[test]
    fn an_admission_rejects_bounds_no_client_may_exceed() {
        let mut table = table();
        assert_eq!(
            table
                .admit(3, ClientBadge::none(), 6, 1, 4_097, 0, DEADLINE, true)
                .err(),
            Some(DispatchError::MessageTooLarge)
        );
        assert_eq!(
            table
                .admit(3, ClientBadge::none(), 6, 1, 0, 4_097, DEADLINE, true)
                .err(),
            Some(DispatchError::MessageTooLarge)
        );
        assert_eq!(
            table
                .admit(3, ClientBadge::none(), 6, 1, 8, 8, 0, true)
                .err(),
            Some(DispatchError::InvalidDeadline),
            "an unbounded deadline is not available to an ordinary client"
        );
        assert_eq!(table.stats().live, 0, "no rejection admitted a call");
    }

    #[test]
    fn a_reused_record_is_a_different_call() {
        let mut table =
            PendingCallTable::new(1, MAX_RETAINED_REQUEST_BYTES).unwrap_or_else(|_| unreachable!());
        let (first, _) = admit(&mut table, 3, true).unwrap_or_else(|_| unreachable!());
        table
            .complete(first, CallOutcome::Replied)
            .unwrap_or_else(|_| unreachable!());
        let (second, _) = admit(&mut table, 3, true).unwrap_or_else(|_| unreachable!());
        assert_eq!(second.slot(), first.slot());
        assert_ne!(second.generation(), first.generation());
        assert_eq!(
            table.state(first).err(),
            Some(DispatchError::InvalidCall),
            "a stale identity must never name the later call in the same record"
        );
    }

    #[test]
    fn the_badge_travels_with_the_call() {
        let mut table = table();
        let badge = ClientBadge::none();
        let (call, _) = admit(&mut table, 3, true).unwrap_or_else(|_| unreachable!());
        assert_eq!(table.badge(call), Ok(badge));
        table
            .complete(call, CallOutcome::Cancelled)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(table.badge(call).err(), Some(DispatchError::InvalidCall));
    }
}

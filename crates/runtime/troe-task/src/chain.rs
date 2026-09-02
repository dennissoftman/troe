//! Synchronous call chains and the donation they represent.
//!
//! When a task calls a server, the server runs on the caller's execution
//! segment rather than waiting for a scheduler turn of its own. ADR 0035 calls
//! that donation, and on the accepted single-CPU scheduler it is the whole
//! priority policy: a provider needed to finish the original request runs now,
//! because the work it is doing belongs to the caller that is blocked on it.
//!
//! A chain is the ordered record of who donated to whom. It exists to answer
//! two questions before a call is delivered.
//!
//! *Would this call wait on itself?* A task already in the chain cannot be
//! entered again, because it is blocked further up the same chain and could
//! never reply. That is rejected as a deadlock rather than discovered as a
//! hang.
//!
//! *Is the chain already as deep as it may go?* Four members is the bound. The
//! deepest intended path is an application, the VFS server, and a provider;
//! the kernel's block broker is a kernel mechanism rather than a chain member,
//! so four leaves one bounded mediation step without admitting recursion.
//!
//! A task takes part in at most one chain, holding at most one outbound call
//! and at most one delivered inbound call. That is what makes a server
//! non-reentrant: a second caller queues at the endpoint instead of entering a
//! server that is already running.

use super::TaskId;
use alloc::vec::Vec;
use core::fmt;

/// Maximum user tasks in one synchronous call chain.
pub const MAX_CALL_CHAIN_MEMBERS: usize = 4;
/// Maximum simultaneously live chains.
///
/// A chain needs at least one member and a task belongs to at most one chain,
/// so the scheduler's live-record ceiling bounds this too.
pub const MAX_CALL_CHAINS: usize = 16;

/// Call-chain admission and unwind failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallChainError {
    /// The callee is already in this chain and could never reply.
    Deadlock,
    /// The chain is already at [`MAX_CALL_CHAIN_MEMBERS`], or no chain record
    /// remains.
    Exhausted,
    /// The caller already owns an outbound call, or the callee already owns a
    /// delivered inbound one.
    Busy,
    /// The named task is not the active member of any chain.
    NotActive,
}

impl fmt::Display for CallChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deadlock => formatter.write_str("call would wait on its own chain"),
            Self::Exhausted => formatter.write_str("call chain capacity exhausted"),
            Self::Busy => formatter.write_str("task already owns a synchronous call"),
            Self::NotActive => formatter.write_str("task is not an active chain member"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Chain {
    members: Vec<TaskId>,
}

/// Live and high-water chain accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallChainStats {
    /// Chains currently holding at least one call.
    pub live: u32,
    /// Greatest depth any chain has reached.
    pub deepest: u32,
    /// Calls entered over this table's lifetime.
    pub entries: u64,
    /// Calls rejected because the callee was already in the chain.
    pub deadlocks: u64,
    /// Calls rejected because the chain or table was full.
    pub exhaustions: u64,
}

/// Bounded table of live synchronous call chains.
#[derive(Debug)]
pub struct CallChainTable {
    chains: Vec<Option<Chain>>,
    stats: CallChainStats,
}

impl CallChainTable {
    /// Reserve every chain record before any call is entered.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-ceiling capacity and a failed reservation.
    pub fn new(capacity: usize) -> Result<Self, CallChainError> {
        if capacity == 0 || capacity > MAX_CALL_CHAINS {
            return Err(CallChainError::Exhausted);
        }
        let mut chains = Vec::new();
        chains
            .try_reserve_exact(capacity)
            .map_err(|_| CallChainError::Exhausted)?;
        for _ in 0..capacity {
            chains.push(None);
        }
        Ok(Self {
            chains,
            stats: CallChainStats::default(),
        })
    }

    /// Admit one synchronous call from `caller` into `target`.
    ///
    /// A caller that is not yet in a chain starts one, so an application's
    /// first call into a server creates the two-member chain that later hops
    /// extend. Returns the chain's depth after the entry.
    ///
    /// # Errors
    ///
    /// Rejects a target already in the caller's chain as [`CallChainError::Deadlock`],
    /// a chain or table at its bound as [`CallChainError::Exhausted`], and a
    /// caller or target that already owns a synchronous call as
    /// [`CallChainError::Busy`]. Every check runs before any mutation, so a
    /// rejected call leaves the table unchanged.
    pub fn enter(&mut self, caller: TaskId, target: TaskId) -> Result<usize, CallChainError> {
        if caller == target {
            self.stats.deadlocks = self.stats.deadlocks.saturating_add(1);
            return Err(CallChainError::Deadlock);
        }
        let caller_chain = self.chain_of(caller);
        // A target already taking part anywhere is either blocked in this
        // chain, which is the deadlock, or busy in another one, which is what
        // makes a server non-reentrant.
        if let Some(target_chain) = self.chain_of(target) {
            if Some(target_chain) == caller_chain {
                self.stats.deadlocks = self.stats.deadlocks.saturating_add(1);
                return Err(CallChainError::Deadlock);
            }
            return Err(CallChainError::Busy);
        }
        if let Some(index) = caller_chain {
            self.extend(index, caller, target)
        } else {
            self.begin(caller, target)
        }
    }

    fn extend(
        &mut self,
        index: usize,
        caller: TaskId,
        target: TaskId,
    ) -> Result<usize, CallChainError> {
        let chain = self
            .chains
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(CallChainError::NotActive)?;
        // Only the member currently running may donate onward. A task further
        // up the chain is blocked and cannot be calling.
        if chain.members.last() != Some(&caller) {
            return Err(CallChainError::Busy);
        }
        if chain.members.len() >= MAX_CALL_CHAIN_MEMBERS {
            self.stats.exhaustions = self.stats.exhaustions.saturating_add(1);
            return Err(CallChainError::Exhausted);
        }
        let chain = self
            .chains
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(CallChainError::NotActive)?;
        chain.members.push(target);
        let depth = chain.members.len();
        self.record_entry(depth);
        Ok(depth)
    }

    fn begin(&mut self, caller: TaskId, target: TaskId) -> Result<usize, CallChainError> {
        let index = self
            .chains
            .iter()
            .position(Option::is_none)
            .ok_or(CallChainError::Exhausted)
            .inspect_err(|_| {
                self.stats.exhaustions = self.stats.exhaustions.saturating_add(1);
            })?;
        let mut members = Vec::new();
        members
            .try_reserve_exact(MAX_CALL_CHAIN_MEMBERS)
            .map_err(|_| CallChainError::Exhausted)?;
        members.push(caller);
        members.push(target);
        let depth = members.len();
        let slot = self
            .chains
            .get_mut(index)
            .ok_or(CallChainError::Exhausted)?;
        *slot = Some(Chain { members });
        self.stats.live = self.stats.live.saturating_add(1);
        self.record_entry(depth);
        Ok(depth)
    }

    /// Unwind one member as its call completes, returning who resumes.
    ///
    /// `member` must be the chain's active member: the reply belongs to the
    /// call that is actually running. Returns the immediate caller that now
    /// resumes, or `None` when the chain's initiator has nothing above it and
    /// the chain is finished.
    ///
    /// # Errors
    ///
    /// Rejects a task that is not the active member of any chain.
    pub fn unwind(&mut self, member: TaskId) -> Result<Option<TaskId>, CallChainError> {
        let index = self.chain_of(member).ok_or(CallChainError::NotActive)?;
        let chain = self
            .chains
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(CallChainError::NotActive)?;
        if chain.members.last() != Some(&member) {
            return Err(CallChainError::NotActive);
        }
        chain.members.pop();
        let resumed = chain.members.last().copied();
        // One remaining member is an initiator with no outstanding call, which
        // is not a chain: the record is released so its slot and that task are
        // both free again.
        if chain.members.len() <= 1 {
            *self
                .chains
                .get_mut(index)
                .ok_or(CallChainError::NotActive)? = None;
            self.stats.live = self.stats.live.saturating_sub(1);
        }
        Ok(resumed)
    }

    /// Abandon the whole chain one task takes part in.
    ///
    /// A lease expiry or fault kills the running task rather than completing
    /// its call, so the chain unwinds at once instead of member by member.
    /// Returns the members that were abandoned, deepest last.
    ///
    /// # Errors
    ///
    /// Rejects a task that takes part in no chain, and a failed reservation.
    pub fn abandon(&mut self, member: TaskId) -> Result<Vec<TaskId>, CallChainError> {
        let index = self.chain_of(member).ok_or(CallChainError::NotActive)?;
        let slot = self
            .chains
            .get_mut(index)
            .ok_or(CallChainError::NotActive)?;
        let chain = slot.take().ok_or(CallChainError::NotActive)?;
        self.stats.live = self.stats.live.saturating_sub(1);
        Ok(chain.members)
    }

    /// The member currently running in the chain one task takes part in.
    #[must_use]
    pub fn active(&self, member: TaskId) -> Option<TaskId> {
        self.chain_of(member)
            .and_then(|index| self.chains.get(index))
            .and_then(Option::as_ref)
            .and_then(|chain| chain.members.last().copied())
    }

    /// Members of the chain one task takes part in, initiator first.
    #[must_use]
    pub fn members(&self, member: TaskId) -> Option<&[TaskId]> {
        self.chain_of(member)
            .and_then(|index| self.chains.get(index))
            .and_then(Option::as_ref)
            .map(|chain| chain.members.as_slice())
    }

    /// Depth of the chain one task takes part in.
    #[must_use]
    pub fn depth(&self, member: TaskId) -> usize {
        self.members(member).map_or(0, <[TaskId]>::len)
    }

    /// Whether one task takes part in any chain.
    #[must_use]
    pub fn is_engaged(&self, member: TaskId) -> bool {
        self.chain_of(member).is_some()
    }

    /// Live, depth, and rejection accounting.
    #[must_use]
    pub const fn stats(&self) -> CallChainStats {
        self.stats
    }

    /// Chain records the table was constructed with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.chains.len()
    }

    fn chain_of(&self, task: TaskId) -> Option<usize> {
        self.chains.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|chain| chain.members.contains(&task))
        })
    }

    fn record_entry(&mut self, depth: usize) {
        self.stats.entries = self.stats.entries.saturating_add(1);
        let depth = u32::try_from(depth).unwrap_or(u32::MAX);
        self.stats.deepest = self.stats.deepest.max(depth);
    }
}

#[cfg(test)]
mod tests {
    use super::{CallChainError, CallChainTable, MAX_CALL_CHAIN_MEMBERS, MAX_CALL_CHAINS};
    use crate::TaskId;

    /// The scheduler issues task identities; a test names them directly.
    fn task(id: u32) -> TaskId {
        TaskId(id)
    }

    fn table() -> CallChainTable {
        CallChainTable::new(MAX_CALL_CHAINS).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn a_table_reserves_every_record_and_rejects_an_impossible_capacity() {
        assert_eq!(
            CallChainTable::new(0).err(),
            Some(CallChainError::Exhausted)
        );
        assert_eq!(
            CallChainTable::new(MAX_CALL_CHAINS + 1).err(),
            Some(CallChainError::Exhausted)
        );
        assert_eq!(table().capacity(), MAX_CALL_CHAINS);
        assert_eq!(table().stats().live, 0);
    }

    #[test]
    fn a_first_call_starts_a_two_member_chain_that_later_hops_extend() {
        let mut chains = table();
        assert_eq!(chains.enter(task(1), task(2)), Ok(2));
        assert_eq!(chains.members(task(1)), Some([task(1), task(2)].as_slice()));
        assert_eq!(chains.active(task(1)), Some(task(2)));
        assert_eq!(chains.stats().live, 1);
        // The intended deepest path: application, VFS server, provider.
        assert_eq!(chains.enter(task(2), task(3)), Ok(3));
        assert_eq!(chains.depth(task(1)), 3);
        assert_eq!(chains.active(task(3)), Some(task(3)));
        assert_eq!(chains.stats().deepest, 3);
    }

    #[test]
    fn a_task_already_in_the_chain_is_a_deadlock_not_a_hang() {
        let mut chains = table();
        chains
            .enter(task(1), task(2))
            .unwrap_or_else(|_| unreachable!());
        chains
            .enter(task(2), task(3))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            chains.enter(task(3), task(1)),
            Err(CallChainError::Deadlock),
            "the initiator is blocked above and could never reply"
        );
        assert_eq!(
            chains.enter(task(3), task(2)),
            Err(CallChainError::Deadlock),
            "a middle member is blocked too"
        );
        assert_eq!(
            chains.enter(task(3), task(3)),
            Err(CallChainError::Deadlock),
            "a self-call is the same condition"
        );
        assert_eq!(chains.depth(task(1)), 3, "no rejection changed the chain");
        assert_eq!(chains.stats().deadlocks, 3);
    }

    #[test]
    fn the_chain_depth_is_bounded() {
        let mut chains = table();
        for member in 1..MAX_CALL_CHAIN_MEMBERS {
            let member = u32::try_from(member).unwrap_or_else(|_| unreachable!());
            chains
                .enter(task(member), task(member + 1))
                .unwrap_or_else(|_| unreachable!());
        }
        let last = u32::try_from(MAX_CALL_CHAIN_MEMBERS).unwrap_or_else(|_| unreachable!());
        assert_eq!(chains.depth(task(1)), MAX_CALL_CHAIN_MEMBERS);
        assert_eq!(
            chains.enter(task(last), task(last + 1)),
            Err(CallChainError::Exhausted),
            "depth is exhausted, which is a different fate from a deadlock"
        );
        assert_eq!(chains.stats().exhaustions, 1);
        assert_eq!(chains.stats().deadlocks, 0);
    }

    #[test]
    fn a_server_running_for_one_client_is_not_reentrant() {
        let mut chains = table();
        chains
            .enter(task(1), task(9))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            chains.enter(task(2), task(9)),
            Err(CallChainError::Busy),
            "a second caller queues rather than entering a running server"
        );
        // The busy server is in another chain, so this is not a deadlock.
        assert_eq!(chains.stats().deadlocks, 0);
        // A blocked member cannot donate onward either; only the active one can.
        chains
            .enter(task(9), task(10))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            chains.enter(task(1), task(11)),
            Err(CallChainError::Busy),
            "the initiator is blocked and is not the one calling"
        );
    }

    #[test]
    fn unwinding_resumes_the_immediate_caller_and_frees_the_chain() {
        let mut chains = table();
        chains
            .enter(task(1), task(2))
            .unwrap_or_else(|_| unreachable!());
        chains
            .enter(task(2), task(3))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            chains.unwind(task(3)),
            Ok(Some(task(2))),
            "the provider's reply resumes the VFS server"
        );
        assert_eq!(chains.depth(task(1)), 2);
        assert_eq!(
            chains.unwind(task(2)),
            Ok(Some(task(1))),
            "the server's reply resumes the application"
        );
        // One member left is an initiator with no outstanding call, so the
        // chain is finished and both tasks are free again.
        assert_eq!(chains.stats().live, 0);
        assert!(!chains.is_engaged(task(1)));
        assert!(!chains.is_engaged(task(2)));
        assert_eq!(chains.enter(task(1), task(2)), Ok(2));
    }

    #[test]
    fn only_the_active_member_may_unwind() {
        let mut chains = table();
        chains
            .enter(task(1), task(2))
            .unwrap_or_else(|_| unreachable!());
        chains
            .enter(task(2), task(3))
            .unwrap_or_else(|_| unreachable!());
        for blocked in [task(1), task(2)] {
            assert_eq!(
                chains.unwind(blocked),
                Err(CallChainError::NotActive),
                "a reply belongs to the call that is actually running"
            );
        }
        assert_eq!(
            chains.unwind(task(7)),
            Err(CallChainError::NotActive),
            "a task in no chain has nothing to unwind"
        );
        assert_eq!(chains.depth(task(1)), 3);
    }

    #[test]
    fn abandoning_unwinds_the_whole_chain_at_once() {
        let mut chains = table();
        chains
            .enter(task(1), task(2))
            .unwrap_or_else(|_| unreachable!());
        chains
            .enter(task(2), task(3))
            .unwrap_or_else(|_| unreachable!());
        // A lease expiry or fault kills the running task rather than completing
        // its call, so the chain does not unwind member by member.
        assert_eq!(
            chains.abandon(task(3)),
            Ok(alloc::vec![task(1), task(2), task(3)])
        );
        assert_eq!(chains.stats().live, 0);
        for member in [task(1), task(2), task(3)] {
            assert!(!chains.is_engaged(member));
        }
        assert_eq!(
            chains.abandon(task(3)),
            Err(CallChainError::NotActive),
            "an abandoned chain is gone, not abandonable twice"
        );
    }

    #[test]
    fn a_full_table_reports_exhaustion_and_independent_chains_coexist() {
        let mut chains = CallChainTable::new(2).unwrap_or_else(|_| unreachable!());
        chains
            .enter(task(1), task(2))
            .unwrap_or_else(|_| unreachable!());
        chains
            .enter(task(3), task(4))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(chains.stats().live, 2);
        assert_eq!(
            chains.enter(task(5), task(6)),
            Err(CallChainError::Exhausted)
        );
        // The two chains are separate: unwinding one leaves the other alone.
        chains.unwind(task(2)).unwrap_or_else(|_| unreachable!());
        assert!(!chains.is_engaged(task(1)));
        assert_eq!(chains.active(task(3)), Some(task(4)));
        assert_eq!(chains.enter(task(5), task(6)), Ok(2));
    }

    #[test]
    fn a_task_in_no_chain_reports_nothing() {
        let chains = table();
        assert_eq!(chains.active(task(1)), None);
        assert_eq!(chains.members(task(1)), None);
        assert_eq!(chains.depth(task(1)), 0);
        assert!(!chains.is_engaged(task(1)));
    }
}

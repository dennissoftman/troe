//! Immutable wait sets and the order in which their sources are selected.
//!
//! ADR 0032's [`crate::wait::WaitSpec`] describes one call waiting on one
//! resource. A persistent server needs the opposite shape: it waits once, on
//! everything it serves, and is told which of those things happened. A wait set
//! is that object — a fixed list of at most four sources, fixed before the
//! server becomes ready and never edited afterwards.
//!
//! Immutability is the security property. A server that could add, retarget, or
//! duplicate a source at runtime could wait on something it was never granted,
//! so the set is built by whoever constructs the server and is thereafter only
//! read.
//!
//! Selection order is the liveness property, and it has three tiers. A source
//! that has closed or been revoked is selected before anything else, because it
//! is a permanent condition that a server must observe to release what it holds.
//! An expired deadline comes next. Only then are ready sources considered, and
//! those rotate: the cursor starts after the last source that actually
//! delivered, so a continuously ready NIC cannot starve a client endpoint, and a
//! continuously busy endpoint cannot starve the NIC.

use alloc::vec::Vec;
use core::fmt;

/// Maximum sources in one immutable wait set.
pub const MAX_WAIT_SET_SOURCES: usize = 4;

/// What one wait-set source observes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSourceKind {
    /// A receive-capable service endpoint: client calls and client closures.
    Endpoint,
    /// One packet device's receive-ready signal.
    PacketReceive,
    /// One block device's completion signal.
    BlockCompletion,
}

/// One generation-checked source named by a wait set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitSource {
    kind: WaitSourceKind,
    identity: u64,
    generation: u32,
}

impl WaitSource {
    /// Name one source by kind, nonzero identity, and nonzero generation.
    ///
    /// # Errors
    ///
    /// Rejects a zero identity or generation, neither of which any live
    /// resource is issued.
    pub const fn new(
        kind: WaitSourceKind,
        identity: u64,
        generation: u32,
    ) -> Result<Self, WaitSetError> {
        if identity == 0 || generation == 0 {
            return Err(WaitSetError::InvalidSource);
        }
        Ok(Self {
            kind,
            identity,
            generation,
        })
    }

    /// What this source observes.
    #[must_use]
    pub const fn kind(self) -> WaitSourceKind {
        self.kind
    }

    /// Stable identity of the named resource.
    #[must_use]
    pub const fn identity(self) -> u64 {
        self.identity
    }

    /// Resource generation captured when the set was built.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Current condition of one source, supplied by composition at each wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceReadiness {
    /// Nothing to deliver.
    Idle,
    /// Work is available now.
    Ready,
    /// The resource closed cleanly.
    Closed,
    /// The resource was revoked.
    Revoked,
}

impl SourceReadiness {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Revoked)
    }
}

/// What one wait selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSelection {
    /// This source is terminal and must be observed before any ready work.
    Terminal {
        /// Immutable index of the source in its set.
        index: u8,
        /// Whether it closed or was revoked.
        readiness: SourceReadiness,
    },
    /// The wait's own deadline has already passed.
    Deadline,
    /// This source has work to deliver.
    Ready {
        /// Immutable index of the source in its set.
        index: u8,
    },
}

/// Wait-set construction and use failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSetError {
    /// A source names a zero identity or generation.
    InvalidSource,
    /// A set is empty or names more than [`MAX_WAIT_SET_SOURCES`] sources.
    InvalidCapacity,
    /// A set names the same resource twice.
    DuplicateSource,
    /// Bounded metadata allocation failed.
    MetadataExhausted,
    /// A readiness slice does not match the set's source count.
    ReadinessMismatch,
    /// A delivery named a source the set does not contain.
    UnknownSource,
}

impl fmt::Display for WaitSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource => formatter.write_str("wait-set source is invalid"),
            Self::InvalidCapacity => formatter.write_str("wait-set source count is invalid"),
            Self::DuplicateSource => formatter.write_str("wait-set names one source twice"),
            Self::MetadataExhausted => formatter.write_str("wait-set allocation failed"),
            Self::ReadinessMismatch => formatter.write_str("readiness does not match the set"),
            Self::UnknownSource => formatter.write_str("wait-set does not contain that source"),
        }
    }
}

/// An immutable set of at most four sources, with a rotating selection cursor.
///
/// The sources never change. The cursor is the only mutable state, and it moves
/// only when a delivery actually happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitSet {
    sources: Vec<WaitSource>,
    cursor: u8,
}

impl WaitSet {
    /// Fix one set of sources before its server becomes ready.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized set, a repeated resource, and a failed
    /// reservation. Two sources of different kinds may share an identity,
    /// because identities are issued per resource kind; the same kind twice on
    /// one identity is the duplicate that matters.
    pub fn new(sources: &[WaitSource]) -> Result<Self, WaitSetError> {
        if sources.is_empty() || sources.len() > MAX_WAIT_SET_SOURCES {
            return Err(WaitSetError::InvalidCapacity);
        }
        for (index, source) in sources.iter().enumerate() {
            if sources[..index]
                .iter()
                .any(|earlier| earlier.kind == source.kind && earlier.identity == source.identity)
            {
                return Err(WaitSetError::DuplicateSource);
            }
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(sources.len())
            .map_err(|_| WaitSetError::MetadataExhausted)?;
        owned.extend_from_slice(sources);
        Ok(Self {
            sources: owned,
            cursor: 0,
        })
    }

    /// Sources this set names, in their immutable order.
    #[must_use]
    pub fn sources(&self) -> &[WaitSource] {
        &self.sources
    }

    /// Number of sources, always between one and [`MAX_WAIT_SET_SOURCES`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether the set is empty, which construction never produces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Index the next rotation begins at.
    #[must_use]
    pub const fn cursor(&self) -> u8 {
        self.cursor
    }

    /// Select what this wait should observe, without changing the cursor.
    ///
    /// `readiness` supplies one condition per source, in the set's own order.
    /// `deadline_expired` is whether the caller's optional deadline has already
    /// passed; a resident server with no idle deadline passes `false`.
    ///
    /// Returns `None` when nothing is selectable, which is the only case in
    /// which the caller may publish a blocked task.
    ///
    /// # Errors
    ///
    /// Rejects a readiness slice whose length is not the set's source count.
    pub fn select(
        &self,
        readiness: &[SourceReadiness],
        deadline_expired: bool,
    ) -> Result<Option<WaitSelection>, WaitSetError> {
        if readiness.len() != self.sources.len() {
            return Err(WaitSetError::ReadinessMismatch);
        }
        // A terminal source outranks everything. It is a permanent condition,
        // and a server that never observes it never releases what it holds for
        // that resource. Among several, the lowest index wins, so the choice
        // does not depend on where the cursor happens to sit.
        if let Some((index, state)) = readiness
            .iter()
            .enumerate()
            .find(|(_, state)| state.is_terminal())
        {
            return Ok(Some(WaitSelection::Terminal {
                index: index_of(index)?,
                readiness: *state,
            }));
        }
        // An expired deadline outranks ready work, so a caller waiting on a
        // deadline cannot be held past it by a continuously busy source.
        if deadline_expired {
            return Ok(Some(WaitSelection::Deadline));
        }
        let len = self.sources.len();
        for step in 0..len {
            let index = (self.cursor as usize + step) % len;
            if readiness
                .get(index)
                .is_some_and(|state| *state == SourceReadiness::Ready)
            {
                return Ok(Some(WaitSelection::Ready {
                    index: index_of(index)?,
                }));
            }
        }
        Ok(None)
    }

    /// Record that one source delivered, advancing the rotation past it.
    ///
    /// Only a delivery moves the cursor. A selection that produced no delivery,
    /// a terminal observation, and a deadline all leave the rotation where it
    /// was, so no source loses its turn to an event that was not its work.
    ///
    /// # Errors
    ///
    /// Rejects an index the set does not contain.
    pub fn record_delivery(&mut self, index: u8) -> Result<(), WaitSetError> {
        let len = self.sources.len();
        if index as usize >= len {
            return Err(WaitSetError::UnknownSource);
        }
        let next = (index as usize + 1) % len;
        self.cursor = index_of(next)?;
        Ok(())
    }
}

fn index_of(index: usize) -> Result<u8, WaitSetError> {
    u8::try_from(index).map_err(|_| WaitSetError::InvalidCapacity)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_WAIT_SET_SOURCES, SourceReadiness, WaitSelection, WaitSet, WaitSetError, WaitSource,
        WaitSourceKind,
    };

    fn endpoint(identity: u64) -> WaitSource {
        WaitSource::new(WaitSourceKind::Endpoint, identity, 1).unwrap_or_else(|_| unreachable!())
    }

    fn packet(identity: u64) -> WaitSource {
        WaitSource::new(WaitSourceKind::PacketReceive, identity, 1)
            .unwrap_or_else(|_| unreachable!())
    }

    fn set(sources: &[WaitSource]) -> WaitSet {
        WaitSet::new(sources).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn a_source_needs_a_real_resource() {
        assert_eq!(
            WaitSource::new(WaitSourceKind::Endpoint, 0, 1).err(),
            Some(WaitSetError::InvalidSource)
        );
        assert_eq!(
            WaitSource::new(WaitSourceKind::Endpoint, 1, 0).err(),
            Some(WaitSetError::InvalidSource)
        );
        let source = endpoint(7);
        assert_eq!(source.kind(), WaitSourceKind::Endpoint);
        assert_eq!(source.identity(), 7);
        assert_eq!(source.generation(), 1);
    }

    #[test]
    fn a_set_is_bounded_nonempty_and_free_of_repeated_resources() {
        assert_eq!(WaitSet::new(&[]).err(), Some(WaitSetError::InvalidCapacity));
        let oversized = [
            endpoint(1),
            endpoint(2),
            endpoint(3),
            endpoint(4),
            endpoint(5),
        ];
        assert_eq!(oversized.len(), MAX_WAIT_SET_SOURCES + 1);
        assert_eq!(
            WaitSet::new(&oversized).err(),
            Some(WaitSetError::InvalidCapacity)
        );
        assert_eq!(
            WaitSet::new(&[endpoint(7), endpoint(7)]).err(),
            Some(WaitSetError::DuplicateSource),
            "a server must not wait on one resource twice"
        );
        // Identities are issued per resource kind, so the same number naming an
        // endpoint and a NIC is two distinct sources.
        let mixed = set(&[endpoint(7), packet(7)]);
        assert_eq!(mixed.len(), 2);
        assert!(!mixed.is_empty());
    }

    #[test]
    fn a_terminal_source_outranks_ready_work_and_a_deadline() {
        let waits = set(&[endpoint(1), packet(2)]);
        for terminal in [SourceReadiness::Closed, SourceReadiness::Revoked] {
            assert_eq!(
                waits.select(&[SourceReadiness::Ready, terminal], true),
                Ok(Some(WaitSelection::Terminal {
                    index: 1,
                    readiness: terminal
                })),
                "a server must observe {terminal:?} before it does more work"
            );
        }
        // The lowest index wins among several, so the choice does not depend on
        // where the cursor happens to sit.
        assert_eq!(
            waits.select(&[SourceReadiness::Revoked, SourceReadiness::Closed], false),
            Ok(Some(WaitSelection::Terminal {
                index: 0,
                readiness: SourceReadiness::Revoked
            }))
        );
    }

    #[test]
    fn an_expired_deadline_outranks_ready_work() {
        let waits = set(&[endpoint(1)]);
        assert_eq!(
            waits.select(&[SourceReadiness::Ready], true),
            Ok(Some(WaitSelection::Deadline)),
            "a busy source must not hold a caller past its own deadline"
        );
        assert_eq!(
            waits.select(&[SourceReadiness::Idle], true),
            Ok(Some(WaitSelection::Deadline))
        );
    }

    #[test]
    fn nothing_selectable_is_the_only_case_that_may_block() {
        let waits = set(&[endpoint(1), packet(2)]);
        assert_eq!(
            waits.select(&[SourceReadiness::Idle, SourceReadiness::Idle], false),
            Ok(None)
        );
    }

    #[test]
    fn a_continuously_ready_source_cannot_starve_the_others() {
        let mut waits = set(&[endpoint(1), packet(2), endpoint(3)]);
        let all_ready = [
            SourceReadiness::Ready,
            SourceReadiness::Ready,
            SourceReadiness::Ready,
        ];
        // Every source takes a turn before any takes a second one.
        let mut served = [0_u32; 3];
        for _ in 0..6 {
            let Ok(Some(WaitSelection::Ready { index })) = waits.select(&all_ready, false) else {
                unreachable!()
            };
            served[index as usize] += 1;
            waits
                .record_delivery(index)
                .unwrap_or_else(|_| unreachable!());
        }
        assert_eq!(served, [2, 2, 2]);
    }

    #[test]
    fn the_cursor_moves_only_after_a_delivery() {
        let mut waits = set(&[endpoint(1), packet(2)]);
        let ready = [SourceReadiness::Ready, SourceReadiness::Ready];
        assert_eq!(waits.cursor(), 0);
        // Selecting twice without delivering keeps offering the same source, so
        // no source loses its turn to a selection that did no work.
        assert_eq!(
            waits.select(&ready, false),
            Ok(Some(WaitSelection::Ready { index: 0 }))
        );
        assert_eq!(
            waits.select(&ready, false),
            Ok(Some(WaitSelection::Ready { index: 0 }))
        );
        assert_eq!(waits.cursor(), 0);
        waits.record_delivery(0).unwrap_or_else(|_| unreachable!());
        assert_eq!(waits.cursor(), 1);
        assert_eq!(
            waits.select(&ready, false),
            Ok(Some(WaitSelection::Ready { index: 1 }))
        );
        // A terminal observation and a deadline are not deliveries either.
        let terminal = [SourceReadiness::Closed, SourceReadiness::Ready];
        assert_eq!(
            waits.select(&terminal, false),
            Ok(Some(WaitSelection::Terminal {
                index: 0,
                readiness: SourceReadiness::Closed
            }))
        );
        assert_eq!(
            waits.cursor(),
            1,
            "observing a closure took no source's turn"
        );
    }

    #[test]
    fn the_rotation_wraps_and_skips_idle_sources() {
        let mut waits = set(&[endpoint(1), packet(2), endpoint(3)]);
        waits.record_delivery(2).unwrap_or_else(|_| unreachable!());
        assert_eq!(waits.cursor(), 0, "the rotation wraps past the last source");
        // From cursor 0 with only the last source ready, selection walks
        // forward rather than reporting nothing.
        assert_eq!(
            waits.select(
                &[
                    SourceReadiness::Idle,
                    SourceReadiness::Idle,
                    SourceReadiness::Ready
                ],
                false
            ),
            Ok(Some(WaitSelection::Ready { index: 2 }))
        );
    }

    #[test]
    fn readiness_must_describe_exactly_this_set() {
        let waits = set(&[endpoint(1), packet(2)]);
        assert_eq!(
            waits.select(&[SourceReadiness::Ready], false).err(),
            Some(WaitSetError::ReadinessMismatch)
        );
        assert_eq!(
            waits.select(&[SourceReadiness::Ready; 3], false).err(),
            Some(WaitSetError::ReadinessMismatch)
        );
    }

    #[test]
    fn a_delivery_must_name_a_source_the_set_contains() {
        let mut waits = set(&[endpoint(1)]);
        assert_eq!(
            waits.record_delivery(1).err(),
            Some(WaitSetError::UnknownSource)
        );
        assert_eq!(
            waits.record_delivery(u8::MAX).err(),
            Some(WaitSetError::UnknownSource)
        );
        assert_eq!(waits.cursor(), 0, "a rejected delivery moved nothing");
    }

    #[test]
    fn the_source_list_is_read_only_after_construction() {
        let sources = [endpoint(1), packet(2)];
        let waits = set(&sources);
        assert_eq!(waits.sources(), sources);
        // Only the cursor differs between two sets built from the same sources,
        // so nothing a server does can retarget what it waits on.
        let mut rotated = set(&sources);
        rotated
            .record_delivery(0)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(rotated.sources(), waits.sources());
        assert_ne!(rotated.cursor(), waits.cursor());
    }
}

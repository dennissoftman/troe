//! Boot-service records, lifecycle, restart policy, and kernel continuations.
//!
//! ADR 0035 gives the supervisor three jobs that no other crate should own.
//!
//! It decides *what* a core server is before one exists: a boot-service record
//! fixes the role, the resident-page ceiling, the initialization deadline, and
//! the restart policy at kernel build time. None of that is the server's
//! preference, and none of it is a disk format; a record is a Rust value in the
//! kernel image, so a server cannot widen its own quota or ask to be restarted
//! more often.
//!
//! It decides *when* a server is usable. `Ready` is published only after the
//! artifact, address space, handles, wait set, endpoint binding, and the
//! server's own initialization reply have all committed, so a client can never
//! obtain a handle to an incarnation that is still starting.
//!
//! And it decides *whether* a dead server comes back. Restart is bounded by a
//! window rather than attempted forever, because a server that fails on the
//! work it is given will fail the same way after restarting, and a machine that
//! restarts it in a loop is less useful than one that reports it offline.
//!
//! A kernel client that calls a server keeps a [`KernelContinuation`], which is
//! a plain scalar enum. ADR 0035 forbids a suspended Rust frame, borrow,
//! trait-object reference, or raw pointer spanning a server wait, and a type
//! that holds only scalars cannot express one.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use core::fmt;

/// Maximum persistent servers the Standard profile admits.
pub const MAX_BOOT_SERVICES: usize = 8;
/// Aggregate resident pages every persistent server may hold together.
pub const MAX_AGGREGATE_RESIDENT_PAGES: u32 = 8_192;
/// Longest a server may take to answer its initialization call.
pub const MAX_INITIALIZATION_DEADLINE_MILLIS: u64 = 4_000;

/// One fixed boot-service role.
///
/// Roles are a closed compile-time set, not a path namespace: the kernel finds
/// a core server by role rather than by parsing a filesystem it cannot read
/// before that server exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRole {
    /// The combined VFS, volume, and filesystem-provider server.
    Storage,
    /// The network protocol server.
    Network,
}

impl ServiceRole {
    /// Stable lowercase name used in diagnostics and fatal output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Storage => "storage-server",
            Self::Network => "network-server",
        }
    }
}

/// How often a faulted server may be restarted.
///
/// A window of `u64::MAX` means the allowance is for the whole boot rather than
/// a sliding interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartPolicy {
    max_starts: u8,
    window_millis: u64,
}

impl RestartPolicy {
    /// The network server's policy: at most three starts in any 60 seconds.
    pub const NETWORK: Self = Self {
        max_starts: 3,
        window_millis: 60_000,
    };
    /// The storage server's policy: one automatic restart for the whole boot.
    ///
    /// Two starts total. Storage failures are far more likely to be about the
    /// media than about a transient fault, and reopening a volume repeatedly is
    /// how a marginal disk becomes a corrupt one.
    pub const STORAGE: Self = Self {
        max_starts: 2,
        window_millis: u64::MAX,
    };
    /// No restart at all: the first exit or fault is final.
    pub const NEVER: Self = Self {
        max_starts: 1,
        window_millis: u64::MAX,
    };

    /// Build a policy from an explicit allowance.
    ///
    /// # Errors
    ///
    /// Rejects a zero allowance, which would forbid even the first start.
    pub const fn new(max_starts: u8, window_millis: u64) -> Result<Self, ServiceError> {
        if max_starts == 0 || window_millis == 0 {
            return Err(ServiceError::InvalidPolicy);
        }
        Ok(Self {
            max_starts,
            window_millis,
        })
    }

    /// Starts allowed inside one window.
    #[must_use]
    pub const fn max_starts(self) -> u8 {
        self.max_starts
    }

    /// Length of the sliding window, or `u64::MAX` for the whole boot.
    #[must_use]
    pub const fn window_millis(self) -> u64 {
        self.window_millis
    }
}

/// One compile-time boot-service record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceRecord {
    role: ServiceRole,
    resident_page_ceiling: u32,
    initialization_deadline_millis: u64,
    restart: RestartPolicy,
}

impl ServiceRecord {
    /// Fix one service's role, quota, deadline, and restart policy.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-aggregate page ceiling and a deadline outside
    /// the profile's bound. A server that cannot be given a page cannot start,
    /// and one with no deadline could stall boot indefinitely.
    pub const fn new(
        role: ServiceRole,
        resident_page_ceiling: u32,
        initialization_deadline_millis: u64,
        restart: RestartPolicy,
    ) -> Result<Self, ServiceError> {
        if resident_page_ceiling == 0
            || resident_page_ceiling > MAX_AGGREGATE_RESIDENT_PAGES
            || initialization_deadline_millis == 0
            || initialization_deadline_millis > MAX_INITIALIZATION_DEADLINE_MILLIS
        {
            return Err(ServiceError::InvalidRecord);
        }
        Ok(Self {
            role,
            resident_page_ceiling,
            initialization_deadline_millis,
            restart,
        })
    }

    /// Role this record configures.
    #[must_use]
    pub const fn role(self) -> ServiceRole {
        self.role
    }

    /// Resident pages this server may hold, charging code, data, IPC, heap,
    /// stack, and page tables alike.
    #[must_use]
    pub const fn resident_page_ceiling(self) -> u32 {
        self.resident_page_ceiling
    }

    /// Milliseconds the server has to answer its initialization call.
    #[must_use]
    pub const fn initialization_deadline_millis(self) -> u64 {
        self.initialization_deadline_millis
    }

    /// Restart allowance for this role.
    #[must_use]
    pub const fn restart(self) -> RestartPolicy {
        self.restart
    }
}

/// Supervisor-visible state of one configured server.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ServiceState {
    /// Configured but never started.
    #[default]
    Absent,
    /// Started, not yet ready: its artifact, handles, and initialization reply
    /// have not all committed, so no client handle exists.
    Starting,
    /// Ready to take client calls.
    Ready,
    /// Ready but currently blocked on a wait.
    Blocked,
    /// Exited cleanly.
    Exited,
    /// Faulted, was revoked, or lost its execution lease.
    Faulted,
    /// Faulted and admitted for another start.
    Restarting,
    /// Will not start again this boot.
    Offline,
}

impl ServiceState {
    /// Whether a client may hold a handle to this incarnation.
    ///
    /// Only a live incarnation qualifies. `Starting` and `Restarting` do not,
    /// which is what keeps a client from reaching a server that has not
    /// finished committing its own state.
    #[must_use]
    pub const fn accepts_clients(self) -> bool {
        matches!(self, Self::Ready | Self::Blocked)
    }

    /// Whether this state can never change again.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Offline)
    }
}

/// What happened to one server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceEvent {
    /// The supervisor began a start.
    Started,
    /// The server answered initialization successfully.
    ReportedReady,
    /// The server published a wait.
    Blocked,
    /// The server was woken from its wait.
    Resumed,
    /// The server exited cleanly and unprompted.
    Exited,
    /// The server faulted, was revoked, or its lease expired.
    Faulted,
    /// The supervisor asked the server to shut down, and it complied.
    ShutdownCompleted,
}

/// Service supervision failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    /// A record names an impossible quota or deadline.
    InvalidRecord,
    /// A policy allows no start at all.
    InvalidPolicy,
    /// The aggregate resident-page ceiling is exceeded by the configured set.
    AggregateExhausted,
    /// A role is configured twice, or no record slot remains.
    DuplicateRole,
    /// The named role is not configured.
    UnknownRole,
    /// The event is not legal in the server's current state.
    IllegalTransition,
    /// Bounded metadata allocation failed.
    MetadataExhausted,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord => formatter.write_str("boot-service record is invalid"),
            Self::InvalidPolicy => formatter.write_str("restart policy is invalid"),
            Self::AggregateExhausted => {
                formatter.write_str("aggregate resident-page ceiling exceeded")
            }
            Self::DuplicateRole => formatter.write_str("boot-service role is already configured"),
            Self::UnknownRole => formatter.write_str("boot-service role is not configured"),
            Self::IllegalTransition => formatter.write_str("service transition is not legal"),
            Self::MetadataExhausted => formatter.write_str("service metadata allocation failed"),
        }
    }
}

/// One kernel client's resumption point.
///
/// Every variant holds scalars only. That is the whole point: ADR 0035 forbids
/// a suspended Rust frame, borrow, trait-object reference, or raw pointer from
/// spanning a server wait, and a type that can hold none of those cannot
/// accidentally acquire one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelContinuation {
    /// Waiting for one boot service to answer its initialization call.
    AwaitingInitialization {
        /// Role being started.
        role: ServiceRole,
        /// Absolute monotonic instant the initialization call expires at.
        deadline_millis: u64,
    },
    /// Staging one artifact through bounded offset reads.
    StagingArtifact {
        /// Role whose artifact is being staged.
        role: ServiceRole,
        /// Bytes already copied.
        offset: u64,
        /// Total bytes the artifact contains.
        total_bytes: u64,
    },
    /// Waiting for one boot service to acknowledge a shutdown request.
    AwaitingShutdown {
        /// Role being shut down.
        role: ServiceRole,
        /// Absolute monotonic instant the shutdown call expires at.
        deadline_millis: u64,
    },
}

impl KernelContinuation {
    /// Role this continuation is waiting on.
    #[must_use]
    pub const fn role(self) -> ServiceRole {
        match self {
            Self::AwaitingInitialization { role, .. }
            | Self::StagingArtifact { role, .. }
            | Self::AwaitingShutdown { role, .. } => role,
        }
    }

    /// Whether staging has copied every byte of its artifact.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        match self {
            Self::StagingArtifact {
                offset,
                total_bytes,
                ..
            } => offset >= total_bytes,
            Self::AwaitingInitialization { .. } | Self::AwaitingShutdown { .. } => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServiceEntry {
    record: ServiceRecord,
    state: ServiceState,
    /// Monotonic instants of each start inside the policy's window.
    starts: Vec<u64>,
    faults: u32,
    ready_transitions: u32,
}

/// Live supervision accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServiceStats {
    /// Servers currently accepting client calls.
    pub ready: u32,
    /// Servers that will not start again this boot.
    pub offline: u32,
    /// Starts admitted across every role.
    pub starts: u64,
    /// Faults recorded across every role.
    pub faults: u64,
    /// Clean exits recorded across every role.
    pub exits: u64,
}

/// Bounded supervisor over the configured boot services.
#[derive(Debug)]
pub struct ServiceSupervisor {
    entries: Vec<ServiceEntry>,
    stats: ServiceStats,
}

impl ServiceSupervisor {
    /// Configure the complete boot-service set before anything starts.
    ///
    /// # Errors
    ///
    /// Rejects more records than the profile admits, a repeated role, an
    /// aggregate page ceiling above the profile's, and a failed reservation.
    /// The aggregate is checked here rather than at start, because ADR 0035
    /// requires it to hold before any server runs.
    pub fn new(records: &[ServiceRecord]) -> Result<Self, ServiceError> {
        if records.is_empty() || records.len() > MAX_BOOT_SERVICES {
            return Err(ServiceError::InvalidRecord);
        }
        let mut aggregate: u32 = 0;
        for (index, record) in records.iter().enumerate() {
            if records[..index]
                .iter()
                .any(|earlier| earlier.role == record.role)
            {
                return Err(ServiceError::DuplicateRole);
            }
            aggregate = aggregate
                .checked_add(record.resident_page_ceiling)
                .ok_or(ServiceError::AggregateExhausted)?;
        }
        if aggregate > MAX_AGGREGATE_RESIDENT_PAGES {
            return Err(ServiceError::AggregateExhausted);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(records.len())
            .map_err(|_| ServiceError::MetadataExhausted)?;
        for record in records {
            let mut starts = Vec::new();
            starts
                .try_reserve_exact(usize::from(record.restart.max_starts))
                .map_err(|_| ServiceError::MetadataExhausted)?;
            entries.push(ServiceEntry {
                record: *record,
                state: ServiceState::Absent,
                starts,
                faults: 0,
                ready_transitions: 0,
            });
        }
        Ok(Self {
            entries,
            stats: ServiceStats::default(),
        })
    }

    /// Aggregate resident pages the configured set reserves.
    #[must_use]
    pub fn aggregate_resident_pages(&self) -> u32 {
        self.entries
            .iter()
            .map(|entry| entry.record.resident_page_ceiling)
            .fold(0_u32, u32::saturating_add)
    }

    /// Current state of one configured role.
    ///
    /// # Errors
    ///
    /// Rejects a role this supervisor does not configure.
    pub fn state(&self, role: ServiceRole) -> Result<ServiceState, ServiceError> {
        self.entry(role).map(|entry| entry.state)
    }

    /// Record of one configured role.
    ///
    /// # Errors
    ///
    /// Rejects a role this supervisor does not configure.
    pub fn record(&self, role: ServiceRole) -> Result<ServiceRecord, ServiceError> {
        self.entry(role).map(|entry| entry.record)
    }

    /// Whether clients may currently hold handles to one role.
    #[must_use]
    pub fn accepts_clients(&self, role: ServiceRole) -> bool {
        self.entry(role)
            .is_ok_and(|entry| entry.state.accepts_clients())
    }

    /// Apply one event at a boot-relative instant.
    ///
    /// `now_millis` orders the restart window and is ignored by every other
    /// transition.
    ///
    /// # Errors
    ///
    /// Rejects an unknown role and an event that is not legal in the current
    /// state. A rejected event changes nothing.
    pub fn apply(
        &mut self,
        role: ServiceRole,
        event: ServiceEvent,
        now_millis: u64,
    ) -> Result<ServiceState, ServiceError> {
        let index = self.index(role)?;
        let entry = self
            .entries
            .get(index)
            .ok_or(ServiceError::UnknownRole)?
            .clone();
        let next = Self::next_state(&entry, event, now_millis)?;
        let admitted_start = matches!(event, ServiceEvent::Started);
        let entry = self
            .entries
            .get_mut(index)
            .ok_or(ServiceError::UnknownRole)?;
        if admitted_start {
            Self::retain_window(entry, now_millis);
            entry.starts.push(now_millis);
        }
        match event {
            ServiceEvent::Faulted => entry.faults = entry.faults.saturating_add(1),
            ServiceEvent::ReportedReady => {
                entry.ready_transitions = entry.ready_transitions.saturating_add(1);
            }
            _ => {}
        }
        entry.state = next;
        match event {
            ServiceEvent::Started => self.stats.starts = self.stats.starts.saturating_add(1),
            ServiceEvent::Faulted => self.stats.faults = self.stats.faults.saturating_add(1),
            ServiceEvent::Exited | ServiceEvent::ShutdownCompleted => {
                self.stats.exits = self.stats.exits.saturating_add(1);
            }
            _ => {}
        }
        self.refresh_stats();
        Ok(next)
    }

    /// Whether a faulted role may start again at this instant.
    #[must_use]
    pub fn admits_restart(&self, role: ServiceRole, now_millis: u64) -> bool {
        self.entry(role).is_ok_and(|entry| {
            matches!(entry.state, ServiceState::Faulted)
                && Self::starts_in_window(entry, now_millis)
                    < u32::from(entry.record.restart.max_starts)
        })
    }

    /// Live supervision accounting.
    #[must_use]
    pub const fn stats(&self) -> ServiceStats {
        self.stats
    }

    fn next_state(
        entry: &ServiceEntry,
        event: ServiceEvent,
        now_millis: u64,
    ) -> Result<ServiceState, ServiceError> {
        let legal = match (entry.state, event) {
            // A start is admitted from `Absent` and from a fault the policy
            // still has an allowance for.
            (ServiceState::Absent, ServiceEvent::Started) => Some(ServiceState::Starting),
            (ServiceState::Faulted, ServiceEvent::Started) => {
                if Self::starts_in_window(entry, now_millis)
                    < u32::from(entry.record.restart.max_starts)
                {
                    Some(ServiceState::Starting)
                } else {
                    // The allowance is spent. The server stays down rather than
                    // restarting into the same failure indefinitely.
                    Some(ServiceState::Offline)
                }
            }
            // Both roads to `Ready`: the first one after initialization
            // commits, and every later one when a published wait fires.
            (ServiceState::Starting, ServiceEvent::ReportedReady)
            | (ServiceState::Blocked, ServiceEvent::Resumed) => Some(ServiceState::Ready),
            (ServiceState::Ready, ServiceEvent::Blocked) => Some(ServiceState::Blocked),
            // A fault is legal from every live state, including one that never
            // reached readiness.
            (
                ServiceState::Starting | ServiceState::Ready | ServiceState::Blocked,
                ServiceEvent::Faulted,
            ) => Some(ServiceState::Faulted),
            // An unsolicited clean exit is recorded distinctly and is never
            // treated as an acknowledged shutdown: a core service that leaves
            // on its own stays offline.
            (
                ServiceState::Starting | ServiceState::Ready | ServiceState::Blocked,
                ServiceEvent::Exited,
            ) => Some(ServiceState::Offline),
            (ServiceState::Ready | ServiceState::Blocked, ServiceEvent::ShutdownCompleted) => {
                Some(ServiceState::Exited)
            }
            _ => None,
        };
        legal.ok_or(ServiceError::IllegalTransition)
    }

    fn starts_in_window(entry: &ServiceEntry, now_millis: u64) -> u32 {
        let window = entry.record.restart.window_millis;
        u32::try_from(
            entry
                .starts
                .iter()
                .filter(|start| window == u64::MAX || now_millis.saturating_sub(**start) < window)
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    fn retain_window(entry: &mut ServiceEntry, now_millis: u64) {
        let window = entry.record.restart.window_millis;
        if window == u64::MAX {
            return;
        }
        entry
            .starts
            .retain(|start| now_millis.saturating_sub(*start) < window);
    }

    fn refresh_stats(&mut self) {
        self.stats.ready = u32::try_from(
            self.entries
                .iter()
                .filter(|entry| entry.state.accepts_clients())
                .count(),
        )
        .unwrap_or(u32::MAX);
        self.stats.offline = u32::try_from(
            self.entries
                .iter()
                .filter(|entry| entry.state.is_final())
                .count(),
        )
        .unwrap_or(u32::MAX);
    }

    fn entry(&self, role: ServiceRole) -> Result<&ServiceEntry, ServiceError> {
        self.entries
            .iter()
            .find(|entry| entry.record.role == role)
            .ok_or(ServiceError::UnknownRole)
    }

    fn index(&self, role: ServiceRole) -> Result<usize, ServiceError> {
        self.entries
            .iter()
            .position(|entry| entry.record.role == role)
            .ok_or(ServiceError::UnknownRole)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KernelContinuation, MAX_AGGREGATE_RESIDENT_PAGES, MAX_BOOT_SERVICES,
        MAX_INITIALIZATION_DEADLINE_MILLIS, RestartPolicy, ServiceError, ServiceEvent,
        ServiceRecord, ServiceRole, ServiceState, ServiceSupervisor,
    };

    fn storage() -> ServiceRecord {
        ServiceRecord::new(ServiceRole::Storage, 4_096, 4_000, RestartPolicy::STORAGE)
            .unwrap_or_else(|_| unreachable!())
    }

    fn network() -> ServiceRecord {
        ServiceRecord::new(ServiceRole::Network, 1_024, 4_000, RestartPolicy::NETWORK)
            .unwrap_or_else(|_| unreachable!())
    }

    fn supervisor() -> ServiceSupervisor {
        ServiceSupervisor::new(&[storage(), network()]).unwrap_or_else(|_| unreachable!())
    }

    /// Drive one role to `Ready` from `Absent`.
    fn start_ready(supervisor: &mut ServiceSupervisor, role: ServiceRole, now: u64) {
        supervisor
            .apply(role, ServiceEvent::Started, now)
            .unwrap_or_else(|_| unreachable!());
        supervisor
            .apply(role, ServiceEvent::ReportedReady, now)
            .unwrap_or_else(|_| unreachable!());
    }

    #[test]
    fn a_record_refuses_a_quota_or_deadline_it_could_not_honour() {
        assert_eq!(
            ServiceRecord::new(ServiceRole::Storage, 0, 4_000, RestartPolicy::NEVER).err(),
            Some(ServiceError::InvalidRecord),
            "a server that cannot be given a page cannot start"
        );
        assert_eq!(
            ServiceRecord::new(
                ServiceRole::Storage,
                MAX_AGGREGATE_RESIDENT_PAGES + 1,
                4_000,
                RestartPolicy::NEVER
            )
            .err(),
            Some(ServiceError::InvalidRecord)
        );
        assert_eq!(
            ServiceRecord::new(ServiceRole::Storage, 8, 0, RestartPolicy::NEVER).err(),
            Some(ServiceError::InvalidRecord),
            "a server with no deadline could stall boot indefinitely"
        );
        assert_eq!(
            ServiceRecord::new(
                ServiceRole::Storage,
                8,
                MAX_INITIALIZATION_DEADLINE_MILLIS + 1,
                RestartPolicy::NEVER
            )
            .err(),
            Some(ServiceError::InvalidRecord)
        );
        assert_eq!(
            RestartPolicy::new(0, 1).err(),
            Some(ServiceError::InvalidPolicy),
            "a policy that allows no start forbids the first one too"
        );
    }

    #[test]
    fn the_aggregate_ceiling_holds_before_any_server_starts() {
        let supervisor = supervisor();
        assert_eq!(supervisor.aggregate_resident_pages(), 5_120);
        let oversized = ServiceRecord::new(
            ServiceRole::Network,
            MAX_AGGREGATE_RESIDENT_PAGES,
            4_000,
            RestartPolicy::NEVER,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            ServiceSupervisor::new(&[storage(), oversized]).err(),
            Some(ServiceError::AggregateExhausted),
            "the aggregate is a construction-time fact, not a start-time one"
        );
        assert_eq!(
            ServiceSupervisor::new(&[storage(), storage()]).err(),
            Some(ServiceError::DuplicateRole)
        );
        assert_eq!(
            ServiceSupervisor::new(&[]).err(),
            Some(ServiceError::InvalidRecord)
        );
        const { assert!(MAX_BOOT_SERVICES >= 2) };
    }

    #[test]
    fn no_client_reaches_a_server_that_has_not_committed() {
        let mut supervisor = supervisor();
        assert_eq!(
            supervisor.state(ServiceRole::Storage),
            Ok(ServiceState::Absent)
        );
        assert!(!supervisor.accepts_clients(ServiceRole::Storage));
        supervisor
            .apply(ServiceRole::Storage, ServiceEvent::Started, 0)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            supervisor.state(ServiceRole::Storage),
            Ok(ServiceState::Starting)
        );
        assert!(
            !supervisor.accepts_clients(ServiceRole::Storage),
            "starting is not ready: initialization has not replied yet"
        );
        supervisor
            .apply(ServiceRole::Storage, ServiceEvent::ReportedReady, 0)
            .unwrap_or_else(|_| unreachable!());
        assert!(supervisor.accepts_clients(ServiceRole::Storage));
        // A blocked server is still reachable; it is waiting, not gone.
        supervisor
            .apply(ServiceRole::Storage, ServiceEvent::Blocked, 0)
            .unwrap_or_else(|_| unreachable!());
        assert!(supervisor.accepts_clients(ServiceRole::Storage));
        assert_eq!(supervisor.stats().ready, 1);
    }

    #[test]
    fn a_start_that_never_reaches_ready_can_still_fault() {
        let mut supervisor = supervisor();
        supervisor
            .apply(ServiceRole::Storage, ServiceEvent::Started, 0)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            supervisor.apply(ServiceRole::Storage, ServiceEvent::Faulted, 0),
            Ok(ServiceState::Faulted),
            "initialization rejection is a fault like any other"
        );
        assert_eq!(supervisor.stats().faults, 1);
    }

    #[test]
    fn an_unsolicited_clean_exit_leaves_a_core_service_offline() {
        let mut supervisor = supervisor();
        start_ready(&mut supervisor, ServiceRole::Storage, 0);
        assert_eq!(
            supervisor.apply(ServiceRole::Storage, ServiceEvent::Exited, 0),
            Ok(ServiceState::Offline),
            "a core service that leaves on its own is not restarted"
        );
        assert!(
            supervisor
                .state(ServiceRole::Storage)
                .unwrap_or_else(|_| unreachable!())
                .is_final()
        );
        assert_eq!(supervisor.stats().offline, 1);
        assert!(!supervisor.admits_restart(ServiceRole::Storage, 0));
    }

    #[test]
    fn an_acknowledged_shutdown_is_recorded_apart_from_an_exit() {
        let mut supervisor = supervisor();
        start_ready(&mut supervisor, ServiceRole::Network, 0);
        assert_eq!(
            supervisor.apply(ServiceRole::Network, ServiceEvent::ShutdownCompleted, 0),
            Ok(ServiceState::Exited),
            "a requested shutdown is a different fate from leaving unprompted"
        );
        assert_ne!(
            supervisor.state(ServiceRole::Network),
            Ok(ServiceState::Offline)
        );
    }

    #[test]
    fn the_network_policy_allows_three_starts_in_its_window_then_stops() {
        let mut supervisor = supervisor();
        // Three starts inside 60 seconds, each ending in a fault.
        for instant in [0_u64, 10_000, 20_000] {
            supervisor
                .apply(ServiceRole::Network, ServiceEvent::Started, instant)
                .unwrap_or_else(|_| unreachable!());
            supervisor
                .apply(ServiceRole::Network, ServiceEvent::Faulted, instant)
                .unwrap_or_else(|_| unreachable!());
        }
        assert!(
            !supervisor.admits_restart(ServiceRole::Network, 30_000),
            "the allowance is spent inside the window"
        );
        assert_eq!(
            supervisor.apply(ServiceRole::Network, ServiceEvent::Started, 30_000),
            Ok(ServiceState::Offline),
            "a start beyond the allowance takes the server offline instead"
        );
    }

    #[test]
    fn the_network_window_slides_so_a_quiet_hour_restores_the_allowance() {
        let mut supervisor = supervisor();
        for instant in [0_u64, 10_000, 20_000] {
            supervisor
                .apply(ServiceRole::Network, ServiceEvent::Started, instant)
                .unwrap_or_else(|_| unreachable!());
            supervisor
                .apply(ServiceRole::Network, ServiceEvent::Faulted, instant)
                .unwrap_or_else(|_| unreachable!());
        }
        // Past the window, the earlier starts no longer count against it.
        assert!(supervisor.admits_restart(ServiceRole::Network, 120_000));
        assert_eq!(
            supervisor.apply(ServiceRole::Network, ServiceEvent::Started, 120_000),
            Ok(ServiceState::Starting)
        );
    }

    #[test]
    fn the_storage_policy_allows_exactly_one_automatic_restart_per_boot() {
        let mut supervisor = supervisor();
        start_ready(&mut supervisor, ServiceRole::Storage, 0);
        supervisor
            .apply(ServiceRole::Storage, ServiceEvent::Faulted, 0)
            .unwrap_or_else(|_| unreachable!());
        assert!(supervisor.admits_restart(ServiceRole::Storage, 0));
        supervisor
            .apply(ServiceRole::Storage, ServiceEvent::Started, 1_000)
            .unwrap_or_else(|_| unreachable!());
        supervisor
            .apply(ServiceRole::Storage, ServiceEvent::Faulted, 2_000)
            .unwrap_or_else(|_| unreachable!());
        // The storage window is the whole boot, so no amount of elapsed time
        // restores the allowance: reopening a marginal volume repeatedly is how
        // it becomes a corrupt one.
        assert!(!supervisor.admits_restart(ServiceRole::Storage, u64::MAX / 2));
        assert_eq!(
            supervisor.apply(ServiceRole::Storage, ServiceEvent::Started, u64::MAX / 2),
            Ok(ServiceState::Offline)
        );
    }

    #[test]
    fn an_illegal_transition_changes_nothing() {
        let mut supervisor = supervisor();
        for illegal in [
            ServiceEvent::ReportedReady,
            ServiceEvent::Blocked,
            ServiceEvent::Resumed,
            ServiceEvent::Faulted,
            ServiceEvent::Exited,
            ServiceEvent::ShutdownCompleted,
        ] {
            assert_eq!(
                supervisor.apply(ServiceRole::Storage, illegal, 0),
                Err(ServiceError::IllegalTransition),
                "{illegal:?} is not legal from Absent"
            );
        }
        assert_eq!(
            supervisor.state(ServiceRole::Storage),
            Ok(ServiceState::Absent)
        );
        assert_eq!(supervisor.stats().starts, 0);
        // An offline server is final: nothing restarts it.
        start_ready(&mut supervisor, ServiceRole::Network, 0);
        supervisor
            .apply(ServiceRole::Network, ServiceEvent::Exited, 0)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            supervisor.apply(ServiceRole::Network, ServiceEvent::Started, 0),
            Err(ServiceError::IllegalTransition)
        );
    }

    #[test]
    fn an_unconfigured_role_is_rejected_rather_than_invented() {
        let mut supervisor =
            ServiceSupervisor::new(&[storage()]).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            supervisor.state(ServiceRole::Network).err(),
            Some(ServiceError::UnknownRole)
        );
        assert_eq!(
            supervisor.record(ServiceRole::Network).err(),
            Some(ServiceError::UnknownRole)
        );
        assert_eq!(
            supervisor.apply(ServiceRole::Network, ServiceEvent::Started, 0),
            Err(ServiceError::UnknownRole)
        );
        assert!(!supervisor.accepts_clients(ServiceRole::Network));
        assert!(!supervisor.admits_restart(ServiceRole::Network, 0));
    }

    #[test]
    fn a_continuation_carries_scalars_and_nothing_else() {
        // The type is `Copy`, which a borrow, trait object, or owned frame
        // could not be. That is the property ADR 0035 asks for.
        fn assert_copy<T: Copy>(_: &T) {}
        let staging = KernelContinuation::StagingArtifact {
            role: ServiceRole::Storage,
            offset: 0,
            total_bytes: 4_096,
        };
        assert_copy(&staging);
        assert_eq!(staging.role(), ServiceRole::Storage);
        assert!(!staging.is_complete());
        let finished = KernelContinuation::StagingArtifact {
            role: ServiceRole::Storage,
            offset: 4_096,
            total_bytes: 4_096,
        };
        assert!(finished.is_complete());
        for waiting in [
            KernelContinuation::AwaitingInitialization {
                role: ServiceRole::Network,
                deadline_millis: 4_000,
            },
            KernelContinuation::AwaitingShutdown {
                role: ServiceRole::Network,
                deadline_millis: 4_000,
            },
        ] {
            assert_eq!(waiting.role(), ServiceRole::Network);
            assert!(
                !waiting.is_complete(),
                "only staging has a completion condition of its own"
            );
        }
    }

    #[test]
    fn a_role_names_itself_for_fatal_output() {
        assert_eq!(ServiceRole::Storage.name(), "storage-server");
        assert_eq!(ServiceRole::Network.name(), "network-server");
    }
}

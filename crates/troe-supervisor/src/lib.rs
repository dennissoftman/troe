//! Bounded, architecture-independent resident-service supervision policy.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use troe_config::{FailureAction, ServiceConfig, StartupMode, SystemConfig};
use troe_task::{MonotonicMillis, TaskId};

/// Maximum configured services accepted by the supervisor policy.
pub const MAX_SERVICES: usize = 32;
/// Default retained output bytes for one supervised service.
pub const DEFAULT_LOG_BYTES: usize = 64 * 1024;
/// Grace interval between a stop request and forced contained teardown.
pub const STOP_GRACE_MILLISECONDS: u64 = 1_000;
const MAX_RESTART_DELAY_MILLISECONDS: u64 = 60_000;

/// Desired administrative state of one configured service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesiredState {
    /// The supervisor should keep the service stopped.
    Down,
    /// The supervisor should make the service ready when dependencies permit.
    Up,
}

/// Stable reason why one service attempt failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureReason {
    /// Resident launch preparation failed transactionally.
    LaunchFailed,
    /// The process exited while its desired state remained up.
    Exited(u32),
    /// The process suffered a contained application fault.
    Faulted,
    /// The process did not report readiness by its configured deadline.
    ReadinessTimeout,
    /// The process missed an explicitly configured watchdog promise.
    WatchdogTimeout,
    /// The optional total service lifetime expired.
    LifetimeExpired,
}

/// Why a running process is being asked to stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// An authorized administrator requested the down state.
    Requested,
    /// An authorized administrator requested a restart.
    Restart,
    /// A hard dependency is no longer ready.
    DependencyUnavailable,
    /// Startup readiness expired.
    ReadinessTimeout,
    /// The configured lifetime expired.
    LifetimeExpired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AfterStop {
    Down,
    Restart,
    Dependency,
    Failure(FailureReason),
}

/// Observable runtime state of one configured service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    /// No resident process is owned.
    Stopped,
    /// A process is live but has not reported readiness.
    Starting {
        /// Exact resident task identity.
        process: TaskId,
        /// Optional startup health deadline.
        health_deadline: Option<MonotonicMillis>,
        /// Optional total lifetime deadline.
        lifetime_deadline: Option<MonotonicMillis>,
    },
    /// The process reported readiness.
    Ready {
        /// Exact resident task identity.
        process: TaskId,
        /// Optional total lifetime deadline.
        lifetime_deadline: Option<MonotonicMillis>,
    },
    /// Restart policy is waiting before another launch.
    Backoff {
        /// Earliest next launch time.
        deadline: MonotonicMillis,
        /// Failure which selected the restart.
        reason: FailureReason,
    },
    /// Cancellation was requested and the process retains resources.
    Stopping {
        /// Exact resident task identity.
        process: TaskId,
        /// Deadline after which teardown must be forced.
        deadline: MonotonicMillis,
        /// Administrative reason for the stop.
        reason: StopReason,
    },
    /// Policy left the service down after a terminal failure.
    Failed {
        /// Terminal failure reason.
        reason: FailureReason,
    },
}

impl ServiceState {
    /// Resident process identity, if this state owns one.
    #[must_use]
    pub const fn process(self) -> Option<TaskId> {
        match self {
            Self::Starting { process, .. }
            | Self::Ready { process, .. }
            | Self::Stopping { process, .. } => Some(process),
            Self::Stopped | Self::Backoff { .. } | Self::Failed { .. } => None,
        }
    }

    /// Whether hard dependents may start.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// One supervisor action for the composition root to execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorAction {
    /// Transactionally launch the configured artifact.
    Launch {
        /// Stable configured service identity.
        service_id: u32,
    },
    /// Cooperatively cancel a resident process.
    RequestStop {
        /// Stable configured service identity.
        service_id: u32,
        /// Exact resident task identity.
        process: TaskId,
        /// Administrative reason for cancellation.
        reason: StopReason,
    },
    /// Terminate and reclaim a process that exceeded its stop grace interval.
    ForceStop {
        /// Stable configured service identity.
        service_id: u32,
        /// Exact resident task identity.
        process: TaskId,
        /// Administrative reason for cancellation.
        reason: StopReason,
    },
    /// Commit the already-validated predecessor generation.
    ActivatePreviousGeneration {
        /// Service whose policy rejected candidate health.
        service_id: u32,
    },
    /// Reject ordinary activation and retain the recovery environment.
    EnterRecovery {
        /// Service whose policy rejected ordinary activation.
        service_id: u32,
    },
}

/// Validated subset of SCFG policy needed by the runtime state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicePolicy {
    id: u32,
    mode: StartupMode,
    failure_action: FailureAction,
    restart_limit: u8,
    health_timeout_ms: u32,
    lifetime_limit_ms: u32,
    dependencies: Vec<u32>,
}

impl ServicePolicy {
    /// Copy one already-validated SCFG service record.
    #[must_use]
    pub fn from_config(config: &ServiceConfig) -> Self {
        Self {
            id: config.id(),
            mode: config.mode(),
            failure_action: config.failure_action(),
            restart_limit: config.restart_limit(),
            health_timeout_ms: config.health_timeout_ms(),
            lifetime_limit_ms: config.lifetime_limit_ms(),
            dependencies: config.dependencies().to_vec(),
        }
    }

    #[cfg(test)]
    fn for_test(
        id: u32,
        mode: StartupMode,
        failure_action: FailureAction,
        restart_limit: u8,
        health_timeout_ms: u32,
        lifetime_limit_ms: u32,
        dependencies: &[u32],
    ) -> Self {
        Self {
            id,
            mode,
            failure_action,
            restart_limit,
            health_timeout_ms,
            lifetime_limit_ms,
            dependencies: dependencies.to_vec(),
        }
    }
}

/// Allocation-bounded recent output retained for one service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedLog {
    bytes: VecDeque<u8>,
    capacity: usize,
    dropped: u64,
}

impl BoundedLog {
    /// Construct an empty log with an immutable byte ceiling.
    ///
    /// # Errors
    ///
    /// Rejects a zero capacity or metadata allocation failure.
    pub fn new(capacity: usize) -> Result<Self, SupervisorError> {
        if capacity == 0 {
            return Err(SupervisorError::InvalidPolicy);
        }
        let mut bytes = VecDeque::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| SupervisorError::MetadataExhausted)?;
        Ok(Self {
            bytes,
            capacity,
            dropped: 0,
        })
    }

    /// Append bytes, evicting the oldest complete byte prefix when necessary.
    pub fn append(&mut self, bytes: &[u8]) {
        let retained_start = bytes.len().saturating_sub(self.capacity);
        let incoming = &bytes[retained_start..];
        let evicted_incoming = retained_start;
        let evicted_existing = self
            .bytes
            .len()
            .saturating_add(incoming.len())
            .saturating_sub(self.capacity);
        for _ in 0..evicted_existing {
            let _removed = self.bytes.pop_front();
        }
        self.bytes.extend(incoming.iter().copied());
        self.dropped = self
            .dropped
            .saturating_add(u64::try_from(evicted_incoming).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(evicted_existing).unwrap_or(u64::MAX));
    }

    /// Copy recent bytes into caller-owned storage in chronological order.
    #[must_use]
    pub fn copy_recent(&self, destination: &mut [u8]) -> usize {
        let count = destination.len().min(self.bytes.len());
        let skip = self.bytes.len() - count;
        for (destination, source) in destination.iter_mut().zip(self.bytes.iter().skip(skip)) {
            *destination = *source;
        }
        count
    }

    /// Bytes currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether no bytes are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Bytes discarded since creation.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[derive(Debug)]
struct ServiceRecord {
    policy: ServicePolicy,
    desired: DesiredState,
    state: ServiceState,
    restarts: u8,
    restart_pending: bool,
    after_stop: Option<AfterStop>,
    log: BoundedLog,
}

/// Read-only service status returned to observation clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceSnapshot {
    /// Stable SCFG service identity.
    pub id: u32,
    /// Administrative target state.
    pub desired: DesiredState,
    /// Current observed lifecycle state.
    pub state: ServiceState,
    /// Restart attempts consumed during this supervisor lifetime.
    pub restarts: u8,
    /// Recent bytes retained in the bounded log.
    pub log_bytes: usize,
    /// Output bytes discarded from the bounded log.
    pub dropped_log_bytes: u64,
}

/// Deterministic service-policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    /// Record count, identity, dependency, or policy fields are invalid.
    InvalidPolicy,
    /// Metadata or log reservation failed.
    MetadataExhausted,
    /// No configured service has the supplied identity.
    UnknownService,
    /// Event does not match the current service state or process identity.
    InvalidState,
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "service supervision policy is invalid",
            Self::MetadataExhausted => "service supervision metadata is exhausted",
            Self::UnknownService => "service identity is unknown",
            Self::InvalidState => "service lifecycle event is invalid",
        })
    }
}

/// Bounded state machine for configured resident services.
#[derive(Debug)]
pub struct Supervisor {
    records: Vec<ServiceRecord>,
    pending_system_action: Option<SupervisorAction>,
}

impl Supervisor {
    /// Construct supervision policy from one validated selected SCFG.
    ///
    /// # Errors
    ///
    /// Rejects excessive records, inconsistent dependencies, or allocation
    /// failure before returning partial state.
    pub fn from_config(config: &SystemConfig, recovery: bool) -> Result<Self, SupervisorError> {
        let mut policies = Vec::new();
        policies
            .try_reserve_exact(config.services().len())
            .map_err(|_| SupervisorError::MetadataExhausted)?;
        for service in config.services() {
            policies.push(ServicePolicy::from_config(service));
        }
        Self::new(&policies, recovery, DEFAULT_LOG_BYTES)
    }

    /// Construct supervision state from validated portable policies.
    ///
    /// # Errors
    ///
    /// Rejects excessive, duplicate, unordered, or inconsistent policies and
    /// invalid log capacity.
    pub fn new(
        policies: &[ServicePolicy],
        recovery: bool,
        log_capacity: usize,
    ) -> Result<Self, SupervisorError> {
        if policies.len() > MAX_SERVICES || log_capacity == 0 {
            return Err(SupervisorError::InvalidPolicy);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(policies.len())
            .map_err(|_| SupervisorError::MetadataExhausted)?;
        for policy in policies {
            if policy.id == 0
                || records
                    .last()
                    .is_some_and(|record: &ServiceRecord| record.policy.id >= policy.id)
                || policy
                    .dependencies
                    .iter()
                    .any(|dependency| !records.iter().any(|record| record.policy.id == *dependency))
                || (policy.failure_action == FailureAction::Restart) != (policy.restart_limit != 0)
            {
                return Err(SupervisorError::InvalidPolicy);
            }
            let desired = match policy.mode {
                StartupMode::BootRequired | StartupMode::BootOptional if !recovery => {
                    DesiredState::Up
                }
                StartupMode::RecoveryOnly if recovery => DesiredState::Up,
                StartupMode::BootRequired
                | StartupMode::BootOptional
                | StartupMode::OnDemand
                | StartupMode::RecoveryOnly => DesiredState::Down,
            };
            records.push(ServiceRecord {
                policy: policy.clone(),
                desired,
                state: ServiceState::Stopped,
                restarts: 0,
                restart_pending: false,
                after_stop: None,
                log: BoundedLog::new(log_capacity)?,
            });
        }
        Ok(Self {
            records,
            pending_system_action: None,
        })
    }

    /// Number of configured service records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no services are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Observe one service without exposing mutable supervisor state.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::UnknownService`] for an absent identity.
    pub fn snapshot(&self, service_id: u32) -> Result<ServiceSnapshot, SupervisorError> {
        let record = self.record(service_id)?;
        Ok(ServiceSnapshot {
            id: record.policy.id,
            desired: record.desired,
            state: record.state,
            restarts: record.restarts,
            log_bytes: record.log.len(),
            dropped_log_bytes: record.log.dropped(),
        })
    }

    /// Whether every boot-required service has reported readiness.
    #[must_use]
    pub fn required_services_ready(&self) -> bool {
        self.records.iter().all(|record| {
            record.policy.mode != StartupMode::BootRequired || record.state.is_ready()
        })
    }

    /// Request a configured service's desired up state.
    ///
    /// # Errors
    ///
    /// Rejects an unknown identity.
    pub fn request_start(&mut self, service_id: u32) -> Result<(), SupervisorError> {
        let record = self.record_mut(service_id)?;
        record.desired = DesiredState::Up;
        record.restart_pending = false;
        if matches!(record.state, ServiceState::Failed { .. }) {
            record.state = ServiceState::Stopped;
            record.restarts = 0;
        }
        Ok(())
    }

    /// Request a configured service's desired down state.
    ///
    /// # Errors
    ///
    /// Rejects an unknown identity.
    pub fn request_stop(&mut self, service_id: u32) -> Result<(), SupervisorError> {
        let record = self.record_mut(service_id)?;
        record.desired = DesiredState::Down;
        record.restart_pending = false;
        Ok(())
    }

    /// Request a dependency-aware stop followed by start.
    ///
    /// # Errors
    ///
    /// Rejects an unknown identity.
    pub fn request_restart(&mut self, service_id: u32) -> Result<(), SupervisorError> {
        let record = self.record_mut(service_id)?;
        record.desired = DesiredState::Up;
        record.restart_pending = true;
        if matches!(
            record.state,
            ServiceState::Stopped | ServiceState::Failed { .. }
        ) {
            record.restart_pending = false;
            record.state = ServiceState::Stopped;
        }
        Ok(())
    }

    /// Record successful transactional process launch.
    ///
    /// # Errors
    ///
    /// Rejects duplicate launch or a service not eligible to start.
    pub fn launched(
        &mut self,
        service_id: u32,
        process: TaskId,
        now: MonotonicMillis,
    ) -> Result<(), SupervisorError> {
        let record = self.record_mut(service_id)?;
        if record.desired != DesiredState::Up || record.state != ServiceState::Stopped {
            return Err(SupervisorError::InvalidState);
        }
        let health_deadline = nonzero_deadline(now, record.policy.health_timeout_ms);
        let lifetime_deadline = nonzero_deadline(now, record.policy.lifetime_limit_ms);
        record.state = ServiceState::Starting {
            process,
            health_deadline,
            lifetime_deadline,
        };
        Ok(())
    }

    /// Record transactional launch failure and apply configured policy.
    ///
    /// # Errors
    ///
    /// Rejects a service that is not stopped and desired up.
    pub fn launch_failed(
        &mut self,
        service_id: u32,
        now: MonotonicMillis,
    ) -> Result<(), SupervisorError> {
        let index = self.index(service_id)?;
        if self.records[index].desired != DesiredState::Up
            || self.records[index].state != ServiceState::Stopped
        {
            return Err(SupervisorError::InvalidState);
        }
        self.apply_failure(index, FailureReason::LaunchFailed, now)
    }

    /// Accept one exact readiness notification from the current process.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, stale, or wrong-owner notification.
    pub fn ready(&mut self, service_id: u32, process: TaskId) -> Result<(), SupervisorError> {
        let record = self.record_mut(service_id)?;
        let ServiceState::Starting {
            process: current,
            lifetime_deadline,
            ..
        } = record.state
        else {
            return Err(SupervisorError::InvalidState);
        };
        if current != process {
            return Err(SupervisorError::InvalidState);
        }
        record.state = ServiceState::Ready {
            process,
            lifetime_deadline,
        };
        Ok(())
    }

    /// Record completion after cooperative or forced stop.
    ///
    /// # Errors
    ///
    /// Rejects a stale identity or a process that is not stopping.
    pub fn stopped(
        &mut self,
        service_id: u32,
        process: TaskId,
        now: MonotonicMillis,
    ) -> Result<(), SupervisorError> {
        let index = self.index(service_id)?;
        let ServiceState::Stopping {
            process: current, ..
        } = self.records[index].state
        else {
            return Err(SupervisorError::InvalidState);
        };
        if current != process {
            return Err(SupervisorError::InvalidState);
        }
        let after = self.records[index]
            .after_stop
            .take()
            .ok_or(SupervisorError::InvalidState)?;
        self.records[index].state = ServiceState::Stopped;
        match after {
            AfterStop::Down | AfterStop::Restart | AfterStop::Dependency => Ok(()),
            AfterStop::Failure(reason) => self.apply_failure(index, reason, now),
        }
    }

    /// Record an unexpected application exit or contained fault.
    ///
    /// # Errors
    ///
    /// Rejects a stale process identity or non-live service state.
    pub fn exited(
        &mut self,
        service_id: u32,
        process: TaskId,
        status: Option<u32>,
        now: MonotonicMillis,
    ) -> Result<(), SupervisorError> {
        let index = self.index(service_id)?;
        if self.records[index].state.process() != Some(process)
            || matches!(self.records[index].state, ServiceState::Stopping { .. })
        {
            return Err(SupervisorError::InvalidState);
        }
        self.records[index].state = ServiceState::Stopped;
        let reason = status.map_or(FailureReason::Faulted, FailureReason::Exited);
        self.apply_failure(index, reason, now)
    }

    /// Append output to one service's bounded recent log.
    ///
    /// # Errors
    ///
    /// Rejects an unknown service.
    pub fn append_log(&mut self, service_id: u32, bytes: &[u8]) -> Result<(), SupervisorError> {
        self.record_mut(service_id)?.log.append(bytes);
        Ok(())
    }

    /// Copy one service's most recent output.
    ///
    /// # Errors
    ///
    /// Rejects an unknown service.
    pub fn copy_log(
        &self,
        service_id: u32,
        destination: &mut [u8],
    ) -> Result<usize, SupervisorError> {
        Ok(self.record(service_id)?.log.copy_recent(destination))
    }

    /// Select one immediately executable supervisor action.
    ///
    /// The caller completes the action through [`Self::launched`],
    /// [`Self::launch_failed`], [`Self::stopped`], or the generation-control
    /// path before asking for the next action.
    #[must_use]
    pub fn next_action(&mut self, now: MonotonicMillis) -> Option<SupervisorAction> {
        if let Some(action) = self.pending_system_action.take() {
            return Some(action);
        }
        for index in 0..self.records.len() {
            let dependencies_ready = self.dependencies_ready(index);
            let record = &mut self.records[index];
            match record.state {
                ServiceState::Stopped
                    if record.desired == DesiredState::Up && dependencies_ready =>
                {
                    return Some(SupervisorAction::Launch {
                        service_id: record.policy.id,
                    });
                }
                ServiceState::Starting {
                    process,
                    health_deadline,
                    lifetime_deadline,
                } => {
                    let (reason, after_stop) = if record.desired == DesiredState::Down {
                        (StopReason::Requested, AfterStop::Down)
                    } else if record.restart_pending {
                        record.restart_pending = false;
                        (StopReason::Restart, AfterStop::Restart)
                    } else if !dependencies_ready {
                        (StopReason::DependencyUnavailable, AfterStop::Dependency)
                    } else if health_deadline.is_some_and(|deadline| now >= deadline) {
                        (
                            StopReason::ReadinessTimeout,
                            AfterStop::Failure(FailureReason::ReadinessTimeout),
                        )
                    } else if lifetime_deadline.is_some_and(|deadline| now >= deadline) {
                        (
                            StopReason::LifetimeExpired,
                            AfterStop::Failure(FailureReason::LifetimeExpired),
                        )
                    } else {
                        continue;
                    };
                    return Some(begin_stop(record, process, now, reason, after_stop));
                }
                ServiceState::Ready {
                    process,
                    lifetime_deadline,
                } => {
                    let (reason, after_stop) = if record.desired == DesiredState::Down {
                        (StopReason::Requested, AfterStop::Down)
                    } else if record.restart_pending {
                        record.restart_pending = false;
                        (StopReason::Restart, AfterStop::Restart)
                    } else if !dependencies_ready {
                        (StopReason::DependencyUnavailable, AfterStop::Dependency)
                    } else if lifetime_deadline.is_some_and(|deadline| now >= deadline) {
                        (
                            StopReason::LifetimeExpired,
                            AfterStop::Failure(FailureReason::LifetimeExpired),
                        )
                    } else {
                        continue;
                    };
                    return Some(begin_stop(record, process, now, reason, after_stop));
                }
                ServiceState::Backoff { deadline, .. } if now >= deadline => {
                    record.state = ServiceState::Stopped;
                    return Some(SupervisorAction::Launch {
                        service_id: record.policy.id,
                    });
                }
                ServiceState::Stopping {
                    process,
                    deadline,
                    reason,
                } if now >= deadline => {
                    return Some(SupervisorAction::ForceStop {
                        service_id: record.policy.id,
                        process,
                        reason,
                    });
                }
                ServiceState::Stopped
                | ServiceState::Backoff { .. }
                | ServiceState::Stopping { .. }
                | ServiceState::Failed { .. } => {}
            }
        }
        None
    }

    /// Earliest supervisor-owned deadline after `now`.
    #[must_use]
    pub fn next_deadline(&self, now: MonotonicMillis) -> Option<MonotonicMillis> {
        self.records
            .iter()
            .filter_map(|record| match record.state {
                ServiceState::Starting {
                    health_deadline,
                    lifetime_deadline,
                    ..
                } => earliest(health_deadline, lifetime_deadline),
                ServiceState::Ready {
                    lifetime_deadline, ..
                } => lifetime_deadline,
                ServiceState::Backoff { deadline, .. }
                | ServiceState::Stopping { deadline, .. } => Some(deadline),
                ServiceState::Stopped | ServiceState::Failed { .. } => None,
            })
            .filter(|deadline| *deadline > now)
            .min()
    }

    fn apply_failure(
        &mut self,
        index: usize,
        reason: FailureReason,
        now: MonotonicMillis,
    ) -> Result<(), SupervisorError> {
        let record = &mut self.records[index];
        match record.policy.failure_action {
            FailureAction::Restart if record.restarts < record.policy.restart_limit => {
                record.restarts = record
                    .restarts
                    .checked_add(1)
                    .ok_or(SupervisorError::InvalidState)?;
                let delay = restart_delay(record.restarts);
                record.state = ServiceState::Backoff {
                    deadline: now.saturating_add(delay),
                    reason,
                };
            }
            FailureAction::Continue | FailureAction::Restart => {
                record.state = ServiceState::Failed { reason };
            }
            FailureAction::PreviousGeneration => {
                record.state = ServiceState::Failed { reason };
                self.pending_system_action = Some(SupervisorAction::ActivatePreviousGeneration {
                    service_id: record.policy.id,
                });
            }
            FailureAction::RecoveryShell => {
                record.state = ServiceState::Failed { reason };
                self.pending_system_action = Some(SupervisorAction::EnterRecovery {
                    service_id: record.policy.id,
                });
            }
        }
        Ok(())
    }

    fn dependencies_ready(&self, index: usize) -> bool {
        self.records[index]
            .policy
            .dependencies
            .iter()
            .all(|dependency| {
                self.records
                    .iter()
                    .find(|record| record.policy.id == *dependency)
                    .is_some_and(|record| record.state.is_ready())
            })
    }

    fn index(&self, service_id: u32) -> Result<usize, SupervisorError> {
        self.records
            .iter()
            .position(|record| record.policy.id == service_id)
            .ok_or(SupervisorError::UnknownService)
    }

    fn record(&self, service_id: u32) -> Result<&ServiceRecord, SupervisorError> {
        self.records
            .iter()
            .find(|record| record.policy.id == service_id)
            .ok_or(SupervisorError::UnknownService)
    }

    fn record_mut(&mut self, service_id: u32) -> Result<&mut ServiceRecord, SupervisorError> {
        self.records
            .iter_mut()
            .find(|record| record.policy.id == service_id)
            .ok_or(SupervisorError::UnknownService)
    }
}

fn begin_stop(
    record: &mut ServiceRecord,
    process: TaskId,
    now: MonotonicMillis,
    reason: StopReason,
    after_stop: AfterStop,
) -> SupervisorAction {
    record.after_stop = Some(after_stop);
    record.state = ServiceState::Stopping {
        process,
        deadline: now.saturating_add(STOP_GRACE_MILLISECONDS),
        reason,
    };
    SupervisorAction::RequestStop {
        service_id: record.policy.id,
        process,
        reason,
    }
}

const fn restart_delay(restarts: u8) -> u64 {
    let shift = if restarts > 6 { 6 } else { restarts - 1 };
    let delay = 1_000_u64 << shift;
    if delay > MAX_RESTART_DELAY_MILLISECONDS {
        MAX_RESTART_DELAY_MILLISECONDS
    } else {
        delay
    }
}

const fn nonzero_deadline(now: MonotonicMillis, milliseconds: u32) -> Option<MonotonicMillis> {
    if milliseconds == 0 {
        None
    } else {
        Some(now.saturating_add(milliseconds as u64))
    }
}

fn earliest(
    first: Option<MonotonicMillis>,
    second: Option<MonotonicMillis>,
) -> Option<MonotonicMillis> {
    match (first, second) {
        (Some(first), Some(second)) => Some(core::cmp::min(first, second)),
        (Some(first), None) => Some(first),
        (None, Some(second)) => Some(second),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        BoundedLog, DesiredState, FailureReason, ServicePolicy, ServiceState, StopReason,
        Supervisor, SupervisorAction,
    };
    use troe_config::{FailureAction, StartupMode};
    use troe_task::{Capabilities, MonotonicMillis, Scheduler, StackResource};

    fn task(ordinal: u8) -> troe_task::TaskId {
        let mut scheduler =
            Scheduler::new(usize::from(ordinal)).unwrap_or_else(|_| std::process::abort());
        let mut selected = None;
        for slot in 0..ordinal {
            selected = Some(
                scheduler
                    .spawn(
                        Capabilities::NONE,
                        StackResource::new(u32::from(slot), 1)
                            .unwrap_or_else(|_| std::process::abort()),
                    )
                    .unwrap_or_else(|_| std::process::abort()),
            );
        }
        selected.unwrap_or_else(|| std::process::abort())
    }

    fn policy(
        id: u32,
        mode: StartupMode,
        action: FailureAction,
        restarts: u8,
        dependencies: &[u32],
    ) -> ServicePolicy {
        ServicePolicy::for_test(id, mode, action, restarts, 100, 0, dependencies)
    }

    #[test]
    fn readiness_dependencies_gate_launch_and_reverse_loss_stops_dependents() {
        let policies = [
            policy(
                1,
                StartupMode::BootRequired,
                FailureAction::RecoveryShell,
                0,
                &[],
            ),
            policy(
                2,
                StartupMode::BootRequired,
                FailureAction::RecoveryShell,
                0,
                &[1],
            ),
        ];
        let mut supervisor =
            Supervisor::new(&policies, false, 16).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(0)),
            Some(SupervisorAction::Launch { service_id: 1 })
        );
        let first = task(1);
        supervisor
            .launched(1, first, MonotonicMillis::from_millis(0))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(1)),
            None
        );
        supervisor
            .ready(1, first)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(1)),
            Some(SupervisorAction::Launch { service_id: 2 })
        );
        let second = task(2);
        supervisor
            .launched(2, second, MonotonicMillis::from_millis(1))
            .unwrap_or_else(|_| std::process::abort());
        supervisor
            .ready(2, second)
            .unwrap_or_else(|_| std::process::abort());
        assert!(supervisor.required_services_ready());

        supervisor
            .request_stop(1)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(2)),
            Some(SupervisorAction::RequestStop {
                service_id: 1,
                process: first,
                reason: StopReason::Requested,
            })
        );
        supervisor
            .stopped(1, first, MonotonicMillis::from_millis(3))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(3)),
            Some(SupervisorAction::RequestStop {
                service_id: 2,
                process: second,
                reason: StopReason::DependencyUnavailable,
            })
        );
    }

    #[test]
    fn readiness_timeout_uses_bounded_restart_backoff_and_ceiling() {
        let policies = [policy(
            1,
            StartupMode::BootRequired,
            FailureAction::Restart,
            2,
            &[],
        )];
        let mut supervisor =
            Supervisor::new(&policies, false, 8).unwrap_or_else(|_| std::process::abort());
        let process = task(1);
        supervisor
            .launched(1, process, MonotonicMillis::from_millis(0))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(100)),
            Some(SupervisorAction::RequestStop {
                service_id: 1,
                process,
                reason: StopReason::ReadinessTimeout,
            })
        );
        supervisor
            .stopped(1, process, MonotonicMillis::from_millis(101))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor
                .snapshot(1)
                .unwrap_or_else(|_| std::process::abort())
                .state,
            ServiceState::Backoff {
                deadline: MonotonicMillis::from_millis(1_101),
                reason: FailureReason::ReadinessTimeout,
            }
        );
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(1_100)),
            None
        );
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(1_101)),
            Some(SupervisorAction::Launch { service_id: 1 })
        );

        let process = task(2);
        supervisor
            .launched(1, process, MonotonicMillis::from_millis(1_101))
            .unwrap_or_else(|_| std::process::abort());
        supervisor
            .exited(1, process, Some(7), MonotonicMillis::from_millis(1_102))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor
                .snapshot(1)
                .unwrap_or_else(|_| std::process::abort())
                .state,
            ServiceState::Backoff {
                deadline: MonotonicMillis::from_millis(3_102),
                reason: FailureReason::Exited(7),
            }
        );
    }

    #[test]
    fn explicit_restart_and_forced_stop_preserve_exact_owner() {
        let policies = [policy(
            1,
            StartupMode::OnDemand,
            FailureAction::Continue,
            0,
            &[],
        )];
        let mut supervisor =
            Supervisor::new(&policies, false, 8).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor
                .snapshot(1)
                .unwrap_or_else(|_| std::process::abort())
                .desired,
            DesiredState::Down
        );
        supervisor
            .request_start(1)
            .unwrap_or_else(|_| std::process::abort());
        let process = task(1);
        supervisor
            .launched(1, process, MonotonicMillis::from_millis(0))
            .unwrap_or_else(|_| std::process::abort());
        supervisor
            .ready(1, process)
            .unwrap_or_else(|_| std::process::abort());
        supervisor
            .request_restart(1)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(5)),
            Some(SupervisorAction::RequestStop {
                service_id: 1,
                process,
                reason: StopReason::Restart,
            })
        );
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(1_005)),
            Some(SupervisorAction::ForceStop {
                service_id: 1,
                process,
                reason: StopReason::Restart,
            })
        );
        assert!(
            supervisor
                .stopped(1, task(2), MonotonicMillis::from_millis(1_005))
                .is_err()
        );
        supervisor
            .stopped(1, process, MonotonicMillis::from_millis(1_005))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            supervisor.next_action(MonotonicMillis::from_millis(1_005)),
            Some(SupervisorAction::Launch { service_id: 1 })
        );
    }

    #[test]
    fn recent_log_is_bounded_and_counts_both_eviction_paths() {
        let mut log = BoundedLog::new(5).unwrap_or_else(|_| std::process::abort());
        log.append(b"abc");
        log.append(b"def");
        let mut bytes = [0_u8; 8];
        let count = log.copy_recent(&mut bytes);
        assert_eq!(&bytes[..count], b"bcdef");
        assert_eq!(log.dropped(), 1);
        log.append(b"01234567");
        let count = log.copy_recent(&mut bytes);
        assert_eq!(&bytes[..count], b"34567");
        assert_eq!(log.dropped(), 9);
    }
}

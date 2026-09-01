//! Supervised background services and the job registry the shell reports.
//!
//! A service is launched as a session-independent background job whose
//! standard input is always empty, so a supervised process can never consume
//! prompt input. The supervisor decides restarts; this module performs them.
//!
//! This is what ADR 0035 names `kernel/src/supervisor.rs`. Phase D and E add
//! the boot-service records, readiness, and restart-window policy for the
//! persistent servers to the same authority.

use crate::console::{DiscardOutput, EmptyInput};
use crate::handles::{OwnedNamespace, SharedProcessTable, SharedRuntime};
use crate::invocation::{CommandApplicationOutcome, command_application_error};
use crate::kex::KexCommandRunner;
use crate::limits::RESIDENT_PROCESS_LOG_BYTES;
use crate::machine::OwnedAccounting;
use crate::resident::{ResidentOwner, ResidentProcessTable};
use crate::support::write_all;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use troe_core::{CommandStatus, Output};
use troe_dispatch::{Dispatcher, Rights, Service};
use troe_fmt_scfg::SystemConfig;
use troe_shell::Shell;
use troe_supervisor::{ServiceState, Supervisor, SupervisorAction};
use troe_task::{Capabilities, Scheduler, TaskId};

pub(crate) struct ServiceRuntime {
    pub(crate) config: SystemConfig,
    pub(crate) supervisor: Supervisor,
}

/// Launch one supervised service as a session-independent background job.
///
/// Services never hold the session terminal loan: their standard input is
/// always empty, so a supervised process cannot consume prompt input.
#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_service_process(
    service: &troe_fmt_scfg::ServiceConfig,
    namespace: &OwnedNamespace,
    shell: &mut Shell,
    residents: &mut ResidentProcessTable,
    processes: &SharedProcessTable,
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    shell_id: TaskId,
    shell_capabilities: Capabilities,
    runtime: &SharedRuntime,
) -> CommandStatus {
    let line = alloc::format!("{} &", service.name());
    let mut input = EmptyInput;
    let mut output = DiscardOutput;
    let mut error = DiscardOutput;
    let mut runner = KexCommandRunner {
        accounting,
        scheduler,
        residents,
        processes: processes.clone(),
        resident_owner: ResidentOwner::Service(service.id()),
        service_initial_handles: Some(service.initial_handles()),
        service_capability_bits: Some(service.capability_bits()),
        service_runtime: None,
        shell_id,
        shell_capabilities,
        runtime: runtime.clone(),
        session_terminal: None,
        pending_script_lines: None,
        composed_namespace: Rc::clone(namespace),
    };
    shell.execute_with_external(&line, &mut input, &mut output, &mut error, &mut runner)
}

impl ServiceRuntime {
    pub(crate) fn new(config: SystemConfig, recovery: bool) -> Result<Self, ()> {
        let supervisor = Supervisor::from_config(&config, recovery).map_err(|_| ())?;
        Ok(Self { config, supervisor })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn drive(
        &mut self,
        namespace: &OwnedNamespace,
        shell: &mut Shell,
        residents: &mut ResidentProcessTable,
        processes: &SharedProcessTable,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        shell_id: TaskId,
        shell_capabilities: Capabilities,
        runtime: &SharedRuntime,
    ) -> Result<(), ()> {
        let now = runtime.borrow().now();
        for service in self.config.services() {
            let Some((process, outcome, log)) = residents.take_service_terminal(service.id())
            else {
                continue;
            };
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(RESIDENT_PROCESS_LOG_BYTES)
                .map_err(|_| ())?;
            bytes.resize(RESIDENT_PROCESS_LOG_BYTES, 0);
            let count = log.try_borrow().map_err(|_| ())?.copy_recent(&mut bytes);
            self.supervisor
                .append_log(service.id(), &bytes[..count])
                .map_err(|_| ())?;
            let state = self
                .supervisor
                .snapshot(service.id())
                .map_err(|_| ())?
                .state;
            if matches!(state, ServiceState::Stopping { .. }) {
                self.supervisor
                    .stopped(service.id(), process, now)
                    .map_err(|_| ())?;
            } else {
                let status = match outcome {
                    CommandApplicationOutcome::Exited(status) => Some(status),
                    CommandApplicationOutcome::Faulted(_) => None,
                };
                self.supervisor
                    .exited(service.id(), process, status, now)
                    .map_err(|_| ())?;
            }
        }

        for _ in 0..=self.config.services().len() {
            let Some(action) = self.supervisor.next_action(now) else {
                break;
            };
            match action {
                SupervisorAction::Launch { service_id } => {
                    let service = self
                        .config
                        .services()
                        .iter()
                        .find(|service| service.id() == service_id)
                        .ok_or(())?;
                    let expected_path = alloc::format!("/bin/{}.kex", service.name());
                    if service.artifact_path() != expected_path {
                        self.supervisor
                            .launch_failed(service_id, now)
                            .map_err(|_| ())?;
                        continue;
                    }
                    let status = launch_service_process(
                        service,
                        namespace,
                        shell,
                        residents,
                        processes,
                        scheduler,
                        accounting,
                        shell_id,
                        shell_capabilities,
                        runtime,
                    );
                    if status != CommandStatus::Success {
                        self.supervisor
                            .launch_failed(service_id, now)
                            .map_err(|_| ())?;
                        continue;
                    }
                    let process = residents.service_task(service_id).ok_or(())?;
                    self.supervisor
                        .launched(service_id, process, now)
                        .map_err(|_| ())?;
                    // SCFG v1's first resident implementation defines
                    // readiness as successful admission into the event loop.
                    // A typed readiness notification can tighten this
                    // boundary without changing the supervisor state model.
                    self.supervisor.ready(service_id, process).map_err(|_| ())?;
                }
                SupervisorAction::RequestStop { service_id, .. }
                | SupervisorAction::ForceStop { service_id, .. } => {
                    residents.request_service_cancel(service_id)?;
                }
                SupervisorAction::ActivatePreviousGeneration { .. }
                | SupervisorAction::EnterRecovery { .. } => return Err(()),
            }
        }
        Ok(())
    }
}

pub(crate) fn copy_service_output(
    residents: &ResidentProcessTable,
    service_id: u32,
    name: &str,
    runtime: &ServiceRuntime,
    stdout: &mut dyn Output,
    stderr: &mut dyn Output,
) -> CommandStatus {
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(RESIDENT_PROCESS_LOG_BYTES).is_err() {
        return command_application_error(stderr, "svc", "buffer allocation failed");
    }
    bytes.resize(RESIDENT_PROCESS_LOG_BYTES, 0);
    let (count, dropped) = if let Some(log) = residents.copy_service_log(service_id, &mut bytes) {
        log
    } else {
        let Ok(count) = runtime.supervisor.copy_log(service_id, &mut bytes) else {
            return command_application_error(stderr, "svc", "service log unavailable");
        };
        let Ok(snapshot) = runtime.supervisor.snapshot(service_id) else {
            return command_application_error(stderr, "svc", "service state unavailable");
        };
        (count, snapshot.dropped_log_bytes)
    };
    if dropped != 0 {
        let notice = alloc::format!("[{name}: {dropped} earlier bytes discarded]\n");
        if write_all(stdout, notice.as_bytes()).is_err() {
            return CommandStatus::Failure;
        }
    }
    if write_all(stdout, &bytes[..count]).is_err() {
        CommandStatus::Failure
    } else {
        CommandStatus::Success
    }
}

pub(crate) fn service_id_by_name(config: &SystemConfig, name: &str) -> Option<u32> {
    config
        .services()
        .iter()
        .find(|service| service.name() == name)
        .map(troe_fmt_scfg::ServiceConfig::id)
}

pub(crate) const fn service_state_label(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Stopped => "stopped",
        ServiceState::Starting { .. } => "starting",
        ServiceState::Ready { .. } => "ready",
        ServiceState::Backoff { .. } => "backoff",
        ServiceState::Stopping { .. } => "stopping",
        ServiceState::Failed { .. } => "failed",
    }
}

pub(crate) fn register_command_service<'service, S: Service + 'service>(
    dispatcher: &mut Dispatcher<'service>,
    service: S,
) -> Result<troe_dispatch::PortId, ()> {
    let (port, kernel_handle) = dispatcher
        .register(Box::new(service), Rights::CALL)
        .map_err(|_| ())?;
    dispatcher.close(kernel_handle).map_err(|_| ())?;
    Ok(port)
}

//! The shell's external command runner.
//!
//! `KexCommandRunner` is the bridge between the shell's command model and a
//! KEX launch: it resolves a command to a package, decides foreground,
//! background, or service placement, wires the standard streams, and reports
//! the outcome back as a command status.

use crate::artifacts::native_application_target;
use crate::deferred::CommandDeferredServices;
use crate::handles::{
    OwnedNamespace, SharedDiagnosticsSnapshot, SharedProcessTable, SharedRuntime,
};
use crate::invocation::{
    CommandApplicationOutcome, CommandStartupService, command_application_error,
    command_application_status_error, command_status,
};
use crate::limits::{
    RESIDENT_POLL_MILLISECONDS, RESIDENT_PROCESS_CAPACITY, RESIDENT_PROCESS_LOG_BYTES,
};
use crate::machine::OwnedAccounting;
use crate::nested::{NestedInput, NestedLaunchContext, NestedOutput, NestedStdio};
use crate::network::services::{
    ApplicationDatagramService, ApplicationDatagramState, ApplicationIcmpEchoService,
    ApplicationNetworkConfigurationService, ApplicationNetworkObservationService,
    ApplicationTcpConnectService,
};
use crate::requirements::BackgroundRequirements;
use crate::resident::launch::{
    prepare_streamed_resident_application, random_application_placement,
};
use crate::resident::{
    ResidentApplication, ResidentExecution, ResidentOwner, ResidentProcessControl,
    ResidentProcessTable,
};
use crate::service::clock::{
    ApplicationClockControlService, ApplicationTimerService, ApplicationWallClockService,
};
use crate::service::diagnostics::{
    ApplicationDiagnosticsProxyService, ApplicationDiagnosticsSnapshotService,
    application_diagnostics_snapshot, machine_snapshot,
};
use crate::service::filesystem::{
    ApplicationFilesystemMutationService, ApplicationFilesystemService,
    ApplicationVolumeControlService,
};
use crate::service::process::{
    ApplicationPipeService, ApplicationProcessLaunchService, ApplicationProcessObservationService,
};
use crate::service::{
    ApplicationEmptyInputService, ApplicationInputService, ApplicationLogService,
    ApplicationOutputService, ApplicationPrivateMemoryService, ApplicationRandomService,
    ApplicationShellScriptService, SubmittedShellScript,
};
use crate::session::SharedSessionTerminal;
use crate::supervision::{
    ServiceRuntime, copy_service_output, register_command_service, service_id_by_name,
    service_state_label,
};
use crate::support::{architecture, fatal, write_all};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use troe_abi::{
    clock_control, command, datagram, diagnostics, filesystem, filesystem_mutation, icmp_echo,
    network_configuration, network_observation, pipe, private_memory, process_launch,
    process_observation, random, shell_script, stream, tcp_connect, timer, volume_control,
    wall_clock,
};
use troe_application::{ABI_MINOR, StreamedKexPackage, parse_streamed_kex_package};
use troe_core::{CommandStatus, Input, Output};
use troe_dispatch::{CommandInvocationService, Dispatcher};
use troe_fs_api::NodeKind;
use troe_process::{ChildTable, MAX_CHILDREN_PER_OWNER, MAX_PIPES_PER_OWNER, OwnerId, PipeTable};
use troe_shell::{
    ExecutionPlacement, ExternalCommand, ExternalCommandReference, JobControl, ServiceControl,
    SharedNamespace, external_command_reference, format_memory_report,
};
use troe_supervisor::BoundedLog;
use troe_task::{Capabilities, ProcessOrigin, Scheduler, TaskFault, TaskId};

pub(crate) struct KexCommandRunner<'a> {
    pub(crate) accounting: &'a mut OwnedAccounting,
    pub(crate) scheduler: &'a mut Scheduler,
    pub(crate) residents: &'a mut ResidentProcessTable,
    pub(crate) processes: SharedProcessTable,
    pub(crate) resident_owner: ResidentOwner,
    pub(crate) service_initial_handles: Option<u8>,
    pub(crate) service_capability_bits: Option<u32>,
    pub(crate) service_runtime: Option<&'a mut ServiceRuntime>,
    pub(crate) shell_id: TaskId,
    pub(crate) shell_capabilities: Capabilities,
    pub(crate) runtime: SharedRuntime,
    pub(crate) session_terminal: Option<SharedSessionTerminal>,
    pub(crate) pending_script_lines: Option<Vec<String>>,
    /// Composition authority. External execution attaches application
    /// filesystem and volume services, which is more than the client
    /// contract the session itself holds.
    pub(crate) composed_namespace: OwnedNamespace,
}

impl KexCommandRunner<'_> {
    fn run_foreground_process(
        &mut self,
        mut process: ResidentApplication<'_>,
    ) -> Result<CommandApplicationOutcome, ()> {
        self.scheduler
            .yield_current(self.shell_id)
            .map_err(|_| ())?;
        let mut cancellation_delivered = false;
        let outcome = loop {
            match process.step(self.scheduler, self.accounting) {
                Ok(Some(outcome)) => {
                    break process.teardown(self.scheduler, self.accounting, outcome, false);
                }
                Err(()) => {
                    break process.teardown(
                        self.scheduler,
                        self.accounting,
                        CommandApplicationOutcome::Faulted(TaskFault::InvalidCall),
                        true,
                    );
                }
                Ok(None) => {}
            }
            if cancellation_delivered {
                break process.teardown(
                    self.scheduler,
                    self.accounting,
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                );
            }
            if self.runtime.borrow_mut().checkpoint().is_err() {
                match process.request_deferred_cancel(self.scheduler) {
                    Ok(true) => {
                        cancellation_delivered = true;
                        continue;
                    }
                    Ok(false) | Err(()) => {
                        break process.teardown(
                            self.scheduler,
                            self.accounting,
                            CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                            true,
                        );
                    }
                }
            }
            if let Some(terminal) = self.session_terminal.as_ref()
                && let Ok(mut terminal) = terminal.try_borrow_mut()
            {
                terminal.pump();
            }
            if self
                .residents
                .pump_processes(self.scheduler, self.accounting)
                .is_err()
            {
                let _cleaned = process.teardown(
                    self.scheduler,
                    self.accounting,
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                );
                break Err(());
            }
            let foreground_blocked = matches!(process.execution, Some(ResidentExecution::Blocked));
            if foreground_blocked
                && !self.residents.has_runnable_process()
                && troe_machine::wait_for_runtime_event_timeout(RESIDENT_POLL_MILLISECONDS).is_err()
            {
                let _cleaned = process.teardown(
                    self.scheduler,
                    self.accounting,
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                );
                break Err(());
            }
        };
        if self
            .scheduler
            .dispatch(self.shell_id, self.shell_capabilities)
            .is_err()
        {
            fatal(b"fatal: shell scheduler restore failed\n");
        }
        outcome
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn launch_background(
        &mut self,
        command: &str,
        words: &[String],
        cwd: &str,
        namespace: &OwnedNamespace,
        artifact_path: &str,
        package: &StreamedKexPackage,
        requirements: BackgroundRequirements,
        diagnostics_snapshot: Option<&SharedDiagnosticsSnapshot>,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        let Some(resource_slot) = self.residents.available_slot() else {
            return command_application_error(stderr, command, "resident process table full");
        };
        if self.residents.jobs.len() >= RESIDENT_PROCESS_CAPACITY {
            return command_application_error(
                stderr,
                command,
                "reap a completed job before starting another",
            );
        }
        let service_count = 4
            + usize::from(requirements.datagram)
            + usize::from(requirements.filesystem)
            + usize::from(requirements.filesystem_mutation)
            + usize::from(requirements.timer)
            + usize::from(requirements.diagnostics)
            + usize::from(requirements.process_observation)
            + usize::from(requirements.process_launch)
            + usize::from(requirements.pipe)
            + usize::from(requirements.network_observation)
            + usize::from(requirements.network_configuration)
            + usize::from(requirements.icmp_echo)
            + usize::from(requirements.tcp_connect)
            + usize::from(requirements.volume_control)
            + usize::from(requirements.wall_clock)
            + usize::from(requirements.clock_control)
            + usize::from(requirements.private_memory)
            + usize::from(requirements.random);
        let Some(handle_capacity) = service_count.checked_mul(2) else {
            return command_application_error(stderr, command, "service resources exhausted");
        };
        let Ok(mut dispatcher): Result<Dispatcher<'static>, _> =
            Dispatcher::new(service_count, handle_capacity)
        else {
            return command_application_error(stderr, command, "service resources exhausted");
        };
        let Ok(log) = BoundedLog::new(RESIDENT_PROCESS_LOG_BYTES) else {
            return command_application_error(stderr, command, "log allocation failed");
        };
        let log = Rc::new(RefCell::new(log));
        let application_network = self.runtime.borrow().network.clone();
        let application_transport_network = if requirements.datagram || requirements.tcp_connect {
            let Some(network) = application_network.clone() else {
                return command_application_error(
                    stderr,
                    command,
                    "required capability unavailable",
                );
            };
            Some(network)
        } else {
            None
        };
        let filesystem_namespace = if requirements.filesystem
            || requirements.filesystem_mutation
            || requirements.volume_control
        {
            Some(Rc::clone(namespace))
        } else {
            None
        };
        let datagram_state = if requirements.datagram {
            let Some(network) = application_transport_network.clone() else {
                return command_application_error(
                    stderr,
                    command,
                    "required capability unavailable",
                );
            };
            Some(Rc::new(RefCell::new(ApplicationDatagramState::new(
                network,
            ))))
        } else {
            None
        };
        let timer_task_id = requirements.timer.then(|| Rc::new(Cell::new(None)));
        let process_owner_binding =
            (requirements.process_launch || requirements.pipe).then(|| Rc::new(Cell::new(None)));
        let process_children = if requirements.process_launch {
            match ChildTable::new(MAX_CHILDREN_PER_OWNER) {
                Ok(children) => Some(Rc::new(RefCell::new(children))),
                Err(_) => {
                    return command_application_error(
                        stderr,
                        command,
                        "process metadata exhausted",
                    );
                }
            }
        } else {
            None
        };
        let process_pipes = if requirements.process_launch || requirements.pipe {
            match PipeTable::new(MAX_PIPES_PER_OWNER) {
                Ok(pipes) => Some(Rc::new(RefCell::new(pipes))),
                Err(_) => {
                    return command_application_error(stderr, command, "pipe metadata exhausted");
                }
            }
        } else {
            None
        };

        // The zone resolved at boot replaces the conventional `UTC0`. It is
        // copied into bounded storage so no borrow of the accounting state
        // is held across the launch, and so composing an environment needs
        // no allocation that could fail here.
        let mut timezone_storage =
            [0_u8; command::TIMEZONE_NAME.len() + 1 + troe_abi::timezone::MAX_TZ_BYTES];
        let timezone_bytes = {
            let resolved = self.accounting.session_timezone.borrow();
            match resolved.as_deref() {
                Some(entry) if entry.len() <= timezone_storage.len() => {
                    timezone_storage[..entry.len()].copy_from_slice(entry.as_bytes());
                    entry.len()
                }
                _ => 0,
            }
        };
        let session_environment = match core::str::from_utf8(&timezone_storage[..timezone_bytes]) {
            Ok(entry) if timezone_bytes != 0 => {
                command::conventional_environment_with_timezone(entry)
            }
            _ => command::CONVENTIONAL_ENVIRONMENT,
        };
        let services = (|| -> Result<Vec<CommandStartupService>, ()> {
            let mut services = Vec::new();
            services.try_reserve_exact(service_count).map_err(|_| ())?;
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    CommandInvocationService::new_with_environment(
                        cwd,
                        words,
                        &session_environment,
                    )
                    .map_err(|_| ())?,
                )?,
                interface: troe_abi::interface::COMMAND,
                major: command::MAJOR,
                minor: command::MINOR,
            });
            services.push(CommandStartupService {
                port: register_command_service(&mut dispatcher, ApplicationEmptyInputService)?,
                interface: troe_abi::interface::STANDARD_INPUT,
                major: stream::MAJOR,
                minor: stream::MINOR,
            });
            for interface in [
                troe_abi::interface::STANDARD_OUTPUT,
                troe_abi::interface::STANDARD_ERROR,
            ] {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationLogService {
                            log: Rc::clone(&log),
                        },
                    )?,
                    interface,
                    major: stream::MAJOR,
                    minor: stream::MINOR,
                });
            }
            if requirements.datagram {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationDatagramService::new(
                            datagram_state.as_ref().ok_or(())?.clone(),
                            self.runtime.clone(),
                        ),
                    )?,
                    interface: troe_abi::interface::DATAGRAM,
                    major: datagram::MAJOR,
                    minor: datagram::MINOR,
                });
            }
            if requirements.filesystem {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationFilesystemService::new(
                            filesystem_namespace.as_ref().ok_or(())?.clone(),
                            cwd,
                        )?,
                    )?,
                    interface: troe_abi::interface::FILESYSTEM_READ,
                    major: filesystem::MAJOR,
                    minor: filesystem::MINOR,
                });
            }
            if requirements.filesystem_mutation {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationFilesystemMutationService::new(
                            filesystem_namespace.as_ref().ok_or(())?.clone(),
                            cwd,
                        )?,
                    )?,
                    interface: troe_abi::interface::FILESYSTEM_MUTATE,
                    major: filesystem_mutation::MAJOR,
                    minor: filesystem_mutation::MINOR,
                });
            }
            if requirements.timer {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationTimerService {
                            runtime: self.runtime.clone(),
                            processes: self.processes.clone(),
                            task_id: timer_task_id.as_ref().ok_or(())?.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::TIMER,
                    major: timer::MAJOR,
                    minor: timer::MINOR,
                });
            }
            if requirements.diagnostics {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationDiagnosticsSnapshotService {
                            snapshot: diagnostics_snapshot.cloned().ok_or(())?,
                        },
                    )?,
                    interface: troe_abi::interface::DIAGNOSTICS,
                    major: diagnostics::MAJOR,
                    minor: diagnostics::MINOR,
                });
            }
            if requirements.process_observation {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationProcessObservationService {
                            processes: self.processes.clone(),
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::PROCESS_OBSERVE,
                    major: process_observation::MAJOR,
                    minor: process_observation::MINOR,
                });
            }
            if requirements.process_launch {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationProcessLaunchService {
                            owner: process_owner_binding.as_ref().ok_or(())?.clone(),
                            children: process_children.as_ref().ok_or(())?.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::PROCESS_LAUNCH,
                    major: process_launch::MAJOR,
                    minor: process_launch::MINOR,
                });
            }
            if requirements.pipe {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationPipeService {
                            owner: process_owner_binding.as_ref().ok_or(())?.clone(),
                            pipes: process_pipes.as_ref().ok_or(())?.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::PIPE,
                    major: pipe::MAJOR,
                    minor: pipe::MINOR,
                });
            }
            if requirements.network_observation {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationNetworkObservationService {
                            network: application_network.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::NETWORK_OBSERVE,
                    major: network_observation::MAJOR,
                    minor: network_observation::MINOR,
                });
            }
            if requirements.network_configuration {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationNetworkConfigurationService {
                            network: application_network.clone(),
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::NETWORK_CONFIGURE,
                    major: network_configuration::MAJOR,
                    minor: network_configuration::MINOR,
                });
            }
            if requirements.icmp_echo {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationIcmpEchoService {
                            network: application_network.clone(),
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::ICMP_ECHO,
                    major: icmp_echo::MAJOR,
                    minor: icmp_echo::MINOR,
                });
            }
            if requirements.tcp_connect {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationTcpConnectService::new(
                            application_transport_network.as_ref().ok_or(())?.clone(),
                            self.runtime.clone(),
                        ),
                    )?,
                    interface: troe_abi::interface::TCP_CONNECT,
                    major: tcp_connect::MAJOR,
                    minor: tcp_connect::MINOR,
                });
            }
            if requirements.volume_control {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationVolumeControlService {
                            namespace: filesystem_namespace.as_ref().ok_or(())?.clone(),
                            mounts: self.accounting.runtime_mounts.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::VOLUME_CONTROL,
                    major: volume_control::MAJOR,
                    minor: volume_control::MINOR,
                });
            }
            if requirements.wall_clock {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationWallClockService {
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::WALL_CLOCK,
                    major: wall_clock::MAJOR,
                    minor: wall_clock::MINOR,
                });
            }
            if requirements.clock_control {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationClockControlService {
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::CLOCK_CONTROL,
                    major: clock_control::MAJOR,
                    minor: clock_control::MINOR,
                });
            }
            if requirements.private_memory {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationPrivateMemoryService,
                    )?,
                    interface: troe_abi::interface::PRIVATE_MEMORY,
                    major: private_memory::MAJOR,
                    minor: private_memory::MINOR,
                });
            }
            if requirements.random {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationRandomService {
                            random: self.accounting.random.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::RANDOM,
                    major: random::MAJOR,
                    minor: random::MINOR,
                });
            }
            Ok(services)
        })();
        let Ok(services) = services else {
            return command_application_error(stderr, command, "service setup failed");
        };
        let process = prepare_streamed_resident_application(
            self.scheduler,
            self.accounting,
            dispatcher,
            &services,
            package,
            |offset, destination| {
                namespace
                    .borrow_mut()
                    .read_file_at(cwd, artifact_path, offset, destination)
                    .map_err(|_| ())
            },
            resource_slot,
            command,
            match self.resident_owner {
                ResidentOwner::Session => ProcessOrigin::Background,
                ResidentOwner::Service(_) => ProcessOrigin::Service,
            },
            self.runtime.borrow().now().as_millis(),
            self.processes.clone(),
        );
        let Ok(mut process) = process else {
            return command_application_error(stderr, command, "application rejected");
        };
        if let Some(task_id) = &timer_task_id {
            task_id.set(Some(process.task_id));
        }
        let process_owner = if let Some(binding) = process_owner_binding.as_ref() {
            let Ok(owner) = OwnerId::new(process.task_id.get()) else {
                let _cleaned = process.teardown(
                    self.scheduler,
                    self.accounting,
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                );
                return command_application_error(stderr, command, "invalid process owner");
            };
            binding.set(Some(owner));
            Some(owner)
        } else {
            None
        };
        let deferred = (requirements.timer
            || requirements.datagram
            || requirements.process_launch
            || requirements.pipe)
            .then(|| CommandDeferredServices {
                runtime: self.runtime.clone(),
                datagram: datagram_state,
                diagnostics: None,
                process_owner,
                children: process_children.clone(),
                pipes: process_pipes.clone(),
                pipe_streams: Vec::new(),
                terminal: None,
            });
        if process.install_deferred_services(deferred).is_err() {
            let _cleaned = process.teardown(
                self.scheduler,
                self.accounting,
                CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                true,
            );
            return command_application_error(stderr, command, "wait metadata exhausted");
        }
        if requirements.process_launch {
            process.process_control = Some(ResidentProcessControl {
                owner: process_owner.unwrap_or_else(|| fatal(b"fatal: process owner missing\n")),
                depth: 1,
                grants: requirements,
                children: process_children
                    .clone()
                    .unwrap_or_else(|| fatal(b"fatal: child table missing\n")),
                pipes: process_pipes
                    .clone()
                    .unwrap_or_else(|| fatal(b"fatal: pipe table missing\n")),
                launch: NestedLaunchContext {
                    namespace: Rc::clone(namespace),
                    runtime: self.runtime.clone(),
                    processes: self.processes.clone(),
                    mounts: self.accounting.runtime_mounts.clone(),
                    stdio: NestedStdio {
                        stdin: NestedInput::Empty,
                        stdout: NestedOutput::Log(log.clone()),
                        stderr: NestedOutput::Log(log.clone()),
                    },
                },
                processes: Vec::new(),
            });
        }
        let invocation = words.join(" ");
        match self
            .residents
            .admit(invocation, self.resident_owner, log, Box::new(process))
        {
            Ok(job_id) => {
                let report = alloc::format!("[{job_id}] started {command}\n");
                if troe_core::write_all(stdout, report.as_bytes()).is_err() {
                    CommandStatus::Failure
                } else {
                    CommandStatus::Success
                }
            }
            Err(process) => {
                let _cleaned = (*process).teardown(
                    self.scheduler,
                    self.accounting,
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                );
                command_application_error(stderr, command, "resident admission failed")
            }
        }
    }
}

impl ExternalCommand for KexCommandRunner<'_> {
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn execute<'stream>(
        &mut self,
        command: &str,
        words: &[String],
        cwd: &str,
        _namespace: &SharedNamespace,
        placement: ExecutionPlacement,
        stdin: &'stream mut dyn Input,
        stdout: &'stream mut dyn Output,
        stderr: &'stream mut dyn Output,
    ) -> Option<CommandStatus> {
        // The session hands over the client contract, but this runner also
        // attaches application filesystem and volume services, so it works
        // through the composition handle it was constructed with.
        let namespace = &Rc::clone(&self.composed_namespace);
        self.pending_script_lines = None;
        let reference = external_command_reference(command)?;
        let explicit_path = matches!(reference, ExternalCommandReference::Path(_));
        let catalog_path = match reference {
            ExternalCommandReference::CatalogName(name) => Some(alloc::format!("/bin/{name}.kex")),
            ExternalCommandReference::Path(_) => None,
        };
        let path = catalog_path.as_deref().unwrap_or(command);
        let metadata = match namespace.borrow_mut().metadata(cwd, path) {
            Ok(metadata) => metadata,
            Err(troe_fs_api::FsError::NotFound) if !explicit_path => return None,
            Err(troe_fs_api::FsError::NotFound) => {
                return Some(command_application_status_error(
                    stderr,
                    command,
                    "not found",
                    CommandStatus::NotFound,
                ));
            }
            Err(_) => return Some(command_application_error(stderr, command, "lookup failed")),
        };
        if metadata.kind != NodeKind::File {
            return Some(command_application_error(
                stderr,
                command,
                "artifact is not a file",
            ));
        }
        let Ok(load_placement) = random_application_placement(&self.accounting.random) else {
            return Some(command_application_error(
                stderr,
                command,
                "application placement failed",
            ));
        };
        let Ok(package) = parse_streamed_kex_package(
            metadata.byte_count,
            |offset, destination| {
                namespace
                    .borrow_mut()
                    .read_file_at(cwd, path, offset, destination)
                    .map_err(|_| ())
            },
            native_application_target(),
            ABI_MINOR,
            load_placement,
        ) else {
            return Some(command_application_error(
                stderr,
                command,
                "application package rejected",
            ));
        };
        let capability_manifest = package.requirements();
        let mut datagram_required = false;
        let mut filesystem_required = false;
        let mut filesystem_mutation_required = false;
        let mut timer_required = false;
        let mut diagnostics_required = false;
        let mut process_observation_required = false;
        let mut process_launch_required = false;
        let mut pipe_required = false;
        let mut network_observation_required = false;
        let mut network_configuration_required = false;
        let mut icmp_echo_required = false;
        let mut tcp_connect_required = false;
        let mut volume_control_required = false;
        let mut shell_script_required = false;
        let mut wall_clock_required = false;
        let mut clock_control_required = false;
        let mut private_memory_required = false;
        let mut random_required = false;
        for requirement in capability_manifest.iter() {
            if requirement.interface == troe_abi::interface::DATAGRAM
                && requirement.major == datagram::MAJOR
                && requirement.minor == datagram::MINOR
            {
                datagram_required = true;
            } else if requirement.interface == troe_abi::interface::FILESYSTEM_READ
                && requirement.major == filesystem::MAJOR
                && requirement.minor == filesystem::MINOR
            {
                filesystem_required = true;
            } else if requirement.interface == troe_abi::interface::FILESYSTEM_MUTATE
                && requirement.major == filesystem_mutation::MAJOR
                && requirement.minor == filesystem_mutation::MINOR
            {
                filesystem_mutation_required = true;
            } else if requirement.interface == troe_abi::interface::TIMER
                && requirement.major == timer::MAJOR
                && requirement.minor == timer::MINOR
            {
                timer_required = true;
            } else if requirement.interface == troe_abi::interface::DIAGNOSTICS
                && requirement.major == diagnostics::MAJOR
                && requirement.minor == diagnostics::MINOR
            {
                diagnostics_required = true;
            } else if requirement.interface == troe_abi::interface::PROCESS_OBSERVE
                && requirement.major == process_observation::MAJOR
                && requirement.minor == process_observation::MINOR
            {
                process_observation_required = true;
            } else if requirement.interface == troe_abi::interface::PROCESS_LAUNCH
                && requirement.major == process_launch::MAJOR
                && requirement.minor == process_launch::MINOR
            {
                process_launch_required = true;
            } else if requirement.interface == troe_abi::interface::PIPE
                && requirement.major == pipe::MAJOR
                && requirement.minor == pipe::MINOR
            {
                pipe_required = true;
            } else if requirement.interface == troe_abi::interface::NETWORK_OBSERVE
                && requirement.major == network_observation::MAJOR
                && requirement.minor == network_observation::MINOR
            {
                network_observation_required = true;
            } else if requirement.interface == troe_abi::interface::NETWORK_CONFIGURE
                && requirement.major == network_configuration::MAJOR
                && requirement.minor == network_configuration::MINOR
            {
                network_configuration_required = true;
            } else if requirement.interface == troe_abi::interface::ICMP_ECHO
                && requirement.major == icmp_echo::MAJOR
                && requirement.minor == icmp_echo::MINOR
            {
                icmp_echo_required = true;
            } else if requirement.interface == troe_abi::interface::TCP_CONNECT
                && requirement.major == tcp_connect::MAJOR
                && requirement.minor == tcp_connect::MINOR
            {
                tcp_connect_required = true;
            } else if requirement.interface == troe_abi::interface::VOLUME_CONTROL
                && requirement.major == volume_control::MAJOR
                && requirement.minor == volume_control::MINOR
            {
                volume_control_required = true;
            } else if requirement.interface == troe_abi::interface::SHELL_SCRIPT
                && requirement.major == shell_script::MAJOR
                && requirement.minor == shell_script::MINOR
            {
                shell_script_required = true;
            } else if requirement.interface == troe_abi::interface::WALL_CLOCK
                && requirement.major == wall_clock::MAJOR
                && requirement.minor == wall_clock::MINOR
            {
                wall_clock_required = true;
            } else if requirement.interface == troe_abi::interface::CLOCK_CONTROL
                && requirement.major == clock_control::MAJOR
                && requirement.minor == clock_control::MINOR
            {
                clock_control_required = true;
            } else if requirement.interface == troe_abi::interface::PRIVATE_MEMORY
                && requirement.major == private_memory::MAJOR
                && requirement.minor == private_memory::MINOR
            {
                private_memory_required = true;
            } else if requirement.interface == troe_abi::interface::RANDOM
                && requirement.major == random::MAJOR
                && requirement.minor == random::MINOR
            {
                random_required = true;
            } else {
                return Some(command_application_error(
                    stderr,
                    command,
                    "unsupported capability requirement",
                ));
            }
        }
        let mut service_capability_bits = 0;
        if datagram_required {
            service_capability_bits |= troe_fmt_scfg::SERVICE_CAPABILITY_DATAGRAM;
        }
        if timer_required {
            service_capability_bits |= troe_fmt_scfg::SERVICE_CAPABILITY_TIMER;
        }
        if clock_control_required {
            service_capability_bits |= troe_fmt_scfg::SERVICE_CAPABILITY_CLOCK_CONTROL;
        }
        if wall_clock_required {
            service_capability_bits |= troe_fmt_scfg::SERVICE_CAPABILITY_WALL_CLOCK;
        }
        if let (Some(initial_handles), Some(authorized)) =
            (self.service_initial_handles, self.service_capability_bits)
        {
            let requested_handles = 4_usize.saturating_add(capability_manifest.len());
            let unsupported_service_authority = filesystem_required
                || filesystem_mutation_required
                || diagnostics_required
                || process_observation_required
                || process_launch_required
                || pipe_required
                || network_observation_required
                || network_configuration_required
                || icmp_echo_required
                || tcp_connect_required
                || volume_control_required
                || shell_script_required;
            if unsupported_service_authority
                || service_capability_bits & !authorized != 0
                || requested_handles > usize::from(initial_handles)
            {
                return Some(command_application_error(
                    stderr,
                    command,
                    "SCFG launch authority denied",
                ));
            }
        } else if clock_control_required {
            return Some(command_application_error(
                stderr,
                command,
                "clock-control authority is service-only",
            ));
        }
        let machine_memory = machine_snapshot(self.accounting);
        let machine_input = troe_machine::input_interrupt_stats();
        let namespace_memory = namespace.borrow().memory_stats();
        let diagnostics_snapshot = if diagnostics_required {
            match application_diagnostics_snapshot(machine_memory, machine_input, namespace_memory)
            {
                Ok(snapshot) => Some(snapshot),
                Err(()) => {
                    return Some(command_application_error(
                        stderr,
                        command,
                        "diagnostics snapshot failed",
                    ));
                }
            }
        } else {
            None
        };
        let memory_report = format_memory_report(
            architecture(),
            machine_memory,
            machine_input,
            namespace_memory,
        );
        if self
            .composed_namespace
            .borrow_mut()
            .set_system_file("/sys/memory", memory_report.as_bytes())
            .is_err()
        {
            return Some(command_application_error(
                stderr,
                command,
                "memory report refresh failed",
            ));
        }
        if placement == ExecutionPlacement::Background {
            if shell_script_required {
                return Some(command_application_error(
                    stderr,
                    command,
                    "interpreter applications require the foreground session",
                ));
            }
            return Some(self.launch_background(
                command,
                words,
                cwd,
                namespace,
                path,
                &package,
                BackgroundRequirements {
                    datagram: datagram_required,
                    filesystem: filesystem_required,
                    filesystem_mutation: filesystem_mutation_required,
                    timer: timer_required,
                    diagnostics: diagnostics_required,
                    process_observation: process_observation_required,
                    process_launch: process_launch_required,
                    pipe: pipe_required,
                    network_observation: network_observation_required,
                    network_configuration: network_configuration_required,
                    icmp_echo: icmp_echo_required,
                    tcp_connect: tcp_connect_required,
                    volume_control: volume_control_required,
                    wall_clock: wall_clock_required,
                    clock_control: clock_control_required,
                    private_memory: private_memory_required,
                    random: random_required,
                },
                diagnostics_snapshot.as_ref(),
                stdout,
                stderr,
            ));
        }
        let application_network = self.runtime.borrow().network.clone();
        let application_transport_network = if datagram_required || tcp_connect_required {
            let Some(network) = application_network.clone() else {
                return Some(command_application_error(
                    stderr,
                    command,
                    "required capability unavailable",
                ));
            };
            Some(network)
        } else {
            None
        };
        let service_count = 4
            + usize::from(datagram_required)
            + usize::from(filesystem_required)
            + usize::from(filesystem_mutation_required)
            + usize::from(timer_required)
            + usize::from(diagnostics_required)
            + usize::from(process_observation_required)
            + usize::from(process_launch_required)
            + usize::from(pipe_required)
            + usize::from(network_observation_required)
            + usize::from(network_configuration_required)
            + usize::from(icmp_echo_required)
            + usize::from(tcp_connect_required)
            + usize::from(volume_control_required)
            + usize::from(shell_script_required)
            + usize::from(wall_clock_required)
            + usize::from(clock_control_required)
            + usize::from(private_memory_required)
            + usize::from(random_required);
        let Some(handle_capacity) = service_count.checked_mul(2) else {
            return Some(command_application_error(
                stderr,
                command,
                "service resources exhausted",
            ));
        };
        let Ok(mut dispatcher) = Dispatcher::new(service_count, handle_capacity) else {
            return Some(command_application_error(
                stderr,
                command,
                "service resources exhausted",
            ));
        };
        let filesystem_namespace =
            if filesystem_required || filesystem_mutation_required || volume_control_required {
                Some(Rc::clone(namespace))
            } else {
                None
            };
        let process_owner_binding =
            (process_launch_required || pipe_required).then(|| Rc::new(Cell::new(None)));
        let process_children = if process_launch_required {
            match ChildTable::new(MAX_CHILDREN_PER_OWNER) {
                Ok(children) => Some(Rc::new(RefCell::new(children))),
                Err(_) => {
                    return Some(command_application_error(
                        stderr,
                        command,
                        "process metadata exhausted",
                    ));
                }
            }
        } else {
            None
        };
        let process_pipes = if process_launch_required || pipe_required {
            match PipeTable::new(MAX_PIPES_PER_OWNER) {
                Ok(pipes) => Some(Rc::new(RefCell::new(pipes))),
                Err(_) => {
                    return Some(command_application_error(
                        stderr,
                        command,
                        "pipe metadata exhausted",
                    ));
                }
            }
        } else {
            None
        };
        // Only the session's own terminal-backed stream takes the loan.
        // Redirected files, pipeline slices, and empty streams do not.
        let session_terminal = stdin
            .is_terminal()
            .then(|| self.session_terminal.clone())
            .flatten();
        let shared_stdin = Rc::new(RefCell::new(&mut *stdin));
        let shared_stdout = Rc::new(RefCell::new(&mut *stdout));
        let shared_stderr = Rc::new(RefCell::new(&mut *stderr));
        let application_datagram_state = if datagram_required {
            let network = application_transport_network
                .clone()
                .unwrap_or_else(|| fatal(b"fatal: datagram capability disappeared\n"));
            Some(Rc::new(RefCell::new(ApplicationDatagramState::new(
                network,
            ))))
        } else {
            None
        };
        let submitted_shell_script =
            shell_script_required.then(|| Rc::new(RefCell::new(SubmittedShellScript::default())));
        let timer_task_id = timer_required.then(|| Rc::new(Cell::new(None)));
        // The zone resolved at boot replaces the conventional `UTC0`. It is
        // copied into bounded storage so no borrow of the accounting state
        // is held across the launch, and so composing an environment needs
        // no allocation that could fail here.
        let mut timezone_storage =
            [0_u8; command::TIMEZONE_NAME.len() + 1 + troe_abi::timezone::MAX_TZ_BYTES];
        let timezone_bytes = {
            let resolved = self.accounting.session_timezone.borrow();
            match resolved.as_deref() {
                Some(entry) if entry.len() <= timezone_storage.len() => {
                    timezone_storage[..entry.len()].copy_from_slice(entry.as_bytes());
                    entry.len()
                }
                _ => 0,
            }
        };
        let session_environment = match core::str::from_utf8(&timezone_storage[..timezone_bytes]) {
            Ok(entry) if timezone_bytes != 0 => {
                command::conventional_environment_with_timezone(entry)
            }
            _ => command::CONVENTIONAL_ENVIRONMENT,
        };
        let services = (|| -> Result<Vec<CommandStartupService>, ()> {
            let mut services = Vec::new();
            services.try_reserve_exact(service_count).map_err(|_| ())?;
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    CommandInvocationService::new_with_environment(
                        cwd,
                        words,
                        &session_environment,
                    )
                    .map_err(|_| ())?,
                )?,
                interface: troe_abi::interface::COMMAND,
                major: command::MAJOR,
                minor: command::MINOR,
            });
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationInputService {
                        input: Rc::clone(&shared_stdin),
                    },
                )?,
                interface: troe_abi::interface::STANDARD_INPUT,
                major: stream::MAJOR,
                minor: stream::MINOR,
            });
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationOutputService {
                        output: Rc::clone(&shared_stdout),
                    },
                )?,
                interface: troe_abi::interface::STANDARD_OUTPUT,
                major: stream::MAJOR,
                minor: stream::MINOR,
            });
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationOutputService {
                        output: Rc::clone(&shared_stderr),
                    },
                )?,
                interface: troe_abi::interface::STANDARD_ERROR,
                major: stream::MAJOR,
                minor: stream::MINOR,
            });
            if datagram_required {
                let state = application_datagram_state.as_ref().ok_or(())?.clone();
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationDatagramService::new(state, self.runtime.clone()),
                    )?,
                    interface: troe_abi::interface::DATAGRAM,
                    major: datagram::MAJOR,
                    minor: datagram::MINOR,
                });
            }
            if filesystem_required {
                let namespace = filesystem_namespace.as_ref().ok_or(())?.clone();
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationFilesystemService::new(namespace, cwd)?,
                    )?,
                    interface: troe_abi::interface::FILESYSTEM_READ,
                    major: filesystem::MAJOR,
                    minor: filesystem::MINOR,
                });
            }
            if filesystem_mutation_required {
                let namespace = filesystem_namespace.as_ref().ok_or(())?.clone();
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationFilesystemMutationService::new(namespace, cwd)?,
                    )?,
                    interface: troe_abi::interface::FILESYSTEM_MUTATE,
                    major: filesystem_mutation::MAJOR,
                    minor: filesystem_mutation::MINOR,
                });
            }
            if timer_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationTimerService {
                            runtime: self.runtime.clone(),
                            processes: self.processes.clone(),
                            task_id: timer_task_id.as_ref().ok_or(())?.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::TIMER,
                    major: timer::MAJOR,
                    minor: timer::MINOR,
                });
            }
            if diagnostics_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationDiagnosticsProxyService,
                    )?,
                    interface: troe_abi::interface::DIAGNOSTICS,
                    major: diagnostics::MAJOR,
                    minor: diagnostics::MINOR,
                });
            }
            if process_observation_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationProcessObservationService {
                            processes: self.processes.clone(),
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::PROCESS_OBSERVE,
                    major: process_observation::MAJOR,
                    minor: process_observation::MINOR,
                });
            }
            if process_launch_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationProcessLaunchService {
                            owner: process_owner_binding.as_ref().ok_or(())?.clone(),
                            children: process_children.as_ref().ok_or(())?.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::PROCESS_LAUNCH,
                    major: process_launch::MAJOR,
                    minor: process_launch::MINOR,
                });
            }
            if pipe_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationPipeService {
                            owner: process_owner_binding.as_ref().ok_or(())?.clone(),
                            pipes: process_pipes.as_ref().ok_or(())?.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::PIPE,
                    major: pipe::MAJOR,
                    minor: pipe::MINOR,
                });
            }
            if network_observation_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationNetworkObservationService {
                            network: application_network.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::NETWORK_OBSERVE,
                    major: network_observation::MAJOR,
                    minor: network_observation::MINOR,
                });
            }
            if network_configuration_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationNetworkConfigurationService {
                            network: application_network.clone(),
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::NETWORK_CONFIGURE,
                    major: network_configuration::MAJOR,
                    minor: network_configuration::MINOR,
                });
            }
            if icmp_echo_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationIcmpEchoService {
                            network: application_network.clone(),
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::ICMP_ECHO,
                    major: icmp_echo::MAJOR,
                    minor: icmp_echo::MINOR,
                });
            }
            if tcp_connect_required {
                let network = application_transport_network.as_ref().ok_or(())?.clone();
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationTcpConnectService::new(network, self.runtime.clone()),
                    )?,
                    interface: troe_abi::interface::TCP_CONNECT,
                    major: tcp_connect::MAJOR,
                    minor: tcp_connect::MINOR,
                });
            }
            if volume_control_required {
                let namespace = filesystem_namespace.as_ref().ok_or(())?.clone();
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationVolumeControlService {
                            namespace,
                            mounts: self.accounting.runtime_mounts.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::VOLUME_CONTROL,
                    major: volume_control::MAJOR,
                    minor: volume_control::MINOR,
                });
            }
            if shell_script_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationShellScriptService {
                            script: submitted_shell_script.as_ref().ok_or(())?.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::SHELL_SCRIPT,
                    major: shell_script::MAJOR,
                    minor: shell_script::MINOR,
                });
            }
            if wall_clock_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationWallClockService {
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::WALL_CLOCK,
                    major: wall_clock::MAJOR,
                    minor: wall_clock::MINOR,
                });
            }
            if clock_control_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationClockControlService {
                            runtime: self.runtime.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::CLOCK_CONTROL,
                    major: clock_control::MAJOR,
                    minor: clock_control::MINOR,
                });
            }
            if private_memory_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationPrivateMemoryService,
                    )?,
                    interface: troe_abi::interface::PRIVATE_MEMORY,
                    major: private_memory::MAJOR,
                    minor: private_memory::MINOR,
                });
            }
            if random_required {
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationRandomService {
                            random: self.accounting.random.clone(),
                        },
                    )?,
                    interface: troe_abi::interface::RANDOM,
                    major: random::MAJOR,
                    minor: random::MINOR,
                });
            }
            Ok(services)
        })();
        let Ok(services) = services else {
            drop(dispatcher);
            let status =
                shared_stderr
                    .try_borrow_mut()
                    .map_or(CommandStatus::Failure, |mut output| {
                        command_application_error(&mut **output, command, "service setup failed")
                    });
            drop(shared_stdin);
            drop(shared_stdout);
            drop(shared_stderr);
            return Some(status);
        };

        let process = prepare_streamed_resident_application(
            self.scheduler,
            self.accounting,
            dispatcher,
            &services,
            &package,
            |offset, destination| {
                namespace
                    .borrow_mut()
                    .read_file_at(cwd, path, offset, destination)
                    .map_err(|_| ())
            },
            0,
            command,
            ProcessOrigin::Foreground,
            self.runtime.borrow().now().as_millis(),
            self.processes.clone(),
        );
        let outcome = match process {
            Ok(mut process) => {
                if let Some(task_id) = &timer_task_id {
                    task_id.set(Some(process.task_id));
                }
                let process_owner = if let Some(binding) = process_owner_binding.as_ref() {
                    match OwnerId::new(process.task_id.get()) {
                        Ok(owner) => {
                            binding.set(Some(owner));
                            Some(owner)
                        }
                        Err(_) => fatal(b"fatal: invalid process owner\n"),
                    }
                } else {
                    None
                };
                let deferred = (timer_required
                    || datagram_required
                    || diagnostics_required
                    || process_launch_required
                    || pipe_required
                    || session_terminal.is_some())
                .then(|| CommandDeferredServices {
                    runtime: self.runtime.clone(),
                    datagram: application_datagram_state,
                    diagnostics: diagnostics_snapshot,
                    process_owner,
                    children: process_children.clone(),
                    pipes: process_pipes.clone(),
                    pipe_streams: Vec::new(),
                    terminal: session_terminal.clone(),
                });
                if process.install_deferred_services(deferred).is_err() {
                    let _cleaned = process.teardown(
                        self.scheduler,
                        self.accounting,
                        CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                        true,
                    );
                    Err(())
                } else {
                    if process_launch_required {
                        process.process_control = Some(ResidentProcessControl {
                            owner: process_owner
                                .unwrap_or_else(|| fatal(b"fatal: process owner missing\n")),
                            depth: 1,
                            grants: BackgroundRequirements {
                                datagram: datagram_required,
                                filesystem: filesystem_required,
                                filesystem_mutation: filesystem_mutation_required,
                                timer: timer_required,
                                diagnostics: diagnostics_required,
                                process_observation: process_observation_required,
                                process_launch: process_launch_required,
                                pipe: pipe_required,
                                network_observation: network_observation_required,
                                network_configuration: network_configuration_required,
                                icmp_echo: icmp_echo_required,
                                tcp_connect: tcp_connect_required,
                                volume_control: volume_control_required,
                                wall_clock: wall_clock_required,
                                clock_control: clock_control_required,
                                private_memory: private_memory_required,
                                random: random_required,
                            },
                            children: process_children
                                .clone()
                                .unwrap_or_else(|| fatal(b"fatal: child table missing\n")),
                            pipes: process_pipes
                                .clone()
                                .unwrap_or_else(|| fatal(b"fatal: pipe table missing\n")),
                            launch: NestedLaunchContext {
                                namespace: Rc::clone(namespace),
                                runtime: self.runtime.clone(),
                                processes: self.processes.clone(),
                                mounts: self.accounting.runtime_mounts.clone(),
                                stdio: NestedStdio {
                                    stdin: NestedInput::Borrowed(Rc::clone(&shared_stdin)),
                                    stdout: NestedOutput::Borrowed(Rc::clone(&shared_stdout)),
                                    stderr: NestedOutput::Borrowed(Rc::clone(&shared_stderr)),
                                },
                            },
                            processes: Vec::new(),
                        });
                    }
                    let loan = session_terminal.as_ref().map(|terminal| {
                        terminal
                            .try_borrow_mut()
                            .map_err(|_| ())
                            .and_then(|mut terminal| terminal.lend(process.task_id))
                    });
                    if matches!(loan, Some(Err(()))) {
                        let _cleaned = process.teardown(
                            self.scheduler,
                            self.accounting,
                            CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                            true,
                        );
                        Err(())
                    } else {
                        let outcome = self.run_foreground_process(process);
                        if let Some(terminal) = session_terminal.as_ref() {
                            match terminal.try_borrow_mut() {
                                Ok(mut terminal) => terminal.release(),
                                Err(_) => fatal(b"fatal: session terminal loan leaked\n"),
                            }
                        }
                        outcome
                    }
                }
            }
            Err(()) => Err(()),
        };
        let mut status = match outcome {
            Ok(CommandApplicationOutcome::Exited(status)) => command_status(status),
            Ok(CommandApplicationOutcome::Faulted(fault)) => {
                let message = match fault {
                    TaskFault::Translation => "application faulted: translation",
                    TaskFault::Permission => "application faulted: permission",
                    TaskFault::IllegalInstruction => "application faulted: illegal instruction",
                    TaskFault::InvalidCall => "application faulted: invalid call",
                    TaskFault::ExecutionLeaseExpired => {
                        "application faulted: execution lease expired"
                    }
                    TaskFault::ServiceCallLimitExceeded => {
                        "application faulted: service call limit exceeded"
                    }
                };
                shared_stderr
                    .try_borrow_mut()
                    .map_or(CommandStatus::Failure, |mut output| {
                        command_application_error(&mut **output, command, message)
                    })
            }
            Err(()) => {
                shared_stderr
                    .try_borrow_mut()
                    .map_or(CommandStatus::Failure, |mut output| {
                        command_application_error(&mut **output, command, "application rejected")
                    })
            }
        };
        if status == CommandStatus::Success
            && let Some(script) = submitted_shell_script
        {
            match script.try_borrow_mut() {
                Ok(mut script) => {
                    self.pending_script_lines = Some(core::mem::take(&mut script.lines));
                }
                Err(_) => {
                    status = shared_stderr.try_borrow_mut().map_or(
                        CommandStatus::Failure,
                        |mut output| {
                            command_application_error(
                                &mut **output,
                                command,
                                "script staging conflict",
                            )
                        },
                    );
                }
            }
        }
        drop(shared_stdin);
        drop(shared_stdout);
        drop(shared_stderr);
        Some(status)
    }

    fn take_script_lines(&mut self) -> Option<Vec<String>> {
        self.pending_script_lines.take()
    }

    fn control_job(
        &mut self,
        request: JobControl,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> Option<CommandStatus> {
        let status = match request {
            JobControl::List => {
                for job in self
                    .residents
                    .jobs
                    .iter()
                    .filter(|job| job.owner == ResidentOwner::Session)
                {
                    let state = if job.outcome.is_some() {
                        "done"
                    } else if job.cancel_requested {
                        "stopping"
                    } else if job.process.as_ref().is_some_and(|process| {
                        matches!(process.execution, Some(ResidentExecution::Blocked))
                    }) {
                        "blocked"
                    } else {
                        "running"
                    };
                    let line = alloc::format!("[{}] {state} {}\n", job.id, job.command);
                    if write_all(stdout, line.as_bytes()).is_err() {
                        return Some(CommandStatus::Failure);
                    }
                }
                CommandStatus::Success
            }
            JobControl::Log(job_id) => self.copy_job_log(job_id, stdout, stderr),
            JobControl::Cancel(job_id) => {
                if self.residents.request_cancel(job_id).is_err() {
                    command_application_error(stderr, "kill", "unknown job")
                } else if self
                    .residents
                    .pump(
                        self.scheduler,
                        self.accounting,
                        self.shell_id,
                        self.shell_capabilities,
                    )
                    .is_err()
                {
                    fatal(b"fatal: resident cancellation failed\n");
                } else {
                    CommandStatus::Success
                }
            }
            JobControl::Wait(job_id) | JobControl::Foreground(job_id) => {
                let foreground = matches!(request, JobControl::Foreground(_));
                let terminal = self.residents.is_terminal(job_id);
                if terminal.is_err() {
                    return Some(command_application_error(
                        stderr,
                        if foreground { "fg" } else { "wait" },
                        "unknown job",
                    ));
                }
                while self.residents.is_terminal(job_id) == Ok(false) {
                    if self.runtime.borrow_mut().checkpoint().is_err() {
                        let _requested = self.residents.request_cancel(job_id);
                    }
                    if self
                        .residents
                        .pump(
                            self.scheduler,
                            self.accounting,
                            self.shell_id,
                            self.shell_capabilities,
                        )
                        .is_err()
                    {
                        fatal(b"fatal: resident wait failed\n");
                    }
                    let _event =
                        troe_machine::wait_for_runtime_event_timeout(RESIDENT_POLL_MILLISECONDS);
                }
                if foreground {
                    let _status = self.copy_job_log(job_id, stdout, stderr);
                }
                match self.residents.remove_terminal(job_id) {
                    Ok(CommandApplicationOutcome::Exited(exit_status)) => {
                        command_status(exit_status)
                    }
                    Ok(CommandApplicationOutcome::Faulted(_)) => CommandStatus::Failure,
                    Err(()) => command_application_error(
                        stderr,
                        if foreground { "fg" } else { "wait" },
                        "job did not become terminal",
                    ),
                }
            }
        };
        Some(status)
    }

    #[allow(clippy::too_many_lines)]
    fn control_service(
        &mut self,
        request: ServiceControl,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> Option<CommandStatus> {
        let Some(runtime) = self.service_runtime.as_mut() else {
            return Some(command_application_error(
                stderr,
                "svc",
                "service supervisor unavailable",
            ));
        };
        let status = match request {
            ServiceControl::List => {
                for service in runtime.config.services() {
                    let Ok(snapshot) = runtime.supervisor.snapshot(service.id()) else {
                        return Some(command_application_error(
                            stderr,
                            "svc",
                            "service state unavailable",
                        ));
                    };
                    let line = alloc::format!(
                        "{} {}\n",
                        service.name(),
                        service_state_label(snapshot.state)
                    );
                    if write_all(stdout, line.as_bytes()).is_err() {
                        return Some(CommandStatus::Failure);
                    }
                }
                CommandStatus::Success
            }
            ServiceControl::Status(name) => {
                let Some(service_id) = service_id_by_name(&runtime.config, &name) else {
                    return Some(command_application_error(stderr, "svc", "unknown service"));
                };
                let Ok(snapshot) = runtime.supervisor.snapshot(service_id) else {
                    return Some(command_application_error(
                        stderr,
                        "svc",
                        "service state unavailable",
                    ));
                };
                let line = alloc::format!(
                    "{name} {} restarts={} log-bytes={} dropped={}\n",
                    service_state_label(snapshot.state),
                    snapshot.restarts,
                    snapshot.log_bytes,
                    snapshot.dropped_log_bytes
                );
                if write_all(stdout, line.as_bytes()).is_err() {
                    CommandStatus::Failure
                } else {
                    CommandStatus::Success
                }
            }
            ServiceControl::Start(name) => {
                let Some(service_id) = service_id_by_name(&runtime.config, &name) else {
                    return Some(command_application_error(stderr, "svc", "unknown service"));
                };
                if runtime.supervisor.request_start(service_id).is_err() {
                    command_application_error(stderr, "svc", "request rejected")
                } else {
                    let line = alloc::format!("{name}: requested\n");
                    if write_all(stdout, line.as_bytes()).is_err() {
                        CommandStatus::Failure
                    } else {
                        CommandStatus::Success
                    }
                }
            }
            ServiceControl::Stop(name) => {
                let Some(service_id) = service_id_by_name(&runtime.config, &name) else {
                    return Some(command_application_error(stderr, "svc", "unknown service"));
                };
                if runtime.supervisor.request_stop(service_id).is_err() {
                    command_application_error(stderr, "svc", "request rejected")
                } else {
                    let line = alloc::format!("{name}: requested\n");
                    if write_all(stdout, line.as_bytes()).is_err() {
                        CommandStatus::Failure
                    } else {
                        CommandStatus::Success
                    }
                }
            }
            ServiceControl::Restart(name) => {
                let Some(service_id) = service_id_by_name(&runtime.config, &name) else {
                    return Some(command_application_error(stderr, "svc", "unknown service"));
                };
                if runtime.supervisor.request_restart(service_id).is_err() {
                    command_application_error(stderr, "svc", "request rejected")
                } else {
                    let line = alloc::format!("{name}: requested\n");
                    if write_all(stdout, line.as_bytes()).is_err() {
                        CommandStatus::Failure
                    } else {
                        CommandStatus::Success
                    }
                }
            }
            ServiceControl::Log(name) => {
                let Some(service_id) = service_id_by_name(&runtime.config, &name) else {
                    return Some(command_application_error(stderr, "svc", "unknown service"));
                };
                copy_service_output(self.residents, service_id, &name, runtime, stdout, stderr)
            }
        };
        Some(status)
    }
}

impl KexCommandRunner<'_> {
    fn copy_job_log(
        &self,
        job_id: u32,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(RESIDENT_PROCESS_LOG_BYTES).is_err() {
            return command_application_error(stderr, "log", "buffer allocation failed");
        }
        bytes.resize(RESIDENT_PROCESS_LOG_BYTES, 0);
        let Ok((count, dropped)) = self.residents.copy_log(job_id, &mut bytes) else {
            return command_application_error(stderr, "log", "unknown job");
        };
        if dropped != 0 {
            let notice = alloc::format!("[log: {dropped} earlier bytes discarded]\n");
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
}

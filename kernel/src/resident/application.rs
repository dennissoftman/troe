//! The resident application step machine.
//!
//! One `step` advances a loaded application by a bounded slice: it pumps
//! nested children, drains the dispatcher, services the calls the application
//! made, and reports whether the application exited, faulted, or yielded.

use crate::artifacts::native_application_target;
use crate::deferred::{
    CommandDeferredServices, CommandDeferredState, DeferredCallKind, DeferredCallPreparation,
    DeferredPipeTarget, SuspendedApplicationCall, command_handle_interface, deferred_reply,
    owned_reply_payload, prepare_deferred_call,
};
use crate::invocation::{CommandApplicationOutcome, CommandStartupService};
use crate::limits::{
    MAX_LAUNCH_DEPTH, RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS, RESIDENT_PROCESS_FIRST_SLOT,
    RESIDENT_SERVICE_CALLS_PER_STEP,
};
use crate::machine::OwnedAccounting;
use crate::memory::growth::{
    application_growth_pages, application_resource_totals, commit_application_heap_growth,
};
use crate::memory::launch::reclaim_command_application;
use crate::memory::private::{
    ApplicationGrowth, PrivateMemoryError, PrivateMemoryReply, handle_private_memory_call,
};
use crate::nested::{
    NestedChild, NestedLaunchContext, NestedStdio, nested_input_for_spawn, nested_output_for_spawn,
    register_nested_input, register_nested_output,
};
use crate::network::services::{
    ApplicationDatagramService, ApplicationDatagramState, ApplicationIcmpEchoService,
    ApplicationNetworkConfigurationService, ApplicationNetworkObservationService,
    ApplicationTcpConnectService,
};
use crate::requirements::decode_application_requirements;
use crate::resident::launch::{
    prepare_streamed_resident_application, random_application_placement,
};
use crate::resident::{ResidentApplication, ResidentExecution, ResidentProcessControl};
use crate::service::clock::{ApplicationTimerService, ApplicationWallClockService};
use crate::service::diagnostics::{
    ApplicationDiagnosticsSnapshotService, application_diagnostics_snapshot, machine_snapshot,
    run_diagnostics_server,
};
use crate::service::filesystem::{
    ApplicationFilesystemMutationService, ApplicationFilesystemService,
    ApplicationVolumeControlService,
};
use crate::service::process::{
    ApplicationPipeService, ApplicationProcessLaunchService, ApplicationProcessObservationService,
    child_process_status,
};
use crate::service::{ApplicationPrivateMemoryService, ApplicationRandomService};
use crate::supervision::register_command_service;
use crate::support::task_fault;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use troe_abi::{
    command, datagram, diagnostics, filesystem, filesystem_mutation, heap_growth, icmp_echo,
    network_configuration, network_observation, pipe, private_memory, process_launch,
    process_observation, random, tcp_connect, timer, volume_control, wall_clock,
};
use troe_application::{ABI_MINOR, PAGE_BYTES, parse_streamed_kex_package};
use troe_dispatch::{CommandInvocationService, Dispatcher, ReplyStatus};
use troe_fs_api::NodeKind;
use troe_process::{
    ChildLifecycle, ChildTable, MAX_CHILDREN_PER_OWNER, MAX_PIPES_PER_OWNER, OwnerId, PipeTable,
    ProcessError as ChildProcessError,
};
use troe_shell::{ExternalCommandReference, external_command_reference};
use troe_task::{
    Capabilities, IsolationResource, PendingCallState, PendingOperationId, ProcessOrigin,
    Scheduler, TaskFault, WaitKey, WaitObservation, WaitRegistration, WaitResource, WakeReason,
};

impl<'service> ResidentApplication<'service> {
    fn spawn_child(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        payload: &[u8],
    ) -> Result<process_launch::SpawnedChild, ReplyStatus> {
        let request =
            process_launch::decode_spawn(payload).map_err(|_| ReplyStatus::InvalidRequest)?;
        let mut control = self.process_control.take().ok_or(ReplyStatus::NotFound)?;
        let result = Self::spawn_child_with_control(&mut control, scheduler, accounting, request);
        self.process_control = Some(control);
        result
    }

    #[allow(clippy::ignored_unit_patterns, clippy::too_many_lines)]
    fn spawn_child_with_control(
        control: &mut ResidentProcessControl<'service>,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        request: process_launch::SpawnRequest<'_>,
    ) -> Result<process_launch::SpawnedChild, ReplyStatus> {
        let depth = control
            .depth
            .checked_add(1)
            .filter(|depth| *depth <= MAX_LAUNCH_DEPTH)
            .ok_or(ReplyStatus::Exhausted)?;
        control
            .processes
            .try_reserve(1)
            .map_err(|_| ReplyStatus::Exhausted)?;
        let invocation = request.invocation();
        let command_name = invocation.argument(0).ok_or(ReplyStatus::InvalidRequest)?;
        let reference =
            external_command_reference(command_name).ok_or(ReplyStatus::InvalidRequest)?;
        let mut words = Vec::new();
        words
            .try_reserve_exact(invocation.len())
            .map_err(|_| ReplyStatus::Exhausted)?;
        for word in invocation.arguments() {
            words.push(String::from(word));
        }
        let mut environment = Vec::new();
        environment
            .try_reserve_exact(request.environment().len())
            .map_err(|_| ReplyStatus::Exhausted)?;
        for value in request.environment() {
            environment.push(String::from(value));
        }
        let mut environment_refs = Vec::new();
        environment_refs
            .try_reserve_exact(environment.len())
            .map_err(|_| ReplyStatus::Exhausted)?;
        for value in &environment {
            environment_refs.push(value.as_str());
        }

        let catalog_path = match reference {
            ExternalCommandReference::CatalogName(name) => Some(alloc::format!("/bin/{name}.kex")),
            ExternalCommandReference::Path(_) => None,
        };
        let path = catalog_path.as_deref().unwrap_or(command_name);
        let cwd = invocation.cwd();
        let metadata = control
            .launch
            .namespace
            .borrow_mut()
            .metadata(cwd, path)
            .map_err(|error| match error {
                troe_fs_api::FsError::NotFound => ReplyStatus::NotFound,
                _ => ReplyStatus::Failure,
            })?;
        if metadata.kind != NodeKind::File {
            return Err(ReplyStatus::NotFound);
        }
        let placement =
            random_application_placement(&accounting.random).map_err(|_| ReplyStatus::Failure)?;
        let package = parse_streamed_kex_package(
            metadata.byte_count,
            |offset, destination| {
                control
                    .launch
                    .namespace
                    .borrow_mut()
                    .read_file_at(cwd, path, offset, destination)
                    .map_err(|_| ())
            },
            native_application_target(),
            ABI_MINOR,
            placement,
        )
        .map_err(|_| ReplyStatus::InvalidRequest)?;
        let (required, shell_script_required) =
            decode_application_requirements(package.requirements())
                .map_err(|_| ReplyStatus::Denied)?;
        if !control.grants.attenuates(required, shell_script_required) {
            return Err(ReplyStatus::Denied);
        }

        let stdin = nested_input_for_spawn(
            request.stdin(),
            &control.launch.stdio.stdin,
            control.owner,
            &control.pipes,
        )?;
        let stdout = nested_output_for_spawn(
            request.stdout(),
            &control.launch.stdio.stdout,
            control.owner,
            &control.pipes,
        )?;
        let stderr = nested_output_for_spawn(
            request.stderr(),
            &control.launch.stdio.stderr,
            control.owner,
            &control.pipes,
        )?;
        let child_stdio = NestedStdio {
            stdin,
            stdout,
            stderr,
        };

        let application_network = control.launch.runtime.borrow().network.clone();
        let application_transport_network = if required.datagram || required.tcp_connect {
            Some(
                application_network
                    .clone()
                    .ok_or(ReplyStatus::NotConfigured)?,
            )
        } else {
            None
        };
        let datagram_state = if required.datagram {
            Some(Rc::new(RefCell::new(ApplicationDatagramState::new(
                application_transport_network
                    .as_ref()
                    .ok_or(ReplyStatus::NotConfigured)?
                    .clone(),
            ))))
        } else {
            None
        };
        let diagnostics_snapshot = if required.diagnostics {
            Some(
                application_diagnostics_snapshot(
                    machine_snapshot(accounting),
                    troe_machine::input_interrupt_stats(),
                    control.launch.namespace.borrow().memory_stats(),
                )
                .map_err(|_| ReplyStatus::Failure)?,
            )
        } else {
            None
        };

        let service_count = 4
            + usize::from(required.datagram)
            + usize::from(required.filesystem)
            + usize::from(required.filesystem_mutation)
            + usize::from(required.timer)
            + usize::from(required.diagnostics)
            + usize::from(required.process_observation)
            + usize::from(required.process_launch)
            + usize::from(required.pipe)
            + usize::from(required.network_observation)
            + usize::from(required.network_configuration)
            + usize::from(required.icmp_echo)
            + usize::from(required.tcp_connect)
            + usize::from(required.volume_control)
            + usize::from(required.wall_clock)
            + usize::from(required.private_memory)
            + usize::from(required.random);
        let handle_capacity = service_count.checked_mul(2).ok_or(ReplyStatus::Exhausted)?;
        let mut dispatcher =
            Dispatcher::new(service_count, handle_capacity).map_err(|_| ReplyStatus::Exhausted)?;
        let timer_task_id = required.timer.then(|| Rc::new(Cell::new(None)));
        let child_owner_binding = Rc::new(Cell::new(None));
        let child_children = Rc::new(RefCell::new(
            ChildTable::new(MAX_CHILDREN_PER_OWNER).map_err(child_process_status)?,
        ));
        let child_pipes = Rc::new(RefCell::new(
            PipeTable::new(MAX_PIPES_PER_OWNER).map_err(child_process_status)?,
        ));
        let mut pipe_streams = Vec::new();
        pipe_streams
            .try_reserve_exact(3)
            .map_err(|_| ReplyStatus::Exhausted)?;
        let mut services = Vec::new();
        services
            .try_reserve_exact(service_count)
            .map_err(|_| ReplyStatus::Exhausted)?;
        services.push(CommandStartupService {
            port: register_command_service(
                &mut dispatcher,
                CommandInvocationService::new_with_environment(
                    invocation.cwd(),
                    &words,
                    &environment_refs,
                )
                .map_err(|_| ReplyStatus::InvalidRequest)?,
            )
            .map_err(|_| ReplyStatus::Exhausted)?,
            interface: troe_abi::interface::COMMAND,
            major: command::MAJOR,
            minor: command::MINOR,
        });
        services.push(
            register_nested_input(&mut dispatcher, &child_stdio.stdin, &mut pipe_streams)
                .map_err(|_| ReplyStatus::Exhausted)?,
        );
        services.push(
            register_nested_output(
                &mut dispatcher,
                &child_stdio.stdout,
                troe_abi::interface::STANDARD_OUTPUT,
                &mut pipe_streams,
            )
            .map_err(|_| ReplyStatus::Exhausted)?,
        );
        services.push(
            register_nested_output(
                &mut dispatcher,
                &child_stdio.stderr,
                troe_abi::interface::STANDARD_ERROR,
                &mut pipe_streams,
            )
            .map_err(|_| ReplyStatus::Exhausted)?,
        );

        if required.datagram {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationDatagramService::new(
                        datagram_state.as_ref().ok_or(ReplyStatus::Failure)?.clone(),
                        control.launch.runtime.clone(),
                    ),
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::DATAGRAM,
                major: datagram::MAJOR,
                minor: datagram::MINOR,
            });
        }
        if required.filesystem {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationFilesystemService::new(
                        control.launch.namespace.clone(),
                        invocation.cwd(),
                    )
                    .map_err(|_| ReplyStatus::InvalidRequest)?,
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::FILESYSTEM_READ,
                major: filesystem::MAJOR,
                minor: filesystem::MINOR,
            });
        }
        if required.filesystem_mutation {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationFilesystemMutationService::new(
                        control.launch.namespace.clone(),
                        invocation.cwd(),
                    )
                    .map_err(|_| ReplyStatus::InvalidRequest)?,
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::FILESYSTEM_MUTATE,
                major: filesystem_mutation::MAJOR,
                minor: filesystem_mutation::MINOR,
            });
        }
        if required.timer {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationTimerService {
                        runtime: control.launch.runtime.clone(),
                        processes: control.launch.processes.clone(),
                        task_id: timer_task_id.as_ref().ok_or(ReplyStatus::Failure)?.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::TIMER,
                major: timer::MAJOR,
                minor: timer::MINOR,
            });
        }
        if required.diagnostics {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationDiagnosticsSnapshotService {
                        snapshot: diagnostics_snapshot
                            .as_ref()
                            .ok_or(ReplyStatus::Failure)?
                            .clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::DIAGNOSTICS,
                major: diagnostics::MAJOR,
                minor: diagnostics::MINOR,
            });
        }
        if required.process_observation {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationProcessObservationService {
                        processes: control.launch.processes.clone(),
                        runtime: control.launch.runtime.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::PROCESS_OBSERVE,
                major: process_observation::MAJOR,
                minor: process_observation::MINOR,
            });
        }
        if required.process_launch {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationProcessLaunchService {
                        owner: child_owner_binding.clone(),
                        children: child_children.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::PROCESS_LAUNCH,
                major: process_launch::MAJOR,
                minor: process_launch::MINOR,
            });
        }
        if required.pipe {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationPipeService {
                        owner: child_owner_binding.clone(),
                        pipes: child_pipes.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::PIPE,
                major: pipe::MAJOR,
                minor: pipe::MINOR,
            });
        }
        if required.network_observation {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationNetworkObservationService {
                        network: application_network.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::NETWORK_OBSERVE,
                major: network_observation::MAJOR,
                minor: network_observation::MINOR,
            });
        }
        if required.network_configuration {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationNetworkConfigurationService {
                        network: application_network.clone(),
                        runtime: control.launch.runtime.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::NETWORK_CONFIGURE,
                major: network_configuration::MAJOR,
                minor: network_configuration::MINOR,
            });
        }
        if required.icmp_echo {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationIcmpEchoService {
                        network: application_network.clone(),
                        runtime: control.launch.runtime.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::ICMP_ECHO,
                major: icmp_echo::MAJOR,
                minor: icmp_echo::MINOR,
            });
        }
        if required.tcp_connect {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationTcpConnectService::new(
                        application_transport_network
                            .as_ref()
                            .ok_or(ReplyStatus::NotConfigured)?
                            .clone(),
                        control.launch.runtime.clone(),
                    ),
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::TCP_CONNECT,
                major: tcp_connect::MAJOR,
                minor: tcp_connect::MINOR,
            });
        }
        if required.volume_control {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationVolumeControlService {
                        namespace: control.launch.namespace.clone(),
                        mounts: control.launch.mounts.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::VOLUME_CONTROL,
                major: volume_control::MAJOR,
                minor: volume_control::MINOR,
            });
        }
        if required.wall_clock {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationWallClockService {
                        runtime: control.launch.runtime.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::WALL_CLOCK,
                major: wall_clock::MAJOR,
                minor: wall_clock::MINOR,
            });
        }
        if required.private_memory {
            services.push(CommandStartupService {
                port: register_command_service(&mut dispatcher, ApplicationPrivateMemoryService)
                    .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::PRIVATE_MEMORY,
                major: private_memory::MAJOR,
                minor: private_memory::MINOR,
            });
        }
        if required.random {
            services.push(CommandStartupService {
                port: register_command_service(
                    &mut dispatcher,
                    ApplicationRandomService {
                        random: accounting.random.clone(),
                    },
                )
                .map_err(|_| ReplyStatus::Exhausted)?,
                interface: troe_abi::interface::RANDOM,
                major: random::MAJOR,
                minor: random::MINOR,
            });
        }
        if services.len() != service_count {
            return Err(ReplyStatus::Failure);
        }

        let resource_slot = scheduler
            .first_available_isolation_slot(
                RESIDENT_PROCESS_FIRST_SLOT,
                u32::try_from(troe_task::MAX_TASKS).map_err(|_| ReplyStatus::Failure)?,
            )
            .ok_or(ReplyStatus::Exhausted)?;
        let mut process = prepare_streamed_resident_application(
            scheduler,
            accounting,
            dispatcher,
            &services,
            &package,
            |offset, destination| {
                control
                    .launch
                    .namespace
                    .borrow_mut()
                    .read_file_at(cwd, path, offset, destination)
                    .map_err(|_| ())
            },
            resource_slot,
            command_name,
            ProcessOrigin::Child,
            control.launch.runtime.borrow().now().as_millis(),
            control.launch.processes.clone(),
        )
        .map_err(|_| ReplyStatus::Exhausted)?;
        if let Some(task_id) = &timer_task_id {
            task_id.set(Some(process.task_id));
        }
        let owner = match OwnerId::new(process.task_id.get()) {
            Ok(owner) => owner,
            Err(error) => {
                let _cleaned = process.teardown(
                    scheduler,
                    accounting,
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                );
                return Err(child_process_status(error));
            }
        };
        child_owner_binding.set(Some(owner));
        let needs_deferred = required.timer
            || required.datagram
            || required.diagnostics
            || required.process_launch
            || required.pipe
            || !pipe_streams.is_empty();
        if needs_deferred
            && process
                .install_deferred_services(Some(CommandDeferredServices {
                    runtime: control.launch.runtime.clone(),
                    datagram: datagram_state,
                    diagnostics: diagnostics_snapshot,
                    process_owner: Some(owner),
                    children: required.process_launch.then(|| child_children.clone()),
                    pipes: required.pipe.then(|| child_pipes.clone()),
                    pipe_streams,
                    terminal: None,
                }))
                .is_err()
        {
            let _cleaned = process.teardown(
                scheduler,
                accounting,
                CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                true,
            );
            return Err(ReplyStatus::Exhausted);
        }
        if required.process_launch {
            process.process_control = Some(ResidentProcessControl {
                owner,
                depth,
                grants: required,
                children: child_children,
                pipes: child_pipes,
                launch: NestedLaunchContext {
                    namespace: control.launch.namespace.clone(),
                    runtime: control.launch.runtime.clone(),
                    processes: control.launch.processes.clone(),
                    mounts: control.launch.mounts.clone(),
                    stdio: child_stdio,
                },
                processes: Vec::new(),
            });
        }
        let process_id = process.process_id.get();
        let token = match control
            .children
            .try_borrow_mut()
            .map_err(|_| ReplyStatus::Conflict)?
            .admit(control.owner, process_id)
        {
            Ok(token) => token,
            Err(error) => {
                let _cleaned = process.teardown(
                    scheduler,
                    accounting,
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                );
                return Err(child_process_status(error));
            }
        };
        control.processes.push(NestedChild {
            token,
            process: Some(Box::new(process)),
            outcome: None,
        });
        Ok(process_launch::SpawnedChild { token, process_id })
    }

    fn pump_children(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        let Some(control) = self.process_control.as_mut() else {
            return Ok(());
        };
        for child in &mut control.processes {
            if child.process.is_none() {
                continue;
            }
            let cancelled = control
                .children
                .try_borrow()
                .map_err(|_| ())?
                .cancellation_requested(control.owner, child.token)
                .map_err(|_| ())?;
            let step = if cancelled {
                None
            } else {
                child
                    .process
                    .as_mut()
                    .map(|process| process.step(scheduler, accounting))
            };
            let terminal = match step {
                Some(Ok(Some(outcome))) => Some((outcome, false)),
                Some(Ok(None)) => None,
                Some(Err(())) => Some((
                    CommandApplicationOutcome::Faulted(TaskFault::InvalidCall),
                    true,
                )),
                None => Some((
                    CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                    true,
                )),
            };
            let Some((outcome, force_cancel)) = terminal else {
                continue;
            };
            let process = child.process.take().ok_or(())?;
            let outcome =
                process.teardown(scheduler, accounting, outcome, cancelled || force_cancel)?;
            let lifecycle = if cancelled || force_cancel {
                ChildLifecycle::Cancelled
            } else {
                match outcome {
                    CommandApplicationOutcome::Exited(status) => ChildLifecycle::Exited(status),
                    CommandApplicationOutcome::Faulted(_) => ChildLifecycle::Faulted,
                }
            };
            control
                .children
                .try_borrow_mut()
                .map_err(|_| ())?
                .finish(control.owner, child.token, lifecycle)
                .map_err(|_| ())?;
            child.outcome = Some(outcome);
        }
        control.processes.retain(|child| {
            child.process.is_some()
                || control
                    .children
                    .try_borrow()
                    .is_ok_and(|children| children.status(control.owner, child.token).is_ok())
        });
        Ok(())
    }

    fn terminate_children(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        let Some(control) = self.process_control.as_mut() else {
            return Ok(());
        };
        for child in &mut control.processes {
            let Some(process) = child.process.take() else {
                continue;
            };
            process.teardown(
                scheduler,
                accounting,
                CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED),
                true,
            )?;
            if control
                .children
                .try_borrow()
                .map_err(|_| ())?
                .status(control.owner, child.token)
                .is_ok_and(|status| status.state == process_launch::ChildState::Running)
            {
                control
                    .children
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .finish(control.owner, child.token, ChildLifecycle::Cancelled)
                    .map_err(|_| ())?;
            }
        }
        Ok(())
    }

    pub(crate) fn request_stop(&self) -> Result<(), ()> {
        self.processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .stopping(self.process_id)
            .map_err(|_| ())
    }

    fn execute_accounted<T, E>(&self, operation: impl FnOnce() -> Result<T, E>) -> Result<T, ()> {
        let started = troe_machine::process_accounting_ticks();
        let result = operation();
        let finished = troe_machine::process_accounting_ticks();
        let elapsed = finished.checked_sub(started).ok_or(())?;
        self.processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .charge_cpu(self.process_id, elapsed)
            .map_err(|_| ())?;
        result.map_err(|_| ())
    }

    pub(crate) fn install_deferred_services(
        &mut self,
        services: Option<CommandDeferredServices>,
    ) -> Result<(), ()> {
        self.deferred_state = services
            .as_ref()
            .map(|_| CommandDeferredState::new())
            .transpose()?;
        self.deferred_services = services;
        Ok(())
    }

    pub(crate) fn step(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<Option<CommandApplicationOutcome>, ()> {
        self.pump_children(scheduler, accounting)?;
        self.run_execution_slice(scheduler, accounting)
    }

    // Kept out of `step` so its frame leaves the recursive pump path: the
    // launch depth bound is sized against the small frame that remains.
    #[allow(clippy::too_many_lines)]
    #[inline(never)]
    fn run_execution_slice(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<Option<CommandApplicationOutcome>, ()> {
        let execution = self.execution.take().ok_or(())?;
        let mut outcome = match execution {
            ResidentExecution::Unstarted(launch) => {
                scheduler
                    .dispatch(self.task_id, Capabilities::SERVICE)
                    .map_err(|_| ())?;
                self.processes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .dispatch(self.process_id)
                    .map_err(|_| ())?;
                self.execute_accounted(|| {
                    troe_machine::run_application(
                        launch.address_space,
                        launch.entry,
                        launch.stack_top,
                        launch.startup_address,
                        PAGE_BYTES,
                        RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                    )
                })?
            }
            ResidentExecution::Pending(outcome) => {
                scheduler
                    .dispatch(self.task_id, Capabilities::SERVICE)
                    .map_err(|_| ())?;
                self.processes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .dispatch(self.process_id)
                    .map_err(|_| ())?;
                match *outcome {
                    troe_machine::ApplicationOutcome::Preempted(application) => self
                        .execute_accounted(|| {
                            troe_machine::resume_application(
                                application,
                                troe_machine::ApplicationResume::Timeslice,
                                RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                            )
                        })?,
                    troe_machine::ApplicationOutcome::Yielded(application) => self
                        .execute_accounted(|| {
                            troe_machine::resume_application(
                                application,
                                troe_machine::ApplicationResume::Yield,
                                RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                            )
                        })?,
                    pending @ (troe_machine::ApplicationOutcome::HandleCall { .. }
                    | troe_machine::ApplicationOutcome::HeapGrow { .. }) => pending,
                    troe_machine::ApplicationOutcome::Exited { .. }
                    | troe_machine::ApplicationOutcome::Faulted(_) => return Err(()),
                }
            }
            ResidentExecution::Blocked => {
                let Some((application, status, payload)) =
                    self.poll_deferred_call(scheduler, accounting)?
                else {
                    self.execution = Some(ResidentExecution::Blocked);
                    return Ok(None);
                };
                scheduler
                    .dispatch(self.task_id, Capabilities::SERVICE)
                    .map_err(|_| ())?;
                self.processes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .dispatch(self.process_id)
                    .map_err(|_| ())?;
                self.execute_accounted(|| {
                    troe_machine::resume_application(
                        application,
                        troe_machine::ApplicationResume::HandleReply {
                            status: status.abi_value(),
                            reply: &payload,
                        },
                        RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                    )
                })?
            }
        };

        let mut service_calls = 0_usize;
        let mut request = [0_u8; troe_abi::MAX_MESSAGE_BYTES];
        let mut direct_reply = [0_u8; troe_abi::MAX_MESSAGE_BYTES];
        loop {
            match outcome {
                pending @ troe_machine::ApplicationOutcome::Preempted(_) => {
                    scheduler.preempt_current(self.task_id).map_err(|_| ())?;
                    self.processes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .preempted(self.process_id)
                        .map_err(|_| ())?;
                    self.execution = Some(ResidentExecution::Pending(Box::new(pending)));
                    return Ok(None);
                }
                pending @ troe_machine::ApplicationOutcome::Yielded(_) => {
                    scheduler.yield_current(self.task_id).map_err(|_| ())?;
                    self.processes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .yielded(self.process_id)
                        .map_err(|_| ())?;
                    self.execution = Some(ResidentExecution::Pending(Box::new(pending)));
                    return Ok(None);
                }
                pending @ troe_machine::ApplicationOutcome::HandleCall { .. }
                    if service_calls >= RESIDENT_SERVICE_CALLS_PER_STEP =>
                {
                    scheduler.preempt_current(self.task_id).map_err(|_| ())?;
                    self.processes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .preempted(self.process_id)
                        .map_err(|_| ())?;
                    self.execution = Some(ResidentExecution::Pending(Box::new(pending)));
                    return Ok(None);
                }
                troe_machine::ApplicationOutcome::HandleCall {
                    mut application,
                    call,
                } => {
                    service_calls = service_calls.checked_add(1).ok_or(())?;
                    if call.request_bytes() < 2 {
                        scheduler
                            .fault_current(self.task_id, TaskFault::InvalidCall)
                            .map_err(|_| ())?;
                        return Ok(Some(CommandApplicationOutcome::Faulted(
                            TaskFault::InvalidCall,
                        )));
                    }
                    let request = &mut request[..call.request_bytes()];
                    application.copy_request(request).map_err(|_| ())?;
                    let opcode = u16::from_le_bytes([request[0], request[1]]);
                    let interface = command_handle_interface(&self.handles, call.handle());
                    if interface == Some(troe_abi::interface::PRIVATE_MEMORY) {
                        let reply = match handle_private_memory_call(
                            accounting,
                            &mut self.allocation,
                            &mut application,
                            self.heap_start,
                            opcode,
                            &request[2..],
                        ) {
                            Ok(reply) => reply,
                            Err(PrivateMemoryError::Reply(status)) => PrivateMemoryReply {
                                status,
                                payload: Vec::new(),
                                resources_changed: false,
                            },
                            Err(PrivateMemoryError::Terminal) => {
                                scheduler
                                    .fault_current(self.task_id, TaskFault::InvalidCall)
                                    .map_err(|_| ())?;
                                return Ok(Some(CommandApplicationOutcome::Faulted(
                                    TaskFault::InvalidCall,
                                )));
                            }
                        };
                        if reply.payload.len() > call.reply_capacity() {
                            return Err(());
                        }
                        if reply.resources_changed {
                            let (table_pages, private_pages) =
                                application_resource_totals(&self.allocation, self.private_pages)?;
                            if application.stats().table_pages > table_pages {
                                return Err(());
                            }
                            let grown_isolation = IsolationResource::new(
                                self.isolation.slot(),
                                table_pages,
                                private_pages,
                                self.isolation.handles(),
                            )
                            .map_err(|_| ())?;
                            scheduler
                                .resize_current_isolation(self.task_id, grown_isolation)
                                .map_err(|_| ())?;
                            self.isolation = grown_isolation;
                            self.processes
                                .try_borrow_mut()
                                .map_err(|_| ())?
                                .update_resources(
                                    self.process_id,
                                    table_pages,
                                    private_pages,
                                    self.handle_count,
                                )
                                .map_err(|_| ())?;
                        }
                        outcome = self.execute_accounted(|| {
                            troe_machine::resume_application(
                                application,
                                troe_machine::ApplicationResume::HandleReply {
                                    status: reply.status.abi_value(),
                                    reply: &reply.payload,
                                },
                                RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                            )
                        })?;
                        continue;
                    }
                    if interface == Some(troe_abi::interface::PROCESS_LAUNCH)
                        && opcode == process_launch::SPAWN
                    {
                        let (status, payload) =
                            match self.spawn_child(scheduler, accounting, &request[2..]) {
                                Ok(child) => (
                                    ReplyStatus::Success,
                                    owned_reply_payload(&process_launch::encode_spawned(child))?,
                                ),
                                Err(status) => (status, Vec::new()),
                            };
                        if payload.len() > call.reply_capacity() {
                            return Err(());
                        }
                        outcome = self.execute_accounted(|| {
                            troe_machine::resume_application(
                                application,
                                troe_machine::ApplicationResume::HandleReply {
                                    status: status.abi_value(),
                                    reply: &payload,
                                },
                                RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                            )
                        })?;
                        continue;
                    }
                    let preparation = if let (Some(interface), Some(services)) =
                        (interface, self.deferred_services.as_ref())
                    {
                        let state = self.deferred_state.as_mut().ok_or(())?;
                        prepare_deferred_call(
                            self.task_id,
                            interface,
                            call.handle(),
                            opcode,
                            &request[2..],
                            call.reply_capacity(),
                            services,
                            &mut state.pending,
                            &mut state.next_request_id,
                        )?
                    } else {
                        DeferredCallPreparation::NotDeferred
                    };
                    match preparation {
                        DeferredCallPreparation::NotDeferred => {
                            if command_handle_interface(&self.handles, call.handle())
                                == Some(troe_abi::interface::SERVER_ENDPOINT)
                            {
                                let reply = self
                                    .dispatcher
                                    .call_owned_abi_into(
                                        self.owner,
                                        call.handle(),
                                        opcode,
                                        &request[2..],
                                        &mut direct_reply[..call.reply_capacity()],
                                    )
                                    .map_err(|_| ())?;
                                outcome = self.execute_accounted(|| {
                                    troe_machine::resume_application(
                                        application,
                                        troe_machine::ApplicationResume::HandleReply {
                                            status: reply.status().abi_value(),
                                            reply: &direct_reply[..reply.payload_bytes()],
                                        },
                                        RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                                    )
                                })?;
                            } else {
                                let reply = self
                                    .dispatcher
                                    .call_owned_abi(
                                        self.owner,
                                        call.handle(),
                                        opcode,
                                        &request[2..],
                                    )
                                    .map_err(|_| ())?;
                                if reply.payload().len() > call.reply_capacity() {
                                    return Err(());
                                }
                                outcome = self.execute_accounted(|| {
                                    troe_machine::resume_application(
                                        application,
                                        troe_machine::ApplicationResume::HandleReply {
                                            status: reply.status().abi_value(),
                                            reply: reply.payload(),
                                        },
                                        RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                                    )
                                })?;
                            }
                        }
                        DeferredCallPreparation::Immediate { status, payload } => {
                            if payload.len() > call.reply_capacity() {
                                return Err(());
                            }
                            outcome = self.execute_accounted(|| {
                                troe_machine::resume_application(
                                    application,
                                    troe_machine::ApplicationResume::HandleReply {
                                        status: status.abi_value(),
                                        reply: &payload,
                                    },
                                    RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                                )
                            })?;
                        }
                        DeferredCallPreparation::Blocked {
                            operation,
                            spec,
                            kind,
                        } => {
                            let services = self.deferred_services.as_ref().ok_or(())?;
                            let state = self.deferred_state.as_mut().ok_or(())?;
                            let registration = state
                                .waits
                                .register(
                                    spec,
                                    WaitObservation::Pending,
                                    services.runtime.borrow().now(),
                                )
                                .map_err(|_| ())?;
                            match registration {
                                WaitRegistration::Ready(reason) => {
                                    state
                                        .pending
                                        .mark_ready(operation, reason)
                                        .map_err(|_| ())?;
                                    let (status, payload) =
                                        deferred_reply(kind, reason, None, &request[2..])?;
                                    state.pending.finish(operation).map_err(|_| ())?;
                                    outcome = self.execute_accounted(|| {
                                        troe_machine::resume_application(
                                            application,
                                            troe_machine::ApplicationResume::HandleReply {
                                                status: status.abi_value(),
                                                reply: &payload,
                                            },
                                            RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                                        )
                                    })?;
                                }
                                WaitRegistration::Blocked(wait) => {
                                    state.pending.bind_wait(operation, wait).map_err(|_| ())?;
                                    state.suspended.insert(SuspendedApplicationCall {
                                        operation,
                                        application,
                                        call,
                                        kind,
                                    })?;
                                    scheduler
                                        .block_current(self.task_id, wait)
                                        .map_err(|_| ())?;
                                    self.processes
                                        .try_borrow_mut()
                                        .map_err(|_| ())?
                                        .blocked(self.process_id)
                                        .map_err(|_| ())?;
                                    self.execution = Some(ResidentExecution::Blocked);
                                    return Ok(None);
                                }
                            }
                        }
                    }
                }
                troe_machine::ApplicationOutcome::HeapGrow {
                    mut application,
                    request,
                } => {
                    match commit_application_heap_growth(
                        accounting,
                        &mut self.allocation,
                        &mut application,
                        self.heap_start,
                        self.maximum_heap_pages,
                        request.minimum_pages(),
                    )? {
                        ApplicationGrowth::Committed {
                            stats,
                            mapped_bytes,
                        } => {
                            let grown_private_pages = self
                                .private_pages
                                .checked_add(application_growth_pages(&self.allocation)?)
                                .ok_or(())?;
                            let grown_table_pages = self
                                .allocation
                                .tables
                                .page_count()
                                .checked_add(
                                    u64::try_from(self.allocation.growth_table_frames.len())
                                        .map_err(|_| ())?,
                                )
                                .ok_or(())?;
                            if stats.table_pages > grown_table_pages {
                                return Err(());
                            }
                            let grown_isolation = IsolationResource::new(
                                self.isolation.slot(),
                                grown_table_pages,
                                grown_private_pages,
                                self.isolation.handles(),
                            )
                            .map_err(|_| ())?;
                            scheduler
                                .resize_current_isolation(self.task_id, grown_isolation)
                                .map_err(|_| ())?;
                            self.isolation = grown_isolation;
                            self.processes
                                .try_borrow_mut()
                                .map_err(|_| ())?
                                .update_resources(
                                    self.process_id,
                                    grown_table_pages,
                                    grown_private_pages,
                                    self.handle_count,
                                )
                                .map_err(|_| ())?;
                            outcome = self.execute_accounted(|| {
                                troe_machine::resume_application(
                                    application,
                                    troe_machine::ApplicationResume::HeapGrowth {
                                        status: heap_growth::SUCCESS,
                                        mapped_bytes,
                                    },
                                    RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                                )
                            })?;
                        }
                        ApplicationGrowth::Exhausted => {
                            outcome = self.execute_accounted(|| {
                                troe_machine::resume_application(
                                    application,
                                    troe_machine::ApplicationResume::HeapGrowth {
                                        status: heap_growth::EXHAUSTED,
                                        mapped_bytes: 0,
                                    },
                                    RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS,
                                )
                            })?;
                        }
                    }
                }
                troe_machine::ApplicationOutcome::Exited { status } => {
                    scheduler
                        .exit_current(self.task_id, status)
                        .map_err(|_| ())?;
                    return Ok(Some(CommandApplicationOutcome::Exited(status)));
                }
                troe_machine::ApplicationOutcome::Faulted(fault) => {
                    let fault = task_fault(fault);
                    scheduler
                        .fault_current(self.task_id, fault)
                        .map_err(|_| ())?;
                    return Ok(Some(CommandApplicationOutcome::Faulted(fault)));
                }
            }
        }
    }

    fn complete_diagnostics_call(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        operation: PendingOperationId,
        wait: WaitKey,
        resource: WaitResource,
    ) -> Result<Option<(troe_machine::ApplicationSession, ReplyStatus, Vec<u8>)>, ()> {
        let services = self.deferred_services.as_ref().ok_or(())?;
        let state = self.deferred_state.as_mut().ok_or(())?;
        let snapshot = services.diagnostics.as_ref().ok_or(())?.clone();
        let reply_capacity = state
            .pending
            .call(operation)
            .map_err(|_| ())?
            .reply_capacity();
        let (reason, server_reply) =
            run_diagnostics_server(scheduler, accounting, operation, snapshot, reply_capacity)?;
        let completion = match reason {
            WakeReason::ResourceReady | WakeReason::Closed => state
                .waits
                .wake_resource(resource, reason)
                .map_err(|_| ())?
                .iter()
                .next()
                .ok_or(())?,
            WakeReason::Revoked => state
                .waits
                .cancel_operation(operation, reason)
                .map_err(|_| ())?
                .ok_or(())?,
            WakeReason::Deadline | WakeReason::Cancelled => return Err(()),
        };
        if completion.key() != wait {
            return Err(());
        }
        state.pending.resolve(completion).map_err(|_| ())?;
        scheduler
            .wake_blocked(completion.owner(), completion.key())
            .map_err(|_| ())?;
        self.processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .woke(self.process_id)
            .map_err(|_| ())?;
        let suspended = state.suspended.take(operation)?;
        let (status, payload) = match reason {
            WakeReason::ResourceReady => server_reply.ok_or(())?,
            WakeReason::Closed => (ReplyStatus::Conflict, Vec::new()),
            WakeReason::Revoked => (ReplyStatus::Cancelled, Vec::new()),
            WakeReason::Deadline | WakeReason::Cancelled => return Err(()),
        };
        if payload.len() > suspended.call.reply_capacity() {
            return Err(());
        }
        state.pending.finish(operation).map_err(|_| ())?;
        Ok(Some((suspended.application, status, payload)))
    }

    pub(crate) fn request_deferred_cancel(
        &mut self,
        scheduler: &mut Scheduler,
    ) -> Result<bool, ()> {
        if !matches!(self.execution, Some(ResidentExecution::Blocked)) {
            return Ok(false);
        }
        let state = self.deferred_state.as_mut().ok_or(())?;
        let operation = state.suspended.slots.first().ok_or(())?.operation;
        let PendingCallState::Waiting(wait) =
            state.pending.call(operation).map_err(|_| ())?.state()
        else {
            return Err(());
        };
        let completion = state
            .waits
            .cancel_operation(operation, WakeReason::Cancelled)
            .map_err(|_| ())?
            .ok_or(())?;
        if completion.key() != wait {
            return Err(());
        }
        state.pending.resolve(completion).map_err(|_| ())?;
        scheduler
            .wake_blocked(completion.owner(), completion.key())
            .map_err(|_| ())?;
        self.processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .woke(self.process_id)
            .map_err(|_| ())?;
        Ok(true)
    }

    fn take_ready_deferred_call(
        &mut self,
        operation: PendingOperationId,
        reason: WakeReason,
    ) -> Result<Option<(troe_machine::ApplicationSession, ReplyStatus, Vec<u8>)>, ()> {
        let state = self.deferred_state.as_mut().ok_or(())?;
        let suspended = state.suspended.take(operation)?;
        let request = state.pending.request(operation).map_err(|_| ())?;
        let (status, payload) = deferred_reply(suspended.kind, reason, None, request)?;
        if payload.len() > suspended.call.reply_capacity() {
            return Err(());
        }
        state.pending.finish(operation).map_err(|_| ())?;
        Ok(Some((suspended.application, status, payload)))
    }

    #[allow(clippy::too_many_lines)]
    fn poll_deferred_call(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<Option<(troe_machine::ApplicationSession, ReplyStatus, Vec<u8>)>, ()> {
        let state = self.deferred_state.as_ref().ok_or(())?;
        let operation = state.suspended.slots.first().ok_or(())?.operation;
        let wait = match state.pending.call(operation).map_err(|_| ())?.state() {
            PendingCallState::Ready(reason) => {
                return self.take_ready_deferred_call(operation, reason);
            }
            PendingCallState::Waiting(wait) => wait,
            PendingCallState::New => return Err(()),
        };
        if let DeferredCallKind::Diagnostics { resource } = &state.suspended.get(operation)?.kind {
            return self
                .complete_diagnostics_call(scheduler, accounting, operation, wait, *resource);
        }
        let services = self.deferred_services.as_ref().ok_or(())?;
        let state = self.deferred_state.as_mut().ok_or(())?;
        services.runtime.borrow_mut().service_ambient();
        let now = services.runtime.borrow().now();
        let mut received = None;
        let suspended = state.suspended.get(operation)?;
        let completion = match &suspended.kind {
            DeferredCallKind::Timer { deadline } if now >= *deadline => {
                state.waits.expire(now).map_err(|_| ())?.iter().next()
            }
            DeferredCallKind::Datagram {
                state: datagram,
                local_port,
                deadline,
                resource,
            } => {
                if let Some(value) = datagram
                    .borrow_mut()
                    .receive_now(*local_port)
                    .map_err(|_| ())?
                {
                    received = Some(value);
                    state
                        .waits
                        .wake_resource(*resource, WakeReason::ResourceReady)
                        .map_err(|_| ())?
                        .iter()
                        .next()
                } else if now >= *deadline {
                    state.waits.expire(now).map_err(|_| ())?.iter().next()
                } else {
                    None
                }
            }
            DeferredCallKind::Timer { .. } => None,
            DeferredCallKind::Diagnostics { .. } => return Err(()),
            DeferredCallKind::Child {
                children,
                owner,
                token,
                resource,
            } => {
                let terminal = children
                    .try_borrow()
                    .map_err(|_| ())?
                    .status(*owner, *token)
                    .map(|status| status.state != process_launch::ChildState::Running);
                match terminal {
                    Ok(true) => state
                        .waits
                        .wake_resource(*resource, WakeReason::ResourceReady)
                        .map_err(|_| ())?
                        .iter()
                        .next(),
                    Ok(false) => None,
                    Err(ChildProcessError::InvalidToken) => state
                        .waits
                        .wake_resource(*resource, WakeReason::Closed)
                        .map_err(|_| ())?
                        .iter()
                        .next(),
                    Err(_) => return Err(()),
                }
            }
            DeferredCallKind::PipeRead {
                pipes,
                target,
                resource,
                ..
            } => {
                let ready = match target {
                    DeferredPipeTarget::Owner { owner, token } => pipes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .owner_read_ready(*owner, *token),
                    DeferredPipeTarget::Endpoint(endpoint) => pipes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .endpoint_read_ready(*endpoint),
                };
                match ready {
                    Ok(true) => state
                        .waits
                        .wake_resource(*resource, WakeReason::ResourceReady)
                        .map_err(|_| ())?
                        .iter()
                        .next(),
                    Ok(false) => None,
                    Err(ChildProcessError::Closed | ChildProcessError::InvalidToken) => state
                        .waits
                        .wake_resource(*resource, WakeReason::Closed)
                        .map_err(|_| ())?
                        .iter()
                        .next(),
                    Err(_) => return Err(()),
                }
            }
            DeferredCallKind::PipeWrite {
                pipes,
                target,
                byte_count,
                resource,
            } => {
                let ready = match target {
                    DeferredPipeTarget::Owner { owner, token } => pipes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .owner_write_ready(*owner, *token, *byte_count),
                    DeferredPipeTarget::Endpoint(endpoint) => pipes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .endpoint_write_ready(*endpoint, *byte_count),
                };
                match ready {
                    Ok(true) => state
                        .waits
                        .wake_resource(*resource, WakeReason::ResourceReady)
                        .map_err(|_| ())?
                        .iter()
                        .next(),
                    Ok(false) => None,
                    Err(ChildProcessError::Closed | ChildProcessError::InvalidToken) => state
                        .waits
                        .wake_resource(*resource, WakeReason::Closed)
                        .map_err(|_| ())?
                        .iter()
                        .next(),
                    Err(_) => return Err(()),
                }
            }
            DeferredCallKind::TerminalRead {
                terminal, resource, ..
            } => {
                let ready = {
                    let mut borrowed = terminal.try_borrow_mut().map_err(|_| ())?;
                    borrowed.pump();
                    borrowed.read_ready()
                };
                if ready {
                    state
                        .waits
                        .wake_resource(*resource, WakeReason::ResourceReady)
                        .map_err(|_| ())?
                        .iter()
                        .next()
                } else {
                    None
                }
            }
        };
        let Some(completion) = completion else {
            return Ok(None);
        };
        if completion.key() != wait {
            return Err(());
        }
        state.pending.resolve(completion).map_err(|_| ())?;
        scheduler
            .wake_blocked(completion.owner(), completion.key())
            .map_err(|_| ())?;
        self.processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .woke(self.process_id)
            .map_err(|_| ())?;
        let suspended = state.suspended.take(operation)?;
        let request = state.pending.request(operation).map_err(|_| ())?;
        let (status, payload) =
            deferred_reply(suspended.kind, completion.reason(), received, request)?;
        if payload.len() > suspended.call.reply_capacity() {
            return Err(());
        }
        state.pending.finish(operation).map_err(|_| ())?;
        Ok(Some((suspended.application, status, payload)))
    }

    pub(crate) fn teardown(
        mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        outcome: CommandApplicationOutcome,
        cancelled: bool,
    ) -> Result<CommandApplicationOutcome, ()> {
        self.terminate_children(scheduler, accounting)?;
        if cancelled {
            self.processes
                .try_borrow_mut()
                .map_err(|_| ())?
                .stopping(self.process_id)
                .map_err(|_| ())?;
            let snapshot = scheduler.task(self.task_id).map_err(|_| ())?;
            match snapshot.state() {
                troe_task::TaskState::Ready => scheduler
                    .cancel_ready(self.task_id, troe_abi::exit::CANCELLED)
                    .map_err(|_| ())?,
                troe_task::TaskState::Blocked(_) => {
                    if let Some(state) = self.deferred_state.as_mut() {
                        state.revoke_owner(self.task_id)?;
                    }
                    scheduler
                        .cancel_blocked(self.task_id, troe_abi::exit::CANCELLED)
                        .map_err(|_| ())?;
                }
                troe_task::TaskState::Running => scheduler
                    .exit_current(self.task_id, troe_abi::exit::CANCELLED)
                    .map_err(|_| ())?,
                troe_task::TaskState::Exited | troe_task::TaskState::Faulted => {}
            }
        }
        if self.dispatcher.close_owner(self.owner).map_err(|_| ())? != self.handle_count {
            return Err(());
        }
        if !cancelled
            && self
                .deferred_state
                .as_ref()
                .is_some_and(|state| !state.is_empty() || !state.respected_bounds())
        {
            return Err(());
        }
        self.execution.take();
        let reaped = scheduler.reap(self.task_id).map_err(|_| ())?;
        let expected_fault = match outcome {
            CommandApplicationOutcome::Exited(_) => None,
            CommandApplicationOutcome::Faulted(fault) => Some(fault),
        };
        let valid = reaped.isolation == Some(self.isolation)
            && reaped.stack.mapped_pages() == self.stack_pages
            && (cancelled || reaped.fault == expected_fault);
        self.processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .remove(self.process_id)
            .map_err(|_| ())?;
        reclaim_command_application(accounting, self.allocation);
        if !valid {
            return Err(());
        }
        Ok(if cancelled {
            CommandApplicationOutcome::Exited(troe_abi::exit::CANCELLED)
        } else {
            outcome
        })
    }
}

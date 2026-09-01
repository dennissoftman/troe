//! Running one command application to completion.
//!
//! `run_command_application` is the synchronous foreground path: it loads the
//! package, attaches the services the requirements asked for, steps the
//! application until it exits or faults, and reclaims everything the launch
//! reserved.

use crate::deferred::{
    CommandDeferredServices, CommandDeferredState, DeferredCallPreparation,
    command_handle_interface, prepare_deferred_call, resume_deferred_application_call,
};
use crate::limits::APPLICATION_TIMESLICE_MILLISECONDS;
use crate::machine::OwnedAccounting;
use crate::memory::growth::{
    application_growth_pages, application_resource_totals, commit_application_heap_growth,
};
use crate::memory::launch::{
    allocate_application, clear_provisional_loader_ownership, prepare_application_memory,
    reclaim_command_application, rollback_command_application_task,
};
use crate::memory::private::{
    ApplicationGrowth, PrivateMemoryError, PrivateMemoryReply, handle_private_memory_call,
};
use crate::resident::launch::parse_native_application;
use crate::support::{fatal, task_fault, write_all};
use alloc::vec::Vec;
use troe_abi::heap_growth;
use troe_application::{InitialHandle, LoaderResource, LoaderTransaction, PAGE_BYTES, StartupInfo};
use troe_core::{CommandStatus, Output};
use troe_dispatch::{Dispatcher, HandleOwner, Rights};
use troe_memory::BASE_PAGE_SIZE;
use troe_task::{Capabilities, IsolationResource, Scheduler, StackResource, TaskFault};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandApplicationOutcome {
    Exited(u32),
    Faulted(TaskFault),
}

#[derive(Clone, Copy)]
pub(crate) struct CommandStartupService {
    pub(crate) port: troe_dispatch::PortId,
    pub(crate) interface: u32,
    pub(crate) major: u16,
    pub(crate) minor: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct CommandApplicationHandle {
    pub(crate) value: u64,
    pub(crate) interface: u32,
}

#[allow(
    clippy::drop_non_drop,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub(crate) fn run_command_application(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    dispatcher: &mut Dispatcher<'_>,
    services: &[CommandStartupService],
    deferred_services: Option<&CommandDeferredServices>,
    source: &[u8],
    resource_slot: u32,
    service_call_limit: Option<u16>,
) -> Result<CommandApplicationOutcome, ()> {
    if services.is_empty() || services.len() > troe_dispatch::MAX_HANDLES {
        return Err(());
    }
    let mut transaction = LoaderTransaction::new();
    transaction
        .acquire(LoaderResource::Staging)
        .map_err(|_| ())?;
    let Ok(plan) = parse_native_application(accounting, source) else {
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    let heap_start = plan.layout().heap_address();
    let maximum_heap_pages = plan
        .layout()
        .lower_guard_address()
        .checked_sub(heap_start)
        .ok_or(())?
        / BASE_PAGE_SIZE;
    let private_pages = plan.charges().private_pages();
    let stack_pages = plan.stack_pages();

    let Ok((mut allocation, mapping_plan)) = allocate_application(accounting, &plan) else {
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    if transaction.acquire(LoaderResource::Frames).is_err() {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }
    if prepare_application_memory(&allocation, &plan).is_err() {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }
    let Ok(address_space) =
        troe_machine::build_user_address_space(&mapping_plan, allocation.tables)
    else {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    if transaction.acquire(LoaderResource::Tables).is_err() {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }
    let Ok((planned_user_regions, planned_user_pages)) =
        troe_machine::planned_user_regions(&mapping_plan)
    else {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    let table_pages = address_space.stats().table_pages;
    if table_pages == 0
        || table_pages != allocation.tables.page_count()
        || address_space.user_region_count() != planned_user_regions
        || planned_user_pages != private_pages
    {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }
    let handle_count = u16::try_from(services.len()).map_err(|_| ())?;
    let retained_table_pages = allocation.tables.page_count();
    let Ok(mut isolation) = IsolationResource::new(
        resource_slot,
        retained_table_pages,
        private_pages,
        handle_count,
    ) else {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    let Ok(stack_resource) = StackResource::new(resource_slot, stack_pages) else {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    let Ok(task_id) = scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
    else {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    if transaction.acquire(LoaderResource::Task).is_err() {
        rollback_command_application_task(
            scheduler, task_id, dispatcher, None, accounting, allocation,
        );
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }

    let entry = plan.entry_address();
    let layout = plan.layout();
    let mut live_owner = None;
    let setup = (|| -> Result<(HandleOwner, Vec<CommandApplicationHandle>), ()> {
        let owner = HandleOwner::isolated(task_id.get()).map_err(|_| ())?;
        live_owner = Some(owner);
        let mut startup_handles = Vec::new();
        startup_handles
            .try_reserve_exact(services.len())
            .map_err(|_| ())?;
        let mut command_handles = Vec::new();
        command_handles
            .try_reserve_exact(services.len())
            .map_err(|_| ())?;
        for service in services {
            let handle = dispatcher
                .open_owned(service.port, Rights::CALL, owner)
                .map_err(|_| ())?;
            command_handles.push(CommandApplicationHandle {
                value: handle.abi_value(),
                interface: service.interface,
            });
            startup_handles.push(InitialHandle {
                value: handle.abi_value(),
                rights: Rights::CALL.bits(),
                interface: service.interface,
                major: service.major,
                minor: service.minor,
            });
        }
        transaction
            .acquire(LoaderResource::Handles)
            .map_err(|_| ())?;
        let mut startup = [0_u8; PAGE_BYTES];
        plan.encode_startup_page(
            StartupInfo {
                task_id: u64::from(task_id.get()),
                handles: &startup_handles,
            },
            &mut startup,
        )
        .map_err(|_| ())?;
        troe_machine::copy_to_physical(allocation.startup, 0, &startup).map_err(|_| ())?;
        Ok((owner, command_handles))
    })();
    let Ok((owner, command_handles)) = setup else {
        rollback_command_application_task(
            scheduler, task_id, dispatcher, live_owner, accounting, allocation,
        );
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    drop(plan);
    drop(mapping_plan);
    if transaction.commit().is_err() {
        rollback_command_application_task(
            scheduler, task_id, dispatcher, live_owner, accounting, allocation,
        );
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }

    let deferred_state = deferred_services
        .map(|_| CommandDeferredState::new())
        .transpose();
    let Ok(mut deferred_state) = deferred_state else {
        rollback_command_application_task(
            scheduler, task_id, dispatcher, live_owner, accounting, allocation,
        );
        return Err(());
    };

    let execution = (|| -> Result<CommandApplicationOutcome, ()> {
        scheduler
            .dispatch(task_id, Capabilities::SERVICE)
            .map_err(|_| ())?;
        let mut outcome = troe_machine::run_application(
            address_space,
            entry,
            layout.stack_top(),
            layout.startup_address(),
            PAGE_BYTES,
            APPLICATION_TIMESLICE_MILLISECONDS,
        )
        .map_err(|_| ())?;
        let mut service_calls = 0_u16;
        let mut request = [0_u8; troe_abi::MAX_MESSAGE_BYTES];
        let mut direct_reply = [0_u8; troe_abi::MAX_MESSAGE_BYTES];
        let terminal = loop {
            let service_call = matches!(
                &outcome,
                troe_machine::ApplicationOutcome::HandleCall { .. }
            );
            if service_call && let Some(service_call_limit) = service_call_limit {
                service_calls = service_calls.checked_add(1).ok_or(())?;
                if service_calls > service_call_limit {
                    scheduler
                        .fault_current(task_id, TaskFault::ServiceCallLimitExceeded)
                        .map_err(|_| ())?;
                    break CommandApplicationOutcome::Faulted(TaskFault::ServiceCallLimitExceeded);
                }
            }
            match outcome {
                troe_machine::ApplicationOutcome::Preempted(application) => {
                    scheduler.preempt_current(task_id).map_err(|_| ())?;
                    scheduler
                        .dispatch(task_id, Capabilities::SERVICE)
                        .map_err(|_| ())?;
                    outcome = troe_machine::resume_application(
                        application,
                        troe_machine::ApplicationResume::Timeslice,
                        APPLICATION_TIMESLICE_MILLISECONDS,
                    )
                    .map_err(|_| ())?;
                }
                troe_machine::ApplicationOutcome::Yielded(application) => {
                    scheduler.yield_current(task_id).map_err(|_| ())?;
                    scheduler
                        .dispatch(task_id, Capabilities::SERVICE)
                        .map_err(|_| ())?;
                    outcome = troe_machine::resume_application(
                        application,
                        troe_machine::ApplicationResume::Yield,
                        APPLICATION_TIMESLICE_MILLISECONDS,
                    )
                    .map_err(|_| ())?;
                }
                troe_machine::ApplicationOutcome::HandleCall {
                    mut application,
                    call,
                } => {
                    if call.request_bytes() < 2 {
                        scheduler
                            .fault_current(task_id, TaskFault::InvalidCall)
                            .map_err(|_| ())?;
                        break CommandApplicationOutcome::Faulted(TaskFault::InvalidCall);
                    }
                    let request = &mut request[..call.request_bytes()];
                    application.copy_request(request).map_err(|_| ())?;
                    let opcode = u16::from_le_bytes([request[0], request[1]]);
                    let interface = command_handle_interface(&command_handles, call.handle());
                    if interface == Some(troe_abi::interface::PRIVATE_MEMORY) {
                        let reply = match handle_private_memory_call(
                            accounting,
                            &mut allocation,
                            &mut application,
                            heap_start,
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
                                    .fault_current(task_id, TaskFault::InvalidCall)
                                    .map_err(|_| ())?;
                                break CommandApplicationOutcome::Faulted(TaskFault::InvalidCall);
                            }
                        };
                        if reply.payload.len() > call.reply_capacity() {
                            scheduler
                                .fault_current(task_id, TaskFault::InvalidCall)
                                .map_err(|_| ())?;
                            break CommandApplicationOutcome::Faulted(TaskFault::InvalidCall);
                        }
                        if reply.resources_changed {
                            let (table_pages, private_page_count) =
                                application_resource_totals(&allocation, private_pages)?;
                            if application.stats().table_pages > table_pages {
                                return Err(());
                            }
                            let grown_isolation = IsolationResource::new(
                                isolation.slot(),
                                table_pages,
                                private_page_count,
                                isolation.handles(),
                            )
                            .map_err(|_| ())?;
                            scheduler
                                .resize_current_isolation(task_id, grown_isolation)
                                .map_err(|_| ())?;
                            isolation = grown_isolation;
                        }
                        outcome = troe_machine::resume_application(
                            application,
                            troe_machine::ApplicationResume::HandleReply {
                                status: reply.status.abi_value(),
                                reply: &reply.payload,
                            },
                            APPLICATION_TIMESLICE_MILLISECONDS,
                        )
                        .map_err(|_| ())?;
                        continue;
                    }
                    let preparation = if let (Some(interface), Some(deferred_services)) =
                        (interface, deferred_services)
                    {
                        let state = deferred_state.as_mut().ok_or(())?;
                        prepare_deferred_call(
                            task_id,
                            interface,
                            call.handle(),
                            opcode,
                            &request[2..],
                            call.reply_capacity(),
                            deferred_services,
                            &mut state.pending,
                            &mut state.next_request_id,
                        )?
                    } else {
                        DeferredCallPreparation::NotDeferred
                    };
                    match preparation {
                        DeferredCallPreparation::NotDeferred => {
                            if command_handle_interface(&command_handles, call.handle())
                                == Some(troe_abi::interface::SERVER_ENDPOINT)
                            {
                                let Ok(reply) = dispatcher.call_owned_abi_into(
                                    owner,
                                    call.handle(),
                                    opcode,
                                    &request[2..],
                                    &mut direct_reply[..call.reply_capacity()],
                                ) else {
                                    scheduler
                                        .fault_current(task_id, TaskFault::InvalidCall)
                                        .map_err(|_| ())?;
                                    break CommandApplicationOutcome::Faulted(
                                        TaskFault::InvalidCall,
                                    );
                                };
                                outcome = troe_machine::resume_application(
                                    application,
                                    troe_machine::ApplicationResume::HandleReply {
                                        status: reply.status().abi_value(),
                                        reply: &direct_reply[..reply.payload_bytes()],
                                    },
                                    APPLICATION_TIMESLICE_MILLISECONDS,
                                )
                                .map_err(|_| ())?;
                                continue;
                            }
                            let Ok(reply) = dispatcher.call_owned_abi(
                                owner,
                                call.handle(),
                                opcode,
                                &request[2..],
                            ) else {
                                scheduler
                                    .fault_current(task_id, TaskFault::InvalidCall)
                                    .map_err(|_| ())?;
                                break CommandApplicationOutcome::Faulted(TaskFault::InvalidCall);
                            };
                            if reply.payload().len() > call.reply_capacity() {
                                scheduler
                                    .fault_current(task_id, TaskFault::InvalidCall)
                                    .map_err(|_| ())?;
                                break CommandApplicationOutcome::Faulted(TaskFault::InvalidCall);
                            }
                            outcome = troe_machine::resume_application(
                                application,
                                troe_machine::ApplicationResume::HandleReply {
                                    status: reply.status().abi_value(),
                                    reply: reply.payload(),
                                },
                                APPLICATION_TIMESLICE_MILLISECONDS,
                            )
                            .map_err(|_| ())?;
                        }
                        DeferredCallPreparation::Immediate { status, payload } => {
                            if payload.len() > call.reply_capacity() {
                                scheduler
                                    .fault_current(task_id, TaskFault::InvalidCall)
                                    .map_err(|_| ())?;
                                break CommandApplicationOutcome::Faulted(TaskFault::InvalidCall);
                            }
                            outcome = troe_machine::resume_application(
                                application,
                                troe_machine::ApplicationResume::HandleReply {
                                    status: status.abi_value(),
                                    reply: &payload,
                                },
                                APPLICATION_TIMESLICE_MILLISECONDS,
                            )
                            .map_err(|_| ())?;
                        }
                        DeferredCallPreparation::Blocked {
                            operation,
                            spec,
                            kind,
                        } => {
                            let deferred_services = deferred_services.ok_or(())?;
                            let state = deferred_state.as_mut().ok_or(())?;
                            outcome = resume_deferred_application_call(
                                scheduler,
                                accounting,
                                task_id,
                                operation,
                                spec,
                                kind,
                                application,
                                call,
                                &deferred_services.runtime,
                                deferred_services.diagnostics.as_ref(),
                                state,
                            )?;
                        }
                    }
                }
                troe_machine::ApplicationOutcome::HeapGrow {
                    mut application,
                    request,
                } => {
                    match commit_application_heap_growth(
                        accounting,
                        &mut allocation,
                        &mut application,
                        heap_start,
                        maximum_heap_pages,
                        request.minimum_pages(),
                    )? {
                        ApplicationGrowth::Committed {
                            stats,
                            mapped_bytes,
                        } => {
                            let grown_private_pages = private_pages
                                .checked_add(application_growth_pages(&allocation)?)
                                .ok_or(())?;
                            let grown_table_pages = allocation
                                .tables
                                .page_count()
                                .checked_add(
                                    u64::try_from(allocation.growth_table_frames.len())
                                        .map_err(|_| ())?,
                                )
                                .ok_or(())?;
                            if stats.table_pages > grown_table_pages {
                                return Err(());
                            }
                            let grown_isolation = IsolationResource::new(
                                isolation.slot(),
                                grown_table_pages,
                                grown_private_pages,
                                isolation.handles(),
                            )
                            .map_err(|_| ())?;
                            scheduler
                                .resize_current_isolation(task_id, grown_isolation)
                                .map_err(|_| ())?;
                            isolation = grown_isolation;
                            outcome = troe_machine::resume_application(
                                application,
                                troe_machine::ApplicationResume::HeapGrowth {
                                    status: heap_growth::SUCCESS,
                                    mapped_bytes,
                                },
                                APPLICATION_TIMESLICE_MILLISECONDS,
                            )
                            .map_err(|_| ())?;
                        }
                        ApplicationGrowth::Exhausted => {
                            outcome = troe_machine::resume_application(
                                application,
                                troe_machine::ApplicationResume::HeapGrowth {
                                    status: heap_growth::EXHAUSTED,
                                    mapped_bytes: 0,
                                },
                                APPLICATION_TIMESLICE_MILLISECONDS,
                            )
                            .map_err(|_| ())?;
                        }
                    }
                }
                troe_machine::ApplicationOutcome::Exited { status } => {
                    scheduler.exit_current(task_id, status).map_err(|_| ())?;
                    break CommandApplicationOutcome::Exited(status);
                }
                troe_machine::ApplicationOutcome::Faulted(fault) => {
                    let fault = task_fault(fault);
                    scheduler.fault_current(task_id, fault).map_err(|_| ())?;
                    break CommandApplicationOutcome::Faulted(fault);
                }
            }
        };
        if dispatcher.close_owner(owner).map_err(|_| ())? != handle_count {
            return Err(());
        }
        if deferred_state
            .as_ref()
            .is_some_and(|state| !state.is_empty() || !state.respected_bounds())
        {
            return Err(());
        }
        live_owner = None;
        Ok(terminal)
    })();
    let Ok(terminal) = execution else {
        if deferred_state
            .as_mut()
            .is_some_and(|state| state.revoke_owner(task_id).is_err())
        {
            fatal(b"fatal: deferred application cleanup failed\n");
        }
        rollback_command_application_task(
            scheduler, task_id, dispatcher, live_owner, accounting, allocation,
        );
        return Err(());
    };
    let Ok(reaped) = scheduler.reap(task_id) else {
        rollback_command_application_task(
            scheduler, task_id, dispatcher, live_owner, accounting, allocation,
        );
        return Err(());
    };
    let expected_fault = match terminal {
        CommandApplicationOutcome::Exited(_) => None,
        CommandApplicationOutcome::Faulted(fault) => Some(fault),
    };
    let valid_reap = reaped.isolation == Some(isolation)
        && reaped.stack.mapped_pages() == stack_pages
        && reaped.fault == expected_fault;
    reclaim_command_application(accounting, allocation);
    if !valid_reap {
        fatal(b"fatal: application reap invariant failed\n");
    }
    Ok(terminal)
}

pub(crate) fn command_application_error(
    stderr: &mut dyn Output,
    command: &str,
    message: &str,
) -> CommandStatus {
    command_application_status_error(stderr, command, message, CommandStatus::Failure)
}

pub(crate) fn command_application_status_error(
    stderr: &mut dyn Output,
    command: &str,
    message: &str,
    status: CommandStatus,
) -> CommandStatus {
    let _ignored = write_all(stderr, alloc::format!("{command}: {message}\n").as_bytes());
    status
}

pub(crate) const fn command_status(status: u32) -> CommandStatus {
    match status {
        troe_abi::exit::SUCCESS => CommandStatus::Success,
        troe_abi::exit::USAGE => CommandStatus::Usage,
        troe_abi::exit::NOT_FOUND => CommandStatus::NotFound,
        troe_abi::exit::DENIED => CommandStatus::Denied,
        troe_abi::exit::CANCELLED => CommandStatus::Cancelled,
        _ => CommandStatus::Failure,
    }
}

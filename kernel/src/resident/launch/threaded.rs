//! Explicit threaded loading; callers select this profile and supply its grants.

use super::{
    Box, Capabilities, CommandApplicationHandle, CommandStartupService, Dispatcher, HandleOwner,
    InitialHandle, IsolationResource, OwnedAccounting, ProcessName, ProcessOrigin,
    ProcessRegistration, ResidentApplication, ResidentExecution, Rights, Scheduler,
    SharedProcessTable, StackResource, StartupInfo, StreamedKexPackage, Vec,
};
use crate::memory::native::{NativeLoadError, NativeLoadLimits, NativeMemory};
use crate::resident::threading::{NativeResident, NativeThreads};
use alloc::rc::Rc;
use troe_abi::threading::{Kind, Token};
use troe_application::process_memory::{ProcessMemoryPlacement, ProcessMemoryPlan};
use troe_dispatch::SchedulerInterface;
use troe_task::thread::ThreadResources;

/// The caller must authenticate package requirements before supplying services
/// and built-in scheduler grants. Ordinary package selection remains separate.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn prepare_threaded_resident_application<'service>(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    mut dispatcher: Dispatcher<'service>,
    services: &[CommandStartupService],
    grants: &[(SchedulerInterface, Rights)],
    package: &StreamedKexPackage,
    placement: ProcessMemoryPlacement,
    limits: NativeLoadLimits,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    resource_slot: u32,
    process_name: &str,
    process_origin: ProcessOrigin,
    started_millis: u64,
    processes: SharedProcessTable,
) -> Result<ResidentApplication<'service>, ()> {
    let count = services.len().checked_add(grants.len()).ok_or(())?;
    if count == 0 || count > troe_dispatch::MAX_HANDLES {
        return Err(());
    }
    let plan = ProcessMemoryPlan::new_streamed(package.executable(), placement, limits.memory)
        .map_err(|_| ())?;
    let name = if process_name.as_bytes().contains(&b'/') {
        ProcessName::from_executable_reference(process_name)
    } else {
        ProcessName::new(process_name)
    }
    .map_err(|_| ())?;
    let handle_count = u16::try_from(count).map_err(|_| ())?;
    let stack_pages = package.executable().stack_pages();
    let private_pages = plan.charges().mapped_pages();
    let policy = NativeThreads::shared(accounting)?;
    // No user execution or publication occurs before final accounting replaces
    // this provisional record. The policy needs the monotonic process identity.
    let provisional =
        IsolationResource::new(resource_slot, 1, private_pages, handle_count).map_err(|_| ())?;
    let task_id = scheduler
        .spawn_isolated(
            Capabilities::SERVICE,
            StackResource::new(resource_slot, stack_pages).map_err(|_| ())?,
            provisional,
        )
        .map_err(|_| ())?;
    let mut registered = None;
    let mut principal = None;
    let mut paired = false;
    let mut resident = None;
    let mut backing_reclaimed = true;
    let setup = (|| {
        let owner = HandleOwner::isolated(task_id.get()).map_err(|_| ())?;
        principal = Some(owner);
        let process_id = processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .register(ProcessRegistration {
                task_id,
                name,
                origin: process_origin,
                started_millis,
                table_pages: 1,
                private_pages,
                handles: handle_count,
            })
            .map_err(|_| ())?;
        registered = Some(process_id);
        let initial = policy.try_borrow_mut().map_err(|_| ())?.register(
            process_id,
            limits
                .memory
                .mapped_pages
                .checked_sub(plan.charges().shared_pages())
                .ok_or(())?,
            ThreadResources {
                reservation: plan.initial_thread().reservation_base(),
                pages: plan.charges().initial_thread_pages(),
            },
        )?;
        paired = true;
        let token = Token::new(
            Kind::Thread,
            u32::try_from(initial.slot()).map_err(|_| ())?,
            initial.generation(),
        )
        .map_err(|_| ())?;
        let mut handles = Vec::new();
        let mut startup_handles = Vec::new();
        handles.try_reserve_exact(count).map_err(|_| ())?;
        startup_handles.try_reserve_exact(count).map_err(|_| ())?;
        for service in services {
            let handle = dispatcher
                .open_owned(service.port, Rights::CALL, owner)
                .map_err(|_| ())?;
            handles.push(CommandApplicationHandle {
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
        for &(interface, rights) in grants {
            let handle = dispatcher
                .open_scheduler_owned(interface, rights, owner)
                .map_err(|_| ())?;
            let (major, minor) = interface.version();
            handles.push(CommandApplicationHandle {
                value: handle.abi_value(),
                interface: interface.id(),
            });
            startup_handles.push(InitialHandle {
                value: handle.abi_value(),
                rights: rights.bits(),
                interface: interface.id(),
                major,
                minor,
            });
        }
        let mut memory = {
            NativeMemory::load(
                accounting,
                package,
                placement,
                limits,
                initial,
                token,
                StartupInfo {
                    task_id: u64::from(task_id.get()),
                    handles: &startup_handles,
                },
                &mut read_at,
            )
            .map_err(|error| {
                backing_reclaimed = error != NativeLoadError::ReclamationFailed;
            })?
        };
        backing_reclaimed = false;
        let admission = policy
            .try_borrow()
            .map_err(|_| ())
            .and_then(|table| memory.admit_initial(&table.threads));
        if admission.is_err() {
            memory.reclaim(accounting)?;
            backing_reclaimed = true;
            return Err(());
        }
        let native = match NativeResident::new(
            memory,
            Rc::clone(&policy),
            process_id,
            task_id,
            accounting,
        ) {
            Ok(native) => native,
            Err(memory) => {
                memory.reclaim(accounting)?;
                backing_reclaimed = true;
                return Err(());
            }
        };
        resident = Some(native);
        let (tables, pages) = resident.as_ref().ok_or(())?.resource_totals()?;
        let isolation =
            IsolationResource::new(resource_slot, tables, pages, handle_count).map_err(|_| ())?;
        scheduler
            .resize_ready_isolation(task_id, isolation)
            .map_err(|_| ())?;
        processes
            .try_borrow_mut()
            .map_err(|_| ())?
            .update_resources(process_id, tables, pages, handle_count)
            .map_err(|_| ())?;
        policy
            .try_borrow_mut()
            .map_err(|_| ())?
            .threads
            .start(process_id, initial)
            .map_err(|_| ())?;
        Ok((process_id, owner, handles, isolation))
    })();
    let Ok((process_id, owner, handles, isolation)) = setup else {
        if let Some(native) = resident.take() {
            native.reclaim(accounting)?;
        } else if paired {
            if !backing_reclaimed {
                policy
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .stop(registered.ok_or(())?)?;
                return Err(());
            }
            policy
                .try_borrow_mut()
                .map_err(|_| ())?
                .remove_reclaimed(registered.ok_or(())?)?;
        }
        if let Some(owner) = principal {
            dispatcher.close_owner(owner).map_err(|_| ())?;
        }
        scheduler
            .cancel_ready(task_id, troe_abi::exit::CANCELLED)
            .map_err(|_| ())?;
        scheduler.reap(task_id).map_err(|_| ())?;
        if let Some(process) = registered {
            processes
                .try_borrow_mut()
                .map_err(|_| ())?
                .remove(process)
                .map_err(|_| ())?;
        }
        return Err(());
    };
    Ok(ResidentApplication {
        diagnostics_generation: accounting
            .persistent_services
            .as_ref()
            .and_then(|services| services.generation()),
        task_id,
        process_id,
        processes,
        allocation: None,
        isolation,
        owner,
        handles,
        handle_count,
        stack_pages,
        heap_start: plan.heap_address(),
        maximum_heap_pages: plan.heap_capacity_pages(),
        private_pages,
        dispatcher,
        deferred_services: None,
        deferred_state: None,
        process_control: None,
        execution: Some(ResidentExecution::Native(Box::new(
            resident.take().ok_or(())?,
        ))),
    })
}

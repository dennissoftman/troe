//! Preparing a resident application for launch.
//!
//! Turns a parsed or streamed package into a placed load plan: chooses the
//! image base, reserves the private memory, and describes the segments the
//! memory layer will map.

use crate::artifacts::native_application_target;
use crate::handles::{SharedProcessTable, SharedRandom};
use crate::invocation::{CommandApplicationHandle, CommandStartupService};
use crate::machine::OwnedAccounting;
use crate::memory::ApplicationAllocation;
use crate::memory::launch::{
    allocate_application, clear_provisional_loader_ownership, prepare_streamed_application_memory,
    reclaim_command_application, rollback_command_application_task,
};
use crate::resident::{ResidentApplication, ResidentExecution, ResidentLaunch};
use alloc::boxed::Box;
use alloc::vec::Vec;
use troe_application::{
    ABI_MINOR, ApplicationLayout, InitialHandle, KEX_V1_IMAGE_ALIGNMENT, KEX_V1_MIN_IMAGE_BASE,
    KEX_V1_USER_END, LoadCharges, LoadPlacement, LoadPlan, LoadSegmentLayout, LoaderResource,
    LoaderTransaction, PAGE_BYTES, StartupInfo, StreamedKexPackage, StreamedLoadPlan, parse_kex_at,
};
use troe_dispatch::{Dispatcher, HandleOwner, Rights};
use troe_memory::BASE_PAGE_SIZE;
use troe_random::Generator as RandomGenerator;
use troe_task::{
    Capabilities, IsolationResource, ProcessName, ProcessOrigin, ProcessRegistration, Scheduler,
    StackResource,
};

#[allow(
    clippy::drop_non_drop,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub(crate) fn prepare_streamed_resident_application<'service>(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    dispatcher: Dispatcher<'service>,
    services: &[CommandStartupService],
    package: &StreamedKexPackage,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    resource_slot: u32,
    process_name: &str,
    process_origin: ProcessOrigin,
    started_millis: u64,
    processes: SharedProcessTable,
) -> Result<ResidentApplication<'service>, ()> {
    prepare_resident_application_with_plan(
        scheduler,
        accounting,
        dispatcher,
        services,
        package.executable(),
        |allocation, _plan| prepare_streamed_application_memory(allocation, package, &mut read_at),
        resource_slot,
        process_name,
        process_origin,
        started_millis,
        processes,
    )
}

#[allow(
    clippy::drop_non_drop,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub(crate) fn prepare_resident_application_with_plan<'service, P: NativeApplicationPlan>(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    mut dispatcher: Dispatcher<'service>,
    services: &[CommandStartupService],
    plan: &P,
    materialize: impl FnOnce(&ApplicationAllocation, &P) -> Result<(), ()>,
    resource_slot: u32,
    process_name: &str,
    process_origin: ProcessOrigin,
    started_millis: u64,
    processes: SharedProcessTable,
) -> Result<ResidentApplication<'service>, ()> {
    if services.is_empty() || services.len() > troe_dispatch::MAX_HANDLES {
        return Err(());
    }
    let process_name = if process_name.as_bytes().contains(&b'/') {
        ProcessName::from_executable_reference(process_name)
    } else {
        ProcessName::new(process_name)
    }
    .map_err(|_| ())?;
    let mut transaction = LoaderTransaction::new();
    transaction
        .acquire(LoaderResource::Staging)
        .map_err(|_| ())?;
    let heap_start = plan.layout().heap_address();
    let maximum_heap_pages = plan
        .layout()
        .lower_guard_address()
        .checked_sub(heap_start)
        .ok_or(())?
        / BASE_PAGE_SIZE;
    let private_pages = plan.charges().private_pages();
    let stack_pages = plan.stack_pages();

    let Ok((allocation, mapping_plan)) = allocate_application(accounting, plan) else {
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    if transaction.acquire(LoaderResource::Frames).is_err() {
        reclaim_command_application(accounting, allocation);
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }
    if materialize(&allocation, plan).is_err() {
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
    let Ok(isolation) = IsolationResource::new(
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
            scheduler,
            task_id,
            &mut dispatcher,
            None,
            accounting,
            allocation,
        );
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }

    let entry = plan.entry_address();
    let stack_top = plan.layout().stack_top();
    let startup_address = plan.layout().startup_address();
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
        )?;
        troe_machine::copy_to_physical(allocation.startup, 0, &startup).map_err(|_| ())?;
        Ok((owner, command_handles))
    })();
    let Ok((owner, handles)) = setup else {
        rollback_command_application_task(
            scheduler,
            task_id,
            &mut dispatcher,
            live_owner,
            accounting,
            allocation,
        );
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    drop(mapping_plan);
    let registration = ProcessRegistration {
        task_id,
        name: process_name,
        origin: process_origin,
        started_millis,
        table_pages: retained_table_pages,
        private_pages,
        handles: handle_count,
    };
    let Ok(process_id) = processes
        .try_borrow_mut()
        .map_err(|_| ())
        .and_then(|mut table| table.register(registration).map_err(|_| ()))
    else {
        rollback_command_application_task(
            scheduler,
            task_id,
            &mut dispatcher,
            live_owner,
            accounting,
            allocation,
        );
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    if transaction.commit().is_err() {
        let _removed = processes
            .try_borrow_mut()
            .map(|mut table| table.remove(process_id));
        rollback_command_application_task(
            scheduler,
            task_id,
            &mut dispatcher,
            live_owner,
            accounting,
            allocation,
        );
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    }

    Ok(ResidentApplication {
        task_id,
        process_id,
        processes,
        allocation,
        isolation,
        owner,
        handles,
        handle_count,
        stack_pages,
        heap_start,
        maximum_heap_pages,
        private_pages,
        dispatcher,
        deferred_services: None,
        deferred_state: None,
        process_control: None,
        execution: Some(ResidentExecution::Unstarted(Box::new(ResidentLaunch {
            address_space,
            entry,
            stack_top,
            startup_address,
        }))),
    })
}

pub(crate) fn random_application_placement(random: &SharedRandom) -> Result<LoadPlacement, ()> {
    const IMAGE_LIMIT: u64 = 0x0000_4000_0000_0000;
    const STACK_MINIMUM: u64 = 0x0000_6000_0000_0000;

    fn aligned_draw(
        generator: &mut RandomGenerator,
        minimum: u64,
        exclusive_limit: u64,
    ) -> Result<u64, ()> {
        if !minimum.is_multiple_of(KEX_V1_IMAGE_ALIGNMENT)
            || !exclusive_limit.is_multiple_of(KEX_V1_IMAGE_ALIGNMENT)
            || minimum >= exclusive_limit
        {
            return Err(());
        }
        let slots = exclusive_limit
            .checked_sub(minimum)
            .and_then(|bytes| bytes.checked_div(KEX_V1_IMAGE_ALIGNMENT))
            .ok_or(())?;
        let selected = generator.uniform_u64(slots).map_err(|_| ())?;
        minimum
            .checked_add(selected.checked_mul(KEX_V1_IMAGE_ALIGNMENT).ok_or(())?)
            .ok_or(())
    }

    let mut generator = random.try_borrow_mut().map_err(|_| ())?;
    let image_base = aligned_draw(&mut generator, KEX_V1_MIN_IMAGE_BASE, IMAGE_LIMIT)?;
    let stack_top = aligned_draw(&mut generator, STACK_MINIMUM, KEX_V1_USER_END)?;
    Ok(LoadPlacement::new(image_base, stack_top))
}

pub(crate) fn parse_native_application<'artifact>(
    accounting: &OwnedAccounting,
    artifact: &'artifact [u8],
) -> Result<LoadPlan<'artifact>, ()> {
    let placement = random_application_placement(&accounting.random)?;
    parse_kex_at(artifact, native_application_target(), ABI_MINOR, placement).map_err(|_| ())
}

pub(crate) trait NativeApplicationPlan {
    fn entry_address(&self) -> u64;
    fn image_base(&self) -> u64;
    fn heap_pages(&self) -> u64;
    fn stack_pages(&self) -> u64;
    fn charges(&self) -> LoadCharges;
    fn layout(&self) -> ApplicationLayout;
    fn segment_count(&self) -> usize;
    fn segment(&self, index: usize) -> Option<LoadSegmentLayout>;
    fn encode_startup_page(
        &self,
        info: StartupInfo<'_>,
        destination: &mut [u8; PAGE_BYTES],
    ) -> Result<(), ()>;
}

impl NativeApplicationPlan for LoadPlan<'_> {
    fn entry_address(&self) -> u64 {
        self.entry_address()
    }

    fn image_base(&self) -> u64 {
        self.image_base()
    }

    fn heap_pages(&self) -> u64 {
        self.heap_pages()
    }

    fn stack_pages(&self) -> u64 {
        self.stack_pages()
    }

    fn charges(&self) -> LoadCharges {
        self.charges()
    }

    fn layout(&self) -> ApplicationLayout {
        self.layout()
    }

    fn segment_count(&self) -> usize {
        self.segments().count()
    }

    fn segment(&self, index: usize) -> Option<LoadSegmentLayout> {
        self.segments()
            .nth(index)
            .map(troe_application::LoadSegment::layout)
    }

    fn encode_startup_page(
        &self,
        info: StartupInfo<'_>,
        destination: &mut [u8; PAGE_BYTES],
    ) -> Result<(), ()> {
        self.encode_startup_page(info, destination).map_err(|_| ())
    }
}

impl NativeApplicationPlan for StreamedLoadPlan {
    fn entry_address(&self) -> u64 {
        self.entry_address()
    }

    fn image_base(&self) -> u64 {
        self.image_base()
    }

    fn heap_pages(&self) -> u64 {
        self.heap_pages()
    }

    fn stack_pages(&self) -> u64 {
        self.stack_pages()
    }

    fn charges(&self) -> LoadCharges {
        self.charges()
    }

    fn layout(&self) -> ApplicationLayout {
        self.layout()
    }

    fn segment_count(&self) -> usize {
        self.segments().count()
    }

    fn segment(&self, index: usize) -> Option<LoadSegmentLayout> {
        self.segments().nth(index)
    }

    fn encode_startup_page(
        &self,
        info: StartupInfo<'_>,
        destination: &mut [u8; PAGE_BYTES],
    ) -> Result<(), ()> {
        self.encode_startup_page(info, destination).map_err(|_| ())
    }
}

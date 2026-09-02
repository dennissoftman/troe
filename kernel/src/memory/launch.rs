//! The launch reservation: writing an image into it, mapping it, and
//! releasing it.
//!
//! Reserves and zeroes the frames one launch needs in bounded substeps, copies
//! segment payloads and relocations across whatever extent boundaries they
//! straddle, builds the application mapping plan, and performs the ADR 0014
//! teardown order on both the success and the rollback paths.

use crate::machine::OwnedAccounting;
use crate::memory::ApplicationAllocation;
use crate::memory::growth::application_growth_pages;
use crate::memory::private::{
    ACCEPTANCE_LAUNCH_QUANTUM_PAGES, APPLICATION_STARTUP_PAGES, ApplicationPrivateAllocation,
    ApplicationPrivateMemory, COALESCE_LAUNCH_EXTENTS, MAX_APPLICATION_EXTENTS,
};
use crate::resident::launch::NativeApplicationPlan;
use crate::support::fatal;
use alloc::vec::Vec;
use troe_application::{
    LoadPlan, LoaderTransaction, SegmentPermissions, StreamedKexPackage, stream_verified_segments,
    visit_verified_relocations,
};
use troe_dispatch::{Dispatcher, HandleOwner};
use troe_memory::{
    BASE_PAGE_SIZE, Mapping, MappingLifetime, MappingOwner, MappingPermissions, MappingPlan,
    PhysicalExtents, PhysicalRange, VirtualRange,
};
use troe_task::{Scheduler, TaskId};

/// Reserve one launch's private frames and zero them in bounded substeps.
///
/// The reservation is a sequence of extents rather than one contiguous run,
/// so a large application launches on a fragmented machine instead of being
/// refused for want of one long free span. Each quantum is zeroed as it is
/// taken, so no substep scales with the total request and no derived range
/// is ever published over frames that still hold a previous owner's bytes.
pub(crate) fn reserve_zeroed_private_extents(
    accounting: &mut OwnedAccounting,
    resource_pages: u64,
) -> Result<PhysicalExtents, ()> {
    let quantum = if cfg!(feature = "acceptance-probes") {
        ACCEPTANCE_LAUNCH_QUANTUM_PAGES
    } else {
        accounting.memory_policy.operation_quantum_pages()
    };
    if quantum == 0 || resource_pages == 0 {
        return Err(());
    }
    let mut extents = PhysicalExtents::new();
    let mut remaining = resource_pages;
    let mut failed = false;
    while remaining != 0 {
        // Halve the request rather than give up when no run of this size
        // is free. A launch then needs only as much contiguity as the
        // machine still has, down to single pages, instead of being refused
        // while enough total frames remain.
        let mut request = remaining.min(quantum);
        let reserved = loop {
            match accounting.frames.allocate_contiguous(request, 1) {
                Ok(range) => break Some(range),
                Err(_) if request > 1 => request /= 2,
                Err(_) => break None,
            }
        };
        let Some(range) = reserved else {
            failed = true;
            break;
        };
        let taken = range.page_count();
        if troe_machine::zero_physical_range(range).is_err()
            || extents
                .push(range, MAX_APPLICATION_EXTENTS, COALESCE_LAUNCH_EXTENTS)
                .is_err()
        {
            accounting.frames.free_range(range).map_err(|_| ())?;
            failed = true;
            break;
        }
        remaining = remaining.checked_sub(taken).ok_or(())?;
    }
    if failed {
        release_launch_extents(accounting, &extents)?;
        return Err(());
    }
    if extents.page_count() != resource_pages {
        release_launch_extents(accounting, &extents)?;
        return Err(());
    }
    Ok(extents)
}

/// Release every extent of one provisional launch reservation.
pub(crate) fn release_launch_extents(
    accounting: &mut OwnedAccounting,
    extents: &PhysicalExtents,
) -> Result<(), ()> {
    for range in extents.extents() {
        accounting.frames.free_range(*range).map_err(|_| ())?;
    }
    Ok(())
}

/// Copy `bytes` to one logical offset in a reservation, crossing extents.
///
/// A relocation target or a streamed payload chunk may straddle an extent
/// boundary, so the copy is split at whatever boundaries it crosses rather
/// than requiring one contiguous destination.
pub(crate) fn write_launch_bytes(
    extents: &PhysicalExtents,
    byte_offset: u64,
    bytes: &[u8],
) -> Result<(), ()> {
    let mut written = 0_usize;
    while written < bytes.len() {
        let remaining = bytes.len().checked_sub(written).ok_or(())?;
        let offset = u64::try_from(written)
            .ok()
            .and_then(|written| byte_offset.checked_add(written))
            .ok_or(())?;
        let (extent, within, count) = extents
            .byte_run_at(offset, u64::try_from(remaining).map_err(|_| ())?)
            .map_err(|_| ())?;
        let chunk = bytes
            .get(written..written.checked_add(count).ok_or(())?)
            .ok_or(())?;
        troe_machine::copy_to_physical(extent, within, chunk).map_err(|_| ())?;
        written = written.checked_add(count).ok_or(())?;
    }
    Ok(())
}

/// Copy one segment's payload bytes at an offset inside that segment.
///
/// The contiguous reservation bounded every payload write to the segment's
/// own physical range, so an offset past the segment's end was refused.
/// Extents address the whole reservation, so that bound is reimposed here
/// rather than letting an overrun spill into the next segment, the startup
/// page, or the heap.
pub(crate) fn write_segment_bytes<P: NativeApplicationPlan>(
    extents: &PhysicalExtents,
    plan: &P,
    segment_index: usize,
    offset_in_segment: u64,
    bytes: &[u8],
) -> Result<(), ()> {
    let segment = plan.segment(segment_index).ok_or(())?;
    let end = u64::try_from(bytes.len())
        .ok()
        .and_then(|length| offset_in_segment.checked_add(length))
        .ok_or(())?;
    if end > segment.memory_bytes() {
        return Err(());
    }
    let logical = segment_logical_offset(plan, segment_index)?
        .checked_add(offset_in_segment)
        .ok_or(())?;
    write_launch_bytes(extents, logical, bytes)
}

/// Map one virtually contiguous region across however many extents back it.
pub(crate) fn map_launch_region(
    plan: &mut MappingPlan,
    extents: &PhysicalExtents,
    start_page: u64,
    page_count: u64,
    virtual_start: u64,
    permissions: MappingPermissions,
) -> Result<(), ()> {
    let mut mapped = 0_u64;
    while mapped < page_count {
        let remaining = page_count.checked_sub(mapped).ok_or(())?;
        let run = extents
            .run_at(start_page.checked_add(mapped).ok_or(())?, remaining)
            .map_err(|_| ())?;
        let address = mapped
            .checked_mul(BASE_PAGE_SIZE)
            .and_then(|bytes| virtual_start.checked_add(bytes))
            .ok_or(())?;
        insert_application_mapping(plan, address, run, permissions)?;
        mapped = mapped.checked_add(run.page_count()).ok_or(())?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn allocate_application<P: NativeApplicationPlan>(
    accounting: &mut OwnedAccounting,
    plan: &P,
) -> Result<(ApplicationAllocation, MappingPlan), ()> {
    let resource_pages = plan.charges().private_pages();
    let committed_pages = accounting
        .application_committed_pages
        .checked_add(resource_pages)
        .ok_or(())?;
    if accounting
        .memory_policy
        .system_application_commit()
        .maximum()
        .is_some_and(|maximum| committed_pages > maximum)
        || accounting
            .memory_policy
            .default_committed_pages()
            .maximum()
            .is_some_and(|maximum| resource_pages > maximum)
        || resource_pages
            > accounting
                .frames
                .free_frames()
                .saturating_sub(accounting.memory_policy.minimum_free_pages())
    {
        return Err(());
    }
    let extents = reserve_zeroed_private_extents(accounting, resource_pages)?;
    let image_pages = plan.charges().image_pages();
    let heap_pages = plan.heap_pages();
    let stack_pages = plan.stack_pages();
    // The reservation must describe exactly the logical sequence the plan
    // charged: image, startup page, heap, stack.
    let derived = image_pages
        .checked_add(APPLICATION_STARTUP_PAGES)
        .and_then(|pages| pages.checked_add(heap_pages))
        .and_then(|pages| pages.checked_add(stack_pages))
        .filter(|total| *total == extents.page_count())
        .ok_or(())
        .and_then(|_| extents.run_at(image_pages, 1).map_err(|_| ()));
    let Ok(startup) = derived else {
        release_launch_extents(accounting, &extents)?;
        return Err(());
    };
    let private = ApplicationPrivateAllocation {
        extents,
        image_pages,
        startup,
        heap_pages,
        stack_pages,
    };
    let Ok(mapping_plan) = build_application_plan(
        &accounting.kernel_plan,
        accounting.kernel_runtime,
        &private,
        plan,
    ) else {
        release_launch_extents(accounting, &private.extents)?;
        return Err(());
    };
    let Ok(table_pages) = troe_machine::required_page_table_pages(&mapping_plan) else {
        release_launch_extents(accounting, &private.extents)?;
        return Err(());
    };
    if table_pages == 0
        || table_pages
            > accounting
                .frames
                .free_frames()
                .saturating_sub(accounting.memory_policy.minimum_free_pages())
    {
        release_launch_extents(accounting, &private.extents)?;
        return Err(());
    }
    let Ok(tables) = accounting.frames.allocate_contiguous(table_pages, 1) else {
        release_launch_extents(accounting, &private.extents)?;
        return Err(());
    };
    accounting.application_committed_pages = committed_pages;
    Ok((
        ApplicationAllocation {
            extents: private.extents,
            tables,
            image_pages: private.image_pages,
            startup: private.startup,
            heap_pages: private.heap_pages,
            growth_ranges: Vec::new(),
            growth_table_frames: Vec::new(),
            private_memory: ApplicationPrivateMemory::new(
                accounting.memory_policy,
                plan.layout().lower_guard_address(),
            ),
        },
        mapping_plan,
    ))
}

pub(crate) fn prepare_application_memory(
    allocation: &ApplicationAllocation,
    plan: &LoadPlan<'_>,
) -> Result<(), ()> {
    let mut logical = 0_u64;
    for (index, segment) in plan.segments().enumerate() {
        write_segment_bytes(&allocation.extents, plan, index, 0, segment.file_bytes())?;
        logical = logical.checked_add(segment.memory_bytes()).ok_or(())?;
    }
    if logical
        != allocation
            .image_pages
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(())?
    {
        return Err(());
    }
    for relocation in plan.relocations() {
        apply_application_relocation(allocation, plan, relocation)?;
    }
    Ok(())
}

pub(crate) fn prepare_streamed_application_memory(
    allocation: &ApplicationAllocation,
    package: &StreamedKexPackage,
    read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
) -> Result<(), ()> {
    stream_verified_segments(
        package,
        |offset, destination| read_at(offset, destination),
        |segment_index, segment_offset, bytes| {
            write_segment_bytes(
                &allocation.extents,
                package.executable(),
                segment_index,
                segment_offset,
                bytes,
            )
        },
    )
    .map_err(|_| ())?;
    visit_verified_relocations(
        package,
        |offset, destination| read_at(offset, destination),
        |relocation| apply_application_relocation(allocation, package.executable(), relocation),
    )
    .map_err(|_| ())
}

/// Logical byte offset of one segment within the launch reservation.
///
/// Segments occupy the reservation in plan order starting at logical zero,
/// exactly as they did when the reservation was one contiguous run, so a
/// segment-relative offset composes with this to address any image byte.
pub(crate) fn segment_logical_offset<P: NativeApplicationPlan>(
    plan: &P,
    wanted_index: usize,
) -> Result<u64, ()> {
    let mut offset = 0_u64;
    for index in 0..plan.segment_count() {
        let segment = plan.segment(index).ok_or(())?;
        if index == wanted_index {
            return Ok(offset);
        }
        offset = offset.checked_add(segment.memory_bytes()).ok_or(())?;
    }
    Err(())
}

pub(crate) fn apply_application_relocation<P: NativeApplicationPlan>(
    allocation: &ApplicationAllocation,
    plan: &P,
    relocation: troe_application::RelativeRelocation,
) -> Result<(), ()> {
    let target_end = relocation.target_offset().checked_add(8).ok_or(())?;
    let mut target = None;
    for index in 0..plan.segment_count() {
        let segment = plan.segment(index).ok_or(())?;
        let segment_end = segment
            .image_offset()
            .checked_add(segment.memory_bytes())
            .ok_or(())?;
        if segment.image_offset() <= relocation.target_offset() && target_end <= segment_end {
            let within = relocation
                .target_offset()
                .checked_sub(segment.image_offset())
                .ok_or(())?;
            target = Some(
                segment_logical_offset(plan, index)?
                    .checked_add(within)
                    .ok_or(())?,
            );
            break;
        }
    }
    let logical = target.ok_or(())?;
    let value = plan
        .image_base()
        .checked_add(relocation.value_offset())
        .ok_or(())?;
    // An eight-byte target may straddle an extent boundary, so the write is
    // split rather than requiring one contiguous destination.
    write_launch_bytes(&allocation.extents, logical, &value.to_le_bytes())
}

pub(crate) fn build_application_plan<P: NativeApplicationPlan>(
    kernel: &MappingPlan,
    kernel_runtime: PhysicalRange,
    allocation: &ApplicationPrivateAllocation,
    application: &P,
) -> Result<MappingPlan, ()> {
    let mut plan = MappingPlan::new();
    for mapping in kernel.mappings() {
        let physical = mapping.physical_range();
        let needed_while_isolated = mapping.owner() != MappingOwner::KernelRuntime
            || (physical.start() >= kernel_runtime.start()
                && physical.end() <= kernel_runtime.end());
        if needed_while_isolated {
            plan.insert(*mapping).map_err(|_| ())?;
        }
    }

    // Each region is virtually contiguous but may be backed by several
    // extents, so one region contributes one mapping record per physically
    // contiguous run rather than exactly one record.
    for index in 0..application.segment_count() {
        let segment = application.segment(index).ok_or(())?;
        let permissions = match segment.permissions() {
            SegmentPermissions::ReadOnly => MappingPermissions::READ_ONLY,
            SegmentPermissions::ReadExecute => MappingPermissions::READ_EXECUTE,
            SegmentPermissions::ReadWrite => MappingPermissions::READ_WRITE,
        };
        map_launch_region(
            &mut plan,
            &allocation.extents,
            segment_logical_offset(application, index)? / BASE_PAGE_SIZE,
            segment.memory_bytes() / BASE_PAGE_SIZE,
            segment.virtual_address(),
            permissions,
        )?;
    }
    insert_application_mapping(
        &mut plan,
        application.layout().startup_address(),
        allocation.startup,
        MappingPermissions::READ_ONLY,
    )?;
    let heap_start_page = allocation
        .image_pages
        .checked_add(APPLICATION_STARTUP_PAGES)
        .ok_or(())?;
    if allocation.heap_pages != 0 {
        map_launch_region(
            &mut plan,
            &allocation.extents,
            heap_start_page,
            allocation.heap_pages,
            application.layout().heap_address(),
            MappingPermissions::READ_WRITE,
        )?;
    }
    map_launch_region(
        &mut plan,
        &allocation.extents,
        heap_start_page
            .checked_add(allocation.heap_pages)
            .ok_or(())?,
        allocation.stack_pages,
        application.layout().stack_bottom(),
        MappingPermissions::READ_WRITE,
    )?;
    if !plan.enforces_global_w_xor_x() {
        return Err(());
    }
    Ok(plan)
}

pub(crate) fn insert_application_mapping(
    plan: &mut MappingPlan,
    virtual_start: u64,
    physical: PhysicalRange,
    permissions: MappingPermissions,
) -> Result<(), ()> {
    let virtual_range =
        VirtualRange::from_pages(virtual_start, physical.page_count()).map_err(|_| ())?;
    let mapping = Mapping::user(
        virtual_range,
        physical,
        permissions,
        MappingOwner::IsolatedTask,
        MappingLifetime::Task,
    )
    .map_err(|_| ())?;
    plan.insert(mapping).map_err(|_| ())
}

pub(crate) fn rollback_application_task(
    scheduler: &mut Scheduler,
    task_id: TaskId,
    dispatcher: &mut Dispatcher<'_>,
    owner: Option<HandleOwner>,
    accounting: &mut OwnedAccounting,
    allocation: ApplicationAllocation,
) -> Result<(), ()> {
    terminate_revoke_and_reap_task(scheduler, task_id, dispatcher, owner)?;
    reclaim_application(accounting, allocation)
}

pub(crate) fn rollback_command_application_task(
    scheduler: &mut Scheduler,
    task_id: TaskId,
    dispatcher: &mut Dispatcher<'_>,
    owner: Option<HandleOwner>,
    accounting: &mut OwnedAccounting,
    allocation: ApplicationAllocation,
) {
    if rollback_application_task(
        scheduler, task_id, dispatcher, owner, accounting, allocation,
    )
    .is_err()
    {
        fatal(b"fatal: application rollback invariant failed\n");
    }
}

pub(crate) fn reclaim_command_application(
    accounting: &mut OwnedAccounting,
    allocation: ApplicationAllocation,
) {
    if reclaim_application(accounting, allocation).is_err() {
        fatal(b"fatal: application reclaim invariant failed\n");
    }
}

pub(crate) fn clear_provisional_loader_ownership(transaction: &mut LoaderTransaction) {
    transaction.rollback(|_resource| {});
}

/// Complete the scheduler/capability portion of ADR 0014 teardown.
///
/// Physical allocations remain owned by the caller until this returns, so
/// no zeroization or frame release can precede terminalization, revocation,
/// and reaping. Any failure deliberately leaks the retained allocation into
/// the terminal boot path instead of making it reusable prematurely.
pub(crate) fn terminate_revoke_and_reap_task(
    scheduler: &mut Scheduler,
    task_id: TaskId,
    dispatcher: &mut Dispatcher<'_>,
    owner: Option<HandleOwner>,
) -> Result<(), ()> {
    scheduler
        .terminate_revoke_and_reap(task_id, 1, |_terminal| {
            if let Some(owner) = owner {
                dispatcher.close_owner(owner).map_err(|_| ())?;
            }
            Ok::<(), ()>(())
        })
        .map(|_reaped| ())
        .map_err(|_| ())
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn reclaim_application(
    accounting: &mut OwnedAccounting,
    allocation: ApplicationAllocation,
) -> Result<(), ()> {
    let committed_pages = allocation
        .extents
        .page_count()
        .checked_add(application_growth_pages(&allocation)?)
        .and_then(|pages| pages.checked_add(allocation.private_memory.committed_pages))
        .ok_or(())?;
    accounting.application_committed_pages = accounting
        .application_committed_pages
        .checked_sub(committed_pages)
        .ok_or(())?;
    accounting.private_metadata_bytes = accounting
        .private_metadata_bytes
        .checked_sub(allocation.private_memory.metadata_bytes)
        .ok_or(())?;
    for mapping in allocation.private_memory.mappings {
        for range in mapping.backing {
            troe_machine::zero_physical_range(range).map_err(|_| ())?;
            accounting.frames.free_range(range).map_err(|_| ())?;
        }
    }
    for range in allocation.growth_ranges {
        troe_machine::zero_physical_range(range).map_err(|_| ())?;
        accounting.frames.free_range(range).map_err(|_| ())?;
    }
    for frame in allocation.growth_table_frames {
        let range = PhysicalRange::from_pages(frame, 1).map_err(|_| ())?;
        troe_machine::zero_physical_range(range).map_err(|_| ())?;
        accounting.frames.free(frame).map_err(|_| ())?;
    }
    troe_machine::zero_physical_range(allocation.tables).map_err(|_| ())?;
    accounting
        .frames
        .free_range(allocation.tables)
        .map_err(|_| ())?;
    for range in allocation.extents.extents() {
        troe_machine::zero_physical_range(*range).map_err(|_| ())?;
        accounting.frames.free_range(*range).map_err(|_| ())?;
    }
    Ok(())
}

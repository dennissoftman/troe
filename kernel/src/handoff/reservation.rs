//! Physical reservation and the kernel mapping plan built before handoff.
//!
//! Reserves the boot arena, heap, page tables, exception stack, and the three
//! kernel task stacks with their guards, then describes the kernel address
//! space: identity ranges for owned RAM, the framebuffer device range, and the
//! normalized final memory map the owned machine keeps.

use crate::limits::{
    BOOT_ARENA_PAGES, EXCEPTION_STACK_BYTES, OWNED_HEAP_BYTES, OWNED_STACK_BYTES, PAGE_TABLE_BYTES,
    SERVER_TASK_STACK_BYTES, SHELL_TASK_STACK_BYTES, TASK_GUARD_BYTES, TASK_STACK_BYTES,
    TASK_STACK_COUNT,
};
use alloc::vec::Vec;
use troe_console::{FramebufferDescriptor, FramebufferPixelFormat};
use troe_memory::{
    BASE_PAGE_SIZE, BootAllocator, MAX_FIRMWARE_REGIONS, Mapping, MappingLifetime,
    MappingMemoryType, MappingOwner, MappingPermissions, MappingPlan, MemoryRegion,
    NormalizedMemoryMap, PhysicalRange, RegionKind,
};
use uefi::boot;
use uefi::mem::memory_map::MemoryMap;
use uefi::mem::memory_map::MemoryMapOwned;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};

#[derive(Clone, Copy)]
pub(crate) struct TaskStackLayout {
    pub(crate) lower_guard: PhysicalRange,
    pub(crate) stack: PhysicalRange,
    pub(crate) upper_guard: PhysicalRange,
}

#[derive(Clone, Copy)]
pub(crate) struct BootMemory {
    pub(crate) arena: PhysicalRange,
    pub(crate) heap: PhysicalRange,
    pub(crate) page_tables: PhysicalRange,
    pub(crate) stack: PhysicalRange,
    pub(crate) exception_stack: PhysicalRange,
    pub(crate) task_stacks: [TaskStackLayout; TASK_STACK_COUNT],
}

pub(crate) fn reserve_and_install_heap() -> Result<BootMemory, ()> {
    let arena_pointer = boot::allocate_pages(
        boot::AllocateType::AnyPages,
        boot::MemoryType::LOADER_DATA,
        BOOT_ARENA_PAGES,
    )
    .map_err(|_| ())?;
    let arena_start = u64::try_from(arena_pointer.as_ptr() as usize).map_err(|_| ())?;
    let arena_pages = u64::try_from(BOOT_ARENA_PAGES).map_err(|_| ())?;
    let arena = PhysicalRange::from_pages(arena_start, arena_pages).map_err(|_| ())?;
    let mut allocator = BootAllocator::new(arena);
    let heap = allocator
        .allocate(OWNED_HEAP_BYTES, BASE_PAGE_SIZE)
        .map_err(|_| ())?;
    let page_tables = allocator
        .allocate(PAGE_TABLE_BYTES, BASE_PAGE_SIZE)
        .map_err(|_| ())?;
    let stack = allocator
        .allocate(OWNED_STACK_BYTES, BASE_PAGE_SIZE)
        .map_err(|_| ())?;
    let exception_stack = allocator
        .allocate(EXCEPTION_STACK_BYTES, BASE_PAGE_SIZE)
        .map_err(|_| ())?;
    let task_stacks = [
        allocate_task_stack(&mut allocator, TASK_STACK_BYTES)?,
        allocate_task_stack(&mut allocator, SERVER_TASK_STACK_BYTES)?,
        allocate_task_stack(&mut allocator, SHELL_TASK_STACK_BYTES)?,
    ];
    allocator.seal();
    let heap_start = usize::try_from(heap.start()).map_err(|_| ())?;
    let heap_bytes = usize::try_from(heap.byte_count()).map_err(|_| ())?;
    if !troe_machine::initialize_heap(heap_start, heap_bytes) {
        return Err(());
    }
    let heap_pages = heap.byte_count() / BASE_PAGE_SIZE;
    let table_pages = page_tables.byte_count() / BASE_PAGE_SIZE;
    Ok(BootMemory {
        arena,
        heap: PhysicalRange::from_pages(heap.start(), heap_pages).map_err(|_| ())?,
        page_tables: PhysicalRange::from_pages(page_tables.start(), table_pages).map_err(|_| ())?,
        stack: PhysicalRange::from_pages(stack.start(), stack.byte_count() / BASE_PAGE_SIZE)
            .map_err(|_| ())?,
        exception_stack: PhysicalRange::from_pages(
            exception_stack.start(),
            exception_stack.byte_count() / BASE_PAGE_SIZE,
        )
        .map_err(|_| ())?,
        task_stacks,
    })
}

pub(crate) fn allocate_task_stack(
    allocator: &mut BootAllocator,
    stack_bytes: u64,
) -> Result<TaskStackLayout, ()> {
    let lower_guard = allocator
        .allocate(TASK_GUARD_BYTES, BASE_PAGE_SIZE)
        .map_err(|_| ())?;
    let stack = allocator
        .allocate(stack_bytes, BASE_PAGE_SIZE)
        .map_err(|_| ())?;
    let upper_guard = allocator
        .allocate(TASK_GUARD_BYTES, BASE_PAGE_SIZE)
        .map_err(|_| ())?;
    Ok(TaskStackLayout {
        lower_guard: allocation_range(lower_guard)?,
        stack: allocation_range(stack)?,
        upper_guard: allocation_range(upper_guard)?,
    })
}

pub(crate) fn allocation_range(
    allocation: troe_memory::BootAllocation,
) -> Result<PhysicalRange, ()> {
    PhysicalRange::from_pages(allocation.start(), allocation.byte_count() / BASE_PAGE_SIZE)
        .map_err(|_| ())
}

pub(crate) fn build_mapping_plan(
    memory_map: &MemoryMapOwned,
    image: &troe_machine::ImageLayout,
    boot_memory: &BootMemory,
    framebuffer: Option<FramebufferDescriptor>,
) -> Result<MappingPlan, ()> {
    let mut plan = MappingPlan::new();
    let framebuffer_range = framebuffer.map(framebuffer_device_range).transpose()?;
    for descriptor in memory_map.entries() {
        if !is_runtime_ram(descriptor.ty) {
            continue;
        }
        let range = PhysicalRange::from_pages(descriptor.phys_start, descriptor.page_count)
            .map_err(|_| ())?;
        insert_runtime_excluding(&mut plan, range, framebuffer_range)?;
    }
    for range in [
        boot_memory.heap,
        boot_memory.page_tables,
        boot_memory.stack,
        boot_memory.exception_stack,
    ] {
        insert_identity(
            &mut plan,
            range,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
        )?;
    }
    for task_stack in boot_memory.task_stacks {
        insert_identity(
            &mut plan,
            task_stack.stack,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
        )?;
    }
    for index in 0..image.region_count() {
        let region = image.region(index).ok_or(())?;
        insert_identity(
            &mut plan,
            region.range(),
            region.permissions(),
            MappingMemoryType::Normal,
            MappingOwner::KernelImage,
        )?;
    }
    for device in troe_machine::input_device_ranges()
        .map_err(|_| ())?
        .into_iter()
        .flatten()
    {
        insert_identity(
            &mut plan,
            device,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Device,
            MappingOwner::MachineDevice,
        )?;
    }
    for device in troe_machine::virtio_device_ranges().map_err(|_| ())? {
        insert_identity(
            &mut plan,
            device,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Device,
            MappingOwner::MachineDevice,
        )?;
    }
    if let Some(framebuffer) = framebuffer {
        insert_identity(
            &mut plan,
            framebuffer_device_range(framebuffer)?,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Device,
            MappingOwner::MachineDevice,
        )?;
    }
    Ok(plan)
}

pub(crate) fn capture_framebuffer() -> Option<FramebufferDescriptor> {
    let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    let mut graphics = boot::open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;
    let info = graphics.current_mode_info();
    let pixel_format = match info.pixel_format() {
        GopPixelFormat::Rgb => FramebufferPixelFormat::Rgb,
        GopPixelFormat::Bgr => FramebufferPixelFormat::Bgr,
        GopPixelFormat::Bitmask | GopPixelFormat::BltOnly => return None,
    };
    let (width, height) = info.resolution();
    let stride = info.stride();
    let mut buffer = graphics.frame_buffer();
    let base = u64::try_from(buffer.as_mut_ptr() as usize).ok()?;
    FramebufferDescriptor::new(base, buffer.size(), width, height, stride, pixel_format).ok()
}

pub(crate) fn framebuffer_device_range(
    framebuffer: FramebufferDescriptor,
) -> Result<PhysicalRange, ()> {
    let page_mask = BASE_PAGE_SIZE - 1;
    let start = framebuffer.base_address() & !page_mask;
    let byte_len = u64::try_from(framebuffer.byte_len()).map_err(|_| ())?;
    let end = framebuffer.base_address().checked_add(byte_len).ok_or(())?;
    let aligned_end = end.checked_add(page_mask).ok_or(())? & !page_mask;
    let page_count = aligned_end.checked_sub(start).ok_or(())? / BASE_PAGE_SIZE;
    PhysicalRange::from_pages(start, page_count).map_err(|_| ())
}

pub(crate) fn insert_runtime_excluding(
    plan: &mut MappingPlan,
    range: PhysicalRange,
    excluded: Option<PhysicalRange>,
) -> Result<(), ()> {
    let Some(excluded) = excluded else {
        return insert_identity(
            plan,
            range,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
        );
    };
    if range.end() <= excluded.start() || range.start() >= excluded.end() {
        return insert_identity(
            plan,
            range,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
        );
    }
    if range.start() < excluded.start() {
        let page_count = (excluded.start() - range.start()) / BASE_PAGE_SIZE;
        let before = PhysicalRange::from_pages(range.start(), page_count).map_err(|_| ())?;
        insert_identity(
            plan,
            before,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
        )?;
    }
    if range.end() > excluded.end() {
        let page_count = (range.end() - excluded.end()) / BASE_PAGE_SIZE;
        let after = PhysicalRange::from_pages(excluded.end(), page_count).map_err(|_| ())?;
        insert_identity(
            plan,
            after,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
        )?;
    }
    Ok(())
}

pub(crate) fn insert_identity(
    plan: &mut MappingPlan,
    range: PhysicalRange,
    permissions: MappingPermissions,
    memory_type: MappingMemoryType,
    owner: MappingOwner,
) -> Result<(), ()> {
    let mapping = Mapping::identity(
        range,
        permissions,
        memory_type,
        owner,
        MappingLifetime::Kernel,
        false,
    )
    .map_err(|_| ())?;
    plan.insert(mapping).map_err(|_| ())
}

pub(crate) const fn is_runtime_ram(memory_type: boot::MemoryType) -> bool {
    memory_type.0 == boot::MemoryType::CONVENTIONAL.0
        || memory_type.0 == boot::MemoryType::BOOT_SERVICES_CODE.0
        || memory_type.0 == boot::MemoryType::BOOT_SERVICES_DATA.0
}

pub(crate) fn normalize_final_map(
    memory_map: &MemoryMapOwned,
    reservations: &[PhysicalRange],
) -> Result<NormalizedMemoryMap, ()> {
    let mut regions = Vec::new();
    for descriptor in memory_map.entries() {
        if regions.len() >= MAX_FIRMWARE_REGIONS {
            return Err(());
        }
        let range = PhysicalRange::from_pages(descriptor.phys_start, descriptor.page_count)
            .map_err(|_| ())?;
        let kind = if is_reclaimable_after_handoff(descriptor.ty) {
            RegionKind::Usable
        } else {
            RegionKind::Reserved
        };
        regions.push(MemoryRegion::new(range, kind));
    }
    NormalizedMemoryMap::build(&regions, reservations).map_err(|_| ())
}

pub(crate) const fn is_reclaimable_after_handoff(memory_type: boot::MemoryType) -> bool {
    memory_type.0 == boot::MemoryType::CONVENTIONAL.0
        || memory_type.0 == boot::MemoryType::BOOT_SERVICES_CODE.0
        || memory_type.0 == boot::MemoryType::BOOT_SERVICES_DATA.0
}

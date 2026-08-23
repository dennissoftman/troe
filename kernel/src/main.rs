//! UEFI-bootstrapped Stage 6 isolated owned-machine image.
#![cfg_attr(target_os = "uefi", no_std)]
#![cfg_attr(target_os = "uefi", no_main)]
#![forbid(unsafe_code)]

#[cfg(not(target_os = "uefi"))]
fn main() {
    println!("build with --target x86_64-unknown-uefi or aarch64-unknown-uefi");
}

#[cfg(target_os = "uefi")]
mod firmware {
    extern crate alloc;

    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt::Write as _;
    use core::panic::PanicInfo;

    use kllm_core::{Input, MAX_LINE_BYTES, MachineMemorySnapshot, Output, StreamError};
    use kllm_dispatch::{
        ConsoleService, CopiedMessage, DispatchedOutput, Dispatcher, HandleOwner, ReplyStatus,
        Request, Rights, Service, ServiceReply,
    };
    use kllm_driver::{InputQueueConfig, InputSource};
    use kllm_memory::{
        BASE_PAGE_SIZE, BootAllocator, FrameAllocator, MAX_FIRMWARE_REGIONS, Mapping,
        MappingLifetime, MappingMemoryType, MappingOwner, MappingPermissions, MappingPlan,
        MemoryMapStats, MemoryRegion, NormalizedMemoryMap, PhysicalRange, RegionKind, VirtualRange,
    };
    use kllm_shell::{CompletionConfig, Shell};
    use kllm_task::{
        Capabilities, IsolationResource, Scheduler, StackResource, TaskFault, TaskId, TaskState,
        TaskStep,
    };
    use kllm_terminal::{
        EditorConfig, EditorOutcome, FramebufferDescriptor, FramebufferPixelFormat, InputDecoder,
        KeyboardConfig, LineEditor, Ps2Set1Decoder, TextConsole, TextConsoleConfig,
    };
    use kllm_vfs::{Namespace, RamFsQuota};
    use uefi::boot;
    use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned};
    use uefi::prelude::*;
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};

    const ROOTFS: &[u8] = include_bytes!("../../assets/root.kefs");
    const OWNED_HEAP_BYTES: u64 = 6 * 1024 * 1024;
    const PAGE_TABLE_BYTES: u64 = 2 * 1024 * 1024;
    const OWNED_STACK_BYTES: u64 = 128 * 1024;
    const EXCEPTION_STACK_BYTES: u64 = 16 * 1024;
    const TASK_STACK_BYTES: u64 = 32 * 1024;
    const TASK_GUARD_BYTES: u64 = BASE_PAGE_SIZE;
    const TASK_STACK_PAGES: u16 = 8;
    const TASK_STACK_COUNT: usize = 3;
    const ISOLATED_TABLE_PAGES: u64 = PAGE_TABLE_BYTES / BASE_PAGE_SIZE;
    const ISOLATED_CODE_PAGES: u64 = 1;
    const ISOLATED_DATA_PAGES: u64 = 1;
    const ISOLATED_STACK_PAGES: u64 = 4;
    const ISOLATED_PRIVATE_PAGES: u64 =
        ISOLATED_CODE_PAGES + ISOLATED_DATA_PAGES + ISOLATED_STACK_PAGES;
    const ISOLATED_RESOURCE_PAGES: u64 = ISOLATED_TABLE_PAGES + ISOLATED_PRIVATE_PAGES;
    const USER_CODE_BASE: u64 = 0x0000_4000_0000_0000;
    const USER_DATA_BASE: u64 = USER_CODE_BASE + BASE_PAGE_SIZE;
    const USER_STACK_BASE: u64 = USER_CODE_BASE + 0x1_0000;
    const USER_UNMAPPED_BASE: u64 = USER_CODE_BASE + 0x1000_0000;
    const ISOLATED_MESSAGE: &[u8] = b"stage6 copied request";
    const BOOT_ARENA_PAGES: usize = ((OWNED_HEAP_BYTES
        + PAGE_TABLE_BYTES
        + OWNED_STACK_BYTES
        + EXCEPTION_STACK_BYTES
        + (TASK_STACK_BYTES + 2 * TASK_GUARD_BYTES) * TASK_STACK_COUNT as u64)
        / BASE_PAGE_SIZE) as usize;

    struct FirmwareConsole;

    impl Output for FirmwareConsole {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            let succeeded = uefi::system::with_stdout(|stdout| {
                if bytes == b"\x1b[2J\x1b[H" {
                    stdout.clear().is_ok()
                } else {
                    let text = String::from_utf8_lossy(bytes);
                    stdout.write_str(text.as_ref()).is_ok()
                }
            });
            if succeeded {
                Ok(bytes.len())
            } else {
                Err(StreamError::Device)
            }
        }
    }

    struct NativeConsole;

    impl Output for NativeConsole {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            if kllm_machine::write(bytes) {
                Ok(bytes.len())
            } else {
                Err(StreamError::Device)
            }
        }
    }

    enum NativeShellConsole {
        Serial(NativeConsole),
        Mirrored {
            serial: NativeConsole,
            framebuffer: TextConsole<kllm_machine::OwnedFramebuffer>,
        },
    }

    impl NativeShellConsole {
        fn new(framebuffer: Option<FramebufferDescriptor>) -> Self {
            let Some(framebuffer) = framebuffer else {
                return Self::Serial(NativeConsole);
            };
            let Ok(surface) = kllm_machine::OwnedFramebuffer::new(framebuffer) else {
                return Self::Serial(NativeConsole);
            };
            let Ok(framebuffer) = TextConsole::new(surface, TextConsoleConfig::tiny()) else {
                return Self::Serial(NativeConsole);
            };
            Self::Mirrored {
                serial: NativeConsole,
                framebuffer,
            }
        }

        const fn has_framebuffer(&self) -> bool {
            matches!(self, Self::Mirrored { .. })
        }
    }

    impl Output for NativeShellConsole {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            match self {
                Self::Serial(serial) => serial.write(bytes),
                Self::Mirrored {
                    serial,
                    framebuffer,
                } => {
                    let count = serial.write(bytes)?;
                    let _mirrored = framebuffer.write(&bytes[..count]);
                    Ok(count)
                }
            }
        }
    }

    struct EmptyInput;

    impl Input for EmptyInput {
        fn read(&mut self, _destination: &mut [u8]) -> Result<usize, StreamError> {
            Ok(0)
        }
    }

    struct OwnedAccounting {
        map: MemoryMapStats,
        frames: FrameAllocator,
        #[cfg(feature = "acceptance-probes")]
        execute_probe_address: usize,
        task_stacks: [TaskStackLayout; TASK_STACK_COUNT],
        framebuffer: Option<FramebufferDescriptor>,
        kernel_plan: MappingPlan,
    }

    #[derive(Clone, Copy)]
    struct TaskStackLayout {
        lower_guard: PhysicalRange,
        stack: PhysicalRange,
        upper_guard: PhysicalRange,
    }

    #[derive(Clone, Copy)]
    struct BootMemory {
        arena: PhysicalRange,
        heap: PhysicalRange,
        page_tables: PhysicalRange,
        stack: PhysicalRange,
        exception_stack: PhysicalRange,
        task_stacks: [TaskStackLayout; TASK_STACK_COUNT],
    }

    struct CooperativeService {
        remaining_yields: u8,
        completed_steps: u8,
    }

    struct ShellTask<'a> {
        accounting: &'a OwnedAccounting,
        capabilities: Capabilities,
        stack: PhysicalRange,
    }

    struct PreparedHandoff {
        image_layout: kllm_machine::ImageLayout,
        boot_memory: BootMemory,
        framebuffer: Option<FramebufferDescriptor>,
    }

    struct IsolatedAllocation {
        complete: PhysicalRange,
        tables: PhysicalRange,
        code: PhysicalRange,
        data: PhysicalRange,
        stack: PhysicalRange,
    }

    struct EchoService;

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum IsolationProbe {
        Success,
        Translation,
        WritePermission,
        ExecutePermission,
        IllegalInstruction,
        UnexpectedEntry,
        InvalidOpcode,
        #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
        InvalidCallEncoding,
        InvalidPointer,
        OversizeMessage,
        InvalidStatus,
    }

    impl IsolationProbe {
        const fn expected_fault(self) -> Option<TaskFault> {
            match self {
                Self::Success => None,
                Self::Translation => Some(TaskFault::Translation),
                Self::WritePermission | Self::ExecutePermission => Some(TaskFault::Permission),
                Self::IllegalInstruction | Self::UnexpectedEntry => {
                    Some(TaskFault::IllegalInstruction)
                }
                Self::InvalidOpcode
                | Self::InvalidCallEncoding
                | Self::InvalidPointer
                | Self::OversizeMessage
                | Self::InvalidStatus => Some(TaskFault::InvalidCall),
            }
        }
    }

    impl Service for EchoService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, kllm_dispatch::DispatchError> {
            if request.opcode() != 1 {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            ServiceReply::with_payload(ReplyStatus::Success, request.payload())
        }
    }

    #[entry]
    fn main() -> Status {
        if uefi::helpers::init().is_err() {
            return Status::DEVICE_ERROR;
        }
        let mut firmware_console = FirmwareConsole;
        match prepare_handoff(&mut firmware_console) {
            Ok(prepared) => {
                let stack = prepared.boot_memory.stack;
                let prepared = Box::leak(Box::new(prepared));
                match kllm_machine::enter_owned_stack(stack, prepared, post_handoff) {
                    Err(_) => Status::ABORTED,
                    Ok(never) => match never {},
                }
            }
            Err(()) => Status::ABORTED,
        }
    }

    fn prepare_handoff(console: &mut FirmwareConsole) -> Result<PreparedHandoff, ()> {
        write_all(console, b"UEFI bootstrap: ready\n")?;
        write_all(console, b"preparing owned memory and native console\n")?;

        let image_layout = kllm_machine::loaded_image_layout().map_err(|_| ())?;
        let framebuffer = capture_framebuffer();
        let boot_memory = reserve_and_install_heap()?;
        kllm_machine::initialize_console();
        if !kllm_machine::write(b"native console: ready\n") {
            return Err(());
        }
        Ok(PreparedHandoff {
            image_layout,
            boot_memory,
            framebuffer,
        })
    }

    fn post_handoff(prepared: &mut PreparedHandoff) -> ! {
        let final_map = kllm_machine::exit_boot_services_after_protocols();
        kllm_machine::mark_firmware_exited();
        kllm_machine::take_interrupt_ownership();
        let stack_pointer = usize_as_u64(kllm_machine::current_stack_pointer());
        if !prepared.boot_memory.stack.contains(stack_pointer) {
            fatal(b"fatal: active stack is not kernel-owned\n");
        }
        if !kllm_machine::write(b"boot services: exited\n") {
            fatal(b"fatal: post-handoff console failed\n");
        }
        let accounting = complete_handoff(prepared, final_map)
            .unwrap_or_else(|()| fatal(b"fatal: post-handoff initialization failed\n"));
        run_owned(accounting)
    }

    fn complete_handoff(
        prepared: &PreparedHandoff,
        final_map: MemoryMapOwned,
    ) -> Result<OwnedAccounting, ()> {
        let reservations = [prepared.boot_memory.arena];
        let normalized = normalize_final_map(&final_map, &reservations)?;
        let framebuffer = prepared.framebuffer;
        let mapping_plan = build_mapping_plan(
            &final_map,
            &prepared.image_layout,
            &prepared.boot_memory,
            framebuffer,
        )?;
        // The final-map buffer is LoaderData recorded as reserved in the map.
        // It must remain live because boot services can no longer free it.
        core::mem::forget(final_map);

        let map = normalized.stats();
        let mut frames = FrameAllocator::from_map(&normalized).map_err(|_| ())?;
        if let Some(framebuffer) = framebuffer {
            frames
                .reserve_range(framebuffer_device_range(framebuffer)?)
                .map_err(|_| ())?;
        }
        let probe = frames.allocate().map_err(|_| ())?;
        frames.free(probe).map_err(|_| ())?;
        if !kllm_machine::write(b"frame bitmap: ready\n") {
            return Err(());
        }
        if !kllm_machine::probe_allocation_failure() {
            return Err(());
        }
        if !kllm_machine::write(b"allocation failure path: bounded\n") {
            return Err(());
        }
        kllm_machine::install_exception_vectors(prepared.boot_memory.exception_stack)
            .map_err(|_| ())?;
        if !kllm_machine::write(b"exception vectors: ready\n") {
            return Err(());
        }
        let mmu = kllm_machine::install_mmu(&mapping_plan, prepared.boot_memory.page_tables)
            .map_err(|_| ())?;
        if mmu.mapped_pages == 0 || mmu.table_pages == 0 {
            return Err(());
        }
        if !kllm_machine::write(b"owned page tables: ready\n")
            || !kllm_machine::write(b"W^X mappings: active\n")
        {
            return Err(());
        }
        kllm_machine::initialize_input_interrupts(InputQueueConfig::tiny()).map_err(|_| ())?;
        if !kllm_machine::write(b"interrupt-driven input: ready\n") {
            return Err(());
        }
        Ok(OwnedAccounting {
            map,
            frames,
            #[cfg(feature = "acceptance-probes")]
            execute_probe_address: usize::try_from(prepared.boot_memory.heap.start())
                .map_err(|_| ())?,
            task_stacks: prepared.boot_memory.task_stacks,
            framebuffer,
            kernel_plan: mapping_plan,
        })
    }

    fn reserve_and_install_heap() -> Result<BootMemory, ()> {
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
            allocate_task_stack(&mut allocator)?,
            allocate_task_stack(&mut allocator)?,
            allocate_task_stack(&mut allocator)?,
        ];
        allocator.seal();
        let heap_start = usize::try_from(heap.start()).map_err(|_| ())?;
        let heap_bytes = usize::try_from(heap.byte_count()).map_err(|_| ())?;
        if !kllm_machine::initialize_heap(heap_start, heap_bytes) {
            return Err(());
        }
        let heap_pages = heap.byte_count() / BASE_PAGE_SIZE;
        let table_pages = page_tables.byte_count() / BASE_PAGE_SIZE;
        Ok(BootMemory {
            arena,
            heap: PhysicalRange::from_pages(heap.start(), heap_pages).map_err(|_| ())?,
            page_tables: PhysicalRange::from_pages(page_tables.start(), table_pages)
                .map_err(|_| ())?,
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

    fn allocate_task_stack(allocator: &mut BootAllocator) -> Result<TaskStackLayout, ()> {
        let lower_guard = allocator
            .allocate(TASK_GUARD_BYTES, BASE_PAGE_SIZE)
            .map_err(|_| ())?;
        let stack = allocator
            .allocate(TASK_STACK_BYTES, BASE_PAGE_SIZE)
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

    fn allocation_range(allocation: kllm_memory::BootAllocation) -> Result<PhysicalRange, ()> {
        PhysicalRange::from_pages(allocation.start(), allocation.byte_count() / BASE_PAGE_SIZE)
            .map_err(|_| ())
    }

    fn build_mapping_plan(
        memory_map: &MemoryMapOwned,
        image: &kllm_machine::ImageLayout,
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
        if let Some(device) = console_device_range() {
            insert_identity(
                &mut plan,
                device,
                MappingPermissions::READ_WRITE,
                MappingMemoryType::Device,
                MappingOwner::MachineDevice,
            )?;
        }
        for device in kllm_machine::input_device_ranges()
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

    fn capture_framebuffer() -> Option<FramebufferDescriptor> {
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

    fn framebuffer_device_range(framebuffer: FramebufferDescriptor) -> Result<PhysicalRange, ()> {
        let page_mask = BASE_PAGE_SIZE - 1;
        let start = framebuffer.base_address() & !page_mask;
        let byte_len = u64::try_from(framebuffer.byte_len()).map_err(|_| ())?;
        let end = framebuffer.base_address().checked_add(byte_len).ok_or(())?;
        let aligned_end = end.checked_add(page_mask).ok_or(())? & !page_mask;
        let page_count = aligned_end.checked_sub(start).ok_or(())? / BASE_PAGE_SIZE;
        PhysicalRange::from_pages(start, page_count).map_err(|_| ())
    }

    fn insert_runtime_excluding(
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

    fn insert_identity(
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

    const fn is_runtime_ram(memory_type: boot::MemoryType) -> bool {
        memory_type.0 == boot::MemoryType::CONVENTIONAL.0
            || memory_type.0 == boot::MemoryType::BOOT_SERVICES_CODE.0
            || memory_type.0 == boot::MemoryType::BOOT_SERVICES_DATA.0
    }

    fn console_device_range() -> Option<PhysicalRange> {
        #[cfg(target_arch = "x86_64")]
        {
            None
        }
        #[cfg(target_arch = "aarch64")]
        {
            PhysicalRange::from_pages(0x0900_0000, 1).ok()
        }
    }

    fn normalize_final_map(
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

    const fn is_reclaimable_after_handoff(memory_type: boot::MemoryType) -> bool {
        memory_type.0 == boot::MemoryType::CONVENTIONAL.0
            || memory_type.0 == boot::MemoryType::BOOT_SERVICES_CODE.0
            || memory_type.0 == boot::MemoryType::BOOT_SERVICES_DATA.0
    }

    fn run_owned(mut accounting: OwnedAccounting) -> ! {
        let mut scheduler = Scheduler::new(TASK_STACK_COUNT)
            .unwrap_or_else(|_| fatal(b"fatal: cannot create task scheduler\n"));
        run_cooperative_services(&mut scheduler, &accounting)
            .unwrap_or_else(|()| fatal(b"fatal: cooperative task verification failed\n"));
        if !kllm_machine::write(b"cooperative tasks: deterministic\n")
            || !kllm_machine::write(b"task stack guards: active\n")
            || !kllm_machine::write(b"task resources: reclaimed\n")
        {
            fatal(b"fatal: task diagnostic failed\n");
        }
        run_isolation_verification(&mut scheduler, &mut accounting)
            .unwrap_or_else(|()| fatal(b"fatal: Stage 6 isolation verification failed\n"));
        if !kllm_machine::write(b"isolated address spaces: active\n")
            || !kllm_machine::write(b"copied task messages: bounded\n")
            || !kllm_machine::write(b"isolated faults: contained\n")
            || !kllm_machine::write(b"isolated resources: reclaimed\n")
        {
            fatal(b"fatal: isolation diagnostic failed\n");
        }

        let capabilities = Capabilities::CONSOLE
            .union(Capabilities::FILESYSTEM)
            .union(Capabilities::MACHINE_CONTROL);
        let stack_resource = StackResource::new(2, TASK_STACK_PAGES)
            .unwrap_or_else(|_| fatal(b"fatal: invalid shell task stack\n"));
        let shell_id = scheduler
            .spawn(capabilities, stack_resource)
            .unwrap_or_else(|_| fatal(b"fatal: cannot spawn shell task\n"));
        let dispatched = scheduler
            .dispatch_next(capabilities)
            .unwrap_or_else(|_| fatal(b"fatal: shell task dispatch failed\n"));
        if dispatched != Some(shell_id)
            || scheduler.stats().owned_stack_pages != u32::from(TASK_STACK_PAGES)
        {
            fatal(b"fatal: shell task accounting failed\n");
        }
        let stack = accounting.task_stacks[2].stack;
        let mut shell_task = ShellTask {
            accounting: &accounting,
            capabilities,
            stack,
        };
        let result = kllm_machine::run_task_step(stack, &mut shell_task, run_shell_task);
        if result.is_err() {
            fatal(b"fatal: shell task stack rejected\n");
        }
        fatal(b"fatal: shell task returned\n")
    }

    fn run_cooperative_services(
        scheduler: &mut Scheduler,
        accounting: &OwnedAccounting,
    ) -> Result<(), ()> {
        for layout in accounting.task_stacks {
            if layout.lower_guard.end() != layout.stack.start()
                || layout.stack.end() != layout.upper_guard.start()
                || layout.lower_guard.page_count() != 1
                || layout.stack.page_count() != u64::from(TASK_STACK_PAGES)
                || layout.upper_guard.page_count() != 1
            {
                return Err(());
            }
        }

        let first_resource = StackResource::new(0, TASK_STACK_PAGES).map_err(|_| ())?;
        let second_resource = StackResource::new(1, TASK_STACK_PAGES).map_err(|_| ())?;
        let first = scheduler
            .spawn(Capabilities::SERVICE, first_resource)
            .map_err(|_| ())?;
        let second = scheduler
            .spawn(Capabilities::SERVICE, second_resource)
            .map_err(|_| ())?;
        let mut first_service = CooperativeService {
            remaining_yields: 2,
            completed_steps: 0,
        };
        let mut second_service = CooperativeService {
            remaining_yields: 3,
            completed_steps: 0,
        };
        let mut completed = 0_u8;
        let mut reusable = None;
        while completed < 2 {
            let id = scheduler
                .dispatch_next(Capabilities::SERVICE)
                .map_err(|_| ())?
                .ok_or(())?;
            let step = if id == first {
                kllm_machine::run_task_step(
                    accounting.task_stacks[0].stack,
                    &mut first_service,
                    cooperative_service_step,
                )
                .map_err(|_| ())?
            } else if id == second {
                kllm_machine::run_task_step(
                    accounting.task_stacks[1].stack,
                    &mut second_service,
                    cooperative_service_step,
                )
                .map_err(|_| ())?
            } else {
                return Err(());
            };
            if complete_task_step(scheduler, id, step, &mut reusable)? {
                completed = completed.checked_add(1).ok_or(())?;
            }
        }
        let stats = scheduler.stats();
        if stats.yields != 5
            || stats.reaped != 2
            || stats.owned_stack_pages != 0
            || first_service.completed_steps != 3
            || second_service.completed_steps != 4
        {
            return Err(());
        }

        let reusable = reusable.ok_or(())?;
        let slot = usize::from(reusable.slot());
        let reused = scheduler
            .spawn(Capabilities::SERVICE, reusable)
            .map_err(|_| ())?;
        let dispatched = scheduler
            .dispatch_next(Capabilities::SERVICE)
            .map_err(|_| ())?;
        if dispatched != Some(reused) || slot >= accounting.task_stacks.len() {
            return Err(());
        }
        let mut reuse_service = CooperativeService {
            remaining_yields: 0,
            completed_steps: 0,
        };
        let step = kllm_machine::run_task_step(
            accounting.task_stacks[slot].stack,
            &mut reuse_service,
            cooperative_service_step,
        )
        .map_err(|_| ())?;
        let mut ignored = None;
        if !complete_task_step(scheduler, reused, step, &mut ignored)?
            || scheduler.stats().reaped != 3
            || scheduler.stats().owned_stack_pages != 0
        {
            return Err(());
        }
        Ok(())
    }

    fn run_isolation_verification(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        let mut dispatcher = Dispatcher::new(1, 4).map_err(|_| ())?;
        let (port, kernel_handle) = dispatcher
            .register(Box::new(EchoService), Rights::CALL)
            .map_err(|_| ())?;
        let baseline_frames = accounting.frames.free_frames();

        let first = run_one_isolated(
            scheduler,
            accounting,
            &mut dispatcher,
            port,
            IsolationProbe::Success,
            0,
        )?;
        if accounting.frames.free_frames() != baseline_frames {
            return Err(());
        }
        #[cfg(target_arch = "x86_64")]
        let fault_probes = [
            IsolationProbe::Translation,
            IsolationProbe::WritePermission,
            IsolationProbe::ExecutePermission,
            IsolationProbe::IllegalInstruction,
            IsolationProbe::UnexpectedEntry,
            IsolationProbe::InvalidOpcode,
            IsolationProbe::InvalidPointer,
            IsolationProbe::OversizeMessage,
            IsolationProbe::InvalidStatus,
        ];
        #[cfg(target_arch = "aarch64")]
        let fault_probes = [
            IsolationProbe::Translation,
            IsolationProbe::WritePermission,
            IsolationProbe::ExecutePermission,
            IsolationProbe::IllegalInstruction,
            IsolationProbe::UnexpectedEntry,
            IsolationProbe::InvalidOpcode,
            IsolationProbe::InvalidCallEncoding,
            IsolationProbe::InvalidPointer,
            IsolationProbe::OversizeMessage,
            IsolationProbe::InvalidStatus,
        ];
        let expected_contained_faults = u32::try_from(fault_probes.len()).map_err(|_| ())?;
        for (index, probe) in fault_probes.into_iter().enumerate() {
            let resource = run_one_isolated(
                scheduler,
                accounting,
                &mut dispatcher,
                port,
                probe,
                u8::try_from(index + 1).map_err(|_| ())?,
            )?;
            if accounting.frames.free_frames() != baseline_frames || resource != first {
                return Err(());
            }
        }
        let reused = run_one_isolated(
            scheduler,
            accounting,
            &mut dispatcher,
            port,
            IsolationProbe::Success,
            0,
        )?;
        let stats = scheduler.stats();
        let kernel_reply = dispatcher
            .call(kernel_handle, 1, b"kernel authority retained")
            .map_err(|_| ())?;
        let dispatch_stats = dispatcher.stats();
        if reused != first
            || accounting.frames.free_frames() != baseline_frames
            || stats.owned_address_spaces != 0
            || stats.owned_isolation_pages != 0
            || stats.owned_handles != 0
            || stats.contained_faults != expected_contained_faults
            || kernel_reply.status() != ReplyStatus::Success
            || kernel_reply.payload() != b"kernel authority retained"
            || dispatch_stats.live_ports != 1
            || dispatch_stats.live_handles != 1
        {
            return Err(());
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn run_one_isolated(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        dispatcher: &mut Dispatcher,
        port: kllm_dispatch::PortId,
        probe: IsolationProbe,
        address_space_slot: u8,
    ) -> Result<u64, ()> {
        let table_pages = u16::try_from(ISOLATED_TABLE_PAGES).map_err(|_| ())?;
        let private_pages = u16::try_from(ISOLATED_PRIVATE_PAGES).map_err(|_| ())?;
        let stack_pages = u16::try_from(ISOLATED_STACK_PAGES).map_err(|_| ())?;
        let isolation = IsolationResource::new(address_space_slot, table_pages, private_pages, 1)
            .map_err(|_| ())?;
        let stack_resource = StackResource::new(address_space_slot, stack_pages).map_err(|_| ())?;

        let allocation = allocate_isolated(&mut accounting.frames)?;
        if prepare_isolated_memory(&allocation, probe).is_err() {
            reclaim_isolated(&mut accounting.frames, allocation)?;
            return Err(());
        }
        let Ok(plan) = build_isolated_plan(&accounting.kernel_plan, &allocation) else {
            reclaim_isolated(&mut accounting.frames, allocation)?;
            return Err(());
        };
        let Ok(address_space) = kllm_machine::build_user_address_space(&plan, allocation.tables)
        else {
            reclaim_isolated(&mut accounting.frames, allocation)?;
            return Err(());
        };
        if address_space.stats().table_pages == 0
            || address_space.stats().table_pages > ISOLATED_TABLE_PAGES
        {
            reclaim_isolated(&mut accounting.frames, allocation)?;
            return Err(());
        }
        let Ok(task_id) =
            scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
        else {
            reclaim_isolated(&mut accounting.frames, allocation)?;
            return Err(());
        };
        let mut live_owner = None;
        let execution = (|| -> Result<(), ()> {
            if scheduler
                .dispatch_next(Capabilities::SERVICE)
                .map_err(|_| ())?
                != Some(task_id)
            {
                return Err(());
            }
            let owner = HandleOwner::isolated(task_id.get()).map_err(|_| ())?;
            let handle = dispatcher
                .open_owned(port, Rights::CALL, owner)
                .map_err(|_| ())?;
            live_owner = Some(owner);

            let mut copied_bytes = [0_u8; kllm_dispatch::MAX_MESSAGE_BYTES];
            let stack_top = USER_STACK_BASE
                .checked_add(ISOLATED_STACK_PAGES.checked_mul(BASE_PAGE_SIZE).ok_or(())?)
                .ok_or(())?;
            let outcome = kllm_machine::run_isolated(
                address_space,
                USER_CODE_BASE,
                stack_top,
                &mut copied_bytes,
            )
            .map_err(|_| ())?;
            match (probe.expected_fault(), outcome) {
                (
                    None,
                    kllm_machine::IsolatedOutcome::Exited {
                        status,
                        message_bytes,
                    },
                ) => {
                    if status != 0 || message_bytes != ISOLATED_MESSAGE.len() {
                        return Err(());
                    }
                    let copied = CopiedMessage::copy_from_untrusted(&copied_bytes[..message_bytes])
                        .map_err(|_| ())?;
                    if copied.as_bytes() != ISOLATED_MESSAGE {
                        return Err(());
                    }
                    let reply = dispatcher
                        .call(handle, 1, copied.as_bytes())
                        .map_err(|_| ())?;
                    if reply.status() != ReplyStatus::Success || reply.payload() != ISOLATED_MESSAGE
                    {
                        return Err(());
                    }
                    scheduler.exit_current(task_id, 0).map_err(|_| ())?;
                }
                (Some(expected), kllm_machine::IsolatedOutcome::Faulted(fault)) => {
                    let fault = match fault {
                        kllm_machine::IsolatedFault::Translation => TaskFault::Translation,
                        kllm_machine::IsolatedFault::Permission => TaskFault::Permission,
                        kllm_machine::IsolatedFault::IllegalInstruction => {
                            TaskFault::IllegalInstruction
                        }
                        kllm_machine::IsolatedFault::InvalidCall => TaskFault::InvalidCall,
                    };
                    if fault != expected || copied_bytes.iter().any(|byte| *byte != 0) {
                        return Err(());
                    }
                    scheduler.fault_current(task_id, fault).map_err(|_| ())?;
                }
                _ => return Err(()),
            }
            if dispatcher.close_owner(owner).map_err(|_| ())? != 1 {
                return Err(());
            }
            live_owner = None;
            if dispatcher.call(handle, 1, b"stale")
                != Err(kllm_dispatch::DispatchError::InvalidHandle)
            {
                return Err(());
            }
            Ok(())
        })();
        if execution.is_err() {
            rollback_isolated_task(
                scheduler,
                task_id,
                dispatcher,
                live_owner,
                &mut accounting.frames,
                allocation,
            )?;
            return Err(());
        }
        let Ok(reaped) = scheduler.reap(task_id) else {
            rollback_isolated_task(
                scheduler,
                task_id,
                dispatcher,
                live_owner,
                &mut accounting.frames,
                allocation,
            )?;
            return Err(());
        };
        let valid_reap = reaped.isolation == Some(isolation)
            && reaped.stack.slot() == address_space_slot
            && reaped.fault == probe.expected_fault();
        let allocation_start = allocation.complete.start();
        reclaim_isolated(&mut accounting.frames, allocation)?;
        if !valid_reap {
            return Err(());
        }
        Ok(allocation_start)
    }

    fn rollback_isolated_task(
        scheduler: &mut Scheduler,
        task_id: TaskId,
        dispatcher: &mut Dispatcher,
        owner: Option<HandleOwner>,
        frames: &mut FrameAllocator,
        allocation: IsolatedAllocation,
    ) -> Result<(), ()> {
        if let Some(owner) = owner {
            dispatcher.close_owner(owner).map_err(|_| ())?;
        }
        match scheduler.task(task_id).map_err(|_| ())?.state() {
            TaskState::Ready => scheduler.cancel_ready(task_id, 1).map_err(|_| ())?,
            TaskState::Running => scheduler.exit_current(task_id, 1).map_err(|_| ())?,
            TaskState::Exited | TaskState::Faulted => {}
        }
        scheduler.reap(task_id).map_err(|_| ())?;
        reclaim_isolated(frames, allocation)
    }

    fn allocate_isolated(frames: &mut FrameAllocator) -> Result<IsolatedAllocation, ()> {
        let complete = frames
            .allocate_contiguous(ISOLATED_RESOURCE_PAGES, 1)
            .map_err(|_| ())?;
        let derived = (|| {
            let tables = PhysicalRange::from_pages(complete.start(), ISOLATED_TABLE_PAGES)
                .map_err(|_| ())?;
            let code =
                PhysicalRange::from_pages(tables.end(), ISOLATED_CODE_PAGES).map_err(|_| ())?;
            let data =
                PhysicalRange::from_pages(code.end(), ISOLATED_DATA_PAGES).map_err(|_| ())?;
            let stack =
                PhysicalRange::from_pages(data.end(), ISOLATED_STACK_PAGES).map_err(|_| ())?;
            if stack.end() != complete.end() {
                return Err(());
            }
            Ok(IsolatedAllocation {
                complete,
                tables,
                code,
                data,
                stack,
            })
        })();
        if derived.is_err() {
            frames.free_range(complete).map_err(|_| ())?;
        }
        derived
    }

    fn prepare_isolated_memory(
        allocation: &IsolatedAllocation,
        probe: IsolationProbe,
    ) -> Result<(), ()> {
        kllm_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
        let code = isolated_program(probe)?;
        kllm_machine::copy_to_physical(allocation.code, 0, &code).map_err(|_| ())?;
        if matches!(
            probe,
            IsolationProbe::Success
                | IsolationProbe::InvalidOpcode
                | IsolationProbe::InvalidCallEncoding
                | IsolationProbe::InvalidPointer
                | IsolationProbe::OversizeMessage
                | IsolationProbe::InvalidStatus
        ) {
            kllm_machine::copy_to_physical(allocation.data, 0, ISOLATED_MESSAGE).map_err(|_| ())?;
        }
        Ok(())
    }

    #[allow(clippy::needless_pass_by_value)] // Consuming the token prevents double teardown.
    fn reclaim_isolated(
        frames: &mut FrameAllocator,
        allocation: IsolatedAllocation,
    ) -> Result<(), ()> {
        kllm_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
        frames.free_range(allocation.complete).map_err(|_| ())
    }

    fn build_isolated_plan(
        kernel: &MappingPlan,
        allocation: &IsolatedAllocation,
    ) -> Result<MappingPlan, ()> {
        let mut plan = MappingPlan::new();
        let mut protected_code = false;
        for mapping in kernel.mappings() {
            let physical = mapping.physical_range();
            if allocation.code.start() < physical.end() && physical.start() < allocation.code.end()
            {
                if protected_code
                    || allocation.code.start() < physical.start()
                    || allocation.code.end() > physical.end()
                    || mapping.virtual_range().start() != physical.start()
                    || mapping.virtual_range().end() != physical.end()
                    || mapping.permissions() != MappingPermissions::READ_WRITE
                {
                    return Err(());
                }
                insert_identity_segment(
                    &mut plan,
                    *mapping,
                    physical.start(),
                    allocation.code.start(),
                )?;
                insert_identity_segment_with_permissions(
                    &mut plan,
                    *mapping,
                    allocation.code.start(),
                    allocation.code.end(),
                    MappingPermissions::READ_ONLY,
                )?;
                insert_identity_segment(
                    &mut plan,
                    *mapping,
                    allocation.code.end(),
                    physical.end(),
                )?;
                protected_code = true;
            } else {
                plan.insert(*mapping).map_err(|_| ())?;
            }
        }
        if !protected_code {
            return Err(());
        }
        for (virtual_start, physical, permissions) in [
            (
                USER_CODE_BASE,
                allocation.code,
                MappingPermissions::READ_EXECUTE,
            ),
            (
                USER_DATA_BASE,
                allocation.data,
                MappingPermissions::READ_WRITE,
            ),
            (
                USER_STACK_BASE,
                allocation.stack,
                MappingPermissions::READ_WRITE,
            ),
        ] {
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
            plan.insert(mapping).map_err(|_| ())?;
        }
        if !plan.enforces_global_w_xor_x() {
            return Err(());
        }
        Ok(plan)
    }

    fn insert_identity_segment(
        plan: &mut MappingPlan,
        template: Mapping,
        start: u64,
        end: u64,
    ) -> Result<(), ()> {
        insert_identity_segment_with_permissions(plan, template, start, end, template.permissions())
    }

    fn insert_identity_segment_with_permissions(
        plan: &mut MappingPlan,
        template: Mapping,
        start: u64,
        end: u64,
        permissions: MappingPermissions,
    ) -> Result<(), ()> {
        if start == end {
            return Ok(());
        }
        let pages = end.checked_sub(start).ok_or(())? / BASE_PAGE_SIZE;
        let range = PhysicalRange::from_pages(start, pages).map_err(|_| ())?;
        let mapping = Mapping::identity(
            range,
            permissions,
            template.memory_type(),
            template.owner(),
            template.lifetime(),
            template.remappable(),
        )
        .map_err(|_| ())?;
        plan.insert(mapping).map_err(|_| ())
    }

    fn isolated_program(probe: IsolationProbe) -> Result<Vec<u8>, ()> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut code = Vec::new();
            match probe {
                IsolationProbe::Translation => {
                    x86_mov_rax(&mut code, USER_UNMAPPED_BASE);
                    code.extend_from_slice(&[0x48, 0x8b, 0x00]);
                }
                IsolationProbe::WritePermission => {
                    x86_mov_rax(&mut code, USER_CODE_BASE);
                    code.extend_from_slice(&[0xc6, 0x00, 0x00]);
                }
                IsolationProbe::ExecutePermission => {
                    x86_mov_rax(&mut code, USER_DATA_BASE);
                    code.extend_from_slice(&[0xff, 0xe0]);
                }
                IsolationProbe::IllegalInstruction => code.extend_from_slice(&[0x0f, 0x0b]),
                IsolationProbe::UnexpectedEntry => code.extend_from_slice(&[0x0f, 0x05]),
                IsolationProbe::Success
                | IsolationProbe::InvalidOpcode
                | IsolationProbe::InvalidCallEncoding
                | IsolationProbe::InvalidPointer
                | IsolationProbe::OversizeMessage
                | IsolationProbe::InvalidStatus => {
                    let (opcode, address, length, status) = exit_call_parameters(probe)?;
                    if matches!(
                        probe,
                        IsolationProbe::Success | IsolationProbe::InvalidOpcode
                    ) {
                        // Enter with hostile user-controlled flags. The native
                        // gate must clear DF for Rust and AC before SMAP-aware
                        // validation/copying, then restore kernel RFLAGS.
                        code.push(0xfd);
                        code.extend_from_slice(&[
                            0x9c, 0x81, 0x0c, 0x24, 0x00, 0x00, 0x04, 0x00, 0x9d,
                        ]);
                    }
                    code.push(0xb8);
                    code.extend_from_slice(&opcode.to_le_bytes());
                    code.extend_from_slice(&[0x48, 0xbf]);
                    code.extend_from_slice(&address.to_le_bytes());
                    code.push(0xbe);
                    code.extend_from_slice(&length.to_le_bytes());
                    code.push(0xba);
                    code.extend_from_slice(&status.to_le_bytes());
                    code.extend_from_slice(&[0xcd, 0x80]);
                }
            }
            code.extend_from_slice(&[0x0f, 0x0b]);
            Ok(code)
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut words = Vec::new();
            match probe {
                IsolationProbe::Translation => {
                    emit_aarch64_immediate(&mut words, 1, USER_UNMAPPED_BASE);
                    words.push(0xf940_0020);
                }
                IsolationProbe::WritePermission => {
                    emit_aarch64_immediate(&mut words, 1, USER_CODE_BASE);
                    words.push(0xf900_003f);
                }
                IsolationProbe::ExecutePermission => {
                    emit_aarch64_immediate(&mut words, 1, USER_DATA_BASE);
                    words.push(0xd61f_0020);
                }
                IsolationProbe::IllegalInstruction => words.push(0xd420_0000),
                IsolationProbe::UnexpectedEntry => words.push(0xd400_0002),
                IsolationProbe::Success
                | IsolationProbe::InvalidOpcode
                | IsolationProbe::InvalidCallEncoding
                | IsolationProbe::InvalidPointer
                | IsolationProbe::OversizeMessage
                | IsolationProbe::InvalidStatus => {
                    let (opcode, address, length, status) = exit_call_parameters(probe)?;
                    emit_aarch64_immediate(&mut words, 0, u64::from(opcode));
                    emit_aarch64_immediate(&mut words, 1, address);
                    emit_aarch64_immediate(&mut words, 2, u64::from(length));
                    emit_aarch64_immediate(&mut words, 3, u64::from(status));
                    words.push(if probe == IsolationProbe::InvalidCallEncoding {
                        0xd400_0021
                    } else {
                        0xd400_0001
                    });
                }
            }
            words.push(0xd420_0000);
            let mut code = Vec::new();
            code.try_reserve_exact(words.len() * 4).map_err(|_| ())?;
            for word in words {
                code.extend_from_slice(&word.to_le_bytes());
            }
            Ok(code)
        }
    }

    fn exit_call_parameters(probe: IsolationProbe) -> Result<(u32, u64, u32, u32), ()> {
        let message_len = u32::try_from(ISOLATED_MESSAGE.len()).map_err(|_| ())?;
        Ok(match probe {
            IsolationProbe::Success => (1, USER_DATA_BASE, message_len, 0),
            IsolationProbe::InvalidOpcode => (99, USER_DATA_BASE, message_len, 0),
            IsolationProbe::InvalidCallEncoding => {
                #[cfg(target_arch = "x86_64")]
                {
                    (99, USER_DATA_BASE, message_len, 0)
                }
                #[cfg(target_arch = "aarch64")]
                {
                    (1, USER_DATA_BASE, message_len, 0)
                }
            }
            IsolationProbe::InvalidPointer => (1, USER_UNMAPPED_BASE, message_len, 0),
            IsolationProbe::OversizeMessage => (
                1,
                USER_DATA_BASE,
                u32::try_from(kllm_dispatch::MAX_MESSAGE_BYTES + 1).map_err(|_| ())?,
                0,
            ),
            IsolationProbe::InvalidStatus => (1, USER_DATA_BASE, message_len, 256),
            IsolationProbe::Translation
            | IsolationProbe::WritePermission
            | IsolationProbe::ExecutePermission
            | IsolationProbe::IllegalInstruction
            | IsolationProbe::UnexpectedEntry => return Err(()),
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn x86_mov_rax(code: &mut Vec<u8>, value: u64) {
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&value.to_le_bytes());
    }

    #[cfg(target_arch = "aarch64")]
    fn emit_aarch64_immediate(words: &mut Vec<u32>, register: u8, value: u64) {
        let low = (value & 0xffff) as u32;
        words.push(0xd280_0000 | (low << 5) | u32::from(register));
        for halfword in 1..4_u32 {
            let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
            words.push(0xf280_0000 | (halfword << 21) | (immediate << 5) | u32::from(register));
        }
    }

    fn cooperative_service_step(service: &mut CooperativeService) -> TaskStep {
        service.completed_steps = service.completed_steps.saturating_add(1);
        if service.remaining_yields == 0 {
            TaskStep::ExitSuccess
        } else {
            service.remaining_yields -= 1;
            TaskStep::Yield
        }
    }

    fn complete_task_step(
        scheduler: &mut Scheduler,
        id: TaskId,
        step: TaskStep,
        reusable: &mut Option<StackResource>,
    ) -> Result<bool, ()> {
        match step {
            TaskStep::Yield => {
                scheduler.yield_current(id).map_err(|_| ())?;
                Ok(false)
            }
            TaskStep::ExitSuccess | TaskStep::ExitFailure => {
                let status = u8::from(step != TaskStep::ExitSuccess);
                scheduler.exit_current(id, status).map_err(|_| ())?;
                let reaped = scheduler.reap(id).map_err(|_| ())?;
                if reaped.exit_status != status {
                    return Err(());
                }
                if reusable.is_none() {
                    *reusable = Some(reaped.stack);
                }
                Ok(true)
            }
        }
    }

    fn run_shell_task(task: &mut ShellTask<'_>) -> TaskStep {
        let stack_pointer = usize_as_u64(kllm_machine::current_stack_pointer());
        if !task.stack.contains(stack_pointer)
            || !task.capabilities.contains(Capabilities::CONSOLE)
            || !task.capabilities.contains(Capabilities::FILESYSTEM)
        {
            fatal(b"fatal: shell task authority or stack invalid\n");
        }
        let mut dispatcher = Dispatcher::new(1, 1)
            .unwrap_or_else(|_| fatal(b"fatal: cannot create service dispatcher\n"));
        let shell_console = NativeShellConsole::new(task.accounting.framebuffer);
        let framebuffer_ready = shell_console.has_framebuffer();
        let (_console_port, console_handle) = dispatcher
            .register(Box::new(ConsoleService::new(shell_console)), Rights::CALL)
            .unwrap_or_else(|_| fatal(b"fatal: cannot register console service\n"));
        let mut console = DispatchedOutput::new(&mut dispatcher, console_handle);
        if write_all(&mut console, b"in-process console dispatch: ready\n").is_err() {
            fatal(b"fatal: console service request failed\n");
        }
        if framebuffer_ready
            && write_all(&mut console, b"owned framebuffer text console: ready\n").is_err()
        {
            fatal(b"fatal: framebuffer console write failed\n");
        }
        let mut namespace = Namespace::new(RamFsQuota::default());
        if namespace.mount_embedded(ROOTFS).is_err() {
            fatal(b"fatal: cannot mount embedded root\n");
        }
        let initial_snapshot = machine_snapshot(task.accounting);
        let machine_control = task.capabilities.contains(Capabilities::MACHINE_CONTROL);
        let Ok(mut shell) =
            Shell::new(namespace, architecture(), initial_snapshot, machine_control)
        else {
            fatal(b"fatal: cannot compose namespace\n");
        };
        let editor_config = EditorConfig::tiny();
        if editor_config.max_line_bytes() > MAX_LINE_BYTES {
            fatal(b"fatal: editor line policy exceeds shell parser policy\n");
        }
        let completion_config = CompletionConfig::tiny();
        let mut decoder = InputDecoder::new(editor_config.input());
        let mut keyboard = Ps2Set1Decoder::new(KeyboardConfig::tiny());
        let mut editor = LineEditor::new(editor_config);

        if write_all(&mut console, b"memory and console: owned; type 'help'\n").is_err() {
            fatal(b"fatal: native console write failed\n");
        }

        loop {
            refresh_shell_stats(&mut shell, task.accounting);
            let mut prompt = String::from("shell:");
            prompt.push_str(shell.cwd());
            prompt.push_str("> ");
            if write_all(&mut console, prompt.as_bytes()).is_err() {
                fatal(b"fatal: native console write failed\n");
            }
            let Ok(line) = read_edited_line(
                &mut editor,
                &mut decoder,
                &mut keyboard,
                &shell,
                completion_config,
                &prompt,
                &mut console,
            ) else {
                fatal(b"fatal: native console input failed\n");
            };
            refresh_shell_stats(&mut shell, task.accounting);
            #[cfg(feature = "acceptance-probes")]
            if line == "mmu-probe write" {
                let _result = write_all(&mut console, b"probing read-only mapping\n");
                kllm_machine::trigger_write_fault(ROOTFS.as_ptr() as usize);
            }
            #[cfg(feature = "acceptance-probes")]
            if line == "mmu-probe execute" {
                let _result = write_all(&mut console, b"probing non-executable mapping\n");
                kllm_machine::trigger_execute_fault(task.accounting.execute_probe_address);
            }
            #[cfg(feature = "acceptance-probes")]
            if line == "mmu-probe exception" {
                let _result = write_all(&mut console, b"probing native exception vector\n");
                kllm_machine::trigger_native_exception();
            }
            #[cfg(feature = "acceptance-probes")]
            if line == "mmu-probe fatal" {
                fatal(b"fatal: acceptance post-handoff failure\n");
            }
            #[cfg(feature = "acceptance-probes")]
            if line == "task-probe guard" {
                let _result = write_all(&mut console, b"probing task stack guard\n");
                let guard = task.accounting.task_stacks[2].lower_guard.start();
                let guard = usize::try_from(guard)
                    .unwrap_or_else(|_| fatal(b"fatal: guard address unsupported\n"));
                kllm_machine::trigger_write_fault(guard);
            }
            let mut input = EmptyInput;
            let mut error = NativeConsole;
            let _status = shell.execute(&line, &mut input, &mut console, &mut error);
            if shell.halt_requested() {
                let _result = write_all(&mut console, b"halting: parking CPU\n");
                kllm_machine::park();
            }
        }
    }

    fn refresh_shell_stats(shell: &mut Shell, accounting: &OwnedAccounting) {
        shell.set_machine_memory(machine_snapshot(accounting));
        shell.set_machine_input(kllm_machine::input_interrupt_stats());
    }

    fn read_edited_line(
        editor: &mut LineEditor,
        decoder: &mut InputDecoder,
        keyboard: &mut Ps2Set1Decoder,
        shell: &Shell,
        completion_config: CompletionConfig,
        prompt: &str,
        console: &mut dyn Output,
    ) -> Result<String, ()> {
        loop {
            let key = loop {
                let event = kllm_machine::wait_for_input_event();
                let key = match event.source() {
                    InputSource::Serial => decoder.push(event.byte()),
                    InputSource::Keyboard => keyboard.push(event.byte()),
                };
                if let Some(key) = key {
                    break key;
                }
            };
            match editor.handle(key) {
                EditorOutcome::Changed => redraw_editor(editor, prompt, console)?,
                EditorOutcome::Submitted(line) => {
                    write_all(console, b"\n")?;
                    return Ok(line);
                }
                EditorOutcome::Cancelled => {
                    write_all(console, b"^C\n")?;
                    return Ok(String::new());
                }
                EditorOutcome::ClearRequested => {
                    write_all(console, b"\x1b[2J\x1b[H")?;
                    redraw_editor(editor, prompt, console)?;
                }
                EditorOutcome::CompletionRequested => {
                    complete_editor(editor, shell, completion_config, prompt, console)?;
                }
                EditorOutcome::LimitReached => write_all(console, b"\x07")?,
                EditorOutcome::Ignored => {}
            }
        }
    }

    fn redraw_editor(
        editor: &LineEditor,
        prompt: &str,
        console: &mut dyn Output,
    ) -> Result<(), ()> {
        write_all(console, b"\r")?;
        write_all(console, prompt.as_bytes())?;
        write_all(console, editor.line().as_bytes())?;
        write_all(console, b"\x1b[K")?;
        let suffix_characters = editor.line()[editor.cursor()..].chars().count();
        if suffix_characters != 0 {
            let mut movement = String::new();
            write!(movement, "\x1b[{suffix_characters}D").map_err(|_| ())?;
            write_all(console, movement.as_bytes())?;
        }
        Ok(())
    }

    fn complete_editor(
        editor: &mut LineEditor,
        shell: &Shell,
        config: CompletionConfig,
        prompt: &str,
        console: &mut dyn Output,
    ) -> Result<(), ()> {
        let completion = shell.complete(editor.line(), editor.cursor(), config);
        if completion.candidates.is_empty() {
            write_all(console, b"\x07")?;
            return Ok(());
        }
        let current = &editor.line()[completion.replacement_start..completion.replacement_end];
        let Some(replacement) = completion.common_replacement() else {
            return Ok(());
        };
        let can_apply = !completion.truncated
            && (completion.candidates.len() == 1 || replacement.len() > current.len());
        if can_apply {
            let _outcome = editor.replace_range(
                completion.replacement_start,
                completion.replacement_end,
                replacement,
            );
            return redraw_editor(editor, prompt, console);
        }

        write_all(console, b"\n")?;
        for candidate in &completion.candidates {
            write_all(console, candidate.display.as_bytes())?;
            write_all(console, b"\n")?;
        }
        if completion.truncated {
            write_all(
                console,
                b"... completion list truncated by profile limits\n",
            )?;
        }
        redraw_editor(editor, prompt, console)
    }

    fn machine_snapshot(accounting: &OwnedAccounting) -> MachineMemorySnapshot {
        let heap = kllm_machine::heap_stats();
        MachineMemorySnapshot::kernel(
            accounting.map.usable_bytes(),
            accounting.map.reserved_bytes(),
            accounting.frames.total_frames(),
            accounting.frames.free_frames(),
            usize_as_u64(heap.total_bytes),
            usize_as_u64(heap.used_bytes),
            usize_as_u64(heap.high_water_bytes),
            usize_as_u64(heap.failed_allocations),
        )
    }

    const fn usize_as_u64(value: usize) -> u64 {
        value as u64
    }

    fn write_all(output: &mut dyn Output, bytes: &[u8]) -> Result<(), ()> {
        kllm_core::write_all(output, bytes).map_err(|_| ())
    }

    fn fatal(message: &[u8]) -> ! {
        let _written = kllm_machine::write(message);
        kllm_machine::park()
    }

    const fn architecture() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "x86_64"
        }
        #[cfg(target_arch = "aarch64")]
        {
            "aarch64"
        }
    }

    #[panic_handler]
    fn panic(_information: &PanicInfo<'_>) -> ! {
        fatal(b"fatal: kernel panic\n")
    }
}

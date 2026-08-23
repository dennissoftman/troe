//! UEFI-bootstrapped Stage 3 W^X owned-machine image.
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

    use kllm_core::{
        Input, MAX_LINE_BYTES, MachineMemorySnapshot, Output, StreamError, is_backspace,
    };
    use kllm_memory::{
        BASE_PAGE_SIZE, BootAllocator, FrameAllocator, MAX_FIRMWARE_REGIONS, Mapping,
        MappingLifetime, MappingMemoryType, MappingOwner, MappingPermissions, MappingPlan,
        MemoryMapStats, MemoryRegion, NormalizedMemoryMap, PhysicalRange, RegionKind,
    };
    use kllm_shell::Shell;
    use kllm_vfs::{Namespace, RamFsQuota};
    use uefi::boot;
    use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned};
    use uefi::prelude::*;

    const ROOTFS: &[u8] = include_bytes!("../../assets/root.kefs");
    const OWNED_HEAP_BYTES: u64 = 6 * 1024 * 1024;
    const PAGE_TABLE_BYTES: u64 = 2 * 1024 * 1024;
    const OWNED_STACK_BYTES: u64 = 128 * 1024;
    const EXCEPTION_STACK_BYTES: u64 = 16 * 1024;
    const BOOT_ARENA_PAGES: usize =
        ((OWNED_HEAP_BYTES + PAGE_TABLE_BYTES + OWNED_STACK_BYTES + EXCEPTION_STACK_BYTES)
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

    struct EmptyInput;

    impl Input for EmptyInput {
        fn read(&mut self, _destination: &mut [u8]) -> Result<usize, StreamError> {
            Ok(0)
        }
    }

    struct LineEditor {
        discard_leading_lf: bool,
    }

    struct OwnedAccounting {
        map: MemoryMapStats,
        frames: FrameAllocator,
        #[cfg(feature = "acceptance-probes")]
        execute_probe_address: usize,
    }

    #[derive(Clone, Copy)]
    struct BootMemory {
        arena: PhysicalRange,
        #[cfg(feature = "acceptance-probes")]
        heap: PhysicalRange,
        page_tables: PhysicalRange,
        stack: PhysicalRange,
        exception_stack: PhysicalRange,
    }

    struct PreparedHandoff {
        image_layout: kllm_machine::ImageLayout,
        boot_memory: BootMemory,
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
        write_all(console, b"kllm 0.1.0 UEFI bootstrap\n")?;
        write_all(console, b"preparing owned memory and native console\n")?;

        let image_layout = kllm_machine::loaded_image_layout().map_err(|_| ())?;
        let boot_memory = reserve_and_install_heap()?;
        kllm_machine::initialize_console();
        if !kllm_machine::write(b"native console: ready\n") {
            return Err(());
        }
        Ok(PreparedHandoff {
            image_layout,
            boot_memory,
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
        run_owned(&accounting)
    }

    fn complete_handoff(
        prepared: &PreparedHandoff,
        final_map: MemoryMapOwned,
    ) -> Result<OwnedAccounting, ()> {
        let reservations = [prepared.boot_memory.arena];
        let normalized = normalize_final_map(&final_map, &reservations)?;
        let mapping_plan = build_mapping_plan(
            &final_map,
            &prepared.image_layout,
            prepared.boot_memory.arena,
        )?;
        // The final-map buffer is LoaderData recorded as reserved in the map.
        // It must remain live because boot services can no longer free it.
        core::mem::forget(final_map);

        let map = normalized.stats();
        let mut frames = FrameAllocator::from_map(&normalized).map_err(|_| ())?;
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
        Ok(OwnedAccounting {
            map,
            frames,
            #[cfg(feature = "acceptance-probes")]
            execute_probe_address: usize::try_from(prepared.boot_memory.heap.start())
                .map_err(|_| ())?,
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
        allocator.seal();
        let heap_start = usize::try_from(heap.start()).map_err(|_| ())?;
        let heap_bytes = usize::try_from(heap.byte_count()).map_err(|_| ())?;
        if !kllm_machine::initialize_heap(heap_start, heap_bytes) {
            return Err(());
        }
        #[cfg(feature = "acceptance-probes")]
        let heap_pages = heap.byte_count() / BASE_PAGE_SIZE;
        let table_pages = page_tables.byte_count() / BASE_PAGE_SIZE;
        Ok(BootMemory {
            arena,
            #[cfg(feature = "acceptance-probes")]
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
        })
    }

    fn build_mapping_plan(
        memory_map: &MemoryMapOwned,
        image: &kllm_machine::ImageLayout,
        boot_arena: PhysicalRange,
    ) -> Result<MappingPlan, ()> {
        let mut plan = MappingPlan::new();
        for descriptor in memory_map.entries() {
            if !is_runtime_ram(descriptor.ty) {
                continue;
            }
            let range = PhysicalRange::from_pages(descriptor.phys_start, descriptor.page_count)
                .map_err(|_| ())?;
            insert_identity(
                &mut plan,
                range,
                MappingPermissions::READ_WRITE,
                MappingMemoryType::Normal,
                MappingOwner::KernelRuntime,
            )?;
        }
        insert_identity(
            &mut plan,
            boot_arena,
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
        )?;
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
        Ok(plan)
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

    fn run_owned(accounting: &OwnedAccounting) -> ! {
        let mut console = NativeConsole;
        let mut namespace = Namespace::new(RamFsQuota::default());
        if namespace.mount_embedded(ROOTFS).is_err() {
            fatal(b"fatal: cannot mount embedded root\n");
        }
        let initial_snapshot = machine_snapshot(accounting);
        let Ok(mut shell) = Shell::new(namespace, architecture(), initial_snapshot, true) else {
            fatal(b"fatal: cannot compose namespace\n");
        };
        let mut editor = LineEditor {
            discard_leading_lf: false,
        };

        if write_all(&mut console, b"kllm owns memory and console; type 'help'\n").is_err() {
            fatal(b"fatal: native console write failed\n");
        }

        loop {
            shell.set_machine_memory(machine_snapshot(accounting));
            if write_all(&mut console, b"kllm:").is_err()
                || write_all(&mut console, shell.cwd().as_bytes()).is_err()
                || write_all(&mut console, b"> ").is_err()
            {
                fatal(b"fatal: native console write failed\n");
            }
            let Ok(line) = editor.read_line(&mut console) else {
                fatal(b"fatal: native console input failed\n");
            };
            #[cfg(feature = "acceptance-probes")]
            if line == "mmu-probe write" {
                let _result = write_all(&mut console, b"probing read-only mapping\n");
                kllm_machine::trigger_write_fault(ROOTFS.as_ptr() as usize);
            }
            #[cfg(feature = "acceptance-probes")]
            if line == "mmu-probe execute" {
                let _result = write_all(&mut console, b"probing non-executable mapping\n");
                kllm_machine::trigger_execute_fault(accounting.execute_probe_address);
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
            let mut input = EmptyInput;
            let mut error = NativeConsole;
            let _status = shell.execute(&line, &mut input, &mut console, &mut error);
            if shell.halt_requested() {
                let _result = write_all(&mut console, b"halting: parking CPU\n");
                kllm_machine::park();
            }
        }
    }

    impl LineEditor {
        fn read_line(&mut self, console: &mut NativeConsole) -> Result<String, ()> {
            let mut line = String::new();
            let mut overflow = false;
            loop {
                let byte = kllm_machine::read_byte();
                if self.discard_leading_lf && byte == b'\n' {
                    self.discard_leading_lf = false;
                    continue;
                }
                self.discard_leading_lf = false;
                match byte {
                    b'\r' | b'\n' => {
                        self.discard_leading_lf = byte == b'\r';
                        write_all(console, b"\n")?;
                        if overflow {
                            write_all(console, b"input: line exceeded 512 bytes; discarded\n")?;
                            line.clear();
                            overflow = false;
                            continue;
                        }
                        return Ok(line);
                    }
                    value if is_backspace(char::from(value)) => {
                        if line.pop().is_some() {
                            write_all(console, b"\x08 \x08")?;
                        }
                    }
                    0x20..=0x7e if !overflow => {
                        if line.len() == MAX_LINE_BYTES {
                            overflow = true;
                        } else {
                            line.push(char::from(byte));
                            write_all(console, &[byte])?;
                        }
                    }
                    _ => {}
                }
            }
        }
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

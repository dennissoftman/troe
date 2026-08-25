//! UEFI-bootstrapped owned-machine image with a staged Stage 7 load boundary.
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
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};
    use core::fmt::Write as _;
    use core::panic::PanicInfo;

    use troe_abi::{
        command, datagram, diagnostics, filesystem, filesystem_mutation, icmp_echo,
        network_configuration, network_observation, requirements, stream, timer,
    };
    #[cfg(feature = "acceptance-probes")]
    use troe_application::ParseError;
    use troe_application::{
        ABI_MINOR, ApplicationLimits, InitialHandle, LoadPlan, LoaderResource, LoaderTransaction,
        MAX_LOAD_RECORDS, PAGE_BYTES, SegmentPermissions, StartupInfo, Target, parse_kex,
        stage_artifact,
    };
    use troe_block::{BlockAccess, BlockRegion};
    use troe_block::{BlockDevice, BlockLimits};
    use troe_config::{ActivationPointer, ActivationRecovery, recover_activation};
    use troe_content::{ContentPack, MAX_PACK_BYTES};
    use troe_core::{
        CommandStatus, Input, MAX_LINE_BYTES, MachineMemoryOwner, MachineMemorySnapshot,
        MemoryStats, Output, PIPE_CAPACITY, StreamError,
    };
    use troe_dispatch::{
        ByteInputService, ByteOutputService, CommandInvocationService, ConsoleService,
        CopiedMessage, DispatchedOutput, Dispatcher, HandleOwner, ReplyStatus, Request, Rights,
        Service, ServiceReply, SharedOutput,
    };
    use troe_driver::{InputEvent, InputQueueConfig, InputQueueStats, InputSource};
    use troe_ext4::Ext4Limits;
    use troe_gpt::{GptGuid, GptLimits, discover};
    use troe_identity::IdentityLimits;
    use troe_memory::{
        BASE_PAGE_SIZE, BootAllocator, FrameAllocator, MAX_FIRMWARE_REGIONS, Mapping,
        MappingLifetime, MappingMemoryType, MappingOwner, MappingPermissions, MappingPlan,
        MemoryMapStats, MemoryRegion, NormalizedMemoryMap, PhysicalRange, RegionKind, VirtualRange,
    };
    use troe_mount::{BootMountManifest, parse_manifest};
    use troe_net::{
        ArpCache, DhcpMessageType, DhcpPacket, Ipv4Address, MAX_UDP_PAYLOAD_BYTES, MacAddress,
        NetError, NetworkDevice, NetworkServiceStats, UdpAdmission, UdpPortTable, build_arp_reply,
        build_arp_request, build_dhcp_discover, build_dhcp_request, build_icmp_echo, build_udp,
        parse_arp, parse_dhcp, parse_icmp_echo, parse_udp,
    };
    use troe_persist::{DualSlotStore, RegionSelector, TRANSACTION_BLOCKS};
    use troe_shell::{
        ArpEntry, CompletionConfig, ExternalCommand, MachineAction, NetworkControl, NetworkError,
        NetworkStats, NetworkStatus, PingReply, ReceivedUdp, Shell, format_memory_report,
    };
    #[cfg(feature = "acceptance-probes")]
    use troe_statefs::STATE_PATH;
    use troe_statefs::StateFs;
    use troe_storage::{
        ActivationLimits, MAX_STORAGE_REPORT_BYTES, STORAGE_REPORT_EXTENSION_BYTES,
        prepare_read_only, read_selected_file, validate_root_activation,
    };
    use troe_task::{
        Cancelled, Capabilities, CooperativeRuntime, IsolationResource, MonotonicMillis, Scheduler,
        StackResource, TaskFault, TaskId, TaskStep,
    };
    use troe_terminal::{
        EditorConfig, EditorOutcome, FramebufferDescriptor, FramebufferPixelFormat, InputDecoder,
        KeyEvent, KeyboardConfig, LineEditor, Ps2Set1Decoder, TextConsole, TextConsoleConfig,
    };
    use troe_vfs::{FsError, Namespace, NodeKind, RamFsQuota, ReadOnlyFileSystem};
    use uefi::boot;
    use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned};
    use uefi::prelude::*;
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};

    #[cfg(target_arch = "x86_64")]
    const ROOTFS: &[u8] = include_bytes!("../../assets/root-x86_64.kefs");
    #[cfg(target_arch = "aarch64")]
    const ROOTFS: &[u8] = include_bytes!("../../assets/root-aarch64.kefs");
    const BOOT_MOUNT_MANIFEST: &[u8] = include_bytes!("../../assets/boot.bmnt");
    const PERSISTENCE_SELECTOR: &[u8] = include_bytes!("../../assets/persist.prgn");
    const STATEFS_SELECTOR: &[u8] = include_bytes!("../../assets/state.prgn");
    const INITIAL_ACTIVATION: &[u8] = include_bytes!("../../assets/system.sact");
    const OWNED_HEAP_BYTES: u64 = 6 * 1024 * 1024;
    const PAGE_TABLE_BYTES: u64 = 2 * 1024 * 1024;
    const OWNED_STACK_BYTES: u64 = 128 * 1024;
    const EXCEPTION_STACK_BYTES: u64 = 16 * 1024;
    const TASK_STACK_BYTES: u64 = 64 * 1024;
    const TASK_GUARD_BYTES: u64 = BASE_PAGE_SIZE;
    const TASK_STACK_PAGES: u16 = 16;
    const TASK_STACK_COUNT: usize = 3;
    const ISOLATED_TABLE_PAGES: u64 = PAGE_TABLE_BYTES / BASE_PAGE_SIZE;
    const ISOLATED_CODE_PAGES: u64 = 1;
    const ISOLATED_DATA_PAGES: u64 = 1;
    const ISOLATED_STACK_PAGES: u64 = 4;
    const ISOLATED_PRIVATE_PAGES: u64 =
        ISOLATED_CODE_PAGES + ISOLATED_DATA_PAGES + ISOLATED_STACK_PAGES;
    const ISOLATED_RESOURCE_PAGES: u64 = ISOLATED_TABLE_PAGES + ISOLATED_PRIVATE_PAGES;
    const APPLICATION_TABLE_PAGES: u64 = 512;
    const STAGE6_USER_REGION_LIMIT: usize = 8;
    const STAGE6_USER_REGIONS: usize = 3;
    const APPLICATION_FIXED_USER_REGIONS: usize = 3;
    const APPLICATION_INTERFACE_ECHO: u32 = 1;
    const APPLICATION_COMMAND_STEP_LIMIT: u16 = 1024;
    const _: () = assert!(filesystem_mutation::MAX_FILE_BYTES == PIPE_CAPACITY);
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
    const BOOT_STATUS_WIDTH: usize = 54;
    const BOOT_MEMORY_LABEL: &str = "Initializing memory and protection";
    const BOOT_DEVICES_LABEL: &str = "Starting devices and input";
    const BOOT_RUNTIME_LABEL: &str = "Starting task and application runtime";
    const _: () = assert!(TASK_STACK_BYTES == TASK_STACK_PAGES as u64 * BASE_PAGE_SIZE);
    const _: () = assert!(TASK_GUARD_BYTES == BASE_PAGE_SIZE);
    const _: () = assert!(TASK_STACK_COUNT == 3);
    const _: () = assert!(STAGE6_USER_REGIONS <= STAGE6_USER_REGION_LIMIT);
    const _: () = assert!(STAGE6_USER_REGION_LIMIT <= troe_machine::UserAddressSpace::MAX_REGIONS);
    const _: () = assert!(
        MAX_LOAD_RECORDS + APPLICATION_FIXED_USER_REGIONS
            == troe_machine::UserAddressSpace::MAX_REGIONS
    );

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
            if troe_machine::write(bytes) {
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
            framebuffer: TextConsole<troe_machine::OwnedFramebuffer>,
        },
    }

    impl NativeShellConsole {
        fn new(framebuffer: Option<FramebufferDescriptor>) -> Self {
            let Some(framebuffer) = framebuffer else {
                return Self::Serial(NativeConsole);
            };
            let Ok(surface) = troe_machine::OwnedFramebuffer::new(framebuffer) else {
                return Self::Serial(NativeConsole);
            };
            let Ok(framebuffer) = TextConsole::new(surface, TextConsoleConfig::standard()) else {
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

        fn replay_completed_boot(&mut self) -> Result<(), StreamError> {
            let Self::Mirrored { framebuffer, .. } = self else {
                return Ok(());
            };
            write_boot_status(framebuffer, BOOT_MEMORY_LABEL, true)
                .map_err(|()| StreamError::Device)?;
            write_boot_status(framebuffer, BOOT_DEVICES_LABEL, true)
                .map_err(|()| StreamError::Device)?;
            write_boot_status(framebuffer, BOOT_RUNTIME_LABEL, true)
                .map_err(|()| StreamError::Device)
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
        kernel_runtime: PhysicalRange,
        kernel_plan: MappingPlan,
        native_blocks: RefCell<Vec<troe_machine::NativeVirtioBlock>>,
        native_statefs: RefCell<Option<Box<dyn ReadOnlyFileSystem>>>,
        native_generation: NativeGenerationState,
        boot_mount_manifest: BootMountManifest,
    }

    struct NativeBlockInitialization {
        blocks: Vec<troe_machine::NativeVirtioBlock>,
        statefs: Option<Box<dyn ReadOnlyFileSystem>>,
        generation: NativeGenerationState,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum NativeGenerationState {
        Active,
        Predecessor,
        Recovery,
    }

    impl NativeGenerationState {
        const fn desired_system_available(self) -> bool {
            !matches!(self, Self::Recovery)
        }

        const fn name(self) -> &'static str {
            match self {
                Self::Active => "active",
                Self::Predecessor => "predecessor",
                Self::Recovery => "recovery",
            }
        }
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
        accounting: &'a mut OwnedAccounting,
        scheduler: &'a mut Scheduler,
        task_id: TaskId,
        capabilities: Capabilities,
        stack: PhysicalRange,
    }

    struct KexCommandRunner<'a> {
        accounting: &'a mut OwnedAccounting,
        scheduler: &'a mut Scheduler,
        shell_id: TaskId,
        shell_capabilities: Capabilities,
        runtime: SharedRuntime,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CommandApplicationOutcome {
        Exited(u32),
        Faulted(TaskFault),
    }

    #[derive(Clone, Copy)]
    struct CommandStartupService {
        port: troe_dispatch::PortId,
        interface: u32,
        major: u16,
        minor: u16,
    }

    #[derive(Clone, Copy)]
    struct Ipv4Configuration {
        address: Ipv4Address,
        subnet_mask: Ipv4Address,
        gateway: Ipv4Address,
        lease_seconds: Option<u32>,
    }

    struct KernelNetworkService {
        device: troe_machine::NativeVirtioNetwork,
        configuration: Option<Ipv4Configuration>,
        next_sequence: u16,
        next_port: u16,
        dhcp_generation: u16,
        arp: ArpCache,
        udp: UdpPortTable,
        dhcp_inbox: VecDeque<DhcpPacket>,
        echo_inbox: VecDeque<EchoReply>,
        stats: NetworkServiceStats,
    }

    #[derive(Clone, Copy)]
    struct EchoReply {
        source: Ipv4Address,
        identifier: u16,
        sequence: u16,
        bytes: usize,
    }

    type SharedNetwork = Rc<RefCell<KernelNetworkService>>;
    type SharedNamespace<'namespace> = Rc<RefCell<&'namespace mut Namespace>>;

    struct KernelNetwork {
        service: SharedNetwork,
    }

    struct KernelRuntime {
        network: Option<SharedNetwork>,
        deferred_input: VecDeque<InputEvent>,
        control_down: bool,
        last_millis: Cell<u64>,
    }

    type SharedRuntime = Rc<RefCell<KernelRuntime>>;

    struct ApplicationDatagramService {
        network: SharedNetwork,
        runtime: SharedRuntime,
        ports: [u16; troe_net::MAX_UDP_PORTS],
        port_count: usize,
    }

    struct ApplicationFilesystemService<'namespace> {
        namespace: SharedNamespace<'namespace>,
        cwd: String,
        files: [ApplicationFileSlot; filesystem::MAX_OPEN_FILES],
    }

    struct ApplicationFilesystemMutationService<'namespace> {
        namespace: SharedNamespace<'namespace>,
        cwd: String,
        next_token: Option<u32>,
        pending: Option<PendingFileReplacement>,
    }

    struct ApplicationTimerService {
        runtime: SharedRuntime,
    }

    struct ApplicationDiagnosticsService {
        snapshot: [u8; diagnostics::SNAPSHOT_BYTES],
    }

    struct ApplicationNetworkObservationService {
        network: Option<SharedNetwork>,
    }

    struct ApplicationNetworkConfigurationService {
        network: Option<SharedNetwork>,
        runtime: SharedRuntime,
    }

    struct ApplicationIcmpEchoService {
        network: Option<SharedNetwork>,
        runtime: SharedRuntime,
    }

    struct PendingFileReplacement {
        token: u32,
        path: String,
        bytes: Vec<u8>,
    }

    struct ApplicationFileSlot {
        generation: u32,
        retired: bool,
        path: Option<String>,
        byte_count: u64,
    }

    struct KernelRuntimeCapability {
        runtime: SharedRuntime,
    }

    enum RuntimeInitError {
        Clock,
        InputMetadata,
    }

    impl core::fmt::Debug for KernelNetwork {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let service = self.service.borrow();
            formatter
                .debug_struct("KernelNetwork")
                .field("mac", &service.device.mac_address().bytes())
                .field("configured", &service.configuration.is_some())
                .finish_non_exhaustive()
        }
    }

    impl core::fmt::Debug for KernelRuntimeCapability {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("KernelRuntimeCapability")
        }
    }

    struct PreparedHandoff {
        image_layout: troe_machine::ImageLayout,
        boot_memory: BootMemory,
        framebuffer: Option<FramebufferDescriptor>,
        boot_mount_manifest: Option<BootMountManifest>,
    }

    struct IsolatedAllocation {
        complete: PhysicalRange,
        tables: PhysicalRange,
        code: PhysicalRange,
        data: PhysicalRange,
        stack: PhysicalRange,
    }

    struct ApplicationAllocation {
        complete: PhysicalRange,
        tables: PhysicalRange,
        image: PhysicalRange,
        startup: PhysicalRange,
        heap: Option<PhysicalRange>,
        stack: PhysicalRange,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum ApplicationProbe {
        Calls,
        #[cfg(feature = "acceptance-probes")]
        Spin,
        #[cfg(feature = "acceptance-probes")]
        InvalidCall,
        #[cfg(feature = "acceptance-probes")]
        UnexpectedReturn,
    }

    impl ApplicationProbe {
        const fn expected_fault(self) -> Option<TaskFault> {
            match self {
                Self::Calls => None,
                #[cfg(feature = "acceptance-probes")]
                Self::Spin => Some(TaskFault::ExecutionLeaseExpired),
                #[cfg(feature = "acceptance-probes")]
                Self::InvalidCall => Some(TaskFault::InvalidCall),
                #[cfg(feature = "acceptance-probes")]
                Self::UnexpectedReturn => Some(TaskFault::Translation),
            }
        }
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
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
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
        if troe_machine::validate_selected_platform().is_err() {
            let mut firmware_console = FirmwareConsole;
            if let Some(failure) = troe_machine::platform_discovery_failure() {
                let _ignored = write_all(&mut firmware_console, b"platform discovery failed: ");
                let _ignored = write_all(&mut firmware_console, failure.label().as_bytes());
                let _ignored = write_all(&mut firmware_console, b"\n");
            }
            return Status::ABORTED;
        }
        let Ok(platform_source) = troe_machine::selected_platform_source() else {
            return Status::ABORTED;
        };
        let mut firmware_console = FirmwareConsole;
        if let Ok(prepared) = prepare_handoff(&mut firmware_console, platform_source) {
            let stack = prepared.boot_memory.stack;
            let prepared = Box::leak(Box::new(prepared));
            match troe_machine::enter_owned_stack(stack, prepared, post_handoff) {
                Err(_) => Status::ABORTED,
                Ok(never) => match never {},
            }
        } else {
            let _ignored = write_boot_status(&mut firmware_console, "TROE initialization", false);
            Status::ABORTED
        }
    }

    fn prepare_handoff(
        console: &mut FirmwareConsole,
        platform_source: troe_machine::PlatformSource,
    ) -> Result<PreparedHandoff, ()> {
        write_all(console, b"\x1b[2J\x1b[H")?;
        match platform_source {
            troe_machine::PlatformSource::Acpi => {
                write_all(console, b"platform discovery: ACPI validated\n")?;
            }
            troe_machine::PlatformSource::Fdt => {
                write_all(console, b"platform discovery: FDT validated\n")?;
            }
            troe_machine::PlatformSource::Fixed => {}
        }

        let image_layout = troe_machine::loaded_image_layout().map_err(|_| ())?;
        let framebuffer = capture_framebuffer();
        let boot_memory = reserve_and_install_heap()?;
        let boot_mount_manifest = parse_manifest(BOOT_MOUNT_MANIFEST).map_err(|_| ())?;
        troe_machine::initialize_console();
        if !troe_machine::initialize_monotonic_clock() {
            return Err(());
        }
        Ok(PreparedHandoff {
            image_layout,
            boot_memory,
            framebuffer,
            boot_mount_manifest: Some(boot_mount_manifest),
        })
    }

    fn post_handoff(prepared: &mut PreparedHandoff) -> ! {
        let final_map = troe_machine::exit_boot_services_after_protocols();
        troe_machine::mark_firmware_exited();
        troe_machine::take_interrupt_ownership();
        let stack_pointer = usize_as_u64(troe_machine::current_stack_pointer());
        if !prepared.boot_memory.stack.contains(stack_pointer) {
            fatal(b"fatal: active stack is not kernel-owned\n");
        }
        let accounting = complete_handoff(prepared, final_map)
            .unwrap_or_else(|()| fatal(b"fatal: post-handoff initialization failed\n"));
        run_owned(accounting)
    }

    fn complete_handoff(
        prepared: &mut PreparedHandoff,
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
        if !troe_machine::probe_allocation_failure() {
            return Err(());
        }
        troe_machine::install_exception_vectors(prepared.boot_memory.exception_stack)
            .map_err(|_| ())?;
        let mmu = troe_machine::install_mmu(&mapping_plan, prepared.boot_memory.page_tables)
            .map_err(|_| ())?;
        if mmu.mapped_pages == 0 || mmu.table_pages == 0 {
            return Err(());
        }
        if !write_machine_boot_status(BOOT_MEMORY_LABEL, true) {
            return Err(());
        }
        let boot_mount_manifest = prepared.boot_mount_manifest.as_ref().ok_or(())?;
        troe_machine::initialize_input_interrupts(InputQueueConfig::standard()).map_err(|_| ())?;
        let native = initialize_native_blocks(boot_mount_manifest)?;
        let boot_mount_manifest = prepared.boot_mount_manifest.take().ok_or(())?;
        if !write_machine_boot_status(BOOT_DEVICES_LABEL, true) {
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
            kernel_runtime: prepared.boot_memory.arena,
            kernel_plan: mapping_plan,
            native_blocks: RefCell::new(native.blocks),
            native_statefs: RefCell::new(native.statefs),
            native_generation: native.generation,
            boot_mount_manifest,
        })
    }

    fn initialize_native_blocks(
        boot_mount_manifest: &BootMountManifest,
    ) -> Result<NativeBlockInitialization, ()> {
        let mut devices = troe_machine::discover_virtio_blocks().map_err(|_| ())?;
        #[cfg(feature = "acceptance-probes")]
        let generation = recover_native_generation(&mut devices, boot_mount_manifest)?;
        #[cfg(not(feature = "acceptance-probes"))]
        let generation = recover_native_generation(&mut devices, boot_mount_manifest);
        #[cfg(feature = "acceptance-probes")]
        let statefs = recover_native_statefs(&mut devices)?;
        #[cfg(not(feature = "acceptance-probes"))]
        let statefs = recover_native_statefs(&mut devices);
        #[cfg(feature = "acceptance-probes")]
        probe_native_network()?;
        Ok(NativeBlockInitialization {
            blocks: devices,
            statefs,
            generation,
        })
    }

    #[cfg(feature = "acceptance-probes")]
    fn probe_native_network() -> Result<(), ()> {
        let mut network = troe_machine::discover_virtio_network()
            .map_err(|_| ())?
            .ok_or(())?;
        network.enable_interrupts().map_err(|_| ())?;
        let _initial_poll = troe_machine::take_network_interrupt();
        if !troe_machine::write(b"native network: device ready\n") {
            return Err(());
        }
        let guest_ip = Ipv4Address::new([10, 0, 2, 15]);
        let host_ip = Ipv4Address::new([10, 0, 2, 2]);
        let arp = build_arp_request(network.mac_address(), guest_ip, host_ip).map_err(|_| ())?;
        network.transmit(&arp).map_err(|_| ())?;
        if !troe_machine::write(b"native network: ARP request transmitted\n") {
            return Err(());
        }
        let gateway_mac = receive_gateway_arp(&mut network, guest_ip, host_ip)?;
        if !troe_machine::write(b"native network: ARP reply verified\n") {
            return Err(());
        }
        #[cfg(feature = "platform-x86_64-q35-uefi")]
        let host_port = 40_123;
        #[cfg(feature = "platform-aarch64-virt-uefi")]
        let host_port = 40_124;
        #[cfg(feature = "platform-x86_64-uefi-virtio-pci")]
        let host_port = 40_125;
        #[cfg(feature = "platform-aarch64-uefi-virtio-mmio")]
        let host_port = 40_126;
        let request = build_udp(
            network.mac_address(),
            gateway_mac,
            guest_ip,
            host_ip,
            49_152,
            host_port,
            b"troe-stage8-request",
        )
        .map_err(|_| ())?;
        network.transmit(&request).map_err(|_| ())?;
        if !troe_machine::write(b"native network: UDP request transmitted\n") {
            return Err(());
        }
        for _ in 0..64 {
            let Some(frame) = network.receive().map_err(|_| ())? else {
                wait_for_network_completion();
                continue;
            };
            if frame.get(..6) != Some(&network.mac_address().bytes()) {
                continue;
            }
            let Ok(datagram) = parse_udp(&frame) else {
                continue;
            };
            if datagram.source_ip == host_ip
                && datagram.destination_ip == guest_ip
                && datagram.source_port == host_port
                && datagram.destination_port == 49_152
                && datagram.payload == b"troe-stage8-reply"
            {
                if !troe_machine::write(b"native network: UDP host exchange complete\n") {
                    return Err(());
                }
                return Ok(());
            }
        }
        Err(())
    }

    #[cfg(feature = "acceptance-probes")]
    fn receive_gateway_arp<D: NetworkDevice>(
        network: &mut D,
        guest_ip: Ipv4Address,
        host_ip: Ipv4Address,
    ) -> Result<MacAddress, ()> {
        let mut saw_frame = false;
        let mut saw_arp = false;
        for _ in 0..64 {
            let frame = match network.receive() {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    wait_for_network_completion();
                    continue;
                }
                Err(_) => {
                    let _ignored = troe_machine::write(b"native network: RX completion invalid\n");
                    return Err(());
                }
            };
            saw_frame = true;
            let Ok(arp) = parse_arp(&frame) else {
                continue;
            };
            saw_arp = true;
            if arp.operation == 2
                && arp.sender_ip == host_ip
                && arp.target_ip == guest_ip
                && arp.target_mac == network.mac_address().bytes()
            {
                return Ok(arp.sender_mac);
            }
        }
        if !saw_frame {
            let _ignored = troe_machine::write(b"native network: ARP RX timeout\n");
        } else if !saw_arp {
            let _ignored = troe_machine::write(b"native network: ARP frame rejected\n");
        } else {
            let _ignored = troe_machine::write(b"native network: ARP identity mismatch\n");
        }
        Err(())
    }

    #[cfg(feature = "acceptance-probes")]
    fn wait_for_network_completion() {
        troe_machine::wait_for_runtime_event();
        let _completion = troe_machine::take_network_interrupt();
    }

    #[cfg(feature = "acceptance-probes")]
    fn recover_native_generation(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
        boot_mount_manifest: &BootMountManifest,
    ) -> Result<NativeGenerationState, ()> {
        recover_native_generation_inner(devices, boot_mount_manifest)
    }

    #[cfg(not(feature = "acceptance-probes"))]
    fn recover_native_generation(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
        boot_mount_manifest: &BootMountManifest,
    ) -> NativeGenerationState {
        recover_native_generation_inner(devices, boot_mount_manifest)
            .unwrap_or(NativeGenerationState::Recovery)
    }

    fn recover_native_generation_inner(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
        boot_mount_manifest: &BootMountManifest,
    ) -> Result<NativeGenerationState, ()> {
        let activation_limits = native_activation_limits()?;
        let content_bytes = read_selected_file(
            boot_mount_manifest,
            devices.as_mut_slice(),
            "root",
            "/system.cspk",
            MAX_PACK_BYTES,
            activation_limits,
        )
        .map_err(|_| ())?;
        let content = ContentPack::parse(&content_bytes).map_err(|_| ())?;
        let bootstrap = ActivationPointer::parse(INITIAL_ACTIVATION).map_err(|_| ())?;
        let selector = RegionSelector::parse(PERSISTENCE_SELECTOR).map_err(|_| ())?;
        let region = take_transaction_region(devices, selector)?;
        let mut store = DualSlotStore::open(region).map_err(|_| ())?;
        let recovered = match store.payload() {
            Some(payload) => Some(ActivationPointer::parse(payload).map_err(|_| ())?),
            None => None,
        };
        let candidate = recovered.unwrap_or(bootstrap);
        let (pointer, validated, state) = match recover_activation(candidate, |pointer| {
            validate_root_activation(&content, pointer, IdentityLimits::standard())
        }) {
            ActivationRecovery::Active { pointer, validated } => {
                (pointer, validated, NativeGenerationState::Active)
            }
            ActivationRecovery::Previous { pointer, validated } => {
                (pointer, validated, NativeGenerationState::Predecessor)
            }
            ActivationRecovery::Unavailable => return Ok(NativeGenerationState::Recovery),
        };
        let newly_published = recovered.is_none() || state == NativeGenerationState::Predecessor;
        if newly_published {
            store.commit(&pointer.encode()).map_err(|_| ())?;
        }

        #[cfg(feature = "acceptance-probes")]
        let state = {
            let mut selected_state = state;
            if selected_state == NativeGenerationState::Active && validated.health_rollback() {
                let previous = pointer.previous().ok_or(())?;
                let previous_pointer = ActivationPointer::new(previous, None).map_err(|_| ())?;
                let previous_validation = validate_root_activation(
                    &content,
                    previous_pointer,
                    IdentityLimits::standard(),
                )
                .map_err(|_| ())?;
                if previous_validation.health_rollback()
                    || !troe_machine::write(b"native generation: candidate published\n")
                {
                    return Err(());
                }
                store.commit(&previous_pointer.encode()).map_err(|_| ())?;
                selected_state = NativeGenerationState::Predecessor;
                if !troe_machine::write(b"native generation: health rollback committed\n") {
                    return Err(());
                }
            } else if !newly_published {
                // Exercise a complete durable transaction on every acceptance
                // boot without changing the production activation policy.
                store.commit(&pointer.encode()).map_err(|_| ())?;
            }
            if !troe_machine::write(b"native identity: generation snapshot verified\n") {
                return Err(());
            }
            if !troe_machine::write(b"native content: selected ext4 CSPK verified\n") {
                return Err(());
            }
            if !troe_machine::write(b"native persistence: committed and flushed\n") {
                return Err(());
            }
            selected_state
        };
        #[cfg(not(feature = "acceptance-probes"))]
        let _ = validated.health_rollback();
        Ok(state)
    }

    fn mount_native_statefs(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
    ) -> Result<StateFs<troe_machine::NativeVirtioBlock>, ()> {
        let state_selector = RegionSelector::parse(STATEFS_SELECTOR).map_err(|_| ())?;
        let state_region = take_transaction_region(devices, state_selector)?;
        StateFs::mount(state_region).map_err(|_| ())
    }

    #[cfg(feature = "acceptance-probes")]
    fn recover_native_statefs(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
    ) -> Result<Option<Box<dyn ReadOnlyFileSystem>>, ()> {
        let statefs = mount_native_statefs(devices)?;
        let mut statefs = statefs;
        probe_native_statefs_mutation(&mut statefs)?;
        Ok(Some(Box::new(statefs)))
    }

    #[cfg(not(feature = "acceptance-probes"))]
    fn recover_native_statefs(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
    ) -> Option<Box<dyn ReadOnlyFileSystem>> {
        mount_native_statefs(devices)
            .ok()
            .map(|statefs| Box::new(statefs) as Box<dyn ReadOnlyFileSystem>)
    }

    #[cfg(feature = "acceptance-probes")]
    fn probe_native_statefs_mutation(
        statefs: &mut StateFs<troe_machine::NativeVirtioBlock>,
    ) -> Result<(), ()> {
        let mut prior = [0_u8; 8];
        let next = match statefs.read_file(STATE_PATH, 0, &mut prior) {
            Ok(8) => u64::from_le_bytes(prior).checked_add(1).ok_or(())?,
            Err(troe_vfs::FsError::NotFound) => 1,
            _ => return Err(()),
        };
        statefs
            .write_file(STATE_PATH, &next.to_le_bytes())
            .map_err(|_| ())?;
        let mut verified = [0_u8; 8];
        if statefs
            .read_file(STATE_PATH, 0, &mut verified)
            .map_err(|_| ())?
            != 8
            || u64::from_le_bytes(verified) != next
        {
            return Err(());
        }
        if !troe_machine::write(b"native statefs: mutation committed and flushed\n") {
            return Err(());
        }
        Ok(())
    }

    fn take_transaction_region(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
        selector: RegionSelector,
    ) -> Result<BlockRegion<troe_machine::NativeVirtioBlock>, ()> {
        let discovery_limits = BlockLimits::new(32, 16 * 1024, 1).map_err(|_| ())?;
        let gpt_limits = GptLimits::new(128, 16 * 1024, 4).map_err(|_| ())?;
        let mut selected = None;
        for (index, device) in devices.iter_mut().enumerate() {
            let geometry = device.geometry();
            if geometry.logical_block_bytes() != 512
                || !geometry.supports_flush()
                || device.profile().read_only()
            {
                continue;
            }
            let Ok(mut whole) =
                BlockRegion::whole_device(device, BlockAccess::ReadOnly, discovery_limits)
            else {
                continue;
            };
            let Ok(gpt) = discover(&mut whole, gpt_limits) else {
                continue;
            };
            if gpt.disk_guid().disk_bytes() != selector.disk_guid() {
                continue;
            }
            let Some(partition) =
                gpt.partition_by_unique_guid(GptGuid::from_disk_bytes(selector.partition_guid()))
            else {
                continue;
            };
            if partition.type_guid().disk_bytes() != selector.partition_type_guid()
                || partition.block_count() != TRANSACTION_BLOCKS
            {
                continue;
            }
            if selected.replace((index, partition.first_lba())).is_some() {
                return Err(());
            }
        }
        let (index, first_lba) = selected.ok_or(())?;
        let device = devices.remove(index);
        let limits = BlockLimits::new(1, 512, 1).map_err(|_| ())?;
        BlockRegion::new(
            device,
            first_lba,
            TRANSACTION_BLOCKS,
            BlockAccess::ReadWrite,
            limits,
        )
        .map_err(|_| ())
    }

    fn native_activation_limits() -> Result<ActivationLimits, ()> {
        let block = BlockLimits::new(8, 4096, 1).map_err(|_| ())?;
        let gpt = GptLimits::new(128, 16 * 1024, 16).map_err(|_| ())?;
        let ext4 = Ext4Limits::new(8, 64, 256, 4096, 1024 * 1024, 4096, 64).map_err(|_| ())?;
        Ok(ActivationLimits::new(block, gpt, ext4))
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
        if !troe_machine::initialize_heap(heap_start, heap_bytes) {
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

    fn allocation_range(allocation: troe_memory::BootAllocation) -> Result<PhysicalRange, ()> {
        PhysicalRange::from_pages(allocation.start(), allocation.byte_count() / BASE_PAGE_SIZE)
            .map_err(|_| ())
    }

    fn build_mapping_plan(
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
        if accounting.native_blocks.borrow().len() > 8 {
            fatal(b"fatal: native block device accounting exceeded\n");
        }
        let mut scheduler = Scheduler::new(TASK_STACK_COUNT)
            .unwrap_or_else(|_| fatal(b"fatal: cannot create task scheduler\n"));
        run_cooperative_services(&mut scheduler, &accounting)
            .unwrap_or_else(|()| fatal(b"fatal: cooperative task verification failed\n"));
        run_isolation_verification(&mut scheduler, &mut accounting)
            .unwrap_or_else(|()| fatal(b"fatal: Stage 6 isolation verification failed\n"));
        run_application_load_verification(&mut scheduler, &mut accounting)
            .unwrap_or_else(|()| fatal(b"fatal: Stage 7 load-boundary verification failed\n"));
        if !write_machine_boot_status(BOOT_RUNTIME_LABEL, true) {
            fatal(b"fatal: application loader diagnostic failed\n");
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
            accounting: &mut accounting,
            scheduler: &mut scheduler,
            task_id: shell_id,
            capabilities,
            stack,
        };
        let result = troe_machine::run_task_step(stack, &mut shell_task, run_shell_task);
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
                troe_machine::run_task_step(
                    accounting.task_stacks[0].stack,
                    &mut first_service,
                    cooperative_service_step,
                )
                .map_err(|_| ())?
            } else if id == second {
                troe_machine::run_task_step(
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
        let step = troe_machine::run_task_step(
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
        dispatcher: &mut Dispatcher<'_>,
        port: troe_dispatch::PortId,
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
        let Ok(address_space) = troe_machine::build_user_address_space(&plan, allocation.tables)
        else {
            reclaim_isolated(&mut accounting.frames, allocation)?;
            return Err(());
        };
        if address_space.stats().table_pages == 0
            || address_space.stats().table_pages > ISOLATED_TABLE_PAGES
            || address_space.user_region_count() != STAGE6_USER_REGIONS
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

            let mut copied_bytes = [0_u8; troe_dispatch::MAX_MESSAGE_BYTES];
            let stack_top = USER_STACK_BASE
                .checked_add(ISOLATED_STACK_PAGES.checked_mul(BASE_PAGE_SIZE).ok_or(())?)
                .ok_or(())?;
            let outcome = troe_machine::run_isolated(
                address_space,
                USER_CODE_BASE,
                stack_top,
                &mut copied_bytes,
            )
            .map_err(|_| ())?;
            match (probe.expected_fault(), outcome) {
                (
                    None,
                    troe_machine::IsolatedOutcome::Exited {
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
                (Some(expected), troe_machine::IsolatedOutcome::Faulted(fault)) => {
                    let fault = match fault {
                        troe_machine::IsolatedFault::Translation => TaskFault::Translation,
                        troe_machine::IsolatedFault::Permission => TaskFault::Permission,
                        troe_machine::IsolatedFault::IllegalInstruction => {
                            TaskFault::IllegalInstruction
                        }
                        troe_machine::IsolatedFault::InvalidCall => TaskFault::InvalidCall,
                        troe_machine::IsolatedFault::ExecutionLeaseExpired => {
                            TaskFault::ExecutionLeaseExpired
                        }
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
                != Err(troe_dispatch::DispatchError::InvalidHandle)
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

    fn run_application_load_verification(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        let artifact = native_kex_artifact(ApplicationProbe::Calls);
        let baseline_frames = accounting.frames.free_frames();
        let baseline_tasks = scheduler.stats();
        let mut dispatcher = Dispatcher::new(1, 2).map_err(|_| ())?;
        let (port, _kernel_handle) = dispatcher
            .register(Box::new(EchoService), Rights::CALL)
            .map_err(|_| ())?;

        let first = load_and_reclaim_application(
            scheduler,
            accounting,
            &mut dispatcher,
            port,
            artifact,
            ApplicationProbe::Calls,
        )?;
        #[cfg(not(feature = "acceptance-probes"))]
        let _ = first;

        #[cfg(feature = "acceptance-probes")]
        let (reused, invalid_reused, return_reused) = {
            let spinning = native_kex_artifact(ApplicationProbe::Spin);
            let reused = load_and_reclaim_application(
                scheduler,
                accounting,
                &mut dispatcher,
                port,
                spinning,
                ApplicationProbe::Spin,
            )?;
            let invalid_call = native_kex_artifact(ApplicationProbe::InvalidCall);
            let invalid_reused = load_and_reclaim_application(
                scheduler,
                accounting,
                &mut dispatcher,
                port,
                invalid_call,
                ApplicationProbe::InvalidCall,
            )?;
            let unexpected_return = native_kex_artifact(ApplicationProbe::UnexpectedReturn);
            let return_reused = load_and_reclaim_application(
                scheduler,
                accounting,
                &mut dispatcher,
                port,
                unexpected_return,
                ApplicationProbe::UnexpectedReturn,
            )?;
            (reused, invalid_reused, return_reused)
        };

        if accounting.frames.free_frames() != baseline_frames
            || scheduler.stats().owned_address_spaces != baseline_tasks.owned_address_spaces
            || scheduler.stats().owned_isolation_pages != baseline_tasks.owned_isolation_pages
            || scheduler.stats().owned_handles != baseline_tasks.owned_handles
            || scheduler.stats().yields != baseline_tasks.yields.checked_add(1).ok_or(())?
            || dispatcher.stats().live_handles != 1
        {
            return Err(());
        }

        #[cfg(not(feature = "acceptance-probes"))]
        if scheduler.stats().contained_faults != baseline_tasks.contained_faults {
            return Err(());
        }

        #[cfg(feature = "acceptance-probes")]
        {
            if reused != first
                || invalid_reused != first
                || return_reused != first
                || scheduler.stats().contained_faults
                    != baseline_tasks.contained_faults.checked_add(3).ok_or(())?
            {
                return Err(());
            }
            #[cfg(target_arch = "x86_64")]
            let rejections = include!("../../tests/kex-corpus/rejections-x86_64.inc");
            #[cfg(target_arch = "aarch64")]
            let rejections = include!("../../tests/kex-corpus/rejections-aarch64.inc");
            for (_name, source, expected) in rejections {
                require_staged_rejection(source, expected)?;
            }
            if accounting.frames.free_frames() != baseline_frames {
                return Err(());
            }
        }
        Ok(())
    }

    #[cfg(feature = "acceptance-probes")]
    fn require_staged_rejection(source: &[u8], expected: ParseError) -> Result<(), ()> {
        let mut staging = Vec::new();
        staging.try_reserve_exact(source.len()).map_err(|_| ())?;
        staging.extend_from_slice(source);
        match parse_kex(&staging, native_application_target(), ABI_MINOR) {
            Err(error) if error == expected => Ok(()),
            _ => Err(()),
        }
    }

    #[allow(clippy::drop_non_drop, clippy::too_many_lines)]
    fn load_and_reclaim_application(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        dispatcher: &mut Dispatcher<'_>,
        port: troe_dispatch::PortId,
        source: &[u8],
        probe: ApplicationProbe,
    ) -> Result<u64, ()> {
        let limits = ApplicationLimits::standard();
        if source.len() > limits.encoded_bytes() {
            return Err(());
        }
        let mut transaction = LoaderTransaction::new();
        let mut staging = Vec::new();
        staging.try_reserve_exact(source.len()).map_err(|_| ())?;
        staging.extend_from_slice(source);
        transaction
            .acquire(LoaderResource::Staging)
            .map_err(|_| ())?;
        let Ok(plan) = parse_kex(&staging, native_application_target(), ABI_MINOR) else {
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let fixed_user_regions = if plan.heap_pages() == 0 {
            APPLICATION_FIXED_USER_REGIONS - 1
        } else {
            APPLICATION_FIXED_USER_REGIONS
        };
        let application_user_regions = plan
            .segments()
            .count()
            .checked_add(fixed_user_regions)
            .ok_or(())?;
        let private_pages = u16::try_from(plan.charges().private_pages()).map_err(|_| ())?;
        let stack_pages = u16::try_from(plan.stack_pages()).map_err(|_| ())?;

        let Ok(allocation) = allocate_application(&mut accounting.frames, &plan) else {
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Frames).is_err() {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        if prepare_application_memory(&allocation, &plan).is_err() {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let Ok(mapping_plan) = build_application_plan(
            &accounting.kernel_plan,
            accounting.kernel_runtime,
            &allocation,
            &plan,
        ) else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(address_space) =
            troe_machine::build_user_address_space(&mapping_plan, allocation.tables)
        else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Tables).is_err() {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let table_pages = address_space.stats().table_pages;
        if table_pages == 0
            || table_pages > APPLICATION_TABLE_PAGES
            || address_space.user_region_count() != application_user_regions
        {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let Ok(table_pages) = u16::try_from(table_pages) else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(isolation) = IsolationResource::new(0, table_pages, private_pages, 1) else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(stack_resource) = StackResource::new(0, stack_pages) else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(task_id) =
            scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
        else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Task).is_err() {
            rollback_application_task(
                scheduler,
                task_id,
                dispatcher,
                None,
                &mut accounting.frames,
                allocation,
            )?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let entry = plan.entry_address();
        let layout = plan.layout();
        let allocation_start = allocation.complete.start();
        let mut live_owner = None;
        let setup = (|| -> Result<(_, _), ()> {
            let owner = HandleOwner::isolated(task_id.get()).map_err(|_| ())?;
            let handle = dispatcher
                .open_owned(port, Rights::CALL, owner)
                .map_err(|_| ())?;
            live_owner = Some(owner);
            transaction
                .acquire(LoaderResource::Handles)
                .map_err(|_| ())?;
            let initial_handles = [InitialHandle {
                value: handle.abi_value(),
                rights: Rights::CALL.bits(),
                interface: APPLICATION_INTERFACE_ECHO,
                major: 1,
                minor: 0,
            }];
            let mut startup = [0_u8; PAGE_BYTES];
            plan.encode_startup_page(
                StartupInfo {
                    task_id: u64::from(task_id.get()),
                    handles: &initial_handles,
                },
                &mut startup,
            )
            .map_err(|_| ())?;
            troe_machine::copy_to_physical(allocation.startup, 0, &startup).map_err(|_| ())?;
            Ok((owner, handle))
        })();
        let Ok((owner, handle)) = setup else {
            rollback_application_task(
                scheduler,
                task_id,
                dispatcher,
                live_owner,
                &mut accounting.frames,
                allocation,
            )?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        drop(plan);
        drop(staging);
        drop(mapping_plan);
        if transaction.commit().is_err() {
            rollback_application_task(
                scheduler,
                task_id,
                dispatcher,
                live_owner,
                &mut accounting.frames,
                allocation,
            )?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let committed = (|| -> Result<(), ()> {
            if scheduler
                .dispatch_next(Capabilities::SERVICE)
                .map_err(|_| ())?
                != Some(task_id)
            {
                return Err(());
            }
            let mut outcome = troe_machine::run_application(
                address_space,
                entry,
                layout.stack_top(),
                layout.startup_address(),
                PAGE_BYTES,
            )
            .map_err(|_| ())?;
            let mut observed_yield = false;
            let mut observed_call = false;
            loop {
                match (probe, outcome) {
                    (
                        ApplicationProbe::Calls,
                        troe_machine::ApplicationOutcome::Yielded(application),
                    ) if !observed_yield && !observed_call => {
                        scheduler.yield_current(task_id).map_err(|_| ())?;
                        if scheduler
                            .dispatch_next(Capabilities::SERVICE)
                            .map_err(|_| ())?
                            != Some(task_id)
                        {
                            return Err(());
                        }
                        observed_yield = true;
                        outcome = troe_machine::resume_application(
                            application,
                            troe_machine::ApplicationResume::Yield,
                        )
                        .map_err(|_| ())?;
                    }
                    (
                        ApplicationProbe::Calls,
                        troe_machine::ApplicationOutcome::HandleCall { application, call },
                    ) if observed_yield && !observed_call => {
                        let mut request = Vec::new();
                        request
                            .try_reserve_exact(call.request_bytes())
                            .map_err(|_| ())?;
                        request.resize(call.request_bytes(), 0);
                        application.copy_request(&mut request).map_err(|_| ())?;
                        let opcode = u16::from_le_bytes([request[0], request[1]]);
                        let reply = dispatcher
                            .call_owned_abi(owner, call.handle(), opcode, &request[2..])
                            .map_err(|_| ())?;
                        if reply.status() != ReplyStatus::Success
                            || reply.payload() != b"ping"
                            || reply.payload().len() > call.reply_capacity()
                        {
                            return Err(());
                        }
                        observed_call = true;
                        outcome = troe_machine::resume_application(
                            application,
                            troe_machine::ApplicationResume::HandleReply {
                                status: reply.status().abi_value(),
                                reply: reply.payload(),
                            },
                        )
                        .map_err(|_| ())?;
                    }
                    (
                        ApplicationProbe::Calls,
                        troe_machine::ApplicationOutcome::Exited { status: 0 },
                    ) if observed_yield && observed_call => {
                        scheduler.exit_current(task_id, 0).map_err(|_| ())?;
                        break;
                    }
                    #[cfg(feature = "acceptance-probes")]
                    (
                        ApplicationProbe::Spin,
                        troe_machine::ApplicationOutcome::Faulted(
                            troe_machine::IsolatedFault::ExecutionLeaseExpired,
                        ),
                    ) => {
                        scheduler
                            .fault_current(task_id, TaskFault::ExecutionLeaseExpired)
                            .map_err(|_| ())?;
                        break;
                    }
                    #[cfg(feature = "acceptance-probes")]
                    (
                        ApplicationProbe::InvalidCall,
                        troe_machine::ApplicationOutcome::Faulted(
                            troe_machine::IsolatedFault::InvalidCall,
                        ),
                    ) => {
                        scheduler
                            .fault_current(task_id, TaskFault::InvalidCall)
                            .map_err(|_| ())?;
                        break;
                    }
                    #[cfg(feature = "acceptance-probes")]
                    (
                        ApplicationProbe::UnexpectedReturn,
                        troe_machine::ApplicationOutcome::Faulted(
                            troe_machine::IsolatedFault::Translation,
                        ),
                    ) => {
                        scheduler
                            .fault_current(task_id, TaskFault::Translation)
                            .map_err(|_| ())?;
                        break;
                    }
                    _ => return Err(()),
                }
            }
            if dispatcher.close_owner(owner).map_err(|_| ())? != 1 {
                return Err(());
            }
            live_owner = None;
            if dispatcher.call(handle, 1, b"stale")
                != Err(troe_dispatch::DispatchError::InvalidHandle)
            {
                return Err(());
            }
            Ok(())
        })();
        if committed.is_err() {
            rollback_application_task(
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
            rollback_application_task(
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
            && reaped.stack.mapped_pages() == stack_pages
            && reaped.fault == probe.expected_fault();
        reclaim_application(&mut accounting.frames, allocation)?;
        if !valid_reap {
            return Err(());
        }
        Ok(allocation_start)
    }

    #[allow(clippy::drop_non_drop, clippy::too_many_lines)]
    fn run_command_application(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        dispatcher: &mut Dispatcher<'_>,
        services: &[CommandStartupService],
        source: &[u8],
    ) -> Result<CommandApplicationOutcome, ()> {
        if services.is_empty() || services.len() > troe_dispatch::MAX_HANDLES {
            return Err(());
        }
        let mut transaction = LoaderTransaction::new();
        transaction
            .acquire(LoaderResource::Staging)
            .map_err(|_| ())?;
        let Ok(plan) = parse_kex(source, native_application_target(), ABI_MINOR) else {
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let fixed_user_regions = if plan.heap_pages() == 0 {
            APPLICATION_FIXED_USER_REGIONS - 1
        } else {
            APPLICATION_FIXED_USER_REGIONS
        };
        let application_user_regions = plan
            .segments()
            .count()
            .checked_add(fixed_user_regions)
            .ok_or(())?;
        let private_pages = u16::try_from(plan.charges().private_pages()).map_err(|_| ())?;
        let stack_pages = u16::try_from(plan.stack_pages()).map_err(|_| ())?;

        let Ok(allocation) = allocate_application(&mut accounting.frames, &plan) else {
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Frames).is_err() {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        if prepare_application_memory(&allocation, &plan).is_err() {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let Ok(mapping_plan) = build_application_plan(
            &accounting.kernel_plan,
            accounting.kernel_runtime,
            &allocation,
            &plan,
        ) else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(address_space) =
            troe_machine::build_user_address_space(&mapping_plan, allocation.tables)
        else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Tables).is_err() {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let table_pages = address_space.stats().table_pages;
        if table_pages == 0
            || table_pages > APPLICATION_TABLE_PAGES
            || address_space.user_region_count() != application_user_regions
        {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let table_pages = u16::try_from(table_pages).map_err(|_| ())?;
        let handle_count = u16::try_from(services.len()).map_err(|_| ())?;
        let Ok(isolation) = IsolationResource::new(0, table_pages, private_pages, handle_count)
        else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(stack_resource) = StackResource::new(0, stack_pages) else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(task_id) =
            scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
        else {
            reclaim_application(&mut accounting.frames, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Task).is_err() {
            rollback_application_task(
                scheduler,
                task_id,
                dispatcher,
                None,
                &mut accounting.frames,
                allocation,
            )?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }

        let entry = plan.entry_address();
        let layout = plan.layout();
        let mut live_owner = None;
        let setup = (|| -> Result<HandleOwner, ()> {
            let owner = HandleOwner::isolated(task_id.get()).map_err(|_| ())?;
            live_owner = Some(owner);
            let mut startup_handles = Vec::new();
            startup_handles
                .try_reserve_exact(services.len())
                .map_err(|_| ())?;
            for service in services {
                let handle = dispatcher
                    .open_owned(service.port, Rights::CALL, owner)
                    .map_err(|_| ())?;
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
            Ok(owner)
        })();
        let Ok(owner) = setup else {
            rollback_application_task(
                scheduler,
                task_id,
                dispatcher,
                live_owner,
                &mut accounting.frames,
                allocation,
            )?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        drop(plan);
        drop(mapping_plan);
        if transaction.commit().is_err() {
            rollback_application_task(
                scheduler,
                task_id,
                dispatcher,
                live_owner,
                &mut accounting.frames,
                allocation,
            )?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }

        let execution = (|| -> Result<CommandApplicationOutcome, ()> {
            if scheduler
                .dispatch_next(Capabilities::SERVICE)
                .map_err(|_| ())?
                != Some(task_id)
            {
                return Err(());
            }
            let mut outcome = troe_machine::run_application(
                address_space,
                entry,
                layout.stack_top(),
                layout.startup_address(),
                PAGE_BYTES,
            )
            .map_err(|_| ())?;
            let mut steps = 0_u16;
            let terminal = loop {
                match outcome {
                    troe_machine::ApplicationOutcome::Yielded(application) => {
                        steps = steps.checked_add(1).ok_or(())?;
                        if steps > APPLICATION_COMMAND_STEP_LIMIT {
                            scheduler
                                .fault_current(task_id, TaskFault::ExecutionLeaseExpired)
                                .map_err(|_| ())?;
                            break CommandApplicationOutcome::Faulted(
                                TaskFault::ExecutionLeaseExpired,
                            );
                        }
                        scheduler.yield_current(task_id).map_err(|_| ())?;
                        if scheduler
                            .dispatch_next(Capabilities::SERVICE)
                            .map_err(|_| ())?
                            != Some(task_id)
                        {
                            return Err(());
                        }
                        outcome = troe_machine::resume_application(
                            application,
                            troe_machine::ApplicationResume::Yield,
                        )
                        .map_err(|_| ())?;
                    }
                    troe_machine::ApplicationOutcome::HandleCall { application, call } => {
                        steps = steps.checked_add(1).ok_or(())?;
                        if steps > APPLICATION_COMMAND_STEP_LIMIT || call.request_bytes() < 2 {
                            scheduler
                                .fault_current(task_id, TaskFault::InvalidCall)
                                .map_err(|_| ())?;
                            break CommandApplicationOutcome::Faulted(TaskFault::InvalidCall);
                        }
                        let mut request = Vec::new();
                        request
                            .try_reserve_exact(call.request_bytes())
                            .map_err(|_| ())?;
                        request.resize(call.request_bytes(), 0);
                        application.copy_request(&mut request).map_err(|_| ())?;
                        let opcode = u16::from_le_bytes([request[0], request[1]]);
                        let Ok(reply) =
                            dispatcher.call_owned_abi(owner, call.handle(), opcode, &request[2..])
                        else {
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
                        )
                        .map_err(|_| ())?;
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
            live_owner = None;
            Ok(terminal)
        })();
        let Ok(terminal) = execution else {
            rollback_application_task(
                scheduler,
                task_id,
                dispatcher,
                live_owner,
                &mut accounting.frames,
                allocation,
            )?;
            return Err(());
        };
        let Ok(reaped) = scheduler.reap(task_id) else {
            rollback_application_task(
                scheduler,
                task_id,
                dispatcher,
                live_owner,
                &mut accounting.frames,
                allocation,
            )?;
            return Err(());
        };
        let expected_fault = match terminal {
            CommandApplicationOutcome::Exited(_) => None,
            CommandApplicationOutcome::Faulted(fault) => Some(fault),
        };
        let valid_reap = reaped.isolation == Some(isolation)
            && reaped.stack.mapped_pages() == stack_pages
            && reaped.fault == expected_fault;
        reclaim_application(&mut accounting.frames, allocation)?;
        if !valid_reap {
            return Err(());
        }
        Ok(terminal)
    }

    const fn task_fault(fault: troe_machine::IsolatedFault) -> TaskFault {
        match fault {
            troe_machine::IsolatedFault::Translation => TaskFault::Translation,
            troe_machine::IsolatedFault::Permission => TaskFault::Permission,
            troe_machine::IsolatedFault::IllegalInstruction => TaskFault::IllegalInstruction,
            troe_machine::IsolatedFault::InvalidCall => TaskFault::InvalidCall,
            troe_machine::IsolatedFault::ExecutionLeaseExpired => TaskFault::ExecutionLeaseExpired,
        }
    }

    fn allocate_application(
        frames: &mut FrameAllocator,
        plan: &LoadPlan<'_>,
    ) -> Result<ApplicationAllocation, ()> {
        let resource_pages = APPLICATION_TABLE_PAGES
            .checked_add(plan.charges().private_pages())
            .ok_or(())?;
        let complete = frames
            .allocate_contiguous(resource_pages, 1)
            .map_err(|_| ())?;
        let derived = (|| {
            let tables = PhysicalRange::from_pages(complete.start(), APPLICATION_TABLE_PAGES)
                .map_err(|_| ())?;
            let private = PhysicalRange::from_pages(tables.end(), plan.charges().private_pages())
                .map_err(|_| ())?;
            let image = PhysicalRange::from_pages(private.start(), plan.charges().image_pages())
                .map_err(|_| ())?;
            let startup = PhysicalRange::from_pages(image.end(), 1).map_err(|_| ())?;
            let heap = if plan.heap_pages() == 0 {
                None
            } else {
                Some(PhysicalRange::from_pages(startup.end(), plan.heap_pages()).map_err(|_| ())?)
            };
            let stack_start = heap.map_or(startup.end(), PhysicalRange::end);
            let stack =
                PhysicalRange::from_pages(stack_start, plan.stack_pages()).map_err(|_| ())?;
            if stack.end() != complete.end() {
                return Err(());
            }
            Ok(ApplicationAllocation {
                complete,
                tables,
                image,
                startup,
                heap,
                stack,
            })
        })();
        if derived.is_err() {
            frames.free_range(complete).map_err(|_| ())?;
        }
        derived
    }

    fn prepare_application_memory(
        allocation: &ApplicationAllocation,
        plan: &LoadPlan<'_>,
    ) -> Result<(), ()> {
        troe_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
        let mut physical_start = allocation.image.start();
        for segment in plan.segments() {
            let physical =
                PhysicalRange::from_pages(physical_start, segment.memory_bytes() / BASE_PAGE_SIZE)
                    .map_err(|_| ())?;
            troe_machine::copy_to_physical(physical, 0, segment.file_bytes()).map_err(|_| ())?;
            physical_start = physical.end();
        }
        if physical_start != allocation.image.end() {
            return Err(());
        }
        Ok(())
    }

    fn build_application_plan(
        kernel: &MappingPlan,
        kernel_runtime: PhysicalRange,
        allocation: &ApplicationAllocation,
        application: &LoadPlan<'_>,
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

        let mut physical_start = allocation.image.start();
        for segment in application.segments() {
            let physical =
                PhysicalRange::from_pages(physical_start, segment.memory_bytes() / BASE_PAGE_SIZE)
                    .map_err(|_| ())?;
            let permissions = match segment.permissions() {
                SegmentPermissions::ReadOnly => MappingPermissions::READ_ONLY,
                SegmentPermissions::ReadExecute => MappingPermissions::READ_EXECUTE,
                SegmentPermissions::ReadWrite => MappingPermissions::READ_WRITE,
            };
            insert_application_mapping(
                &mut plan,
                segment.virtual_address(),
                physical,
                permissions,
            )?;
            physical_start = physical.end();
        }
        if physical_start != allocation.image.end() {
            return Err(());
        }
        insert_application_mapping(
            &mut plan,
            application.layout().startup_address(),
            allocation.startup,
            MappingPermissions::READ_ONLY,
        )?;
        if let Some(heap) = allocation.heap {
            insert_application_mapping(
                &mut plan,
                application.layout().heap_address(),
                heap,
                MappingPermissions::READ_WRITE,
            )?;
        }
        insert_application_mapping(
            &mut plan,
            application.layout().stack_bottom(),
            allocation.stack,
            MappingPermissions::READ_WRITE,
        )?;
        if !plan.enforces_global_w_xor_x() {
            return Err(());
        }
        Ok(plan)
    }

    fn insert_application_mapping(
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

    fn rollback_application_task(
        scheduler: &mut Scheduler,
        task_id: TaskId,
        dispatcher: &mut Dispatcher<'_>,
        owner: Option<HandleOwner>,
        frames: &mut FrameAllocator,
        allocation: ApplicationAllocation,
    ) -> Result<(), ()> {
        terminate_revoke_and_reap_task(scheduler, task_id, dispatcher, owner)?;
        reclaim_application(frames, allocation)
    }

    fn clear_provisional_loader_ownership(transaction: &mut LoaderTransaction) {
        transaction.rollback(|_resource| {});
    }

    /// Complete the scheduler/capability portion of ADR 0014 teardown.
    ///
    /// Physical allocations remain owned by the caller until this returns, so
    /// no zeroization or frame release can precede terminalization, revocation,
    /// and reaping. Any failure deliberately leaks the retained allocation into
    /// the terminal boot path instead of making it reusable prematurely.
    fn terminate_revoke_and_reap_task(
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
    fn reclaim_application(
        frames: &mut FrameAllocator,
        allocation: ApplicationAllocation,
    ) -> Result<(), ()> {
        troe_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
        frames.free_range(allocation.complete).map_err(|_| ())
    }

    const fn native_application_target() -> Target {
        #[cfg(target_arch = "x86_64")]
        {
            Target::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Target::Aarch64
        }
    }

    fn native_kex_artifact(probe: ApplicationProbe) -> &'static [u8] {
        match probe {
            ApplicationProbe::Calls => {
                #[cfg(target_arch = "x86_64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-calls-x86_64.kex")
                }
                #[cfg(target_arch = "aarch64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-calls-aarch64.kex")
                }
            }
            #[cfg(feature = "acceptance-probes")]
            ApplicationProbe::Spin => {
                #[cfg(target_arch = "x86_64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-spin-x86_64.kex")
                }
                #[cfg(target_arch = "aarch64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-spin-aarch64.kex")
                }
            }
            #[cfg(feature = "acceptance-probes")]
            ApplicationProbe::InvalidCall => {
                #[cfg(target_arch = "x86_64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-invalid-call-x86_64.kex")
                }
                #[cfg(target_arch = "aarch64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-invalid-call-aarch64.kex")
                }
            }
            #[cfg(feature = "acceptance-probes")]
            ApplicationProbe::UnexpectedReturn => {
                #[cfg(target_arch = "x86_64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-unexpected-return-x86_64.kex")
                }
                #[cfg(target_arch = "aarch64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-unexpected-return-aarch64.kex")
                }
            }
        }
    }

    fn rollback_isolated_task(
        scheduler: &mut Scheduler,
        task_id: TaskId,
        dispatcher: &mut Dispatcher<'_>,
        owner: Option<HandleOwner>,
        frames: &mut FrameAllocator,
        allocation: IsolatedAllocation,
    ) -> Result<(), ()> {
        terminate_revoke_and_reap_task(scheduler, task_id, dispatcher, owner)?;
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
        troe_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
        let code = isolated_program(probe)?;
        troe_machine::copy_to_physical(allocation.code, 0, &code).map_err(|_| ())?;
        if matches!(
            probe,
            IsolationProbe::Success
                | IsolationProbe::InvalidOpcode
                | IsolationProbe::InvalidCallEncoding
                | IsolationProbe::InvalidPointer
                | IsolationProbe::OversizeMessage
                | IsolationProbe::InvalidStatus
        ) {
            troe_machine::copy_to_physical(allocation.data, 0, ISOLATED_MESSAGE).map_err(|_| ())?;
        }
        Ok(())
    }

    #[allow(clippy::needless_pass_by_value)] // Consuming the token prevents double teardown.
    fn reclaim_isolated(
        frames: &mut FrameAllocator,
        allocation: IsolatedAllocation,
    ) -> Result<(), ()> {
        troe_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
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
        let user_mappings: [(u64, PhysicalRange, MappingPermissions); STAGE6_USER_REGIONS] = [
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
        ];
        for (virtual_start, physical, permissions) in user_mappings {
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
                u32::try_from(troe_dispatch::MAX_MESSAGE_BYTES + 1).map_err(|_| ())?,
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

    fn write_boot_status(output: &mut dyn Output, label: &str, ok: bool) -> Result<(), ()> {
        let mut line = String::from(" * ");
        line.push_str(label);
        line.push(' ');
        while line.len() < BOOT_STATUS_WIDTH {
            line.push('.');
        }
        if ok {
            line.push_str(" [ OK ]\n");
        } else {
            line.push_str(" [ ERR ]\n");
        }
        write_all(output, line.as_bytes())
    }

    fn write_machine_boot_status(label: &str, ok: bool) -> bool {
        write_boot_status(&mut NativeConsole, label, ok).is_ok()
    }

    fn write_ipv4(output: &mut String, address: [u8; 4]) -> core::fmt::Result {
        write!(
            output,
            "{}.{}.{}.{}",
            address[0], address[1], address[2], address[3]
        )
    }

    fn subnet_prefix(mask: [u8; 4]) -> u32 {
        mask.into_iter().map(u8::count_ones).sum()
    }

    fn network_boot_label(status: NetworkStatus) -> String {
        let mut label = String::from("Configuring network");
        if let Some(address) = status.address {
            label.push_str(": ");
            let _formatted = write_ipv4(&mut label, address);
            if let Some(mask) = status.subnet_mask {
                let _formatted = write!(&mut label, "/{}", subnet_prefix(mask));
            }
        }
        label
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
                scheduler
                    .exit_current(id, u32::from(status))
                    .map_err(|_| ())?;
                let reaped = scheduler.reap(id).map_err(|_| ())?;
                if reaped.exit_status != u32::from(status) {
                    return Err(());
                }
                if reusable.is_none() {
                    *reusable = Some(reaped.stack);
                }
                Ok(true)
            }
        }
    }

    fn write_shell_banner(
        console: &mut dyn Output,
        motd: &[u8],
        native_root: bool,
        network: Option<NetworkStatus>,
    ) -> bool {
        if write_all(console, b"\n").is_err()
            || write_all(console, motd).is_err()
            || !motd.ends_with(b"\n") && write_all(console, b"\n").is_err()
            || write_all(console, b"\n").is_err()
        {
            return false;
        }

        let root = if native_root {
            "/vol/root (read-only)"
        } else {
            "recovery root (read-only)"
        };
        let mut summary = String::new();
        let _formatted = write!(&mut summary, "{} | {root} | ", architecture());
        if let Some(address) = network.and_then(|status| status.address) {
            let _formatted = write_ipv4(&mut summary, address);
            if let Some(mask) = network.and_then(|status| status.subnet_mask) {
                let _formatted = write!(&mut summary, "/{}", subnet_prefix(mask));
            }
        } else {
            summary.push_str("network unavailable");
        }
        summary.push_str(
            "\n\nWelcome to TROE.\nType `man COMMAND` for help. Tab completes commands.\n\n",
        );
        write_all(console, summary.as_bytes()).is_ok()
    }

    fn append_internal_storage_report(
        report: &mut String,
        generation: NativeGenerationState,
        statefs_mounted: bool,
    ) -> Result<(), ()> {
        let activation = RegionSelector::parse(PERSISTENCE_SELECTOR).map_err(|_| ())?;
        let statefs = RegionSelector::parse(STATEFS_SELECTOR).map_err(|_| ())?;
        report.push_str("internal activation disk=");
        write_storage_identity(report, activation.disk_guid())?;
        report.push_str(" partition=");
        write_storage_identity(report, activation.partition_guid())?;
        report.push_str(" type=");
        write_storage_identity(report, activation.partition_type_guid())?;
        writeln!(report, " state={}", generation.name()).map_err(|_| ())?;
        report.push_str("internal statefs disk=");
        write_storage_identity(report, statefs.disk_guid())?;
        report.push_str(" partition=");
        write_storage_identity(report, statefs.partition_guid())?;
        report.push_str(" type=");
        write_storage_identity(report, statefs.partition_type_guid())?;
        writeln!(
            report,
            " state={}",
            if statefs_mounted {
                "mounted"
            } else {
                "missing"
            }
        )
        .map_err(|_| ())?;
        if report.len() > MAX_STORAGE_REPORT_BYTES {
            return Err(());
        }
        Ok(())
    }

    fn write_storage_identity(report: &mut String, identity: [u8; 16]) -> Result<(), ()> {
        for byte in identity {
            write!(report, "{byte:02x}").map_err(|_| ())?;
        }
        Ok(())
    }

    fn activate_native_storage(
        accounting: &OwnedAccounting,
        namespace: &mut Namespace,
        console: &mut dyn Output,
    ) -> bool {
        let limits = native_activation_limits()
            .unwrap_or_else(|()| fatal(b"fatal: invalid native storage limits\n"));
        let devices = core::mem::take(&mut *accounting.native_blocks.borrow_mut());
        let activation = prepare_read_only(&accounting.boot_mount_manifest, devices, limits)
            .unwrap_or_else(|_| fatal(b"fatal: native storage activation failed\n"));
        let desired_system_available = activation.desired_system_available();
        let root_mounted = activation
            .mounts()
            .iter()
            .any(|mount| mount.path() == "/vol/root");
        let mut storage_report = String::new();
        let report_capacity = activation
            .report()
            .len()
            .checked_add(STORAGE_REPORT_EXTENSION_BYTES)
            .unwrap_or_else(|| fatal(b"fatal: native storage diagnostic overflow\n"));
        if storage_report.try_reserve_exact(report_capacity).is_err() {
            fatal(b"fatal: cannot retain native storage diagnostic\n");
        }
        storage_report.push_str(activation.report());
        for mount in activation.into_mounts() {
            mount
                .attach(namespace)
                .unwrap_or_else(|_| fatal(b"fatal: cannot attach native filesystem provider\n"));
        }
        let statefs_mounted = accounting.native_statefs.borrow().is_some();
        if let Some(statefs) = accounting.native_statefs.borrow_mut().take() {
            namespace
                .mount_writable("/vol/state", statefs)
                .unwrap_or_else(|_| fatal(b"fatal: cannot attach native state filesystem\n"));
        }
        append_internal_storage_report(
            &mut storage_report,
            accounting.native_generation,
            statefs_mounted,
        )
        .unwrap_or_else(|()| fatal(b"fatal: cannot extend native storage diagnostic\n"));
        namespace
            .set_system_file("/sys/storage", storage_report.as_bytes())
            .unwrap_or_else(|_| fatal(b"fatal: cannot publish native storage diagnostic\n"));
        if desired_system_available
            && root_mounted
            && accounting.native_generation.desired_system_available()
        {
            if write_boot_status(console, "Mounting /vol/root read-only", true).is_err() {
                fatal(b"fatal: native storage diagnostic failed\n");
            }
            true
        } else {
            if write_boot_status(console, "Mounting recovery root read-only", true).is_err() {
                fatal(b"fatal: native storage diagnostic failed\n");
            }
            false
        }
    }

    fn compose_namespace(
        accounting: &OwnedAccounting,
        console: &mut dyn Output,
    ) -> (Namespace, bool) {
        let mut namespace = Namespace::new(RamFsQuota::default());
        if namespace.mount_embedded(ROOTFS).is_err() {
            fatal(b"fatal: cannot mount embedded root\n");
        }
        let native_root = activate_native_storage(accounting, &mut namespace, console);
        (namespace, native_root)
    }

    impl KernelNetworkService {
        const POLL_BUDGET: usize = 8;
        const INBOX_CAPACITY: usize = 4;

        fn new(device: troe_machine::NativeVirtioNetwork) -> Result<Self, NetError> {
            let mut dhcp_inbox = VecDeque::new();
            dhcp_inbox
                .try_reserve_exact(Self::INBOX_CAPACITY)
                .map_err(|_| NetError::Exhausted)?;
            let mut echo_inbox = VecDeque::new();
            echo_inbox
                .try_reserve_exact(Self::INBOX_CAPACITY)
                .map_err(|_| NetError::Exhausted)?;
            Ok(Self {
                device,
                configuration: None,
                next_sequence: 1,
                next_port: 49_152,
                dhcp_generation: 0,
                arp: ArpCache::new(),
                udp: UdpPortTable::new()?,
                dhcp_inbox,
                echo_inbox,
                stats: NetworkServiceStats::default(),
            })
        }

        fn shell_status(&self) -> NetworkStatus {
            NetworkStatus {
                mac: self.device.mac_address().bytes(),
                address: self.configuration.map(|value| value.address.bytes()),
                subnet_mask: self.configuration.map(|value| value.subnet_mask.bytes()),
                gateway: self.configuration.map(|value| value.gateway.bytes()),
                lease_seconds: self.configuration.and_then(|value| value.lease_seconds),
            }
        }

        fn next_dhcp_transaction(&mut self) -> u32 {
            self.dhcp_generation = self.dhcp_generation.wrapping_add(1);
            let mac = self.device.mac_address().bytes();
            u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]])
                ^ u32::from(self.dhcp_generation)
                ^ 0x5452_4f45
        }

        fn transmit(&mut self, frame: &[u8]) -> Result<(), NetworkError> {
            match self.device.transmit(frame) {
                Ok(()) => {
                    self.stats.transmitted_frames = self.stats.transmitted_frames.saturating_add(1);
                    Ok(())
                }
                Err(error) => {
                    self.stats.errors = self.stats.errors.saturating_add(1);
                    Err(map_network_error(error))
                }
            }
        }

        fn poll(&mut self) -> Result<(), NetworkError> {
            self.stats.checkpoints = self.stats.checkpoints.saturating_add(1);
            for _ in 0..Self::POLL_BUDGET {
                let frame = match self.device.receive() {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error) => {
                        self.stats.errors = self.stats.errors.saturating_add(1);
                        return Err(map_network_error(error));
                    }
                };
                self.stats.received_frames = self.stats.received_frames.saturating_add(1);
                if self.handle_frame(&frame).is_err() {
                    self.stats.errors = self.stats.errors.saturating_add(1);
                }
            }
            Ok(())
        }

        fn handle_frame(&mut self, frame: &[u8]) -> Result<(), NetworkError> {
            if let Ok(packet) = parse_dhcp(frame) {
                if self.dhcp_inbox.len() < Self::INBOX_CAPACITY {
                    self.dhcp_inbox.push_back(packet);
                }
                return Ok(());
            }
            if let Ok(arp) = parse_arp(frame) {
                self.arp.learn(arp.sender_ip, arp.sender_mac);
                let Some(configuration) = self.configuration else {
                    return Ok(());
                };
                if arp.operation == 1 && arp.target_ip == configuration.address {
                    let reply = build_arp_reply(
                        self.device.mac_address(),
                        configuration.address,
                        arp.sender_mac,
                        arp.sender_ip,
                    )
                    .map_err(map_network_error)?;
                    self.transmit(&reply)?;
                    self.stats.arp_replies = self.stats.arp_replies.saturating_add(1);
                }
                return Ok(());
            }
            let Some(configuration) = self.configuration else {
                self.stats.ignored_frames = self.stats.ignored_frames.saturating_add(1);
                return Ok(());
            };
            if let Ok(echo) = parse_icmp_echo(frame)
                && echo.destination_ip == configuration.address
            {
                self.arp.learn(echo.source_ip, echo.source_mac);
                if echo.kind == 8 {
                    let reply = build_icmp_echo(
                        self.device.mac_address(),
                        echo.source_mac,
                        configuration.address,
                        echo.source_ip,
                        0,
                        echo.identifier,
                        echo.sequence,
                        echo.payload,
                    )
                    .map_err(map_network_error)?;
                    self.transmit(&reply)?;
                    self.stats.icmp_replies = self.stats.icmp_replies.saturating_add(1);
                } else if echo.kind == 0 && self.echo_inbox.len() < Self::INBOX_CAPACITY {
                    self.echo_inbox.push_back(EchoReply {
                        source: echo.source_ip,
                        identifier: echo.identifier,
                        sequence: echo.sequence,
                        bytes: echo.payload.len(),
                    });
                }
                return Ok(());
            }
            if let Ok(datagram) = parse_udp(frame)
                && datagram.destination_ip == configuration.address
            {
                self.arp.learn(datagram.source_ip, datagram.source_mac);
                match self.udp.admit(datagram).map_err(map_network_error)? {
                    UdpAdmission::Retained => {
                        self.stats.udp_retained = self.stats.udp_retained.saturating_add(1);
                    }
                    UdpAdmission::Unbound => {
                        self.stats.udp_unbound = self.stats.udp_unbound.saturating_add(1);
                    }
                    UdpAdmission::Dropped => {
                        self.stats.udp_dropped = self.stats.udp_dropped.saturating_add(1);
                    }
                }
                return Ok(());
            }
            self.stats.ignored_frames = self.stats.ignored_frames.saturating_add(1);
            Ok(())
        }

        fn take_dhcp(&mut self, transaction_id: u32) -> Option<DhcpPacket> {
            let index = self.dhcp_inbox.iter().position(|packet| {
                packet.transaction_id == transaction_id
                    && packet.client_mac == self.device.mac_address()
            })?;
            self.dhcp_inbox.remove(index)
        }

        fn take_echo(&mut self, identifier: u16, sequence: u16) -> Option<EchoReply> {
            let index = self
                .echo_inbox
                .iter()
                .position(|reply| reply.identifier == identifier && reply.sequence == sequence)?;
            self.echo_inbox.remove(index)
        }
    }

    impl KernelNetwork {
        const WAIT_MILLISECONDS: u64 = 2_000;

        fn new(service: SharedNetwork) -> Self {
            Self { service }
        }

        fn configure_dhcp(
            &mut self,
            runtime: &mut dyn CooperativeRuntime,
        ) -> Result<NetworkStatus, NetworkError> {
            let (transaction_id, mac) = {
                let mut service = self.service.borrow_mut();
                (
                    service.next_dhcp_transaction(),
                    service.device.mac_address(),
                )
            };
            let discover = build_dhcp_discover(mac, transaction_id).map_err(map_network_error)?;
            self.service.borrow_mut().transmit(&discover)?;
            let offer = self.wait_for_dhcp(transaction_id, DhcpMessageType::Offer, runtime)?;
            let server = offer.server_identifier.ok_or(NetworkError::Protocol)?;
            let request = build_dhcp_request(mac, transaction_id, offer.your_ip, server)
                .map_err(map_network_error)?;
            self.service.borrow_mut().transmit(&request)?;
            let acknowledgement =
                self.wait_for_dhcp(transaction_id, DhcpMessageType::Acknowledge, runtime)?;
            let subnet_mask = acknowledgement
                .subnet_mask
                .or(offer.subnet_mask)
                .ok_or(NetworkError::Protocol)?;
            let gateway = acknowledgement
                .router
                .or(offer.router)
                .ok_or(NetworkError::Protocol)?;
            let address = acknowledgement.your_ip;
            if address.bytes() == [0; 4] {
                return Err(NetworkError::Protocol);
            }
            let mut service = self.service.borrow_mut();
            service.configuration = Some(Ipv4Configuration {
                address,
                subnet_mask,
                gateway,
                lease_seconds: acknowledgement.lease_seconds.or(offer.lease_seconds),
            });
            Ok(service.shell_status())
        }

        fn wait_for_dhcp(
            &self,
            transaction_id: u32,
            wanted: DhcpMessageType,
            runtime: &mut dyn CooperativeRuntime,
        ) -> Result<DhcpPacket, NetworkError> {
            let deadline = runtime.now().saturating_add(Self::WAIT_MILLISECONDS);
            while runtime.now() < deadline {
                runtime.checkpoint().map_err(|_| NetworkError::Cancelled)?;
                if let Some(packet) = self.service.borrow_mut().take_dhcp(transaction_id) {
                    if packet.message_type == DhcpMessageType::NegativeAcknowledge {
                        return Err(NetworkError::Protocol);
                    }
                    if packet.message_type == wanted {
                        return Ok(packet);
                    }
                }
            }
            Err(NetworkError::Timeout)
        }

        fn resolve(
            &self,
            destination: Ipv4Address,
            runtime: &mut dyn CooperativeRuntime,
        ) -> Result<MacAddress, NetworkError> {
            let (next_hop, request) = {
                let service = self.service.borrow();
                let configuration = service.configuration.ok_or(NetworkError::NotConfigured)?;
                let next_hop = if same_subnet(
                    configuration.address,
                    destination,
                    configuration.subnet_mask,
                ) {
                    destination
                } else {
                    configuration.gateway
                };
                if let Some(mac) = service.arp.lookup(next_hop) {
                    return Ok(mac);
                }
                let request = build_arp_request(
                    service.device.mac_address(),
                    configuration.address,
                    next_hop,
                )
                .map_err(map_network_error)?;
                (next_hop, request)
            };
            self.service.borrow_mut().transmit(&request)?;
            let deadline = runtime.now().saturating_add(Self::WAIT_MILLISECONDS);
            while runtime.now() < deadline {
                runtime.checkpoint().map_err(|_| NetworkError::Cancelled)?;
                if let Some(mac) = self.service.borrow().arp.lookup(next_hop) {
                    return Ok(mac);
                }
            }
            Err(NetworkError::Timeout)
        }
    }

    impl NetworkControl for KernelNetwork {
        fn status(&self) -> NetworkStatus {
            self.service.borrow().shell_status()
        }

        fn stats(&self) -> NetworkStats {
            let service = self.service.borrow();
            NetworkStats {
                received_frames: service.stats.received_frames,
                transmitted_frames: service.stats.transmitted_frames,
                arp_replies: service.stats.arp_replies,
                icmp_replies: service.stats.icmp_replies,
                udp_retained: service.stats.udp_retained,
                udp_unbound: service.stats.udp_unbound,
                udp_dropped: service.stats.udp_dropped,
                arp_entries: service.arp.len(),
                udp_ports: service.udp.len(),
                checkpoints: service.stats.checkpoints,
                errors: service.stats.errors,
            }
        }

        fn arp_entries(&self) -> Vec<ArpEntry> {
            self.service
                .borrow()
                .arp
                .entries()
                .map(|entry| ArpEntry {
                    address: entry.address.bytes(),
                    mac: entry.mac.bytes(),
                })
                .collect()
        }

        fn dhcp(
            &mut self,
            runtime: &mut dyn CooperativeRuntime,
        ) -> Result<NetworkStatus, NetworkError> {
            self.configure_dhcp(runtime)
        }

        fn ping(
            &mut self,
            destination: [u8; 4],
            runtime: &mut dyn CooperativeRuntime,
        ) -> Result<PingReply, NetworkError> {
            let configuration = self
                .service
                .borrow()
                .configuration
                .ok_or(NetworkError::NotConfigured)?;
            let destination = Ipv4Address::new(destination);
            if destination == configuration.address {
                let mut service = self.service.borrow_mut();
                let sequence = service.next_sequence;
                service.next_sequence = service.next_sequence.wrapping_add(1);
                return Ok(PingReply {
                    source: destination.bytes(),
                    sequence,
                    bytes: 9,
                });
            }
            let destination_mac = self.resolve(destination, runtime)?;
            let (source_mac, sequence) = {
                let mut service = self.service.borrow_mut();
                let sequence = service.next_sequence;
                service.next_sequence = service.next_sequence.wrapping_add(1);
                (service.device.mac_address(), sequence)
            };
            let request = build_icmp_echo(
                source_mac,
                destination_mac,
                configuration.address,
                destination,
                8,
                0x5452,
                sequence,
                b"troe-ping",
            )
            .map_err(map_network_error)?;
            self.service.borrow_mut().transmit(&request)?;
            let deadline = runtime.now().saturating_add(Self::WAIT_MILLISECONDS);
            while runtime.now() < deadline {
                runtime.checkpoint().map_err(|_| NetworkError::Cancelled)?;
                if let Some(echo) = self.service.borrow_mut().take_echo(0x5452, sequence)
                    && echo.source == destination
                {
                    return Ok(PingReply {
                        source: echo.source.bytes(),
                        sequence,
                        bytes: echo.bytes,
                    });
                }
            }
            Err(NetworkError::Timeout)
        }

        fn send_udp(
            &mut self,
            source_port: Option<u16>,
            destination: [u8; 4],
            destination_port: u16,
            payload: &[u8],
            runtime: &mut dyn CooperativeRuntime,
        ) -> Result<u16, NetworkError> {
            if payload.len() > MAX_UDP_PAYLOAD_BYTES {
                return Err(NetworkError::TooLarge);
            }
            let configuration = self
                .service
                .borrow()
                .configuration
                .ok_or(NetworkError::NotConfigured)?;
            let destination = Ipv4Address::new(destination);
            let destination_mac = self.resolve(destination, runtime)?;
            let source_port = if let Some(port) = source_port {
                self.service
                    .borrow_mut()
                    .udp
                    .bind(port)
                    .map_err(map_network_error)?;
                port
            } else {
                let mut service = self.service.borrow_mut();
                let mut selected = None;
                for _ in 0..troe_net::MAX_UDP_PORTS {
                    let port = service.next_port;
                    service.next_port = if port == u16::MAX { 49_152 } else { port + 1 };
                    if !service.udp.is_bound(port) {
                        service.udp.bind(port).map_err(map_network_error)?;
                        selected = Some(port);
                        break;
                    }
                }
                selected.ok_or(NetworkError::Exhausted)?
            };
            let source_mac = self.service.borrow().device.mac_address();
            let datagram = build_udp(
                source_mac,
                destination_mac,
                configuration.address,
                destination,
                source_port,
                destination_port,
                payload,
            )
            .map_err(map_network_error)?;
            self.service.borrow_mut().transmit(&datagram)?;
            Ok(source_port)
        }

        fn listen_udp(
            &mut self,
            local_port: u16,
            runtime: &mut dyn CooperativeRuntime,
        ) -> Result<ReceivedUdp, NetworkError> {
            if self.service.borrow().configuration.is_none() {
                return Err(NetworkError::NotConfigured);
            }
            self.service
                .borrow_mut()
                .udp
                .bind(local_port)
                .map_err(map_network_error)?;
            loop {
                if let Some(datagram) = self.service.borrow_mut().udp.receive(local_port) {
                    return Ok(ReceivedUdp {
                        source: datagram.source_ip.bytes(),
                        source_port: datagram.source_port,
                        payload: datagram.payload,
                    });
                }
                runtime.checkpoint().map_err(|_| NetworkError::Cancelled)?;
            }
        }
    }

    impl<'namespace> ApplicationFilesystemService<'namespace> {
        fn new(namespace: SharedNamespace<'namespace>, cwd: &str) -> Result<Self, ()> {
            let mut owned_cwd = String::new();
            owned_cwd.try_reserve_exact(cwd.len()).map_err(|_| ())?;
            owned_cwd.push_str(cwd);
            Ok(Self {
                namespace,
                cwd: owned_cwd,
                files: core::array::from_fn(|_| ApplicationFileSlot {
                    generation: 1,
                    retired: false,
                    path: None,
                    byte_count: 0,
                }),
            })
        }

        fn open(&mut self, path: &str) -> Result<filesystem::OpenFile, ReplyStatus> {
            let metadata = self
                .namespace
                .borrow_mut()
                .metadata(&self.cwd, path)
                .map_err(application_filesystem_status)?;
            if metadata.kind != NodeKind::File {
                return Err(ReplyStatus::WrongType);
            }
            let Some((index, slot)) = self
                .files
                .iter_mut()
                .enumerate()
                .find(|(_, slot)| slot.path.is_none() && !slot.retired)
            else {
                return Err(ReplyStatus::Exhausted);
            };
            if slot.generation > 0x00ff_ffff {
                slot.retired = true;
                return Err(ReplyStatus::Exhausted);
            }
            let mut owned_path = String::new();
            owned_path
                .try_reserve_exact(path.len())
                .map_err(|_| ReplyStatus::Exhausted)?;
            owned_path.push_str(path);
            slot.path = Some(owned_path);
            slot.byte_count = metadata.byte_count;
            let token = (slot.generation << 8)
                | u32::try_from(index + 1).map_err(|_| ReplyStatus::Failure)?;
            filesystem::OpenFile::new(token, metadata.byte_count).map_err(|_| ReplyStatus::Failure)
        }

        fn slot(
            files: &[ApplicationFileSlot; filesystem::MAX_OPEN_FILES],
            token: u32,
        ) -> Result<&ApplicationFileSlot, ReplyStatus> {
            let encoded_slot = token & 0xff;
            let generation = token >> 8;
            if encoded_slot == 0 || generation == 0 {
                return Err(ReplyStatus::InvalidRequest);
            }
            let slot = files
                .get(usize::try_from(encoded_slot - 1).map_err(|_| ReplyStatus::InvalidRequest)?)
                .ok_or(ReplyStatus::InvalidRequest)?;
            if slot.generation != generation || slot.path.is_none() {
                return Err(ReplyStatus::InvalidRequest);
            }
            Ok(slot)
        }

        fn close(&mut self, token: u32) -> Result<(), ReplyStatus> {
            let encoded_slot = token & 0xff;
            let generation = token >> 8;
            if encoded_slot == 0 || generation == 0 {
                return Err(ReplyStatus::InvalidRequest);
            }
            let slot = self
                .files
                .get_mut(
                    usize::try_from(encoded_slot - 1).map_err(|_| ReplyStatus::InvalidRequest)?,
                )
                .ok_or(ReplyStatus::InvalidRequest)?;
            if slot.generation != generation || slot.path.is_none() {
                return Err(ReplyStatus::InvalidRequest);
            }
            slot.path = None;
            slot.byte_count = 0;
            match slot.generation.checked_add(1) {
                Some(generation) if generation <= 0x00ff_ffff => slot.generation = generation,
                _ => slot.retired = true,
            }
            Ok(())
        }
    }

    impl Service for ApplicationFilesystemService<'_> {
        #[allow(clippy::too_many_lines)]
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                filesystem::OPEN => {
                    let Ok(path) = filesystem::decode_path_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let file = match self.open(path) {
                        Ok(file) => file,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &filesystem::encode_open_reply(file),
                    )
                }
                filesystem::READ => {
                    let Ok((token, offset, requested)) =
                        filesystem::decode_read_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let path = match Self::slot(&self.files, token)
                        .and_then(|slot| slot.path.as_deref().ok_or(ReplyStatus::InvalidRequest))
                    {
                        Ok(path) => path,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
                    let count = match self.namespace.borrow_mut().read_file_at(
                        &self.cwd,
                        path,
                        offset,
                        &mut bytes[..requested],
                    ) {
                        Ok(count) if count <= requested => count,
                        Ok(_) => return Ok(ServiceReply::empty(ReplyStatus::Corrupt)),
                        Err(error) => {
                            return Ok(ServiceReply::empty(application_filesystem_status(error)));
                        }
                    };
                    ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count])
                }
                filesystem::CLOSE => {
                    let Ok(token) = filesystem::decode_close_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    match self.close(token) {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(status) => Ok(ServiceReply::empty(status)),
                    }
                }
                filesystem::LIST => {
                    let Ok(decoded) = filesystem::decode_list_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let listing = match self.namespace.borrow_mut().list_bounded(
                        &self.cwd,
                        decoded.path,
                        decoded.cursor,
                        decoded.max_entries,
                        decoded.max_name_bytes,
                    ) {
                        Ok(listing) => listing,
                        Err(error) => {
                            return Ok(ServiceReply::empty(application_filesystem_status(error)));
                        }
                    };
                    let mut entries = Vec::new();
                    entries
                        .try_reserve_exact(listing.entries.len())
                        .map_err(|_| troe_dispatch::DispatchError::MetadataExhausted)?;
                    for entry in &listing.entries {
                        entries.push(filesystem::DirectoryEntry {
                            kind: match entry.kind {
                                NodeKind::File => filesystem::NodeKind::File,
                                NodeKind::Directory => filesystem::NodeKind::Directory,
                            },
                            name: &entry.name,
                        });
                    }
                    let mut encoded = [0_u8; filesystem::MAX_LIST_REPLY_BYTES];
                    let count =
                        filesystem::encode_list_reply(listing.next_cursor, &entries, &mut encoded)
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &encoded[..count])
                }
                filesystem::METADATA => {
                    let Ok(path) = filesystem::decode_path_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let metadata = match self.namespace.borrow_mut().metadata(&self.cwd, path) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            return Ok(ServiceReply::empty(application_filesystem_status(error)));
                        }
                    };
                    let metadata = filesystem::Metadata {
                        kind: match metadata.kind {
                            NodeKind::File => filesystem::NodeKind::File,
                            NodeKind::Directory => filesystem::NodeKind::Directory,
                        },
                        byte_count: metadata.byte_count,
                    };
                    ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &filesystem::encode_metadata_reply(metadata),
                    )
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl<'namespace> ApplicationFilesystemMutationService<'namespace> {
        fn new(namespace: SharedNamespace<'namespace>, cwd: &str) -> Result<Self, ()> {
            let mut owned_cwd = String::new();
            owned_cwd.try_reserve_exact(cwd.len()).map_err(|_| ())?;
            owned_cwd.push_str(cwd);
            Ok(Self {
                namespace,
                cwd: owned_cwd,
                next_token: Some(1),
                pending: None,
            })
        }

        fn begin_replace(&mut self, path: &str) -> Result<u32, ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            let token = self.next_token.ok_or(ReplyStatus::Exhausted)?;
            let mut owned_path = String::new();
            owned_path
                .try_reserve_exact(path.len())
                .map_err(|_| ReplyStatus::Exhausted)?;
            owned_path.push_str(path);
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(filesystem_mutation::MAX_FILE_BYTES)
                .map_err(|_| ReplyStatus::Exhausted)?;
            self.next_token = token.checked_add(1);
            self.pending = Some(PendingFileReplacement {
                token,
                path: owned_path,
                bytes,
            });
            Ok(token)
        }

        fn append(
            &mut self,
            append: filesystem_mutation::AppendRequest<'_>,
        ) -> Result<(), ReplyStatus> {
            let pending = self.pending.as_mut().ok_or(ReplyStatus::InvalidRequest)?;
            let offset = usize::try_from(append.offset).map_err(|_| ReplyStatus::Overflow)?;
            if pending.token != append.token || pending.bytes.len() != offset {
                return Err(ReplyStatus::InvalidRequest);
            }
            let next = offset
                .checked_add(append.bytes.len())
                .ok_or(ReplyStatus::Overflow)?;
            if next > filesystem_mutation::MAX_FILE_BYTES {
                return Err(ReplyStatus::TooLarge);
            }
            pending.bytes.extend_from_slice(append.bytes);
            Ok(())
        }

        fn finish(&mut self, token: u32, commit: bool) -> Result<(), ReplyStatus> {
            let Some(pending) = self.pending.take() else {
                return Err(ReplyStatus::InvalidRequest);
            };
            if pending.token != token {
                self.pending = Some(pending);
                return Err(ReplyStatus::InvalidRequest);
            }
            if !commit {
                return Ok(());
            }
            self.namespace
                .borrow_mut()
                .write_file(&self.cwd, &pending.path, &pending.bytes)
                .map_err(application_filesystem_status)
        }

        fn remove(&mut self, path: &str) -> Result<(), ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            self.namespace
                .borrow_mut()
                .remove_file(&self.cwd, path)
                .map_err(application_filesystem_status)
        }
    }

    impl Service for ApplicationFilesystemMutationService<'_> {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                filesystem_mutation::BEGIN_REPLACE => {
                    let Ok(path) = filesystem_mutation::decode_path_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let token = match self.begin_replace(path) {
                        Ok(token) => token,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    let reply = filesystem_mutation::encode_token(token)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &reply)
                }
                filesystem_mutation::APPEND => {
                    let Ok(append) = filesystem_mutation::decode_append_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    match self.append(append) {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(status) => Ok(ServiceReply::empty(status)),
                    }
                }
                filesystem_mutation::COMMIT_REPLACE | filesystem_mutation::ABORT_REPLACE => {
                    let Ok(token) = filesystem_mutation::decode_token(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let commit = request.opcode() == filesystem_mutation::COMMIT_REPLACE;
                    match self.finish(token, commit) {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(status) => Ok(ServiceReply::empty(status)),
                    }
                }
                filesystem_mutation::REMOVE => {
                    let Ok(path) = filesystem_mutation::decode_path_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    match self.remove(path) {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(status) => Ok(ServiceReply::empty(status)),
                    }
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationTimerService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                timer::NOW if request.payload().is_empty() => {
                    let milliseconds = self.runtime.borrow().now().as_millis();
                    ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &timer::encode_milliseconds(milliseconds),
                    )
                }
                timer::SLEEP_UNTIL => {
                    let Ok(deadline) = timer::decode_milliseconds(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let mut runtime = KernelRuntimeCapability {
                        runtime: self.runtime.clone(),
                    };
                    match runtime.sleep_until(MonotonicMillis::from_millis(deadline)) {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(Cancelled) => Ok(ServiceReply::empty(ReplyStatus::Cancelled)),
                    }
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationDiagnosticsService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != diagnostics::GET_SNAPSHOT || !request.payload().is_empty() {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            ServiceReply::with_payload(ReplyStatus::Success, &self.snapshot)
        }
    }

    fn encode_application_network_status(
        status: NetworkStatus,
    ) -> Result<[u8; network_observation::STATUS_BYTES], troe_dispatch::DispatchError> {
        let configuration = match (status.address, status.subnet_mask, status.gateway) {
            (Some(address), Some(subnet_mask), Some(gateway)) => {
                Some(network_observation::Ipv4Configuration {
                    address,
                    subnet_mask,
                    gateway,
                    lease_seconds: status.lease_seconds,
                })
            }
            (None, None, None) if status.lease_seconds.is_none() => None,
            _ => return Err(troe_dispatch::DispatchError::AccountingOverflow),
        };
        network_observation::encode_status(network_observation::Status {
            mac: status.mac,
            configuration,
        })
        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)
    }

    impl Service for ApplicationNetworkObservationService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if !request.payload().is_empty() {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Some(network) = &self.network else {
                return Ok(ServiceReply::empty(ReplyStatus::NotFound));
            };
            let service = network.borrow();
            match request.opcode() {
                network_observation::GET_STATUS => ServiceReply::with_payload(
                    ReplyStatus::Success,
                    &encode_application_network_status(service.shell_status())?,
                ),
                network_observation::GET_STATS => {
                    let stats = network_observation::Stats {
                        received_frames: service.stats.received_frames,
                        transmitted_frames: service.stats.transmitted_frames,
                        arp_replies: service.stats.arp_replies,
                        icmp_replies: service.stats.icmp_replies,
                        udp_retained: service.stats.udp_retained,
                        udp_unbound: service.stats.udp_unbound,
                        udp_dropped: service.stats.udp_dropped,
                        arp_entries: u64::try_from(service.arp.len())
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                        udp_ports: u64::try_from(service.udp.len())
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                        checkpoints: service.stats.checkpoints,
                        errors: service.stats.errors,
                    };
                    ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &network_observation::encode_stats(stats)
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                    )
                }
                network_observation::GET_NEIGHBORS => {
                    let mut entries = [network_observation::Neighbor::default();
                        network_observation::MAX_NEIGHBORS];
                    let mut count = 0;
                    for entry in service.arp.entries() {
                        let Some(destination) = entries.get_mut(count) else {
                            return Err(troe_dispatch::DispatchError::AccountingOverflow);
                        };
                        *destination = network_observation::Neighbor {
                            address: entry.address.bytes(),
                            mac: entry.mac.bytes(),
                        };
                        count += 1;
                    }
                    let neighbors =
                        network_observation::Neighbors::from_slice(&entries[..count])
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    let mut encoded = [0_u8; network_observation::MAX_NEIGHBOR_REPLY_BYTES];
                    let count = network_observation::encode_neighbors(neighbors, &mut encoded)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &encoded[..count])
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationNetworkConfigurationService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != network_configuration::DHCP || !request.payload().is_empty() {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Some(network) = &self.network else {
                return Ok(ServiceReply::empty(ReplyStatus::NotFound));
            };
            let mut network = KernelNetwork::new(network.clone());
            let mut runtime = KernelRuntimeCapability {
                runtime: self.runtime.clone(),
            };
            let status = match network.configure_dhcp(&mut runtime) {
                Ok(status) => status,
                Err(error) => {
                    return Ok(ServiceReply::empty(application_network_status(error)));
                }
            };
            ServiceReply::with_payload(
                ReplyStatus::Success,
                &encode_application_network_status(status)?,
            )
        }
    }

    impl Service for ApplicationIcmpEchoService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != icmp_echo::ECHO {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Ok(destination) = icmp_echo::decode_request(request.payload()) else {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            };
            let Some(network) = &self.network else {
                return Ok(ServiceReply::empty(ReplyStatus::NotFound));
            };
            let mut network = KernelNetwork::new(network.clone());
            let mut runtime = KernelRuntimeCapability {
                runtime: self.runtime.clone(),
            };
            let reply = match network.ping(destination, &mut runtime) {
                Ok(reply) => reply,
                Err(error) => {
                    return Ok(ServiceReply::empty(application_network_status(error)));
                }
            };
            let reply = icmp_echo::Reply {
                source: reply.source,
                sequence: reply.sequence,
                bytes: u16::try_from(reply.bytes)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
            };
            ServiceReply::with_payload(ReplyStatus::Success, &icmp_echo::encode_reply(reply))
        }
    }

    const fn application_filesystem_status(error: FsError) -> ReplyStatus {
        match error {
            FsError::Invalid => ReplyStatus::InvalidPath,
            FsError::NotFound => ReplyStatus::NotFound,
            FsError::WrongType => ReplyStatus::WrongType,
            FsError::ReadOnly => ReplyStatus::ReadOnly,
            FsError::NoSpace => ReplyStatus::NoSpace,
            FsError::Overflow => ReplyStatus::Overflow,
            FsError::Exists => ReplyStatus::Exists,
            FsError::Corrupt => ReplyStatus::Corrupt,
            FsError::Io => ReplyStatus::Io,
            FsError::Unsupported => ReplyStatus::Unsupported,
        }
    }

    impl ApplicationDatagramService {
        fn new(network: SharedNetwork, runtime: SharedRuntime) -> Self {
            Self {
                network,
                runtime,
                ports: [0; troe_net::MAX_UDP_PORTS],
                port_count: 0,
            }
        }

        fn claim_port(&mut self, requested: Option<u16>) -> Result<u16, ReplyStatus> {
            if let Some(port) = requested {
                if port == 0 {
                    return Err(ReplyStatus::InvalidRequest);
                }
                if self.ports[..self.port_count].contains(&port) {
                    return Ok(port);
                }
                if self.port_count == self.ports.len() {
                    return Err(ReplyStatus::Exhausted);
                }
                let mut network = self.network.borrow_mut();
                if network.udp.is_bound(port) {
                    return Err(ReplyStatus::Conflict);
                }
                network
                    .udp
                    .bind(port)
                    .map_err(map_network_error)
                    .map_err(application_network_status)?;
                drop(network);
                self.ports[self.port_count] = port;
                self.port_count += 1;
                return Ok(port);
            }

            if self.port_count == self.ports.len() {
                return Err(ReplyStatus::Exhausted);
            }
            let mut network = self.network.borrow_mut();
            for _ in 0..troe_net::MAX_UDP_PORTS {
                let port = network.next_port;
                network.next_port = if port == u16::MAX { 49_152 } else { port + 1 };
                if !network.udp.is_bound(port) {
                    network
                        .udp
                        .bind(port)
                        .map_err(map_network_error)
                        .map_err(application_network_status)?;
                    drop(network);
                    self.ports[self.port_count] = port;
                    self.port_count += 1;
                    return Ok(port);
                }
            }
            Err(ReplyStatus::Exhausted)
        }
    }

    impl Service for ApplicationDatagramService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                datagram::SEND => {
                    let Ok(send) = datagram::decode_send_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let requested = (send.source_port != 0).then_some(send.source_port);
                    let source_port = match self.claim_port(requested) {
                        Ok(port) => port,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    let mut network = KernelNetwork::new(self.network.clone());
                    let mut runtime = KernelRuntimeCapability {
                        runtime: self.runtime.clone(),
                    };
                    if let Err(error) = network.send_udp(
                        Some(source_port),
                        send.destination,
                        send.destination_port,
                        send.payload,
                        &mut runtime,
                    ) {
                        return Ok(ServiceReply::empty(application_network_status(error)));
                    }
                    let reply = datagram::encode_send_reply(source_port)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &reply)
                }
                datagram::RECEIVE => {
                    let Ok(local_port) = datagram::decode_receive_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let local_port = match self.claim_port(Some(local_port)) {
                        Ok(port) => port,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    let mut network = KernelNetwork::new(self.network.clone());
                    let mut runtime = KernelRuntimeCapability {
                        runtime: self.runtime.clone(),
                    };
                    let received = match network.listen_udp(local_port, &mut runtime) {
                        Ok(received) => received,
                        Err(error) => {
                            return Ok(ServiceReply::empty(application_network_status(error)));
                        }
                    };
                    let mut encoded = [0_u8; datagram::MAX_RECEIVE_REPLY_BYTES];
                    let count = datagram::encode_receive_reply(
                        received.source,
                        received.source_port,
                        &received.payload,
                        &mut encoded,
                    )
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &encoded[..count])
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Drop for ApplicationDatagramService {
        fn drop(&mut self) {
            let mut network = self.network.borrow_mut();
            for port in &self.ports[..self.port_count] {
                let _released = network.udp.unbind(*port);
            }
        }
    }

    const fn application_network_status(error: NetworkError) -> ReplyStatus {
        match error {
            NetworkError::NotConfigured => ReplyStatus::NotConfigured,
            NetworkError::Timeout => ReplyStatus::Timeout,
            NetworkError::TooLarge => ReplyStatus::TooLarge,
            NetworkError::Exhausted => ReplyStatus::Exhausted,
            NetworkError::Cancelled => ReplyStatus::Cancelled,
            NetworkError::Unavailable => ReplyStatus::NotFound,
            NetworkError::Protocol => ReplyStatus::NetworkProtocol,
            NetworkError::Device => ReplyStatus::Failure,
        }
    }

    fn same_subnet(left: Ipv4Address, right: Ipv4Address, mask: Ipv4Address) -> bool {
        left.bytes()
            .iter()
            .zip(right.bytes())
            .zip(mask.bytes())
            .all(|((left, right), mask)| *left & mask == right & mask)
    }

    const fn map_network_error(error: NetError) -> NetworkError {
        match error {
            NetError::Invalid
            | NetError::Truncated
            | NetError::Checksum
            | NetError::Unsupported => NetworkError::Protocol,
            NetError::Exhausted => NetworkError::Exhausted,
            NetError::Device => NetworkError::Device,
            NetError::Timeout => NetworkError::Timeout,
        }
    }

    impl KernelRuntime {
        const DEFERRED_INPUT_CAPACITY: usize = 128;
        const INPUT_CHECKPOINT_BUDGET: usize = 32;

        fn new(network: Option<SharedNetwork>) -> Result<Self, RuntimeInitError> {
            let initial = troe_machine::monotonic_millis().ok_or(RuntimeInitError::Clock)?;
            let mut deferred_input = VecDeque::new();
            deferred_input
                .try_reserve_exact(Self::DEFERRED_INPUT_CAPACITY)
                .map_err(|_| RuntimeInitError::InputMetadata)?;
            Ok(Self {
                network,
                deferred_input,
                control_down: false,
                last_millis: Cell::new(initial),
            })
        }

        fn now(&self) -> MonotonicMillis {
            let previous = self.last_millis.get();
            let current = troe_machine::monotonic_millis()
                .unwrap_or(previous)
                .max(previous);
            self.last_millis.set(current);
            MonotonicMillis::from_millis(current)
        }

        fn checkpoint(&mut self) -> Result<(), Cancelled> {
            if troe_machine::take_network_interrupt()
                && let Some(network) = &self.network
            {
                let _bounded_poll = network.borrow_mut().poll();
            }
            for _ in 0..Self::INPUT_CHECKPOINT_BUDGET {
                let Some(event) = troe_machine::try_input_event() else {
                    break;
                };
                match event.source() {
                    InputSource::Serial if event.byte() == 3 => return Err(Cancelled),
                    InputSource::Keyboard if event.byte() == 0x1d => {
                        self.control_down = true;
                    }
                    InputSource::Keyboard if event.byte() == 0x9d => {
                        self.control_down = false;
                    }
                    InputSource::Keyboard if self.control_down && event.byte() == 0x2e => {
                        return Err(Cancelled);
                    }
                    _ if self.deferred_input.len() < Self::DEFERRED_INPUT_CAPACITY => {
                        self.deferred_input.push_back(event);
                    }
                    _ => {}
                }
            }
            Ok(())
        }

        fn next_input_event(&mut self) -> Option<InputEvent> {
            let _cancel_at_prompt = self.checkpoint();
            if let Some(event) = self.deferred_input.pop_front() {
                return Some(event);
            }
            troe_machine::wait_for_runtime_event();
            let _cancel_at_prompt = self.checkpoint();
            self.deferred_input.pop_front()
        }
    }

    impl CooperativeRuntime for KernelRuntimeCapability {
        fn now(&self) -> MonotonicMillis {
            self.runtime.borrow().now()
        }

        fn checkpoint(&mut self) -> Result<(), Cancelled> {
            self.runtime.borrow_mut().checkpoint()
        }
    }

    fn discover_network_service() -> Option<SharedNetwork> {
        let mut device = troe_machine::discover_virtio_network().ok().flatten()?;
        device.enable_interrupts().ok()?;
        let service = KernelNetworkService::new(device).ok()?;
        Some(Rc::new(RefCell::new(service)))
    }

    fn install_shell_runtime(
        shell: &mut Shell,
        console: &mut dyn Output,
    ) -> (Option<NetworkStatus>, SharedRuntime) {
        let service = discover_network_service();
        let runtime_state = match KernelRuntime::new(service.clone()) {
            Ok(runtime) => runtime,
            Err(RuntimeInitError::Clock) => fatal(b"fatal: monotonic runtime unavailable\n"),
            Err(RuntimeInitError::InputMetadata) => {
                fatal(b"fatal: runtime input metadata exhausted\n")
            }
        };
        let runtime = Rc::new(RefCell::new(runtime_state));
        shell.set_runtime(Box::new(KernelRuntimeCapability {
            runtime: runtime.clone(),
        }));
        if let Some(service) = service {
            let mut network = KernelNetwork::new(service);
            let mut bootstrap_runtime = KernelRuntimeCapability {
                runtime: runtime.clone(),
            };
            let status = network.configure_dhcp(&mut bootstrap_runtime).ok();
            let label =
                status.map_or_else(|| String::from("Configuring network"), network_boot_label);
            if write_boot_status(console, &label, status.is_some()).is_err() {
                fatal(b"fatal: native network diagnostic failed\n");
            }
            shell.set_network(Box::new(network));
            (status, runtime)
        } else {
            if write_boot_status(console, "Configuring network", false).is_err() {
                fatal(b"fatal: native network diagnostic failed\n");
            }
            (None, runtime)
        }
    }

    fn finish_shell_startup(
        shell: &mut Shell,
        console: &mut dyn Output,
        motd: &[u8],
        native_root: bool,
    ) -> SharedRuntime {
        let (network_status, runtime) = install_shell_runtime(shell, console);
        if !write_shell_banner(console, motd, native_root, network_status) {
            fatal(b"fatal: native console write failed\n");
        }
        runtime
    }

    fn shell_prompt(shell: &Shell) -> String {
        let mut prompt = String::from("sh:");
        prompt.push_str(shell.cwd());
        prompt.push_str("> ");
        prompt
    }

    impl ExternalCommand for KexCommandRunner<'_> {
        #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
        fn execute(
            &mut self,
            command: &str,
            words: &[String],
            cwd: &str,
            namespace: &mut Namespace,
            stdin: &mut dyn Input,
            stdout: &mut dyn Output,
            stderr: &mut dyn Output,
        ) -> Option<CommandStatus> {
            if !valid_application_name(command) {
                return None;
            }
            let path = alloc::format!("/bin/{command}.kex");
            let metadata = match namespace.metadata("/", &path) {
                Ok(metadata) => metadata,
                Err(troe_vfs::FsError::NotFound) => return None,
                Err(_) => return Some(command_application_error(stderr, command, "lookup failed")),
            };
            if metadata.kind != NodeKind::File {
                return Some(command_application_error(
                    stderr,
                    command,
                    "artifact is not a file",
                ));
            }
            let Ok(artifact) = stage_artifact(metadata.byte_count, |offset, destination| {
                namespace
                    .read_file_at("/", &path, offset, destination)
                    .map_err(|_| ())
            }) else {
                return Some(command_application_error(
                    stderr,
                    command,
                    "artifact staging failed",
                ));
            };
            let capability_path = alloc::format!("/bin/{command}.kcap");
            let Ok(capability_bytes) = namespace.read_file_bounded(
                "/",
                &capability_path,
                requirements::MAX_MANIFEST_BYTES,
            ) else {
                return Some(command_application_error(
                    stderr,
                    command,
                    "capability manifest unavailable",
                ));
            };
            let Ok(capability_manifest) = requirements::Manifest::parse(&capability_bytes) else {
                return Some(command_application_error(
                    stderr,
                    command,
                    "capability manifest rejected",
                ));
            };
            let mut datagram_required = false;
            let mut filesystem_required = false;
            let mut filesystem_mutation_required = false;
            let mut timer_required = false;
            let mut diagnostics_required = false;
            let mut network_observation_required = false;
            let mut network_configuration_required = false;
            let mut icmp_echo_required = false;
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
                } else {
                    return Some(command_application_error(
                        stderr,
                        command,
                        "unsupported capability requirement",
                    ));
                }
            }
            let machine_memory = machine_snapshot(self.accounting);
            let machine_input = troe_machine::input_interrupt_stats();
            let namespace_memory = namespace.memory_stats();
            let diagnostics_snapshot = if diagnostics_required {
                match application_diagnostics_snapshot(
                    machine_memory,
                    machine_input,
                    namespace_memory,
                ) {
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
            if namespace
                .set_system_file("/sys/memory", memory_report.as_bytes())
                .is_err()
            {
                return Some(command_application_error(
                    stderr,
                    command,
                    "memory report refresh failed",
                ));
            }
            let Ok(input) = read_command_input(stdin) else {
                return Some(command_application_error(
                    stderr,
                    command,
                    "input exceeds command limit",
                ));
            };
            let retained_stdout = SharedOutput::new(PIPE_CAPACITY);
            let retained_stderr = SharedOutput::new(PIPE_CAPACITY);
            let application_network = self.runtime.borrow().network.clone();
            let datagram_network = if datagram_required {
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
                + usize::from(network_observation_required)
                + usize::from(network_configuration_required)
                + usize::from(icmp_echo_required);
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
            let filesystem_namespace = if filesystem_required || filesystem_mutation_required {
                Some(Rc::new(RefCell::new(namespace)))
            } else {
                None
            };
            let services = (|| -> Result<Vec<CommandStartupService>, ()> {
                let mut services = Vec::new();
                services.try_reserve_exact(service_count).map_err(|_| ())?;
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        CommandInvocationService::new(cwd, words).map_err(|_| ())?,
                    )?,
                    interface: troe_abi::interface::COMMAND,
                    major: command::MAJOR,
                    minor: command::MINOR,
                });
                services.push(CommandStartupService {
                    port: register_command_service(&mut dispatcher, ByteInputService::new(input))?,
                    interface: troe_abi::interface::STANDARD_INPUT,
                    major: stream::MAJOR,
                    minor: stream::MINOR,
                });
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ByteOutputService::new(retained_stdout.clone()),
                    )?,
                    interface: troe_abi::interface::STANDARD_OUTPUT,
                    major: stream::MAJOR,
                    minor: stream::MINOR,
                });
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        ByteOutputService::new(retained_stderr.clone()),
                    )?,
                    interface: troe_abi::interface::STANDARD_ERROR,
                    major: stream::MAJOR,
                    minor: stream::MINOR,
                });
                if let Some(network) = datagram_network {
                    services.push(CommandStartupService {
                        port: register_command_service(
                            &mut dispatcher,
                            ApplicationDatagramService::new(network, self.runtime.clone()),
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
                            ApplicationDiagnosticsService {
                                snapshot: diagnostics_snapshot.ok_or(())?,
                            },
                        )?,
                        interface: troe_abi::interface::DIAGNOSTICS,
                        major: diagnostics::MAJOR,
                        minor: diagnostics::MINOR,
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
                Ok(services)
            })();
            let Ok(services) = services else {
                return Some(command_application_error(
                    stderr,
                    command,
                    "service setup failed",
                ));
            };

            if self.scheduler.yield_current(self.shell_id).is_err() {
                fatal(b"fatal: shell scheduler yield failed\n");
            }
            let outcome = run_command_application(
                self.scheduler,
                self.accounting,
                &mut dispatcher,
                services.as_slice(),
                &artifact,
            );
            if self
                .scheduler
                .dispatch_next(self.shell_capabilities)
                .ok()
                .flatten()
                != Some(self.shell_id)
            {
                fatal(b"fatal: shell scheduler restore failed\n");
            }

            if retained_stdout.copy_to(stdout).is_err() || retained_stderr.copy_to(stderr).is_err()
            {
                return Some(CommandStatus::Failure);
            }
            Some(match outcome {
                Ok(CommandApplicationOutcome::Exited(status)) => command_status(status),
                Ok(CommandApplicationOutcome::Faulted(_)) => {
                    command_application_error(stderr, command, "application faulted")
                }
                Err(()) => command_application_error(stderr, command, "application rejected"),
            })
        }
    }

    fn register_command_service<'service, S: Service + 'service>(
        dispatcher: &mut Dispatcher<'service>,
        service: S,
    ) -> Result<troe_dispatch::PortId, ()> {
        let (port, kernel_handle) = dispatcher
            .register(Box::new(service), Rights::CALL)
            .map_err(|_| ())?;
        dispatcher.close(kernel_handle).map_err(|_| ())?;
        Ok(port)
    }

    fn read_command_input(input: &mut dyn Input) -> Result<Vec<u8>, ()> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
        loop {
            let count = input.read(&mut chunk).map_err(|_| ())?;
            if count > chunk.len() {
                return Err(());
            }
            if count == 0 {
                return Ok(bytes);
            }
            let next = bytes.len().checked_add(count).ok_or(())?;
            if next > PIPE_CAPACITY {
                return Err(());
            }
            bytes.try_reserve_exact(count).map_err(|_| ())?;
            bytes.extend_from_slice(&chunk[..count]);
        }
    }

    fn command_application_error(
        stderr: &mut dyn Output,
        command: &str,
        message: &str,
    ) -> CommandStatus {
        let _ignored = write_all(stderr, alloc::format!("{command}: {message}\n").as_bytes());
        CommandStatus::Failure
    }

    const fn command_status(status: u32) -> CommandStatus {
        match status {
            troe_abi::exit::SUCCESS => CommandStatus::Success,
            troe_abi::exit::USAGE => CommandStatus::Usage,
            troe_abi::exit::NOT_FOUND => CommandStatus::NotFound,
            troe_abi::exit::DENIED => CommandStatus::Denied,
            troe_abi::exit::CANCELLED => CommandStatus::Cancelled,
            _ => CommandStatus::Failure,
        }
    }

    fn valid_application_name(name: &str) -> bool {
        !name.is_empty()
            && name.as_bytes().iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
    }

    #[allow(clippy::too_many_lines)]
    fn run_shell_task(task: &mut ShellTask<'_>) -> TaskStep {
        let stack_pointer = usize_as_u64(troe_machine::current_stack_pointer());
        if !task.stack.contains(stack_pointer)
            || !task.capabilities.contains(Capabilities::CONSOLE)
            || !task.capabilities.contains(Capabilities::FILESYSTEM)
        {
            fatal(b"fatal: shell task authority or stack invalid\n");
        }
        let mut dispatcher = Dispatcher::new(1, 1)
            .unwrap_or_else(|_| fatal(b"fatal: cannot create service dispatcher\n"));
        let mut shell_console = NativeShellConsole::new(task.accounting.framebuffer);
        let framebuffer_ready = shell_console.has_framebuffer();
        if shell_console.replay_completed_boot().is_err() {
            fatal(b"fatal: framebuffer boot replay failed\n");
        }
        let (_console_port, console_handle) = dispatcher
            .register(Box::new(ConsoleService::new(shell_console)), Rights::CALL)
            .unwrap_or_else(|_| fatal(b"fatal: cannot register console service\n"));
        let mut console = DispatchedOutput::new(&mut dispatcher, console_handle);
        let console_label = if framebuffer_ready {
            "Starting console and framebuffer"
        } else {
            "Starting console"
        };
        if write_boot_status(&mut console, console_label, true).is_err() {
            fatal(b"fatal: framebuffer console write failed\n");
        }
        let (mut namespace, native_root) = compose_namespace(task.accounting, &mut console);
        let motd = namespace
            .read_file("/", "/etc/motd")
            .unwrap_or_else(|_| fatal(b"fatal: cannot read /etc/motd\n"));
        let initial_snapshot = machine_snapshot(task.accounting);
        let machine_control = task.capabilities.contains(Capabilities::MACHINE_CONTROL);
        let Ok(mut shell) =
            Shell::new(namespace, architecture(), initial_snapshot, machine_control)
        else {
            fatal(b"fatal: cannot compose namespace\n");
        };
        let runtime = finish_shell_startup(&mut shell, &mut console, &motd, native_root);
        let editor_config = EditorConfig::standard();
        if editor_config.max_line_bytes() > MAX_LINE_BYTES {
            fatal(b"fatal: editor line policy exceeds shell parser policy\n");
        }
        let completion_config = CompletionConfig::standard();
        let mut decoder = InputDecoder::new(editor_config.input());
        let mut keyboard = Ps2Set1Decoder::new(KeyboardConfig::standard());
        let mut editor = LineEditor::new(editor_config);

        loop {
            refresh_shell_stats(&mut shell, task.accounting);
            let prompt = shell_prompt(&shell);
            if write_all(&mut console, prompt.as_bytes()).is_err() {
                fatal(b"fatal: native console write failed\n");
            }
            let Ok(line) = read_edited_line(
                &mut editor,
                &mut decoder,
                &mut keyboard,
                &mut shell,
                &runtime,
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
                troe_machine::trigger_write_fault(ROOTFS.as_ptr() as usize);
            }
            #[cfg(feature = "acceptance-probes")]
            if line == "mmu-probe execute" {
                let _result = write_all(&mut console, b"probing non-executable mapping\n");
                troe_machine::trigger_execute_fault(task.accounting.execute_probe_address);
            }
            #[cfg(feature = "acceptance-probes")]
            if line == "mmu-probe exception" {
                let _result = write_all(&mut console, b"probing native exception vector\n");
                troe_machine::trigger_native_exception();
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
                troe_machine::trigger_write_fault(guard);
            }
            let mut input = EmptyInput;
            let mut error = NativeConsole;
            let mut external = KexCommandRunner {
                accounting: task.accounting,
                scheduler: task.scheduler,
                shell_id: task.task_id,
                shell_capabilities: task.capabilities,
                runtime: runtime.clone(),
            };
            let _status = shell.execute_with_external(
                &line,
                &mut input,
                &mut console,
                &mut error,
                &mut external,
            );
            if let Some(action) = shell.machine_action() {
                perform_machine_action(action, &mut console);
            }
        }
    }

    fn perform_machine_action(action: MachineAction, console: &mut dyn Output) -> ! {
        match action {
            MachineAction::PowerOff => {
                let _result = write_all(console, b"poweroff: requesting soft off\n");
                troe_machine::poweroff();
            }
            MachineAction::Reboot => {
                let _result = write_all(console, b"reboot: requesting cold reset\n");
                troe_machine::reboot();
            }
        }
    }

    fn refresh_shell_stats(shell: &mut Shell, accounting: &OwnedAccounting) {
        shell.set_machine_memory(machine_snapshot(accounting));
        shell.set_machine_input(troe_machine::input_interrupt_stats());
    }

    #[allow(clippy::too_many_arguments)]
    fn read_edited_line(
        editor: &mut LineEditor,
        decoder: &mut InputDecoder,
        keyboard: &mut Ps2Set1Decoder,
        shell: &mut Shell,
        runtime: &SharedRuntime,
        completion_config: CompletionConfig,
        prompt: &str,
        console: &mut dyn Output,
    ) -> Result<String, ()> {
        loop {
            let key = loop {
                let event = loop {
                    if let Some(event) = runtime.borrow_mut().next_input_event() {
                        break event;
                    }
                };
                let key = match event.source() {
                    InputSource::Serial => decoder.push(event.byte()),
                    InputSource::Keyboard => keyboard.push(event.byte()),
                };
                if let Some(key) = key {
                    break key;
                }
            };
            match editor.handle(key) {
                EditorOutcome::Changed => match key {
                    KeyEvent::Left => write_all(console, b"\x1b[D")?,
                    KeyEvent::Right => write_all(console, b"\x1b[C")?,
                    _ => redraw_editor(editor, prompt, console)?,
                },
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
        shell: &mut Shell,
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
                b"... completion list truncated by standard limits\n",
            )?;
        }
        redraw_editor(editor, prompt, console)
    }

    fn machine_snapshot(accounting: &OwnedAccounting) -> MachineMemorySnapshot {
        let heap = troe_machine::heap_stats();
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

    fn application_diagnostics_snapshot(
        machine: MachineMemorySnapshot,
        input: Option<InputQueueStats>,
        memory: MemoryStats,
    ) -> Result<[u8; diagnostics::SNAPSHOT_BYTES], ()> {
        let machine_memory = if machine.owner() == MachineMemoryOwner::Kernel {
            Some(diagnostics::MachineMemory {
                usable_bytes: machine.usable_bytes().ok_or(())?,
                reserved_bytes: machine.reserved_bytes().ok_or(())?,
                total_frames: machine.total_frames().ok_or(())?,
                free_frames: machine.free_frames().ok_or(())?,
                heap_total_bytes: machine.heap_total_bytes().ok_or(())?,
                heap_used_bytes: machine.heap_used_bytes().ok_or(())?,
                heap_high_water_bytes: machine.heap_high_water_bytes().ok_or(())?,
                failed_allocations: machine.failed_allocations().ok_or(())?,
            })
        } else {
            None
        };
        let input = input
            .map(|input| {
                Ok(diagnostics::InputQueue {
                    queued: u64::try_from(input.queued).map_err(|_| ())?,
                    capacity: u64::try_from(input.capacity).map_err(|_| ())?,
                    interrupts: input.interrupts,
                    delivered: input.delivered,
                    dropped: input.dropped,
                    idle_waits: input.idle_waits,
                    wakeups: input.wakeups,
                })
            })
            .transpose()?;
        diagnostics::encode_snapshot(diagnostics::Snapshot {
            architecture: if cfg!(target_arch = "x86_64") {
                diagnostics::Architecture::X86_64
            } else {
                diagnostics::Architecture::Aarch64
            },
            memory_owner: match machine.owner() {
                MachineMemoryOwner::Host => diagnostics::MemoryOwner::Host,
                MachineMemoryOwner::Firmware => diagnostics::MemoryOwner::Firmware,
                MachineMemoryOwner::Kernel => diagnostics::MemoryOwner::Kernel,
            },
            pressure: diagnostics::Pressure::Normal,
            machine_memory,
            input,
            ramfs_used_bytes: memory.ramfs_used,
            ramfs_limit_bytes: memory.ramfs_limit,
            ramfs_high_water_bytes: memory.ramfs_high_water,
            caches_used_bytes: 0,
            caches_limit_bytes: 0,
        })
        .map_err(|_| ())
    }

    const fn usize_as_u64(value: usize) -> u64 {
        value as u64
    }

    fn write_all(output: &mut dyn Output, bytes: &[u8]) -> Result<(), ()> {
        troe_core::write_all(output, bytes).map_err(|_| ())
    }

    fn fatal(message: &[u8]) -> ! {
        let _status = write_machine_boot_status("TROE initialization", false);
        let _written = troe_machine::write(message);
        troe_machine::park()
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

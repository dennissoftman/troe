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
    #[cfg(feature = "acceptance-probes")]
    use core::sync::atomic::{AtomicBool, Ordering};

    use troe_abi::{
        clock_control, command, datagram, diagnostics, filesystem, filesystem_mutation,
        heap_growth, icmp_echo, network_configuration, network_observation, pipe, private_memory,
        process_launch, process_observation, random, server, shell_script, stream, tcp_connect,
        timer, volume_control, wall_clock,
    };
    use troe_application::{
        ABI_MINOR, ApplicationLayout, ApplicationLimits, InitialHandle, KEX_V1_IMAGE_ALIGNMENT,
        KEX_V1_MIN_IMAGE_BASE, KEX_V1_USER_END, LoadCharges, LoadPlacement, LoadPlan,
        LoadSegmentLayout, LoaderResource, LoaderTransaction, PAGE_BYTES, SegmentPermissions,
        StartupInfo, StreamedKexPackage, StreamedLoadPlan, Target, parse_kex_at, parse_kex_package,
        parse_streamed_kex_package, stream_verified_segments, visit_verified_relocations,
    };
    #[cfg(feature = "acceptance-probes")]
    use troe_application::{ParseError, parse_kex};
    use troe_block::{BlockAccess, BlockRegion};
    use troe_block::{BlockDevice, BlockLimits};
    use troe_core::{
        CommandStatus, Input, MAX_LINE_BYTES, MachineMemoryOwner, MachineMemorySnapshot,
        MemoryStats, Output, StreamError,
    };
    use troe_dispatch::{
        CommandInvocationService, ConsoleService, CopiedMessage, DispatchedOutput, Dispatcher,
        HandleOwner, ReplyStatus, Request, Rights, Service, ServiceReply, ServiceReplyInfo,
    };
    use troe_driver::{InputEvent, InputQueueConfig, InputQueueStats, InputSource};
    use troe_fmt_bmnt::{
        AccessMode, ActivationMode, BootMountManifest, FilesystemProfile, MAX_MANIFEST_BYTES,
        parse_manifest,
    };
    use troe_fmt_cspk::{ContentPack, MAX_PACK_BYTES, ObjectKind};
    use troe_fmt_gpt::{GptGuid, GptLimits, discover};
    use troe_fmt_prgn::RegionSelector;
    use troe_fmt_scfg::{
        ActivationPointer, ActivationRecovery, MemoryPolicy, SystemConfig,
        normalize_memory_policy_toml, parse_config, recover_activation,
    };
    use troe_fs_api::{
        FILE_IO_BUFFER_BYTES, FileSystemProvider, FsError, NodeKind, WallClock, canonicalize,
    };
    use troe_fs_ext4::Ext4Limits;
    use troe_fs_fat::Fat32Limits;
    use troe_fs_kefs::Kefs;

    /// Directories the embedded image supplies but does not own, because
    /// manifest-selected volumes mount beneath them.
    const EMBEDDED_MOUNT_ROOTS: &[&str] = &["/vol"];
    use troe_fs_ramfs::{RamFs, RamFsQuota};
    #[cfg(feature = "acceptance-probes")]
    use troe_fs_statefs::STATE_PATH;
    use troe_fs_statefs::StateFs;
    use troe_identity::IdentityLimits;
    use troe_memory::{
        BASE_PAGE_SIZE, BootAllocator, FrameAllocationError, FrameAllocator, MAX_FIRMWARE_REGIONS,
        Mapping, MappingLifetime, MappingMemoryType, MappingOwner, MappingPermissions, MappingPlan,
        MemoryMapStats, MemoryRegion, NormalizedMemoryMap, PhysicalExtents, PhysicalRange,
        RegionKind, VirtualRange,
    };
    use troe_namespace::Namespace;
    use troe_net::{
        ArpCache, DhcpMessageType, DhcpPacket, Ipv4Address, MAX_UDP_PAYLOAD_BYTES, MacAddress,
        NetError, NetworkDevice, NetworkServiceStats, TcpConnection, TcpEndpoint, TcpError,
        TcpSegment, UdpAdmission, UdpPortTable, build_arp_reply, build_arp_request,
        build_dhcp_discover, build_dhcp_request, build_icmp_echo, build_tcp, build_udp, parse_arp,
        parse_dhcp, parse_icmp_echo, parse_tcp, parse_udp,
    };
    use troe_process::{
        ChildLifecycle, ChildTable, MAX_CHILDREN_PER_OWNER, MAX_PIPES_PER_OWNER, OwnerId,
        PipeDirection, PipeEndpoint, PipeTable, ProcessError as ChildProcessError,
    };
    use troe_random::{Generator as RandomGenerator, SEED_BYTES as RANDOM_SEED_BYTES};
    use troe_shell::{
        CompletionConfig, CompletionEnvironment, CompletionVisitor, DynamicCompletionDomain,
        ExecutionPlacement, ExternalCommand, ExternalCommandReference, JobControl, MachineAction,
        ServiceControl, SharedNamespace, Shell, Word, external_command_reference,
        format_memory_report, parse_command_list,
    };
    use troe_supervisor::{BoundedLog, ServiceState, Supervisor, SupervisorAction};
    use troe_task::{
        Cancelled, Capabilities, CooperativeRuntime, IsolationResource, MonotonicMillis,
        PendingCallState, PendingCallTable, PendingOperationId, ProcessId, ProcessName,
        ProcessOrigin, ProcessRegistration, ProcessState, ProcessTable, Scheduler, StackResource,
        TaskFault, TaskId, TaskStep, WaitKey, WaitObservation, WaitRegistration, WaitResource,
        WaitSpec, WaitTable, WakeInterest, WakeReason,
    };
    use troe_terminal::{
        EditorConfig, EditorOutcome, FramebufferDescriptor, FramebufferPixelFormat, InputConfig,
        InputDecoder, KeyEvent, KeyboardConfig, LineEditor, Ps2Set1Decoder, TextConsole,
        TextConsoleConfig,
    };
    use troe_txslot::{DualSlotStore, TRANSACTION_BLOCKS};
    use troe_volume::{
        ActivationLimits, MAX_STORAGE_REPORT_BYTES, PreparedMount, STORAGE_REPORT_EXTENSION_BYTES,
        prepare_mounts, read_selected_file, validate_root_activation,
    };
    use uefi::boot;
    use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned};
    use uefi::prelude::*;
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};
    use uefi::proto::rng::{Rng, RngAlgorithmType};

    #[cfg(target_arch = "x86_64")]
    const ROOTFS: &[u8] = include_bytes!("../../assets/root-x86_64.kefs");
    #[cfg(target_arch = "aarch64")]
    const ROOTFS: &[u8] = include_bytes!("../../assets/root-aarch64.kefs");
    const PERSISTENCE_SELECTOR: &[u8] = include_bytes!("../../assets/persist.prgn");
    const STATEFS_SELECTOR: &[u8] = include_bytes!("../../assets/state.prgn");
    const INITIAL_ACTIVATION: &[u8] = include_bytes!("../../assets/system.sact");
    const OWNED_HEAP_BYTES: u64 = 6 * 1024 * 1024;
    const PAGE_TABLE_BYTES: u64 = 2 * 1024 * 1024;
    const OWNED_STACK_BYTES: u64 = 128 * 1024;
    const EXCEPTION_STACK_BYTES: u64 = 16 * 1024;
    const TASK_STACK_BYTES: u64 = 64 * 1024;
    const SERVER_TASK_STACK_BYTES: u64 = 128 * 1024;
    const SHELL_TASK_STACK_BYTES: u64 = 128 * 1024;
    const TASK_GUARD_BYTES: u64 = BASE_PAGE_SIZE;
    const TASK_STACK_PAGES: u64 = 16;
    const SERVER_TASK_STACK_PAGES: u64 = 32;
    const SHELL_TASK_STACK_PAGES: u64 = 32;
    const TASK_STACK_COUNT: usize = 3;
    const SHELL_SCHEDULER_SLOT: u32 = 65_536;
    const RESIDENT_PROCESS_FIRST_SLOT: u32 = 3;
    const RESIDENT_PROCESS_CAPACITY: usize = troe_task::MAX_TASKS - 3;
    const INITIAL_RESIDENT_PROCESS_CAPACITY: usize = 64;
    const RESIDENT_PROCESS_LOG_BYTES: usize = 64 * 1024;
    // Nested children run on the launching task's kernel stack: pumping a child
    // re-enters `ResidentApplication::step`, so nesting costs one frame per
    // level. `step` keeps only the pump on that recursive path and leaves its
    // message buffers and service handlers in `run_execution_slice`, which is
    // never recursive, so a level costs about 1 KiB and the one running slice
    // about 53 KiB. Eight levels stay near two thirds of
    // SHELL_TASK_STACK_BYTES on both architectures.
    const MAX_LAUNCH_DEPTH: u32 = 8;
    const RESIDENT_APPLICATION_TIMESLICE_MILLISECONDS: u32 = 10;
    const RESIDENT_SERVICE_CALLS_PER_STEP: usize = 4;
    const RESIDENT_POLL_MILLISECONDS: u32 = 10;
    const ISOLATED_TABLE_PAGES: u64 = PAGE_TABLE_BYTES / BASE_PAGE_SIZE;
    const ISOLATED_CODE_PAGES: u64 = 1;
    const ISOLATED_DATA_PAGES: u64 = 1;
    const ISOLATED_STACK_PAGES: u64 = 4;
    const ISOLATED_PRIVATE_PAGES: u64 =
        ISOLATED_CODE_PAGES + ISOLATED_DATA_PAGES + ISOLATED_STACK_PAGES;
    const ISOLATED_RESOURCE_PAGES: u64 = ISOLATED_TABLE_PAGES + ISOLATED_PRIVATE_PAGES;
    const STAGE6_USER_REGION_LIMIT: usize = 8;
    const STAGE6_USER_REGIONS: usize = 3;
    const APPLICATION_INTERFACE_ECHO: u32 = 1;
    const APPLICATION_TIMESLICE_MILLISECONDS: u32 = 50;
    const APPLICATION_DATAGRAM_WAIT_MILLISECONDS: u64 = 4_000;
    #[cfg(feature = "acceptance-probes")]
    const IPC_BASELINE_WARMUP_CALLS: usize = 64;
    #[cfg(feature = "acceptance-probes")]
    const IPC_BASELINE_SAMPLES: usize = 256;
    #[cfg(feature = "acceptance-probes")]
    const IPC_ISOLATED_SERVICE_CALL_LIMIT: u16 = 1536;
    #[cfg(feature = "acceptance-probes")]
    const DIAGNOSTICS_SERVER_MAX_RETAINED_REQUESTS: usize = 1;
    #[cfg(feature = "acceptance-probes")]
    const DIAGNOSTICS_SERVER_MAX_CONTEXTS: usize = 1;
    const USER_CODE_BASE: u64 = 0x0000_4000_0000_0000;
    const USER_DATA_BASE: u64 = USER_CODE_BASE + BASE_PAGE_SIZE;
    const USER_STACK_BASE: u64 = USER_CODE_BASE + 0x1_0000;
    const USER_UNMAPPED_BASE: u64 = USER_CODE_BASE + 0x1000_0000;
    const ISOLATED_MESSAGE: &[u8] = b"stage6 copied request";
    const BOOT_ARENA_PAGES: usize = ((OWNED_HEAP_BYTES
        + PAGE_TABLE_BYTES
        + OWNED_STACK_BYTES
        + EXCEPTION_STACK_BYTES
        + TASK_STACK_BYTES
        + SERVER_TASK_STACK_BYTES
        + SHELL_TASK_STACK_BYTES
        + 2 * TASK_GUARD_BYTES * TASK_STACK_COUNT as u64)
        / BASE_PAGE_SIZE) as usize;
    const BOOT_STATUS_WIDTH: usize = 54;
    const BOOT_MEMORY_LABEL: &str = "Initializing memory and protection";
    const BOOT_DEVICES_LABEL: &str = "Starting devices and input";
    const BOOT_RUNTIME_LABEL: &str = "Starting task and application runtime";
    const _: () = assert!(TASK_STACK_BYTES == TASK_STACK_PAGES * BASE_PAGE_SIZE);
    const _: () = assert!(SERVER_TASK_STACK_BYTES == SERVER_TASK_STACK_PAGES * BASE_PAGE_SIZE);
    const _: () = assert!(SHELL_TASK_STACK_BYTES == SHELL_TASK_STACK_PAGES * BASE_PAGE_SIZE);
    const _: () = assert!(TASK_GUARD_BYTES == BASE_PAGE_SIZE);
    const _: () = assert!(TASK_STACK_COUNT == 3);
    const _: () = assert!(STAGE6_USER_REGIONS <= STAGE6_USER_REGION_LIMIT);

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

    struct DiscardOutput;

    impl Input for EmptyInput {
        fn read(&mut self, _destination: &mut [u8]) -> Result<usize, StreamError> {
            Ok(0)
        }
    }

    type SharedShellConsole = Rc<RefCell<NativeShellConsole>>;

    /// Client for the single owned shell console.
    ///
    /// The dispatched console service and session terminal echo both write
    /// through this handle, so serial and framebuffer output stay mirrored
    /// regardless of which one produced the bytes.
    struct SharedConsoleOutput {
        console: SharedShellConsole,
    }

    impl SharedConsoleOutput {
        const fn new(console: SharedShellConsole) -> Self {
            Self { console }
        }
    }

    impl Output for SharedConsoleOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            self.console
                .try_borrow_mut()
                .map_err(|_| StreamError::Device)?
                .write(bytes)
        }
    }

    /// Reserved generation-checked identity for one session terminal read.
    const SESSION_TERMINAL_WAIT_IDENTITY: u64 = u64::MAX;
    /// Cooked bytes retained for a foreground reader before input is refused.
    const SESSION_TERMINAL_READY_BYTES: usize = 4 * (MAX_LINE_BYTES + 1);

    /// The single owner of session input decoding and the cooked line
    /// discipline.
    ///
    /// The line editor consumes decoded keys at the prompt. While one
    /// foreground process holds the loan, the same decoders instead feed a
    /// bounded cooked byte stream that the process reads through its ordinary
    /// standard-input handle. Background jobs, services, staged script lines,
    /// and owner-scoped children never hold the loan.
    struct SessionTerminal {
        runtime: SharedRuntime,
        echo: SharedConsoleOutput,
        input_config: InputConfig,
        keyboard_config: KeyboardConfig,
        decoder: InputDecoder,
        keyboard: Ps2Set1Decoder,
        pending: String,
        ready: VecDeque<u8>,
        end_of_input: bool,
        owner: Option<TaskId>,
    }

    type SharedSessionTerminal = Rc<RefCell<SessionTerminal>>;

    impl SessionTerminal {
        fn new(
            runtime: SharedRuntime,
            echo: SharedConsoleOutput,
            input_config: InputConfig,
            keyboard_config: KeyboardConfig,
        ) -> Result<Self, ()> {
            let mut pending = String::new();
            pending.try_reserve_exact(MAX_LINE_BYTES).map_err(|_| ())?;
            let mut ready = VecDeque::new();
            ready
                .try_reserve_exact(SESSION_TERMINAL_READY_BYTES)
                .map_err(|_| ())?;
            Ok(Self {
                runtime,
                echo,
                input_config,
                keyboard_config,
                decoder: InputDecoder::new(input_config),
                keyboard: Ps2Set1Decoder::new(keyboard_config),
                pending,
                ready,
                end_of_input: false,
                owner: None,
            })
        }

        /// Decode one machine event with the session-owned decoders.
        fn decode(&mut self, event: InputEvent) -> Option<KeyEvent> {
            match event.source() {
                InputSource::Serial => self.decoder.push(event.byte()),
                InputSource::Keyboard => self.keyboard.push(event.byte()),
            }
        }

        /// Lend the terminal to one foreground process.
        fn lend(&mut self, owner: TaskId) -> Result<(), ()> {
            if self.owner.is_some() {
                return Err(());
            }
            self.reset();
            self.owner = Some(owner);
            Ok(())
        }

        /// Return the loan and discard unread cooked input.
        fn release(&mut self) {
            self.owner = None;
            self.reset();
        }

        fn reset(&mut self) {
            self.pending.clear();
            self.ready.clear();
            self.end_of_input = false;
            self.decoder = InputDecoder::new(self.input_config);
            self.keyboard = Ps2Set1Decoder::new(self.keyboard_config);
        }

        /// Drain retained machine events into the cooked stream.
        ///
        /// Cancellation is intercepted before this point, so a cancelling key
        /// never reaches the line discipline.
        fn pump(&mut self) {
            if self.owner.is_none() {
                return;
            }
            loop {
                let event = match self.runtime.try_borrow_mut() {
                    Ok(mut runtime) => runtime.take_input_event(),
                    Err(_) => return,
                };
                let Some(event) = event else {
                    return;
                };
                if let Some(key) = self.decode(event) {
                    self.apply(key);
                }
            }
        }

        fn apply(&mut self, key: KeyEvent) {
            if self.end_of_input {
                return;
            }
            match key {
                KeyEvent::Character(character) => self.insert(character),
                KeyEvent::Enter => self.submit(),
                KeyEvent::Backspace => self.erase(),
                KeyEvent::KillBefore => {
                    while !self.pending.is_empty() {
                        self.erase();
                    }
                }
                KeyEvent::EndOfInput => {
                    if self.pending.is_empty() {
                        self.end_of_input = true;
                    } else {
                        self.publish(false);
                    }
                }
                // The cooked discipline has no completion, history, or cursor
                // movement, so the editor keys those transports carry are
                // either taken literally or ignored.
                KeyEvent::Complete => self.insert('\t'),
                KeyEvent::Cancel
                | KeyEvent::Delete
                | KeyEvent::Left
                | KeyEvent::Right
                | KeyEvent::Home
                | KeyEvent::End
                | KeyEvent::Up
                | KeyEvent::Down
                | KeyEvent::ClearDisplay
                | KeyEvent::KillAfter
                | KeyEvent::DeletePreviousWord => {}
            }
        }

        fn insert(&mut self, character: char) {
            let width = character.len_utf8();
            if self.pending.len().saturating_add(width) > MAX_LINE_BYTES {
                return;
            }
            let mut encoded = [0_u8; 4];
            let text = character.encode_utf8(&mut encoded);
            if write_all(&mut self.echo, text.as_bytes()).is_err() {
                return;
            }
            self.pending.push(character);
        }

        fn erase(&mut self) {
            if self.pending.pop().is_none() {
                return;
            }
            let _echo = write_all(&mut self.echo, b"\x08 \x08");
        }

        fn submit(&mut self) {
            self.publish(true);
        }

        /// Move the pending line into the cooked stream when it fits.
        fn publish(&mut self, newline: bool) {
            let terminator = usize::from(newline);
            let required = self.pending.len().saturating_add(terminator);
            if self.ready.len().saturating_add(required) > SESSION_TERMINAL_READY_BYTES {
                return;
            }
            if newline && write_all(&mut self.echo, b"\n").is_err() {
                return;
            }
            for byte in self.pending.as_bytes() {
                self.ready.push_back(*byte);
            }
            if newline {
                self.ready.push_back(b'\n');
            }
            self.pending.clear();
        }

        /// Whether a read can complete without waiting.
        fn read_ready(&self) -> bool {
            !self.ready.is_empty() || self.end_of_input
        }

        /// Copy cooked bytes out of the stream. Zero means end of input.
        fn take(&mut self, destination: &mut [u8]) -> usize {
            let mut count = 0;
            while count < destination.len() {
                let Some(byte) = self.ready.pop_front() else {
                    break;
                };
                destination[count] = byte;
                count += 1;
            }
            count
        }
    }

    /// Standard input bound to the session terminal loan.
    ///
    /// Application reads are admitted through the deferred-call path, which
    /// blocks without starving the event loop. This direct implementation
    /// serves shell-owned consumers that read the same stream synchronously.
    struct SessionTerminalInput {
        terminal: SharedSessionTerminal,
    }

    impl SessionTerminalInput {
        const fn new(terminal: SharedSessionTerminal) -> Self {
            Self { terminal }
        }
    }

    impl Input for SessionTerminalInput {
        fn read(&mut self, destination: &mut [u8]) -> Result<usize, StreamError> {
            loop {
                let runtime = {
                    let mut terminal = self
                        .terminal
                        .try_borrow_mut()
                        .map_err(|_| StreamError::Device)?;
                    terminal.pump();
                    if terminal.read_ready() {
                        return Ok(terminal.take(destination));
                    }
                    terminal.runtime.clone()
                };
                if runtime.borrow_mut().checkpoint().is_err() {
                    return Ok(0);
                }
                troe_machine::wait_for_runtime_event_timeout(RESIDENT_POLL_MILLISECONDS)
                    .map_err(|_| StreamError::Device)?;
            }
        }

        fn is_terminal(&self) -> bool {
            true
        }
    }

    impl Output for DiscardOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, StreamError> {
            Ok(bytes.len())
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
        native_statefs: RefCell<Option<Box<dyn FileSystemProvider>>>,
        native_generation: NativeGenerationState,
        selected_config: Option<SystemConfig>,
        memory_policy: MemoryPolicy,
        application_committed_pages: u64,
        private_metadata_bytes: u64,
        random: SharedRandom,
        firmware_wall_seconds: Option<u64>,
        boot_mount_manifest: BootMountManifest,
        runtime_mounts: SharedRuntimeMounts,
    }

    struct NativeBlockInitialization {
        blocks: Vec<troe_machine::NativeVirtioBlock>,
        statefs: Option<Box<dyn FileSystemProvider>>,
        generation: NativeGenerationState,
        config: Option<SystemConfig>,
    }

    struct RecoveredNativeGeneration {
        state: NativeGenerationState,
        config: Option<SystemConfig>,
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
        residents: &'a mut ResidentProcessTable,
        processes: SharedProcessTable,
        resident_owner: ResidentOwner,
        service_initial_handles: Option<u8>,
        service_capability_bits: Option<u32>,
        service_runtime: Option<&'a mut ServiceRuntime>,
        shell_id: TaskId,
        shell_capabilities: Capabilities,
        runtime: SharedRuntime,
        session_terminal: Option<SharedSessionTerminal>,
        pending_script_lines: Option<Vec<String>>,
        /// Composition authority. External execution attaches application
        /// filesystem and volume services, which is more than the client
        /// contract the session itself holds.
        composed_namespace: OwnedNamespace,
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
    struct CommandApplicationHandle {
        value: u64,
        interface: u32,
    }

    type SharedResidentLog = Rc<RefCell<BoundedLog>>;
    type SharedProcessTable = Rc<RefCell<ProcessTable>>;
    type SharedTaskIdentity = Rc<Cell<Option<TaskId>>>;
    /// The composition root retains the concrete namespace, because mounting
    /// providers and projecting generated state are authorities a client of
    /// the namespace must not hold.
    type OwnedNamespace = Rc<RefCell<Namespace>>;

    /// The architecture name with its trailing newline, for `/sys/arch`.
    fn architecture_line() -> String {
        let mut line = String::from(architecture());
        line.push('\n');
        line
    }
    type SharedChildTable = Rc<RefCell<ChildTable>>;
    type SharedPipeTable = Rc<RefCell<PipeTable>>;
    type SharedRandom = Rc<RefCell<RandomGenerator>>;
    type SharedProcessOwner = Rc<Cell<Option<OwnerId>>>;

    struct ApplicationEmptyInputService;

    struct ApplicationDiscardOutputService;

    /// Registration marker. Calls are intercepted while the application is
    /// suspended so the dispatcher never receives memory-management state.
    struct ApplicationPrivateMemoryService;

    struct ApplicationRandomService {
        random: SharedRandom,
    }

    struct ApplicationLogService {
        log: SharedResidentLog,
    }

    #[derive(Clone)]
    enum NestedInput<'stream> {
        Empty,
        Borrowed(Rc<RefCell<&'stream mut dyn Input>>),
        Pipe {
            pipes: SharedPipeTable,
            owner: OwnerId,
            token: pipe::PipeToken,
        },
    }

    #[derive(Clone)]
    enum NestedOutput<'stream> {
        Discard,
        Borrowed(Rc<RefCell<&'stream mut dyn Output>>),
        Log(SharedResidentLog),
        Pipe {
            pipes: SharedPipeTable,
            owner: OwnerId,
            token: pipe::PipeToken,
        },
    }

    #[derive(Clone)]
    struct NestedStdio<'stream> {
        stdin: NestedInput<'stream>,
        stdout: NestedOutput<'stream>,
        stderr: NestedOutput<'stream>,
    }

    #[derive(Clone)]
    struct NestedLaunchContext<'stream> {
        namespace: OwnedNamespace,
        runtime: SharedRuntime,
        processes: SharedProcessTable,
        mounts: SharedRuntimeMounts,
        stdio: NestedStdio<'stream>,
    }

    struct NestedChild<'service> {
        token: process_launch::ChildToken,
        process: Option<Box<ResidentApplication<'service>>>,
        outcome: Option<CommandApplicationOutcome>,
    }

    struct ResidentProcessControl<'service> {
        owner: OwnerId,
        depth: u32,
        grants: BackgroundRequirements,
        children: SharedChildTable,
        pipes: SharedPipeTable,
        launch: NestedLaunchContext<'service>,
        processes: Vec<NestedChild<'service>>,
    }

    enum ResidentExecution {
        Unstarted(Box<ResidentLaunch>),
        Pending(Box<troe_machine::ApplicationOutcome>),
        Blocked,
    }

    struct ResidentLaunch {
        address_space: troe_machine::UserAddressSpace,
        entry: u64,
        stack_top: u64,
        startup_address: u64,
    }

    struct ResidentApplication<'service> {
        task_id: TaskId,
        process_id: ProcessId,
        processes: SharedProcessTable,
        allocation: ApplicationAllocation,
        isolation: IsolationResource,
        owner: HandleOwner,
        handles: Vec<CommandApplicationHandle>,
        handle_count: u16,
        stack_pages: u64,
        heap_start: u64,
        maximum_heap_pages: u64,
        private_pages: u64,
        dispatcher: Dispatcher<'service>,
        deferred_services: Option<CommandDeferredServices>,
        deferred_state: Option<CommandDeferredState>,
        process_control: Option<ResidentProcessControl<'service>>,
        execution: Option<ResidentExecution>,
    }

    struct ResidentJob {
        id: u32,
        task_id: TaskId,
        command: String,
        owner: ResidentOwner,
        log: SharedResidentLog,
        process: Option<Box<ResidentApplication<'static>>>,
        outcome: Option<CommandApplicationOutcome>,
        cancel_requested: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ResidentOwner {
        Session,
        Service(u32),
    }

    struct ResidentProcessTable {
        jobs: Vec<ResidentJob>,
        next_id: u32,
    }

    struct ServiceRuntime {
        config: SystemConfig,
        supervisor: Supervisor,
    }

    struct CommandDeferredServices {
        runtime: SharedRuntime,
        datagram: Option<SharedApplicationDatagram>,
        diagnostics: Option<Rc<[u8; diagnostics::SNAPSHOT_BYTES]>>,
        process_owner: Option<OwnerId>,
        children: Option<SharedChildTable>,
        pipes: Option<SharedPipeTable>,
        pipe_streams: Vec<PipeStreamService>,
        terminal: Option<SharedSessionTerminal>,
    }

    #[derive(Clone)]
    struct PipeStreamService {
        interface: u32,
        pipes: SharedPipeTable,
        endpoint: PipeEndpoint,
    }

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Clone, Copy)]
    struct BackgroundRequirements {
        datagram: bool,
        filesystem: bool,
        filesystem_mutation: bool,
        timer: bool,
        diagnostics: bool,
        process_observation: bool,
        process_launch: bool,
        pipe: bool,
        network_observation: bool,
        network_configuration: bool,
        icmp_echo: bool,
        tcp_connect: bool,
        volume_control: bool,
        wall_clock: bool,
        clock_control: bool,
        private_memory: bool,
        random: bool,
    }

    impl BackgroundRequirements {
        fn attenuates(self, required: Self, shell_script: bool) -> bool {
            !shell_script
                && !required.clock_control
                && (!required.datagram || self.datagram)
                && (!required.filesystem || self.filesystem)
                && (!required.filesystem_mutation || self.filesystem_mutation)
                && (!required.timer || self.timer)
                && (!required.diagnostics || self.diagnostics)
                && (!required.process_observation || self.process_observation)
                && (!required.process_launch || self.process_launch)
                && (!required.pipe || self.pipe)
                && (!required.network_observation || self.network_observation)
                && (!required.network_configuration || self.network_configuration)
                && (!required.icmp_echo || self.icmp_echo)
                && (!required.tcp_connect || self.tcp_connect)
                && (!required.volume_control || self.volume_control)
                && (!required.wall_clock || self.wall_clock)
                && (!required.private_memory || self.private_memory)
                && (!required.random || self.random)
        }
    }

    #[allow(clippy::too_many_lines)]
    fn decode_application_requirements(
        manifest: troe_abi::requirements::Manifest<'_>,
    ) -> Result<(BackgroundRequirements, bool), ()> {
        let mut required = BackgroundRequirements {
            datagram: false,
            filesystem: false,
            filesystem_mutation: false,
            timer: false,
            diagnostics: false,
            process_observation: false,
            process_launch: false,
            pipe: false,
            network_observation: false,
            network_configuration: false,
            icmp_echo: false,
            tcp_connect: false,
            volume_control: false,
            wall_clock: false,
            clock_control: false,
            private_memory: false,
            random: false,
        };
        let mut shell_script = false;
        for requirement in manifest.iter() {
            let supported = match requirement.interface {
                troe_abi::interface::DATAGRAM => {
                    required.datagram = true;
                    requirement.major == datagram::MAJOR && requirement.minor == datagram::MINOR
                }
                troe_abi::interface::FILESYSTEM_READ => {
                    required.filesystem = true;
                    requirement.major == filesystem::MAJOR && requirement.minor == filesystem::MINOR
                }
                troe_abi::interface::FILESYSTEM_MUTATE => {
                    required.filesystem_mutation = true;
                    requirement.major == filesystem_mutation::MAJOR
                        && requirement.minor == filesystem_mutation::MINOR
                }
                troe_abi::interface::TIMER => {
                    required.timer = true;
                    requirement.major == timer::MAJOR && requirement.minor == timer::MINOR
                }
                troe_abi::interface::DIAGNOSTICS => {
                    required.diagnostics = true;
                    requirement.major == diagnostics::MAJOR
                        && requirement.minor == diagnostics::MINOR
                }
                troe_abi::interface::PROCESS_OBSERVE => {
                    required.process_observation = true;
                    requirement.major == process_observation::MAJOR
                        && requirement.minor == process_observation::MINOR
                }
                troe_abi::interface::PROCESS_LAUNCH => {
                    required.process_launch = true;
                    requirement.major == process_launch::MAJOR
                        && requirement.minor == process_launch::MINOR
                }
                troe_abi::interface::PIPE => {
                    required.pipe = true;
                    requirement.major == pipe::MAJOR && requirement.minor == pipe::MINOR
                }
                troe_abi::interface::NETWORK_OBSERVE => {
                    required.network_observation = true;
                    requirement.major == network_observation::MAJOR
                        && requirement.minor == network_observation::MINOR
                }
                troe_abi::interface::NETWORK_CONFIGURE => {
                    required.network_configuration = true;
                    requirement.major == network_configuration::MAJOR
                        && requirement.minor == network_configuration::MINOR
                }
                troe_abi::interface::ICMP_ECHO => {
                    required.icmp_echo = true;
                    requirement.major == icmp_echo::MAJOR && requirement.minor == icmp_echo::MINOR
                }
                troe_abi::interface::TCP_CONNECT => {
                    required.tcp_connect = true;
                    requirement.major == tcp_connect::MAJOR
                        && requirement.minor == tcp_connect::MINOR
                }
                troe_abi::interface::VOLUME_CONTROL => {
                    required.volume_control = true;
                    requirement.major == volume_control::MAJOR
                        && requirement.minor == volume_control::MINOR
                }
                troe_abi::interface::SHELL_SCRIPT => {
                    shell_script = true;
                    requirement.major == shell_script::MAJOR
                        && requirement.minor == shell_script::MINOR
                }
                troe_abi::interface::WALL_CLOCK => {
                    required.wall_clock = true;
                    requirement.major == wall_clock::MAJOR && requirement.minor == wall_clock::MINOR
                }
                troe_abi::interface::CLOCK_CONTROL => {
                    required.clock_control = true;
                    requirement.major == clock_control::MAJOR
                        && requirement.minor == clock_control::MINOR
                }
                troe_abi::interface::PRIVATE_MEMORY => {
                    required.private_memory = true;
                    requirement.major == private_memory::MAJOR
                        && requirement.minor == private_memory::MINOR
                }
                troe_abi::interface::RANDOM => {
                    required.random = true;
                    requirement.major == random::MAJOR && requirement.minor == random::MINOR
                }
                _ => false,
            };
            if !supported {
                return Err(());
            }
        }
        Ok((required, shell_script))
    }

    enum DeferredCallKind {
        Timer {
            deadline: MonotonicMillis,
        },
        Datagram {
            state: SharedApplicationDatagram,
            local_port: u16,
            deadline: MonotonicMillis,
            resource: WaitResource,
        },
        Diagnostics {
            resource: WaitResource,
        },
        Child {
            children: SharedChildTable,
            owner: OwnerId,
            token: process_launch::ChildToken,
            resource: WaitResource,
        },
        PipeRead {
            pipes: SharedPipeTable,
            target: DeferredPipeTarget,
            maximum: usize,
            resource: WaitResource,
        },
        PipeWrite {
            pipes: SharedPipeTable,
            target: DeferredPipeTarget,
            byte_count: usize,
            resource: WaitResource,
        },
        TerminalRead {
            terminal: SharedSessionTerminal,
            maximum: usize,
            resource: WaitResource,
        },
    }

    #[derive(Clone, Copy)]
    enum DeferredPipeTarget {
        Owner {
            owner: OwnerId,
            token: pipe::PipeToken,
        },
        Endpoint(PipeEndpoint),
    }

    struct SuspendedApplicationCall {
        operation: PendingOperationId,
        application: troe_machine::ApplicationSession,
        call: troe_machine::ApplicationCall,
        kind: DeferredCallKind,
    }

    struct SuspendedApplicationCalls {
        slots: Vec<SuspendedApplicationCall>,
        high_water: u8,
    }

    struct CommandDeferredState {
        pending: PendingCallTable,
        waits: WaitTable,
        suspended: SuspendedApplicationCalls,
        next_request_id: u64,
    }

    enum DeferredCallPreparation {
        NotDeferred,
        Immediate {
            status: ReplyStatus,
            payload: Vec<u8>,
        },
        Blocked {
            operation: PendingOperationId,
            spec: WaitSpec,
            kind: DeferredCallKind,
        },
    }

    #[derive(Clone, Copy)]
    struct Ipv4Configuration {
        address: Ipv4Address,
        subnet_mask: Ipv4Address,
        gateway: Ipv4Address,
        lease_seconds: Option<u32>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum NetworkError {
        NotConfigured,
        Timeout,
        Device,
        Protocol,
        TooLarge,
        Exhausted,
        Cancelled,
        Closed,
    }

    #[derive(Clone, Copy)]
    struct NetworkStatus {
        mac: [u8; 6],
        address: Option<[u8; 4]>,
        subnet_mask: Option<[u8; 4]>,
        gateway: Option<[u8; 4]>,
        lease_seconds: Option<u32>,
    }

    #[derive(Clone, Copy)]
    struct PingReply {
        source: [u8; 4],
        sequence: u16,
        bytes: usize,
    }

    struct ReceivedUdp {
        source: [u8; 4],
        source_port: u16,
        payload: Vec<u8>,
    }

    struct KernelNetworkService {
        device: troe_machine::NativeVirtioNetwork,
        configuration: Option<Ipv4Configuration>,
        next_sequence: u16,
        next_port: u16,
        next_tcp_port: u16,
        next_tcp_id: u64,
        tcp_generation: u32,
        dhcp_generation: u16,
        arp: ArpCache,
        udp: UdpPortTable,
        dhcp_inbox: VecDeque<DhcpPacket>,
        echo_inbox: VecDeque<EchoReply>,
        tcp: Vec<SharedTcpConnection>,
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
    type SharedTcpConnection = Rc<RefCell<KernelTcpConnection>>;
    type SharedRuntimeMounts = Rc<RefCell<RuntimeMountRegistry>>;
    type SharedApplicationDatagram = Rc<RefCell<ApplicationDatagramState>>;
    type SharedDiagnosticsSnapshot = Rc<[u8; diagnostics::SNAPSHOT_BYTES]>;
    type DiagnosticsServerCompletion = (ReplyStatus, Vec<u8>);
    type DiagnosticsServerFate = (WakeReason, Option<DiagnosticsServerCompletion>);

    struct RuntimeMountRecord {
        name: String,
        filesystem: volume_control::Filesystem,
        access: volume_control::Access,
        activation: volume_control::Activation,
        state: volume_control::State,
        prepared: Option<PreparedMount>,
    }

    struct RuntimeMountRegistry {
        entries: Vec<RuntimeMountRecord>,
    }

    impl RuntimeMountRegistry {
        const fn empty() -> Self {
            Self {
                entries: Vec::new(),
            }
        }

        fn configure(
            &mut self,
            manifest: &BootMountManifest,
            mut prepared: Vec<PreparedMount>,
            namespace: &mut Namespace,
        ) -> Result<(), ()> {
            if !self.entries.is_empty() {
                return Err(());
            }
            self.entries
                .try_reserve_exact(manifest.entries().len())
                .map_err(|_| ())?;
            for entry in manifest.entries() {
                let path = alloc::format!("/vol/{}", entry.name());
                let plan = prepared
                    .iter()
                    .position(|plan| plan.path() == path)
                    .map(|index| prepared.remove(index));
                if plan
                    .as_ref()
                    .is_some_and(|plan| plan.activation() != entry.activation())
                {
                    return Err(());
                }
                let (state, prepared) = match (entry.activation(), plan) {
                    (ActivationMode::Auto, Some(plan)) => {
                        plan.attach(namespace).map_err(|_| ())?;
                        (volume_control::State::Mounted, None)
                    }
                    (ActivationMode::Manual, Some(plan)) => {
                        (volume_control::State::Ready, Some(plan))
                    }
                    (_, None) => (volume_control::State::Unavailable, None),
                };
                let mut name = String::new();
                name.try_reserve_exact(entry.name().len()).map_err(|_| ())?;
                name.push_str(entry.name());
                self.entries.push(RuntimeMountRecord {
                    name,
                    filesystem: match entry.filesystem() {
                        FilesystemProfile::Fat32 => volume_control::Filesystem::Fat32,
                        FilesystemProfile::Ext4V1 => volume_control::Filesystem::Ext4V1,
                    },
                    access: match entry.access() {
                        AccessMode::ReadOnly => volume_control::Access::ReadOnly,
                        AccessMode::ReadWrite => volume_control::Access::ReadWrite,
                    },
                    activation: match entry.activation() {
                        ActivationMode::Auto => volume_control::Activation::Auto,
                        ActivationMode::Manual => volume_control::Activation::Manual,
                    },
                    state,
                    prepared,
                });
            }
            if prepared.is_empty() { Ok(()) } else { Err(()) }
        }

        fn encode_list(&self, output: &mut [u8]) -> Result<usize, ()> {
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(self.entries.len())
                .map_err(|_| ())?;
            for entry in &self.entries {
                entries.push(volume_control::VolumeInfo {
                    name: &entry.name,
                    filesystem: entry.filesystem,
                    access: entry.access,
                    activation: entry.activation,
                    state: entry.state,
                });
            }
            volume_control::encode_list(&entries, output).map_err(|_| ())
        }

        fn activate(&mut self, name: &str, namespace: &mut Namespace) -> Result<(), ReplyStatus> {
            let entry = self
                .entries
                .iter_mut()
                .find(|entry| entry.name == name)
                .ok_or(ReplyStatus::NotFound)?;
            match entry.state {
                volume_control::State::Mounted => Ok(()),
                volume_control::State::Unavailable => Err(ReplyStatus::NotFound),
                volume_control::State::Failed => Err(ReplyStatus::Failure),
                volume_control::State::Ready => {
                    if entry.activation != volume_control::Activation::Manual {
                        return Err(ReplyStatus::InvalidRequest);
                    }
                    let plan = entry.prepared.take().ok_or(ReplyStatus::Corrupt)?;
                    if let Ok(()) = plan.attach(namespace) {
                        entry.state = volume_control::State::Mounted;
                        let _updated = mark_storage_role_mounted(namespace, name);
                        Ok(())
                    } else {
                        entry.state = volume_control::State::Failed;
                        Err(ReplyStatus::Failure)
                    }
                }
            }
        }
    }

    fn mark_storage_role_mounted(namespace: &mut Namespace, name: &str) -> Result<(), ()> {
        let current = namespace.read_file("/", "/sys/storage").map_err(|_| ())?;
        let current = core::str::from_utf8(&current).map_err(|_| ())?;
        let prefix = alloc::format!("role {name} ");
        let marker = " state=ready volume=";
        let replacement = " state=mounted volume=";
        let mut updated = String::new();
        updated
            .try_reserve_exact(
                current
                    .len()
                    .saturating_add(replacement.len() - marker.len()),
            )
            .map_err(|_| ())?;
        let mut changed = false;
        for line in current.split_inclusive('\n') {
            if line.starts_with(&prefix) {
                let offset = line.find(marker).ok_or(())?;
                updated.push_str(&line[..offset]);
                updated.push_str(replacement);
                updated.push_str(&line[offset + marker.len()..]);
                changed = true;
            } else {
                updated.push_str(line);
            }
        }
        if !changed {
            return Err(());
        }
        namespace
            .set_system_file("/sys/storage", updated.as_bytes())
            .map_err(|_| ())
    }

    struct KernelTcpConnection {
        id: u64,
        local_port: u16,
        peer_mac: MacAddress,
        machine: TcpConnection,
    }

    struct KernelNetwork {
        service: SharedNetwork,
    }

    struct KernelRuntime {
        network: Option<SharedNetwork>,
        wall_clock: Option<WallClockAnchor>,
        deferred_input: VecDeque<InputEvent>,
        control_down: bool,
        last_millis: Cell<u64>,
    }

    type SharedRuntime = Rc<RefCell<KernelRuntime>>;

    #[derive(Clone, Copy)]
    struct WallClockAnchor {
        unix_seconds: u64,
        monotonic_milliseconds: u64,
    }

    /// The runtime's wall clock, as filesystem providers read it.
    ///
    /// Providers hold this handle and ask it at each mutation, so a volume
    /// mounted at boot stamps the current time rather than its mount time.
    struct RuntimeWallClock {
        runtime: SharedRuntime,
    }

    impl core::fmt::Debug for RuntimeWallClock {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.debug_struct("RuntimeWallClock").finish()
        }
    }

    impl WallClock for RuntimeWallClock {
        fn unix_seconds(&self) -> Option<u64> {
            // A mutation reached from inside a runtime borrow reports no time
            // rather than panicking; the provider then leaves its timestamps
            // untouched, which is the same contract as having no clock.
            self.runtime.try_borrow().ok()?.wall_seconds()
        }
    }

    struct ApplicationDatagramService {
        state: SharedApplicationDatagram,
        runtime: SharedRuntime,
    }

    struct ApplicationDatagramState {
        network: SharedNetwork,
        ports: Vec<u16>,
    }

    struct ApplicationFilesystemService {
        namespace: SharedNamespace,
        cwd: String,
        files: Vec<ApplicationFileSlot>,
    }

    struct ApplicationInputService<'stream> {
        input: Rc<RefCell<&'stream mut dyn Input>>,
    }

    struct ApplicationOutputService<'stream> {
        output: Rc<RefCell<&'stream mut dyn Output>>,
    }

    struct ApplicationFilesystemMutationService {
        namespace: SharedNamespace,
        cwd: String,
        next_token: Option<u32>,
        pending: Option<PendingFileReplacement>,
    }

    struct ApplicationVolumeControlService {
        /// Activating a manifest volume attaches a provider, which is
        /// composition authority rather than client access.
        namespace: OwnedNamespace,
        mounts: SharedRuntimeMounts,
    }

    struct ApplicationTimerService {
        runtime: SharedRuntime,
        processes: SharedProcessTable,
        task_id: SharedTaskIdentity,
    }

    struct ApplicationWallClockService {
        runtime: SharedRuntime,
    }

    struct ApplicationClockControlService {
        runtime: SharedRuntime,
    }

    #[derive(Default)]
    struct SubmittedShellScript {
        lines: Vec<String>,
        source_bytes: usize,
    }

    struct ApplicationShellScriptService {
        script: Rc<RefCell<SubmittedShellScript>>,
    }

    struct ApplicationDiagnosticsProxyService;

    struct ApplicationDiagnosticsSnapshotService {
        snapshot: SharedDiagnosticsSnapshot,
    }

    struct ApplicationProcessObservationService {
        processes: SharedProcessTable,
        runtime: SharedRuntime,
    }

    struct ApplicationProcessLaunchService {
        owner: SharedProcessOwner,
        children: SharedChildTable,
    }

    struct ApplicationPipeService {
        owner: SharedProcessOwner,
        pipes: SharedPipeTable,
    }

    struct ApplicationPipeInputService {
        pipes: SharedPipeTable,
        endpoint: PipeEndpoint,
    }

    struct ApplicationPipeOutputService {
        pipes: SharedPipeTable,
        endpoint: PipeEndpoint,
    }

    struct DiagnosticsServerExchange {
        operation: PendingOperationId,
        snapshot: SharedDiagnosticsSnapshot,
        reply_capacity: usize,
        received: bool,
        completed: bool,
        status: ReplyStatus,
        reply: Vec<u8>,
        reply_bytes: usize,
        steady_allocation_calls: Option<usize>,
        steady_allocation_free: bool,
    }

    struct DiagnosticsServerEndpoint {
        exchange: Rc<RefCell<DiagnosticsServerExchange>>,
    }

    struct DiagnosticsServerRunner<'a> {
        accounting: &'a mut OwnedAccounting,
        scheduler: &'a mut Scheduler,
        exchange: Rc<RefCell<DiagnosticsServerExchange>>,
        artifact: &'static [u8],
        fault_probe: bool,
        outcome: Option<Result<CommandApplicationOutcome, ()>>,
    }

    #[cfg(feature = "acceptance-probes")]
    struct DiagnosticsBenchmarkExchange {
        payload: [u8; troe_abi::MAX_MESSAGE_BYTES],
        payload_bytes: usize,
        logical_index: usize,
        fragment_index: usize,
        received: bool,
        expected_token: u64,
        started_ticks: u64,
        started_execution: troe_machine::ApplicationExecutionStats,
        started_allocations: usize,
        samples: [u64; IPC_BASELINE_SAMPLES],
        measured: usize,
        address_space_switches: u64,
        tlb_invalidations: u64,
        timer_programs: u64,
        steady_allocation_calls: u64,
    }

    #[cfg(feature = "acceptance-probes")]
    struct DiagnosticsBenchmarkEndpoint {
        exchange: Rc<RefCell<DiagnosticsBenchmarkExchange>>,
    }

    #[cfg(feature = "acceptance-probes")]
    struct DiagnosticsBenchmarkRunner<'a> {
        accounting: &'a mut OwnedAccounting,
        scheduler: &'a mut Scheduler,
        exchange: Rc<RefCell<DiagnosticsBenchmarkExchange>>,
        outcome: Option<Result<CommandApplicationOutcome, ()>>,
    }

    #[cfg(feature = "acceptance-probes")]
    static DIAGNOSTICS_FAULT_PROBE_REQUESTED: AtomicBool = AtomicBool::new(false);
    #[cfg(feature = "acceptance-probes")]
    static DIAGNOSTICS_FAULT_PROBE_CONTAINED: AtomicBool = AtomicBool::new(false);

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

    struct ApplicationTcpConnectService {
        network: SharedNetwork,
        runtime: SharedRuntime,
        attempted: bool,
        connection: Option<SharedTcpConnection>,
    }

    struct PendingFileReplacement {
        token: u32,
        path: String,
        start_offset: u64,
        offset: u64,
        bytes: Vec<u8>,
        chunk_bytes: usize,
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
        firmware_wall_seconds: Option<u64>,
        boot_mount_manifest: Option<BootMountManifest>,
        entropy_seed: [u8; RANDOM_SEED_BYTES],
    }

    struct IsolatedAllocation {
        complete: PhysicalRange,
        tables: PhysicalRange,
        code: PhysicalRange,
        data: PhysicalRange,
        stack: PhysicalRange,
    }

    struct ApplicationAllocation {
        extents: PhysicalExtents,
        tables: PhysicalRange,
        image_pages: u64,
        startup: PhysicalRange,
        heap_pages: u64,
        growth_ranges: Vec<PhysicalRange>,
        growth_table_frames: Vec<u64>,
        private_memory: ApplicationPrivateMemory,
    }

    /// Largest number of physical extents one launch reservation may use.
    ///
    /// Every extent contributes at least one bounded mapping-plan record, and
    /// one plan holds at most `troe_memory::MAX_MAPPINGS` records across kernel
    /// and application mappings together. Refusing a more fragmented
    /// reservation up front keeps the allocation loop bounded and turns "too
    /// fragmented to describe" into the same fail-closed refusal as "not enough
    /// frames", rather than a failure discovered while building the plan.
    const MAX_APPLICATION_EXTENTS: usize = 256;

    /// Pages the startup page occupies between the image and the heap.
    const APPLICATION_STARTUP_PAGES: u64 = 1;

    /// Whether a launch reservation coalesces physically adjacent quanta.
    ///
    /// Production always coalesces, so an unfragmented machine reserves exactly
    /// one extent and builds exactly the mapping records the former contiguous
    /// reservation built. The acceptance image deliberately does not, so every
    /// command launch exercises the multi-extent mapping, payload-copy, and
    /// straddling-relocation paths that real fragmentation would otherwise
    /// reach only rarely and nondeterministically.
    const COALESCE_LAUNCH_EXTENTS: bool = !cfg!(feature = "acceptance-probes");

    /// Pages reserved per launch step in the acceptance image.
    ///
    /// Production reserves the configured operation quantum and coalesces, so an
    /// unfragmented machine takes exactly one extent. The acceptance image takes
    /// tiny non-coalescing steps instead, so every command launch is backed by
    /// several extents and exercises the split mapping, payload-copy,
    /// straddling-relocation, and buffer-validation paths on every run rather
    /// than only when memory happens to be fragmented.
    const ACCEPTANCE_LAUNCH_QUANTUM_PAGES: u64 = 4;

    struct ApplicationPrivateMemory {
        mappings: Vec<ApplicationPrivateMapping>,
        arena_end: u64,
        maximum_committed_pages: Option<u64>,
        maximum_reserved_pages: Option<u64>,
        maximum_mappings: u64,
        maximum_metadata_bytes: u64,
        operation_quantum_pages: u64,
        reserved_pages: u64,
        committed_pages: u64,
        metadata_bytes: u64,
        high_water_reserved_pages: u64,
        high_water_committed_pages: u64,
        high_water_mappings: u64,
        high_water_metadata_bytes: u64,
    }

    struct ApplicationPrivateMapping {
        range: VirtualRange,
        protection: private_memory::Protection,
        backing: Vec<PhysicalRange>,
    }

    impl ApplicationPrivateMemory {
        fn new(policy: MemoryPolicy, arena_end: u64) -> Self {
            Self {
                mappings: Vec::new(),
                arena_end,
                maximum_committed_pages: policy.default_committed_pages().maximum(),
                maximum_reserved_pages: policy.default_reserved_pages().maximum(),
                maximum_mappings: policy.default_maximum_mappings(),
                maximum_metadata_bytes: policy.default_maximum_metadata_bytes(),
                operation_quantum_pages: policy.operation_quantum_pages(),
                reserved_pages: 0,
                committed_pages: 0,
                metadata_bytes: 0,
                high_water_reserved_pages: 0,
                high_water_committed_pages: 0,
                high_water_mappings: 0,
                high_water_metadata_bytes: 0,
            }
        }

        fn statistics(&self) -> private_memory::Statistics {
            private_memory::Statistics {
                flags: (u64::from(self.maximum_committed_pages.is_some())
                    * private_memory::COMMITTED_LIMITED)
                    | (u64::from(self.maximum_reserved_pages.is_some())
                        * private_memory::RESERVED_LIMITED),
                maximum_committed_pages: self.maximum_committed_pages.unwrap_or(0),
                maximum_reserved_pages: self.maximum_reserved_pages.unwrap_or(0),
                maximum_mappings: self.maximum_mappings,
                maximum_metadata_bytes: self.maximum_metadata_bytes,
                operation_quantum_pages: self.operation_quantum_pages,
                reserved_pages: self.reserved_pages,
                committed_pages: self.committed_pages,
                mappings: u64::try_from(self.mappings.len()).unwrap_or(u64::MAX),
                metadata_bytes: self.metadata_bytes,
                high_water_reserved_pages: self.high_water_reserved_pages,
                high_water_committed_pages: self.high_water_committed_pages,
                high_water_mappings: self.high_water_mappings,
                high_water_metadata_bytes: self.high_water_metadata_bytes,
            }
        }
    }

    struct ApplicationPrivateAllocation {
        extents: PhysicalExtents,
        image_pages: u64,
        startup: PhysicalRange,
        heap_pages: u64,
        stack_pages: u64,
    }

    enum ApplicationGrowth {
        Committed {
            stats: troe_machine::MmuStats,
            mapped_bytes: u64,
        },
        Exhausted,
    }

    enum PrivateMemoryError {
        Reply(ReplyStatus),
        Terminal,
    }

    struct PrivateMemoryReply {
        status: ReplyStatus,
        payload: Vec<u8>,
        resources_changed: bool,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum ApplicationProbe {
        Calls,
        #[cfg(feature = "acceptance-probes")]
        Spin,
        #[cfg(feature = "acceptance-probes")]
        HeapGrowthLimit,
        #[cfg(all(feature = "acceptance-probes", target_arch = "aarch64"))]
        ThreadPointer,
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
                Self::HeapGrowthLimit => None,
                #[cfg(all(feature = "acceptance-probes", target_arch = "aarch64"))]
                Self::ThreadPointer => None,
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
        let boot_mount_manifest = load_boot_mount_manifest()?;
        troe_machine::initialize_console();
        if !troe_machine::initialize_monotonic_clock() {
            return Err(());
        }
        let firmware_wall_seconds = firmware_unix_seconds();
        let entropy_seed = capture_entropy_seed()?;
        Ok(PreparedHandoff {
            image_layout,
            boot_memory,
            framebuffer,
            firmware_wall_seconds,
            boot_mount_manifest: Some(boot_mount_manifest),
            entropy_seed,
        })
    }

    fn capture_entropy_seed() -> Result<[u8; RANDOM_SEED_BYTES], ()> {
        let handle = boot::get_handle_for_protocol::<Rng>().map_err(|_| ())?;
        let mut rng = boot::open_protocol_exclusive::<Rng>(handle).map_err(|_| ())?;
        let mut seed = [0_u8; RANDOM_SEED_BYTES];
        if rng
            .get_rng(Some(RngAlgorithmType::ALGORITHM_RAW), &mut seed)
            .is_err()
        {
            rng.get_rng(None, &mut seed).map_err(|_| ())?;
        }
        if seed.iter().all(|byte| *byte == 0) {
            return Err(());
        }
        Ok(seed)
    }

    fn load_boot_mount_manifest() -> Result<BootMountManifest, ()> {
        let protocol = boot::get_image_file_system(boot::image_handle()).map_err(|_| ())?;
        let mut filesystem = uefi::fs::FileSystem::new(protocol);
        let path = cstr16!("\\EFI\\BOOT\\VOLUMES.BMT");
        let file_bytes = usize::try_from(filesystem.metadata(path).map_err(|_| ())?.file_size())
            .map_err(|_| ())?;
        if file_bytes > MAX_MANIFEST_BYTES {
            return Err(());
        }
        let bytes = filesystem.read(path).map_err(|_| ())?;
        if bytes.len() != file_bytes {
            return Err(());
        }
        parse_manifest(&bytes).map_err(|_| ())
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
        let null_page = PhysicalRange::from_pages(0, 1).map_err(|_| ())?;
        frames.reserve_range(null_page).map_err(|_| ())?;
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
        let memory_policy = native
            .config
            .as_ref()
            .map_or_else(MemoryPolicy::standard, SystemConfig::memory);
        let entropy_seed =
            core::mem::replace(&mut prepared.entropy_seed, [0_u8; RANDOM_SEED_BYTES]);
        let random = Rc::new(RefCell::new(
            RandomGenerator::new(entropy_seed).map_err(|_| ())?,
        ));
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
            selected_config: native.config,
            memory_policy,
            application_committed_pages: 0,
            private_metadata_bytes: 0,
            random,
            firmware_wall_seconds: prepared.firmware_wall_seconds,
            boot_mount_manifest,
            runtime_mounts: Rc::new(RefCell::new(RuntimeMountRegistry::empty())),
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
            generation: generation.state,
            config: generation.config,
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
    ) -> Result<RecoveredNativeGeneration, ()> {
        recover_native_generation_inner(devices, boot_mount_manifest)
    }

    #[cfg(not(feature = "acceptance-probes"))]
    fn recover_native_generation(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
        boot_mount_manifest: &BootMountManifest,
    ) -> RecoveredNativeGeneration {
        recover_native_generation_inner(devices, boot_mount_manifest).unwrap_or(
            RecoveredNativeGeneration {
                state: NativeGenerationState::Recovery,
                config: None,
            },
        )
    }

    fn recover_native_generation_inner(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
        boot_mount_manifest: &BootMountManifest,
    ) -> Result<RecoveredNativeGeneration, ()> {
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
        #[allow(unused_mut)]
        let (mut pointer, validated, state) = match recover_activation(candidate, |pointer| {
            validate_root_activation(&content, pointer, IdentityLimits::standard())
        }) {
            ActivationRecovery::Active { pointer, validated } => {
                (pointer, validated, NativeGenerationState::Active)
            }
            ActivationRecovery::Previous { pointer, validated } => {
                (pointer, validated, NativeGenerationState::Predecessor)
            }
            ActivationRecovery::Unavailable => {
                return Ok(RecoveredNativeGeneration {
                    state: NativeGenerationState::Recovery,
                    config: None,
                });
            }
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
                pointer = previous_pointer;
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
        let config_object = content.get(pointer.active().digest()).ok_or(())?;
        if config_object.kind != ObjectKind::SystemConfig {
            return Err(());
        }
        let selected_config = parse_config(config_object.bytes).map_err(|_| ())?;
        Ok(RecoveredNativeGeneration {
            state,
            config: Some(selected_config),
        })
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
    ) -> Result<Option<Box<dyn FileSystemProvider>>, ()> {
        let statefs = mount_native_statefs(devices)?;
        let mut statefs = statefs;
        probe_native_statefs_mutation(&mut statefs)?;
        Ok(Some(Box::new(statefs)))
    }

    #[cfg(not(feature = "acceptance-probes"))]
    fn recover_native_statefs(
        devices: &mut Vec<troe_machine::NativeVirtioBlock>,
    ) -> Option<Box<dyn FileSystemProvider>> {
        mount_native_statefs(devices)
            .ok()
            .map(|statefs| Box::new(statefs) as Box<dyn FileSystemProvider>)
    }

    #[cfg(feature = "acceptance-probes")]
    fn probe_native_statefs_mutation(
        statefs: &mut StateFs<troe_machine::NativeVirtioBlock>,
    ) -> Result<(), ()> {
        let mut prior = [0_u8; 8];
        let next = match statefs.read_file(STATE_PATH, 0, &mut prior) {
            Ok(8) => u64::from_le_bytes(prior).checked_add(1).ok_or(())?,
            Err(troe_fs_api::FsError::NotFound) => 1,
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
        let ext4 = Ext4Limits::new(8, 64, 256, 4096, u64::from(u32::MAX) * 4096, 4096, 64)
            .map_err(|_| ())?;
        let fat32 =
            Fat32Limits::new(u32::MAX, 4096, u64::from(u32::MAX), 4096, 64).map_err(|_| ())?;
        Ok(ActivationLimits::new(block, gpt, ext4, fat32))
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

    fn allocate_task_stack(
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
        let mut scheduler = Scheduler::new(troe_task::MAX_TASKS)
            .unwrap_or_else(|_| fatal(b"fatal: cannot create task scheduler\n"));
        run_cooperative_services(&mut scheduler, &accounting)
            .unwrap_or_else(|()| fatal(b"fatal: cooperative task verification failed\n"));
        run_isolation_verification(&mut scheduler, &mut accounting)
            .unwrap_or_else(|()| fatal(b"fatal: Stage 6 isolation verification failed\n"));
        run_application_load_verification(&mut scheduler, &mut accounting)
            .unwrap_or_else(|()| fatal(b"fatal: Stage 7 load-boundary verification failed\n"));
        #[cfg(feature = "acceptance-probes")]
        run_ipc_baseline_verification(&mut scheduler, &mut accounting)
            .unwrap_or_else(|()| fatal(b"fatal: IPC baseline verification failed\n"));
        if !write_machine_boot_status(BOOT_RUNTIME_LABEL, true) {
            fatal(b"fatal: application loader diagnostic failed\n");
        }

        let capabilities = Capabilities::CONSOLE
            .union(Capabilities::FILESYSTEM)
            .union(Capabilities::MACHINE_CONTROL);
        let stack_resource = StackResource::new(SHELL_SCHEDULER_SLOT, SHELL_TASK_STACK_PAGES)
            .unwrap_or_else(|_| fatal(b"fatal: invalid shell task stack\n"));
        let shell_id = scheduler
            .spawn(capabilities, stack_resource)
            .unwrap_or_else(|_| fatal(b"fatal: cannot spawn shell task\n"));
        let dispatched = scheduler
            .dispatch_next(capabilities)
            .unwrap_or_else(|_| fatal(b"fatal: shell task dispatch failed\n"));
        if dispatched != Some(shell_id)
            || scheduler.stats().owned_stack_pages != SHELL_TASK_STACK_PAGES
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
        for (slot, layout) in accounting.task_stacks.iter().copied().enumerate() {
            let expected_pages = match slot {
                0 => TASK_STACK_PAGES,
                1 => SERVER_TASK_STACK_PAGES,
                2 => SHELL_TASK_STACK_PAGES,
                _ => return Err(()),
            };
            if layout.lower_guard.end() != layout.stack.start()
                || layout.stack.end() != layout.upper_guard.start()
                || layout.lower_guard.page_count() != 1
                || layout.stack.page_count() != expected_pages
                || layout.upper_guard.page_count() != 1
            {
                return Err(());
            }
        }

        let first_resource = StackResource::new(0, TASK_STACK_PAGES).map_err(|_| ())?;
        let second_resource = StackResource::new(1, SERVER_TASK_STACK_PAGES).map_err(|_| ())?;
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
        let slot = usize::try_from(reusable.slot()).map_err(|_| ())?;
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

    #[cfg(feature = "acceptance-probes")]
    fn run_ipc_baseline_verification(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        let frequency = troe_machine::benchmark_counter_frequency_hz().ok_or(())?;
        let payload = [0x5a_u8; troe_dispatch::MAX_MESSAGE_BYTES];
        for payload_bytes in [0_usize, 64, 256, 4 * 1024] {
            let mut dispatcher = Dispatcher::new(1, 1).map_err(|_| ())?;
            let (_port, handle) = dispatcher
                .register(Box::new(EchoService), Rights::CALL)
                .map_err(|_| ())?;
            let request = &payload[..payload_bytes];
            for _ in 0..IPC_BASELINE_WARMUP_CALLS {
                let reply = dispatcher.call(handle, 1, request).map_err(|_| ())?;
                if reply.status() != ReplyStatus::Success || reply.payload() != request {
                    return Err(());
                }
                core::hint::black_box(reply);
            }
            let baseline = dispatcher.stats();
            let mut samples = [0_u64; IPC_BASELINE_SAMPLES];
            for sample in &mut samples {
                let started = troe_machine::benchmark_counter_ticks();
                let reply = dispatcher
                    .call(handle, 1, core::hint::black_box(request))
                    .map_err(|_| ())?;
                let finished = troe_machine::benchmark_counter_ticks();
                if reply.status() != ReplyStatus::Success || reply.payload() != request {
                    return Err(());
                }
                core::hint::black_box(reply);
                *sample = finished.checked_sub(started).ok_or(())?;
            }
            samples.sort_unstable();
            let stats = dispatcher.stats();
            let completed_calls = stats.replies.checked_sub(baseline.replies).ok_or(())?;
            let request_bytes = stats
                .request_bytes
                .checked_sub(baseline.request_bytes)
                .ok_or(())?;
            let reply_bytes = stats
                .reply_bytes
                .checked_sub(baseline.reply_bytes)
                .ok_or(())?;
            let reply_copies = stats
                .reply_payload_copies
                .checked_sub(baseline.reply_payload_copies)
                .ok_or(())?;
            let expected_calls = u64::try_from(IPC_BASELINE_SAMPLES).map_err(|_| ())?;
            let expected_bytes = expected_calls
                .checked_mul(u64::try_from(payload_bytes).map_err(|_| ())?)
                .ok_or(())?;
            let expected_copies = if payload_bytes == 0 {
                0
            } else {
                expected_calls
            };
            if stats.calls.checked_sub(baseline.calls) != Some(expected_calls)
                || completed_calls != expected_calls
                || request_bytes != expected_bytes
                || reply_bytes != expected_bytes
                || reply_copies != expected_copies
                || stats
                    .reply_payload_allocations
                    .checked_sub(baseline.reply_payload_allocations)
                    != Some(expected_copies)
                || stats.request_payload_copies != 0
                || stats.request_payload_allocations != 0
            {
                return Err(());
            }
            let mut line = String::new();
            writeln!(
                line,
                "ipc-baseline path=in-process payload={payload_bytes} warmup={} samples={} counter_hz={frequency} p50_ticks={} p95_ticks={} p99_ticks={} max_ticks={} calls={completed_calls} request_bytes={request_bytes} request_copies=0 request_allocations=0 reply_bytes={reply_bytes} reply_copies={reply_copies} reply_allocations={reply_copies} address_space_switches=0 tlb_invalidations=0 timer_programs=0",
                IPC_BASELINE_WARMUP_CALLS,
                IPC_BASELINE_SAMPLES,
                ipc_percentile(&samples, 50),
                ipc_percentile(&samples, 95),
                ipc_percentile(&samples, 99),
                samples[IPC_BASELINE_SAMPLES - 1],
            )
            .map_err(|_| ())?;
            if !troe_machine::write(line.as_bytes()) {
                return Err(());
            }
        }
        run_isolated_ipc_baseline_verification(scheduler, accounting, frequency)
    }

    #[cfg(feature = "acceptance-probes")]
    #[allow(
        clippy::drop_non_drop,
        clippy::too_many_arguments,
        clippy::too_many_lines
    )]
    fn run_isolated_ipc_baseline_verification(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        frequency: u64,
    ) -> Result<(), ()> {
        for payload_bytes in [0_usize, 64, 256, 4 * 1024] {
            let baseline_frames = accounting.frames.free_frames();
            let exchange = Rc::new(RefCell::new(DiagnosticsBenchmarkExchange {
                payload: [0x5a; troe_abi::MAX_MESSAGE_BYTES],
                payload_bytes,
                logical_index: 0,
                fragment_index: 0,
                received: false,
                expected_token: 0,
                started_ticks: 0,
                started_execution: troe_machine::ApplicationExecutionStats::default(),
                started_allocations: 0,
                samples: [0; IPC_BASELINE_SAMPLES],
                measured: 0,
                address_space_switches: 0,
                tlb_invalidations: 0,
                timer_programs: 0,
                steady_allocation_calls: 0,
            }));
            let stack = accounting.task_stacks[1].stack;
            let mut runner = DiagnosticsBenchmarkRunner {
                accounting,
                scheduler,
                exchange: Rc::clone(&exchange),
                outcome: None,
            };
            let step =
                troe_machine::run_task_step(stack, &mut runner, run_diagnostics_benchmark_task)
                    .map_err(|_| ())?;
            let outcome = runner.outcome.take().ok_or(())?;
            if step != TaskStep::ExitSuccess
                || !matches!(
                    outcome,
                    Ok(CommandApplicationOutcome::Exited(troe_abi::exit::SUCCESS))
                )
            {
                return Err(());
            }
            drop(runner);
            if accounting.frames.free_frames() != baseline_frames {
                return Err(());
            }
            let mut exchange = exchange.borrow_mut();
            let fragments = DiagnosticsBenchmarkEndpoint::fragments(payload_bytes);
            let measured_fragments = IPC_BASELINE_SAMPLES.checked_mul(fragments).ok_or(())?;
            let measured_boundaries = IPC_BASELINE_SAMPLES
                .checked_mul(
                    fragments
                        .checked_mul(2)
                        .ok_or(())?
                        .checked_sub(1)
                        .ok_or(())?,
                )
                .ok_or(())?;
            let expected_switches = u64::try_from(measured_boundaries)
                .map_err(|_| ())?
                .checked_mul(2)
                .ok_or(())?;
            let expected_bytes = u64::try_from(IPC_BASELINE_SAMPLES)
                .map_err(|_| ())?
                .checked_mul(u64::try_from(payload_bytes).map_err(|_| ())?)
                .ok_or(())?;
            let expected_payload_copies = if payload_bytes == 0 {
                0
            } else {
                u64::try_from(measured_fragments)
                    .map_err(|_| ())?
                    .checked_mul(2)
                    .ok_or(())?
            };
            if exchange.logical_index != IPC_BASELINE_WARMUP_CALLS + IPC_BASELINE_SAMPLES
                || exchange.fragment_index != 0
                || exchange.received
                || exchange.measured != IPC_BASELINE_SAMPLES
                || exchange.steady_allocation_calls != 0
                || exchange.address_space_switches != expected_switches
                || exchange.tlb_invalidations != expected_switches
                || exchange.timer_programs != u64::try_from(measured_boundaries).map_err(|_| ())?
            {
                return Err(());
            }
            exchange.samples.sort_unstable();
            let completed_calls = u64::try_from(IPC_BASELINE_SAMPLES).map_err(|_| ())?;
            let mut line = String::new();
            writeln!(
                line,
                "ipc-baseline path=isolated-diagnostics payload={payload_bytes} warmup={} samples={} counter_hz={frequency} p50_ticks={} p95_ticks={} p99_ticks={} max_ticks={} calls={completed_calls} request_bytes={expected_bytes} request_copies={expected_payload_copies} request_allocations=0 reply_bytes={expected_bytes} reply_copies={expected_payload_copies} reply_allocations=0 address_space_switches={} tlb_invalidations={} timer_programs={} wire_fragments={measured_fragments} retained_requests={} contexts={} steady_allocations=0",
                IPC_BASELINE_WARMUP_CALLS,
                IPC_BASELINE_SAMPLES,
                ipc_percentile(&exchange.samples, 50),
                ipc_percentile(&exchange.samples, 95),
                ipc_percentile(&exchange.samples, 99),
                exchange.samples[IPC_BASELINE_SAMPLES - 1],
                exchange.address_space_switches,
                exchange.tlb_invalidations,
                exchange.timer_programs,
                DIAGNOSTICS_SERVER_MAX_RETAINED_REQUESTS,
                DIAGNOSTICS_SERVER_MAX_CONTEXTS,
            )
            .map_err(|_| ())?;
            if !troe_machine::write(line.as_bytes()) {
                return Err(());
            }
        }
        Ok(())
    }

    #[cfg(feature = "acceptance-probes")]
    fn ipc_percentile(sorted: &[u64; IPC_BASELINE_SAMPLES], percentile: usize) -> u64 {
        let rank = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
        sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
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
                u32::try_from(index + 1).map_err(|_| ())?,
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
        address_space_slot: u32,
    ) -> Result<u64, ()> {
        let table_pages = ISOLATED_TABLE_PAGES;
        let private_pages = ISOLATED_PRIVATE_PAGES;
        let stack_pages = ISOLATED_STACK_PAGES;
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
            #[cfg(target_arch = "aarch64")]
            verify_application_thread_pointer(scheduler, accounting, &mut dispatcher, port, first)?;
            verify_application_heap_growth_limit(scheduler, accounting, &mut dispatcher, port)?;
            (reused, invalid_reused, return_reused)
        };

        #[cfg(not(all(feature = "acceptance-probes", target_arch = "aarch64")))]
        let expected_yields = baseline_tasks.yields.checked_add(1).ok_or(())?;
        #[cfg(all(feature = "acceptance-probes", target_arch = "aarch64"))]
        let expected_yields = baseline_tasks.yields.checked_add(2).ok_or(())?;
        if accounting.frames.free_frames() != baseline_frames
            || scheduler.stats().owned_address_spaces != baseline_tasks.owned_address_spaces
            || scheduler.stats().owned_isolation_pages != baseline_tasks.owned_isolation_pages
            || scheduler.stats().owned_handles != baseline_tasks.owned_handles
            || scheduler.stats().yields != expected_yields
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

    #[cfg(all(feature = "acceptance-probes", target_arch = "aarch64"))]
    fn verify_application_thread_pointer(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        dispatcher: &mut Dispatcher<'_>,
        port: troe_dispatch::PortId,
        expected_allocation: u64,
    ) -> Result<(), ()> {
        let source = native_kex_artifact(ApplicationProbe::ThreadPointer);
        let allocation = load_and_reclaim_application(
            scheduler,
            accounting,
            dispatcher,
            port,
            source,
            ApplicationProbe::ThreadPointer,
        )?;
        if allocation == expected_allocation {
            Ok(())
        } else {
            Err(())
        }
    }

    #[cfg(feature = "acceptance-probes")]
    fn verify_application_heap_growth_limit(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        dispatcher: &mut Dispatcher<'_>,
        port: troe_dispatch::PortId,
    ) -> Result<(), ()> {
        let services = [CommandStartupService {
            port,
            interface: APPLICATION_INTERFACE_ECHO,
            major: 1,
            minor: 0,
        }];
        let source = native_kex_artifact(ApplicationProbe::HeapGrowthLimit);
        match run_command_application(
            scheduler, accounting, dispatcher, &services, None, source, 0, None,
        )? {
            CommandApplicationOutcome::Exited(troe_abi::exit::SUCCESS) => Ok(()),
            CommandApplicationOutcome::Exited(_) | CommandApplicationOutcome::Faulted(_) => Err(()),
        }
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
        let Ok(plan) = parse_native_application(accounting, &staging) else {
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let private_pages = plan.charges().private_pages();
        let stack_pages = plan.stack_pages();

        let Ok((allocation, mapping_plan)) = allocate_application(accounting, &plan) else {
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Frames).is_err() {
            reclaim_application(accounting, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        if prepare_application_memory(&allocation, &plan).is_err() {
            reclaim_application(accounting, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let Ok(address_space) =
            troe_machine::build_user_address_space(&mapping_plan, allocation.tables)
        else {
            reclaim_application(accounting, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Tables).is_err() {
            reclaim_application(accounting, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let (planned_user_regions, planned_user_pages) =
            troe_machine::planned_user_regions(&mapping_plan).map_err(|_| ())?;
        let table_pages = address_space.stats().table_pages;
        if table_pages == 0
            || table_pages != allocation.tables.page_count()
            || address_space.user_region_count() != planned_user_regions
            || planned_user_pages != private_pages
        {
            reclaim_application(accounting, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let retained_table_pages = allocation.tables.page_count();
        let Ok(isolation) = IsolationResource::new(0, retained_table_pages, private_pages, 1)
        else {
            reclaim_application(accounting, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(stack_resource) = StackResource::new(0, stack_pages) else {
            reclaim_application(accounting, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        let Ok(task_id) =
            scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
        else {
            reclaim_application(accounting, allocation)?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        if transaction.acquire(LoaderResource::Task).is_err() {
            rollback_application_task(
                scheduler, task_id, dispatcher, None, accounting, allocation,
            )?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        }
        let entry = plan.entry_address();
        let layout = plan.layout();
        let allocation_start = allocation.extents.first_start().map_err(|_| ())?;
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
                scheduler, task_id, dispatcher, live_owner, accounting, allocation,
            )?;
            clear_provisional_loader_ownership(&mut transaction);
            return Err(());
        };
        drop(plan);
        drop(staging);
        drop(mapping_plan);
        if transaction.commit().is_err() {
            rollback_application_task(
                scheduler, task_id, dispatcher, live_owner, accounting, allocation,
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
                APPLICATION_TIMESLICE_MILLISECONDS,
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
                            APPLICATION_TIMESLICE_MILLISECONDS,
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
                            APPLICATION_TIMESLICE_MILLISECONDS,
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
                    #[cfg(all(feature = "acceptance-probes", target_arch = "aarch64"))]
                    (
                        ApplicationProbe::ThreadPointer,
                        troe_machine::ApplicationOutcome::Yielded(application),
                    ) if !observed_yield => {
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
                            APPLICATION_TIMESLICE_MILLISECONDS,
                        )
                        .map_err(|_| ())?;
                    }
                    #[cfg(all(feature = "acceptance-probes", target_arch = "aarch64"))]
                    (
                        ApplicationProbe::ThreadPointer,
                        troe_machine::ApplicationOutcome::Exited { status: 0 },
                    ) if observed_yield => {
                        scheduler.exit_current(task_id, 0).map_err(|_| ())?;
                        break;
                    }
                    #[cfg(feature = "acceptance-probes")]
                    (ApplicationProbe::Spin, troe_machine::ApplicationOutcome::Preempted(_)) => {
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
                scheduler, task_id, dispatcher, live_owner, accounting, allocation,
            )?;
            return Err(());
        }
        let Ok(reaped) = scheduler.reap(task_id) else {
            rollback_application_task(
                scheduler, task_id, dispatcher, live_owner, accounting, allocation,
            )?;
            return Err(());
        };
        let valid_reap = reaped.isolation == Some(isolation)
            && reaped.stack.mapped_pages() == stack_pages
            && reaped.fault == probe.expected_fault();
        reclaim_application(accounting, allocation)?;
        if !valid_reap {
            return Err(());
        }
        Ok(allocation_start)
    }

    impl SuspendedApplicationCalls {
        fn new() -> Result<Self, ()> {
            let mut slots = Vec::new();
            slots.try_reserve_exact(1).map_err(|_| ())?;
            Ok(Self {
                slots,
                high_water: 0,
            })
        }

        fn insert(&mut self, call: SuspendedApplicationCall) -> Result<(), ()> {
            if !self.slots.is_empty() {
                return Err(());
            }
            self.slots.push(call);
            self.high_water = 1;
            Ok(())
        }

        fn get(&self, operation: PendingOperationId) -> Result<&SuspendedApplicationCall, ()> {
            self.slots
                .first()
                .filter(|call| call.operation == operation)
                .ok_or(())
        }

        fn take(&mut self, operation: PendingOperationId) -> Result<SuspendedApplicationCall, ()> {
            if self
                .slots
                .first()
                .is_none_or(|call| call.operation != operation)
            {
                return Err(());
            }
            Ok(self.slots.remove(0))
        }

        fn clear(&mut self) {
            self.slots.clear();
        }
    }

    impl CommandDeferredState {
        #[inline(never)]
        fn new() -> Result<Self, ()> {
            Ok(Self {
                pending: PendingCallTable::new(1, troe_task::MAX_PENDING_REQUEST_BYTES)
                    .map_err(|_| ())?,
                waits: WaitTable::new(1).map_err(|_| ())?,
                suspended: SuspendedApplicationCalls::new()?,
                next_request_id: 1,
            })
        }

        fn is_empty(&self) -> bool {
            self.pending.stats().live == 0
                && self.pending.stats().retained_bytes == 0
                && self.waits.stats().live == 0
                && self.suspended.slots.is_empty()
        }

        fn respected_bounds(&self) -> bool {
            self.pending.stats().high_water <= 1
                && self.waits.stats().high_water <= 1
                && self.suspended.high_water <= 1
        }

        fn revoke_owner(&mut self, owner: TaskId) -> Result<(), ()> {
            self.waits
                .cancel_owner(owner, WakeReason::Revoked)
                .map_err(|_| ())?;
            self.pending
                .teardown_owner(owner, WakeReason::Revoked)
                .map_err(|_| ())?;
            self.suspended.clear();
            Ok(())
        }
    }

    fn command_handle_interface(handles: &[CommandApplicationHandle], value: u64) -> Option<u32> {
        handles
            .iter()
            .find(|handle| handle.value == value)
            .map(|handle| handle.interface)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_resource_wait(
        task_id: TaskId,
        handle: u64,
        opcode: u16,
        payload: &[u8],
        reply_capacity: usize,
        resource: WaitResource,
        kind: DeferredCallKind,
        pending: &mut PendingCallTable,
        next_request_id: &mut u64,
    ) -> Result<DeferredCallPreparation, ()> {
        let operation = pending
            .begin(
                task_id,
                *next_request_id,
                handle,
                opcode,
                payload,
                reply_capacity,
            )
            .map_err(|_| ())?;
        *next_request_id = (*next_request_id).checked_add(1).ok_or(())?;
        let spec = WaitSpec::new(
            task_id,
            operation,
            Some(resource),
            WakeInterest::RESOURCE_READY,
            None,
        )
        .map_err(|_| ())?;
        Ok(DeferredCallPreparation::Blocked {
            operation,
            spec,
            kind,
        })
    }

    fn owned_reply_payload(bytes: &[u8]) -> Result<Vec<u8>, ()> {
        let mut payload = Vec::new();
        payload.try_reserve_exact(bytes.len()).map_err(|_| ())?;
        payload.extend_from_slice(bytes);
        Ok(payload)
    }

    #[inline(never)]
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn prepare_deferred_call(
        task_id: TaskId,
        interface: u32,
        handle: u64,
        opcode: u16,
        payload: &[u8],
        reply_capacity: usize,
        services: &CommandDeferredServices,
        pending: &mut PendingCallTable,
        next_request_id: &mut u64,
    ) -> Result<DeferredCallPreparation, ()> {
        if interface == troe_abi::interface::PROCESS_LAUNCH && opcode == process_launch::WAIT {
            let Some(owner) = services.process_owner else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Conflict,
                    payload: Vec::new(),
                });
            };
            let Some(children) = &services.children else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::NotFound,
                    payload: Vec::new(),
                });
            };
            let Ok(token) = process_launch::decode_token(payload) else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::InvalidRequest,
                    payload: Vec::new(),
                });
            };
            let status = match children.try_borrow() {
                Ok(children) => children.status(owner, token),
                Err(_) => {
                    return Ok(DeferredCallPreparation::Immediate {
                        status: ReplyStatus::Conflict,
                        payload: Vec::new(),
                    });
                }
            };
            let status = match status {
                Ok(status) => status,
                Err(error) => {
                    return Ok(DeferredCallPreparation::Immediate {
                        status: child_process_status(error),
                        payload: Vec::new(),
                    });
                }
            };
            if status.state != process_launch::ChildState::Running {
                let encoded = process_launch::encode_status(status).map_err(|_| ())?;
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Success,
                    payload: owned_reply_payload(&encoded)?,
                });
            }
            let resource = WaitResource::new(token.value(), owner.get()).map_err(|_| ())?;
            return prepare_resource_wait(
                task_id,
                handle,
                opcode,
                payload,
                reply_capacity,
                resource,
                DeferredCallKind::Child {
                    children: children.clone(),
                    owner,
                    token,
                    resource,
                },
                pending,
                next_request_id,
            );
        }

        if interface == troe_abi::interface::PIPE && matches!(opcode, pipe::READ | pipe::WRITE) {
            let Some(owner) = services.process_owner else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Conflict,
                    payload: Vec::new(),
                });
            };
            let Some(pipes) = &services.pipes else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::NotFound,
                    payload: Vec::new(),
                });
            };
            if opcode == pipe::READ {
                let Ok((token, maximum)) = pipe::decode_read(payload) else {
                    return Ok(DeferredCallPreparation::Immediate {
                        status: ReplyStatus::InvalidRequest,
                        payload: Vec::new(),
                    });
                };
                let mut bytes = [0_u8; pipe::MAX_IO_BYTES];
                let result = pipes.try_borrow_mut().map_err(|_| ())?.read_owner(
                    owner,
                    token,
                    &mut bytes[..maximum],
                );
                return match result {
                    Ok(count) => Ok(DeferredCallPreparation::Immediate {
                        status: ReplyStatus::Success,
                        payload: owned_reply_payload(&bytes[..count])?,
                    }),
                    Err(ChildProcessError::WouldBlock) => {
                        let resource =
                            WaitResource::new(token.value(), owner.get()).map_err(|_| ())?;
                        prepare_resource_wait(
                            task_id,
                            handle,
                            opcode,
                            payload,
                            reply_capacity,
                            resource,
                            DeferredCallKind::PipeRead {
                                pipes: pipes.clone(),
                                target: DeferredPipeTarget::Owner { owner, token },
                                maximum,
                                resource,
                            },
                            pending,
                            next_request_id,
                        )
                    }
                    Err(error) => Ok(DeferredCallPreparation::Immediate {
                        status: child_process_status(error),
                        payload: Vec::new(),
                    }),
                };
            }
            let Ok((token, bytes)) = pipe::decode_write(payload) else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::InvalidRequest,
                    payload: Vec::new(),
                });
            };
            let result = pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .write_owner(owner, token, bytes);
            return match result {
                Ok(count) if count == bytes.len() => Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Success,
                    payload: Vec::new(),
                }),
                Ok(_) => Err(()),
                Err(ChildProcessError::WouldBlock) => {
                    let resource = WaitResource::new(token.value(), owner.get()).map_err(|_| ())?;
                    prepare_resource_wait(
                        task_id,
                        handle,
                        opcode,
                        payload,
                        reply_capacity,
                        resource,
                        DeferredCallKind::PipeWrite {
                            pipes: pipes.clone(),
                            target: DeferredPipeTarget::Owner { owner, token },
                            byte_count: bytes.len(),
                            resource,
                        },
                        pending,
                        next_request_id,
                    )
                }
                Err(error) => Ok(DeferredCallPreparation::Immediate {
                    status: child_process_status(error),
                    payload: Vec::new(),
                }),
            };
        }

        if interface == troe_abi::interface::STANDARD_INPUT
            && opcode == stream::READ
            && let Some(terminal) = &services.terminal
        {
            let Ok(maximum) = stream::decode_read_request(payload) else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::InvalidRequest,
                    payload: Vec::new(),
                });
            };
            let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
            let ready = {
                let mut borrowed = terminal.try_borrow_mut().map_err(|_| ())?;
                borrowed.pump();
                borrowed
                    .read_ready()
                    .then(|| borrowed.take(&mut bytes[..maximum]))
            };
            if let Some(count) = ready {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Success,
                    payload: owned_reply_payload(&bytes[..count])?,
                });
            }
            let resource =
                WaitResource::new(SESSION_TERMINAL_WAIT_IDENTITY, task_id.get()).map_err(|_| ())?;
            return prepare_resource_wait(
                task_id,
                handle,
                opcode,
                payload,
                reply_capacity,
                resource,
                DeferredCallKind::TerminalRead {
                    terminal: Rc::clone(terminal),
                    maximum,
                    resource,
                },
                pending,
                next_request_id,
            );
        }

        if matches!(
            interface,
            troe_abi::interface::STANDARD_INPUT
                | troe_abi::interface::STANDARD_OUTPUT
                | troe_abi::interface::STANDARD_ERROR
        ) && let Some(binding) = services
            .pipe_streams
            .iter()
            .find(|binding| binding.interface == interface)
        {
            let resource = WaitResource::new(binding.endpoint.token().value(), task_id.get())
                .map_err(|_| ())?;
            if interface == troe_abi::interface::STANDARD_INPUT && opcode == stream::READ {
                let Ok(maximum) = stream::decode_read_request(payload) else {
                    return Ok(DeferredCallPreparation::Immediate {
                        status: ReplyStatus::InvalidRequest,
                        payload: Vec::new(),
                    });
                };
                let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
                let result = binding
                    .pipes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .read_endpoint(binding.endpoint, &mut bytes[..maximum]);
                return match result {
                    Ok(count) => Ok(DeferredCallPreparation::Immediate {
                        status: ReplyStatus::Success,
                        payload: owned_reply_payload(&bytes[..count])?,
                    }),
                    Err(ChildProcessError::WouldBlock) => prepare_resource_wait(
                        task_id,
                        handle,
                        opcode,
                        payload,
                        reply_capacity,
                        resource,
                        DeferredCallKind::PipeRead {
                            pipes: binding.pipes.clone(),
                            target: DeferredPipeTarget::Endpoint(binding.endpoint),
                            maximum,
                            resource,
                        },
                        pending,
                        next_request_id,
                    ),
                    Err(error) => Ok(DeferredCallPreparation::Immediate {
                        status: child_process_status(error),
                        payload: Vec::new(),
                    }),
                };
            }
            if matches!(
                interface,
                troe_abi::interface::STANDARD_OUTPUT | troe_abi::interface::STANDARD_ERROR
            ) && opcode == stream::WRITE
                && !payload.is_empty()
            {
                let result = binding
                    .pipes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .write_endpoint(binding.endpoint, payload);
                return match result {
                    Ok(count) if count == payload.len() => Ok(DeferredCallPreparation::Immediate {
                        status: ReplyStatus::Success,
                        payload: Vec::new(),
                    }),
                    Ok(_) => Err(()),
                    Err(ChildProcessError::WouldBlock) => prepare_resource_wait(
                        task_id,
                        handle,
                        opcode,
                        payload,
                        reply_capacity,
                        resource,
                        DeferredCallKind::PipeWrite {
                            pipes: binding.pipes.clone(),
                            target: DeferredPipeTarget::Endpoint(binding.endpoint),
                            byte_count: payload.len(),
                            resource,
                        },
                        pending,
                        next_request_id,
                    ),
                    Err(error) => Ok(DeferredCallPreparation::Immediate {
                        status: child_process_status(error),
                        payload: Vec::new(),
                    }),
                };
            }
        }

        if interface == troe_abi::interface::TIMER && opcode == timer::SLEEP_UNTIL {
            let Ok(deadline) = timer::decode_milliseconds(payload) else {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::InvalidRequest,
                    payload: Vec::new(),
                });
            };
            let deadline = MonotonicMillis::from_millis(deadline);
            let now = services.runtime.borrow().now();
            if deadline <= now {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Success,
                    payload: Vec::new(),
                });
            }
            let operation = pending
                .begin(
                    task_id,
                    *next_request_id,
                    handle,
                    opcode,
                    payload,
                    reply_capacity,
                )
                .map_err(|_| ())?;
            *next_request_id = (*next_request_id).checked_add(1).ok_or(())?;
            let spec = WaitSpec::new(
                task_id,
                operation,
                None,
                WakeInterest::DEADLINE,
                Some(deadline),
            )
            .map_err(|_| ())?;
            return Ok(DeferredCallPreparation::Blocked {
                operation,
                spec,
                kind: DeferredCallKind::Timer { deadline },
            });
        }
        if interface == troe_abi::interface::DIAGNOSTICS {
            if opcode != diagnostics::GET_SNAPSHOT || !payload.is_empty() {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::InvalidRequest,
                    payload: Vec::new(),
                });
            }
            if services.diagnostics.is_none() {
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::NotFound,
                    payload: Vec::new(),
                });
            }
            let operation = pending
                .begin(
                    task_id,
                    *next_request_id,
                    handle,
                    opcode,
                    payload,
                    reply_capacity,
                )
                .map_err(|_| ())?;
            *next_request_id = (*next_request_id).checked_add(1).ok_or(())?;
            let resource =
                WaitResource::new(operation.abi_value(), task_id.get()).map_err(|_| ())?;
            let spec = WaitSpec::new(
                task_id,
                operation,
                Some(resource),
                WakeInterest::RESOURCE_READY,
                None,
            )
            .map_err(|_| ())?;
            return Ok(DeferredCallPreparation::Blocked {
                operation,
                spec,
                kind: DeferredCallKind::Diagnostics { resource },
            });
        }
        if interface != troe_abi::interface::DATAGRAM || opcode != datagram::RECEIVE {
            return Ok(DeferredCallPreparation::NotDeferred);
        }
        let Ok(local_port) = datagram::decode_receive_request(payload) else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::InvalidRequest,
                payload: Vec::new(),
            });
        };
        let Some(state) = &services.datagram else {
            return Ok(DeferredCallPreparation::Immediate {
                status: ReplyStatus::NotFound,
                payload: Vec::new(),
            });
        };
        let local_port = match state.borrow_mut().claim_port(Some(local_port)) {
            Ok(port) => port,
            Err(status) => {
                return Ok(DeferredCallPreparation::Immediate {
                    status,
                    payload: Vec::new(),
                });
            }
        };
        match state.borrow_mut().receive_now(local_port) {
            Ok(Some(received)) => {
                let payload = encode_received_datagram(&received)?;
                return Ok(DeferredCallPreparation::Immediate {
                    status: ReplyStatus::Success,
                    payload,
                });
            }
            Err(status) => {
                return Ok(DeferredCallPreparation::Immediate {
                    status,
                    payload: Vec::new(),
                });
            }
            Ok(None) => {}
        }
        let now = services.runtime.borrow().now();
        let deadline = now.saturating_add(APPLICATION_DATAGRAM_WAIT_MILLISECONDS);
        let operation = pending
            .begin(
                task_id,
                *next_request_id,
                handle,
                opcode,
                payload,
                reply_capacity,
            )
            .map_err(|_| ())?;
        *next_request_id = (*next_request_id).checked_add(1).ok_or(())?;
        let resource = WaitResource::new(u64::from(local_port), task_id.get()).map_err(|_| ())?;
        let spec = WaitSpec::new(
            task_id,
            operation,
            Some(resource),
            WakeInterest::RESOURCE_READY.union(WakeInterest::DEADLINE),
            Some(deadline),
        )
        .map_err(|_| ())?;
        Ok(DeferredCallPreparation::Blocked {
            operation,
            spec,
            kind: DeferredCallKind::Datagram {
                state: state.clone(),
                local_port,
                deadline,
                resource,
            },
        })
    }

    fn encode_received_datagram(received: &ReceivedUdp) -> Result<Vec<u8>, ()> {
        let mut encoded = [0_u8; datagram::MAX_RECEIVE_REPLY_BYTES];
        let count = datagram::encode_receive_reply(
            received.source,
            received.source_port,
            &received.payload,
            &mut encoded,
        )
        .map_err(|_| ())?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(count).map_err(|_| ())?;
        payload.extend_from_slice(&encoded[..count]);
        Ok(payload)
    }

    #[cfg(feature = "acceptance-probes")]
    #[inline(never)]
    fn run_diagnostics_benchmark_task(runner: &mut DiagnosticsBenchmarkRunner<'_>) -> TaskStep {
        let outcome = (|| -> Result<CommandApplicationOutcome, ()> {
            let package =
                parse_kex_package(native_diagnostics_benchmark_artifact()).map_err(|_| ())?;
            let mut requirements = package.requirements().iter();
            let requirement = requirements.next().ok_or(())?;
            if requirements.next().is_some()
                || requirement.interface != troe_abi::interface::SERVER_ENDPOINT
                || requirement.major != server::MAJOR
                || requirement.minor != server::MINOR
            {
                return Err(());
            }
            let mut dispatcher = Dispatcher::new(1, 2).map_err(|_| ())?;
            let port = register_command_service(
                &mut dispatcher,
                DiagnosticsBenchmarkEndpoint {
                    exchange: Rc::clone(&runner.exchange),
                },
            )?;
            let services = [CommandStartupService {
                port,
                interface: troe_abi::interface::SERVER_ENDPOINT,
                major: server::MAJOR,
                minor: server::MINOR,
            }];
            run_command_application(
                runner.scheduler,
                runner.accounting,
                &mut dispatcher,
                &services,
                None,
                package.executable(),
                1,
                Some(IPC_ISOLATED_SERVICE_CALL_LIMIT),
            )
        })();
        let success = outcome.is_ok();
        runner.outcome = Some(outcome);
        if success {
            TaskStep::ExitSuccess
        } else {
            TaskStep::ExitFailure
        }
    }

    #[inline(never)]
    fn run_diagnostics_server_task(runner: &mut DiagnosticsServerRunner<'_>) -> TaskStep {
        let outcome = (|| -> Result<CommandApplicationOutcome, ()> {
            let package = parse_kex_package(runner.artifact).map_err(|_| ())?;
            let mut requirements = package.requirements().iter();
            let requirement = requirements.next().ok_or(())?;
            if requirements.next().is_some()
                || requirement.interface != troe_abi::interface::SERVER_ENDPOINT
                || requirement.major != server::MAJOR
                || requirement.minor != server::MINOR
            {
                return Err(());
            }
            let mut dispatcher = Dispatcher::new(1, 2).map_err(|_| ())?;
            let port = register_command_service(
                &mut dispatcher,
                DiagnosticsServerEndpoint {
                    exchange: Rc::clone(&runner.exchange),
                },
            )?;
            let services = [CommandStartupService {
                port,
                interface: troe_abi::interface::SERVER_ENDPOINT,
                major: server::MAJOR,
                minor: server::MINOR,
            }];
            run_command_application(
                runner.scheduler,
                runner.accounting,
                &mut dispatcher,
                &services,
                None,
                package.executable(),
                1,
                None,
            )
        })();
        let success = outcome.is_ok();
        runner.outcome = Some(outcome);
        if success {
            TaskStep::ExitSuccess
        } else {
            TaskStep::ExitFailure
        }
    }

    #[inline(never)]
    fn run_diagnostics_server(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        operation: PendingOperationId,
        snapshot: SharedDiagnosticsSnapshot,
        reply_capacity: usize,
    ) -> Result<DiagnosticsServerFate, ()> {
        let baseline_frames = accounting.frames.free_frames();
        let (artifact, fault_probe) = native_diagnostics_server_artifact();
        let mut reply_storage = Vec::new();
        reply_storage
            .try_reserve_exact(troe_abi::MAX_MESSAGE_BYTES)
            .map_err(|_| ())?;
        reply_storage.resize(troe_abi::MAX_MESSAGE_BYTES, 0);
        let exchange = Rc::new(RefCell::new(DiagnosticsServerExchange {
            operation,
            snapshot,
            reply_capacity,
            received: false,
            completed: false,
            status: ReplyStatus::Failure,
            reply: reply_storage,
            reply_bytes: 0,
            steady_allocation_calls: None,
            steady_allocation_free: false,
        }));
        let stack = accounting.task_stacks[1].stack;
        let mut runner = DiagnosticsServerRunner {
            accounting,
            scheduler,
            exchange: Rc::clone(&exchange),
            artifact,
            fault_probe,
            outcome: None,
        };
        let step = troe_machine::run_task_step(stack, &mut runner, run_diagnostics_server_task)
            .map_err(|_| ())?;
        let outcome = runner.outcome.take().ok_or(())?;
        if (step == TaskStep::ExitSuccess) != outcome.is_ok() {
            return Err(());
        }
        let fault_probe = runner.fault_probe;
        drop(runner);
        if accounting.frames.free_frames() != baseline_frames {
            return Err(());
        }
        #[cfg(feature = "acceptance-probes")]
        if fault_probe {
            if !matches!(outcome, Ok(CommandApplicationOutcome::Faulted(_))) {
                return Err(());
            }
            DIAGNOSTICS_FAULT_PROBE_CONTAINED.store(true, Ordering::Release);
        }
        #[cfg(not(feature = "acceptance-probes"))]
        let _ = fault_probe;
        let mut exchange = exchange.borrow_mut();
        if exchange.completed && exchange.steady_allocation_free {
            let reply_bytes = exchange.reply_bytes;
            let status = exchange.status;
            let mut reply = Vec::new();
            reply.try_reserve_exact(reply_bytes).map_err(|_| ())?;
            reply.extend_from_slice(&exchange.reply[..reply_bytes]);
            exchange.reply[..reply_bytes].fill(0);
            return Ok((WakeReason::ResourceReady, Some((status, reply))));
        }
        match outcome {
            Ok(CommandApplicationOutcome::Exited(troe_abi::exit::SUCCESS)) => {
                Ok((WakeReason::Closed, None))
            }
            Ok(CommandApplicationOutcome::Exited(_) | CommandApplicationOutcome::Faulted(_))
            | Err(()) => Ok((WakeReason::Revoked, None)),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn deferred_reply(
        kind: DeferredCallKind,
        reason: WakeReason,
        received: Option<ReceivedUdp>,
        request: &[u8],
    ) -> Result<(ReplyStatus, Vec<u8>), ()> {
        match (kind, reason) {
            (DeferredCallKind::Timer { .. }, WakeReason::Deadline) => {
                Ok((ReplyStatus::Success, Vec::new()))
            }
            (DeferredCallKind::Datagram { .. }, WakeReason::ResourceReady) => Ok((
                ReplyStatus::Success,
                encode_received_datagram(&received.ok_or(())?)?,
            )),
            (DeferredCallKind::Datagram { .. }, WakeReason::Deadline) => {
                Ok((ReplyStatus::Timeout, Vec::new()))
            }
            (
                DeferredCallKind::Child {
                    children,
                    owner,
                    token,
                    ..
                },
                WakeReason::ResourceReady,
            ) => {
                let status = children
                    .try_borrow()
                    .map_err(|_| ())?
                    .status(owner, token)
                    .map_err(|_| ())?;
                if status.state == process_launch::ChildState::Running {
                    return Err(());
                }
                let encoded = process_launch::encode_status(status).map_err(|_| ())?;
                Ok((ReplyStatus::Success, owned_reply_payload(&encoded)?))
            }
            (
                DeferredCallKind::PipeRead {
                    pipes,
                    target,
                    maximum,
                    ..
                },
                WakeReason::ResourceReady,
            ) => {
                let mut bytes = [0_u8; pipe::MAX_IO_BYTES];
                let count = match target {
                    DeferredPipeTarget::Owner { owner, token } => pipes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .read_owner(owner, token, &mut bytes[..maximum]),
                    DeferredPipeTarget::Endpoint(endpoint) => pipes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .read_endpoint(endpoint, &mut bytes[..maximum]),
                }
                .map_err(|_| ())?;
                Ok((ReplyStatus::Success, owned_reply_payload(&bytes[..count])?))
            }
            (
                DeferredCallKind::PipeWrite {
                    pipes,
                    target,
                    byte_count,
                    ..
                },
                WakeReason::ResourceReady,
            ) => {
                let bytes = match target {
                    DeferredPipeTarget::Owner { token, .. } => {
                        let (encoded_token, bytes) = pipe::decode_write(request).map_err(|_| ())?;
                        if encoded_token != token {
                            return Err(());
                        }
                        bytes
                    }
                    DeferredPipeTarget::Endpoint(_) => request,
                };
                if bytes.len() != byte_count {
                    return Err(());
                }
                let count = match target {
                    DeferredPipeTarget::Owner { owner, token } => pipes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .write_owner(owner, token, bytes),
                    DeferredPipeTarget::Endpoint(endpoint) => pipes
                        .try_borrow_mut()
                        .map_err(|_| ())?
                        .write_endpoint(endpoint, bytes),
                }
                .map_err(|_| ())?;
                if count != bytes.len() {
                    return Err(());
                }
                Ok((ReplyStatus::Success, Vec::new()))
            }
            (
                DeferredCallKind::TerminalRead {
                    terminal, maximum, ..
                },
                WakeReason::ResourceReady,
            ) => {
                let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
                let count = terminal
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .take(&mut bytes[..maximum]);
                Ok((ReplyStatus::Success, owned_reply_payload(&bytes[..count])?))
            }
            (_, WakeReason::Cancelled | WakeReason::Revoked) => {
                Ok((ReplyStatus::Cancelled, Vec::new()))
            }
            (_, WakeReason::Closed) => Ok((ReplyStatus::Conflict, Vec::new())),
            (
                DeferredCallKind::Timer { .. } | DeferredCallKind::Diagnostics { .. },
                WakeReason::ResourceReady,
            )
            | (
                DeferredCallKind::Diagnostics { .. }
                | DeferredCallKind::Child { .. }
                | DeferredCallKind::PipeRead { .. }
                | DeferredCallKind::PipeWrite { .. }
                | DeferredCallKind::TerminalRead { .. },
                WakeReason::Deadline,
            ) => Err(()),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn wait_for_deferred_call(
        scheduler: &mut Scheduler,
        task_id: TaskId,
        operation: PendingOperationId,
        runtime: &SharedRuntime,
        pending: &mut PendingCallTable,
        waits: &mut WaitTable,
        suspended: &mut SuspendedApplicationCalls,
    ) -> Result<
        (
            troe_machine::ApplicationSession,
            troe_machine::ApplicationCall,
            ReplyStatus,
            Vec<u8>,
        ),
        (),
    > {
        let mut received = None;
        let completion = loop {
            let state = pending.call(operation).map_err(|_| ())?.state();
            let PendingCallState::Waiting(wait) = state else {
                return Err(());
            };
            let cancelled = runtime.borrow_mut().checkpoint().is_err();
            if cancelled {
                if let Some(completion) = waits
                    .cancel_operation(operation, WakeReason::Cancelled)
                    .map_err(|_| ())?
                {
                    break completion;
                }
                return Err(());
            }
            let now = runtime.borrow().now();
            let suspended_call = suspended.get(operation)?;
            match &suspended_call.kind {
                DeferredCallKind::Timer { deadline } => {
                    if now >= *deadline {
                        let batch = waits.expire(now).map_err(|_| ())?;
                        if let Some(completion) = batch.iter().next() {
                            break completion;
                        }
                    }
                }
                DeferredCallKind::Datagram {
                    state,
                    local_port,
                    deadline,
                    resource,
                } => {
                    if let Some(datagram) = state
                        .borrow_mut()
                        .receive_now(*local_port)
                        .map_err(|_| ())?
                    {
                        received = Some(datagram);
                        let batch = waits
                            .wake_resource(*resource, WakeReason::ResourceReady)
                            .map_err(|_| ())?;
                        if let Some(completion) = batch.iter().next() {
                            break completion;
                        }
                        return Err(());
                    }
                    if now >= *deadline {
                        let batch = waits.expire(now).map_err(|_| ())?;
                        if let Some(completion) = batch.iter().next() {
                            break completion;
                        }
                    }
                }
                DeferredCallKind::Diagnostics { .. }
                | DeferredCallKind::Child { .. }
                | DeferredCallKind::PipeRead { .. }
                | DeferredCallKind::PipeWrite { .. }
                | DeferredCallKind::TerminalRead { .. } => return Err(()),
            }
            let deadline = match &suspended_call.kind {
                DeferredCallKind::Timer { deadline }
                | DeferredCallKind::Datagram { deadline, .. } => *deadline,
                DeferredCallKind::Diagnostics { .. }
                | DeferredCallKind::Child { .. }
                | DeferredCallKind::PipeRead { .. }
                | DeferredCallKind::PipeWrite { .. }
                | DeferredCallKind::TerminalRead { .. } => return Err(()),
            };
            let remaining = deadline.as_millis().saturating_sub(now.as_millis());
            if remaining == 0 {
                continue;
            }
            // A logical wait may span hours or days, while architecture
            // one-shot counters have a much smaller exact range. Re-arm in
            // bounded idle slices so hardware width never becomes a process
            // lifetime limit.
            let interval =
                u32::try_from(remaining.min(u64::from(APPLICATION_TIMESLICE_MILLISECONDS)))
                    .map_err(|_| ())?;
            let _deadline_fired =
                troe_machine::wait_for_runtime_event_timeout(interval).map_err(|_| ())?;
            if pending.call(operation).map_err(|_| ())?.state() != PendingCallState::Waiting(wait) {
                return Err(());
            }
        };
        pending.resolve(completion).map_err(|_| ())?;
        scheduler
            .wake_blocked(completion.owner(), completion.key())
            .map_err(|_| ())?;
        scheduler
            .dispatch(task_id, Capabilities::SERVICE)
            .map_err(|_| ())?;
        let suspended_call = suspended.take(operation)?;
        let request = pending.request(operation).map_err(|_| ())?;
        let (status, payload) =
            deferred_reply(suspended_call.kind, completion.reason(), received, request)?;
        if payload.len() > suspended_call.call.reply_capacity() {
            return Err(());
        }
        pending.finish(operation).map_err(|_| ())?;
        Ok((
            suspended_call.application,
            suspended_call.call,
            status,
            payload,
        ))
    }

    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn complete_diagnostics_deferred_call(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        task_id: TaskId,
        operation: PendingOperationId,
        snapshot: SharedDiagnosticsSnapshot,
        resource: WaitResource,
        pending: &mut PendingCallTable,
        waits: &mut WaitTable,
        suspended: &mut SuspendedApplicationCalls,
    ) -> Result<
        (
            troe_machine::ApplicationSession,
            troe_machine::ApplicationCall,
            ReplyStatus,
            Vec<u8>,
        ),
        (),
    > {
        let reply_capacity = pending.call(operation).map_err(|_| ())?.reply_capacity();
        let (reason, server_reply) =
            run_diagnostics_server(scheduler, accounting, operation, snapshot, reply_capacity)?;
        let completion = match reason {
            WakeReason::ResourceReady | WakeReason::Closed => {
                let batch = waits.wake_resource(resource, reason).map_err(|_| ())?;
                let completion = batch.iter().next().ok_or(())?;
                if batch.iter().nth(1).is_some() {
                    return Err(());
                }
                completion
            }
            WakeReason::Revoked => waits
                .cancel_operation(operation, reason)
                .map_err(|_| ())?
                .ok_or(())?,
            WakeReason::Deadline | WakeReason::Cancelled => return Err(()),
        };
        pending.resolve(completion).map_err(|_| ())?;
        scheduler
            .wake_blocked(completion.owner(), completion.key())
            .map_err(|_| ())?;
        scheduler
            .dispatch(task_id, Capabilities::SERVICE)
            .map_err(|_| ())?;
        let suspended_call = suspended.take(operation)?;
        if !matches!(
            suspended_call.kind,
            DeferredCallKind::Diagnostics { resource: owned, .. } if owned == resource
        ) {
            return Err(());
        }
        let (status, payload) = match reason {
            WakeReason::ResourceReady => server_reply.ok_or(())?,
            WakeReason::Closed => (ReplyStatus::Conflict, Vec::new()),
            WakeReason::Revoked => (ReplyStatus::Cancelled, Vec::new()),
            WakeReason::Deadline | WakeReason::Cancelled => return Err(()),
        };
        if payload.len() > suspended_call.call.reply_capacity() {
            return Err(());
        }
        pending.finish(operation).map_err(|_| ())?;
        Ok((
            suspended_call.application,
            suspended_call.call,
            status,
            payload,
        ))
    }

    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn resume_deferred_application_call(
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        task_id: TaskId,
        operation: PendingOperationId,
        spec: WaitSpec,
        kind: DeferredCallKind,
        application: troe_machine::ApplicationSession,
        call: troe_machine::ApplicationCall,
        runtime: &SharedRuntime,
        diagnostics_snapshot: Option<&SharedDiagnosticsSnapshot>,
        state: &mut CommandDeferredState,
    ) -> Result<troe_machine::ApplicationOutcome, ()> {
        let registration = state
            .waits
            .register(spec, WaitObservation::Pending, runtime.borrow().now())
            .map_err(|_| ())?;
        match registration {
            WaitRegistration::Ready(reason) => {
                state
                    .pending
                    .mark_ready(operation, reason)
                    .map_err(|_| ())?;
                let (status, payload) = deferred_reply(kind, reason, None, &[])?;
                if payload.len() > call.reply_capacity() {
                    return Err(());
                }
                state.pending.finish(operation).map_err(|_| ())?;
                troe_machine::resume_application(
                    application,
                    troe_machine::ApplicationResume::HandleReply {
                        status: status.abi_value(),
                        reply: &payload,
                    },
                    APPLICATION_TIMESLICE_MILLISECONDS,
                )
                .map_err(|_| ())
            }
            WaitRegistration::Blocked(wait) => {
                let diagnostics = match &kind {
                    DeferredCallKind::Diagnostics { resource } => {
                        Some((Rc::clone(diagnostics_snapshot.ok_or(())?), *resource))
                    }
                    DeferredCallKind::Timer { .. }
                    | DeferredCallKind::Datagram { .. }
                    | DeferredCallKind::Child { .. }
                    | DeferredCallKind::PipeRead { .. }
                    | DeferredCallKind::PipeWrite { .. }
                    | DeferredCallKind::TerminalRead { .. } => None,
                };
                state.pending.bind_wait(operation, wait).map_err(|_| ())?;
                state.suspended.insert(SuspendedApplicationCall {
                    operation,
                    application,
                    call,
                    kind,
                })?;
                scheduler.block_current(task_id, wait).map_err(|_| ())?;
                let (application, _call, status, payload) =
                    if let Some((snapshot, resource)) = diagnostics {
                        complete_diagnostics_deferred_call(
                            scheduler,
                            accounting,
                            task_id,
                            operation,
                            snapshot,
                            resource,
                            &mut state.pending,
                            &mut state.waits,
                            &mut state.suspended,
                        )?
                    } else {
                        wait_for_deferred_call(
                            scheduler,
                            task_id,
                            operation,
                            runtime,
                            &mut state.pending,
                            &mut state.waits,
                            &mut state.suspended,
                        )?
                    };
                troe_machine::resume_application(
                    application,
                    troe_machine::ApplicationResume::HandleReply {
                        status: status.abi_value(),
                        reply: &payload,
                    },
                    APPLICATION_TIMESLICE_MILLISECONDS,
                )
                .map_err(|_| ())
            }
        }
    }

    #[allow(
        clippy::drop_non_drop,
        clippy::too_many_arguments,
        clippy::too_many_lines
    )]
    fn prepare_streamed_resident_application<'service>(
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
            |allocation, _plan| {
                prepare_streamed_application_memory(allocation, package, &mut read_at)
            },
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
    fn prepare_resident_application_with_plan<'service, P: NativeApplicationPlan>(
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
        let Ok(task_id) =
            scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
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

    #[allow(
        clippy::drop_non_drop,
        clippy::too_many_arguments,
        clippy::too_many_lines
    )]
    fn run_command_application(
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
        let Ok(task_id) =
            scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
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
                        break CommandApplicationOutcome::Faulted(
                            TaskFault::ServiceCallLimitExceeded,
                        );
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
                                    break CommandApplicationOutcome::Faulted(
                                        TaskFault::InvalidCall,
                                    );
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
                                    break CommandApplicationOutcome::Faulted(
                                        TaskFault::InvalidCall,
                                    );
                                };
                                if reply.payload().len() > call.reply_capacity() {
                                    scheduler
                                        .fault_current(task_id, TaskFault::InvalidCall)
                                        .map_err(|_| ())?;
                                    break CommandApplicationOutcome::Faulted(
                                        TaskFault::InvalidCall,
                                    );
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
                                    break CommandApplicationOutcome::Faulted(
                                        TaskFault::InvalidCall,
                                    );
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

    fn nested_input_for_spawn<'service>(
        spec: process_launch::StreamSpec,
        inherited: &NestedInput<'service>,
        owner: OwnerId,
        pipes: &SharedPipeTable,
    ) -> Result<NestedInput<'service>, ReplyStatus> {
        match spec.mode {
            // The session terminal loan is not transitive. A child that
            // inherits terminal-backed standard input receives an empty stream
            // instead, so two readers never compete for one keystroke.
            process_launch::StreamMode::Inherit => Ok(match inherited {
                NestedInput::Borrowed(input) => {
                    let terminal = input
                        .try_borrow()
                        .map_err(|_| ReplyStatus::Conflict)?
                        .is_terminal();
                    if terminal {
                        NestedInput::Empty
                    } else {
                        inherited.clone()
                    }
                }
                NestedInput::Empty | NestedInput::Pipe { .. } => inherited.clone(),
            }),
            process_launch::StreamMode::Null => Ok(NestedInput::Empty),
            process_launch::StreamMode::Pipe => {
                let token =
                    pipe::PipeToken::new(spec.pipe).map_err(|_| ReplyStatus::InvalidRequest)?;
                pipes
                    .try_borrow_mut()
                    .map_err(|_| ReplyStatus::Conflict)?
                    .owner_read_ready(owner, token)
                    .map_err(child_process_status)?;
                Ok(NestedInput::Pipe {
                    pipes: pipes.clone(),
                    owner,
                    token,
                })
            }
        }
    }

    fn nested_output_for_spawn<'service>(
        spec: process_launch::StreamSpec,
        inherited: &NestedOutput<'service>,
        owner: OwnerId,
        pipes: &SharedPipeTable,
    ) -> Result<NestedOutput<'service>, ReplyStatus> {
        match spec.mode {
            process_launch::StreamMode::Inherit => Ok(inherited.clone()),
            process_launch::StreamMode::Null => Ok(NestedOutput::Discard),
            process_launch::StreamMode::Pipe => {
                let token =
                    pipe::PipeToken::new(spec.pipe).map_err(|_| ReplyStatus::InvalidRequest)?;
                // Zero-length readiness is false but still validates token,
                // ownership, writer openness, and the existence of a reader.
                let _ready = pipes
                    .try_borrow_mut()
                    .map_err(|_| ReplyStatus::Conflict)?
                    .owner_write_ready(owner, token, 0)
                    .map_err(child_process_status)?;
                Ok(NestedOutput::Pipe {
                    pipes: pipes.clone(),
                    owner,
                    token,
                })
            }
        }
    }

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
            let result =
                Self::spawn_child_with_control(&mut control, scheduler, accounting, request);
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
                ExternalCommandReference::CatalogName(name) => {
                    Some(alloc::format!("/bin/{name}.kex"))
                }
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
            let placement = random_application_placement(&accounting.random)
                .map_err(|_| ReplyStatus::Failure)?;
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
            let mut dispatcher = Dispatcher::new(service_count, handle_capacity)
                .map_err(|_| ReplyStatus::Exhausted)?;
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
                    port: register_command_service(
                        &mut dispatcher,
                        ApplicationPrivateMemoryService,
                    )
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

        fn request_stop(&self) -> Result<(), ()> {
            self.processes
                .try_borrow_mut()
                .map_err(|_| ())?
                .stopping(self.process_id)
                .map_err(|_| ())
        }

        fn execute_accounted<T, E>(
            &self,
            operation: impl FnOnce() -> Result<T, E>,
        ) -> Result<T, ()> {
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

        fn install_deferred_services(
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

        fn step(
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
                                let (table_pages, private_pages) = application_resource_totals(
                                    &self.allocation,
                                    self.private_pages,
                                )?;
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
                                        owned_reply_payload(&process_launch::encode_spawned(
                                            child,
                                        ))?,
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

        fn request_deferred_cancel(&mut self, scheduler: &mut Scheduler) -> Result<bool, ()> {
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
            if let DeferredCallKind::Diagnostics { resource } =
                &state.suspended.get(operation)?.kind
            {
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

        fn teardown(
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

    impl ResidentProcessTable {
        fn new() -> Result<Self, ()> {
            let mut jobs = Vec::new();
            jobs.try_reserve_exact(INITIAL_RESIDENT_PROCESS_CAPACITY)
                .map_err(|_| ())?;
            Ok(Self { jobs, next_id: 1 })
        }

        fn available_slot(&self) -> Option<u32> {
            (0..RESIDENT_PROCESS_CAPACITY).find_map(|offset| {
                let offset = u32::try_from(offset).ok()?;
                let slot = RESIDENT_PROCESS_FIRST_SLOT.checked_add(offset)?;
                (!self.jobs.iter().any(|job| {
                    job.process
                        .as_ref()
                        .is_some_and(|process| process.isolation.slot() == slot)
                }))
                .then_some(slot)
            })
        }

        fn admit(
            &mut self,
            command: String,
            owner: ResidentOwner,
            log: SharedResidentLog,
            process: Box<ResidentApplication<'static>>,
        ) -> Result<u32, Box<ResidentApplication<'static>>> {
            if self.jobs.len() >= RESIDENT_PROCESS_CAPACITY {
                return Err(process);
            }
            if self.jobs.try_reserve(1).is_err() {
                return Err(process);
            }
            let (id, next_id) = match owner {
                ResidentOwner::Session => {
                    let Some(next_id) = self.next_id.checked_add(1) else {
                        return Err(process);
                    };
                    (self.next_id, next_id)
                }
                ResidentOwner::Service(_) => (0, self.next_id),
            };
            self.jobs.push(ResidentJob {
                id,
                task_id: process.task_id,
                command,
                owner,
                log,
                process: Some(process),
                outcome: None,
                cancel_requested: false,
            });
            self.next_id = next_id;
            Ok(id)
        }

        fn pump(
            &mut self,
            scheduler: &mut Scheduler,
            accounting: &mut OwnedAccounting,
            shell_id: TaskId,
            shell_capabilities: Capabilities,
        ) -> Result<(), ()> {
            scheduler.yield_current(shell_id).map_err(|_| ())?;
            self.pump_processes(scheduler, accounting)?;
            scheduler
                .dispatch(shell_id, shell_capabilities)
                .map_err(|_| ())?;
            Ok(())
        }

        fn pump_processes(
            &mut self,
            scheduler: &mut Scheduler,
            accounting: &mut OwnedAccounting,
        ) -> Result<(), ()> {
            for index in 0..self.jobs.len() {
                if self.jobs[index].outcome.is_some() {
                    continue;
                }
                let cancelled = self.jobs[index].cancel_requested;
                let result = if cancelled {
                    None
                } else {
                    self.jobs[index]
                        .process
                        .as_mut()
                        .map(|process| process.step(scheduler, accounting))
                };
                let terminal = match result {
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
                if let Some((outcome, force_cancel)) = terminal {
                    let process = self.jobs[index].process.take().ok_or(())?;
                    self.jobs[index].outcome = Some(process.teardown(
                        scheduler,
                        accounting,
                        outcome,
                        cancelled || force_cancel,
                    )?);
                }
            }
            Ok(())
        }

        fn has_runnable_process(&self) -> bool {
            self.jobs.iter().any(|job| {
                job.outcome.is_none()
                    && !job.cancel_requested
                    && job.process.as_ref().is_some_and(|process| {
                        !matches!(process.execution, Some(ResidentExecution::Blocked))
                    })
            })
        }

        fn request_cancel(&mut self, job_id: u32) -> Result<(), ()> {
            let job = self
                .jobs
                .iter_mut()
                .find(|job| job.id == job_id && job.owner == ResidentOwner::Session)
                .ok_or(())?;
            if job.outcome.is_some() {
                return Ok(());
            }
            job.process.as_ref().ok_or(())?.request_stop()?;
            job.cancel_requested = true;
            Ok(())
        }

        fn is_terminal(&self, job_id: u32) -> Result<bool, ()> {
            self.jobs
                .iter()
                .find(|job| job.id == job_id && job.owner == ResidentOwner::Session)
                .map(|job| job.outcome.is_some())
                .ok_or(())
        }

        fn copy_log(&self, job_id: u32, destination: &mut [u8]) -> Result<(usize, u64), ()> {
            let job = self
                .jobs
                .iter()
                .find(|job| job.id == job_id && job.owner == ResidentOwner::Session)
                .ok_or(())?;
            let log = job.log.try_borrow().map_err(|_| ())?;
            Ok((log.copy_recent(destination), log.dropped()))
        }

        fn remove_terminal(&mut self, job_id: u32) -> Result<CommandApplicationOutcome, ()> {
            let index = self
                .jobs
                .iter()
                .position(|job| job.id == job_id && job.owner == ResidentOwner::Session)
                .ok_or(())?;
            let outcome = self.jobs[index].outcome.ok_or(())?;
            self.jobs.remove(index);
            Ok(outcome)
        }

        fn service_task(&self, service_id: u32) -> Option<TaskId> {
            self.jobs
                .iter()
                .find(|job| job.owner == ResidentOwner::Service(service_id))
                .and_then(|job| job.process.as_ref())
                .map(|process| process.task_id)
        }

        fn request_service_cancel(&mut self, service_id: u32) -> Result<(), ()> {
            let job = self
                .jobs
                .iter_mut()
                .find(|job| job.owner == ResidentOwner::Service(service_id))
                .ok_or(())?;
            if job.outcome.is_none() {
                job.process.as_ref().ok_or(())?.request_stop()?;
                job.cancel_requested = true;
            }
            Ok(())
        }

        fn copy_service_log(
            &self,
            service_id: u32,
            destination: &mut [u8],
        ) -> Option<(usize, u64)> {
            let job = self
                .jobs
                .iter()
                .find(|job| job.owner == ResidentOwner::Service(service_id))?;
            let log = job.log.try_borrow().ok()?;
            Some((log.copy_recent(destination), log.dropped()))
        }

        fn take_service_terminal(
            &mut self,
            service_id: u32,
        ) -> Option<(TaskId, CommandApplicationOutcome, SharedResidentLog)> {
            let index = self.jobs.iter().position(|job| {
                job.owner == ResidentOwner::Service(service_id) && job.outcome.is_some()
            })?;
            let job = self.jobs.remove(index);
            Some((job.task_id, job.outcome?, job.log))
        }
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

    fn private_permissions(protection: private_memory::Protection) -> Option<MappingPermissions> {
        match protection {
            private_memory::Protection::None => None,
            private_memory::Protection::Read => Some(MappingPermissions::READ_ONLY),
            private_memory::Protection::ReadWrite => Some(MappingPermissions::READ_WRITE),
        }
    }

    fn random_application_placement(random: &SharedRandom) -> Result<LoadPlacement, ()> {
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

    fn parse_native_application<'artifact>(
        accounting: &OwnedAccounting,
        artifact: &'artifact [u8],
    ) -> Result<LoadPlan<'artifact>, ()> {
        let placement = random_application_placement(&accounting.random)?;
        parse_kex_at(artifact, native_application_target(), ABI_MINOR, placement).map_err(|_| ())
    }

    trait NativeApplicationPlan {
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

    fn private_metadata_bytes(mappings: &[ApplicationPrivateMapping]) -> Option<u64> {
        let mapping_count = u64::try_from(mappings.len()).ok()?;
        let extent_count = mappings.iter().try_fold(0_u64, |total, mapping| {
            total.checked_add(u64::try_from(mapping.backing.len()).ok()?)
        })?;
        mapping_count
            .checked_mul(u64::try_from(core::mem::size_of::<ApplicationPrivateMapping>()).ok()?)?
            .checked_add(
                extent_count
                    .checked_mul(u64::try_from(core::mem::size_of::<PhysicalRange>()).ok()?)?,
            )
    }

    fn private_heap_end(
        allocation: &ApplicationAllocation,
        heap_start: u64,
    ) -> Result<u64, PrivateMemoryError> {
        let pages = allocation
            .heap_pages
            .checked_add(
                application_growth_pages(allocation).map_err(|()| PrivateMemoryError::Terminal)?,
            )
            .ok_or(PrivateMemoryError::Terminal)?;
        heap_start
            .checked_add(
                pages
                    .checked_mul(BASE_PAGE_SIZE)
                    .ok_or(PrivateMemoryError::Terminal)?,
            )
            .ok_or(PrivateMemoryError::Terminal)
    }

    fn private_range_available(
        state: &ApplicationPrivateMemory,
        floor: u64,
        range: VirtualRange,
    ) -> bool {
        range.start() >= floor
            && range.end() <= state.arena_end
            && state.mappings.iter().all(|mapping| {
                mapping.range.end() <= range.start() || range.end() <= mapping.range.start()
            })
    }

    fn align_down(value: u64, alignment: u64) -> Option<u64> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return None;
        }
        Some(value & !(alignment - 1))
    }

    fn align_up(value: u64, alignment: u64) -> Option<u64> {
        value
            .checked_add(alignment.checked_sub(1)?)
            .and_then(|rounded| align_down(rounded, alignment))
    }

    fn private_gap_slots(
        gap_start: u64,
        gap_end: u64,
        byte_count: u64,
        alignment: u64,
    ) -> Option<(u64, u64)> {
        let first = align_up(gap_start, alignment)?;
        let last = gap_end
            .checked_sub(byte_count)
            .and_then(|value| align_down(value, alignment))?;
        if first > last {
            return None;
        }
        let slots = last
            .checked_sub(first)?
            .checked_div(alignment)?
            .checked_add(1)?;
        Some((first, slots))
    }

    fn select_private_gap(
        gap_start: u64,
        gap_end: u64,
        byte_count: u64,
        alignment: u64,
        selected: &mut u64,
    ) -> Result<Option<u64>, PrivateMemoryError> {
        let Some((first, slots)) = private_gap_slots(gap_start, gap_end, byte_count, alignment)
        else {
            return Ok(None);
        };
        if *selected >= slots {
            *selected = selected
                .checked_sub(slots)
                .ok_or(PrivateMemoryError::Terminal)?;
            return Ok(None);
        }
        let offset = selected
            .checked_mul(alignment)
            .ok_or(PrivateMemoryError::Terminal)?;
        Ok(Some(
            first
                .checked_add(offset)
                .ok_or(PrivateMemoryError::Terminal)?,
        ))
    }

    fn choose_private_range(
        state: &ApplicationPrivateMemory,
        floor: u64,
        request: private_memory::MapRequest,
        random: &SharedRandom,
    ) -> Result<VirtualRange, PrivateMemoryError> {
        let byte_count = request
            .page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
        let alignment = request
            .alignment_pages
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
        if request.address_hint != 0
            && request.address_hint.is_multiple_of(alignment)
            && let Ok(range) = VirtualRange::from_pages(request.address_hint, request.page_count)
            && private_range_available(state, floor, range)
        {
            return Ok(range);
        }
        let mut total_slots = 0_u64;
        let mut gap_start = floor;
        for mapping in &state.mappings {
            if let Some((_, slots)) =
                private_gap_slots(gap_start, mapping.range.start(), byte_count, alignment)
            {
                total_slots = total_slots
                    .checked_add(slots)
                    .ok_or(PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
            }
            gap_start = mapping.range.end().max(gap_start);
        }
        if let Some((_, slots)) =
            private_gap_slots(gap_start, state.arena_end, byte_count, alignment)
        {
            total_slots = total_slots
                .checked_add(slots)
                .ok_or(PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
        }
        if total_slots == 0 {
            return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
        }
        let mut selected = random
            .try_borrow_mut()
            .map_err(|_| PrivateMemoryError::Terminal)?
            .uniform_u64(total_slots)
            .map_err(|_| PrivateMemoryError::Terminal)?;
        gap_start = floor;
        let mut selected_start = None;
        for mapping in &state.mappings {
            if let Some(start) = select_private_gap(
                gap_start,
                mapping.range.start(),
                byte_count,
                alignment,
                &mut selected,
            )? {
                selected_start = Some(start);
                break;
            }
            gap_start = mapping.range.end().max(gap_start);
        }
        if selected_start.is_none() {
            selected_start = select_private_gap(
                gap_start,
                state.arena_end,
                byte_count,
                alignment,
                &mut selected,
            )?;
        }
        let range = VirtualRange::from_pages(
            selected_start.ok_or(PrivateMemoryError::Terminal)?,
            request.page_count,
        )
        .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Overflow))?;
        Ok(range)
    }

    fn append_private_extent(
        extents: &mut Vec<PhysicalRange>,
        frame: u64,
    ) -> Result<(), PrivateMemoryError> {
        if let Some(last) = extents.last_mut()
            && last.end() == frame
        {
            *last = PhysicalRange::from_pages(
                last.start(),
                last.page_count()
                    .checked_add(1)
                    .ok_or(PrivateMemoryError::Terminal)?,
            )
            .map_err(|_| PrivateMemoryError::Terminal)?;
            return Ok(());
        }
        extents
            .try_reserve(1)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
        extents
            .push(PhysicalRange::from_pages(frame, 1).map_err(|_| PrivateMemoryError::Terminal)?);
        Ok(())
    }

    fn release_private_extents(
        frames: &mut FrameAllocator,
        extents: &[PhysicalRange],
    ) -> Result<(), PrivateMemoryError> {
        for range in extents {
            troe_machine::zero_physical_range(*range).map_err(|_| PrivateMemoryError::Terminal)?;
            frames
                .free_range(*range)
                .map_err(|_| PrivateMemoryError::Terminal)?;
        }
        Ok(())
    }

    fn allocate_private_extents(
        frames: &mut FrameAllocator,
        page_count: u64,
        operation_quantum_pages: u64,
    ) -> Result<Vec<PhysicalRange>, PrivateMemoryError> {
        if operation_quantum_pages == 0 {
            return Err(PrivateMemoryError::Terminal);
        }
        let mut extents = Vec::new();
        let mut remaining = page_count;
        while remaining != 0 {
            let quantum = remaining.min(operation_quantum_pages);
            match frames.allocate_contiguous(quantum, 1) {
                Ok(range) => {
                    if extents.try_reserve(1).is_err() {
                        frames
                            .free_range(range)
                            .map_err(|_| PrivateMemoryError::Terminal)?;
                        release_private_extents(frames, &extents)?;
                        return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
                    }
                    if troe_machine::zero_physical_range(range).is_err() {
                        frames
                            .free_range(range)
                            .map_err(|_| PrivateMemoryError::Terminal)?;
                        release_private_extents(frames, &extents)?;
                        return Err(PrivateMemoryError::Terminal);
                    }
                    extents.push(range);
                }
                Err(FrameAllocationError::Exhausted) => {
                    for _ in 0..quantum {
                        let Ok(frame) = frames.allocate() else {
                            release_private_extents(frames, &extents)?;
                            return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
                        };
                        let range = PhysicalRange::from_pages(frame, 1)
                            .map_err(|_| PrivateMemoryError::Terminal)?;
                        if troe_machine::zero_physical_range(range).is_err() {
                            frames
                                .free(frame)
                                .map_err(|_| PrivateMemoryError::Terminal)?;
                            release_private_extents(frames, &extents)?;
                            return Err(PrivateMemoryError::Terminal);
                        }
                        if let Err(error) = append_private_extent(&mut extents, frame) {
                            frames
                                .free(frame)
                                .map_err(|_| PrivateMemoryError::Terminal)?;
                            release_private_extents(frames, &extents)?;
                            return Err(error);
                        }
                    }
                }
                Err(_) => {
                    release_private_extents(frames, &extents)?;
                    return Err(PrivateMemoryError::Terminal);
                }
            }
            remaining = remaining
                .checked_sub(quantum)
                .ok_or(PrivateMemoryError::Terminal)?;
        }
        Ok(extents)
    }

    fn private_policy_allows(
        accounting: &OwnedAccounting,
        allocation: &ApplicationAllocation,
        reserved_pages: u64,
        committed_pages: u64,
        mappings: u64,
        metadata_bytes: u64,
    ) -> Result<(), PrivateMemoryError> {
        let state = &allocation.private_memory;
        let process_commit = allocation
            .extents
            .page_count()
            .checked_add(
                application_growth_pages(allocation).map_err(|()| PrivateMemoryError::Terminal)?,
            )
            .and_then(|pages| pages.checked_add(committed_pages))
            .ok_or(PrivateMemoryError::Terminal)?;
        if state
            .maximum_reserved_pages
            .is_some_and(|maximum| reserved_pages > maximum)
            || state
                .maximum_committed_pages
                .is_some_and(|maximum| process_commit > maximum)
            || mappings > state.maximum_mappings
            || metadata_bytes > state.maximum_metadata_bytes
        {
            return Err(PrivateMemoryError::Reply(ReplyStatus::ResourceLimit));
        }
        let global_metadata = accounting
            .private_metadata_bytes
            .checked_sub(state.metadata_bytes)
            .and_then(|value| value.checked_add(metadata_bytes))
            .ok_or(PrivateMemoryError::Terminal)?;
        let system_commit = accounting
            .application_committed_pages
            .checked_sub(state.committed_pages)
            .and_then(|value| value.checked_add(committed_pages))
            .ok_or(PrivateMemoryError::Terminal)?;
        if global_metadata > accounting.memory_policy.global_metadata_bytes()
            || accounting
                .memory_policy
                .system_application_commit()
                .maximum()
                .is_some_and(|maximum| system_commit > maximum)
        {
            return Err(PrivateMemoryError::Reply(ReplyStatus::ResourceLimit));
        }
        Ok(())
    }

    fn commit_private_accounting(
        accounting: &mut OwnedAccounting,
        state: &mut ApplicationPrivateMemory,
        reserved_pages: u64,
        committed_pages: u64,
        metadata_bytes: u64,
    ) -> Result<(), PrivateMemoryError> {
        accounting.private_metadata_bytes = accounting
            .private_metadata_bytes
            .checked_sub(state.metadata_bytes)
            .and_then(|value| value.checked_add(metadata_bytes))
            .ok_or(PrivateMemoryError::Terminal)?;
        accounting.application_committed_pages = accounting
            .application_committed_pages
            .checked_sub(state.committed_pages)
            .and_then(|value| value.checked_add(committed_pages))
            .ok_or(PrivateMemoryError::Terminal)?;
        state.reserved_pages = reserved_pages;
        state.committed_pages = committed_pages;
        state.metadata_bytes = metadata_bytes;
        state.high_water_reserved_pages = state.high_water_reserved_pages.max(reserved_pages);
        state.high_water_committed_pages = state.high_water_committed_pages.max(committed_pages);
        state.high_water_mappings = state
            .high_water_mappings
            .max(u64::try_from(state.mappings.len()).map_err(|_| PrivateMemoryError::Terminal)?);
        state.high_water_metadata_bytes = state.high_water_metadata_bytes.max(metadata_bytes);
        Ok(())
    }

    fn reserve_private_table_frames(
        frames: &mut FrameAllocator,
        allocation: &mut ApplicationAllocation,
        application: &troe_machine::ApplicationSession,
        virtual_start: u64,
        page_count: u64,
        minimum_free_pages: u64,
    ) -> Result<usize, PrivateMemoryError> {
        let range = VirtualRange::from_pages(virtual_start, page_count)
            .map_err(|_| PrivateMemoryError::Terminal)?;
        let required = troe_machine::maximum_additional_page_table_pages(range)
            .map_err(|_| PrivateMemoryError::Terminal)?;
        let retained = allocation
            .tables
            .page_count()
            .checked_add(
                u64::try_from(allocation.growth_table_frames.len())
                    .map_err(|_| PrivateMemoryError::Terminal)?,
            )
            .ok_or(PrivateMemoryError::Terminal)?;
        let available = retained
            .checked_sub(application.stats().table_pages)
            .ok_or(PrivateMemoryError::Terminal)?;
        let deficit = usize::try_from(required.saturating_sub(available))
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
        allocation
            .growth_table_frames
            .try_reserve_exact(deficit)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
        let needed = u64::try_from(deficit).map_err(|_| PrivateMemoryError::Terminal)?;
        if frames.free_frames().saturating_sub(minimum_free_pages) < needed {
            return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
        }
        let retained_len = allocation.growth_table_frames.len();
        for _ in 0..deficit {
            let Ok(frame) = frames.allocate() else {
                while allocation.growth_table_frames.len() > retained_len {
                    let frame = allocation
                        .growth_table_frames
                        .pop()
                        .ok_or(PrivateMemoryError::Terminal)?;
                    frames
                        .free(frame)
                        .map_err(|_| PrivateMemoryError::Terminal)?;
                }
                return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
            };
            allocation.growth_table_frames.push(frame);
        }
        Ok(retained_len)
    }

    fn insert_private_mapping(
        state: &mut ApplicationPrivateMemory,
        mapping: ApplicationPrivateMapping,
    ) -> Result<(), PrivateMemoryError> {
        state
            .mappings
            .try_reserve(1)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
        let index = state
            .mappings
            .binary_search_by_key(&mapping.range.start(), |current| current.range.start())
            .unwrap_or_else(|index| index);
        state.mappings.insert(index, mapping);
        Ok(())
    }

    fn private_extent_slice(
        extents: &[PhysicalRange],
        start_page: u64,
        page_count: u64,
    ) -> Result<Vec<PhysicalRange>, PrivateMemoryError> {
        let wanted_end = start_page
            .checked_add(page_count)
            .ok_or(PrivateMemoryError::Terminal)?;
        let mut result = Vec::new();
        let mut logical_start = 0_u64;
        for extent in extents {
            let logical_end = logical_start
                .checked_add(extent.page_count())
                .ok_or(PrivateMemoryError::Terminal)?;
            let overlap_start = logical_start.max(start_page);
            let overlap_end = logical_end.min(wanted_end);
            if overlap_start < overlap_end {
                result
                    .try_reserve(1)
                    .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
                result.push(
                    PhysicalRange::from_pages(
                        extent
                            .start()
                            .checked_add(
                                overlap_start
                                    .checked_sub(logical_start)
                                    .ok_or(PrivateMemoryError::Terminal)?
                                    .checked_mul(BASE_PAGE_SIZE)
                                    .ok_or(PrivateMemoryError::Terminal)?,
                            )
                            .ok_or(PrivateMemoryError::Terminal)?,
                        overlap_end
                            .checked_sub(overlap_start)
                            .ok_or(PrivateMemoryError::Terminal)?,
                    )
                    .map_err(|_| PrivateMemoryError::Terminal)?,
                );
            }
            logical_start = logical_end;
        }
        let represented = result.iter().try_fold(0_u64, |pages, extent| {
            pages.checked_add(extent.page_count())
        });
        if represented != Some(page_count) {
            return Err(PrivateMemoryError::Terminal);
        }
        Ok(result)
    }

    fn private_subrange(
        range: VirtualRange,
        start_page: u64,
        page_count: u64,
    ) -> Result<VirtualRange, PrivateMemoryError> {
        let byte_offset = start_page
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(PrivateMemoryError::Terminal)?;
        VirtualRange::from_pages(
            range
                .start()
                .checked_add(byte_offset)
                .ok_or(PrivateMemoryError::Terminal)?,
            page_count,
        )
        .map_err(|_| PrivateMemoryError::Terminal)
    }

    fn private_backing_slice(
        mapping: &ApplicationPrivateMapping,
        start_page: u64,
        page_count: u64,
    ) -> Result<Vec<PhysicalRange>, PrivateMemoryError> {
        if mapping.backing.is_empty() {
            Ok(Vec::new())
        } else {
            private_extent_slice(&mapping.backing, start_page, page_count)
        }
    }

    fn split_private_mapping(
        mapping: &ApplicationPrivateMapping,
        address: u64,
        page_count: u64,
        middle_protection: Option<private_memory::Protection>,
        new_middle_backing: Option<Vec<PhysicalRange>>,
    ) -> Result<(Vec<ApplicationPrivateMapping>, Vec<PhysicalRange>), PrivateMemoryError> {
        let request = VirtualRange::from_pages(address, page_count)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
        if request.start() < mapping.range.start() || request.end() > mapping.range.end() {
            return Err(PrivateMemoryError::Reply(ReplyStatus::NotFound));
        }
        let before_pages = request
            .start()
            .checked_sub(mapping.range.start())
            .and_then(|bytes| bytes.checked_div(BASE_PAGE_SIZE))
            .ok_or(PrivateMemoryError::Terminal)?;
        let after_pages = mapping
            .range
            .page_count()
            .checked_sub(before_pages)
            .and_then(|pages| pages.checked_sub(page_count))
            .ok_or(PrivateMemoryError::Terminal)?;
        if new_middle_backing.is_some() && !mapping.backing.is_empty() {
            return Err(PrivateMemoryError::Terminal);
        }
        let mut replacements = Vec::new();
        replacements
            .try_reserve_exact(usize::from(before_pages != 0) + usize::from(after_pages != 0) + 1)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
        if before_pages != 0 {
            replacements.push(ApplicationPrivateMapping {
                range: private_subrange(mapping.range, 0, before_pages)?,
                protection: mapping.protection,
                backing: private_backing_slice(mapping, 0, before_pages)?,
            });
        }
        let existing_middle = private_backing_slice(mapping, before_pages, page_count)?;
        let (middle_backing, removed) = if middle_protection.is_some() {
            (
                Some(new_middle_backing.unwrap_or(existing_middle)),
                Vec::new(),
            )
        } else {
            (None, existing_middle)
        };
        if let Some(protection) = middle_protection {
            replacements.push(ApplicationPrivateMapping {
                range: request,
                protection,
                backing: middle_backing.ok_or(PrivateMemoryError::Terminal)?,
            });
        }
        if after_pages != 0 {
            replacements.push(ApplicationPrivateMapping {
                range: private_subrange(
                    mapping.range,
                    before_pages
                        .checked_add(page_count)
                        .ok_or(PrivateMemoryError::Terminal)?,
                    after_pages,
                )?,
                protection: mapping.protection,
                backing: private_backing_slice(
                    mapping,
                    before_pages
                        .checked_add(page_count)
                        .ok_or(PrivateMemoryError::Terminal)?,
                    after_pages,
                )?,
            });
        }
        Ok((replacements, removed))
    }

    fn private_replacement_metadata(
        state: &ApplicationPrivateMemory,
        index: usize,
        replacements: &[ApplicationPrivateMapping],
    ) -> Result<(u64, u64), PrivateMemoryError> {
        let old = state
            .mappings
            .get(index)
            .ok_or(PrivateMemoryError::Terminal)?;
        let mapping_count = u64::try_from(state.mappings.len())
            .map_err(|_| PrivateMemoryError::Terminal)?
            .checked_sub(1)
            .and_then(|count| count.checked_add(u64::try_from(replacements.len()).ok()?))
            .ok_or(PrivateMemoryError::Terminal)?;
        let old_extent_bytes = u64::try_from(old.backing.len())
            .map_err(|_| PrivateMemoryError::Terminal)?
            .checked_mul(
                u64::try_from(core::mem::size_of::<PhysicalRange>())
                    .map_err(|_| PrivateMemoryError::Terminal)?,
            )
            .ok_or(PrivateMemoryError::Terminal)?;
        let replacement_extent_count = replacements.iter().try_fold(0_u64, |count, mapping| {
            count.checked_add(u64::try_from(mapping.backing.len()).ok()?)
        });
        let replacement_extent_bytes = replacement_extent_count
            .ok_or(PrivateMemoryError::Terminal)?
            .checked_mul(
                u64::try_from(core::mem::size_of::<PhysicalRange>())
                    .map_err(|_| PrivateMemoryError::Terminal)?,
            )
            .ok_or(PrivateMemoryError::Terminal)?;
        let mapping_bytes = mapping_count
            .checked_mul(
                u64::try_from(core::mem::size_of::<ApplicationPrivateMapping>())
                    .map_err(|_| PrivateMemoryError::Terminal)?,
            )
            .ok_or(PrivateMemoryError::Terminal)?;
        let current_extent_bytes = state
            .metadata_bytes
            .checked_sub(
                u64::try_from(state.mappings.len())
                    .map_err(|_| PrivateMemoryError::Terminal)?
                    .checked_mul(
                        u64::try_from(core::mem::size_of::<ApplicationPrivateMapping>())
                            .map_err(|_| PrivateMemoryError::Terminal)?,
                    )
                    .ok_or(PrivateMemoryError::Terminal)?,
            )
            .ok_or(PrivateMemoryError::Terminal)?;
        let metadata_bytes = current_extent_bytes
            .checked_sub(old_extent_bytes)
            .and_then(|bytes| bytes.checked_add(replacement_extent_bytes))
            .and_then(|bytes| bytes.checked_add(mapping_bytes))
            .ok_or(PrivateMemoryError::Terminal)?;
        Ok((mapping_count, metadata_bytes))
    }

    fn install_private_replacements(
        state: &mut ApplicationPrivateMemory,
        index: usize,
        replacements: Vec<ApplicationPrivateMapping>,
    ) -> Result<(), PrivateMemoryError> {
        let additional = replacements.len().saturating_sub(1);
        state
            .mappings
            .try_reserve(additional)
            .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
        let _removed = state.mappings.remove(index);
        for (offset, replacement) in replacements.into_iter().enumerate() {
            state.mappings.insert(index + offset, replacement);
        }
        Ok(())
    }

    fn coalesce_private_mappings(
        state: &mut ApplicationPrivateMemory,
    ) -> Result<(), PrivateMemoryError> {
        let mut index = 1_usize;
        while index < state.mappings.len() {
            let left_index = index - 1;
            let compatible = {
                let left = &state.mappings[left_index];
                let right = &state.mappings[index];
                left.range.end() == right.range.start()
                    && left.protection == right.protection
                    && left.backing.is_empty() == right.backing.is_empty()
            };
            if !compatible {
                index = index.checked_add(1).ok_or(PrivateMemoryError::Terminal)?;
                continue;
            }
            let merged_range = {
                let left = &state.mappings[left_index];
                let right = &state.mappings[index];
                VirtualRange::from_pages(
                    left.range.start(),
                    left.range
                        .page_count()
                        .checked_add(right.range.page_count())
                        .ok_or(PrivateMemoryError::Terminal)?,
                )
                .map_err(|_| PrivateMemoryError::Terminal)?
            };
            let boundary_merges = state.mappings[left_index]
                .backing
                .last()
                .zip(state.mappings[index].backing.first())
                .is_some_and(|(left, right)| left.end() == right.start());
            let additional_extents = state.mappings[index]
                .backing
                .len()
                .saturating_sub(usize::from(boundary_merges));
            if state.mappings[left_index]
                .backing
                .try_reserve(additional_extents)
                .is_err()
            {
                index = index.checked_add(1).ok_or(PrivateMemoryError::Terminal)?;
                continue;
            }
            let right = state.mappings.remove(index);
            let left = &mut state.mappings[left_index];
            left.range = merged_range;
            let mut skip = 0_usize;
            if boundary_merges {
                let left_extent = left
                    .backing
                    .last_mut()
                    .ok_or(PrivateMemoryError::Terminal)?;
                let right_extent = right.backing.first().ok_or(PrivateMemoryError::Terminal)?;
                *left_extent = PhysicalRange::from_pages(
                    left_extent.start(),
                    left_extent
                        .page_count()
                        .checked_add(right_extent.page_count())
                        .ok_or(PrivateMemoryError::Terminal)?,
                )
                .map_err(|_| PrivateMemoryError::Terminal)?;
                skip = 1;
            }
            left.backing.extend_from_slice(&right.backing[skip..]);
        }
        Ok(())
    }

    fn private_address_reply(address: u64) -> Result<Vec<u8>, PrivateMemoryError> {
        let encoded =
            private_memory::encode_address(address).map_err(|_| PrivateMemoryError::Terminal)?;
        owned_reply_payload(&encoded)
            .map_err(|()| PrivateMemoryError::Reply(ReplyStatus::Exhausted))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn handle_private_memory_call(
        accounting: &mut OwnedAccounting,
        allocation: &mut ApplicationAllocation,
        application: &mut troe_machine::ApplicationSession,
        heap_start: u64,
        opcode: u16,
        payload: &[u8],
    ) -> Result<PrivateMemoryReply, PrivateMemoryError> {
        if opcode == private_memory::QUERY {
            if !payload.is_empty() {
                return Err(PrivateMemoryError::Reply(ReplyStatus::InvalidRequest));
            }
            let encoded = private_memory::encode_statistics(allocation.private_memory.statistics())
                .map_err(|_| PrivateMemoryError::Terminal)?;
            return Ok(PrivateMemoryReply {
                status: ReplyStatus::Success,
                payload: owned_reply_payload(&encoded)
                    .map_err(|()| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?,
                resources_changed: false,
            });
        }

        if matches!(opcode, private_memory::RESERVE | private_memory::MAP_ZEROED) {
            let request = private_memory::decode_map_request(payload)
                .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
            if opcode == private_memory::RESERVE
                && request.protection != private_memory::Protection::None
            {
                return Err(PrivateMemoryError::Reply(ReplyStatus::InvalidRequest));
            }
            let floor = private_heap_end(allocation, heap_start)?;
            let range = choose_private_range(
                &allocation.private_memory,
                floor,
                request,
                &accounting.random,
            )?;
            let address_reply = private_address_reply(range.start())?;
            allocation
                .private_memory
                .mappings
                .try_reserve(1)
                .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
            let mut backing = Vec::new();
            if opcode == private_memory::MAP_ZEROED {
                let minimum_free = accounting.memory_policy.minimum_free_pages();
                let available = accounting.frames.free_frames().saturating_sub(minimum_free);
                if request.page_count > available {
                    return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
                }
                backing = allocate_private_extents(
                    &mut accounting.frames,
                    request.page_count,
                    accounting.memory_policy.operation_quantum_pages(),
                )?;
            }
            let retained_tables = if opcode == private_memory::MAP_ZEROED
                && request.protection != private_memory::Protection::None
            {
                match reserve_private_table_frames(
                    &mut accounting.frames,
                    allocation,
                    application,
                    range.start(),
                    range.page_count(),
                    accounting.memory_policy.minimum_free_pages(),
                ) {
                    Ok(retained) => Some(retained),
                    Err(error) => {
                        release_private_extents(&mut accounting.frames, &backing)?;
                        return Err(error);
                    }
                }
            } else {
                None
            };
            let mapping = ApplicationPrivateMapping {
                range,
                protection: request.protection,
                backing,
            };
            insert_private_mapping(&mut allocation.private_memory, mapping)?;
            let reserved = allocation
                .private_memory
                .reserved_pages
                .checked_add(request.page_count)
                .ok_or(PrivateMemoryError::Terminal)?;
            let committed = allocation
                .private_memory
                .committed_pages
                .checked_add(u64::from(opcode == private_memory::MAP_ZEROED) * request.page_count)
                .ok_or(PrivateMemoryError::Terminal)?;
            let metadata = private_metadata_bytes(&allocation.private_memory.mappings)
                .ok_or(PrivateMemoryError::Terminal)?;
            let mapping_count = u64::try_from(allocation.private_memory.mappings.len())
                .map_err(|_| PrivateMemoryError::Terminal)?;
            if let Err(error) = private_policy_allows(
                accounting,
                allocation,
                reserved,
                committed,
                mapping_count,
                metadata,
            ) {
                let mapping = allocation.private_memory.mappings.remove(
                    allocation
                        .private_memory
                        .mappings
                        .iter()
                        .position(|mapping| mapping.range == range)
                        .ok_or(PrivateMemoryError::Terminal)?,
                );
                release_private_extents(&mut accounting.frames, &mapping.backing)?;
                if let Some(retained) = retained_tables {
                    while allocation.growth_table_frames.len() > retained {
                        let frame = allocation
                            .growth_table_frames
                            .pop()
                            .ok_or(PrivateMemoryError::Terminal)?;
                        accounting
                            .frames
                            .free(frame)
                            .map_err(|_| PrivateMemoryError::Terminal)?;
                    }
                }
                return Err(error);
            }
            commit_private_accounting(
                accounting,
                &mut allocation.private_memory,
                reserved,
                committed,
                metadata,
            )?;
            if opcode == private_memory::MAP_ZEROED
                && request.protection != private_memory::Protection::None
            {
                let mapping = allocation
                    .private_memory
                    .mappings
                    .iter()
                    .find(|mapping| mapping.range == range)
                    .ok_or(PrivateMemoryError::Terminal)?;
                application
                    .replace_private_access(
                        range.start(),
                        &mapping.backing,
                        false,
                        private_permissions(request.protection),
                        &allocation.growth_table_frames,
                    )
                    .map_err(|_| PrivateMemoryError::Terminal)?;
            }
            return Ok(PrivateMemoryReply {
                status: ReplyStatus::Success,
                payload: address_reply,
                resources_changed: opcode == private_memory::MAP_ZEROED,
            });
        }

        if opcode == private_memory::PROTECT {
            let request = private_memory::decode_protect_request(payload)
                .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
            let request_range = VirtualRange::from_pages(request.address, request.page_count)
                .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
            let index = allocation
                .private_memory
                .mappings
                .iter()
                .position(|mapping| {
                    mapping.range.start() <= request_range.start()
                        && request_range.end() <= mapping.range.end()
                })
                .ok_or(PrivateMemoryError::Reply(ReplyStatus::NotFound))?;
            let old_protection = allocation.private_memory.mappings[index].protection;
            if old_protection == request.protection {
                return Ok(PrivateMemoryReply {
                    status: ReplyStatus::Success,
                    payload: Vec::new(),
                    resources_changed: false,
                });
            }
            let needs_backing = allocation.private_memory.mappings[index].backing.is_empty()
                && request.protection != private_memory::Protection::None;
            let (mut replacements, removed) = split_private_mapping(
                &allocation.private_memory.mappings[index],
                request.address,
                request.page_count,
                Some(request.protection),
                None,
            )?;
            if !removed.is_empty() {
                return Err(PrivateMemoryError::Terminal);
            }
            let middle = replacements
                .iter()
                .position(|mapping| mapping.range == request_range)
                .ok_or(PrivateMemoryError::Terminal)?;
            if needs_backing {
                let available = accounting
                    .frames
                    .free_frames()
                    .saturating_sub(accounting.memory_policy.minimum_free_pages());
                if request.page_count > available {
                    return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
                }
                replacements[middle].backing = allocate_private_extents(
                    &mut accounting.frames,
                    request.page_count,
                    accounting.memory_policy.operation_quantum_pages(),
                )?;
            }
            let committed = allocation
                .private_memory
                .committed_pages
                .checked_add(u64::from(needs_backing) * request.page_count)
                .ok_or(PrivateMemoryError::Terminal)?;
            let (mapping_count, metadata) =
                private_replacement_metadata(&allocation.private_memory, index, &replacements)?;
            if let Err(error) = private_policy_allows(
                accounting,
                allocation,
                allocation.private_memory.reserved_pages,
                committed,
                mapping_count,
                metadata,
            ) {
                if needs_backing {
                    release_private_extents(&mut accounting.frames, &replacements[middle].backing)?;
                }
                return Err(error);
            }
            let additional = replacements.len().saturating_sub(1);
            if allocation
                .private_memory
                .mappings
                .try_reserve(additional)
                .is_err()
            {
                if needs_backing {
                    release_private_extents(&mut accounting.frames, &replacements[middle].backing)?;
                }
                return Err(PrivateMemoryError::Reply(ReplyStatus::Exhausted));
            }
            let retained_tables = if request.protection == private_memory::Protection::None {
                None
            } else {
                match reserve_private_table_frames(
                    &mut accounting.frames,
                    allocation,
                    application,
                    request.address,
                    request.page_count,
                    accounting.memory_policy.minimum_free_pages(),
                ) {
                    Ok(retained) => Some(retained),
                    Err(error) => {
                        if needs_backing {
                            release_private_extents(
                                &mut accounting.frames,
                                &replacements[middle].backing,
                            )?;
                        }
                        return Err(error);
                    }
                }
            };
            if !replacements[middle].backing.is_empty()
                && application
                    .replace_private_access(
                        request.address,
                        &replacements[middle].backing,
                        !allocation.private_memory.mappings[index].backing.is_empty()
                            && old_protection != private_memory::Protection::None,
                        private_permissions(request.protection),
                        &allocation.growth_table_frames,
                    )
                    .is_err()
            {
                if let Some(retained) = retained_tables {
                    while allocation.growth_table_frames.len() > retained {
                        let frame = allocation
                            .growth_table_frames
                            .pop()
                            .ok_or(PrivateMemoryError::Terminal)?;
                        accounting
                            .frames
                            .free(frame)
                            .map_err(|_| PrivateMemoryError::Terminal)?;
                    }
                }
                if needs_backing {
                    release_private_extents(&mut accounting.frames, &replacements[middle].backing)?;
                }
                return Err(PrivateMemoryError::Terminal);
            }
            install_private_replacements(&mut allocation.private_memory, index, replacements)?;
            coalesce_private_mappings(&mut allocation.private_memory)?;
            let metadata = private_metadata_bytes(&allocation.private_memory.mappings)
                .ok_or(PrivateMemoryError::Terminal)?;
            let reserved = allocation.private_memory.reserved_pages;
            commit_private_accounting(
                accounting,
                &mut allocation.private_memory,
                reserved,
                committed,
                metadata,
            )?;
            return Ok(PrivateMemoryReply {
                status: ReplyStatus::Success,
                payload: Vec::new(),
                resources_changed: needs_backing,
            });
        }

        if opcode == private_memory::UNMAP {
            let request = private_memory::decode_unmap_request(payload)
                .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
            let request_range = VirtualRange::from_pages(request.address, request.page_count)
                .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))?;
            let index = allocation
                .private_memory
                .mappings
                .iter()
                .position(|mapping| {
                    mapping.range.start() <= request_range.start()
                        && request_range.end() <= mapping.range.end()
                })
                .ok_or(PrivateMemoryError::Reply(ReplyStatus::NotFound))?;
            let old_protection = allocation.private_memory.mappings[index].protection;
            let (replacements, removed_backing) = split_private_mapping(
                &allocation.private_memory.mappings[index],
                request.address,
                request.page_count,
                None,
                None,
            )?;
            let committed_removed = removed_backing
                .iter()
                .try_fold(0_u64, |total, range| total.checked_add(range.page_count()))
                .ok_or(PrivateMemoryError::Terminal)?;
            let reserved = allocation
                .private_memory
                .reserved_pages
                .checked_sub(request.page_count)
                .ok_or(PrivateMemoryError::Terminal)?;
            let committed = allocation
                .private_memory
                .committed_pages
                .checked_sub(committed_removed)
                .ok_or(PrivateMemoryError::Terminal)?;
            let (mapping_count, metadata) =
                private_replacement_metadata(&allocation.private_memory, index, &replacements)?;
            private_policy_allows(
                accounting,
                allocation,
                reserved,
                committed,
                mapping_count,
                metadata,
            )?;
            allocation
                .private_memory
                .mappings
                .try_reserve(replacements.len().saturating_sub(1))
                .map_err(|_| PrivateMemoryError::Reply(ReplyStatus::Exhausted))?;
            if !removed_backing.is_empty() && old_protection != private_memory::Protection::None {
                application
                    .replace_private_access(
                        request.address,
                        &removed_backing,
                        true,
                        None,
                        &allocation.growth_table_frames,
                    )
                    .map_err(|_| PrivateMemoryError::Terminal)?;
            }
            install_private_replacements(&mut allocation.private_memory, index, replacements)?;
            release_private_extents(&mut accounting.frames, &removed_backing)?;
            coalesce_private_mappings(&mut allocation.private_memory)?;
            let metadata = private_metadata_bytes(&allocation.private_memory.mappings)
                .ok_or(PrivateMemoryError::Terminal)?;
            commit_private_accounting(
                accounting,
                &mut allocation.private_memory,
                reserved,
                committed,
                metadata,
            )?;
            return Ok(PrivateMemoryReply {
                status: ReplyStatus::Success,
                payload: Vec::new(),
                resources_changed: committed_removed != 0,
            });
        }

        Err(PrivateMemoryError::Reply(ReplyStatus::InvalidRequest))
    }

    fn application_resource_totals(
        allocation: &ApplicationAllocation,
        initial_private_pages: u64,
    ) -> Result<(u64, u64), ()> {
        let table_pages = allocation
            .tables
            .page_count()
            .checked_add(u64::try_from(allocation.growth_table_frames.len()).map_err(|_| ())?)
            .ok_or(())?;
        let private_pages = initial_private_pages
            .checked_add(application_growth_pages(allocation)?)
            .and_then(|value| value.checked_add(allocation.private_memory.committed_pages))
            .ok_or(())?;
        Ok((table_pages, private_pages))
    }
    #[allow(clippy::too_many_lines)]
    fn commit_application_heap_growth(
        accounting: &mut OwnedAccounting,
        allocation: &mut ApplicationAllocation,
        application: &mut troe_machine::ApplicationSession,
        heap_start: u64,
        maximum_heap_pages: u64,
        minimum_pages: u64,
    ) -> Result<ApplicationGrowth, ()> {
        let initial_pages = allocation.heap_pages;
        let current_pages = initial_pages
            .checked_add(application_growth_pages(allocation)?)
            .ok_or(())?;
        let private_ceiling_pages = allocation
            .private_memory
            .mappings
            .first()
            .map_or(maximum_heap_pages, |mapping| {
                mapping.range.start().saturating_sub(heap_start) / BASE_PAGE_SIZE
            });
        let maximum_heap_pages = maximum_heap_pages.min(private_ceiling_pages);
        let remaining = maximum_heap_pages.checked_sub(current_pages).ok_or(())?;
        if minimum_pages == 0 || minimum_pages > remaining {
            return Ok(ApplicationGrowth::Exhausted);
        }
        if allocation.growth_ranges.try_reserve(1).is_err() {
            return Ok(ApplicationGrowth::Exhausted);
        }
        let heap_virtual_start = heap_start
            .checked_add(current_pages.checked_mul(BASE_PAGE_SIZE).ok_or(())?)
            .ok_or(())?;
        let required_new_tables = additional_table_pages(heap_virtual_start, minimum_pages)?;
        let retained_table_pages = allocation
            .tables
            .page_count()
            .checked_add(u64::try_from(allocation.growth_table_frames.len()).map_err(|_| ())?)
            .ok_or(())?;
        let available_table_pages = retained_table_pages
            .checked_sub(application.stats().table_pages)
            .ok_or(())?;
        let table_deficit = required_new_tables.saturating_sub(available_table_pages);
        let table_deficit = usize::try_from(table_deficit).map_err(|_| ())?;
        if allocation
            .growth_table_frames
            .try_reserve_exact(table_deficit)
            .is_err()
        {
            return Ok(ApplicationGrowth::Exhausted);
        }
        let needed_frames = minimum_pages
            .checked_add(u64::try_from(table_deficit).map_err(|_| ())?)
            .ok_or(())?;
        let application_commit = accounting
            .application_committed_pages
            .checked_add(minimum_pages)
            .ok_or(())?;
        let process_commit = allocation
            .extents
            .page_count()
            .checked_add(application_growth_pages(allocation)?)
            .and_then(|pages| pages.checked_add(allocation.private_memory.committed_pages))
            .and_then(|pages| pages.checked_add(minimum_pages))
            .ok_or(())?;
        if accounting
            .memory_policy
            .system_application_commit()
            .maximum()
            .is_some_and(|maximum| application_commit > maximum)
            || allocation
                .private_memory
                .maximum_committed_pages
                .is_some_and(|maximum| process_commit > maximum)
            || needed_frames
                > accounting
                    .frames
                    .free_frames()
                    .saturating_sub(accounting.memory_policy.minimum_free_pages())
        {
            return Ok(ApplicationGrowth::Exhausted);
        }
        let start = allocation.growth_ranges.len();
        let table_start = allocation.growth_table_frames.len();
        for _ in 0..table_deficit {
            let Ok(frame) = accounting.frames.allocate() else {
                release_application_growth_suffix(
                    &mut accounting.frames,
                    allocation,
                    start,
                    table_start,
                )?;
                return Ok(ApplicationGrowth::Exhausted);
            };
            allocation.growth_table_frames.push(frame);
        }
        match accounting.frames.allocate_contiguous(minimum_pages, 1) {
            Ok(range) => {
                if troe_machine::zero_physical_range(range).is_err() {
                    accounting.frames.free_range(range).map_err(|_| ())?;
                    release_application_growth_suffix(
                        &mut accounting.frames,
                        allocation,
                        start,
                        table_start,
                    )?;
                    return Err(());
                }
                allocation.growth_ranges.push(range);
            }
            Err(FrameAllocationError::Exhausted) => {
                for _ in 0..minimum_pages {
                    let Ok(frame) = accounting.frames.allocate() else {
                        release_application_growth_suffix(
                            &mut accounting.frames,
                            allocation,
                            start,
                            table_start,
                        )?;
                        return Ok(ApplicationGrowth::Exhausted);
                    };
                    let range = PhysicalRange::from_pages(frame, 1).map_err(|_| ())?;
                    if troe_machine::zero_physical_range(range).is_err() {
                        accounting.frames.free(frame).map_err(|_| ())?;
                        release_application_growth_suffix(
                            &mut accounting.frames,
                            allocation,
                            start,
                            table_start,
                        )?;
                        return Err(());
                    }
                    if !append_application_growth_frame(allocation, start, frame)? {
                        accounting.frames.free(frame).map_err(|_| ())?;
                        release_application_growth_suffix(
                            &mut accounting.frames,
                            allocation,
                            start,
                            table_start,
                        )?;
                        return Ok(ApplicationGrowth::Exhausted);
                    }
                }
            }
            Err(_) => {
                release_application_growth_suffix(
                    &mut accounting.frames,
                    allocation,
                    start,
                    table_start,
                )?;
                return Err(());
            }
        }
        let new_ranges = &allocation.growth_ranges[start..];
        let Ok(stats) =
            application.commit_heap_growth(heap_start, new_ranges, &allocation.growth_table_frames)
        else {
            release_application_growth_suffix(
                &mut accounting.frames,
                allocation,
                start,
                table_start,
            )?;
            return Err(());
        };
        accounting.application_committed_pages = application_commit;
        let mapped_pages = current_pages.checked_add(minimum_pages).ok_or(())?;
        let mapped_bytes = mapped_pages.checked_mul(BASE_PAGE_SIZE).ok_or(())?;
        Ok(ApplicationGrowth::Committed {
            stats,
            mapped_bytes,
        })
    }

    fn release_application_growth_suffix(
        frames: &mut FrameAllocator,
        allocation: &mut ApplicationAllocation,
        retained: usize,
        retained_tables: usize,
    ) -> Result<(), ()> {
        while allocation.growth_ranges.len() > retained {
            let range = *allocation.growth_ranges.last().ok_or(())?;
            troe_machine::zero_physical_range(range).map_err(|_| ())?;
            frames.free_range(range).map_err(|_| ())?;
            allocation.growth_ranges.pop();
        }
        while allocation.growth_table_frames.len() > retained_tables {
            let frame = *allocation.growth_table_frames.last().ok_or(())?;
            let range = PhysicalRange::from_pages(frame, 1).map_err(|_| ())?;
            troe_machine::zero_physical_range(range).map_err(|_| ())?;
            frames.free(frame).map_err(|_| ())?;
            allocation.growth_table_frames.pop();
        }
        Ok(())
    }

    fn application_growth_pages(allocation: &ApplicationAllocation) -> Result<u64, ()> {
        allocation
            .growth_ranges
            .iter()
            .try_fold(0_u64, |pages, range| pages.checked_add(range.page_count()))
            .ok_or(())
    }

    fn append_application_growth_frame(
        allocation: &mut ApplicationAllocation,
        request_start: usize,
        frame: u64,
    ) -> Result<bool, ()> {
        if allocation.growth_ranges.len() > request_start {
            let last = allocation.growth_ranges.last_mut().ok_or(())?;
            if last.end() == frame {
                *last = PhysicalRange::from_pages(last.start(), last.page_count() + 1)
                    .map_err(|_| ())?;
                return Ok(true);
            }
        }
        if allocation.growth_ranges.try_reserve(1).is_err() {
            return Ok(false);
        }
        allocation
            .growth_ranges
            .push(PhysicalRange::from_pages(frame, 1).map_err(|_| ())?);
        Ok(true)
    }

    fn additional_table_pages(virtual_start: u64, page_count: u64) -> Result<u64, ()> {
        let start_page = virtual_start / BASE_PAGE_SIZE;
        let end_page = start_page.checked_add(page_count).ok_or(())?;
        if start_page == 0 || end_page <= start_page {
            return Err(());
        }
        [512_u64, 512 * 512, 512 * 512 * 512]
            .into_iter()
            .try_fold(0_u64, |total, coverage| {
                let before = (start_page - 1) / coverage;
                let after = (end_page - 1) / coverage;
                total.checked_add(after.checked_sub(before)?)
            })
            .ok_or(())
    }

    /// Reserve one launch's private frames and zero them in bounded substeps.
    ///
    /// The reservation is a sequence of extents rather than one contiguous run,
    /// so a large application launches on a fragmented machine instead of being
    /// refused for want of one long free span. Each quantum is zeroed as it is
    /// taken, so no substep scales with the total request and no derived range
    /// is ever published over frames that still hold a previous owner's bytes.
    fn reserve_zeroed_private_extents(
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
    fn release_launch_extents(
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
    fn write_launch_bytes(
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
    fn write_segment_bytes<P: NativeApplicationPlan>(
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
    fn map_launch_region(
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
    fn allocate_application<P: NativeApplicationPlan>(
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

    fn prepare_application_memory(
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

    fn prepare_streamed_application_memory(
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
    fn segment_logical_offset<P: NativeApplicationPlan>(
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

    fn apply_application_relocation<P: NativeApplicationPlan>(
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

    fn build_application_plan<P: NativeApplicationPlan>(
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
        accounting: &mut OwnedAccounting,
        allocation: ApplicationAllocation,
    ) -> Result<(), ()> {
        terminate_revoke_and_reap_task(scheduler, task_id, dispatcher, owner)?;
        reclaim_application(accounting, allocation)
    }

    fn rollback_command_application_task(
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

    fn reclaim_command_application(
        accounting: &mut OwnedAccounting,
        allocation: ApplicationAllocation,
    ) {
        if reclaim_application(accounting, allocation).is_err() {
            fatal(b"fatal: application reclaim invariant failed\n");
        }
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

    fn native_diagnostics_server_artifact() -> (&'static [u8], bool) {
        #[cfg(feature = "acceptance-probes")]
        if DIAGNOSTICS_FAULT_PROBE_REQUESTED.swap(false, Ordering::AcqRel) {
            #[cfg(target_arch = "x86_64")]
            {
                return (
                    include_bytes!("../../tests/kex-corpus/x86_64/diagnostics-fault-server.kex"),
                    true,
                );
            }
            #[cfg(target_arch = "aarch64")]
            {
                return (
                    include_bytes!("../../tests/kex-corpus/aarch64/diagnostics-fault-server.kex"),
                    true,
                );
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            (
                include_bytes!("../../tests/kex-corpus/x86_64/diagnostics-server.kex"),
                false,
            )
        }
        #[cfg(target_arch = "aarch64")]
        {
            (
                include_bytes!("../../tests/kex-corpus/aarch64/diagnostics-server.kex"),
                false,
            )
        }
    }

    #[cfg(feature = "acceptance-probes")]
    fn native_diagnostics_benchmark_artifact() -> &'static [u8] {
        #[cfg(target_arch = "x86_64")]
        {
            include_bytes!("../../tests/kex-corpus/x86_64/diagnostics-benchmark-server.kex")
        }
        #[cfg(target_arch = "aarch64")]
        {
            include_bytes!("../../tests/kex-corpus/aarch64/diagnostics-benchmark-server.kex")
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
            ApplicationProbe::HeapGrowthLimit => {
                #[cfg(target_arch = "x86_64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-heap-growth-limit-x86_64.kex")
                }
                #[cfg(target_arch = "aarch64")]
                {
                    include_bytes!("../../tests/kex-corpus/native-heap-growth-limit-aarch64.kex")
                }
            }
            #[cfg(all(feature = "acceptance-probes", target_arch = "aarch64"))]
            ApplicationProbe::ThreadPointer => {
                include_bytes!("../../tests/kex-corpus/native-thread-pointer-aarch64.kex")
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

    #[derive(Clone, Copy)]
    enum NativeRootMode {
        Recovery,
        ReadOnly,
        ReadWrite,
    }

    impl NativeRootMode {
        const fn summary(self) -> &'static str {
            match self {
                Self::Recovery => "recovery root (read-only)",
                Self::ReadOnly => "/vol/root (read-only)",
                Self::ReadWrite => "/vol/root (read-write)",
            }
        }

        const fn boot_label(self) -> &'static str {
            match self {
                Self::Recovery => "Mounting recovery root read-only",
                Self::ReadOnly => "Mounting /vol/root read-only",
                Self::ReadWrite => "Mounting /vol/root read-write",
            }
        }
    }

    fn write_shell_banner(
        console: &mut dyn Output,
        motd: &[u8],
        root_mode: NativeRootMode,
        network: Option<NetworkStatus>,
    ) -> bool {
        if write_all(console, b"\n").is_err()
            || write_all(console, motd).is_err()
            || !motd.ends_with(b"\n") && write_all(console, b"\n").is_err()
            || write_all(console, b"\n").is_err()
        {
            return false;
        }

        let mut summary = String::new();
        let _formatted = write!(
            &mut summary,
            "{} | {} | ",
            architecture(),
            root_mode.summary()
        );
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
    ) -> NativeRootMode {
        let limits = native_activation_limits()
            .unwrap_or_else(|()| fatal(b"fatal: invalid native storage limits\n"));
        let devices = core::mem::take(&mut *accounting.native_blocks.borrow_mut());
        let activation = prepare_mounts(&accounting.boot_mount_manifest, devices, limits)
            .unwrap_or_else(|_| fatal(b"fatal: native storage activation failed\n"));
        let desired_system_available = activation.desired_system_available();
        let root_mode = activation
            .mounts()
            .iter()
            .find(|mount| mount.path() == "/vol/root")
            .map_or(NativeRootMode::Recovery, |mount| {
                if mount.is_writable() {
                    NativeRootMode::ReadWrite
                } else {
                    NativeRootMode::ReadOnly
                }
            });
        let root_mounted = !matches!(root_mode, NativeRootMode::Recovery);
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
        accounting
            .runtime_mounts
            .borrow_mut()
            .configure(
                &accounting.boot_mount_manifest,
                activation.into_mounts(),
                namespace,
            )
            .unwrap_or_else(|()| fatal(b"fatal: cannot configure native mount registry\n"));
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
            if write_boot_status(console, root_mode.boot_label(), true).is_err() {
                fatal(b"fatal: native storage diagnostic failed\n");
            }
            root_mode
        } else {
            let recovery = NativeRootMode::Recovery;
            if write_boot_status(console, recovery.boot_label(), true).is_err() {
                fatal(b"fatal: native storage diagnostic failed\n");
            }
            recovery
        }
    }

    fn compose_namespace(
        accounting: &OwnedAccounting,
        console: &mut dyn Output,
    ) -> (Namespace, NativeRootMode) {
        let mut namespace = Namespace::new();
        if namespace
            .mount_writable("/tmp", Box::new(RamFs::new(RamFsQuota::default())))
            .is_err()
        {
            fatal(b"fatal: cannot mount the writable filesystem\n");
        }
        let Ok(embedded) = Kefs::parse(ROOTFS) else {
            fatal(b"fatal: cannot mount embedded root\n");
        };
        let embedded = embedded.into_mounts(EMBEDDED_MOUNT_ROOTS);
        for path in embedded.directories {
            if namespace.add_read_only_dir(&path).is_err() {
                fatal(b"fatal: cannot mount embedded root\n");
            }
        }
        for (path, bytes) in embedded.files {
            if namespace.add_read_only_file(&path, &bytes).is_err() {
                fatal(b"fatal: cannot mount embedded root\n");
            }
        }
        for (path, view) in embedded.mounts {
            if namespace.mount_read_only(&path, Box::new(view)).is_err() {
                fatal(b"fatal: cannot mount embedded root\n");
            }
        }
        let root_mode = activate_native_storage(accounting, &mut namespace, console);
        (namespace, root_mode)
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
            let mut tcp = Vec::new();
            tcp.try_reserve_exact(troe_net::MAX_TCP_CONNECTIONS)
                .map_err(|_| NetError::Exhausted)?;
            Ok(Self {
                device,
                configuration: None,
                next_sequence: 1,
                next_port: 49_152,
                next_tcp_port: 49_152,
                next_tcp_id: 1,
                tcp_generation: 0,
                dhcp_generation: 0,
                arp: ArpCache::new(),
                udp: UdpPortTable::new()?,
                dhcp_inbox,
                echo_inbox,
                tcp,
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

        #[allow(clippy::too_many_lines)]
        fn handle_frame(&mut self, frame: &[u8]) -> Result<(), NetworkError> {
            if let Ok(packet) = parse_dhcp(frame) {
                if self.dhcp_inbox.len() < Self::INBOX_CAPACITY {
                    self.dhcp_inbox.push_back(packet);
                }
                return Ok(());
            }
            if let Ok(arp) = parse_arp(frame) {
                self.arp
                    .learn(arp.sender_ip, arp.sender_mac)
                    .map_err(map_network_error)?;
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
                self.arp
                    .learn(echo.source_ip, echo.source_mac)
                    .map_err(map_network_error)?;
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
            if let Ok(segment) = parse_tcp(frame)
                && segment.destination.address() == configuration.address
            {
                let source_mac = MacAddress::new(
                    frame
                        .get(6..12)
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or(NetworkError::Protocol)?,
                )
                .map_err(map_network_error)?;
                self.arp
                    .learn(segment.source.address(), source_mac)
                    .map_err(map_network_error)?;
                if let Some(connection) = self
                    .tcp
                    .iter()
                    .find(|connection| connection.borrow().machine.accepts(segment))
                {
                    let _admission = connection.borrow_mut().machine.on_segment(segment);
                } else {
                    self.stats.ignored_frames = self.stats.ignored_frames.saturating_add(1);
                }
                return Ok(());
            }
            if let Ok(datagram) = parse_udp(frame)
                && datagram.destination_ip == configuration.address
            {
                self.arp
                    .learn(datagram.source_ip, datagram.source_mac)
                    .map_err(map_network_error)?;
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

    impl KernelNetwork {
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
    }

    impl Service for ApplicationInputService<'_> {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != stream::READ {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Ok(requested) = stream::decode_read_request(request.payload()) else {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            };
            let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
            let Ok(mut input) = self.input.try_borrow_mut() else {
                return Ok(ServiceReply::empty(ReplyStatus::Conflict));
            };
            match input.read(&mut bytes[..requested]) {
                Ok(count) if count <= requested => {
                    ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count])
                }
                Ok(_) => Ok(ServiceReply::empty(ReplyStatus::Corrupt)),
                Err(_) => Ok(ServiceReply::empty(ReplyStatus::Failure)),
            }
        }
    }

    impl Service for ApplicationEmptyInputService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != stream::READ
                || stream::decode_read_request(request.payload()).is_err()
            {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            Ok(ServiceReply::empty(ReplyStatus::Success))
        }
    }

    impl Service for ApplicationDiscardOutputService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                stream::WRITE if !request.payload().is_empty() => {
                    Ok(ServiceReply::empty(ReplyStatus::Success))
                }
                stream::SET_CHUNK_SIZE if stream::decode_chunk_size(request.payload()).is_ok() => {
                    Ok(ServiceReply::empty(ReplyStatus::Success))
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationPrivateMemoryService {
        fn call(
            &mut self,
            _request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            Ok(ServiceReply::empty(ReplyStatus::InvalidRequest))
        }
    }

    impl Service for ApplicationRandomService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != random::GET {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Ok(byte_count) = random::decode_request(request.payload()) else {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            };
            let Ok(byte_count) = usize::try_from(byte_count) else {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            };
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(byte_count).is_err() {
                return Ok(ServiceReply::empty(ReplyStatus::Exhausted));
            }
            bytes.resize(byte_count, 0);
            let Ok(mut generator) = self.random.try_borrow_mut() else {
                return Ok(ServiceReply::empty(ReplyStatus::Conflict));
            };
            if generator.fill(&mut bytes).is_err() {
                return Ok(ServiceReply::empty(ReplyStatus::Failure));
            }
            ServiceReply::with_payload(ReplyStatus::Success, &bytes)
        }
    }

    impl Service for ApplicationPipeInputService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != stream::READ {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Ok(maximum) = stream::decode_read_request(request.payload()) else {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            };
            let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
            match self
                .pipes
                .try_borrow_mut()
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?
                .read_endpoint(self.endpoint, &mut bytes[..maximum])
            {
                Ok(count) => ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count]),
                Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
            }
        }
    }

    impl Drop for ApplicationPipeInputService {
        fn drop(&mut self) {
            if let Ok(mut pipes) = self.pipes.try_borrow_mut() {
                let _detached = pipes.detach(self.endpoint);
            }
        }
    }

    impl Service for ApplicationPipeOutputService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                stream::WRITE if !request.payload().is_empty() => match self
                    .pipes
                    .try_borrow_mut()
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?
                    .write_endpoint(self.endpoint, request.payload())
                {
                    Ok(count) if count == request.payload().len() => {
                        Ok(ServiceReply::empty(ReplyStatus::Success))
                    }
                    Ok(_) => Ok(ServiceReply::empty(ReplyStatus::Failure)),
                    Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                },
                stream::SET_CHUNK_SIZE if stream::decode_chunk_size(request.payload()).is_ok() => {
                    Ok(ServiceReply::empty(ReplyStatus::Success))
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Drop for ApplicationPipeOutputService {
        fn drop(&mut self) {
            if let Ok(mut pipes) = self.pipes.try_borrow_mut() {
                let _detached = pipes.detach(self.endpoint);
            }
        }
    }

    impl Service for ApplicationLogService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                stream::WRITE
                    if !request.payload().is_empty()
                        && request.payload().len() <= troe_abi::MAX_SERVICE_PAYLOAD_BYTES =>
                {
                    let Ok(mut log) = self.log.try_borrow_mut() else {
                        return Ok(ServiceReply::empty(ReplyStatus::Conflict));
                    };
                    log.append(request.payload());
                    Ok(ServiceReply::empty(ReplyStatus::Success))
                }
                stream::SET_CHUNK_SIZE => {
                    let Ok(bytes) = stream::decode_chunk_size(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let status = if bytes == 0 {
                        ReplyStatus::InvalidRequest
                    } else {
                        ReplyStatus::Success
                    };
                    Ok(ServiceReply::empty(status))
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationOutputService<'_> {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            let Ok(mut output) = self.output.try_borrow_mut() else {
                return Ok(ServiceReply::empty(ReplyStatus::Conflict));
            };
            match request.opcode() {
                stream::WRITE
                    if !request.payload().is_empty()
                        && request.payload().len() <= troe_abi::MAX_SERVICE_PAYLOAD_BYTES =>
                {
                    let status = if troe_core::write_all(&mut **output, request.payload()).is_ok() {
                        ReplyStatus::Success
                    } else {
                        ReplyStatus::Failure
                    };
                    Ok(ServiceReply::empty(status))
                }
                stream::SET_CHUNK_SIZE => {
                    let Ok(bytes) = stream::decode_chunk_size(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let status = if output.set_chunk_size(bytes).is_ok() {
                        ReplyStatus::Success
                    } else {
                        ReplyStatus::Unsupported
                    };
                    Ok(ServiceReply::empty(status))
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationShellScriptService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != shell_script::SUBMIT_LINE {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Ok(line) = shell_script::decode_submit_line(request.payload()) else {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            };
            if parse_command_list(line.source()).is_err() {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Ok(mut script) = self.script.try_borrow_mut() else {
                return Ok(ServiceReply::empty(ReplyStatus::Conflict));
            };
            let Some(source_bytes) = script.source_bytes.checked_add(line.source().len()) else {
                return Ok(ServiceReply::empty(ReplyStatus::Exhausted));
            };
            if script.lines.len() >= shell_script::MAX_LINES
                || source_bytes > shell_script::MAX_SCRIPT_BYTES
            {
                return Ok(ServiceReply::empty(ReplyStatus::Exhausted));
            }
            let mut source = String::new();
            if source.try_reserve_exact(line.source().len()).is_err()
                || script.lines.try_reserve(1).is_err()
            {
                return Ok(ServiceReply::empty(ReplyStatus::Exhausted));
            }
            source.push_str(line.source());
            script.lines.push(source);
            script.source_bytes = source_bytes;
            Ok(ServiceReply::empty(ReplyStatus::Success))
        }
    }

    impl ApplicationFilesystemService {
        fn new(namespace: SharedNamespace, cwd: &str) -> Result<Self, ()> {
            let mut owned_cwd = String::new();
            owned_cwd.try_reserve_exact(cwd.len()).map_err(|_| ())?;
            owned_cwd.push_str(cwd);
            let mut files = Vec::new();
            files.try_reserve_exact(64).map_err(|_| ())?;
            Ok(Self {
                namespace,
                cwd: owned_cwd,
                files,
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
            let index = if let Some(index) = self
                .files
                .iter()
                .position(|slot| slot.path.is_none() && !slot.retired)
            {
                index
            } else {
                if self.files.len() == filesystem::MAX_OPEN_FILES {
                    return Err(ReplyStatus::Exhausted);
                }
                self.files
                    .try_reserve(1)
                    .map_err(|_| ReplyStatus::Exhausted)?;
                self.files.push(ApplicationFileSlot {
                    generation: 1,
                    retired: false,
                    path: None,
                    byte_count: 0,
                });
                self.files.len() - 1
            };
            let slot = self.files.get_mut(index).ok_or(ReplyStatus::Failure)?;
            if slot.generation > u32::from(u16::MAX) {
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
            let token = (slot.generation << 16)
                | u32::try_from(index + 1).map_err(|_| ReplyStatus::Failure)?;
            filesystem::OpenFile::new(token, metadata.byte_count).map_err(|_| ReplyStatus::Failure)
        }

        fn slot(
            files: &[ApplicationFileSlot],
            token: u32,
        ) -> Result<&ApplicationFileSlot, ReplyStatus> {
            let encoded_slot = token & u32::from(u16::MAX);
            let generation = token >> 16;
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
            let encoded_slot = token & u32::from(u16::MAX);
            let generation = token >> 16;
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
                Some(generation) if u16::try_from(generation).is_ok() => {
                    slot.generation = generation;
                }
                _ => slot.retired = true,
            }
            Ok(())
        }
    }

    impl Service for ApplicationFilesystemService {
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
                                NodeKind::Symlink => filesystem::NodeKind::Symlink,
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
                filesystem::METADATA | filesystem::METADATA_NO_FOLLOW => {
                    let Ok(path) = filesystem::decode_path_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let metadata = match if request.opcode() == filesystem::METADATA {
                        self.namespace.borrow_mut().metadata(&self.cwd, path)
                    } else {
                        self.namespace
                            .borrow_mut()
                            .metadata_no_follow(&self.cwd, path)
                    } {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            return Ok(ServiceReply::empty(application_filesystem_status(error)));
                        }
                    };
                    let metadata = filesystem::Metadata {
                        kind: match metadata.kind {
                            NodeKind::File => filesystem::NodeKind::File,
                            NodeKind::Directory => filesystem::NodeKind::Directory,
                            NodeKind::Symlink => filesystem::NodeKind::Symlink,
                        },
                        byte_count: metadata.byte_count,
                        modified_unix_seconds: metadata.modified_unix_seconds,
                    };
                    ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &filesystem::encode_metadata_reply(metadata),
                    )
                }
                filesystem::READ_LINK => {
                    let Ok(path) = filesystem::decode_path_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let target = match self.namespace.borrow_mut().read_link(&self.cwd, path) {
                        Ok(target) => target,
                        Err(error) => {
                            return Ok(ServiceReply::empty(application_filesystem_status(error)));
                        }
                    };
                    let mut encoded = [0_u8; filesystem::MAX_LINK_BYTES];
                    let count = filesystem::encode_link_reply(&target, &mut encoded)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &encoded[..count])
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl ApplicationFilesystemMutationService {
        fn new(namespace: SharedNamespace, cwd: &str) -> Result<Self, ()> {
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
            self.namespace
                .borrow_mut()
                .truncate_file(&self.cwd, path)
                .map_err(application_filesystem_status)?;
            self.next_token = token.checked_add(1);
            self.pending = Some(PendingFileReplacement {
                token,
                path: owned_path,
                start_offset: 0,
                offset: 0,
                bytes: Vec::new(),
                chunk_bytes: FILE_IO_BUFFER_BYTES,
            });
            Ok(token)
        }

        fn begin_append(&mut self, path: &str) -> Result<(u32, u64), ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            let metadata = self
                .namespace
                .borrow_mut()
                .metadata(&self.cwd, path)
                .map_err(application_filesystem_status)?;
            if metadata.kind != NodeKind::File {
                return Err(ReplyStatus::WrongType);
            }
            let token = self.next_token.ok_or(ReplyStatus::Exhausted)?;
            let mut owned_path = String::new();
            owned_path
                .try_reserve_exact(path.len())
                .map_err(|_| ReplyStatus::Exhausted)?;
            owned_path.push_str(path);
            self.next_token = token.checked_add(1);
            self.pending = Some(PendingFileReplacement {
                token,
                path: owned_path,
                start_offset: metadata.byte_count,
                offset: metadata.byte_count,
                bytes: Vec::new(),
                chunk_bytes: FILE_IO_BUFFER_BYTES,
            });
            Ok((token, metadata.byte_count))
        }

        fn append(
            &mut self,
            append: filesystem_mutation::AppendRequest<'_>,
        ) -> Result<(), ReplyStatus> {
            let pending = self.pending.as_mut().ok_or(ReplyStatus::InvalidRequest)?;
            if pending.token != append.token || pending.offset != append.offset {
                return Err(ReplyStatus::InvalidRequest);
            }
            pending
                .bytes
                .try_reserve_exact(append.bytes.len())
                .map_err(|_| ReplyStatus::Exhausted)?;
            pending.bytes.extend_from_slice(append.bytes);
            pending.offset = pending
                .offset
                .checked_add(u64::try_from(append.bytes.len()).map_err(|_| ReplyStatus::Overflow)?)
                .ok_or(ReplyStatus::Overflow)?;
            if pending.bytes.len() >= pending.chunk_bytes {
                self.namespace
                    .borrow_mut()
                    .append_file(&self.cwd, &pending.path, &pending.bytes)
                    .map_err(application_filesystem_status)?;
                pending.bytes.clear();
            }
            Ok(())
        }

        fn read_replacement(
            &mut self,
            token: u32,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<usize, ReplyStatus> {
            let pending = self.pending.as_mut().ok_or(ReplyStatus::InvalidRequest)?;
            if pending.token != token || offset > pending.offset {
                return Err(ReplyStatus::InvalidRequest);
            }
            // Reads observe every staged byte, so flush the aggregation buffer
            // before consulting the streamed file.
            if !pending.bytes.is_empty() {
                self.namespace
                    .borrow_mut()
                    .append_file(&self.cwd, &pending.path, &pending.bytes)
                    .map_err(application_filesystem_status)?;
                pending.bytes.clear();
            }
            let available = pending.offset - offset;
            let limit = usize::try_from(available).unwrap_or(usize::MAX);
            let count = destination.len().min(limit);
            if count == 0 {
                return Ok(0);
            }
            let path = pending.path.clone();
            self.namespace
                .borrow_mut()
                .read_file_at(&self.cwd, &path, offset, &mut destination[..count])
                .map_err(application_filesystem_status)
        }

        fn set_chunk_size(&mut self, token: u32, bytes: usize) -> Result<(), ReplyStatus> {
            let pending = self.pending.as_mut().ok_or(ReplyStatus::InvalidRequest)?;
            if pending.token != token
                || pending.offset != pending.start_offset
                || !pending.bytes.is_empty()
            {
                return Err(ReplyStatus::InvalidRequest);
            }
            pending.chunk_bytes = bytes;
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
            let mut namespace = self.namespace.borrow_mut();
            if !pending.bytes.is_empty() {
                namespace
                    .append_file(&self.cwd, &pending.path, &pending.bytes)
                    .map_err(application_filesystem_status)?;
            }
            namespace
                .sync_file(&self.cwd, &pending.path)
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

        fn create_symlink(&mut self, target: &str, link_path: &str) -> Result<(), ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            self.namespace
                .borrow_mut()
                .create_symlink(&self.cwd, target, link_path)
                .map_err(application_filesystem_status)
        }

        fn create_hard_link(&mut self, existing: &str, new_path: &str) -> Result<(), ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            self.namespace
                .borrow_mut()
                .create_hard_link(&self.cwd, existing, new_path)
                .map_err(application_filesystem_status)
        }

        fn create_directory(&mut self, path: &str) -> Result<(), ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            self.namespace
                .borrow_mut()
                .create_directory(&self.cwd, path)
                .map_err(application_filesystem_status)
        }

        fn remove_directory(&mut self, path: &str) -> Result<(), ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            self.namespace
                .borrow_mut()
                .remove_directory(&self.cwd, path)
                .map_err(application_filesystem_status)
        }

        fn set_modified_time(
            &mut self,
            path: &str,
            unix_seconds: Option<u64>,
        ) -> Result<(), ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            self.namespace
                .borrow_mut()
                .set_modified_time(&self.cwd, path, unix_seconds)
                .map_err(application_filesystem_status)
        }

        fn rename(&mut self, source: &str, destination: &str) -> Result<(), ReplyStatus> {
            if self.pending.is_some() {
                return Err(ReplyStatus::Conflict);
            }
            self.namespace
                .borrow_mut()
                .rename(&self.cwd, source, destination)
                .map_err(application_filesystem_status)
        }
    }

    impl Service for ApplicationFilesystemMutationService {
        #[allow(clippy::too_many_lines)]
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
                filesystem_mutation::BEGIN_APPEND => {
                    let Ok(path) = filesystem_mutation::decode_path_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let (token, offset) = match self.begin_append(path) {
                        Ok(result) => result,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    let reply = filesystem_mutation::encode_begin_append_reply(token, offset)
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
                filesystem_mutation::READ_REPLACEMENT => {
                    let Ok((token, offset, length)) =
                        filesystem_mutation::decode_read_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let mut staged = [0_u8; filesystem_mutation::MAX_READ_BYTES];
                    let limit = length.min(staged.len());
                    let count = match self.read_replacement(token, offset, &mut staged[..limit]) {
                        Ok(count) => count,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    ServiceReply::with_payload(ReplyStatus::Success, &staged[..count])
                }
                filesystem_mutation::SET_CHUNK_SIZE => {
                    let Ok((token, bytes)) =
                        filesystem_mutation::decode_chunk_size_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    match self.set_chunk_size(token, bytes) {
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
                filesystem_mutation::CREATE_SYMLINK | filesystem_mutation::CREATE_HARD_LINK => {
                    let Ok(link) = filesystem_mutation::decode_link_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let result = if request.opcode() == filesystem_mutation::CREATE_SYMLINK {
                        self.create_symlink(link.target, link.link_path)
                    } else {
                        self.create_hard_link(link.target, link.link_path)
                    };
                    match result {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(status) => Ok(ServiceReply::empty(status)),
                    }
                }
                filesystem_mutation::CREATE_DIRECTORY => {
                    let Ok(path) = filesystem_mutation::decode_path_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    match self.create_directory(path) {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(status) => Ok(ServiceReply::empty(status)),
                    }
                }
                filesystem_mutation::REMOVE_DIRECTORY => {
                    let Ok(path) = filesystem_mutation::decode_path_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    Ok(application_mutation_reply(self.remove_directory(path)))
                }
                filesystem_mutation::SET_MODIFIED_TIME => {
                    let Ok((path, unix_seconds)) =
                        filesystem_mutation::decode_set_modified_time_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    Ok(application_mutation_reply(
                        self.set_modified_time(path, unix_seconds),
                    ))
                }
                filesystem_mutation::RENAME => {
                    let Ok(paths) = filesystem_mutation::decode_two_path_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    Ok(application_mutation_reply(
                        self.rename(paths.source, paths.destination),
                    ))
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationVolumeControlService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                volume_control::LIST if request.payload().is_empty() => {
                    let mut reply = [0_u8; volume_control::MAX_LIST_REPLY_BYTES];
                    let count = self
                        .mounts
                        .borrow()
                        .encode_list(&mut reply)
                        .map_err(|()| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &reply[..count])
                }
                volume_control::ACTIVATE => {
                    let Ok(name) = volume_control::decode_activate_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let status = self
                        .mounts
                        .borrow_mut()
                        .activate(name, &mut self.namespace.borrow_mut());
                    match status {
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
                timer::PROCESS_CPU_TIME if request.payload().is_empty() => {
                    let task_id = self
                        .task_id
                        .get()
                        .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                    let ticks = self
                        .processes
                        .try_borrow()
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?
                        .snapshot_for_task(task_id)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?
                        .cpu_ticks();
                    let frequency_hz = troe_machine::process_accounting_frequency_hz()
                        .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                    let reply = timer::encode_process_cpu_time(timer::ProcessCpuTime {
                        ticks,
                        frequency_hz,
                    })
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &reply)
                }
                timer::SLEEP_UNTIL => {
                    let Ok(deadline) = timer::decode_milliseconds(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let deadline = MonotonicMillis::from_millis(deadline);
                    let now = self.runtime.borrow().now();
                    if deadline <= now {
                        Ok(ServiceReply::empty(ReplyStatus::Success))
                    } else {
                        // Future sleeps are intercepted at the composition
                        // boundary and retained as deferred calls.
                        Ok(ServiceReply::empty(ReplyStatus::Failure))
                    }
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationWallClockService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != wall_clock::NOW || !request.payload().is_empty() {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Some(seconds) = self.runtime.borrow().wall_seconds() else {
                return Ok(ServiceReply::empty(ReplyStatus::NotConfigured));
            };
            ServiceReply::with_payload(ReplyStatus::Success, &wall_clock::encode_seconds(seconds))
        }
    }

    impl Service for ApplicationClockControlService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != clock_control::SET {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            let Ok(seconds) = clock_control::decode_seconds(request.payload()) else {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            };
            let status = if self.runtime.borrow_mut().set_wall_seconds(seconds).is_ok() {
                ReplyStatus::Success
            } else {
                ReplyStatus::InvalidRequest
            };
            Ok(ServiceReply::empty(status))
        }
    }

    impl Service for ApplicationDiagnosticsProxyService {
        fn call(
            &mut self,
            _request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            // Diagnostics calls are intercepted before synchronous dispatch
            // and completed by the isolated diagnostics server.
            Ok(ServiceReply::empty(ReplyStatus::Failure))
        }
    }

    impl Service for ApplicationDiagnosticsSnapshotService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            if request.opcode() != diagnostics::GET_SNAPSHOT || !request.payload().is_empty() {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            }
            ServiceReply::with_payload(ReplyStatus::Success, self.snapshot.as_ref())
        }
    }

    fn child_process_status(error: ChildProcessError) -> ReplyStatus {
        match error {
            ChildProcessError::CapacityExhausted | ChildProcessError::MetadataExhausted => {
                ReplyStatus::Exhausted
            }
            ChildProcessError::InvalidToken => ReplyStatus::NotFound,
            ChildProcessError::ForeignOwner | ChildProcessError::Closed => ReplyStatus::Conflict,
            ChildProcessError::WouldBlock => ReplyStatus::Failure,
            ChildProcessError::InvalidCapacity
            | ChildProcessError::InvalidOwner
            | ChildProcessError::InvalidProcess
            | ChildProcessError::InvalidState
            | ChildProcessError::InvalidMessage => ReplyStatus::InvalidRequest,
            ChildProcessError::GenerationExhausted | ChildProcessError::AccountingOverflow => {
                ReplyStatus::Failure
            }
        }
    }

    impl Service for ApplicationProcessLaunchService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            let Some(owner) = self.owner.get() else {
                return Ok(ServiceReply::empty(ReplyStatus::Conflict));
            };
            if request.opcode() == process_launch::SPAWN {
                // Admission needs scheduler and namespace authority and is
                // intercepted by ResidentApplication::step.
                return Ok(ServiceReply::empty(ReplyStatus::Failure));
            }
            let Ok(token) = process_launch::decode_token(request.payload()) else {
                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
            };
            match request.opcode() {
                process_launch::POLL | process_launch::WAIT => {
                    let status = match self.children.try_borrow() {
                        Ok(children) => children.status(owner, token),
                        Err(_) => return Ok(ServiceReply::empty(ReplyStatus::Conflict)),
                    };
                    match status {
                        Ok(status) => ServiceReply::with_payload(
                            ReplyStatus::Success,
                            &process_launch::encode_status(status)
                                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                        ),
                        Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                    }
                }
                process_launch::CANCEL => {
                    let status = match self.children.try_borrow_mut() {
                        Ok(mut children) => children
                            .request_cancel(owner, token)
                            .and_then(|_| children.status(owner, token)),
                        Err(_) => return Ok(ServiceReply::empty(ReplyStatus::Conflict)),
                    };
                    match status {
                        Ok(status) => ServiceReply::with_payload(
                            ReplyStatus::Success,
                            &process_launch::encode_status(status)
                                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                        ),
                        Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                    }
                }
                process_launch::REAP => {
                    let result = match self.children.try_borrow_mut() {
                        Ok(mut children) => children.reap(owner, token),
                        Err(_) => return Ok(ServiceReply::empty(ReplyStatus::Conflict)),
                    };
                    match result {
                        Ok(_) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                    }
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationPipeService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            let Some(owner) = self.owner.get() else {
                return Ok(ServiceReply::empty(ReplyStatus::Conflict));
            };
            let Ok(mut pipes) = self.pipes.try_borrow_mut() else {
                return Ok(ServiceReply::empty(ReplyStatus::Conflict));
            };
            match request.opcode() {
                pipe::CREATE => {
                    let Ok(capacity) = pipe::decode_create(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    match pipes.create(owner, capacity) {
                        Ok(token) => ServiceReply::with_payload(
                            ReplyStatus::Success,
                            &pipe::encode_token(token),
                        ),
                        Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                    }
                }
                pipe::WRITE => {
                    let Ok((token, payload)) = pipe::decode_write(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    match pipes.write_owner(owner, token, payload) {
                        Ok(count) if count == payload.len() => {
                            Ok(ServiceReply::empty(ReplyStatus::Success))
                        }
                        Ok(_) => Ok(ServiceReply::empty(ReplyStatus::Failure)),
                        Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                    }
                }
                pipe::READ => {
                    let Ok((token, maximum)) = pipe::decode_read(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let mut bytes = [0_u8; pipe::MAX_IO_BYTES];
                    match pipes.read_owner(owner, token, &mut bytes[..maximum]) {
                        Ok(count) => {
                            ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count])
                        }
                        Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                    }
                }
                pipe::CLOSE_WRITER | pipe::CLOSE_READER => {
                    let Ok(token) = pipe::decode_token(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let direction = if request.opcode() == pipe::CLOSE_WRITER {
                        PipeDirection::Writer
                    } else {
                        PipeDirection::Reader
                    };
                    match pipes.close_owner(owner, token, direction) {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(error) => Ok(ServiceReply::empty(child_process_status(error))),
                    }
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for ApplicationProcessObservationService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            let frequency = troe_machine::process_accounting_frequency_hz()
                .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
            let processes = self
                .processes
                .try_borrow()
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
            let mut records = Vec::new();
            records
                .try_reserve_exact(processes.snapshots().len())
                .map_err(|_| troe_dispatch::DispatchError::MetadataExhausted)?;
            for process in processes.snapshots() {
                records.push(process_observation::Process {
                    id: process.id().get(),
                    task_id: u64::from(process.task_id().get()),
                    started_millis: process.started_millis(),
                    cpu_ticks: process.cpu_ticks(),
                    resident_pages: process.resident_pages(),
                    table_pages: process.table_pages(),
                    private_pages: process.private_pages(),
                    dispatches: process.dispatches(),
                    yields: process.yields(),
                    preemptions: process.preemptions(),
                    handles: process.handles(),
                    state: match process.state() {
                        ProcessState::Ready => process_observation::State::Ready,
                        ProcessState::Running => process_observation::State::Running,
                        ProcessState::Blocked => process_observation::State::Blocked,
                        ProcessState::Stopping => process_observation::State::Stopping,
                    },
                    origin: match process.origin() {
                        ProcessOrigin::Foreground => process_observation::Origin::Foreground,
                        ProcessOrigin::Background => process_observation::Origin::Background,
                        ProcessOrigin::Service => process_observation::Origin::Service,
                        ProcessOrigin::Child => process_observation::Origin::Child,
                    },
                    name: process_observation::ProcessName::new(process.name().as_str())
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                });
            }
            let observed_millis = self.runtime.borrow().now().as_millis();
            match request.opcode() {
                process_observation::GET_SNAPSHOT if request.payload().is_empty() => {
                    let retained = records.len().min(process_observation::MAX_PROCESSES);
                    let snapshot = process_observation::Snapshot::new(
                        observed_millis,
                        frequency,
                        &records[..retained],
                    )
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &process_observation::encode_snapshot(snapshot)
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                    )
                }
                process_observation::GET_PAGE => {
                    let Ok(after) = process_observation::decode_page_request(request.payload())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let start = records.partition_point(|process| process.id <= after);
                    let end = start
                        .saturating_add(process_observation::MAX_PAGE_PROCESSES)
                        .min(records.len());
                    let page_records = &records[start..end];
                    let next_cursor = if end < records.len() {
                        page_records.last().map_or(0, |process| process.id)
                    } else {
                        0
                    };
                    let page = process_observation::Page::new(
                        observed_millis,
                        frequency,
                        next_cursor,
                        u32::try_from(records.len())
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                        page_records,
                    )
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &process_observation::encode_page(page)
                            .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                    )
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Service for DiagnosticsServerEndpoint {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                server::RECEIVE if request.payload().is_empty() => {
                    let mut encoded = Vec::new();
                    encoded
                        .try_reserve_exact(troe_abi::MAX_MESSAGE_BYTES)
                        .map_err(|_| troe_dispatch::DispatchError::MetadataExhausted)?;
                    encoded.resize(troe_abi::MAX_MESSAGE_BYTES, 0);
                    let encoded_bytes = {
                        let exchange = self.exchange.borrow();
                        if exchange.received || exchange.completed {
                            return Ok(ServiceReply::empty(ReplyStatus::Conflict));
                        }
                        match server::encode_received_request(
                            exchange.operation.abi_value(),
                            troe_abi::interface::DIAGNOSTICS,
                            diagnostics::GET_SNAPSHOT,
                            exchange.reply_capacity,
                            exchange.snapshot.as_ref(),
                            &mut encoded,
                        ) {
                            Ok(bytes) => bytes,
                            Err(_) => {
                                return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                            }
                        }
                    };
                    let reply = ServiceReply::with_payload(
                        ReplyStatus::Success,
                        &encoded[..encoded_bytes],
                    )?;
                    let mut exchange = self.exchange.borrow_mut();
                    exchange.received = true;
                    exchange.steady_allocation_calls =
                        Some(troe_machine::heap_stats().allocation_calls);
                    Ok(reply)
                }
                server::REPLY => {
                    let Ok(completion) = server::decode_reply_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let Ok(operation) = PendingOperationId::from_abi_value(completion.token())
                    else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let Some(status) = ReplyStatus::from_abi_value(completion.status()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let mut exchange = self.exchange.borrow_mut();
                    if !exchange.received
                        || exchange.completed
                        || exchange.operation != operation
                        || completion.payload().len() > exchange.reply_capacity
                    {
                        return Ok(ServiceReply::empty(ReplyStatus::Conflict));
                    }
                    let reply_bytes = completion.payload().len();
                    exchange.reply[..reply_bytes].copy_from_slice(completion.payload());
                    exchange.reply_bytes = reply_bytes;
                    exchange.status = status;
                    exchange.completed = true;
                    exchange.steady_allocation_free = exchange.steady_allocation_calls
                        == Some(troe_machine::heap_stats().allocation_calls);
                    Ok(ServiceReply::empty(ReplyStatus::Success))
                }
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }

        fn call_into(
            &mut self,
            request: Request<'_>,
            destination: &mut [u8],
        ) -> Result<ServiceReplyInfo, troe_dispatch::DispatchError> {
            if request.opcode() != server::RECEIVE || !request.payload().is_empty() {
                let reply = self.call(request)?;
                if reply.payload().len() > destination.len() {
                    return Err(troe_dispatch::DispatchError::MessageTooLarge);
                }
                destination[..reply.payload().len()].copy_from_slice(reply.payload());
                return Ok(if reply.payload().is_empty() {
                    ServiceReplyInfo::empty(reply.status())
                } else {
                    ServiceReplyInfo::copied(reply.status(), reply.payload().len())
                });
            }
            let encoded_bytes = {
                let exchange = self.exchange.borrow();
                if exchange.received || exchange.completed {
                    return Ok(ServiceReplyInfo::empty(ReplyStatus::Conflict));
                }
                match server::encode_received_request(
                    exchange.operation.abi_value(),
                    troe_abi::interface::DIAGNOSTICS,
                    diagnostics::GET_SNAPSHOT,
                    exchange.reply_capacity,
                    exchange.snapshot.as_ref(),
                    destination,
                ) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(ServiceReplyInfo::empty(ReplyStatus::InvalidRequest));
                    }
                }
            };
            let mut exchange = self.exchange.borrow_mut();
            exchange.received = true;
            exchange.steady_allocation_calls = Some(troe_machine::heap_stats().allocation_calls);
            Ok(ServiceReplyInfo::copied(
                ReplyStatus::Success,
                encoded_bytes,
            ))
        }
    }

    #[cfg(feature = "acceptance-probes")]
    impl DiagnosticsBenchmarkEndpoint {
        const FRAGMENT_BYTES: usize =
            if server::MAX_RECEIVE_REQUEST_BYTES < server::MAX_REPLY_PAYLOAD_BYTES {
                server::MAX_RECEIVE_REQUEST_BYTES
            } else {
                server::MAX_REPLY_PAYLOAD_BYTES
            };

        fn fragments(payload_bytes: usize) -> usize {
            if payload_bytes > Self::FRAGMENT_BYTES {
                2
            } else {
                1
            }
        }

        fn fragment_range(payload_bytes: usize, fragment_index: usize) -> Option<(usize, usize)> {
            let first = payload_bytes.min(Self::FRAGMENT_BYTES);
            match fragment_index {
                0 => Some((0, first)),
                1 if first < payload_bytes => Some((first, payload_bytes)),
                _ => None,
            }
        }

        #[allow(clippy::too_many_lines)]
        fn direct_call(
            &mut self,
            request: Request<'_>,
            destination: &mut [u8],
        ) -> Result<ServiceReplyInfo, troe_dispatch::DispatchError> {
            match request.opcode() {
                server::RECEIVE if request.payload().is_empty() => {
                    let mut exchange = self.exchange.borrow_mut();
                    let total = IPC_BASELINE_WARMUP_CALLS + IPC_BASELINE_SAMPLES;
                    if exchange.logical_index == total {
                        return Ok(ServiceReplyInfo::empty(ReplyStatus::Conflict));
                    }
                    if exchange.received {
                        return Ok(ServiceReplyInfo::empty(ReplyStatus::Conflict));
                    }
                    let fragments = Self::fragments(exchange.payload_bytes);
                    let (start, end) =
                        Self::fragment_range(exchange.payload_bytes, exchange.fragment_index)
                            .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                    if exchange.fragment_index == 0 {
                        exchange.started_ticks = troe_machine::benchmark_counter_ticks();
                        exchange.started_execution = troe_machine::application_execution_stats();
                        exchange.started_allocations = troe_machine::heap_stats().allocation_calls;
                    }
                    let transport_index = exchange
                        .logical_index
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(exchange.fragment_index))
                        .and_then(|value| value.checked_add(1))
                        .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                    let generation = u32::try_from(transport_index)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    let token = u64::from(generation) << 32;
                    let final_fragment = exchange.fragment_index + 1 == fragments;
                    let opcode = if final_fragment { 1 } else { 2 };
                    let encoded = server::encode_received_request(
                        token,
                        troe_abi::interface::DIAGNOSTICS,
                        opcode,
                        end - start,
                        &exchange.payload[start..end],
                        destination,
                    )
                    .map_err(|_| troe_dispatch::DispatchError::MessageTooLarge)?;
                    exchange.received = true;
                    exchange.expected_token = token;
                    Ok(ServiceReplyInfo::copied(ReplyStatus::Success, encoded))
                }
                server::REPLY => {
                    let completion = server::decode_reply_request(request.payload())
                        .map_err(|_| troe_dispatch::DispatchError::InvalidHandle)?;
                    let mut exchange = self.exchange.borrow_mut();
                    if !exchange.received
                        || completion.token() != exchange.expected_token
                        || completion.status() != troe_abi::reply::SUCCESS
                    {
                        return Ok(ServiceReplyInfo::empty(ReplyStatus::Conflict));
                    }
                    PendingOperationId::from_abi_value(completion.token())
                        .map_err(|_| troe_dispatch::DispatchError::InvalidHandle)?;
                    let fragments = Self::fragments(exchange.payload_bytes);
                    let (start, end) =
                        Self::fragment_range(exchange.payload_bytes, exchange.fragment_index)
                            .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                    if completion.payload() != &exchange.payload[start..end] {
                        return Ok(ServiceReplyInfo::empty(ReplyStatus::InvalidRequest));
                    }
                    exchange.received = false;
                    if exchange.fragment_index + 1 == fragments {
                        if exchange.logical_index >= IPC_BASELINE_WARMUP_CALLS {
                            let finished_ticks = troe_machine::benchmark_counter_ticks();
                            let finished_execution = troe_machine::application_execution_stats();
                            let finished_allocations = troe_machine::heap_stats().allocation_calls;
                            let sample_index = exchange
                                .logical_index
                                .checked_sub(IPC_BASELINE_WARMUP_CALLS)
                                .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                            exchange.samples[sample_index] = finished_ticks
                                .checked_sub(exchange.started_ticks)
                                .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                            exchange.measured = exchange
                                .measured
                                .checked_add(1)
                                .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                            exchange.address_space_switches = exchange
                                .address_space_switches
                                .checked_add(
                                    finished_execution
                                        .address_space_switches
                                        .checked_sub(
                                            exchange.started_execution.address_space_switches,
                                        )
                                        .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?,
                                )
                                .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                            exchange.tlb_invalidations = exchange
                                .tlb_invalidations
                                .checked_add(
                                    finished_execution
                                        .tlb_invalidations
                                        .checked_sub(exchange.started_execution.tlb_invalidations)
                                        .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?,
                                )
                                .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                            exchange.timer_programs = exchange
                                .timer_programs
                                .checked_add(
                                    finished_execution
                                        .timer_programs
                                        .checked_sub(exchange.started_execution.timer_programs)
                                        .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?,
                                )
                                .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                            exchange.steady_allocation_calls = exchange
                                .steady_allocation_calls
                                .checked_add(
                                    u64::try_from(
                                        finished_allocations
                                            .checked_sub(exchange.started_allocations)
                                            .ok_or(
                                                troe_dispatch::DispatchError::AccountingOverflow,
                                            )?,
                                    )
                                    .map_err(|_| {
                                        troe_dispatch::DispatchError::AccountingOverflow
                                    })?,
                                )
                                .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                        }
                        exchange.logical_index = exchange
                            .logical_index
                            .checked_add(1)
                            .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                        exchange.fragment_index = 0;
                    } else {
                        exchange.fragment_index += 1;
                    }
                    Ok(ServiceReplyInfo::empty(ReplyStatus::Success))
                }
                _ => Ok(ServiceReplyInfo::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    #[cfg(feature = "acceptance-probes")]
    impl Service for DiagnosticsBenchmarkEndpoint {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            let mut destination = [0_u8; troe_abi::MAX_MESSAGE_BYTES];
            let reply = self.direct_call(request, &mut destination)?;
            ServiceReply::with_payload(reply.status(), &destination[..reply.payload_bytes()])
        }

        fn call_into(
            &mut self,
            request: Request<'_>,
            destination: &mut [u8],
        ) -> Result<ServiceReplyInfo, troe_dispatch::DispatchError> {
            self.direct_call(request, destination)
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
            FsError::NotConfigured => ReplyStatus::NotConfigured,
            FsError::NotEmpty => ReplyStatus::NotEmpty,
            FsError::CrossDevice => ReplyStatus::CrossDevice,
        }
    }

    fn application_mutation_reply(result: Result<(), ReplyStatus>) -> ServiceReply {
        ServiceReply::empty(match result {
            Ok(()) => ReplyStatus::Success,
            Err(status) => status,
        })
    }

    impl ApplicationDatagramService {
        fn new(state: SharedApplicationDatagram, runtime: SharedRuntime) -> Self {
            Self { state, runtime }
        }
    }

    impl ApplicationDatagramState {
        fn new(network: SharedNetwork) -> Self {
            Self {
                network,
                ports: Vec::new(),
            }
        }

        fn claim_port(&mut self, requested: Option<u16>) -> Result<u16, ReplyStatus> {
            if let Some(port) = requested {
                if port == 0 {
                    return Err(ReplyStatus::InvalidRequest);
                }
                if self.ports.contains(&port) {
                    return Ok(port);
                }
                if self.ports.len() == troe_net::MAX_UDP_PORTS {
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
                if self.ports.try_reserve(1).is_err() {
                    let _released = self.network.borrow_mut().udp.unbind(port);
                    return Err(ReplyStatus::Exhausted);
                }
                self.ports.push(port);
                return Ok(port);
            }

            if self.ports.len() == troe_net::MAX_UDP_PORTS {
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
                    if self.ports.try_reserve(1).is_err() {
                        let _released = self.network.borrow_mut().udp.unbind(port);
                        return Err(ReplyStatus::Exhausted);
                    }
                    self.ports.push(port);
                    return Ok(port);
                }
            }
            Err(ReplyStatus::Exhausted)
        }

        fn receive_now(&mut self, local_port: u16) -> Result<Option<ReceivedUdp>, ReplyStatus> {
            if self.network.borrow().configuration.is_none() {
                return Err(ReplyStatus::NotConfigured);
            }
            let datagram = self.network.borrow_mut().udp.receive(local_port);
            Ok(datagram.map(|datagram| ReceivedUdp {
                source: datagram.source_ip.bytes(),
                source_port: datagram.source_port,
                payload: datagram.payload,
            }))
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
                    let source_port = match self.state.borrow_mut().claim_port(requested) {
                        Ok(port) => port,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    let mut network = KernelNetwork::new(self.state.borrow().network.clone());
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
                    let local_port = match self.state.borrow_mut().claim_port(Some(local_port)) {
                        Ok(port) => port,
                        Err(status) => return Ok(ServiceReply::empty(status)),
                    };
                    let received = match self.state.borrow_mut().receive_now(local_port) {
                        Ok(Some(received)) => received,
                        Ok(None) => return Ok(ServiceReply::empty(ReplyStatus::Timeout)),
                        Err(status) => return Ok(ServiceReply::empty(status)),
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

    impl Drop for ApplicationDatagramState {
        fn drop(&mut self) {
            let mut network = self.network.borrow_mut();
            for port in &self.ports {
                let _released = network.udp.unbind(*port);
            }
        }
    }

    impl ApplicationTcpConnectService {
        const OPERATION_MILLISECONDS: u64 = 4_000;
        const FLUSH_BUDGET: usize = 2;

        fn new(network: SharedNetwork, runtime: SharedRuntime) -> Self {
            Self {
                network,
                runtime,
                attempted: false,
                connection: None,
            }
        }

        fn connect(
            &mut self,
            destination: [u8; 4],
            destination_port: u16,
        ) -> Result<u16, NetworkError> {
            if self.attempted {
                return Err(NetworkError::Exhausted);
            }
            self.attempted = true;
            let started = self.runtime.borrow().now();
            let deadline = started.saturating_add(Self::OPERATION_MILLISECONDS);
            let configuration = self
                .network
                .borrow()
                .configuration
                .ok_or(NetworkError::NotConfigured)?;
            let destination = Ipv4Address::new(destination);
            let peer_mac = {
                let network = KernelNetwork::new(self.network.clone());
                let mut runtime = KernelRuntimeCapability {
                    runtime: self.runtime.clone(),
                };
                network.resolve(destination, &mut runtime)?
            };
            let now = self.runtime.borrow().now().as_millis();
            let (id, local_port, initial_sequence) = {
                let mut network = self.network.borrow_mut();
                if network.tcp.len() == troe_net::MAX_TCP_CONNECTIONS {
                    return Err(NetworkError::Exhausted);
                }
                let mut selected = None;
                for _ in 0..=troe_net::MAX_TCP_CONNECTIONS {
                    let port = network.next_tcp_port;
                    network.next_tcp_port = if port == u16::MAX { 49_152 } else { port + 1 };
                    if !network
                        .tcp
                        .iter()
                        .any(|connection| connection.borrow().local_port == port)
                    {
                        selected = Some(port);
                        break;
                    }
                }
                let local_port = selected.ok_or(NetworkError::Exhausted)?;
                let id = network.next_tcp_id;
                network.next_tcp_id = network
                    .next_tcp_id
                    .checked_add(1)
                    .ok_or(NetworkError::Exhausted)?;
                network.tcp_generation = network.tcp_generation.wrapping_add(1);
                let mac = network.device.mac_address().bytes();
                let mac_word = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
                let initial_sequence = u32::try_from(now & u64::from(u32::MAX)).unwrap_or(u32::MAX)
                    ^ u32::try_from(now >> 32).unwrap_or(u32::MAX).rotate_left(7)
                    ^ mac_word.rotate_left(13)
                    ^ network.tcp_generation.wrapping_mul(0x9e37_79b9);
                (id, local_port, initial_sequence)
            };
            let local =
                TcpEndpoint::new(configuration.address, local_port).map_err(map_network_error)?;
            let remote =
                TcpEndpoint::new(destination, destination_port).map_err(map_network_error)?;
            let machine =
                TcpConnection::connect(local, remote, initial_sequence).map_err(map_tcp_error)?;
            let connection = Rc::new(RefCell::new(KernelTcpConnection {
                id,
                local_port,
                peer_mac,
                machine,
            }));
            self.network.borrow_mut().tcp.push(connection.clone());
            self.connection = Some(connection);

            loop {
                if let Err(error) = self.flush() {
                    self.release();
                    return Err(error);
                }
                let state = self.connection_state()?;
                if state.0 {
                    return Ok(local_port);
                }
                if state.1 {
                    let error = self.connection_error().unwrap_or(NetworkError::Closed);
                    self.release();
                    return Err(error);
                }
                if self.runtime.borrow().now() >= deadline {
                    self.release();
                    return Err(NetworkError::Timeout);
                }
                if self.runtime.borrow_mut().checkpoint().is_err() {
                    self.release();
                    return Err(NetworkError::Cancelled);
                }
            }
        }

        fn write(&mut self, bytes: &[u8]) -> Result<(), NetworkError> {
            let deadline = self
                .runtime
                .borrow()
                .now()
                .saturating_add(Self::OPERATION_MILLISECONDS);
            let mut offset = 0;
            while offset < bytes.len() {
                let capacity = {
                    let connection = self.connection.as_ref().ok_or(NetworkError::Closed)?;
                    let connection = connection.borrow();
                    if !connection.machine.is_established() {
                        return Err(connection
                            .machine
                            .terminal_error()
                            .map_or(NetworkError::Closed, map_tcp_error));
                    }
                    connection.machine.send_capacity()
                };
                if capacity == 0 {
                    self.wait_checkpoint(deadline)?;
                    continue;
                }
                let count = capacity.min(bytes.len() - offset);
                self.connection
                    .as_ref()
                    .ok_or(NetworkError::Closed)?
                    .borrow_mut()
                    .machine
                    .begin_send(&bytes[offset..offset + count])
                    .map_err(map_tcp_error)?;
                loop {
                    self.flush()?;
                    let complete = self
                        .connection
                        .as_ref()
                        .ok_or(NetworkError::Closed)?
                        .borrow()
                        .machine
                        .send_complete()
                        .map_err(map_tcp_error)?;
                    if complete {
                        break;
                    }
                    self.wait_checkpoint(deadline)?;
                }
                offset += count;
            }
            Ok(())
        }

        fn read(&mut self, destination: &mut [u8]) -> Result<usize, NetworkError> {
            let deadline = self
                .runtime
                .borrow()
                .now()
                .saturating_add(Self::OPERATION_MILLISECONDS);
            loop {
                let read = self
                    .connection
                    .as_ref()
                    .ok_or(NetworkError::Closed)?
                    .borrow_mut()
                    .machine
                    .read(destination)
                    .map_err(map_tcp_error)?;
                if let Some(count) = read {
                    self.flush()?;
                    return Ok(count);
                }
                self.wait_checkpoint(deadline)?;
            }
        }

        fn close(&mut self) -> Result<(), NetworkError> {
            let deadline = self
                .runtime
                .borrow()
                .now()
                .saturating_add(Self::OPERATION_MILLISECONDS);
            let begin = {
                let connection = self.connection.as_ref().ok_or(NetworkError::Closed)?;
                let mut connection = connection.borrow_mut();
                if connection.machine.is_closed() {
                    connection
                        .machine
                        .terminal_error()
                        .map_or(Ok(()), |error| Err(map_tcp_error(error)))
                } else {
                    connection.machine.begin_close().map_err(map_tcp_error)
                }
            };
            if let Err(error) = begin {
                self.release();
                return Err(error);
            }
            loop {
                if let Err(error) = self.flush() {
                    self.release();
                    return Err(error);
                }
                let closed = self
                    .connection
                    .as_ref()
                    .is_none_or(|connection| connection.borrow().machine.is_closed());
                if closed {
                    self.release();
                    return Ok(());
                }
                if let Err(error) = self.wait_checkpoint(deadline) {
                    self.release();
                    return Err(error);
                }
            }
        }

        fn wait_checkpoint(&mut self, deadline: MonotonicMillis) -> Result<(), NetworkError> {
            if self.runtime.borrow().now() >= deadline {
                return Err(NetworkError::Timeout);
            }
            self.runtime
                .borrow_mut()
                .checkpoint()
                .map_err(|_| NetworkError::Cancelled)?;
            self.flush()
        }

        fn flush(&mut self) -> Result<(), NetworkError> {
            for _ in 0..Self::FLUSH_BUDGET {
                let now = self.runtime.borrow().now().as_millis();
                let frame = {
                    let connection = self.connection.as_ref().ok_or(NetworkError::Closed)?;
                    let mut connection = connection.borrow_mut();
                    let peer_mac = connection.peer_mac;
                    let Some(emission) = connection
                        .machine
                        .poll_emission(now)
                        .map_err(map_tcp_error)?
                    else {
                        break;
                    };
                    let source_mac = self.network.borrow().device.mac_address();
                    build_tcp(
                        source_mac,
                        peer_mac,
                        TcpSegment {
                            source: emission.source,
                            destination: emission.destination,
                            sequence: emission.sequence,
                            acknowledgement: emission.acknowledgement,
                            flags: emission.flags,
                            window: emission.window,
                            payload: emission.payload,
                        },
                    )
                    .map_err(map_network_error)?
                };
                self.network.borrow_mut().transmit(&frame)?;
            }
            Ok(())
        }

        fn connection_state(&self) -> Result<(bool, bool), NetworkError> {
            let connection = self.connection.as_ref().ok_or(NetworkError::Closed)?;
            let machine = &connection.borrow().machine;
            Ok((machine.is_established(), machine.is_closed()))
        }

        fn connection_error(&self) -> Option<NetworkError> {
            self.connection
                .as_ref()
                .and_then(|connection| connection.borrow().machine.terminal_error())
                .map(map_tcp_error)
        }

        fn release(&mut self) {
            let Some(connection) = self.connection.take() else {
                return;
            };
            let id = connection.borrow().id;
            self.network
                .borrow_mut()
                .tcp
                .retain(|candidate| candidate.borrow().id != id);
        }
    }

    impl Service for ApplicationTcpConnectService {
        fn call(
            &mut self,
            request: Request<'_>,
        ) -> Result<ServiceReply, troe_dispatch::DispatchError> {
            match request.opcode() {
                tcp_connect::CONNECT => {
                    let Ok(connect) = tcp_connect::decode_connect_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let local_port =
                        match self.connect(connect.destination, connect.destination_port) {
                            Ok(port) => port,
                            Err(error) => {
                                return Ok(ServiceReply::empty(application_network_status(error)));
                            }
                        };
                    let reply = tcp_connect::encode_connect_reply(local_port)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                    ServiceReply::with_payload(ReplyStatus::Success, &reply)
                }
                tcp_connect::WRITE => {
                    let Ok(bytes) = tcp_connect::decode_write_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    match self.write(bytes) {
                        Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                        Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
                    }
                }
                tcp_connect::READ => {
                    let Ok(requested) = tcp_connect::decode_read_request(request.payload()) else {
                        return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                    };
                    let mut bytes = [0_u8; tcp_connect::MAX_READ_BYTES];
                    match self.read(&mut bytes[..requested]) {
                        Ok(count) => {
                            ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count])
                        }
                        Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
                    }
                }
                tcp_connect::CLOSE if request.payload().is_empty() => match self.close() {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
                },
                _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
            }
        }
    }

    impl Drop for ApplicationTcpConnectService {
        fn drop(&mut self) {
            self.release();
        }
    }

    const fn application_network_status(error: NetworkError) -> ReplyStatus {
        match error {
            NetworkError::NotConfigured => ReplyStatus::NotConfigured,
            NetworkError::Timeout => ReplyStatus::Timeout,
            NetworkError::TooLarge => ReplyStatus::TooLarge,
            NetworkError::Exhausted => ReplyStatus::Exhausted,
            NetworkError::Cancelled => ReplyStatus::Cancelled,
            NetworkError::Closed | NetworkError::Device => ReplyStatus::Failure,
            NetworkError::Protocol => ReplyStatus::NetworkProtocol,
        }
    }

    const fn map_tcp_error(error: TcpError) -> NetworkError {
        match error {
            TcpError::Invalid => NetworkError::Protocol,
            TcpError::Busy | TcpError::WindowClosed | TcpError::Exhausted => {
                NetworkError::Exhausted
            }
            TcpError::Timeout => NetworkError::Timeout,
            TcpError::Reset | TcpError::Closed => NetworkError::Closed,
        }
    }

    fn same_subnet(left: Ipv4Address, right: Ipv4Address, mask: Ipv4Address) -> bool {
        left.bytes()
            .iter()
            .zip(right.bytes())
            .zip(mask.bytes())
            .all(|((left, right), mask)| *left & mask == right & mask)
    }

    fn firmware_unix_seconds() -> Option<u64> {
        const MONTH_DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

        let time = uefi::runtime::get_time().ok()?;
        if time.year() < 1970 {
            return None;
        }
        let mut days = 0_u64;
        for year in 1970..time.year() {
            days = days.checked_add(if is_leap_year(year) { 366 } else { 365 })?;
        }
        for month in 1..time.month() {
            let mut month_days = *MONTH_DAYS.get(usize::from(month - 1))?;
            if month == 2 && is_leap_year(time.year()) {
                month_days += 1;
            }
            days = days.checked_add(month_days)?;
        }
        days = days.checked_add(u64::from(time.day().checked_sub(1)?))?;
        let local = days
            .checked_mul(86_400)?
            .checked_add(u64::from(time.hour()).checked_mul(3_600)?)?
            .checked_add(u64::from(time.minute()).checked_mul(60)?)?
            .checked_add(u64::from(time.second()))?;
        match time.time_zone() {
            Some(offset) if offset >= 0 => local.checked_sub(u64::from(offset.unsigned_abs()) * 60),
            Some(offset) => local.checked_add(u64::from(offset.unsigned_abs()) * 60),
            None => Some(local),
        }
    }

    const fn is_leap_year(year: u16) -> bool {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
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

        fn new(
            network: Option<SharedNetwork>,
            firmware_wall_seconds: Option<u64>,
        ) -> Result<Self, RuntimeInitError> {
            let initial = troe_machine::monotonic_millis().ok_or(RuntimeInitError::Clock)?;
            let mut deferred_input = VecDeque::new();
            deferred_input
                .try_reserve_exact(Self::DEFERRED_INPUT_CAPACITY)
                .map_err(|_| RuntimeInitError::InputMetadata)?;
            Ok(Self {
                network,
                wall_clock: firmware_wall_seconds.map(|unix_seconds| WallClockAnchor {
                    unix_seconds,
                    monotonic_milliseconds: initial,
                }),
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
            self.service_ambient();
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

        fn service_ambient(&mut self) {
            if troe_machine::take_network_interrupt()
                && let Some(network) = &self.network
            {
                let _bounded_poll = network.borrow_mut().poll();
            }
        }

        fn wall_seconds(&self) -> Option<u64> {
            let anchor = self.wall_clock?;
            let elapsed = self
                .now()
                .as_millis()
                .saturating_sub(anchor.monotonic_milliseconds)
                / 1_000;
            Some(anchor.unix_seconds.saturating_add(elapsed))
        }

        fn set_wall_seconds(&mut self, unix_seconds: u64) -> Result<(), ()> {
            if unix_seconds > 253_402_300_799 {
                return Err(());
            }
            self.wall_clock = Some(WallClockAnchor {
                unix_seconds,
                monotonic_milliseconds: self.now().as_millis(),
            });
            Ok(())
        }

        fn poll_input_event(&mut self) -> Option<InputEvent> {
            let _cancel_at_prompt = self.checkpoint();
            self.take_input_event()
        }

        /// Take one retained event without observing cancellation.
        ///
        /// Foreground callers detect cancellation with their own checkpoint,
        /// so draining here must not consume that observation.
        fn take_input_event(&mut self) -> Option<InputEvent> {
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

    fn install_command_runtime(
        console: &mut dyn Output,
        firmware_wall_seconds: Option<u64>,
    ) -> (Option<NetworkStatus>, SharedRuntime) {
        let service = discover_network_service();
        let runtime_state = match KernelRuntime::new(service.clone(), firmware_wall_seconds) {
            Ok(runtime) => runtime,
            Err(RuntimeInitError::Clock) => fatal(b"fatal: monotonic runtime unavailable\n"),
            Err(RuntimeInitError::InputMetadata) => {
                fatal(b"fatal: runtime input metadata exhausted\n")
            }
        };
        let runtime = Rc::new(RefCell::new(runtime_state));
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
            (status, runtime)
        } else {
            if write_boot_status(console, "Configuring network", false).is_err() {
                fatal(b"fatal: native network diagnostic failed\n");
            }
            (None, runtime)
        }
    }

    fn finish_shell_startup(
        console: &mut dyn Output,
        motd: &[u8],
        root_mode: NativeRootMode,
        firmware_wall_seconds: Option<u64>,
    ) -> SharedRuntime {
        let (network_status, runtime) = install_command_runtime(console, firmware_wall_seconds);
        if !write_shell_banner(console, motd, root_mode, network_status) {
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
                let foreground_blocked =
                    matches!(process.execution, Some(ResidentExecution::Blocked));
                if foreground_blocked
                    && !self.residents.has_runnable_process()
                    && troe_machine::wait_for_runtime_event_timeout(RESIDENT_POLL_MILLISECONDS)
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
            let application_transport_network = if requirements.datagram || requirements.tcp_connect
            {
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
            let process_owner_binding = (requirements.process_launch || requirements.pipe)
                .then(|| Rc::new(Cell::new(None)));
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
                        return command_application_error(
                            stderr,
                            command,
                            "pipe metadata exhausted",
                        );
                    }
                }
            } else {
                None
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
                            &command::CONVENTIONAL_ENVIRONMENT,
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
                    owner: process_owner
                        .unwrap_or_else(|| fatal(b"fatal: process owner missing\n")),
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

    /// Launch one supervised service as a session-independent background job.
    ///
    /// Services never hold the session terminal loan: their standard input is
    /// always empty, so a supervised process cannot consume prompt input.
    #[allow(clippy::too_many_arguments)]
    fn launch_service_process(
        service: &troe_fmt_scfg::ServiceConfig,
        namespace: &OwnedNamespace,
        shell: &mut Shell,
        residents: &mut ResidentProcessTable,
        processes: &SharedProcessTable,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        shell_id: TaskId,
        shell_capabilities: Capabilities,
        runtime: &SharedRuntime,
    ) -> CommandStatus {
        let line = alloc::format!("{} &", service.name());
        let mut input = EmptyInput;
        let mut output = DiscardOutput;
        let mut error = DiscardOutput;
        let mut runner = KexCommandRunner {
            accounting,
            scheduler,
            residents,
            processes: processes.clone(),
            resident_owner: ResidentOwner::Service(service.id()),
            service_initial_handles: Some(service.initial_handles()),
            service_capability_bits: Some(service.capability_bits()),
            service_runtime: None,
            shell_id,
            shell_capabilities,
            runtime: runtime.clone(),
            session_terminal: None,
            pending_script_lines: None,
            composed_namespace: Rc::clone(namespace),
        };
        shell.execute_with_external(&line, &mut input, &mut output, &mut error, &mut runner)
    }

    impl ServiceRuntime {
        fn new(config: SystemConfig, recovery: bool) -> Result<Self, ()> {
            let supervisor = Supervisor::from_config(&config, recovery).map_err(|_| ())?;
            Ok(Self { config, supervisor })
        }

        #[allow(clippy::too_many_arguments)]
        fn drive(
            &mut self,
            namespace: &OwnedNamespace,
            shell: &mut Shell,
            residents: &mut ResidentProcessTable,
            processes: &SharedProcessTable,
            scheduler: &mut Scheduler,
            accounting: &mut OwnedAccounting,
            shell_id: TaskId,
            shell_capabilities: Capabilities,
            runtime: &SharedRuntime,
        ) -> Result<(), ()> {
            let now = runtime.borrow().now();
            for service in self.config.services() {
                let Some((process, outcome, log)) = residents.take_service_terminal(service.id())
                else {
                    continue;
                };
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(RESIDENT_PROCESS_LOG_BYTES)
                    .map_err(|_| ())?;
                bytes.resize(RESIDENT_PROCESS_LOG_BYTES, 0);
                let count = log.try_borrow().map_err(|_| ())?.copy_recent(&mut bytes);
                self.supervisor
                    .append_log(service.id(), &bytes[..count])
                    .map_err(|_| ())?;
                let state = self
                    .supervisor
                    .snapshot(service.id())
                    .map_err(|_| ())?
                    .state;
                if matches!(state, ServiceState::Stopping { .. }) {
                    self.supervisor
                        .stopped(service.id(), process, now)
                        .map_err(|_| ())?;
                } else {
                    let status = match outcome {
                        CommandApplicationOutcome::Exited(status) => Some(status),
                        CommandApplicationOutcome::Faulted(_) => None,
                    };
                    self.supervisor
                        .exited(service.id(), process, status, now)
                        .map_err(|_| ())?;
                }
            }

            for _ in 0..=self.config.services().len() {
                let Some(action) = self.supervisor.next_action(now) else {
                    break;
                };
                match action {
                    SupervisorAction::Launch { service_id } => {
                        let service = self
                            .config
                            .services()
                            .iter()
                            .find(|service| service.id() == service_id)
                            .ok_or(())?;
                        let expected_path = alloc::format!("/bin/{}.kex", service.name());
                        if service.artifact_path() != expected_path {
                            self.supervisor
                                .launch_failed(service_id, now)
                                .map_err(|_| ())?;
                            continue;
                        }
                        let status = launch_service_process(
                            service,
                            namespace,
                            shell,
                            residents,
                            processes,
                            scheduler,
                            accounting,
                            shell_id,
                            shell_capabilities,
                            runtime,
                        );
                        if status != CommandStatus::Success {
                            self.supervisor
                                .launch_failed(service_id, now)
                                .map_err(|_| ())?;
                            continue;
                        }
                        let process = residents.service_task(service_id).ok_or(())?;
                        self.supervisor
                            .launched(service_id, process, now)
                            .map_err(|_| ())?;
                        // SCFG v1's first resident implementation defines
                        // readiness as successful admission into the event loop.
                        // A typed readiness notification can tighten this
                        // boundary without changing the supervisor state model.
                        self.supervisor.ready(service_id, process).map_err(|_| ())?;
                    }
                    SupervisorAction::RequestStop { service_id, .. }
                    | SupervisorAction::ForceStop { service_id, .. } => {
                        residents.request_service_cancel(service_id)?;
                    }
                    SupervisorAction::ActivatePreviousGeneration { .. }
                    | SupervisorAction::EnterRecovery { .. } => return Err(()),
                }
            }
            Ok(())
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
                ExternalCommandReference::CatalogName(name) => {
                    Some(alloc::format!("/bin/{name}.kex"))
                }
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
            let submitted_shell_script = shell_script_required
                .then(|| Rc::new(RefCell::new(SubmittedShellScript::default())));
            let timer_task_id = timer_required.then(|| Rc::new(Cell::new(None)));
            let services = (|| -> Result<Vec<CommandStartupService>, ()> {
                let mut services = Vec::new();
                services.try_reserve_exact(service_count).map_err(|_| ())?;
                services.push(CommandStartupService {
                    port: register_command_service(
                        &mut dispatcher,
                        CommandInvocationService::new_with_environment(
                            cwd,
                            words,
                            &command::CONVENTIONAL_ENVIRONMENT,
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
                            command_application_error(
                                &mut **output,
                                command,
                                "service setup failed",
                            )
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
                            command_application_error(
                                &mut **output,
                                command,
                                "application rejected",
                            )
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
                        let _event = troe_machine::wait_for_runtime_event_timeout(
                            RESIDENT_POLL_MILLISECONDS,
                        );
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

    fn copy_service_output(
        residents: &ResidentProcessTable,
        service_id: u32,
        name: &str,
        runtime: &ServiceRuntime,
        stdout: &mut dyn Output,
        stderr: &mut dyn Output,
    ) -> CommandStatus {
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(RESIDENT_PROCESS_LOG_BYTES).is_err() {
            return command_application_error(stderr, "svc", "buffer allocation failed");
        }
        bytes.resize(RESIDENT_PROCESS_LOG_BYTES, 0);
        let (count, dropped) = if let Some(log) = residents.copy_service_log(service_id, &mut bytes)
        {
            log
        } else {
            let Ok(count) = runtime.supervisor.copy_log(service_id, &mut bytes) else {
                return command_application_error(stderr, "svc", "service log unavailable");
            };
            let Ok(snapshot) = runtime.supervisor.snapshot(service_id) else {
                return command_application_error(stderr, "svc", "service state unavailable");
            };
            (count, snapshot.dropped_log_bytes)
        };
        if dropped != 0 {
            let notice = alloc::format!("[{name}: {dropped} earlier bytes discarded]\n");
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

    fn service_id_by_name(config: &SystemConfig, name: &str) -> Option<u32> {
        config
            .services()
            .iter()
            .find(|service| service.name() == name)
            .map(troe_fmt_scfg::ServiceConfig::id)
    }

    const fn service_state_label(state: ServiceState) -> &'static str {
        match state {
            ServiceState::Stopped => "stopped",
            ServiceState::Starting { .. } => "starting",
            ServiceState::Ready { .. } => "ready",
            ServiceState::Backoff { .. } => "backoff",
            ServiceState::Stopping { .. } => "stopping",
            ServiceState::Failed { .. } => "failed",
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

    fn register_nested_input<'service>(
        dispatcher: &mut Dispatcher<'service>,
        input: &NestedInput<'service>,
        pipe_streams: &mut Vec<PipeStreamService>,
    ) -> Result<CommandStartupService, ()> {
        let port = match input {
            NestedInput::Empty => {
                register_command_service(dispatcher, ApplicationEmptyInputService)?
            }
            NestedInput::Borrowed(input) => register_command_service(
                dispatcher,
                ApplicationInputService {
                    input: input.clone(),
                },
            )?,
            NestedInput::Pipe {
                pipes,
                owner,
                token,
            } => {
                pipe_streams.try_reserve(1).map_err(|_| ())?;
                let endpoint = pipes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .attach(*owner, *token, PipeDirection::Reader)
                    .map_err(|_| ())?;
                let port = register_command_service(
                    dispatcher,
                    ApplicationPipeInputService {
                        pipes: pipes.clone(),
                        endpoint,
                    },
                )?;
                pipe_streams.push(PipeStreamService {
                    interface: troe_abi::interface::STANDARD_INPUT,
                    pipes: pipes.clone(),
                    endpoint,
                });
                port
            }
        };
        Ok(CommandStartupService {
            port,
            interface: troe_abi::interface::STANDARD_INPUT,
            major: stream::MAJOR,
            minor: stream::MINOR,
        })
    }

    fn register_nested_output<'service>(
        dispatcher: &mut Dispatcher<'service>,
        output: &NestedOutput<'service>,
        interface: u32,
        pipe_streams: &mut Vec<PipeStreamService>,
    ) -> Result<CommandStartupService, ()> {
        let port = match output {
            NestedOutput::Discard => {
                register_command_service(dispatcher, ApplicationDiscardOutputService)?
            }
            NestedOutput::Borrowed(output) => register_command_service(
                dispatcher,
                ApplicationOutputService {
                    output: output.clone(),
                },
            )?,
            NestedOutput::Log(log) => {
                register_command_service(dispatcher, ApplicationLogService { log: log.clone() })?
            }
            NestedOutput::Pipe {
                pipes,
                owner,
                token,
            } => {
                pipe_streams.try_reserve(1).map_err(|_| ())?;
                let endpoint = pipes
                    .try_borrow_mut()
                    .map_err(|_| ())?
                    .attach(*owner, *token, PipeDirection::Writer)
                    .map_err(|_| ())?;
                let port = register_command_service(
                    dispatcher,
                    ApplicationPipeOutputService {
                        pipes: pipes.clone(),
                        endpoint,
                    },
                )?;
                pipe_streams.push(PipeStreamService {
                    interface,
                    pipes: pipes.clone(),
                    endpoint,
                });
                port
            }
        };
        Ok(CommandStartupService {
            port,
            interface,
            major: stream::MAJOR,
            minor: stream::MINOR,
        })
    }

    fn command_application_error(
        stderr: &mut dyn Output,
        command: &str,
        message: &str,
    ) -> CommandStatus {
        command_application_status_error(stderr, command, message, CommandStatus::Failure)
    }

    fn command_application_status_error(
        stderr: &mut dyn Output,
        command: &str,
        message: &str,
        status: CommandStatus,
    ) -> CommandStatus {
        let _ignored = write_all(stderr, alloc::format!("{command}: {message}\n").as_bytes());
        status
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
        let shell_console = Rc::new(RefCell::new(NativeShellConsole::new(
            task.accounting.framebuffer,
        )));
        let framebuffer_ready = shell_console.borrow().has_framebuffer();
        if shell_console.borrow_mut().replay_completed_boot().is_err() {
            fatal(b"fatal: framebuffer boot replay failed\n");
        }
        let (_console_port, console_handle) = dispatcher
            .register(
                Box::new(ConsoleService::new(SharedConsoleOutput::new(Rc::clone(
                    &shell_console,
                )))),
                Rights::CALL,
            )
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
        let (mut namespace, root_mode) = compose_namespace(task.accounting, &mut console);
        if let Some(config) = task.accounting.selected_config.as_ref() {
            let active_memory = normalize_memory_policy_toml(config.memory())
                .unwrap_or_else(|_| fatal(b"fatal: cannot normalize active memory policy\n"));
            namespace
                .replace_system_config(
                    config.generation(),
                    &[("system/resources/memory.toml", active_memory.as_bytes())],
                )
                .unwrap_or_else(|_| fatal(b"fatal: cannot project active configuration\n"));
        }
        let motd = namespace
            .read_file("/", "/recovery/motd")
            .unwrap_or_else(|_| fatal(b"fatal: cannot read /recovery/motd\n"));
        let initial_snapshot = machine_snapshot(task.accounting);
        let machine_control = task.capabilities.contains(Capabilities::MACHINE_CONTROL);
        // Generated /sys state is composition authority, so it is written here
        // rather than by the session, which holds only the client contract.
        let mut namespace = namespace;
        if namespace
            .set_system_file("/sys/arch", architecture_line().as_bytes())
            .is_err()
            || namespace
                .set_system_file("/sys/version", b"0.1.0\n")
                .is_err()
        {
            fatal(b"fatal: cannot compose namespace\n");
        }
        let memory_report = format_memory_report(
            architecture(),
            initial_snapshot,
            None,
            namespace.memory_stats(),
        );
        if namespace
            .set_system_file("/sys/memory", memory_report.as_bytes())
            .is_err()
        {
            fatal(b"fatal: cannot compose namespace\n");
        }
        let namespace: OwnedNamespace = Rc::new(RefCell::new(namespace));
        let session: SharedNamespace = Rc::clone(&namespace) as SharedNamespace;
        let Ok(mut shell) = Shell::new(session, machine_control) else {
            fatal(b"fatal: cannot compose namespace\n");
        };
        let runtime = finish_shell_startup(
            &mut console,
            &motd,
            root_mode,
            task.accounting.firmware_wall_seconds,
        );
        // Providers were mounted before the runtime existed, so the clock is
        // installed here and reaches both those mounts and every later one.
        // It goes through the composition handle rather than the session,
        // because installing a clock into every provider is composition.
        namespace
            .borrow_mut()
            .set_wall_clock(Rc::new(RuntimeWallClock {
                runtime: runtime.clone(),
            }));
        let editor_config = EditorConfig::standard();
        if editor_config.max_line_bytes() > MAX_LINE_BYTES {
            fatal(b"fatal: editor line policy exceeds shell parser policy\n");
        }
        let completion_config = CompletionConfig::standard();
        // One decoder pair owns session input. Handing the terminal between the
        // line editor and a foreground process cannot split a UTF-8 or escape
        // sequence across two decoding states.
        let terminal = Rc::new(RefCell::new(
            SessionTerminal::new(
                runtime.clone(),
                SharedConsoleOutput::new(Rc::clone(&shell_console)),
                editor_config.input(),
                KeyboardConfig::standard(),
            )
            .unwrap_or_else(|()| fatal(b"fatal: cannot allocate session terminal\n")),
        ));
        let mut editor = LineEditor::new(editor_config);
        let mut residents = ResidentProcessTable::new()
            .unwrap_or_else(|()| fatal(b"fatal: cannot allocate resident process table\n"));
        let processes = Rc::new(RefCell::new(
            ProcessTable::new(troe_task::MAX_TASKS)
                .unwrap_or_else(|_| fatal(b"fatal: cannot allocate process registry\n")),
        ));
        let mut services = task
            .accounting
            .selected_config
            .take()
            .map(|config| {
                ServiceRuntime::new(config, matches!(root_mode, NativeRootMode::Recovery))
            })
            .transpose()
            .unwrap_or_else(|()| fatal(b"fatal: cannot initialize service supervisor\n"));
        if let Some(services) = services.as_mut() {
            services
                .drive(
                    &namespace,
                    &mut shell,
                    &mut residents,
                    &processes,
                    task.scheduler,
                    task.accounting,
                    task.task_id,
                    task.capabilities,
                    &runtime,
                )
                .unwrap_or_else(|()| fatal(b"fatal: service activation failed\n"));
        }
        residents
            .pump(
                task.scheduler,
                task.accounting,
                task.task_id,
                task.capabilities,
            )
            .unwrap_or_else(|()| fatal(b"fatal: initial service process pump failed\n"));

        loop {
            let prompt = shell_prompt(&shell);
            if write_all(&mut console, prompt.as_bytes()).is_err() {
                fatal(b"fatal: native console write failed\n");
            }
            let Ok(line) = read_edited_line(
                &mut editor,
                &terminal,
                &namespace,
                &mut shell,
                &runtime,
                &mut residents,
                &processes,
                &mut services,
                task.scheduler,
                task.accounting,
                task.task_id,
                task.capabilities,
                completion_config,
                &prompt,
                &mut console,
            ) else {
                fatal(b"fatal: native console input failed\n");
            };
            #[cfg(feature = "acceptance-probes")]
            let diagnostics_fault_probe = line == "service-probe fault";
            #[cfg(feature = "acceptance-probes")]
            if diagnostics_fault_probe {
                DIAGNOSTICS_FAULT_PROBE_CONTAINED.store(false, Ordering::Release);
                if DIAGNOSTICS_FAULT_PROBE_REQUESTED.swap(true, Ordering::AcqRel) {
                    fatal(b"fatal: diagnostics fault probe already pending\n");
                }
            }
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
            let confirmation_cwd = String::from(shell.cwd());
            let confirmed = confirm_untrusted_application_paths(
                &line,
                &confirmation_cwd,
                &terminal,
                &namespace,
                &mut shell,
                &runtime,
                &mut residents,
                &processes,
                &mut services,
                task.scheduler,
                task.accounting,
                task.task_id,
                task.capabilities,
                completion_config,
                &mut console,
            )
            .unwrap_or_else(|()| fatal(b"fatal: executable confirmation failed\n"));
            if !confirmed {
                continue;
            }
            let mut input = SessionTerminalInput::new(Rc::clone(&terminal));
            let mut error = NativeConsole;
            let mut external = KexCommandRunner {
                composed_namespace: Rc::clone(&namespace),
                accounting: task.accounting,
                scheduler: task.scheduler,
                residents: &mut residents,
                processes: processes.clone(),
                resident_owner: ResidentOwner::Session,
                service_initial_handles: None,
                service_capability_bits: None,
                service_runtime: services.as_mut(),
                shell_id: task.task_id,
                shell_capabilities: task.capabilities,
                runtime: runtime.clone(),
                session_terminal: Some(Rc::clone(&terminal)),
                pending_script_lines: None,
            };
            #[cfg(feature = "acceptance-probes")]
            let execution_line = if diagnostics_fault_probe {
                "mem"
            } else {
                &line
            };
            #[cfg(not(feature = "acceptance-probes"))]
            let execution_line = &line;
            let _status = shell.execute_with_external(
                execution_line,
                &mut input,
                &mut console,
                &mut error,
                &mut external,
            );
            drop(external);
            residents
                .pump(
                    task.scheduler,
                    task.accounting,
                    task.task_id,
                    task.capabilities,
                )
                .unwrap_or_else(|()| fatal(b"fatal: resident process pump failed\n"));
            if let Some(services) = services.as_mut() {
                services
                    .drive(
                        &namespace,
                        &mut shell,
                        &mut residents,
                        &processes,
                        task.scheduler,
                        task.accounting,
                        task.task_id,
                        task.capabilities,
                        &runtime,
                    )
                    .unwrap_or_else(|()| fatal(b"fatal: service supervision failed\n"));
            }
            #[cfg(feature = "acceptance-probes")]
            if diagnostics_fault_probe {
                if DIAGNOSTICS_FAULT_PROBE_REQUESTED.load(Ordering::Acquire)
                    || !DIAGNOSTICS_FAULT_PROBE_CONTAINED.swap(false, Ordering::AcqRel)
                {
                    fatal(b"fatal: diagnostics server fault was not contained\n");
                }
                if write_all(
                    &mut console,
                    b"isolated diagnostics server fault contained\n",
                )
                .is_err()
                {
                    fatal(b"fatal: diagnostics fault probe report failed\n");
                }
            }
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

    #[allow(clippy::too_many_arguments)]
    fn confirm_untrusted_application_paths(
        line: &str,
        cwd: &str,
        terminal: &SharedSessionTerminal,
        namespace: &OwnedNamespace,
        shell: &mut Shell,
        runtime: &SharedRuntime,
        residents: &mut ResidentProcessTable,
        processes: &SharedProcessTable,
        services: &mut Option<ServiceRuntime>,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        shell_id: TaskId,
        shell_capabilities: Capabilities,
        completion_config: CompletionConfig,
        console: &mut dyn Output,
    ) -> Result<bool, ()> {
        let Ok(command_list) = parse_command_list(line) else {
            return Ok(true);
        };
        for stage in command_list
            .entries
            .into_iter()
            .flat_map(|entry| entry.pipeline.stages)
        {
            let Some(command) = stage.words.first().map(Word::text) else {
                continue;
            };
            if !matches!(
                external_command_reference(command),
                Some(ExternalCommandReference::Path(_))
            ) {
                continue;
            }
            let Ok(path) = canonicalize(cwd, command) else {
                continue;
            };
            if path.starts_with("/bin/") {
                continue;
            }
            let prompt =
                alloc::format!("Run untrusted application '{command}' outside /bin? [y/N] ");
            write_all(console, prompt.as_bytes())?;
            let mut confirmation_editor = LineEditor::new(EditorConfig::standard());
            let answer = read_edited_line(
                &mut confirmation_editor,
                terminal,
                namespace,
                shell,
                runtime,
                residents,
                processes,
                services,
                scheduler,
                accounting,
                shell_id,
                shell_capabilities,
                completion_config,
                &prompt,
                console,
            )?;
            if !answer.eq_ignore_ascii_case("y") {
                write_all(console, b"execution cancelled\n")?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn read_edited_line(
        editor: &mut LineEditor,
        terminal: &SharedSessionTerminal,
        namespace: &OwnedNamespace,
        shell: &mut Shell,
        runtime: &SharedRuntime,
        residents: &mut ResidentProcessTable,
        processes: &SharedProcessTable,
        services: &mut Option<ServiceRuntime>,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        shell_id: TaskId,
        shell_capabilities: Capabilities,
        completion_config: CompletionConfig,
        prompt: &str,
        console: &mut dyn Output,
    ) -> Result<String, ()> {
        loop {
            let key = loop {
                let event = loop {
                    if let Some(event) = runtime.borrow_mut().poll_input_event() {
                        break event;
                    }
                    residents.pump(scheduler, accounting, shell_id, shell_capabilities)?;
                    if let Some(services) = services.as_mut() {
                        services.drive(
                            namespace,
                            shell,
                            residents,
                            processes,
                            scheduler,
                            accounting,
                            shell_id,
                            shell_capabilities,
                            runtime,
                        )?;
                    }
                    let _event =
                        troe_machine::wait_for_runtime_event_timeout(RESIDENT_POLL_MILLISECONDS);
                };
                let key = terminal.try_borrow_mut().map_err(|_| ())?.decode(event);
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
                    let mut environment = NativeCompletionEnvironment {
                        residents,
                        services: services.as_ref(),
                        volumes: &accounting.boot_mount_manifest,
                    };
                    complete_editor(
                        editor,
                        shell,
                        completion_config,
                        &mut environment,
                        prompt,
                        console,
                    )?;
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
        environment: &mut dyn CompletionEnvironment,
        prompt: &str,
        console: &mut dyn Output,
    ) -> Result<(), ()> {
        let completion =
            shell.complete_with_environment(editor.line(), editor.cursor(), config, environment);
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

    struct NativeCompletionEnvironment<'state> {
        residents: &'state ResidentProcessTable,
        services: Option<&'state ServiceRuntime>,
        volumes: &'state BootMountManifest,
    }

    impl CompletionEnvironment for NativeCompletionEnvironment<'_> {
        fn visit(&mut self, domain: DynamicCompletionDomain, visitor: &mut dyn CompletionVisitor) {
            match domain {
                DynamicCompletionDomain::Job => {
                    for job in self
                        .residents
                        .jobs
                        .iter()
                        .filter(|job| job.owner == ResidentOwner::Session)
                    {
                        let id = alloc::format!("{}", job.id);
                        if !visitor.candidate(&id) {
                            break;
                        }
                    }
                }
                DynamicCompletionDomain::Service => {
                    let Some(services) = self.services else {
                        return;
                    };
                    for service in services.config.services() {
                        if !visitor.candidate(service.name()) {
                            break;
                        }
                    }
                }
                DynamicCompletionDomain::Volume => {
                    for volume in self.volumes.entries() {
                        if !visitor.candidate(volume.name()) {
                            break;
                        }
                    }
                }
            }
        }
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
    ) -> Result<SharedDiagnosticsSnapshot, ()> {
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
        let snapshot = diagnostics::encode_snapshot(diagnostics::Snapshot {
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
        .map_err(|_| ())?;
        Ok(Rc::new(snapshot))
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

//! Shell integration: the shell task, its banner, completion, and machine
//! actions.
//!
//! `run_shell_task` is the interactive loop. Around it sit the boot banner,
//! the completion environment the line editor consults, the untrusted-path
//! confirmation, and the reboot and shutdown actions the shell may request.

use crate::console::{NativeConsole, NativeShellConsole, SharedConsoleOutput};
use crate::handles::{OwnedNamespace, SharedProcessTable, SharedRuntime};
use crate::handoff::write_boot_status;
use crate::kex::KexCommandRunner;
#[cfg(feature = "acceptance-probes")]
use crate::limits::ROOTFS;
use crate::machine::OwnedAccounting;
use crate::namespace::{architecture_line, compose_namespace};
use crate::network::{
    KernelNetwork, NetworkStatus, discover_network_service, network_boot_label, subnet_prefix,
    write_ipv4,
};
use crate::resident::{ResidentOwner, ResidentProcessTable};
use crate::runtime::{KernelRuntime, KernelRuntimeCapability, RuntimeInitError};
use crate::service::clock::RuntimeWallClock;
use crate::service::diagnostics::machine_snapshot;
#[cfg(feature = "acceptance-probes")]
use crate::service::diagnostics::{
    DIAGNOSTICS_FAULT_PROBE_CONTAINED, DIAGNOSTICS_FAULT_PROBE_REQUESTED,
};
use crate::session::{
    SessionTerminal, SessionTerminalInput, SharedSessionTerminal, read_edited_line,
};
use crate::storage::NativeRootMode;
use crate::supervision::ServiceRuntime;
use crate::support::{architecture, fatal, usize_as_u64, write_all};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use core::fmt::Write as _;
#[cfg(feature = "acceptance-probes")]
use core::sync::atomic::Ordering;
use troe_core::{MAX_LINE_BYTES, Output};
use troe_dispatch::{ConsoleService, DispatchedOutput, Dispatcher, Rights};
use troe_fmt_bmnt::BootMountManifest;
use troe_fmt_scfg::normalize_memory_policy_toml;
use troe_fs_api::canonicalize;
use troe_memory::PhysicalRange;
use troe_shell::{
    CompletionConfig, CompletionEnvironment, CompletionVisitor, DynamicCompletionDomain,
    ExternalCommandReference, MachineAction, SharedNamespace, Shell, Word,
    external_command_reference, format_memory_report, parse_command_list,
};
use troe_task::{Capabilities, ProcessTable, Scheduler, TaskId, TaskStep};
use troe_terminal::{EditorConfig, KeyboardConfig, LineEditor};

pub(crate) struct ShellTask<'a> {
    pub(crate) accounting: &'a mut OwnedAccounting,
    pub(crate) scheduler: &'a mut Scheduler,
    pub(crate) task_id: TaskId,
    pub(crate) capabilities: Capabilities,
    pub(crate) stack: PhysicalRange,
}

pub(crate) fn write_shell_banner(
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
    summary
        .push_str("\n\nWelcome to TROE.\nType `man COMMAND` for help. Tab completes commands.\n\n");
    write_all(console, summary.as_bytes()).is_ok()
}

pub(crate) fn install_command_runtime(
    console: &mut dyn Output,
    firmware_wall_seconds: Option<u64>,
) -> (Option<NetworkStatus>, SharedRuntime) {
    let service = discover_network_service();
    let runtime_state = match KernelRuntime::new(service.clone(), firmware_wall_seconds) {
        Ok(runtime) => runtime,
        Err(RuntimeInitError::Clock) => fatal(b"fatal: monotonic runtime unavailable\n"),
        Err(RuntimeInitError::InputMetadata) => fatal(b"fatal: runtime input metadata exhausted\n"),
    };
    let runtime = Rc::new(RefCell::new(runtime_state));
    if let Some(service) = service {
        let mut network = KernelNetwork::new(service);
        let mut bootstrap_runtime = KernelRuntimeCapability {
            runtime: runtime.clone(),
        };
        let status = network.configure_dhcp(&mut bootstrap_runtime).ok();
        let label = status.map_or_else(|| String::from("Configuring network"), network_boot_label);
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

pub(crate) fn finish_shell_startup(
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

pub(crate) fn shell_prompt(shell: &Shell) -> String {
    let mut prompt = String::from("sh:");
    prompt.push_str(shell.cwd());
    prompt.push_str("> ");
    prompt
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_shell_task(task: &mut ShellTask<'_>) -> TaskStep {
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
        .map(|config| ServiceRuntime::new(config, matches!(root_mode, NativeRootMode::Recovery)))
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

pub(crate) fn perform_machine_action(action: MachineAction, console: &mut dyn Output) -> ! {
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
pub(crate) fn confirm_untrusted_application_paths(
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
        let prompt = alloc::format!("Run untrusted application '{command}' outside /bin? [y/N] ");
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

pub(crate) struct NativeCompletionEnvironment<'state> {
    pub(crate) residents: &'state ResidentProcessTable,
    pub(crate) services: Option<&'state ServiceRuntime>,
    pub(crate) volumes: &'state BootMountManifest,
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

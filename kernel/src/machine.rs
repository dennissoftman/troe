//! The owned machine: its accounting root and its cooperative run loop.
//!
//! `OwnedAccounting` is the state the kernel owns after the firmware handoff —
//! the frame allocator, the kernel mapping plan, the task stacks, the native
//! block devices, the selected system configuration, and the runtime mount
//! registry. `run_owned` builds it and never returns.
//!
//! ADR 0035 Phase D and E want several of its fields out of kernel privilege:
//! `native_blocks`, `native_statefs`, `native_generation`, `selected_config`,
//! and `runtime_mounts` are storage authority, and they are held here because
//! the kernel still performs volume activation itself.

use crate::handles::{SharedRandom, SharedRuntimeMounts};
use crate::handoff::reservation::TaskStackLayout;
use crate::handoff::write_machine_boot_status;
use crate::limits::{
    BOOT_RUNTIME_LABEL, SERVER_TASK_STACK_PAGES, SHELL_SCHEDULER_SLOT, SHELL_TASK_STACK_PAGES,
    TASK_STACK_COUNT, TASK_STACK_PAGES,
};
#[cfg(feature = "acceptance-probes")]
use crate::probes::run_ipc_baseline_verification;
use crate::probes::{run_application_load_verification, run_isolation_verification};
use crate::shell::{ShellTask, run_shell_task};
use crate::storage::NativeGenerationState;
use crate::support::fatal;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use troe_console::FramebufferDescriptor;
use troe_fmt_bmnt::BootMountManifest;
use troe_fmt_scfg::{MemoryPolicy, SystemConfig};
use troe_fs_api::FileSystemProvider;
use troe_memory::{FrameAllocator, MappingPlan, MemoryMapStats, PhysicalRange};
use troe_task::{Capabilities, Scheduler, StackResource, TaskId, TaskStep};

pub(crate) struct OwnedAccounting {
    pub(crate) map: MemoryMapStats,
    pub(crate) frames: FrameAllocator,
    #[cfg(feature = "acceptance-probes")]
    pub(crate) execute_probe_address: usize,
    pub(crate) task_stacks: [TaskStackLayout; TASK_STACK_COUNT],
    pub(crate) framebuffer: Option<FramebufferDescriptor>,
    pub(crate) kernel_runtime: PhysicalRange,
    pub(crate) kernel_plan: MappingPlan,
    pub(crate) native_blocks: RefCell<Vec<troe_machine::NativeVirtioBlock>>,
    pub(crate) native_statefs: RefCell<Option<Box<dyn FileSystemProvider>>>,
    pub(crate) native_generation: NativeGenerationState,
    pub(crate) selected_config: Option<SystemConfig>,
    pub(crate) memory_policy: MemoryPolicy,
    pub(crate) application_committed_pages: u64,
    pub(crate) private_metadata_bytes: u64,
    pub(crate) random: SharedRandom,
    pub(crate) firmware_wall_seconds: Option<u64>,
    pub(crate) boot_mount_manifest: BootMountManifest,
    pub(crate) runtime_mounts: SharedRuntimeMounts,
    /// Complete `TZ=VALUE` entry resolved from desired state at boot.
    ///
    /// ADR 0068 resolves the zone once, so an edit to `/config` takes
    /// effect at the next session rather than changing a running one,
    /// which is what ADR 0043 requires of desired state. `None` keeps the
    /// conventional `UTC0` the ABI compiles in.
    pub(crate) session_timezone: RefCell<Option<String>>,
}

pub(crate) struct CooperativeService {
    remaining_yields: u8,
    completed_steps: u8,
}

pub(crate) fn run_owned(mut accounting: OwnedAccounting) -> ! {
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
    if dispatched != Some(shell_id) || scheduler.stats().owned_stack_pages != SHELL_TASK_STACK_PAGES
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

pub(crate) fn run_cooperative_services(
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

pub(crate) fn cooperative_service_step(service: &mut CooperativeService) -> TaskStep {
    service.completed_steps = service.completed_steps.saturating_add(1);
    if service.remaining_yields == 0 {
        TaskStep::ExitSuccess
    } else {
        service.remaining_yields -= 1;
        TaskStep::Yield
    }
}

pub(crate) fn complete_task_step(
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

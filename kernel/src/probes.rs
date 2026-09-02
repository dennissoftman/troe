//! Acceptance-only verification probes.
//!
//! These run inside the acceptance image to demonstrate properties the QEMU
//! scenarios then assert: IPC latency baselines for owned and isolated calls,
//! containment of a user-mode fault, and the application load, thread-pointer,
//! and heap-growth-limit paths. The production image builds none of it.

#[cfg(feature = "acceptance-probes")]
use crate::artifacts::native_application_target;
use crate::artifacts::native_kex_artifact;
#[cfg(feature = "acceptance-probes")]
use crate::invocation::{
    CommandApplicationOutcome, CommandStartupService, run_command_application,
};
use crate::limits::{
    APPLICATION_INTERFACE_ECHO, APPLICATION_TIMESLICE_MILLISECONDS, ISOLATED_MESSAGE,
    ISOLATED_PRIVATE_PAGES, ISOLATED_STACK_PAGES, ISOLATED_TABLE_PAGES, STAGE6_USER_REGIONS,
    USER_CODE_BASE, USER_STACK_BASE,
};
#[cfg(feature = "acceptance-probes")]
use crate::limits::{
    DIAGNOSTICS_SERVER_MAX_CONTEXTS, DIAGNOSTICS_SERVER_MAX_RETAINED_REQUESTS,
    IPC_BASELINE_SAMPLES, IPC_BASELINE_WARMUP_CALLS,
};
use crate::machine::OwnedAccounting;
use crate::memory::isolated::{
    allocate_isolated, build_isolated_plan, prepare_isolated_memory, reclaim_isolated,
    rollback_isolated_task,
};
use crate::memory::launch::{
    allocate_application, clear_provisional_loader_ownership, prepare_application_memory,
    reclaim_application, rollback_application_task,
};
use crate::resident::launch::parse_native_application;
#[cfg(feature = "acceptance-probes")]
use crate::service::diagnostics::{
    DiagnosticsBenchmarkEndpoint, DiagnosticsBenchmarkExchange, DiagnosticsBenchmarkRunner,
    run_diagnostics_benchmark_task,
};
use alloc::boxed::Box;
#[cfg(feature = "acceptance-probes")]
use alloc::rc::Rc;
#[cfg(feature = "acceptance-probes")]
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "acceptance-probes")]
use core::cell::RefCell;
#[cfg(feature = "acceptance-probes")]
use core::fmt::Write as _;
#[cfg(feature = "acceptance-probes")]
use troe_application::ABI_MINOR;
use troe_application::{
    ApplicationLimits, InitialHandle, LoaderResource, LoaderTransaction, PAGE_BYTES, StartupInfo,
};
#[cfg(feature = "acceptance-probes")]
use troe_application::{ParseError, parse_kex};
use troe_dispatch::{
    CopiedMessage, Dispatcher, HandleOwner, ReplyStatus, Request, Rights, Service, ServiceReply,
};
use troe_memory::BASE_PAGE_SIZE;
#[cfg(feature = "acceptance-probes")]
use troe_task::TaskStep;
use troe_task::{Capabilities, IsolationResource, Scheduler, StackResource, TaskFault};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ApplicationProbe {
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

pub(crate) struct EchoService;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum IsolationProbe {
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
            Self::IllegalInstruction | Self::UnexpectedEntry => Some(TaskFault::IllegalInstruction),
            Self::InvalidOpcode
            | Self::InvalidCallEncoding
            | Self::InvalidPointer
            | Self::OversizeMessage
            | Self::InvalidStatus => Some(TaskFault::InvalidCall),
        }
    }
}

impl Service for EchoService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != 1 {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        ServiceReply::with_payload(ReplyStatus::Success, request.payload())
    }
}

#[cfg(feature = "acceptance-probes")]
pub(crate) fn run_ipc_baseline_verification(
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
pub(crate) fn run_isolated_ipc_baseline_verification(
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
        let step = troe_machine::run_task_step(stack, &mut runner, run_diagnostics_benchmark_task)
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
pub(crate) fn ipc_percentile(sorted: &[u64; IPC_BASELINE_SAMPLES], percentile: usize) -> u64 {
    let rank = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

pub(crate) fn run_isolation_verification(
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
pub(crate) fn run_one_isolated(
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
    let Ok(address_space) = troe_machine::build_user_address_space(&plan, allocation.tables) else {
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
    let Ok(task_id) = scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
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
        let outcome =
            troe_machine::run_isolated(address_space, USER_CODE_BASE, stack_top, &mut copied_bytes)
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
                if reply.status() != ReplyStatus::Success || reply.payload() != ISOLATED_MESSAGE {
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
        if dispatcher.call(handle, 1, b"stale") != Err(troe_dispatch::DispatchError::InvalidHandle)
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

pub(crate) fn run_application_load_verification(
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
pub(crate) fn verify_application_thread_pointer(
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
pub(crate) fn verify_application_heap_growth_limit(
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
pub(crate) fn require_staged_rejection(source: &[u8], expected: ParseError) -> Result<(), ()> {
    let mut staging = Vec::new();
    staging.try_reserve_exact(source.len()).map_err(|_| ())?;
    staging.extend_from_slice(source);
    match parse_kex(&staging, native_application_target(), ABI_MINOR) {
        Err(error) if error == expected => Ok(()),
        _ => Err(()),
    }
}

#[allow(clippy::drop_non_drop, clippy::too_many_lines)]
pub(crate) fn load_and_reclaim_application(
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
    let Ok(isolation) = IsolationResource::new(0, retained_table_pages, private_pages, 1) else {
        reclaim_application(accounting, allocation)?;
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    let Ok(stack_resource) = StackResource::new(0, stack_pages) else {
        reclaim_application(accounting, allocation)?;
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    let Ok(task_id) = scheduler.spawn_isolated(Capabilities::SERVICE, stack_resource, isolation)
    else {
        reclaim_application(accounting, allocation)?;
        clear_provisional_loader_ownership(&mut transaction);
        return Err(());
    };
    if transaction.acquire(LoaderResource::Task).is_err() {
        rollback_application_task(scheduler, task_id, dispatcher, None, accounting, allocation)?;
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
        if dispatcher.call(handle, 1, b"stale") != Err(troe_dispatch::DispatchError::InvalidHandle)
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

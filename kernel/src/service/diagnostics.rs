//! Diagnostics: the snapshot projection, the proxy service, and the two
//! in-kernel diagnostics servers.
//!
//! The snapshot is what `/sys` and the diagnostics clients read. The server
//! and benchmark runners exist for the acceptance image: they exercise the
//! server ABI, the fault-containment probe, and the IPC latency baseline from
//! inside the kernel.

#[cfg(feature = "acceptance-probes")]
use crate::artifacts::native_diagnostics_benchmark_artifact;
use crate::artifacts::native_diagnostics_server_artifact;
use crate::handles::{DiagnosticsServerFate, SharedDiagnosticsSnapshot};
use crate::invocation::{
    CommandApplicationOutcome, CommandStartupService, run_command_application,
};
#[cfg(feature = "acceptance-probes")]
use crate::limits::{
    IPC_BASELINE_SAMPLES, IPC_BASELINE_WARMUP_CALLS, IPC_ISOLATED_SERVICE_CALL_LIMIT,
};
use crate::machine::OwnedAccounting;
use crate::supervision::register_command_service;
use crate::support::usize_as_u64;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
#[cfg(feature = "acceptance-probes")]
use core::sync::atomic::{AtomicBool, Ordering};
use troe_abi::{diagnostics, server};
use troe_application::parse_kex_package;
use troe_core::{MachineMemoryOwner, MachineMemorySnapshot, MemoryStats};
use troe_dispatch::{Dispatcher, ReplyStatus, Request, Service, ServiceReply, ServiceReplyInfo};
use troe_driver::InputQueueStats;
use troe_task::{PendingOperationId, Scheduler, TaskStep, WakeReason};

pub(crate) struct ApplicationDiagnosticsProxyService;

pub(crate) struct ApplicationDiagnosticsSnapshotService {
    pub(crate) snapshot: SharedDiagnosticsSnapshot,
}

pub(crate) struct DiagnosticsServerExchange {
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

pub(crate) struct DiagnosticsServerEndpoint {
    exchange: Rc<RefCell<DiagnosticsServerExchange>>,
}

pub(crate) struct DiagnosticsServerRunner<'a> {
    accounting: &'a mut OwnedAccounting,
    scheduler: &'a mut Scheduler,
    exchange: Rc<RefCell<DiagnosticsServerExchange>>,
    artifact: &'static [u8],
    fault_probe: bool,
    outcome: Option<Result<CommandApplicationOutcome, ()>>,
}

#[cfg(feature = "acceptance-probes")]
pub(crate) struct DiagnosticsBenchmarkExchange {
    pub(crate) payload: [u8; troe_abi::MAX_MESSAGE_BYTES],
    pub(crate) payload_bytes: usize,
    pub(crate) logical_index: usize,
    pub(crate) fragment_index: usize,
    pub(crate) received: bool,
    pub(crate) expected_token: u64,
    pub(crate) started_ticks: u64,
    pub(crate) started_execution: troe_machine::ApplicationExecutionStats,
    pub(crate) started_allocations: usize,
    pub(crate) samples: [u64; IPC_BASELINE_SAMPLES],
    pub(crate) measured: usize,
    pub(crate) address_space_switches: u64,
    pub(crate) tlb_invalidations: u64,
    pub(crate) timer_programs: u64,
    pub(crate) steady_allocation_calls: u64,
}

#[cfg(feature = "acceptance-probes")]
pub(crate) struct DiagnosticsBenchmarkEndpoint {
    exchange: Rc<RefCell<DiagnosticsBenchmarkExchange>>,
}

#[cfg(feature = "acceptance-probes")]
pub(crate) struct DiagnosticsBenchmarkRunner<'a> {
    pub(crate) accounting: &'a mut OwnedAccounting,
    pub(crate) scheduler: &'a mut Scheduler,
    pub(crate) exchange: Rc<RefCell<DiagnosticsBenchmarkExchange>>,
    pub(crate) outcome: Option<Result<CommandApplicationOutcome, ()>>,
}

#[cfg(feature = "acceptance-probes")]
pub(crate) static DIAGNOSTICS_FAULT_PROBE_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "acceptance-probes")]
pub(crate) static DIAGNOSTICS_FAULT_PROBE_CONTAINED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "acceptance-probes")]
#[inline(never)]
pub(crate) fn run_diagnostics_benchmark_task(
    runner: &mut DiagnosticsBenchmarkRunner<'_>,
) -> TaskStep {
    let outcome = (|| -> Result<CommandApplicationOutcome, ()> {
        let package = parse_kex_package(native_diagnostics_benchmark_artifact()).map_err(|_| ())?;
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
pub(crate) fn run_diagnostics_server_task(runner: &mut DiagnosticsServerRunner<'_>) -> TaskStep {
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
pub(crate) fn run_diagnostics_server(
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
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != diagnostics::GET_SNAPSHOT || !request.payload().is_empty() {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        ServiceReply::with_payload(ReplyStatus::Success, self.snapshot.as_ref())
    }
}

impl Service for DiagnosticsServerEndpoint {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
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
                let reply =
                    ServiceReply::with_payload(ReplyStatus::Success, &encoded[..encoded_bytes])?;
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
                let Ok(operation) = PendingOperationId::from_abi_value(completion.token()) else {
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

    pub(crate) fn fragments(payload_bytes: usize) -> usize {
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
                                    .checked_sub(exchange.started_execution.address_space_switches)
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
                                        .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?,
                                )
                                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
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
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
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

pub(crate) fn machine_snapshot(accounting: &OwnedAccounting) -> MachineMemorySnapshot {
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

pub(crate) fn application_diagnostics_snapshot(
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

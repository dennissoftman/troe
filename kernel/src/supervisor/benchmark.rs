//! The general context runtime measured against the same boot's compatibility calls.
use super::{ServerSpec, Supervisor};
use crate::{machine::OwnedAccounting, memory::launch::reclaim_application};
use alloc::boxed::Box;
use core::fmt::Write;
use troe_dispatch::{Dispatcher, Rights};
use troe_machine::ProtectedStop;
use troe_service::{RestartPolicy, ServiceEvent, ServiceRecord, ServiceRole};
use troe_task::{Capabilities, Scheduler};

#[allow(clippy::too_many_lines)]
pub(crate) fn measure(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
    bytes: usize,
    compatibility: u64,
    transcript: &mut alloc::string::String,
) -> Result<(), ()> {
    let free = accounting.frames.free_frames();
    let mut s = Supervisor::new(&[ServerSpec {
        record: ServiceRecord::new(ServiceRole::Acceptance(0), 256, 4000, RestartPolicy::NEVER)
            .map_err(|_| ())?,
        artifact: super::probes::artifact(false),
        nested: None,
    }])?;
    while !s.lifecycle.accepts_clients(ServiceRole::Acceptance(0)) {
        s.step(scheduler, accounting)?;
    }
    let endpoint = s.instances[0].as_ref().ok_or(())?.endpoint;
    let mut dispatcher = Dispatcher::new(1, 16).map_err(|_| ())?;
    let (port, _) = dispatcher
        .register(Box::new(crate::probes::EchoService), Rights::CALL)
        .map_err(|_| ())?;
    let client = crate::ipc::launch_protected(
        accounting,
        scheduler,
        &mut dispatcher,
        port,
        crate::ipc::ProbeRequest {
            bytes,
            opcode: 1,
            argument: 0,
        },
        s.runtime.as_mut().ok_or(())?,
        endpoint,
    )?;
    let actor = client.actor.ok_or(())?;
    s.runtime
        .as_mut()
        .ok_or(())?
        .install(actor, client.session)
        .map_err(|_| ())?;
    // Warmup can consume the initialization handle's mandatory closure first.
    let mut next = actor;
    loop {
        scheduler
            .dispatch(client.task, Capabilities::SERVICE)
            .map_err(|_| ())?;
        let (mut runtime, stop) = s.runtime.take().ok_or(())?.run(next).map_err(|_| ())?;
        scheduler.yield_current(client.task).map_err(|_| ())?;
        if stop == ProtectedStop::Yielded(actor) {
            s.runtime = Some(runtime);
            break;
        }
        if !matches!(stop, ProtectedStop::Blocked(_)) {
            let _ = troe_machine::write(
                alloc::format!("ipc-phase-c-benchmark warmup-stop={stop:?}\n").as_bytes(),
            );
            return Err(());
        }
        next = runtime.poll().map_err(|_| ())?.ok_or(())?;
        s.runtime = Some(runtime);
    }
    let runtime = s.runtime.as_mut().ok_or(())?;
    runtime.measure(actor);
    let baseline = runtime.stats();
    let tags_before = troe_machine::tag_stats();
    scheduler
        .dispatch(client.task, Capabilities::SERVICE)
        .map_err(|_| ())?;
    let allocations = troe_machine::heap_stats().allocation_calls;
    let execution = troe_machine::application_execution_stats();
    let tasks = scheduler.stats();
    let (mut runtime, stop) = s.runtime.take().ok_or(())?.run(actor).map_err(|_| ())?;
    if troe_machine::heap_stats().allocation_calls != allocations
        || scheduler.stats() != tasks
        || troe_machine::application_execution_stats().timer_programs - execution.timer_programs
            != 1
    {
        return Err(());
    }
    scheduler.yield_current(client.task).map_err(|_| ())?;
    if stop != ProtectedStop::Yielded(actor) || runtime.samples().len() != 256 {
        let _ = troe_machine::write(
            alloc::format!(
                "ipc-phase-c-benchmark stop={stop:?} samples={}\n",
                runtime.samples().len()
            )
            .as_bytes(),
        );
        return Err(());
    }
    let samples: [u64; 256] = runtime.samples().try_into().map_err(|_| ())?;
    let mut sorted = samples;
    sorted.sort_unstable();
    let p95 = crate::probes::ipc_percentile(&sorted, 95);
    let stats = runtime.stats();
    let tags = troe_machine::tag_stats();
    let request_copies = stats.request_copies - baseline.request_copies;
    let reply_copies = stats.reply_copies - baseline.reply_copies;
    let roots = tags.root_writes - tags_before.root_writes;
    let full = tags.full_invalidations - tags_before.full_invalidations;
    let hits = tags.hits - tags_before.hits;
    let targeted = tags.targeted_invalidations - tags_before.targeted_invalidations;
    let traps = stats.traps - baseline.traps;
    let leases = stats.additional_lease_programs - baseline.additional_lease_programs;
    if stats.completed - baseline.completed != 256
        || stats.direct - baseline.direct != 256
        || stats.queued != baseline.queued
        || stats.queue_zeroes != baseline.queue_zeroes
        || request_copies != if bytes == 0 { 0 } else { 256 }
        || reply_copies != request_copies
        || roots != 512
        || targeted != 0
        || traps != 513
        || leases != 0
        || (tags.supported && (hits != 512 || full != 0))
        || (!tags.supported && (hits != 0 || full != 512))
    {
        return Err(());
    }
    crate::probes::append_ipc_samples(
        transcript,
        "general-direct",
        bytes,
        troe_machine::benchmark_counter_frequency_hz().ok_or(())?,
        &samples,
    )?;
    let ratio_limit = if bytes == 4096 { 70 } else { 60 };
    let pass = p95.saturating_mul(100) <= compatibility.saturating_mul(ratio_limit);
    writeln!(transcript, "ipc-phase-c-latency path=general-direct payload={bytes} warmup=64 samples=256 p95_ticks={p95} compatibility_p95={compatibility} ratio_limit={ratio_limit} ratio_pass={} tagged={} calls=256 request_copies={request_copies} reply_copies={reply_copies} root_writes={roots} targeted_invalidations={targeted} full_invalidations={full} queue_slots=0 traps={traps} tag_hits={hits} steady_allocations=0 scheduler_scans=0 additional_lease_programs={leases}", u8::from(pass), u8::from(tags.supported)).map_err(|_| ())?;
    runtime.terminate(actor, true).map_err(|_| ())?;
    drop(runtime.remove(actor).map_err(|_| ())?);
    crate::memory::launch::terminate_revoke_and_reap_task(
        scheduler,
        client.task,
        &mut dispatcher,
        Some(client.owner),
    )?;
    reclaim_application(accounting, client.allocation)?;
    s.runtime = Some(runtime);
    let actor = s.instances[0].as_ref().ok_or(())?.actor;
    s.runtime
        .as_mut()
        .ok_or(())?
        .terminate(actor, true)
        .map_err(|_| ())?;
    s.reap(scheduler, accounting, actor, ServiceEvent::Exited)?;
    drop(s);
    if accounting.frames.free_frames() != free {
        return Err(());
    }
    Ok(())
}

//! Prepared Abort keeps the caller's native claim through actual reclamation.

use super::{
    ApplicationResume, IpcPagePair, IsolatedFault, NativeProcessContext, NativeSchedulerExecution,
    NativeThreadBacking, NativeThreadStart, NativeThreadStop, Outcome, OwnedAccounting, PAGE,
    PhysicalRange, Policy, Progress, Reclamation, Response, Scenario, TX, ZERO, verify_rx_tail,
};
use troe_service::threading::{Aborting, Error};
use troe_task::thread::ThreadError;

pub(super) struct Fixture {
    pub native: NativeProcessContext,
    pub policy: Policy,
    pub starts: [NativeThreadStart; 2],
    pub identities: [(usize, u64, PhysicalRange); 2],
    pub scenario: Scenario,
}

const _: () = assert!(
    core::mem::size_of::<NativeSchedulerExecution>() + core::mem::size_of::<Aborting>() <= 4096
);

#[allow(clippy::too_many_lines)] // Keep claim, native/physical retirement and reply ordering together.
pub(super) fn run(
    accounting: &mut OwnedAccounting,
    retained: &mut Option<PhysicalRange>,
    fixture: Fixture,
) -> Result<Reclamation, ()> {
    let Fixture {
        mut native,
        mut policy,
        starts,
        identities,
        scenario,
    } = fixture;
    let owner = policy.ids[1].process();
    let target = policy.ids[0];
    let caller = policy.ids[1];
    let worker = retained.ok_or(())?;
    let stack = [PhysicalRange::from_pages(worker.start(), 1).map_err(|_| ())?];
    let tls = [PhysicalRange::from_pages(worker.start() + PAGE, 1).map_err(|_| ())?];
    let startup = [PhysicalRange::from_pages(worker.start() + 2 * PAGE, 1).map_err(|_| ())?];
    let backing = NativeThreadBacking {
        stack: &stack,
        tls: &tls,
        startup: &startup,
    };
    let charges = native.stats();
    let metadata = native.metadata_bytes();
    // Neither Prepared nor Ready is proof that logical revocation won.
    if native
        .discard_revoked(&policy.threads, target, backing)
        .is_ok()
        || native.is_stopped()
        || native.stats() != charges
    {
        return Err(());
    }
    let (_, execution, current) = policy.capture(&mut native, 1)?;
    let Progress::Complete(current) = current
        .execute(&mut policy.threads, &mut policy.sync, ZERO)
        .map_err(|_| ())?
    else {
        return Err(());
    };
    native
        .complete_scheduler_execution(execution, current.response())
        .map_err(|_| ())?;
    policy
        .threads
        .yield_running(owner, caller)
        .map_err(|_| ())?;
    let (captured, execution, operation) = policy.capture(&mut native, 1)?;
    let progress = operation
        .execute(&mut policy.threads, &mut policy.sync, ZERO)
        .map_err(|_| ())?;
    let mut replacement = None;
    let mut reaped = false;
    let completion = if matches!(scenario, Scenario::StartWins) {
        let Progress::Complete(completion) = progress else {
            return Err(());
        };
        if completion.response().outcome != Outcome::InvalidState
            || native
                .discard_revoked(&policy.threads, target, backing)
                .is_ok()
            || native.stats() != charges
            || native.is_stopped()
        {
            return Err(());
        }
        completion
    } else {
        let Progress::Aborting(action) = progress else {
            return Err(());
        };
        if action.caller() != execution.caller()
            || action.request() != execution.request()
            || action.target() != target
        {
            return Err(());
        }
        let (error, action) = action.finish(&mut policy.threads).err().ok_or(())?;
        if error != Error::Thread(ThreadError::Busy) {
            return Err(());
        }
        if matches!(scenario, Scenario::AbortAlias | Scenario::AbortReference) {
            if native
                .discard_revoked(&policy.threads, target, backing)
                .is_ok()
                || native.is_stopped()
                || native.stats() != charges
                || native.probe_word(starts[0].tls.start()).is_err()
            {
                return Err(());
            }
            native.stop();
            policy
                .sync
                .stop_process(&mut policy.threads, owner)
                .map_err(|_| ())?;
            if native
                .complete_scheduler_execution(
                    execution,
                    Response {
                        outcome: Outcome::Success,
                        value: 0,
                        snapshot: None,
                    },
                )
                .is_ok()
                || action.finish(&mut policy.threads).is_ok()
            {
                return Err(());
            }
            return finish(native, policy, identities, false);
        }
        let bad = NativeThreadBacking {
            stack: &tls,
            tls: &stack,
            startup: &startup,
        };
        if native.discard_revoked(&policy.threads, target, bad).is_ok()
            || native.is_stopped()
            || native.stats() != charges
        {
            return Err(());
        }
        let retired = native
            .discard_revoked(&policy.threads, target, backing)
            .map_err(|_| ())?;
        if retired.thread() != target
            || retired.ordinary_pages() != 3
            || native.stats().mapped_pages != charges.mapped_pages - 5
            || native.stats().table_pages != charges.table_pages
            || native.metadata_bytes() != metadata
            || native
                .discard_revoked(&policy.threads, target, backing)
                .is_ok()
            || native
                .resume(target, ApplicationResume::Timeslice, 50)
                .is_ok()
        {
            return Err(());
        }
        for address in [
            starts[0].stack.start(),
            starts[0].tls.start(),
            starts[0].private_startup.ok_or(())?.start(),
            TX[0],
            TX[0] + PAGE,
        ] {
            if native.probe_word(address).is_ok() {
                return Err(());
            }
        }
        let pair = IpcPagePair::allocate().map_err(|_| ())?;
        if (pair.slot(), pair.generation(), pair.range())
            != (identities[0].0, identities[0].1 + 1, identities[0].2)
            || !troe_machine::ipc_range_is_zero(pair.range())
        {
            return Err(());
        }
        replacement = Some(pair);
        let (error, action) = action.finish(&mut policy.threads).err().ok_or(())?;
        if error != Error::Thread(ThreadError::Busy) {
            return Err(());
        }
        let free = accounting.frames.free_frames();
        troe_machine::zero_physical_range(worker).map_err(|_| ())?;
        accounting.frames.free_range(worker).map_err(|_| ())?;
        *retained = None;
        if accounting.frames.free_frames() != free + 3
            || policy
                .threads
                .release_resources(owner, target)
                .map_err(|_| ())?
                .pages
                != 5
        {
            return Err(());
        }
        let completion = action.finish(&mut policy.threads).map_err(|_| ())?;
        if policy.threads.snapshot(owner, target).is_ok() {
            return Err(());
        }
        reaped = true;
        completion
    };
    if native
        .claim_scheduler(captured, execution.request())
        .is_ok()
        || native.complete_scheduler(captured, None).is_ok()
    {
        return Err(());
    }
    native
        .complete_scheduler_execution(execution, completion.response())
        .map_err(|_| ())?;
    verify_rx_tail(&native, TX[1], 32)?;
    let mut stop = NativeThreadStop::Preempted;
    for _ in 0..128 {
        stop = native
            .resume(caller, ApplicationResume::Timeslice, 50)
            .map_err(|_| ())?;
        if stop != NativeThreadStop::Preempted {
            break;
        }
    }
    let expected = if matches!(scenario, Scenario::StartWins) {
        // The same user load must succeed while the started worker's page remains mapped.
        NativeThreadStop::ProcessExited(1)
    } else {
        NativeThreadStop::ProcessFaulted(IsolatedFault::Translation)
    };
    if stop != expected
        || native
            .probe_word(starts[1].tls.start() + 16)
            .map_err(|_| ())?
            != 2
        || replacement
            .as_ref()
            .is_some_and(|pair| !troe_machine::ipc_range_is_zero(pair.range()))
    {
        return Err(());
    }
    drop(replacement);
    finish(native, policy, identities, reaped)
}

fn finish(
    mut native: NativeProcessContext,
    mut policy: Policy,
    identities: [(usize, u64, PhysicalRange); 2],
    reaped: bool,
) -> Result<Reclamation, ()> {
    native.stop();
    policy
        .sync
        .stop_process(&mut policy.threads, policy.ids[1].process())
        .map_err(|_| ())?;
    drop(native);
    if identities
        .iter()
        .any(|identity| !troe_machine::ipc_range_is_zero(identity.2))
    {
        return Err(());
    }
    policy.stop_and_reclaim(reaped)
}

//! Dynamic prepared mappings with compiler TLS, initial exit and fault containment.

use super::{
    IsolatedAllocation, METADATA_LIMIT, PAGE, ProbeScheduler, allocate_isolated,
    build_isolated_plan, reclaim_isolated, thread_token,
};
use crate::{
    limits::{USER_CODE_BASE, USER_DATA_BASE, USER_STACK_BASE},
    machine::OwnedAccounting,
};
use troe_abi::threading::{Kind, Request, StartupDescriptor, StartupReference, Token};
use troe_application::{
    Target,
    static_tls::StaticTlsLayout,
    thread_memory::{ThreadMemoryBudget, ThreadMemoryPlan},
};
use troe_machine::{
    ApplicationResume, IpcPagePair, IsolatedFault, NativeProcessContext, NativeThreadAdmission,
    NativeThreadAdmissionError, NativeThreadBacking, NativeThreadStop,
};
use troe_memory::{
    Mapping, MappingLifetime, MappingOwner, MappingPermissions, MappingPlan, PhysicalRange,
    VirtualRange,
};
use troe_service::threading::{Operation, Progress};
use troe_task::{
    Capabilities, MonotonicMillis, ProcessId, ProcessName, ProcessOrigin, ProcessRegistration,
    ProcessTable, Scheduler, StackResource,
    thread::{ThreadId, ThreadQuota, ThreadResources, ThreadTable, sync},
};

mod program;
const SEED: u64 = 0x1122_3344_5566_7788;
const HEADER: u64 = 0x1234_5678_9abc_def0;
const ZERO: MonotonicMillis = MonotonicMillis::from_millis(0);
const BUDGET: ThreadMemoryBudget = ThreadMemoryBudget {
    mapped_pages: 5,
    resident_pages: 16,
    reserved_pages: 16,
    ordinary_frames: 14,
    ipc_pairs: 1,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Scenario {
    Complete,
    Reuse,
    RetiredRead,
    DescriptorWrite,
    GuardRead,
    Partial,
    Ready,
    Capacity,
    Tables,
    HeaderAlias,
}
impl Scenario {
    fn code(self) -> u64 {
        match self {
            Self::RetiredRead => 1,
            Self::DescriptorWrite => 2,
            Self::GuardRead => 3,
            _ => 0,
        }
    }
}

pub(super) fn verify(accounting: &mut OwnedAccounting) -> Result<(), ()> {
    for scenario in [
        Scenario::Complete,
        Scenario::Reuse,
        Scenario::RetiredRead,
        Scenario::DescriptorWrite,
        Scenario::GuardRead,
        Scenario::Partial,
        Scenario::Ready,
        Scenario::Capacity,
        Scenario::Tables,
        Scenario::HeaderAlias,
    ] {
        let free = accounting.frames.free_frames();
        let allocation = allocate_isolated(&mut accounting.frames)?;
        let mut frames = [None; 2];
        let result = (|| {
            for owner in &mut frames {
                *owner = Some(
                    accounting
                        .frames
                        .allocate_contiguous(3, 1)
                        .map_err(|_| ())?,
                );
            }
            run(accounting, &allocation, &mut frames, scenario)
        })();
        // Every run-local root dropped before either ordinary owner is recycled.
        for range in frames.into_iter().flatten() {
            troe_machine::zero_physical_range(range).map_err(|_| ())?;
            accounting.frames.free_range(range).map_err(|_| ())?;
        }
        reclaim_isolated(&mut accounting.frames, allocation)?;
        result?.finish()?;
        if accounting.frames.free_frames() != free {
            return Err(());
        }
    }
    Ok(())
}

struct Policy {
    threads: ThreadTable,
    sync: sync::SyncTable,
    authority: ProbeScheduler,
    ids: [Option<ThreadId>; 2],
}
struct Reclamation {
    threads: ThreadTable,
    sync: sync::SyncTable,
    owner: ProcessId,
    ids: [Option<ThreadId>; 2],
}
impl Reclamation {
    fn finish(mut self) -> Result<(), ()> {
        for id in self.ids.into_iter().flatten() {
            self.threads
                .release_resources(self.owner, id)
                .map_err(|_| ())?;
            self.threads.reap(self.owner, id).map_err(|_| ())?;
        }
        if self.sync.usage(self.owner) != (0, 0) {
            return Err(());
        }
        self.threads.remove_process(self.owner).map_err(|_| ())?;
        if self.threads.committed_pages() != 0 {
            return Err(());
        }
        Ok(())
    }
}
impl Policy {
    fn new(table_pages: u64) -> Result<Self, ()> {
        let mut scheduler = Scheduler::new(1).map_err(|_| ())?;
        let task_id = scheduler
            .spawn(
                Capabilities::SERVICE,
                StackResource::new(0, 1).map_err(|_| ())?,
            )
            .map_err(|_| ())?;
        let mut processes = ProcessTable::new(1).map_err(|_| ())?;
        let owner = processes
            .register(ProcessRegistration {
                task_id,
                name: ProcessName::new("native-admission-probe").map_err(|_| ())?,
                origin: ProcessOrigin::Foreground,
                started_millis: 0,
                table_pages,
                private_pages: 12,
                handles: 1,
            })
            .map_err(|_| ())?;
        let authority = ProbeScheduler::new(&processes, owner)?;
        let mut threads = ThreadTable::new(1, 2, 10, METADATA_LIMIT).map_err(|_| ())?;
        threads
            .register_process(
                owner,
                ThreadQuota {
                    records: 2,
                    pages: 10,
                },
            )
            .map_err(|_| ())?;
        let initial = threads
            .prepare_initial(
                owner,
                ThreadResources {
                    reservation: 1,
                    pages: 5,
                },
            )
            .map_err(|_| ())?;
        let mut sync = sync::SyncTable::new(1, 1, 1, METADATA_LIMIT).map_err(|_| ())?;
        sync.register_process(
            &mut threads,
            owner,
            sync::SyncQuota {
                objects: 1,
                waits: 1,
            },
        )
        .map_err(|_| ())?;
        Ok(Self {
            threads,
            sync,
            authority,
            ids: [Some(initial), None],
        })
    }
    fn stop(mut self) -> Result<Reclamation, ()> {
        let owner = self.authority.process.id();
        self.sync
            .stop_process(&mut self.threads, owner)
            .map_err(|_| ())?;
        self.authority.revoke()?;
        Ok(Reclamation {
            threads: self.threads,
            sync: self.sync,
            ids: self.ids,
            owner,
        })
    }
}

struct Memory {
    plan: ThreadMemoryPlan,
    descriptor: StartupDescriptor,
    extents: [PhysicalRange; 3],
    entry: u64,
}
impl Memory {
    fn new(
        index: usize,
        id: ThreadId,
        threads: &ThreadTable,
        range: PhysicalRange,
        tls: StaticTlsLayout,
    ) -> Result<Self, ()> {
        let plan = ThreadMemoryPlan::new(USER_STACK_BASE + index as u64 * 0x2_0000, 1, tls, BUDGET)
            .map_err(|_| ())?;
        let [stack, tls_region, ipc, startup] = plan.regions();
        let descriptor = StartupDescriptor {
            thread: Token::decode(thread_token(threads, id.process(), id)?).map_err(|_| ())?,
            process_startup: USER_DATA_BASE,
            stack_bottom: stack.start(),
            stack_top: stack.end(),
            tls_base: tls_region.start(),
            tls_bytes: PAGE,
            thread_pointer: plan.thread_pointer(),
            ipc_tx: ipc.start(),
            entry: if index == 0 { 0 } else { USER_CODE_BASE },
            argument: if index == 0 { 0 } else { 0x55 },
            initial: index == 0,
            address: startup.start(),
        };
        let extents = [
            PhysicalRange::from_pages(range.start(), 1).map_err(|_| ())?,
            PhysicalRange::from_pages(range.start() + PAGE, 1).map_err(|_| ())?,
            PhysicalRange::from_pages(range.start() + 2 * PAGE, 1).map_err(|_| ())?,
        ];
        // Deliberately poison all unpublished pages: admission must clear the
        // stack and descriptor, while compiler initialization clears all TLS slack.
        for extent in extents {
            troe_machine::copy_to_physical(extent, 0, &[0xa5; 4096]).map_err(|_| ())?;
        }
        let mut bytes = [0xa5; 4096];
        if tls
            .initialize(tls_region.start(), &SEED.to_le_bytes(), &mut bytes)
            .map_err(|_| ())?
            != plan.thread_pointer()
        {
            return Err(());
        }
        troe_machine::copy_to_physical(extents[1], 0, &bytes).map_err(|_| ())?;
        Ok(Self {
            plan,
            descriptor,
            extents,
            entry: USER_CODE_BASE + if index == 0 { 0 } else { program::WORKER_ENTRY },
        })
    }
    fn backing(&self) -> NativeThreadBacking<'_> {
        NativeThreadBacking {
            stack: &self.extents[..1],
            tls: &self.extents[1..2],
            startup: &self.extents[2..],
        }
    }
    fn admission(&self, thread: ThreadId) -> NativeThreadAdmission<'_> {
        NativeThreadAdmission {
            thread,
            descriptor: self.descriptor,
            entry: self.entry,
            backing: self.backing(),
        }
    }
    fn verify(
        &self,
        native: &NativeProcessContext,
        tls: StaticTlsLayout,
        cycles: u64,
    ) -> Result<(), ()> {
        let increment = if self.descriptor.initial { 0x11 } else { 0x22 };
        if native
            .probe_word(self.descriptor.tls_base + tls.template_offset())
            .map_err(|_| ())?
            != SEED + cycles * increment
            || native
                .probe_word(self.descriptor.tls_base + tls.template_offset() + 8)
                .map_err(|_| ())?
                != cycles
        {
            return Err(());
        }
        let encoded = self.descriptor.encode().map_err(|_| ())?;
        for offset in (0..4096_usize).step_by(8) {
            let expected = if offset < encoded.len() {
                u64::from_le_bytes(encoded[offset..offset + 8].try_into().map_err(|_| ())?)
            } else {
                0
            };
            if native
                .probe_word(self.descriptor.address + offset as u64)
                .map_err(|_| ())?
                != expected
            {
                return Err(());
            }
        }
        for page in [
            self.plan.reservation_base(),
            self.descriptor.stack_top,
            self.plan.reservation_end() - PAGE,
        ] {
            if native.probe_word(page).is_ok() {
                return Err(());
            }
        }
        if cycles == 0 {
            for offset in (0..PAGE).step_by(8) {
                let expected = if offset == tls.template_offset() {
                    SEED
                } else if cfg!(target_arch = "x86_64") && offset == tls.thread_pointer_offset() {
                    self.descriptor.thread_pointer
                } else {
                    0
                };
                if native
                    .probe_word(self.descriptor.tls_base + offset)
                    .map_err(|_| ())?
                    != expected
                {
                    return Err(());
                }
            }
            for offset in (0..PAGE).step_by(8) {
                if native
                    .probe_word(self.descriptor.stack_bottom + offset)
                    .map_err(|_| ())?
                    != 0
                {
                    return Err(());
                }
            }
        }
        Ok(())
    }
}

fn mappings(
    accounting: &OwnedAccounting,
    allocation: &IsolatedAllocation,
) -> Result<MappingPlan, ()> {
    troe_machine::zero_physical_range(allocation.complete).map_err(|_| ())?;
    troe_machine::copy_to_physical(allocation.code, 0, program::CODE).map_err(|_| ())?;
    let base = build_isolated_plan(&accounting.kernel_plan, allocation)?;
    let mut plan = MappingPlan::new();
    for mapping in base.mappings() {
        if ![USER_DATA_BASE, USER_STACK_BASE].contains(&mapping.virtual_range().start()) {
            plan.insert(*mapping).map_err(|_| ())?;
        }
    }
    plan.insert(
        Mapping::user(
            VirtualRange::from_pages(USER_DATA_BASE, 1).map_err(|_| ())?,
            PhysicalRange::from_pages(allocation.data.start(), 1).map_err(|_| ())?,
            MappingPermissions::READ_ONLY,
            MappingOwner::IsolatedTask,
            MappingLifetime::Task,
        )
        .map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    Ok(plan)
}

#[allow(clippy::too_many_lines)]
fn run(
    accounting: &mut OwnedAccounting,
    allocation: &IsolatedAllocation,
    frames: &mut [Option<PhysicalRange>; 2],
    scenario: Scenario,
) -> Result<Reclamation, ()> {
    let mut plan = mappings(accounting, allocation)?;
    if scenario == Scenario::HeaderAlias {
        plan.insert(
            Mapping::user(
                VirtualRange::from_pages(USER_DATA_BASE + PAGE, 1).map_err(|_| ())?,
                PhysicalRange::from_pages(allocation.data.start(), 1).map_err(|_| ())?,
                MappingPermissions::READ_WRITE,
                MappingOwner::IsolatedTask,
                MappingLifetime::Task,
            )
            .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
    }
    let tables = if scenario == Scenario::Tables {
        PhysicalRange::from_pages(
            allocation.tables.start(),
            troe_machine::required_page_table_pages(&plan).map_err(|_| ())?,
        )
        .map_err(|_| ())?
    } else {
        allocation.tables
    };
    let root = troe_machine::build_user_address_space(&plan, tables).map_err(|_| ())?;
    let mut policy = Policy::new(root.stats().table_pages)?;
    let owner = policy.authority.process.id();
    let initial = policy.ids[0].ok_or(())?;
    let target = if cfg!(target_arch = "x86_64") {
        Target::X86_64
    } else {
        Target::Aarch64
    };
    let tls = StaticTlsLayout::new(target, 8, 16, 8, 1).map_err(|_| ())?;
    let first = Memory::new(0, initial, &policy.threads, frames[0].ok_or(())?, tls)?;
    for (offset, value) in [
        (0, HEADER),
        (112, scenario.code()),
        (120, policy.authority.handle.abi_value()),
    ] {
        troe_machine::copy_to_physical(allocation.data, offset, &value.to_le_bytes())
            .map_err(|_| ())?;
    }
    let reference = StartupReference {
        address: first.descriptor.address,
    }
    .encode()
    .map_err(|_| ())?;
    troe_machine::copy_to_physical(allocation.data, 80, &reference).map_err(|_| ())?;
    troe_machine::copy_to_physical(
        allocation.data,
        256,
        &Request::Exit(u64::MAX).encode().map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let mut native = NativeProcessContext::new(
        owner,
        root,
        if scenario == Scenario::Capacity { 1 } else { 2 },
        METADATA_LIMIT,
    )
    .map_err(|_| ())?;
    let baseline = native.stats();
    let metadata = native.metadata_bytes();
    let pair = IpcPagePair::allocate().map_err(|_| ())?;
    let mut identities = [(pair.slot(), pair.generation(), pair.range()); 2];
    if matches!(scenario, Scenario::Tables | Scenario::HeaderAlias) {
        let NativeThreadAdmissionError::Rejected { error, ipc } = native
            .admit_prepared(&policy.threads, first.admission(initial), pair)
            .err()
            .ok_or(())?
        else {
            return Err(());
        };
        let expected = if scenario == Scenario::Tables {
            troe_machine::MmuError::TableArenaExhausted
        } else {
            troe_machine::MmuError::InvalidUserContext
        };
        if error != expected || native.is_stopped() || native.stats() != baseline || !ipc.is_live()
        {
            return Err(());
        }
        drop(ipc);
        native.stop();
        drop(native);
        return policy.stop();
    }
    let pair = rejections(
        &mut native,
        &policy.threads,
        first.admission(initial),
        pair,
        allocation,
    )?;
    native
        .admit_prepared(&policy.threads, first.admission(initial), pair)
        .map_err(|_| ())?;
    first.verify(&native, tls, 0)?;
    if native.stats().mapped_pages != baseline.mapped_pages + 5
        || native.metadata_bytes() != metadata
    {
        return Err(());
    }
    policy.threads.start(owner, initial).map_err(|_| ())?;
    policy.threads.dispatch(owner, initial).map_err(|_| ())?;
    if resume(&mut native, initial)? != NativeThreadStop::Yielded {
        return Err(());
    }
    first.verify(&native, tls, 1)?;
    let mut worker = policy
        .threads
        .prepare_worker(
            owner,
            initial,
            ThreadResources {
                reservation: 2,
                pages: 5,
            },
        )
        .map_err(|_| ())?;
    policy.ids[1] = Some(worker);
    let mut second = Memory::new(1, worker, &policy.threads, frames[1].ok_or(())?, tls)?;
    let pair = IpcPagePair::allocate().map_err(|_| ())?;
    identities[1] = (pair.slot(), pair.generation(), pair.range());
    let before = native.stats();
    let mut wrong_header = second.admission(worker);
    wrong_header.descriptor.process_startup = first.descriptor.address;
    let NativeThreadAdmissionError::Rejected { ipc: pair, .. } = native
        .admit_prepared(&policy.threads, wrong_header, pair)
        .err()
        .ok_or(())?
    else {
        return Err(());
    };
    if native.stats() != before || native.is_stopped() {
        return Err(());
    }
    if scenario == Scenario::Ready {
        policy.threads.start(owner, worker).map_err(|_| ())?;
    }
    let result = if scenario == Scenario::Partial {
        native.probe_admission_failure(&policy.threads, second.admission(worker), pair)
    } else {
        native.admit_prepared(&policy.threads, second.admission(worker), pair)
    };
    if matches!(
        scenario,
        Scenario::Partial | Scenario::Ready | Scenario::Capacity
    ) {
        match result {
            Err(NativeThreadAdmissionError::Stopped(_)) if scenario == Scenario::Partial => {
                if !native.is_stopped()
                    || native.stats().mapped_pages != before.mapped_pages + 1
                    || native.probe_word(second.descriptor.stack_bottom).is_err()
                    || native.probe_word(second.descriptor.tls_base).is_ok()
                    || native
                        .resume(initial, ApplicationResume::Timeslice, 1)
                        .is_ok()
                {
                    return Err(());
                }
                // Partially mapped admission retains its IPC slot even before an
                // IPC leaf was inserted. A new owner cannot reuse either pair.
                let spare = IpcPagePair::allocate().map_err(|_| ())?;
                if identities.iter().any(|identity| identity.0 == spare.slot()) {
                    return Err(());
                }
                drop(spare);
            }
            Err(NativeThreadAdmissionError::Rejected { ipc, .. })
                if scenario != Scenario::Partial =>
            {
                if native.is_stopped() || native.stats() != before || !ipc.is_live() {
                    return Err(());
                }
                first.verify(&native, tls, 1)?;
                drop(ipc);
            }
            _ => return Err(()),
        }
        native.stop();
        drop(native);
        if identities
            .iter()
            .any(|identity| !troe_machine::ipc_range_is_zero(identity.2))
        {
            return Err(());
        }
        return policy.stop();
    }
    result.map_err(|_| ())?;
    if scenario == Scenario::Reuse {
        let old = worker;
        policy.threads.abort_prepared(owner, old).map_err(|_| ())?;
        let removed = native
            .discard_revoked(&policy.threads, old, second.backing())
            .map_err(|_| ())?;
        if removed.thread() != old
            || removed.ordinary_pages() != 3
            || native.stats().mapped_pages != before.mapped_pages
        {
            return Err(());
        }
        let range = frames[1].ok_or(())?;
        troe_machine::zero_physical_range(range).map_err(|_| ())?;
        accounting.frames.free_range(range).map_err(|_| ())?;
        frames[1] = None;
        policy
            .threads
            .release_resources(owner, old)
            .map_err(|_| ())?;
        policy.threads.reap(owner, old).map_err(|_| ())?;
        frames[1] = Some(
            accounting
                .frames
                .allocate_contiguous(3, 1)
                .map_err(|_| ())?,
        );
        worker = policy
            .threads
            .prepare_worker(
                owner,
                initial,
                ThreadResources {
                    reservation: 2,
                    pages: 5,
                },
            )
            .map_err(|_| ())?;
        policy.ids[1] = Some(worker);
        if worker.slot() != old.slot() || worker.generation() != old.generation() + 1 {
            return Err(());
        }
        second = Memory::new(1, worker, &policy.threads, frames[1].ok_or(())?, tls)?;
        let pair = IpcPagePair::allocate().map_err(|_| ())?;
        if (pair.slot(), pair.generation(), pair.range())
            != (identities[1].0, identities[1].1 + 1, identities[1].2)
            || !troe_machine::ipc_range_is_zero(pair.range())
        {
            return Err(());
        }
        identities[1] = (pair.slot(), pair.generation(), pair.range());
        native
            .admit_prepared(&policy.threads, second.admission(worker), pair)
            .map_err(|_| ())?;
        if native.resume(old, ApplicationResume::Timeslice, 1).is_ok()
            || policy
                .threads
                .resolve(owner, old.slot(), old.generation())
                .is_ok()
        {
            return Err(());
        }
    }
    second.verify(&native, tls, 0)?;
    first.verify(&native, tls, 1)?;
    policy
        .threads
        .yield_running(owner, initial)
        .map_err(|_| ())?;
    policy.threads.start(owner, worker).map_err(|_| ())?;
    for (id, memory, cycles) in [
        (worker, &second, 1),
        (initial, &first, 2),
        (worker, &second, 2),
    ] {
        policy.threads.dispatch(owner, id).map_err(|_| ())?;
        if resume(&mut native, id)? != NativeThreadStop::Yielded {
            return Err(());
        }
        memory.verify(&native, tls, cycles)?;
        policy.threads.yield_running(owner, id).map_err(|_| ())?;
    }
    policy.threads.dispatch(owner, initial).map_err(|_| ())?;
    retire(
        &mut native,
        &mut policy,
        &first,
        initial,
        &mut frames[0],
        accounting,
    )?;
    if native.probe_word(first.descriptor.address).is_ok()
        || native.probe_word(USER_DATA_BASE + 80).map_err(|_| ())? != first.descriptor.address
        || native.probe_word(USER_DATA_BASE).map_err(|_| ())? != HEADER
    {
        return Err(());
    }
    // Prove the old IPC incarnation was cleared and can now be reused while a
    // sibling retains its own descriptor, TLS and IPC mapping in the same root.
    let replacement = IpcPagePair::allocate().map_err(|_| ())?;
    if (
        replacement.slot(),
        replacement.generation(),
        replacement.range(),
    ) != (identities[0].0, identities[0].1 + 1, identities[0].2)
        || !troe_machine::ipc_range_is_zero(replacement.range())
    {
        return Err(());
    }
    second.verify(&native, tls, 2)?;
    policy.threads.dispatch(owner, worker).map_err(|_| ())?;
    if matches!(scenario, Scenario::Complete | Scenario::Reuse) {
        retire(
            &mut native,
            &mut policy,
            &second,
            worker,
            &mut frames[1],
            accounting,
        )?;
        if native.stats().mapped_pages != baseline.mapped_pages {
            return Err(());
        }
    } else {
        let expected = if scenario == Scenario::DescriptorWrite {
            IsolatedFault::Permission
        } else {
            IsolatedFault::Translation
        };
        if resume(&mut native, worker)? != NativeThreadStop::ProcessFaulted(expected)
            || !native.is_stopped()
        {
            return Err(());
        }
    }
    if !troe_machine::ipc_range_is_zero(replacement.range()) || native.metadata_bytes() != metadata
    {
        return Err(());
    }
    drop(replacement);
    native.stop();
    drop(native);
    if identities
        .iter()
        .any(|identity| !troe_machine::ipc_range_is_zero(identity.2))
    {
        return Err(());
    }
    policy.stop()
}

fn resume(native: &mut NativeProcessContext, id: ThreadId) -> Result<NativeThreadStop, ()> {
    for _ in 0..20 {
        let stop = native
            .resume(id, ApplicationResume::Timeslice, 50)
            .map_err(|_| ())?;
        if stop != NativeThreadStop::Preempted {
            return Ok(stop);
        }
    }
    Err(())
}

fn rejections(
    native: &mut NativeProcessContext,
    threads: &ThreadTable,
    admission: NativeThreadAdmission<'_>,
    mut ipc: IpcPagePair,
    allocation: &IsolatedAllocation,
) -> Result<IpcPagePair, ()> {
    let before = native.stats();
    let reference = StartupReference {
        address: admission.descriptor.address + PAGE,
    }
    .encode()
    .map_err(|_| ())?;
    troe_machine::copy_to_physical(allocation.data, 80, &reference).map_err(|_| ())?;
    let NativeThreadAdmissionError::Rejected { ipc: returned, .. } = native
        .admit_prepared(threads, admission, ipc)
        .err()
        .ok_or(())?
    else {
        return Err(());
    };
    ipc = returned;
    let reference = StartupReference {
        address: admission.descriptor.address,
    }
    .encode()
    .map_err(|_| ())?;
    troe_machine::copy_to_physical(allocation.data, 80, &reference).map_err(|_| ())?;
    let table = [PhysicalRange::from_pages(allocation.tables.start(), 1).map_err(|_| ())?];
    let alias = [PhysicalRange::from_pages(allocation.data.start(), 1).map_err(|_| ())?];
    let mut bad = [admission; 5];
    bad[0].backing.tls = &table;
    bad[1].backing.tls = &alias;
    bad[2].entry = USER_DATA_BASE;
    bad[3].descriptor.thread = Token::new(
        Kind::Thread,
        admission.descriptor.thread.slot(),
        admission.thread.generation() + 1,
    )
    .map_err(|_| ())?;
    bad[4].descriptor.initial = false;
    bad[4].descriptor.entry = USER_CODE_BASE;
    for attempt in bad {
        let NativeThreadAdmissionError::Rejected { ipc: returned, .. } = native
            .admit_prepared(threads, attempt, ipc)
            .err()
            .ok_or(())?
        else {
            return Err(());
        };
        ipc = returned;
        if native.is_stopped() || native.stats() != before || !ipc.is_live() {
            return Err(());
        }
    }
    Ok(ipc)
}

fn retire(
    native: &mut NativeProcessContext,
    policy: &mut Policy,
    memory: &Memory,
    id: ThreadId,
    frames: &mut Option<PhysicalRange>,
    accounting: &mut OwnedAccounting,
) -> Result<(), ()> {
    let NativeThreadStop::SchedulerCall(call) = resume(native, id)? else {
        return Err(());
    };
    let admitted = policy
        .authority
        .dispatcher
        .authorize_scheduler_owned_abi(
            policy.authority.principal,
            call.call().ok_or(())?.handle,
            call.request_bytes().ok_or(())?,
        )
        .map_err(|_| ())?;
    if call.caller() != id || admitted.request() != Request::Exit(u64::MAX) {
        return Err(());
    }
    let execution = native
        .claim_scheduler(call, admitted.request())
        .map_err(|_| ())?;
    let operation = Operation::bind(policy.authority.process, id, admitted).map_err(|_| ())?;
    let Progress::Retiring(retiring) = operation
        .execute(&mut policy.threads, &mut policy.sync, ZERO)
        .map_err(|_| ())?
    else {
        return Err(());
    };
    let before = native.stats();
    let retired = native
        .retire_thread(execution, memory.backing())
        .map_err(|_| ())?;
    if retired.thread() != id
        || retired.ordinary_pages() != 3
        || native.stats().mapped_pages != before.mapped_pages - 5
        || native.stats().table_pages != before.table_pages
    {
        return Err(());
    }
    retiring
        .complete_thread(&mut policy.threads)
        .map_err(|_| ())?;
    let range = frames.ok_or(())?;
    troe_machine::zero_physical_range(range).map_err(|_| ())?;
    accounting.frames.free_range(range).map_err(|_| ())?;
    *frames = None;
    if policy
        .threads
        .release_resources(id.process(), id)
        .map_err(|_| ())?
        .pages
        != 5
    {
        return Err(());
    }
    if !memory.descriptor.initial {
        policy.threads.detach(id.process(), id).map_err(|_| ())?;
    }
    policy.threads.reap(id.process(), id).map_err(|_| ())?;
    let index = usize::from(!memory.descriptor.initial);
    policy.ids[index] = None;
    Ok(())
}

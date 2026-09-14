//! Resident native image ownership: retire the root before returning any backing.

use super::launch::{map_launch_region, reserve_zeroed_private_extents, write_launch_bytes};
use crate::machine::OwnedAccounting;
use alloc::{rc::Rc, vec::Vec};
use troe_abi::threading::{StartupDescriptor, Token};
use troe_application::{
    SegmentPermissions, StartupInfo, StreamedKexPackage,
    process_memory::{ProcessMemoryBudget, ProcessMemoryKind, ProcessMemoryPlacement},
    tls_owner::ProcessTls,
};
use troe_machine::{NativeProcessContext, NativeThreadAdmission, NativeThreadBacking};
use troe_memory::{
    BASE_PAGE_SIZE, MappingOwner, MappingPermissions, MappingPlan, PhysicalExtents, PhysicalRange,
    VirtualRange,
};
use troe_task::thread::{ThreadId, ThreadTable};

mod creation;
mod execution;
mod growth;

/// Work performed synchronously for one worker preparation or heap commit.
const MAX_NATIVE_BATCH_PAGES: u64 = 256;

/// Caller-selected bounds, checked again against current physical/system capacity.
#[derive(Clone, Copy)]
pub(crate) struct NativeLoadLimits {
    pub(crate) memory: ProcessMemoryBudget,
    pub(crate) contexts: usize,
    pub(crate) metadata_bytes: usize,
    /// Retained table headroom for the initial and permitted worker windows.
    pub(crate) extra_table_pages: u64,
}

/// Only a fully reclaimed rejection permits logical resource acknowledgement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeLoadError {
    Rejected,
    ReclamationFailed,
}

impl From<()> for NativeLoadError {
    fn from((): ()) -> Self {
        Self::Rejected
    }
}

pub(crate) struct NativeThreadMemory {
    thread: ThreadId,
    descriptor: StartupDescriptor,
    window: troe_application::thread_memory::ThreadMemoryPlan,
    stack: PhysicalExtents,
    tls: PhysicalExtents,
    startup: PhysicalExtents,
}

impl NativeThreadMemory {
    fn empty(
        thread: ThreadId,
        descriptor: StartupDescriptor,
        window: troe_application::thread_memory::ThreadMemoryPlan,
    ) -> Self {
        Self {
            thread,
            descriptor,
            window,
            stack: PhysicalExtents::new(),
            tls: PhysicalExtents::new(),
            startup: PhysicalExtents::new(),
        }
    }
    fn backing(&self) -> NativeThreadBacking<'_> {
        NativeThreadBacking {
            stack: self.stack.extents(),
            tls: self.tls.extents(),
            startup: self.startup.extents(),
        }
    }
}

/// The root is dropped before IPC, and all ordinary frames remain retained here.
/// Explicit `reclaim` is required to return frames and their accounting. An
/// abandoned owner drops continuations but never makes mapped frames reusable.
pub(crate) struct NativeMemory {
    native: Option<NativeProcessContext>,
    threads: Vec<NativeThreadMemory>,
    shared: PhysicalExtents,
    tables: Option<PhysicalRange>,
    tls: ProcessTls<'static>,
    committed_pages: u64,
    metadata_bytes: u64,
    limits: NativeLoadLimits,
    executable: [Option<(u64, u64)>; troe_application::MAX_LOAD_RECORDS],
    target: troe_application::Target,
    heap_growth: Vec<PhysicalExtents>,
    heap_pages: u64,
    reclamation_failed: bool,
}

impl NativeMemory {
    /// Materialize only a coherently verified threaded package into owned frames.
    /// The initial logical record remains Prepared; this never executes or starts it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn load(
        accounting: &mut OwnedAccounting,
        package: &StreamedKexPackage,
        placement: ProcessMemoryPlacement,
        limits: NativeLoadLimits,
        initial: ThreadId,
        token: Token,
        startup: StartupInfo<'_>,
        mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    ) -> Result<Self, NativeLoadError> {
        if limits.contexts == 0 || limits.contexts >= troe_machine::IPC_APPLICATION_THREAD_PAIRS {
            return Err(NativeLoadError::Rejected);
        }
        let tls = ProcessTls::prepare_streamed(
            package,
            placement,
            limits.memory,
            Rc::clone(&accounting.thread_tls_backing),
            &mut read_at,
        )
        .map_err(|_| ())?;
        let descriptor = tls.plan().initial_descriptor(token).map_err(|_| ())?;
        let mut executable = [None; troe_application::MAX_LOAD_RECORDS];
        for (slot, segment) in executable.iter_mut().zip(package.executable().segments()) {
            if segment.permissions() == SegmentPermissions::ReadExecute {
                *slot = Some((
                    segment.image_offset(),
                    segment
                        .image_offset()
                        .checked_add(segment.file_byte_count())
                        .ok_or(())?,
                ));
            }
        }
        let mut owner = Self {
            native: None,
            threads: Vec::new(),
            shared: PhysicalExtents::new(),
            tables: None,
            tls,
            committed_pages: 0,
            metadata_bytes: 0,
            limits,
            executable,
            target: package.executable().target(),
            heap_growth: Vec::new(),
            heap_pages: package.executable().heap_pages(),
            reclamation_failed: false,
        };
        let result = owner.materialize(
            accounting,
            package,
            &limits,
            initial,
            descriptor,
            token,
            startup,
            &mut read_at,
        );
        if result.is_err() {
            owner
                .reclaim(accounting)
                .map_err(|()| NativeLoadError::ReclamationFailed)?;
            return Err(NativeLoadError::Rejected);
        }
        Ok(owner)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn materialize(
        &mut self,
        accounting: &mut OwnedAccounting,
        package: &StreamedKexPackage,
        limits: &NativeLoadLimits,
        initial: ThreadId,
        descriptor: StartupDescriptor,
        token: Token,
        startup: StartupInfo<'_>,
        read_at: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, ()>,
    ) -> Result<(), ()> {
        let process_plan = self.tls.plan();
        let pages = process_plan.charges().mapped_pages();
        let committed = accounting
            .application_committed_pages
            .checked_add(pages)
            .ok_or(())?;
        if accounting
            .memory_policy
            .system_application_commit()
            .maximum()
            .is_some_and(|max| committed > max)
            || accounting
                .memory_policy
                .default_committed_pages()
                .maximum()
                .is_some_and(|max| pages > max)
            || pages
                > accounting
                    .frames
                    .free_frames()
                    .saturating_sub(accounting.memory_policy.minimum_free_pages())
        {
            return Err(());
        }
        self.threads
            .try_reserve_exact(limits.contexts)
            .map_err(|_| ())?;
        self.heap_growth
            .try_reserve_exact(growth::MAX_GROWTH_RECORDS)
            .map_err(|_| ())?;
        self.threads.push(NativeThreadMemory::empty(
            initial,
            descriptor,
            process_plan.initial_thread(),
        ));
        // Charge the whole reservation before any frame can enter a mapping.
        // The same owner refunds it after all partial allocations are retired.
        accounting.application_committed_pages = committed;
        self.committed_pages = pages;
        self.shared =
            reserve_zeroed_private_extents(accounting, process_plan.charges().shared_pages())?;
        let [stack, tls, _, _] = process_plan.initial_thread().regions();
        let first = &mut self.threads[0];
        first.stack = reserve_zeroed_private_extents(accounting, stack.pages())?;
        first.tls = reserve_zeroed_private_extents(accounting, tls.pages())?;
        first.startup = reserve_zeroed_private_extents(accounting, 1)?;
        let mut page = [0; 4096];
        for offset in (0..descriptor.tls_bytes).step_by(4096) {
            if self
                .tls
                .initialize_chunk(descriptor.tls_base, offset, &mut page)
                .map_err(|_| ())?
                != descriptor.thread_pointer
            {
                return Err(());
            }
            write_launch_bytes(&first.tls, offset, &page)?;
        }

        let mut mapping = MappingPlan::new();
        for entry in accounting.kernel_plan.mappings() {
            let physical = entry.physical_range();
            if entry.owner() != MappingOwner::KernelRuntime
                || (physical.start() >= accounting.kernel_runtime.start()
                    && physical.end() <= accounting.kernel_runtime.end())
            {
                mapping.insert(*entry).map_err(|_| ())?;
            }
        }
        let mut logical = 0;
        for region in process_plan
            .regions()
            .filter(|region| !matches!(region.kind(), ProcessMemoryKind::Thread(_)))
        {
            let permissions = match region.permissions() {
                SegmentPermissions::ReadOnly => MappingPermissions::READ_ONLY,
                SegmentPermissions::ReadWrite => MappingPermissions::READ_WRITE,
                SegmentPermissions::ReadExecute => MappingPermissions::READ_EXECUTE,
            };
            map_launch_region(
                &mut mapping,
                &self.shared,
                logical,
                region.pages(),
                region.start(),
                permissions,
            )?;
            logical = logical.checked_add(region.pages()).ok_or(())?;
        }
        if logical != self.shared.page_count() || !mapping.enforces_global_w_xor_x() {
            return Err(());
        }
        troe_application::stream_verified_segments(
            package,
            &mut *read_at,
            |index, offset, bytes| {
                let logical = segment_offset(package, index)?
                    .checked_add(offset)
                    .ok_or(())?;
                write_launch_bytes(&self.shared, logical, bytes)
            },
        )
        .map_err(|_| ())?;
        troe_application::visit_verified_relocations(package, &mut *read_at, |relocation| {
            let (index, segment) = package
                .executable()
                .segments()
                .enumerate()
                .find(|(_, segment)| {
                    segment.image_offset() <= relocation.target_offset()
                        && relocation
                            .target_offset()
                            .checked_add(8)
                            .is_some_and(|end| {
                                end <= segment.image_offset() + segment.memory_bytes()
                            })
                })
                .ok_or(())?;
            let offset = segment_offset(package, index)?
                .checked_add(relocation.target_offset() - segment.image_offset())
                .ok_or(())?;
            let value = package
                .executable()
                .image_base()
                .checked_add(relocation.value_offset())
                .ok_or(())?;
            write_launch_bytes(&self.shared, offset, &value.to_le_bytes())
        })
        .map_err(|_| ())?;
        process_plan
            .encode_startup_page(token, startup, &mut page)
            .map_err(|_| ())?;
        let image_pages = package.executable().charges().image_pages();
        write_launch_bytes(
            &self.shared,
            image_pages.checked_mul(BASE_PAGE_SIZE).ok_or(())?,
            &page,
        )?;

        let tables = troe_machine::required_page_table_pages(&mapping)
            .map_err(|_| ())?
            .checked_add(limits.extra_table_pages)
            .ok_or(())?;
        let resident = pages
            .checked_add(tables)
            .and_then(|n| n.checked_add(self.tls.backing_pages()))
            .ok_or(())?;
        if resident > limits.memory.resident_pages
            || resident
                .checked_sub(2)
                .is_none_or(|n| n > limits.memory.ordinary_frames)
            || tables
                > accounting
                    .frames
                    .free_frames()
                    .saturating_sub(accounting.memory_policy.minimum_free_pages())
        {
            return Err(());
        }
        self.tables = Some(
            accounting
                .frames
                .allocate_contiguous(tables, 1)
                .map_err(|_| ())?,
        );
        let root = troe_machine::build_user_address_space(&mapping, self.tables.ok_or(())?)
            .map_err(|_| ())?;
        let owned_metadata = self.owned_metadata_bytes()?;
        let remaining = accounting
            .memory_policy
            .global_metadata_bytes()
            .checked_sub(accounting.private_metadata_bytes)
            .ok_or(())?
            .min(accounting.memory_policy.default_maximum_metadata_bytes());
        let native_limit = limits
            .metadata_bytes
            .min(usize::try_from(remaining).map_err(|_| ())?)
            .checked_sub(owned_metadata)
            .ok_or(())?;
        self.native = Some(
            NativeProcessContext::new(initial.process(), root, limits.contexts, native_limit)
                .map_err(|_| ())?,
        );
        let native = self.native.as_mut().ok_or(())?;
        let metadata_bytes = u64::try_from(
            native
                .metadata_bytes()
                .checked_add(owned_metadata)
                .ok_or(())?,
        )
        .map_err(|_| ())?;
        accounting.private_metadata_bytes = accounting
            .private_metadata_bytes
            .checked_add(metadata_bytes)
            .ok_or(())?;
        self.metadata_bytes = metadata_bytes;
        let heap = VirtualRange::from_pages(
            process_plan.heap_address(),
            process_plan.heap_capacity_pages(),
        )
        .map_err(|_| ())?;
        native.bind_heap(heap).map_err(|_| ())?;
        Ok(())
    }

    /// Publish the initial native context after all source callbacks have returned.
    pub(crate) fn admit_initial(&mut self, policy: &ThreadTable) -> Result<(), ()> {
        let first = self.threads.first().ok_or(())?;
        self.native
            .as_mut()
            .ok_or(())?
            .admit_prepared(
                policy,
                NativeThreadAdmission {
                    thread: first.thread,
                    descriptor: first.descriptor,
                    entry: self.tls.plan().entry_address(),
                    backing: first.backing(),
                },
                troe_machine::IpcPagePair::allocate_application_thread().map_err(|_| ())?,
            )
            .map_err(|_| ())?;
        Ok(())
    }

    fn owned_metadata_bytes(&self) -> Result<usize, ()> {
        // NativeProcessContext separately charges its own inline storage.
        let mut bytes = core::mem::size_of::<Self>()
            .checked_sub(core::mem::size_of::<NativeProcessContext>())
            .and_then(|bytes| {
                self.threads
                    .capacity()
                    .checked_mul(core::mem::size_of::<NativeThreadMemory>())
                    .and_then(|records| bytes.checked_add(records))
            })
            .and_then(|bytes| bytes.checked_add(self.shared.buffer_bytes()))
            .and_then(|bytes| {
                bytes.checked_add(
                    self.heap_growth.capacity() * core::mem::size_of::<PhysicalExtents>(),
                )
            })
            .ok_or(())?;
        for thread in &self.threads {
            for frames in [&thread.stack, &thread.tls, &thread.startup] {
                bytes = bytes.checked_add(frames.buffer_bytes()).ok_or(())?;
            }
        }
        Ok(bytes)
    }

    pub(crate) fn stop(&mut self) {
        self.tls.stop_creation();
        if let Some(native) = &mut self.native {
            native.stop();
        }
    }

    /// Failed provisional cleanup must also prevent later logical acknowledgement.
    fn release_unpublished(
        &mut self,
        accounting: &mut OwnedAccounting,
        frames: &[PhysicalExtents],
    ) -> Result<(), ()> {
        if self.reclamation_failed {
            return Err(());
        }
        self.reclamation_failed = true;
        for extent in frames {
            release(accounting, extent)?;
        }
        self.reclamation_failed = false;
        Ok(())
    }

    pub(crate) fn reclaim(mut self, accounting: &mut OwnedAccounting) -> Result<(), ()> {
        self.stop();
        drop(self.native.take());
        // A partially failed thread reclamation quarantines its accounting.
        // Never acknowledge all logical resources after that physical failure.
        if self.reclamation_failed {
            return Err(());
        }
        for thread in &self.threads {
            for frames in [&thread.stack, &thread.tls, &thread.startup] {
                release(accounting, frames)?;
            }
        }
        release(accounting, &self.shared)?;
        for frames in &self.heap_growth {
            release(accounting, frames)?;
        }
        if let Some(tables) = self.tables.take() {
            troe_machine::zero_physical_range(tables).map_err(|_| ())?;
            accounting.frames.free_range(tables).map_err(|_| ())?;
        }
        accounting.application_committed_pages = accounting
            .application_committed_pages
            .checked_sub(self.committed_pages)
            .ok_or(())?;
        accounting.private_metadata_bytes = accounting
            .private_metadata_bytes
            .checked_sub(self.metadata_bytes)
            .ok_or(())?;
        Ok(())
    }
}

fn segment_offset(package: &StreamedKexPackage, index: usize) -> Result<u64, ()> {
    if index >= package.executable().segments().count() {
        return Err(());
    }
    package
        .executable()
        .segments()
        .take(index)
        .try_fold(0_u64, |offset, segment| {
            offset.checked_add(segment.memory_bytes())
        })
        .ok_or(())
}

fn release(accounting: &mut OwnedAccounting, frames: &PhysicalExtents) -> Result<(), ()> {
    for range in frames.extents() {
        troe_machine::zero_physical_range(*range).map_err(|_| ())?;
        accounting.frames.free_range(*range).map_err(|_| ())?;
    }
    Ok(())
}

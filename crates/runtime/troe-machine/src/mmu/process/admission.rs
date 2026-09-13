//! Transactional mapping of one retained logical preparation.

use super::{NativeProcessContext, NativeThreadBacking, NativeThreadStart};
use crate::{IpcPagePair, MmuError, mmu};
use troe_abi::threading::{STARTUP_BYTES, StartupDescriptor, StartupReference};
use troe_memory::{MappingMemoryType, MappingPrivilege, PhysicalRange, VirtualRange};
use troe_task::thread::{ThreadId, ThreadTable};

const PAGE: u64 = 4096;

/// Trusted admitted entry and exclusively retained, unpublished thread backing.
///
/// Composition initializes compiler TLS from its immutable process template,
/// reserves the complete virtual window and physical/metadata/table charges,
/// and retains every ordinary frame until native retirement or root teardown.
/// No physical extent or trampoline address may come from unchecked user input.
#[derive(Clone, Copy)]
pub struct NativeThreadAdmission<'a> {
    /// Exact process-scoped logical preparation.
    pub thread: ThreadId,
    /// Immutable bootstrap fields, matched to the live token and private maps.
    /// Uses the managed order: guarded stack, TLS, adjacent IPC and descriptor,
    /// then a final guard. Alignment slack before TLS stays reserved/unmapped.
    pub descriptor: StartupDescriptor,
    /// Validated image initial entry or kernel-selected worker trampoline.
    pub entry: u64,
    /// Stack, compiler TLS and exactly one private descriptor page.
    pub backing: NativeThreadBacking<'a>,
}

/// Failure preserves the owner required by the point of rejection.
#[derive(Debug)]
#[must_use = "Retain ordinary frames until rejected admission or stopped-root teardown"]
pub enum NativeThreadAdmissionError {
    /// No mapping changed; the caller recovers its unpublished IPC owner.
    Rejected {
        /// Rejected state, geometry, backing or capacity.
        error: MmuError,
        /// Still owned and never mapped by this attempt.
        ipc: IpcPagePair,
    },
    /// Mutation may have occurred; the stopped process retains the root and IPC.
    /// Drop it before reclaiming any ordinary or table frames.
    Stopped(MmuError),
}

struct Geometry {
    start: NativeThreadStart,
    window: VirtualRange,
    ipc: VirtualRange,
    encoded: [u8; STARTUP_BYTES],
}
impl Geometry {
    fn new(descriptor: StartupDescriptor, entry: u64) -> Result<Self, MmuError> {
        let encoded = descriptor
            .encode()
            .map_err(|_| MmuError::InvalidUserContext)?;
        let range = |start, pages| {
            VirtualRange::from_pages(start, pages).map_err(|_| MmuError::InvalidUserContext)
        };
        let stack = range(
            descriptor.stack_bottom,
            (descriptor.stack_top - descriptor.stack_bottom) / PAGE,
        )?;
        let tls = range(descriptor.tls_base, descriptor.tls_bytes / PAGE)?;
        let ipc = range(descriptor.ipc_tx, 2)?;
        let startup = range(descriptor.address, 1)?;
        let lower = stack.start() - PAGE;
        let upper = startup
            .end()
            .checked_add(PAGE)
            .ok_or(MmuError::InvalidUserContext)?;
        // The managed window includes both stack guards, TLS alignment slack
        // and the final guard. No other mapping may occupy any of these bytes.
        if stack.end() + PAGE > tls.start()
            || tls.end() != ipc.start()
            || ipc.end() != startup.start()
            || descriptor.process_startup >= lower && descriptor.process_startup < upper
        {
            return Err(MmuError::InvalidUserContext);
        }
        Ok(Self {
            start: NativeThreadStart {
                entry,
                stack,
                tls,
                thread_pointer: descriptor.thread_pointer,
                startup: if descriptor.initial {
                    descriptor.process_startup
                } else {
                    descriptor.address
                },
                startup_bytes: if descriptor.initial {
                    4096
                } else {
                    STARTUP_BYTES
                },
                private_startup: Some(startup),
            },
            window: range(lower, (upper - lower) / PAGE)?,
            ipc,
            encoded,
        })
    }

    fn targets<'a>(
        &self,
        backing: NativeThreadBacking<'a>,
        ipc: &'a [PhysicalRange],
    ) -> [mmu::retirement::Backing<'a>; 4] {
        use mmu::retirement::Backing;
        [
            Backing {
                range: self.start.stack,
                physical: backing.stack,
                writable: true,
            },
            Backing {
                range: self.start.tls,
                physical: backing.tls,
                writable: true,
            },
            Backing {
                range: self.ipc,
                physical: ipc,
                writable: true,
            },
            Backing {
                range: self.start.private_startup.unwrap_or(self.start.stack),
                physical: backing.startup,
                writable: false,
            },
        ]
    }
}

impl NativeProcessContext {
    /// Map and bind a live Prepared record without allocating or publishing Start.
    ///
    /// Preflight checks the complete reserved window, physical backing, all
    /// existing user aliases, role, exact mapped-page charge and conservative
    /// unused root-table capacity. Stack, descriptor and IPC are cleared before
    /// mapping; TLS must already be initialized by its retained process owner.
    /// Initial entry receives the shared process header; workers receive their
    /// private descriptor. The initial header's descriptor reference is bootstrap
    /// data, valid only until that initial thread's resources are reclaimed.
    ///
    /// The same exclusive root/table borrows span preflight through publication;
    /// this invokes no callback, user execution or scheduler operation. Ordinary
    /// frames and the complete table arena remain owned and charged externally.
    ///
    /// # Errors
    /// Returns the IPC owner before any mapping mutation. After mutation begins,
    /// failure stops every continuation and retains IPC until root teardown.
    pub fn admit_prepared(
        &mut self,
        threads: &ThreadTable,
        admission: NativeThreadAdmission<'_>,
        ipc: IpcPagePair,
    ) -> Result<(), NativeThreadAdmissionError> {
        self.admit_inner(threads, admission, ipc, false)
    }

    /// Fail after the first new leaf to verify terminal admission containment.
    ///
    /// # Errors
    /// Returns rejected ownership or a stopped root retaining the partially mapped IPC.
    #[cfg(feature = "acceptance-probes")]
    pub fn probe_admission_failure(
        &mut self,
        threads: &ThreadTable,
        admission: NativeThreadAdmission<'_>,
        ipc: IpcPagePair,
    ) -> Result<(), NativeThreadAdmissionError> {
        self.admit_inner(threads, admission, ipc, true)
    }

    #[allow(clippy::too_many_lines)]
    fn admit_inner(
        &mut self,
        threads: &ThreadTable,
        admission: NativeThreadAdmission<'_>,
        ipc: IpcPagePair,
        inject_failure: bool,
    ) -> Result<(), NativeThreadAdmissionError> {
        let geometry = match Geometry::new(admission.descriptor, admission.entry) {
            Ok(value) => value,
            Err(error) => return Err(NativeThreadAdmissionError::Rejected { error, ipc }),
        };
        let pair_range = [ipc.range()];
        let targets = geometry.targets(admission.backing, &pair_range);
        let checked = (|| {
            self.admission_preflight(threads, &admission, &ipc, &geometry, &targets)?;
            let capabilities = mmu::architecture_mmu_capabilities()?;
            // No published mappings refer to these exclusive frames. Initialize
            // descriptor bytes ourselves so RO publication cannot bless caller
            // bytes that disagree with the trusted geometry.
            for extent in admission
                .backing
                .stack
                .iter()
                .chain(admission.backing.startup)
                .chain(&pair_range)
            {
                crate::zero_physical_range(*extent).map_err(|_| MmuError::InvalidUserContext)?;
            }
            crate::copy_to_physical(admission.backing.startup[0], 0, &geometry.encoded)
                .map_err(|_| MmuError::InvalidUserContext)?;
            Ok(capabilities)
        })();
        let capabilities = match checked {
            Ok(value) => value,
            Err(error) => return Err(NativeThreadAdmissionError::Rejected { error, ipc }),
        };
        // Own IPC before any PTE can refer to it. Every subsequent error retains
        // this owner, even when the new context itself has not been published.
        let pair_index = self.backing.pairs.len();
        self.backing.pairs.push(ipc);
        let space = &mut self.backing.address_space;
        let mut mapped = 0_u64;
        let result = (|| {
            let mut arena =
                mmu::TableArena::resume(space.table_arena, space.stats.table_pages, &[])?;
            let result = mmu::admission::map(&targets, |address, physical, permissions| {
                if inject_failure && mapped != 0 {
                    return Err(MmuError::InvalidUserContext);
                }
                mmu::architecture_map_page(
                    &mut arena,
                    space.root,
                    address,
                    physical,
                    permissions,
                    MappingMemoryType::Normal,
                    MappingPrivilege::User,
                    capabilities,
                )?;
                mapped += 1;
                Ok(())
            });
            space.stats.table_pages = arena.used_pages;
            space.stats.mapped_pages += mapped; // checked for the complete addition before writes
            result?;
            mmu::admission::add_regions(&mut space.regions, &targets)
        })();
        if let Err(error) = result {
            self.stop();
            return Err(NativeThreadAdmissionError::Stopped(error));
        }
        let result = self
            .prepare(admission.thread, geometry.start)
            .and_then(|()| {
                self.bind_thread_ipc(admission.thread, pair_index, geometry.ipc.start())
            });
        if let Err(error) = result {
            self.stop();
            return Err(NativeThreadAdmissionError::Stopped(error));
        }
        // prepare appends exactly once; preflight and this publication hold the
        // same exclusive owner. No reference survives into user execution.
        let Some(context) = self.contexts.last_mut() else {
            self.stop();
            return Err(NativeThreadAdmissionError::Stopped(
                MmuError::InvalidUserContext,
            ));
        };
        context.window = Some(geometry.window);
        self.process_startup = Some(admission.descriptor.process_startup);
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn admission_preflight(
        &self,
        threads: &ThreadTable,
        admission: &NativeThreadAdmission<'_>,
        ipc: &IpcPagePair,
        geometry: &Geometry,
        targets: &[mmu::retirement::Backing<'_>],
    ) -> Result<(), MmuError> {
        let space = &self.backing.address_space;
        let descriptor = admission.descriptor;
        let pages = targets
            .iter()
            .try_fold(0_u64, |sum, target| {
                sum.checked_add(target.range.page_count())
            })
            .ok_or(MmuError::InvalidUserContext)?;
        threads
            .validate_prepared(self.process, admission.thread, descriptor.initial, pages)
            .map_err(|_| MmuError::InvalidUserContext)?;
        if self.stopped
            || space.tag.is_some()
            || space.ipc.is_some()
            || self.contexts.len() == self.capacity
            || self.backing.pairs.len() == self.capacity
            || self.backing.pairs.len() == self.backing.pairs.capacity()
            || ipc.slot() >= crate::IPC_TASK_PAIRS
            || !ipc.is_live()
            || admission.thread.slot() != descriptor.thread.slot() as usize
            || admission.thread.generation() != descriptor.thread.generation()
            || admission.backing.startup.len() != 1
            || match self.process_startup {
                Some(address) => descriptor.process_startup != address,
                None => !descriptor.initial,
            }
            || self.contexts.iter().any(|context| {
                context.id == admission.thread
                    || context
                        .window
                        .is_some_and(|old| super::overlaps(old, geometry.window))
                    || conflicts(context.start, geometry.window)
            })
            || !read_only_nx(space, descriptor.process_startup, 4096)
            || !super::user_range_contains(&space.regions, admission.entry, 1, false, true)
            || !descriptor.initial
                && !super::user_range_contains(&space.regions, descriptor.entry, 1, false, true)
            || !descriptor
                .thread_pointer
                .is_multiple_of(if cfg!(target_arch = "aarch64") { 16 } else { 8 })
        {
            return Err(MmuError::InvalidUserContext);
        }
        // The first mapped initial thread binds the shared header identity for
        // the root's lifetime. A writable alias must not make an RO header
        // mutable by a sibling; a duplicate alias is unnecessary for this page.
        if self.process_startup.is_none() {
            unique_startup_page(space, descriptor.process_startup)?;
        }
        if descriptor.initial {
            let mut reference = [0; 16];
            mmu::copy_user_from_physical(
                space.root,
                &space.regions,
                descriptor.process_startup + 80,
                &mut reference,
            )?;
            if StartupReference::decode(&reference)
                .map_err(|_| MmuError::InvalidUserContext)?
                .address
                != descriptor.address
            {
                return Err(MmuError::InvalidUserContext);
            }
        }
        let needed = mmu::maximum_additional_page_table_pages(geometry.window)?;
        if space
            .table_arena
            .page_count()
            .checked_sub(space.stats.table_pages)
            .is_none_or(|free| free < needed)
        {
            return Err(MmuError::TableArenaExhausted);
        }
        space
            .stats
            .mapped_pages
            .checked_add(pages)
            .ok_or(MmuError::InvalidUserContext)?;
        mmu::admission::preflight(
            &space.regions,
            geometry.window,
            targets,
            space.table_arena,
            space.regions.capacity(),
            |address| mmu::architecture_translate_page(space.root, address),
        )?;
        Ok(())
    }
}

pub(super) fn conflicts(start: NativeThreadStart, window: VirtualRange) -> bool {
    let lower = start.stack.start().saturating_sub(PAGE);
    let upper = start.stack.end().saturating_add(PAGE);
    lower < window.end() && window.start() < upper
        || super::private_ranges(start).any(|range| super::overlaps(range, window))
        || start.startup < window.end()
            && window.start() < start.startup.saturating_add(start.startup_bytes as u64)
}

fn read_only_nx(space: &mmu::UserAddressSpace, address: u64, bytes: usize) -> bool {
    mmu::user_range_contains(&space.regions, address, bytes, false, false)
        && !space.regions.iter().any(|region| {
            region.range.start() < address + bytes as u64
                && address < region.range.end()
                && (region.permissions.write || region.permissions.execute)
        })
}

fn unique_startup_page(space: &mmu::UserAddressSpace, address: u64) -> Result<(), MmuError> {
    let physical = mmu::architecture_translate_page(space.root, address)?;
    if space.table_arena.start() <= physical && physical < space.table_arena.end() {
        return Err(MmuError::InvalidUserContext);
    }
    for region in &space.regions {
        for alias in (region.range.start()..region.range.end()).step_by(4096) {
            if alias != address && mmu::architecture_translate_page(space.root, alias)? == physical
            {
                return Err(MmuError::InvalidUserContext);
            }
        }
    }
    Ok(())
}

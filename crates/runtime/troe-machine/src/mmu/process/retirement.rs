//! Inactive native thread retirement; ordinary physical owners stay in composition.

use super::{NativeProcessContext, NativeSchedulerExecution};
use crate::mmu::{
    MmuError,
    retirement::{self, Backing},
};
use troe_memory::{PhysicalRange, VirtualRange};
use troe_task::thread::{ThreadId, ThreadState, ThreadTable};

/// Borrowed extents from the exact thread's retained kernel frame reservations.
///
/// Extents are in virtual-page order and may be physically fragmented. Startup
/// must be empty when the admitted context uses a shared startup record. This
/// describes backing; it transfers no ownership and must never come from user
/// supplied physical addresses.
#[derive(Clone, Copy)]
pub struct NativeThreadBacking<'a> {
    /// Complete stack backing.
    pub stack: &'a [PhysicalRange],
    /// Complete compiler TLS backing, including its thread-control block.
    pub tls: &'a [PhysicalRange],
    /// Complete private read-only startup backing, or an empty shared record.
    pub startup: &'a [PhysicalRange],
}

/// Proof that one continuation and its private user mappings have been removed.
///
/// IPC storage has been zeroed and released (or permanently quarantined on a
/// zeroing failure). Ordinary frames still belong to composition, which must
/// zero/reclaim them before acknowledging logical resource release. Shared root
/// table frames and their accounting remain owned by the process.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "Reclaim the retained physical owners before acknowledging thread resources"]
pub struct NativeThreadRetirement {
    thread: ThreadId,
    ordinary_pages: u64,
}
impl NativeThreadRetirement {
    /// Exact retired process-scoped incarnation.
    #[must_use]
    pub const fn thread(&self) -> ThreadId {
        self.thread
    }

    /// Stack, TLS and private startup pages; excludes the two boot-arena IPC pages.
    #[must_use]
    pub const fn ordinary_pages(&self) -> u64 {
        self.ordinary_pages
    }
}

impl NativeProcessContext {
    /// Remove a fully bound, never-executed context after logical revocation.
    ///
    /// Composition must first win prepared Abort or creator-exit revocation in
    /// the paired lifecycle table. `started == false` alone is insufficient:
    /// logical Start may already have published a runnable thread. This call
    /// rechecks the exact live Revoked record and retained resource charge while
    /// borrowing that table, then applies the same complete backing/alias checks
    /// and native quiescence contract as [`Self::retire_thread`]. It neither
    /// refunds logical charges nor completes the separate caller's Abort request.
    ///
    /// # Errors
    /// Rejects non-revoked, released, stale, executed or captured targets before
    /// writes. A failure after mutation stops the complete native process and
    /// retains its backing until root teardown.
    pub fn discard_revoked(
        &mut self,
        threads: &ThreadTable,
        target: ThreadId,
        backing: NativeThreadBacking<'_>,
    ) -> Result<NativeThreadRetirement, MmuError> {
        let snapshot = threads
            .snapshot(self.process, target)
            .map_err(|_| MmuError::InvalidUserContext)?;
        if snapshot.state != ThreadState::Revoked || snapshot.resources_released {
            return Err(MmuError::InvalidUserContext);
        }
        let index = self
            .contexts
            .iter()
            .position(|context| context.id == target)
            .ok_or(MmuError::InvalidUserContext)?;
        let context = &self.contexts[index];
        if context.started
            || context.scheduler_operation.is_some()
            || !matches!(context.pending, super::ApplicationPending::Timeslice)
        {
            return Err(MmuError::InvalidUserContext);
        }
        self.retire_index(index, backing, crate::mmu::architecture_unmap_page)
    }

    /// Consume a claimed Exit after trusted lifecycle and owner-death checks.
    ///
    /// Requires an inactive untagged root. Validates complete physical backing,
    /// private geometry, sibling entry/startup references and all user aliases
    /// before removing leaves. It allocates nothing and never publishes a reply
    /// or runs cleanup. Metadata split space is bounded and charged at admission.
    /// Untagged native gates flush user translations before returning to the
    /// kernel and before the next user activation; no other CPU uses this root.
    ///
    /// This proves native quiescence, not lifecycle authority or ordinary frame
    /// reclamation. Composition handles initial-thread exit, synchronization
    /// owner death, prepared children and logical completion/resource accounting.
    ///
    /// # Errors
    /// Returns the original execution on preflight failure without writes. Any
    /// failure after mutation stops every continuation and retains all IPC owners
    /// until root teardown. The returned execution then has no live authority.
    #[allow(clippy::result_large_err)] // Preserve bounded ownership without allocation.
    pub fn retire_thread(
        &mut self,
        execution: NativeSchedulerExecution,
        backing: NativeThreadBacking<'_>,
    ) -> Result<NativeThreadRetirement, (MmuError, NativeSchedulerExecution)> {
        match self.retire_inner(&execution, backing, crate::mmu::architecture_unmap_page) {
            Ok(retired) => Ok(retired),
            Err(error) => Err((error, execution)),
        }
    }

    /// Inject a terminal failure after removing the first validated leaf.
    ///
    /// # Errors
    /// Returns ownership exactly as retirement does, with the complete process stopped.
    #[cfg(feature = "acceptance-probes")]
    #[allow(clippy::result_large_err)]
    pub fn probe_retirement_failure(
        &mut self,
        execution: NativeSchedulerExecution,
        backing: NativeThreadBacking<'_>,
    ) -> Result<NativeThreadRetirement, (MmuError, NativeSchedulerExecution)> {
        let mut removed = false;
        let result = self.retire_inner(&execution, backing, |root, address| {
            if removed {
                return Err(MmuError::InvalidUserContext);
            }
            removed = true;
            crate::mmu::architecture_unmap_page(root, address)
        });
        result.map_err(|error| (error, execution))
    }

    // Keep preflight, mutation failure containment and successful owner release together.
    #[allow(clippy::too_many_lines)]
    fn retire_inner(
        &mut self,
        execution: &NativeSchedulerExecution,
        backing: NativeThreadBacking<'_>,
        unmap: impl FnMut(u64, u64) -> Result<u64, MmuError>,
    ) -> Result<NativeThreadRetirement, MmuError> {
        if !matches!(execution.request(), troe_abi::threading::Request::Exit(_))
            || self.backing.address_space.tag.is_some()
        {
            return Err(MmuError::InvalidUserContext);
        }
        let index = self.scheduler_index(execution.operation, true)?;
        self.retire_index(index, backing, unmap)
    }

    // All entry points share read-only preflight and terminal mutation failure handling.
    #[allow(clippy::too_many_lines)]
    fn retire_index(
        &mut self,
        index: usize,
        backing: NativeThreadBacking<'_>,
        mut unmap: impl FnMut(u64, u64) -> Result<u64, MmuError>,
    ) -> Result<NativeThreadRetirement, MmuError> {
        if self.stopped || self.backing.address_space.tag.is_some() {
            return Err(MmuError::InvalidUserContext);
        }
        let context = &self.contexts[index];
        let target = context.id;
        let start = context.start;
        let (ipc, _) = self.bound_ipc(target)?;
        let pair = [self.backing.pairs[ipc.index].range()];
        let ipc_range =
            VirtualRange::from_pages(ipc.tx, 2).map_err(|_| MmuError::InvalidUserContext)?;
        let mut targets = [
            Backing {
                range: start.stack,
                physical: backing.stack,
                writable: true,
            },
            Backing {
                range: start.tls,
                physical: backing.tls,
                writable: true,
            },
            Backing {
                range: ipc_range,
                physical: &pair,
                writable: true,
            },
            Backing {
                range: start.stack,
                physical: backing.startup,
                writable: false,
            },
        ];
        let count = if let Some(range) = start.private_startup {
            targets[3].range = range;
            4
        } else {
            if !backing.startup.is_empty() {
                return Err(MmuError::InvalidUserContext);
            }
            3
        };
        let targets = &targets[..count];
        if self.contexts.iter().any(|peer| {
            peer.id != context.id
                && targets.iter().any(|target| {
                    super::private_ranges(peer.start)
                        .any(|range| super::overlaps(range, target.range))
                        || (target.range.start() <= peer.start.entry
                            && peer.start.entry < target.range.end())
                        || (peer.start.startup < target.range.end()
                            && target.range.start()
                                < peer.start.startup + peer.start.startup_bytes as u64)
                        || peer.ipc.is_some_and(|binding| {
                            binding.tx < target.range.end()
                                && target.range.start() < binding.tx + 8192
                        })
                })
        }) {
            return Err(MmuError::InvalidUserContext);
        }
        let space = &mut self.backing.address_space;
        let pages = retirement::preflight(
            &space.regions,
            targets,
            space.regions.capacity(),
            |address| crate::mmu::architecture_translate_page(space.root, address),
        )?;
        let mapped_pages = space
            .stats
            .mapped_pages
            .checked_sub(pages)
            .ok_or(MmuError::InvalidUserContext)?;
        // No native execution can race this exclusive borrow. Every failing
        // path below is terminal, retaining the root and all backing owners.
        if let Err(error) = retirement::unmap(targets, |address| unmap(space.root, address))
            .and_then(|()| retirement::remove_regions(&mut space.regions, targets))
        {
            self.stop();
            return Err(error);
        }
        space.stats.mapped_pages = mapped_pages;
        let last = self.contexts.len() - 1;
        // Swap first, then truncate in place: ThreadContext::drop erases the
        // retired registers in the array itself. swap_remove would instead leave
        // a moved sibling's register bytes in the uninitialized allocation tail.
        self.contexts.swap(index, last);
        self.contexts.truncate(last);
        let moved_pair = self.backing.pairs.len() - 1;
        let released = self.backing.pairs.swap_remove(ipc.index);
        for peer in &mut self.contexts {
            if let Some(binding) = &mut peer.ipc
                && binding.index == moved_pair
            {
                binding.index = ipc.index;
            }
        }
        // All user aliases were removed; the inactive untagged root cannot
        // retain usable translations. Pair Drop zeros before publishing reuse.
        drop(released);
        Ok(NativeThreadRetirement {
            thread: target,
            ordinary_pages: pages - 2,
        })
    }
}

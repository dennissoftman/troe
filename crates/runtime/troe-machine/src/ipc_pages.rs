//! Boot-arena private IPC storage. Ordinary frames never back these aliases.

use crate::MmuError;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use troe_memory::PhysicalRange;

/// Isolated-task pairs retained permanently in the owned boot arena.
pub const IPC_TASK_PAIRS: usize = 16;
/// Kernel continuation pairs, never mapped at user privilege.
pub const IPC_KERNEL_PAIRS: usize = 4;
/// Complete boot reservation, including the kernel clients.
pub const IPC_POOL_PAGES: u64 = 2 * (IPC_TASK_PAIRS + IPC_KERNEL_PAIRS) as u64;
static BASE: AtomicU64 = AtomicU64::new(0);
static OCCUPIED: AtomicU32 = AtomicU32::new(0);
static GENERATIONS: [AtomicU64; IPC_TASK_PAIRS + IPC_KERNEL_PAIRS] =
    [const { AtomicU64::new(1) }; IPC_TASK_PAIRS + IPC_KERNEL_PAIRS];

/// Initialize the complete pool before publishing any isolated task.
///
/// # Errors
/// Rejects repeated initialization or a reservation with the wrong geometry.
pub fn initialize_ipc_pool(range: PhysicalRange) -> Result<(), MmuError> {
    if range.page_count() != IPC_POOL_PAGES
        || range.start() == 0
        || BASE.load(Ordering::Acquire) != 0
    {
        return Err(MmuError::InvalidPlan);
    }
    crate::zero_physical_range(range).map_err(|_| MmuError::InvalidPlan)?;
    BASE.compare_exchange(0, range.start(), Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| MmuError::InvalidPlan)?;
    Ok(())
}

/// Unique retained pair. Drop zeros both pages before releasing the slot.
///
/// Composition must revoke all task roots before dropping this owner, just as
/// it must revoke roots before returning ordinary task frames.
#[derive(Debug, Eq, PartialEq)]
pub struct IpcPagePair {
    slot: usize,
    generation: u64,
    range: PhysicalRange,
}

impl IpcPagePair {
    /// Reserve and zero one isolated-task pair before constructing user mappings.
    ///
    /// # Errors
    /// Fails atomically when the pool is unpublished or its 16 task pairs are busy.
    pub fn allocate() -> Result<Self, MmuError> {
        Self::allocate_between(0, IPC_TASK_PAIRS)
    }

    /// Reserve one of the four pairs for a kernel continuation.
    ///
    /// # Errors
    /// Fails atomically if the pool is unpublished or all kernel pairs are busy.
    pub fn allocate_kernel() -> Result<Self, MmuError> {
        Self::allocate_between(IPC_TASK_PAIRS, IPC_TASK_PAIRS + IPC_KERNEL_PAIRS)
    }

    fn allocate_between(start: usize, end: usize) -> Result<Self, MmuError> {
        let base = BASE.load(Ordering::Acquire);
        if base == 0 {
            return Err(MmuError::InvalidPlan);
        }
        for (slot, generation) in GENERATIONS.iter().enumerate().take(end).skip(start) {
            let generation = generation.load(Ordering::Acquire);
            if generation == u64::MAX {
                continue;
            }
            let bit = 1_u32 << slot;
            if OCCUPIED.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
                continue;
            }
            let range = PhysicalRange::from_pages(base + slot as u64 * 8192, 2)
                .map_err(|_| MmuError::InvalidPlan)?;
            let pair = Self {
                slot,
                generation,
                range,
            };
            crate::zero_physical_range(range).map_err(|_| MmuError::InvalidPlan)?;
            return Ok(pair);
        }
        Err(MmuError::IsolationBusy)
    }

    /// Supervisor identity alias; only task pairs may be additionally mapped to users.
    #[must_use]
    pub const fn range(&self) -> PhysicalRange {
        self.range
    }

    /// Stable pool index, also the task's hardware tag minus one.
    #[must_use]
    pub const fn slot(&self) -> usize {
        self.slot
    }

    /// Nonwrapping incarnation of this pool slot.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether this identity still names the current occupied pair.
    #[must_use]
    pub fn is_live(&self) -> bool {
        OCCUPIED.load(Ordering::Acquire) & (1 << self.slot) != 0
            && GENERATIONS[self.slot].load(Ordering::Acquire) == self.generation
    }
}

impl Drop for IpcPagePair {
    fn drop(&mut self) {
        // A failed zero deliberately retires the slot rather than publishing
        // storage whose prior task data might remain visible.
        if !self.is_live() || crate::zero_physical_range(self.range).is_err() {
            GENERATIONS[self.slot].store(u64::MAX, Ordering::Release);
            return;
        }
        GENERATIONS[self.slot].store(self.generation + 1, Ordering::Release);
        OCCUPIED.fetch_and(!(1 << self.slot), Ordering::AcqRel);
    }
}

/// Exercise pool capacity, disjoint kernel storage, rollback, and zero-before-reuse.
///
/// # Errors
/// Fails if any slot leaks data or a stale incarnation becomes live again.
#[cfg(feature = "acceptance-probes")]
pub fn verify_ipc_pool() -> Result<(), MmuError> {
    let mut tasks: [Option<IpcPagePair>; IPC_TASK_PAIRS] = core::array::from_fn(|_| None);
    let mut kernel: [Option<IpcPagePair>; IPC_KERNEL_PAIRS] = core::array::from_fn(|_| None);
    for pair in &mut tasks {
        *pair = Some(IpcPagePair::allocate()?);
    }
    for pair in &mut kernel {
        *pair = Some(IpcPagePair::allocate_kernel()?);
    }
    if IpcPagePair::allocate().is_ok() || IpcPagePair::allocate_kernel().is_ok() {
        return Err(MmuError::InvalidPlan);
    }
    for pair in tasks.iter_mut().chain(kernel.iter_mut()) {
        let prior = pair.take().ok_or(MmuError::InvalidPlan)?;
        let slot = prior.slot();
        let generation = prior.generation();
        let range = prior.range();
        let pattern = [0xa5; 4096];
        crate::copy_to_physical(range, 0, &pattern).map_err(|_| MmuError::InvalidPlan)?;
        crate::copy_to_physical(range, 4096, &pattern).map_err(|_| MmuError::InvalidPlan)?;
        // This is also the partial-launch rollback path: no root was published.
        drop(prior);
        if !crate::mechanism::physical_range_is_zero(range) {
            return Err(MmuError::InvalidPlan);
        }
        let next = if slot < IPC_TASK_PAIRS {
            IpcPagePair::allocate()?
        } else {
            IpcPagePair::allocate_kernel()?
        };
        if next.slot() != slot
            || next.generation() != generation + 1
            || next.range() != range
            || GENERATIONS[slot].load(Ordering::Acquire) == generation
            || !next.is_live()
        {
            return Err(MmuError::InvalidPlan);
        }
        *pair = Some(next);
    }
    Ok(())
}

/// Verify a released task pair is zero while its boot reservation remains owned.
#[cfg(feature = "acceptance-probes")]
#[must_use]
pub fn ipc_range_is_zero(range: PhysicalRange) -> bool {
    let base = BASE.load(Ordering::Acquire);
    range.page_count() == 2
        && range.start() >= base
        && range.end() <= base + IPC_POOL_PAGES * 4096
        && (range.start() - base).is_multiple_of(8192)
        && crate::mechanism::physical_range_is_zero(range)
}

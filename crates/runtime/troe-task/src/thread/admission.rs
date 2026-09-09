//! Paired portable table preflight; this does not reserve native IPC or memory.

use super::{
    ThreadError, ThreadTable,
    sync::{SyncError, SyncTable},
};

/// Global portable capacities and the ceiling for one application's thread quota.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadAdmissionLimits {
    /// Concurrent registered application processes.
    pub processes: usize,
    /// All retained records; no more than `processes * threads_per_process`.
    pub threads: usize,
    /// All synchronization objects, including poisoned objects.
    pub objects: usize,
    /// Initial plus worker records per process; strictly below `threads`.
    pub threads_per_process: usize,
}

/// Trusted resource envelope after accounting for other storage consumers.
///
/// Counts are configuration inputs, not a new pool or entitlement. Native
/// composition must use the actual usable task IPC capacity, exclude retired
/// slots, and include all essential-service/teardown needs in the protected
/// reservation. Kernel-continuation pairs must never enter task capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadAdmissionBudget {
    /// Usable task IPC-pair capacity before protected reservations.
    pub task_ipc_pairs: usize,
    /// Nonzero protected task-pair headroom unavailable to this application pool.
    pub reserved_task_ipc_pairs: usize,
    /// Logical metadata bytes available for both owners and all five buffers.
    pub metadata_bytes: usize,
}

/// Rejected paired capacity, resource envelope or table construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadAdmissionError {
    /// Per-process limits or protected headroom violate the admission policy.
    InvalidLimit,
    /// Retained records would consume protected or unavailable task IPC capacity.
    ContextBudget,
    /// Both tables cannot fit together in the metadata-byte allowance.
    MetadataBudget,
    /// Lifecycle table validation/allocation failed; no pair was published.
    Thread(ThreadError),
    /// Synchronization table validation/allocation failed; no pair was published.
    Sync(SyncError),
}

impl From<ThreadError> for ThreadAdmissionError {
    fn from(error: ThreadError) -> Self {
        Self::Thread(error)
    }
}

impl From<SyncError> for ThreadAdmissionError {
    fn from(error: SyncError) -> Self {
        Self::Sync(error)
    }
}

/// Checked capacity configuration, not a resource owner or reservation token.
///
/// Each retained thread has one preallocated synchronization wait slot. A process
/// may not consume the entire global thread table. Protected task IPC headroom
/// stays outside the application pool. These are simultaneous ceilings; they do
/// not promise every configured process can use its maximum quota at once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadAdmissionPlan {
    limits: ThreadAdmissionLimits,
    metadata_bytes: usize,
    sync_metadata_bytes: usize,
    max_metadata_bytes: usize,
    available_contexts: usize,
}

impl ThreadAdmissionPlan {
    /// Derive the largest global thread capacity that fits a supplied envelope.
    ///
    /// Process/object counts and the per-process ceiling stay fixed. Each added
    /// thread costs one compiled lifecycle slot and one compiled wait slot. The
    /// result is also capped by aggregate process quotas, unreserved task contexts
    /// and the record backstop.
    /// This is capacity inspection, not a selected product default or allocation.
    ///
    /// # Errors
    /// Rejects invalid counts or an envelope unable to support the minimum valid
    /// configuration (including one record beyond the per-process ceiling).
    pub fn maximum_capacity(
        processes: usize,
        objects: usize,
        threads_per_process: usize,
        budget: ThreadAdmissionBudget,
    ) -> Result<Self, ThreadAdmissionError> {
        let minimum = processes.max(
            threads_per_process
                .checked_add(1)
                .ok_or(ThreadAdmissionError::InvalidLimit)?,
        );
        let limits = ThreadAdmissionLimits {
            processes,
            threads: minimum,
            objects,
            threads_per_process,
        };
        let baseline = Self::new(limits, budget)?;
        let thread_stride = ThreadTable::metadata_layout(1, 1)?.buffers()[1].size();
        let wait_stride = SyncTable::metadata_layout(1, 1, 1)?.buffers()[2].size();
        let per_thread = thread_stride
            .checked_add(wait_stride)
            .filter(|stride| *stride != 0)
            .ok_or(ThreadAdmissionError::MetadataBudget)?;
        let extra = (budget.metadata_bytes - baseline.metadata_bytes) / per_thread;
        let maximum = minimum
            .saturating_add(extra)
            .min(baseline.available_contexts)
            .min(
                processes
                    .checked_mul(threads_per_process)
                    .ok_or(ThreadAdmissionError::InvalidLimit)?,
            )
            .min(crate::MAX_TASKS);
        Self::new(
            ThreadAdmissionLimits {
                threads: maximum,
                ..limits
            },
            budget,
        )
    }

    /// Reject an impossible table configuration without allocating anything.
    ///
    /// No default record counts or physical-memory grants are inferred. Stack,
    /// TLS, mappings, native contexts, IPC ownership, allocator overhead and
    /// runtime metadata require independent admission before native publication.
    ///
    /// # Errors
    /// Rejects invalid counts, missing headroom, or insufficient contexts/metadata.
    pub fn new(
        limits: ThreadAdmissionLimits,
        budget: ThreadAdmissionBudget,
    ) -> Result<Self, ThreadAdmissionError> {
        if limits.threads_per_process == 0
            || limits.threads_per_process >= limits.threads
            || limits
                .processes
                .checked_mul(limits.threads_per_process)
                .is_none_or(|maximum| limits.threads > maximum)
            || budget.reserved_task_ipc_pairs == 0
        {
            return Err(ThreadAdmissionError::InvalidLimit);
        }
        let available_contexts = budget
            .task_ipc_pairs
            .checked_sub(budget.reserved_task_ipc_pairs)
            .ok_or(ThreadAdmissionError::ContextBudget)?;
        if limits.threads > available_contexts {
            return Err(ThreadAdmissionError::ContextBudget);
        }
        let threads = ThreadTable::metadata_layout(limits.processes, limits.threads)
            .map_err(ThreadAdmissionError::Thread)?;
        let sync = SyncTable::metadata_layout(limits.processes, limits.objects, limits.threads)
            .map_err(ThreadAdmissionError::Sync)?;
        let metadata_bytes = threads
            .bytes()
            .checked_add(sync.bytes())
            .ok_or(ThreadAdmissionError::MetadataBudget)?;
        if metadata_bytes > budget.metadata_bytes {
            return Err(ThreadAdmissionError::MetadataBudget);
        }
        Ok(Self {
            limits,
            metadata_bytes,
            sync_metadata_bytes: sync.bytes(),
            max_metadata_bytes: budget.metadata_bytes,
            available_contexts,
        })
    }

    /// Validated global and per-process table ceilings.
    #[must_use]
    pub const fn limits(self) -> ThreadAdmissionLimits {
        self.limits
    }

    /// Compiled minimum storage for both inline owners and all five arrays.
    #[must_use]
    pub const fn metadata_bytes(self) -> usize {
        self.metadata_bytes
    }

    /// Task IPC capacity left after protected headroom, not currently free slots.
    #[must_use]
    pub const fn available_contexts(self) -> usize {
        self.available_contexts
    }

    /// Build both empty tables under their combined logical metadata budget.
    ///
    /// The lifecycle table leaves the synchronization table's full compiled
    /// request available. Actual retained capacity is charged before assigning
    /// the remaining budget to synchronization. No process is registered here;
    /// the pair is returned only after both allocations succeed. On failure,
    /// local owners drop their buffers. `pages` separately caps retained native
    /// thread pages; this operation does not allocate or reserve those pages.
    ///
    /// # Errors
    /// Propagates invalid page limits, capacity overflow or allocation failure.
    pub fn create_tables(
        self,
        pages: u64,
    ) -> Result<(ThreadTable, SyncTable), ThreadAdmissionError> {
        let thread_budget = self
            .max_metadata_bytes
            .checked_sub(self.sync_metadata_bytes)
            .ok_or(ThreadAdmissionError::MetadataBudget)?;
        let mut threads = ThreadTable::new(
            self.limits.processes,
            self.limits.threads,
            pages,
            thread_budget,
        )
        .map_err(ThreadAdmissionError::Thread)?;
        let sync_budget = self
            .max_metadata_bytes
            .checked_sub(threads.metadata_bytes())
            .ok_or(ThreadAdmissionError::MetadataBudget)?;
        let sync = SyncTable::new(
            self.limits.processes,
            self.limits.objects,
            self.limits.threads,
            sync_budget,
        )
        .map_err(ThreadAdmissionError::Sync)?;
        threads.max_process_threads = self.limits.threads_per_process;
        Ok((threads, sync))
    }
}

#[cfg(test)]
mod tests;

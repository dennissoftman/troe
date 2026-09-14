//! One shared policy owner, with short borrows between native entries and callbacks.

mod execution;
pub(crate) use execution::NativeResident;
#[cfg(feature = "acceptance-probes")]
pub(crate) mod probe;

use crate::machine::OwnedAccounting;
use alloc::rc::Rc;
use core::cell::RefCell;
use troe_task::{
    ProcessId,
    thread::{
        ThreadId, ThreadQuota, ThreadResources, ThreadTable,
        admission::{ThreadAdmissionBudget, ThreadAdmissionLimits, ThreadAdmissionPlan},
        sync::{SyncQuota, SyncTable},
    },
};

pub(crate) const PROCESS_THREADS: usize = 8;
const OBJECTS: usize = 256;
const PROCESS_OBJECTS: usize = 128;
const POLICY_METADATA_BYTES: usize = 64 * 1024;

pub(crate) type SharedNativeThreads = Rc<RefCell<NativeThreads>>;

pub(crate) struct NativeThreads {
    pub(crate) threads: ThreadTable,
    pub(crate) sync: SyncTable,
}

impl NativeThreads {
    /// Allocate both global tables once, charged alongside native VM metadata.
    /// This preallocates policy capacity; actual IPC remains separately acquired.
    pub(crate) fn shared(accounting: &mut OwnedAccounting) -> Result<SharedNativeThreads, ()> {
        if let Some(shared) = &accounting.native_threads {
            return Ok(Rc::clone(shared));
        }
        // Table metadata includes both inline owners. Add RefCell/Rc storage
        // explicitly; neither a second table owner nor its buffers are hidden.
        let overhead = core::mem::size_of::<RefCell<Self>>() - core::mem::size_of::<Self>()
            + 2 * core::mem::size_of::<usize>();
        let available = usize::try_from(
            accounting
                .memory_policy
                .global_metadata_bytes()
                .checked_sub(accounting.private_metadata_bytes)
                .ok_or(())?,
        )
        .map_err(|_| ())?
        .min(POLICY_METADATA_BYTES)
        .checked_sub(overhead)
        .ok_or(())?;
        let plan = ThreadAdmissionPlan::new(
            ThreadAdmissionLimits {
                processes: troe_machine::IPC_APPLICATION_THREAD_PAIRS,
                threads: troe_machine::IPC_APPLICATION_THREAD_PAIRS,
                objects: OBJECTS,
                threads_per_process: PROCESS_THREADS,
            },
            ThreadAdmissionBudget {
                task_ipc_pairs: troe_machine::IPC_TASK_PAIRS,
                reserved_task_ipc_pairs: troe_machine::IPC_PROTECTED_TASK_PAIRS,
                metadata_bytes: available,
            },
        )
        .map_err(|_| ())?;
        let pages = accounting
            .memory_policy
            .system_application_commit()
            .maximum()
            .unwrap_or(accounting.frames.free_frames())
            .min(
                accounting
                    .frames
                    .free_frames()
                    .saturating_sub(accounting.memory_policy.minimum_free_pages()),
            );
        let (threads, sync) = plan.create_tables(pages).map_err(|_| ())?;
        let charge = threads
            .metadata_bytes()
            .checked_add(sync.metadata_bytes())
            .and_then(|bytes| bytes.checked_add(overhead))
            .ok_or(())?;
        let shared = Rc::new(RefCell::new(Self { threads, sync }));
        accounting.private_metadata_bytes = accounting
            .private_metadata_bytes
            .checked_add(u64::try_from(charge).map_err(|_| ())?)
            .ok_or(())?;
        accounting.native_threads = Some(Rc::clone(&shared));
        Ok(shared)
    }

    /// Register only a Prepared initial thread; native backing and Start follow.
    pub(crate) fn register(
        &mut self,
        process: ProcessId,
        pages: u64,
        resources: ThreadResources,
    ) -> Result<ThreadId, ()> {
        self.threads
            .register_process(
                process,
                ThreadQuota {
                    records: PROCESS_THREADS,
                    pages,
                },
            )
            .map_err(|_| ())?;
        if self
            .sync
            .register_process(
                &mut self.threads,
                process,
                SyncQuota {
                    objects: PROCESS_OBJECTS,
                    waits: PROCESS_THREADS,
                },
            )
            .is_err()
        {
            self.threads.remove_process(process).map_err(|_| ())?;
            return Err(());
        }
        if let Ok(initial) = self.threads.prepare_initial(process, resources) {
            Ok(initial)
        } else {
            self.stop(process)?;
            self.threads.remove_process(process).map_err(|_| ())?;
            Err(())
        }
    }

    pub(crate) fn stop(&mut self, process: ProcessId) -> Result<(), ()> {
        self.sync
            .stop_process(&mut self.threads, process)
            .map_err(|_| ())
    }

    /// Call only after native root, pending calls, IPC and ordinary frames retire.
    pub(crate) fn remove_reclaimed(&mut self, process: ProcessId) -> Result<(), ()> {
        self.stop(process)?;
        let mut ids = [None; troe_machine::IPC_APPLICATION_THREAD_PAIRS];
        for (slot, snapshot) in ids.iter_mut().zip(self.threads.snapshots(process)) {
            *slot = Some(snapshot);
        }
        for snapshot in ids.into_iter().flatten() {
            if !snapshot.resources_released {
                self.threads
                    .release_resources(process, snapshot.id)
                    .map_err(|_| ())?;
            }
            self.threads.reap(process, snapshot.id).map_err(|_| ())?;
        }
        self.threads.remove_process(process).map_err(|_| ())
    }
}

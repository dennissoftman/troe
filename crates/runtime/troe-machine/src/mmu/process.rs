//! One native root with bounded, process-owned register continuations.
//!
//! This mechanism does not admit threaded packages, allocate user frames, or
//! schedule process shares. Composition authenticates lifecycle tokens, owns
//! guarded frame reservations and supplies the process's remaining timeslice.

use super::{
    ApplicationCall, ApplicationHeapGrowth, ApplicationPending, ApplicationResume,
    ArchitectureApplicationContext, IsolatedFault, MmuError, MmuStats,
    OUTCOME_APPLICATION_HANDLE_CALL, OUTCOME_APPLICATION_HEAP_GROW, OUTCOME_APPLICATION_PREEMPTED,
    OUTCOME_APPLICATION_YIELD, OUTCOME_FAULT_BIT, UserAddressSpace, apply_application_resume,
    decode_fault, run_saved_application, user_range_contains,
};
use alloc::vec::Vec;
use troe_memory::VirtualRange;
use troe_task::{ProcessId, thread::ThreadId};

/// Trusted initial register and mapping geometry for an already owned thread.
#[derive(Clone, Copy, Debug)]
pub struct NativeThreadStart {
    /// Entry instruction in an executable user mapping.
    pub entry: u64,
    /// Complete writable/NX stack payload with an unmapped page at each end.
    pub stack: VirtualRange,
    /// Complete writable/NX TLS mapping; composition initializes its compiler layout.
    pub tls: VirtualRange,
    /// Aligned architecture thread pointer inside `tls`.
    pub thread_pointer: u64,
    /// Readable startup record passed as the first argument.
    pub startup: u64,
    /// Nonzero startup record length passed as the second argument.
    pub startup_bytes: usize,
}

/// Copied stop information; no root or runnable context escapes its process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeThreadStop {
    /// The selected thread yielded; its continuation remains owned.
    Yielded,
    /// The selected thread used the caller-supplied remaining timeslice.
    Preempted,
    /// One validated copied-message call awaits a kernel completion.
    HandleCall(ApplicationCall),
    /// One heap request awaits a kernel completion.
    HeapGrow(ApplicationHeapGrowth),
    /// ABI call 0 exits the whole process and revokes every continuation.
    ProcessExited(u32),
    /// A native fault revokes every continuation in this process.
    ProcessFaulted(IsolatedFault),
}

#[derive(Clone, Copy)]
struct ThreadIpc {
    index: usize,
    tx: u64,
}

/// Root and IPC owners whose declaration order enforces root-before-pair drop.
///
/// Construct only after all mappings are prepared while the pairs are retained.
/// Moving this bundle into native admission also keeps rejected preparation from
/// dropping an IPC pair before the root which maps it.
pub struct NativeProcessBacking {
    address_space: UserAddressSpace,
    pairs: Vec<crate::IpcPagePair>,
}
impl NativeProcessBacking {
    /// Transfer the unique root and every retained task IPC pair together.
    #[must_use]
    pub const fn new(address_space: UserAddressSpace, pairs: Vec<crate::IpcPagePair>) -> Self {
        Self {
            address_space,
            pairs,
        }
    }
}

struct ThreadContext {
    id: ThreadId,
    start: NativeThreadStart,
    registers: ArchitectureApplicationContext,
    pending: ApplicationPending,
    started: bool,
    ipc: Option<ThreadIpc>,
}

impl Drop for ThreadContext {
    fn drop(&mut self) {
        // SAFETY: Exclusive final access to a live integer/byte-only register
        // record. Volatile erasure prevents retained user registers from being
        // optimized away when the metadata allocation is released.
        let bytes = core::ptr::from_mut(&mut self.registers).cast::<u8>();
        for offset in 0..core::mem::size_of::<ArchitectureApplicationContext>() {
            unsafe { core::ptr::write_volatile(bytes.add(offset), 0) };
        }
    }
}

/// Exclusive native address-space owner with preallocated thread records.
///
/// Records never expose their registers or root. Execution requires unique
/// access, and a native run returns to the kernel before another record can run
/// or mappings can be reclaimed. This retains its IPC page pairs, but composition
/// must drop this owner before zeroing and releasing ordinary user/table frames.
/// The current mechanism rejects roots bound to the single-thread IPC profile.
/// Owned per-thread IPC buffers do not enable threaded package admission or
/// the scheduler-call dispatcher.
pub struct NativeProcessContext {
    // Contexts precede the root so dropping the owner retires them first.
    contexts: Vec<ThreadContext>,
    backing: NativeProcessBacking,
    process: ProcessId,
    capacity: usize,
    metadata_bytes: usize,
    stopped: bool,
}

impl NativeProcessContext {
    /// Reserve bounded native metadata before publishing any thread.
    ///
    /// # Errors
    /// Rejects zero/excess capacity, an IPC-bound root, allocation failure, or
    /// requested/actual retained metadata beyond the supplied byte allowance.
    pub fn new(
        process: ProcessId,
        address_space: UserAddressSpace,
        capacity: usize,
        metadata_limit: usize,
    ) -> Result<Self, MmuError> {
        Self::with_backing(
            process,
            NativeProcessBacking::new(address_space, Vec::new()),
            capacity,
            metadata_limit,
        )
    }

    /// Admit an owned root/IPC bundle with bounded native metadata.
    ///
    /// # Errors
    /// Rejects a legacy IPC-bound root, non-task/stale pairs, excess capacity,
    /// or requested/actual metadata over budget. The bundle retires its root
    /// before releasing any pair on every rejected path.
    pub fn with_backing(
        process: ProcessId,
        backing: NativeProcessBacking,
        capacity: usize,
        metadata_limit: usize,
    ) -> Result<Self, MmuError> {
        if capacity == 0
            || capacity > crate::IPC_TASK_PAIRS
            || backing.address_space.ipc.is_some()
            || backing.pairs.len() > capacity
            || backing
                .pairs
                .iter()
                .any(|pair| pair.slot() >= crate::IPC_TASK_PAIRS || !pair.is_live())
        {
            return Err(MmuError::InvalidUserContext);
        }
        let pair_bytes = backing
            .pairs
            .capacity()
            .checked_mul(core::mem::size_of::<crate::IpcPagePair>())
            .ok_or(MmuError::InvalidUserContext)?;
        let retained_root = backing
            .address_space
            .regions
            .capacity()
            .checked_mul(core::mem::size_of::<super::UserRegion>())
            .and_then(|bytes| bytes.checked_add(core::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(pair_bytes))
            .ok_or(MmuError::InvalidUserContext)?;
        let charge = |slots: usize| {
            slots
                .checked_mul(core::mem::size_of::<ThreadContext>())
                .and_then(|bytes| bytes.checked_add(retained_root))
                .filter(|bytes| *bytes <= metadata_limit)
                .ok_or(MmuError::InvalidUserContext)
        };
        charge(capacity)?;
        let mut contexts = Vec::new();
        contexts
            .try_reserve_exact(capacity)
            .map_err(|_| MmuError::InvalidUserContext)?;
        let metadata_bytes = charge(contexts.capacity())?;
        Ok(Self {
            contexts,
            backing,
            process,
            capacity,
            metadata_bytes,
            stopped: false,
        })
    }

    /// Actual context/mapping/IPC-owner capacities plus the compiled inline owner.
    #[must_use]
    pub const fn metadata_bytes(&self) -> usize {
        self.metadata_bytes
    }

    /// Shared mapped-page and root-table charges, counted once for the process.
    #[must_use]
    pub const fn stats(&self) -> MmuStats {
        self.backing.address_space.stats
    }

    /// Whether native process exit, fault or explicit stop forbids execution.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Read an acceptance word through the retained, inactive user root.
    ///
    /// # Errors
    /// Rejects an unmapped or unreadable word before exposing any bytes.
    #[cfg(feature = "acceptance-probes")]
    pub fn probe_word(&self, address: u64) -> Result<u64, MmuError> {
        let mut bytes = [0; 8];
        super::copy_user_from_physical(
            self.backing.address_space.root,
            &self.backing.address_space.regions,
            address,
            &mut bytes,
        )?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Copy one suspended thread's validated request into kernel-owned storage.
    ///
    /// # Errors
    /// Rejects a stopped process, foreign/stale token, non-call continuation,
    /// wrong destination length or invalid retained mapping.
    pub fn copy_request(&self, id: ThreadId, destination: &mut [u8]) -> Result<(), MmuError> {
        if self.stopped || id.process() != self.process {
            return Err(MmuError::InvalidUserContext);
        }
        let context = self
            .contexts
            .iter()
            .find(|context| context.id == id)
            .ok_or(MmuError::InvalidUserContext)?;
        let ApplicationPending::HandleCall(call) = context.pending else {
            return Err(MmuError::InvalidUserContext);
        };
        if destination.len() != call.request_bytes {
            return Err(MmuError::InvalidUserContext);
        }
        super::copy_user_from_physical(
            self.backing.address_space.root,
            &self.backing.address_space.regions,
            call.request_address,
            destination,
        )
    }

    /// Install one fresh context after composition reserves its guarded memory.
    ///
    /// The lifecycle table must authenticate and retain this token until stop.
    /// Duplicate tokens and overlapping stack/TLS payloads are rejected. No
    /// allocation occurs and a rejected configuration publishes no record.
    ///
    /// # Errors
    /// Rejects stopped/wrong-owner/duplicate/exhausted admission, missing stack
    /// guards, aliasing private ranges, or invalid initial register geometry.
    pub fn prepare(&mut self, id: ThreadId, start: NativeThreadStart) -> Result<(), MmuError> {
        if self.stopped
            || id.process() != self.process
            || self.contexts.len() == self.capacity
            || self.contexts.iter().any(|context| context.id == id)
            || !valid_start(&self.backing.address_space, start)
            || self.contexts.iter().any(|context| {
                [context.start.stack, context.start.tls].iter().any(|old| {
                    [start.stack, start.tls]
                        .iter()
                        .any(|new| overlaps(*old, *new))
                }) || context.ipc.is_some_and(|ipc| {
                    [start.stack, start.tls]
                        .iter()
                        .any(|new| ipc.tx < new.end() && new.start() < ipc.tx + 8192)
                })
            })
        {
            return Err(MmuError::InvalidUserContext);
        }
        self.contexts.push(ThreadContext {
            id,
            start,
            registers: initial_registers(start),
            pending: ApplicationPending::Timeslice,
            started: false,
            ipc: None,
        });
        Ok(())
    }

    /// Bind one retained pair to a never-started thread after mapping validation.
    ///
    /// The pair remains owned until the complete root is retired, including
    /// after `stop`. This method does not allocate, map pages or publish entry 6.
    ///
    /// # Errors
    /// Rejects foreign/stale threads, duplicate/rebound pairs, started contexts,
    /// overlaps, non-page-aligned TX, or physical/permission mismatches.
    pub fn bind_thread_ipc(
        &mut self,
        id: ThreadId,
        pair_index: usize,
        tx: u64,
    ) -> Result<(), MmuError> {
        if self.stopped || id.process() != self.process || !tx.is_multiple_of(4096) {
            return Err(MmuError::InvalidUserContext);
        }
        let range = VirtualRange::from_pages(tx, 2).map_err(|_| MmuError::InvalidUserContext)?;
        let pair = self
            .backing
            .pairs
            .get(pair_index)
            .ok_or(MmuError::InvalidUserContext)?;
        if !pair.is_live()
            || !writable_nx(&self.backing.address_space, range)
            || super::architecture_translate_page(self.backing.address_space.root, tx)?
                != pair.range().start()
            || super::architecture_translate_page(self.backing.address_space.root, tx + 4096)?
                != pair.range().start() + 4096
            || self.contexts.iter().any(|context| {
                overlaps(range, context.start.stack)
                    || overlaps(range, context.start.tls)
                    || context.ipc.is_some_and(|ipc| {
                        ipc.index == pair_index
                            || (ipc.tx < range.end() && range.start() < ipc.tx + 8192)
                    })
            })
        {
            return Err(MmuError::InvalidUserContext);
        }
        let context = self
            .contexts
            .iter_mut()
            .find(|context| context.id == id)
            .ok_or(MmuError::InvalidUserContext)?;
        if context.started || context.ipc.is_some() {
            return Err(MmuError::InvalidUserContext);
        }
        context.ipc = Some(ThreadIpc {
            index: pair_index,
            tx,
        });
        Ok(())
    }

    /// Retained virtual TX/RX addresses for a live thread's immutable binding.
    ///
    /// # Errors
    /// Rejects stopped, foreign, stale or unbound threads/pairs.
    pub fn ipc_addresses(&self, id: ThreadId) -> Result<(u64, u64), MmuError> {
        let (ipc, _) = self.bound_ipc(id)?;
        Ok((ipc.tx, ipc.tx + 4096))
    }

    /// Copy a bounded TX prefix from the caller's retained pair into kernel storage.
    ///
    /// # Errors
    /// Rejects invalid bindings and prefixes larger than one page before copying.
    pub fn copy_thread_tx(&self, id: ThreadId, destination: &mut [u8]) -> Result<(), MmuError> {
        if destination.len() > 4096 {
            return Err(MmuError::InvalidUserContext);
        }
        let (ipc, _) = self.bound_ipc(id)?;
        super::copy_user_from_physical(
            self.backing.address_space.root,
            &self.backing.address_space.regions,
            ipc.tx,
            destination,
        )
    }

    /// Clear the whole caller RX page, then publish one bounded kernel-owned prefix.
    ///
    /// This is a storage primitive; scheduler capability, operation identity and
    /// response validation are composition obligations before calling it.
    ///
    /// # Errors
    /// Rejects invalid bindings/oversized prefixes before writing. Native storage
    /// failure stops the complete process rather than permitting further execution.
    pub fn publish_thread_rx(&mut self, id: ThreadId, bytes: &[u8]) -> Result<(), MmuError> {
        if bytes.len() > 4096 {
            return Err(MmuError::InvalidUserContext);
        }
        let (_, pair) = self.bound_ipc(id)?;
        let rx = troe_memory::PhysicalRange::from_pages(pair.range().start() + 4096, 1)
            .map_err(|_| MmuError::InvalidUserContext)?;
        let result = crate::zero_physical_range(rx)
            .and_then(|()| crate::copy_to_physical(rx, 0, bytes))
            .map_err(|_| MmuError::InvalidUserContext);
        if result.is_err() {
            self.stop();
        }
        result
    }

    fn bound_ipc(&self, id: ThreadId) -> Result<(ThreadIpc, &crate::IpcPagePair), MmuError> {
        if self.stopped || id.process() != self.process {
            return Err(MmuError::InvalidUserContext);
        }
        let ipc = self
            .contexts
            .iter()
            .find(|context| context.id == id)
            .and_then(|context| context.ipc)
            .ok_or(MmuError::InvalidUserContext)?;
        let pair = self
            .backing
            .pairs
            .get(ipc.index)
            .filter(|pair| pair.is_live())
            .ok_or(MmuError::InvalidUserContext)?;
        Ok((ipc, pair))
    }

    /// Run one authenticated thread within the caller's remaining process slice.
    ///
    /// The caller must debit process time across yields and sibling switches;
    /// this low-level bound is not a new entitlement. No callback into process
    /// ownership occurs while the trap owns the moved mapping summary.
    ///
    /// # Errors
    /// Rejects stale/wrong-owner tokens, zero or over-50-ms slices and mismatched
    /// completions. Completion or native mechanism failure for an accepted token
    /// stops all sibling execution. Foreign tokens and invalid slice bounds do
    /// not mutate the owner.
    pub fn resume(
        &mut self,
        id: ThreadId,
        completion: ApplicationResume<'_>,
        remaining_milliseconds: u32,
    ) -> Result<NativeThreadStop, MmuError> {
        if self.stopped
            || id.process() != self.process
            || !(1..=50).contains(&remaining_milliseconds)
        {
            return Err(MmuError::InvalidUserContext);
        }
        let index = self
            .contexts
            .iter()
            .position(|context| context.id == id)
            .ok_or(MmuError::InvalidUserContext)?;
        let context = &mut self.contexts[index];
        if let Err(error) = apply_application_resume(
            &self.backing.address_space,
            &mut context.registers,
            context.pending,
            completion,
        ) {
            self.stop();
            return Err(error);
        }
        context.started = true;
        let result = run_saved_application(
            &mut self.backing.address_space,
            &context.registers,
            remaining_milliseconds,
        );
        let result = result.and_then(|(raw, mut state)| {
            if raw & OUTCOME_FAULT_BIT != 0 {
                return Ok(NativeThreadStop::ProcessFaulted(decode_fault(raw)?));
            }
            if state.application_context.is_some() != state.pending_application.is_some() {
                return Err(MmuError::InvalidUserContext);
            }
            if let (Some(registers), Some(pending)) = (
                state.application_context.take(),
                state.pending_application.take(),
            ) {
                let stop = match (raw, pending) {
                    (OUTCOME_APPLICATION_YIELD, ApplicationPending::Yield) => {
                        NativeThreadStop::Yielded
                    }
                    (OUTCOME_APPLICATION_PREEMPTED, ApplicationPending::Timeslice) => {
                        NativeThreadStop::Preempted
                    }
                    (OUTCOME_APPLICATION_HANDLE_CALL, ApplicationPending::HandleCall(call)) => {
                        NativeThreadStop::HandleCall(call)
                    }
                    (OUTCOME_APPLICATION_HEAP_GROW, ApplicationPending::HeapGrow(request)) => {
                        NativeThreadStop::HeapGrow(request)
                    }
                    _ => return Err(MmuError::InvalidUserContext),
                };
                context.registers = registers;
                context.pending = pending;
                Ok(stop)
            } else {
                Ok(NativeThreadStop::ProcessExited(
                    u32::try_from(raw).map_err(|_| MmuError::InvalidUserContext)?,
                ))
            }
        });
        if matches!(
            result,
            Err(_) | Ok(NativeThreadStop::ProcessExited(_) | NativeThreadStop::ProcessFaulted(_))
        ) {
            self.stop();
        }
        result
    }

    /// Revoke every continuation synchronously, without running user cleanup.
    /// Unique access proves no native gate from this owner is still running.
    /// IPC pairs remain owned until the root is retired when this owner drops.
    pub fn stop(&mut self) {
        self.stopped = true;
        self.contexts.clear();
    }
}

fn overlaps(a: VirtualRange, b: VirtualRange) -> bool {
    a.start() < b.end() && b.start() < a.end()
}
fn writable_nx(space: &UserAddressSpace, range: VirtualRange) -> bool {
    let Ok(bytes) = usize::try_from(range.byte_count()) else {
        return false;
    };
    user_range_contains(&space.regions, range.start(), bytes, true, false)
        && !space
            .regions
            .iter()
            .any(|region| region.permissions.execute && overlaps(region.range, range))
}
fn valid_start(space: &UserAddressSpace, start: NativeThreadStart) -> bool {
    let Some(lower) = start.stack.start().checked_sub(4096) else {
        return false;
    };
    let Some(upper) = start.stack.end().checked_add(4096) else {
        return false;
    };
    let Some(tp_end) = start.thread_pointer.checked_add(8) else {
        return false;
    };
    !overlaps(start.stack, start.tls)
        && writable_nx(space, start.stack)
        && writable_nx(space, start.tls)
        && start
            .thread_pointer
            .is_multiple_of(if cfg!(target_arch = "aarch64") { 16 } else { 8 })
        && start.tls.start() <= start.thread_pointer
        && tp_end <= start.tls.end()
        && start.startup_bytes != 0
        && user_range_contains(
            &space.regions,
            start.startup,
            start.startup_bytes,
            false,
            false,
        )
        && user_range_contains(&space.regions, start.entry, 1, false, true)
        && !space.regions.iter().any(|region| {
            (region.range.start() < start.stack.start() && lower < region.range.end())
                || (region.range.start() < upper && start.stack.end() < region.range.end())
        })
}

#[cfg(target_arch = "x86_64")]
fn initial_registers(start: NativeThreadStart) -> ArchitectureApplicationContext {
    let mut floating_point = [0; 512];
    floating_point[..2].copy_from_slice(&0x037f_u16.to_le_bytes());
    floating_point[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
    ArchitectureApplicationContext {
        floating_point,
        thread_pointer: start.thread_pointer,
        segment_selectors: [0; 4],
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rbp: 0,
        rsi: start.startup_bytes as u64,
        rdi: start.startup,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        instruction: start.entry,
        code_selector: u64::from(super::X86_USER_CODE_SELECTOR),
        flags: 0x202,
        stack: start.stack.end() - 8,
        stack_selector: u64::from(super::X86_USER_DATA_SELECTOR),
    }
}
#[cfg(target_arch = "aarch64")]
fn initial_registers(start: NativeThreadStart) -> ArchitectureApplicationContext {
    let mut general = [0; 31];
    general[0] = start.startup;
    general[1] = start.startup_bytes as u64;
    ArchitectureApplicationContext {
        general,
        general_padding: 0,
        floating_point: [[0; 16]; 32],
        fpcr: 0,
        fpsr: 0,
        instruction: start.entry,
        status: 0,
        stack: start.stack.end(),
        thread_pointer: start.thread_pointer,
    }
}

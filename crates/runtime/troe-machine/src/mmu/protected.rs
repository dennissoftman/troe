//! Multiple owned contexts sharing the Phase B masked, tagged-root gate.

use super::{
    ApplicationPending, ApplicationSession, ArchitectureApplicationContext, ISOLATED_ACTIVE,
    ISOLATED_RUN, IsolatedFault, IsolatedRunState, MmuError, OUTCOME_APPLICATION_YIELD,
    OUTCOME_FAULT_BIT, RunKind, application_context_set_results, architecture_resume_application,
    decode_fault, encoded_fault, ipc,
};
use alloc::vec::Vec;
use core::{cell::UnsafeCell, ptr, sync::atomic::Ordering};
use troe_service::ipc::{Actor, Buffer, KERNEL_CLIENTS, Resume, Runtime, TASKS, Transition};

struct RuntimeCell(UnsafeCell<Option<ProtectedRuntime>>);
// SAFETY: The sole masked trap accesses this cell only during ISOLATED_ACTIVE.
unsafe impl Sync for RuntimeCell {}
static ACTIVE: RuntimeCell = RuntimeCell(UnsafeCell::new(None));

/// Owned native contexts and copied queue storage for persistent services.
#[derive(Debug)]
pub struct ProtectedRuntime {
    model: Runtime,
    peers: Vec<Option<(Actor, ApplicationSession)>>,
    kernel: [Option<(Actor, crate::IpcPagePair)>; KERNEL_CLIENTS],
    queues: Vec<[u8; 4096]>,
    active: Option<Actor>,
    roots_validated: bool,
    stop: Option<ProtectedStop>,
    stats: ipc::IpcStats,
    #[cfg(feature = "acceptance-probes")]
    fault: Option<(Actor, FaultPoint)>,
    #[cfg(feature = "acceptance-probes")]
    probe: Option<Actor>,
    #[cfg(feature = "acceptance-probes")]
    samples: [u64; 256],
    #[cfg(feature = "acceptance-probes")]
    sample_count: usize,
    #[cfg(feature = "acceptance-probes")]
    started: (u64, u64),
}

/// Deliberate acceptance-only faults at ownership transition boundaries.
#[cfg(feature = "acceptance-probes")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    /// Selected request has not yet resumed its receive instruction.
    BeforeReceive,
    /// Server has observed RX and reaches its first explicit yield.
    AfterReceive,
    /// Fault the currently executing nested server at its next ABI boundary.
    NestedCall,
    /// Server has prepared TX but no reply validation has run.
    BeforeReply,
    /// Validated reply has not consumed its token or copied into client RX.
    AfterReplyValidation,
}

/// Return to the kernel root and its explicit continuation pump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedStop {
    /// The task published a wait or queued its call.
    Blocked(Actor),
    /// A user voluntarily ended its execution segment.
    Yielded(Actor),
    /// A kernel continuation has a scalar result and valid RX prefix.
    Kernel(Actor),
    /// A user exited; transport ownership has already been revoked.
    Exited {
        /// Exact terminal incarnation.
        actor: Actor,
        /// User exit status.
        status: u32,
    },
    /// A user faulted; no service request is replayed.
    Faulted {
        /// Exact terminal incarnation.
        actor: Actor,
        /// Architectural containment reason.
        fault: IsolatedFault,
    },
}
impl ProtectedRuntime {
    /// Allocate all metadata and queue bytes before any endpoint is ready.
    ///
    /// # Errors
    /// Rejects allocation or portable table construction failure.
    pub fn new() -> Result<Self, MmuError> {
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(TASKS)
            .map_err(|_| MmuError::InvalidUserContext)?;
        peers.resize_with(TASKS, || None);
        let mut queues = Vec::new();
        queues
            .try_reserve_exact(32)
            .map_err(|_| MmuError::InvalidUserContext)?;
        queues.resize(32, [0; 4096]);
        Ok(Self {
            model: Runtime::new().map_err(|_| MmuError::InvalidUserContext)?,
            peers,
            kernel: core::array::from_fn(|_| None),
            queues,
            active: None,
            roots_validated: false,
            stop: None,
            stats: ipc::IpcStats::default(),
            #[cfg(feature = "acceptance-probes")]
            fault: None,
            #[cfg(feature = "acceptance-probes")]
            probe: None,
            #[cfg(feature = "acceptance-probes")]
            samples: [0; 256],
            #[cfg(feature = "acceptance-probes")]
            sample_count: 0,
            #[cfg(feature = "acceptance-probes")]
            started: (0, 0),
        })
    }

    /// Begin a measured batch after the client's warmup yield.
    #[cfg(feature = "acceptance-probes")]
    pub fn measure(&mut self, actor: Actor) {
        self.probe = Some(actor);
        self.sample_count = 0;
        self.samples.fill(0);
    }

    /// Measured native round trips, in admission order.
    #[cfg(feature = "acceptance-probes")]
    #[must_use]
    pub fn samples(&self) -> &[u64] {
        &self.samples[..self.sample_count]
    }

    /// Arm one exact-incarnation fault; replacement actors never inherit it.
    ///
    /// # Errors
    /// Rejects stale actors or overlapping injections.
    #[cfg(feature = "acceptance-probes")]
    pub fn inject(&mut self, actor: Actor, point: FaultPoint) -> Result<(), MmuError> {
        if self.fault.is_some() || !self.model.is_live(actor) {
            return Err(MmuError::InvalidUserContext);
        }
        self.fault = Some((actor, point));
        Ok(())
    }

    #[cfg(feature = "acceptance-probes")]
    fn injected(&mut self, actor: Actor, point: FaultPoint) -> bool {
        if self.fault == Some((actor, point)) {
            self.fault = None;
            true
        } else {
            false
        }
    }

    /// Poison a stopped kernel client's RX before an ownership-fault probe.
    ///
    /// # Errors
    /// Rejects user or foreign actors.
    #[cfg(feature = "acceptance-probes")]
    pub fn poison_kernel_rx(&mut self, actor: Actor) -> Result<(), MmuError> {
        if actor.slot() < TASKS {
            return Err(MmuError::InvalidUserContext);
        }
        let alias = self.alias(actor)? + 4096;
        // SAFETY: Exclusive stopped kernel IPC pair; never mapped to a user.
        unsafe {
            ptr::write_bytes(alias as *mut u8, 0xa5, 4096);
        }
        Ok(())
    }

    /// Prove a terminal reply wrote no bytes into a poisoned client RX page.
    ///
    /// # Errors
    /// Rejects user or foreign actors.
    #[cfg(feature = "acceptance-probes")]
    pub fn kernel_rx_unchanged(&self, actor: Actor) -> Result<bool, MmuError> {
        if actor.slot() < TASKS {
            return Err(MmuError::InvalidUserContext);
        }
        let alias = self.alias(actor)? + 4096;
        // SAFETY: Exact live private kernel pair, read only while users stop.
        Ok(
            unsafe { core::slice::from_raw_parts(alias as *const u8, 4096) }
                .iter()
                .all(|byte| *byte == 0xa5),
        )
    }

    /// Snapshot the retained tag identity for teardown and reuse assertions.
    ///
    /// # Errors
    /// Rejects stale contexts or absent tags.
    #[cfg(feature = "acceptance-probes")]
    pub fn tag_identity(&self, actor: Actor) -> Result<super::tags::TagIdentity, MmuError> {
        self.peer(actor)?
            .tag_identity()
            .ok_or(MmuError::InvalidUserContext)
    }

    /// Exact native payload/transition counters.
    #[must_use]
    pub fn stats(&self) -> ipc::IpcStats {
        let mut stats = self.stats;
        let policy = self.model.stats();
        stats.direct = policy.direct_admissions;
        stats.queued = policy.queued_admissions;
        stats.completed = policy.replied;
        stats.peer_deaths = policy.peer_died;
        stats.timeouts = policy.timed_out;
        stats
    }

    /// Transport configuration, accessed only while all users are stopped.
    pub fn model(&mut self) -> &mut Runtime {
        &mut self.model
    }

    /// Install the complete already-suspended context in its exact owned slot.
    ///
    /// # Errors
    /// Rejects duplicate slots, absent IPC pages or noncanonical initial waits.
    pub fn install(
        &mut self,
        actor: Actor,
        mut session: ApplicationSession,
    ) -> Result<(), MmuError> {
        if actor.slot() >= TASKS
            || self.peers[actor.slot()].is_some()
            || session.address_space.ipc.is_none()
        {
            return Err(MmuError::InvalidUserContext);
        }
        let ipc = session
            .address_space
            .ipc
            .ok_or(MmuError::InvalidUserContext)?;
        let (grant, task) = super::ipc::authority(
            &session.address_space,
            ipc.tx
                .checked_sub(4096)
                .ok_or(MmuError::InvalidUserContext)?,
            if matches!(session.pending, ApplicationPending::Yield) {
                troe_abi::interface::DIAGNOSTICS
            } else {
                troe_abi::interface::WAIT_SET
            },
            1,
            if matches!(session.pending, ApplicationPending::Yield) {
                1
            } else {
                8
            },
        )?;
        if self
            .model
            .task(actor)
            .map_err(|_| MmuError::InvalidUserContext)?
            .map(|id| u64::from(id.get()))
            != Some(task)
        {
            return Err(MmuError::InvalidUserContext);
        }
        if matches!(session.pending, ApplicationPending::Yield) {
            self.model
                .validate_client_startup(actor, grant, troe_abi::interface::DIAGNOSTICS, 1, 0)
                .map_err(|_| MmuError::InvalidUserContext)?;
        } else {
            let (receive, _) = super::ipc::authority(
                &session.address_space,
                ipc.tx
                    .checked_sub(4096)
                    .ok_or(MmuError::InvalidUserContext)?,
                troe_abi::interface::SERVER_ENDPOINT,
                2,
                6,
            )?;
            self.model
                .validate_server_startup(actor, receive, grant)
                .map_err(|_| MmuError::InvalidUserContext)?;
        }
        let wait = match session.pending {
            ApplicationPending::IpcWait(wait) => Some(wait),
            ApplicationPending::Yield => {
                application_context_set_results(&mut session.context, 0, 0);
                None
            }
            _ => return Err(MmuError::InvalidUserContext),
        };
        self.peers[actor.slot()] = Some((actor, session));
        if let Some(wait) = wait {
            let transition = self
                .model
                .reply_wait(actor, wait, now()?)
                .map_err(|_| MmuError::InvalidUserContext)?;
            self.commit(transition)?;
        }
        Ok(())
    }

    /// Install one of the four separately reserved kernel IPC pairs.
    ///
    /// # Errors
    /// Rejects a user pair, foreign actor or occupied kernel slot.
    pub fn install_kernel(
        &mut self,
        actor: Actor,
        pair: crate::IpcPagePair,
    ) -> Result<(), MmuError> {
        let index = actor
            .slot()
            .checked_sub(TASKS)
            .ok_or(MmuError::InvalidUserContext)?;
        let slot = self
            .kernel
            .get_mut(index)
            .ok_or(MmuError::InvalidUserContext)?;
        if slot.is_some() || pair.slot() < crate::IPC_TASK_PAIRS || !pair.is_live() {
            return Err(MmuError::InvalidUserContext);
        }
        *slot = Some((actor, pair));
        Ok(())
    }

    /// Copy a kernel client's request before publishing its scalar continuation.
    ///
    /// # Errors
    /// Rejects a foreign client or oversized request.
    pub fn kernel_request(&mut self, actor: Actor, bytes: &[u8]) -> Result<(), MmuError> {
        if actor.slot() < TASKS || bytes.len() > 4096 {
            return Err(MmuError::InvalidUserContext);
        }
        let destination = self.alias(actor)?;
        // SAFETY: Exclusive stopped kernel pair; exact bounded TX prefix.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), destination as *mut u8, bytes.len());
        }
        Ok(())
    }

    /// Admit a kernel call without running the server inside a client frame.
    ///
    /// # Errors
    /// Rejects invalid authority or copy accounting.
    pub fn kernel_call(
        &mut self,
        actor: Actor,
        call: troe_abi::ipc::Call,
    ) -> Result<Option<Actor>, MmuError> {
        if actor.slot() < TASKS {
            return Err(MmuError::InvalidUserContext);
        }
        let transition = self
            .model
            .call(actor, call, now()?)
            .map_err(|_| MmuError::InvalidUserContext)?;
        self.commit(transition)?;
        Ok(transition.handoff)
    }

    /// Consume a kernel result in a later continuation step.
    ///
    /// # Errors
    /// Rejects foreign actors, non-client events or insufficient destination.
    pub fn kernel_reply(
        &mut self,
        actor: Actor,
        destination: &mut [u8],
    ) -> Result<Option<(u32, usize)>, MmuError> {
        if actor.slot() < TASKS {
            return Err(MmuError::InvalidUserContext);
        }
        let Some(Resume::Reply { status, bytes }) = self
            .model
            .peek_resume(actor)
            .map_err(|_| MmuError::InvalidUserContext)?
        else {
            return Ok(None);
        };
        let length = usize::from(bytes);
        if length > destination.len() {
            return Err(MmuError::InvalidUserContext);
        }
        self.model
            .take_resume(actor)
            .map_err(|_| MmuError::InvalidUserContext)?;
        let source = self.alias(actor)? + 4096;
        // SAFETY: The completed kernel client is stopped and the result length
        // was validated before its server's TX prefix was copied here.
        unsafe {
            ptr::copy_nonoverlapping(source as *const u8, destination.as_mut_ptr(), length);
        }
        Ok(Some((status, length)))
    }

    /// Observe deadlines and source readiness under the kernel root.
    ///
    /// # Errors
    /// Rejects inconsistent wait or zeroization accounting.
    pub fn poll(&mut self) -> Result<Option<Actor>, MmuError> {
        let transition = self
            .model
            .poll_waits(now()?)
            .map_err(|_| MmuError::InvalidUserContext)?;
        self.commit(transition)?;
        Ok(transition.handoff.or_else(|| self.model.select()))
    }

    /// Cancel one client and zero each detached copied queue before returning.
    ///
    /// # Errors
    /// Rejects stale callers or inconsistent queue accounting.
    pub fn cancel(&mut self, actor: Actor) -> Result<(), MmuError> {
        self.model
            .cancel(actor)
            .map_err(|_| MmuError::InvalidUserContext)?;
        self.zero_queues()
    }

    /// Terminate before removing tags or returning ordinary frames.
    ///
    /// # Errors
    /// Rejects stale actors or inconsistent teardown accounting.
    pub fn terminate(&mut self, actor: Actor, clean: bool) -> Result<(), MmuError> {
        self.model
            .expire(now()?)
            .map_err(|_| MmuError::InvalidUserContext)?;
        self.model
            .terminate(actor, clean)
            .map_err(|_| MmuError::InvalidUserContext)?;
        self.zero_queues()?;
        let alias = self.alias(actor)?;
        // SAFETY: Revocation completed and no user context can run concurrently.
        unsafe {
            ptr::write_bytes(alias as *mut u8, 0, 8192);
        }
        Ok(())
    }

    /// Release an already terminal native context after transport revocation.
    ///
    /// # Errors
    /// Rejects a foreign context. Composition retains its frame allocation
    /// until the returned address-space owner has been dropped.
    pub fn remove(&mut self, actor: Actor) -> Result<ApplicationSession, MmuError> {
        if self.model.is_live(actor) {
            return Err(MmuError::InvalidUserContext);
        }
        let slot = self
            .peers
            .get_mut(actor.slot())
            .ok_or(MmuError::InvalidUserContext)?;
        if slot.as_ref().is_none_or(|(owner, _)| *owner != actor) {
            return Err(MmuError::InvalidUserContext);
        }
        slot.take()
            .map(|(_, session)| session)
            .ok_or(MmuError::InvalidUserContext)
    }

    /// Resume one execution segment with a single absolute 50 ms lease.
    /// Every direct handoff reuses that programmed deadline unchanged.
    ///
    /// # Errors
    /// Rejects concurrent execution, stale roots or an unavailable timer.
    pub fn run(mut self, actor: Actor) -> Result<(Self, ProtectedStop), MmuError> {
        #[cfg(feature = "acceptance-probes")]
        if self.injected(actor, FaultPoint::BeforeReceive) {
            self.terminate(actor, false)?;
            return Ok((
                self,
                ProtectedStop::Faulted {
                    actor,
                    fault: IsolatedFault::InvalidCall,
                },
            ));
        }
        // All peers remain owned and immovable throughout the sole masked
        // run. No syscall path removes a session, IPC pair or tag lease.
        // Validate their generations once before any user can execute; every
        // destination activation still validates its retained tag separately.
        for (owner, _) in self.peers.iter().flatten() {
            self.alias(*owner)?;
        }
        for (owner, _) in self.kernel.iter().flatten() {
            self.alias(*owner)?;
        }
        self.roots_validated = true;
        self.model
            .expire(now()?)
            .map_err(|_| MmuError::InvalidUserContext)?;
        self.zero_queues()?;
        self.apply_resume(actor)?;
        let peer = self.peer(actor)?;
        let root = peer.address_space.root;
        let context = peer.context.clone();
        if ISOLATED_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(MmuError::IsolationBusy);
        }
        self.active = Some(actor);
        self.stop = None;
        // SAFETY: Sole run ownership is acquired before publishing the complete
        // owned runtime. No callback or borrowed service object enters this cell.
        unsafe {
            *ACTIVE.0.get() = Some(self);
            *ISOLATED_RUN.0.get() = Some(IsolatedRunState {
                kind: RunKind::Protected,
                regions: Vec::new(),
                destination: ptr::null_mut(),
                destination_len: 0,
                application_context: None,
                pending_application: None,
                scheduler_tx: None,
                scheduler_request: None,
                ipc: None,
            });
        }
        if crate::mechanism::prepare_application_execution(50).is_err() {
            unsafe {
                *ISOLATED_RUN.0.get() = None;
                *ACTIVE.0.get() = None;
            }
            ISOLATED_ACTIVE.store(false, Ordering::Release);
            crate::mechanism::finish_application_execution();
            return Err(MmuError::ExecutionTimerUnavailable);
        }
        let raw = architecture_resume_application(root, &context);
        crate::mechanism::quiesce_application_execution();
        // SAFETY: The native gate returned with the kernel root and IRQ mask.
        let mut runtime =
            unsafe { (*ACTIVE.0.get()).take() }.ok_or(MmuError::InvalidUserContext)?;
        unsafe {
            *ISOLATED_RUN.0.get() = None;
        }
        ISOLATED_ACTIVE.store(false, Ordering::Release);
        crate::mechanism::finish_application_execution();
        runtime.roots_validated = false;
        let active = runtime.active.take().ok_or(MmuError::InvalidUserContext)?;
        let stop = if raw & OUTCOME_FAULT_BIT != 0 {
            let fault = decode_fault(raw)?;
            runtime.terminate(active, false)?;
            ProtectedStop::Faulted {
                actor: active,
                fault,
            }
        } else if raw == OUTCOME_APPLICATION_YIELD {
            runtime.stop.take().ok_or(MmuError::InvalidUserContext)?
        } else {
            runtime.terminate(active, true)?;
            ProtectedStop::Exited {
                actor: active,
                status: u32::try_from(raw).map_err(|_| MmuError::InvalidUserContext)?,
            }
        };
        Ok((runtime, stop))
    }

    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn peer(&self, actor: Actor) -> Result<&ApplicationSession, MmuError> {
        self.peers
            .get(actor.slot())
            .and_then(Option::as_ref)
            .filter(|(owner, _)| *owner == actor)
            .map(|(_, peer)| peer)
            .ok_or(MmuError::InvalidUserContext)
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn peer_mut(&mut self, actor: Actor) -> Result<&mut ApplicationSession, MmuError> {
        self.peers
            .get_mut(actor.slot())
            .and_then(Option::as_mut)
            .filter(|(owner, _)| *owner == actor)
            .map(|(_, peer)| peer)
            .ok_or(MmuError::InvalidUserContext)
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn alias(&self, actor: Actor) -> Result<u64, MmuError> {
        if actor.slot() < TASKS {
            let peer = self.peer(actor)?;
            if !self.roots_validated
                && !peer
                    .address_space
                    .tag
                    .as_ref()
                    .is_some_and(super::tags::TagLease::live)
            {
                return Err(MmuError::InvalidUserContext);
            }
            return peer
                .address_space
                .ipc
                .map(|ipc| ipc.alias)
                .ok_or(MmuError::InvalidUserContext);
        }
        self.kernel
            .get(actor.slot() - TASKS)
            .and_then(Option::as_ref)
            .filter(|(owner, pair)| *owner == actor && pair.is_live())
            .map(|(_, pair)| pair.range().start())
            .ok_or(MmuError::InvalidUserContext)
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn buffer(&mut self, buffer: Buffer) -> Result<*mut u8, MmuError> {
        match buffer {
            Buffer::Tx(actor) => Ok(self.alias(actor)? as *mut u8),
            Buffer::Rx(actor) => Ok((self.alias(actor)? + 4096) as *mut u8),
            Buffer::Queue(slot) => self
                .queues
                .get_mut(slot.index() as usize)
                .map(|queue| queue.as_mut_ptr())
                .ok_or(MmuError::InvalidUserContext),
        }
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn commit(&mut self, transition: Transition) -> Result<(), MmuError> {
        if let Some(transfer) = transition.transfer {
            let source = self.buffer(transfer.source)?;
            let destination = self.buffer(transfer.destination)?;
            if source == destination {
                return Err(MmuError::InvalidUserContext);
            }
            // SAFETY: The scalar model admitted the exact bounds and distinct
            // owned pages/queue; every peer is stopped under the masked trap.
            unsafe {
                ptr::copy_nonoverlapping(source, destination, usize::from(transfer.bytes));
            }
            if transfer.bytes != 0 {
                if transfer.reply {
                    self.stats.reply_copies = self.stats.reply_copies.saturating_add(1);
                } else {
                    self.stats.request_copies = self.stats.request_copies.saturating_add(1);
                }
            }
        }
        self.zero_queues()
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn zero_queues(&mut self) -> Result<(), MmuError> {
        while let Some(slot) = self.model.dirty_queue() {
            self.queues[slot.index() as usize].fill(0);
            self.model
                .recycled(slot)
                .map_err(|_| MmuError::InvalidUserContext)?;
            self.stats.queue_zeroes = self.stats.queue_zeroes.saturating_add(1);
        }
        Ok(())
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn apply_resume(&mut self, actor: Actor) -> Result<(), MmuError> {
        let resume = self
            .model
            .take_resume(actor)
            .map_err(|_| MmuError::InvalidUserContext)?;
        let context = &mut self.peer_mut(actor)?.context;
        Self::resume_context(context, resume);
        Ok(())
    }
    // Write the consumed scalar result using the already checked context owner.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn resume_context(context: &mut ArchitectureApplicationContext, resume: Option<Resume>) {
        match resume {
            Some(Resume::Reply { status, bytes }) => {
                application_context_set_results(context, status, u64::from(bytes));
            }
            Some(Resume::Event(event)) => ipc::set_event(context, event),
            None => {}
        }
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn transition(
        &mut self,
        transition: Transition,
        frame: &mut ArchitectureApplicationContext,
    ) -> Result<u64, MmuError> {
        let active = self.active.ok_or(MmuError::InvalidUserContext)?;
        self.peer_mut(active)?.context = frame.clone();
        self.commit(transition)?;
        let Some(destination) = transition.handoff else {
            self.stop = Some(ProtectedStop::Blocked(active));
            return Ok(OUTCOME_APPLICATION_YIELD);
        };
        if destination.slot() >= TASKS {
            self.stop = Some(ProtectedStop::Kernel(destination));
            return Ok(OUTCOME_APPLICATION_YIELD);
        }
        let resume = self
            .model
            .take_resume(destination)
            .map_err(|_| MmuError::InvalidUserContext)?;
        let peer = self.peer_mut(destination)?;
        Self::resume_context(&mut peer.context, resume);
        *frame = peer.context.clone();
        peer.address_space
            .tag
            .as_ref()
            .ok_or(MmuError::InvalidUserContext)?
            .activate()?;
        self.active = Some(destination);
        Ok(1 << 58)
    }
}

fn now() -> Result<u64, MmuError> {
    crate::monotonic_millis().ok_or(MmuError::ExecutionTimerUnavailable)
}

pub(super) fn syscall(
    number: u64,
    args: [u64; 6],
    frame: &mut ArchitectureApplicationContext,
) -> u64 {
    // SAFETY: Only the sole masked protected trap accesses the published owner.
    let Some(runtime) = (unsafe { &mut *ACTIVE.0.get() }).as_mut() else {
        return encoded_fault(IsolatedFault::InvalidCall);
    };
    let Some(actor) = runtime.active else {
        return encoded_fault(IsolatedFault::InvalidCall);
    };
    runtime.stats.traps = runtime.stats.traps.saturating_add(1);
    let result = (|| {
        let transition = match number {
            troe_abi::ipc::CALL => {
                #[cfg(feature = "acceptance-probes")]
                if runtime.probe == Some(actor) {
                    runtime.started = (
                        crate::benchmark_counter_ticks(),
                        crate::application_execution_stats().timer_programs,
                    );
                }
                runtime.model.call(
                    actor,
                    troe_abi::ipc::Call::decode(args).ok_or(MmuError::InvalidUserContext)?,
                    now()?,
                )
            }
            troe_abi::ipc::REPLY_WAIT => {
                let wait =
                    troe_abi::ipc::ReplyWait::decode(args).ok_or(MmuError::InvalidUserContext)?;
                #[cfg(feature = "acceptance-probes")]
                if wait.token != 0
                    && (runtime.injected(actor, FaultPoint::BeforeReply)
                        || runtime.injected(actor, FaultPoint::NestedCall))
                {
                    return Err(MmuError::InvalidUserContext);
                }
                let now = now()?;
                #[cfg(feature = "acceptance-probes")]
                if wait.token != 0 && runtime.injected(actor, FaultPoint::AfterReplyValidation) {
                    runtime
                        .model
                        .validate_reply(actor, wait, now)
                        .map_err(|_| MmuError::InvalidUserContext)?;
                    return Err(MmuError::InvalidUserContext);
                }
                runtime.model.reply_wait(actor, wait, now)
            }
            super::APPLICATION_YIELD_CALL => {
                #[cfg(feature = "acceptance-probes")]
                if runtime.injected(actor, FaultPoint::AfterReceive) {
                    return Err(MmuError::InvalidUserContext);
                }
                application_context_set_results(frame, 0, 0);
                runtime.peer_mut(actor)?.context = frame.clone();
                runtime.stop = Some(ProtectedStop::Yielded(actor));
                return Ok(OUTCOME_APPLICATION_YIELD);
            }
            super::APPLICATION_HEAP_GROW_CALL => {
                if args[0] == 0 || args[1..].iter().any(|argument| *argument != 0) {
                    return Err(MmuError::InvalidUserContext);
                }
                // This runtime's fixed boot records reserve all private pages
                // up front. A dynamic request cannot widen that reservation.
                application_context_set_results(frame, troe_abi::heap_growth::EXHAUSTED, 0);
                return Ok(1 << 58);
            }
            super::APPLICATION_EXIT_CALL => {
                return u32::try_from(args[0])
                    .map(u64::from)
                    .map_err(|_| MmuError::InvalidUserContext);
            }
            _ => return Err(MmuError::InvalidUserContext),
        }
        .map_err(|_| MmuError::InvalidUserContext)?;
        let result = runtime.transition(transition, frame)?;
        #[cfg(feature = "acceptance-probes")]
        if transition.transfer.is_some_and(|transfer| transfer.reply)
            && transition.handoff == runtime.probe
        {
            let ticks = crate::benchmark_counter_ticks().saturating_sub(runtime.started.0);
            if let Some(sample) = runtime.samples.get_mut(runtime.sample_count) {
                *sample = ticks;
                runtime.sample_count += 1;
            }
            runtime.stats.additional_lease_programs =
                runtime.stats.additional_lease_programs.saturating_add(
                    crate::application_execution_stats()
                        .timer_programs
                        .saturating_sub(runtime.started.1),
                );
        }
        Ok(result)
    })();
    result.unwrap_or_else(|_| encoded_fault(IsolatedFault::InvalidCall))
}

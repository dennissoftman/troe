//! Owned two-task IPC execution for the Phase B synthetic endpoint.
//!
//! This mechanism retains complete contexts, never a callback or suspended
//! service frame. General endpoint scheduling and supervision are separate
//! composition work. All steady payload access uses boot-arena aliases.

use super::{
    APPLICATION_EXIT_CALL, APPLICATION_YIELD_CALL, ApplicationPending, ApplicationSession,
    ArchitectureApplicationContext, ISOLATED_ACTIVE, ISOLATED_RUN, IsolatedFault, IsolatedRunState,
    MmuError, OUTCOME_APPLICATION_YIELD, OUTCOME_FAULT_BIT, RunKind, UserAddressSpace,
    application_context_set_results, architecture_resume_application, copy_user_from_physical,
    decode_fault, encoded_fault, tags,
};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use troe_abi::ipc::{Call, Event, EventKind, ReplyWait};

const CONTINUE: u64 = 1 << 58;
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
struct PairCell(UnsafeCell<Option<IpcPair>>);
// SAFETY: Publication uses ISOLATED_ACTIVE; trap access is single-CPU with
// interrupts masked. The owning entry removes the value before enabling IRQs.
unsafe impl Sync for PairCell {}
static PAIR: PairCell = PairCell(UnsafeCell::new(None));

/// Exact payload and transition counters for a two-task IPC execution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpcStats {
    /// Admitted immediately to a waiting endpoint.
    pub direct: u64,
    /// Admitted to the preallocated copied queue.
    pub queued: u64,
    /// Actual nonempty request copies.
    pub request_copies: u64,
    /// Actual nonempty reply copies.
    pub reply_copies: u64,
    /// Completed, single-use replies.
    pub completed: u64,
    /// Native ABI trap entries, including initial waits and yields.
    pub traps: u64,
    /// Whole queue slots zeroed after delivery or cancellation.
    pub queue_zeroes: u64,
    /// Calls ended because a server became terminal.
    pub peer_deaths: u64,
    /// Calls that reached their absolute service deadline.
    pub timeouts: u64,
    /// Last completed round trip in the native benchmark counter's ticks.
    pub last_ticks: u64,
    /// Timer programs observed between admission and completion.
    pub additional_lease_programs: u64,
}

#[derive(Debug)]
struct Pending {
    call: Call,
    token: u64,
    delivered: bool,
    started: u64,
    lease_programs: u64,
}

/// Complete owned contexts and private queue storage for one synthetic endpoint.
#[derive(Debug)]
pub struct IpcPair {
    peers: [ApplicationSession; 2],
    client_handle: u64,
    wait_handle: u64,
    badge: u32,
    active: usize,
    waiting: bool,
    server_status: Option<u32>,
    client_dead: bool,
    pending: Option<Pending>,
    queue: [u8; 4096],
    stats: IpcStats,
    #[cfg(feature = "acceptance-probes")]
    samples: [u64; 256],
    #[cfg(feature = "acceptance-probes")]
    sample_count: usize,
}

/// Why the owned pair returned to kernel scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcStop {
    /// The initiating client explicitly ended its execution segment.
    Yielded,
    /// One peer exited cleanly.
    Exited {
        /// Zero for the client, one for the server.
        peer: usize,
        /// Application exit status.
        status: u32,
    },
    /// One peer faulted, including absolute execution-lease expiry.
    Faulted {
        /// Zero for the client, one for the server.
        peer: usize,
        /// Contained architectural fate.
        fault: IsolatedFault,
    },
}

impl IpcPair {
    /// Bind the two already suspended ABI 1.3 tasks to startup authority.
    ///
    /// The client must have yielded and the server must have published its
    /// initial reply/wait. The supplied startup addresses are checked against
    /// the mapped IPC geometry, task identities, and exact capability records.
    ///
    /// # Errors
    /// Rejects foreign roots/pages, stale tags, incompatible authority, or a
    /// server that has not published a canonical initial wait.
    pub fn new(
        client: ApplicationSession,
        server: ApplicationSession,
        client_startup: u64,
        server_startup: u64,
        badge: u32,
    ) -> Result<Self, MmuError> {
        if !matches!(client.pending, ApplicationPending::Yield) || badge == 0 {
            return Err(MmuError::InvalidUserContext);
        }
        let ApplicationPending::IpcWait(wait) = server.pending else {
            return Err(MmuError::InvalidUserContext);
        };
        let (client_handle, client_id) = authority(
            &client.address_space,
            client_startup,
            troe_abi::interface::DIAGNOSTICS,
            1,
            1,
        )?;
        let (wait_handle, server_id) = authority(
            &server.address_space,
            server_startup,
            troe_abi::interface::WAIT_SET,
            1,
            8,
        )?;
        authority(
            &server.address_space,
            server_startup,
            troe_abi::interface::SERVER_ENDPOINT,
            2,
            6,
        )?;
        if wait.wait_set != wait_handle
            || wait.token != 0
            || client_id == server_id
            || client.address_space.root == server.address_space.root
            || client.address_space.ipc == server.address_space.ipc
        {
            return Err(MmuError::InvalidUserContext);
        }
        let mut pair = Self {
            peers: [client, server],
            client_handle,
            wait_handle,
            badge,
            active: 0,
            waiting: true,
            server_status: None,
            client_dead: false,
            pending: None,
            queue: [0; 4096],
            stats: IpcStats::default(),
            #[cfg(feature = "acceptance-probes")]
            samples: [0; 256],
            #[cfg(feature = "acceptance-probes")]
            sample_count: 0,
        };
        pair.publish_wait(wait.deadline_millis)?;
        application_context_set_results(&mut pair.peers[0].context, 0, 0);
        Ok(pair)
    }

    /// Exact cumulative structural accounting.
    #[must_use]
    pub const fn stats(&self) -> IpcStats {
        self.stats
    }

    /// Unsorted completed-call ticks from the current execution segment.
    #[cfg(feature = "acceptance-probes")]
    #[must_use]
    pub fn samples(&self) -> &[u64] {
        &self.samples[..self.sample_count]
    }

    /// Whether the retained queue contains only zeroes and no call is pending.
    #[must_use]
    pub fn quiescent(&self) -> bool {
        self.pending.is_none() && self.queue.iter().all(|byte| *byte == 0)
    }

    /// Execute one absolute 50 ms segment, donating it across direct handoffs.
    ///
    /// # Errors
    /// Rejects concurrent execution, stale roots, or an unavailable lease timer.
    pub fn run(mut self) -> Result<(Self, IpcStop), MmuError> {
        if self.client_dead {
            return Err(MmuError::InvalidUserContext);
        }
        for peer in &self.peers {
            if !peer
                .address_space
                .tag
                .as_ref()
                .is_some_and(tags::TagLease::live)
            {
                return Err(MmuError::InvalidUserContext);
            }
        }
        if ISOLATED_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(MmuError::IsolationBusy);
        }
        self.active = 0;
        #[cfg(feature = "acceptance-probes")]
        {
            self.sample_count = 0;
        }
        let root = self.peers[0].address_space.root;
        let context = self.peers[0].context.clone();
        // SAFETY: This entry owns the sole active run. All retained state is
        // moved into native storage before user execution can observe it.
        unsafe {
            *PAIR.0.get() = Some(self);
            *ISOLATED_RUN.0.get() = Some(IsolatedRunState {
                kind: RunKind::Ipc,
                regions: Vec::new(),
                destination: ptr::null_mut(),
                destination_len: 0,
                application_context: None,
                pending_application: None,
                ipc: None,
            });
        }
        if crate::mechanism::prepare_application_execution(50).is_err() {
            unsafe {
                *ISOLATED_RUN.0.get() = None;
                *PAIR.0.get() = None;
            }
            ISOLATED_ACTIVE.store(false, Ordering::Release);
            crate::mechanism::finish_application_execution();
            return Err(MmuError::ExecutionTimerUnavailable);
        }
        let raw = architecture_resume_application(root, &context);
        crate::mechanism::quiesce_application_execution();
        // SAFETY: The native return restored the kernel root and IRQ mask.
        let mut pair = unsafe { (*PAIR.0.get()).take() }.ok_or(MmuError::InvalidUserContext)?;
        unsafe {
            *ISOLATED_RUN.0.get() = None;
        }
        ISOLATED_ACTIVE.store(false, Ordering::Release);
        crate::mechanism::finish_application_execution();
        let stop = if raw == OUTCOME_APPLICATION_YIELD {
            IpcStop::Yielded
        } else if raw & OUTCOME_FAULT_BIT != 0 {
            let fault = decode_fault(raw)?;
            let peer = pair.active;
            pair.terminal(peer, troe_abi::reply::PEER_DIED);
            IpcStop::Faulted { peer, fault }
        } else {
            let peer = pair.active;
            pair.terminal(peer, troe_abi::reply::CLOSED);
            IpcStop::Exited {
                peer,
                status: u32::try_from(raw).map_err(|_| MmuError::InvalidUserContext)?,
            }
        };
        Ok((pair, stop))
    }

    fn terminal(&mut self, peer: usize, status: u32) {
        if let Some(ipc) = self.peers[peer].address_space.ipc {
            // SAFETY: The terminal peer is stopped, and the kernel root is active.
            unsafe {
                ptr::write_bytes(ipc.alias as *mut u8, 0, 8192);
            }
        }
        if peer == 1 {
            self.server_status = Some(status);
        } else {
            self.client_dead = true;
        }
        let pending = self.pending.take();
        if pending.as_ref().is_some_and(|pending| !pending.delivered) {
            self.stats.queue_zeroes = self.stats.queue_zeroes.saturating_add(1);
        }
        if pending.is_some() && peer == 1 {
            application_context_set_results(&mut self.peers[0].context, status, 0);
            self.stats.peer_deaths = self.stats.peer_deaths.saturating_add(1);
        }
        self.queue.fill(0);
    }

    fn publish_wait(&mut self, deadline: u64) -> Result<(), MmuError> {
        let now = crate::monotonic_millis().ok_or(MmuError::ExecutionTimerUnavailable)?;
        // The synthetic endpoint has no device sources. A finite future wait
        // remains retained until a client or its deadline is observed.
        self.waiting = deadline == u64::MAX || deadline > now;
        if !self.waiting {
            set_event(&mut self.peers[1].context, idle_event(EventKind::Deadline));
        }
        self.peers[1].pending = ApplicationPending::IpcWait(ReplyWait {
            wait_set: self.wait_handle,
            token: 0,
            status: 0,
            reply_bytes: 0,
            deadline_millis: deadline,
        });
        Ok(())
    }

    fn switch(
        &mut self,
        destination: usize,
        frame: &mut ArchitectureApplicationContext,
    ) -> Result<(), MmuError> {
        self.peers[self.active].context = frame.clone();
        self.resume_saved(destination, frame)
    }

    /// Resume a peer after the outgoing context has already been saved.
    /// Reply/wait can change the saved server event, so copying the old trap
    /// frame over it here would lose the newly published wait completion.
    fn resume_saved(
        &mut self,
        destination: usize,
        frame: &mut ArchitectureApplicationContext,
    ) -> Result<(), MmuError> {
        *frame = self.peers[destination].context.clone();
        self.peers[destination]
            .address_space
            .tag
            .as_ref()
            .ok_or(MmuError::InvalidUserContext)?
            .activate()?;
        self.active = destination;
        Ok(())
    }

    fn deliver(&mut self, frame: &mut ArchitectureApplicationContext) -> Result<(), MmuError> {
        let pending = self.pending.as_mut().ok_or(MmuError::InvalidUserContext)?;
        if pending.delivered {
            return Err(MmuError::InvalidUserContext);
        }
        let destination = self.peers[1]
            .address_space
            .ipc
            .ok_or(MmuError::InvalidUserContext)?
            .alias
            + 4096;
        let length = usize::from(pending.call.request_bytes);
        // SAFETY: The server's live boot-arena RX alias is a distinct owned
        // page; its task is stopped and the complete length was admitted.
        unsafe {
            ptr::copy_nonoverlapping(self.queue.as_ptr(), destination as *mut u8, length);
        }
        if length != 0 {
            self.stats.request_copies = self.stats.request_copies.saturating_add(1);
        }
        self.queue.fill(0);
        self.stats.queue_zeroes = self.stats.queue_zeroes.saturating_add(1);
        pending.delivered = true;
        set_event(frame, call_event(pending, self.badge));
        self.waiting = false;
        Ok(())
    }

    fn call(
        &mut self,
        args: [u64; 6],
        frame: &mut ArchitectureApplicationContext,
    ) -> Result<(), MmuError> {
        let started = ticks();
        let call = Call::decode(args).ok_or(MmuError::InvalidUserContext)?;
        let now = crate::monotonic_millis().ok_or(MmuError::ExecutionTimerUnavailable)?;
        if self.active != 0
            || call.handle != self.client_handle
            || call.object_parameter != 0
            || self.pending.is_some()
        {
            return Err(MmuError::InvalidUserContext);
        }
        if call.deadline_millis <= now || self.server_status.is_some() {
            let status = self.server_status.unwrap_or(troe_abi::reply::TIMEOUT);
            if self.server_status.is_none() {
                self.stats.timeouts = self.stats.timeouts.saturating_add(1);
            }
            application_context_set_results(frame, status, 0);
            return Ok(());
        }
        if !call.deadline_valid(now, troe_abi::ipc::MAX_CALL_MILLIS) {
            return Err(MmuError::InvalidUserContext);
        }
        let Ok(token) = NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        }) else {
            application_context_set_results(frame, troe_abi::reply::EXHAUSTED, 0);
            return Ok(());
        };
        if self.waiting
            && let ApplicationPending::IpcWait(wait) = self.peers[1].pending
        {
            self.publish_wait(wait.deadline_millis)?;
        }
        let pending = Pending {
            call,
            token,
            delivered: self.waiting,
            started,
            lease_programs: lease_programs(),
        };
        let source = self.peers[0]
            .address_space
            .ipc
            .ok_or(MmuError::InvalidUserContext)?
            .alias;
        let length = usize::from(call.request_bytes);
        if self.waiting {
            let destination = self.peers[1]
                .address_space
                .ipc
                .ok_or(MmuError::InvalidUserContext)?
                .alias
                + 4096;
            // SAFETY: Exclusive stopped peers, distinct prevalidated private
            // aliases, and a complete bounded prefix; no arbitrary user pointer.
            unsafe {
                ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, length);
            }
            set_event(&mut self.peers[1].context, call_event(&pending, self.badge));
            self.stats.direct = self.stats.direct.saturating_add(1);
        } else {
            // SAFETY: Exact source prefix is live and the private queue slot
            // cannot be observed or modified by either unprivileged peer.
            unsafe {
                ptr::copy_nonoverlapping(source as *const u8, self.queue.as_mut_ptr(), length);
            }
            self.stats.queued = self.stats.queued.saturating_add(1);
        }
        if length != 0 {
            self.stats.request_copies = self.stats.request_copies.saturating_add(1);
        }
        self.waiting = false;
        self.pending = Some(pending);
        self.switch(1, frame)
    }

    fn reply_wait(
        &mut self,
        args: [u64; 6],
        frame: &mut ArchitectureApplicationContext,
    ) -> Result<(), MmuError> {
        let wait = ReplyWait::decode(args).ok_or(MmuError::InvalidUserContext)?;
        if self.active != 1 || wait.wait_set != self.wait_handle {
            return Err(MmuError::InvalidUserContext);
        }
        if wait.token == 0 {
            if self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.delivered)
            {
                return Err(MmuError::InvalidUserContext);
            }
            if wait.deadline_millis != u64::MAX
                && wait.deadline_millis
                    <= crate::monotonic_millis().ok_or(MmuError::ExecutionTimerUnavailable)?
            {
                set_event(frame, idle_event(EventKind::Deadline));
                return Ok(());
            }
            return self.deliver(frame);
        }
        let pending = self.pending.as_ref().ok_or(MmuError::InvalidUserContext)?;
        if !pending.delivered
            || wait.token != pending.token
            || wait.reply_bytes > pending.call.reply_capacity
        {
            return Err(MmuError::InvalidUserContext);
        }
        let expired = pending.call.deadline_millis
            <= crate::monotonic_millis().ok_or(MmuError::ExecutionTimerUnavailable)?;
        let source = self.peers[1]
            .address_space
            .ipc
            .ok_or(MmuError::InvalidUserContext)?
            .alias;
        let destination = self.peers[0]
            .address_space
            .ipc
            .ok_or(MmuError::InvalidUserContext)?
            .alias
            + 4096;
        let length = if expired {
            0
        } else {
            usize::from(wait.reply_bytes)
        };
        // SAFETY: Every token/status/deadline/capacity check precedes the first
        // write; aliases are private stopped-task pages in the shared arena.
        unsafe {
            ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, length);
        }
        if length != 0 {
            self.stats.reply_copies = self.stats.reply_copies.saturating_add(1);
        }
        let started = pending.started;
        self.stats.additional_lease_programs = self
            .stats
            .additional_lease_programs
            .saturating_add(lease_programs().saturating_sub(pending.lease_programs));
        self.pending = None;
        // Save the post-reply context, publish the wait, then resume the exact
        // caller. No scheduler scan or execution-timer operation occurs here.
        self.peers[1].context = frame.clone();
        self.publish_wait(wait.deadline_millis)?;
        application_context_set_results(
            &mut self.peers[0].context,
            if expired {
                troe_abi::reply::TIMEOUT
            } else {
                wait.status
            },
            length as u64,
        );
        if expired {
            self.stats.timeouts = self.stats.timeouts.saturating_add(1);
        }
        self.resume_saved(0, frame)?;
        self.stats.completed = self.stats.completed.saturating_add(1);
        self.stats.last_ticks = ticks().saturating_sub(started);
        #[cfg(feature = "acceptance-probes")]
        if let Some(sample) = self.samples.get_mut(self.sample_count) {
            *sample = self.stats.last_ticks;
            self.sample_count += 1;
        }
        Ok(())
    }
}

impl UserAddressSpace {
    /// Authorize the initial receive using immutable, owner-selected startup grants.
    ///
    /// # Errors
    /// Rejects absent or incompatible endpoint and wait-set authority. Only the
    /// kernel composition publishes persistent endpoints.
    pub fn authorize_persistent_ipc(&mut self, startup: u64) -> Result<(), MmuError> {
        authority(self, startup, troe_abi::interface::SERVER_ENDPOINT, 2, 6)?;
        let (wait_set, _) = authority(self, startup, troe_abi::interface::WAIT_SET, 1, 8)?;
        self.ipc
            .as_mut()
            .ok_or(MmuError::InvalidUserContext)?
            .wait_set = wait_set;
        Ok(())
    }
}

pub(super) fn authority(
    space: &UserAddressSpace,
    startup: u64,
    interface: u32,
    major: u16,
    rights: u32,
) -> Result<(u64, u64), MmuError> {
    let ipc = space.ipc.ok_or(MmuError::InvalidUserContext)?;
    if startup.checked_add(4096) != Some(ipc.tx)
        || !space.tag.as_ref().is_some_and(tags::TagLease::live)
    {
        return Err(MmuError::InvalidUserContext);
    }
    let mut bytes = [0; 4096];
    copy_user_from_physical(space.root, &space.regions, startup, &mut bytes)?;
    let u16_at = |i| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
    let u32_at = |i| {
        u32::from_le_bytes(
            bytes[i..i + 4]
                .try_into()
                .unwrap_or_else(|_| unreachable!()),
        )
    };
    let u64_at = |i| {
        u64::from_le_bytes(
            bytes[i..i + 8]
                .try_into()
                .unwrap_or_else(|_| unreachable!()),
        )
    };
    let count = usize::from(u16_at(14));
    if u16_at(4) != 1
        || u16_at(6) != 3
        || u16_at(12) != 0
        || u32_at(8) != 4096
        || count > troe_abi::startup::max_initial_handles(3)
        || u32_at(0) as usize != 80 + count * 24
        || u64_at(56) == 0
        || u64_at(64) != ipc.tx
        || u64_at(72) != ipc.tx + 4096
        || bytes[80 + count * 24..].iter().any(|byte| *byte != 0)
    {
        return Err(MmuError::InvalidUserContext);
    }
    let mut found = None;
    for offset in (80..80 + count * 24).step_by(24) {
        if u32_at(offset + 12) == interface {
            if found.is_some()
                || u64_at(offset) == 0
                || u32_at(offset + 8) != rights
                || u16_at(offset + 16) != major
                || u16_at(offset + 18) != 0
                || u32_at(offset + 20) != 0
            {
                return Err(MmuError::InvalidUserContext);
            }
            found = Some((u64_at(offset), u64_at(56)));
        }
    }
    found.ok_or(MmuError::InvalidUserContext)
}

fn call_event(pending: &Pending, badge: u32) -> Event {
    Event {
        kind: EventKind::Call,
        token: pending.token,
        source: 0,
        badge,
        interface: troe_abi::interface::DIAGNOSTICS,
        opcode: pending.call.opcode,
        request_bytes: pending.call.request_bytes,
        reply_capacity: pending.call.reply_capacity,
    }
}
fn idle_event(kind: EventKind) -> Event {
    Event {
        kind,
        token: 0,
        source: 0,
        badge: 0,
        interface: 0,
        opcode: 0,
        request_bytes: 0,
        reply_capacity: 0,
    }
}
#[cfg(target_arch = "x86_64")]
// Keep scalar event encoding inside the checked context handoff.
#[allow(clippy::inline_always)]
#[inline(always)]
pub(super) fn set_event(context: &mut ArchitectureApplicationContext, event: Event) {
    let words = event.words();
    (
        context.rax,
        context.rdx,
        context.rdi,
        context.rsi,
        context.r8,
        context.r9,
    ) = (words[0], words[1], words[2], words[3], words[4], words[5]);
}
#[cfg(target_arch = "aarch64")]
// Keep scalar event encoding inside the checked context handoff.
#[allow(clippy::inline_always)]
#[inline(always)]
pub(super) fn set_event(context: &mut ArchitectureApplicationContext, event: Event) {
    context.general[..6].copy_from_slice(&event.words());
}

#[cfg(feature = "acceptance-probes")]
fn lease_programs() -> u64 {
    crate::application_execution_stats().timer_programs
}
#[cfg(not(feature = "acceptance-probes"))]
fn lease_programs() -> u64 {
    0
}

#[cfg(feature = "acceptance-probes")]
fn ticks() -> u64 {
    crate::benchmark_counter_ticks()
}
#[cfg(not(feature = "acceptance-probes"))]
fn ticks() -> u64 {
    0
}

pub(super) fn syscall(
    number: u64,
    args: [u64; 6],
    frame: &mut ArchitectureApplicationContext,
) -> u64 {
    // SAFETY: Only the exclusive masked trap path accesses the published pair.
    let Some(pair) = (unsafe { &mut *PAIR.0.get() }).as_mut() else {
        return encoded_fault(IsolatedFault::InvalidCall);
    };
    pair.stats.traps = pair.stats.traps.saturating_add(1);
    let result = match number {
        troe_abi::ipc::CALL => pair.call(args, frame),
        troe_abi::ipc::REPLY_WAIT => pair.reply_wait(args, frame),
        APPLICATION_YIELD_CALL if pair.active == 0 && pair.pending.is_none() => {
            pair.peers[0].context = frame.clone();
            application_context_set_results(&mut pair.peers[0].context, 0, 0);
            return OUTCOME_APPLICATION_YIELD;
        }
        APPLICATION_EXIT_CALL => {
            return u32::try_from(args[0])
                .map_or_else(|_| encoded_fault(IsolatedFault::InvalidCall), u64::from);
        }
        _ => Err(MmuError::InvalidUserContext),
    };
    if result.is_ok() {
        CONTINUE
    } else {
        encoded_fault(IsolatedFault::InvalidCall)
    }
}

#[cfg(target_arch = "x86_64")]
pub(super) const fn continue_value() -> u64 {
    CONTINUE
}

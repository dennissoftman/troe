//! Pointer-free composition of bounded endpoints, calls, chains and wait sets.
//!
//! A transition returns at most one bounded payload transfer. Native composition
//! executes it under the masked trap before resuming either context. Payloads,
//! address spaces and saved registers are owned separately by the machine.

use alloc::vec::Vec;
use core::num::NonZeroU32;
use troe_abi::{
    ipc::{Call, Event, EventKind, ReplyWait},
    reply,
};
use troe_dispatch::{
    Admission, BadgeTable, CallId, CallOutcome, ClientBadge, EndpointId, EndpointLimits,
    EndpointTable, HandleOwner, InterfaceSet, PendingCallTable, QueueSlotId,
};
use troe_task::{
    CallChainError, CallChainTable, SourceReadiness, TaskId, WaitSelection, WaitSet, WaitSource,
    WaitSourceKind,
};

/// Simultaneously owned unprivileged contexts in the protected service profile.
pub const TASKS: usize = 16;
/// Kernel continuation clients have separate private IPC pairs.
pub const KERNEL_CLIENTS: usize = 4;
const ACTORS: usize = TASKS + KERNEL_CLIENTS;
const HANDLES: usize = 256;
const CALLS: usize = 32;

/// Runtime slot and incarnation; possession alone grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Actor {
    slot: u32,
    generation: NonZeroU32,
}
// Zero is never an incarnation. Encode that invariant so optional handoffs do
// not need a separate discriminator or fragment the scalar transition copy.
const _: () = assert!(core::mem::size_of::<Option<Actor>>() == 8);
impl Actor {
    /// Index for the matching machine-owned context or kernel IPC pair.
    #[must_use]
    pub const fn slot(self) -> usize {
        self.slot as usize
    }
}

/// Invalid authority is a contained task fault; resource pressure is a reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A noncanonical, stale, foreign or unauthorized operation.
    Invalid,
    /// A bounded construction failed before publication.
    Exhausted,
}

/// A private page or queue slot; no virtual or physical pointer is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Buffer {
    /// One stopped actor's outbound page.
    Tx(Actor),
    /// One stopped actor's inbound page.
    Rx(Actor),
    /// One preallocated copied request slot.
    Queue(QueueSlotId),
}

/// Copy to perform before the selected destination may execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transfer {
    /// True only for a validated server reply, for exact native copy counters.
    pub reply: bool,
    /// Fully validated source.
    pub source: Buffer,
    /// Fully validated destination.
    pub destination: Buffer,
    /// Exact prefix; zero means no payload copy.
    pub bytes: u16,
}

/// Scalar ABI completion retained beside a stopped context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resume {
    /// Client call result.
    Reply {
        /// Typed service or kernel transport status.
        status: u32,
        /// Exact valid RX prefix.
        bytes: u16,
    },
    /// Server receive event.
    Event(Event),
}

/// One atomic transition and optional immediate donated handoff.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Transition {
    /// Bounded copy required before publication to userspace.
    pub transfer: Option<Transfer>,
    /// Exact task that wins the direct handoff, without scheduler selection.
    pub handoff: Option<Actor>,
}

#[derive(Debug)]
struct Context {
    generation: u32,
    task: Option<TaskId>,
    occupied: bool,
    terminal: bool,
    inbound: Option<CallId>,
    outbound: Option<CallId>,
    wait: Option<WaitSet>,
    waiting: bool,
    deadline: u64,
    resume: Option<Resume>,
}
#[derive(Clone, Copy, Debug)]
struct Endpoint {
    id: EndpointId,
    server: Actor,
    ready: bool,
}
#[derive(Clone, Copy, Debug)]
enum Grant {
    Call {
        endpoint: EndpointId,
        interface: u32,
        major: u16,
        minor: u16,
        badge: ClientBadge,
    },
    Wait,
    Receive,
}
#[derive(Clone, Copy, Debug)]
struct Handle {
    owner: Actor,
    grant: Grant,
}
#[derive(Clone, Copy, Debug, Default)]
struct HandleSlot {
    generation: u32,
    handle: Option<Handle>,
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    id: CallId,
    caller: Actor,
    server: Actor,
    endpoint: EndpointId,
    badge: ClientBadge,
    interface: u32,
    deadline_millis: u64,
    opcode: u16,
    request_bytes: u16,
    reply_capacity: u16,
}

/// Live state used to prove exact cancellation and teardown.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Live {
    /// Occupied contexts including kernel clients.
    pub contexts: usize,
    /// Published endpoint incarnations.
    pub endpoints: u32,
    /// Live capability grants.
    pub handles: usize,
    /// Live pending synchronous calls.
    pub calls: u32,
    /// Published immutable waits.
    pub waits: usize,
    /// Queue slots whose bytes must be zeroed before reuse.
    pub dirty_queues: usize,
}

/// Fixed-capacity transport composition. Construction reserves all metadata.
#[derive(Debug)]
pub struct Runtime {
    contexts: Vec<Context>,
    endpoints: EndpointTable,
    bindings: [Option<Endpoint>; 16],
    handles: [HandleSlot; HANDLES],
    badges: BadgeTable,
    pending: PendingCallTable,
    calls: [Option<Pending>; CALLS],
    chains: CallChainTable,
    dirty: [Option<QueueSlotId>; CALLS],
    dirty_count: usize,
    cursor: usize,
    wait_cursor: usize,
}
impl Runtime {
    /// Reserve all steady transport metadata before publishing a server.
    ///
    /// # Errors
    /// Returns exhaustion without exposing a partially constructed runtime.
    pub fn new() -> Result<Self, Error> {
        let mut contexts = Vec::new();
        contexts
            .try_reserve_exact(ACTORS)
            .map_err(|_| Error::Exhausted)?;
        for _ in 0..ACTORS {
            contexts.push(Context {
                generation: 0,
                task: None,
                occupied: false,
                terminal: false,
                inbound: None,
                outbound: None,
                wait: None,
                waiting: false,
                deadline: u64::MAX,
                resume: None,
            });
        }
        Ok(Self {
            contexts,
            endpoints: EndpointTable::new(16).map_err(|_| Error::Exhausted)?,
            bindings: [None; 16],
            handles: [HandleSlot::default(); HANDLES],
            badges: BadgeTable::new(256).map_err(|_| Error::Exhausted)?,
            pending: PendingCallTable::new(CALLS, 128 * 1024).map_err(|_| Error::Exhausted)?,
            calls: [None; CALLS],
            chains: CallChainTable::new(TASKS).map_err(|_| Error::Exhausted)?,
            dirty: [None; CALLS],
            dirty_count: 0,
            cursor: 0,
            wait_cursor: 0,
        })
    }

    /// Attach one independently owned user context, or a kernel continuation.
    ///
    /// # Errors
    /// Rejects duplicate task identities and exhausted or retired slots.
    pub fn attach(&mut self, task: Option<TaskId>) -> Result<Actor, Error> {
        if task.is_some() && self.contexts.iter().any(|c| c.occupied && c.task == task) {
            return Err(Error::Invalid);
        }
        let range = if task.is_some() {
            0..TASKS
        } else {
            TASKS..ACTORS
        };
        let slot = range
            .into_iter()
            .find(|i| !self.contexts[*i].occupied && self.contexts[*i].generation != u32::MAX)
            .ok_or(Error::Exhausted)?;
        let c = &mut self.contexts[slot];
        c.generation += 1;
        c.task = task;
        c.occupied = true;
        c.terminal = false;
        c.inbound = None;
        c.outbound = None;
        c.waiting = false;
        c.wait = None;
        c.resume = None;
        c.deadline = u64::MAX;
        Ok(Actor {
            slot: u32::try_from(slot).map_err(|_| Error::Invalid)?,
            generation: NonZeroU32::new(c.generation).ok_or(Error::Invalid)?,
        })
    }

    /// Bind an endpoint to a starting server; ordinary clients remain excluded.
    ///
    /// # Errors
    /// Rejects a stale owner, kernel server, invalid interface set or exhaustion.
    pub fn bind(
        &mut self,
        server: Actor,
        interfaces: InterfaceSet,
        limits: EndpointLimits,
    ) -> Result<EndpointId, Error> {
        let task = self.context(server)?.task.ok_or(Error::Invalid)?;
        if !self.bindings.iter().flatten().any(|e| e.server == server)
            && self
                .contexts
                .iter()
                .enumerate()
                .filter(|(slot, c)| {
                    c.occupied
                        && self
                            .bindings
                            .iter()
                            .flatten()
                            .any(|e| e.server.slot() == *slot)
                })
                .count()
                >= crate::MAX_BOOT_SERVICES
        {
            return Err(Error::Exhausted);
        }
        let id = self
            .endpoints
            .bind(HandleOwner::IsolatedTask(task.get()), interfaces, limits)
            .map_err(|_| Error::Exhausted)?;
        self.bindings[id.slot() as usize] = Some(Endpoint {
            id,
            server,
            ready: false,
        });
        Ok(id)
    }

    /// Construct the server's immutable endpoint wait set and startup grants.
    ///
    /// # Errors
    /// Rejects duplicate, foreign or more than four sources, or capacity failure.
    pub fn configure_wait(
        &mut self,
        server: Actor,
        endpoints: &[EndpointId],
    ) -> Result<(u64, u64), Error> {
        if self.context(server)?.wait.is_some() || endpoints.is_empty() || endpoints.len() > 4 {
            return Err(Error::Invalid);
        }
        let mut sources =
            [WaitSource::new(WaitSourceKind::Endpoint, 1, 1).map_err(|_| Error::Invalid)?; 4];
        for (index, id) in endpoints.iter().enumerate() {
            if self.endpoint(*id)?.server != server {
                return Err(Error::Invalid);
            }
            sources[index] = WaitSource::new(
                WaitSourceKind::Endpoint,
                u64::from(id.slot()) + 1,
                id.generation(),
            )
            .map_err(|_| Error::Invalid)?;
        }
        let wait = WaitSet::new(&sources[..endpoints.len()]).map_err(|_| Error::Invalid)?;
        if self.free_handles(server)? < 2 {
            return Err(Error::Exhausted);
        }
        let receive = self.grant(server, Grant::Receive)?;
        let wait_handle = self.grant(server, Grant::Wait)?;
        self.contexts[server.slot()].wait = Some(wait);
        Ok((receive, wait_handle))
    }

    /// Publish readiness only after composition validates initialization success.
    ///
    /// # Errors
    /// Requires a committed immutable wait and an idle, live server incarnation.
    pub fn ready(&mut self, endpoint: EndpointId) -> Result<(), Error> {
        let server = self.endpoint(endpoint)?.server;
        let c = self.context(server)?;
        if c.wait.is_none() || !c.waiting || c.inbound.is_some() {
            return Err(Error::Invalid);
        }
        self.bindings[endpoint.slot() as usize]
            .as_mut()
            .ok_or(Error::Invalid)?
            .ready = true;
        Ok(())
    }

    /// Derive a client handle to an exact endpoint and interface version.
    /// Initialization authority is restricted to kernel clients before readiness.
    ///
    /// # Errors
    /// Rejects stale/starting endpoints, unsupported versions and handle quotas.
    pub fn open(
        &mut self,
        owner: Actor,
        endpoint: EndpointId,
        interface: u32,
        major: u16,
        minor: u16,
    ) -> Result<u64, Error> {
        self.context(owner)?;
        let binding = self.endpoint(endpoint)?;
        if (interface == troe_abi::interface::SERVICE_LIFECYCLE && owner.slot() < TASKS)
            || major != 1
            || minor != 0
            || (interface != troe_abi::interface::SERVICE_LIFECYCLE && !binding.ready)
        {
            return Err(Error::Invalid);
        }
        self.endpoints
            .resolve_for(endpoint, interface, troe_dispatch::Rights::CALL)
            .map_err(|_| Error::Invalid)?;
        if self.free_handles(owner)? == 0 {
            return Err(Error::Exhausted);
        }
        let principal = self
            .context(owner)?
            .task
            .map_or(HandleOwner::Kernel, |task| {
                HandleOwner::IsolatedTask(task.get())
            });
        let badge = self
            .badges
            .open(endpoint.slot(), principal)
            .map_err(|_| Error::Exhausted)?;
        self.grant(
            owner,
            Grant::Call {
                endpoint,
                interface,
                major,
                minor,
                badge,
            },
        )
    }

    /// Validate and admit one call, preserving its absolute deadline.
    ///
    /// # Errors
    /// Invalid authority/scalars fault the caller; capacity/cycle/timeout become
    /// typed client results with no service-visible admission.
    #[allow(clippy::too_many_lines)]
    // Elide aggregate transition copies at the native trap boundary.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn call(&mut self, caller: Actor, call: Call, now: u64) -> Result<Transition, Error> {
        let c = self.context(caller)?;
        if c.outbound.is_some()
            || c.resume.is_some()
            || call.object_parameter != 0
            || call.request_bytes > 4096
            || call.reply_capacity > 4096
            || call.deadline_millis == u64::MAX
        {
            return Err(Error::Invalid);
        }
        let Grant::Call {
            endpoint,
            interface,
            major,
            minor,
            badge,
        } = self.handle(caller, call.handle)?
        else {
            return Err(Error::Invalid);
        };
        if major != 1 || minor != 0 {
            return Err(Error::Invalid);
        }
        // Resolve the endpoint generation once, then bind its immutable limits
        // and owning incarnation to this admission before any mutation.
        let limits = self
            .endpoints
            .resolve(endpoint)
            .map_err(|_| Error::Invalid)?
            .limits();
        let binding = self.bindings[endpoint.slot() as usize]
            .filter(|binding| binding.id == endpoint)
            .ok_or(Error::Invalid)?;
        if call.deadline_millis <= now {
            return self.immediate(caller, reply::TIMEOUT);
        }
        if !call.deadline_valid(now, u64::from(limits.deadline_millis())) {
            return Err(Error::Invalid);
        }
        let server = binding.server;
        if self
            .context(caller)?
            .task
            .is_some_and(|task| self.chains.depth(task) >= 4)
        {
            return self.immediate(caller, reply::EXHAUSTED);
        }
        let target = self.context(server)?;
        // A server with no outbound call cannot lead back to the caller.
        // Self-calls still fail, and queued/blocked targets retain the complete
        // transitive graph walk rather than only checking donated chains.
        if caller == server || (target.outbound.is_some() && self.cycle(caller, server)) {
            return self.immediate(caller, reply::DEADLOCK);
        }
        let direct = target.waiting
            && target.inbound.is_none()
            && target.outbound.is_none()
            && target.deadline > now
            && self.pending.queued_at(endpoint.slot()) == 0
            && !self.badges.has_closed(endpoint.slot())
            && self.direct_source(server, endpoint, now)?;
        if !direct
            && (self.pending.queued_at(endpoint.slot()) >= usize::from(limits.queued_calls())
                || self
                    .calls
                    .iter()
                    .flatten()
                    .filter(|p| {
                        p.endpoint == endpoint
                            && self.pending.payload_slot(p.id).ok().flatten().is_some()
                    })
                    .map(|p| u32::from(p.request_bytes))
                    .sum::<u32>()
                    .saturating_add(u32::from(call.request_bytes))
                    > limits.retained_bytes())
        {
            return self.immediate(caller, reply::EXHAUSTED);
        }
        let (from, to) = (self.context(caller)?.task, target.task);
        let chained = if direct {
            if let (Some(from), Some(to)) = (from, to) {
                match self.chains.enter(from, to) {
                    Ok(_) => true,
                    Err(CallChainError::Deadlock) => {
                        return self.immediate(caller, reply::DEADLOCK);
                    }
                    Err(_) => return self.immediate(caller, reply::EXHAUSTED),
                }
            } else {
                false
            }
        } else {
            false
        };
        let Ok((id, admission)) = self.pending.admit(
            endpoint.slot(),
            badge,
            interface,
            call.opcode,
            usize::from(call.request_bytes),
            usize::from(call.reply_capacity),
            call.deadline_millis,
            direct,
        ) else {
            if chained {
                self.chains
                    .unwind(to.ok_or(Error::Invalid)?)
                    .map_err(|_| Error::Invalid)?;
            }
            return self.immediate(caller, reply::EXHAUSTED);
        };
        let pending = Pending {
            id,
            caller,
            server,
            endpoint,
            badge,
            interface,
            deadline_millis: call.deadline_millis,
            opcode: call.opcode,
            request_bytes: call.request_bytes,
            reply_capacity: call.reply_capacity,
        };
        self.calls[id.slot() as usize] = Some(pending);
        self.contexts[caller.slot()].outbound = Some(id);
        let destination = if admission == Admission::Direct {
            self.delivered(pending)?;
            Buffer::Rx(server)
        } else {
            Buffer::Queue(
                self.pending
                    .payload_slot(id)
                    .map_err(|_| Error::Invalid)?
                    .ok_or(Error::Invalid)?,
            )
        };
        Ok(Transition {
            transfer: Some(Transfer {
                reply: false,
                source: Buffer::Tx(caller),
                destination,
                bytes: call.request_bytes,
            }),
            handoff: direct.then_some(server),
        })
    }

    /// Complete an exact reply and atomically publish the server's next wait.
    ///
    /// # Errors
    /// Stale, cancelled, oversized, foreign or transport-status replies fault
    /// the server before any client RX bytes are written.
    // Elide aggregate transition copies at the native trap boundary.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn reply_wait(
        &mut self,
        server: Actor,
        wait: ReplyWait,
        now: u64,
    ) -> Result<Transition, Error> {
        if let Err(error) = self.validate_reply(server, wait, now) {
            // A late/invalid reply cannot change an already due client fate
            // into peer-died when native containment tears down the server.
            self.expire(now)?;
            return Err(error);
        }
        if wait.token == 0 {
            self.contexts[server.slot()].deadline = wait.deadline_millis;
            self.expire(now)?;
            return self.observe_wait(server, now);
        }
        let id = self.context(server)?.inbound.ok_or(Error::Invalid)?;
        let p = self.pending_record(id)?;
        // All reply checks precede the first payload action. The newly requested
        // wait deadline has no effect on the call just completed.
        self.end_call(id, CallOutcome::Replied, wait.status, wait.reply_bytes)?;
        self.contexts[server.slot()].inbound = None;
        self.contexts[server.slot()].deadline = wait.deadline_millis;
        self.contexts[server.slot()].waiting = true;
        // The replied caller wins even when other endpoint work is pending.
        Ok(Transition {
            transfer: Some(Transfer {
                reply: true,
                source: Buffer::Tx(server),
                destination: Buffer::Rx(p.caller),
                bytes: wait.reply_bytes,
            }),
            handoff: Some(p.caller),
        })
    }

    /// Check every reply scalar without consuming a token or changing client fate.
    /// Native composition also validates page ownership before committing.
    ///
    /// # Errors
    /// Rejects stale authority, cancelled tokens, deadlines and invalid replies.
    // Inline checked metadata operations so the trap can reuse validated fields.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn validate_reply(&self, server: Actor, wait: ReplyWait, now: u64) -> Result<(), Error> {
        if !matches!(self.handle(server, wait.wait_set)?, Grant::Wait)
            || !reply::is_known(wait.status)
            || wait.reply_bytes > 4096
        {
            return Err(Error::Invalid);
        }
        let inbound = self.context(server)?.inbound;
        if wait.token == 0 {
            if inbound.is_some() || wait.status != 0 || wait.reply_bytes != 0 {
                return Err(Error::Invalid);
            }
            return Ok(());
        }
        let id = inbound.ok_or(Error::Invalid)?;
        if token(id) != wait.token {
            return Err(Error::Invalid);
        }
        let p = self.pending_record(id)?;
        if p.server != server || wait.reply_bytes > p.reply_capacity || p.deadline_millis <= now {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Match the immutable native startup grants to this runtime's authority.
    ///
    /// # Errors
    /// Rejects a foreign receive grant or wait set.
    pub fn validate_server_startup(
        &self,
        actor: Actor,
        receive: u64,
        wait: u64,
    ) -> Result<(), Error> {
        if !matches!(self.handle(actor, receive)?, Grant::Receive)
            || !matches!(self.handle(actor, wait)?, Grant::Wait)
            || self.context(actor)?.wait.is_none()
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Match a native client startup descriptor to its exact typed call grant.
    ///
    /// # Errors
    /// Rejects a foreign grant or mismatched interface version.
    pub fn validate_client_startup(
        &self,
        actor: Actor,
        value: u64,
        id: u32,
        ma: u16,
        mi: u16,
    ) -> Result<(), Error> {
        if !matches!(self.handle(actor, value)?, Grant::Call { interface, major, minor, .. }
            if (interface, major, minor) == (id, ma, mi))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Immutable task identity used to bind a native startup page to its actor.
    ///
    /// # Errors
    /// Rejects a retired or foreign actor.
    pub fn task(&self, actor: Actor) -> Result<Option<TaskId>, Error> {
        Ok(self.context(actor)?.task)
    }

    /// Whether an exact client grant still belongs to its original incarnation.
    #[must_use]
    pub fn has_handle(&self, owner: Actor, value: u64) -> bool {
        self.handle(owner, value).is_ok()
    }

    /// Observe source readiness before publishing an immutable wait.
    ///
    /// # Errors
    /// Rejects a foreign/stale set or inconsistent delivery accounting.
    pub fn observe_wait(&mut self, server: Actor, now: u64) -> Result<Transition, Error> {
        let c = self.context(server)?;
        let set = c.wait.as_ref().ok_or(Error::Invalid)?;
        let readiness = self.readiness(set)?;
        let selection = set
            .select(&readiness[..set.len()], c.deadline <= now)
            .map_err(|_| Error::Invalid)?;
        let Some(selection) = selection else {
            self.contexts[server.slot()].waiting = true;
            return Ok(Transition::default());
        };
        let mut event = Event {
            kind: EventKind::Deadline,
            token: 0,
            source: 0,
            badge: 0,
            interface: 0,
            opcode: 0,
            request_bytes: 0,
            reply_capacity: 0,
        };
        match selection {
            WaitSelection::Deadline => {}
            WaitSelection::Terminal { index, .. } => {
                event.kind = EventKind::Revoked;
                event.source = u16::from(index);
            }
            WaitSelection::Ready { index } => {
                let source = set.sources()[usize::from(index)];
                let slot = u32::try_from(source.identity() - 1).map_err(|_| Error::Invalid)?;
                if let Some(badge) = self.badges.take_closed(slot).map_err(|_| Error::Invalid)? {
                    event.kind = EventKind::ClientClosed;
                    event.source = u16::from(index);
                    event.badge = u32::try_from(badge.event_value()).map_err(|_| Error::Invalid)?;
                } else {
                    let next = self.pending.next_queued(slot).ok_or(Error::Invalid)?;
                    let p = self.pending_record(next)?;
                    if let (Some(caller), Some(target)) =
                        (self.context(p.caller)?.task, self.context(server)?.task)
                    {
                        match self.chains.enter(caller, target) {
                            Ok(_) => {}
                            Err(error) => {
                                let status = if error == CallChainError::Deadlock {
                                    reply::DEADLOCK
                                } else {
                                    reply::EXHAUSTED
                                };
                                self.end_call(next, CallOutcome::Cancelled, status, 0)?;
                                return Ok(Transition::default());
                            }
                        }
                    }
                    let delivery = self
                        .pending
                        .deliver_next(slot)
                        .map_err(|_| Error::Invalid)?
                        .ok_or(Error::Invalid)?;
                    let p = self.pending_record(delivery.call)?;
                    if p.deadline_millis <= now {
                        return Err(Error::Invalid);
                    }
                    self.delivered(p)?;
                    let queue = delivery.payload.ok_or(Error::Invalid)?;
                    self.mark_dirty(queue);
                    return Ok(Transition {
                        transfer: Some(Transfer {
                            reply: false,
                            source: Buffer::Queue(queue),
                            destination: Buffer::Rx(server),
                            bytes: p.request_bytes,
                        }),
                        handoff: Some(server),
                    });
                }
                self.contexts[server.slot()]
                    .wait
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .record_delivery(index)
                    .map_err(|_| Error::Invalid)?;
            }
        }
        self.contexts[server.slot()].resume = Some(Resume::Event(event));
        self.contexts[server.slot()].waiting = false;
        Ok(Transition {
            transfer: None,
            handoff: Some(server),
        })
    }

    /// Close an exact client handle. The last handle cancels badge-owned calls
    /// before its mandatory closure event becomes observable.
    ///
    /// # Errors
    /// Rejects a stale, foreign or non-client handle.
    pub fn close(&mut self, owner: Actor, value: u64) -> Result<(), Error> {
        let Grant::Call { badge, .. } = self.handle(owner, value)? else {
            return Err(Error::Invalid);
        };
        if self.badges.handles(badge).map_err(|_| Error::Invalid)? == 1 {
            for index in 0..CALLS {
                if let Some(p) = self.calls[index]
                    && p.badge == badge
                {
                    self.end_call(p.id, CallOutcome::Cancelled, reply::CANCELLED, 0)?;
                }
            }
        }
        self.close_index(
            ((u32::try_from(value & u64::from(u32::MAX)).map_err(|_| Error::Invalid)?) - 1)
                as usize,
        )
    }

    /// Observe waiting servers after time advances or another task publishes work.
    ///
    /// # Errors
    /// Propagates inconsistent wait state. Each result must be committed before
    /// asking for another transition.
    pub fn poll_waits(&mut self, now: u64) -> Result<Transition, Error> {
        self.expire(now)?;
        for offset in 0..TASKS {
            let slot = (self.wait_cursor + offset) % TASKS;
            let c = &self.contexts[slot];
            if c.occupied && c.waiting && c.inbound.is_none() && c.outbound.is_none() {
                let actor = Actor {
                    slot: u32::try_from(slot).map_err(|_| Error::Invalid)?,
                    generation: NonZeroU32::new(c.generation).ok_or(Error::Invalid)?,
                };
                let transition = self.observe_wait(actor, now)?;
                if transition.handoff.is_some() {
                    self.wait_cursor = (slot + 1) % TASKS;
                    return Ok(transition);
                }
            }
        }
        Ok(Transition::default())
    }

    /// Cancel one caller without replaying a delivered request.
    ///
    /// # Errors
    /// Rejects a stale actor. Repeated cancellation has no additional effect.
    pub fn cancel(&mut self, caller: Actor) -> Result<(), Error> {
        if let Some(id) = self.context(caller)?.outbound {
            self.end_call(id, CallOutcome::Cancelled, reply::CANCELLED, 0)?;
        }
        Ok(())
    }

    /// Resolve all elapsed absolute call deadlines before scheduling work.
    ///
    /// # Errors
    /// Returns inconsistent internal accounting; no deadline is ever extended.
    pub fn expire(&mut self, now: u64) -> Result<(), Error> {
        while let Some(id) = self.pending.due(now) {
            self.end_call(id, CallOutcome::TimedOut, reply::TIMEOUT, 0)?;
        }
        Ok(())
    }

    /// Stop admission and revoke all incarnation-owned transport state.
    /// Composition reclaims frames/tags only after zeroing returned dirty slots.
    ///
    /// # Errors
    /// Rejects stale actors or inconsistent ownership accounting.
    pub fn terminate(&mut self, actor: Actor, clean: bool) -> Result<(), Error> {
        self.context(actor)?;
        self.contexts[actor.slot()].terminal = true;
        for index in 0..self.bindings.len() {
            if let Some(endpoint) = self.bindings[index]
                && endpoint.server == actor
            {
                self.endpoints
                    .close(endpoint.id)
                    .map_err(|_| Error::Invalid)?;
                self.bindings[index] = None;
                for handle_index in 0..HANDLES {
                    if let Some(Handle {
                        grant: Grant::Call { endpoint: id, .. },
                        ..
                    }) = self.handles[handle_index].handle
                        && id == endpoint.id
                    {
                        self.close_index(handle_index)?;
                    }
                }
                while self
                    .badges
                    .take_closed(endpoint.id.slot())
                    .map_err(|_| Error::Invalid)?
                    .is_some()
                {}
            }
        }
        for index in 0..CALLS {
            if let Some(p) = self.calls[index] {
                if p.server == actor {
                    self.end_call(
                        p.id,
                        CallOutcome::PeerDied,
                        if clean {
                            reply::CLOSED
                        } else {
                            reply::PEER_DIED
                        },
                        0,
                    )?;
                } else if p.caller == actor {
                    self.end_call(p.id, CallOutcome::Cancelled, reply::CANCELLED, 0)?;
                }
            }
        }
        for index in 0..HANDLES {
            if self.handles[index].handle.is_some_and(|h| h.owner == actor) {
                self.close_index(index)?;
            }
        }
        let c = &mut self.contexts[actor.slot()];
        c.wait = None;
        c.waiting = false;
        c.inbound = None;
        c.resume = None;
        c.occupied = false;
        Ok(())
    }

    /// Whether this incarnation still owns a nonterminal context.
    #[must_use]
    pub fn is_live(&self, actor: Actor) -> bool {
        self.context(actor).is_ok()
    }

    /// Read a completion without consuming its single delivery.
    ///
    /// # Errors
    /// Rejects stale or terminal actors.
    pub fn peek_resume(&self, actor: Actor) -> Result<Option<Resume>, Error> {
        Ok(self.context(actor)?.resume)
    }

    /// Portable admission and terminal-fate accounting.
    #[must_use]
    pub const fn stats(&self) -> troe_dispatch::PendingCallStats {
        self.pending.stats()
    }

    /// Take one completion exactly once, before the matching context resumes.
    ///
    /// # Errors
    /// Rejects stale/terminal actors.
    // Keep the scalar completion in registers at the native handoff boundary.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn take_resume(&mut self, actor: Actor) -> Result<Option<Resume>, Error> {
        self.context(actor)?;
        Ok(self.contexts[actor.slot()].resume.take())
    }

    /// Round-robin slow scheduling; direct transitions never call this method.
    #[must_use]
    pub fn select(&mut self) -> Option<Actor> {
        for offset in 0..ACTORS {
            let slot = (self.cursor + offset) % ACTORS;
            let c = &self.contexts[slot];
            if c.occupied && !c.terminal && !c.waiting && c.outbound.is_none() {
                self.cursor = (slot + 1) % ACTORS;
                return Some(Actor {
                    slot: u32::try_from(slot).ok()?,
                    generation: NonZeroU32::new(c.generation)?,
                });
            }
        }
        None
    }

    /// Queue slots whose entire storage must be zeroed before recycling.
    #[must_use]
    // Direct calls have no dirty slot; avoid an out-of-line empty-table probe.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn dirty_queue(&self) -> Option<QueueSlotId> {
        if self.dirty_count == 0 {
            return None;
        }
        self.dirty.iter().flatten().next().copied()
    }

    /// Acknowledge native zeroization after copy or cancellation.
    ///
    /// # Errors
    /// Rejects stale or duplicate acknowledgements.
    pub fn recycled(&mut self, slot: QueueSlotId) -> Result<(), Error> {
        let dirty = self
            .dirty
            .get_mut(slot.index() as usize)
            .ok_or(Error::Invalid)?;
        if *dirty != Some(slot) {
            return Err(Error::Invalid);
        }
        self.pending.recycle(slot).map_err(|_| Error::Invalid)?;
        *dirty = None;
        self.dirty_count -= 1;
        Ok(())
    }

    /// Current exact transport ownership counts.
    #[must_use]
    pub fn live(&self) -> Live {
        Live {
            contexts: self.contexts.iter().filter(|c| c.occupied).count(),
            endpoints: self.endpoints.stats().live,
            handles: self.handles.iter().filter(|h| h.handle.is_some()).count(),
            calls: self.pending.stats().live,
            waits: self.contexts.iter().filter(|c| c.waiting).count(),
            dirty_queues: self.dirty.iter().flatten().count(),
        }
    }

    fn mark_dirty(&mut self, slot: QueueSlotId) {
        let dirty = &mut self.dirty[slot.index() as usize];
        if dirty.is_none() {
            self.dirty_count += 1;
        }
        *dirty = Some(slot);
    }

    fn readiness(&self, set: &WaitSet) -> Result<[SourceReadiness; 4], Error> {
        let mut readiness = [SourceReadiness::Idle; 4];
        for (index, source) in set.sources().iter().enumerate() {
            let endpoint = self.bindings
                [usize::try_from(source.identity() - 1).map_err(|_| Error::Invalid)?];
            readiness[index] = match endpoint {
                Some(e) if e.id.generation() == source.generation() => {
                    if self.badges.has_closed(e.id.slot())
                        || self.pending.queued_at(e.id.slot()) != 0
                    {
                        SourceReadiness::Ready
                    } else {
                        SourceReadiness::Idle
                    }
                }
                _ => SourceReadiness::Revoked,
            };
        }
        Ok(readiness)
    }
    // Inline checked metadata operations so the trap can reuse validated fields.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn direct_source(&self, server: Actor, endpoint: EndpointId, now: u64) -> Result<bool, Error> {
        let c = self.context(server)?;
        let set = c.wait.as_ref().ok_or(Error::Invalid)?;
        let Some(index) = set.sources().iter().position(|source| {
            source.identity() == u64::from(endpoint.slot()) + 1
                && source.generation() == endpoint.generation()
        }) else {
            return Err(Error::Invalid);
        };
        // Admission already validated this endpoint and excluded queued calls
        // and mandatory closures. With one immutable source there is no other
        // terminal/ready source to arbitrate; retain the absolute deadline check.
        if set.len() == 1 {
            return Ok(c.deadline > now);
        }
        let mut readiness = self.readiness(set)?;
        readiness[index] = SourceReadiness::Ready;
        Ok(set
            .select(&readiness[..set.len()], c.deadline <= now)
            .map_err(|_| Error::Invalid)?
            == Some(WaitSelection::Ready {
                index: u8::try_from(index).map_err(|_| Error::Invalid)?,
            }))
    }

    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn context(&self, actor: Actor) -> Result<&Context, Error> {
        self.contexts
            .get(actor.slot())
            .filter(|c| c.occupied && !c.terminal && c.generation == actor.generation.get())
            .ok_or(Error::Invalid)
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn endpoint(&self, id: EndpointId) -> Result<Endpoint, Error> {
        self.endpoints.resolve(id).map_err(|_| Error::Invalid)?;
        self.bindings[id.slot() as usize]
            .filter(|e| e.id == id)
            .ok_or(Error::Invalid)
    }
    fn free_handles(&self, owner: Actor) -> Result<usize, Error> {
        self.context(owner)?;
        let count = self
            .handles
            .iter()
            .filter(|h| h.handle.is_some_and(|h| h.owner == owner))
            .count();
        Ok((32 - count).min(
            self.handles
                .iter()
                .filter(|h| h.handle.is_none() && h.generation != u32::MAX)
                .count(),
        ))
    }
    fn grant(&mut self, owner: Actor, grant: Grant) -> Result<u64, Error> {
        if self.free_handles(owner)? == 0 {
            return Err(Error::Exhausted);
        }
        let index = self
            .handles
            .iter()
            .position(|h| h.handle.is_none() && h.generation != u32::MAX)
            .ok_or(Error::Exhausted)?;
        let slot = &mut self.handles[index];
        slot.generation += 1;
        slot.handle = Some(Handle { owner, grant });
        Ok((u64::from(slot.generation) << 32) | (index as u64 + 1))
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn handle(&self, owner: Actor, value: u64) -> Result<Grant, Error> {
        self.context(owner)?;
        let index = (u32::try_from(value & u64::from(u32::MAX)).map_err(|_| Error::Invalid)?)
            .checked_sub(1)
            .ok_or(Error::Invalid)? as usize;
        let slot = self
            .handles
            .get(index)
            .filter(|h| u64::from(h.generation) == value >> 32)
            .ok_or(Error::Invalid)?;
        slot.handle
            .filter(|h| h.owner == owner)
            .map(|h| h.grant)
            .ok_or(Error::Invalid)
    }
    fn close_index(&mut self, index: usize) -> Result<(), Error> {
        if let Some(h) = self.handles[index].handle.take()
            && let Grant::Call { badge, .. } = h.grant
        {
            self.badges
                .close_handle(badge)
                .map_err(|_| Error::Invalid)?;
        }
        Ok(())
    }
    fn immediate(&mut self, caller: Actor, status: u32) -> Result<Transition, Error> {
        self.context(caller)?;
        self.contexts[caller.slot()].resume = Some(Resume::Reply { status, bytes: 0 });
        Ok(Transition {
            transfer: None,
            handoff: Some(caller),
        })
    }
    // Keep checked metadata access inside the measured trap path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn pending_record(&self, id: CallId) -> Result<Pending, Error> {
        self.calls
            .get(id.slot() as usize)
            .copied()
            .flatten()
            .filter(|p| p.id == id)
            .ok_or(Error::Invalid)
    }
    // Inline checked metadata operations so the trap can reuse validated fields.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn delivered(&mut self, p: Pending) -> Result<(), Error> {
        let c = &mut self.contexts[p.server.slot()];
        let set = c.wait.as_mut().ok_or(Error::Invalid)?;
        let index = set
            .sources()
            .iter()
            .position(|s| {
                s.identity() == u64::from(p.endpoint.slot()) + 1
                    && s.generation() == p.endpoint.generation()
            })
            .ok_or(Error::Invalid)?;
        set.record_delivery(u8::try_from(index).map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Invalid)?;
        c.inbound = Some(p.id);
        c.waiting = false;
        c.resume = Some(Resume::Event(Event {
            kind: EventKind::Call,
            token: token(p.id),
            source: u16::try_from(index).map_err(|_| Error::Invalid)?,
            badge: u32::try_from(p.badge.event_value()).map_err(|_| Error::Invalid)?,
            interface: p.interface,
            opcode: p.opcode,
            request_bytes: p.request_bytes,
            reply_capacity: p.reply_capacity,
        }));
        Ok(())
    }
    // Inline checked metadata operations so the trap can reuse validated fields.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn end_call(
        &mut self,
        id: CallId,
        outcome: CallOutcome,
        status: u32,
        bytes: u16,
    ) -> Result<(), Error> {
        let p = self.pending_record(id)?;
        let queue = self
            .pending
            .complete(id, outcome)
            .map_err(|_| Error::Invalid)?;
        if let Some(slot) = queue {
            self.mark_dirty(slot);
        }
        self.calls[id.slot() as usize] = None;
        let c = &mut self.contexts[p.caller.slot()];
        c.outbound = None;
        c.resume = Some(Resume::Reply { status, bytes });
        if self.contexts[p.server.slot()].inbound == Some(id)
            && let Some(task) = self.contexts[p.server.slot()].task
            && let Some(active) = self.chains.active(task)
        {
            if active == task {
                self.chains.unwind(task).map_err(|_| Error::Invalid)?;
            } else {
                self.chains.detach(task).map_err(|_| Error::Invalid)?;
            }
        }
        Ok(())
    }
    fn cycle(&self, caller: Actor, server: Actor) -> bool {
        let mut target = server;
        for _ in 0..ACTORS {
            if target == caller {
                return true;
            }
            let Some(id) = self.contexts[target.slot()].outbound else {
                return false;
            };
            let Ok(pending) = self.pending_record(id) else {
                return true;
            };
            target = pending.server;
        }
        true
    }
}

fn token(call: CallId) -> u64 {
    (u64::from(call.generation()) << 32) | (u64::from(call.slot()) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use troe_task::{Capabilities, Scheduler, StackResource};

    fn actors(runtime: &mut Runtime, count: u32) -> Vec<Actor> {
        let mut scheduler = Scheduler::new(count as usize).unwrap_or_else(|_| unreachable!());
        (0..count)
            .map(|i| {
                let task = scheduler
                    .spawn(
                        Capabilities::SERVICE,
                        StackResource::new(i, 1).unwrap_or_else(|_| unreachable!()),
                    )
                    .unwrap_or_else(|_| unreachable!());
                runtime
                    .attach(Some(task))
                    .unwrap_or_else(|_| unreachable!())
            })
            .collect()
    }
    fn server(r: &mut Runtime, actor: Actor) -> (EndpointId, u64) {
        let e = r
            .bind(
                actor,
                InterfaceSet::new(&[
                    troe_abi::interface::DIAGNOSTICS,
                    troe_abi::interface::SERVICE_LIFECYCLE,
                ])
                .unwrap_or_else(|_| unreachable!()),
                EndpointLimits::STANDARD,
            )
            .unwrap_or_else(|_| unreachable!());
        let (_, wait) = r
            .configure_wait(actor, &[e])
            .unwrap_or_else(|_| unreachable!());
        r.reply_wait(actor, idle(wait), 0)
            .unwrap_or_else(|_| unreachable!());
        r.ready(e).unwrap_or_else(|_| unreachable!());
        (e, wait)
    }
    fn idle(wait_set: u64) -> ReplyWait {
        ReplyWait {
            wait_set,
            token: 0,
            status: 0,
            reply_bytes: 0,
            deadline_millis: u64::MAX,
        }
    }
    fn call(handle: u64) -> Call {
        Call {
            handle,
            opcode: 1,
            request_bytes: 64,
            reply_capacity: 64,
            deadline_millis: 4000,
            object_parameter: 0,
        }
    }
    fn open(r: &mut Runtime, a: Actor, e: EndpointId) -> u64 {
        r.open(a, e, troe_abi::interface::DIAGNOSTICS, 1, 0)
            .unwrap_or_else(|_| unreachable!())
    }
    fn event(r: &mut Runtime, a: Actor) -> Event {
        let Some(Resume::Event(e)) = r.take_resume(a).unwrap_or_else(|_| unreachable!()) else {
            unreachable!()
        };
        e
    }
    fn reply_to(r: &mut Runtime, a: Actor, wait: u64, event: Event) -> Transition {
        r.reply_wait(
            a,
            ReplyWait {
                token: event.token,
                reply_bytes: event.request_bytes,
                ..idle(wait)
            },
            1,
        )
        .unwrap_or_else(|_| unreachable!())
    }
    fn clean_queues(r: &mut Runtime) {
        while let Some(q) = r.dirty_queue() {
            r.recycled(q).unwrap_or_else(|_| unreachable!());
        }
    }

    #[test]
    fn nested_direct_replies_resume_immediate_callers_and_keep_deadlines() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 4);
        let (one, w1) = server(&mut r, a[1]);
        let (two, w2) = server(&mut r, a[2]);
        let h1 = open(&mut r, a[0], one);
        let h2 = open(&mut r, a[1], two);
        assert_eq!(r.call(a[0], call(h1), 0).map(|s| s.handoff), Ok(Some(a[1])));
        let e1 = event(&mut r, a[1]);
        assert_eq!(r.call(a[1], call(h2), 0).map(|s| s.handoff), Ok(Some(a[2])));
        let e2 = event(&mut r, a[2]);
        assert_eq!(reply_to(&mut r, a[2], w2, e2).handoff, Some(a[1]));
        assert_eq!(reply_to(&mut r, a[1], w1, e1).handoff, Some(a[0]));
        assert_eq!(r.live().calls, 0);
        assert_eq!(r.chains.stats().live, 0);
        assert_eq!(r.pending.stats().direct_admissions, 2);
        assert_eq!(r.pending.stats().queue_slots_consumed, 0);
    }

    #[test]
    fn immutable_wait_arbitration_prevents_direct_calls_bypassing_another_source() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 3);
        let endpoints = [0, 1].map(|_| {
            r.bind(
                a[1],
                InterfaceSet::new(&[troe_abi::interface::DIAGNOSTICS])
                    .unwrap_or_else(|_| unreachable!()),
                EndpointLimits::STANDARD,
            )
            .unwrap_or_else(|_| unreachable!())
        });
        let (_, wait) = r
            .configure_wait(a[1], &endpoints)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(r.configure_wait(a[1], &endpoints), Err(Error::Invalid));
        r.reply_wait(a[1], idle(wait), 0)
            .unwrap_or_else(|_| unreachable!());
        for endpoint in endpoints {
            r.ready(endpoint).unwrap_or_else(|_| unreachable!());
        }
        let first = open(&mut r, a[0], endpoints[0]);
        let second = open(&mut r, a[2], endpoints[1]);
        r.call(a[0], call(first), 0)
            .unwrap_or_else(|_| unreachable!());
        let received = event(&mut r, a[1]);
        assert_eq!(received.source, 0);
        r.call(a[2], call(second), 0)
            .unwrap_or_else(|_| unreachable!());
        reply_to(&mut r, a[1], wait, received);
        r.take_resume(a[0]).unwrap_or_else(|_| unreachable!());
        assert_eq!(r.call(a[0], call(first), 1).map(|t| t.handoff), Ok(None));
        r.poll_waits(1).unwrap_or_else(|_| unreachable!());
        let received = event(&mut r, a[1]);
        assert_eq!(received.source, 1);
        reply_to(&mut r, a[1], wait, received);
        clean_queues(&mut r);
        r.poll_waits(1).unwrap_or_else(|_| unreachable!());
        assert_eq!(event(&mut r, a[1]).source, 0);
    }

    #[test]
    fn queued_cancel_does_not_detach_an_unrelated_donated_chain() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 3);
        let (e, wait) = server(&mut r, a[1]);
        let h1 = open(&mut r, a[0], e);
        let h2 = open(&mut r, a[2], e);
        r.call(a[0], call(h1), 0).unwrap_or_else(|_| unreachable!());
        let received = event(&mut r, a[1]);
        assert_eq!(r.call(a[2], call(h2), 0).map(|s| s.handoff), Ok(None));
        r.cancel(a[2]).unwrap_or_else(|_| unreachable!());
        assert_eq!(r.chains.stats().live, 1);
        assert_eq!(r.live().dirty_queues, 1);
        clean_queues(&mut r);
        assert_eq!(reply_to(&mut r, a[1], wait, received).handoff, Some(a[0]));
        assert_eq!(
            r.take_resume(a[2]),
            Ok(Some(Resume::Reply {
                status: reply::CANCELLED,
                bytes: 0
            }))
        );
        r.cancel(a[2]).unwrap_or_else(|_| unreachable!());
        assert_eq!(r.take_resume(a[2]), Ok(None));
    }

    #[test]
    fn fifo_delivery_and_full_queue_are_atomic() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 11);
        let (e, wait) = server(&mut r, a[0]);
        let handles: Vec<_> = a[1..].iter().map(|actor| open(&mut r, *actor, e)).collect();
        for (index, handle) in handles.iter().enumerate() {
            r.call(a[index + 1], call(*handle), 0)
                .unwrap_or_else(|_| unreachable!());
        }
        assert_eq!(r.live().calls, 9);
        assert_eq!(
            r.take_resume(a[10]),
            Ok(Some(Resume::Reply {
                status: reply::EXHAUSTED,
                bytes: 0
            }))
        );
        for client in 1..10 {
            let received = event(&mut r, a[0]);
            assert_eq!(
                reply_to(&mut r, a[0], wait, received).handoff,
                Some(a[client])
            );
            r.poll_waits(2).unwrap_or_else(|_| unreachable!());
            clean_queues(&mut r);
        }
        assert_eq!(r.live().calls, 0);
        assert_eq!(r.live().dirty_queues, 0);
    }

    #[test]
    fn cancellation_deadline_and_reply_have_one_consumer() {
        for cancelled in [false, true] {
            let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
            let a = actors(&mut r, 2);
            let (e, wait) = server(&mut r, a[1]);
            let h = open(&mut r, a[0], e);
            r.call(a[0], call(h), 0).unwrap_or_else(|_| unreachable!());
            let received = event(&mut r, a[1]);
            if cancelled {
                r.cancel(a[0]).unwrap_or_else(|_| unreachable!());
            }
            // A late reply itself establishes timeout before fault containment;
            // no prior scheduler poll is needed to preserve the client fate.
            assert_eq!(
                r.reply_wait(
                    a[1],
                    ReplyWait {
                        token: received.token,
                        reply_bytes: 64,
                        ..idle(wait)
                    },
                    4000
                ),
                Err(Error::Invalid)
            );
            r.terminate(a[1], false).unwrap_or_else(|_| unreachable!());
            assert_eq!(
                r.take_resume(a[0]),
                Ok(Some(Resume::Reply {
                    status: if cancelled {
                        reply::CANCELLED
                    } else {
                        reply::TIMEOUT
                    },
                    bytes: 0
                }))
            );
            assert_eq!(r.take_resume(a[0]), Ok(None));
            assert_eq!(r.live().calls, 0);
        }
    }

    #[test]
    fn teardown_invalidates_waits_handles_tokens_and_reused_contexts() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 3);
        let (e, _) = server(&mut r, a[1]);
        let h1 = open(&mut r, a[0], e);
        let h2 = open(&mut r, a[2], e);
        r.call(a[0], call(h1), 0).unwrap_or_else(|_| unreachable!());
        r.call(a[2], call(h2), 0).unwrap_or_else(|_| unreachable!());
        r.terminate(a[1], false).unwrap_or_else(|_| unreachable!());
        clean_queues(&mut r);
        assert_eq!(
            r.live(),
            Live {
                contexts: 2,
                ..Live::default()
            }
        );
        for client in [a[0], a[2]] {
            assert_eq!(
                r.take_resume(client),
                Ok(Some(Resume::Reply {
                    status: reply::PEER_DIED,
                    bytes: 0
                }))
            );
        }
        assert_eq!(r.call(a[0], call(h1), 0), Err(Error::Invalid));
        let fresh = r
            .attach(r.contexts[a[1].slot()].task)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(fresh.slot(), a[1].slot());
        assert_ne!(fresh, a[1]);
        assert_eq!(r.take_resume(a[1]), Err(Error::Invalid));
        let (new_endpoint, wait) = server(&mut r, fresh);
        assert_ne!(e, new_endpoint);
        let handle = open(&mut r, a[0], new_endpoint);
        r.call(a[0], call(handle), 0)
            .unwrap_or_else(|_| unreachable!());
        let received = event(&mut r, fresh);
        reply_to(&mut r, fresh, wait, received);
        assert_eq!(
            r.take_resume(a[0]),
            Ok(Some(Resume::Reply {
                status: 0,
                bytes: 64
            }))
        );
    }
    #[test]
    fn eight_servers_and_per_owner_handles_are_hard_limits() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 10);
        let mut endpoints = Vec::new();
        for actor in &a[..8] {
            endpoints.push(server(&mut r, *actor).0);
        }
        let before = r.live();
        assert_eq!(
            r.bind(
                a[8],
                InterfaceSet::new(&[troe_abi::interface::DIAGNOSTICS])
                    .unwrap_or_else(|_| unreachable!()),
                EndpointLimits::STANDARD
            ),
            Err(Error::Exhausted)
        );
        assert_eq!(r.live(), before);
        for _ in 0..32 {
            open(&mut r, a[9], endpoints[0]);
        }
        let before = r.live();
        assert_eq!(
            r.open(a[9], endpoints[0], troe_abi::interface::DIAGNOSTICS, 1, 0),
            Err(Error::Exhausted)
        );
        assert_eq!(r.live(), before);
    }

    #[test]
    fn reply_validation_cannot_complete_or_consume_a_client() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 2);
        let (e, wait) = server(&mut r, a[1]);
        let h = open(&mut r, a[0], e);
        r.call(a[0], call(h), 0).unwrap_or_else(|_| unreachable!());
        let event = event(&mut r, a[1]);
        let valid = ReplyWait {
            token: event.token,
            reply_bytes: 64,
            ..idle(wait)
        };
        let before = r.live();
        assert_eq!(r.validate_reply(a[1], valid, 1), Ok(()));
        assert_eq!(r.live(), before);
        assert_eq!(r.peek_resume(a[0]), Ok(None));
        for status in reply::CLOSED..=reply::DEADLOCK {
            assert_eq!(
                r.validate_reply(a[1], ReplyWait { status, ..valid }, 1),
                Err(Error::Invalid)
            );
        }
        r.terminate(a[1], false).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            r.take_resume(a[0]),
            Ok(Some(Resume::Reply {
                status: reply::PEER_DIED,
                bytes: 0
            }))
        );
        assert_eq!(r.take_resume(a[0]), Ok(None));
        assert_eq!(r.stats().replied, 0);
    }

    #[test]
    fn idle_self_calls_and_cycles_through_queued_calls_are_rejected() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 2);
        let (first, _) = server(&mut r, a[0]);
        let (second, wait) = server(&mut r, a[1]);
        let own = open(&mut r, a[0], first);
        r.call(a[0], call(own), 0)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            r.take_resume(a[0]),
            Ok(Some(Resume::Reply {
                status: reply::DEADLOCK,
                bytes: 0
            }))
        );
        assert_eq!(r.live().calls, 0);

        // Wake the second server without an inbound call, so the first call
        // queues instead of forming a donated chain.
        let expired = ReplyWait {
            deadline_millis: 1,
            ..idle(wait)
        };
        r.reply_wait(a[1], expired, 1)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(event(&mut r, a[1]).kind, EventKind::Deadline);
        let forward = open(&mut r, a[0], second);
        assert_eq!(r.call(a[0], call(forward), 2).map(|t| t.handoff), Ok(None));
        let back = open(&mut r, a[1], first);
        r.call(a[1], call(back), 2)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            r.take_resume(a[1]),
            Ok(Some(Resume::Reply {
                status: reply::DEADLOCK,
                bytes: 0
            }))
        );
        assert_eq!(r.live().calls, 1);
        r.reply_wait(a[1], idle(wait), 2)
            .unwrap_or_else(|_| unreachable!());
        let received = event(&mut r, a[1]);
        r.reply_wait(
            a[1],
            ReplyWait {
                token: received.token,
                reply_bytes: 8,
                ..idle(wait)
            },
            3,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            r.take_resume(a[0]),
            Ok(Some(Resume::Reply {
                status: 0,
                bytes: 8
            }))
        );
        clean_queues(&mut r);
        assert_eq!(r.live().calls, 0);
    }

    #[test]
    fn depth_cycle_and_middle_death_preserve_exact_fates() {
        let mut r = Runtime::new().unwrap_or_else(|_| unreachable!());
        let a = actors(&mut r, 5);
        let endpoints: Vec<_> = a.iter().map(|actor| server(&mut r, *actor).0).collect();
        for index in 0..3 {
            let h = open(&mut r, a[index], endpoints[index + 1]);
            assert_eq!(
                r.call(a[index], call(h), 0).map(|t| t.handoff),
                Ok(Some(a[index + 1]))
            );
            event(&mut r, a[index + 1]);
        }
        let h = open(&mut r, a[3], endpoints[4]);
        r.call(a[3], call(h), 0).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            r.take_resume(a[3]),
            Ok(Some(Resume::Reply {
                status: reply::EXHAUSTED,
                bytes: 0
            }))
        );
        r.terminate(a[2], false).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            r.take_resume(a[1]),
            Ok(Some(Resume::Reply {
                status: reply::PEER_DIED,
                bytes: 0
            }))
        );
        assert_eq!(r.live().calls, 1);
        assert_eq!(r.chains.stats().live, 0);
        r.terminate(a[1], false).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            r.take_resume(a[0]),
            Ok(Some(Resume::Reply {
                status: reply::PEER_DIED,
                bytes: 0
            }))
        );
        assert_eq!(r.live().calls, 0);
    }
}

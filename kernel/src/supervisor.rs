//! Persistent boot-service ownership, initialization and bounded replacement.

use crate::artifacts::native_application_target;
use crate::machine::OwnedAccounting;
use crate::memory::ApplicationAllocation;
use crate::memory::launch::{
    allocate_application, prepare_application_memory, reclaim_application,
};
use alloc::boxed::Box;
use troe_application::{InitialHandle, StartupInfo, parse_kex, parse_kex_package};
use troe_dispatch::{EndpointId, EndpointLimits, InterfaceSet};
use troe_machine::{ApplicationOutcome, ProtectedRuntime, ProtectedStop};
use troe_service::ipc::Actor;
use troe_service::{
    Incarnation, RestartPolicy, ServiceEvent, ServiceRecord, ServiceRole, ServiceState,
    ServiceSupervisor,
};
use troe_task::{
    Capabilities, IsolationResource, MonotonicMillis, PendingOperationId, Scheduler, StackResource,
    TaskId, WaitKey, WaitObservation, WaitRegistration, WaitResource, WaitSpec, WaitTable,
    WakeInterest, WakeReason,
};

#[cfg(feature = "acceptance-probes")]
pub(crate) mod benchmark;
#[cfg(feature = "acceptance-probes")]
pub(crate) mod probes;

const ROLE: ServiceRole = ServiceRole::Diagnostics;
const SERVICE_SLOT_BASE: u32 = crate::limits::SHELL_SCHEDULER_SLOT + 1;

pub(crate) struct Instance {
    pub(crate) actor: Actor,
    pub(crate) task: TaskId,
    pub(crate) endpoint: EndpointId,
    pub(crate) ticket: Incarnation,
    pub(crate) allocation: ApplicationAllocation,
    wait: Option<WaitKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClientKey {
    pub(crate) task: TaskId,
    pub(crate) operation: PendingOperationId,
}

pub(crate) struct Client {
    pub(crate) actor: Actor,
    pub(crate) key: Option<ClientKey>,
    pub(crate) handle: Option<u64>,
    pub(crate) continuation: Option<troe_service::KernelContinuation>,
}

#[derive(Clone, Copy)]
pub(crate) struct ServerSpec {
    pub(crate) record: ServiceRecord,
    pub(crate) artifact: &'static [u8],
    /// An earlier initialized role to which this service may make nested calls.
    pub(crate) nested: Option<usize>,
}

pub(crate) struct Supervisor {
    pub(crate) runtime: Option<ProtectedRuntime>,
    pub(crate) lifecycle: ServiceSupervisor,
    specs: alloc::vec::Vec<ServerSpec>,
    pub(crate) instances: [Option<Instance>; troe_service::MAX_BOOT_SERVICES],
    pub(crate) clients: [Client; 4],
    pub(crate) next: Option<Actor>,
    initializing: Option<(usize, usize)>,
    waits: WaitTable,
    next_wait_operation: u32,
    shutting_down: bool,
    shutdown: Option<(usize, usize, bool)>,
}

fn artifact() -> &'static [u8] {
    #[cfg(target_arch = "aarch64")]
    {
        include_bytes!("../../tests/kex-corpus/aarch64/diagnostics-persistent-server.kex")
    }
    #[cfg(target_arch = "x86_64")]
    {
        include_bytes!("../../tests/kex-corpus/x86_64/diagnostics-persistent-server.kex")
    }
}

pub(crate) fn initialize(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
) -> Result<(), ()> {
    let record = ServiceRecord::new(ROLE, 256, 4000, RestartPolicy::NETWORK).map_err(|_| ())?;
    accounting.persistent_services = Some(Box::new(Supervisor::new(&[ServerSpec {
        record,
        artifact: artifact(),
        nested: None,
    }])?));
    step(scheduler, accounting)
}

pub(crate) fn step(scheduler: &mut Scheduler, accounting: &mut OwnedAccounting) -> Result<(), ()> {
    let mut supervisor = accounting.persistent_services.take().ok_or(())?;
    let result = supervisor.step(scheduler, accounting);
    accounting.persistent_services = Some(supervisor);
    result
}

/// Stop service incarnations through scalar lifecycle continuations before poweroff.
pub(crate) fn shutdown_all(
    scheduler: &mut Scheduler,
    accounting: &mut OwnedAccounting,
) -> Result<(), ()> {
    let mut supervisor = accounting.persistent_services.take().ok_or(())?;
    let result = (|| {
        supervisor.shutting_down = true;
        // Poweroff cancels outstanding ordinary operations before reserving a
        // lifecycle channel. No client record or handle survives shutdown.
        for client in &mut supervisor.clients {
            if client.key.take().is_some() {
                let runtime = supervisor.runtime.as_mut().ok_or(())?;
                runtime.cancel(client.actor).map_err(|_| ())?;
                runtime.model().take_resume(client.actor).map_err(|_| ())?;
                if let Some(handle) = client.handle.take()
                    && runtime.model().has_handle(client.actor, handle)
                {
                    runtime
                        .model()
                        .close(client.actor, handle)
                        .map_err(|_| ())?;
                }
                client.continuation = None;
            }
        }
        while supervisor.initializing.is_some() {
            supervisor.step(scheduler, accounting)?;
        }
        for index in 0..supervisor.specs.len() {
            if supervisor.instances[index].is_none() {
                continue;
            }
            supervisor.request_shutdown(index)?;
            while supervisor.instances[index].is_some() {
                supervisor.step(scheduler, accounting)?;
            }
        }
        Ok(())
    })();
    accounting.persistent_services = Some(supervisor);
    result
}

impl Supervisor {
    pub(crate) fn new(specs: &[ServerSpec]) -> Result<Self, ()> {
        let mut capsule_bytes = 0usize;
        for (index, spec) in specs.iter().enumerate() {
            capsule_bytes = capsule_bytes.checked_add(spec.artifact.len()).ok_or(())?;
            if spec.artifact.len() > 4 * 1024 * 1024
                || capsule_bytes > 8 * 1024 * 1024
                || spec.nested.is_some_and(|dependency| dependency >= index)
            {
                return Err(());
            }
        }
        let records: alloc::vec::Vec<_> = specs.iter().map(|s| s.record).collect();
        let lifecycle = ServiceSupervisor::new(&records).map_err(|_| ())?;
        let mut runtime = ProtectedRuntime::new().map_err(|_| ())?;
        let mut clients = [None; 4];
        for client in &mut clients {
            let actor = runtime.model().attach(None).map_err(|_| ())?;
            runtime
                .install_kernel(
                    actor,
                    troe_machine::IpcPagePair::allocate_kernel().map_err(|_| ())?,
                )
                .map_err(|_| ())?;
            *client = Some(actor);
        }
        Ok(Self {
            runtime: Some(runtime),
            lifecycle,
            specs: specs.to_vec(),
            instances: core::array::from_fn(|_| None),
            clients: clients.map(|actor| Client {
                actor: actor.unwrap_or_else(|| unreachable!()),
                key: None,
                handle: None,
                continuation: None,
            }),
            next: None,
            initializing: None,
            waits: WaitTable::new(8).map_err(|_| ())?,
            next_wait_operation: 0,
            shutting_down: false,
            shutdown: None,
        })
    }

    pub(crate) fn ready(&self) -> bool {
        self.lifecycle.accepts_clients(ROLE)
    }
    pub(crate) fn offline(&self) -> bool {
        self.lifecycle.state(ROLE).is_ok_and(ServiceState::is_final)
    }
    pub(crate) fn generation(&self) -> Option<u32> {
        self.instances[0]
            .as_ref()
            .filter(|_| self.ready())
            .map(|i| i.ticket.generation())
    }

    #[allow(clippy::too_many_lines)]
    fn start(
        &mut self,
        index: usize,
        client_index: usize,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        let spec = *self.specs.get(index).ok_or(())?;
        if self.instances[index].is_some() || spec.artifact.len() > 4 * 1024 * 1024 {
            return Err(());
        }
        let package = parse_kex_package(spec.artifact).map_err(|_| ())?;
        let requirements: alloc::vec::Vec<_> = package.requirements().iter().collect();
        let expected = if spec.nested.is_some() {
            &[
                (troe_abi::interface::SERVER_ENDPOINT, 2),
                (troe_abi::interface::WAIT_SET, 1),
                (troe_abi::interface::DIAGNOSTICS, 1),
            ][..]
        } else {
            &[
                (troe_abi::interface::SERVER_ENDPOINT, 2),
                (troe_abi::interface::WAIT_SET, 1),
            ][..]
        };
        if requirements.len() != expected.len()
            || expected.iter().any(|&(id, major)| {
                requirements
                    .iter()
                    .filter(|r| r.interface == id && r.major == major && r.minor == 0)
                    .count()
                    != 1
            })
        {
            return Err(());
        }
        let plan =
            parse_kex(package.executable(), native_application_target(), 3).map_err(|_| ())?;
        let (allocation, mapping) = allocate_application(accounting, &plan)?;
        let mut task = None;
        let mut actor = None;
        let mut started_ticket = None;
        let result = (|| {
            if plan
                .charges()
                .private_pages()
                .checked_add(allocation.tables.page_count())
                .ok_or(())?
                > u64::from(spec.record.resident_page_ceiling())
            {
                return Err(());
            }
            prepare_application_memory(&allocation, &plan)?;
            let mut root = troe_machine::build_user_address_space(&mapping, allocation.tables)
                .map_err(|_| ())?;
            let pair = allocation.ipc.as_ref().ok_or(())?;
            root.bind_ipc(pair, plan.layout().ipc_addresses().ok_or(())?.0)
                .map_err(|_| ())?;
            let slot = SERVICE_SLOT_BASE
                .checked_add(u32::try_from(pair.slot()).map_err(|_| ())?)
                .ok_or(())?;
            let identity = scheduler
                .spawn_isolated(
                    Capabilities::SERVICE,
                    StackResource::new(slot, plan.stack_pages()).map_err(|_| ())?,
                    IsolationResource::new(
                        slot,
                        allocation.tables.page_count(),
                        plan.charges().private_pages(),
                        if spec.nested.is_some() { 3 } else { 2 },
                    )
                    .map_err(|_| ())?,
                )
                .map_err(|_| ())?;
            task = Some(identity);
            let ticket = self
                .lifecycle
                .start(spec.record.role(), identity.get(), now()?)
                .map_err(|_| ())?;
            started_ticket = Some(ticket);
            let runtime = self.runtime.as_mut().ok_or(())?;
            let owner = runtime.model().attach(Some(identity)).map_err(|_| ())?;
            actor = Some(owner);
            let endpoint = runtime
                .model()
                .bind(
                    owner,
                    InterfaceSet::new(&[
                        troe_abi::interface::DIAGNOSTICS,
                        troe_abi::interface::SERVICE_LIFECYCLE,
                    ])
                    .map_err(|_| ())?,
                    EndpointLimits::STANDARD,
                )
                .map_err(|_| ())?;
            let (receive, wait) = runtime
                .model()
                .configure_wait(owner, &[endpoint])
                .map_err(|_| ())?;
            let mut handles = alloc::vec![
                InitialHandle {
                    value: receive,
                    interface: troe_abi::interface::SERVER_ENDPOINT,
                    major: 2,
                    minor: 0,
                    rights: 6,
                },
                InitialHandle {
                    value: wait,
                    interface: troe_abi::interface::WAIT_SET,
                    major: 1,
                    minor: 0,
                    rights: 8,
                },
            ];
            if let Some(nested) = spec.nested {
                let endpoint = self
                    .instances
                    .get(nested)
                    .and_then(Option::as_ref)
                    .ok_or(())?
                    .endpoint;
                let handle = runtime
                    .model()
                    .open(owner, endpoint, troe_abi::interface::DIAGNOSTICS, 1, 0)
                    .map_err(|_| ())?;
                handles.push(InitialHandle {
                    value: handle,
                    interface: troe_abi::interface::DIAGNOSTICS,
                    major: 1,
                    minor: 0,
                    rights: 1,
                });
            }
            let mut startup = [0; 4096];
            plan.encode_startup_page(
                StartupInfo {
                    task_id: u64::from(identity.get()),
                    handles: &handles,
                },
                &mut startup,
            )
            .map_err(|_| ())?;
            troe_machine::copy_to_physical(allocation.startup, 0, &startup).map_err(|_| ())?;
            root.authorize_persistent_ipc(plan.layout().startup_address())
                .map_err(|_| ())?;
            scheduler
                .dispatch(identity, Capabilities::SERVICE)
                .map_err(|_| ())?;
            let outcome = troe_machine::run_application(
                root,
                plan.entry_address(),
                plan.layout().stack_top(),
                plan.layout().startup_address(),
                4096,
                50,
            )
            .map_err(|_| ())?;
            scheduler.yield_current(identity).map_err(|_| ())?;
            let ApplicationOutcome::Yielded(session) = outcome else {
                return Err(());
            };
            runtime.install(owner, session).map_err(|_| ())?;
            Ok((owner, identity, endpoint, ticket))
        })();
        let Ok((owner, task, endpoint, ticket)) = result else {
            if let Some(actor) = actor {
                let runtime = self.runtime.as_mut().ok_or(())?;
                if runtime.model().is_live(actor) {
                    runtime.model().terminate(actor, false).map_err(|_| ())?;
                }
                if let Ok(session) = runtime.remove(actor) {
                    drop(session);
                }
            }
            if let Some(task) = task {
                scheduler
                    .terminate_revoke_and_reap(task, 1, |_| Ok::<(), ()>(()))
                    .map_err(|_| ())?;
            }
            reclaim_application(accounting, allocation)?;
            if let Some(ticket) = started_ticket {
                self.lifecycle
                    .observe(ticket, ServiceEvent::InitializationRejected, now()?)
                    .map_err(|_| ())?;
                return Ok(());
            }
            return Err(());
        };
        self.instances[index] = Some(Instance {
            actor: owner,
            task,
            endpoint,
            ticket,
            allocation,
            wait: None,
        });
        if self.park(index, scheduler).is_err()
            || self.begin_initialization(index, client_index).is_err()
        {
            self.runtime
                .as_mut()
                .ok_or(())?
                .terminate(owner, false)
                .map_err(|_| ())?;
            self.reap(
                scheduler,
                accounting,
                owner,
                ServiceEvent::InitializationRejected,
            )?;
        }
        Ok(())
    }

    fn begin_initialization(&mut self, index: usize, client_index: usize) -> Result<(), ()> {
        let instance = self.instances[index].as_ref().ok_or(())?;
        let deadline = self
            .lifecycle
            .initialization_deadline(instance.ticket)
            .map_err(|_| ())?;
        let runtime = self.runtime.as_mut().ok_or(())?;
        let client = self.clients[client_index].actor;
        let handle = runtime
            .model()
            .open(
                client,
                instance.endpoint,
                troe_abi::interface::SERVICE_LIFECYCLE,
                1,
                0,
            )
            .map_err(|_| ())?;
        self.clients[client_index].handle = Some(handle);
        self.initializing = Some((index, client_index));
        self.next = runtime
            .kernel_call(
                client,
                troe_abi::ipc::Call {
                    handle,
                    opcode: 1,
                    request_bytes: 0,
                    reply_capacity: 0,
                    deadline_millis: deadline,
                    object_parameter: 0,
                },
            )
            .map_err(|_| ())?;
        Ok(())
    }

    fn park(&mut self, index: usize, scheduler: &mut Scheduler) -> Result<(), ()> {
        let instance = self.instances[index].as_mut().ok_or(())?;
        self.next_wait_operation = self.next_wait_operation.checked_add(1).ok_or(())?;
        let operation =
            PendingOperationId::from_abi_value(u64::from(self.next_wait_operation) << 32)
                .map_err(|_| ())?;
        let resource = WaitResource::new(
            u64::from(instance.endpoint.slot()) + 1,
            instance.endpoint.generation(),
        )
        .map_err(|_| ())?;
        let spec = WaitSpec::new(
            instance.task,
            operation,
            Some(resource),
            WakeInterest::RESOURCE_READY,
            None,
        )
        .map_err(|_| ())?;
        let WaitRegistration::Blocked(wait) = self
            .waits
            .register(
                spec,
                WaitObservation::Pending,
                MonotonicMillis::from_millis(now()?),
            )
            .map_err(|_| ())?
        else {
            return Err(());
        };
        scheduler
            .dispatch(instance.task, Capabilities::SERVICE)
            .map_err(|_| ())?;
        scheduler
            .block_current(instance.task, wait)
            .map_err(|_| ())?;
        instance.wait = Some(wait);
        if self
            .lifecycle
            .state(self.specs[index].record.role())
            .map_err(|_| ())?
            == ServiceState::Ready
        {
            self.lifecycle
                .observe(instance.ticket, ServiceEvent::Blocked, now()?)
                .map_err(|_| ())?;
        }
        Ok(())
    }

    fn unpark(&mut self, index: usize, scheduler: &mut Scheduler) -> Result<(), ()> {
        let instance = self.instances[index].as_mut().ok_or(())?;
        let wait = instance.wait.take().ok_or(())?;
        if self
            .lifecycle
            .state(self.specs[index].record.role())
            .map_err(|_| ())?
            == ServiceState::Blocked
        {
            self.lifecycle
                .observe(instance.ticket, ServiceEvent::Resumed, now()?)
                .map_err(|_| ())?;
        }
        let resource = WaitResource::new(
            u64::from(instance.endpoint.slot()) + 1,
            instance.endpoint.generation(),
        )
        .map_err(|_| ())?;
        let completion = self
            .waits
            .wake_resource(resource, WakeReason::ResourceReady)
            .map_err(|_| ())?;
        if completion.iter().next().is_none_or(|c| c.key() != wait)
            || completion.iter().nth(1).is_some()
        {
            return Err(());
        }
        scheduler
            .wake_blocked(instance.task, wait)
            .map_err(|_| ())?;
        scheduler
            .dispatch(instance.task, Capabilities::SERVICE)
            .map_err(|_| ())?;
        Ok(())
    }

    pub(crate) fn step(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        if let Some((index, client, _)) = self.shutdown
            && let Some(troe_service::KernelContinuation::AwaitingShutdown {
                deadline_millis, ..
            }) = self.clients[client].continuation
            && now()? >= deadline_millis
        {
            let actor = self.instances[index].as_ref().ok_or(())?.actor;
            self.runtime
                .as_mut()
                .ok_or(())?
                .terminate(actor, false)
                .map_err(|_| ())?;
            self.reap(scheduler, accounting, actor, ServiceEvent::Revoked)?;
        }
        if self.initializing.is_none() && !self.shutting_down {
            for index in 0..self.specs.len() {
                let role = self.specs[index].record.role();
                let state = self.lifecycle.state(role).map_err(|_| ())?;
                if self.instances[index].is_none()
                    && matches!(state, ServiceState::Absent | ServiceState::Faulted)
                {
                    if state == ServiceState::Faulted
                        && !self.lifecycle.admits_restart(role, now()?)
                    {
                        self.lifecycle
                            .apply(role, ServiceEvent::RestartRequested, now()?)
                            .map_err(|_| ())?;
                        continue;
                    }
                    let free = self
                        .clients
                        .iter()
                        .position(|client| client.key.is_none() && client.handle.is_none());
                    if let Some(client) = free {
                        self.start(index, client, scheduler, accounting)?;
                    }
                    break;
                }
            }
        }
        let next = match self.next.take() {
            Some(actor) if self.runtime.as_mut().ok_or(())?.model().is_live(actor) => Some(actor),
            _ => self.runtime.as_mut().ok_or(())?.poll().map_err(|_| ())?,
        };
        if let Some(actor) = next
            && actor.slot() < troe_service::ipc::TASKS
        {
            let index = self.index(actor)?;
            let task = self.instances[index].as_ref().ok_or(())?.task;
            if self.unpark(index, scheduler).is_err() {
                self.runtime
                    .as_mut()
                    .ok_or(())?
                    .terminate(actor, false)
                    .map_err(|_| ())?;
                return self.reap(scheduler, accounting, actor, ServiceEvent::Revoked);
            }
            let (runtime, stop) = self.runtime.take().ok_or(())?.run(actor).map_err(|_| ())?;
            self.runtime = Some(runtime);
            scheduler.yield_current(task).map_err(|_| ())?;
            let terminal = match stop {
                ProtectedStop::Faulted { actor, fault } => Some((
                    actor,
                    if fault == troe_machine::IsolatedFault::ExecutionLeaseExpired {
                        ServiceEvent::LeaseExpired
                    } else {
                        ServiceEvent::Faulted
                    },
                )),
                ProtectedStop::Exited { actor, .. } => Some((
                    actor,
                    if self.shutdown.is_some_and(|(index, _, acknowledged)| {
                        acknowledged
                            && self.instances[index]
                                .as_ref()
                                .is_some_and(|i| i.actor == actor)
                    }) {
                        ServiceEvent::ShutdownCompleted
                    } else {
                        ServiceEvent::Exited
                    },
                )),
                _ => None,
            };
            if terminal.is_none_or(|(terminal, _)| terminal != actor)
                && self.park(index, scheduler).is_err()
            {
                self.runtime
                    .as_mut()
                    .ok_or(())?
                    .terminate(actor, false)
                    .map_err(|_| ())?;
                self.reap(scheduler, accounting, actor, ServiceEvent::Revoked)?;
            }
            if let Some((actor, event)) = terminal {
                self.reap(scheduler, accounting, actor, event)?;
            }
        }
        self.complete_handshakes(scheduler, accounting)
    }

    fn complete_handshakes(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
    ) -> Result<(), ()> {
        if let Some((index, client, false)) = self.shutdown {
            let runtime = self.runtime.as_mut().ok_or(())?;
            if let Some((status, bytes)) = runtime
                .kernel_reply(self.clients[client].actor, &mut [])
                .map_err(|_| ())?
            {
                if status != 0 || bytes != 0 {
                    let actor = self.instances[index].as_ref().ok_or(())?.actor;
                    runtime.terminate(actor, false).map_err(|_| ())?;
                    self.reap(scheduler, accounting, actor, ServiceEvent::Revoked)?;
                } else {
                    runtime
                        .model()
                        .close(
                            self.clients[client].actor,
                            self.clients[client].handle.take().ok_or(())?,
                        )
                        .map_err(|_| ())?;
                    self.shutdown = Some((index, client, true));
                }
            }
        }
        if let Some((index, client)) = self.initializing {
            let runtime = self.runtime.as_mut().ok_or(())?;
            if let Some((status, bytes)) = runtime
                .kernel_reply(self.clients[client].actor, &mut [])
                .map_err(|_| ())?
            {
                let instance = self.instances[index].as_ref().ok_or(())?;
                let actor = instance.actor;
                if self
                    .lifecycle
                    .initialized(instance.ticket, status, bytes, now()?)
                    .is_err()
                {
                    runtime.terminate(actor, false).map_err(|_| ())?;
                    self.reap(
                        scheduler,
                        accounting,
                        actor,
                        ServiceEvent::InitializationRejected,
                    )?;
                    return Ok(());
                }
                runtime.model().ready(instance.endpoint).map_err(|_| ())?;
                runtime
                    .model()
                    .close(
                        self.clients[client].actor,
                        self.clients[client].handle.take().ok_or(())?,
                    )
                    .map_err(|_| ())?;
                self.initializing = None;
                self.lifecycle
                    .observe(instance.ticket, ServiceEvent::Blocked, now()?)
                    .map_err(|_| ())?;
            }
        }
        Ok(())
    }

    pub(crate) fn request_shutdown(&mut self, index: usize) -> Result<(), ()> {
        if self.initializing.is_some() || self.shutdown.is_some() {
            return Err(());
        }
        let instance = self
            .instances
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(())?;
        let client = self
            .clients
            .iter()
            .position(|c| c.key.is_none() && c.handle.is_none())
            .ok_or(())?;
        let runtime = self.runtime.as_mut().ok_or(())?;
        let actor = self.clients[client].actor;
        let handle = runtime
            .model()
            .open(
                actor,
                instance.endpoint,
                troe_abi::interface::SERVICE_LIFECYCLE,
                1,
                0,
            )
            .map_err(|_| ())?;
        let deadline = now()?.checked_add(4000).ok_or(())?;
        self.clients[client].handle = Some(handle);
        self.clients[client].continuation =
            Some(troe_service::KernelContinuation::AwaitingShutdown {
                role: self.specs[index].record.role(),
                deadline_millis: deadline,
            });
        self.shutting_down = true;
        self.shutdown = Some((index, client, false));
        self.next = runtime
            .kernel_call(
                actor,
                troe_abi::ipc::Call {
                    handle,
                    opcode: 2,
                    request_bytes: 0,
                    reply_capacity: 0,
                    deadline_millis: deadline,
                    object_parameter: 0,
                },
            )
            .map_err(|_| ())?;
        Ok(())
    }

    fn index(&self, actor: Actor) -> Result<usize, ()> {
        self.instances
            .iter()
            .position(|i| i.as_ref().is_some_and(|i| i.actor == actor))
            .ok_or(())
    }

    pub(crate) fn reap(
        &mut self,
        scheduler: &mut Scheduler,
        accounting: &mut OwnedAccounting,
        actor: Actor,
        event: ServiceEvent,
    ) -> Result<(), ()> {
        let index = self.index(actor)?;
        let instance = self.instances[index].take().ok_or(())?;
        #[cfg(feature = "acceptance-probes")]
        if self.specs[index].record.role() == ServiceRole::Diagnostics
            && event == ServiceEvent::Faulted
        {
            crate::service::diagnostics::DIAGNOSTICS_FAULT_PROBE_CONTAINED
                .store(true, core::sync::atomic::Ordering::Release);
        }
        self.lifecycle
            .observe(instance.ticket, event, now()?)
            .map_err(|_| ())?;
        self.waits
            .cancel_owner(instance.task, WakeReason::Revoked)
            .map_err(|_| ())?;
        scheduler
            .terminate_revoke_and_reap(instance.task, 1, |_| Ok::<(), ()>(()))
            .map_err(|_| ())?;
        let runtime = self.runtime.as_mut().ok_or(())?;
        if self
            .initializing
            .is_some_and(|(initializing, _)| initializing == index)
        {
            let (_, client) = self.initializing.take().ok_or(())?;
            runtime
                .model()
                .take_resume(self.clients[client].actor)
                .map_err(|_| ())?;
            self.clients[client].handle = None;
        }
        if self
            .shutdown
            .is_some_and(|(shutdown, _, _)| shutdown == index)
        {
            let (_, client, _) = self.shutdown.take().ok_or(())?;
            runtime
                .model()
                .take_resume(self.clients[client].actor)
                .map_err(|_| ())?;
            self.clients[client].handle = None;
            self.clients[client].continuation = None;
        }
        drop(runtime.remove(actor).map_err(|_| ())?);
        reclaim_application(accounting, instance.allocation)?;
        Ok(())
    }
}

fn now() -> Result<u64, ()> {
    troe_machine::monotonic_millis().ok_or(())
}

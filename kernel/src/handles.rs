//! Shared handle aliases for state the composition root hands out.
//!
//! Each alias names one piece of owned-machine state that more than one
//! service, task, or continuation observes. The aliases exist so the sharing
//! is visible at every use site rather than spelled out as an anonymous
//! `Rc<RefCell<_>>`, and so the authority each handle carries can be described
//! once.

use crate::mounts::RuntimeMountRegistry;
use crate::network::services::ApplicationDatagramState;
use crate::network::{KernelNetworkService, KernelTcpConnection};
use crate::runtime::KernelRuntime;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use troe_abi::diagnostics;
use troe_dispatch::ReplyStatus;
use troe_namespace::Namespace;
use troe_process::{ChildTable, OwnerId, PipeTable};
use troe_random::Generator as RandomGenerator;
use troe_supervisor::BoundedLog;
use troe_task::{ProcessTable, TaskId, WakeReason};

pub(crate) type SharedResidentLog = Rc<RefCell<BoundedLog>>;

pub(crate) type SharedProcessTable = Rc<RefCell<ProcessTable>>;

pub(crate) type SharedTaskIdentity = Rc<Cell<Option<TaskId>>>;

/// The composition root retains the concrete namespace, because mounting
/// providers and projecting generated state are authorities a client of
/// the namespace must not hold.
pub(crate) type OwnedNamespace = Rc<RefCell<Namespace>>;

pub(crate) type SharedChildTable = Rc<RefCell<ChildTable>>;

pub(crate) type SharedPipeTable = Rc<RefCell<PipeTable>>;

pub(crate) type SharedRandom = Rc<RefCell<RandomGenerator>>;

pub(crate) type SharedProcessOwner = Rc<Cell<Option<OwnerId>>>;

pub(crate) type SharedNetwork = Rc<RefCell<KernelNetworkService>>;

pub(crate) type SharedTcpConnection = Rc<RefCell<KernelTcpConnection>>;

pub(crate) type SharedRuntimeMounts = Rc<RefCell<RuntimeMountRegistry>>;

pub(crate) type SharedApplicationDatagram = Rc<RefCell<ApplicationDatagramState>>;

pub(crate) type SharedDiagnosticsSnapshot = Rc<[u8; diagnostics::SNAPSHOT_BYTES]>;

pub(crate) type DiagnosticsServerCompletion = (ReplyStatus, Vec<u8>);

pub(crate) type DiagnosticsServerFate = (WakeReason, Option<DiagnosticsServerCompletion>);

pub(crate) type SharedRuntime = Rc<RefCell<KernelRuntime>>;

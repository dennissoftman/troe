//! Nested standard streams for children a running application spawns.
//!
//! A spawned child's stdio is either inherited from the parent, bound to a
//! pipe endpoint, or empty. These types carry that decision down the launch
//! path without the child ever observing the session terminal loan.

use crate::deferred::PipeStreamService;
use crate::handles::{
    OwnedNamespace, SharedPipeTable, SharedProcessTable, SharedResidentLog, SharedRuntime,
    SharedRuntimeMounts,
};
use crate::invocation::{CommandApplicationOutcome, CommandStartupService};
use crate::resident::ResidentApplication;
use crate::service::process::{
    ApplicationPipeInputService, ApplicationPipeOutputService, child_process_status,
};
use crate::service::{
    ApplicationDiscardOutputService, ApplicationEmptyInputService, ApplicationInputService,
    ApplicationLogService, ApplicationOutputService,
};
use crate::supervision::register_command_service;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use troe_abi::{pipe, process_launch, stream};
use troe_core::{Input, Output};
use troe_dispatch::{Dispatcher, ReplyStatus};
use troe_process::{OwnerId, PipeDirection};

#[derive(Clone)]
pub(crate) enum NestedInput<'stream> {
    Empty,
    Borrowed(Rc<RefCell<&'stream mut dyn Input>>),
    Pipe {
        pipes: SharedPipeTable,
        owner: OwnerId,
        token: pipe::PipeToken,
    },
}

#[derive(Clone)]
pub(crate) enum NestedOutput<'stream> {
    Discard,
    Borrowed(Rc<RefCell<&'stream mut dyn Output>>),
    Log(SharedResidentLog),
    Pipe {
        pipes: SharedPipeTable,
        owner: OwnerId,
        token: pipe::PipeToken,
    },
}

#[derive(Clone)]
pub(crate) struct NestedStdio<'stream> {
    pub(crate) stdin: NestedInput<'stream>,
    pub(crate) stdout: NestedOutput<'stream>,
    pub(crate) stderr: NestedOutput<'stream>,
}

#[derive(Clone)]
pub(crate) struct NestedLaunchContext<'stream> {
    pub(crate) namespace: OwnedNamespace,
    pub(crate) runtime: SharedRuntime,
    pub(crate) processes: SharedProcessTable,
    pub(crate) mounts: SharedRuntimeMounts,
    pub(crate) stdio: NestedStdio<'stream>,
}

pub(crate) struct NestedChild<'service> {
    pub(crate) token: process_launch::ChildToken,
    pub(crate) process: Option<Box<ResidentApplication<'service>>>,
    pub(crate) outcome: Option<CommandApplicationOutcome>,
}

pub(crate) fn nested_input_for_spawn<'service>(
    spec: process_launch::StreamSpec,
    inherited: &NestedInput<'service>,
    owner: OwnerId,
    pipes: &SharedPipeTable,
) -> Result<NestedInput<'service>, ReplyStatus> {
    match spec.mode {
        // The session terminal loan is not transitive. A child that
        // inherits terminal-backed standard input receives an empty stream
        // instead, so two readers never compete for one keystroke.
        process_launch::StreamMode::Inherit => Ok(match inherited {
            NestedInput::Borrowed(input) => {
                let terminal = input
                    .try_borrow()
                    .map_err(|_| ReplyStatus::Conflict)?
                    .is_terminal();
                if terminal {
                    NestedInput::Empty
                } else {
                    inherited.clone()
                }
            }
            NestedInput::Empty | NestedInput::Pipe { .. } => inherited.clone(),
        }),
        process_launch::StreamMode::Null => Ok(NestedInput::Empty),
        process_launch::StreamMode::Pipe => {
            let token = pipe::PipeToken::new(spec.pipe).map_err(|_| ReplyStatus::InvalidRequest)?;
            pipes
                .try_borrow_mut()
                .map_err(|_| ReplyStatus::Conflict)?
                .owner_read_ready(owner, token)
                .map_err(child_process_status)?;
            Ok(NestedInput::Pipe {
                pipes: pipes.clone(),
                owner,
                token,
            })
        }
    }
}

pub(crate) fn nested_output_for_spawn<'service>(
    spec: process_launch::StreamSpec,
    inherited: &NestedOutput<'service>,
    owner: OwnerId,
    pipes: &SharedPipeTable,
) -> Result<NestedOutput<'service>, ReplyStatus> {
    match spec.mode {
        process_launch::StreamMode::Inherit => Ok(inherited.clone()),
        process_launch::StreamMode::Null => Ok(NestedOutput::Discard),
        process_launch::StreamMode::Pipe => {
            let token = pipe::PipeToken::new(spec.pipe).map_err(|_| ReplyStatus::InvalidRequest)?;
            // Zero-length readiness is false but still validates token,
            // ownership, writer openness, and the existence of a reader.
            let _ready = pipes
                .try_borrow_mut()
                .map_err(|_| ReplyStatus::Conflict)?
                .owner_write_ready(owner, token, 0)
                .map_err(child_process_status)?;
            Ok(NestedOutput::Pipe {
                pipes: pipes.clone(),
                owner,
                token,
            })
        }
    }
}

pub(crate) fn register_nested_input<'service>(
    dispatcher: &mut Dispatcher<'service>,
    input: &NestedInput<'service>,
    pipe_streams: &mut Vec<PipeStreamService>,
) -> Result<CommandStartupService, ()> {
    let port = match input {
        NestedInput::Empty => register_command_service(dispatcher, ApplicationEmptyInputService)?,
        NestedInput::Borrowed(input) => register_command_service(
            dispatcher,
            ApplicationInputService {
                input: input.clone(),
            },
        )?,
        NestedInput::Pipe {
            pipes,
            owner,
            token,
        } => {
            pipe_streams.try_reserve(1).map_err(|_| ())?;
            let endpoint = pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .attach(*owner, *token, PipeDirection::Reader)
                .map_err(|_| ())?;
            let port = register_command_service(
                dispatcher,
                ApplicationPipeInputService {
                    pipes: pipes.clone(),
                    endpoint,
                },
            )?;
            pipe_streams.push(PipeStreamService {
                interface: troe_abi::interface::STANDARD_INPUT,
                pipes: pipes.clone(),
                endpoint,
            });
            port
        }
    };
    Ok(CommandStartupService {
        port,
        interface: troe_abi::interface::STANDARD_INPUT,
        major: stream::MAJOR,
        minor: stream::MINOR,
    })
}

pub(crate) fn register_nested_output<'service>(
    dispatcher: &mut Dispatcher<'service>,
    output: &NestedOutput<'service>,
    interface: u32,
    pipe_streams: &mut Vec<PipeStreamService>,
) -> Result<CommandStartupService, ()> {
    let port = match output {
        NestedOutput::Discard => {
            register_command_service(dispatcher, ApplicationDiscardOutputService)?
        }
        NestedOutput::Borrowed(output) => register_command_service(
            dispatcher,
            ApplicationOutputService {
                output: output.clone(),
            },
        )?,
        NestedOutput::Log(log) => {
            register_command_service(dispatcher, ApplicationLogService { log: log.clone() })?
        }
        NestedOutput::Pipe {
            pipes,
            owner,
            token,
        } => {
            pipe_streams.try_reserve(1).map_err(|_| ())?;
            let endpoint = pipes
                .try_borrow_mut()
                .map_err(|_| ())?
                .attach(*owner, *token, PipeDirection::Writer)
                .map_err(|_| ())?;
            let port = register_command_service(
                dispatcher,
                ApplicationPipeOutputService {
                    pipes: pipes.clone(),
                    endpoint,
                },
            )?;
            pipe_streams.push(PipeStreamService {
                interface,
                pipes: pipes.clone(),
                endpoint,
            });
            port
        }
    };
    Ok(CommandStartupService {
        port,
        interface,
        major: stream::MAJOR,
        minor: stream::MINOR,
    })
}

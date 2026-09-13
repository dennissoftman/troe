//! Command outcomes, startup service identities and user-facing errors.
//!
//! The acceptance-only child module retains the synchronous compatibility
//! runner. Product command execution lives in the resident continuation machine.

use crate::support::write_all;
use troe_core::{CommandStatus, Output};
use troe_task::TaskFault;

#[cfg(feature = "acceptance-probes")]
mod compatibility;
#[cfg(feature = "acceptance-probes")]
pub(crate) use compatibility::run_command_application;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandApplicationOutcome {
    Exited(u32),
    Faulted(TaskFault),
}

#[derive(Clone, Copy)]
pub(crate) struct CommandStartupService {
    pub(crate) port: troe_dispatch::PortId,
    pub(crate) interface: u32,
    pub(crate) major: u16,
    pub(crate) minor: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct CommandApplicationHandle {
    pub(crate) value: u64,
    pub(crate) interface: u32,
}

pub(crate) fn command_application_error(
    stderr: &mut dyn Output,
    command: &str,
    message: &str,
) -> CommandStatus {
    command_application_status_error(stderr, command, message, CommandStatus::Failure)
}

pub(crate) fn command_application_status_error(
    stderr: &mut dyn Output,
    command: &str,
    message: &str,
    status: CommandStatus,
) -> CommandStatus {
    let _ignored = write_all(stderr, alloc::format!("{command}: {message}\n").as_bytes());
    status
}

pub(crate) const fn command_status(status: u32) -> CommandStatus {
    match status {
        troe_abi::exit::SUCCESS => CommandStatus::Success,
        troe_abi::exit::USAGE => CommandStatus::Usage,
        troe_abi::exit::NOT_FOUND => CommandStatus::NotFound,
        troe_abi::exit::DENIED => CommandStatus::Denied,
        troe_abi::exit::CANCELLED => CommandStatus::Cancelled,
        _ => CommandStatus::Failure,
    }
}

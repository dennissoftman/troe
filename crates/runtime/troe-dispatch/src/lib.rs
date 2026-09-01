//! Bounded handles, ports, and synchronous in-process request/reply dispatch.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod dispatcher;
mod message;
mod services;

use core::fmt;

pub use dispatcher::{DispatchStats, Dispatcher, Service};
pub use message::{
    CopiedMessage, Handle, HandleOwner, PortId, Reply, ReplyInfo, ReplyStatus, Request, Rights,
    ServiceReply, ServiceReplyInfo,
};
pub use services::{
    ByteInputService, ByteOutputService, CONSOLE_WRITE, CommandInvocationService, ConsoleService,
    DispatchedOutput, SharedOutput,
};

/// Hard ceiling for one request or reply payload.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
/// Hard ceiling for registered service ports.
pub const MAX_PORTS: usize = 65_536;
/// Hard ceiling for live client handles.
pub const MAX_HANDLES: usize = 262_144;

/// Dispatcher mechanism and resource failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError {
    /// A configured table bound is zero or exceeds its hard ceiling.
    InvalidCapacity,
    /// A zero or otherwise reserved task owner was supplied.
    InvalidOwner,
    /// Bounded metadata allocation failed.
    MetadataExhausted,
    /// No reusable port slot remains.
    PortCapacityExhausted,
    /// No reusable handle slot remains.
    HandleCapacityExhausted,
    /// A request or reply exceeds [`MAX_MESSAGE_BYTES`].
    MessageTooLarge,
    /// A stale, closed, or foreign handle was supplied.
    InvalidHandle,
    /// A stale, closed, or foreign port was supplied.
    InvalidPort,
    /// The handle lacks the requested operation right.
    PermissionDenied,
    /// A monotonic request or accounting counter overflowed.
    AccountingOverflow,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("dispatch capacity is invalid"),
            Self::InvalidOwner => formatter.write_str("handle owner is invalid"),
            Self::MetadataExhausted => formatter.write_str("dispatch metadata allocation failed"),
            Self::PortCapacityExhausted => formatter.write_str("service port capacity exhausted"),
            Self::HandleCapacityExhausted => {
                formatter.write_str("service handle capacity exhausted")
            }
            Self::MessageTooLarge => formatter.write_str("message payload exceeds its bound"),
            Self::InvalidHandle => formatter.write_str("service handle is invalid"),
            Self::InvalidPort => formatter.write_str("service port is invalid"),
            Self::PermissionDenied => formatter.write_str("service handle right denied"),
            Self::AccountingOverflow => formatter.write_str("dispatch accounting overflowed"),
        }
    }
}

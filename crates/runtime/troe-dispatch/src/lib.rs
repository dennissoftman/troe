//! Bounded handles, ports, and synchronous in-process request/reply dispatch.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod badge;
mod dispatcher;
mod endpoint;
mod message;
mod pending;
mod services;

use core::fmt;

pub use badge::{
    BadgeClosure, BadgeStats, BadgeTable, ClientBadge, MAX_BADGES_PER_ENDPOINT, MAX_CLIENT_BADGES,
};
pub use dispatcher::{DispatchStats, Dispatcher, Service};
pub use endpoint::{
    EndpointBinding, EndpointId, EndpointLimits, EndpointStats, EndpointTable, InterfaceSet,
    MAX_CALL_DEADLINE_MILLIS, MAX_ENDPOINT_INTERFACES, MAX_ENDPOINTS,
    MAX_QUEUED_CALLS_PER_ENDPOINT, MAX_RETAINED_REQUEST_BYTES,
};
pub use message::{
    CopiedMessage, Handle, HandleOwner, PortId, Reply, ReplyInfo, ReplyStatus, Request, Rights,
    ServiceReply, ServiceReplyInfo,
};
pub use pending::{
    Admission, CallId, CallOutcome, CallState, Delivery, MAX_PENDING_CALLS,
    MAX_QUEUED_PER_ENDPOINT, PendingCallStats, PendingCallTable, QueueSlotId,
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
    /// A rights set carries an unassigned bit, or one the interface has no
    /// operation for.
    InvalidRights,
    /// No reusable endpoint slot remains.
    EndpointCapacityExhausted,
    /// A stale, closed, retired, or foreign endpoint was supplied.
    InvalidEndpoint,
    /// An interface is unassigned, duplicated, or outside an endpoint's set.
    InvalidInterface,
    /// No reusable client-badge slot remains, system-wide or at one endpoint.
    BadgeCapacityExhausted,
    /// A stale, retired, closed, or unoccupied client badge was supplied.
    InvalidBadge,
    /// A stale, retired, or already ended pending call was supplied.
    InvalidCall,
    /// A call deadline is zero, which no ordinary client may request.
    InvalidDeadline,
    /// No reusable pending-call record remains system-wide.
    CallCapacityExhausted,
    /// One endpoint's queue is full.
    QueueFull,
    /// Retaining the request would exceed the queued-byte ceiling.
    RetainedBytesExhausted,
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
            Self::InvalidRights => formatter.write_str("service handle rights are invalid"),
            Self::EndpointCapacityExhausted => {
                formatter.write_str("service endpoint capacity exhausted")
            }
            Self::InvalidEndpoint => formatter.write_str("service endpoint is invalid"),
            Self::InvalidInterface => formatter.write_str("service interface is invalid"),
            Self::BadgeCapacityExhausted => formatter.write_str("client badge capacity exhausted"),
            Self::InvalidBadge => formatter.write_str("client badge is invalid"),
            Self::InvalidCall => formatter.write_str("pending call is invalid"),
            Self::InvalidDeadline => formatter.write_str("call deadline is invalid"),
            Self::CallCapacityExhausted => formatter.write_str("pending call capacity exhausted"),
            Self::QueueFull => formatter.write_str("service endpoint queue is full"),
            Self::RetainedBytesExhausted => {
                formatter.write_str("queued request byte ceiling exhausted")
            }
            Self::AccountingOverflow => formatter.write_str("dispatch accounting overflowed"),
        }
    }
}

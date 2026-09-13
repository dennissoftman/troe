//! Closed built-in scheduler authority, distinct from callable service ports.

use crate::HandleOwner;
use troe_abi::{interface, threading};

#[cfg(test)]
mod tests;

/// A kernel-owned scheduler interface at exactly version 1.0.
/// No application service can acquire this type by advertising an interface ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerInterface {
    /// Process-owned thread lifecycle control.
    ControlV1,
    /// Process-private synchronization objects and waits.
    SyncV1,
}

impl SchedulerInterface {
    /// Interface assignment for validating the complete request.
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::ControlV1 => interface::THREAD_CONTROL,
            Self::SyncV1 => interface::THREAD_SYNC,
        }
    }

    /// Exact supported major and minor, fixed by the closed target type.
    #[must_use]
    pub const fn version(self) -> (u16, u16) {
        (threading::MAJOR, threading::MINOR)
    }
}

/// Owned result of authenticating one copied request against a live capability.
///
/// No dispatcher borrow or service callback crosses the scheduler boundary.
/// This validates authority at admission; composition must admit the matching
/// native operation once, execute it and retain its completion identity.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthorizedSchedulerCall {
    pub(crate) owner: HandleOwner,
    pub(crate) request: threading::Request,
}

impl AuthorizedSchedulerCall {
    /// Kernel principal authenticated against the live handle record.
    #[must_use]
    pub const fn owner(&self) -> HandleOwner {
        self.owner
    }

    /// Decoded immutable request whose full operation rights were checked.
    #[must_use]
    pub const fn request(&self) -> threading::Request {
        self.request
    }
}

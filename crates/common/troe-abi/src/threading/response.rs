use super::{EncodingError, Kind, MAJOR, RESPONSE_BYTES, Request, WaitMode, read, token};

/// Scheduler-operation result, separate from IPC transport status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Outcome {
    /// Operation completed; a successful acquisition grants ownership/one permit.
    Success = 0,
    /// Immediate acquisition or join could not complete without waiting.
    WouldBlock = 1,
    /// The admitted absolute deadline expired.
    TimedOut = 2,
    /// The caller's sticky stop request was observed at this cooperative wait.
    Stopped = 3,
    /// The mutex is permanently poisoned; ownership was not granted.
    Poisoned = 4,
    /// Another operation or retained reference prevents this transition.
    Busy = 5,
    /// Self-join or recursive acquisition was detected.
    Deadlock = 6,
    /// The token does not identify a retained generation owned by this process.
    Stale = 7,
    /// The caller does not own the mutex it must release.
    NotOwner = 8,
    /// Outstanding condition operations bind this queue to a different mutex.
    DifferentMutex = 9,
    /// Admission or an identity counter is exhausted.
    Exhausted = 10,
    /// The lifecycle does not permit this operation.
    InvalidState = 11,
    /// The process is stopping and no longer accepts this work.
    Stopping = 12,
    /// The operation record is malformed or noncanonical.
    InvalidRequest = 13,
    /// The admitted implementation does not support this version or operation.
    Unsupported = 14,
    /// The trusted handle lacks the required authority.
    Denied = 15,
    /// A permit release would exceed the immutable maximum.
    Overflow = 16,
}

impl Outcome {
    fn decode(value: u16) -> Result<Self, EncodingError> {
        Ok(match value {
            0 => Self::Success,
            1 => Self::WouldBlock,
            2 => Self::TimedOut,
            3 => Self::Stopped,
            4 => Self::Poisoned,
            5 => Self::Busy,
            6 => Self::Deadlock,
            7 => Self::Stale,
            8 => Self::NotOwner,
            9 => Self::DifferentMutex,
            10 => Self::Exhausted,
            11 => Self::InvalidState,
            12 => Self::Stopping,
            13 => Self::InvalidRequest,
            14 => Self::Unsupported,
            15 => Self::Denied,
            16 => Self::Overflow,
            _ => return Err(EncodingError),
        })
    }
}

/// Lifecycle state observed at one serialized instant, not a continuing lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum State {
    /// Resources are reserved but execution has not been published.
    Prepared = 1,
    /// Runnable, awaiting dispatch.
    Ready = 2,
    /// Currently dispatched.
    Running = 3,
    /// Suspended on an owned wait.
    Blocked = 4,
    /// User execution ended; cleanup is pending.
    Exiting = 5,
    /// Normal completion is retained.
    Completed = 6,
    /// Process termination revoked this execution.
    Revoked = 7,
}

impl State {
    fn decode(value: u8) -> Result<Self, EncodingError> {
        Ok(match value {
            1 => Self::Prepared,
            2 => Self::Ready,
            3 => Self::Running,
            4 => Self::Blocked,
            5 => Self::Exiting,
            6 => Self::Completed,
            7 => Self::Revoked,
            _ => return Err(EncodingError),
        })
    }
}

/// Informational lifecycle flags; they cannot authorize release or reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// State at the observation's linearization point.
    pub state: State,
    /// Sticky cooperative stop has been requested.
    pub stop_requested: bool,
    /// No application join result is retained for this thread.
    pub detached: bool,
    /// Native backing was acknowledged quiescent and released.
    pub resources_released: bool,
}

/// Exact response correlated with the request interface and operation.
///
/// For a valid condition wait, success, timeout and cooperative stop all return
/// with the original mutex reacquired. Poison grants no ownership. Timeout and
/// stop never cancel the reacquisition phase. A snapshot is informational only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response {
    /// Operation outcome, never an IPC transport status.
    pub outcome: Outcome,
    /// Success-only token or join result; zero for every other operation.
    pub value: u64,
    /// Present only for a successful observation.
    pub snapshot: Option<Snapshot>,
}

impl Response {
    /// Decode a response for a validated request.
    ///
    /// # Errors
    /// Rejects noncanonical lengths, reserved bits, mismatched correlation,
    /// impossible payloads and outcomes incompatible with the wait mode.
    pub fn decode(request: Request, bytes: &[u8]) -> Result<Self, EncodingError> {
        request.encode()?;
        if bytes.len() != RESPONSE_BYTES
            || u32::from_le_bytes(read(bytes, 0)?) != request.interface()
            || u16::from_le_bytes(read(bytes, 4)?) != MAJOR
            || u16::from_le_bytes(read(bytes, 6)?) != request.opcode()
            || bytes[11] & !7 != 0
            || bytes[12..16] != [0; 4]
            || bytes[24..32] != [0; 8]
        {
            return Err(EncodingError);
        }
        let snapshot = if bytes[10] == 0 {
            if bytes[11] != 0 {
                return Err(EncodingError);
            }
            None
        } else {
            Some(Snapshot {
                state: State::decode(bytes[10])?,
                stop_requested: bytes[11] & 1 != 0,
                detached: bytes[11] & 2 != 0,
                resources_released: bytes[11] & 4 != 0,
            })
        };
        let result = Self {
            outcome: Outcome::decode(u16::from_le_bytes(read(bytes, 8)?))?,
            value: u64::from_le_bytes(read(bytes, 16)?),
            snapshot,
        };
        result.validate(request)?;
        Ok(result)
    }

    /// Encode a canonical response for the given request without partial output.
    ///
    /// # Errors
    /// Rejects invalid requests and incompatible result payloads or outcomes.
    pub fn encode(self, request: Request) -> Result<[u8; RESPONSE_BYTES], EncodingError> {
        request.encode()?;
        self.validate(request)?;
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..4].copy_from_slice(&request.interface().to_le_bytes());
        bytes[4..6].copy_from_slice(&MAJOR.to_le_bytes());
        bytes[6..8].copy_from_slice(&request.opcode().to_le_bytes());
        bytes[8..10].copy_from_slice(&(self.outcome as u16).to_le_bytes());
        if let Some(snapshot) = self.snapshot {
            bytes[10] = snapshot.state as u8;
            bytes[11] = u8::from(snapshot.stop_requested)
                | u8::from(snapshot.detached) << 1
                | u8::from(snapshot.resources_released) << 2;
        }
        bytes[16..24].copy_from_slice(&self.value.to_le_bytes());
        Ok(bytes)
    }

    fn validate(self, request: Request) -> Result<(), EncodingError> {
        if self.outcome == Outcome::Success {
            match request {
                Request::Prepare { .. } | Request::Current => {
                    token(self.value, Kind::Thread)?;
                }
                Request::CreateMutex(_) => {
                    token(self.value, Kind::Mutex)?;
                }
                Request::CreateCondition => {
                    token(self.value, Kind::Condition)?;
                }
                Request::CreatePermit { .. } => {
                    token(self.value, Kind::Permit)?;
                }
                Request::Join { .. } => (),
                Request::Exit(_) => return Err(EncodingError),
                _ if self.value != 0 => return Err(EncodingError),
                _ => (),
            }
            if matches!(request, Request::Observe(_)) != self.snapshot.is_some() {
                return Err(EncodingError);
            }
            if self.snapshot.is_some_and(|s| {
                s.resources_released && !matches!(s.state, State::Completed | State::Revoked)
            }) {
                return Err(EncodingError);
            }
        } else {
            if self.value != 0 || self.snapshot.is_some() {
                return Err(EncodingError);
            }
            let compatible = match self.outcome {
                Outcome::WouldBlock => request.wait() == Some(WaitMode::Try),
                Outcome::TimedOut => {
                    matches!(request.wait(), Some(WaitMode::Wait(w)) if w.deadline.is_some())
                }
                Outcome::Stopped => {
                    matches!(request.wait(), Some(WaitMode::Wait(w)) if w.observe_stop)
                }
                Outcome::Poisoned => matches!(
                    request,
                    Request::Lock { .. } | Request::ConditionWait { .. }
                ),
                Outcome::Deadlock => matches!(request, Request::Join { .. } | Request::Lock { .. }),
                Outcome::NotOwner => {
                    matches!(request, Request::Unlock(_) | Request::ConditionWait { .. })
                }
                Outcome::DifferentMutex => matches!(request, Request::ConditionWait { .. }),
                Outcome::Overflow => matches!(request, Request::ReleasePermit { .. }),
                _ => true,
            };
            if !compatible {
                return Err(EncodingError);
            }
        }
        Ok(())
    }
}

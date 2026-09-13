use super::{
    EncodingError, Kind, MAJOR, OwnerDeath, REQUEST_BYTES, Token, Wait, WaitMode, read, token,
};
use crate::interface::{self, rights};

/// Closed operations on process-owned lifecycle and synchronization records.
///
/// Record tokens are identities, not capabilities. Trusted composition derives
/// the process and caller from the scheduled context and checks handle rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    /// Prepare an unpublished worker using an immutable image-relative entry.
    Prepare {
        /// Offset in the admitted image; execution permission needs a native check.
        entry_offset: u64,
        /// Opaque word delivered to the worker entry.
        argument: u64,
        /// Fully committed stack pages, additionally bounded by admission policy.
        stack_pages: u64,
    },
    /// Publish a prepared worker created by this caller.
    Start(Token),
    /// Discard a worker still prepared by this caller.
    Abort(Token),
    /// Collect a noninitial thread's scalar result, with one exclusive joiner.
    Join {
        /// Process-owned thread record.
        thread: Token,
        /// Immediate test or bounded/cooperative wait.
        wait: WaitMode,
    },
    /// Relinquish the right to collect a noninitial thread's result.
    Detach(Token),
    /// Set a thread's sticky cooperative stop request.
    RequestStop(Token),
    /// Read a thread lifecycle snapshot.
    Observe(Token),
    /// Read the caller's own thread token.
    Current,
    /// Complete the caller with a scalar result; successful exit never returns.
    Exit(u64),
    /// Suspend the caller until its deadline or an observed stop request.
    Sleep(Wait),
    /// Create a nonrecursive owner-checked mutex with immutable death policy.
    CreateMutex(OwnerDeath),
    /// Create a condition queue, bound to one mutex while waits are outstanding.
    CreateCondition,
    /// Create an ownerless bounded permit counter.
    CreatePermit {
        /// Initially available permits.
        count: u32,
        /// Nonzero immutable maximum count.
        maximum: u32,
    },
    /// Acquire a mutex; poison never grants ownership.
    Lock {
        /// Process-owned mutex record.
        mutex: Token,
        /// Immediate test or bounded/cooperative wait.
        wait: WaitMode,
    },
    /// Release a mutex owned by the caller.
    Unlock(Token),
    /// Atomically enqueue and release the owned mutex, then reacquire it.
    ConditionWait {
        /// Process-owned condition record.
        condition: Token,
        /// Mutex owned by the caller before entry.
        mutex: Token,
        /// Deadline/stop affect the condition phase, not mutex reacquisition.
        wait: Wait,
    },
    /// Notify one or every waiter already queued on a condition.
    Notify {
        /// Process-owned condition record.
        condition: Token,
        /// Broadcast when true, otherwise select one queued waiter.
        all: bool,
    },
    /// Acquire one ownerless permit.
    AcquirePermit {
        /// Process-owned permit record.
        permit: Token,
        /// Immediate test or bounded/cooperative wait.
        wait: WaitMode,
    },
    /// Release a nonzero count; overflow fails without a partial release.
    ReleasePermit {
        /// Process-owned permit record.
        permit: Token,
        /// Number of permits to release.
        count: u32,
    },
    /// Destroy an unowned mutex with no pending operations or references.
    DestroyMutex(Token),
    /// Destroy a condition with no pending operations or references.
    DestroyCondition(Token),
    /// Destroy a permit counter with no pending operations or references.
    DestroyPermit(Token),
}

impl Request {
    /// Trusted handle interface required for this operation.
    #[must_use]
    pub const fn interface(self) -> u32 {
        match self {
            Self::Prepare { .. }
            | Self::Start(_)
            | Self::Abort(_)
            | Self::Join { .. }
            | Self::Detach(_)
            | Self::RequestStop(_)
            | Self::Observe(_)
            | Self::Current
            | Self::Exit(_)
            | Self::Sleep(_) => interface::THREAD_CONTROL,
            _ => interface::THREAD_SYNC,
        }
    }

    /// Operation number within its interface major.
    #[must_use]
    pub const fn opcode(self) -> u16 {
        match self {
            Self::Prepare { .. } | Self::CreateMutex(_) => 1,
            Self::Start(_) | Self::CreateCondition => 2,
            Self::Abort(_) | Self::CreatePermit { .. } => 3,
            Self::Join { .. } | Self::Lock { .. } => 4,
            Self::Detach(_) | Self::Unlock(_) => 5,
            Self::RequestStop(_) | Self::ConditionWait { .. } => 6,
            Self::Observe(_) | Self::Notify { .. } => 7,
            Self::Current | Self::AcquirePermit { .. } => 8,
            Self::Exit(_) | Self::ReleasePermit { .. } => 9,
            Self::Sleep(_) | Self::DestroyMutex(_) => 10,
            Self::DestroyCondition(_) => 11,
            Self::DestroyPermit(_) => 12,
        }
    }

    /// Required rights, checked against the kernel capability rather than bytes.
    #[must_use]
    pub const fn required_rights(self) -> u16 {
        rights::CALL
            | match self {
                Self::Prepare { .. } => rights::THREAD_CREATE,
                Self::Start(_) | Self::Abort(_) => rights::THREAD_START,
                Self::Join { .. } => rights::THREAD_JOIN,
                Self::Detach(_) => rights::THREAD_DETACH,
                Self::RequestStop(_) => rights::THREAD_STOP,
                Self::Observe(_) | Self::Current => rights::THREAD_OBSERVE,
                _ => 0,
            }
    }

    /// Decode exact-length bytes against a previously authenticated interface.
    ///
    /// # Errors
    /// Rejects unknown versions, opcodes, flags, token kinds, invalid bounds and
    /// any nonzero unused word. This does not check live state or authority.
    pub fn decode(expected_interface: u32, bytes: &[u8]) -> Result<Self, EncodingError> {
        if bytes.len() != REQUEST_BYTES
            || u16::from_le_bytes(read(bytes, 0)?) != MAJOR
            || u32::from_le_bytes(read(bytes, 4)?) != expected_interface
        {
            return Err(EncodingError);
        }
        let opcode = u16::from_le_bytes(read(bytes, 2)?);
        let mut words = [0; 7];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u64::from_le_bytes(read(bytes, 8 + index * 8)?);
        }
        let [a, b, c, d, _, _, _] = words;
        let (request, used) = match (expected_interface, opcode) {
            (interface::THREAD_CONTROL, 1) if a < 1 << 30 && c > 0 && c <= 1 << 32 => (
                Self::Prepare {
                    entry_offset: a,
                    argument: b,
                    stack_pages: c,
                },
                3,
            ),
            (interface::THREAD_CONTROL, 2) => (Self::Start(token(a, Kind::Thread)?), 1),
            (interface::THREAD_CONTROL, 3) => (Self::Abort(token(a, Kind::Thread)?), 1),
            (interface::THREAD_CONTROL, 4) => (
                Self::Join {
                    thread: token(a, Kind::Thread)?,
                    wait: WaitMode::decode(b, c)?,
                },
                3,
            ),
            (interface::THREAD_CONTROL, 5) => (Self::Detach(token(a, Kind::Thread)?), 1),
            (interface::THREAD_CONTROL, 6) => (Self::RequestStop(token(a, Kind::Thread)?), 1),
            (interface::THREAD_CONTROL, 7) => (Self::Observe(token(a, Kind::Thread)?), 1),
            (interface::THREAD_CONTROL, 8) => (Self::Current, 0),
            (interface::THREAD_CONTROL, 9) => (Self::Exit(a), 1),
            (interface::THREAD_CONTROL, 10) => (Self::Sleep(WaitMode::decode(a, b)?.waiting()?), 2),
            (interface::THREAD_SYNC, 1) if a <= 1 => (
                Self::CreateMutex(if a == 0 {
                    OwnerDeath::Poison
                } else {
                    OwnerDeath::FailProcess
                }),
                1,
            ),
            (interface::THREAD_SYNC, 2) => (Self::CreateCondition, 0),
            (interface::THREAD_SYNC, 3) if b > 0 && a <= b => (
                Self::CreatePermit {
                    count: u32::try_from(a).map_err(|_| EncodingError)?,
                    maximum: u32::try_from(b).map_err(|_| EncodingError)?,
                },
                2,
            ),
            (interface::THREAD_SYNC, 4) => (
                Self::Lock {
                    mutex: token(a, Kind::Mutex)?,
                    wait: WaitMode::decode(b, c)?,
                },
                3,
            ),
            (interface::THREAD_SYNC, 5) => (Self::Unlock(token(a, Kind::Mutex)?), 1),
            (interface::THREAD_SYNC, 6) => (
                Self::ConditionWait {
                    condition: token(a, Kind::Condition)?,
                    mutex: token(b, Kind::Mutex)?,
                    wait: WaitMode::decode(c, d)?.waiting()?,
                },
                4,
            ),
            (interface::THREAD_SYNC, 7) if b <= 1 => (
                Self::Notify {
                    condition: token(a, Kind::Condition)?,
                    all: b == 1,
                },
                2,
            ),
            (interface::THREAD_SYNC, 8) => (
                Self::AcquirePermit {
                    permit: token(a, Kind::Permit)?,
                    wait: WaitMode::decode(b, c)?,
                },
                3,
            ),
            (interface::THREAD_SYNC, 9) if b > 0 => (
                Self::ReleasePermit {
                    permit: token(a, Kind::Permit)?,
                    count: u32::try_from(b).map_err(|_| EncodingError)?,
                },
                2,
            ),
            (interface::THREAD_SYNC, 10) => (Self::DestroyMutex(token(a, Kind::Mutex)?), 1),
            (interface::THREAD_SYNC, 11) => (Self::DestroyCondition(token(a, Kind::Condition)?), 1),
            (interface::THREAD_SYNC, 12) => (Self::DestroyPermit(token(a, Kind::Permit)?), 1),
            _ => return Err(EncodingError),
        };
        if words[used..].iter().any(|word| *word != 0) {
            return Err(EncodingError);
        }
        Ok(request)
    }

    /// Produce a canonical record, validating even directly constructed values.
    ///
    /// # Errors
    /// Rejects invalid bounds or tokens of the wrong kind, without partial output.
    pub fn encode(self) -> Result<[u8; REQUEST_BYTES], EncodingError> {
        let mut words = [0; 7];
        match self {
            Self::Prepare {
                entry_offset,
                argument,
                stack_pages,
            } => words[..3].copy_from_slice(&[entry_offset, argument, stack_pages]),
            Self::Start(t)
            | Self::Abort(t)
            | Self::Detach(t)
            | Self::RequestStop(t)
            | Self::Observe(t)
            | Self::Unlock(t)
            | Self::DestroyMutex(t)
            | Self::DestroyCondition(t)
            | Self::DestroyPermit(t) => words[0] = t.bits(),
            Self::Join { thread: t, wait }
            | Self::Lock { mutex: t, wait }
            | Self::AcquirePermit { permit: t, wait } => {
                let (flags, deadline) = wait.words();
                words[..3].copy_from_slice(&[t.bits(), flags, deadline]);
            }
            Self::Exit(value) => words[0] = value,
            Self::Sleep(wait) => {
                let (flags, deadline) = WaitMode::Wait(wait).words();
                words[..2].copy_from_slice(&[flags, deadline]);
            }
            Self::CreateMutex(policy) => words[0] = policy as u64,
            Self::CreatePermit { count, maximum } => {
                words[..2].copy_from_slice(&[u64::from(count), u64::from(maximum)]);
            }
            Self::ConditionWait {
                condition,
                mutex,
                wait,
            } => {
                let (flags, deadline) = WaitMode::Wait(wait).words();
                words[..4].copy_from_slice(&[condition.bits(), mutex.bits(), flags, deadline]);
            }
            Self::Notify { condition, all } => {
                words[..2].copy_from_slice(&[condition.bits(), u64::from(all)]);
            }
            Self::ReleasePermit { permit, count } => {
                words[..2].copy_from_slice(&[permit.bits(), u64::from(count)]);
            }
            Self::Current | Self::CreateCondition => (),
        }
        let mut bytes = [0; REQUEST_BYTES];
        bytes[..2].copy_from_slice(&MAJOR.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.opcode().to_le_bytes());
        bytes[4..8].copy_from_slice(&self.interface().to_le_bytes());
        for (index, word) in words.into_iter().enumerate() {
            bytes[8 + index * 8..16 + index * 8].copy_from_slice(&word.to_le_bytes());
        }
        Self::decode(self.interface(), &bytes)?;
        Ok(bytes)
    }

    pub(super) const fn wait(self) -> Option<WaitMode> {
        match self {
            Self::Join { wait, .. }
            | Self::Lock { wait, .. }
            | Self::AcquirePermit { wait, .. } => Some(wait),
            Self::Sleep(wait) | Self::ConditionWait { wait, .. } => Some(WaitMode::Wait(wait)),
            _ => None,
        }
    }
}

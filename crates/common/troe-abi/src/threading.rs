//! Closed thread/synchronization wire contracts. Native admission is disabled.
//!
//! These allocation-free codecs neither authenticate tokens nor execute calls.
//! The threaded startup profile is separate from ABI 1.3 and must be admitted
//! before using the scheduler call entry. In particular, a synchronization wait
//! is not an IPC endpoint call and never renews a delegated execution lease.

mod request;
mod response;
mod startup;
pub use request::Request;
pub use response::{Outcome, Response, Snapshot, State};
pub use startup::{StartupDescriptor, StartupReference};

/// Thread/synchronization interface major.
pub const MAJOR: u16 = 1;
/// Thread/synchronization interface minor.
pub const MINOR: u16 = 0;
/// Assigned scheduler-call entry; the current native dispatcher rejects it.
pub const CALL: u64 = 6;
/// Exact private TX request prefix.
pub const REQUEST_BYTES: usize = 64;
/// Exact private RX response prefix.
pub const RESPONSE_BYTES: usize = 32;
/// Exact immutable per-thread startup descriptor prefix.
pub const STARTUP_BYTES: usize = 128;
/// Dedicated read-only descriptor mapping, including zeroed trailing bytes.
pub const STARTUP_MAPPING_BYTES: u64 = 4096;
/// Page size of the closed threaded profile.
pub const PAGE_BYTES: u64 = 4096;
/// Exclusive end of the lower 48-bit user range.
pub const USER_END: u64 = 0x0000_8000_0000_0000;

/// Invalid, noncanonical, unsupported or inconsistent protocol bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Canonical call-6 arguments using the caller's already-owned TX/RX pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Call {
    /// Capability handle, subject to trusted owner/type/version/right checks.
    pub handle: u64,
}

/// Two-register call completion; operation outcomes live only in the RX record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// A canonical, request-correlated 32-byte response is available.
    Response,
    /// Invalid frame, profile or capability; no operation or RX prefix is exposed.
    Rejected,
}

impl Completion {
    /// Decode the complete pair, rejecting truncation and unexpected lengths.
    #[must_use]
    pub const fn decode(words: [u64; 2]) -> Option<Self> {
        match words {
            [0, 32] => Some(Self::Response),
            [1, 0] => Some(Self::Rejected),
            _ => None,
        }
    }

    /// Encode the exact status and available RX byte count.
    #[must_use]
    pub const fn encode(self) -> [u64; 2] {
        match self {
            Self::Response => [0, RESPONSE_BYTES as u64],
            Self::Rejected => [1, 0],
        }
    }
}

impl Call {
    /// Validate every register without truncation; no user pointer is accepted.
    #[must_use]
    pub fn decode(words: [u64; 6]) -> Option<Self> {
        (words[0] != 0
            && words[1] == REQUEST_BYTES as u64
            && words[2] == RESPONSE_BYTES as u64
            && words[3..] == [0; 3])
            .then_some(Self { handle: words[0] })
    }

    /// Encode the six canonical registers.
    ///
    /// # Errors
    /// Rejects a zero capability handle.
    pub fn encode(self) -> Result<[u64; 6], EncodingError> {
        if self.handle == 0 {
            return Err(EncodingError);
        }
        Ok([
            self.handle,
            REQUEST_BYTES as u64,
            RESPONSE_BYTES as u64,
            0,
            0,
            0,
        ])
    }
}

/// A token's closed domain tag; tags are not authority or a process identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    /// Thread lifecycle record.
    Thread = 1,
    /// Owner-checked mutex.
    Mutex = 2,
    /// Condition queue.
    Condition = 3,
    /// Ownerless bounded permit counter.
    Permit = 4,
}

/// Process-scoped opaque record identity, distinct from a capability handle.
///
/// Bits 0..23 encode slot + 1, bits 24..31 the kind, and bits 32..63 a nonzero
/// generation. Generation exhaustion retires storage; it must never wrap.
/// A valid shape proves no ownership, liveness, authority or originating table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token(u64);

impl Token {
    /// Construct a token from trusted record metadata.
    ///
    /// # Errors
    /// Rejects an unrepresentable slot or zero generation.
    pub const fn new(kind: Kind, slot: u32, generation: u32) -> Result<Self, EncodingError> {
        if slot >= 0x00ff_ffff || generation == 0 {
            return Err(EncodingError);
        }
        Ok(Self(
            ((generation as u64) << 32) | ((kind as u64) << 24) | (slot as u64 + 1),
        ))
    }

    /// Decode a token's shape, without looking up a kernel record.
    ///
    /// # Errors
    /// Rejects zero slot/generation fields or unknown kind tags.
    pub const fn decode(bits: u64) -> Result<Self, EncodingError> {
        if bits >> 32 == 0
            || bits.trailing_zeros() >= 24
            || (bits >> 24) & 0xff < 1
            || (bits >> 24) & 0xff > 4
        {
            return Err(EncodingError);
        }
        Ok(Self(bits))
    }

    /// Complete opaque wire value.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Nonzero generation; trusted composition must compare it with live state.
    #[must_use]
    pub fn generation(self) -> u32 {
        u32::try_from(self.0 >> 32).unwrap_or_else(|_| unreachable!())
    }

    /// Zero-based record slot, never an unchecked array index.
    #[must_use]
    pub fn slot(self) -> u32 {
        u32::try_from((self.0 & 0x00ff_ffff) - 1).unwrap_or_else(|_| unreachable!())
    }

    /// Closed domain tag.
    #[must_use]
    pub const fn kind(self) -> Kind {
        match (self.0 >> 24) & 0xff {
            1 => Kind::Thread,
            2 => Kind::Mutex,
            3 => Kind::Condition,
            _ => Kind::Permit,
        }
    }
}

/// Absolute boot-relative monotonic milliseconds; zero and the largest deadline
/// are real values, distinct from an indefinite wait.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Wait {
    /// `None` means no deadline, with a separate wire tag rather than a sentinel.
    pub deadline: Option<u64>,
    /// Observe the caller's sticky cooperative stop request.
    pub observe_stop: bool,
}

/// Immediate availability testing is separate from deadline-aware waiting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitMode {
    /// No queue admission, deadline or cooperative stop observation.
    Try,
    /// Potentially suspend on one generation-checked wait operation.
    Wait(Wait),
}

impl WaitMode {
    fn words(self) -> (u64, u64) {
        match self {
            Self::Try => (0, 0),
            Self::Wait(wait) => (
                if wait.deadline.is_some() { 2 } else { 1 }
                    | if wait.observe_stop { 0x100 } else { 0 },
                wait.deadline.unwrap_or(0),
            ),
        }
    }

    fn decode(flags: u64, deadline: u64) -> Result<Self, EncodingError> {
        if flags & !0x103 != 0 {
            return Err(EncodingError);
        }
        match flags & 3 {
            0 if flags == 0 && deadline == 0 => Ok(Self::Try),
            1 if deadline == 0 => Ok(Self::Wait(Wait {
                deadline: None,
                observe_stop: flags & 0x100 != 0,
            })),
            2 => Ok(Self::Wait(Wait {
                deadline: Some(deadline),
                observe_stop: flags & 0x100 != 0,
            })),
            _ => Err(EncodingError),
        }
    }

    fn waiting(self) -> Result<Wait, EncodingError> {
        match self {
            Self::Wait(wait) => Ok(wait),
            Self::Try => Err(EncodingError),
        }
    }
}

/// Immutable mutex-owner death policy, independent of language exceptions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum OwnerDeath {
    /// Permanent poison, with no ownership granted after owner death.
    Poison = 0,
    /// Stop the whole process for loss of an essential runtime invariant.
    FailProcess = 1,
}

fn token(bits: u64, kind: Kind) -> Result<Token, EncodingError> {
    let value = Token::decode(bits)?;
    if value.kind() != kind {
        return Err(EncodingError);
    }
    Ok(value)
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], EncodingError> {
    bytes
        .get(offset..offset + N)
        .ok_or(EncodingError)?
        .try_into()
        .map_err(|_| EncodingError)
}

fn user_range(start: u64, bytes: u64) -> Result<u64, EncodingError> {
    if start < PAGE_BYTES
        || !start.is_multiple_of(PAGE_BYTES)
        || bytes == 0
        || !bytes.is_multiple_of(PAGE_BYTES)
    {
        return Err(EncodingError);
    }
    start
        .checked_add(bytes)
        .filter(|end| *end <= USER_END)
        .ok_or(EncodingError)
}

#[cfg(test)]
mod tests;

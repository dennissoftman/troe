//! ABI 1.3 private-page synchronous IPC scalars and receive registers.

/// Private-page client call number.
pub const CALL: u64 = 4;
/// Atomic server reply and wait call number.
pub const REPLY_WAIT: u64 = 5;
/// Persistent endpoint interface version.
pub const ENDPOINT_MAJOR: u16 = 2;
/// Immutable wait-set interface version.
pub const WAIT_SET_MAJOR: u16 = 1;
/// Longest admitted absolute call deadline relative to admission.
pub const MAX_CALL_MILLIS: u64 = 4_000;
/// Resident-server idle wait without a deadline.
pub const IDLE: u64 = u64::MAX;

/// Canonical client call, before authority and deadline admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Call {
    /// Owner-scoped capability token.
    pub handle: u64,
    /// Service operation scalar, separate from payload bytes.
    pub opcode: u16,
    /// Exact TX prefix length.
    pub request_bytes: u16,
    /// Largest accepted RX prefix.
    pub reply_capacity: u16,
    /// Absolute boot-relative deadline in milliseconds.
    pub deadline_millis: u64,
    /// Interface-defined object offset; zero for user endpoints.
    pub object_parameter: u64,
}

impl Call {
    /// Decode all six argument registers without truncation.
    #[must_use]
    #[inline]
    pub fn decode(words: [u64; 6]) -> Option<Self> {
        if words[0] == 0 || words[2] > 4096 || words[3] > 4096 || words[4] == IDLE {
            return None;
        }
        Some(Self {
            handle: words[0],
            opcode: u16::try_from(words[1]).ok()?,
            request_bytes: u16::try_from(words[2]).ok()?,
            reply_capacity: u16::try_from(words[3]).ok()?,
            deadline_millis: words[4],
            object_parameter: words[5],
        })
    }

    /// Whether the absolute deadline is live and within both fixed ceilings.
    #[must_use]
    pub fn deadline_valid(self, now: u64, endpoint_millis: u64) -> bool {
        self.deadline_millis
            .checked_sub(now)
            .is_some_and(|remaining| {
                remaining != 0 && remaining <= endpoint_millis.min(MAX_CALL_MILLIS)
            })
    }
}

/// Canonical server reply and newly requested wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyWait {
    /// Owned immutable wait-set capability.
    pub wait_set: u64,
    /// Exact delivered token, or zero for an initial wait.
    pub token: u64,
    /// Service result; transport-only results cannot be forged by a server.
    pub status: u32,
    /// Exact outbound TX prefix.
    pub reply_bytes: u16,
    /// Absolute new wait deadline, or [`IDLE`].
    pub deadline_millis: u64,
}

impl ReplyWait {
    /// Decode the five arguments and require the unused sixth word to be zero.
    #[must_use]
    #[inline]
    pub fn decode(words: [u64; 6]) -> Option<Self> {
        let status = u32::try_from(words[2]).ok()?;
        if words[0] == 0
            || !crate::reply::is_known(status)
            || words[3] > 4096
            || words[5] != 0
            || (words[1] == 0 && (status != 0 || words[3] != 0))
        {
            return None;
        }
        Some(Self {
            wait_set: words[0],
            token: words[1],
            status,
            reply_bytes: u16::try_from(words[3]).ok()?,
            deadline_millis: words[4],
        })
    }
}

/// Closed receive-event vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum EventKind {
    /// A copied synchronous request.
    Call = 1,
    /// A device source became ready.
    ResourceReady = 2,
    /// The new wait's absolute deadline elapsed.
    Deadline = 3,
    /// A source closed cleanly.
    Closed = 4,
    /// A source was revoked.
    Revoked = 5,
    /// The last handle belonging to this client badge closed.
    ClientClosed = 6,
}

/// Typed interpretation of the six call-specific result registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    /// Closed event kind.
    pub kind: EventKind,
    /// Generation-checked delivered-call identity.
    pub token: u64,
    /// Immutable wait-set source index.
    pub source: u16,
    /// Endpoint-scoped opaque client identity.
    pub badge: u32,
    /// Delivered interface identity.
    pub interface: u32,
    /// Delivered operation scalar.
    pub opcode: u16,
    /// Exact copied RX prefix length.
    pub request_bytes: u16,
    /// Client's accepted maximum reply length.
    pub reply_capacity: u16,
}

impl Event {
    /// Encode the six result words, including canonical zero reservations.
    #[must_use]
    pub const fn words(self) -> [u64; 6] {
        [
            self.kind as u64,
            self.token,
            self.source as u64 | ((self.badge as u64) << 32),
            self.interface as u64 | ((self.opcode as u64) << 32),
            self.request_bytes as u64,
            self.reply_capacity as u64,
        ]
    }

    /// Reject unknown kinds, reserved bits, impossible lengths, and non-call metadata.
    #[must_use]
    pub fn decode(words: [u64; 6]) -> Option<Self> {
        let kind = match words[0] {
            1 => EventKind::Call,
            2 => EventKind::ResourceReady,
            3 => EventKind::Deadline,
            4 => EventKind::Closed,
            5 => EventKind::Revoked,
            6 => EventKind::ClientClosed,
            _ => return None,
        };
        if words[2] & 0xffff_0000 != 0 || words[3] >> 48 != 0 || words[4] > 4096 || words[5] > 4096
        {
            return None;
        }
        let badge = u32::try_from(words[2] >> 32).ok()?;
        if kind == EventKind::Call {
            if words[1] == 0 || badge == 0 || words[3].trailing_zeros() >= 32 {
                return None;
            }
        } else if words[1] != 0
            || words[3..].iter().any(|word| *word != 0)
            || (kind == EventKind::ClientClosed) != (badge != 0)
        {
            return None;
        }
        Some(Self {
            kind,
            token: words[1],
            source: u16::try_from(words[2] & 0xffff).ok()?,
            badge,
            interface: u32::try_from(words[3] & 0xffff_ffff).ok()?,
            opcode: u16::try_from(words[3] >> 32).ok()?,
            request_bytes: u16::try_from(words[4]).ok()?,
            reply_capacity: u16::try_from(words[5]).ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_payload_and_scalar_boundaries() {
        let valid = [1, 65535, 4096, 4096, 4001, 0];
        let call = Call::decode(valid).unwrap_or_else(|| unreachable!());
        assert!(call.deadline_valid(1, 4000));
        assert!(!call.deadline_valid(0, 4000));
        assert!(!call.deadline_valid(4001, 4000));
        for (index, bad) in [(0, 0), (1, 65536), (2, 4097), (3, 4097), (4, IDLE)] {
            let mut words = valid;
            words[index] = bad;
            assert!(Call::decode(words).is_none());
        }
        assert!(ReplyWait::decode([1, 0, 0, 0, IDLE, 0]).is_some());
        for status in 0..=crate::reply::DEADLOCK + 1 {
            assert_eq!(
                ReplyWait::decode([1, 1, u64::from(status), 4096, IDLE, 0]).is_some(),
                crate::reply::is_known(status)
            );
        }
        assert!(ReplyWait::decode([1, 0, 1, 0, IDLE, 0]).is_none());
        assert!(ReplyWait::decode([1, 0, 0, 1, IDLE, 0]).is_none());
    }

    #[test]
    fn receive_registers_are_canonical() {
        let words = [
            1,
            u64::MAX,
            u64::from(u32::MAX) << 32 | 3,
            0xffff_u64 << 32 | 0x1d,
            4096,
            4096,
        ];
        assert_eq!(Event::decode(words).map(Event::words), Some(words));
        for (index, bad) in [
            (0, 0),
            (0, 7),
            (1, 0),
            (2, 1 << 16),
            (3, 1 << 48),
            (4, 4097),
            (5, 4097),
        ] {
            let mut invalid = words;
            invalid[index] = bad;
            assert!(Event::decode(invalid).is_none());
        }
        for kind in 2..=6 {
            let event = [kind, 0, if kind == 6 { 1 << 32 } else { 0 }, 0, 0, 0];
            assert_eq!(Event::decode(event).map(Event::words), Some(event));
            let mut invalid = event;
            invalid[4] = 1;
            assert!(Event::decode(invalid).is_none());
        }
    }
}

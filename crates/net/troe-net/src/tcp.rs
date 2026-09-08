//! Bounded active and passive TCP state for the typed KEX connect and listen
//! services.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::{Ipv4Address, NetError};

/// Maximum TCP payload under the 1,500-byte IPv4 MTU without options.
pub const MAX_TCP_PAYLOAD_BYTES: usize = 1_460;
/// Per-connection receive FIFO bytes.
pub const MAX_TCP_RECEIVE_BYTES: usize = 4 * 1024;
/// System-wide live TCP connection ceiling, counting half-open passive opens
/// and connections still holding their tuple in `TimeWait`.
pub const MAX_TCP_CONNECTIONS: usize = 16;
/// System-wide bound on owned listening local endpoints.
pub const MAX_TCP_LISTENERS: usize = 2;
/// Per-listener bound on passive opens awaiting acceptance.
pub const MAX_TCP_BACKLOG: usize = 4;
/// Total transmissions permitted for one SYN, data segment, or FIN.
pub const TCP_TRANSMIT_ATTEMPTS: u8 = 4;
/// Interval an actively closed connection retains its tuple before reclamation.
///
/// The bounded profile deliberately does not use the conventional two-maximum-
/// segment-lifetime interval. This value covers the complete 2,750 ms
/// retransmission schedule, so a peer's delayed final FIN cannot arrive after
/// the tuple has been reused.
pub const TCP_TIME_WAIT_MILLISECONDS: u64 = 4_000;

const RETRANSMIT_DELAYS_MILLISECONDS: [u64; 4] = [250, 500, 1_000, 1_000];

/// Stable TCP state-machine failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpError {
    /// Endpoint, flags, payload, or state transition was invalid.
    Invalid,
    /// Another operation is already awaiting acknowledgement.
    Busy,
    /// The peer's advertised window cannot currently accept data.
    WindowClosed,
    /// Bounded receive or transmit storage could not be reserved.
    Exhausted,
    /// The bounded retransmission schedule expired.
    Timeout,
    /// An exact in-window reset terminated the connection.
    Reset,
    /// The peer closed its sending half.
    Closed,
}

/// One literal IPv4 TCP endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpEndpoint {
    address: Ipv4Address,
    port: u16,
}

impl TcpEndpoint {
    /// Construct an endpoint with a nonzero port.
    ///
    /// # Errors
    ///
    /// Rejects port zero.
    pub const fn new(address: Ipv4Address, port: u16) -> Result<Self, NetError> {
        if port == 0 {
            return Err(NetError::Invalid);
        }
        Ok(Self { address, port })
    }

    /// Literal IPv4 address.
    #[must_use]
    pub const fn address(self) -> Ipv4Address {
        self.address
    }

    /// Nonzero TCP port after validation.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    const fn is_valid(self) -> bool {
        self.port != 0
    }
}

/// Accepted initial-profile TCP control bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    /// Finish flag.
    pub const FIN: Self = Self(0x01);
    /// Synchronize flag.
    pub const SYN: Self = Self(0x02);
    /// Reset flag.
    pub const RST: Self = Self(0x04);
    /// Acknowledgement flag.
    pub const ACK: Self = Self(0x10);
    /// Synchronize plus acknowledgement.
    pub const SYN_ACK: Self = Self(Self::SYN.0 | Self::ACK.0);
    /// Push plus acknowledgement for application data.
    pub const PSH_ACK: Self = Self(0x08 | Self::ACK.0);
    /// Finish plus acknowledgement.
    pub const FIN_ACK: Self = Self(Self::FIN.0 | Self::ACK.0);

    /// Validate raw TCP flag bits against the initial profile.
    ///
    /// # Errors
    ///
    /// Rejects unsupported bits and contradictory SYN/FIN/RST combinations.
    pub const fn from_bits(bits: u8) -> Result<Self, NetError> {
        const ALLOWED: u8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;
        let controls = bits & (Self::FIN.0 | Self::SYN.0 | Self::RST.0);
        if bits & !ALLOWED != 0
            || controls.count_ones() > 1
            || bits == 0
            || bits & 0x08 != 0 && bits & Self::ACK.0 == 0
        {
            return Err(NetError::Unsupported);
        }
        Ok(Self(bits))
    }

    /// Exact wire bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether all requested bits are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Parsed or synthetic TCP segment at the portable state-machine boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment<'a> {
    /// Remote or local source endpoint.
    pub source: TcpEndpoint,
    /// Remote or local destination endpoint.
    pub destination: TcpEndpoint,
    /// First sequence number represented by the segment.
    pub sequence: u32,
    /// Next sequence expected from the other endpoint when ACK is present.
    pub acknowledgement: u32,
    /// Validated initial-profile flags.
    pub flags: TcpFlags,
    /// Unscaled advertised receive window.
    pub window: u16,
    /// At-most-one-MTU payload.
    pub payload: &'a [u8],
}

/// Current portable connection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
    /// Outbound SYN is awaiting an exact SYN+ACK.
    SynSent,
    /// An admitted inbound SYN was answered and awaits the exact final ACK.
    SynReceived,
    /// Both byte-stream directions are open.
    Established,
    /// Local FIN is awaiting acknowledgement.
    FinWaitOne,
    /// Local FIN was acknowledged and the peer FIN is pending.
    FinWaitTwo,
    /// Both sides sent FIN and the local FIN remains unacknowledged.
    Closing,
    /// Peer FIN was accepted; buffered bytes remain readable.
    CloseWait,
    /// Local FIN after peer close is awaiting acknowledgement.
    LastAck,
    /// The active closer retains its tuple for `TCP_TIME_WAIT_MILLISECONDS`.
    TimeWait,
    /// Terminal state after close, reset, or retransmission timeout.
    Closed,
}

/// Classification of one input segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpAdmission {
    /// Segment advanced valid connection state.
    Accepted,
    /// Already-acknowledged bytes were not retained again.
    Duplicate,
    /// Segment failed tuple, sequence, acknowledgement, flag, or window checks.
    Ignored,
}

/// One bounded segment the caller must encode and transmit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpEmission<'a> {
    /// Local endpoint.
    pub source: TcpEndpoint,
    /// Exact remote endpoint.
    pub destination: TcpEndpoint,
    /// Segment sequence number.
    pub sequence: u32,
    /// Current exact receive acknowledgement.
    pub acknowledgement: u32,
    /// Initial-profile flags.
    pub flags: TcpFlags,
    /// Remaining receive FIFO capacity.
    pub window: u16,
    /// SYN/FIN have an empty payload; data is at most one MTU.
    pub payload: &'a [u8],
}

#[derive(Debug)]
struct PendingTransmit {
    sequence: u32,
    flags: TcpFlags,
    payload: Vec<u8>,
    attempts: u8,
    deadline: Option<u64>,
}

impl PendingTransmit {
    fn end_sequence(&self) -> u32 {
        let controls = u32::from(self.flags.contains(TcpFlags::SYN))
            + u32::from(self.flags.contains(TcpFlags::FIN));
        self.sequence
            .wrapping_add(u32::try_from(self.payload.len()).unwrap_or(u32::MAX))
            .wrapping_add(controls)
    }
}

/// One allocation-bounded active TCP connection.
#[derive(Debug)]
pub struct TcpConnection {
    local: TcpEndpoint,
    remote: TcpEndpoint,
    state: TcpState,
    send_unacknowledged: u32,
    send_next: u32,
    receive_next: u32,
    receive: VecDeque<u8>,
    pending: Option<PendingTransmit>,
    ack_pending: bool,
    peer_window: u16,
    terminal: Option<TcpError>,
    last_attempts: u8,
    time_wait_deadline: Option<u64>,
}

impl TcpConnection {
    /// Begin one active open with one preallocated receive FIFO.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoints and bounded allocation failure.
    pub fn connect(
        local: TcpEndpoint,
        remote: TcpEndpoint,
        initial_sequence: u32,
    ) -> Result<Self, TcpError> {
        if !local.is_valid() || !remote.is_valid() {
            return Err(TcpError::Invalid);
        }
        let mut receive = VecDeque::new();
        receive
            .try_reserve_exact(MAX_TCP_RECEIVE_BYTES)
            .map_err(|_| TcpError::Exhausted)?;
        Ok(Self {
            local,
            remote,
            state: TcpState::SynSent,
            send_unacknowledged: initial_sequence,
            send_next: initial_sequence.wrapping_add(1),
            receive_next: 0,
            receive,
            pending: Some(PendingTransmit {
                sequence: initial_sequence,
                flags: TcpFlags::SYN,
                payload: Vec::new(),
                attempts: 0,
                deadline: None,
            }),
            ack_pending: false,
            peer_window: 0,
            terminal: None,
            last_attempts: 0,
            time_wait_deadline: None,
        })
    }

    /// Answer one admitted inbound SYN with one preallocated receive FIFO.
    ///
    /// The connection starts in `SynReceived` with a pending SYN+ACK on the
    /// existing bounded retransmission schedule and completes only on an exact
    /// final acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects invalid endpoints and bounded allocation failure.
    pub fn accept(
        local: TcpEndpoint,
        remote: TcpEndpoint,
        initial_sequence: u32,
        peer_sequence: u32,
        peer_window: u16,
    ) -> Result<Self, TcpError> {
        if !local.is_valid() || !remote.is_valid() {
            return Err(TcpError::Invalid);
        }
        let mut receive = VecDeque::new();
        receive
            .try_reserve_exact(MAX_TCP_RECEIVE_BYTES)
            .map_err(|_| TcpError::Exhausted)?;
        Ok(Self {
            local,
            remote,
            state: TcpState::SynReceived,
            send_unacknowledged: initial_sequence,
            send_next: initial_sequence.wrapping_add(1),
            receive_next: peer_sequence.wrapping_add(1),
            receive,
            pending: Some(PendingTransmit {
                sequence: initial_sequence,
                flags: TcpFlags::SYN_ACK,
                payload: Vec::new(),
                attempts: 0,
                deadline: None,
            }),
            ack_pending: false,
            peer_window,
            terminal: None,
            last_attempts: 0,
            time_wait_deadline: None,
        })
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> TcpState {
        self.state
    }

    /// Local endpoint of this connection.
    #[must_use]
    pub const fn local(&self) -> TcpEndpoint {
        self.local
    }

    /// Exact remote endpoint this connection admits segments from.
    #[must_use]
    pub const fn remote(&self) -> TcpEndpoint {
        self.remote
    }

    /// Exact endpoint tuple match used before state admission.
    #[must_use]
    pub fn accepts(&self, segment: TcpSegment<'_>) -> bool {
        segment.source == self.remote && segment.destination == self.local
    }

    /// Current retained application byte count.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.receive.len()
    }

    /// Current unscaled receive window.
    #[must_use]
    pub fn advertised_window(&self) -> u16 {
        u16::try_from(MAX_TCP_RECEIVE_BYTES.saturating_sub(self.receive.len())).unwrap_or(u16::MAX)
    }

    /// Peer-advertised bytes available for the next single segment.
    #[must_use]
    pub fn send_capacity(&self) -> usize {
        usize::from(self.peer_window).min(MAX_TCP_PAYLOAD_BYTES)
    }

    /// Number of transmissions of the current or most recently expired item.
    #[must_use]
    pub fn transmit_attempts(&self) -> u8 {
        self.pending
            .as_ref()
            .map_or(self.last_attempts, |pending| pending.attempts)
    }

    /// Whether the open completed in either direction.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == TcpState::Established
    }

    /// Whether the active or passive open completed.
    ///
    /// A peer that has already closed its sending half remains complete, so a
    /// connection carrying a complete request and a FIN is still acceptable.
    #[must_use]
    pub fn handshake_complete(&self) -> bool {
        !matches!(self.state, TcpState::SynSent | TcpState::SynReceived)
    }

    /// Whether `poll_emission` currently has due work.
    ///
    /// The owner scans many connections per frame and per timer tick; this
    /// answers without taking the mutable borrow an emission requires.
    #[must_use]
    pub fn emission_due(&self, now_milliseconds: u64) -> bool {
        if self.ack_pending {
            return true;
        }
        if self.state == TcpState::TimeWait {
            return self
                .time_wait_deadline
                .is_none_or(|deadline| now_milliseconds >= deadline);
        }
        self.pending.as_ref().is_some_and(|pending| {
            pending
                .deadline
                .is_none_or(|deadline| now_milliseconds >= deadline)
        })
    }

    /// Whether connection state is terminal.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == TcpState::Closed
    }

    /// Terminal reset or retransmission failure, if one closed the state.
    #[must_use]
    pub const fn terminal_error(&self) -> Option<TcpError> {
        self.terminal
    }

    /// Queue one at-most-MTU segment when the prior segment was acknowledged.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized data, a closed sending half, a pending send, or
    /// data exceeding the peer's current unscaled window.
    pub fn begin_send(&mut self, payload: &[u8]) -> Result<(), TcpError> {
        self.check_terminal()?;
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait)
            || payload.is_empty()
            || payload.len() > MAX_TCP_PAYLOAD_BYTES
        {
            return Err(TcpError::Invalid);
        }
        if self.pending.is_some() {
            return Err(TcpError::Busy);
        }
        if payload.len() > usize::from(self.peer_window) {
            return Err(TcpError::WindowClosed);
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(payload.len())
            .map_err(|_| TcpError::Exhausted)?;
        retained.extend_from_slice(payload);
        let sequence = self.send_next;
        self.send_next = self
            .send_next
            .wrapping_add(u32::try_from(payload.len()).map_err(|_| TcpError::Invalid)?);
        self.pending = Some(PendingTransmit {
            sequence,
            flags: TcpFlags::PSH_ACK,
            payload: retained,
            attempts: 0,
            deadline: None,
        });
        self.last_attempts = 0;
        Ok(())
    }

    /// Whether the current data segment has an exact complete acknowledgement.
    ///
    /// # Errors
    ///
    /// Reports terminal reset or timeout.
    pub fn send_complete(&self) -> Result<bool, TcpError> {
        self.check_terminal()?;
        Ok(self.pending.is_none())
    }

    /// Begin a graceful active or passive close.
    ///
    /// # Errors
    ///
    /// Rejects invalid state or an unacknowledged data segment.
    pub fn begin_close(&mut self) -> Result<(), TcpError> {
        self.check_terminal()?;
        if self.pending.is_some() {
            return Err(TcpError::Busy);
        }
        self.state = match self.state {
            TcpState::Established => TcpState::FinWaitOne,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return Err(TcpError::Invalid),
        };
        let sequence = self.send_next;
        self.send_next = self.send_next.wrapping_add(1);
        self.pending = Some(PendingTransmit {
            sequence,
            flags: TcpFlags::FIN_ACK,
            payload: Vec::new(),
            attempts: 0,
            deadline: None,
        });
        self.last_attempts = 0;
        Ok(())
    }

    /// Drain retained bytes, return zero on orderly peer EOF, or report that a
    /// live connection currently has no data.
    ///
    /// # Errors
    ///
    /// Reports reset, timeout, or an empty destination.
    pub fn read(&mut self, destination: &mut [u8]) -> Result<Option<usize>, TcpError> {
        self.check_terminal_for_read()?;
        if destination.is_empty() {
            return Err(TcpError::Invalid);
        }
        let count = destination.len().min(self.receive.len());
        if count != 0 {
            for byte in &mut destination[..count] {
                *byte = self.receive.pop_front().ok_or(TcpError::Invalid)?;
            }
            self.ack_pending = true;
            return Ok(Some(count));
        }
        if matches!(
            self.state,
            TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait | TcpState::Closed
        ) {
            return Ok(Some(0));
        }
        Ok(None)
    }

    /// Admit one exact-tuple segment through the bounded state machine.
    ///
    /// # Errors
    ///
    /// Reports an accepted reset or invalid synthetic segment payload.
    pub fn on_segment(&mut self, segment: TcpSegment<'_>) -> Result<TcpAdmission, TcpError> {
        if !segment.source.is_valid()
            || !segment.destination.is_valid()
            || segment.payload.len() > MAX_TCP_PAYLOAD_BYTES
            || !self.accepts(segment)
        {
            return Ok(TcpAdmission::Ignored);
        }
        if self.state == TcpState::Closed {
            return Ok(TcpAdmission::Ignored);
        }
        if self.state == TcpState::SynSent {
            return self.admit_syn_sent(segment);
        }
        if self.state == TcpState::SynReceived
            && let Some(admission) = self.admit_syn_received(segment)?
        {
            return Ok(admission);
        }
        if segment.flags.contains(TcpFlags::RST) {
            if segment.sequence != self.receive_next {
                self.ack_pending = true;
                return Ok(TcpAdmission::Ignored);
            }
            self.pending = None;
            self.state = TcpState::Closed;
            self.terminal = Some(TcpError::Reset);
            return Err(TcpError::Reset);
        }
        if segment.flags.contains(TcpFlags::SYN)
            || !segment.flags.contains(TcpFlags::ACK)
            || !self.acknowledge(segment.acknowledgement)
        {
            self.ack_pending = true;
            return Ok(TcpAdmission::Ignored);
        }
        self.peer_window = segment.window;

        let sequence_bytes = u32::try_from(segment.payload.len()).map_err(|_| TcpError::Invalid)?
            + u32::from(segment.flags.contains(TcpFlags::FIN));
        let end_sequence = segment.sequence.wrapping_add(sequence_bytes);
        if segment.sequence != self.receive_next {
            self.ack_pending = true;
            if sequence_bytes != 0 && !sequence_after(end_sequence, self.receive_next) {
                return Ok(TcpAdmission::Duplicate);
            }
            return Ok(TcpAdmission::Ignored);
        }
        if segment.payload.len() > MAX_TCP_RECEIVE_BYTES.saturating_sub(self.receive.len()) {
            self.ack_pending = true;
            return Ok(TcpAdmission::Ignored);
        }
        self.receive.extend(segment.payload.iter().copied());
        self.receive_next = self
            .receive_next
            .wrapping_add(u32::try_from(segment.payload.len()).map_err(|_| TcpError::Invalid)?);
        if !segment.payload.is_empty() {
            self.ack_pending = true;
        }
        if segment.flags.contains(TcpFlags::FIN) {
            self.receive_next = self.receive_next.wrapping_add(1);
            self.ack_pending = true;
            self.state = match self.state {
                TcpState::Established => TcpState::CloseWait,
                TcpState::FinWaitOne => TcpState::Closing,
                TcpState::FinWaitTwo | TcpState::Closing => TcpState::TimeWait,
                TcpState::CloseWait | TcpState::LastAck => return Ok(TcpAdmission::Duplicate),
                TcpState::SynSent
                | TcpState::SynReceived
                | TcpState::TimeWait
                | TcpState::Closed => return Ok(TcpAdmission::Ignored),
            };
        }
        Ok(TcpAdmission::Accepted)
    }

    /// Produce at most one due ACK, SYN/data/FIN transmission, or bounded
    /// retransmission at `now_milliseconds`.
    ///
    /// # Errors
    ///
    /// Returns timeout exactly when the fourth transmission's deadline passes.
    pub fn poll_emission(
        &mut self,
        now_milliseconds: u64,
    ) -> Result<Option<TcpEmission<'_>>, TcpError> {
        if self.state == TcpState::TimeWait {
            let deadline = *self
                .time_wait_deadline
                .get_or_insert(now_milliseconds.saturating_add(TCP_TIME_WAIT_MILLISECONDS));
            if now_milliseconds >= deadline {
                self.pending = None;
                self.ack_pending = false;
                self.state = TcpState::Closed;
                return Ok(None);
            }
        }
        if self.ack_pending {
            self.ack_pending = false;
            return Ok(Some(TcpEmission {
                source: self.local,
                destination: self.remote,
                sequence: self.send_next,
                acknowledgement: self.receive_next,
                flags: TcpFlags::ACK,
                window: self.advertised_window(),
                payload: &[],
            }));
        }
        let Some(pending) = self.pending.as_ref() else {
            return Ok(None);
        };
        if pending
            .deadline
            .is_some_and(|deadline| now_milliseconds < deadline)
        {
            return Ok(None);
        }
        if pending.attempts == TCP_TRANSMIT_ATTEMPTS {
            self.last_attempts = pending.attempts;
            self.pending = None;
            self.state = TcpState::Closed;
            self.terminal = Some(TcpError::Timeout);
            return Err(TcpError::Timeout);
        }
        let pending = self.pending.as_mut().ok_or(TcpError::Invalid)?;
        let delay = RETRANSMIT_DELAYS_MILLISECONDS[usize::from(pending.attempts)];
        pending.attempts = pending.attempts.saturating_add(1);
        pending.deadline = Some(now_milliseconds.saturating_add(delay));
        let flags = pending.flags;
        Ok(Some(TcpEmission {
            source: self.local,
            destination: self.remote,
            sequence: pending.sequence,
            acknowledgement: self.receive_next,
            flags,
            window: u16::try_from(MAX_TCP_RECEIVE_BYTES.saturating_sub(self.receive.len()))
                .unwrap_or(u16::MAX),
            payload: &pending.payload,
        }))
    }

    /// Complete or reject one segment arriving in `SynReceived`.
    ///
    /// `None` reports that the handshake completed and that the caller must
    /// process the same segment's payload and FIN through the established
    /// path, so a final acknowledgement carrying request bytes is retained.
    fn admit_syn_received(
        &mut self,
        segment: TcpSegment<'_>,
    ) -> Result<Option<TcpAdmission>, TcpError> {
        if segment.flags.contains(TcpFlags::RST) {
            if segment.sequence != self.receive_next {
                return Ok(Some(TcpAdmission::Ignored));
            }
            self.pending = None;
            self.state = TcpState::Closed;
            self.terminal = Some(TcpError::Reset);
            return Err(TcpError::Reset);
        }
        if segment.flags.contains(TcpFlags::SYN) {
            // A retransmitted inbound SYN is answered only by the pending
            // SYN+ACK schedule, never by a second connection or a bare ACK.
            if segment.flags == TcpFlags::SYN
                && segment.payload.is_empty()
                && segment.sequence == self.receive_next.wrapping_sub(1)
            {
                return Ok(Some(TcpAdmission::Duplicate));
            }
            return Ok(Some(TcpAdmission::Ignored));
        }
        if !segment.flags.contains(TcpFlags::ACK)
            || segment.acknowledgement != self.send_next
            || segment.sequence != self.receive_next
        {
            return Ok(Some(TcpAdmission::Ignored));
        }
        self.send_unacknowledged = segment.acknowledgement;
        self.peer_window = segment.window;
        self.pending = None;
        self.state = TcpState::Established;
        Ok(None)
    }

    fn admit_syn_sent(&mut self, segment: TcpSegment<'_>) -> Result<TcpAdmission, TcpError> {
        if segment.flags.contains(TcpFlags::RST) {
            if segment.flags.contains(TcpFlags::ACK) && segment.acknowledgement == self.send_next {
                self.pending = None;
                self.state = TcpState::Closed;
                self.terminal = Some(TcpError::Reset);
                return Err(TcpError::Reset);
            }
            return Ok(TcpAdmission::Ignored);
        }
        if segment.flags != TcpFlags::SYN_ACK
            || !segment.payload.is_empty()
            || segment.acknowledgement != self.send_next
        {
            return Ok(TcpAdmission::Ignored);
        }
        self.send_unacknowledged = segment.acknowledgement;
        self.receive_next = segment.sequence.wrapping_add(1);
        self.peer_window = segment.window;
        self.pending = None;
        self.state = TcpState::Established;
        self.ack_pending = true;
        Ok(TcpAdmission::Accepted)
    }

    fn acknowledge(&mut self, acknowledgement: u32) -> bool {
        if acknowledgement == self.send_unacknowledged {
            return true;
        }
        let Some(end_sequence) = self.pending.as_ref().map(PendingTransmit::end_sequence) else {
            return false;
        };
        if acknowledgement != end_sequence {
            return false;
        }
        self.send_unacknowledged = acknowledgement;
        self.pending = None;
        self.state = match self.state {
            TcpState::FinWaitOne => TcpState::FinWaitTwo,
            TcpState::Closing => TcpState::TimeWait,
            TcpState::LastAck => TcpState::Closed,
            state => state,
        };
        true
    }

    fn check_terminal(&self) -> Result<(), TcpError> {
        match self.terminal {
            Some(error) => Err(error),
            None if matches!(self.state, TcpState::TimeWait | TcpState::Closed) => {
                Err(TcpError::Closed)
            }
            None => Ok(()),
        }
    }

    fn check_terminal_for_read(&self) -> Result<(), TcpError> {
        match self.terminal {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

const fn sequence_after(left: u32, right: u32) -> bool {
    left != right && left.wrapping_sub(right) < 0x8000_0000
}

/// One owned listening local endpoint with a bounded passive-open queue.
///
/// The listener owns every connection between an admitted inbound SYN and its
/// acceptance, so the complete passive handshake is portable and testable
/// without the kernel. Its queue is the denial-of-service containment point: a
/// full backlog drops further inbound SYNs rather than growing, and one
/// client's reset, malformed segment, or silence terminates only its own
/// connection.
///
/// The system-wide `MAX_TCP_CONNECTIONS` ceiling spans accepted connections and
/// every listener's queue together; the owner enforces that total, because this
/// type sees only its own endpoint.
#[derive(Debug)]
pub struct TcpListener {
    local: TcpEndpoint,
    capacity: usize,
    backlog: VecDeque<TcpConnection>,
}

impl TcpListener {
    /// Claim one local endpoint with a bounded backlog.
    ///
    /// # Errors
    ///
    /// Rejects an invalid endpoint, a zero or above-`MAX_TCP_BACKLOG`
    /// capacity, and bounded allocation failure.
    pub fn bind(local: TcpEndpoint, capacity: usize) -> Result<Self, TcpError> {
        if !local.is_valid() || capacity == 0 || capacity > MAX_TCP_BACKLOG {
            return Err(TcpError::Invalid);
        }
        let mut backlog = VecDeque::new();
        backlog
            .try_reserve_exact(capacity)
            .map_err(|_| TcpError::Exhausted)?;
        Ok(Self {
            local,
            capacity,
            backlog,
        })
    }

    /// Claimed local endpoint.
    #[must_use]
    pub const fn local(&self) -> TcpEndpoint {
        self.local
    }

    /// Bounded backlog capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Connections queued between admission and acceptance.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.backlog.len()
    }

    /// Whether one segment is addressed to this listener's exact endpoint.
    #[must_use]
    pub fn owns(&self, segment: TcpSegment<'_>) -> bool {
        segment.destination == self.local
    }

    /// Admit one segment addressed to this endpoint.
    ///
    /// A segment matching a queued connection's exact four-tuple advances that
    /// connection. An otherwise unmatched bare SYN opens one new queued
    /// connection using `initial_sequence`, which the owner supplies and this
    /// type consumes only when it admits a new passive open. Every other
    /// segment, and every SYN arriving at a full backlog, is ignored.
    pub fn on_segment(&mut self, segment: TcpSegment<'_>, initial_sequence: u32) -> TcpAdmission {
        if !self.owns(segment) || !segment.source.is_valid() {
            return TcpAdmission::Ignored;
        }
        if let Some(index) = self
            .backlog
            .iter()
            .position(|connection| connection.accepts(segment))
        {
            let Some(connection) = self.backlog.get_mut(index) else {
                return TcpAdmission::Ignored;
            };
            return match connection.on_segment(segment) {
                Ok(admission) => admission,
                // An accepted reset terminates one client's connection and
                // leaves the listener claiming its endpoint.
                Err(TcpError::Reset) => {
                    let _closed = self.backlog.remove(index);
                    TcpAdmission::Accepted
                }
                Err(_) => TcpAdmission::Ignored,
            };
        }
        if segment.flags != TcpFlags::SYN
            || !segment.payload.is_empty()
            || self.backlog.len() == self.capacity
        {
            return TcpAdmission::Ignored;
        }
        match TcpConnection::accept(
            self.local,
            segment.source,
            initial_sequence,
            segment.sequence,
            segment.window,
        ) {
            Ok(connection) => {
                self.backlog.push_back(connection);
                TcpAdmission::Accepted
            }
            Err(_) => TcpAdmission::Ignored,
        }
    }

    /// Whether this segment belongs to a connection already in the backlog.
    #[must_use]
    pub fn has_connection(&self, segment: TcpSegment<'_>) -> bool {
        self.backlog
            .iter()
            .any(|connection| connection.accepts(segment))
    }

    /// Remove and return the oldest connection whose handshake completed.
    ///
    /// A connection whose peer already sent data or FIN is returned with those
    /// bytes retained. Reset and timed-out connections are never returned.
    pub fn poll_accept(&mut self) -> Option<TcpConnection> {
        let index = self.backlog.iter().position(|connection| {
            connection.handshake_complete()
                && !connection.is_closed()
                && connection.terminal_error().is_none()
        })?;
        self.backlog.remove(index)
    }

    /// Discard queued connections that reset, timed out, or left `TimeWait`.
    pub fn reap(&mut self) {
        self.backlog
            .retain(|connection| connection.terminal_error().is_none() && !connection.is_closed());
    }

    /// Produce at most one due transmission from the queue.
    ///
    /// A queued peer that stops answering expires its own SYN+ACK schedule and
    /// is reclaimed; it never fails the listener.
    pub fn poll_emission(&mut self, now_milliseconds: u64) -> Option<TcpEmission<'_>> {
        self.reap();
        let mut index = 0;
        while index < self.backlog.len() {
            if self
                .backlog
                .get(index)
                .is_some_and(|connection| connection.emission_due(now_milliseconds))
            {
                break;
            }
            index = index.saturating_add(1);
        }
        self.backlog
            .get_mut(index)?
            .poll_emission(now_milliseconds)
            .unwrap_or(None)
    }
}

//! Bounded Ethernet, ARP, IPv4, UDP, TCP, and receive-queue primitives.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

mod tcp;

pub use tcp::{
    MAX_TCP_CONNECTIONS, MAX_TCP_PAYLOAD_BYTES, MAX_TCP_RECEIVE_BYTES, TCP_TRANSMIT_ATTEMPTS,
    TcpAdmission, TcpConnection, TcpEmission, TcpEndpoint, TcpError, TcpFlags, TcpSegment,
    TcpState,
};

/// Ethernet header bytes without VLAN tags.
pub const ETHERNET_HEADER_BYTES: usize = 14;
/// Largest accepted initial-profile Ethernet frame without FCS.
pub const MAX_FRAME_BYTES: usize = 1514;
/// Minimum transmitted Ethernet frame without FCS.
pub const MIN_FRAME_BYTES: usize = 60;
/// Maximum UDP payload under the 1500-byte IPv4 MTU.
pub const MAX_UDP_PAYLOAD_BYTES: usize = 1472;
/// Virtio network device type identifier.
pub const VIRTIO_DEVICE_ID_NETWORK: u32 = 1;
/// Initial RX virtqueue index.
pub const RECEIVE_QUEUE_INDEX: u16 = 0;
/// Initial TX virtqueue index.
pub const TRANSMIT_QUEUE_INDEX: u16 = 1;
/// Fixed power-of-two split-queue entry count.
pub const NETWORK_QUEUE_SIZE: u16 = 8;
/// Modern virtio-net v1 header bytes, including the reserved buffer-count field.
pub const VIRTIO_NET_HEADER_BYTES: usize = 12;
/// Maximum retained IPv4-to-Ethernet neighbor records.
pub const MAX_ARP_CACHE_ENTRIES: usize = 8;
/// Maximum persistent local UDP port bindings.
pub const MAX_UDP_PORTS: usize = 8;
/// Maximum datagrams retained for one bound UDP port.
pub const UDP_QUEUE_DATAGRAMS: usize = 4;
/// Maximum payload bytes retained for one bound UDP port.
pub const UDP_QUEUE_BYTES: usize = 4 * 1024;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_FIXED_BYTES: usize = 240;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Stable network parse, construction, or resource failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetError {
    /// Address, port, size, limit, or packet field is invalid.
    Invalid,
    /// A packet is truncated or contains inconsistent length fields.
    Truncated,
    /// A required header or transport checksum failed.
    Checksum,
    /// A protocol or feature is outside the initial profile.
    Unsupported,
    /// Bounded packet allocation failed.
    Exhausted,
    /// The native device rejected or failed an operation.
    Device,
    /// A bounded native completion did not arrive.
    Timeout,
}

/// Feature subset and MAC accepted before native queue activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioNetworkProfile {
    features: u64,
    mac: MacAddress,
}

impl VirtioNetworkProfile {
    /// Negotiate the deliberately tiny modern virtio-net profile.
    ///
    /// # Errors
    ///
    /// Requires `VERSION_1` and `MAC`, rejects an invalid config MAC, and accepts
    /// no device/guest offloads, mergeable buffers, control queues, or MQ.
    pub fn negotiate(offered: u64, configuration: &[u8]) -> Result<Self, NetError> {
        const FEATURE_MAC: u64 = 1 << 5;
        const FEATURE_VERSION_1: u64 = 1 << 32;
        if offered & FEATURE_VERSION_1 == 0 || offered & FEATURE_MAC == 0 {
            return Err(NetError::Unsupported);
        }
        let mac = MacAddress::new(copy_array(configuration, 0)?)?;
        Ok(Self {
            features: FEATURE_VERSION_1 | FEATURE_MAC,
            mac,
        })
    }

    /// Exact accepted feature subset.
    #[must_use]
    pub const fn negotiated_features(self) -> u64 {
        self.features
    }

    /// Stable configured unicast MAC.
    #[must_use]
    pub const fn mac(self) -> MacAddress {
        self.mac
    }
}

/// Bounded complete-frame network capability.
pub trait NetworkDevice {
    /// Stable unicast address selected during negotiation.
    fn mac_address(&self) -> MacAddress;

    /// Transmit one complete Ethernet frame.
    ///
    /// # Errors
    ///
    /// Rejects invalid size and returns bounded device/timeout failures.
    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError>;

    /// Poll boundedly for one complete received Ethernet frame.
    ///
    /// `Ok(None)` means the bounded poll found no completion. Returned frames
    /// are always within the initial Ethernet ceiling.
    ///
    /// # Errors
    ///
    /// Reports invalid device completions and bounded allocation failure.
    fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError>;
}

/// Canonical unicast Ethernet address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Construct a nonzero unicast address.
    ///
    /// # Errors
    ///
    /// Rejects all-zero and multicast/group addresses.
    pub fn new(bytes: [u8; 6]) -> Result<Self, NetError> {
        if bytes == [0; 6] || bytes[0] & 1 != 0 {
            return Err(NetError::Invalid);
        }
        Ok(Self(bytes))
    }

    /// Exact address bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 6] {
        self.0
    }
}

/// IPv4 address retained as exact network-order octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    /// Construct an address. The all-zero address is reserved for ARP probes.
    #[must_use]
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Exact network-order octets.
    #[must_use]
    pub const fn bytes(self) -> [u8; 4] {
        self.0
    }
}

/// Hard receive-queue resource ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveLimits {
    frames: usize,
    bytes: usize,
    frame_bytes: usize,
}

impl ReceiveLimits {
    /// Construct explicit queue ceilings.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive frame, byte, and per-frame budgets.
    pub const fn new(
        max_frames: usize,
        max_bytes: usize,
        max_frame_bytes: usize,
    ) -> Result<Self, NetError> {
        if max_frames == 0
            || max_frames > 64
            || max_frame_bytes < ETHERNET_HEADER_BYTES
            || max_frame_bytes > MAX_FRAME_BYTES
            || max_bytes < max_frame_bytes
            || max_bytes > 128 * 1024
        {
            return Err(NetError::Invalid);
        }
        Ok(Self {
            frames: max_frames,
            bytes: max_bytes,
            frame_bytes: max_frame_bytes,
        })
    }
}

/// Outcome of one receive-queue admission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// The complete frame was retained.
    Retained,
    /// The newest frame was dropped at a configured ceiling.
    Dropped,
}

/// Owned FIFO that drops newest input at hard count and byte ceilings.
#[derive(Debug)]
pub struct ReceiveQueue {
    limits: ReceiveLimits,
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
    dropped: u64,
}

impl ReceiveQueue {
    /// Create an empty bounded queue.
    #[must_use]
    pub fn new(limits: ReceiveLimits) -> Self {
        Self {
            limits,
            frames: VecDeque::new(),
            bytes: 0,
            dropped: 0,
        }
    }

    /// Copy one complete frame or drop it without changing retained state.
    ///
    /// # Errors
    ///
    /// Rejects malformed frame sizes and allocation failure.
    pub fn push(&mut self, frame: &[u8]) -> Result<Admission, NetError> {
        if !(ETHERNET_HEADER_BYTES..=self.limits.frame_bytes).contains(&frame.len()) {
            return Err(NetError::Invalid);
        }
        let next_bytes = self
            .bytes
            .checked_add(frame.len())
            .ok_or(NetError::Invalid)?;
        if self.frames.len() == self.limits.frames || next_bytes > self.limits.bytes {
            self.dropped = self.dropped.saturating_add(1);
            return Ok(Admission::Dropped);
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(frame.len())
            .map_err(|_| NetError::Exhausted)?;
        retained.extend_from_slice(frame);
        self.frames.push_back(retained);
        self.bytes = next_bytes;
        Ok(Admission::Retained)
    }

    /// Remove the oldest retained frame.
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let frame = self.frames.pop_front()?;
        self.bytes = self.bytes.saturating_sub(frame.len());
        Some(frame)
    }

    /// Retained frame count and bytes.
    #[must_use]
    pub fn usage(&self) -> (usize, usize) {
        (self.frames.len(), self.bytes)
    }

    /// Number of frames dropped at a resource ceiling.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// One retained ARP neighbor record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpCacheEntry {
    /// Neighbor IPv4 address.
    pub address: Ipv4Address,
    /// Most recently observed unicast Ethernet address.
    pub mac: MacAddress,
    generation: u64,
}

/// Fixed-size least-recently-observed ARP cache.
#[derive(Debug)]
pub struct ArpCache {
    entries: [Option<ArpCacheEntry>; MAX_ARP_CACHE_ENTRIES],
    generation: u64,
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpCache {
    /// Construct an empty cache without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_ARP_CACHE_ENTRIES],
            generation: 0,
        }
    }

    /// Learn or refresh one validated neighbor, evicting the oldest at capacity.
    pub fn learn(&mut self, address: Ipv4Address, mac: MacAddress) {
        if address.bytes() == [0; 4] {
            return;
        }
        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        if let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.address == address)
        {
            *entry = ArpCacheEntry {
                address,
                mac,
                generation,
            };
            return;
        }
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries
                    .iter()
                    .enumerate()
                    .filter_map(|(index, entry)| entry.map(|entry| (index, entry.generation)))
                    .min_by_key(|(_, generation)| *generation)
                    .map_or(0, |(index, _)| index)
            });
        self.entries[index] = Some(ArpCacheEntry {
            address,
            mac,
            generation,
        });
    }

    /// Look up a retained neighbor without changing replacement order.
    #[must_use]
    pub fn lookup(&self, address: Ipv4Address) -> Option<MacAddress> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.address == address)
            .map(|entry| entry.mac)
    }

    /// Iterate over the at-most-eight retained entries.
    pub fn entries(&self) -> impl Iterator<Item = ArpCacheEntry> + '_ {
        self.entries.iter().flatten().copied()
    }

    /// Current retained entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Whether no neighbor record is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One owned UDP datagram admitted to a bound port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedUdpDatagram {
    /// Peer IPv4 address.
    pub source_ip: Ipv4Address,
    /// Peer UDP source port.
    pub source_port: u16,
    /// Exact bounded payload.
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct UdpBinding {
    port: u16,
    queue: VecDeque<OwnedUdpDatagram>,
    bytes: usize,
    dropped: u64,
}

/// Admission result for a persistent per-port receive queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpAdmission {
    /// Datagram was retained by the matching bound port.
    Retained,
    /// No local binding matched the destination port.
    Unbound,
    /// Matching queue was full and dropped the newest datagram.
    Dropped,
}

/// Snapshot of one persistent local UDP binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPortSnapshot {
    /// Bound local port.
    pub port: u16,
    /// Retained datagram count.
    pub datagrams: usize,
    /// Retained payload bytes.
    pub bytes: usize,
    /// Datagrams dropped at this queue's ceiling.
    pub dropped: u64,
}

/// Fixed-count persistent UDP bindings with independent receive queues.
#[derive(Debug)]
pub struct UdpPortTable {
    bindings: Vec<UdpBinding>,
}

impl UdpPortTable {
    /// Preallocate binding metadata for the complete hard ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Exhausted`] if metadata cannot be reserved.
    pub fn new() -> Result<Self, NetError> {
        let mut bindings = Vec::new();
        bindings
            .try_reserve_exact(MAX_UDP_PORTS)
            .map_err(|_| NetError::Exhausted)?;
        Ok(Self { bindings })
    }

    /// Persistently bind a nonzero local port. Rebinding is idempotent.
    ///
    /// # Errors
    ///
    /// Rejects port zero and binding-table or metadata exhaustion.
    pub fn bind(&mut self, port: u16) -> Result<(), NetError> {
        if port == 0 {
            return Err(NetError::Invalid);
        }
        if self.bindings.iter().any(|binding| binding.port == port) {
            return Ok(());
        }
        if self.bindings.len() == MAX_UDP_PORTS {
            return Err(NetError::Exhausted);
        }
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(UDP_QUEUE_DATAGRAMS)
            .map_err(|_| NetError::Exhausted)?;
        self.bindings.push(UdpBinding {
            port,
            queue,
            bytes: 0,
            dropped: 0,
        });
        Ok(())
    }

    /// Whether a local port remains bound.
    #[must_use]
    pub fn is_bound(&self, port: u16) -> bool {
        self.bindings.iter().any(|binding| binding.port == port)
    }

    /// Release one local port and discard every retained datagram.
    ///
    /// Returns whether a live binding was removed. This is the teardown path
    /// for application-owned endpoint capabilities.
    pub fn unbind(&mut self, port: u16) -> bool {
        let Some(index) = self
            .bindings
            .iter()
            .position(|binding| binding.port == port)
        else {
            return false;
        };
        self.bindings.remove(index);
        true
    }

    /// Copy one parsed datagram into its destination port's bounded queue.
    ///
    /// # Errors
    ///
    /// Reports payload or allocation failure without exceeding queue ceilings.
    pub fn admit(&mut self, datagram: UdpDatagram<'_>) -> Result<UdpAdmission, NetError> {
        let Some(binding) = self
            .bindings
            .iter_mut()
            .find(|binding| binding.port == datagram.destination_port)
        else {
            return Ok(UdpAdmission::Unbound);
        };
        let next_bytes = binding
            .bytes
            .checked_add(datagram.payload.len())
            .ok_or(NetError::Invalid)?;
        if binding.queue.len() == UDP_QUEUE_DATAGRAMS || next_bytes > UDP_QUEUE_BYTES {
            binding.dropped = binding.dropped.saturating_add(1);
            return Ok(UdpAdmission::Dropped);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(datagram.payload.len())
            .map_err(|_| NetError::Exhausted)?;
        payload.extend_from_slice(datagram.payload);
        binding.queue.push_back(OwnedUdpDatagram {
            source_ip: datagram.source_ip,
            source_port: datagram.source_port,
            payload,
        });
        binding.bytes = next_bytes;
        Ok(UdpAdmission::Retained)
    }

    /// Remove the oldest datagram from one bound port.
    pub fn receive(&mut self, port: u16) -> Option<OwnedUdpDatagram> {
        let binding = self
            .bindings
            .iter_mut()
            .find(|binding| binding.port == port)?;
        let datagram = binding.queue.pop_front()?;
        binding.bytes = binding.bytes.saturating_sub(datagram.payload.len());
        Some(datagram)
    }

    /// Iterate over bounded per-port queue snapshots.
    pub fn snapshots(&self) -> impl Iterator<Item = UdpPortSnapshot> + '_ {
        self.bindings.iter().map(|binding| UdpPortSnapshot {
            port: binding.port,
            datagrams: binding.queue.len(),
            bytes: binding.bytes,
            dropped: binding.dropped,
        })
    }

    /// Current number of persistent bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether no local port is bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

/// Ambient network service counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetworkServiceStats {
    /// Complete Ethernet frames received from the device.
    pub received_frames: u64,
    /// Complete Ethernet frames successfully submitted to the device.
    pub transmitted_frames: u64,
    /// ARP requests answered for the configured local address.
    pub arp_replies: u64,
    /// ICMP echo requests answered for the configured local address.
    pub icmp_replies: u64,
    /// UDP datagrams retained by bound-port queues.
    pub udp_retained: u64,
    /// UDP datagrams arriving at unbound local ports.
    pub udp_unbound: u64,
    /// UDP datagrams dropped at a per-port queue ceiling.
    pub udp_dropped: u64,
    /// Frames ignored because no supported ambient protocol accepted them.
    pub ignored_frames: u64,
    /// Device or packet-processing failures observed by ambient polling.
    pub errors: u64,
    /// Bounded service checkpoints completed.
    pub checkpoints: u64,
}

/// Verified ARP Ethernet/IPv4 message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpPacket {
    /// Operation: one request or two reply.
    pub operation: u16,
    /// Sender Ethernet address.
    pub sender_mac: MacAddress,
    /// Sender IPv4 address.
    pub sender_ip: Ipv4Address,
    /// Target Ethernet bytes (zero for unresolved requests).
    pub target_mac: [u8; 6],
    /// Target IPv4 address.
    pub target_ip: Ipv4Address,
}

/// Verified UDP datagram borrowed from one frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDatagram<'a> {
    /// Ethernet source.
    pub source_mac: MacAddress,
    /// IPv4 source.
    pub source_ip: Ipv4Address,
    /// IPv4 destination.
    pub destination_ip: Ipv4Address,
    /// UDP source port.
    pub source_port: u16,
    /// UDP destination port.
    pub destination_port: u16,
    /// Exact UDP payload.
    pub payload: &'a [u8],
}

/// Accepted ICMP echo message borrowed from one Ethernet frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpEcho<'a> {
    /// Ethernet source.
    pub source_mac: MacAddress,
    /// IPv4 source.
    pub source_ip: Ipv4Address,
    /// IPv4 destination.
    pub destination_ip: Ipv4Address,
    /// Eight for an echo request and zero for an echo reply.
    pub kind: u8,
    /// Caller-selected echo identifier.
    pub identifier: u16,
    /// Caller-selected echo sequence number.
    pub sequence: u16,
    /// Exact echo data following the ICMP header.
    pub payload: &'a [u8],
}

/// DHCP message kind used by the initial four-message client exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhcpMessageType {
    /// Server address proposal.
    Offer,
    /// Server acknowledgement of the requested lease.
    Acknowledge,
    /// Server rejection of the requested lease.
    NegativeAcknowledge,
}

/// Verified DHCP server message and the bounded configuration options TROE uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhcpPacket {
    /// DHCP transaction identifier.
    pub transaction_id: u32,
    /// Client hardware address echoed by the server.
    pub client_mac: MacAddress,
    /// Address offered or assigned to the client.
    pub your_ip: Ipv4Address,
    /// DHCP message kind.
    pub message_type: DhcpMessageType,
    /// Server identifier option, when present.
    pub server_identifier: Option<Ipv4Address>,
    /// IPv4 subnet mask option, when present.
    pub subnet_mask: Option<Ipv4Address>,
    /// First default-router option, when present.
    pub router: Option<Ipv4Address>,
    /// Lease duration in seconds, when present.
    pub lease_seconds: Option<u32>,
}

/// Build a broadcast ARP request for one configured IPv4 address.
///
/// # Errors
///
/// Allocation failure is reported before returning a partial frame.
pub fn build_arp_request(
    source_mac: MacAddress,
    source_ip: Ipv4Address,
    target_ip: Ipv4Address,
) -> Result<Vec<u8>, NetError> {
    build_arp(source_mac, source_ip, [0; 6], target_ip, 1, [0xff; 6])
}

/// Build a unicast ARP reply for this host's configured IPv4 address.
///
/// # Errors
///
/// Allocation failure is reported before returning a partial frame.
pub fn build_arp_reply(
    source_mac: MacAddress,
    source_ip: Ipv4Address,
    target_mac: MacAddress,
    target_ip: Ipv4Address,
) -> Result<Vec<u8>, NetError> {
    build_arp(
        source_mac,
        source_ip,
        target_mac.bytes(),
        target_ip,
        2,
        target_mac.bytes(),
    )
}

fn build_arp(
    source_mac: MacAddress,
    source_ip: Ipv4Address,
    target_mac: [u8; 6],
    target_ip: Ipv4Address,
    operation: u16,
    destination_mac: [u8; 6],
) -> Result<Vec<u8>, NetError> {
    let mut frame = allocate_frame(MIN_FRAME_BYTES)?;
    frame[..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&source_mac.bytes());
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&operation.to_be_bytes());
    frame[22..28].copy_from_slice(&source_mac.bytes());
    frame[28..32].copy_from_slice(&source_ip.bytes());
    frame[32..38].copy_from_slice(&target_mac);
    frame[38..42].copy_from_slice(&target_ip.bytes());
    Ok(frame)
}

/// Parse a canonical initial-profile ARP message.
///
/// # Errors
///
/// Rejects invalid Ethernet/ARP fields, unsupported operations, truncation,
/// nonzero padding, and invalid unicast sender addresses.
pub fn parse_arp(frame: &[u8]) -> Result<ArpPacket, NetError> {
    if frame.len() < 42 || frame.len() > MAX_FRAME_BYTES {
        return Err(NetError::Truncated);
    }
    if read_be16(frame, 12)? != ETHERTYPE_ARP
        || read_be16(frame, 14)? != 1
        || read_be16(frame, 16)? != ETHERTYPE_IPV4
        || frame[18] != 6
        || frame[19] != 4
        || frame[42..].iter().any(|byte| *byte != 0)
    {
        return Err(NetError::Unsupported);
    }
    let operation = read_be16(frame, 20)?;
    if operation != 1 && operation != 2 {
        return Err(NetError::Unsupported);
    }
    let sender_mac = MacAddress::new(copy_array(frame, 22)?)?;
    Ok(ArpPacket {
        operation,
        sender_mac,
        sender_ip: Ipv4Address::new(copy_array(frame, 28)?),
        target_mac: copy_array(frame, 32)?,
        target_ip: Ipv4Address::new(copy_array(frame, 38)?),
    })
}

/// Build one checksummed Ethernet/IPv4/UDP frame.
///
/// # Errors
///
/// Rejects zero ports, oversized payloads, arithmetic overflow, and allocation
/// failure before returning a partial frame.
pub fn build_udp(
    source_mac: MacAddress,
    destination_mac: MacAddress,
    source_ip: Ipv4Address,
    destination_ip: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, NetError> {
    build_udp_to(
        source_mac,
        destination_mac.bytes(),
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        payload,
    )
}

/// Build one checksummed Ethernet/IPv4/TCP segment without protocol options.
///
/// # Errors
///
/// Rejects invalid endpoints, flags, acknowledgement fields, payload size, and
/// allocation failure before returning a partial frame.
pub fn build_tcp(
    source_mac: MacAddress,
    destination_mac: MacAddress,
    segment: TcpSegment<'_>,
) -> Result<Vec<u8>, NetError> {
    let flags = TcpFlags::from_bits(segment.flags.bits())?;
    if segment.source.port() == 0
        || segment.destination.port() == 0
        || segment.payload.len() > MAX_TCP_PAYLOAD_BYTES
        || (!flags.contains(TcpFlags::ACK) && segment.acknowledgement != 0)
        || (!segment.payload.is_empty()
            && (flags.contains(TcpFlags::SYN) || flags.contains(TcpFlags::RST)))
    {
        return Err(NetError::Invalid);
    }
    let tcp_len = 20_usize
        .checked_add(segment.payload.len())
        .ok_or(NetError::Invalid)?;
    let mut frame = build_ipv4_frame(
        source_mac,
        destination_mac.bytes(),
        segment.source.address(),
        segment.destination.address(),
        IP_PROTOCOL_TCP,
        tcp_len,
    )?;
    let tcp = ETHERNET_HEADER_BYTES + 20;
    frame[tcp..tcp + 2].copy_from_slice(&segment.source.port().to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&segment.destination.port().to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&segment.sequence.to_be_bytes());
    frame[tcp + 8..tcp + 12].copy_from_slice(&segment.acknowledgement.to_be_bytes());
    frame[tcp + 12] = 5 << 4;
    frame[tcp + 13] = flags.bits();
    frame[tcp + 14..tcp + 16].copy_from_slice(&segment.window.to_be_bytes());
    frame[tcp + 20..tcp + tcp_len].copy_from_slice(segment.payload);
    let tcp_checksum = tcp_checksum(
        segment.source.address(),
        segment.destination.address(),
        &frame[tcp..tcp + tcp_len],
    );
    frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(frame)
}

fn build_udp_to(
    source_mac: MacAddress,
    destination_mac: [u8; 6],
    source_ip: Ipv4Address,
    destination_ip: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, NetError> {
    if source_port == 0 || destination_port == 0 || payload.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(NetError::Invalid);
    }
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or(NetError::Invalid)?;
    let mut frame = build_ipv4_frame(
        source_mac,
        destination_mac,
        source_ip,
        destination_ip,
        IP_PROTOCOL_UDP,
        udp_len,
    )?;
    frame[..6].copy_from_slice(&destination_mac);
    let ip = ETHERNET_HEADER_BYTES;
    let udp = ip + 20;
    frame[udp..udp + 2].copy_from_slice(&source_port.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&destination_port.to_be_bytes());
    frame[udp + 4..udp + 6].copy_from_slice(
        &u16::try_from(udp_len)
            .map_err(|_| NetError::Invalid)?
            .to_be_bytes(),
    );
    frame[udp + 8..udp + udp_len].copy_from_slice(payload);
    let udp_checksum = udp_checksum(source_ip, destination_ip, &frame[udp..udp + udp_len]);
    frame[udp + 6..udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(frame)
}

/// Build a DHCP discover broadcast from the unconfigured IPv4 address.
///
/// # Errors
///
/// Reports invalid size or bounded allocation failure.
pub fn build_dhcp_discover(
    source_mac: MacAddress,
    transaction_id: u32,
) -> Result<Vec<u8>, NetError> {
    let payload = build_dhcp_client_payload(source_mac, transaction_id, None)?;
    build_udp_to(
        source_mac,
        [0xff; 6],
        Ipv4Address::new([0; 4]),
        Ipv4Address::new([255; 4]),
        DHCP_CLIENT_PORT,
        DHCP_SERVER_PORT,
        &payload,
    )
}

/// Build a DHCP request broadcast selecting one offer and server.
///
/// # Errors
///
/// Reports invalid size or bounded allocation failure.
pub fn build_dhcp_request(
    source_mac: MacAddress,
    transaction_id: u32,
    requested_ip: Ipv4Address,
    server_identifier: Ipv4Address,
) -> Result<Vec<u8>, NetError> {
    let payload = build_dhcp_client_payload(
        source_mac,
        transaction_id,
        Some((requested_ip, server_identifier)),
    )?;
    build_udp_to(
        source_mac,
        [0xff; 6],
        Ipv4Address::new([0; 4]),
        Ipv4Address::new([255; 4]),
        DHCP_CLIENT_PORT,
        DHCP_SERVER_PORT,
        &payload,
    )
}

/// Parse one DHCP offer, acknowledgement, or negative acknowledgement.
///
/// # Errors
///
/// Rejects malformed BOOTP fields, invalid options, unknown message kinds,
/// transport corruption, and replies not addressed to the DHCP client port.
pub fn parse_dhcp(frame: &[u8]) -> Result<DhcpPacket, NetError> {
    let datagram = parse_udp(frame)?;
    if datagram.source_port != DHCP_SERVER_PORT
        || datagram.destination_port != DHCP_CLIENT_PORT
        || datagram.payload.len() < DHCP_FIXED_BYTES
    {
        return Err(NetError::Unsupported);
    }
    let bytes = datagram.payload;
    if bytes[0] != 2
        || bytes[1] != 1
        || bytes[2] != 6
        || bytes[3] != 0
        || bytes[236..240] != DHCP_MAGIC_COOKIE
    {
        return Err(NetError::Unsupported);
    }
    let transaction_id = u32::from_be_bytes(copy_array(bytes, 4)?);
    let your_ip = Ipv4Address::new(copy_array(bytes, 16)?);
    let client_mac = MacAddress::new(copy_array(bytes, 28)?)?;
    let mut message_type = None;
    let mut server_identifier = None;
    let mut subnet_mask = None;
    let mut router = None;
    let mut lease_seconds = None;
    let mut offset = DHCP_FIXED_BYTES;
    while offset < bytes.len() {
        let kind = bytes[offset];
        offset = offset.checked_add(1).ok_or(NetError::Invalid)?;
        if kind == 0 {
            continue;
        }
        if kind == 255 {
            break;
        }
        let length = usize::from(*bytes.get(offset).ok_or(NetError::Truncated)?);
        offset = offset.checked_add(1).ok_or(NetError::Invalid)?;
        let end = offset.checked_add(length).ok_or(NetError::Invalid)?;
        let value = bytes.get(offset..end).ok_or(NetError::Truncated)?;
        match (kind, value) {
            (53, [2]) => message_type = Some(DhcpMessageType::Offer),
            (53, [5]) => message_type = Some(DhcpMessageType::Acknowledge),
            (53, [6]) => message_type = Some(DhcpMessageType::NegativeAcknowledge),
            (53, [_]) => return Err(NetError::Unsupported),
            (1, [a, b, c, d]) => subnet_mask = Some(Ipv4Address::new([*a, *b, *c, *d])),
            (3, [a, b, c, d, ..]) => router = Some(Ipv4Address::new([*a, *b, *c, *d])),
            (51, [a, b, c, d]) => lease_seconds = Some(u32::from_be_bytes([*a, *b, *c, *d])),
            (54, [a, b, c, d]) => {
                server_identifier = Some(Ipv4Address::new([*a, *b, *c, *d]));
            }
            _ => {}
        }
        offset = end;
    }
    Ok(DhcpPacket {
        transaction_id,
        client_mac,
        your_ip,
        message_type: message_type.ok_or(NetError::Unsupported)?,
        server_identifier,
        subnet_mask,
        router,
        lease_seconds,
    })
}

/// Build an ICMP echo request or reply.
///
/// # Errors
///
/// Rejects kinds other than zero/eight, oversized data, and allocation failure.
#[allow(clippy::too_many_arguments)] // Complete L2/L3 identity plus the three ICMP echo fields.
pub fn build_icmp_echo(
    source_mac: MacAddress,
    destination_mac: MacAddress,
    source_ip: Ipv4Address,
    destination_ip: Ipv4Address,
    kind: u8,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>, NetError> {
    if (kind != 0 && kind != 8) || payload.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(NetError::Invalid);
    }
    let icmp_len = 8_usize
        .checked_add(payload.len())
        .ok_or(NetError::Invalid)?;
    let mut frame = build_ipv4_frame(
        source_mac,
        destination_mac.bytes(),
        source_ip,
        destination_ip,
        IP_PROTOCOL_ICMP,
        icmp_len,
    )?;
    let icmp = ETHERNET_HEADER_BYTES + 20;
    frame[icmp] = kind;
    frame[icmp + 4..icmp + 6].copy_from_slice(&identifier.to_be_bytes());
    frame[icmp + 6..icmp + 8].copy_from_slice(&sequence.to_be_bytes());
    frame[icmp + 8..icmp + icmp_len].copy_from_slice(payload);
    let icmp_checksum = checksum(&frame[icmp..icmp + icmp_len]);
    frame[icmp + 2..icmp + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(frame)
}

/// Parse a checksummed, unfragmented IPv4 ICMP echo request or reply.
///
/// # Errors
///
/// Rejects options, fragments, other ICMP kinds/codes, corrupt checksums,
/// invalid padding, and truncated frames.
pub fn parse_icmp_echo(frame: &[u8]) -> Result<IcmpEcho<'_>, NetError> {
    if frame.len() < ETHERNET_HEADER_BYTES + 28 || frame.len() > MAX_FRAME_BYTES {
        return Err(NetError::Truncated);
    }
    if read_be16(frame, 12)? != ETHERTYPE_IPV4 {
        return Err(NetError::Unsupported);
    }
    let source_mac = MacAddress::new(copy_array(frame, 6)?)?;
    let ip = ETHERNET_HEADER_BYTES;
    if frame[ip] != 0x45 || frame[ip + 9] != IP_PROTOCOL_ICMP {
        return Err(NetError::Unsupported);
    }
    let ip_len = usize::from(read_be16(frame, ip + 2)?);
    if ip_len < 28 || ip + ip_len > frame.len() || read_be16(frame, ip + 6)? & 0x3fff != 0 {
        return Err(NetError::Truncated);
    }
    if checksum(&frame[ip..ip + 20]) != 0 {
        return Err(NetError::Checksum);
    }
    let icmp = ip + 20;
    let icmp_len = ip_len - 20;
    if (frame[icmp] != 0 && frame[icmp] != 8)
        || frame[icmp + 1] != 0
        || checksum(&frame[icmp..icmp + icmp_len]) != 0
    {
        return Err(NetError::Checksum);
    }
    if frame[ip + ip_len..].iter().any(|byte| *byte != 0) {
        return Err(NetError::Invalid);
    }
    Ok(IcmpEcho {
        source_mac,
        source_ip: Ipv4Address::new(copy_array(frame, ip + 12)?),
        destination_ip: Ipv4Address::new(copy_array(frame, ip + 16)?),
        kind: frame[icmp],
        identifier: read_be16(frame, icmp + 4)?,
        sequence: read_be16(frame, icmp + 6)?,
        payload: &frame[icmp + 8..icmp + icmp_len],
    })
}

fn build_ipv4_frame(
    source_mac: MacAddress,
    destination_mac: [u8; 6],
    source_ip: Ipv4Address,
    destination_ip: Ipv4Address,
    protocol: u8,
    payload_bytes: usize,
) -> Result<Vec<u8>, NetError> {
    let ip_len = 20_usize
        .checked_add(payload_bytes)
        .ok_or(NetError::Invalid)?;
    let wire_len = ETHERNET_HEADER_BYTES
        .checked_add(ip_len)
        .ok_or(NetError::Invalid)?;
    let mut frame = allocate_frame(wire_len.max(MIN_FRAME_BYTES))?;
    frame[..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&source_mac.bytes());
    frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    let ip = ETHERNET_HEADER_BYTES;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(
        &u16::try_from(ip_len)
            .map_err(|_| NetError::Invalid)?
            .to_be_bytes(),
    );
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = protocol;
    frame[ip + 12..ip + 16].copy_from_slice(&source_ip.bytes());
    frame[ip + 16..ip + 20].copy_from_slice(&destination_ip.bytes());
    let header_checksum = checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(frame)
}

fn build_dhcp_client_payload(
    source_mac: MacAddress,
    transaction_id: u32,
    request: Option<(Ipv4Address, Ipv4Address)>,
) -> Result<Vec<u8>, NetError> {
    let option_bytes = if request.is_some() { 30 } else { 18 };
    let mut bytes = allocate_bytes(DHCP_FIXED_BYTES + option_bytes)?;
    bytes[0] = 1;
    bytes[1] = 1;
    bytes[2] = 6;
    bytes[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    bytes[10..12].copy_from_slice(&0x8000_u16.to_be_bytes());
    bytes[28..34].copy_from_slice(&source_mac.bytes());
    bytes[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    let mut offset = DHCP_FIXED_BYTES;
    bytes[offset..offset + 3].copy_from_slice(&[53, 1, if request.is_some() { 3 } else { 1 }]);
    offset += 3;
    bytes[offset..offset + 9].copy_from_slice(&[
        61,
        7,
        1,
        source_mac.bytes()[0],
        source_mac.bytes()[1],
        source_mac.bytes()[2],
        source_mac.bytes()[3],
        source_mac.bytes()[4],
        source_mac.bytes()[5],
    ]);
    offset += 9;
    if let Some((requested_ip, server_identifier)) = request {
        bytes[offset..offset + 6].copy_from_slice(&[
            50,
            4,
            requested_ip.bytes()[0],
            requested_ip.bytes()[1],
            requested_ip.bytes()[2],
            requested_ip.bytes()[3],
        ]);
        offset += 6;
        bytes[offset..offset + 6].copy_from_slice(&[
            54,
            4,
            server_identifier.bytes()[0],
            server_identifier.bytes()[1],
            server_identifier.bytes()[2],
            server_identifier.bytes()[3],
        ]);
        offset += 6;
    }
    bytes[offset] = 55;
    bytes[offset + 1] = 3;
    bytes[offset + 2..offset + 5].copy_from_slice(&[1, 3, 51]);
    bytes[offset + 5] = 255;
    Ok(bytes)
}

fn allocate_bytes(bytes: usize) -> Result<Vec<u8>, NetError> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(bytes)
        .map_err(|_| NetError::Exhausted)?;
    value.resize(bytes, 0);
    Ok(value)
}

/// Parse one initial-profile Ethernet/IPv4/UDP frame.
///
/// # Errors
///
/// Rejects options, fragments, invalid lengths/checksums, zero ports, unknown
/// protocol, oversized payloads, and nonzero Ethernet padding.
pub fn parse_udp(frame: &[u8]) -> Result<UdpDatagram<'_>, NetError> {
    if frame.len() < ETHERNET_HEADER_BYTES + 28 || frame.len() > MAX_FRAME_BYTES {
        return Err(NetError::Truncated);
    }
    if read_be16(frame, 12)? != ETHERTYPE_IPV4 {
        return Err(NetError::Unsupported);
    }
    let source_mac = MacAddress::new(copy_array(frame, 6)?)?;
    let ip = ETHERNET_HEADER_BYTES;
    if frame[ip] != 0x45 || frame[ip + 9] != IP_PROTOCOL_UDP {
        return Err(NetError::Unsupported);
    }
    let ip_len = usize::from(read_be16(frame, ip + 2)?);
    if ip_len < 28 || ip + ip_len > frame.len() || read_be16(frame, ip + 6)? & 0x3fff != 0 {
        return Err(NetError::Truncated);
    }
    if checksum(&frame[ip..ip + 20]) != 0 {
        return Err(NetError::Checksum);
    }
    let source_ip = Ipv4Address::new(copy_array(frame, ip + 12)?);
    let destination_ip = Ipv4Address::new(copy_array(frame, ip + 16)?);
    let udp = ip + 20;
    let udp_len = usize::from(read_be16(frame, udp + 4)?);
    if udp_len < 8 || udp_len != ip_len - 20 {
        return Err(NetError::Truncated);
    }
    let source_port = read_be16(frame, udp)?;
    let destination_port = read_be16(frame, udp + 2)?;
    if source_port == 0 || destination_port == 0 || udp_len - 8 > MAX_UDP_PAYLOAD_BYTES {
        return Err(NetError::Invalid);
    }
    let stored_checksum = read_be16(frame, udp + 6)?;
    if stored_checksum != 0
        && finalize_sum(udp_sum(
            source_ip,
            destination_ip,
            &frame[udp..udp + udp_len],
        )) != 0
    {
        return Err(NetError::Checksum);
    }
    if frame[ip + ip_len..].iter().any(|byte| *byte != 0) {
        return Err(NetError::Invalid);
    }
    Ok(UdpDatagram {
        source_mac,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        payload: &frame[udp + 8..udp + udp_len],
    })
}

/// Parse one checksummed, unfragmented Ethernet/IPv4/TCP segment.
///
/// # Errors
///
/// Rejects IPv4 options, fragmentation, invalid lengths/checksums, zero ports,
/// unsupported flags or TCP options, invalid acknowledgement fields,
/// oversized payloads, and nonzero Ethernet padding. A single well-formed MSS
/// option is tolerated on SYN segments for interoperability but is not exposed.
pub fn parse_tcp(frame: &[u8]) -> Result<TcpSegment<'_>, NetError> {
    if frame.len() < ETHERNET_HEADER_BYTES + 40 || frame.len() > MAX_FRAME_BYTES {
        return Err(NetError::Truncated);
    }
    if read_be16(frame, 12)? != ETHERTYPE_IPV4 {
        return Err(NetError::Unsupported);
    }
    let ip = ETHERNET_HEADER_BYTES;
    if frame[ip] != 0x45 || frame[ip + 9] != IP_PROTOCOL_TCP {
        return Err(NetError::Unsupported);
    }
    let ip_len = usize::from(read_be16(frame, ip + 2)?);
    if ip_len < 40 || ip + ip_len > frame.len() || read_be16(frame, ip + 6)? & 0x3fff != 0 {
        return Err(NetError::Truncated);
    }
    if checksum(&frame[ip..ip + 20]) != 0 {
        return Err(NetError::Checksum);
    }
    let source_ip = Ipv4Address::new(copy_array(frame, ip + 12)?);
    let destination_ip = Ipv4Address::new(copy_array(frame, ip + 16)?);
    let tcp = ip + 20;
    let tcp_len = ip_len - 20;
    let header_words = usize::from(frame[tcp + 12] >> 4);
    if !(5..=15).contains(&header_words)
        || frame[tcp + 12] & 0x0f != 0
        || read_be16(frame, tcp + 18)? != 0
    {
        return Err(NetError::Unsupported);
    }
    let header_bytes = header_words.checked_mul(4).ok_or(NetError::Invalid)?;
    if header_bytes > tcp_len {
        return Err(NetError::Truncated);
    }
    let flags = TcpFlags::from_bits(frame[tcp + 13])?;
    validate_tcp_syn_options(&frame[tcp + 20..tcp + header_bytes], flags)?;
    let payload = &frame[tcp + header_bytes..tcp + tcp_len];
    if payload.len() > MAX_TCP_PAYLOAD_BYTES
        || (!flags.contains(TcpFlags::ACK) && read_be32(frame, tcp + 8)? != 0)
        || (!payload.is_empty() && (flags.contains(TcpFlags::SYN) || flags.contains(TcpFlags::RST)))
    {
        return Err(NetError::Invalid);
    }
    if !tcp_checksum_valid(source_ip, destination_ip, &frame[tcp..tcp + tcp_len]) {
        return Err(NetError::Checksum);
    }
    if frame[ip + ip_len..].iter().any(|byte| *byte != 0) {
        return Err(NetError::Invalid);
    }
    Ok(TcpSegment {
        source: TcpEndpoint::new(source_ip, read_be16(frame, tcp)?)?,
        destination: TcpEndpoint::new(destination_ip, read_be16(frame, tcp + 2)?)?,
        sequence: read_be32(frame, tcp + 4)?,
        acknowledgement: read_be32(frame, tcp + 8)?,
        flags,
        window: read_be16(frame, tcp + 14)?,
        payload,
    })
}

fn validate_tcp_syn_options(options: &[u8], flags: TcpFlags) -> Result<(), NetError> {
    if options.is_empty() {
        return Ok(());
    }
    if !flags.contains(TcpFlags::SYN) {
        return Err(NetError::Unsupported);
    }
    let mut offset = 0;
    let mut saw_mss = false;
    while offset < options.len() {
        match options[offset] {
            0 => {
                if options[offset..].iter().any(|byte| *byte != 0) {
                    return Err(NetError::Unsupported);
                }
                return Ok(());
            }
            1 => offset += 1,
            2 => {
                let option = options.get(offset..offset + 4).ok_or(NetError::Truncated)?;
                if saw_mss || option[1] != 4 || u16::from_be_bytes([option[2], option[3]]) == 0 {
                    return Err(NetError::Unsupported);
                }
                saw_mss = true;
                offset += 4;
            }
            _ => return Err(NetError::Unsupported),
        }
    }
    Ok(())
}

fn allocate_frame(bytes: usize) -> Result<Vec<u8>, NetError> {
    if bytes > MAX_FRAME_BYTES {
        return Err(NetError::Invalid);
    }
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(bytes)
        .map_err(|_| NetError::Exhausted)?;
    frame.resize(bytes, 0);
    Ok(frame)
}

fn read_be16(bytes: &[u8], offset: usize) -> Result<u16, NetError> {
    let raw = bytes.get(offset..offset + 2).ok_or(NetError::Truncated)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_be32(bytes: &[u8], offset: usize) -> Result<u32, NetError> {
    let raw = bytes.get(offset..offset + 4).ok_or(NetError::Truncated)?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn copy_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], NetError> {
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes.get(offset..offset + N).ok_or(NetError::Truncated)?);
    Ok(output)
}

fn checksum(bytes: &[u8]) -> u16 {
    finalize_sum(sum_words(0, bytes))
}

fn udp_checksum(source: Ipv4Address, destination: Ipv4Address, udp: &[u8]) -> u16 {
    let result = finalize_sum(udp_sum(source, destination, udp));
    if result == 0 { 0xffff } else { result }
}

fn tcp_checksum(source: Ipv4Address, destination: Ipv4Address, tcp: &[u8]) -> u16 {
    let result = finalize_sum(tcp_sum(source, destination, tcp));
    if result == 0 { 0xffff } else { result }
}

fn tcp_checksum_valid(source: Ipv4Address, destination: Ipv4Address, tcp: &[u8]) -> bool {
    finalize_sum(tcp_sum(source, destination, tcp)) == 0
}

fn tcp_sum(source: Ipv4Address, destination: Ipv4Address, tcp: &[u8]) -> u32 {
    let mut sum = sum_words(0, &source.bytes());
    sum = sum_words(sum, &destination.bytes());
    sum = sum.wrapping_add(u32::from(IP_PROTOCOL_TCP));
    sum = sum.wrapping_add(u32::try_from(tcp.len()).unwrap_or(u32::MAX));
    sum_words(sum, tcp)
}

fn udp_sum(source: Ipv4Address, destination: Ipv4Address, udp: &[u8]) -> u32 {
    let mut sum = sum_words(0, &source.bytes());
    sum = sum_words(sum, &destination.bytes());
    sum = sum.wrapping_add(u32::from(IP_PROTOCOL_UDP));
    sum = sum.wrapping_add(u32::try_from(udp.len()).unwrap_or(u32::MAX));
    sum_words(sum, udp)
}

fn sum_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(*byte) << 8);
    }
    sum
}

fn finalize_sum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        Admission, ArpCache, DhcpMessageType, ETHERNET_HEADER_BYTES, Ipv4Address,
        MAX_ARP_CACHE_ENTRIES, MacAddress, NetError, ReceiveLimits, ReceiveQueue,
        TCP_TRANSMIT_ATTEMPTS, TcpEndpoint, TcpFlags, TcpSegment, UDP_QUEUE_DATAGRAMS,
        UdpAdmission, UdpPortTable, build_arp_reply, build_arp_request, build_dhcp_discover,
        build_dhcp_request, build_icmp_echo, build_tcp, build_udp, checksum, parse_arp, parse_dhcp,
        parse_icmp_echo, parse_tcp, parse_udp, tcp_checksum,
    };

    fn mac(bytes: [u8; 6]) -> Result<MacAddress, NetError> {
        MacAddress::new(bytes)
    }

    #[test]
    fn arp_and_udp_round_trip_exact_fields() -> Result<(), NetError> {
        let source_mac = mac([0x02, 0, 0, 0, 0, 1])?;
        let destination_mac = mac([0x02, 0, 0, 0, 0, 2])?;
        let source_ip = Ipv4Address::new([10, 0, 2, 15]);
        let destination_ip = Ipv4Address::new([10, 0, 2, 2]);
        let arp = build_arp_request(source_mac, source_ip, destination_ip)?;
        let parsed_arp = parse_arp(&arp)?;
        assert_eq!(parsed_arp.operation, 1);
        assert_eq!(parsed_arp.sender_mac, source_mac);
        assert_eq!(parsed_arp.target_ip, destination_ip);
        let arp_reply = build_arp_reply(source_mac, source_ip, destination_mac, destination_ip)?;
        let parsed_reply = parse_arp(&arp_reply)?;
        assert_eq!(parsed_reply.operation, 2);
        assert_eq!(parsed_reply.target_mac, destination_mac.bytes());

        let udp = build_udp(
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            49152,
            40123,
            b"stage8",
        )?;
        let parsed_udp = parse_udp(&udp)?;
        assert_eq!(parsed_udp.source_port, 49152);
        assert_eq!(parsed_udp.destination_port, 40123);
        assert_eq!(parsed_udp.payload, b"stage8");
        Ok(())
    }

    #[test]
    fn icmp_echo_and_dhcp_profile_round_trip() -> Result<(), NetError> {
        let client_mac = mac([0x02, 0, 0, 0, 0, 1])?;
        let server_mac = mac([0x02, 0, 0, 0, 0, 2])?;
        let client_ip = Ipv4Address::new([10, 0, 2, 15]);
        let server_ip = Ipv4Address::new([10, 0, 2, 2]);
        let echo = build_icmp_echo(
            server_mac, client_mac, server_ip, client_ip, 0, 0x1234, 7, b"alive",
        )?;
        let parsed_echo = parse_icmp_echo(&echo)?;
        assert_eq!(parsed_echo.kind, 0);
        assert_eq!(parsed_echo.identifier, 0x1234);
        assert_eq!(parsed_echo.sequence, 7);
        assert_eq!(parsed_echo.payload, b"alive");

        let transaction_id = 0x5452_4f45;
        assert!(build_dhcp_discover(client_mac, transaction_id)?.len() >= 60);
        assert!(build_dhcp_request(client_mac, transaction_id, client_ip, server_ip)?.len() >= 60);
        let mut payload = alloc::vec![0_u8; 240 + 28];
        payload[0] = 2;
        payload[1] = 1;
        payload[2] = 6;
        payload[4..8].copy_from_slice(&transaction_id.to_be_bytes());
        payload[16..20].copy_from_slice(&client_ip.bytes());
        payload[28..34].copy_from_slice(&client_mac.bytes());
        payload[236..240].copy_from_slice(&[99, 130, 83, 99]);
        payload[240..].copy_from_slice(&[
            53, 1, 5, 54, 4, 10, 0, 2, 2, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 2, 2, 51, 4, 0, 0,
            14, 16, 255,
        ]);
        let ack = build_udp(
            server_mac, client_mac, server_ip, client_ip, 67, 68, &payload,
        )?;
        let parsed = parse_dhcp(&ack)?;
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.client_mac, client_mac);
        assert_eq!(parsed.your_ip, client_ip);
        assert_eq!(parsed.message_type, DhcpMessageType::Acknowledge);
        assert_eq!(parsed.server_identifier, Some(server_ip));
        assert_eq!(
            parsed.subnet_mask,
            Some(Ipv4Address::new([255, 255, 255, 0]))
        );
        assert_eq!(parsed.router, Some(server_ip));
        assert_eq!(parsed.lease_seconds, Some(3600));
        Ok(())
    }

    #[test]
    fn every_truncation_and_checksum_corruption_fails() -> Result<(), NetError> {
        let frame = build_udp(
            mac([0x02, 1, 2, 3, 4, 5])?,
            mac([0x02, 6, 7, 8, 9, 10])?,
            Ipv4Address::new([192, 0, 2, 1]),
            Ipv4Address::new([192, 0, 2, 2]),
            1000,
            2000,
            b"bounded",
        )?;
        for length in 0..42 {
            assert!(parse_udp(&frame[..length]).is_err());
        }
        let mut header = frame.clone();
        header[24] ^= 1;
        assert_eq!(parse_udp(&header), Err(NetError::Checksum));
        let mut transport = frame;
        transport[42] ^= 1;
        assert_eq!(parse_udp(&transport), Err(NetError::Checksum));
        Ok(())
    }

    #[test]
    fn tcp_wire_profile_is_exact_and_corruption_closed() -> Result<(), NetError> {
        let source_mac = mac([0x02, 1, 2, 3, 4, 5])?;
        let destination_mac = mac([0x02, 6, 7, 8, 9, 10])?;
        let source = TcpEndpoint::new(Ipv4Address::new([192, 0, 2, 1]), 49_152)?;
        let destination = TcpEndpoint::new(Ipv4Address::new([192, 0, 2, 2]), 8080)?;
        let segment = TcpSegment {
            source,
            destination,
            sequence: 0xffff_fffe,
            acknowledgement: 17,
            flags: TcpFlags::PSH_ACK,
            window: 4096,
            payload: b"stream",
        };
        let frame = build_tcp(source_mac, destination_mac, segment)?;
        let parsed = parse_tcp(&frame)?;
        assert_eq!(parsed, segment);
        assert_eq!(TCP_TRANSMIT_ATTEMPTS, 4);

        for end in 0..54 {
            assert!(parse_tcp(&frame[..end]).is_err());
        }
        let mut ip_corrupt = frame.clone();
        ip_corrupt[24] ^= 1;
        assert_eq!(parse_tcp(&ip_corrupt), Err(NetError::Checksum));
        let mut tcp_corrupt = frame.clone();
        tcp_corrupt[54] ^= 1;
        assert_eq!(parse_tcp(&tcp_corrupt), Err(NetError::Checksum));
        let mut fragment = frame.clone();
        fragment[20..22].copy_from_slice(&0x2000_u16.to_be_bytes());
        assert!(parse_tcp(&fragment).is_err());
        let mut padded_syn = build_tcp(
            source_mac,
            destination_mac,
            TcpSegment {
                source,
                destination,
                sequence: 1,
                acknowledgement: 0,
                flags: TcpFlags::SYN,
                window: 4096,
                payload: &[],
            },
        )?;
        let last = padded_syn.len() - 1;
        padded_syn[last] = 1;
        assert_eq!(parse_tcp(&padded_syn), Err(NetError::Invalid));

        let mut mss_syn = build_tcp(
            source_mac,
            destination_mac,
            TcpSegment {
                source,
                destination,
                sequence: 2,
                acknowledgement: 0,
                flags: TcpFlags::SYN,
                window: 4096,
                payload: &[],
            },
        )?;
        let ip = ETHERNET_HEADER_BYTES;
        let tcp = ip + 20;
        mss_syn[ip + 2..ip + 4].copy_from_slice(&44_u16.to_be_bytes());
        mss_syn[tcp + 12] = 6 << 4;
        mss_syn[tcp + 20..tcp + 24].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        mss_syn[ip + 10..ip + 12].fill(0);
        let ip_checksum = checksum(&mss_syn[ip..ip + 20]);
        mss_syn[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());
        mss_syn[tcp + 16..tcp + 18].fill(0);
        let transport_checksum = tcp_checksum(
            source.address(),
            destination.address(),
            &mss_syn[tcp..tcp + 24],
        );
        mss_syn[tcp + 16..tcp + 18].copy_from_slice(&transport_checksum.to_be_bytes());
        assert_eq!(parse_tcp(&mss_syn)?.flags, TcpFlags::SYN);

        let mut option_on_ack = mss_syn;
        option_on_ack[tcp + 13] = TcpFlags::ACK.bits();
        assert_eq!(parse_tcp(&option_on_ack), Err(NetError::Unsupported));
        Ok(())
    }

    #[test]
    fn high_volume_input_stays_within_count_and_byte_limits() -> Result<(), NetError> {
        let limits = ReceiveLimits::new(4, 256, 64)?;
        let mut queue = ReceiveQueue::new(limits);
        let frame = [0_u8; 64];
        for index in 0..10_000 {
            let admission = queue.push(&frame)?;
            assert_eq!(
                admission,
                if index < 4 {
                    Admission::Retained
                } else {
                    Admission::Dropped
                }
            );
        }
        assert_eq!(queue.usage(), (4, 256));
        assert_eq!(queue.dropped(), 9_996);
        while queue.pop().is_some() {}
        assert_eq!(queue.usage(), (0, 0));
        Ok(())
    }

    #[test]
    fn arp_cache_is_fixed_and_evicts_the_oldest_neighbor() -> Result<(), NetError> {
        let mut cache = ArpCache::new();
        for index in 0..=MAX_ARP_CACHE_ENTRIES {
            cache.learn(
                Ipv4Address::new([10, 0, 0, u8::try_from(index + 1).unwrap_or(u8::MAX)]),
                mac([0x02, 0, 0, 0, 0, u8::try_from(index + 1).unwrap_or(u8::MAX)])?,
            );
        }
        assert_eq!(cache.len(), MAX_ARP_CACHE_ENTRIES);
        assert_eq!(cache.lookup(Ipv4Address::new([10, 0, 0, 1])), None);
        assert!(cache.lookup(Ipv4Address::new([10, 0, 0, 9])).is_some());
        Ok(())
    }

    #[test]
    fn persistent_udp_ports_drop_newest_at_per_port_ceiling() -> Result<(), NetError> {
        let source_mac = mac([0x02, 0, 0, 0, 0, 1])?;
        let destination_mac = mac([0x02, 0, 0, 0, 0, 2])?;
        let source_ip = Ipv4Address::new([10, 0, 2, 2]);
        let destination_ip = Ipv4Address::new([10, 0, 2, 15]);
        let mut ports = UdpPortTable::new()?;
        ports.bind(40_000)?;
        ports.bind(40_000)?;
        assert_eq!(ports.len(), 1);
        for index in 0..UDP_QUEUE_DATAGRAMS + 2 {
            let frame = build_udp(
                source_mac,
                destination_mac,
                source_ip,
                destination_ip,
                49_152,
                40_000,
                &[u8::try_from(index).unwrap_or(u8::MAX)],
            )?;
            assert_eq!(
                ports.admit(parse_udp(&frame)?)?,
                if index < UDP_QUEUE_DATAGRAMS {
                    UdpAdmission::Retained
                } else {
                    UdpAdmission::Dropped
                }
            );
        }
        let snapshot = ports.snapshots().next().ok_or(NetError::Invalid)?;
        assert_eq!(snapshot.datagrams, UDP_QUEUE_DATAGRAMS);
        assert_eq!(snapshot.dropped, 2);
        for expected in 0..UDP_QUEUE_DATAGRAMS {
            let received = ports.receive(40_000).ok_or(NetError::Invalid)?;
            assert_eq!(
                received.payload,
                [u8::try_from(expected).unwrap_or(u8::MAX)]
            );
        }
        assert!(ports.receive(40_000).is_none());
        assert!(ports.unbind(40_000));
        assert!(!ports.unbind(40_000));
        assert!(ports.is_empty());
        Ok(())
    }
}

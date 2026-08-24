//! Bounded Ethernet, ARP, IPv4, UDP, and receive-queue primitives.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Ethernet header bytes without VLAN tags.
pub const ETHERNET_HEADER_BYTES: usize = 14;
/// Largest accepted initial-profile Ethernet frame without FCS.
pub const MAX_FRAME_BYTES: usize = 1514;
/// Minimum transmitted Ethernet frame without FCS.
pub const MIN_FRAME_BYTES: usize = 60;
/// Maximum UDP payload under the 1500-byte IPv4 MTU.
pub const MAX_UDP_PAYLOAD_BYTES: usize = 1472;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const IP_PROTOCOL_UDP: u8 = 17;

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
    if source_port == 0 || destination_port == 0 || payload.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(NetError::Invalid);
    }
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or(NetError::Invalid)?;
    let ip_len = 20_usize.checked_add(udp_len).ok_or(NetError::Invalid)?;
    let wire_len = ETHERNET_HEADER_BYTES
        .checked_add(ip_len)
        .ok_or(NetError::Invalid)?;
    let mut frame = allocate_frame(wire_len.max(MIN_FRAME_BYTES))?;
    frame[..6].copy_from_slice(&destination_mac.bytes());
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
    frame[ip + 9] = IP_PROTOCOL_UDP;
    frame[ip + 12..ip + 16].copy_from_slice(&source_ip.bytes());
    frame[ip + 16..ip + 20].copy_from_slice(&destination_ip.bytes());
    let header_checksum = checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&header_checksum.to_be_bytes());
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
        Admission, Ipv4Address, MacAddress, NetError, ReceiveLimits, ReceiveQueue,
        build_arp_request, build_udp, parse_arp, parse_udp,
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
}

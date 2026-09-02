//! Read-only typed IPv4 configuration, counters, and neighbor protocol.

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Read current link and IPv4 configuration.
pub const GET_STATUS: u16 = 1;
/// Read current ambient counters and bounded resource use.
pub const GET_STATS: u16 = 2;
/// Read the complete bounded neighbor cache.
pub const GET_NEIGHBORS: u16 = 3;
/// Exact link/configuration reply bytes.
pub const STATUS_BYTES: usize = 24;
/// Exact counter reply bytes.
pub const STATS_BYTES: usize = 88;
/// Maximum retained IPv4 neighbors.
pub const MAX_NEIGHBORS: usize = 256;
/// Maximum canonical neighbor-list reply bytes.
pub const MAX_NEIGHBOR_REPLY_BYTES: usize = 8 + MAX_NEIGHBORS * 10;

const CONFIGURED: u8 = 1 << 0;
const LEASE_PRESENT: u8 = 1 << 1;
const KNOWN_STATUS_FLAGS: u8 = CONFIGURED | LEASE_PRESENT;

/// Current configured IPv4 values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Configuration {
    /// Interface address.
    pub address: [u8; 4],
    /// Subnet mask.
    pub subnet_mask: [u8; 4],
    /// Default gateway.
    pub gateway: [u8; 4],
    /// DHCP lease duration when supplied by the server.
    pub lease_seconds: Option<u32>,
}

/// Current link and optional IPv4 configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Attached interface Ethernet address.
    pub mac: [u8; 6],
    /// Complete IPv4 configuration when acquired.
    pub configuration: Option<Ipv4Configuration>,
}

/// Ambient network counters and bounded resource use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stats {
    /// Complete received frames.
    pub received_frames: u64,
    /// Complete transmitted frames.
    pub transmitted_frames: u64,
    /// Answered ARP requests.
    pub arp_replies: u64,
    /// Answered ICMP echo requests.
    pub icmp_replies: u64,
    /// UDP datagrams retained by bound ports.
    pub udp_retained: u64,
    /// UDP datagrams dropped without a bound port.
    pub udp_unbound: u64,
    /// UDP datagrams dropped at queue ceilings.
    pub udp_dropped: u64,
    /// Currently retained neighbor entries.
    pub arp_entries: u64,
    /// Currently bound UDP ports.
    pub udp_ports: u64,
    /// Ambient service checkpoints.
    pub checkpoints: u64,
    /// Device or packet-processing errors.
    pub errors: u64,
}

/// One retained IPv4-to-Ethernet neighbor mapping.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Neighbor {
    /// Neighbor IPv4 address.
    pub address: [u8; 4],
    /// Neighbor Ethernet address.
    pub mac: [u8; 6],
}

/// Complete fixed-capacity neighbor snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Neighbors {
    entries: [Neighbor; MAX_NEIGHBORS],
    count: usize,
}

impl Neighbors {
    /// Construct one bounded neighbor snapshot.
    ///
    /// # Errors
    ///
    /// Rejects excess or duplicate IPv4 entries.
    pub fn from_slice(entries: &[Neighbor]) -> Result<Self, EncodingError> {
        if entries.len() > MAX_NEIGHBORS
            || entries.iter().enumerate().any(|(index, entry)| {
                entries[..index]
                    .iter()
                    .any(|prior| prior.address == entry.address)
            })
        {
            return Err(EncodingError);
        }
        let mut retained = [Neighbor::default(); MAX_NEIGHBORS];
        retained[..entries.len()].copy_from_slice(entries);
        Ok(Self {
            entries: retained,
            count: entries.len(),
        })
    }

    /// Number of retained entries.
    #[must_use]
    pub const fn len(self) -> usize {
        self.count
    }

    /// Whether the snapshot contains no neighbors.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Iterate over retained entries in service order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Neighbor> + '_ {
        self.entries[..self.count].iter().copied()
    }
}

/// Invalid, inconsistent, or noncanonical network-observation encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Encode one exact link/configuration status.
///
/// # Errors
///
/// Rejects a configured zero interface address.
pub fn encode_status(status: Status) -> Result<[u8; STATUS_BYTES], EncodingError> {
    let mut bytes = [0_u8; STATUS_BYTES];
    bytes[..6].copy_from_slice(&status.mac);
    if let Some(configuration) = status.configuration {
        if configuration.address == [0; 4] {
            return Err(EncodingError);
        }
        bytes[6] = CONFIGURED;
        bytes[8..12].copy_from_slice(&configuration.address);
        bytes[12..16].copy_from_slice(&configuration.subnet_mask);
        bytes[16..20].copy_from_slice(&configuration.gateway);
        if let Some(lease) = configuration.lease_seconds {
            bytes[6] |= LEASE_PRESENT;
            bytes[20..24].copy_from_slice(&lease.to_le_bytes());
        }
    }
    Ok(bytes)
}

/// Decode one exact canonical link/configuration status.
///
/// # Errors
///
/// Rejects unknown flags, nonzero reserved/absent fields, a lease without
/// configuration, a configured zero address, or the wrong length.
pub fn decode_status(bytes: &[u8]) -> Result<Status, EncodingError> {
    if bytes.len() != STATUS_BYTES
        || bytes[6] & !KNOWN_STATUS_FLAGS != 0
        || bytes[7] != 0
        || bytes[6] & LEASE_PRESENT != 0 && bytes[6] & CONFIGURED == 0
    {
        return Err(EncodingError);
    }
    let configured_values_nonzero = bytes[8..24].iter().any(|byte| *byte != 0);
    let configuration = if bytes[6] & CONFIGURED != 0 {
        let address = [bytes[8], bytes[9], bytes[10], bytes[11]];
        if address == [0; 4] {
            return Err(EncodingError);
        }
        Some(Ipv4Configuration {
            address,
            subnet_mask: [bytes[12], bytes[13], bytes[14], bytes[15]],
            gateway: [bytes[16], bytes[17], bytes[18], bytes[19]],
            lease_seconds: if bytes[6] & LEASE_PRESENT != 0 {
                Some(u32::from_le_bytes([
                    bytes[20], bytes[21], bytes[22], bytes[23],
                ]))
            } else {
                if bytes[20..24] != [0; 4] {
                    return Err(EncodingError);
                }
                None
            },
        })
    } else if configured_values_nonzero {
        return Err(EncodingError);
    } else {
        None
    };
    Ok(Status {
        mac: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
        configuration,
    })
}

/// Encode one exact counter snapshot.
///
/// # Errors
///
/// Rejects resource counts above their fixed service ceilings.
pub fn encode_stats(stats: Stats) -> Result<[u8; STATS_BYTES], EncodingError> {
    if stats.arp_entries > MAX_NEIGHBORS as u64 || stats.udp_ports > MAX_NEIGHBORS as u64 {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; STATS_BYTES];
    write_values(
        &mut bytes,
        &[
            stats.received_frames,
            stats.transmitted_frames,
            stats.arp_replies,
            stats.icmp_replies,
            stats.udp_retained,
            stats.udp_unbound,
            stats.udp_dropped,
            stats.arp_entries,
            stats.udp_ports,
            stats.checkpoints,
            stats.errors,
        ],
    );
    Ok(bytes)
}

/// Decode one exact counter snapshot.
///
/// # Errors
///
/// Rejects the wrong length or resource counts above fixed ceilings.
pub fn decode_stats(bytes: &[u8]) -> Result<Stats, EncodingError> {
    if bytes.len() != STATS_BYTES {
        return Err(EncodingError);
    }
    let values = read_values::<11>(bytes)?;
    let stats = Stats {
        received_frames: values[0],
        transmitted_frames: values[1],
        arp_replies: values[2],
        icmp_replies: values[3],
        udp_retained: values[4],
        udp_unbound: values[5],
        udp_dropped: values[6],
        arp_entries: values[7],
        udp_ports: values[8],
        checkpoints: values[9],
        errors: values[10],
    };
    encode_stats(stats)?;
    Ok(stats)
}

/// Encode one complete bounded neighbor snapshot.
///
/// # Errors
///
/// Rejects insufficient storage without modifying it.
pub fn encode_neighbors(neighbors: Neighbors, output: &mut [u8]) -> Result<usize, EncodingError> {
    let count = 8 + neighbors.count.checked_mul(10).ok_or(EncodingError)?;
    if output.len() < count {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; MAX_NEIGHBOR_REPLY_BYTES];
    bytes[..2].copy_from_slice(
        &u16::try_from(neighbors.count)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    for (index, entry) in neighbors.iter().enumerate() {
        let offset = 8 + index * 10;
        bytes[offset..offset + 4].copy_from_slice(&entry.address);
        bytes[offset + 4..offset + 10].copy_from_slice(&entry.mac);
    }
    output[..count].copy_from_slice(&bytes[..count]);
    Ok(count)
}

/// Decode one exact complete bounded neighbor snapshot.
///
/// # Errors
///
/// Rejects excess, truncation, trailing bytes, nonzero reserved fields, or
/// duplicate IPv4 entries.
pub fn decode_neighbors(bytes: &[u8]) -> Result<Neighbors, EncodingError> {
    if bytes.len() < 8 || bytes[2..8] != [0; 6] {
        return Err(EncodingError);
    }
    let count = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    let expected = 8_usize
        .checked_add(count.checked_mul(10).ok_or(EncodingError)?)
        .ok_or(EncodingError)?;
    if count > MAX_NEIGHBORS || bytes.len() != expected {
        return Err(EncodingError);
    }
    let mut entries = [Neighbor::default(); MAX_NEIGHBORS];
    for (index, entry) in entries[..count].iter_mut().enumerate() {
        let offset = 8 + index * 10;
        entry.address = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        entry.mac.copy_from_slice(&bytes[offset + 4..offset + 10]);
    }
    Neighbors::from_slice(&entries[..count])
}

fn write_values(bytes: &mut [u8], values: &[u64]) {
    for (index, value) in values.iter().copied().enumerate() {
        let offset = index * 8;
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

fn read_values<const N: usize>(bytes: &[u8]) -> Result<[u64; N], EncodingError> {
    let mut values = [0_u64; N];
    for (index, value) in values.iter_mut().enumerate() {
        let offset = index * 8;
        let raw = bytes.get(offset..offset + 8).ok_or(EncodingError)?;
        *value = u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use crate::network_observation;

    #[test]
    fn network_observation_records_are_exact_and_bounded() {
        let configured_link = network_observation::Status {
            mac: [2, 0, 0, 0, 0, 1],
            configuration: Some(network_observation::Ipv4Configuration {
                address: [10, 0, 2, 15],
                subnet_mask: [255, 255, 255, 0],
                gateway: [10, 0, 2, 2],
                lease_seconds: Some(86_400),
            }),
        };
        let encoded = network_observation::encode_status(configured_link)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            network_observation::decode_status(&encoded),
            Ok(configured_link)
        );
        assert!(network_observation::decode_status(&encoded[..23]).is_err());

        let counters = network_observation::Stats {
            received_frames: 1,
            transmitted_frames: 2,
            arp_replies: 3,
            icmp_replies: 4,
            udp_retained: 5,
            udp_unbound: 6,
            udp_dropped: 7,
            arp_entries: 8,
            udp_ports: 8,
            checkpoints: 9,
            errors: 10,
        };
        let encoded =
            network_observation::encode_stats(counters).unwrap_or_else(|_| std::process::abort());
        assert_eq!(network_observation::decode_stats(&encoded), Ok(counters));

        let entries = [
            network_observation::Neighbor {
                address: [10, 0, 2, 2],
                mac: [0x52, 0x55, 0x0a, 0, 2, 2],
            },
            network_observation::Neighbor {
                address: [10, 0, 2, 3],
                mac: [0x52, 0x55, 0x0a, 0, 2, 3],
            },
        ];
        let neighbors = network_observation::Neighbors::from_slice(&entries)
            .unwrap_or_else(|_| std::process::abort());
        let mut bytes = [0_u8; network_observation::MAX_NEIGHBOR_REPLY_BYTES];
        let count = network_observation::encode_neighbors(neighbors, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let decoded = network_observation::decode_neighbors(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.iter().collect::<std::vec::Vec<_>>(), entries);
        assert!(network_observation::decode_neighbors(&bytes[..count - 1]).is_err());
        assert!(network_observation::Neighbors::from_slice(&[entries[0], entries[0]]).is_err());
    }
}

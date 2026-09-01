#![no_std]

/// Bytes in the fixed SNTP header used by the first client.
pub const PACKET_BYTES: usize = 48;
/// Whole seconds between the NTP and Unix epochs.
pub const NTP_TO_UNIX_SECONDS: u64 = 2_208_988_800;

/// Closed validation failure for one SNTP reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// The fixed header is incomplete.
    Truncated,
    /// Leap, version, mode, or stratum fields reject the packet.
    Header,
    /// The server did not echo the exact client transmit token.
    Originate,
    /// A required server timestamp is zero.
    Timestamp,
    /// The era-zero server timestamp precedes the Unix epoch.
    Era,
}

/// Create one SNTPv4 client request carrying an opaque nonzero token.
#[must_use]
pub fn request(token: u64) -> [u8; PACKET_BYTES] {
    let mut packet = [0_u8; PACKET_BYTES];
    packet[0] = 0x23;
    packet[40..48].copy_from_slice(&token.max(1).to_be_bytes());
    packet
}

/// Validate one server reply and return its era-zero Unix transmit second.
///
/// The first implementation deliberately accepts only NTP era zero, which
/// covers Unix time through 2036-02-07. A later client can add era selection
/// using a trusted wall-clock estimate without guessing at wraparound.
pub fn unix_transmit_seconds(packet: &[u8], token: u64) -> Result<u64, ProtocolError> {
    if packet.len() < PACKET_BYTES {
        return Err(ProtocolError::Truncated);
    }
    let leap = packet[0] >> 6;
    let version = (packet[0] >> 3) & 0x07;
    let mode = packet[0] & 0x07;
    if leap == 3 || version != 4 || mode != 4 || !(1..=15).contains(&packet[1]) {
        return Err(ProtocolError::Header);
    }
    if packet[24..32] != token.max(1).to_be_bytes() {
        return Err(ProtocolError::Originate);
    }
    if packet[32..40].iter().all(|byte| *byte == 0) || packet[40..48].iter().all(|byte| *byte == 0)
    {
        return Err(ProtocolError::Timestamp);
    }
    let seconds = u64::from(u32::from_be_bytes([
        packet[40], packet[41], packet[42], packet[43],
    ]));
    seconds
        .checked_sub(NTP_TO_UNIX_SECONDS)
        .ok_or(ProtocolError::Era)
}

#[cfg(test)]
mod tests {
    use super::{NTP_TO_UNIX_SECONDS, ProtocolError, request, unix_transmit_seconds};

    fn reply(token: u64) -> [u8; 48] {
        let mut packet = [0_u8; 48];
        packet[0] = 0x24;
        packet[1] = 2;
        packet[24..32].copy_from_slice(&token.to_be_bytes());
        packet[32..40].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
        let transmit = u32::try_from(NTP_TO_UNIX_SECONDS + 1_800_000_000);
        assert!(transmit.is_ok(), "the fixture epoch fits an NTP timestamp");
        packet[40..44].copy_from_slice(&transmit.unwrap_or_default().to_be_bytes());
        packet[47] = 1;
        packet
    }

    #[test]
    fn request_is_v4_client_and_carries_nonzero_token() {
        let packet = request(0);
        assert_eq!(packet[0], 0x23);
        assert_eq!(&packet[40..48], &1_u64.to_be_bytes());
    }

    #[test]
    fn valid_reply_returns_unix_seconds() {
        assert_eq!(unix_transmit_seconds(&reply(9), 9), Ok(1_800_000_000));
    }

    #[test]
    fn rejects_truncation_header_replay_zero_stamps_and_pre_epoch_era() {
        let valid = reply(9);
        assert_eq!(
            unix_transmit_seconds(&valid[..47], 9),
            Err(ProtocolError::Truncated)
        );

        let mut invalid = valid;
        invalid[0] = 0xe4;
        assert_eq!(
            unix_transmit_seconds(&invalid, 9),
            Err(ProtocolError::Header)
        );

        assert_eq!(
            unix_transmit_seconds(&valid, 8),
            Err(ProtocolError::Originate)
        );

        let mut zero = valid;
        zero[32..40].fill(0);
        assert_eq!(
            unix_transmit_seconds(&zero, 9),
            Err(ProtocolError::Timestamp)
        );

        let mut old = valid;
        old[40..44].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(unix_transmit_seconds(&old, 9), Err(ProtocolError::Era));
    }
}

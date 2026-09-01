//! Bounded ICMP echo protocol.

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Send one echo request and wait for its matching reply.
pub const ECHO: u16 = 1;
/// Exact destination request bytes.
pub const REQUEST_BYTES: usize = 4;
/// Exact echo reply bytes.
pub const REPLY_BYTES: usize = 8;

/// Successful typed ICMP echo result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reply {
    /// Reply source address.
    pub source: [u8; 4],
    /// Echo sequence number.
    pub sequence: u16,
    /// Echo payload byte count.
    pub bytes: u16,
}

/// Invalid ICMP echo request or reply encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Encode one exact echo destination.
#[must_use]
pub const fn encode_request(destination: [u8; 4]) -> [u8; REQUEST_BYTES] {
    destination
}

/// Decode one exact echo destination.
///
/// # Errors
///
/// Rejects every length other than four bytes.
pub fn decode_request(bytes: &[u8]) -> Result<[u8; 4], EncodingError> {
    if bytes.len() != REQUEST_BYTES {
        return Err(EncodingError);
    }
    Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Encode one exact typed echo reply.
#[must_use]
pub fn encode_reply(reply: Reply) -> [u8; REPLY_BYTES] {
    let mut bytes = [0_u8; REPLY_BYTES];
    bytes[..4].copy_from_slice(&reply.source);
    bytes[4..6].copy_from_slice(&reply.sequence.to_le_bytes());
    bytes[6..8].copy_from_slice(&reply.bytes.to_le_bytes());
    bytes
}

/// Decode one exact typed echo reply.
///
/// # Errors
///
/// Rejects every length other than eight bytes.
pub fn decode_reply(bytes: &[u8]) -> Result<Reply, EncodingError> {
    if bytes.len() != REPLY_BYTES {
        return Err(EncodingError);
    }
    Ok(Reply {
        source: [bytes[0], bytes[1], bytes[2], bytes[3]],
        sequence: u16::from_le_bytes([bytes[4], bytes[5]]),
        bytes: u16::from_le_bytes([bytes[6], bytes[7]]),
    })
}

#[cfg(test)]
mod tests {
    use crate::icmp_echo;

    #[test]
    fn icmp_echo_records_are_exact() {
        let destination = [192, 0, 2, 1];
        assert_eq!(
            icmp_echo::decode_request(&icmp_echo::encode_request(destination)),
            Ok(destination)
        );
        let reply = icmp_echo::Reply {
            source: destination,
            sequence: u16::MAX,
            bytes: 9,
        };
        assert_eq!(
            icmp_echo::decode_reply(&icmp_echo::encode_reply(reply)),
            Ok(reply)
        );
        assert!(icmp_echo::decode_request(&destination[..3]).is_err());
    }
}

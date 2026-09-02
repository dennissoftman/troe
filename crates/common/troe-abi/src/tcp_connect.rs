//! One bounded outbound IPv4/TCP byte-stream protocol.

use super::MAX_SERVICE_PAYLOAD_BYTES;

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Attempt one connection to one literal IPv4 endpoint.
pub const CONNECT: u16 = 1;
/// Write and acknowledge one bounded stream chunk.
pub const WRITE: u16 = 2;
/// Wait for and return one bounded stream chunk; zero bytes is EOF.
pub const READ: u16 = 3;
/// Gracefully close the one connection.
pub const CLOSE: u16 = 4;
/// Exact connect request bytes, including two reserved zero bytes.
pub const CONNECT_REQUEST_BYTES: usize = 8;
/// Exact selected-local-port connect reply bytes.
pub const CONNECT_REPLY_BYTES: usize = 2;
/// Largest write admitted as one TCP segment.
pub const MAX_WRITE_BYTES: usize = 1_460;
/// Largest read returned through the generic KEX service call gate.
pub const MAX_READ_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES;
/// Exact read request bytes.
pub const READ_REQUEST_BYTES: usize = 2;

/// Invalid TCP connect request or reply encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// One validated literal IPv4 destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    /// Destination in network display order.
    pub destination: [u8; 4],
    /// Nonzero destination TCP port.
    pub destination_port: u16,
}

/// Encode one exact literal endpoint request.
///
/// # Errors
///
/// Rejects unspecified, loopback, multicast, broadcast, and class-E
/// destinations plus port zero.
pub fn encode_connect_request(
    destination: [u8; 4],
    destination_port: u16,
) -> Result<[u8; CONNECT_REQUEST_BYTES], EncodingError> {
    if !valid_destination(destination) || destination_port == 0 {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; CONNECT_REQUEST_BYTES];
    bytes[..4].copy_from_slice(&destination);
    bytes[4..6].copy_from_slice(&destination_port.to_le_bytes());
    Ok(bytes)
}

/// Decode one exact literal endpoint request.
///
/// # Errors
///
/// Rejects every truncation/trailing byte, nonzero reserved field, invalid
/// address class, and port zero.
pub fn decode_connect_request(bytes: &[u8]) -> Result<ConnectRequest, EncodingError> {
    if bytes.len() != CONNECT_REQUEST_BYTES || bytes[6..8] != [0, 0] {
        return Err(EncodingError);
    }
    let destination = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let destination_port = u16::from_le_bytes([bytes[4], bytes[5]]);
    if !valid_destination(destination) || destination_port == 0 {
        return Err(EncodingError);
    }
    Ok(ConnectRequest {
        destination,
        destination_port,
    })
}

/// Encode the exact selected local port.
///
/// # Errors
///
/// Rejects port zero.
pub fn encode_connect_reply(local_port: u16) -> Result<[u8; CONNECT_REPLY_BYTES], EncodingError> {
    if local_port == 0 {
        return Err(EncodingError);
    }
    Ok(local_port.to_le_bytes())
}

/// Decode the exact selected local port.
///
/// # Errors
///
/// Rejects every length other than two bytes and port zero.
pub fn decode_connect_reply(bytes: &[u8]) -> Result<u16, EncodingError> {
    if bytes.len() != CONNECT_REPLY_BYTES {
        return Err(EncodingError);
    }
    let port = u16::from_le_bytes([bytes[0], bytes[1]]);
    if port == 0 {
        return Err(EncodingError);
    }
    Ok(port)
}

/// Validate one write payload and return it unchanged.
///
/// # Errors
///
/// Rejects empty or multi-segment writes.
pub fn decode_write_request(bytes: &[u8]) -> Result<&[u8], EncodingError> {
    if bytes.is_empty() || bytes.len() > MAX_WRITE_BYTES {
        return Err(EncodingError);
    }
    Ok(bytes)
}

/// Encode one bounded read byte count.
///
/// # Errors
///
/// Rejects zero and values above the KEX reply-payload ceiling.
pub fn encode_read_request(requested: usize) -> Result<[u8; READ_REQUEST_BYTES], EncodingError> {
    if requested == 0 || requested > MAX_READ_BYTES {
        return Err(EncodingError);
    }
    Ok(u16::try_from(requested)
        .map_err(|_| EncodingError)?
        .to_le_bytes())
}

/// Decode one exact bounded read byte count.
///
/// # Errors
///
/// Rejects every length other than two bytes, zero, and values above the
/// KEX reply-payload ceiling.
pub fn decode_read_request(bytes: &[u8]) -> Result<usize, EncodingError> {
    if bytes.len() != READ_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let requested = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    if requested == 0 || requested > MAX_READ_BYTES {
        return Err(EncodingError);
    }
    Ok(requested)
}

fn valid_destination(address: [u8; 4]) -> bool {
    address != [0; 4]
        && address != [255; 4]
        && address[0] != 0
        && address[0] != 127
        && address[0] < 224
}

#[cfg(test)]
mod tests {
    use crate::tcp_connect;

    #[test]
    fn tcp_connect_records_are_exact_literal_and_bounded() {
        let encoded = tcp_connect::encode_connect_request([192, 0, 2, 1], 443)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            tcp_connect::decode_connect_request(&encoded),
            Ok(tcp_connect::ConnectRequest {
                destination: [192, 0, 2, 1],
                destination_port: 443,
            })
        );
        for end in 0..encoded.len() {
            assert!(tcp_connect::decode_connect_request(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(tcp_connect::decode_connect_request(&trailing).is_err());
        let mut reserved = encoded;
        reserved[7] = 1;
        assert!(tcp_connect::decode_connect_request(&reserved).is_err());

        for address in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
            assert!(tcp_connect::encode_connect_request(address, 80).is_err());
        }
        assert!(tcp_connect::encode_connect_request([192, 0, 2, 1], 0).is_err());
        assert_eq!(
            tcp_connect::decode_connect_reply(
                &tcp_connect::encode_connect_reply(49_152)
                    .unwrap_or_else(|_| std::process::abort())
            ),
            Ok(49_152)
        );
        assert!(tcp_connect::decode_connect_reply(&[0, 0]).is_err());

        let maximum = [0xa5_u8; tcp_connect::MAX_WRITE_BYTES];
        assert_eq!(
            tcp_connect::decode_write_request(&maximum)
                .unwrap_or_else(|_| std::process::abort())
                .len(),
            tcp_connect::MAX_WRITE_BYTES
        );
        assert!(tcp_connect::decode_write_request(&[]).is_err());
        let oversize = [0_u8; tcp_connect::MAX_WRITE_BYTES + 1];
        assert!(tcp_connect::decode_write_request(&oversize).is_err());

        let read = tcp_connect::encode_read_request(tcp_connect::MAX_READ_BYTES)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            tcp_connect::decode_read_request(&read),
            Ok(tcp_connect::MAX_READ_BYTES)
        );
        assert!(tcp_connect::decode_read_request(&[1]).is_err());
        assert!(tcp_connect::encode_read_request(0).is_err());
    }
}

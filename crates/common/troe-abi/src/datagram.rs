//! Owned IPv4/UDP datagram protocol.

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Send one datagram and retain ownership of its selected source port.
pub const SEND: u16 = 1;
/// Wait cooperatively for one datagram on an owned local port.
pub const RECEIVE: u16 = 2;
/// Maximum UDP payload admitted by the platform profile.
pub const MAX_PAYLOAD_BYTES: usize = 1_472;
/// Fixed bytes preceding the payload in a send request.
pub const SEND_HEADER_BYTES: usize = 8;
/// Largest canonical send request payload.
pub const MAX_SEND_REQUEST_BYTES: usize = SEND_HEADER_BYTES + MAX_PAYLOAD_BYTES;
/// Fixed bytes preceding the payload in a receive reply.
pub const RECEIVE_HEADER_BYTES: usize = 6;
/// Largest canonical receive reply.
pub const MAX_RECEIVE_REPLY_BYTES: usize = RECEIVE_HEADER_BYTES + MAX_PAYLOAD_BYTES;

/// Invalid datagram request or reply encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Borrowed, validated send request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendRequest<'a> {
    /// Zero requests an ephemeral source port.
    pub source_port: u16,
    /// Destination IPv4 address in network display order.
    pub destination: [u8; 4],
    /// Nonzero destination UDP port.
    pub destination_port: u16,
    /// Exact datagram payload.
    pub payload: &'a [u8],
}

/// Borrowed, validated received datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedDatagram<'a> {
    /// Source IPv4 address in network display order.
    pub source: [u8; 4],
    /// Nonzero source UDP port.
    pub source_port: u16,
    /// Exact datagram payload.
    pub payload: &'a [u8],
}

/// Encode one canonical send request into caller-owned storage.
///
/// A zero source port selects an ephemeral port. All other ports must be
/// nonzero, and no destination bytes are modified on failure.
///
/// # Errors
///
/// Rejects zero explicit/destination ports, oversize payloads, overflow,
/// or insufficient destination storage.
pub fn encode_send_request(
    source_port: Option<u16>,
    destination: [u8; 4],
    destination_port: u16,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    if source_port == Some(0) {
        return Err(EncodingError);
    }
    let source_port = source_port.unwrap_or(0);
    let count = SEND_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(EncodingError)?;
    if destination_port == 0 || payload.len() > MAX_PAYLOAD_BYTES || output.len() < count {
        return Err(EncodingError);
    }
    let mut encoded = [0_u8; MAX_SEND_REQUEST_BYTES];
    encoded[0..2].copy_from_slice(&source_port.to_le_bytes());
    encoded[2..6].copy_from_slice(&destination);
    encoded[6..8].copy_from_slice(&destination_port.to_le_bytes());
    encoded[8..count].copy_from_slice(payload);
    output[..count].copy_from_slice(&encoded[..count]);
    Ok(count)
}

/// Parse one exact send request.
///
/// # Errors
///
/// Rejects truncated, oversized, or zero-destination-port records.
pub fn decode_send_request(bytes: &[u8]) -> Result<SendRequest<'_>, EncodingError> {
    if bytes.len() < SEND_HEADER_BYTES || bytes.len() > MAX_SEND_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let destination_port = read_u16(bytes, 6)?;
    if destination_port == 0 {
        return Err(EncodingError);
    }
    Ok(SendRequest {
        source_port: read_u16(bytes, 0)?,
        destination: [bytes[2], bytes[3], bytes[4], bytes[5]],
        destination_port,
        payload: &bytes[SEND_HEADER_BYTES..],
    })
}

/// Encode the exact selected source-port reply.
///
/// # Errors
///
/// Rejects port zero.
pub fn encode_send_reply(source_port: u16) -> Result<[u8; 2], EncodingError> {
    if source_port == 0 {
        return Err(EncodingError);
    }
    Ok(source_port.to_le_bytes())
}

/// Decode the exact selected source-port reply.
///
/// # Errors
///
/// Rejects any length other than two bytes or port zero.
pub fn decode_send_reply(bytes: &[u8]) -> Result<u16, EncodingError> {
    let port = read_u16(bytes, 0)?;
    if bytes.len() != 2 || port == 0 {
        return Err(EncodingError);
    }
    Ok(port)
}

/// Encode one exact receive request.
///
/// # Errors
///
/// Rejects port zero.
pub fn encode_receive_request(local_port: u16) -> Result<[u8; 2], EncodingError> {
    if local_port == 0 {
        return Err(EncodingError);
    }
    Ok(local_port.to_le_bytes())
}

/// Decode one exact receive request.
///
/// # Errors
///
/// Rejects any length other than two bytes or port zero.
pub fn decode_receive_request(bytes: &[u8]) -> Result<u16, EncodingError> {
    let port = read_u16(bytes, 0)?;
    if bytes.len() != 2 || port == 0 {
        return Err(EncodingError);
    }
    Ok(port)
}

/// Encode one canonical received datagram into caller-owned storage.
///
/// # Errors
///
/// Rejects port zero, oversize payloads, overflow, or insufficient space.
pub fn encode_receive_reply(
    source: [u8; 4],
    source_port: u16,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    let count = RECEIVE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(EncodingError)?;
    if source_port == 0 || payload.len() > MAX_PAYLOAD_BYTES || output.len() < count {
        return Err(EncodingError);
    }
    let mut encoded = [0_u8; MAX_RECEIVE_REPLY_BYTES];
    encoded[0..4].copy_from_slice(&source);
    encoded[4..6].copy_from_slice(&source_port.to_le_bytes());
    encoded[6..count].copy_from_slice(payload);
    output[..count].copy_from_slice(&encoded[..count]);
    Ok(count)
}

/// Parse one exact received datagram reply.
///
/// # Errors
///
/// Rejects truncated, oversized, or zero-source-port records.
pub fn decode_receive_reply(bytes: &[u8]) -> Result<ReceivedDatagram<'_>, EncodingError> {
    if bytes.len() < RECEIVE_HEADER_BYTES || bytes.len() > MAX_RECEIVE_REPLY_BYTES {
        return Err(EncodingError);
    }
    let source_port = read_u16(bytes, 4)?;
    if source_port == 0 {
        return Err(EncodingError);
    }
    Ok(ReceivedDatagram {
        source: [bytes[0], bytes[1], bytes[2], bytes[3]],
        source_port,
        payload: &bytes[RECEIVE_HEADER_BYTES..],
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
    let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

#[cfg(test)]
mod tests {
    use crate::datagram;

    #[test]
    fn datagram_records_round_trip_and_reject_noncanonical_ports() {
        let mut request = [0_u8; datagram::MAX_SEND_REQUEST_BYTES];
        let count = datagram::encode_send_request(
            Some(40_000),
            [10, 0, 2, 2],
            49_152,
            b"hello",
            &mut request,
        )
        .unwrap_or_else(|_| std::process::abort());
        let decoded = datagram::decode_send_request(&request[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.source_port, 40_000);
        assert_eq!(decoded.destination, [10, 0, 2, 2]);
        assert_eq!(decoded.destination_port, 49_152);
        assert_eq!(decoded.payload, b"hello");

        let mut reply = [0_u8; datagram::MAX_RECEIVE_REPLY_BYTES];
        let count = datagram::encode_receive_reply([192, 0, 2, 1], 7, b"reply", &mut reply)
            .unwrap_or_else(|_| std::process::abort());
        let decoded = datagram::decode_receive_reply(&reply[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.source, [192, 0, 2, 1]);
        assert_eq!(decoded.source_port, 7);
        assert_eq!(decoded.payload, b"reply");
        assert!(datagram::encode_receive_request(0).is_err());
        assert!(datagram::decode_send_reply(&[0, 0]).is_err());
    }
}

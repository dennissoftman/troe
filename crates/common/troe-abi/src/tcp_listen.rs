//! One bounded inbound IPv4/TCP listening endpoint and its accepted streams.
//!
//! This protocol is deliberately not a widened `tcp_connect`. A connect handle
//! owns exactly one stream and therefore names none, while a listener owns
//! several at once, so every stream operation here carries the connection
//! identifier the accept reply assigned. There is still no descriptor, address
//! family, protocol, socket option, or generic socket argument.

use super::MAX_SERVICE_PAYLOAD_BYTES;

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Claim the handle's one local port and its bounded backlog.
pub const LISTEN: u16 = 1;
/// Wait for and return one accepted connection and its peer.
pub const ACCEPT: u16 = 2;
/// Write and acknowledge one bounded chunk on one accepted connection.
pub const WRITE: u16 = 3;
/// Wait for and return one bounded chunk; zero bytes is orderly end of stream.
pub const READ: u16 = 4;
/// Gracefully close one accepted connection.
pub const CLOSE: u16 = 5;
/// Exact listen request bytes, including one reserved zero byte.
pub const LISTEN_REQUEST_BYTES: usize = 4;
/// Exact bound-port listen reply bytes.
pub const LISTEN_REPLY_BYTES: usize = 2;
/// Exact accept reply bytes: connection, peer address, and peer port.
pub const ACCEPT_REPLY_BYTES: usize = 8;
/// Fixed bytes preceding the payload in a write request.
pub const WRITE_HEADER_BYTES: usize = 2;
/// Largest write admitted as one TCP segment.
pub const MAX_WRITE_BYTES: usize = 1_460;
/// Largest complete write request.
pub const MAX_WRITE_REQUEST_BYTES: usize = WRITE_HEADER_BYTES + MAX_WRITE_BYTES;
/// Exact read request bytes: connection and requested count.
pub const READ_REQUEST_BYTES: usize = 4;
/// Largest read returned through the generic KEX service call gate.
pub const MAX_READ_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES;
/// Exact close request bytes.
pub const CLOSE_REQUEST_BYTES: usize = 2;
/// Largest backlog a listen request may name.
pub const MAX_BACKLOG: u8 = 4;

/// Invalid TCP listen request or reply encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// One validated local endpoint claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenRequest {
    /// Requested local TCP port; zero requests an ephemeral port.
    pub port: u16,
    /// Nonzero passive-open queue depth.
    pub backlog: u8,
}

/// One accepted connection and the peer that opened it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptReply {
    /// Nonzero identifier naming this connection for the handle's lifetime.
    pub connection: u16,
    /// Peer IPv4 address in network display order.
    pub peer: [u8; 4],
    /// Nonzero peer TCP port.
    pub peer_port: u16,
}

/// One validated write target and its payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteRequest<'a> {
    /// Nonzero accepted-connection identifier.
    pub connection: u16,
    /// Exact at-most-one-segment payload.
    pub payload: &'a [u8],
}

/// One validated read target and byte count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    /// Nonzero accepted-connection identifier.
    pub connection: u16,
    /// Nonzero requested byte count.
    pub requested: usize,
}

/// Encode one exact local endpoint claim.
///
/// # Errors
///
/// Rejects a zero backlog and any backlog above `MAX_BACKLOG`.
pub fn encode_listen_request(
    port: u16,
    backlog: u8,
) -> Result<[u8; LISTEN_REQUEST_BYTES], EncodingError> {
    if backlog == 0 || backlog > MAX_BACKLOG {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; LISTEN_REQUEST_BYTES];
    bytes[..2].copy_from_slice(&port.to_le_bytes());
    bytes[2] = backlog;
    Ok(bytes)
}

/// Decode one exact local endpoint claim.
///
/// # Errors
///
/// Rejects every truncation/trailing byte, a nonzero reserved field, a zero
/// backlog, and any backlog above `MAX_BACKLOG`.
pub fn decode_listen_request(bytes: &[u8]) -> Result<ListenRequest, EncodingError> {
    if bytes.len() != LISTEN_REQUEST_BYTES || bytes[3] != 0 {
        return Err(EncodingError);
    }
    let port = u16::from_le_bytes([bytes[0], bytes[1]]);
    let backlog = bytes[2];
    if backlog == 0 || backlog > MAX_BACKLOG {
        return Err(EncodingError);
    }
    Ok(ListenRequest { port, backlog })
}

/// Encode the exact bound local port.
///
/// # Errors
///
/// Rejects port zero, because an ephemeral request resolves before reply.
pub fn encode_listen_reply(port: u16) -> Result<[u8; LISTEN_REPLY_BYTES], EncodingError> {
    if port == 0 {
        return Err(EncodingError);
    }
    Ok(port.to_le_bytes())
}

/// Decode the exact bound local port.
///
/// # Errors
///
/// Rejects every length other than two bytes and port zero.
pub fn decode_listen_reply(bytes: &[u8]) -> Result<u16, EncodingError> {
    if bytes.len() != LISTEN_REPLY_BYTES {
        return Err(EncodingError);
    }
    let port = u16::from_le_bytes([bytes[0], bytes[1]]);
    if port == 0 {
        return Err(EncodingError);
    }
    Ok(port)
}

/// Encode one exact accepted connection and peer.
///
/// # Errors
///
/// Rejects a zero connection identifier, a zero peer port, and a peer address
/// no unicast connection can originate from.
pub fn encode_accept_reply(
    connection: u16,
    peer: [u8; 4],
    peer_port: u16,
) -> Result<[u8; ACCEPT_REPLY_BYTES], EncodingError> {
    if connection == 0 || peer_port == 0 || !valid_peer(peer) {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; ACCEPT_REPLY_BYTES];
    bytes[..2].copy_from_slice(&connection.to_le_bytes());
    bytes[2..6].copy_from_slice(&peer);
    bytes[6..8].copy_from_slice(&peer_port.to_le_bytes());
    Ok(bytes)
}

/// Decode one exact accepted connection and peer.
///
/// # Errors
///
/// Rejects every truncation/trailing byte, a zero connection identifier, a
/// zero peer port, and a non-unicast peer address.
pub fn decode_accept_reply(bytes: &[u8]) -> Result<AcceptReply, EncodingError> {
    if bytes.len() != ACCEPT_REPLY_BYTES {
        return Err(EncodingError);
    }
    let connection = u16::from_le_bytes([bytes[0], bytes[1]]);
    let peer = [bytes[2], bytes[3], bytes[4], bytes[5]];
    let peer_port = u16::from_le_bytes([bytes[6], bytes[7]]);
    if connection == 0 || peer_port == 0 || !valid_peer(peer) {
        return Err(EncodingError);
    }
    Ok(AcceptReply {
        connection,
        peer,
        peer_port,
    })
}

/// Encode one write request into caller-owned storage.
///
/// # Errors
///
/// Rejects a zero connection identifier, an empty or multi-segment payload,
/// overflow, and insufficient destination storage. No destination byte is
/// modified on failure.
pub fn encode_write_request(
    connection: u16,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    let count = WRITE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(EncodingError)?;
    if connection == 0
        || payload.is_empty()
        || payload.len() > MAX_WRITE_BYTES
        || output.len() < count
    {
        return Err(EncodingError);
    }
    let mut encoded = [0_u8; MAX_WRITE_REQUEST_BYTES];
    encoded[..2].copy_from_slice(&connection.to_le_bytes());
    encoded[WRITE_HEADER_BYTES..count].copy_from_slice(payload);
    output
        .get_mut(..count)
        .ok_or(EncodingError)?
        .copy_from_slice(encoded.get(..count).ok_or(EncodingError)?);
    Ok(count)
}

/// Decode one write request, borrowing its payload.
///
/// # Errors
///
/// Rejects truncation, a zero connection identifier, and an empty or
/// multi-segment payload.
pub fn decode_write_request(bytes: &[u8]) -> Result<WriteRequest<'_>, EncodingError> {
    if bytes.len() <= WRITE_HEADER_BYTES || bytes.len() > MAX_WRITE_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let connection = u16::from_le_bytes([bytes[0], bytes[1]]);
    if connection == 0 {
        return Err(EncodingError);
    }
    Ok(WriteRequest {
        connection,
        payload: bytes.get(WRITE_HEADER_BYTES..).ok_or(EncodingError)?,
    })
}

/// Encode one exact bounded read request.
///
/// # Errors
///
/// Rejects a zero connection identifier, zero, and values above the KEX
/// reply-payload ceiling.
pub fn encode_read_request(
    connection: u16,
    requested: usize,
) -> Result<[u8; READ_REQUEST_BYTES], EncodingError> {
    if connection == 0 || requested == 0 || requested > MAX_READ_BYTES {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; READ_REQUEST_BYTES];
    bytes[..2].copy_from_slice(&connection.to_le_bytes());
    bytes[2..4].copy_from_slice(
        &u16::try_from(requested)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    Ok(bytes)
}

/// Decode one exact bounded read request.
///
/// # Errors
///
/// Rejects every length other than four bytes, a zero connection identifier,
/// zero, and values above the KEX reply-payload ceiling.
pub fn decode_read_request(bytes: &[u8]) -> Result<ReadRequest, EncodingError> {
    if bytes.len() != READ_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let connection = u16::from_le_bytes([bytes[0], bytes[1]]);
    let requested = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    if connection == 0 || requested == 0 || requested > MAX_READ_BYTES {
        return Err(EncodingError);
    }
    Ok(ReadRequest {
        connection,
        requested,
    })
}

/// Encode one exact close request.
///
/// # Errors
///
/// Rejects a zero connection identifier.
pub fn encode_close_request(connection: u16) -> Result<[u8; CLOSE_REQUEST_BYTES], EncodingError> {
    if connection == 0 {
        return Err(EncodingError);
    }
    Ok(connection.to_le_bytes())
}

/// Decode one exact close request.
///
/// # Errors
///
/// Rejects every length other than two bytes and a zero connection identifier.
pub fn decode_close_request(bytes: &[u8]) -> Result<u16, EncodingError> {
    if bytes.len() != CLOSE_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let connection = u16::from_le_bytes([bytes[0], bytes[1]]);
    if connection == 0 {
        return Err(EncodingError);
    }
    Ok(connection)
}

/// Whether an address can be the unicast source of an inbound connection.
///
/// This is the same class filter `tcp_connect` applies to a destination, minus
/// the loopback exclusion's direction: no unspecified, broadcast, multicast, or
/// class-E address, and no loopback, because this machine has no loopback route.
fn valid_peer(address: [u8; 4]) -> bool {
    address != [0; 4]
        && address != [255; 4]
        && address[0] != 0
        && address[0] != 127
        && address[0] < 224
}

#[cfg(test)]
mod tests {
    use crate::tcp_listen;

    #[test]
    fn listen_records_are_exact_and_bounded() {
        let encoded = tcp_listen::encode_listen_request(8_080, tcp_listen::MAX_BACKLOG)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            tcp_listen::decode_listen_request(&encoded),
            Ok(tcp_listen::ListenRequest {
                port: 8_080,
                backlog: tcp_listen::MAX_BACKLOG,
            })
        );
        for end in 0..encoded.len() {
            assert!(tcp_listen::decode_listen_request(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(tcp_listen::decode_listen_request(&trailing).is_err());
        let mut reserved = encoded;
        reserved[3] = 1;
        assert!(tcp_listen::decode_listen_request(&reserved).is_err());

        // Zero requests an ephemeral port, so it is valid input; zero backlog
        // and an above-ceiling backlog are not.
        assert_eq!(
            tcp_listen::encode_listen_request(0, 1)
                .and_then(|bytes| tcp_listen::decode_listen_request(&bytes))
                .map(|request| request.port),
            Ok(0)
        );
        assert!(tcp_listen::encode_listen_request(8_080, 0).is_err());
        assert!(tcp_listen::encode_listen_request(8_080, tcp_listen::MAX_BACKLOG + 1).is_err());

        // The reply always names a resolved nonzero port.
        assert_eq!(
            tcp_listen::decode_listen_reply(
                &tcp_listen::encode_listen_reply(8_080).unwrap_or_else(|_| std::process::abort())
            ),
            Ok(8_080)
        );
        assert!(tcp_listen::encode_listen_reply(0).is_err());
        assert!(tcp_listen::decode_listen_reply(&[0, 0]).is_err());
        assert!(tcp_listen::decode_listen_reply(&[1]).is_err());
    }

    #[test]
    fn accept_replies_name_one_connection_and_one_unicast_peer() {
        let encoded = tcp_listen::encode_accept_reply(1, [10, 0, 2, 2], 49_152)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            tcp_listen::decode_accept_reply(&encoded),
            Ok(tcp_listen::AcceptReply {
                connection: 1,
                peer: [10, 0, 2, 2],
                peer_port: 49_152,
            })
        );
        for end in 0..encoded.len() {
            assert!(tcp_listen::decode_accept_reply(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(tcp_listen::decode_accept_reply(&trailing).is_err());

        assert!(tcp_listen::encode_accept_reply(0, [10, 0, 2, 2], 49_152).is_err());
        assert!(tcp_listen::encode_accept_reply(1, [10, 0, 2, 2], 0).is_err());
        for peer in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
            assert!(tcp_listen::encode_accept_reply(1, peer, 49_152).is_err());
        }
    }

    #[test]
    fn stream_records_always_name_a_nonzero_connection() {
        let mut storage = [0_u8; tcp_listen::MAX_WRITE_REQUEST_BYTES];
        let count = tcp_listen::encode_write_request(7, b"HTTP/1.1 200 OK", &mut storage)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            tcp_listen::decode_write_request(&storage[..count]),
            Ok(tcp_listen::WriteRequest {
                connection: 7,
                payload: b"HTTP/1.1 200 OK",
            })
        );
        assert!(tcp_listen::encode_write_request(0, b"body", &mut storage).is_err());
        assert!(tcp_listen::encode_write_request(7, b"", &mut storage).is_err());
        let oversize = [0_u8; tcp_listen::MAX_WRITE_BYTES + 1];
        assert!(tcp_listen::encode_write_request(7, &oversize, &mut storage).is_err());
        assert!(tcp_listen::encode_write_request(7, b"body", &mut storage[..4]).is_err());
        // A write with a header but no payload is not an empty write, it is a
        // truncated one.
        assert!(tcp_listen::decode_write_request(&[7, 0]).is_err());
        assert!(tcp_listen::decode_write_request(&[0, 0, b'x']).is_err());

        let read = tcp_listen::encode_read_request(7, tcp_listen::MAX_READ_BYTES)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            tcp_listen::decode_read_request(&read),
            Ok(tcp_listen::ReadRequest {
                connection: 7,
                requested: tcp_listen::MAX_READ_BYTES,
            })
        );
        for end in 0..read.len() {
            assert!(tcp_listen::decode_read_request(&read[..end]).is_err());
        }
        assert!(tcp_listen::encode_read_request(0, 16).is_err());
        assert!(tcp_listen::encode_read_request(7, 0).is_err());
        assert!(tcp_listen::encode_read_request(7, tcp_listen::MAX_READ_BYTES + 1).is_err());
        assert!(tcp_listen::decode_read_request(&[7, 0, 0, 0]).is_err());

        assert_eq!(
            tcp_listen::decode_close_request(
                &tcp_listen::encode_close_request(7).unwrap_or_else(|_| std::process::abort())
            ),
            Ok(7)
        );
        assert!(tcp_listen::encode_close_request(0).is_err());
        assert!(tcp_listen::decode_close_request(&[0, 0]).is_err());
        assert!(tcp_listen::decode_close_request(&[7]).is_err());
    }
}

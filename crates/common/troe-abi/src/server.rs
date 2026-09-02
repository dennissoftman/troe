//! Copied request/reply transport for one isolated user service.

use super::{MAX_MESSAGE_BYTES, MAX_SERVICE_PAYLOAD_BYTES, reply};

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Receive the one copied request currently assigned to this server.
pub const RECEIVE: u16 = 1;
/// Complete one received request exactly once.
pub const REPLY: u16 = 2;
/// Fixed bytes before a received request payload.
pub const RECEIVE_HEADER_BYTES: usize = 24;
/// Fixed bytes before a server reply payload.
pub const REPLY_HEADER_BYTES: usize = 16;
/// Largest copied request that can be returned by `RECEIVE`.
pub const MAX_RECEIVE_REQUEST_BYTES: usize = MAX_MESSAGE_BYTES - RECEIVE_HEADER_BYTES;
/// Largest copied reply that can be supplied to `REPLY`.
pub const MAX_REPLY_PAYLOAD_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES - REPLY_HEADER_BYTES;

/// Invalid, excessive, or noncanonical server-transport bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Borrowed request assigned to one isolated server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedRequest<'a> {
    token: u64,
    interface: u32,
    opcode: u16,
    reply_capacity: u16,
    payload: &'a [u8],
}

impl<'a> ReceivedRequest<'a> {
    /// Opaque generation-checked token required by `REPLY`.
    #[must_use]
    pub const fn token(self) -> u64 {
        self.token
    }

    /// Client-visible service interface identifier.
    #[must_use]
    pub const fn interface(self) -> u32 {
        self.interface
    }

    /// Client-visible service operation.
    #[must_use]
    pub const fn opcode(self) -> u16 {
        self.opcode
    }

    /// Maximum copied reply bytes accepted by the client.
    #[must_use]
    pub const fn reply_capacity(self) -> usize {
        self.reply_capacity as usize
    }

    /// Immutable copied client request bytes.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// Borrowed completion supplied by an isolated server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyRequest<'a> {
    token: u64,
    status: u32,
    payload: &'a [u8],
}

impl<'a> ReplyRequest<'a> {
    /// Opaque generation-checked request token.
    #[must_use]
    pub const fn token(self) -> u64 {
        self.token
    }

    /// Stable service reply status returned to the client.
    #[must_use]
    pub const fn status(self) -> u32 {
        self.status
    }

    /// Immutable copied reply bytes.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// Encode one request for delivery to an isolated server.
///
/// # Errors
///
/// Rejects reserved scalar values, ABI bounds, or insufficient storage
/// without modifying `destination`.
pub fn encode_received_request(
    token: u64,
    interface: u32,
    opcode: u16,
    reply_capacity: usize,
    payload: &[u8],
    destination: &mut [u8],
) -> Result<usize, EncodingError> {
    let encoded_bytes = RECEIVE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(EncodingError)?;
    if token == 0
        || interface == 0
        || opcode == 0
        || payload.len() > MAX_RECEIVE_REQUEST_BYTES
        || reply_capacity > MAX_MESSAGE_BYTES
        || destination.len() < encoded_bytes
    {
        return Err(EncodingError);
    }
    let request_bytes = u16::try_from(payload.len()).map_err(|_| EncodingError)?;
    let reply_capacity = u16::try_from(reply_capacity).map_err(|_| EncodingError)?;
    destination[..encoded_bytes].fill(0);
    destination[0..8].copy_from_slice(&token.to_le_bytes());
    destination[8..12].copy_from_slice(&interface.to_le_bytes());
    destination[12..14].copy_from_slice(&opcode.to_le_bytes());
    destination[14..16].copy_from_slice(&request_bytes.to_le_bytes());
    destination[16..18].copy_from_slice(&reply_capacity.to_le_bytes());
    destination[RECEIVE_HEADER_BYTES..encoded_bytes].copy_from_slice(payload);
    Ok(encoded_bytes)
}

/// Decode one exact canonical request delivered to a server.
///
/// # Errors
///
/// Rejects every truncation, trailing byte, reserved field, or invalid
/// scalar value.
pub fn decode_received_request(bytes: &[u8]) -> Result<ReceivedRequest<'_>, EncodingError> {
    if bytes.len() < RECEIVE_HEADER_BYTES {
        return Err(EncodingError);
    }
    let token = read_u64(bytes, 0)?;
    let interface = read_u32(bytes, 8)?;
    let opcode = read_u16(bytes, 12)?;
    let request_bytes = usize::from(read_u16(bytes, 14)?);
    let reply_capacity = read_u16(bytes, 16)?;
    if token == 0
        || interface == 0
        || opcode == 0
        || usize::from(reply_capacity) > MAX_MESSAGE_BYTES
        || request_bytes > MAX_RECEIVE_REQUEST_BYTES
        || bytes.len() != RECEIVE_HEADER_BYTES + request_bytes
        || bytes[18..RECEIVE_HEADER_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(EncodingError);
    }
    Ok(ReceivedRequest {
        token,
        interface,
        opcode,
        reply_capacity,
        payload: &bytes[RECEIVE_HEADER_BYTES..],
    })
}

/// Encode one completion supplied by an isolated server.
///
/// # Errors
///
/// Rejects a reserved token, unknown status, ABI bounds, or insufficient
/// storage without modifying `destination`.
pub fn encode_reply_request(
    token: u64,
    status: u32,
    payload: &[u8],
    destination: &mut [u8],
) -> Result<usize, EncodingError> {
    let encoded_bytes = REPLY_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(EncodingError)?;
    if token == 0
        || !reply::is_known(status)
        || payload.len() > MAX_REPLY_PAYLOAD_BYTES
        || destination.len() < encoded_bytes
    {
        return Err(EncodingError);
    }
    let payload_bytes = u16::try_from(payload.len()).map_err(|_| EncodingError)?;
    destination[..encoded_bytes].fill(0);
    destination[0..8].copy_from_slice(&token.to_le_bytes());
    destination[8..12].copy_from_slice(&status.to_le_bytes());
    destination[12..14].copy_from_slice(&payload_bytes.to_le_bytes());
    destination[REPLY_HEADER_BYTES..encoded_bytes].copy_from_slice(payload);
    Ok(encoded_bytes)
}

/// Decode one exact canonical completion supplied by a server.
///
/// # Errors
///
/// Rejects every truncation, trailing byte, reserved field, unknown
/// status, or excessive payload.
pub fn decode_reply_request(bytes: &[u8]) -> Result<ReplyRequest<'_>, EncodingError> {
    if bytes.len() < REPLY_HEADER_BYTES {
        return Err(EncodingError);
    }
    let token = read_u64(bytes, 0)?;
    let status = read_u32(bytes, 8)?;
    let payload_bytes = usize::from(read_u16(bytes, 12)?);
    if token == 0
        || !reply::is_known(status)
        || payload_bytes > MAX_REPLY_PAYLOAD_BYTES
        || bytes.len() != REPLY_HEADER_BYTES + payload_bytes
        || bytes[14..REPLY_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(EncodingError);
    }
    Ok(ReplyRequest {
        token,
        status,
        payload: &bytes[REPLY_HEADER_BYTES..],
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
    let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EncodingError> {
    let raw = bytes.get(offset..offset + 4).ok_or(EncodingError)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EncodingError> {
    let raw = bytes.get(offset..offset + 8).ok_or(EncodingError)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg(test)]
mod tests {
    use crate::{MAX_MESSAGE_BYTES, diagnostics, interface, reply, server};

    #[test]
    fn isolated_server_transport_is_exact_bounded_and_canonical() {
        let mut receive = [0_u8; MAX_MESSAGE_BYTES];
        let receive_bytes = server::encode_received_request(
            0x0000_0007_0000_0003,
            interface::DIAGNOSTICS,
            diagnostics::GET_SNAPSHOT,
            diagnostics::SNAPSHOT_BYTES,
            b"copied request",
            &mut receive,
        )
        .unwrap_or_else(|_| std::process::abort());
        let decoded = server::decode_received_request(&receive[..receive_bytes])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.token(), 0x0000_0007_0000_0003);
        assert_eq!(decoded.interface(), interface::DIAGNOSTICS);
        assert_eq!(decoded.opcode(), diagnostics::GET_SNAPSHOT);
        assert_eq!(decoded.reply_capacity(), diagnostics::SNAPSHOT_BYTES);
        assert_eq!(decoded.payload(), b"copied request");
        for end in 0..receive_bytes {
            assert!(server::decode_received_request(&receive[..end]).is_err());
        }
        let mut noncanonical = receive[..receive_bytes].to_vec();
        noncanonical[18] = 1;
        assert!(server::decode_received_request(&noncanonical).is_err());

        let mut completion = [0_u8; super::MAX_SERVICE_PAYLOAD_BYTES];
        let completion_bytes = server::encode_reply_request(
            decoded.token(),
            reply::SUCCESS,
            b"copied reply",
            &mut completion,
        )
        .unwrap_or_else(|_| std::process::abort());
        let completion = server::decode_reply_request(&completion[..completion_bytes])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(completion.token(), decoded.token());
        assert_eq!(completion.status(), reply::SUCCESS);
        assert_eq!(completion.payload(), b"copied reply");

        let mut unchanged = [0xa5_u8; 8];
        assert!(server::encode_received_request(0, 1, 1, 0, &[], &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; 8]);
        assert!(server::encode_reply_request(1, u32::MAX, &[], &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; 8]);
    }
}

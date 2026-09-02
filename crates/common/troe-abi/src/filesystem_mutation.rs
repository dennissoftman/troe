//! Streaming filesystem-mutation protocol.

use core::str;

use super::{MAX_SERVICE_PAYLOAD_BYTES, filesystem};

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 5;
/// Truncate or create one file and begin a sequential streamed replacement.
pub const BEGIN_REPLACE: u16 = 1;
/// Append one sequential chunk to the pending replacement.
pub const APPEND: u16 = 2;
/// Flush and durably order the pending streamed replacement.
pub const COMMIT_REPLACE: u16 = 3;
/// End the replacement without flushing its final buffered chunk.
pub const ABORT_REPLACE: u16 = 4;
/// Atomically remove one regular file or symbolic link.
pub const REMOVE: u16 = 5;
/// Create one symbolic link with a provider-owned target.
pub const CREATE_SYMLINK: u16 = 6;
/// Create one same-provider hard link to an existing regular file.
pub const CREATE_HARD_LINK: u16 = 7;
/// Create one empty directory without replacing an existing entry.
pub const CREATE_DIRECTORY: u16 = 8;
/// Select the aggregation size for one pending streamed replacement.
pub const SET_CHUNK_SIZE: u16 = 9;
/// Atomically rename one same-provider object.
pub const RENAME: u16 = 10;
/// Atomically remove one empty directory.
pub const REMOVE_DIRECTORY: u16 = 11;
/// Preserve one existing regular file and begin appending at its exact end.
pub const BEGIN_APPEND: u16 = 12;
/// Read already-staged bytes back from one pending streamed replacement.
pub const READ_REPLACEMENT: u16 = 13;
/// Set one object's modification time, or stamp it from the wall clock.
pub const SET_MODIFIED_TIME: u16 = 14;
/// Fixed bytes of one set-modified-time request ahead of its path.
pub const SET_MODIFIED_TIME_HEADER_BYTES: usize = 16;
/// Fixed bytes preceding an append payload.
pub const APPEND_HEADER_BYTES: usize = 12;
/// Maximum bytes carried by one append call.
pub const MAX_APPEND_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES - APPEND_HEADER_BYTES;
/// Exact replacement-token reply/request bytes.
pub const TOKEN_BYTES: usize = 4;
/// Exact begin-append reply bytes: token followed by initial offset.
pub const BEGIN_APPEND_REPLY_BYTES: usize = 12;
/// Exact replacement-token plus chunk-size request bytes.
pub const CHUNK_SIZE_REQUEST_BYTES: usize = 8;
/// Exact staged-read request bytes: token, offset, then requested length.
pub const READ_REQUEST_BYTES: usize = 16;
/// Maximum bytes returned by one staged-read call.
pub const MAX_READ_BYTES: usize = MAX_SERVICE_PAYLOAD_BYTES;
/// Fixed bytes preceding the two strings in a link request.
pub const LINK_REQUEST_HEADER_BYTES: usize = 4;
/// Largest canonical two-string link request.
pub const MAX_LINK_REQUEST_BYTES: usize =
    LINK_REQUEST_HEADER_BYTES + 2 * filesystem::MAX_PATH_BYTES;
/// Largest canonical two-path request.
pub const MAX_TWO_PATH_REQUEST_BYTES: usize = MAX_LINK_REQUEST_BYTES;

/// Invalid mutation request or reply encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Borrowed validated append request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendRequest<'a> {
    /// Opaque active replacement token.
    pub token: u32,
    /// Required sequential byte offset.
    pub offset: u64,
    /// Nonempty bytes appended at `offset`.
    pub bytes: &'a [u8],
}

/// Borrowed validated symbolic- or hard-link request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkRequest<'a> {
    /// Symbolic target or existing regular-file path.
    pub target: &'a str,
    /// New directory-entry path.
    pub link_path: &'a str,
}

/// Borrowed validated request carrying two filesystem paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoPathRequest<'a> {
    /// Existing source path.
    pub source: &'a str,
    /// New destination path.
    pub destination: &'a str,
}

/// Encode a begin-replace or remove path request.
///
/// # Errors
///
/// Rejects empty, excessive, invalid, or short destinations atomically.
pub fn encode_path_request(path: &str, output: &mut [u8]) -> Result<usize, EncodingError> {
    filesystem::encode_path_request(path, output).map_err(|_| EncodingError)
}

/// Decode a begin-replace or remove path request.
///
/// # Errors
///
/// Rejects noncanonical filesystem paths.
pub fn decode_path_request(bytes: &[u8]) -> Result<&str, EncodingError> {
    filesystem::decode_path_request(bytes).map_err(|_| EncodingError)
}

/// Encode one set-modified-time request.
///
/// The instant is carried as a present flag plus a value so an absent time
/// asks for the wall clock rather than encoding 1970 as a sentinel.
///
/// # Errors
///
/// Rejects noncanonical paths and insufficient output.
pub fn encode_set_modified_time_request(
    path: &str,
    unix_seconds: Option<u64>,
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    let count = SET_MODIFIED_TIME_HEADER_BYTES
        .checked_add(path.len())
        .ok_or(EncodingError)?;
    if output.len() < count {
        return Err(EncodingError);
    }
    let mut header = [0_u8; SET_MODIFIED_TIME_HEADER_BYTES];
    header[0] = u8::from(unix_seconds.is_some());
    header[8..16].copy_from_slice(&unix_seconds.unwrap_or(0).to_le_bytes());
    let mut encoded = [0_u8; filesystem::MAX_PATH_BYTES];
    let path_count =
        filesystem::encode_path_request(path, &mut encoded).map_err(|_| EncodingError)?;
    let total = SET_MODIFIED_TIME_HEADER_BYTES
        .checked_add(path_count)
        .ok_or(EncodingError)?;
    if output.len() < total {
        return Err(EncodingError);
    }
    output[..SET_MODIFIED_TIME_HEADER_BYTES].copy_from_slice(&header);
    output[SET_MODIFIED_TIME_HEADER_BYTES..total]
        .copy_from_slice(encoded.get(..path_count).ok_or(EncodingError)?);
    Ok(total)
}

/// Decode one set-modified-time request.
///
/// # Errors
///
/// Rejects short requests, padding, a flag outside its closed domain, a
/// value without its flag, and noncanonical paths.
pub fn decode_set_modified_time_request(
    bytes: &[u8],
) -> Result<(&str, Option<u64>), EncodingError> {
    let header = bytes
        .get(..SET_MODIFIED_TIME_HEADER_BYTES)
        .ok_or(EncodingError)?;
    if header[1..8].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    let seconds = u64::from_le_bytes(
        header
            .get(8..16)
            .ok_or(EncodingError)?
            .try_into()
            .map_err(|_| EncodingError)?,
    );
    let unix_seconds = match header[0] {
        0 if seconds == 0 => None,
        1 => Some(seconds),
        _ => return Err(EncodingError),
    };
    let path = filesystem::decode_path_request(
        bytes
            .get(SET_MODIFIED_TIME_HEADER_BYTES..)
            .ok_or(EncodingError)?,
    )
    .map_err(|_| EncodingError)?;
    Ok((path, unix_seconds))
}

/// Encode one symbolic- or hard-link request.
///
/// # Errors
///
/// Rejects empty, excessive, NUL-containing strings or insufficient
/// output without modifying it.
pub fn encode_link_request(
    target: &str,
    link_path: &str,
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    validate_link_string(target)?;
    validate_link_string(link_path)?;
    let count = LINK_REQUEST_HEADER_BYTES
        .checked_add(target.len())
        .and_then(|count| count.checked_add(link_path.len()))
        .ok_or(EncodingError)?;
    if output.len() < count {
        return Err(EncodingError);
    }
    let target_bytes = u16::try_from(target.len()).map_err(|_| EncodingError)?;
    let link_bytes = u16::try_from(link_path.len()).map_err(|_| EncodingError)?;
    let mut encoded = [0_u8; MAX_LINK_REQUEST_BYTES];
    encoded[..2].copy_from_slice(&target_bytes.to_le_bytes());
    encoded[2..4].copy_from_slice(&link_bytes.to_le_bytes());
    let target_end = LINK_REQUEST_HEADER_BYTES + target.len();
    encoded[LINK_REQUEST_HEADER_BYTES..target_end].copy_from_slice(target.as_bytes());
    encoded[target_end..count].copy_from_slice(link_path.as_bytes());
    output[..count].copy_from_slice(&encoded[..count]);
    Ok(count)
}

/// Decode one exact symbolic- or hard-link request.
///
/// # Errors
///
/// Rejects malformed lengths, non-UTF-8, empty, excessive, NUL-containing,
/// or trailing bytes.
pub fn decode_link_request(bytes: &[u8]) -> Result<LinkRequest<'_>, EncodingError> {
    if bytes.len() < LINK_REQUEST_HEADER_BYTES || bytes.len() > MAX_LINK_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let target_bytes = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    let link_bytes = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    let target_end = LINK_REQUEST_HEADER_BYTES
        .checked_add(target_bytes)
        .ok_or(EncodingError)?;
    let end = target_end.checked_add(link_bytes).ok_or(EncodingError)?;
    if end != bytes.len() {
        return Err(EncodingError);
    }
    let target = str::from_utf8(
        bytes
            .get(LINK_REQUEST_HEADER_BYTES..target_end)
            .ok_or(EncodingError)?,
    )
    .map_err(|_| EncodingError)?;
    let link_path = str::from_utf8(bytes.get(target_end..end).ok_or(EncodingError)?)
        .map_err(|_| EncodingError)?;
    validate_link_string(target)?;
    validate_link_string(link_path)?;
    Ok(LinkRequest { target, link_path })
}

/// Encode one exact source/destination path pair.
///
/// # Errors
///
/// Rejects empty, excessive, NUL-containing paths or insufficient output
/// without modifying it.
pub fn encode_two_path_request(
    source: &str,
    destination: &str,
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    encode_link_request(source, destination, output)
}

/// Decode one exact source/destination path pair.
///
/// # Errors
///
/// Rejects malformed lengths, invalid UTF-8, empty, excessive,
/// NUL-containing, or trailing bytes.
pub fn decode_two_path_request(bytes: &[u8]) -> Result<TwoPathRequest<'_>, EncodingError> {
    let decoded = decode_link_request(bytes)?;
    Ok(TwoPathRequest {
        source: decoded.target,
        destination: decoded.link_path,
    })
}

/// Encode one opaque nonzero replacement token.
///
/// # Errors
///
/// Rejects token zero.
pub fn encode_token(token: u32) -> Result<[u8; TOKEN_BYTES], EncodingError> {
    if token == 0 {
        return Err(EncodingError);
    }
    Ok(token.to_le_bytes())
}

/// Decode one exact opaque replacement token.
///
/// # Errors
///
/// Rejects the wrong length or token zero.
pub fn decode_token(bytes: &[u8]) -> Result<u32, EncodingError> {
    if bytes.len() != TOKEN_BYTES {
        return Err(EncodingError);
    }
    let token = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if token == 0 {
        return Err(EncodingError);
    }
    Ok(token)
}

/// Encode one nonzero replacement token and its exact initial offset.
///
/// # Errors
///
/// Rejects token zero.
pub fn encode_begin_append_reply(
    token: u32,
    offset: u64,
) -> Result<[u8; BEGIN_APPEND_REPLY_BYTES], EncodingError> {
    if token == 0 {
        return Err(EncodingError);
    }
    let mut output = [0_u8; BEGIN_APPEND_REPLY_BYTES];
    output[..4].copy_from_slice(&token.to_le_bytes());
    output[4..].copy_from_slice(&offset.to_le_bytes());
    Ok(output)
}

/// Decode one exact begin-append token and initial offset.
///
/// # Errors
///
/// Rejects the wrong length or token zero.
pub fn decode_begin_append_reply(bytes: &[u8]) -> Result<(u32, u64), EncodingError> {
    if bytes.len() != BEGIN_APPEND_REPLY_BYTES {
        return Err(EncodingError);
    }
    let token = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| EncodingError)?);
    if token == 0 {
        return Err(EncodingError);
    }
    let offset = u64::from_le_bytes(bytes[4..].try_into().map_err(|_| EncodingError)?);
    Ok((token, offset))
}

/// Encode a token-scoped streamed-write aggregation size.
///
/// # Errors
///
/// Rejects zero tokens and sizes outside the standard stream policy.
pub fn encode_chunk_size_request(
    token: u32,
    bytes: usize,
) -> Result<[u8; CHUNK_SIZE_REQUEST_BYTES], EncodingError> {
    if token == 0 {
        return Err(EncodingError);
    }
    let size = super::stream::encode_chunk_size(bytes).map_err(|_| EncodingError)?;
    let mut output = [0_u8; CHUNK_SIZE_REQUEST_BYTES];
    output[..4].copy_from_slice(&token.to_le_bytes());
    output[4..].copy_from_slice(&size);
    Ok(output)
}

/// Decode a token-scoped streamed-write aggregation size.
///
/// # Errors
///
/// Rejects malformed tokens or out-of-policy sizes.
pub fn decode_chunk_size_request(bytes: &[u8]) -> Result<(u32, usize), EncodingError> {
    if bytes.len() != CHUNK_SIZE_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let token = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| EncodingError)?);
    if token == 0 {
        return Err(EncodingError);
    }
    let size = super::stream::decode_chunk_size(&bytes[4..]).map_err(|_| EncodingError)?;
    Ok((token, size))
}

/// Encode one nonempty sequential append request.
///
/// # Errors
///
/// Rejects zero tokens, empty/excessive chunks, or insufficient output
/// without modifying it.
pub fn encode_append_request(
    token: u32,
    offset: u64,
    bytes: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    let count = APPEND_HEADER_BYTES
        .checked_add(bytes.len())
        .ok_or(EncodingError)?;
    if token == 0 || bytes.is_empty() || bytes.len() > MAX_APPEND_BYTES || output.len() < count {
        return Err(EncodingError);
    }
    let mut encoded = [0_u8; MAX_SERVICE_PAYLOAD_BYTES];
    encoded[..4].copy_from_slice(&token.to_le_bytes());
    encoded[4..12].copy_from_slice(&offset.to_le_bytes());
    encoded[APPEND_HEADER_BYTES..count].copy_from_slice(bytes);
    output[..count].copy_from_slice(&encoded[..count]);
    Ok(count)
}

/// Decode one exact sequential append request.
///
/// # Errors
///
/// Rejects zero tokens or empty/excessive byte payloads.
pub fn decode_append_request(bytes: &[u8]) -> Result<AppendRequest<'_>, EncodingError> {
    if bytes.len() <= APPEND_HEADER_BYTES || bytes.len() > MAX_SERVICE_PAYLOAD_BYTES {
        return Err(EncodingError);
    }
    let token = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let offset = u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| EncodingError)?);
    let payload = &bytes[APPEND_HEADER_BYTES..];
    if token == 0 || payload.len() > MAX_APPEND_BYTES {
        return Err(EncodingError);
    }
    Ok(AppendRequest {
        token,
        offset,
        bytes: payload,
    })
}

/// Encode one exact staged-read request.
///
/// # Errors
///
/// Rejects zero tokens, empty or excessive lengths, and short buffers.
pub fn encode_read_request(
    token: u32,
    offset: u64,
    length: usize,
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    let Ok(requested) = u32::try_from(length) else {
        return Err(EncodingError);
    };
    if token == 0 || length == 0 || length > MAX_READ_BYTES || output.len() < READ_REQUEST_BYTES {
        return Err(EncodingError);
    }
    output[..4].copy_from_slice(&token.to_le_bytes());
    output[4..12].copy_from_slice(&offset.to_le_bytes());
    output[12..READ_REQUEST_BYTES].copy_from_slice(&requested.to_le_bytes());
    Ok(READ_REQUEST_BYTES)
}

/// Decode one exact staged-read request into token, offset, and length.
///
/// # Errors
///
/// Rejects noncanonical lengths, zero tokens, and empty or excessive reads.
pub fn decode_read_request(bytes: &[u8]) -> Result<(u32, u64, usize), EncodingError> {
    if bytes.len() != READ_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let token = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let offset = u64::from_le_bytes(bytes[4..12].try_into().map_err(|_| EncodingError)?);
    let requested = u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| EncodingError)?);
    let length = requested as usize;
    if token == 0 || length == 0 || length > MAX_READ_BYTES {
        return Err(EncodingError);
    }
    Ok((token, offset, length))
}

fn validate_link_string(value: &str) -> Result<(), EncodingError> {
    if value.is_empty() || value.len() > filesystem::MAX_PATH_BYTES || value.as_bytes().contains(&0)
    {
        return Err(EncodingError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{filesystem, filesystem_mutation, reply};

    #[test]
    #[allow(clippy::too_many_lines)]
    fn filesystem_mutation_is_sequential_streamed_and_exact() {
        assert_eq!(filesystem_mutation::MAJOR, 1);
        assert_eq!(filesystem_mutation::MINOR, 5);

        // A set-modified-time request round-trips both an exact instant and the
        // request for the wall clock's own.
        let mut request = [0_u8;
            filesystem_mutation::SET_MODIFIED_TIME_HEADER_BYTES + filesystem::MAX_PATH_BYTES];
        for instant in [None, Some(1_788_000_000_u64)] {
            let count = filesystem_mutation::encode_set_modified_time_request(
                "/vol/root/note",
                instant,
                &mut request,
            )
            .unwrap_or_else(|_| unreachable!());
            assert_eq!(
                filesystem_mutation::decode_set_modified_time_request(&request[..count]),
                Ok(("/vol/root/note", instant))
            );
        }
        let count = filesystem_mutation::encode_set_modified_time_request(
            "/vol/root/note",
            Some(7),
            &mut request,
        )
        .unwrap_or_else(|_| unreachable!());
        // A value without its flag, and a flag outside its closed domain, are
        // both producers that did not encode this request.
        let mut cleared = request;
        cleared[0] = 0;
        assert!(filesystem_mutation::decode_set_modified_time_request(&cleared[..count]).is_err());
        let mut invalid = request;
        invalid[0] = 2;
        assert!(filesystem_mutation::decode_set_modified_time_request(&invalid[..count]).is_err());
        let mut padded = request;
        padded[3] = 1;
        assert!(filesystem_mutation::decode_set_modified_time_request(&padded[..count]).is_err());
        assert!(
            filesystem_mutation::decode_set_modified_time_request(
                &request[..filesystem_mutation::SET_MODIFIED_TIME_HEADER_BYTES - 1]
            )
            .is_err()
        );
        let mut read_request = [0_u8; filesystem_mutation::READ_REQUEST_BYTES];
        assert_eq!(
            filesystem_mutation::encode_read_request(3, 17, 64, &mut read_request),
            Ok(filesystem_mutation::READ_REQUEST_BYTES)
        );
        assert_eq!(
            filesystem_mutation::decode_read_request(&read_request),
            Ok((3, 17, 64))
        );
        assert!(filesystem_mutation::encode_read_request(0, 0, 1, &mut read_request).is_err());
        assert!(filesystem_mutation::encode_read_request(1, 0, 0, &mut read_request).is_err());
        assert!(
            filesystem_mutation::encode_read_request(
                1,
                0,
                filesystem_mutation::MAX_READ_BYTES + 1,
                &mut read_request
            )
            .is_err()
        );
        assert!(filesystem_mutation::decode_read_request(&read_request[..15]).is_err());
        assert_eq!(filesystem::MAJOR, 1);
        assert_eq!(filesystem::MINOR, 5);

        // An absent time is a zero flag and an all-zero value, so it never
        // collides with the epoch as a real instant. The three times are
        // independently absent, so every combination has to survive a round
        // trip rather than only all-present and all-absent.
        for modified in [None, Some(1_788_000_000_u64)] {
            for changed in [None, Some(1_788_000_001_u64)] {
                for created in [None, Some(1_788_000_002_u64)] {
                    let metadata = filesystem::Metadata {
                        kind: filesystem::NodeKind::File,
                        byte_count: 9,
                        modified_unix_seconds: modified,
                        changed_unix_seconds: changed,
                        created_unix_seconds: created,
                    };
                    let encoded = filesystem::encode_metadata_reply(metadata);
                    assert_eq!(filesystem::decode_metadata_reply(&encoded), Ok(metadata));
                }
            }
        }
        // Each time's flag is validated against its own value, so a producer
        // that sets one without the other is rejected for whichever it was.
        for flag in [1_usize, 2, 3] {
            let mut mismatched = filesystem::encode_metadata_reply(filesystem::Metadata {
                kind: filesystem::NodeKind::File,
                byte_count: 9,
                modified_unix_seconds: Some(5),
                changed_unix_seconds: Some(6),
                created_unix_seconds: Some(7),
            });
            mismatched[flag] = 0;
            assert!(filesystem::decode_metadata_reply(&mismatched).is_err());
            mismatched[flag] = 2;
            assert!(filesystem::decode_metadata_reply(&mismatched).is_err());
        }
        // The reserved span shrank to make room for the two extra flags, so a
        // stale producer writing the old six-byte reserved field is rejected.
        let mut reserved = filesystem::encode_metadata_reply(filesystem::Metadata {
            kind: filesystem::NodeKind::File,
            byte_count: 9,
            modified_unix_seconds: None,
            changed_unix_seconds: None,
            created_unix_seconds: None,
        });
        reserved[4] = 1;
        assert!(filesystem::decode_metadata_reply(&reserved).is_err());
        assert_eq!(filesystem::METADATA_REPLY_BYTES, 40);
        let token = filesystem_mutation::encode_token(7).unwrap_or_else(|_| std::process::abort());
        assert_eq!(filesystem_mutation::decode_token(&token), Ok(7));
        assert!(filesystem_mutation::decode_token(&[7, 0, 0, 0, 0]).is_err());
        assert!(filesystem_mutation::encode_token(0).is_err());
        let begin_append = filesystem_mutation::encode_begin_append_reply(9, u64::MAX - 1)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem_mutation::decode_begin_append_reply(&begin_append),
            Ok((9, u64::MAX - 1))
        );
        assert!(filesystem_mutation::decode_begin_append_reply(&begin_append[..11]).is_err());

        let mut bytes = [0_u8; super::MAX_SERVICE_PAYLOAD_BYTES];
        let large_offset = u64::from(u32::MAX) + 9;
        let count = filesystem_mutation::encode_append_request(7, large_offset, b"end", &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let append = filesystem_mutation::decode_append_request(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(append.token, 7);
        assert_eq!(append.offset, large_offset);
        assert_eq!(append.bytes, b"end");
        let configured = filesystem_mutation::encode_chunk_size_request(7, 1024 * 1024)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem_mutation::decode_chunk_size_request(&configured),
            Ok((7, 1024 * 1024))
        );

        let mut unchanged = [0xa5_u8; 8];
        assert!(filesystem_mutation::encode_append_request(0, 0, b"x", &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; 8]);

        let mut link_bytes = [0_u8; filesystem_mutation::MAX_LINK_REQUEST_BYTES];
        let count = filesystem_mutation::encode_link_request(
            "../target",
            "/vol/root/link",
            &mut link_bytes,
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem_mutation::decode_link_request(&link_bytes[..count]),
            Ok(filesystem_mutation::LinkRequest {
                target: "../target",
                link_path: "/vol/root/link",
            })
        );
        assert!(filesystem_mutation::decode_link_request(&link_bytes[..count - 1]).is_err());
        let count = filesystem_mutation::encode_two_path_request(
            "/vol/root/old",
            "/vol/root/new",
            &mut link_bytes,
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem_mutation::decode_two_path_request(&link_bytes[..count]),
            Ok(filesystem_mutation::TwoPathRequest {
                source: "/vol/root/old",
                destination: "/vol/root/new",
            })
        );
        assert!(filesystem_mutation::decode_two_path_request(&link_bytes[..count - 1]).is_err());
        let mut unchanged = [0xa5_u8; 7];
        assert!(
            filesystem_mutation::encode_link_request("target", "link", &mut unchanged).is_err()
        );
        assert_eq!(unchanged, [0xa5; 7]);
        assert!(reply::is_known(reply::NOT_EMPTY));
        assert!(reply::is_known(reply::CROSS_DEVICE));
        assert!(reply::is_known(reply::RESOURCE_LIMIT));
        assert!(!reply::is_known(reply::RESOURCE_LIMIT + 1));
    }
}

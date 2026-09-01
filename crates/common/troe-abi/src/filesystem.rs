//! Bounded read-only filesystem protocol.

use core::str;

use super::MAX_SERVICE_PAYLOAD_BYTES;

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 5;
/// Resolve and open one regular file.
pub const OPEN: u16 = 1;
/// Read one bounded range through an open-file token.
pub const READ: u16 = 2;
/// Release one open-file token.
pub const CLOSE: u16 = 3;
/// Return one bounded page of immediate directory children.
pub const LIST: u16 = 4;
/// Return metadata without opening an object.
pub const METADATA: u16 = 5;
/// Read one symbolic-link target without following the final component.
pub const READ_LINK: u16 = 6;
/// Return metadata without following the final symbolic-link component.
pub const METADATA_NO_FOLLOW: u16 = 7;
/// Maximum path bytes accepted by this interface.
pub const MAX_PATH_BYTES: usize = 256;
/// Maximum simultaneously open files per application service.
pub const MAX_OPEN_FILES: usize = 4096;
/// Maximum entries returned by one list call.
pub const MAX_LIST_ENTRIES: usize = 64;
/// Maximum encoded bytes in one entry name.
pub const MAX_NAME_BYTES: usize = 255;
/// Maximum aggregate name bytes returned by one list call.
pub const MAX_LIST_NAME_BYTES: usize = 3 * 1024;
/// Fixed open-file reply bytes.
pub const OPEN_REPLY_BYTES: usize = 16;
/// Fixed range-read request bytes.
pub const READ_REQUEST_BYTES: usize = 16;
/// Fixed list request bytes preceding its path.
pub const LIST_REQUEST_HEADER_BYTES: usize = 12;
/// Largest canonical list request.
pub const MAX_LIST_REQUEST_BYTES: usize = LIST_REQUEST_HEADER_BYTES + MAX_PATH_BYTES;
/// Fixed list reply bytes preceding entries.
pub const LIST_REPLY_HEADER_BYTES: usize = 12;
/// Fixed bytes preceding each variable entry name.
pub const LIST_ENTRY_HEADER_BYTES: usize = 4;
/// Largest canonical list reply.
pub const MAX_LIST_REPLY_BYTES: usize =
    LIST_REPLY_HEADER_BYTES + MAX_LIST_ENTRIES * LIST_ENTRY_HEADER_BYTES + MAX_LIST_NAME_BYTES;
/// Fixed metadata reply bytes.
pub const METADATA_REPLY_BYTES: usize = 40;
/// Maximum encoded bytes in one symbolic-link target.
pub const MAX_LINK_BYTES: usize = MAX_PATH_BYTES;

/// Invalid filesystem request or reply encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Visible filesystem object kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NodeKind {
    /// Regular byte file.
    File = 1,
    /// Directory containing named children.
    Directory = 2,
    /// Symbolic link owned and resolved by a filesystem provider.
    Symlink = 3,
}

impl NodeKind {
    fn parse(value: u8) -> Result<Self, EncodingError> {
        match value {
            1 => Ok(Self::File),
            2 => Ok(Self::Directory),
            3 => Ok(Self::Symlink),
            _ => Err(EncodingError),
        }
    }
}

/// Metadata returned for one resolved object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    /// Object kind.
    pub kind: NodeKind,
    /// Exact regular-file bytes, or zero for a directory.
    pub byte_count: u64,
    /// Whole Unix UTC seconds of the last payload modification, when the
    /// provider recorded one.
    ///
    /// `None` where the provider stores no timestamp, and where it stores
    /// one that was never stamped. A zero is therefore an absent time
    /// rather than 1970.
    pub modified_unix_seconds: Option<u64>,
    /// Whole Unix UTC seconds of the last metadata change, when recorded.
    ///
    /// Advances on changes a modification time does not see, such as a
    /// rename. `None` where the format has no such field.
    pub changed_unix_seconds: Option<u64>,
    /// Whole Unix UTC seconds of the object's creation, when recorded.
    ///
    /// `None` where the format stamps none. Absence is never filled in
    /// from a field that means something else.
    pub created_unix_seconds: Option<u64>,
}

/// Opaque open-file token plus immutable size observed at open time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenFile {
    token: u32,
    /// Exact file bytes observed at open time.
    pub byte_count: u64,
}

impl OpenFile {
    /// Construct a validated opaque token from a service reply.
    ///
    /// # Errors
    ///
    /// Rejects token zero.
    pub fn new(token: u32, byte_count: u64) -> Result<Self, EncodingError> {
        if token == 0 {
            return Err(EncodingError);
        }
        Ok(Self { token, byte_count })
    }

    /// Opaque token for protocol encoders; applications must not interpret it.
    #[must_use]
    pub const fn token(self) -> u32 {
        self.token
    }
}

/// Borrowed validated list request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListRequest<'a> {
    /// Opaque cursor; zero begins a traversal.
    pub cursor: u64,
    /// Maximum entries requested in this page.
    pub max_entries: usize,
    /// Maximum aggregate entry-name bytes.
    pub max_name_bytes: usize,
    /// Path resolved relative to the invocation cwd.
    pub path: &'a str,
}

/// One borrowed directory entry used by encoders and decoders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntry<'a> {
    /// Entry kind.
    pub kind: NodeKind,
    /// UTF-8 base name without a slash.
    pub name: &'a str,
}

/// Borrowed validated directory page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryPage<'a> {
    bytes: &'a [u8],
    entry_count: usize,
    next_cursor: Option<u64>,
}

impl<'a> DirectoryPage<'a> {
    /// Parse one exact bounded page.
    ///
    /// # Errors
    ///
    /// Rejects malformed flags, padding, counts, kinds, names, bounds, or
    /// trailing bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, EncodingError> {
        if bytes.len() < LIST_REPLY_HEADER_BYTES || bytes.len() > MAX_LIST_REPLY_BYTES {
            return Err(EncodingError);
        }
        let next = read_u64(bytes, 0)?;
        let next_cursor = match bytes[8] {
            0 if next == 0 => None,
            1 => Some(next),
            _ => return Err(EncodingError),
        };
        if bytes[9] != 0 {
            return Err(EncodingError);
        }
        let entry_count = usize::from(read_u16(bytes, 10)?);
        if entry_count > MAX_LIST_ENTRIES {
            return Err(EncodingError);
        }
        let page = Self {
            bytes,
            entry_count,
            next_cursor,
        };
        let mut cursor = LIST_REPLY_HEADER_BYTES;
        let mut name_bytes = 0_usize;
        let mut previous = None;
        for _ in 0..entry_count {
            let (entry, end) = decode_entry(bytes, cursor)?;
            if previous.is_some_and(|name| name >= entry.name) {
                return Err(EncodingError);
            }
            previous = Some(entry.name);
            name_bytes = name_bytes
                .checked_add(entry.name.len())
                .ok_or(EncodingError)?;
            if name_bytes > MAX_LIST_NAME_BYTES {
                return Err(EncodingError);
            }
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(EncodingError);
        }
        Ok(page)
    }

    /// Number of entries in this page.
    #[must_use]
    pub const fn len(self) -> usize {
        self.entry_count
    }

    /// Whether the page contains no entries.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.entry_count == 0
    }

    /// Cursor to pass to the next list call, or `None` at end-of-directory.
    #[must_use]
    pub const fn next_cursor(self) -> Option<u64> {
        self.next_cursor
    }

    /// Iterate through lexical entries.
    #[must_use]
    pub const fn entries(self) -> DirectoryEntries<'a> {
        DirectoryEntries {
            page: self,
            index: 0,
            cursor: LIST_REPLY_HEADER_BYTES,
        }
    }
}

/// Iterator over one validated directory page.
pub struct DirectoryEntries<'a> {
    page: DirectoryPage<'a>,
    index: usize,
    cursor: usize,
}

impl<'a> Iterator for DirectoryEntries<'a> {
    type Item = DirectoryEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.page.entry_count {
            return None;
        }
        let (entry, end) = decode_entry(self.page.bytes, self.cursor).ok()?;
        self.index += 1;
        self.cursor = end;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.page.entry_count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for DirectoryEntries<'_> {}

/// Encode a path-only request.
///
/// # Errors
///
/// Rejects empty/excessive paths or insufficient output without mutation.
pub fn encode_path_request(path: &str, output: &mut [u8]) -> Result<usize, EncodingError> {
    validate_path(path)?;
    if output.len() < path.len() {
        return Err(EncodingError);
    }
    output[..path.len()].copy_from_slice(path.as_bytes());
    Ok(path.len())
}

/// Decode one exact path-only request.
///
/// # Errors
///
/// Rejects non-UTF-8, empty, excessive, or NUL-containing paths.
pub fn decode_path_request(bytes: &[u8]) -> Result<&str, EncodingError> {
    let path = str::from_utf8(bytes).map_err(|_| EncodingError)?;
    validate_path(path)?;
    Ok(path)
}

/// Encode an open-file reply.
#[must_use]
pub fn encode_open_reply(file: OpenFile) -> [u8; OPEN_REPLY_BYTES] {
    let mut bytes = [0_u8; OPEN_REPLY_BYTES];
    bytes[..4].copy_from_slice(&file.token.to_le_bytes());
    bytes[8..16].copy_from_slice(&file.byte_count.to_le_bytes());
    bytes
}

/// Decode one exact open-file reply.
///
/// # Errors
///
/// Rejects wrong length, padding, or token zero.
pub fn decode_open_reply(bytes: &[u8]) -> Result<OpenFile, EncodingError> {
    if bytes.len() != OPEN_REPLY_BYTES || read_u32(bytes, 4)? != 0 {
        return Err(EncodingError);
    }
    OpenFile::new(read_u32(bytes, 0)?, read_u64(bytes, 8)?)
}

/// Encode one exact range-read request.
///
/// # Errors
///
/// Rejects zero or excessive requested bytes.
pub fn encode_read_request(
    file: OpenFile,
    offset: u64,
    max_bytes: usize,
) -> Result<[u8; READ_REQUEST_BYTES], EncodingError> {
    if max_bytes == 0 || max_bytes > MAX_SERVICE_PAYLOAD_BYTES {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; READ_REQUEST_BYTES];
    bytes[..4].copy_from_slice(&file.token.to_le_bytes());
    bytes[4..6].copy_from_slice(
        &u16::try_from(max_bytes)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    bytes[8..16].copy_from_slice(&offset.to_le_bytes());
    Ok(bytes)
}

/// Decode one exact range-read request.
///
/// # Errors
///
/// Rejects wrong length, padding, token zero, or invalid requested bytes.
pub fn decode_read_request(bytes: &[u8]) -> Result<(u32, u64, usize), EncodingError> {
    if bytes.len() != READ_REQUEST_BYTES || read_u16(bytes, 6)? != 0 {
        return Err(EncodingError);
    }
    let token = read_u32(bytes, 0)?;
    let max_bytes = usize::from(read_u16(bytes, 4)?);
    if token == 0 || max_bytes == 0 || max_bytes > MAX_SERVICE_PAYLOAD_BYTES {
        return Err(EncodingError);
    }
    Ok((token, read_u64(bytes, 8)?, max_bytes))
}

/// Encode an exact close request.
#[must_use]
pub const fn encode_close_request(file: OpenFile) -> [u8; 4] {
    file.token.to_le_bytes()
}

/// Decode an exact close request.
///
/// # Errors
///
/// Rejects wrong length or token zero.
pub fn decode_close_request(bytes: &[u8]) -> Result<u32, EncodingError> {
    if bytes.len() != 4 {
        return Err(EncodingError);
    }
    let token = read_u32(bytes, 0)?;
    if token == 0 {
        return Err(EncodingError);
    }
    Ok(token)
}

/// Encode one bounded directory-list request.
///
/// # Errors
///
/// Rejects invalid paths, zero/excessive budgets, overflow, or short output.
pub fn encode_list_request(
    cursor: u64,
    max_entries: usize,
    max_name_bytes: usize,
    path: &str,
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    validate_path(path)?;
    let count = LIST_REQUEST_HEADER_BYTES
        .checked_add(path.len())
        .ok_or(EncodingError)?;
    if max_entries == 0
        || max_entries > MAX_LIST_ENTRIES
        || max_name_bytes == 0
        || max_name_bytes > MAX_LIST_NAME_BYTES
        || output.len() < count
    {
        return Err(EncodingError);
    }
    let mut encoded = [0_u8; MAX_LIST_REQUEST_BYTES];
    encoded[..8].copy_from_slice(&cursor.to_le_bytes());
    encoded[8..10].copy_from_slice(
        &u16::try_from(max_entries)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    encoded[10..12].copy_from_slice(
        &u16::try_from(max_name_bytes)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    encoded[LIST_REQUEST_HEADER_BYTES..count].copy_from_slice(path.as_bytes());
    output[..count].copy_from_slice(&encoded[..count]);
    Ok(count)
}

/// Decode one exact bounded directory-list request.
///
/// # Errors
///
/// Rejects malformed length, path, or list budgets.
pub fn decode_list_request(bytes: &[u8]) -> Result<ListRequest<'_>, EncodingError> {
    if bytes.len() <= LIST_REQUEST_HEADER_BYTES || bytes.len() > MAX_LIST_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let max_entries = usize::from(read_u16(bytes, 8)?);
    let max_name_bytes = usize::from(read_u16(bytes, 10)?);
    let path = decode_path_request(&bytes[LIST_REQUEST_HEADER_BYTES..])?;
    if max_entries == 0
        || max_entries > MAX_LIST_ENTRIES
        || max_name_bytes == 0
        || max_name_bytes > MAX_LIST_NAME_BYTES
    {
        return Err(EncodingError);
    }
    Ok(ListRequest {
        cursor: read_u64(bytes, 0)?,
        max_entries,
        max_name_bytes,
        path,
    })
}

/// Encode one lexical bounded directory page.
///
/// # Errors
///
/// Rejects excessive, invalid, non-lexical entries or insufficient output.
pub fn encode_list_reply(
    next_cursor: Option<u64>,
    entries: &[DirectoryEntry<'_>],
    output: &mut [u8],
) -> Result<usize, EncodingError> {
    if entries.len() > MAX_LIST_ENTRIES {
        return Err(EncodingError);
    }
    let mut count = LIST_REPLY_HEADER_BYTES;
    let mut name_bytes = 0_usize;
    let mut previous = None;
    for entry in entries {
        validate_name(entry.name)?;
        if previous.is_some_and(|name| name >= entry.name) {
            return Err(EncodingError);
        }
        previous = Some(entry.name);
        name_bytes = name_bytes
            .checked_add(entry.name.len())
            .ok_or(EncodingError)?;
        count = count
            .checked_add(LIST_ENTRY_HEADER_BYTES)
            .and_then(|value| value.checked_add(entry.name.len()))
            .ok_or(EncodingError)?;
    }
    if name_bytes > MAX_LIST_NAME_BYTES || count > MAX_LIST_REPLY_BYTES || output.len() < count {
        return Err(EncodingError);
    }
    let mut encoded = [0_u8; MAX_LIST_REPLY_BYTES];
    if let Some(cursor) = next_cursor {
        encoded[..8].copy_from_slice(&cursor.to_le_bytes());
        encoded[8] = 1;
    }
    encoded[10..12].copy_from_slice(
        &u16::try_from(entries.len())
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    let mut cursor = LIST_REPLY_HEADER_BYTES;
    for entry in entries {
        encoded[cursor] = entry.kind as u8;
        encoded[cursor + 1] = u8::try_from(entry.name.len()).map_err(|_| EncodingError)?;
        cursor += LIST_ENTRY_HEADER_BYTES;
        let end = cursor + entry.name.len();
        encoded[cursor..end].copy_from_slice(entry.name.as_bytes());
        cursor = end;
    }
    output[..count].copy_from_slice(&encoded[..count]);
    Ok(count)
}

/// Encode one exact metadata reply.
#[must_use]
pub fn encode_metadata_reply(metadata: Metadata) -> [u8; METADATA_REPLY_BYTES] {
    let mut bytes = [0_u8; METADATA_REPLY_BYTES];
    bytes[0] = metadata.kind as u8;
    // An absent time is one flag byte and an all-zero value, so a decoder
    // never has to treat a valid instant as a sentinel. Each time carries
    // its own flag because the three are independently absent.
    bytes[1] = u8::from(metadata.modified_unix_seconds.is_some());
    bytes[2] = u8::from(metadata.changed_unix_seconds.is_some());
    bytes[3] = u8::from(metadata.created_unix_seconds.is_some());
    bytes[8..16].copy_from_slice(&metadata.byte_count.to_le_bytes());
    bytes[16..24].copy_from_slice(&metadata.modified_unix_seconds.unwrap_or(0).to_le_bytes());
    bytes[24..32].copy_from_slice(&metadata.changed_unix_seconds.unwrap_or(0).to_le_bytes());
    bytes[32..40].copy_from_slice(&metadata.created_unix_seconds.unwrap_or(0).to_le_bytes());
    bytes
}

/// Pair one time's presence flag with its value.
///
/// A present flag with no value, or a value with no flag, is a producer
/// that did not encode this reply.
fn decode_optional_time(flag: u8, seconds: u64) -> Result<Option<u64>, EncodingError> {
    match flag {
        0 if seconds == 0 => Ok(None),
        1 => Ok(Some(seconds)),
        _ => Err(EncodingError),
    }
}

/// Decode one exact metadata reply.
///
/// # Errors
///
/// Rejects wrong length, padding, kind, or nonzero directory size.
pub fn decode_metadata_reply(bytes: &[u8]) -> Result<Metadata, EncodingError> {
    if bytes.len() != METADATA_REPLY_BYTES || bytes[4..8].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    let kind = NodeKind::parse(bytes[0])?;
    let byte_count = read_u64(bytes, 8)?;
    if kind == NodeKind::Directory && byte_count != 0 {
        return Err(EncodingError);
    }
    Ok(Metadata {
        kind,
        byte_count,
        modified_unix_seconds: decode_optional_time(bytes[1], read_u64(bytes, 16)?)?,
        changed_unix_seconds: decode_optional_time(bytes[2], read_u64(bytes, 24)?)?,
        created_unix_seconds: decode_optional_time(bytes[3], read_u64(bytes, 32)?)?,
    })
}

/// Encode one exact UTF-8 symbolic-link target.
///
/// # Errors
///
/// Rejects empty, excessive, NUL-containing targets or short output.
pub fn encode_link_reply(target: &str, output: &mut [u8]) -> Result<usize, EncodingError> {
    validate_link(target)?;
    if output.len() < target.len() {
        return Err(EncodingError);
    }
    output[..target.len()].copy_from_slice(target.as_bytes());
    Ok(target.len())
}

/// Decode one exact UTF-8 symbolic-link target.
///
/// # Errors
///
/// Rejects empty, excessive, invalid UTF-8, or NUL-containing targets.
pub fn decode_link_reply(bytes: &[u8]) -> Result<&str, EncodingError> {
    let target = str::from_utf8(bytes).map_err(|_| EncodingError)?;
    validate_link(target)?;
    Ok(target)
}

fn validate_path(path: &str) -> Result<(), EncodingError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.as_bytes().contains(&0) {
        return Err(EncodingError);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), EncodingError> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name.contains('/')
        || matches!(name, "." | "..")
    {
        return Err(EncodingError);
    }
    Ok(())
}

fn validate_link(target: &str) -> Result<(), EncodingError> {
    if target.is_empty() || target.len() > MAX_LINK_BYTES || target.as_bytes().contains(&0) {
        return Err(EncodingError);
    }
    Ok(())
}

fn decode_entry(bytes: &[u8], offset: usize) -> Result<(DirectoryEntry<'_>, usize), EncodingError> {
    let header = bytes
        .get(offset..offset + LIST_ENTRY_HEADER_BYTES)
        .ok_or(EncodingError)?;
    if header[2] != 0 || header[3] != 0 {
        return Err(EncodingError);
    }
    let end = offset
        .checked_add(LIST_ENTRY_HEADER_BYTES)
        .and_then(|value| value.checked_add(usize::from(header[1])))
        .ok_or(EncodingError)?;
    let name = str::from_utf8(
        bytes
            .get(offset + LIST_ENTRY_HEADER_BYTES..end)
            .ok_or(EncodingError)?,
    )
    .map_err(|_| EncodingError)?;
    validate_name(name)?;
    Ok((
        DirectoryEntry {
            kind: NodeKind::parse(header[0])?,
            name,
        },
        end,
    ))
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
    use crate::filesystem;

    #[test]
    fn filesystem_records_round_trip_and_reject_ambiguity() {
        let file = filesystem::decode_open_reply(&filesystem::encode_open_reply(
            filesystem::OpenFile::new(0x101, 65_537).unwrap_or_else(|_| std::process::abort()),
        ))
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(file.byte_count, 65_537);
        let read = filesystem::encode_read_request(file, 4096, 512)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem::decode_read_request(&read),
            Ok((0x101, 4096, 512))
        );

        let entries = [
            filesystem::DirectoryEntry {
                kind: filesystem::NodeKind::Directory,
                name: "etc",
            },
            filesystem::DirectoryEntry {
                kind: filesystem::NodeKind::File,
                name: "motd",
            },
            filesystem::DirectoryEntry {
                kind: filesystem::NodeKind::Symlink,
                name: "motd-link",
            },
        ];
        let mut bytes = [0_u8; filesystem::MAX_LIST_REPLY_BYTES];
        let count = filesystem::encode_list_reply(Some(2), &entries, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let page = filesystem::DirectoryPage::parse(&bytes[..count])
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(page.next_cursor(), Some(2));
        assert_eq!(page.entries().collect::<std::vec::Vec<_>>(), entries);
        for end in 0..count {
            assert!(filesystem::DirectoryPage::parse(&bytes[..end]).is_err());
        }
        let mut trailing = bytes[..count].to_vec();
        trailing.push(0);
        assert!(filesystem::DirectoryPage::parse(&trailing).is_err());

        let mut unchanged = [0xa5_u8; filesystem::MAX_LIST_REPLY_BYTES];
        let unsorted = [entries[1], entries[0]];
        assert!(filesystem::encode_list_reply(None, &unsorted, &mut unchanged).is_err());
        assert_eq!(unchanged, [0xa5; filesystem::MAX_LIST_REPLY_BYTES]);

        let mut link = [0_u8; filesystem::MAX_LINK_BYTES];
        let count = filesystem::encode_link_reply("../target", &mut link)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            filesystem::decode_link_reply(&link[..count]),
            Ok("../target")
        );
        assert!(filesystem::decode_link_reply(b"").is_err());
        assert!(filesystem::decode_link_reply(b"bad\0target").is_err());
    }
}

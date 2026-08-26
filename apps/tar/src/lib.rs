#![no_std]

#[cfg(test)]
extern crate std;

use core::str;

/// Bytes in one POSIX tar record.
pub const BLOCK_BYTES: usize = 512;
/// Maximum path bytes representable by the supported ustar name/prefix fields.
pub const MAX_MEMBER_BYTES: usize = 255;

const NAME_OFFSET: usize = 0;
const NAME_BYTES: usize = 100;
const MODE_OFFSET: usize = 100;
const UID_OFFSET: usize = 108;
const GID_OFFSET: usize = 116;
const SIZE_OFFSET: usize = 124;
const MTIME_OFFSET: usize = 136;
const CHECKSUM_OFFSET: usize = 148;
const TYPE_OFFSET: usize = 156;
const LINK_OFFSET: usize = 157;
const LINK_BYTES: usize = 100;
const MAGIC_OFFSET: usize = 257;
const PREFIX_OFFSET: usize = 345;
const PREFIX_BYTES: usize = 155;

/// Supported portable archive entry kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    /// Regular byte file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// A rejected or unsupported tar record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderError;

/// One decoded bounded ustar header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    path: [u8; MAX_MEMBER_BYTES],
    path_len: usize,
    link: [u8; LINK_BYTES],
    link_len: usize,
    /// Entry kind.
    pub kind: EntryKind,
    /// Regular-file payload bytes.
    pub size: u64,
}

impl Header {
    /// Validated archive member path.
    #[must_use]
    pub fn path(&self) -> &str {
        str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }

    /// Validated symbolic-link target, or the empty string for other kinds.
    #[must_use]
    pub fn link(&self) -> &str {
        str::from_utf8(&self.link[..self.link_len]).unwrap_or("")
    }
}

/// Encode one canonical POSIX ustar header.
pub fn encode_header(
    path: &str,
    kind: EntryKind,
    size: u64,
    link: &str,
    output: &mut [u8; BLOCK_BYTES],
) -> Result<(), HeaderError> {
    let path = normalized_member(path, kind)?;
    let (prefix, name) = split_ustar_path(path)?;
    if kind == EntryKind::Symlink {
        validate_link(link)?;
    } else if !link.is_empty() {
        return Err(HeaderError);
    }
    if kind != EntryKind::File && size != 0 {
        return Err(HeaderError);
    }

    output.fill(0);
    output[NAME_OFFSET..NAME_OFFSET + name.len()].copy_from_slice(name.as_bytes());
    output[PREFIX_OFFSET..PREFIX_OFFSET + prefix.len()].copy_from_slice(prefix.as_bytes());
    let mode = match kind {
        EntryKind::File => 0o644,
        EntryKind::Directory => 0o755,
        EntryKind::Symlink => 0o777,
    };
    encode_octal(mode, &mut output[MODE_OFFSET..MODE_OFFSET + 8])?;
    encode_octal(0, &mut output[UID_OFFSET..UID_OFFSET + 8])?;
    encode_octal(0, &mut output[GID_OFFSET..GID_OFFSET + 8])?;
    encode_octal(size, &mut output[SIZE_OFFSET..SIZE_OFFSET + 12])?;
    encode_octal(0, &mut output[MTIME_OFFSET..MTIME_OFFSET + 12])?;
    output[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 8].fill(b' ');
    output[TYPE_OFFSET] = match kind {
        EntryKind::File => b'0',
        EntryKind::Directory => b'5',
        EntryKind::Symlink => b'2',
    };
    output[LINK_OFFSET..LINK_OFFSET + link.len()].copy_from_slice(link.as_bytes());
    output[MAGIC_OFFSET..MAGIC_OFFSET + 6].copy_from_slice(b"ustar\0");
    output[MAGIC_OFFSET + 6..MAGIC_OFFSET + 8].copy_from_slice(b"00");
    let checksum = output.iter().map(|byte| u64::from(*byte)).sum();
    encode_checksum(checksum, &mut output[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 8])
}

/// Parse and validate one supported POSIX/GNU-compatible ustar header.
pub fn decode_header(input: &[u8; BLOCK_BYTES]) -> Result<Option<Header>, HeaderError> {
    if input.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let stored = decode_octal(&input[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 8])?;
    let actual: u64 = input
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (CHECKSUM_OFFSET..CHECKSUM_OFFSET + 8).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    if stored != actual
        || (&input[MAGIC_OFFSET..MAGIC_OFFSET + 6] != b"ustar\0"
            && &input[MAGIC_OFFSET..MAGIC_OFFSET + 6] != b"ustar ")
    {
        return Err(HeaderError);
    }
    let name = field_text(&input[NAME_OFFSET..NAME_OFFSET + NAME_BYTES])?;
    let prefix = field_text(&input[PREFIX_OFFSET..PREFIX_OFFSET + PREFIX_BYTES])?;
    let mut path = [0_u8; MAX_MEMBER_BYTES];
    let path_len = if prefix.is_empty() {
        copy_checked(name.as_bytes(), &mut path)?
    } else {
        let mut used = copy_checked(prefix.as_bytes(), &mut path)?;
        *path.get_mut(used).ok_or(HeaderError)? = b'/';
        used += 1;
        used + copy_checked(name.as_bytes(), &mut path[used..])?
    };
    let raw_path = str::from_utf8(&path[..path_len]).map_err(|_| HeaderError)?;
    let kind = match input[TYPE_OFFSET] {
        0 | b'0' => EntryKind::File,
        b'5' => EntryKind::Directory,
        b'2' => EntryKind::Symlink,
        _ => return Err(HeaderError),
    };
    let path_len = normalized_member(raw_path, kind)?.len();
    let size = decode_octal(&input[SIZE_OFFSET..SIZE_OFFSET + 12])?;
    if kind != EntryKind::File && size != 0 {
        return Err(HeaderError);
    }
    let link_text = field_text(&input[LINK_OFFSET..LINK_OFFSET + LINK_BYTES])?;
    let mut link = [0_u8; LINK_BYTES];
    let link_len = if kind == EntryKind::Symlink {
        validate_link(link_text)?;
        copy_checked(link_text.as_bytes(), &mut link)?
    } else if link_text.is_empty() {
        0
    } else {
        return Err(HeaderError);
    };
    Ok(Some(Header {
        path,
        path_len,
        link,
        link_len,
        kind,
        size,
    }))
}

/// Payload bytes rounded up to the next tar record boundary.
pub fn padded_size(size: u64) -> Result<u64, HeaderError> {
    size.checked_add((BLOCK_BYTES as u64 - size % BLOCK_BYTES as u64) % BLOCK_BYTES as u64)
        .ok_or(HeaderError)
}

fn normalized_member(path: &str, kind: EntryKind) -> Result<&str, HeaderError> {
    let path = if kind == EntryKind::Directory {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };
    if path.is_empty()
        || path.len() > MAX_MEMBER_BYTES
        || path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(HeaderError);
    }
    Ok(path)
}

fn validate_link(target: &str) -> Result<(), HeaderError> {
    if target.is_empty()
        || target.len() > LINK_BYTES
        || target.starts_with('/')
        || target.as_bytes().contains(&0)
        || target.split('/').any(|part| matches!(part, ".."))
    {
        return Err(HeaderError);
    }
    Ok(())
}

fn split_ustar_path(path: &str) -> Result<(&str, &str), HeaderError> {
    if path.len() <= NAME_BYTES {
        return Ok(("", path));
    }
    path.char_indices()
        .rev()
        .find_map(|(index, character)| {
            (character == '/' && index <= PREFIX_BYTES && path.len() - index - 1 <= NAME_BYTES)
                .then(|| (&path[..index], &path[index + 1..]))
        })
        .ok_or(HeaderError)
}

fn field_text(bytes: &[u8]) -> Result<&str, HeaderError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(HeaderError);
    }
    str::from_utf8(&bytes[..end]).map_err(|_| HeaderError)
}

fn encode_octal(value: u64, output: &mut [u8]) -> Result<(), HeaderError> {
    if output.len() < 2 {
        return Err(HeaderError);
    }
    output.fill(b'0');
    output[output.len() - 1] = 0;
    let mut value = value;
    let mut cursor = output.len() - 1;
    loop {
        if cursor == 0 {
            return Err(HeaderError);
        }
        cursor -= 1;
        output[cursor] = b'0' + (value & 7) as u8;
        value >>= 3;
        if value == 0 {
            return Ok(());
        }
    }
}

fn encode_checksum(value: u64, output: &mut [u8]) -> Result<(), HeaderError> {
    if output.len() != 8 || value > 0o777_777 {
        return Err(HeaderError);
    }
    output.fill(b'0');
    output[6] = 0;
    output[7] = b' ';
    let mut value = value;
    for index in (0..6).rev() {
        output[index] = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    (value == 0).then_some(()).ok_or(HeaderError)
}

fn decode_octal(bytes: &[u8]) -> Result<u64, HeaderError> {
    let mut value = 0_u64;
    let mut digit_seen = false;
    let mut terminated = false;
    for byte in bytes {
        match *byte {
            b' ' | 0 if !digit_seen => {}
            b'0'..=b'7' if !terminated => {
                digit_seen = true;
                value = value
                    .checked_mul(8)
                    .and_then(|number| number.checked_add(u64::from(*byte - b'0')))
                    .ok_or(HeaderError)?;
            }
            b' ' | 0 => terminated = true,
            _ => return Err(HeaderError),
        }
    }
    digit_seen.then_some(value).ok_or(HeaderError)
}

fn copy_checked(source: &[u8], destination: &mut [u8]) -> Result<usize, HeaderError> {
    let target = destination.get_mut(..source.len()).ok_or(HeaderError)?;
    target.copy_from_slice(source);
    Ok(source.len())
}

#[cfg(test)]
mod tests {
    use super::{BLOCK_BYTES, EntryKind, HeaderError, decode_header, encode_header, padded_size};

    #[test]
    fn canonical_headers_round_trip_all_supported_kinds() {
        for (path, kind, size, link) in [
            ("docs/readme.txt", EntryKind::File, 123, ""),
            ("docs", EntryKind::Directory, 0, ""),
            ("latest", EntryKind::Symlink, 0, "docs/readme.txt"),
        ] {
            let mut bytes = [0_u8; BLOCK_BYTES];
            assert_eq!(encode_header(path, kind, size, link, &mut bytes), Ok(()));
            let header = decode_header(&bytes)
                .unwrap_or_else(|_| unreachable!())
                .unwrap_or_else(|| unreachable!());
            assert_eq!(header.path(), path);
            assert_eq!(header.kind, kind);
            assert_eq!(header.size, size);
            assert_eq!(header.link(), link);
        }
    }

    #[test]
    fn ustar_prefix_and_padding_are_exact() {
        let path = "directory/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut bytes = [0_u8; BLOCK_BYTES];
        assert_eq!(
            encode_header(path, EntryKind::File, 1, "", &mut bytes),
            Ok(())
        );
        let header = decode_header(&bytes)
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|| unreachable!());
        assert_eq!(header.path(), path);
        assert_eq!(padded_size(0), Ok(0));
        assert_eq!(padded_size(1), Ok(512));
        assert_eq!(padded_size(513), Ok(1024));
    }

    #[test]
    fn unsafe_unsupported_and_corrupt_headers_fail_closed() {
        let mut bytes = [0_u8; BLOCK_BYTES];
        assert_eq!(
            encode_header("../escape", EntryKind::File, 0, "", &mut bytes),
            Err(HeaderError)
        );
        assert_eq!(decode_header(&bytes), Ok(None));
        assert_eq!(
            encode_header("file", EntryKind::File, 4, "", &mut bytes),
            Ok(())
        );
        bytes[0] ^= 1;
        assert_eq!(decode_header(&bytes), Err(HeaderError));
    }
}

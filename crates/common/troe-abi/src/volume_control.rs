//! Manifest-authorized runtime volume activation protocol.

use core::str;

use super::MAX_SERVICE_PAYLOAD_BYTES;

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// List every configured volume in canonical name order.
pub const LIST: u16 = 1;
/// Activate one prepared manual volume by manifest name.
pub const ACTIVATE: u16 = 2;
/// Maximum canonical volume-name bytes.
pub const MAX_NAME_BYTES: usize = 32;
/// Fixed list header bytes.
pub const LIST_HEADER_BYTES: usize = 4;
/// Fixed bytes per list record.
pub const LIST_RECORD_BYTES: usize = 40;
/// Maximum configured volume records.
pub const MAX_VOLUMES: usize = 16;
/// Largest canonical list reply.
pub const MAX_LIST_REPLY_BYTES: usize = LIST_HEADER_BYTES + MAX_VOLUMES * LIST_RECORD_BYTES;
/// Largest canonical activation request.
pub const MAX_ACTIVATE_REQUEST_BYTES: usize = 1 + MAX_NAME_BYTES;

const _: () = assert!(MAX_LIST_REPLY_BYTES <= MAX_SERVICE_PAYLOAD_BYTES);

/// Filesystem provider selected by policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Filesystem {
    /// FAT32 provider.
    Fat32 = 1,
    /// Constrained ext4-v1 provider.
    Ext4V1 = 2,
}

/// Authority granted to the mounted provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Access {
    /// Read-only provider.
    ReadOnly = 1,
    /// Read/write provider.
    ReadWrite = 2,
}

/// Configured activation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Activation {
    /// Attached automatically during boot.
    Auto = 1,
    /// Requires an authorized activation request.
    Manual = 2,
}

/// Current runtime volume state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum State {
    /// No unique matching provider was prepared.
    Unavailable = 1,
    /// A manual provider is validated and ready.
    Ready = 2,
    /// The provider is attached below `/vol`.
    Mounted = 3,
    /// An attachment attempt failed.
    Failed = 4,
}

/// One borrowed configured-volume record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeInfo<'a> {
    /// Manifest name, mapping to `/vol/<name>`.
    pub name: &'a str,
    /// Filesystem provider profile.
    pub filesystem: Filesystem,
    /// Effective access mode.
    pub access: Access,
    /// Boot or manual activation policy.
    pub activation: Activation,
    /// Current runtime state.
    pub state: State,
}

/// Borrowed validated list reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeList<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> VolumeList<'a> {
    /// Number of configured volumes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.count
    }

    /// Whether the policy contains no volumes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Iterate canonical name-sorted volume records.
    #[must_use]
    pub const fn iter(self) -> VolumeIter<'a> {
        VolumeIter {
            list: self,
            index: 0,
        }
    }
}

/// Iterator over one validated list reply.
pub struct VolumeIter<'a> {
    list: VolumeList<'a>,
    index: usize,
}

impl<'a> Iterator for VolumeIter<'a> {
    type Item = VolumeInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.list.count {
            return None;
        }
        let offset = LIST_HEADER_BYTES + self.index * LIST_RECORD_BYTES;
        self.index += 1;
        decode_record(self.list.bytes.get(offset..offset + LIST_RECORD_BYTES)?).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.list.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for VolumeIter<'_> {}

/// Invalid volume-control request or reply encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Encode one canonical configured-volume list.
///
/// # Errors
///
/// Rejects excessive, unsorted, invalid, or short output transactionally.
pub fn encode_list(entries: &[VolumeInfo<'_>], output: &mut [u8]) -> Result<usize, EncodingError> {
    let count = LIST_HEADER_BYTES
        .checked_add(
            entries
                .len()
                .checked_mul(LIST_RECORD_BYTES)
                .ok_or(EncodingError)?,
        )
        .ok_or(EncodingError)?;
    if entries.len() > MAX_VOLUMES || output.len() < count {
        return Err(EncodingError);
    }
    let mut encoded = [0_u8; MAX_LIST_REPLY_BYTES];
    encoded[..2].copy_from_slice(
        &u16::try_from(entries.len())
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    encoded[2..4].copy_from_slice(
        &u16::try_from(LIST_RECORD_BYTES)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    let mut previous = "";
    for (index, entry) in entries.iter().enumerate() {
        validate_name(entry.name)?;
        if index != 0 && previous >= entry.name {
            return Err(EncodingError);
        }
        previous = entry.name;
        let offset = LIST_HEADER_BYTES + index * LIST_RECORD_BYTES;
        encoded[offset] = u8::try_from(entry.name.len()).map_err(|_| EncodingError)?;
        encoded[offset + 1] = entry.filesystem as u8;
        encoded[offset + 2] = entry.access as u8;
        encoded[offset + 3] = entry.activation as u8;
        encoded[offset + 4] = entry.state as u8;
        encoded[offset + 8..offset + 8 + entry.name.len()].copy_from_slice(entry.name.as_bytes());
    }
    output[..count].copy_from_slice(&encoded[..count]);
    Ok(count)
}

/// Decode one exact canonical configured-volume list.
///
/// # Errors
///
/// Rejects every invalid enum, name, order, length, or reserved byte.
pub fn decode_list(bytes: &[u8]) -> Result<VolumeList<'_>, EncodingError> {
    if bytes.len() < LIST_HEADER_BYTES
        || bytes.len() > MAX_LIST_REPLY_BYTES
        || usize::from(read_u16(bytes, 2)?) != LIST_RECORD_BYTES
    {
        return Err(EncodingError);
    }
    let count = usize::from(read_u16(bytes, 0)?);
    let expected = LIST_HEADER_BYTES
        .checked_add(count.checked_mul(LIST_RECORD_BYTES).ok_or(EncodingError)?)
        .ok_or(EncodingError)?;
    if count > MAX_VOLUMES || expected != bytes.len() {
        return Err(EncodingError);
    }
    let mut previous = "";
    for index in 0..count {
        let offset = LIST_HEADER_BYTES + index * LIST_RECORD_BYTES;
        let entry = decode_record(
            bytes
                .get(offset..offset + LIST_RECORD_BYTES)
                .ok_or(EncodingError)?,
        )?;
        if index != 0 && previous >= entry.name {
            return Err(EncodingError);
        }
        previous = entry.name;
    }
    Ok(VolumeList { bytes, count })
}

/// Encode one manifest volume name for activation.
///
/// # Errors
///
/// Rejects invalid names or insufficient output without modifying it.
pub fn encode_activate_request(name: &str, output: &mut [u8]) -> Result<usize, EncodingError> {
    validate_name(name)?;
    let count = 1 + name.len();
    if output.len() < count {
        return Err(EncodingError);
    }
    let mut encoded = [0_u8; MAX_ACTIVATE_REQUEST_BYTES];
    encoded[0] = u8::try_from(name.len()).map_err(|_| EncodingError)?;
    encoded[1..count].copy_from_slice(name.as_bytes());
    output[..count].copy_from_slice(&encoded[..count]);
    Ok(count)
}

/// Decode one exact manifest volume name for activation.
///
/// # Errors
///
/// Rejects malformed lengths, UTF-8, names, or trailing bytes.
pub fn decode_activate_request(bytes: &[u8]) -> Result<&str, EncodingError> {
    let name_bytes = usize::from(*bytes.first().ok_or(EncodingError)?);
    if name_bytes + 1 != bytes.len() {
        return Err(EncodingError);
    }
    let name = str::from_utf8(bytes.get(1..).ok_or(EncodingError)?).map_err(|_| EncodingError)?;
    validate_name(name)?;
    Ok(name)
}

fn decode_record(record: &[u8]) -> Result<VolumeInfo<'_>, EncodingError> {
    if record.len() != LIST_RECORD_BYTES || record[5..8].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    let name_bytes = usize::from(record[0]);
    if name_bytes > MAX_NAME_BYTES || record[8 + name_bytes..].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    let name = str::from_utf8(record.get(8..8 + name_bytes).ok_or(EncodingError)?)
        .map_err(|_| EncodingError)?;
    validate_name(name)?;
    Ok(VolumeInfo {
        name,
        filesystem: match record[1] {
            1 => Filesystem::Fat32,
            2 => Filesystem::Ext4V1,
            _ => return Err(EncodingError),
        },
        access: match record[2] {
            1 => Access::ReadOnly,
            2 => Access::ReadWrite,
            _ => return Err(EncodingError),
        },
        activation: match record[3] {
            1 => Activation::Auto,
            2 => Activation::Manual,
            _ => return Err(EncodingError),
        },
        state: match record[4] {
            1 => State::Unavailable,
            2 => State::Ready,
            3 => State::Mounted,
            4 => State::Failed,
            _ => return Err(EncodingError),
        },
    })
}

fn validate_name(name: &str) -> Result<(), EncodingError> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(EncodingError);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
    let raw = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

#[cfg(test)]
mod tests {
    use crate::volume_control;

    #[test]
    fn volume_control_records_are_canonical_and_bounded() {
        let entries = [
            volume_control::VolumeInfo {
                name: "archive",
                filesystem: volume_control::Filesystem::Ext4V1,
                access: volume_control::Access::ReadOnly,
                activation: volume_control::Activation::Manual,
                state: volume_control::State::Ready,
            },
            volume_control::VolumeInfo {
                name: "root",
                filesystem: volume_control::Filesystem::Ext4V1,
                access: volume_control::Access::ReadWrite,
                activation: volume_control::Activation::Auto,
                state: volume_control::State::Mounted,
            },
        ];
        let mut bytes = [0_u8; volume_control::MAX_LIST_REPLY_BYTES];
        let count = volume_control::encode_list(&entries, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        let decoded =
            volume_control::decode_list(&bytes[..count]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.iter().collect::<std::vec::Vec<_>>(), entries);
        assert!(volume_control::decode_list(&bytes[..count - 1]).is_err());

        let mut request = [0_u8; volume_control::MAX_ACTIVATE_REQUEST_BYTES];
        let request_bytes = volume_control::encode_activate_request("archive", &mut request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            volume_control::decode_activate_request(&request[..request_bytes]),
            Ok("archive")
        );
        assert!(volume_control::decode_activate_request(b"\x04bad/").is_err());
    }
}

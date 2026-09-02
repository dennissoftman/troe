//! Short-name encoding and long-file-name reassembly.

use crate::{DIRECTORY_ENTRY_BYTES, FatEntry, read_u16};
use alloc::format;
use alloc::string::String;
use core::char::decode_utf16;
use troe_fs_api::FsError;

pub(crate) const LFN_UNITS_PER_ENTRY: usize = 13;
pub(crate) const MAX_LFN_ENTRIES: usize = 20;
const MAX_LFN_UNITS: usize = LFN_UNITS_PER_ENTRY * MAX_LFN_ENTRIES;
pub(crate) fn validate_writable_name(name: &str) -> Result<(), FsError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || name
            .chars()
            .any(|character| character <= '\u{1f}' || "\"*/:<>?\\|".contains(character))
    {
        return Err(FsError::Invalid);
    }
    Ok(())
}

pub(crate) fn encode_exact_short_name(name: &str) -> Option<([u8; 11], u8)> {
    let (base, extension) = match name.rsplit_once('.') {
        Some((base, extension)) if !base.is_empty() && !extension.is_empty() => (base, extension),
        Some(_) => return None,
        None => (name, ""),
    };
    if base.len() > 8
        || extension.len() > 3
        || !base.bytes().all(short_name_byte)
        || !extension.bytes().all(short_name_byte)
    {
        return None;
    }
    let base_lower = component_case(base)?;
    let extension_lower = component_case(extension)?;
    let mut raw = [b' '; 11];
    for (destination, source) in raw[..8].iter_mut().zip(base.bytes()) {
        *destination = source.to_ascii_uppercase();
    }
    for (destination, source) in raw[8..].iter_mut().zip(extension.bytes()) {
        *destination = source.to_ascii_uppercase();
    }
    if raw[0] == 0xe5 {
        raw[0] = 0x05;
    }
    Some((
        raw,
        u8::from(base_lower) << 3 | u8::from(extension_lower) << 4,
    ))
}

fn short_name_byte(byte: u8) -> bool {
    byte.is_ascii() && byte > 0x20 && byte != 0x7f && !b"\"*+,./:;<=>?[\\]|".contains(&byte)
}

fn component_case(component: &str) -> Option<bool> {
    let has_lower = component.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = component.bytes().any(|byte| byte.is_ascii_uppercase());
    (!has_lower || !has_upper).then_some(has_lower)
}

pub(crate) fn unique_short_alias(name: &str, entries: &[FatEntry]) -> Result<[u8; 11], FsError> {
    let (base_source, extension_source) = name
        .rsplit_once('.')
        .filter(|(base, extension)| !base.is_empty() && !extension.is_empty())
        .unwrap_or((name, ""));
    let mut base = String::new();
    for character in base_source.chars() {
        if character.is_ascii_alphanumeric() || "$%'-_@~`!(){}^#&".contains(character) {
            base.push(character.to_ascii_uppercase());
        }
    }
    if base.is_empty() {
        base.push_str("FILE");
    }
    let mut extension = String::new();
    for character in extension_source.chars() {
        if extension.len() >= 3 {
            break;
        }
        if character.is_ascii_alphanumeric() || "$%'-_@~`!(){}^#&".contains(character) {
            extension.push(character.to_ascii_uppercase());
        }
    }
    for sequence in 1_u16..=9999 {
        let suffix = format!("~{sequence}");
        let prefix_bytes = 8_usize.checked_sub(suffix.len()).ok_or(FsError::Overflow)?;
        let mut raw = [b' '; 11];
        for (destination, source) in raw[..prefix_bytes].iter_mut().zip(base.bytes()) {
            *destination = source;
        }
        let suffix_start = prefix_bytes.min(base.len());
        raw[suffix_start..suffix_start + suffix.len()].copy_from_slice(suffix.as_bytes());
        for (destination, source) in raw[8..].iter_mut().zip(extension.bytes()) {
            *destination = source;
        }
        if entries.iter().all(|entry| entry.short_name != raw) {
            return Ok(raw);
        }
    }
    Err(FsError::NoSpace)
}
#[derive(Clone, Debug)]
pub(crate) struct LfnState {
    units: [u16; MAX_LFN_UNITS],
    expected: u8,
    checksum: u8,
    pub(crate) active: bool,
}

impl Default for LfnState {
    fn default() -> Self {
        Self {
            units: [0xffff; MAX_LFN_UNITS],
            expected: 0,
            checksum: 0,
            active: false,
        }
    }
}

impl LfnState {
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn push(&mut self, raw: &[u8]) -> Result<(), FsError> {
        if raw.len() != DIRECTORY_ENTRY_BYTES || raw[12] != 0 || read_u16(raw, 26)? != 0 {
            return Err(FsError::Corrupt);
        }
        let sequence = raw[0];
        let ordinal = sequence & 0x1f;
        if ordinal == 0 || usize::from(ordinal) > MAX_LFN_ENTRIES || sequence & 0x80 != 0 {
            return Err(FsError::Corrupt);
        }
        if sequence & 0x40 != 0 {
            if self.active {
                return Err(FsError::Corrupt);
            }
            self.active = true;
            self.expected = ordinal;
            self.checksum = raw[13];
        }
        if !self.active || ordinal != self.expected || raw[13] != self.checksum {
            return Err(FsError::Corrupt);
        }
        let start = usize::from(ordinal - 1) * LFN_UNITS_PER_ENTRY;
        let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (index, offset) in offsets.iter().enumerate() {
            self.units[start + index] = read_u16(raw, *offset)?;
        }
        self.expected -= 1;
        Ok(())
    }

    pub(crate) fn finish(&self, checksum: u8, max_name_bytes: usize) -> Result<String, FsError> {
        if !self.active || self.expected != 0 || self.checksum != checksum {
            return Err(FsError::Corrupt);
        }
        let mut length = self.units.len();
        let mut terminated = false;
        for (index, unit) in self.units.iter().enumerate() {
            if *unit == 0 {
                if !terminated {
                    length = index;
                    terminated = true;
                }
            } else if terminated && *unit != 0xffff {
                return Err(FsError::Corrupt);
            }
        }
        while length > 0 && self.units[length - 1] == 0xffff {
            length -= 1;
        }
        if length == 0 || self.units[..length].contains(&0xffff) {
            return Err(FsError::Corrupt);
        }
        let mut name = String::new();
        name.try_reserve(max_name_bytes)
            .map_err(|_| FsError::NoSpace)?;
        for character in decode_utf16(self.units[..length].iter().copied()) {
            let character = character.map_err(|_| FsError::Corrupt)?;
            if character == '/' || character == '\0' {
                return Err(FsError::Corrupt);
            }
            name.push(character);
            if name.len() > max_name_bytes {
                return Err(FsError::NoSpace);
            }
        }
        Ok(name)
    }
}

pub(crate) fn short_name(raw: &[u8], max_name_bytes: usize) -> Result<String, FsError> {
    let base = short_component(&raw[..8], raw[12] & 0x08 != 0)?;
    let extension = short_component(&raw[8..11], raw[12] & 0x10 != 0)?;
    if base.is_empty() {
        return Err(FsError::Corrupt);
    }
    let name = if extension.is_empty() {
        base
    } else {
        format!("{base}.{extension}")
    };
    if name.len() > max_name_bytes {
        return Err(FsError::NoSpace);
    }
    Ok(name)
}

fn short_component(bytes: &[u8], lowercase: bool) -> Result<String, FsError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != b' ') {
        return Err(FsError::Corrupt);
    }
    let mut output = String::new();
    for byte in &bytes[..end] {
        if !byte.is_ascii() || *byte < 0x20 || b"\"*+,/:;<=>?[\\]|".contains(byte) {
            return Err(FsError::Unsupported);
        }
        output.push(if lowercase {
            char::from(byte.to_ascii_lowercase())
        } else {
            char::from(*byte)
        });
    }
    Ok(output)
}

pub(crate) fn short_name_checksum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

pub(crate) fn names_equal(left: &str, right: &str) -> bool {
    left == right || (left.is_ascii() && right.is_ascii() && left.eq_ignore_ascii_case(right))
}

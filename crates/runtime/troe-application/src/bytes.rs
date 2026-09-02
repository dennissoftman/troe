//! Bounded little-endian scalar reads and writes over artifact bytes.

use crate::ParseError;

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ParseError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ParseError::ArithmeticOverflow)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ParseError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ParseError::ArithmeticOverflow)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ParseError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(ParseError::ArithmeticOverflow)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

pub(crate) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

//! Reflected CRC-32 primitives shared by the on-disk format codecs.
//!
//! Every TROE container format that carries an integrity field uses the same
//! reflected CRC-32: polynomial `0xEDB8_8820` in its reversed `0xEDB8_8320`
//! form, initial value `0xFFFF_FFFF`, and a final one's complement. Formats
//! that store the checksum inside the region it covers compute it with that
//! field zeroed.
//!
//! ext4 metadata checksums use CRC-32C, a different polynomial, and are not
//! served by this crate.
#![no_std]
#![forbid(unsafe_code)]

/// Width of an encoded checksum field.
pub const CHECKSUM_BYTES: usize = 4;

/// Reflected CRC-32 over the complete input.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    crc32_inner(bytes, None)
}

/// Reflected CRC-32 with the four-byte checksum field at `offset` read as zero.
///
/// The field is only masked where it overlaps the input, so an offset at or
/// past the end produces the same value as [`crc32`]. Callers that require the
/// field to be present must validate the bound themselves.
#[must_use]
pub fn crc32_with_zeroed_field(bytes: &[u8], offset: usize) -> u32 {
    crc32_inner(bytes, Some(offset))
}

fn crc32_inner(bytes: &[u8], zero_offset: Option<usize>) -> u32 {
    let mut crc = u32::MAX;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let byte = match zero_offset {
            Some(offset) if index >= offset && index < offset.saturating_add(CHECKSUM_BYTES) => 0,
            _ => byte,
        };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::{crc32, crc32_with_zeroed_field};

    #[test]
    fn matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn zeroed_field_masks_exactly_four_bytes() {
        let mut bytes = *b"0123456789abcdef";
        assert_eq!(
            crc32_with_zeroed_field(&bytes, 4),
            crc32(b"0123\x00\x00\x00\x0089abcdef")
        );
        bytes[4..8].fill(0);
        assert_eq!(crc32_with_zeroed_field(&bytes, 4), crc32(&bytes));
    }

    #[test]
    fn offset_past_the_end_is_a_plain_checksum() {
        let bytes = b"short";
        assert_eq!(crc32_with_zeroed_field(bytes, bytes.len()), crc32(bytes));
        assert_eq!(crc32_with_zeroed_field(bytes, usize::MAX), crc32(bytes));
    }
}

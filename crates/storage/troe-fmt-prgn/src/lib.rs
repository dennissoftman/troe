//! Installed persistence-region selector (PRGN) format.
//!
//! A selector names the exact GPT disk, partition, and partition-type
//! identities that authorize one writable persistence region. It is a pure
//! codec over a fixed 80-byte record: no allocation, no block device, and no
//! knowledge of what is later written into the region it selects.
#![no_std]
#![forbid(unsafe_code)]

/// Product-independent installed persistence-region selector identifier.
pub const REGION_SELECTOR_MAGIC: [u8; 8] = *b"PRGNv1\0\0";
/// Exact encoded size of one persistence-region selector.
pub const REGION_SELECTOR_BYTES: usize = 80;

const CHECKSUM_OFFSET: usize = 20;

/// Exact GPT identities required to grant one writable persistence region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSelector {
    disk: [u8; 16],
    partition: [u8; 16],
    partition_type: [u8; 16],
}

impl RegionSelector {
    /// Parse one canonical PRGN v1 selector.
    ///
    /// # Errors
    ///
    /// Rejects every non-exact length, magic/version/header mismatch, checksum
    /// failure, nonzero reserved byte, and all-zero GPT identifier.
    pub fn parse(bytes: &[u8]) -> Result<Self, SelectorError> {
        if bytes.len() != REGION_SELECTOR_BYTES {
            return Err(SelectorError::WrongLength);
        }
        if bytes.get(..8) != Some(&REGION_SELECTOR_MAGIC)
            || read_u16_selector(bytes, 8)? != 1
            || read_u16_selector(bytes, 10)? != 0
            || usize::from(read_u16_selector(bytes, 12)?) != REGION_SELECTOR_BYTES
            || read_u16_selector(bytes, 14)? != 0
            || usize::try_from(read_u32_selector(bytes, 16)?)
                .map_err(|_| SelectorError::InvalidHeader)?
                != REGION_SELECTOR_BYTES
        {
            return Err(SelectorError::InvalidHeader);
        }
        if crc32_zeroed_checksum(bytes) != read_u32_selector(bytes, CHECKSUM_OFFSET)? {
            return Err(SelectorError::Checksum);
        }
        if bytes[72..].iter().any(|byte| *byte != 0) {
            return Err(SelectorError::Reserved);
        }
        let disk_guid = copy_guid(bytes, 24)?;
        let partition_guid = copy_guid(bytes, 40)?;
        let partition_type_guid = copy_guid(bytes, 56)?;
        if disk_guid.iter().all(|byte| *byte == 0)
            || partition_guid.iter().all(|byte| *byte == 0)
            || partition_type_guid.iter().all(|byte| *byte == 0)
        {
            return Err(SelectorError::ZeroIdentifier);
        }
        Ok(Self {
            disk: disk_guid,
            partition: partition_guid,
            partition_type: partition_type_guid,
        })
    }

    /// Exact GPT disk GUID bytes.
    #[must_use]
    pub const fn disk_guid(self) -> [u8; 16] {
        self.disk
    }

    /// Exact GPT unique partition GUID bytes.
    #[must_use]
    pub const fn partition_guid(self) -> [u8; 16] {
        self.partition
    }

    /// Exact GPT partition type GUID bytes.
    #[must_use]
    pub const fn partition_type_guid(self) -> [u8; 16] {
        self.partition_type
    }
}

/// Stable PRGN selector parse failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorError {
    /// Encoded input was not exactly 80 bytes.
    WrongLength,
    /// Magic, version, header size, flags, or total size was invalid.
    InvalidHeader,
    /// CRC32 did not cover the canonical complete selector.
    Checksum,
    /// A reserved byte was nonzero.
    Reserved,
    /// A required GPT identity was all zero.
    ZeroIdentifier,
}

fn read_u16_selector(bytes: &[u8], offset: usize) -> Result<u16, SelectorError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(SelectorError::InvalidHeader)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32_selector(bytes: &[u8], offset: usize) -> Result<u32, SelectorError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(SelectorError::InvalidHeader)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn copy_guid(bytes: &[u8], offset: usize) -> Result<[u8; 16], SelectorError> {
    let mut guid = [0_u8; 16];
    guid.copy_from_slice(
        bytes
            .get(offset..offset + 16)
            .ok_or(SelectorError::InvalidHeader)?,
    );
    Ok(guid)
}

fn crc32_zeroed_checksum(bytes: &[u8]) -> u32 {
    troe_checksum::crc32_with_zeroed_field(bytes, CHECKSUM_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::{
        CHECKSUM_OFFSET, REGION_SELECTOR_BYTES, REGION_SELECTOR_MAGIC, RegionSelector,
        SelectorError, crc32_zeroed_checksum,
    };

    fn selector_bytes() -> [u8; REGION_SELECTOR_BYTES] {
        let mut bytes = [0_u8; REGION_SELECTOR_BYTES];
        bytes[..8].copy_from_slice(&REGION_SELECTOR_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[12..14].copy_from_slice(&80_u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&80_u32.to_le_bytes());
        bytes[24..40].copy_from_slice(&[1; 16]);
        bytes[40..56].copy_from_slice(&[2; 16]);
        bytes[56..72].copy_from_slice(&[3; 16]);
        let checksum = crc32_zeroed_checksum(&bytes);
        bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }

    #[test]
    fn region_selector_is_exact_and_product_independent() -> Result<(), SelectorError> {
        let bytes = selector_bytes();
        let selector = RegionSelector::parse(&bytes)?;
        assert_eq!(selector.disk_guid(), [1; 16]);
        assert_eq!(selector.partition_guid(), [2; 16]);
        assert_eq!(selector.partition_type_guid(), [3; 16]);
        assert!(!REGION_SELECTOR_MAGIC.windows(4).any(|part| part == b"TROE"));
        for length in 0..REGION_SELECTOR_BYTES {
            assert_eq!(
                RegionSelector::parse(&bytes[..length]),
                Err(SelectorError::WrongLength)
            );
        }
        Ok(())
    }

    #[test]
    fn region_selector_checksum_reserved_and_identities_fail_closed() {
        let mut checksum = selector_bytes();
        checksum[40] ^= 1;
        assert_eq!(
            RegionSelector::parse(&checksum),
            Err(SelectorError::Checksum)
        );

        for range in [24..40, 40..56, 56..72] {
            let mut zero = selector_bytes();
            zero[range].fill(0);
            let crc = crc32_zeroed_checksum(&zero);
            zero[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
            assert_eq!(
                RegionSelector::parse(&zero),
                Err(SelectorError::ZeroIdentifier)
            );
        }

        let mut reserved = selector_bytes();
        reserved[79] = 1;
        let crc = crc32_zeroed_checksum(&reserved);
        reserved[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            RegionSelector::parse(&reserved),
            Err(SelectorError::Reserved)
        );
    }
}

//! Capability-scoped private anonymous memory protocol.

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 0;
/// Reserve inaccessible virtual address space without backing frames.
pub const RESERVE: u16 = 1;
/// Map a new zeroed private range.
pub const MAP_ZEROED: u16 = 2;
/// Change access over one complete owned range.
pub const PROTECT: u16 = 3;
/// Remove one complete or partial owned range.
pub const UNMAP: u16 = 4;
/// Read the caller's granted policy and live accounting.
pub const QUERY: u16 = 5;
/// Exact map or reservation request bytes.
pub const MAP_REQUEST_BYTES: usize = 32;
/// Exact protection request bytes.
pub const PROTECT_REQUEST_BYTES: usize = 24;
/// Exact unmap request bytes.
pub const UNMAP_REQUEST_BYTES: usize = 16;
/// Exact successful address reply bytes.
pub const ADDRESS_REPLY_BYTES: usize = 8;
/// Exact policy and accounting reply bytes.
pub const STATISTICS_REPLY_BYTES: usize = 112;
/// Query flag indicating a configured committed-page ceiling.
pub const COMMITTED_LIMITED: u64 = 1 << 0;
/// Query flag indicating a configured reserved-page ceiling.
pub const RESERVED_LIMITED: u64 = 1 << 1;
const KNOWN_STATISTICS_FLAGS: u64 = COMMITTED_LIMITED | RESERVED_LIMITED;

/// Page access accepted by the private-memory mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Protection {
    /// No user-mode access; backing, when present, remains owned.
    None = 0,
    /// Read-only, non-executable data.
    Read = 1,
    /// Read/write, non-executable data.
    ReadWrite = 2,
}

impl Protection {
    fn decode(value: u8) -> Result<Self, EncodingError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Read),
            2 => Ok(Self::ReadWrite),
            _ => Err(EncodingError),
        }
    }
}

/// Invalid, excessive, or noncanonical private-memory bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// One page-aligned reservation or zeroed-map request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapRequest {
    /// Nonzero number of 4 KiB pages.
    pub page_count: u64,
    /// Nonzero power-of-two alignment in pages.
    pub alignment_pages: u64,
    /// Optional page-aligned placement hint; zero selects no hint.
    pub address_hint: u64,
    /// Initial page access.
    pub protection: Protection,
}

/// One page-aligned protection change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectRequest {
    /// Start of an owned private range.
    pub address: u64,
    /// Nonzero number of 4 KiB pages.
    pub page_count: u64,
    /// Replacement page access.
    pub protection: Protection,
}

/// One page-aligned unmap request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnmapRequest {
    /// Start of an owned private range.
    pub address: u64,
    /// Nonzero number of 4 KiB pages.
    pub page_count: u64,
}

/// Granted limits and current/high-water private-memory use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Statistics {
    /// [`COMMITTED_LIMITED`] and [`RESERVED_LIMITED`].
    pub flags: u64,
    /// Configured committed-page maximum, or zero when not limited.
    pub maximum_committed_pages: u64,
    /// Configured reserved-page maximum, or zero when not limited.
    pub maximum_reserved_pages: u64,
    /// Mandatory maximum normalized mapping records.
    pub maximum_mappings: u64,
    /// Mandatory maximum charged metadata bytes.
    pub maximum_metadata_bytes: u64,
    /// Maximum pages processed by one bounded mutating call.
    pub operation_quantum_pages: u64,
    /// Currently reserved private pages.
    pub reserved_pages: u64,
    /// Currently committed private pages.
    pub committed_pages: u64,
    /// Currently retained normalized mapping records.
    pub mappings: u64,
    /// Currently charged metadata bytes.
    pub metadata_bytes: u64,
    /// Peak reserved private pages.
    pub high_water_reserved_pages: u64,
    /// Peak committed private pages.
    pub high_water_committed_pages: u64,
    /// Peak normalized mapping records.
    pub high_water_mappings: u64,
    /// Peak charged metadata bytes.
    pub high_water_metadata_bytes: u64,
}

/// Encode one exact map or reservation request.
///
/// # Errors
///
/// Rejects zero counts, non-power-of-two alignment, or an unaligned hint.
pub fn encode_map_request(request: MapRequest) -> Result<[u8; MAP_REQUEST_BYTES], EncodingError> {
    if request.page_count == 0
        || request.alignment_pages == 0
        || !request.alignment_pages.is_power_of_two()
        || (request.address_hint != 0 && !request.address_hint.is_multiple_of(4096))
    {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; MAP_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&request.page_count.to_le_bytes());
    bytes[8..16].copy_from_slice(&request.alignment_pages.to_le_bytes());
    bytes[16..24].copy_from_slice(&request.address_hint.to_le_bytes());
    bytes[24] = request.protection as u8;
    Ok(bytes)
}

/// Decode one exact canonical map or reservation request.
///
/// # Errors
///
/// Rejects truncation, trailing bytes, invalid scalars, and nonzero reserve.
pub fn decode_map_request(bytes: &[u8]) -> Result<MapRequest, EncodingError> {
    if bytes.len() != MAP_REQUEST_BYTES || bytes[25..].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    let request = MapRequest {
        page_count: read_u64(bytes, 0)?,
        alignment_pages: read_u64(bytes, 8)?,
        address_hint: read_u64(bytes, 16)?,
        protection: Protection::decode(bytes[24])?,
    };
    if request.page_count == 0
        || request.alignment_pages == 0
        || !request.alignment_pages.is_power_of_two()
        || (request.address_hint != 0 && !request.address_hint.is_multiple_of(4096))
    {
        return Err(EncodingError);
    }
    Ok(request)
}

/// Encode one exact protection request.
///
/// # Errors
///
/// Rejects zero, unaligned, or overflowing ranges.
pub fn encode_protect_request(
    request: ProtectRequest,
) -> Result<[u8; PROTECT_REQUEST_BYTES], EncodingError> {
    validate_range(request.address, request.page_count)?;
    let mut bytes = [0_u8; PROTECT_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&request.address.to_le_bytes());
    bytes[8..16].copy_from_slice(&request.page_count.to_le_bytes());
    bytes[16] = request.protection as u8;
    Ok(bytes)
}

/// Decode one exact canonical protection request.
///
/// # Errors
///
/// Rejects truncation, trailing bytes, reserved fields, or invalid ranges.
pub fn decode_protect_request(bytes: &[u8]) -> Result<ProtectRequest, EncodingError> {
    if bytes.len() != PROTECT_REQUEST_BYTES || bytes[17..].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    let request = ProtectRequest {
        address: read_u64(bytes, 0)?,
        page_count: read_u64(bytes, 8)?,
        protection: Protection::decode(bytes[16])?,
    };
    validate_range(request.address, request.page_count)?;
    Ok(request)
}

/// Encode one exact unmap request.
///
/// # Errors
///
/// Rejects zero, unaligned, or overflowing ranges.
pub fn encode_unmap_request(
    request: UnmapRequest,
) -> Result<[u8; UNMAP_REQUEST_BYTES], EncodingError> {
    validate_range(request.address, request.page_count)?;
    let mut bytes = [0_u8; UNMAP_REQUEST_BYTES];
    bytes[0..8].copy_from_slice(&request.address.to_le_bytes());
    bytes[8..16].copy_from_slice(&request.page_count.to_le_bytes());
    Ok(bytes)
}

/// Decode one exact canonical unmap request.
///
/// # Errors
///
/// Rejects truncation, trailing bytes, or invalid ranges.
pub fn decode_unmap_request(bytes: &[u8]) -> Result<UnmapRequest, EncodingError> {
    if bytes.len() != UNMAP_REQUEST_BYTES {
        return Err(EncodingError);
    }
    let request = UnmapRequest {
        address: read_u64(bytes, 0)?,
        page_count: read_u64(bytes, 8)?,
    };
    validate_range(request.address, request.page_count)?;
    Ok(request)
}

/// Encode one successful mapped address.
///
/// # Errors
///
/// Rejects zero or non-page-aligned addresses.
pub fn encode_address(address: u64) -> Result<[u8; ADDRESS_REPLY_BYTES], EncodingError> {
    if address == 0 || !address.is_multiple_of(4096) {
        return Err(EncodingError);
    }
    Ok(address.to_le_bytes())
}

/// Decode one exact successful mapped address.
///
/// # Errors
///
/// Rejects truncation, trailing bytes, zero, or unaligned addresses.
pub fn decode_address(bytes: &[u8]) -> Result<u64, EncodingError> {
    if bytes.len() != ADDRESS_REPLY_BYTES {
        return Err(EncodingError);
    }
    let address = read_u64(bytes, 0)?;
    if address == 0 || !address.is_multiple_of(4096) {
        return Err(EncodingError);
    }
    Ok(address)
}

/// Encode one canonical statistics reply.
///
/// # Errors
///
/// Rejects unknown flags, inconsistent limits, or invalid accounting.
pub fn encode_statistics(
    statistics: Statistics,
) -> Result<[u8; STATISTICS_REPLY_BYTES], EncodingError> {
    validate_statistics(statistics)?;
    let values = [
        statistics.flags,
        statistics.maximum_committed_pages,
        statistics.maximum_reserved_pages,
        statistics.maximum_mappings,
        statistics.maximum_metadata_bytes,
        statistics.operation_quantum_pages,
        statistics.reserved_pages,
        statistics.committed_pages,
        statistics.mappings,
        statistics.metadata_bytes,
        statistics.high_water_reserved_pages,
        statistics.high_water_committed_pages,
        statistics.high_water_mappings,
        statistics.high_water_metadata_bytes,
    ];
    let mut bytes = [0_u8; STATISTICS_REPLY_BYTES];
    for (index, value) in values.into_iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(bytes)
}

/// Decode one exact canonical statistics reply.
///
/// # Errors
///
/// Rejects truncation, trailing bytes, inconsistent limits, or accounting.
pub fn decode_statistics(bytes: &[u8]) -> Result<Statistics, EncodingError> {
    if bytes.len() != STATISTICS_REPLY_BYTES {
        return Err(EncodingError);
    }
    let statistics = Statistics {
        flags: read_u64(bytes, 0)?,
        maximum_committed_pages: read_u64(bytes, 8)?,
        maximum_reserved_pages: read_u64(bytes, 16)?,
        maximum_mappings: read_u64(bytes, 24)?,
        maximum_metadata_bytes: read_u64(bytes, 32)?,
        operation_quantum_pages: read_u64(bytes, 40)?,
        reserved_pages: read_u64(bytes, 48)?,
        committed_pages: read_u64(bytes, 56)?,
        mappings: read_u64(bytes, 64)?,
        metadata_bytes: read_u64(bytes, 72)?,
        high_water_reserved_pages: read_u64(bytes, 80)?,
        high_water_committed_pages: read_u64(bytes, 88)?,
        high_water_mappings: read_u64(bytes, 96)?,
        high_water_metadata_bytes: read_u64(bytes, 104)?,
    };
    validate_statistics(statistics)?;
    Ok(statistics)
}

fn validate_range(address: u64, page_count: u64) -> Result<(), EncodingError> {
    if address == 0
        || !address.is_multiple_of(4096)
        || page_count == 0
        || page_count
            .checked_mul(4096)
            .and_then(|bytes| address.checked_add(bytes))
            .is_none()
    {
        return Err(EncodingError);
    }
    Ok(())
}

fn validate_statistics(statistics: Statistics) -> Result<(), EncodingError> {
    if statistics.flags & !KNOWN_STATISTICS_FLAGS != 0
        || (statistics.flags & COMMITTED_LIMITED != 0) != (statistics.maximum_committed_pages != 0)
        || (statistics.flags & RESERVED_LIMITED != 0) != (statistics.maximum_reserved_pages != 0)
        || statistics.maximum_mappings == 0
        || statistics.maximum_metadata_bytes == 0
        || statistics.operation_quantum_pages == 0
        || statistics.committed_pages > statistics.reserved_pages
        || statistics.mappings > statistics.maximum_mappings
        || statistics.metadata_bytes > statistics.maximum_metadata_bytes
        || statistics.high_water_reserved_pages < statistics.reserved_pages
        || statistics.high_water_committed_pages < statistics.committed_pages
        || statistics.high_water_mappings < statistics.mappings
        || statistics.high_water_metadata_bytes < statistics.metadata_bytes
        || (statistics.maximum_committed_pages != 0
            && (statistics.committed_pages > statistics.maximum_committed_pages
                || statistics.high_water_committed_pages > statistics.maximum_committed_pages))
        || (statistics.maximum_reserved_pages != 0
            && (statistics.reserved_pages > statistics.maximum_reserved_pages
                || statistics.high_water_reserved_pages > statistics.maximum_reserved_pages))
    {
        return Err(EncodingError);
    }
    Ok(())
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EncodingError> {
    let raw = bytes.get(offset..offset + 8).ok_or(EncodingError)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg(test)]
mod tests {
    use crate::private_memory;

    #[test]
    fn private_memory_records_are_exact_full_width_and_canonical() {
        let mapping = private_memory::MapRequest {
            page_count: u64::from(u32::MAX) + 17,
            alignment_pages: 512,
            address_hint: 0x7000_0000_0000,
            protection: private_memory::Protection::ReadWrite,
        };
        let bytes =
            private_memory::encode_map_request(mapping).unwrap_or_else(|_| std::process::abort());
        assert_eq!(private_memory::decode_map_request(&bytes), Ok(mapping));
        for end in 0..bytes.len() {
            assert!(private_memory::decode_map_request(&bytes[..end]).is_err());
        }
        let mut reserved = bytes;
        reserved[31] = 1;
        assert!(private_memory::decode_map_request(&reserved).is_err());

        let protection = private_memory::ProtectRequest {
            address: mapping.address_hint,
            page_count: mapping.page_count,
            protection: private_memory::Protection::None,
        };
        let bytes = private_memory::encode_protect_request(protection)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            private_memory::decode_protect_request(&bytes),
            Ok(protection)
        );
        let unmap = private_memory::UnmapRequest {
            address: mapping.address_hint,
            page_count: mapping.page_count,
        };
        let bytes =
            private_memory::encode_unmap_request(unmap).unwrap_or_else(|_| std::process::abort());
        assert_eq!(private_memory::decode_unmap_request(&bytes), Ok(unmap));
        assert!(
            private_memory::encode_unmap_request(private_memory::UnmapRequest {
                address: mapping.address_hint + 1,
                page_count: 1,
            })
            .is_err()
        );

        let statistics = private_memory::Statistics {
            flags: private_memory::COMMITTED_LIMITED,
            maximum_committed_pages: u64::from(u32::MAX) + 1,
            maximum_reserved_pages: 0,
            maximum_mappings: 65_536,
            maximum_metadata_bytes: 8 * 1024 * 1024,
            operation_quantum_pages: 256,
            reserved_pages: 4096,
            committed_pages: 2048,
            mappings: 7,
            metadata_bytes: 1024,
            high_water_reserved_pages: 8192,
            high_water_committed_pages: 4096,
            high_water_mappings: 9,
            high_water_metadata_bytes: 2048,
        };
        let bytes =
            private_memory::encode_statistics(statistics).unwrap_or_else(|_| std::process::abort());
        assert_eq!(private_memory::decode_statistics(&bytes), Ok(statistics));
        assert!(private_memory::decode_statistics(&bytes[..bytes.len() - 1]).is_err());
    }
}

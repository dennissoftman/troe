//! Strict, bounded, read-only GPT discovery over block-region capabilities.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::char::decode_utf16;
use troe_block::{BlockDevice, BlockError, BlockRegion};

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_REVISION_1_0: u32 = 0x0001_0000;
const GPT_HEADER_BYTES: usize = 92;
const GPT_HEADER_BYTES_U32: u32 = 92;
const GPT_ENTRY_BYTES: u32 = 128;
const GPT_NAME_UNITS: usize = 36;
const PROTECTIVE_MBR_BYTES: usize = 512;
const PROTECTIVE_MBR_BYTES_U32: u32 = 512;
const MAX_GPT_ENTRIES: u32 = 256;
const MAX_GPT_ARRAY_BYTES: usize = 64 * 1024;

/// Resource ceilings applied before retaining partition metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptLimits {
    entries: u32,
    entry_array_bytes: usize,
    partitions: u16,
}

impl GptLimits {
    /// Construct checked GPT discovery ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero values, limits above the hard parser profile, an array too
    /// small for one canonical entry, or more retained partitions than entries.
    pub const fn new(
        max_entries: u32,
        max_entry_array_bytes: usize,
        max_partitions: u16,
    ) -> Result<Self, GptError> {
        if max_entries == 0
            || max_entries > MAX_GPT_ENTRIES
            || max_entry_array_bytes < GPT_ENTRY_BYTES as usize
            || max_entry_array_bytes > MAX_GPT_ARRAY_BYTES
            || max_partitions == 0
            || max_partitions as u32 > max_entries
        {
            return Err(GptError::InvalidLimits);
        }
        Ok(Self {
            entries: max_entries,
            entry_array_bytes: max_entry_array_bytes,
            partitions: max_partitions,
        })
    }

    /// Maximum encoded entries accepted from either GPT copy.
    #[must_use]
    pub const fn max_entries(self) -> u32 {
        self.entries
    }

    /// Maximum exact bytes covered by one entry-array checksum.
    #[must_use]
    pub const fn max_entry_array_bytes(self) -> usize {
        self.entry_array_bytes
    }

    /// Maximum live partition records retained after validation.
    #[must_use]
    pub const fn max_partitions(self) -> u16 {
        self.partitions
    }
}

/// An opaque GPT GUID retained in its exact 16-byte on-disk representation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GptGuid([u8; 16]);

impl GptGuid {
    /// Construct a GUID from its exact GPT field bytes.
    #[must_use]
    pub const fn from_disk_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the exact GPT field bytes without applying display endianness.
    #[must_use]
    pub const fn disk_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Whether this is the reserved all-zero unused identifier.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// One fully validated used GPT entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GptPartition {
    type_guid: GptGuid,
    unique_guid: GptGuid,
    first_lba: u64,
    last_lba: u64,
    attributes: u64,
    name: [u16; GPT_NAME_UNITS],
    name_units: u8,
}

impl GptPartition {
    /// Partition type identifier.
    #[must_use]
    pub const fn type_guid(&self) -> GptGuid {
        self.type_guid
    }

    /// Unique partition identifier.
    #[must_use]
    pub const fn unique_guid(&self) -> GptGuid {
        self.unique_guid
    }

    /// First region-relative logical block, inclusive.
    #[must_use]
    pub const fn first_lba(&self) -> u64 {
        self.first_lba
    }

    /// Last region-relative logical block, inclusive.
    #[must_use]
    pub const fn last_lba(&self) -> u64 {
        self.last_lba
    }

    /// Exact GPT attribute bits retained for later mount policy.
    #[must_use]
    pub const fn attributes(&self) -> u64 {
        self.attributes
    }

    /// Validated, NUL-trimmed UTF-16 partition name units.
    #[must_use]
    pub fn name_utf16(&self) -> &[u16] {
        &self.name[..usize::from(self.name_units)]
    }

    /// Exact partition length in logical blocks.
    #[must_use]
    pub const fn block_count(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

/// A complete primary/backup-consistent GPT discovery result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GptDisk {
    disk_guid: GptGuid,
    first_usable_lba: u64,
    last_usable_lba: u64,
    partitions: Vec<GptPartition>,
}

impl GptDisk {
    /// Disk identifier shared by both GPT headers.
    #[must_use]
    pub const fn disk_guid(&self) -> GptGuid {
        self.disk_guid
    }

    /// First usable partition block, inclusive.
    #[must_use]
    pub const fn first_usable_lba(&self) -> u64 {
        self.first_usable_lba
    }

    /// Last usable partition block, inclusive.
    #[must_use]
    pub const fn last_usable_lba(&self) -> u64 {
        self.last_usable_lba
    }

    /// Used entries sorted by first LBA after overlap validation.
    #[must_use]
    pub fn partitions(&self) -> &[GptPartition] {
        &self.partitions
    }

    /// Find exactly one partition by its validated unique identifier.
    #[must_use]
    pub fn partition_by_unique_guid(&self, guid: GptGuid) -> Option<&GptPartition> {
        self.partitions
            .iter()
            .find(|partition| partition.unique_guid == guid)
    }
}

/// Stable GPT discovery failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GptError {
    /// Parser limits are empty or outside the hard profile.
    InvalidLimits,
    /// Region geometry cannot support strict one-block metadata reads.
    UnsupportedGeometry,
    /// The protective MBR is missing, hybrid, or noncanonical.
    InvalidProtectiveMbr,
    /// A GPT header field or metadata placement is invalid.
    InvalidHeader,
    /// A GPT header checksum does not cover its canonical bytes.
    HeaderChecksum,
    /// Entry count, size, location, or retained count exceeds policy.
    InvalidEntryLayout,
    /// A partition-entry-array checksum does not match.
    EntryChecksum,
    /// Primary and backup GPT metadata are both valid but inconsistent.
    InconsistentCopies,
    /// A used or unused partition entry is malformed or noncanonical.
    InvalidPartition,
    /// Two used partition ranges overlap.
    OverlappingPartitions,
    /// Two used entries carry the same nonzero unique identifier.
    DuplicateIdentifier,
    /// Bounded parser allocation failed.
    MetadataExhausted,
    /// The checked block capability rejected or failed a read.
    Block(BlockError),
}

impl From<BlockError> for GptError {
    fn from(error: BlockError) -> Self {
        Self::Block(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GptHeader {
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: GptGuid,
    entry_lba: u64,
    entry_count: u32,
    entry_bytes: u32,
    entry_crc32: u32,
}

/// Discover and validate one complete GPT without mutating media.
///
/// The supplied capability is treated as a whole-device namespace: all LBAs in
/// the result are relative to that region, and no read can escape it.
///
/// # Errors
///
/// Rejects unsupported geometry, invalid protective MBR or GPT fields,
/// checksum failures, inconsistent copies, malformed entries, duplicate IDs,
/// overlaps, resource exhaustion, and block-read failures.
pub fn discover<D: BlockDevice>(
    region: &mut BlockRegion<D>,
    limits: GptLimits,
) -> Result<GptDisk, GptError> {
    validate_limits(limits)?;
    let info = region.info();
    if info.required_alignment_blocks() != 1
        || info.block_count() < 6
        || info.block_bytes() < PROTECTIVE_MBR_BYTES_U32
    {
        return Err(GptError::UnsupportedGeometry);
    }
    let block_bytes =
        usize::try_from(info.block_bytes()).map_err(|_| GptError::UnsupportedGeometry)?;
    let last_lba = info
        .block_count()
        .checked_sub(1)
        .ok_or(GptError::UnsupportedGeometry)?;

    let protective = read_one_block(region, 0, block_bytes)?;
    validate_protective_mbr(&protective, last_lba)?;

    let primary_block = read_one_block(region, 1, block_bytes)?;
    let primary = parse_header(&primary_block, 1, last_lba, limits, block_bytes)?;
    let backup_block = read_one_block(region, last_lba, block_bytes)?;
    let backup = parse_header(&backup_block, last_lba, 1, limits, block_bytes)?;
    validate_header_placement(primary, true, last_lba, block_bytes)?;
    validate_header_placement(backup, false, last_lba, block_bytes)?;
    validate_consistency(primary, backup)?;

    let primary_entries = read_entry_array(region, primary, limits, block_bytes)?;
    if crc32(&primary_entries) != primary.entry_crc32 {
        return Err(GptError::EntryChecksum);
    }
    let backup_entries = read_entry_array(region, backup, limits, block_bytes)?;
    if crc32(&backup_entries) != backup.entry_crc32 {
        return Err(GptError::EntryChecksum);
    }
    if primary_entries != backup_entries {
        return Err(GptError::InconsistentCopies);
    }

    let partitions = parse_partitions(&primary_entries, primary, limits)?;
    Ok(GptDisk {
        disk_guid: primary.disk_guid,
        first_usable_lba: primary.first_usable_lba,
        last_usable_lba: primary.last_usable_lba,
        partitions,
    })
}

fn validate_limits(limits: GptLimits) -> Result<(), GptError> {
    GptLimits::new(
        limits.max_entries(),
        limits.max_entry_array_bytes(),
        limits.max_partitions(),
    )
    .map(|_| ())
}

fn read_one_block<D: BlockDevice>(
    region: &mut BlockRegion<D>,
    lba: u64,
    block_bytes: usize,
) -> Result<Vec<u8>, GptError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(block_bytes)
        .map_err(|_| GptError::MetadataExhausted)?;
    bytes.resize(block_bytes, 0);
    region.read_blocks(lba, 1, &mut bytes)?;
    Ok(bytes)
}

fn validate_protective_mbr(block: &[u8], last_lba: u64) -> Result<(), GptError> {
    if block.len() < PROTECTIVE_MBR_BYTES || block[510..512] != [0x55, 0xaa] {
        return Err(GptError::InvalidProtectiveMbr);
    }
    let expected_sectors = last_lba.min(u64::from(u32::MAX));
    let expected_sectors =
        u32::try_from(expected_sectors).map_err(|_| GptError::InvalidProtectiveMbr)?;
    let mut protective_count = 0_u8;
    for index in 0..4 {
        let offset = 446 + index * 16;
        let entry = block
            .get(offset..offset + 16)
            .ok_or(GptError::InvalidProtectiveMbr)?;
        if entry.iter().all(|byte| *byte == 0) {
            continue;
        }
        if entry[0] != 0
            || entry[4] != 0xee
            || read_u32(entry, 8)? != 1
            || read_u32(entry, 12)? != expected_sectors
        {
            return Err(GptError::InvalidProtectiveMbr);
        }
        protective_count = protective_count
            .checked_add(1)
            .ok_or(GptError::InvalidProtectiveMbr)?;
    }
    if protective_count != 1 {
        return Err(GptError::InvalidProtectiveMbr);
    }
    Ok(())
}

fn parse_header(
    block: &[u8],
    expected_current_lba: u64,
    expected_backup_lba: u64,
    limits: GptLimits,
    block_bytes: usize,
) -> Result<GptHeader, GptError> {
    if block.len() != block_bytes
        || block.get(..8) != Some(GPT_SIGNATURE)
        || read_u32(block, 8)? != GPT_REVISION_1_0
        || read_u32(block, 12)? != GPT_HEADER_BYTES_U32
        || read_u32(block, 20)? != 0
        || block
            .get(GPT_HEADER_BYTES..)
            .ok_or(GptError::InvalidHeader)?
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(GptError::InvalidHeader);
    }
    let expected_crc = read_u32(block, 16)?;
    let mut header_bytes = [0_u8; GPT_HEADER_BYTES];
    header_bytes.copy_from_slice(
        block
            .get(..GPT_HEADER_BYTES)
            .ok_or(GptError::InvalidHeader)?,
    );
    header_bytes[16..20].fill(0);
    if crc32(&header_bytes) != expected_crc {
        return Err(GptError::HeaderChecksum);
    }
    let current_lba = read_u64(block, 24)?;
    let backup_lba = read_u64(block, 32)?;
    let disk_guid = GptGuid(copy_array_16(block, 56)?);
    let entry_count = read_u32(block, 80)?;
    let entry_bytes = read_u32(block, 84)?;
    let entry_array_bytes = usize::try_from(entry_count)
        .ok()
        .and_then(|count| count.checked_mul(usize::try_from(entry_bytes).ok()?))
        .ok_or(GptError::InvalidEntryLayout)?;
    if current_lba != expected_current_lba
        || backup_lba != expected_backup_lba
        || disk_guid.is_zero()
        || entry_count == 0
        || entry_count > limits.max_entries()
        || entry_bytes != GPT_ENTRY_BYTES
        || entry_array_bytes > limits.max_entry_array_bytes()
    {
        return Err(GptError::InvalidEntryLayout);
    }
    Ok(GptHeader {
        current_lba,
        backup_lba,
        first_usable_lba: read_u64(block, 40)?,
        last_usable_lba: read_u64(block, 48)?,
        disk_guid,
        entry_lba: read_u64(block, 72)?,
        entry_count,
        entry_bytes,
        entry_crc32: read_u32(block, 88)?,
    })
}

fn validate_header_placement(
    header: GptHeader,
    primary: bool,
    last_lba: u64,
    block_bytes: usize,
) -> Result<(), GptError> {
    if header.first_usable_lba > header.last_usable_lba || header.last_usable_lba >= last_lba {
        return Err(GptError::InvalidHeader);
    }
    let array_bytes = u64::from(header.entry_count)
        .checked_mul(u64::from(header.entry_bytes))
        .ok_or(GptError::InvalidEntryLayout)?;
    let block_bytes = u64::try_from(block_bytes).map_err(|_| GptError::InvalidEntryLayout)?;
    let array_blocks = array_bytes
        .checked_add(block_bytes - 1)
        .ok_or(GptError::InvalidEntryLayout)?
        / block_bytes;
    let array_end = header
        .entry_lba
        .checked_add(array_blocks)
        .ok_or(GptError::InvalidEntryLayout)?;
    if primary {
        if header.entry_lba <= header.current_lba || array_end > header.first_usable_lba {
            return Err(GptError::InvalidEntryLayout);
        }
    } else if header.entry_lba <= header.last_usable_lba || array_end > header.current_lba {
        return Err(GptError::InvalidEntryLayout);
    }
    Ok(())
}

fn validate_consistency(primary: GptHeader, backup: GptHeader) -> Result<(), GptError> {
    if primary.current_lba != backup.backup_lba
        || primary.backup_lba != backup.current_lba
        || primary.first_usable_lba != backup.first_usable_lba
        || primary.last_usable_lba != backup.last_usable_lba
        || primary.disk_guid != backup.disk_guid
        || primary.entry_count != backup.entry_count
        || primary.entry_bytes != backup.entry_bytes
        || primary.entry_crc32 != backup.entry_crc32
        || primary.entry_lba == backup.entry_lba
    {
        return Err(GptError::InconsistentCopies);
    }
    Ok(())
}

fn read_entry_array<D: BlockDevice>(
    region: &mut BlockRegion<D>,
    header: GptHeader,
    limits: GptLimits,
    block_bytes: usize,
) -> Result<Vec<u8>, GptError> {
    let exact_bytes = usize::try_from(header.entry_count)
        .ok()
        .and_then(|count| count.checked_mul(usize::try_from(header.entry_bytes).ok()?))
        .ok_or(GptError::InvalidEntryLayout)?;
    if exact_bytes > limits.max_entry_array_bytes() {
        return Err(GptError::InvalidEntryLayout);
    }
    let stored_bytes = exact_bytes
        .checked_add(block_bytes - 1)
        .ok_or(GptError::InvalidEntryLayout)?
        / block_bytes
        * block_bytes;
    let blocks = stored_bytes / block_bytes;
    let mut stored = Vec::new();
    stored
        .try_reserve_exact(stored_bytes)
        .map_err(|_| GptError::MetadataExhausted)?;
    stored.resize(stored_bytes, 0);
    for index in 0..blocks {
        let lba = header
            .entry_lba
            .checked_add(u64::try_from(index).map_err(|_| GptError::InvalidEntryLayout)?)
            .ok_or(GptError::InvalidEntryLayout)?;
        let start = index
            .checked_mul(block_bytes)
            .ok_or(GptError::InvalidEntryLayout)?;
        let end = start
            .checked_add(block_bytes)
            .ok_or(GptError::InvalidEntryLayout)?;
        region.read_blocks(lba, 1, &mut stored[start..end])?;
    }
    stored.truncate(exact_bytes);
    Ok(stored)
}

fn parse_partitions(
    entries: &[u8],
    header: GptHeader,
    limits: GptLimits,
) -> Result<Vec<GptPartition>, GptError> {
    let mut partitions = Vec::new();
    partitions
        .try_reserve_exact(usize::from(limits.max_partitions()))
        .map_err(|_| GptError::MetadataExhausted)?;
    for index in 0..header.entry_count {
        let start = usize::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(GPT_ENTRY_BYTES as usize))
            .ok_or(GptError::InvalidEntryLayout)?;
        let entry = entries
            .get(start..start + GPT_ENTRY_BYTES as usize)
            .ok_or(GptError::InvalidEntryLayout)?;
        let type_guid = GptGuid(copy_array_16(entry, 0)?);
        if type_guid.is_zero() {
            if entry.iter().any(|byte| *byte != 0) {
                return Err(GptError::InvalidPartition);
            }
            continue;
        }
        if partitions.len() >= usize::from(limits.max_partitions()) {
            return Err(GptError::InvalidEntryLayout);
        }
        let unique_guid = GptGuid(copy_array_16(entry, 16)?);
        let first_lba = read_u64(entry, 32)?;
        let last_lba = read_u64(entry, 40)?;
        if unique_guid.is_zero()
            || first_lba > last_lba
            || first_lba < header.first_usable_lba
            || last_lba > header.last_usable_lba
        {
            return Err(GptError::InvalidPartition);
        }
        if partitions
            .iter()
            .any(|partition: &GptPartition| partition.unique_guid == unique_guid)
        {
            return Err(GptError::DuplicateIdentifier);
        }
        let (name, name_units) = parse_name(entry)?;
        partitions.push(GptPartition {
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            attributes: read_u64(entry, 48)?,
            name,
            name_units,
        });
    }
    partitions.sort_unstable_by_key(|partition| partition.first_lba);
    for pair in partitions.windows(2) {
        if pair[0].last_lba >= pair[1].first_lba {
            return Err(GptError::OverlappingPartitions);
        }
    }
    Ok(partitions)
}

fn parse_name(entry: &[u8]) -> Result<([u16; GPT_NAME_UNITS], u8), GptError> {
    let mut name = [0_u16; GPT_NAME_UNITS];
    let mut name_units = GPT_NAME_UNITS;
    let mut terminated = false;
    for (index, unit) in name.iter_mut().enumerate() {
        let offset = 56 + index * 2;
        *unit = read_u16(entry, offset)?;
        if *unit == 0 {
            if !terminated {
                name_units = index;
                terminated = true;
            }
        } else if terminated {
            return Err(GptError::InvalidPartition);
        }
    }
    if decode_utf16(name[..name_units].iter().copied()).any(|value| value.is_err()) {
        return Err(GptError::InvalidPartition);
    }
    let name_units = u8::try_from(name_units).map_err(|_| GptError::InvalidPartition)?;
    Ok((name, name_units))
}

fn copy_array_16(bytes: &[u8], offset: usize) -> Result<[u8; 16], GptError> {
    let mut value = [0_u8; 16];
    value.copy_from_slice(
        bytes
            .get(offset..offset + 16)
            .ok_or(GptError::InvalidHeader)?,
    );
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, GptError> {
    let array = bytes
        .get(offset..offset + 2)
        .and_then(|value| <[u8; 2]>::try_from(value).ok())
        .ok_or(GptError::InvalidHeader)?;
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GptError> {
    let array = bytes
        .get(offset..offset + 4)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .ok_or(GptError::InvalidHeader)?;
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, GptError> {
    let array = bytes
        .get(offset..offset + 8)
        .and_then(|value| <[u8; 8]>::try_from(value).ok())
        .ok_or(GptError::InvalidHeader)?;
    Ok(u64::from_le_bytes(array))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use troe_block::{BlockAccess, BlockGeometry, BlockLimits};

    use super::{
        BlockDevice, BlockError, BlockRegion, GPT_ENTRY_BYTES, GPT_HEADER_BYTES,
        GPT_HEADER_BYTES_U32, GPT_REVISION_1_0, GptError, GptLimits, crc32, discover,
    };

    const BLOCK_BYTES: usize = 512;
    const BLOCK_COUNT: usize = 256;
    const ENTRY_COUNT: usize = 128;
    const ENTRY_BLOCKS: usize = ENTRY_COUNT * GPT_ENTRY_BYTES as usize / BLOCK_BYTES;
    const PRIMARY_ENTRIES: usize = 2;
    const BACKUP_HEADER: usize = BLOCK_COUNT - 1;
    const BACKUP_ENTRIES: usize = BACKUP_HEADER - ENTRY_BLOCKS;

    struct MemoryDevice {
        geometry: BlockGeometry,
        bytes: Vec<u8>,
    }

    impl MemoryDevice {
        fn from_bytes(bytes: Vec<u8>) -> Result<Self, BlockError> {
            Ok(Self {
                geometry: BlockGeometry::new(512, BLOCK_COUNT as u64, 1, false, false)?,
                bytes,
            })
        }
    }

    impl BlockDevice for MemoryDevice {
        fn geometry(&self) -> BlockGeometry {
            self.geometry
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            let start = usize::try_from(start_block)
                .ok()
                .and_then(|value| value.checked_mul(BLOCK_BYTES))
                .ok_or(BlockError::Device)?;
            let bytes = usize::try_from(block_count)
                .ok()
                .and_then(|value| value.checked_mul(BLOCK_BYTES))
                .ok_or(BlockError::Device)?;
            let end = start.checked_add(bytes).ok_or(BlockError::Device)?;
            let source = self.bytes.get(start..end).ok_or(BlockError::Device)?;
            if source.len() != destination.len() {
                return Err(BlockError::Device);
            }
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    fn limits() -> Result<GptLimits, GptError> {
        GptLimits::new(128, 16 * 1024, 16)
    }

    fn block_limits() -> Result<BlockLimits, BlockError> {
        BlockLimits::new(8, 8 * BLOCK_BYTES, 1)
    }

    fn discover_bytes(bytes: Vec<u8>) -> Result<super::GptDisk, GptError> {
        let mut device = MemoryDevice::from_bytes(bytes).map_err(GptError::Block)?;
        let mut region = BlockRegion::whole_device(
            &mut device,
            BlockAccess::ReadOnly,
            block_limits().map_err(GptError::Block)?,
        )
        .map_err(GptError::Block)?;
        discover(&mut region, limits()?)
    }

    fn valid_image() -> Vec<u8> {
        let mut image = vec![0_u8; BLOCK_COUNT * BLOCK_BYTES];
        image[510] = 0x55;
        image[511] = 0xaa;
        image[446 + 4] = 0xee;
        put_u32(&mut image[446..462], 8, 1);
        put_u32(&mut image[446..462], 12, 255);

        let mut entries = vec![0_u8; ENTRY_COUNT * GPT_ENTRY_BYTES as usize];
        set_partition(&mut entries, 0, 40, 49, 0x21, 0x31, "system");
        set_partition(&mut entries, 1, 60, 79, 0x22, 0x32, "data");
        image[PRIMARY_ENTRIES * BLOCK_BYTES..(PRIMARY_ENTRIES + ENTRY_BLOCKS) * BLOCK_BYTES]
            .copy_from_slice(&entries);
        image[BACKUP_ENTRIES * BLOCK_BYTES..BACKUP_HEADER * BLOCK_BYTES].copy_from_slice(&entries);
        refresh_headers(&mut image);
        image
    }

    fn set_partition(
        entries: &mut [u8],
        index: usize,
        first: u64,
        last: u64,
        type_seed: u8,
        unique_seed: u8,
        name: &str,
    ) {
        let start = index * GPT_ENTRY_BYTES as usize;
        let entry = &mut entries[start..start + GPT_ENTRY_BYTES as usize];
        entry[..16].fill(type_seed);
        entry[16..32].fill(unique_seed);
        put_u64(entry, 32, first);
        put_u64(entry, 40, last);
        for (unit_index, unit) in name.encode_utf16().enumerate() {
            put_u16(entry, 56 + unit_index * 2, unit);
        }
    }

    fn refresh_headers(image: &mut [u8]) {
        let entries =
            &image[PRIMARY_ENTRIES * BLOCK_BYTES..(PRIMARY_ENTRIES + ENTRY_BLOCKS) * BLOCK_BYTES];
        let entries_crc = crc32(entries);
        write_header(image, 1, BACKUP_HEADER, PRIMARY_ENTRIES, entries_crc);
        write_header(image, BACKUP_HEADER, 1, BACKUP_ENTRIES, entries_crc);
    }

    fn write_header(
        image: &mut [u8],
        current: usize,
        backup: usize,
        entries: usize,
        entries_crc: u32,
    ) {
        let block = &mut image[current * BLOCK_BYTES..(current + 1) * BLOCK_BYTES];
        block.fill(0);
        block[..8].copy_from_slice(b"EFI PART");
        put_u32(block, 8, GPT_REVISION_1_0);
        put_u32(block, 12, GPT_HEADER_BYTES_U32);
        put_u64(block, 24, current as u64);
        put_u64(block, 32, backup as u64);
        put_u64(block, 40, 34);
        put_u64(block, 48, (BACKUP_ENTRIES - 1) as u64);
        block[56..72].fill(0x11);
        put_u64(block, 72, entries as u64);
        put_u32(block, 80, 128);
        put_u32(block, 84, GPT_ENTRY_BYTES);
        put_u32(block, 88, entries_crc);
        put_u32(block, 16, 0);
        put_u32(block, 16, crc32(&block[..GPT_HEADER_BYTES]));
    }

    fn refresh_entry_arrays(image: &mut [u8], entries: &[u8]) {
        image[PRIMARY_ENTRIES * BLOCK_BYTES..(PRIMARY_ENTRIES + ENTRY_BLOCKS) * BLOCK_BYTES]
            .copy_from_slice(entries);
        image[BACKUP_ENTRIES * BLOCK_BYTES..BACKUP_HEADER * BLOCK_BYTES].copy_from_slice(entries);
        refresh_headers(image);
    }

    fn mutate_header(image: &mut [u8], lba: usize, operation: impl FnOnce(&mut [u8])) {
        let block = &mut image[lba * BLOCK_BYTES..(lba + 1) * BLOCK_BYTES];
        operation(block);
        put_u32(block, 16, 0);
        put_u32(block, 16, crc32(&block[..GPT_HEADER_BYTES]));
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn valid_primary_and_backup_discover_sorted_partitions() -> Result<(), GptError> {
        let disk = discover_bytes(valid_image())?;
        assert_eq!(disk.partitions().len(), 2);
        assert_eq!(disk.partitions()[0].first_lba(), 40);
        assert_eq!(disk.partitions()[0].last_lba(), 49);
        assert_eq!(
            disk.partitions()[0].name_utf16(),
            &[115, 121, 115, 116, 101, 109]
        );
        assert_eq!(disk.partitions()[1].block_count(), 20);
        assert_eq!(disk.first_usable_lba(), 34);
        assert_eq!(disk.last_usable_lba(), (BACKUP_ENTRIES - 1) as u64);
        Ok(())
    }

    #[test]
    fn protective_mbr_must_be_single_and_canonical() {
        let mut image = valid_image();
        image[462 + 4] = 0x83;
        assert_eq!(discover_bytes(image), Err(GptError::InvalidProtectiveMbr));
    }

    #[test]
    fn header_and_entry_checksums_fail_closed() {
        let mut header = valid_image();
        header[BLOCK_BYTES + 40] ^= 1;
        assert_eq!(discover_bytes(header), Err(GptError::HeaderChecksum));

        let mut entries = valid_image();
        entries[PRIMARY_ENTRIES * BLOCK_BYTES + 3] ^= 1;
        assert_eq!(discover_bytes(entries), Err(GptError::EntryChecksum));
    }

    #[test]
    fn valid_but_different_backup_metadata_is_rejected() {
        let mut image = valid_image();
        mutate_header(&mut image, BACKUP_HEADER, |header| header[56] ^= 1);
        assert_eq!(discover_bytes(image), Err(GptError::InconsistentCopies));
    }

    #[test]
    fn entry_count_size_and_location_obey_exact_bounds() {
        let mut count = valid_image();
        mutate_header(&mut count, 1, |header| put_u32(header, 80, 129));
        assert_eq!(discover_bytes(count), Err(GptError::InvalidEntryLayout));

        let mut size = valid_image();
        mutate_header(&mut size, 1, |header| put_u32(header, 84, 256));
        assert_eq!(discover_bytes(size), Err(GptError::InvalidEntryLayout));

        let mut location = valid_image();
        mutate_header(&mut location, 1, |header| put_u64(header, 72, u64::MAX));
        assert_eq!(discover_bytes(location), Err(GptError::InvalidEntryLayout));
    }

    #[test]
    fn overlaps_duplicate_ids_and_out_of_range_entries_are_rejected() {
        let mut overlap = valid_image();
        let mut entries = overlap
            [PRIMARY_ENTRIES * BLOCK_BYTES..(PRIMARY_ENTRIES + ENTRY_BLOCKS) * BLOCK_BYTES]
            .to_vec();
        put_u64(&mut entries[GPT_ENTRY_BYTES as usize..], 32, 49);
        refresh_entry_arrays(&mut overlap, &entries);
        assert_eq!(
            discover_bytes(overlap),
            Err(GptError::OverlappingPartitions)
        );

        let mut duplicate = valid_image();
        let mut entries = duplicate
            [PRIMARY_ENTRIES * BLOCK_BYTES..(PRIMARY_ENTRIES + ENTRY_BLOCKS) * BLOCK_BYTES]
            .to_vec();
        let first_guid = entries[16..32].to_vec();
        entries[GPT_ENTRY_BYTES as usize + 16..GPT_ENTRY_BYTES as usize + 32]
            .copy_from_slice(&first_guid);
        refresh_entry_arrays(&mut duplicate, &entries);
        assert_eq!(
            discover_bytes(duplicate),
            Err(GptError::DuplicateIdentifier)
        );

        let mut outside = valid_image();
        let mut entries = outside
            [PRIMARY_ENTRIES * BLOCK_BYTES..(PRIMARY_ENTRIES + ENTRY_BLOCKS) * BLOCK_BYTES]
            .to_vec();
        put_u64(&mut entries, 32, 2);
        refresh_entry_arrays(&mut outside, &entries);
        assert_eq!(discover_bytes(outside), Err(GptError::InvalidPartition));
    }

    #[test]
    fn unused_entries_and_utf16_names_are_canonical() {
        let mut unused = valid_image();
        let mut entries = unused
            [PRIMARY_ENTRIES * BLOCK_BYTES..(PRIMARY_ENTRIES + ENTRY_BLOCKS) * BLOCK_BYTES]
            .to_vec();
        entries[2 * GPT_ENTRY_BYTES as usize + 20] = 1;
        refresh_entry_arrays(&mut unused, &entries);
        assert_eq!(discover_bytes(unused), Err(GptError::InvalidPartition));

        let mut name = valid_image();
        let mut entries = name
            [PRIMARY_ENTRIES * BLOCK_BYTES..(PRIMARY_ENTRIES + ENTRY_BLOCKS) * BLOCK_BYTES]
            .to_vec();
        put_u16(&mut entries, 56, 0xd800);
        refresh_entry_arrays(&mut name, &entries);
        assert_eq!(discover_bytes(name), Err(GptError::InvalidPartition));
    }

    #[test]
    fn parser_limits_are_validated_before_media_access() {
        assert_eq!(GptLimits::new(0, 128, 1), Err(GptError::InvalidLimits));
        assert_eq!(GptLimits::new(1, 127, 1), Err(GptError::InvalidLimits));
        assert_eq!(GptLimits::new(1, 128, 2), Err(GptError::InvalidLimits));
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}

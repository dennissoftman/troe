//! Bounded crash-consistent dual-slot persistence transactions.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use troe_block::{BlockAccess, BlockDevice, BlockError, BlockRegion};

/// Product-independent transaction data-block identifier.
pub const DATA_MAGIC: [u8; 8] = *b"TXDTv1\0\0";
/// Product-independent transaction commit-block identifier.
pub const COMMIT_MAGIC: [u8; 8] = *b"TXCMv1\0\0";
/// Exact region size used by the two data/commit slots.
pub const TRANSACTION_BLOCKS: u64 = 4;
/// Product-independent installed persistence-region selector identifier.
pub const REGION_SELECTOR_MAGIC: [u8; 8] = *b"PRGNv1\0\0";
/// Exact encoded size of one persistence-region selector.
pub const REGION_SELECTOR_BYTES: usize = 80;

const DATA_HEADER_BYTES: usize = 32;
const CHECKSUM_OFFSET: usize = 20;
const CHECKSUM_END: usize = 24;

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

/// Stable persistence transaction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistError {
    /// Region geometry, authority, flush support, or transfer limits are insufficient.
    UnsupportedRegion,
    /// Both slots claim the same fully committed generation.
    Corrupt,
    /// Payload exceeds the exact one-block bounded profile.
    PayloadTooLarge,
    /// Generation `u64` is exhausted and may not wrap.
    GenerationExhausted,
    /// Bounded buffer allocation failed.
    MetadataExhausted,
    /// The checked block capability rejected or failed an operation.
    Block(BlockError),
}

impl From<BlockError> for PersistError {
    fn from(error: BlockError) -> Self {
        Self::Block(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    slot: u8,
    generation: u64,
    payload: Vec<u8>,
}

/// One opened four-block store retaining the newest fully committed slot.
pub struct DualSlotStore<D: BlockDevice> {
    region: BlockRegion<D>,
    block_bytes: usize,
    active: Option<Candidate>,
}

impl<D: BlockDevice> DualSlotStore<D> {
    /// Recover the newest valid slot from an exactly bounded writable region.
    ///
    /// Empty zero-filled media is generation zero with no payload. A slot is
    /// visible only when its canonical data and commit blocks agree completely.
    ///
    /// # Errors
    ///
    /// Rejects missing write/flush authority, unsuitable geometry or limits,
    /// allocation/read failure, and duplicate committed generations.
    pub fn open(mut region: BlockRegion<D>) -> Result<Self, PersistError> {
        let info = region.info();
        let block_bytes =
            usize::try_from(info.block_bytes()).map_err(|_| PersistError::UnsupportedRegion)?;
        if info.access() != BlockAccess::ReadWrite
            || !info.supports_flush()
            || info.required_alignment_blocks() != 1
            || info.block_count() != TRANSACTION_BLOCKS
            || block_bytes < DATA_HEADER_BYTES + 1
            || info.limits().max_transfer_blocks() < 1
            || info.limits().max_transfer_bytes() < block_bytes
        {
            return Err(PersistError::UnsupportedRegion);
        }
        let first = read_candidate(&mut region, 0, block_bytes)?;
        let second = read_candidate(&mut region, 1, block_bytes)?;
        let active = match (first, second) {
            (Some(left), Some(right)) if left.generation == right.generation => {
                return Err(PersistError::Corrupt);
            }
            (Some(left), Some(right)) => Some(if left.generation > right.generation {
                left
            } else {
                right
            }),
            (Some(candidate), None) | (None, Some(candidate)) => Some(candidate),
            (None, None) => None,
        };
        Ok(Self {
            region,
            block_bytes,
            active,
        })
    }

    /// Newest fully committed generation, or zero on empty media.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.active
            .as_ref()
            .map_or(0, |candidate| candidate.generation)
    }

    /// Payload of the newest fully committed generation.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.active
            .as_ref()
            .map(|candidate| candidate.payload.as_slice())
    }

    /// Maximum payload accepted by this region's logical block size.
    #[must_use]
    pub const fn max_payload_bytes(&self) -> usize {
        self.block_bytes - DATA_HEADER_BYTES
    }

    /// Commit a new generation using data-flush-marker-flush ordering.
    ///
    /// The in-memory active state changes only after the second flush succeeds.
    /// If any operation fails, reopening chooses whichever slot is fully durable.
    ///
    /// # Errors
    ///
    /// Rejects an oversized payload or generation wrap, allocation failure, and
    /// any checked write/flush failure.
    pub fn commit(&mut self, payload: &[u8]) -> Result<u64, PersistError> {
        if payload.len() > self.max_payload_bytes() {
            return Err(PersistError::PayloadTooLarge);
        }
        let generation = self
            .generation()
            .checked_add(1)
            .ok_or(PersistError::GenerationExhausted)?;
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(payload.len())
            .map_err(|_| PersistError::MetadataExhausted)?;
        retained.extend_from_slice(payload);
        let slot = self.active.as_ref().map_or(0, |active| active.slot ^ 1);
        let data = encode_data(self.block_bytes, generation, payload)?;
        let data_checksum = read_u32(&data, CHECKSUM_OFFSET)?;
        let commit = encode_commit(self.block_bytes, generation, data_checksum)?;
        let data_lba = u64::from(slot) * 2;
        self.region.write_blocks(data_lba, 1, &data, false)?;
        self.region.flush()?;
        self.region.write_blocks(data_lba + 1, 1, &commit, false)?;
        self.region.flush()?;

        self.active = Some(Candidate {
            slot,
            generation,
            payload: retained,
        });
        Ok(generation)
    }
}

fn read_candidate<D: BlockDevice>(
    region: &mut BlockRegion<D>,
    slot: u8,
    block_bytes: usize,
) -> Result<Option<Candidate>, PersistError> {
    let mut data = zeroed(block_bytes)?;
    let mut commit = zeroed(block_bytes)?;
    let data_lba = u64::from(slot) * 2;
    region.read_blocks(data_lba, 1, &mut data)?;
    region.read_blocks(data_lba + 1, 1, &mut commit)?;
    if data.iter().all(|byte| *byte == 0) && commit.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let Some((generation, payload, data_checksum)) = parse_data(&data)? else {
        return Ok(None);
    };
    if !parse_commit(&commit, generation, data_checksum)? {
        return Ok(None);
    }
    Ok(Some(Candidate {
        slot,
        generation,
        payload,
    }))
}

fn encode_data(
    block_bytes: usize,
    generation: u64,
    payload: &[u8],
) -> Result<Vec<u8>, PersistError> {
    let mut block = zeroed(block_bytes)?;
    block[..8].copy_from_slice(&DATA_MAGIC);
    block[8..16].copy_from_slice(&generation.to_le_bytes());
    block[16..20].copy_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| PersistError::PayloadTooLarge)?
            .to_le_bytes(),
    );
    block[DATA_HEADER_BYTES..DATA_HEADER_BYTES + payload.len()].copy_from_slice(payload);
    let checksum = crc32_zeroed_checksum(&block);
    block[CHECKSUM_OFFSET..CHECKSUM_END].copy_from_slice(&checksum.to_le_bytes());
    Ok(block)
}

fn encode_commit(
    block_bytes: usize,
    generation: u64,
    data_checksum: u32,
) -> Result<Vec<u8>, PersistError> {
    let mut block = zeroed(block_bytes)?;
    block[..8].copy_from_slice(&COMMIT_MAGIC);
    block[8..16].copy_from_slice(&generation.to_le_bytes());
    block[16..20].copy_from_slice(&data_checksum.to_le_bytes());
    let checksum = crc32_zeroed_checksum(&block);
    block[CHECKSUM_OFFSET..CHECKSUM_END].copy_from_slice(&checksum.to_le_bytes());
    Ok(block)
}

fn parse_data(block: &[u8]) -> Result<Option<(u64, Vec<u8>, u32)>, PersistError> {
    if block.get(..8) != Some(&DATA_MAGIC) || crc32_zeroed_checksum(block) != read_u32(block, 20)? {
        return Ok(None);
    }
    if block[24..DATA_HEADER_BYTES].iter().any(|byte| *byte != 0) {
        return Ok(None);
    }
    let generation = read_u64(block, 8)?;
    let length = usize::try_from(read_u32(block, 16)?).map_err(|_| PersistError::Corrupt)?;
    let end = DATA_HEADER_BYTES
        .checked_add(length)
        .ok_or(PersistError::Corrupt)?;
    if generation == 0 || end > block.len() || block[end..].iter().any(|byte| *byte != 0) {
        return Ok(None);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| PersistError::MetadataExhausted)?;
    payload.extend_from_slice(&block[DATA_HEADER_BYTES..end]);
    Ok(Some((generation, payload, read_u32(block, 20)?)))
}

fn parse_commit(block: &[u8], generation: u64, data_checksum: u32) -> Result<bool, PersistError> {
    Ok(block.get(..8) == Some(&COMMIT_MAGIC)
        && read_u64(block, 8)? == generation
        && read_u32(block, 16)? == data_checksum
        && crc32_zeroed_checksum(block) == read_u32(block, 20)?
        && block[24..].iter().all(|byte| *byte == 0))
}

fn zeroed(bytes: usize) -> Result<Vec<u8>, PersistError> {
    let mut block = Vec::new();
    block
        .try_reserve_exact(bytes)
        .map_err(|_| PersistError::MetadataExhausted)?;
    block.resize(bytes, 0);
    Ok(block)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PersistError> {
    let raw = bytes.get(offset..offset + 4).ok_or(PersistError::Corrupt)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PersistError> {
    let raw = bytes.get(offset..offset + 8).ok_or(PersistError::Corrupt)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
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
    let mut crc = u32::MAX;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let byte = if (CHECKSUM_OFFSET..CHECKSUM_END).contains(&index) {
            0
        } else {
            byte
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
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use super::{
        CHECKSUM_OFFSET, DualSlotStore, PersistError, REGION_SELECTOR_BYTES, REGION_SELECTOR_MAGIC,
        RegionSelector, SelectorError, crc32_zeroed_checksum,
    };
    use troe_block::{
        BlockAccess, BlockDevice, BlockError, BlockGeometry, BlockLimits, BlockRegion,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Operation {
        Write(u64),
        Flush,
    }

    struct Media {
        stable: Vec<u8>,
        volatile: Vec<u8>,
        operations: Vec<Operation>,
        fail_at: Option<(usize, bool)>,
        operation_count: usize,
    }

    #[derive(Clone)]
    struct TestDevice(Rc<RefCell<Media>>);

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

    impl TestDevice {
        fn new() -> Self {
            let bytes = vec![0; 4 * 512];
            Self(Rc::new(RefCell::new(Media {
                stable: bytes.clone(),
                volatile: bytes,
                operations: Vec::new(),
                fail_at: None,
                operation_count: 0,
            })))
        }

        fn fail_at(&self, operation: usize, after_effect: bool) {
            let mut media = self.0.borrow_mut();
            media.fail_at = Some((operation, after_effect));
            media.operation_count = 0;
            media.operations.clear();
        }

        fn power_loss(&self) {
            let mut media = self.0.borrow_mut();
            media.volatile = media.stable.clone();
            media.fail_at = None;
            media.operation_count = 0;
        }

        fn should_fail(&self) -> (bool, bool) {
            let mut media = self.0.borrow_mut();
            media.operation_count += 1;
            let fail = media
                .fail_at
                .is_some_and(|(operation, _)| operation == media.operation_count);
            let after = fail && media.fail_at.is_some_and(|(_, after)| after);
            (fail, after)
        }
    }

    impl BlockDevice for TestDevice {
        fn geometry(&self) -> BlockGeometry {
            BlockGeometry::new(512, 4, 1, true, false).unwrap_or_else(|_| std::process::abort())
        }

        fn read_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            let start = usize::try_from(start_block)
                .ok()
                .and_then(|value| value.checked_mul(512))
                .ok_or(BlockError::OutOfBounds)?;
            let bytes = usize::try_from(block_count)
                .ok()
                .and_then(|value| value.checked_mul(512))
                .ok_or(BlockError::OutOfBounds)?;
            let media = self.0.borrow();
            destination.copy_from_slice(
                media
                    .volatile
                    .get(start..start + bytes)
                    .ok_or(BlockError::OutOfBounds)?,
            );
            Ok(())
        }

        fn write_blocks(
            &mut self,
            start_block: u64,
            _block_count: u32,
            source: &[u8],
            _force_unit_access: bool,
        ) -> Result<(), BlockError> {
            let (fail, after) = self.should_fail();
            if fail && !after {
                return Err(BlockError::Device);
            }
            let start = usize::try_from(start_block)
                .ok()
                .and_then(|value| value.checked_mul(512))
                .ok_or(BlockError::OutOfBounds)?;
            let mut media = self.0.borrow_mut();
            media.volatile[start..start + source.len()].copy_from_slice(source);
            media.operations.push(Operation::Write(start_block));
            if fail {
                Err(BlockError::Device)
            } else {
                Ok(())
            }
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            let (fail, after) = self.should_fail();
            if fail && !after {
                return Err(BlockError::Device);
            }
            let mut media = self.0.borrow_mut();
            media.stable = media.volatile.clone();
            media.operations.push(Operation::Flush);
            if fail {
                Err(BlockError::Device)
            } else {
                Ok(())
            }
        }
    }

    fn open(device: TestDevice) -> Result<DualSlotStore<TestDevice>, PersistError> {
        let limits = BlockLimits::new(1, 512, 1).map_err(PersistError::Block)?;
        let region = BlockRegion::new(device, 0, 4, BlockAccess::ReadWrite, limits)?;
        DualSlotStore::open(region)
    }

    #[test]
    fn commit_order_and_successful_recovery_are_exact() -> Result<(), PersistError> {
        let device = TestDevice::new();
        let mut store = open(device.clone())?;
        assert_eq!(store.commit(b"alpha")?, 1);
        assert_eq!(
            device.0.borrow().operations,
            vec![
                Operation::Write(0),
                Operation::Flush,
                Operation::Write(1),
                Operation::Flush
            ]
        );
        device.power_loss();
        let recovered = open(device)?;
        assert_eq!(recovered.generation(), 1);
        assert_eq!(recovered.payload(), Some(b"alpha".as_slice()));
        Ok(())
    }

    #[test]
    fn every_failed_boundary_recovers_the_predecessor() -> Result<(), PersistError> {
        for operation in 1..=4 {
            let device = TestDevice::new();
            let mut store = open(device.clone())?;
            store.commit(b"predecessor")?;
            device.fail_at(operation, false);
            assert_eq!(
                store.commit(b"candidate"),
                Err(PersistError::Block(BlockError::Device))
            );
            drop(store);
            device.power_loss();
            let recovered = open(device)?;
            assert_eq!(recovered.generation(), 1);
            assert_eq!(recovered.payload(), Some(b"predecessor".as_slice()));
        }
        Ok(())
    }

    #[test]
    fn uncertain_final_flush_is_resolved_by_reopen() -> Result<(), PersistError> {
        let device = TestDevice::new();
        let mut store = open(device.clone())?;
        store.commit(b"predecessor")?;
        device.fail_at(4, true);
        assert_eq!(
            store.commit(b"candidate"),
            Err(PersistError::Block(BlockError::Device))
        );
        drop(store);
        device.power_loss();
        let recovered = open(device)?;
        assert_eq!(recovered.generation(), 2);
        assert_eq!(recovered.payload(), Some(b"candidate".as_slice()));
        Ok(())
    }

    #[test]
    fn corrupt_newest_data_falls_back_to_valid_predecessor() -> Result<(), PersistError> {
        let device = TestDevice::new();
        let mut store = open(device.clone())?;
        store.commit(b"alpha")?;
        store.commit(b"beta")?;
        drop(store);
        device.0.borrow_mut().stable[2 * 512 + 64] ^= 0x80;
        device.power_loss();
        let recovered = open(device)?;
        assert_eq!(recovered.generation(), 1);
        assert_eq!(recovered.payload(), Some(b"alpha".as_slice()));
        Ok(())
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

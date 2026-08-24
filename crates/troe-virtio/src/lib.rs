//! Bounded transport-independent modern virtio block profile.
#![no_std]
#![forbid(unsafe_code)]

use troe_block::{
    BlockDevice, BlockError, BlockGeometry, MAX_LOGICAL_BLOCK_BYTES, MAX_TRANSFER_BYTES,
    MIN_LOGICAL_BLOCK_BYTES,
};

/// Virtio block device type identifier.
pub const VIRTIO_DEVICE_ID_BLOCK: u32 = 2;
/// The initial profile uses request virtqueue zero.
pub const REQUEST_QUEUE_INDEX: u16 = 0;
/// Small power-of-two split queue sufficient for one three-descriptor request.
pub const REQUEST_QUEUE_SIZE: u16 = 8;
/// Virtio block capacity and request sectors are always 512 bytes.
pub const VIRTIO_SECTOR_BYTES: u32 = 512;
/// Bytes in the fixed virtio block request header.
pub const REQUEST_HEADER_BYTES: u32 = 16;
/// Bytes in the device-written request status trailer.
pub const REQUEST_STATUS_BYTES: u32 = 1;

const FEATURE_SIZE_MAX: u64 = 1 << 1;
const FEATURE_SEG_MAX: u64 = 1 << 2;
const FEATURE_READ_ONLY: u64 = 1 << 5;
const FEATURE_BLOCK_SIZE: u64 = 1 << 6;
const FEATURE_FLUSH: u64 = 1 << 9;
const FEATURE_VERSION_1: u64 = 1 << 32;
const ACCEPTED_FEATURES: u64 = FEATURE_SIZE_MAX
    | FEATURE_SEG_MAX
    | FEATURE_READ_ONLY
    | FEATURE_BLOCK_SIZE
    | FEATURE_FLUSH
    | FEATURE_VERSION_1;

const DESCRIPTOR_BYTES: usize = 16;
const AVAILABLE_HEADER_BYTES: usize = 4;
const AVAILABLE_TRAILER_BYTES: usize = 2;
const USED_HEADER_BYTES: usize = 4;
const USED_ELEMENT_BYTES: usize = 8;
const USED_TRAILER_BYTES: usize = 2;

/// Invalid device negotiation, configuration, queue, request, or completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioBlockError {
    /// The device did not offer the mandatory modern virtio feature.
    LegacyOnly,
    /// Capacity, block size, or optional limits are outside the bounded profile.
    InvalidConfiguration,
    /// Queue size is not a supported power of two with room for one request.
    InvalidQueue,
    /// Queue-layout size or offset arithmetic overflowed.
    QueueOverflow,
    /// A request cannot be represented in exact 512-byte virtio sectors.
    InvalidRequest,
    /// A completion returned a wrong head, length, or unknown status.
    InvalidCompletion,
}

/// Feature subset and immutable geometry accepted before queue activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioBlockProfile {
    negotiated_features: u64,
    geometry: BlockGeometry,
    max_segment_bytes: usize,
}

impl VirtioBlockProfile {
    /// Validate offered features and a stable block configuration snapshot.
    ///
    /// The snapshot begins with the mandatory little-endian capacity field and
    /// includes conditional fields through `blk_size` when those features are
    /// offered. The caller must obtain it using the transport's stable config
    /// generation procedure before committing the returned feature subset.
    ///
    /// # Errors
    ///
    /// Rejects legacy-only devices, zero or overflowing capacity, unsupported
    /// logical block sizes, a capacity not divisible by that block size, and
    /// optional segment limits too small for the fixed request profile.
    pub fn negotiate(
        offered_features: u64,
        configuration: &[u8],
    ) -> Result<Self, VirtioBlockError> {
        if offered_features & FEATURE_VERSION_1 == 0 {
            return Err(VirtioBlockError::LegacyOnly);
        }
        let capacity_sectors = read_u64(configuration, 0)?;
        if capacity_sectors == 0 {
            return Err(VirtioBlockError::InvalidConfiguration);
        }
        let negotiated_features = offered_features & ACCEPTED_FEATURES;
        let logical_block_bytes = if offered_features & FEATURE_BLOCK_SIZE != 0 {
            read_u32(configuration, 20)?
        } else {
            VIRTIO_SECTOR_BYTES
        };
        if !(MIN_LOGICAL_BLOCK_BYTES..=MAX_LOGICAL_BLOCK_BYTES).contains(&logical_block_bytes)
            || !logical_block_bytes.is_power_of_two()
            || !logical_block_bytes.is_multiple_of(VIRTIO_SECTOR_BYTES)
        {
            return Err(VirtioBlockError::InvalidConfiguration);
        }
        let capacity_bytes = capacity_sectors
            .checked_mul(u64::from(VIRTIO_SECTOR_BYTES))
            .ok_or(VirtioBlockError::InvalidConfiguration)?;
        if !capacity_bytes.is_multiple_of(u64::from(logical_block_bytes)) {
            return Err(VirtioBlockError::InvalidConfiguration);
        }
        let block_count = capacity_bytes / u64::from(logical_block_bytes);
        let size_max = if offered_features & FEATURE_SIZE_MAX != 0 {
            usize::try_from(read_u32(configuration, 8)?)
                .map_err(|_| VirtioBlockError::InvalidConfiguration)?
        } else {
            MAX_TRANSFER_BYTES
        };
        let seg_max = if offered_features & FEATURE_SEG_MAX != 0 {
            read_u32(configuration, 12)?
        } else {
            1
        };
        if size_max < usize::try_from(logical_block_bytes).unwrap_or(usize::MAX) || seg_max == 0 {
            return Err(VirtioBlockError::InvalidConfiguration);
        }
        let max_segment_bytes = size_max.min(MAX_TRANSFER_BYTES);
        let geometry = BlockGeometry::new(
            logical_block_bytes,
            block_count,
            1,
            negotiated_features & FEATURE_FLUSH != 0,
            false,
        )
        .map_err(|_| VirtioBlockError::InvalidConfiguration)?;
        Ok(Self {
            negotiated_features,
            geometry,
            max_segment_bytes,
        })
    }

    /// Exact feature subset to write before setting `FEATURES_OK`.
    #[must_use]
    pub const fn negotiated_features(self) -> u64 {
        self.negotiated_features
    }

    /// Immutable block geometry derived from the stable configuration.
    #[must_use]
    pub const fn geometry(self) -> BlockGeometry {
        self.geometry
    }

    /// Whether the device itself forbids writes.
    #[must_use]
    pub const fn read_only(self) -> bool {
        self.negotiated_features & FEATURE_READ_ONLY != 0
    }

    /// Maximum bytes accepted in the single data descriptor.
    #[must_use]
    pub const fn max_segment_bytes(self) -> usize {
        self.max_segment_bytes
    }

    /// Plan an exact read request.
    ///
    /// # Errors
    ///
    /// Rejects empty, overflowing, out-of-capacity, incorrectly buffered, or
    /// over-profile requests.
    pub fn plan_read(
        self,
        start_block: u64,
        block_count: u32,
        buffer_bytes: usize,
    ) -> Result<RequestPlan, VirtioBlockError> {
        self.plan_data(RequestKind::Read, start_block, block_count, buffer_bytes)
    }

    /// Plan an exact write request.
    ///
    /// # Errors
    ///
    /// Rejects device read-only policy plus every invalid read condition.
    pub fn plan_write(
        self,
        start_block: u64,
        block_count: u32,
        buffer_bytes: usize,
    ) -> Result<RequestPlan, VirtioBlockError> {
        if self.read_only() {
            return Err(VirtioBlockError::InvalidRequest);
        }
        self.plan_data(RequestKind::Write, start_block, block_count, buffer_bytes)
    }

    /// Plan an explicit cache flush request.
    ///
    /// # Errors
    ///
    /// Rejects a read-only device or one without negotiated flush support.
    pub fn plan_flush(self) -> Result<RequestPlan, VirtioBlockError> {
        if self.read_only() || !self.geometry.supports_flush() {
            return Err(VirtioBlockError::InvalidRequest);
        }
        Ok(RequestPlan {
            kind: RequestKind::Flush,
            sector: 0,
            data_bytes: 0,
        })
    }

    fn plan_data(
        self,
        kind: RequestKind,
        start_block: u64,
        block_count: u32,
        buffer_bytes: usize,
    ) -> Result<RequestPlan, VirtioBlockError> {
        if block_count == 0 {
            return Err(VirtioBlockError::InvalidRequest);
        }
        let end_block = start_block
            .checked_add(u64::from(block_count))
            .ok_or(VirtioBlockError::InvalidRequest)?;
        if end_block > self.geometry.block_count() {
            return Err(VirtioBlockError::InvalidRequest);
        }
        let block_bytes = usize::try_from(self.geometry.logical_block_bytes())
            .map_err(|_| VirtioBlockError::InvalidRequest)?;
        let data_bytes = usize::try_from(block_count)
            .ok()
            .and_then(|count| count.checked_mul(block_bytes))
            .ok_or(VirtioBlockError::InvalidRequest)?;
        if data_bytes != buffer_bytes
            || data_bytes > self.max_segment_bytes
            || data_bytes > MAX_TRANSFER_BYTES
        {
            return Err(VirtioBlockError::InvalidRequest);
        }
        let byte_offset = start_block
            .checked_mul(u64::from(self.geometry.logical_block_bytes()))
            .ok_or(VirtioBlockError::InvalidRequest)?;
        if !byte_offset.is_multiple_of(u64::from(VIRTIO_SECTOR_BYTES)) {
            return Err(VirtioBlockError::InvalidRequest);
        }
        Ok(RequestPlan {
            kind,
            sector: byte_offset / u64::from(VIRTIO_SECTOR_BYTES),
            data_bytes: u32::try_from(data_bytes).map_err(|_| VirtioBlockError::InvalidRequest)?,
        })
    }
}

/// Closed operation set for the initial virtio block profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    /// Device writes the data descriptor.
    Read,
    /// Device reads the data descriptor.
    Write,
    /// Device flushes volatile write state; no data descriptor is present.
    Flush,
}

/// Fully checked request metadata consumed by a transport queue implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestPlan {
    kind: RequestKind,
    sector: u64,
    data_bytes: u32,
}

impl RequestPlan {
    /// Operation encoded in the fixed request header.
    #[must_use]
    pub const fn kind(self) -> RequestKind {
        self.kind
    }

    /// Starting 512-byte sector, or zero for flush.
    #[must_use]
    pub const fn sector(self) -> u64 {
        self.sector
    }

    /// Exact data descriptor length; zero only for flush.
    #[must_use]
    pub const fn data_bytes(self) -> u32 {
        self.data_bytes
    }

    /// Canonical 16-byte little-endian virtio block request header.
    #[must_use]
    pub fn header(self) -> [u8; REQUEST_HEADER_BYTES as usize] {
        let request_type = match self.kind {
            RequestKind::Read => 0_u32,
            RequestKind::Write => 1,
            RequestKind::Flush => 4,
        };
        let mut header = [0_u8; REQUEST_HEADER_BYTES as usize];
        header[..4].copy_from_slice(&request_type.to_le_bytes());
        header[8..].copy_from_slice(&self.sector.to_le_bytes());
        header
    }

    /// Number of direct descriptors in this request chain.
    #[must_use]
    pub const fn descriptor_count(self) -> u16 {
        if matches!(self.kind, RequestKind::Flush) {
            2
        } else {
            3
        }
    }

    /// Expected used-ring byte count for exact completion.
    #[must_use]
    pub const fn expected_used_bytes(self) -> u32 {
        match self.kind {
            RequestKind::Read => self.data_bytes + REQUEST_STATUS_BYTES,
            RequestKind::Write | RequestKind::Flush => REQUEST_STATUS_BYTES,
        }
    }

    /// Validate a used-ring element and final device status byte.
    ///
    /// # Errors
    ///
    /// Rejects a nonzero descriptor head, incomplete or overlong device write,
    /// I/O error, unsupported operation, and every unknown status.
    pub fn validate_completion(
        self,
        descriptor_head: u32,
        used_bytes: u32,
        status: u8,
    ) -> Result<(), BlockError> {
        if descriptor_head != 0 || used_bytes != self.expected_used_bytes() {
            return Err(BlockError::Device);
        }
        match status {
            0 => Ok(()),
            2 => Err(BlockError::Unsupported),
            _ => Err(BlockError::Device),
        }
    }
}

/// Byte offsets and sizes for three physically contiguous split-queue parts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplitQueueLayout {
    queue_size: u16,
    descriptor_offset: usize,
    descriptor_bytes: usize,
    available_offset: usize,
    available_bytes: usize,
    used_offset: usize,
    used_bytes: usize,
    total_bytes: usize,
}

impl SplitQueueLayout {
    /// Calculate a canonical modern split-queue layout.
    ///
    /// # Errors
    ///
    /// Rejects non-power-of-two sizes, fewer than three entries, sizes above
    /// the virtio maximum, and all offset or size overflow.
    pub fn new(queue_size: u16) -> Result<Self, VirtioBlockError> {
        if queue_size < 3 || !queue_size.is_power_of_two() || queue_size > 32_768 {
            return Err(VirtioBlockError::InvalidQueue);
        }
        let count = usize::from(queue_size);
        let descriptor_bytes = count
            .checked_mul(DESCRIPTOR_BYTES)
            .ok_or(VirtioBlockError::QueueOverflow)?;
        let available_bytes = AVAILABLE_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(2)
                    .ok_or(VirtioBlockError::QueueOverflow)?,
            )
            .and_then(|bytes| bytes.checked_add(AVAILABLE_TRAILER_BYTES))
            .ok_or(VirtioBlockError::QueueOverflow)?;
        let available_offset = align_up(descriptor_bytes, 2)?;
        let used_offset = align_up(
            available_offset
                .checked_add(available_bytes)
                .ok_or(VirtioBlockError::QueueOverflow)?,
            4,
        )?;
        let used_bytes = USED_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(USED_ELEMENT_BYTES)
                    .ok_or(VirtioBlockError::QueueOverflow)?,
            )
            .and_then(|bytes| bytes.checked_add(USED_TRAILER_BYTES))
            .ok_or(VirtioBlockError::QueueOverflow)?;
        let total_bytes = used_offset
            .checked_add(used_bytes)
            .ok_or(VirtioBlockError::QueueOverflow)?;
        Ok(Self {
            queue_size,
            descriptor_offset: 0,
            descriptor_bytes,
            available_offset,
            available_bytes,
            used_offset,
            used_bytes,
            total_bytes,
        })
    }

    /// Queue entry count.
    #[must_use]
    pub const fn queue_size(self) -> u16 {
        self.queue_size
    }

    /// Descriptor-table byte offset.
    #[must_use]
    pub const fn descriptor_offset(self) -> usize {
        self.descriptor_offset
    }

    /// Descriptor-table byte count.
    #[must_use]
    pub const fn descriptor_bytes(self) -> usize {
        self.descriptor_bytes
    }

    /// Available-ring byte offset.
    #[must_use]
    pub const fn available_offset(self) -> usize {
        self.available_offset
    }

    /// Available-ring byte count.
    #[must_use]
    pub const fn available_bytes(self) -> usize {
        self.available_bytes
    }

    /// Used-ring byte offset.
    #[must_use]
    pub const fn used_offset(self) -> usize {
        self.used_offset
    }

    /// Used-ring byte count.
    #[must_use]
    pub const fn used_bytes(self) -> usize {
        self.used_bytes
    }

    /// Complete allocation bytes with required internal padding.
    #[must_use]
    pub const fn total_bytes(self) -> usize {
        self.total_bytes
    }
}

/// Synchronous DMA mechanism supplied by a bus-specific implementation.
pub trait VirtioBlockTransport {
    /// Execute one checked read chain to exact completion.
    ///
    /// # Errors
    ///
    /// Returns a stable block-boundary error without claiming partial success.
    fn read(&mut self, request: RequestPlan, destination: &mut [u8]) -> Result<(), BlockError>;

    /// Execute one checked write chain to exact completion.
    ///
    /// # Errors
    ///
    /// Returns a stable block-boundary error without claiming partial success.
    fn write(&mut self, request: RequestPlan, source: &[u8]) -> Result<(), BlockError>;

    /// Execute one checked flush chain to exact completion.
    ///
    /// # Errors
    ///
    /// Returns a stable block-boundary error when durable completion is not
    /// confirmed.
    fn flush(&mut self, request: RequestPlan) -> Result<(), BlockError>;
}

/// Checked [`BlockDevice`] adapter over one initialized virtio transport.
#[derive(Debug)]
pub struct VirtioBlock<T> {
    transport: T,
    profile: VirtioBlockProfile,
}

impl<T> VirtioBlock<T> {
    /// Bind an initialized transport to its previously negotiated profile.
    #[must_use]
    pub const fn new(transport: T, profile: VirtioBlockProfile) -> Self {
        Self { transport, profile }
    }

    /// Immutable negotiated profile.
    #[must_use]
    pub const fn profile(&self) -> VirtioBlockProfile {
        self.profile
    }

    /// Recover the transport during explicit device teardown.
    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T: VirtioBlockTransport> BlockDevice for VirtioBlock<T> {
    fn geometry(&self) -> BlockGeometry {
        self.profile.geometry()
    }

    fn read_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        destination: &mut [u8],
    ) -> Result<(), BlockError> {
        let request = self
            .profile
            .plan_read(start_block, block_count, destination.len())
            .map_err(map_request_error)?;
        self.transport.read(request, destination)
    }

    fn write_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        source: &[u8],
        force_unit_access: bool,
    ) -> Result<(), BlockError> {
        if force_unit_access {
            return Err(BlockError::Unsupported);
        }
        if self.profile.read_only() {
            return Err(BlockError::ReadOnly);
        }
        let request = self
            .profile
            .plan_write(start_block, block_count, source.len())
            .map_err(map_request_error)?;
        self.transport.write(request, source)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        if self.profile.read_only() {
            return Err(BlockError::ReadOnly);
        }
        let request = self.profile.plan_flush().map_err(map_request_error)?;
        self.transport.flush(request)
    }
}

fn map_request_error(error: VirtioBlockError) -> BlockError {
    match error {
        VirtioBlockError::InvalidRequest => BlockError::OutOfBounds,
        _ => BlockError::Device,
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, VirtioBlockError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(VirtioBlockError::InvalidConfiguration)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, VirtioBlockError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(VirtioBlockError::InvalidConfiguration)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn align_up(value: usize, alignment: usize) -> Result<usize, VirtioBlockError> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
        .ok_or(VirtioBlockError::QueueOverflow)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use troe_block::{BlockDevice, BlockError};

    use super::{
        FEATURE_BLOCK_SIZE, FEATURE_FLUSH, FEATURE_READ_ONLY, FEATURE_SEG_MAX, FEATURE_SIZE_MAX,
        FEATURE_VERSION_1, REQUEST_HEADER_BYTES, REQUEST_QUEUE_SIZE, RequestKind, SplitQueueLayout,
        VirtioBlock, VirtioBlockError, VirtioBlockProfile, VirtioBlockTransport,
    };

    fn configuration(
        capacity_sectors: u64,
        size_max: u32,
        seg_max: u32,
        block_size: u32,
    ) -> [u8; 24] {
        let mut bytes = [0_u8; 24];
        bytes[..8].copy_from_slice(&capacity_sectors.to_le_bytes());
        bytes[8..12].copy_from_slice(&size_max.to_le_bytes());
        bytes[12..16].copy_from_slice(&seg_max.to_le_bytes());
        bytes[20..24].copy_from_slice(&block_size.to_le_bytes());
        bytes
    }

    fn writable_profile() -> VirtioBlockProfile {
        VirtioBlockProfile::negotiate(
            FEATURE_VERSION_1 | FEATURE_BLOCK_SIZE | FEATURE_FLUSH,
            &configuration(32_768, 0, 0, 4096),
        )
        .unwrap_or_else(|_| std::process::abort())
    }

    #[test]
    fn negotiation_requires_modern_bounded_geometry() {
        let config = configuration(32_768, 0, 0, 4096);
        assert_eq!(
            VirtioBlockProfile::negotiate(FEATURE_BLOCK_SIZE, &config),
            Err(VirtioBlockError::LegacyOnly)
        );
        let profile = writable_profile();
        assert_eq!(profile.geometry().logical_block_bytes(), 4096);
        assert_eq!(profile.geometry().block_count(), 4096);
        assert!(profile.geometry().supports_flush());
        assert!(!profile.geometry().supports_force_unit_access());
        assert!(!profile.read_only());
        assert_eq!(
            profile.negotiated_features(),
            FEATURE_VERSION_1 | FEATURE_BLOCK_SIZE | FEATURE_FLUSH
        );
    }

    #[test]
    fn configuration_capacity_block_and_segment_limits_fail_closed() {
        let features = FEATURE_VERSION_1 | FEATURE_BLOCK_SIZE | FEATURE_SIZE_MAX | FEATURE_SEG_MAX;
        for config in [
            configuration(0, 4096, 1, 4096),
            configuration(9, 4096, 1, 4096),
            configuration(32_768, 4096, 1, 1000),
            configuration(32_768, 2048, 1, 4096),
            configuration(32_768, 4096, 0, 4096),
        ] {
            assert_eq!(
                VirtioBlockProfile::negotiate(features, &config),
                Err(VirtioBlockError::InvalidConfiguration)
            );
        }
        assert_eq!(
            VirtioBlockProfile::negotiate(FEATURE_VERSION_1, &[0; 7]),
            Err(VirtioBlockError::InvalidConfiguration)
        );
    }

    #[test]
    fn unknown_features_are_not_accepted_and_read_only_is_retained() {
        let unknown = 1_u64 << 63;
        let profile = VirtioBlockProfile::negotiate(
            FEATURE_VERSION_1 | FEATURE_READ_ONLY | unknown,
            &configuration(128, 0, 0, 0),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            profile.negotiated_features(),
            FEATURE_VERSION_1 | FEATURE_READ_ONLY
        );
        assert!(profile.read_only());
        assert_eq!(profile.geometry().logical_block_bytes(), 512);
        assert!(!profile.geometry().supports_flush());
    }

    #[test]
    fn request_plans_translate_logical_blocks_to_exact_sectors() {
        let profile = writable_profile();
        let read = profile
            .plan_read(2, 3, 12 * 1024)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read.kind(), RequestKind::Read);
        assert_eq!(read.sector(), 16);
        assert_eq!(read.data_bytes(), 12 * 1024);
        assert_eq!(read.descriptor_count(), 3);
        assert_eq!(read.expected_used_bytes(), 12 * 1024 + 1);
        let header = read.header();
        assert_eq!(header.len(), REQUEST_HEADER_BYTES as usize);
        assert_eq!(&header[..4], &0_u32.to_le_bytes());
        assert_eq!(&header[4..8], &[0; 4]);
        assert_eq!(&header[8..], &16_u64.to_le_bytes());

        let write = profile
            .plan_write(4, 1, 4096)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&write.header()[..4], &1_u32.to_le_bytes());
        assert_eq!(write.expected_used_bytes(), 1);

        let flush = profile
            .plan_flush()
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(flush.kind(), RequestKind::Flush);
        assert_eq!(flush.descriptor_count(), 2);
        assert_eq!(&flush.header()[..4], &4_u32.to_le_bytes());
    }

    #[test]
    fn request_bounds_and_read_only_policy_fail_before_transport() {
        let profile = writable_profile();
        assert_eq!(
            profile.plan_read(0, 0, 0),
            Err(VirtioBlockError::InvalidRequest)
        );
        assert_eq!(
            profile.plan_read(4095, 2, 8192),
            Err(VirtioBlockError::InvalidRequest)
        );
        assert_eq!(
            profile.plan_read(0, 1, 512),
            Err(VirtioBlockError::InvalidRequest)
        );

        let read_only = VirtioBlockProfile::negotiate(
            FEATURE_VERSION_1 | FEATURE_READ_ONLY | FEATURE_FLUSH,
            &configuration(128, 0, 0, 0),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            read_only.plan_write(0, 1, 512),
            Err(VirtioBlockError::InvalidRequest)
        );
        assert_eq!(
            read_only.plan_flush(),
            Err(VirtioBlockError::InvalidRequest)
        );
    }

    #[test]
    fn completions_require_exact_head_length_and_known_status() {
        let read = writable_profile()
            .plan_read(0, 1, 4096)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read.validate_completion(0, 4097, 0), Ok(()));
        assert_eq!(
            read.validate_completion(1, 4097, 0),
            Err(BlockError::Device)
        );
        assert_eq!(read.validate_completion(0, 1, 0), Err(BlockError::Device));
        assert_eq!(
            read.validate_completion(0, 4097, 1),
            Err(BlockError::Device)
        );
        assert_eq!(
            read.validate_completion(0, 4097, 2),
            Err(BlockError::Unsupported)
        );
        assert_eq!(
            read.validate_completion(0, 4097, 3),
            Err(BlockError::Device)
        );
    }

    #[test]
    fn split_queue_layout_obeys_each_part_alignment_and_exact_size() {
        let layout =
            SplitQueueLayout::new(REQUEST_QUEUE_SIZE).unwrap_or_else(|_| std::process::abort());
        assert_eq!(layout.queue_size(), 8);
        assert_eq!(layout.descriptor_offset(), 0);
        assert_eq!(layout.descriptor_bytes(), 128);
        assert_eq!(layout.available_offset(), 128);
        assert_eq!(layout.available_bytes(), 22);
        assert_eq!(layout.used_offset(), 152);
        assert_eq!(layout.used_bytes(), 70);
        assert_eq!(layout.total_bytes(), 222);
        assert!(layout.descriptor_offset().is_multiple_of(16));
        assert!(layout.available_offset().is_multiple_of(2));
        assert!(layout.used_offset().is_multiple_of(4));
        for invalid in [0, 2, 3, 6, 32_769] {
            assert_eq!(
                SplitQueueLayout::new(invalid),
                Err(VirtioBlockError::InvalidQueue)
            );
        }
    }

    #[derive(Debug, Default)]
    struct MockTransport {
        operations: Vec<RequestKind>,
    }

    impl VirtioBlockTransport for MockTransport {
        fn read(
            &mut self,
            request: super::RequestPlan,
            destination: &mut [u8],
        ) -> Result<(), BlockError> {
            self.operations.push(request.kind());
            destination.fill(0xa5);
            Ok(())
        }

        fn write(&mut self, request: super::RequestPlan, _source: &[u8]) -> Result<(), BlockError> {
            self.operations.push(request.kind());
            Ok(())
        }

        fn flush(&mut self, request: super::RequestPlan) -> Result<(), BlockError> {
            self.operations.push(request.kind());
            Ok(())
        }
    }

    #[test]
    fn block_adapter_forwards_only_checked_requests_and_never_claims_fua() {
        let mut device = VirtioBlock::new(MockTransport::default(), writable_profile());
        let mut destination = vec![0_u8; 4096];
        assert_eq!(device.read_blocks(0, 1, &mut destination), Ok(()));
        assert!(destination.iter().all(|byte| *byte == 0xa5));
        assert_eq!(device.write_blocks(1, 1, &[7; 4096], false), Ok(()));
        assert_eq!(device.flush(), Ok(()));
        assert_eq!(
            device.write_blocks(1, 1, &[7; 4096], true),
            Err(BlockError::Unsupported)
        );
        assert_eq!(
            device.into_transport().operations,
            [RequestKind::Read, RequestKind::Write, RequestKind::Flush]
        );
    }
}

//! Bounded synchronous block-device and block-region capabilities.
#![no_std]
#![forbid(unsafe_code)]

/// Smallest logical block accepted by the core storage boundary.
pub const MIN_LOGICAL_BLOCK_BYTES: u32 = 512;
/// Largest logical block accepted by the core storage boundary.
pub const MAX_LOGICAL_BLOCK_BYTES: u32 = 64 * 1024;
/// Hard ceiling for one device request.
pub const MAX_TRANSFER_BYTES: usize = 1024 * 1024;
/// The synchronous block contract permits exactly one request in flight.
pub const SYNCHRONOUS_QUEUE_DEPTH: u16 = 1;

/// Device geometry and durability properties validated at the capability edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockGeometry {
    logical_block_bytes: u32,
    block_count: u64,
    required_alignment_blocks: u32,
    supports_flush: bool,
    supports_force_unit_access: bool,
}

impl BlockGeometry {
    /// Construct checked device geometry.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity, non-power-of-two block sizes outside the hard
    /// supported range, invalid alignment, and byte-capacity overflow.
    pub fn new(
        logical_block_bytes: u32,
        block_count: u64,
        required_alignment_blocks: u32,
        supports_flush: bool,
        supports_force_unit_access: bool,
    ) -> Result<Self, BlockError> {
        if !(MIN_LOGICAL_BLOCK_BYTES..=MAX_LOGICAL_BLOCK_BYTES).contains(&logical_block_bytes)
            || !logical_block_bytes.is_power_of_two()
            || block_count == 0
            || required_alignment_blocks == 0
            || !required_alignment_blocks.is_power_of_two()
            || block_count
                .checked_mul(u64::from(logical_block_bytes))
                .is_none()
        {
            return Err(BlockError::InvalidGeometry);
        }
        Ok(Self {
            logical_block_bytes,
            block_count,
            required_alignment_blocks,
            supports_flush,
            supports_force_unit_access,
        })
    }

    /// Bytes in one addressable logical block.
    #[must_use]
    pub const fn logical_block_bytes(self) -> u32 {
        self.logical_block_bytes
    }

    /// Number of addressable logical blocks.
    #[must_use]
    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    /// Required alignment for request starts and lengths, in logical blocks.
    #[must_use]
    pub const fn required_alignment_blocks(self) -> u32 {
        self.required_alignment_blocks
    }

    /// Whether the device exposes an explicit cache flush operation.
    #[must_use]
    pub const fn supports_flush(self) -> bool {
        self.supports_flush
    }

    /// Whether writes may request force-unit-access durability.
    #[must_use]
    pub const fn supports_force_unit_access(self) -> bool {
        self.supports_force_unit_access
    }

    /// Exact device capacity in bytes.
    #[must_use]
    pub const fn byte_count(self) -> u64 {
        // Construction proves this multiplication representable.
        self.block_count * self.logical_block_bytes as u64
    }
}

/// Per-capability request ceilings selected during capability construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockLimits {
    max_transfer_blocks: u32,
    max_transfer_bytes: usize,
    queue_depth: u16,
}

impl BlockLimits {
    /// Construct checked request ceilings for the synchronous block contract.
    ///
    /// # Errors
    ///
    /// Rejects empty transfers, byte ceilings above the hard maximum, or a
    /// queue depth other than the one request enforced by exclusive borrowing.
    pub const fn new(
        max_transfer_blocks: u32,
        max_transfer_bytes: usize,
        queue_depth: u16,
    ) -> Result<Self, BlockError> {
        if max_transfer_blocks == 0
            || max_transfer_bytes == 0
            || max_transfer_bytes > MAX_TRANSFER_BYTES
            || queue_depth != SYNCHRONOUS_QUEUE_DEPTH
        {
            return Err(BlockError::InvalidLimits);
        }
        Ok(Self {
            max_transfer_blocks,
            max_transfer_bytes,
            queue_depth,
        })
    }

    /// Maximum blocks transferred by one request.
    #[must_use]
    pub const fn max_transfer_blocks(self) -> u32 {
        self.max_transfer_blocks
    }

    /// Maximum bytes transferred by one request.
    #[must_use]
    pub const fn max_transfer_bytes(self) -> usize {
        self.max_transfer_bytes
    }

    /// Maximum requests in flight. The initial contract is synchronous.
    #[must_use]
    pub const fn queue_depth(self) -> u16 {
        self.queue_depth
    }
}

/// Mutation authority carried by one block-region capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockAccess {
    /// Read requests only.
    ReadOnly,
    /// Read, write, and supported durability requests.
    ReadWrite,
}

/// Stable failures at the block capability boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockError {
    /// Device geometry is outside the supported range.
    InvalidGeometry,
    /// Request ceilings are empty, inconsistent, or unsupported.
    InvalidLimits,
    /// A region is empty, out of device bounds, or improperly aligned.
    InvalidRegion,
    /// A request contains no blocks.
    EmptyTransfer,
    /// A request violates the device's block-alignment requirement.
    Misaligned,
    /// Checked translation placed a request outside its granted region.
    OutOfBounds,
    /// A request exceeds its block or byte ceiling.
    TransferTooLarge,
    /// The supplied buffer length is not exactly the requested byte count.
    BufferLength,
    /// Mutation was attempted through a read-only capability.
    ReadOnly,
    /// The device does not implement the requested durability operation.
    Unsupported,
    /// The underlying device reported an I/O failure.
    Device,
    /// The device did not report completion inside the driver's bounded wait.
    ///
    /// Distinct from [`BlockError::Device`], which is a completed request the
    /// device or its completion record reported as failed. An expired wait
    /// leaves the request's outcome unknown, so a caller that treats the two
    /// alike cannot tell a dead device from a slow one.
    Timeout,
}

/// Synchronous device mechanism consumed only through checked region wrappers.
///
/// Implementations receive absolute device LBAs after the wrapper has checked
/// arithmetic, authority, alignment, transfer ceilings, and exact buffer size.
pub trait BlockDevice {
    /// Report immutable geometry selected when the device was initialized.
    fn geometry(&self) -> BlockGeometry;

    /// Read exactly `block_count` logical blocks from an absolute device LBA.
    ///
    /// # Errors
    ///
    /// Returns a device-specific boundary error without partial success.
    fn read_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        destination: &mut [u8],
    ) -> Result<(), BlockError>;

    /// Write exactly `block_count` logical blocks to an absolute device LBA.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Unsupported`] by default or a device boundary
    /// error without partial success.
    fn write_blocks(
        &mut self,
        _start_block: u64,
        _block_count: u32,
        _source: &[u8],
        _force_unit_access: bool,
    ) -> Result<(), BlockError> {
        Err(BlockError::Unsupported)
    }

    /// Flush volatile write state to stable media.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Unsupported`] by default or a device boundary
    /// error when stable completion cannot be guaranteed.
    fn flush(&mut self) -> Result<(), BlockError> {
        Err(BlockError::Unsupported)
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for &mut D {
    fn geometry(&self) -> BlockGeometry {
        (**self).geometry()
    }

    fn read_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        destination: &mut [u8],
    ) -> Result<(), BlockError> {
        (**self).read_blocks(start_block, block_count, destination)
    }

    fn write_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        source: &[u8],
        force_unit_access: bool,
    ) -> Result<(), BlockError> {
        (**self).write_blocks(start_block, block_count, source, force_unit_access)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        (**self).flush()
    }
}

/// Geometry of a granted region, expressed relative to its own block zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRegionInfo {
    block_bytes: u32,
    block_count: u64,
    required_alignment_blocks: u32,
    supports_flush: bool,
    supports_force_unit_access: bool,
    access: BlockAccess,
    limits: BlockLimits,
}

impl BlockRegionInfo {
    /// Bytes in one logical block.
    #[must_use]
    pub const fn block_bytes(self) -> u32 {
        self.block_bytes
    }

    /// Number of blocks visible through the region.
    #[must_use]
    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    /// Required request alignment in logical blocks.
    #[must_use]
    pub const fn required_alignment_blocks(self) -> u32 {
        self.required_alignment_blocks
    }

    /// Whether explicit flush is supported.
    #[must_use]
    pub const fn supports_flush(self) -> bool {
        self.supports_flush
    }

    /// Whether force-unit-access writes are supported.
    #[must_use]
    pub const fn supports_force_unit_access(self) -> bool {
        self.supports_force_unit_access
    }

    /// Mutation authority of the capability.
    #[must_use]
    pub const fn access(self) -> BlockAccess {
        self.access
    }

    /// Per-request resource ceilings.
    #[must_use]
    pub const fn limits(self) -> BlockLimits {
        self.limits
    }
}

/// Exclusive, bounds-checked authority over one contiguous device region.
pub struct BlockRegion<D: BlockDevice> {
    device: D,
    start_block: u64,
    block_count: u64,
    access: BlockAccess,
    limits: BlockLimits,
    geometry: BlockGeometry,
}

impl<D: BlockDevice> BlockRegion<D> {
    /// Grant a checked region over a device.
    ///
    /// # Errors
    ///
    /// Rejects invalid device geometry, empty or out-of-bounds ranges,
    /// misaligned region starts, and limits too small for one logical block.
    pub fn new(
        device: D,
        start_block: u64,
        block_count: u64,
        access: BlockAccess,
        limits: BlockLimits,
    ) -> Result<Self, BlockError> {
        let geometry = device.geometry();
        validate_geometry(geometry)?;
        let end = start_block
            .checked_add(block_count)
            .ok_or(BlockError::InvalidRegion)?;
        if block_count == 0
            || end > geometry.block_count()
            || !start_block.is_multiple_of(u64::from(geometry.required_alignment_blocks()))
            || usize::try_from(geometry.logical_block_bytes()).map_or(true, |block_bytes| {
                block_bytes > limits.max_transfer_bytes()
            })
        {
            return Err(BlockError::InvalidRegion);
        }
        Ok(Self {
            device,
            start_block,
            block_count,
            access,
            limits,
            geometry,
        })
    }

    /// Grant the complete device as one region.
    ///
    /// # Errors
    ///
    /// Rejects invalid geometry or capability limits.
    pub fn whole_device(
        device: D,
        access: BlockAccess,
        limits: BlockLimits,
    ) -> Result<Self, BlockError> {
        let block_count = device.geometry().block_count();
        Self::new(device, 0, block_count, access, limits)
    }

    /// Report the relative geometry and authority visible to the holder.
    #[must_use]
    pub const fn info(&self) -> BlockRegionInfo {
        BlockRegionInfo {
            block_bytes: self.geometry.logical_block_bytes(),
            block_count: self.block_count,
            required_alignment_blocks: self.geometry.required_alignment_blocks(),
            supports_flush: self.geometry.supports_flush(),
            supports_force_unit_access: self.geometry.supports_force_unit_access(),
            access: self.access,
            limits: self.limits,
        }
    }

    /// Reborrow a strictly bounded child capability relative to this region.
    ///
    /// # Errors
    ///
    /// Rejects authority escalation, empty or escaping ranges, arithmetic
    /// overflow, invalid alignment, and invalid child limits.
    pub fn subregion(
        &mut self,
        start_block: u64,
        block_count: u64,
        access: BlockAccess,
        limits: BlockLimits,
    ) -> Result<BlockRegion<&mut D>, BlockError> {
        if self.access == BlockAccess::ReadOnly && access == BlockAccess::ReadWrite {
            return Err(BlockError::ReadOnly);
        }
        let relative_end = start_block
            .checked_add(block_count)
            .ok_or(BlockError::OutOfBounds)?;
        if block_count == 0 || relative_end > self.block_count {
            return Err(BlockError::OutOfBounds);
        }
        let absolute = self
            .start_block
            .checked_add(start_block)
            .ok_or(BlockError::OutOfBounds)?;
        BlockRegion::new(&mut self.device, absolute, block_count, access, limits)
    }

    /// Read exactly the requested relative blocks into `destination`.
    ///
    /// # Errors
    ///
    /// Rejects an empty, misaligned, out-of-bounds, oversized, or incorrectly
    /// buffered request before calling the device, and forwards device errors.
    pub fn read_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        destination: &mut [u8],
    ) -> Result<(), BlockError> {
        let absolute = self.validate_request(start_block, block_count, destination.len())?;
        self.device.read_blocks(absolute, block_count, destination)
    }

    /// Write exactly the requested relative blocks from `source`.
    ///
    /// # Errors
    ///
    /// Rejects missing mutation authority, unsupported force-unit-access, or
    /// any invalid request before calling the device, and forwards device errors.
    pub fn write_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        source: &[u8],
        force_unit_access: bool,
    ) -> Result<(), BlockError> {
        if self.access != BlockAccess::ReadWrite {
            return Err(BlockError::ReadOnly);
        }
        if force_unit_access && !self.geometry.supports_force_unit_access() {
            return Err(BlockError::Unsupported);
        }
        let absolute = self.validate_request(start_block, block_count, source.len())?;
        self.device
            .write_blocks(absolute, block_count, source, force_unit_access)
    }

    /// Flush supported writable device state.
    ///
    /// # Errors
    ///
    /// Rejects missing mutation authority or flush support and forwards device
    /// failures.
    pub fn flush(&mut self) -> Result<(), BlockError> {
        if self.access != BlockAccess::ReadWrite {
            return Err(BlockError::ReadOnly);
        }
        if !self.geometry.supports_flush() {
            return Err(BlockError::Unsupported);
        }
        self.device.flush()
    }

    fn validate_request(
        &self,
        start_block: u64,
        block_count: u32,
        buffer_bytes: usize,
    ) -> Result<u64, BlockError> {
        if block_count == 0 {
            return Err(BlockError::EmptyTransfer);
        }
        let alignment = u64::from(self.geometry.required_alignment_blocks());
        if !start_block.is_multiple_of(alignment)
            || !u64::from(block_count).is_multiple_of(alignment)
        {
            return Err(BlockError::Misaligned);
        }
        let end = start_block
            .checked_add(u64::from(block_count))
            .ok_or(BlockError::OutOfBounds)?;
        if end > self.block_count {
            return Err(BlockError::OutOfBounds);
        }
        let block_bytes = usize::try_from(self.geometry.logical_block_bytes())
            .map_err(|_| BlockError::InvalidGeometry)?;
        let bytes = usize::try_from(block_count)
            .ok()
            .and_then(|count| count.checked_mul(block_bytes))
            .ok_or(BlockError::TransferTooLarge)?;
        if block_count > self.limits.max_transfer_blocks()
            || bytes > self.limits.max_transfer_bytes()
        {
            return Err(BlockError::TransferTooLarge);
        }
        if buffer_bytes != bytes {
            return Err(BlockError::BufferLength);
        }
        self.start_block
            .checked_add(start_block)
            .ok_or(BlockError::OutOfBounds)
    }
}

fn validate_geometry(geometry: BlockGeometry) -> Result<(), BlockError> {
    BlockGeometry::new(
        geometry.logical_block_bytes(),
        geometry.block_count(),
        geometry.required_alignment_blocks(),
        geometry.supports_flush(),
        geometry.supports_force_unit_access(),
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

    use super::{
        BlockAccess, BlockDevice, BlockError, BlockGeometry, BlockLimits, BlockRegion,
        MAX_TRANSFER_BYTES, SYNCHRONOUS_QUEUE_DEPTH,
    };

    struct MemoryDevice {
        geometry: BlockGeometry,
        bytes: Vec<u8>,
        reads: u32,
        writes: u32,
        flushes: u32,
    }

    impl MemoryDevice {
        fn new(
            block_count: u64,
            alignment: u32,
            flush: bool,
            fua: bool,
        ) -> Result<Self, BlockError> {
            let geometry = BlockGeometry::new(512, block_count, alignment, flush, fua)?;
            Ok(Self {
                geometry,
                bytes: vec![0; usize::try_from(geometry.byte_count()).unwrap_or(0)],
                reads: 0,
                writes: 0,
                flushes: 0,
            })
        }

        fn byte_range(
            &self,
            start_block: u64,
            block_count: u32,
        ) -> Result<core::ops::Range<usize>, BlockError> {
            let start = usize::try_from(start_block)
                .ok()
                .and_then(|block| block.checked_mul(512))
                .ok_or(BlockError::Device)?;
            let bytes = usize::try_from(block_count)
                .ok()
                .and_then(|count| count.checked_mul(512))
                .ok_or(BlockError::Device)?;
            let end = start.checked_add(bytes).ok_or(BlockError::Device)?;
            if end > self.bytes.len() {
                return Err(BlockError::Device);
            }
            Ok(start..end)
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
            let range = self.byte_range(start_block, block_count)?;
            destination.copy_from_slice(&self.bytes[range]);
            self.reads = self.reads.checked_add(1).ok_or(BlockError::Device)?;
            Ok(())
        }

        fn write_blocks(
            &mut self,
            start_block: u64,
            block_count: u32,
            source: &[u8],
            force_unit_access: bool,
        ) -> Result<(), BlockError> {
            if force_unit_access && !self.geometry.supports_force_unit_access() {
                return Err(BlockError::Unsupported);
            }
            let range = self.byte_range(start_block, block_count)?;
            self.bytes[range].copy_from_slice(source);
            self.writes = self.writes.checked_add(1).ok_or(BlockError::Device)?;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            self.flushes = self.flushes.checked_add(1).ok_or(BlockError::Device)?;
            Ok(())
        }
    }

    fn limits(blocks: u32) -> Result<BlockLimits, BlockError> {
        BlockLimits::new(blocks, usize::try_from(blocks).unwrap_or(0) * 512, 1)
    }

    #[test]
    fn geometry_and_limits_reject_invalid_configurations() {
        assert_eq!(
            BlockGeometry::new(0, 1, 1, false, false),
            Err(BlockError::InvalidGeometry)
        );
        assert_eq!(
            BlockGeometry::new(1000, 1, 1, false, false),
            Err(BlockError::InvalidGeometry)
        );
        assert_eq!(
            BlockGeometry::new(512, 0, 1, false, false),
            Err(BlockError::InvalidGeometry)
        );
        assert_eq!(
            BlockGeometry::new(512, 8, 3, false, false),
            Err(BlockError::InvalidGeometry)
        );
        assert_eq!(
            BlockLimits::new(0, 512, SYNCHRONOUS_QUEUE_DEPTH),
            Err(BlockError::InvalidLimits)
        );
        assert_eq!(
            BlockLimits::new(1, MAX_TRANSFER_BYTES + 1, SYNCHRONOUS_QUEUE_DEPTH),
            Err(BlockError::InvalidLimits)
        );
        assert_eq!(
            BlockLimits::new(1, 512, SYNCHRONOUS_QUEUE_DEPTH + 1),
            Err(BlockError::InvalidLimits)
        );
    }

    #[test]
    fn regions_translate_relative_lbas_and_preserve_exact_bounds() -> Result<(), BlockError> {
        let mut device = MemoryDevice::new(32, 1, true, true)?;
        device.bytes[8 * 512..9 * 512].fill(0x5a);
        let mut region = BlockRegion::new(&mut device, 8, 8, BlockAccess::ReadWrite, limits(4)?)?;
        let mut block = [0_u8; 512];
        assert_eq!(region.read_blocks(0, 1, &mut block), Ok(()));
        assert!(block.iter().all(|byte| *byte == 0x5a));
        assert_eq!(
            region.read_blocks(8, 1, &mut block),
            Err(BlockError::OutOfBounds)
        );
        assert_eq!(
            region.read_blocks(u64::MAX, 1, &mut block),
            Err(BlockError::OutOfBounds)
        );
        assert_eq!(device.reads, 1);
        Ok(())
    }

    #[test]
    fn requests_enforce_empty_alignment_transfer_and_buffer_limits() -> Result<(), BlockError> {
        let mut device = MemoryDevice::new(32, 2, false, false)?;
        let mut region = BlockRegion::new(&mut device, 2, 16, BlockAccess::ReadOnly, limits(4)?)?;
        let mut empty = [];
        assert_eq!(
            region.read_blocks(0, 0, &mut empty),
            Err(BlockError::EmptyTransfer)
        );
        let mut one = [0_u8; 512];
        assert_eq!(
            region.read_blocks(1, 1, &mut one),
            Err(BlockError::Misaligned)
        );
        let mut too_many = vec![0_u8; 6 * 512];
        assert_eq!(
            region.read_blocks(0, 6, &mut too_many),
            Err(BlockError::TransferTooLarge)
        );
        let mut wrong = [0_u8; 513];
        assert_eq!(
            region.read_blocks(0, 2, &mut wrong),
            Err(BlockError::BufferLength)
        );
        assert_eq!(device.reads, 0);
        Ok(())
    }

    #[test]
    fn read_only_and_durability_authority_fail_before_device_access() -> Result<(), BlockError> {
        let mut device = MemoryDevice::new(16, 1, false, false)?;
        {
            let mut read_only =
                BlockRegion::whole_device(&mut device, BlockAccess::ReadOnly, limits(2)?)?;
            assert_eq!(
                read_only.write_blocks(0, 1, &[0; 512], false),
                Err(BlockError::ReadOnly)
            );
            assert_eq!(read_only.flush(), Err(BlockError::ReadOnly));
        }
        {
            let mut writable =
                BlockRegion::whole_device(&mut device, BlockAccess::ReadWrite, limits(2)?)?;
            assert_eq!(
                writable.write_blocks(0, 1, &[0; 512], true),
                Err(BlockError::Unsupported)
            );
            assert_eq!(writable.flush(), Err(BlockError::Unsupported));
        }
        assert_eq!((device.writes, device.flushes), (0, 0));
        Ok(())
    }

    #[test]
    fn subregions_cannot_expand_bounds_or_authority() -> Result<(), BlockError> {
        let mut device = MemoryDevice::new(64, 1, true, true)?;
        let mut parent = BlockRegion::new(&mut device, 8, 32, BlockAccess::ReadOnly, limits(8)?)?;
        assert!(matches!(
            parent.subregion(0, 8, BlockAccess::ReadWrite, limits(4)?),
            Err(BlockError::ReadOnly)
        ));
        assert!(matches!(
            parent.subregion(31, 2, BlockAccess::ReadOnly, limits(2)?),
            Err(BlockError::OutOfBounds)
        ));
        let child = parent.subregion(4, 8, BlockAccess::ReadOnly, limits(4)?)?;
        assert_eq!(child.info().block_count(), 8);
        assert_eq!(child.info().access(), BlockAccess::ReadOnly);
        assert_eq!(child.info().limits().max_transfer_blocks(), 4);
        Ok(())
    }

    #[test]
    fn writable_regions_forward_checked_writes_flush_and_fua() -> Result<(), BlockError> {
        let mut device = MemoryDevice::new(16, 1, true, true)?;
        {
            let mut region =
                BlockRegion::whole_device(&mut device, BlockAccess::ReadWrite, limits(2)?)?;
            assert_eq!(region.write_blocks(3, 1, &[0xa5; 512], true), Ok(()));
            assert_eq!(region.flush(), Ok(()));
        }
        assert!(
            device.bytes[3 * 512..4 * 512]
                .iter()
                .all(|byte| *byte == 0xa5)
        );
        assert_eq!((device.writes, device.flushes), (1, 1));
        Ok(())
    }
}

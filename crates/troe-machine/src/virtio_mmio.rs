//! `AArch64` QEMU `virt` modern virtio-MMIO block transport.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt;
use core::hint::spin_loop;
use core::ptr;

use troe_block::BlockError;
use troe_memory::{BASE_PAGE_SIZE, PhysicalRange};
use troe_virtio::{
    REQUEST_HEADER_BYTES, REQUEST_QUEUE_INDEX, REQUEST_QUEUE_SIZE, RequestKind, RequestPlan,
    SplitQueueLayout, VIRTIO_DEVICE_ID_BLOCK, VirtioBlock, VirtioBlockProfile,
    VirtioBlockTransport,
};

const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
const VIRTIO_MMIO_SLOT_BYTES: u64 = 0x200;
const VIRTIO_MMIO_SLOT_COUNT: usize = 32;
const VIRTIO_MMIO_APERTURE_BYTES: u64 = VIRTIO_MMIO_SLOT_BYTES * VIRTIO_MMIO_SLOT_COUNT as u64;
const MAX_NATIVE_BLOCK_DEVICES: usize = 8;
const REGISTER_SPIN_LIMIT: usize = 1_000_000;
const CONFIG_READ_ATTEMPTS: usize = 8;
const QUEUE_ALLOCATION_BYTES: usize = 4096;
const REQUEST_HEADER_OFFSET: usize = 256;
const REQUEST_STATUS_OFFSET: usize = REQUEST_HEADER_OFFSET + REQUEST_HEADER_BYTES as usize;

const MMIO_MAGIC_VALUE: usize = 0x000;
const MMIO_VERSION: usize = 0x004;
const MMIO_DEVICE_ID: usize = 0x008;
const MMIO_DEVICE_FEATURES: usize = 0x010;
const MMIO_DEVICE_FEATURES_SEL: usize = 0x014;
const MMIO_DRIVER_FEATURES: usize = 0x020;
const MMIO_DRIVER_FEATURES_SEL: usize = 0x024;
const MMIO_QUEUE_SEL: usize = 0x030;
const MMIO_QUEUE_SIZE_MAX: usize = 0x034;
const MMIO_QUEUE_SIZE: usize = 0x038;
const MMIO_QUEUE_READY: usize = 0x044;
const MMIO_QUEUE_NOTIFY: usize = 0x050;
const MMIO_INTERRUPT_STATUS: usize = 0x060;
const MMIO_INTERRUPT_ACK: usize = 0x064;
const MMIO_STATUS: usize = 0x070;
const MMIO_QUEUE_DESC_LOW: usize = 0x080;
const MMIO_QUEUE_DESC_HIGH: usize = 0x084;
const MMIO_QUEUE_DRIVER_LOW: usize = 0x090;
const MMIO_QUEUE_DRIVER_HIGH: usize = 0x094;
const MMIO_QUEUE_DEVICE_LOW: usize = 0x0a0;
const MMIO_QUEUE_DEVICE_HIGH: usize = 0x0a4;
const MMIO_CONFIG_GENERATION: usize = 0x0fc;
const MMIO_CONFIG: usize = 0x100;

const VIRTIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_MMIO_MODERN_VERSION: u32 = 2;
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 128;

const DESCRIPTOR_NEXT: u16 = 1;
const DESCRIPTOR_WRITE: u16 = 2;
const NO_INTERRUPT: u16 = 1;

/// Bounded native virtio-MMIO initialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioMmioError {
    /// The pinned profile MMIO aperture could not form a checked page range.
    InvalidResource,
    /// More block devices were exposed than the selected profile permits.
    DeviceLimit,
    /// Queue memory allocation failed.
    QueueAllocation,
    /// Device reset did not complete or required registers were inconsistent.
    DeviceState,
    /// Modern feature or block-configuration validation failed.
    UnsupportedProfile,
    /// Request virtqueue zero is absent, live, or smaller than the fixed queue.
    InvalidQueue,
}

/// One initialized `AArch64` `virt` block device behind the portable adapter.
pub type NativeVirtioBlock = VirtioBlock<VirtioMmioTransport>;

/// Page-aligned MMIO apertures owned by the pinned `AArch64` `virt` profile.
///
/// # Errors
///
/// Returns a typed failure if the fixed aperture is not page-aligned or cannot
/// form a checked physical range.
pub fn virtio_mmio_device_ranges() -> Result<[PhysicalRange; 1], VirtioMmioError> {
    if !VIRTIO_MMIO_BASE.is_multiple_of(BASE_PAGE_SIZE)
        || !VIRTIO_MMIO_APERTURE_BYTES.is_multiple_of(BASE_PAGE_SIZE)
    {
        return Err(VirtioMmioError::InvalidResource);
    }
    let pages = VIRTIO_MMIO_APERTURE_BYTES / BASE_PAGE_SIZE;
    let range = PhysicalRange::from_pages(VIRTIO_MMIO_BASE, pages)
        .map_err(|_| VirtioMmioError::InvalidResource)?;
    Ok([range])
}

/// Discover and initialize every modern virtio-MMIO block device in the pinned
/// `AArch64` QEMU `virt` aperture.
///
/// Device enumeration order is retained only for discovery diagnostics. It is
/// never sufficient for assigning a persistent volume role.
///
/// # Errors
///
/// Fails transactionally if the device ceiling or metadata allocation is
/// exceeded, or if one advertised block device cannot establish the selected
/// modern feature, configuration, and split-queue profile.
pub fn discover_virtio_mmio_blocks() -> Result<Vec<NativeVirtioBlock>, VirtioMmioError> {
    let mut devices = Vec::new();
    devices
        .try_reserve_exact(MAX_NATIVE_BLOCK_DEVICES)
        .map_err(|_| VirtioMmioError::QueueAllocation)?;
    for index in 0..VIRTIO_MMIO_SLOT_COUNT {
        let slot = u64::try_from(index).map_err(|_| VirtioMmioError::InvalidResource)?;
        let address = VIRTIO_MMIO_BASE
            .checked_add(
                slot.checked_mul(VIRTIO_MMIO_SLOT_BYTES)
                    .ok_or(VirtioMmioError::InvalidResource)?,
            )
            .ok_or(VirtioMmioError::InvalidResource)?;
        let base = usize::try_from(address).map_err(|_| VirtioMmioError::InvalidResource)?;
        if mmio_read(base, MMIO_MAGIC_VALUE) != VIRTIO_MAGIC
            || mmio_read(base, MMIO_VERSION) != VIRTIO_MMIO_MODERN_VERSION
            || mmio_read(base, MMIO_DEVICE_ID) != VIRTIO_DEVICE_ID_BLOCK
        {
            continue;
        }
        if devices.len() >= MAX_NATIVE_BLOCK_DEVICES {
            return Err(VirtioMmioError::DeviceLimit);
        }
        devices.push(initialize_device(base)?);
    }
    Ok(devices)
}

fn initialize_device(base: usize) -> Result<NativeVirtioBlock, VirtioMmioError> {
    reset_device(base)?;
    write_status(base, STATUS_ACKNOWLEDGE);
    write_status(base, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let offered_features = read_features(base);
    let configuration = read_stable_configuration(base)?;
    let profile = match VirtioBlockProfile::negotiate(offered_features, &configuration) {
        Ok(profile) => profile,
        Err(_error) => {
            fail_and_reset(base);
            return Err(VirtioMmioError::UnsupportedProfile);
        }
    };
    write_features(base, profile.negotiated_features());
    let feature_status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
    write_status(base, feature_status);
    if mmio_read(base, MMIO_STATUS) & STATUS_FEATURES_OK == 0 {
        fail_and_reset(base);
        return Err(VirtioMmioError::UnsupportedProfile);
    }

    let queue = match QueueMemory::new() {
        Ok(queue) => Box::new(queue),
        Err(error) => {
            fail_and_reset(base);
            return Err(error);
        }
    };
    if let Err(error) = configure_queue(base, &queue) {
        fail_and_reset(base);
        return Err(error);
    }
    write_status(base, feature_status | STATUS_DRIVER_OK);
    if mmio_read(base, MMIO_STATUS) & STATUS_DRIVER_OK == 0 {
        fail_and_reset(base);
        return Err(VirtioMmioError::DeviceState);
    }
    Ok(VirtioBlock::new(
        VirtioMmioTransport {
            base,
            queue,
            available_index: 0,
            used_index: 0,
        },
        profile,
    ))
}

fn configure_queue(base: usize, queue: &QueueMemory) -> Result<(), VirtioMmioError> {
    mmio_write(base, MMIO_QUEUE_SEL, u32::from(REQUEST_QUEUE_INDEX));
    if mmio_read(base, MMIO_QUEUE_READY) != 0
        || mmio_read(base, MMIO_QUEUE_SIZE_MAX) < u32::from(REQUEST_QUEUE_SIZE)
    {
        return Err(VirtioMmioError::InvalidQueue);
    }
    mmio_write(base, MMIO_QUEUE_SIZE, u32::from(REQUEST_QUEUE_SIZE));
    write_address_pair(
        base,
        MMIO_QUEUE_DESC_LOW,
        MMIO_QUEUE_DESC_HIGH,
        queue.address(queue.layout.descriptor_offset())?,
    );
    write_address_pair(
        base,
        MMIO_QUEUE_DRIVER_LOW,
        MMIO_QUEUE_DRIVER_HIGH,
        queue.address(queue.layout.available_offset())?,
    );
    write_address_pair(
        base,
        MMIO_QUEUE_DEVICE_LOW,
        MMIO_QUEUE_DEVICE_HIGH,
        queue.address(queue.layout.used_offset())?,
    );
    queue.write_u16(queue.layout.available_offset(), NO_INTERRUPT);
    dma_publish();
    mmio_write(base, MMIO_QUEUE_READY, 1);
    if mmio_read(base, MMIO_QUEUE_READY) != 1 {
        return Err(VirtioMmioError::InvalidQueue);
    }
    Ok(())
}

fn read_features(base: usize) -> u64 {
    mmio_write(base, MMIO_DEVICE_FEATURES_SEL, 0);
    let low = mmio_read(base, MMIO_DEVICE_FEATURES);
    mmio_write(base, MMIO_DEVICE_FEATURES_SEL, 1);
    let high = mmio_read(base, MMIO_DEVICE_FEATURES);
    u64::from(low) | (u64::from(high) << 32)
}

fn write_features(base: usize, features: u64) {
    mmio_write(base, MMIO_DRIVER_FEATURES_SEL, 0);
    mmio_write(base, MMIO_DRIVER_FEATURES, low_u32(features));
    mmio_write(base, MMIO_DRIVER_FEATURES_SEL, 1);
    mmio_write(base, MMIO_DRIVER_FEATURES, high_u32(features));
}

fn read_stable_configuration(base: usize) -> Result<[u8; 24], VirtioMmioError> {
    for _ in 0..CONFIG_READ_ATTEMPTS {
        let before = mmio_read(base, MMIO_CONFIG_GENERATION);
        let mut configuration = [0_u8; 24];
        for (index, chunk) in configuration.chunks_exact_mut(4).enumerate() {
            let offset = index
                .checked_mul(4)
                .and_then(|value| MMIO_CONFIG.checked_add(value))
                .ok_or(VirtioMmioError::DeviceState)?;
            chunk.copy_from_slice(&mmio_read(base, offset).to_le_bytes());
        }
        let after = mmio_read(base, MMIO_CONFIG_GENERATION);
        if before == after {
            return Ok(configuration);
        }
    }
    Err(VirtioMmioError::DeviceState)
}

fn write_status(base: usize, status: u32) {
    mmio_write(base, MMIO_STATUS, status);
}

fn fail_and_reset(base: usize) {
    let status = mmio_read(base, MMIO_STATUS);
    mmio_write(base, MMIO_STATUS, status | STATUS_FAILED);
    if reset_device(base).is_err() {
        terminal_park();
    }
}

fn reset_device(base: usize) -> Result<(), VirtioMmioError> {
    mmio_write(base, MMIO_STATUS, 0);
    for _ in 0..REGISTER_SPIN_LIMIT {
        if mmio_read(base, MMIO_STATUS) == 0 {
            return Ok(());
        }
        spin_loop();
    }
    Err(VirtioMmioError::DeviceState)
}

fn write_address_pair(base: usize, low: usize, high: usize, address: u64) {
    mmio_write(base, low, low_u32(address));
    mmio_write(base, high, high_u32(address));
}

fn low_u32(value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn high_u32(value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
}

/// Live MMIO and split-queue state for one synchronous device.
pub struct VirtioMmioTransport {
    base: usize,
    queue: Box<QueueMemory>,
    available_index: u16,
    used_index: u16,
}

impl fmt::Debug for VirtioMmioTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VirtioMmioTransport")
            .field("base", &self.base)
            .field("available_index", &self.available_index)
            .field("used_index", &self.used_index)
            .finish_non_exhaustive()
    }
}

impl VirtioBlockTransport for VirtioMmioTransport {
    fn read(&mut self, request: RequestPlan, destination: &mut [u8]) -> Result<(), BlockError> {
        if request.kind() != RequestKind::Read || request.data_bytes() as usize != destination.len()
        {
            return Err(BlockError::Device);
        }
        destination.fill(0);
        self.execute(request, destination.as_mut_ptr() as u64)
    }

    fn write(&mut self, request: RequestPlan, source: &[u8]) -> Result<(), BlockError> {
        if request.kind() != RequestKind::Write || request.data_bytes() as usize != source.len() {
            return Err(BlockError::Device);
        }
        self.execute(request, source.as_ptr() as u64)
    }

    fn flush(&mut self, request: RequestPlan) -> Result<(), BlockError> {
        if request.kind() != RequestKind::Flush || request.data_bytes() != 0 {
            return Err(BlockError::Device);
        }
        self.execute(request, 0)
    }
}

impl VirtioMmioTransport {
    fn execute(&mut self, request: RequestPlan, data_address: u64) -> Result<(), BlockError> {
        self.queue.prepare(request, data_address)?;
        let slot = usize::from(self.available_index % REQUEST_QUEUE_SIZE);
        let ring_offset = self
            .queue
            .layout
            .available_offset()
            .checked_add(4)
            .and_then(|offset| offset.checked_add(slot * 2))
            .ok_or(BlockError::Device)?;
        self.queue.write_u16(ring_offset, 0);
        dma_publish();
        self.available_index = self.available_index.wrapping_add(1);
        self.queue.write_u16(
            self.queue.layout.available_offset() + 2,
            self.available_index,
        );
        dma_publish();
        mmio_write(self.base, MMIO_QUEUE_NOTIFY, u32::from(REQUEST_QUEUE_INDEX));

        let expected_used = self.used_index.wrapping_add(1);
        let mut completed = false;
        for _ in 0..REGISTER_SPIN_LIMIT {
            if self.queue.read_u16(self.queue.layout.used_offset() + 2) == expected_used {
                completed = true;
                break;
            }
            spin_loop();
        }
        if !completed {
            if reset_device(self.base).is_err() {
                terminal_park();
            }
            return Err(BlockError::Device);
        }
        dma_observe();
        let used_slot = usize::from(self.used_index % REQUEST_QUEUE_SIZE);
        let used_offset = self
            .queue
            .layout
            .used_offset()
            .checked_add(4)
            .and_then(|offset| offset.checked_add(used_slot * 8))
            .ok_or(BlockError::Device)?;
        let descriptor_head = self.queue.read_u32(used_offset);
        let used_bytes = self.queue.read_u32(used_offset + 4);
        let status = self.queue.read_u8(REQUEST_STATUS_OFFSET);
        self.used_index = expected_used;
        let interrupt_status = mmio_read(self.base, MMIO_INTERRUPT_STATUS) & 0x3;
        if interrupt_status != 0 {
            mmio_write(self.base, MMIO_INTERRUPT_ACK, interrupt_status);
        }
        request.validate_completion(descriptor_head, used_bytes, status)
    }
}

impl Drop for VirtioMmioTransport {
    fn drop(&mut self) {
        if reset_device(self.base).is_err() {
            terminal_park();
        }
    }
}

#[repr(C, align(4096))]
struct QueueMemory {
    bytes: [UnsafeCell<u8>; QUEUE_ALLOCATION_BYTES],
    layout: SplitQueueLayout,
}

impl QueueMemory {
    fn new() -> Result<Self, VirtioMmioError> {
        let layout =
            SplitQueueLayout::new(REQUEST_QUEUE_SIZE).map_err(|_| VirtioMmioError::InvalidQueue)?;
        if layout.total_bytes() > REQUEST_HEADER_OFFSET
            || REQUEST_STATUS_OFFSET >= QUEUE_ALLOCATION_BYTES
        {
            return Err(VirtioMmioError::InvalidQueue);
        }
        Ok(Self {
            bytes: core::array::from_fn(|_| UnsafeCell::new(0)),
            layout,
        })
    }

    fn address(&self, offset: usize) -> Result<u64, VirtioMmioError> {
        if offset >= QUEUE_ALLOCATION_BYTES {
            return Err(VirtioMmioError::InvalidQueue);
        }
        let pointer = self.bytes[offset].get();
        u64::try_from(pointer as usize).map_err(|_| VirtioMmioError::InvalidQueue)
    }

    fn prepare(&self, request: RequestPlan, data_address: u64) -> Result<(), BlockError> {
        self.write_bytes(REQUEST_HEADER_OFFSET, &request.header());
        self.write_u8(REQUEST_STATUS_OFFSET, 0xff);
        let header = self
            .address(REQUEST_HEADER_OFFSET)
            .map_err(|_| BlockError::Device)?;
        let status = self
            .address(REQUEST_STATUS_OFFSET)
            .map_err(|_| BlockError::Device)?;
        self.write_descriptor(0, header, REQUEST_HEADER_BYTES, DESCRIPTOR_NEXT, 1);
        match request.kind() {
            RequestKind::Read => {
                self.write_descriptor(
                    1,
                    data_address,
                    request.data_bytes(),
                    DESCRIPTOR_NEXT | DESCRIPTOR_WRITE,
                    2,
                );
                self.write_descriptor(2, status, 1, DESCRIPTOR_WRITE, 0);
            }
            RequestKind::Write => {
                self.write_descriptor(1, data_address, request.data_bytes(), DESCRIPTOR_NEXT, 2);
                self.write_descriptor(2, status, 1, DESCRIPTOR_WRITE, 0);
            }
            RequestKind::Flush => {
                self.write_descriptor(1, status, 1, DESCRIPTOR_WRITE, 0);
                self.write_descriptor(2, 0, 0, 0, 0);
            }
        }
        Ok(())
    }

    fn write_descriptor(&self, index: usize, address: u64, len: u32, flags: u16, next: u16) {
        let offset = self.layout.descriptor_offset() + index * 16;
        self.write_u64(offset, address);
        self.write_u32(offset + 8, len);
        self.write_u16(offset + 12, flags);
        self.write_u16(offset + 14, next);
    }

    fn write_bytes(&self, offset: usize, bytes: &[u8]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.write_u8(offset + index, byte);
        }
    }

    fn read_u8(&self, offset: usize) -> u8 {
        // SAFETY: Every call uses a checked constant or a layout-derived offset
        // within this live aligned allocation. Volatile access observes DMA.
        unsafe { ptr::read_volatile(self.bytes[offset].get()) }
    }

    fn write_u8(&self, offset: usize, value: u8) {
        // SAFETY: Every call uses a checked constant or a layout-derived offset
        // within this exclusively driver-written part of the live allocation.
        unsafe { ptr::write_volatile(self.bytes[offset].get(), value) };
    }

    fn read_u16(&self, offset: usize) -> u16 {
        let bytes = [self.read_u8(offset), self.read_u8(offset + 1)];
        u16::from_le_bytes(bytes)
    }

    fn write_u16(&self, offset: usize, value: u16) {
        self.write_bytes(offset, &value.to_le_bytes());
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let bytes = [
            self.read_u8(offset),
            self.read_u8(offset + 1),
            self.read_u8(offset + 2),
            self.read_u8(offset + 3),
        ];
        u32::from_le_bytes(bytes)
    }

    fn write_u32(&self, offset: usize, value: u32) {
        self.write_bytes(offset, &value.to_le_bytes());
    }

    fn write_u64(&self, offset: usize, value: u64) {
        self.write_bytes(offset, &value.to_le_bytes());
    }
}

fn mmio_read(base: usize, offset: usize) -> u32 {
    let address = base + offset;
    // SAFETY: Callers use aligned offsets within the mapped pinned `virt`
    // aperture. Each register is read according to the virtio-MMIO profile.
    unsafe { ptr::read_volatile(address as *const u32) }
}

fn mmio_write(base: usize, offset: usize, value: u32) {
    let address = base + offset;
    // SAFETY: Callers use aligned writable register offsets within the mapped
    // pinned `virt` aperture and follow the required initialization order.
    unsafe { ptr::write_volatile(address as *mut u32, value) };
}

fn dma_publish() {
    // SAFETY: `dmb oshst` orders normal-memory queue and payload writes before
    // the following device notification in the outer-shareable domain.
    unsafe { core::arch::asm!("dmb oshst", options(nostack, preserves_flags)) };
}

fn dma_observe() {
    // SAFETY: `dmb oshld` orders the observed used index before subsequent
    // normal-memory reads of device-written ring, status, and payload bytes.
    unsafe { core::arch::asm!("dmb oshld", options(nostack, preserves_flags)) };
}

fn terminal_park() -> ! {
    loop {
        // SAFETY: A device that cannot confirm reset may still hold DMA
        // pointers, so returning would violate memory ownership. Parking with
        // interrupts masked is the only safe terminal outcome.
        unsafe { core::arch::asm!("msr daifset, #0xf", "wfe", options(nomem, nostack)) };
    }
}

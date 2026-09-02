//! Descriptor-selected modern virtio-MMIO block and network transport.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt;
use core::hint::spin_loop;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{compiler_fence, fence};

use troe_block::BlockError;
use troe_memory::{BASE_PAGE_SIZE, PhysicalRange};
use troe_net::{
    ETHERNET_HEADER_BYTES, MAX_FRAME_BYTES, MacAddress, NETWORK_QUEUE_SIZE, NetError,
    NetworkDevice, RECEIVE_QUEUE_INDEX, TRANSMIT_QUEUE_INDEX, VIRTIO_DEVICE_ID_NETWORK,
    VIRTIO_NET_HEADER_BYTES, VirtioNetworkProfile,
};
use troe_platform::{MmioRole, VirtioTransportKind};
use troe_virtio::{
    REQUEST_HEADER_BYTES, REQUEST_QUEUE_INDEX, REQUEST_QUEUE_SIZE, RequestKind, RequestPlan,
    SplitQueueLayout, VIRTIO_DEVICE_ID_BLOCK, VirtioBlock, VirtioBlockProfile,
    VirtioBlockTransport,
};

use crate::mechanism::{
    ActiveNetworkInterrupt, CompletionWait, CompletionWaitState, DmaInitializationState,
    NetworkInterruptRoute, UsedIndexTransition, claim_network_interrupt_publication,
    classify_used_index, monotonic_millis, revoke_network_interrupt_publication,
};

const MAX_NATIVE_BLOCK_DEVICES: usize = 8;
const REGISTER_SPIN_LIMIT: usize = 1_000_000;
const CONFIG_READ_ATTEMPTS: usize = 8;
const QUEUE_ALLOCATION_BYTES: usize = 4096;
const REQUEST_HEADER_OFFSET: usize = 256;
const REQUEST_STATUS_OFFSET: usize = REQUEST_HEADER_OFFSET + REQUEST_HEADER_BYTES as usize;
const NETWORK_BUFFER_OFFSET: usize = 256;
const NETWORK_BUFFER_BYTES: usize = VIRTIO_NET_HEADER_BYTES + MAX_FRAME_BYTES;

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
static NETWORK_INTERRUPT_BASE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmioPlatformResources {
    aperture_base: u64,
    aperture_bytes: u64,
    slot_bytes: u64,
    slot_count: usize,
    first_interrupt: u32,
}

impl MmioPlatformResources {
    fn selected() -> Result<Self, VirtioMmioError> {
        let platform = crate::selected_platform().map_err(|_| VirtioMmioError::InvalidResource)?;
        let aperture = platform
            .mmio(MmioRole::VirtioMmio)
            .ok_or(VirtioMmioError::InvalidResource)?;
        let VirtioTransportKind::Mmio {
            slot_bytes,
            slot_count,
            first_interrupt,
            ..
        } = platform.virtio()
        else {
            return Err(VirtioMmioError::InvalidResource);
        };
        let slot_bytes = u64::from(slot_bytes);
        let slot_count = usize::from(slot_count);
        let described_bytes = slot_bytes
            .checked_mul(u64::try_from(slot_count).map_err(|_| VirtioMmioError::InvalidResource)?)
            .ok_or(VirtioMmioError::InvalidResource)?;
        let minimum_slot_bytes =
            u64::try_from(MMIO_CONFIG + 24).map_err(|_| VirtioMmioError::InvalidResource)?;
        if described_bytes != aperture.byte_len()
            || slot_bytes < minimum_slot_bytes
            || !slot_bytes.is_multiple_of(4)
            || !aperture.base().is_multiple_of(4)
        {
            return Err(VirtioMmioError::InvalidResource);
        }
        aperture
            .base()
            .checked_add(aperture.byte_len())
            .ok_or(VirtioMmioError::InvalidResource)?;
        Ok(Self {
            aperture_base: aperture.base(),
            aperture_bytes: aperture.byte_len(),
            slot_bytes,
            slot_count,
            first_interrupt,
        })
    }

    fn slot_base(self, index: usize) -> Result<usize, VirtioMmioError> {
        if index >= self.slot_count {
            return Err(VirtioMmioError::InvalidResource);
        }
        let offset = u64::try_from(index)
            .ok()
            .and_then(|slot| slot.checked_mul(self.slot_bytes))
            .ok_or(VirtioMmioError::InvalidResource)?;
        let address = self
            .aperture_base
            .checked_add(offset)
            .ok_or(VirtioMmioError::InvalidResource)?;
        let slot_end = address
            .checked_add(self.slot_bytes)
            .ok_or(VirtioMmioError::InvalidResource)?;
        let aperture_end = self
            .aperture_base
            .checked_add(self.aperture_bytes)
            .ok_or(VirtioMmioError::InvalidResource)?;
        if slot_end > aperture_end {
            return Err(VirtioMmioError::InvalidResource);
        }
        usize::try_from(slot_end).map_err(|_| VirtioMmioError::InvalidResource)?;
        usize::try_from(address).map_err(|_| VirtioMmioError::InvalidResource)
    }

    fn slot_index(self, base: usize) -> Result<u32, VirtioMmioError> {
        let offset = u64::try_from(base)
            .ok()
            .and_then(|base| base.checked_sub(self.aperture_base))
            .ok_or(VirtioMmioError::InvalidResource)?;
        if !offset.is_multiple_of(self.slot_bytes) {
            return Err(VirtioMmioError::InvalidResource);
        }
        let index = u32::try_from(offset / self.slot_bytes)
            .map_err(|_| VirtioMmioError::InvalidResource)?;
        if usize::try_from(index).map_err(|_| VirtioMmioError::InvalidResource)? >= self.slot_count
        {
            return Err(VirtioMmioError::InvalidResource);
        }
        Ok(index)
    }
}

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

/// One initialized modern virtio-MMIO block device behind the portable adapter.
pub type NativeVirtioBlock = VirtioBlock<VirtioMmioTransport>;

/// One initialized modern virtio-MMIO network device.
pub struct NativeVirtioNetwork {
    base: usize,
    mac: MacAddress,
    receive: Box<NetworkQueueMemory>,
    transmit: Box<NetworkQueueMemory>,
    receive_available: u16,
    receive_used: u16,
    transmit_available: u16,
    transmit_used: u16,
    interrupt_route: Option<NetworkInterruptRoute>,
    active_interrupt: Option<ActiveNetworkInterrupt>,
    failed: bool,
}

struct MmioInitializationGuard {
    base: usize,
    state: DmaInitializationState,
}

impl MmioInitializationGuard {
    const fn new(base: usize) -> Self {
        Self {
            base,
            state: DmaInitializationState::new(),
        }
    }

    const fn mark_queue_published(&mut self) {
        self.state.mark_queue_published();
    }

    const fn mark_driver_ok(&mut self) {
        self.state.mark_driver_ok();
    }

    const fn transfer_ownership(&mut self) {
        self.state.transfer_ownership();
    }
}

impl Drop for MmioInitializationGuard {
    fn drop(&mut self) {
        if self.state.cleanup_requires_reset() {
            fail_and_reset(self.base);
        }
    }
}

/// Page-aligned MMIO aperture owned by the selected platform descriptor.
///
/// # Errors
///
/// Returns a typed failure if the fixed aperture is not page-aligned or cannot
/// form a checked physical range.
pub fn virtio_mmio_device_ranges() -> Result<[PhysicalRange; 1], VirtioMmioError> {
    let resources = MmioPlatformResources::selected()?;
    if !resources.aperture_base.is_multiple_of(BASE_PAGE_SIZE)
        || !resources.aperture_bytes.is_multiple_of(BASE_PAGE_SIZE)
    {
        return Err(VirtioMmioError::InvalidResource);
    }
    let pages = resources.aperture_bytes / BASE_PAGE_SIZE;
    let range = PhysicalRange::from_pages(resources.aperture_base, pages)
        .map_err(|_| VirtioMmioError::InvalidResource)?;
    Ok([range])
}

/// Discover and initialize every modern virtio-MMIO block device in the
/// selected platform aperture.
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
    let resources = MmioPlatformResources::selected()?;
    let mut devices = Vec::new();
    devices
        .try_reserve_exact(MAX_NATIVE_BLOCK_DEVICES)
        .map_err(|_| VirtioMmioError::QueueAllocation)?;
    for index in 0..resources.slot_count {
        let base = resources.slot_base(index)?;
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

/// Discover exactly zero or one modern virtio-MMIO network device.
///
/// # Errors
///
/// Rejects multiple NICs and every device that cannot establish the minimal
/// feature, MAC, two-queue, DMA, status, and reset profile.
pub fn discover_virtio_mmio_network() -> Result<Option<NativeVirtioNetwork>, VirtioMmioError> {
    let resources = MmioPlatformResources::selected()?;
    let mut network = None;
    for index in 0..resources.slot_count {
        let base = resources.slot_base(index)?;
        if mmio_read(base, MMIO_MAGIC_VALUE) != VIRTIO_MAGIC
            || mmio_read(base, MMIO_VERSION) != VIRTIO_MMIO_MODERN_VERSION
            || mmio_read(base, MMIO_DEVICE_ID) != VIRTIO_DEVICE_ID_NETWORK
        {
            continue;
        }
        if network.is_some() {
            return Err(VirtioMmioError::DeviceLimit);
        }
        network = Some(initialize_network_device(base, resources)?);
    }
    Ok(network)
}

fn initialize_network_device(
    base: usize,
    resources: MmioPlatformResources,
) -> Result<NativeVirtioNetwork, VirtioMmioError> {
    let interrupt_route = virtio_mmio_interrupt_route(base, resources)?;
    // Keep both DMA allocations older than the reset guard: Rust drops locals
    // in reverse declaration order, so every error resets before freeing them.
    let receive = Box::new(NetworkQueueMemory::new()?);
    let transmit = Box::new(NetworkQueueMemory::new()?);
    let mut reset_guard = MmioInitializationGuard::new(base);
    reset_device(base)?;
    write_status(base, STATUS_ACKNOWLEDGE);
    write_status(base, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    let profile = VirtioNetworkProfile::negotiate(
        read_features(base),
        &read_stable_network_configuration(base)?,
    )
    .map_err(|_| VirtioMmioError::UnsupportedProfile)?;
    write_features(base, profile.negotiated_features());
    let feature_status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
    write_status(base, feature_status);
    if mmio_read(base, MMIO_STATUS) & STATUS_FEATURES_OK == 0 {
        return Err(VirtioMmioError::UnsupportedProfile);
    }
    configure_network_queue(base, RECEIVE_QUEUE_INDEX, &receive)?;
    reset_guard.mark_queue_published();
    configure_network_queue(base, TRANSMIT_QUEUE_INDEX, &transmit)?;
    reset_guard.mark_queue_published();
    write_status(base, feature_status | STATUS_DRIVER_OK);
    if mmio_read(base, MMIO_STATUS) & STATUS_DRIVER_OK == 0 {
        return Err(VirtioMmioError::DeviceState);
    }
    reset_guard.mark_driver_ok();
    let mut network = NativeVirtioNetwork {
        base,
        mac: profile.mac(),
        receive,
        transmit,
        receive_available: 0,
        receive_used: 0,
        transmit_available: 0,
        transmit_used: 0,
        interrupt_route: Some(interrupt_route),
        active_interrupt: None,
        failed: false,
    };
    reset_guard.transfer_ownership();
    network
        .post_receive()
        .map_err(|_| VirtioMmioError::InvalidQueue)?;
    Ok(network)
}

fn virtio_mmio_interrupt_route(
    base: usize,
    resources: MmioPlatformResources,
) -> Result<NetworkInterruptRoute, VirtioMmioError> {
    let slot = resources.slot_index(base)?;
    let slot_count =
        u32::try_from(resources.slot_count).map_err(|_| VirtioMmioError::InvalidResource)?;
    NetworkInterruptRoute::virtio_mmio(slot, slot_count, resources.first_interrupt)
        .map_err(|_| VirtioMmioError::InvalidResource)
}

fn configure_network_queue(
    base: usize,
    index: u16,
    queue: &NetworkQueueMemory,
) -> Result<(), VirtioMmioError> {
    mmio_write(base, MMIO_QUEUE_SEL, u32::from(index));
    if mmio_read(base, MMIO_QUEUE_READY) != 0
        || mmio_read(base, MMIO_QUEUE_SIZE_MAX) < u32::from(NETWORK_QUEUE_SIZE)
    {
        return Err(VirtioMmioError::InvalidQueue);
    }
    mmio_write(base, MMIO_QUEUE_SIZE, u32::from(NETWORK_QUEUE_SIZE));
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
    let flags = if index == RECEIVE_QUEUE_INDEX {
        0
    } else {
        NO_INTERRUPT
    };
    queue.write_u16(queue.layout.available_offset(), flags);
    dma_publish();
    mmio_write(base, MMIO_QUEUE_READY, 1);
    if mmio_read(base, MMIO_QUEUE_READY) != 1 {
        return Err(VirtioMmioError::InvalidQueue);
    }
    Ok(())
}

fn read_stable_network_configuration(base: usize) -> Result<[u8; 8], VirtioMmioError> {
    for _ in 0..CONFIG_READ_ATTEMPTS {
        let before = mmio_read(base, MMIO_CONFIG_GENERATION);
        let mut configuration = [0_u8; 8];
        for (index, chunk) in configuration.chunks_exact_mut(4).enumerate() {
            chunk.copy_from_slice(&mmio_read(base, MMIO_CONFIG + index * 4).to_le_bytes());
        }
        if before == mmio_read(base, MMIO_CONFIG_GENERATION) {
            return Ok(configuration);
        }
    }
    Err(VirtioMmioError::DeviceState)
}

fn initialize_device(base: usize) -> Result<NativeVirtioBlock, VirtioMmioError> {
    // Keep the DMA allocation older than the reset guard: Rust drops locals in
    // reverse declaration order, so every error resets before freeing `queue`.
    let queue = Box::new(QueueMemory::new()?);
    let mut reset_guard = MmioInitializationGuard::new(base);
    reset_device(base)?;
    write_status(base, STATUS_ACKNOWLEDGE);
    write_status(base, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let offered_features = read_features(base);
    let configuration = read_stable_configuration(base)?;
    let profile = VirtioBlockProfile::negotiate(offered_features, &configuration)
        .map_err(|_| VirtioMmioError::UnsupportedProfile)?;
    write_features(base, profile.negotiated_features());
    let feature_status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
    write_status(base, feature_status);
    if mmio_read(base, MMIO_STATUS) & STATUS_FEATURES_OK == 0 {
        return Err(VirtioMmioError::UnsupportedProfile);
    }

    configure_queue(base, &queue)?;
    reset_guard.mark_queue_published();
    write_status(base, feature_status | STATUS_DRIVER_OK);
    if mmio_read(base, MMIO_STATUS) & STATUS_DRIVER_OK == 0 {
        return Err(VirtioMmioError::DeviceState);
    }
    reset_guard.mark_driver_ok();
    let device = VirtioBlock::new(
        VirtioMmioTransport {
            base,
            queue,
            available_index: 0,
            used_index: 0,
        },
        profile,
    );
    reset_guard.transfer_ownership();
    Ok(device)
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
        let mut wait = CompletionWait::new(monotonic_millis(), REGISTER_SPIN_LIMIT);
        loop {
            if self.queue.read_u16(self.queue.layout.used_offset() + 2) == expected_used {
                break;
            }
            if wait.poll(monotonic_millis()) == CompletionWaitState::Expired {
                if reset_device(self.base).is_err() {
                    terminal_park();
                }
                return Err(BlockError::Timeout);
            }
            spin_loop();
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

impl NetworkDevice for NativeVirtioNetwork {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if self.failed {
            return Err(NetError::Device);
        }
        self.transmit.prepare_transmit(frame)?;
        publish_network_descriptor(
            &self.transmit,
            &mut self.transmit_available,
            TRANSMIT_QUEUE_INDEX,
            self.base,
        )?;
        let expected = self.transmit_used.wrapping_add(1);
        for _ in 0..REGISTER_SPIN_LIMIT {
            let observed = self
                .transmit
                .read_u16(self.transmit.layout.used_offset() + 2);
            match classify_used_index(self.transmit_used, observed) {
                UsedIndexTransition::Empty => spin_loop(),
                UsedIndexTransition::Completed => {
                    dma_observe();
                    let Ok((head, bytes)) = self.transmit.used_element(self.transmit_used) else {
                        return Err(self.fail_device(NetError::Device));
                    };
                    self.transmit_used = expected;
                    return if head == 0 && bytes == 0 {
                        Ok(())
                    } else {
                        Err(self.fail_device(NetError::Device))
                    };
                }
                UsedIndexTransition::Invalid => {
                    return Err(self.fail_device(NetError::Device));
                }
            }
        }
        Err(self.fail_device(NetError::Timeout))
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        if self.failed {
            return Err(NetError::Device);
        }
        let expected = self.receive_used.wrapping_add(1);
        let observed = self.receive.read_u16(self.receive.layout.used_offset() + 2);
        match classify_used_index(self.receive_used, observed) {
            UsedIndexTransition::Empty => return Ok(None),
            UsedIndexTransition::Completed => {}
            UsedIndexTransition::Invalid => return Err(self.fail_device(NetError::Device)),
        }
        dma_observe();
        let Ok((head, bytes)) = self.receive.used_element(self.receive_used) else {
            return Err(self.fail_device(NetError::Device));
        };
        self.receive_used = expected;
        let Ok(bytes) = usize::try_from(bytes) else {
            return Err(self.fail_device(NetError::Device));
        };
        if head != 0
            || !(VIRTIO_NET_HEADER_BYTES + ETHERNET_HEADER_BYTES
                ..=VIRTIO_NET_HEADER_BYTES + MAX_FRAME_BYTES)
                .contains(&bytes)
            || !self.receive.header_is_zero()
        {
            return Err(self.fail_device(NetError::Device));
        }
        let Ok(frame) = self.receive.copy_frame(bytes - VIRTIO_NET_HEADER_BYTES) else {
            return Err(self.fail_device(NetError::Device));
        };
        if self.post_receive().is_err() {
            return Err(self.fail_device(NetError::Device));
        }
        Ok(Some(frame))
    }
}

impl NativeVirtioNetwork {
    /// Connect this slot's completion source to the owned interrupt controller.
    ///
    /// The IRQ handler only acknowledges the MMIO source and schedules a
    /// bounded cooperative poll; it never parses or allocates packets.
    ///
    /// # Errors
    ///
    /// Returns a resource error when the slot cannot map to an implemented SPI.
    pub fn enable_interrupts(&mut self) -> Result<(), VirtioMmioError> {
        if self.failed || self.active_interrupt.is_some() {
            return Err(VirtioMmioError::DeviceState);
        }
        let route = self
            .interrupt_route
            .take()
            .ok_or(VirtioMmioError::DeviceState)?;
        let prepared = crate::mechanism::prepare_network_interrupt(route)
            .map_err(|_| VirtioMmioError::InvalidResource)?;
        if !claim_network_interrupt_publication(&NETWORK_INTERRUPT_BASE, self.base) {
            crate::mechanism::cancel_prepared_network_interrupt(prepared);
            return Err(VirtioMmioError::DeviceState);
        }
        self.active_interrupt = Some(crate::mechanism::activate_network_interrupt(prepared));
        Ok(())
    }

    fn post_receive(&mut self) -> Result<(), NetError> {
        self.receive.prepare_receive()?;
        publish_network_descriptor(
            &self.receive,
            &mut self.receive_available,
            RECEIVE_QUEUE_INDEX,
            self.base,
        )
    }

    fn fail_device(&mut self, error: NetError) -> NetError {
        self.failed = true;
        self.disable_interrupts();
        if reset_device(self.base).is_err() {
            terminal_park();
        }
        error
    }

    fn disable_interrupts(&mut self) {
        if let Some(active) = self.active_interrupt.take() {
            let deactivated = crate::mechanism::deactivate_network_interrupt(active);
            if !revoke_network_interrupt_publication(&NETWORK_INTERRUPT_BASE, self.base) {
                terminal_park();
            }
            crate::mechanism::finish_network_interrupt_deactivation(deactivated);
        }
    }
}

pub(crate) fn acknowledge_network_interrupt_from_isr() -> bool {
    let base = NETWORK_INTERRUPT_BASE.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    let status = mmio_read(base, MMIO_INTERRUPT_STATUS) & 0x3;
    if status != 0 {
        mmio_write(base, MMIO_INTERRUPT_ACK, status);
    }
    status & 1 != 0
}

impl Drop for NativeVirtioNetwork {
    fn drop(&mut self) {
        self.disable_interrupts();
        if reset_device(self.base).is_err() {
            terminal_park();
        }
    }
}

fn publish_network_descriptor(
    queue: &NetworkQueueMemory,
    available: &mut u16,
    index: u16,
    base: usize,
) -> Result<(), NetError> {
    let slot = usize::from(*available % NETWORK_QUEUE_SIZE);
    let ring = queue
        .layout
        .available_offset()
        .checked_add(4 + slot * 2)
        .ok_or(NetError::Device)?;
    queue.write_u16(ring, 0);
    dma_publish();
    *available = available.wrapping_add(1);
    queue.write_u16(queue.layout.available_offset() + 2, *available);
    dma_publish();
    mmio_write(base, MMIO_QUEUE_NOTIFY, u32::from(index));
    Ok(())
}

#[repr(C, align(4096))]
struct NetworkQueueMemory {
    bytes: [UnsafeCell<u8>; QUEUE_ALLOCATION_BYTES],
    layout: SplitQueueLayout,
}

impl NetworkQueueMemory {
    fn new() -> Result<Self, VirtioMmioError> {
        let layout =
            SplitQueueLayout::new(NETWORK_QUEUE_SIZE).map_err(|_| VirtioMmioError::InvalidQueue)?;
        if layout.total_bytes() > NETWORK_BUFFER_OFFSET
            || NETWORK_BUFFER_OFFSET + NETWORK_BUFFER_BYTES > QUEUE_ALLOCATION_BYTES
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
        u64::try_from(self.bytes[offset].get() as usize).map_err(|_| VirtioMmioError::InvalidQueue)
    }

    fn prepare_receive(&self) -> Result<(), NetError> {
        for index in 0..NETWORK_BUFFER_BYTES {
            self.write_u8(NETWORK_BUFFER_OFFSET + index, 0);
        }
        self.write_descriptor(
            self.address(NETWORK_BUFFER_OFFSET)
                .map_err(|_| NetError::Device)?,
            u32::try_from(NETWORK_BUFFER_BYTES).map_err(|_| NetError::Device)?,
            DESCRIPTOR_WRITE,
        );
        Ok(())
    }

    fn prepare_transmit(&self, frame: &[u8]) -> Result<(), NetError> {
        if !(ETHERNET_HEADER_BYTES..=MAX_FRAME_BYTES).contains(&frame.len()) {
            return Err(NetError::Invalid);
        }
        for index in 0..VIRTIO_NET_HEADER_BYTES {
            self.write_u8(NETWORK_BUFFER_OFFSET + index, 0);
        }
        self.write_bytes(NETWORK_BUFFER_OFFSET + VIRTIO_NET_HEADER_BYTES, frame);
        self.write_descriptor(
            self.address(NETWORK_BUFFER_OFFSET)
                .map_err(|_| NetError::Device)?,
            u32::try_from(VIRTIO_NET_HEADER_BYTES + frame.len()).map_err(|_| NetError::Device)?,
            0,
        );
        Ok(())
    }

    fn write_descriptor(&self, address: u64, len: u32, flags: u16) {
        let offset = self.layout.descriptor_offset();
        self.write_u64(offset, address);
        self.write_u32(offset + 8, len);
        self.write_u16(offset + 12, flags);
        self.write_u16(offset + 14, 0);
    }

    fn used_element(&self, used: u16) -> Result<(u32, u32), NetError> {
        let slot = usize::from(used % NETWORK_QUEUE_SIZE);
        let offset = self
            .layout
            .used_offset()
            .checked_add(4 + slot * 8)
            .ok_or(NetError::Device)?;
        Ok((self.read_u32(offset), self.read_u32(offset + 4)))
    }

    fn header_is_zero(&self) -> bool {
        (0..VIRTIO_NET_HEADER_BYTES).all(|index| self.read_u8(NETWORK_BUFFER_OFFSET + index) == 0)
    }

    fn copy_frame(&self, bytes: usize) -> Result<Vec<u8>, NetError> {
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(bytes)
            .map_err(|_| NetError::Exhausted)?;
        for index in 0..bytes {
            frame.push(self.read_u8(NETWORK_BUFFER_OFFSET + VIRTIO_NET_HEADER_BYTES + index));
        }
        Ok(frame)
    }

    fn write_bytes(&self, offset: usize, bytes: &[u8]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.write_u8(offset + index, byte);
        }
    }

    fn read_u8(&self, offset: usize) -> u8 {
        // SAFETY: All offsets are queue-layout or fixed-buffer checked and the
        // aligned allocation remains alive while DMA is enabled.
        unsafe { ptr::read_volatile(self.bytes[offset].get()) }
    }

    fn write_u8(&self, offset: usize, value: u8) {
        // SAFETY: Driver-written queue and buffer offsets are checked above.
        unsafe { ptr::write_volatile(self.bytes[offset].get(), value) };
    }

    fn read_u16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.read_u8(offset), self.read_u8(offset + 1)])
    }

    fn write_u16(&self, offset: usize, value: u16) {
        self.write_bytes(offset, &value.to_le_bytes());
    }

    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.read_u8(offset),
            self.read_u8(offset + 1),
            self.read_u8(offset + 2),
            self.read_u8(offset + 3),
        ])
    }

    fn write_u32(&self, offset: usize, value: u32) {
        self.write_bytes(offset, &value.to_le_bytes());
    }

    fn write_u64(&self, offset: usize, value: u64) {
        self.write_bytes(offset, &value.to_le_bytes());
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

#[cfg(target_arch = "aarch64")]
fn dma_publish() {
    // SAFETY: `dmb oshst` orders normal-memory queue and payload writes before
    // the following device notification in the outer-shareable domain.
    unsafe { core::arch::asm!("dmb oshst", options(nostack, preserves_flags)) };
}

#[cfg(target_arch = "aarch64")]
fn dma_observe() {
    // SAFETY: `dmb oshld` orders the observed used index before subsequent
    // normal-memory reads of device-written ring, status, and payload bytes.
    unsafe { core::arch::asm!("dmb oshld", options(nostack, preserves_flags)) };
}

#[cfg(target_arch = "x86_64")]
fn dma_publish() {
    compiler_fence(Ordering::Release);
    fence(Ordering::SeqCst);
}

#[cfg(target_arch = "x86_64")]
fn dma_observe() {
    fence(Ordering::SeqCst);
    compiler_fence(Ordering::Acquire);
}

fn terminal_park() -> ! {
    // The machine mechanism owns the architecture-specific interrupt mask and
    // terminal idle instruction. A failed reset must never return to a scope
    // that could release device-visible DMA memory.
    crate::mechanism::park()
}

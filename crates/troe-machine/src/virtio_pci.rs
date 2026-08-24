//! x86-64 q35 modern virtio PCI block transport.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt;
use core::hint::spin_loop;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering, compiler_fence, fence};

use troe_block::BlockError;
use troe_memory::{BASE_PAGE_SIZE, PhysicalRange};
use troe_net::{
    ETHERNET_HEADER_BYTES, MAX_FRAME_BYTES, MacAddress, NETWORK_QUEUE_SIZE, NetError,
    NetworkDevice, RECEIVE_QUEUE_INDEX, TRANSMIT_QUEUE_INDEX, VIRTIO_NET_HEADER_BYTES,
    VirtioNetworkProfile,
};
use troe_virtio::{
    REQUEST_HEADER_BYTES, REQUEST_QUEUE_INDEX, REQUEST_QUEUE_SIZE, RequestKind, RequestPlan,
    SplitQueueLayout, VirtioBlock, VirtioBlockProfile, VirtioBlockTransport,
};

const PCI_CONFIG_ADDRESS: u16 = 0x0cf8;
const PCI_CONFIG_DATA: u16 = 0x0cfc;
const PCI_VENDOR_VIRTIO: u16 = 0x1af4;
const PCI_DEVICE_MODERN_NETWORK: u16 = 0x1041;
const PCI_DEVICE_MODERN_BLOCK: u16 = 0x1042;
const PCI_STATUS_CAPABILITIES: u16 = 1 << 4;
const PCI_COMMAND_MEMORY: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;
const PCI_COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;
const PCI_CAP_VENDOR_SPECIFIC: u8 = 0x09;
const PCI_CAP_COMMON: u8 = 1;
const PCI_CAP_NOTIFY: u8 = 2;
const PCI_CAP_ISR: u8 = 3;
const PCI_CAP_DEVICE: u8 = 4;
const MAX_NATIVE_BLOCK_DEVICES: usize = 8;
const MAX_CAPABILITIES: usize = 48;
const REGISTER_SPIN_LIMIT: usize = 1_000_000;
const CONFIG_READ_ATTEMPTS: usize = 8;
const QUEUE_ALLOCATION_BYTES: usize = 4096;
const REQUEST_HEADER_OFFSET: usize = 256;
const REQUEST_STATUS_OFFSET: usize = REQUEST_HEADER_OFFSET + REQUEST_HEADER_BYTES as usize;
const NETWORK_BUFFER_OFFSET: usize = 256;
const NETWORK_BUFFER_BYTES: usize = VIRTIO_NET_HEADER_BYTES + MAX_FRAME_BYTES;

const COMMON_DEVICE_FEATURE_SELECT: usize = 0;
const COMMON_DEVICE_FEATURE: usize = 4;
const COMMON_DRIVER_FEATURE_SELECT: usize = 8;
const COMMON_DRIVER_FEATURE: usize = 12;
const COMMON_MSIX_CONFIG: usize = 16;
const COMMON_DEVICE_STATUS: usize = 20;
const COMMON_CONFIG_GENERATION: usize = 21;
const COMMON_QUEUE_SELECT: usize = 22;
const COMMON_QUEUE_SIZE: usize = 24;
const COMMON_QUEUE_MSIX_VECTOR: usize = 26;
const COMMON_QUEUE_ENABLE: usize = 28;
const COMMON_QUEUE_NOTIFY_OFF: usize = 30;
const COMMON_QUEUE_DESC: usize = 32;
const COMMON_QUEUE_DRIVER: usize = 40;
const COMMON_QUEUE_DEVICE: usize = 48;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;
const NO_VECTOR: u16 = u16::MAX;
const DESCRIPTOR_NEXT: u16 = 1;
const DESCRIPTOR_WRITE: u16 = 2;
const NO_INTERRUPT: u16 = 1;
const PCI_INTERRUPT_LINE: u8 = 0x3c;
const PCI_INTERRUPT_PIN: u8 = 0x3d;

static NETWORK_ISR_ADDRESS: AtomicUsize = AtomicUsize::new(0);

/// Bounded q35 virtio PCI initialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioPciError {
    /// PCI configuration or one modern capability was malformed.
    InvalidCapability,
    /// A BAR was absent, I/O-typed, malformed, or outside addressable memory.
    InvalidBar,
    /// More matching devices or capabilities were exposed than permitted.
    DeviceLimit,
    /// A physical MMIO range could not be represented by the mapping contract.
    InvalidResource,
    /// Queue memory allocation or layout failed.
    QueueAllocation,
    /// Device reset or status transition did not complete.
    DeviceState,
    /// Modern feature or block configuration validation failed.
    UnsupportedProfile,
    /// Request queue zero is absent, live, or smaller than the fixed queue.
    InvalidQueue,
}

/// One initialized q35 block device behind the portable virtio adapter.
pub type NativeVirtioBlock = VirtioBlock<VirtioPciTransport>;

/// One initialized q35 modern virtio network device.
pub struct NativeVirtioNetwork {
    address: PciAddress,
    common: MmioRegion,
    isr: MmioRegion,
    receive_notify: usize,
    transmit_notify: usize,
    mac: MacAddress,
    receive: Box<NetworkQueueMemory>,
    transmit: Box<NetworkQueueMemory>,
    receive_available: u16,
    receive_used: u16,
    transmit_available: u16,
    transmit_used: u16,
    interrupt_line: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceKind {
    Network,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PciAddress {
    bus: u8,
    device: u8,
    function: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmioRegion {
    address: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BarInfo {
    base: u64,
    size: u64,
}

#[derive(Clone, Copy, Debug)]
struct PciCapabilities {
    address: PciAddress,
    kind: DeviceKind,
    common: MmioRegion,
    notify: MmioRegion,
    notify_multiplier: u32,
    isr: MmioRegion,
    device: MmioRegion,
}

/// Page-aligned BAR portions required by modern virtio PCI capabilities.
///
/// The pinned q35 profile scans bus zero only. Persistent role assignment is
/// still performed later by stable media identities, never this scan order.
///
/// # Errors
///
/// Rejects malformed capability chains, invalid BAR sizing, excessive matching
/// devices, and ranges that cannot be represented by the page mapper.
pub fn virtio_pci_device_ranges() -> Result<Vec<PhysicalRange>, VirtioPciError> {
    let devices = scan_devices()?;
    let mut spans = Vec::new();
    spans
        .try_reserve_exact(devices.len().saturating_mul(4))
        .map_err(|_| VirtioPciError::InvalidResource)?;
    for device in devices {
        for region in [device.common, device.notify, device.isr, device.device] {
            let start = u64::try_from(region.address)
                .map_err(|_| VirtioPciError::InvalidResource)?
                & !(BASE_PAGE_SIZE - 1);
            let raw_end = u64::try_from(region.address)
                .ok()
                .and_then(|base| base.checked_add(u64::try_from(region.length).ok()?))
                .ok_or(VirtioPciError::InvalidResource)?;
            let end = raw_end
                .checked_add(BASE_PAGE_SIZE - 1)
                .ok_or(VirtioPciError::InvalidResource)?
                & !(BASE_PAGE_SIZE - 1);
            spans.push((start, end));
        }
    }
    spans.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in spans {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(merged.len())
        .map_err(|_| VirtioPciError::InvalidResource)?;
    for (start, end) in merged {
        let pages = end
            .checked_sub(start)
            .ok_or(VirtioPciError::InvalidResource)?
            / BASE_PAGE_SIZE;
        ranges.push(
            PhysicalRange::from_pages(start, pages).map_err(|_| VirtioPciError::InvalidResource)?,
        );
    }
    Ok(ranges)
}

/// Discover and initialize modern virtio block functions on pinned q35 bus 0.
///
/// # Errors
///
/// Fails transactionally if any advertised modern block function cannot
/// establish the selected feature, configuration, and queue profile.
pub fn discover_virtio_pci_blocks() -> Result<Vec<NativeVirtioBlock>, VirtioPciError> {
    let locations = scan_devices()?;
    let mut devices = Vec::new();
    devices
        .try_reserve_exact(locations.len())
        .map_err(|_| VirtioPciError::QueueAllocation)?;
    for location in locations
        .into_iter()
        .filter(|device| device.kind == DeviceKind::Block)
    {
        devices.push(initialize_device(location)?);
    }
    Ok(devices)
}

/// Discover exactly zero or one q35 modern virtio network function.
///
/// # Errors
///
/// Rejects multiple NICs and every malformed capability, feature, MAC, queue,
/// status, DMA, completion, timeout, or reset condition.
pub fn discover_virtio_pci_network() -> Result<Option<NativeVirtioNetwork>, VirtioPciError> {
    let mut network = None;
    for capabilities in scan_devices()?
        .into_iter()
        .filter(|device| device.kind == DeviceKind::Network)
    {
        if network.is_some() {
            return Err(VirtioPciError::DeviceLimit);
        }
        network = Some(initialize_network_device(capabilities)?);
    }
    Ok(network)
}

fn scan_devices() -> Result<Vec<PciCapabilities>, VirtioPciError> {
    let mut devices = Vec::new();
    devices
        .try_reserve_exact(MAX_NATIVE_BLOCK_DEVICES)
        .map_err(|_| VirtioPciError::InvalidResource)?;
    for device in 0_u8..32 {
        for function in 0_u8..8 {
            let address = PciAddress {
                bus: 0,
                device,
                function,
            };
            let identity = pci_read32(address, 0);
            if low_u16(identity) != PCI_VENDOR_VIRTIO {
                continue;
            }
            let kind = match high_u16(identity) {
                PCI_DEVICE_MODERN_NETWORK => DeviceKind::Network,
                PCI_DEVICE_MODERN_BLOCK => DeviceKind::Block,
                _ => continue,
            };
            if devices.len() >= MAX_NATIVE_BLOCK_DEVICES {
                return Err(VirtioPciError::DeviceLimit);
            }
            devices.push(parse_capabilities(address, kind)?);
        }
    }
    Ok(devices)
}

fn parse_capabilities(
    address: PciAddress,
    kind: DeviceKind,
) -> Result<PciCapabilities, VirtioPciError> {
    if pci_read16(address, 6) & PCI_STATUS_CAPABILITIES == 0 {
        return Err(VirtioPciError::InvalidCapability);
    }
    let mut common = None;
    let mut notify = None;
    let mut notify_multiplier = None;
    let mut isr = None;
    let mut device = None;
    let mut visited = [false; 256];
    let mut pointer = pci_read8(address, 0x34) & !3;
    for _ in 0..MAX_CAPABILITIES {
        let index = usize::from(pointer);
        if !(0x40..=0xfc).contains(&pointer) || visited[index] {
            return Err(VirtioPciError::InvalidCapability);
        }
        visited[index] = true;
        let identifier = pci_read8(address, pointer);
        let next = pci_read8(address, pointer + 1) & !3;
        if identifier == PCI_CAP_VENDOR_SPECIFIC {
            let length = pci_read8(address, pointer + 2);
            if length < 16 || usize::from(pointer) + usize::from(length) > 256 {
                return Err(VirtioPciError::InvalidCapability);
            }
            let configuration_type = pci_read8(address, pointer + 3);
            match configuration_type {
                PCI_CAP_COMMON if length >= 16 => {
                    let region = capability_region(address, pointer)?;
                    if region.length < 56 {
                        return Err(VirtioPciError::InvalidCapability);
                    }
                    set_once(&mut common, region)?;
                }
                PCI_CAP_NOTIFY if length >= 20 => {
                    let region = capability_region(address, pointer)?;
                    if region.length < 2 {
                        return Err(VirtioPciError::InvalidCapability);
                    }
                    set_once(&mut notify, region)?;
                    let multiplier = pci_read32(address, pointer + 16);
                    if multiplier == 0 {
                        return Err(VirtioPciError::InvalidCapability);
                    }
                    set_once(&mut notify_multiplier, multiplier)?;
                }
                PCI_CAP_ISR if length >= 16 => {
                    let region = capability_region(address, pointer)?;
                    if region.length < 1 {
                        return Err(VirtioPciError::InvalidCapability);
                    }
                    set_once(&mut isr, region)?;
                }
                PCI_CAP_DEVICE if length >= 16 => {
                    let region = capability_region(address, pointer)?;
                    let minimum = if kind == DeviceKind::Block { 24 } else { 8 };
                    if region.length < minimum {
                        return Err(VirtioPciError::InvalidCapability);
                    }
                    set_once(&mut device, region)?;
                }
                _ => {}
            }
        }
        if next == 0 {
            return Ok(PciCapabilities {
                address,
                kind,
                common: common.ok_or(VirtioPciError::InvalidCapability)?,
                notify: notify.ok_or(VirtioPciError::InvalidCapability)?,
                notify_multiplier: notify_multiplier.ok_or(VirtioPciError::InvalidCapability)?,
                isr: isr.ok_or(VirtioPciError::InvalidCapability)?,
                device: device.ok_or(VirtioPciError::InvalidCapability)?,
            });
        }
        pointer = next;
    }
    Err(VirtioPciError::InvalidCapability)
}

fn capability_region(address: PciAddress, pointer: u8) -> Result<MmioRegion, VirtioPciError> {
    resolve_region(
        address,
        pci_read8(address, pointer + 4),
        pci_read32(address, pointer + 8),
        pci_read32(address, pointer + 12),
    )
}

fn set_once<T: Copy>(slot: &mut Option<T>, value: T) -> Result<(), VirtioPciError> {
    if slot.replace(value).is_some() {
        return Err(VirtioPciError::InvalidCapability);
    }
    Ok(())
}

fn resolve_region(
    address: PciAddress,
    bar_index: u8,
    offset: u32,
    length: u32,
) -> Result<MmioRegion, VirtioPciError> {
    if bar_index >= 6 || length == 0 {
        return Err(VirtioPciError::InvalidCapability);
    }
    let bar = probe_bar(address, bar_index)?;
    let end = u64::from(offset)
        .checked_add(u64::from(length))
        .ok_or(VirtioPciError::InvalidCapability)?;
    if end > bar.size {
        return Err(VirtioPciError::InvalidCapability);
    }
    let address = bar
        .base
        .checked_add(u64::from(offset))
        .ok_or(VirtioPciError::InvalidBar)?;
    Ok(MmioRegion {
        address: usize::try_from(address).map_err(|_| VirtioPciError::InvalidBar)?,
        length: usize::try_from(length).map_err(|_| VirtioPciError::InvalidCapability)?,
    })
}

fn probe_bar(address: PciAddress, index: u8) -> Result<BarInfo, VirtioPciError> {
    let offset = 0x10_u8
        .checked_add(index.checked_mul(4).ok_or(VirtioPciError::InvalidBar)?)
        .ok_or(VirtioPciError::InvalidBar)?;
    let low = pci_read32(address, offset);
    if low & 1 != 0 {
        return Err(VirtioPciError::InvalidBar);
    }
    let kind = (low >> 1) & 3;
    if kind != 0 && kind != 2 {
        return Err(VirtioPciError::InvalidBar);
    }
    let is_64 = kind == 2;
    if is_64 && index == 5 {
        return Err(VirtioPciError::InvalidBar);
    }
    let high = if is_64 {
        pci_read32(address, offset + 4)
    } else {
        0
    };
    let command = pci_read16(address, 4);
    pci_write16(address, 4, command & !PCI_COMMAND_MEMORY);
    pci_write32(address, offset, u32::MAX);
    if is_64 {
        pci_write32(address, offset + 4, u32::MAX);
    }
    let mask_low = pci_read32(address, offset);
    let mask_high = if is_64 {
        pci_read32(address, offset + 4)
    } else {
        u32::MAX
    };
    pci_write32(address, offset, low);
    if is_64 {
        pci_write32(address, offset + 4, high);
    }
    pci_write16(address, 4, command);

    let base = (u64::from(high) << 32) | u64::from(low & !0xf);
    let mask = (u64::from(mask_high) << 32) | u64::from(mask_low & !0xf);
    let size = (!mask).wrapping_add(1);
    if base == 0 || size == 0 || !size.is_power_of_two() || !base.is_multiple_of(size) {
        return Err(VirtioPciError::InvalidBar);
    }
    Ok(BarInfo { base, size })
}

fn initialize_device(capabilities: PciCapabilities) -> Result<NativeVirtioBlock, VirtioPciError> {
    let command = pci_read16(capabilities.address, 4);
    pci_write16(
        capabilities.address,
        4,
        command | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );
    reset_device(capabilities.common)?;
    write_status(capabilities.common, STATUS_ACKNOWLEDGE);
    write_status(capabilities.common, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    let offered_features = read_features(capabilities.common);
    let configuration = read_stable_configuration(capabilities)?;
    let profile = match VirtioBlockProfile::negotiate(offered_features, &configuration) {
        Ok(profile) => profile,
        Err(_error) => {
            fail_and_reset(capabilities.common);
            return Err(VirtioPciError::UnsupportedProfile);
        }
    };
    write_features(capabilities.common, profile.negotiated_features());
    let feature_status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
    write_status(capabilities.common, feature_status);
    if mmio_read_u8(capabilities.common.address + COMMON_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
        fail_and_reset(capabilities.common);
        return Err(VirtioPciError::UnsupportedProfile);
    }
    mmio_write_u16(capabilities.common.address + COMMON_MSIX_CONFIG, NO_VECTOR);
    let queue = Box::new(QueueMemory::new()?);
    let notify = match configure_queue(capabilities, &queue) {
        Ok(notify) => notify,
        Err(error) => {
            fail_and_reset(capabilities.common);
            return Err(error);
        }
    };
    write_status(capabilities.common, feature_status | STATUS_DRIVER_OK);
    if mmio_read_u8(capabilities.common.address + COMMON_DEVICE_STATUS) & STATUS_DRIVER_OK == 0 {
        fail_and_reset(capabilities.common);
        return Err(VirtioPciError::DeviceState);
    }
    Ok(VirtioBlock::new(
        VirtioPciTransport {
            common: capabilities.common,
            notify,
            isr: capabilities.isr,
            queue,
            available_index: 0,
            used_index: 0,
        },
        profile,
    ))
}

fn initialize_network_device(
    capabilities: PciCapabilities,
) -> Result<NativeVirtioNetwork, VirtioPciError> {
    let command = pci_read16(capabilities.address, 4);
    pci_write16(
        capabilities.address,
        4,
        command | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );
    reset_device(capabilities.common)?;
    write_status(capabilities.common, STATUS_ACKNOWLEDGE);
    write_status(capabilities.common, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    let profile = VirtioNetworkProfile::negotiate(
        read_features(capabilities.common),
        &read_stable_network_configuration(capabilities)?,
    )
    .map_err(|_| VirtioPciError::UnsupportedProfile)?;
    write_features(capabilities.common, profile.negotiated_features());
    let feature_status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
    write_status(capabilities.common, feature_status);
    if mmio_read_u8(capabilities.common.address + COMMON_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
        fail_and_reset(capabilities.common);
        return Err(VirtioPciError::UnsupportedProfile);
    }
    mmio_write_u16(capabilities.common.address + COMMON_MSIX_CONFIG, NO_VECTOR);
    let receive = Box::new(NetworkQueueMemory::new()?);
    let transmit = Box::new(NetworkQueueMemory::new()?);
    let receive_notify = configure_network_queue(capabilities, RECEIVE_QUEUE_INDEX, &receive)?;
    let transmit_notify = configure_network_queue(capabilities, TRANSMIT_QUEUE_INDEX, &transmit)?;
    write_status(capabilities.common, feature_status | STATUS_DRIVER_OK);
    if mmio_read_u8(capabilities.common.address + COMMON_DEVICE_STATUS) & STATUS_DRIVER_OK == 0 {
        fail_and_reset(capabilities.common);
        return Err(VirtioPciError::DeviceState);
    }
    let mut network = NativeVirtioNetwork {
        address: capabilities.address,
        common: capabilities.common,
        isr: capabilities.isr,
        receive_notify,
        transmit_notify,
        mac: profile.mac(),
        receive,
        transmit,
        receive_available: 0,
        receive_used: 0,
        transmit_available: 0,
        transmit_used: 0,
        interrupt_line: pci_interrupt_line(capabilities.address)?,
    };
    network
        .post_receive()
        .map_err(|_| VirtioPciError::InvalidQueue)?;
    Ok(network)
}

fn configure_network_queue(
    capabilities: PciCapabilities,
    index: u16,
    queue: &NetworkQueueMemory,
) -> Result<usize, VirtioPciError> {
    let common = capabilities.common.address;
    mmio_write_u16(common + COMMON_QUEUE_SELECT, index);
    if mmio_read_u16(common + COMMON_QUEUE_ENABLE) != 0
        || mmio_read_u16(common + COMMON_QUEUE_SIZE) < NETWORK_QUEUE_SIZE
    {
        return Err(VirtioPciError::InvalidQueue);
    }
    mmio_write_u16(common + COMMON_QUEUE_SIZE, NETWORK_QUEUE_SIZE);
    mmio_write_u16(common + COMMON_QUEUE_MSIX_VECTOR, NO_VECTOR);
    if mmio_read_u16(common + COMMON_QUEUE_MSIX_VECTOR) != NO_VECTOR {
        return Err(VirtioPciError::InvalidQueue);
    }
    mmio_write_u64(
        common + COMMON_QUEUE_DESC,
        queue.address(queue.layout.descriptor_offset())?,
    );
    mmio_write_u64(
        common + COMMON_QUEUE_DRIVER,
        queue.address(queue.layout.available_offset())?,
    );
    mmio_write_u64(
        common + COMMON_QUEUE_DEVICE,
        queue.address(queue.layout.used_offset())?,
    );
    let flags = if index == RECEIVE_QUEUE_INDEX {
        0
    } else {
        NO_INTERRUPT
    };
    queue.write_u16(queue.layout.available_offset(), flags);
    dma_publish();
    mmio_write_u16(common + COMMON_QUEUE_ENABLE, 1);
    if mmio_read_u16(common + COMMON_QUEUE_ENABLE) != 1 {
        return Err(VirtioPciError::InvalidQueue);
    }
    let notify_offset = u64::from(mmio_read_u16(common + COMMON_QUEUE_NOTIFY_OFF))
        .checked_mul(u64::from(capabilities.notify_multiplier))
        .ok_or(VirtioPciError::InvalidQueue)?;
    if notify_offset
        .checked_add(2)
        .is_none_or(|end| end > capabilities.notify.length as u64)
    {
        return Err(VirtioPciError::InvalidQueue);
    }
    capabilities
        .notify
        .address
        .checked_add(usize::try_from(notify_offset).map_err(|_| VirtioPciError::InvalidQueue)?)
        .ok_or(VirtioPciError::InvalidQueue)
}

fn read_stable_network_configuration(
    capabilities: PciCapabilities,
) -> Result<[u8; 8], VirtioPciError> {
    for _ in 0..CONFIG_READ_ATTEMPTS {
        let before = mmio_read_u8(capabilities.common.address + COMMON_CONFIG_GENERATION);
        let mut configuration = [0_u8; 8];
        for (index, byte) in configuration.iter_mut().enumerate() {
            *byte = mmio_read_u8(capabilities.device.address + index);
        }
        if before == mmio_read_u8(capabilities.common.address + COMMON_CONFIG_GENERATION) {
            return Ok(configuration);
        }
    }
    Err(VirtioPciError::DeviceState)
}

fn configure_queue(
    capabilities: PciCapabilities,
    queue: &QueueMemory,
) -> Result<usize, VirtioPciError> {
    let common = capabilities.common.address;
    mmio_write_u16(common + COMMON_QUEUE_SELECT, REQUEST_QUEUE_INDEX);
    if mmio_read_u16(common + COMMON_QUEUE_ENABLE) != 0
        || mmio_read_u16(common + COMMON_QUEUE_SIZE) < REQUEST_QUEUE_SIZE
    {
        return Err(VirtioPciError::InvalidQueue);
    }
    mmio_write_u16(common + COMMON_QUEUE_SIZE, REQUEST_QUEUE_SIZE);
    mmio_write_u16(common + COMMON_QUEUE_MSIX_VECTOR, NO_VECTOR);
    if mmio_read_u16(common + COMMON_QUEUE_MSIX_VECTOR) != NO_VECTOR {
        return Err(VirtioPciError::InvalidQueue);
    }
    mmio_write_u64(
        common + COMMON_QUEUE_DESC,
        queue.address(queue.layout.descriptor_offset())?,
    );
    mmio_write_u64(
        common + COMMON_QUEUE_DRIVER,
        queue.address(queue.layout.available_offset())?,
    );
    mmio_write_u64(
        common + COMMON_QUEUE_DEVICE,
        queue.address(queue.layout.used_offset())?,
    );
    queue.write_u16(queue.layout.available_offset(), NO_INTERRUPT);
    dma_publish();
    mmio_write_u16(common + COMMON_QUEUE_ENABLE, 1);
    if mmio_read_u16(common + COMMON_QUEUE_ENABLE) != 1 {
        return Err(VirtioPciError::InvalidQueue);
    }
    let notify_offset = u64::from(mmio_read_u16(common + COMMON_QUEUE_NOTIFY_OFF))
        .checked_mul(u64::from(capabilities.notify_multiplier))
        .ok_or(VirtioPciError::InvalidQueue)?;
    if notify_offset
        .checked_add(2)
        .is_none_or(|end| end > capabilities.notify.length as u64)
    {
        return Err(VirtioPciError::InvalidQueue);
    }
    capabilities
        .notify
        .address
        .checked_add(usize::try_from(notify_offset).map_err(|_| VirtioPciError::InvalidQueue)?)
        .ok_or(VirtioPciError::InvalidQueue)
}

fn read_features(common: MmioRegion) -> u64 {
    mmio_write_u32(common.address + COMMON_DEVICE_FEATURE_SELECT, 0);
    let low = mmio_read_u32(common.address + COMMON_DEVICE_FEATURE);
    mmio_write_u32(common.address + COMMON_DEVICE_FEATURE_SELECT, 1);
    let high = mmio_read_u32(common.address + COMMON_DEVICE_FEATURE);
    u64::from(low) | (u64::from(high) << 32)
}

fn write_features(common: MmioRegion, features: u64) {
    mmio_write_u32(common.address + COMMON_DRIVER_FEATURE_SELECT, 0);
    mmio_write_u32(common.address + COMMON_DRIVER_FEATURE, low_u32(features));
    mmio_write_u32(common.address + COMMON_DRIVER_FEATURE_SELECT, 1);
    mmio_write_u32(common.address + COMMON_DRIVER_FEATURE, high_u32(features));
}

fn read_stable_configuration(capabilities: PciCapabilities) -> Result<[u8; 24], VirtioPciError> {
    for _ in 0..CONFIG_READ_ATTEMPTS {
        let before = mmio_read_u8(capabilities.common.address + COMMON_CONFIG_GENERATION);
        let mut configuration = [0_u8; 24];
        for (index, byte) in configuration.iter_mut().enumerate() {
            *byte = mmio_read_u8(capabilities.device.address + index);
        }
        let after = mmio_read_u8(capabilities.common.address + COMMON_CONFIG_GENERATION);
        if before == after {
            return Ok(configuration);
        }
    }
    Err(VirtioPciError::DeviceState)
}

fn write_status(common: MmioRegion, status: u8) {
    mmio_write_u8(common.address + COMMON_DEVICE_STATUS, status);
}

fn reset_device(common: MmioRegion) -> Result<(), VirtioPciError> {
    write_status(common, 0);
    for _ in 0..REGISTER_SPIN_LIMIT {
        if mmio_read_u8(common.address + COMMON_DEVICE_STATUS) == 0 {
            return Ok(());
        }
        spin_loop();
    }
    Err(VirtioPciError::DeviceState)
}

fn fail_and_reset(common: MmioRegion) {
    let status = mmio_read_u8(common.address + COMMON_DEVICE_STATUS);
    write_status(common, status | STATUS_FAILED);
    if reset_device(common).is_err() {
        terminal_park();
    }
}

/// Live modern PCI and split-queue state for one synchronous device.
pub struct VirtioPciTransport {
    common: MmioRegion,
    notify: usize,
    isr: MmioRegion,
    queue: Box<QueueMemory>,
    available_index: u16,
    used_index: u16,
}

impl fmt::Debug for VirtioPciTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VirtioPciTransport")
            .field("common", &self.common)
            .field("notify", &self.notify)
            .field("available_index", &self.available_index)
            .field("used_index", &self.used_index)
            .finish_non_exhaustive()
    }
}

impl VirtioBlockTransport for VirtioPciTransport {
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

impl VirtioPciTransport {
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
        mmio_write_u16(self.notify, REQUEST_QUEUE_INDEX);

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
            if reset_device(self.common).is_err() {
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
        let _acknowledged_interrupt = mmio_read_u8(self.isr.address);
        request.validate_completion(descriptor_head, used_bytes, status)
    }
}

impl Drop for VirtioPciTransport {
    fn drop(&mut self) {
        if reset_device(self.common).is_err() {
            terminal_park();
        }
    }
}

impl NetworkDevice for NativeVirtioNetwork {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        self.transmit.prepare_transmit(frame)?;
        publish_network_descriptor(
            &self.transmit,
            &mut self.transmit_available,
            TRANSMIT_QUEUE_INDEX,
            self.transmit_notify,
        )?;
        let expected = self.transmit_used.wrapping_add(1);
        for _ in 0..REGISTER_SPIN_LIMIT {
            if self
                .transmit
                .read_u16(self.transmit.layout.used_offset() + 2)
                == expected
            {
                dma_observe();
                let (head, bytes) = self.transmit.used_element(self.transmit_used)?;
                self.transmit_used = expected;
                let _acknowledged = mmio_read_u8(self.isr.address);
                return if head == 0 && bytes == 0 {
                    Ok(())
                } else {
                    Err(NetError::Device)
                };
            }
            spin_loop();
        }
        if reset_device(self.common).is_err() {
            terminal_park();
        }
        Err(NetError::Timeout)
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        let expected = self.receive_used.wrapping_add(1);
        if self.receive.read_u16(self.receive.layout.used_offset() + 2) != expected {
            return Ok(None);
        }
        dma_observe();
        let (head, bytes) = self.receive.used_element(self.receive_used)?;
        self.receive_used = expected;
        let bytes = usize::try_from(bytes).map_err(|_| NetError::Device)?;
        if head != 0
            || !(VIRTIO_NET_HEADER_BYTES + ETHERNET_HEADER_BYTES
                ..=VIRTIO_NET_HEADER_BYTES + MAX_FRAME_BYTES)
                .contains(&bytes)
            || !self.receive.header_is_zero()
        {
            return Err(NetError::Device);
        }
        let frame = self.receive.copy_frame(bytes - VIRTIO_NET_HEADER_BYTES)?;
        self.post_receive()?;
        Ok(Some(frame))
    }
}

impl NativeVirtioNetwork {
    /// Connect this device's legacy `INTx` completion source to the owned I/O APIC.
    ///
    /// Packet processing remains in cooperative kernel context; the interrupt
    /// path only acknowledges the device and marks bounded work pending.
    ///
    /// # Errors
    ///
    /// Returns a resource error when the advertised PCI line cannot be routed.
    pub fn enable_interrupts(&mut self) -> Result<(), VirtioPciError> {
        let command = pci_read16(self.address, 4);
        pci_write16(self.address, 4, command & !PCI_COMMAND_INTERRUPT_DISABLE);
        NETWORK_ISR_ADDRESS.store(self.isr.address, Ordering::Release);
        crate::mechanism::initialize_network_interrupt(u32::from(self.interrupt_line))
            .map_err(|_| VirtioPciError::InvalidResource)
    }

    fn post_receive(&mut self) -> Result<(), NetError> {
        self.receive.prepare_receive()?;
        publish_network_descriptor(
            &self.receive,
            &mut self.receive_available,
            RECEIVE_QUEUE_INDEX,
            self.receive_notify,
        )
    }
}

pub(crate) fn acknowledge_network_interrupt_from_isr() -> bool {
    let address = NETWORK_ISR_ADDRESS.load(Ordering::Acquire);
    address != 0 && mmio_read_u8(address) & 1 != 0
}

fn pci_interrupt_line(address: PciAddress) -> Result<u8, VirtioPciError> {
    let line = pci_read8(address, PCI_INTERRUPT_LINE);
    let pin = pci_read8(address, PCI_INTERRUPT_PIN);
    if line == u8::MAX || pin == 0 {
        return Err(VirtioPciError::InvalidResource);
    }
    Ok(line)
}

impl Drop for NativeVirtioNetwork {
    fn drop(&mut self) {
        if reset_device(self.common).is_err() {
            terminal_park();
        }
    }
}

fn publish_network_descriptor(
    queue: &NetworkQueueMemory,
    available: &mut u16,
    index: u16,
    notify: usize,
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
    mmio_write_u16(notify, index);
    Ok(())
}

#[repr(C, align(4096))]
struct NetworkQueueMemory {
    bytes: [UnsafeCell<u8>; QUEUE_ALLOCATION_BYTES],
    layout: SplitQueueLayout,
}

impl NetworkQueueMemory {
    fn new() -> Result<Self, VirtioPciError> {
        let layout =
            SplitQueueLayout::new(NETWORK_QUEUE_SIZE).map_err(|_| VirtioPciError::InvalidQueue)?;
        if layout.total_bytes() > NETWORK_BUFFER_OFFSET
            || NETWORK_BUFFER_OFFSET + NETWORK_BUFFER_BYTES > QUEUE_ALLOCATION_BYTES
        {
            return Err(VirtioPciError::InvalidQueue);
        }
        Ok(Self {
            bytes: core::array::from_fn(|_| UnsafeCell::new(0)),
            layout,
        })
    }

    fn address(&self, offset: usize) -> Result<u64, VirtioPciError> {
        if offset >= QUEUE_ALLOCATION_BYTES {
            return Err(VirtioPciError::InvalidQueue);
        }
        u64::try_from(self.bytes[offset].get() as usize).map_err(|_| VirtioPciError::InvalidQueue)
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
        // SAFETY: Queue-layout and fixed-buffer offsets are checked and the
        // aligned allocation remains alive while bus mastering is enabled.
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
    fn new() -> Result<Self, VirtioPciError> {
        let layout =
            SplitQueueLayout::new(REQUEST_QUEUE_SIZE).map_err(|_| VirtioPciError::InvalidQueue)?;
        if layout.total_bytes() > REQUEST_HEADER_OFFSET
            || REQUEST_STATUS_OFFSET >= QUEUE_ALLOCATION_BYTES
        {
            return Err(VirtioPciError::InvalidQueue);
        }
        Ok(Self {
            bytes: core::array::from_fn(|_| UnsafeCell::new(0)),
            layout,
        })
    }

    fn address(&self, offset: usize) -> Result<u64, VirtioPciError> {
        if offset >= QUEUE_ALLOCATION_BYTES {
            return Err(VirtioPciError::InvalidQueue);
        }
        u64::try_from(self.bytes[offset].get() as usize).map_err(|_| VirtioPciError::InvalidQueue)
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
        // SAFETY: Offsets are checked constants or layout-derived indices in
        // this live aligned allocation. Volatile access observes device DMA.
        unsafe { ptr::read_volatile(self.bytes[offset].get()) }
    }

    fn write_u8(&self, offset: usize, value: u8) {
        // SAFETY: Offsets are checked constants or layout-derived indices in
        // the exclusively driver-written portion of the live allocation.
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

fn pci_read8(address: PciAddress, offset: u8) -> u8 {
    let bytes = pci_read32(address, offset).to_le_bytes();
    bytes[usize::from(offset & 3)]
}

fn pci_read16(address: PciAddress, offset: u8) -> u16 {
    let bytes = pci_read32(address, offset).to_le_bytes();
    let index = usize::from(offset & 2);
    u16::from_le_bytes([bytes[index], bytes[index + 1]])
}

fn pci_write16(address: PciAddress, offset: u8, value: u16) {
    let selector = 0x8000_0000_u32
        | (u32::from(address.bus) << 16)
        | (u32::from(address.device) << 11)
        | (u32::from(address.function) << 8)
        | u32::from(offset & !3);
    let data_port = PCI_CONFIG_DATA + u16::from(offset & 2);
    // SAFETY: The first output selects one bus-0 configuration dword. The
    // width-specific second output changes only the requested 16-bit field,
    // avoiding a read/modify/write of adjacent write-one-to-clear status bits.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_ADDRESS,
            in("eax") selector,
            options(nostack, preserves_flags)
        );
        core::arch::asm!(
            "out dx, ax",
            in("dx") data_port,
            in("ax") value,
            options(nostack, preserves_flags)
        );
    }
}

fn pci_read32(address: PciAddress, offset: u8) -> u32 {
    let selector = 0x8000_0000_u32
        | (u32::from(address.bus) << 16)
        | (u32::from(address.device) << 11)
        | (u32::from(address.function) << 8)
        | u32::from(offset & !3);
    let value: u32;
    // SAFETY: CF8/CFC are the bounded PCI mechanism #1 ports owned by the
    // single-core q35 profile. The selector names bus 0 and one checked field.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_ADDRESS,
            in("eax") selector,
            options(nostack, preserves_flags)
        );
        core::arch::asm!(
            "in eax, dx",
            in("dx") PCI_CONFIG_DATA,
            out("eax") value,
            options(nostack, preserves_flags)
        );
    }
    value
}

fn pci_write32(address: PciAddress, offset: u8, value: u32) {
    let selector = 0x8000_0000_u32
        | (u32::from(address.bus) << 16)
        | (u32::from(address.device) << 11)
        | (u32::from(address.function) << 8)
        | u32::from(offset & !3);
    // SAFETY: CF8/CFC are the bounded PCI mechanism #1 ports owned by the
    // single-core q35 profile. BAR probing disables decode and restores state.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_ADDRESS,
            in("eax") selector,
            options(nostack, preserves_flags)
        );
        core::arch::asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_DATA,
            in("eax") value,
            options(nostack, preserves_flags)
        );
    }
}

fn low_u16(value: u32) -> u16 {
    let bytes = value.to_le_bytes();
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn high_u16(value: u32) -> u16 {
    let bytes = value.to_le_bytes();
    u16::from_le_bytes([bytes[2], bytes[3]])
}

fn low_u32(value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn high_u32(value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
}

fn mmio_read_u8(address: usize) -> u8 {
    // SAFETY: The address belongs to a validated, mapped virtio PCI capability.
    unsafe { ptr::read_volatile(address as *const u8) }
}

fn mmio_read_u16(address: usize) -> u16 {
    // SAFETY: The address is naturally aligned within a mapped common config.
    unsafe { ptr::read_volatile(address as *const u16) }
}

fn mmio_read_u32(address: usize) -> u32 {
    // SAFETY: The address is naturally aligned within a mapped common config.
    unsafe { ptr::read_volatile(address as *const u32) }
}

fn mmio_write_u8(address: usize, value: u8) {
    // SAFETY: The address is a writable byte field in mapped common config.
    unsafe { ptr::write_volatile(address as *mut u8, value) };
}

fn mmio_write_u16(address: usize, value: u16) {
    // SAFETY: The address is a writable aligned field in mapped common/notify config.
    unsafe { ptr::write_volatile(address as *mut u16, value) };
}

fn mmio_write_u32(address: usize, value: u32) {
    // SAFETY: The address is a writable aligned field in mapped common config.
    unsafe { ptr::write_volatile(address as *mut u32, value) };
}

fn mmio_write_u64(address: usize, value: u64) {
    // SAFETY: The address is a writable aligned queue-address field.
    unsafe { ptr::write_volatile(address as *mut u64, value) };
}

fn dma_publish() {
    compiler_fence(Ordering::Release);
    fence(Ordering::SeqCst);
}

fn dma_observe() {
    fence(Ordering::SeqCst);
    compiler_fence(Ordering::Acquire);
}

fn terminal_park() -> ! {
    loop {
        // SAFETY: Failed reset may leave DMA live. Interrupt-masked parking is
        // the only safe outcome because returning could free borrowed buffers.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

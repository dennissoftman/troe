//! Early, fail-closed firmware evidence for discoverable cloud platforms.
//!
//! Safe parsers live in `troe-platform`. This module owns the single native
//! boundary needed to turn memory-map-contained UEFI configuration-table
//! pointers into immutable byte slices before any TROE device I/O begins.

#[cfg(target_os = "uefi")]
use core::slice;
#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
use troe_platform::discovery::acpi::{
    AcpiMemory, IntiPolarity, IntiTrigger, MadtEntry, RegisterSpace, SerialInterface, X86VirtioAcpi,
};
#[cfg(all(target_os = "uefi", feature = "platform-aarch64-uefi-virtio-mmio"))]
use troe_platform::discovery::fdt::{
    GicVersion, InterruptKind, InterruptPolarity, InterruptTrigger, PsciConduit, UartKind,
};
#[cfg(target_os = "uefi")]
use uefi::boot;
#[cfg(target_os = "uefi")]
use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned, MemoryType};
#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
use uefi::table::cfg::ConfigTableEntry;

use crate::PlatformDiscoveryFailure as DiscoveryError;

const UEFI_PAGE_BYTES: u64 = 4_096;
#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
const ECAM_BUS_BYTES: u64 = 1 << 20;

#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
static X86_ECAM_BASE: AtomicU64 = AtomicU64::new(0);
#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
static X86_ECAM_BUSES: AtomicU16 = AtomicU16::new(0);
#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
static X86_ECAM_READY: AtomicBool = AtomicBool::new(false);

/// Validated, selected segment-zero ECAM aperture for the bounded PCI scan.
#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct X86EcamWindow {
    base_address: u64,
    first_bus: u8,
    last_bus: u8,
}

#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
impl X86EcamWindow {
    const fn new(base_address: u64, first_bus: u8, last_bus: u8) -> Option<Self> {
        if base_address == 0 || !base_address.is_multiple_of(ECAM_BUS_BYTES) || first_bus > last_bus
        {
            return None;
        }
        Some(Self {
            base_address,
            first_bus,
            last_bus,
        })
    }

    pub(crate) const fn first_bus(self) -> u8 {
        self.first_bus
    }

    pub(crate) const fn last_bus(self) -> u8 {
        self.last_bus
    }

    pub(crate) fn physical_range(self) -> Option<(u64, u64)> {
        let bus_count = u64::from(self.last_bus)
            .checked_sub(u64::from(self.first_bus))?
            .checked_add(1)?;
        let start = self
            .base_address
            .checked_add(u64::from(self.first_bus).checked_mul(ECAM_BUS_BYTES)?)?;
        Some((start, bus_count.checked_mul(ECAM_BUS_BYTES)?))
    }

    pub(crate) fn configuration_address(
        self,
        bus: u8,
        device: u8,
        function: u8,
        register_offset: u8,
    ) -> Option<u64> {
        if !(self.first_bus..=self.last_bus).contains(&bus) || device >= 32 || function >= 8 {
            return None;
        }
        self.base_address
            .checked_add(u64::from(bus).checked_mul(ECAM_BUS_BYTES)?)?
            .checked_add(u64::from(device).checked_mul(1 << 15)?)?
            .checked_add(u64::from(function).checked_mul(1 << 12)?)?
            .checked_add(u64::from(register_offset))
    }
}

#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
fn publish_x86_ecam(window: X86EcamWindow) {
    let buses = u16::from(window.first_bus) | (u16::from(window.last_bus) << 8);
    X86_ECAM_BASE.store(window.base_address, Ordering::Relaxed);
    X86_ECAM_BUSES.store(buses, Ordering::Relaxed);
    X86_ECAM_READY.store(true, Ordering::Release);
}

#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
pub(crate) fn x86_ecam_window() -> Option<X86EcamWindow> {
    if !X86_ECAM_READY.load(Ordering::Acquire) {
        return None;
    }
    let buses = X86_ECAM_BUSES.load(Ordering::Relaxed);
    X86EcamWindow::new(
        X86_ECAM_BASE.load(Ordering::Relaxed),
        buses.to_le_bytes()[0],
        buses.to_le_bytes()[1],
    )
}

#[cfg(target_os = "uefi")]
struct MappedFirmwareMemory<'a> {
    map: &'a MemoryMapOwned,
}

#[cfg(target_os = "uefi")]
impl<'a> MappedFirmwareMemory<'a> {
    const fn new(map: &'a MemoryMapOwned) -> Self {
        Self { map }
    }

    fn mapped_region(&self, physical_address: u64, byte_len: usize) -> Option<&[u8]> {
        let byte_len_u64 = u64::try_from(byte_len).ok()?;
        let virtual_address = usize::try_from(physical_address).ok()?;
        if !self.map.entries().any(|descriptor| {
            firmware_region_contains(
                descriptor.ty,
                descriptor.phys_start,
                descriptor.page_count,
                physical_address,
                byte_len_u64,
            )
        }) {
            return None;
        }
        let pointer = core::ptr::with_exposed_provenance::<u8>(virtual_address);
        // SAFETY: A nonempty, nonoverflowing span was proven to lie wholly in
        // one live UEFI firmware-data descriptor. Before ExitBootServices the
        // configuration-table physical view is identity-addressable, and the
        // returned borrow cannot outlive the retained memory-map transaction.
        Some(unsafe { slice::from_raw_parts(pointer, byte_len) })
    }
}

#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
impl AcpiMemory for MappedFirmwareMemory<'_> {
    fn region(&self, physical_address: u64, byte_len: usize) -> Option<&[u8]> {
        self.mapped_region(physical_address, byte_len)
    }
}

#[cfg(target_os = "uefi")]
fn firmware_region_contains(
    memory_type: MemoryType,
    region_start: u64,
    page_count: u64,
    requested_start: u64,
    requested_len: u64,
) -> bool {
    if requested_len == 0 || !firmware_memory_type(memory_type) {
        return false;
    }
    let Some(region_len) = page_count.checked_mul(UEFI_PAGE_BYTES) else {
        return false;
    };
    let Some(region_end) = region_start.checked_add(region_len) else {
        return false;
    };
    let Some(requested_end) = requested_start.checked_add(requested_len) else {
        return false;
    };
    requested_start >= region_start && requested_end <= region_end
}

#[cfg(target_os = "uefi")]
const fn firmware_memory_type(memory_type: MemoryType) -> bool {
    matches!(
        memory_type,
        MemoryType::LOADER_DATA
            | MemoryType::BOOT_SERVICES_DATA
            | MemoryType::RUNTIME_SERVICES_DATA
            | MemoryType::ACPI_RECLAIM
            | MemoryType::ACPI_NON_VOLATILE
    )
}

#[cfg(target_os = "uefi")]
fn unique_config_address(guid: uefi::Guid) -> Result<Option<u64>, DiscoveryError> {
    uefi::system::with_config_table(|entries| {
        let mut address = None;
        for entry in entries.iter().filter(|entry| entry.guid == guid) {
            if address.is_some() {
                return Err(DiscoveryError::ConfigurationTable);
            }
            let raw = u64::try_from(entry.address.addr())
                .map_err(|_| DiscoveryError::ConfigurationTable)?;
            if raw == 0 {
                return Err(DiscoveryError::ConfigurationTable);
            }
            address = Some(raw);
        }
        Ok(address)
    })
}

#[cfg(all(
    target_os = "uefi",
    feature = "platform-x86_64-uefi-virtio-pci",
    not(any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-aarch64-uefi-virtio-mmio"
    ))
))]
pub(super) fn validate() -> Result<(), DiscoveryError> {
    let rsdp_address = unique_config_address(ConfigTableEntry::ACPI2_GUID)?
        .or(unique_config_address(ConfigTableEntry::ACPI_GUID)?)
        .ok_or(DiscoveryError::ConfigurationTable)?;
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| DiscoveryError::MemoryMap)?;
    let memory = MappedFirmwareMemory::new(&map);
    let prefix = memory
        .mapped_region(rsdp_address, 20)
        .ok_or(DiscoveryError::FirmwareMapping)?;
    let rsdp_len = match prefix.get(15).copied() {
        Some(0 | 1) => 20,
        Some(_) => {
            let extended = memory
                .mapped_region(rsdp_address, 36)
                .ok_or(DiscoveryError::FirmwareMapping)?;
            usize::try_from(u32::from_le_bytes([
                extended[20],
                extended[21],
                extended[22],
                extended[23],
            ]))
            .map_err(|_| DiscoveryError::FirmwareParse)?
        }
        None => return Err(DiscoveryError::FirmwareParse),
    };
    if !(20..=troe_platform::discovery::acpi::MAX_RSDP_BYTES).contains(&rsdp_len) {
        return Err(DiscoveryError::FirmwareParse);
    }
    let rsdp = memory
        .mapped_region(rsdp_address, rsdp_len)
        .ok_or(DiscoveryError::FirmwareMapping)?;
    let discovered = X86VirtioAcpi::discover(rsdp_address, rsdp, &memory)
        .map_err(|_| DiscoveryError::FirmwareParse)?;
    let ecam = validate_x86(&discovered)?;
    publish_x86_ecam(ecam);
    Ok(())
}

#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
fn validate_x86<M: AcpiMemory + ?Sized>(
    discovered: &X86VirtioAcpi<'_, M>,
) -> Result<X86EcamWindow, DiscoveryError> {
    use troe_platform::{
        InterruptRole, MmioRole, PciConfigurationKind, TriggerMode, VirtioTransportKind,
    };

    let platform = troe_platform::X86_64_UEFI_VIRTIO_PCI
        .validate()
        .map_err(|_| DiscoveryError::PlatformDescriptor)?;
    let VirtioTransportKind::Pci {
        configuration: PciConfigurationKind::Ecam,
        first_bus,
        last_bus,
        ..
    } = platform.virtio()
    else {
        return Err(DiscoveryError::PlatformDescriptor);
    };
    let mut matching_segments = (0..discovered.mcfg().segment_count())
        .filter_map(|index| discovered.mcfg().segment(index))
        .filter(|segment| {
            segment.segment_group() == 0
                && segment.start_bus() <= first_bus
                && segment.end_bus() >= last_bus
        });
    let segment = matching_segments.next().ok_or(DiscoveryError::X86Ecam)?;
    if matching_segments.next().is_some() {
        return Err(DiscoveryError::X86Ecam);
    }
    let ecam = X86EcamWindow::new(segment.base_address(), first_bus, last_bus)
        .ok_or(DiscoveryError::X86Ecam)?;

    let local_apic = platform
        .mmio(MmioRole::LocalApic)
        .ok_or(DiscoveryError::X86Apic)?;
    if discovered.madt().local_apic_address() != local_apic.base() {
        return Err(DiscoveryError::X86Apic);
    }
    if !discovered.madt().legacy_pic_compatible() {
        return Err(DiscoveryError::X86Apic);
    }
    let mut enabled_processors = discovered.madt().entries().filter_map(|entry| match entry {
        MadtEntry::Processor(processor) if processor.enabled() => Some(processor),
        _ => None,
    });
    let boot_processor = enabled_processors.next().ok_or(DiscoveryError::X86Apic)?;
    if enabled_processors.next().is_some()
        || boot_processor.is_x2apic()
        || boot_processor.apic_id() > u32::from(u8::MAX)
    {
        return Err(DiscoveryError::X86Apic);
    }
    let io_apic = platform
        .mmio(MmioRole::IoApic)
        .ok_or(DiscoveryError::X86Apic)?;
    let mut io_apics = discovered.madt().entries().filter_map(|entry| match entry {
        MadtEntry::IoApic(controller) => Some(controller),
        _ => None,
    });
    let controller = io_apics.next().ok_or(DiscoveryError::X86Apic)?;
    if io_apics.next().is_some()
        || u64::from(controller.address()) != io_apic.base()
        || controller.global_interrupt_base() != 0
    {
        return Err(DiscoveryError::X86Apic);
    }

    let keyboard_route = platform
        .interrupt(InterruptRole::Keyboard)
        .ok_or(DiscoveryError::X86Apic)?;
    let serial_route = platform
        .interrupt(InterruptRole::Serial)
        .ok_or(DiscoveryError::X86Apic)?;
    for entry in discovered.madt().entries() {
        let MadtEntry::InterruptSourceOverride(route) = entry else {
            continue;
        };
        let expected = match route.source_irq() {
            1 => keyboard_route,
            4 => serial_route,
            _ => {
                if [keyboard_route.line(), serial_route.line()].contains(&route.global_interrupt())
                {
                    return Err(DiscoveryError::X86Apic);
                }
                continue;
            }
        };
        if route.global_interrupt() != expected.line()
            || route.resolved_trigger() != IntiTrigger::Edge
            || route.resolved_polarity() != IntiPolarity::ActiveHigh
            || expected.trigger() != TriggerMode::Edge
        {
            return Err(DiscoveryError::X86Apic);
        }
    }

    validate_x86_serial_and_power(discovered, platform)?;
    Ok(ecam)
}

#[cfg(all(target_os = "uefi", feature = "platform-x86_64-uefi-virtio-pci"))]
fn validate_x86_serial_and_power<M: AcpiMemory + ?Sized>(
    discovered: &X86VirtioAcpi<'_, M>,
    platform: troe_platform::ValidatedPlatform<'_>,
) -> Result<(), DiscoveryError> {
    use troe_platform::{InterruptRole, IoPortRole, PowerKind, TimerKind};

    let console = discovered
        .spcr()
        .and_then(troe_platform::discovery::acpi::Spcr::console)
        .ok_or(DiscoveryError::X86Spcr)?;
    let serial = platform
        .io_ports(IoPortRole::Serial)
        .ok_or(DiscoveryError::X86Spcr)?;
    let serial_route = platform
        .interrupt(InterruptRole::Serial)
        .ok_or(DiscoveryError::X86Spcr)?;
    let register = console.register();
    if console.interface() != SerialInterface::Uart16550
        || register.space() != RegisterSpace::SystemIo
        || register.address() != u64::from(serial.base())
        || register.bit_width() != 8
        || register.access_bytes() != 1
        || console.pci().is_some()
        || console.legacy_irq().map(u32::from) != Some(serial_route.line())
        || console.global_interrupt() != Some(serial_route.line())
    {
        return Err(DiscoveryError::X86Spcr);
    }

    let PowerKind::X86Reset {
        reset_control_port,
        reset_value,
    } = platform.power()
    else {
        return Err(DiscoveryError::PlatformDescriptor);
    };
    let TimerKind::X86AcpiPmTsc {
        pm_timer_port,
        counter_bits,
        ..
    } = platform.timer()
    else {
        return Err(DiscoveryError::PlatformDescriptor);
    };
    let pm_timer_resource = platform
        .io_ports(IoPortRole::AcpiPmTimer)
        .ok_or(DiscoveryError::PlatformDescriptor)?;
    let fadt = discovered.fadt().ok_or(DiscoveryError::X86Fadt)?;
    let reset = fadt.reset().ok_or(DiscoveryError::X86Fadt)?;
    let pm_timer = fadt.pm_timer().ok_or(DiscoveryError::X86Fadt)?;
    let reset_register = reset.register();
    let timer_register = pm_timer.register();
    let boot_architecture = fadt.ia_pc_boot_architecture();
    if fadt.hardware_reduced()
        || !boot_architecture.i8042_present()
        || reset_register.space() != RegisterSpace::SystemIo
        || reset_register.address() != u64::from(reset_control_port)
        || reset_register.bit_width() != 8
        || reset_register.access_bytes() != 1
        || reset.value() != reset_value
        || timer_register.space() != RegisterSpace::SystemIo
        || timer_register.address() != u64::from(pm_timer_port)
        || timer_register.bit_width() != 32
        || timer_register.access_bytes() != 4
        || pm_timer.counter_bits() != counter_bits
        || pm_timer_resource.base() != pm_timer_port
        || pm_timer_resource.count() < 4
    {
        return Err(DiscoveryError::X86Fadt);
    }
    Ok(())
}

#[cfg(all(
    target_os = "uefi",
    feature = "platform-aarch64-uefi-virtio-mmio",
    not(any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    ))
))]
pub(super) fn validate() -> Result<(), DiscoveryError> {
    const FDT_GUID: uefi::Guid = uefi::guid!("b1b621d5-f19c-41a5-830b-d9152c69aae0");

    let fdt_address = unique_config_address(FDT_GUID)?.ok_or(DiscoveryError::ConfigurationTable)?;
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| DiscoveryError::MemoryMap)?;
    let memory = MappedFirmwareMemory::new(&map);
    let header = memory
        .mapped_region(fdt_address, 40)
        .ok_or(DiscoveryError::FirmwareMapping)?;
    let total_size = usize::try_from(u32::from_be_bytes([
        header[4], header[5], header[6], header[7],
    ]))
    .map_err(|_| DiscoveryError::FirmwareParse)?;
    if !(40..=troe_platform::discovery::fdt::MAX_BLOB_BYTES).contains(&total_size) {
        return Err(DiscoveryError::FirmwareParse);
    }
    let blob = memory
        .mapped_region(fdt_address, total_size)
        .ok_or(DiscoveryError::FirmwareMapping)?;
    let discovered =
        troe_platform::discovery::fdt::discover(blob).map_err(|_| DiscoveryError::FirmwareParse)?;
    validate_aarch64(&discovered)
}

#[cfg(all(target_os = "uefi", feature = "platform-aarch64-uefi-virtio-mmio"))]
fn validate_aarch64(
    discovered: &troe_platform::discovery::fdt::Inventory<'_>,
) -> Result<(), DiscoveryError> {
    use troe_platform::{ConsoleKind, InterruptRole, MmioRole, PowerKind};

    let platform = troe_platform::AARCH64_UEFI_VIRTIO_MMIO
        .validate()
        .map_err(|_| DiscoveryError::PlatformDescriptor)?;
    let gic = discovered.gic().ok_or(DiscoveryError::ArmGic)?;
    let distributor = platform
        .mmio(MmioRole::GicV3Distributor)
        .ok_or(DiscoveryError::ArmGic)?;
    let redistributors = platform
        .mmio(MmioRole::GicV3Redistributor)
        .ok_or(DiscoveryError::ArmGic)?;
    // The second region is the redistributor block rather than a CPU
    // interface, which version 3 reaches through system registers instead.
    if gic.version() != GicVersion::V3
        || gic.regions().count() != 2
        || gic.distributor().base() != distributor.base()
        || gic.distributor().byte_len() != distributor.byte_len()
        || gic.cpu_or_redistributor().base() != redistributors.base()
        || gic.cpu_or_redistributor().byte_len() != redistributors.byte_len()
    {
        return Err(DiscoveryError::ArmGic);
    }
    if discovered
        .psci()
        .is_none_or(|psci| psci.conduit() != PsciConduit::Hvc)
        || platform.power() != PowerKind::PsciHvc
    {
        return Err(DiscoveryError::ArmPsci);
    }

    let uart = discovered.stdout_uart().ok_or(DiscoveryError::ArmUart)?;
    let uart_mmio = platform
        .mmio(MmioRole::Pl011)
        .ok_or(DiscoveryError::ArmUart)?;
    let uart_route = platform
        .interrupt(InterruptRole::Serial)
        .ok_or(DiscoveryError::ArmUart)?;
    let ConsoleKind::Pl011 { clock_hz } = platform.console() else {
        return Err(DiscoveryError::ArmUart);
    };
    if uart.kind() != UartKind::Pl011
        || uart.registers().base() != uart_mmio.base()
        || uart.registers().byte_len() != uart_mmio.byte_len()
        || uart.clock_hz() != Some(clock_hz)
        || !matches!(uart.register_shift(), None | Some(0))
        || !matches!(uart.register_io_width(), None | Some(4))
        || !gic_interrupt_matches(
            uart.interrupt(),
            uart_route.line(),
            uart_route.trigger(),
            uart_route.polarity(),
            InterruptKind::Spi,
        )
    {
        return Err(DiscoveryError::ArmUart);
    }

    let timer_route = platform
        .interrupt(InterruptRole::Timer)
        .ok_or(DiscoveryError::ArmTimer)?;
    let physical_timer = discovered
        .timer()
        .and_then(|timer| timer.interrupts().nth(1))
        .ok_or(DiscoveryError::ArmTimer)?;
    if !gic_interrupt_matches(
        physical_timer,
        timer_route.line(),
        timer_route.trigger(),
        timer_route.polarity(),
        InterruptKind::Ppi,
    ) || physical_timer.ppi_cpu_mask() & 1 == 0
    {
        return Err(DiscoveryError::ArmTimer);
    }

    validate_aarch64_virtio(discovered, platform)
}

#[cfg(all(target_os = "uefi", feature = "platform-aarch64-uefi-virtio-mmio"))]
fn validate_aarch64_virtio(
    discovered: &troe_platform::discovery::fdt::Inventory<'_>,
    platform: troe_platform::ValidatedPlatform<'_>,
) -> Result<(), DiscoveryError> {
    use troe_platform::{MmioRole, VirtioTransportKind};

    let aperture = platform
        .mmio(MmioRole::VirtioMmio)
        .ok_or(DiscoveryError::ArmVirtio)?;
    let VirtioTransportKind::Mmio {
        slot_bytes,
        slot_count,
        first_interrupt,
        network_trigger,
        network_polarity,
        ..
    } = platform.virtio()
    else {
        return Err(DiscoveryError::ArmVirtio);
    };
    if slot_count != 32 || aperture.byte_len() != u64::from(slot_bytes) * u64::from(slot_count) {
        return Err(DiscoveryError::ArmVirtio);
    }
    let mut seen = 0u32;
    let mut count = 0usize;
    for device in discovered.virtio_mmio_devices() {
        let Some(offset) = device.registers().base().checked_sub(aperture.base()) else {
            return Err(DiscoveryError::ArmVirtio);
        };
        if device.registers().byte_len() != u64::from(slot_bytes)
            || !offset.is_multiple_of(u64::from(slot_bytes))
        {
            return Err(DiscoveryError::ArmVirtio);
        }
        let index = offset / u64::from(slot_bytes);
        if index >= u64::from(slot_count) {
            return Err(DiscoveryError::ArmVirtio);
        }
        let bit = 1u32
            .checked_shl(u32::try_from(index).map_err(|_| DiscoveryError::ArmVirtio)?)
            .ok_or(DiscoveryError::ArmVirtio)?;
        let expected_interrupt = first_interrupt
            .checked_add(u32::try_from(index).map_err(|_| DiscoveryError::ArmVirtio)?)
            .ok_or(DiscoveryError::ArmVirtio)?;
        if seen & bit != 0
            || !gic_interrupt_matches(
                device.interrupt(),
                expected_interrupt,
                network_trigger,
                network_polarity,
                InterruptKind::Spi,
            )
        {
            return Err(DiscoveryError::ArmVirtio);
        }
        seen |= bit;
        count += 1;
    }
    if count != usize::from(slot_count) || seen != u32::MAX {
        return Err(DiscoveryError::ArmVirtio);
    }
    Ok(())
}

#[cfg(all(target_os = "uefi", feature = "platform-aarch64-uefi-virtio-mmio"))]
fn gic_interrupt_matches(
    interrupt: troe_platform::discovery::fdt::GicInterrupt,
    intid: u32,
    trigger: troe_platform::TriggerMode,
    polarity: troe_platform::Polarity,
    kind: InterruptKind,
) -> bool {
    let trigger_matches = matches!(
        (interrupt.trigger(), trigger),
        (InterruptTrigger::Edge, troe_platform::TriggerMode::Edge)
            | (InterruptTrigger::Level, troe_platform::TriggerMode::Level)
    );
    let polarity_matches = matches!(
        (interrupt.polarity(), polarity),
        (
            InterruptPolarity::ActiveHigh,
            troe_platform::Polarity::ActiveHigh
        ) | (
            InterruptPolarity::ActiveLow,
            troe_platform::Polarity::ActiveLow
        )
    );
    interrupt.kind() == kind && interrupt.intid() == intid && trigger_matches && polarity_matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_span_requires_one_complete_nonoverflowing_region() {
        assert!(firmware_region_contains(
            MemoryType::ACPI_RECLAIM,
            0x1000,
            2,
            0x1800,
            0x1000,
        ));
        assert!(!firmware_region_contains(
            MemoryType::ACPI_RECLAIM,
            0x1000,
            1,
            0x1800,
            0x1000,
        ));
        assert!(!firmware_region_contains(
            MemoryType::ACPI_RECLAIM,
            u64::MAX - 0xfff,
            1,
            u64::MAX - 0xfff,
            1,
        ));
        assert!(!firmware_region_contains(
            MemoryType::ACPI_RECLAIM,
            0x1000,
            1,
            0x1000,
            0,
        ));
    }

    #[test]
    fn physical_span_rejects_free_code_and_device_memory() {
        for memory_type in [
            MemoryType::CONVENTIONAL,
            MemoryType::LOADER_CODE,
            MemoryType::BOOT_SERVICES_CODE,
            MemoryType::RUNTIME_SERVICES_CODE,
            MemoryType::UNUSABLE,
            MemoryType::MMIO,
            MemoryType::MMIO_PORT_SPACE,
        ] {
            assert!(!firmware_region_contains(memory_type, 0x1000, 1, 0x1000, 1,));
        }
    }
}

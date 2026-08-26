//! Audited native mechanisms consuming validated TROE platform descriptors.
#![no_std]
#![deny(unsafe_code)]

#[cfg(all(
    target_os = "uefi",
    not(any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    ))
))]
compile_error!("UEFI builds require exactly one explicit platform feature");
#[cfg(all(
    target_os = "uefi",
    feature = "platform-x86_64-q35-uefi",
    any(
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
compile_error!("UEFI builds cannot select more than one platform feature");
#[cfg(all(
    target_os = "uefi",
    feature = "platform-aarch64-virt-uefi",
    any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
compile_error!("UEFI builds cannot select more than one platform feature");
#[cfg(all(
    target_os = "uefi",
    feature = "platform-x86_64-uefi-virtio-pci",
    feature = "platform-aarch64-uefi-virtio-mmio"
))]
compile_error!("UEFI builds cannot select more than one platform feature");
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    ),
    not(target_arch = "x86_64")
))]
compile_error!("the selected x86-64 platform requires the x86_64 target architecture");
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-aarch64-uefi-virtio-mmio"
    ),
    not(target_arch = "aarch64")
))]
compile_error!("the selected AArch64 platform requires the AArch64 target architecture");

#[cfg(target_os = "uefi")]
extern crate alloc;

#[cfg(target_os = "uefi")]
use alloc::vec::Vec;
#[cfg(target_os = "uefi")]
use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(target_os = "uefi")]
use troe_block::{BlockDevice, BlockError, BlockGeometry};
#[cfg(target_os = "uefi")]
use troe_memory::PhysicalRange;
#[cfg(target_os = "uefi")]
use troe_net::{MacAddress, NetError, NetworkDevice};
#[cfg(target_os = "uefi")]
use troe_platform::VirtioTransportKind;

#[cfg(target_os = "uefi")]
static PLATFORM_VALIDATION_STATE: AtomicU8 = AtomicU8::new(0);
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
static FIRMWARE_DISCOVERY_STATE: AtomicU8 = AtomicU8::new(0);
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
static FIRMWARE_DISCOVERY_FAILURE: AtomicU8 = AtomicU8::new(0);

/// Provenance of the selected platform composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformSource {
    /// Immutable platform descriptor selected at build time.
    Fixed,
    /// Runtime x86 composition validated from UEFI ACPI tables.
    Acpi,
    /// Runtime `AArch64` composition validated from a UEFI devicetree.
    Fdt,
}

/// Sanitized reason that early firmware evidence failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformDiscoveryFailure {
    /// Required UEFI configuration-table entry was absent or ambiguous.
    ConfigurationTable,
    /// A fresh bounded UEFI memory map could not be obtained.
    MemoryMap,
    /// Firmware bytes were not wholly contained by an allowed mapped region.
    FirmwareMapping,
    /// The bounded ACPI or devicetree parser rejected the supplied bytes.
    FirmwareParse,
    /// The selected immutable platform descriptor was internally invalid.
    PlatformDescriptor,
    /// ACPI MCFG did not prove the selected segment-zero ECAM window.
    X86Ecam,
    /// ACPI MADT did not prove the selected APIC and legacy interrupt contract.
    X86Apic,
    /// ACPI SPCR did not prove the selected recovery serial contract.
    X86Spcr,
    /// ACPI FADT did not prove the selected legacy, i8042, and reset contract.
    X86Fadt,
    /// Devicetree evidence did not prove the selected `GICv2` contract.
    ArmGic,
    /// Devicetree evidence did not prove the selected PSCI HVC conduit.
    ArmPsci,
    /// Devicetree evidence did not prove the selected PL011 contract.
    ArmUart,
    /// Devicetree evidence did not prove the selected physical timer route.
    ArmTimer,
    /// Devicetree evidence did not prove all selected virtio-MMIO slots.
    ArmVirtio,
}

impl PlatformDiscoveryFailure {
    #[cfg(all(
        target_os = "uefi",
        any(
            feature = "platform-x86_64-uefi-virtio-pci",
            feature = "platform-aarch64-uefi-virtio-mmio"
        )
    ))]
    const fn code(self) -> u8 {
        match self {
            Self::ConfigurationTable => 1,
            Self::MemoryMap => 2,
            Self::FirmwareMapping => 3,
            Self::FirmwareParse => 4,
            Self::PlatformDescriptor => 5,
            Self::X86Ecam => 6,
            Self::X86Apic => 7,
            Self::X86Spcr => 8,
            Self::X86Fadt => 9,
            Self::ArmGic => 10,
            Self::ArmPsci => 11,
            Self::ArmUart => 12,
            Self::ArmTimer => 13,
            Self::ArmVirtio => 14,
        }
    }

    #[cfg(all(
        target_os = "uefi",
        any(
            feature = "platform-x86_64-uefi-virtio-pci",
            feature = "platform-aarch64-uefi-virtio-mmio"
        )
    ))]
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ConfigurationTable),
            2 => Some(Self::MemoryMap),
            3 => Some(Self::FirmwareMapping),
            4 => Some(Self::FirmwareParse),
            5 => Some(Self::PlatformDescriptor),
            6 => Some(Self::X86Ecam),
            7 => Some(Self::X86Apic),
            8 => Some(Self::X86Spcr),
            9 => Some(Self::X86Fadt),
            10 => Some(Self::ArmGic),
            11 => Some(Self::ArmPsci),
            12 => Some(Self::ArmUart),
            13 => Some(Self::ArmTimer),
            14 => Some(Self::ArmVirtio),
            _ => None,
        }
    }

    /// Stable bounded diagnostic label containing no firmware-supplied bytes.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConfigurationTable => "configuration-table",
            Self::MemoryMap => "memory-map",
            Self::FirmwareMapping => "firmware-mapping",
            Self::FirmwareParse => "firmware-parse",
            Self::PlatformDescriptor => "platform-descriptor",
            Self::X86Ecam => "x86-ecam",
            Self::X86Apic => "x86-apic",
            Self::X86Spcr => "x86-spcr",
            Self::X86Fadt => "x86-fadt",
            Self::ArmGic => "arm-gic",
            Self::ArmPsci => "arm-psci",
            Self::ArmUart => "arm-uart",
            Self::ArmTimer => "arm-timer",
            Self::ArmVirtio => "arm-virtio",
        }
    }
}

#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
#[allow(unsafe_code)]
mod firmware_discovery;
#[cfg(any(test, target_os = "uefi"))]
#[allow(unsafe_code)]
mod mechanism;
#[cfg(any(test, target_os = "uefi"))]
#[allow(unsafe_code)]
mod mmu;
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
#[allow(unsafe_code)]
mod virtio_mmio;
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    )
))]
#[allow(unsafe_code)]
mod virtio_pci;

#[cfg(all(
    target_os = "uefi",
    feature = "platform-x86_64-q35-uefi",
    not(any(
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    ))
))]
fn selected_platform()
-> Result<troe_platform::ValidatedPlatform<'static>, troe_platform::PlatformError> {
    selected_builtin_platform(
        &troe_platform::X86_64_Q35_UEFI,
        troe_platform::VALIDATED_X86_64_Q35_UEFI,
    )
}

#[cfg(all(
    target_os = "uefi",
    feature = "platform-aarch64-virt-uefi",
    not(any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    ))
))]
fn selected_platform()
-> Result<troe_platform::ValidatedPlatform<'static>, troe_platform::PlatformError> {
    selected_builtin_platform(
        &troe_platform::AARCH64_VIRT_UEFI,
        troe_platform::VALIDATED_AARCH64_VIRT_UEFI,
    )
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
fn selected_platform()
-> Result<troe_platform::ValidatedPlatform<'static>, troe_platform::PlatformError> {
    selected_discovered_platform(
        &troe_platform::X86_64_UEFI_VIRTIO_PCI,
        troe_platform::VALIDATED_X86_64_UEFI_VIRTIO_PCI,
    )
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
fn selected_platform()
-> Result<troe_platform::ValidatedPlatform<'static>, troe_platform::PlatformError> {
    selected_discovered_platform(
        &troe_platform::AARCH64_UEFI_VIRTIO_MMIO,
        troe_platform::VALIDATED_AARCH64_UEFI_VIRTIO_MMIO,
    )
}

#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
fn selected_discovered_platform(
    descriptor: &'static troe_platform::PlatformDescriptor<'static>,
    validated: troe_platform::ValidatedPlatform<'static>,
) -> Result<troe_platform::ValidatedPlatform<'static>, troe_platform::PlatformError> {
    if FIRMWARE_DISCOVERY_STATE.load(Ordering::Acquire) != 1 {
        return Err(troe_platform::PlatformError::IncompatibleComposition);
    }
    selected_builtin_platform(descriptor, validated)
}

#[cfg(target_os = "uefi")]
fn selected_builtin_platform(
    descriptor: &'static troe_platform::PlatformDescriptor<'static>,
    validated: troe_platform::ValidatedPlatform<'static>,
) -> Result<troe_platform::ValidatedPlatform<'static>, troe_platform::PlatformError> {
    match PLATFORM_VALIDATION_STATE.load(Ordering::Acquire) {
        1 => Ok(validated),
        2 => Err(troe_platform::PlatformError::InvalidIdentity),
        _ => match descriptor.validate() {
            Ok(token) => {
                PLATFORM_VALIDATION_STATE.store(1, Ordering::Release);
                Ok(token)
            }
            Err(error) => {
                PLATFORM_VALIDATION_STATE.store(2, Ordering::Release);
                Err(error)
            }
        },
    }
}

/// Validate the explicitly selected platform before owned device I/O begins.
///
/// # Errors
///
/// Returns the descriptor's fail-closed validation error.
#[cfg(target_os = "uefi")]
pub fn validate_selected_platform() -> Result<(), troe_platform::PlatformError> {
    #[cfg(any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    ))]
    match FIRMWARE_DISCOVERY_STATE.load(Ordering::Acquire) {
        1 => {}
        2 => return Err(troe_platform::PlatformError::IncompatibleComposition),
        _ => {
            if let Err(failure) = firmware_discovery::validate() {
                FIRMWARE_DISCOVERY_FAILURE.store(failure.code(), Ordering::Release);
                FIRMWARE_DISCOVERY_STATE.store(2, Ordering::Release);
                return Err(troe_platform::PlatformError::IncompatibleComposition);
            }
            FIRMWARE_DISCOVERY_STATE.store(1, Ordering::Release);
        }
    }
    let result = selected_platform().map(|_| ());
    #[cfg(any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    ))]
    if result.is_err() {
        FIRMWARE_DISCOVERY_FAILURE.store(
            PlatformDiscoveryFailure::PlatformDescriptor.code(),
            Ordering::Release,
        );
    }
    result
}

/// Return the stable sanitized reason for a failed discoverable-platform gate.
#[cfg(target_os = "uefi")]
#[must_use]
pub fn platform_discovery_failure() -> Option<PlatformDiscoveryFailure> {
    #[cfg(any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    ))]
    {
        PlatformDiscoveryFailure::from_code(FIRMWARE_DISCOVERY_FAILURE.load(Ordering::Acquire))
    }
    #[cfg(not(any(
        feature = "platform-x86_64-uefi-virtio-pci",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )))]
    None
}

/// Return the evidence source for a platform that has completed validation.
///
/// # Errors
///
/// Returns a fail-closed platform error until descriptor validation and, for a
/// discoverable profile, firmware discovery have both succeeded.
#[cfg(target_os = "uefi")]
pub fn selected_platform_source() -> Result<PlatformSource, troe_platform::PlatformError> {
    selected_platform()?;
    #[cfg(any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-aarch64-virt-uefi"
    ))]
    return Ok(PlatformSource::Fixed);
    #[cfg(feature = "platform-x86_64-uefi-virtio-pci")]
    return Ok(PlatformSource::Acpi);
    #[cfg(feature = "platform-aarch64-uefi-virtio-mmio")]
    return Ok(PlatformSource::Fdt);
}

#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub use mechanism::{
    ApplicationExecutionStats, application_execution_stats, benchmark_counter_frequency_hz,
    benchmark_counter_ticks,
};
#[cfg(target_os = "uefi")]
pub use mechanism::{
    FramebufferError, HeapStats, InputInterruptError, OwnedFramebuffer, PhysicalMemoryError,
    StackSwitchError, TaskStackError, copy_to_physical, current_stack_pointer, enter_owned_stack,
    exit_boot_services_after_protocols, heap_stats, initialize_console, initialize_heap,
    initialize_input_interrupts, initialize_monotonic_clock, input_device_ranges,
    input_interrupt_stats, mark_firmware_exited, monotonic_millis, park, poweroff,
    probe_allocation_failure, read_byte, reboot, run_task_step, take_interrupt_ownership,
    take_network_interrupt, try_input_event, try_read_byte, try_read_keyboard_scancode,
    wait_for_input_event, wait_for_runtime_event, wait_for_runtime_event_timeout, write,
    zero_physical_range,
};

#[cfg(target_os = "uefi")]
pub use mmu::{
    ApplicationCall, ApplicationResume, ApplicationSession, build_user_address_space,
    install_exception_vectors, install_mmu, loaded_image_layout, resume_application,
    run_application, run_isolated,
};
#[cfg(any(test, target_os = "uefi"))]
pub use mmu::{ApplicationOutcome, IsolatedFault, IsolatedOutcome, UserAddressSpace};
#[cfg(any(test, target_os = "uefi"))]
pub use mmu::{ImageLayout, ImageRegion, MmuError, MmuStats};
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub use mmu::{trigger_execute_fault, trigger_native_exception, trigger_write_fault};

#[doc(hidden)]
#[cfg(target_os = "uefi")]
pub use virtio_mmio::{
    NativeVirtioBlock as MmioNativeVirtioBlock, NativeVirtioNetwork as MmioNativeVirtioNetwork,
};
#[doc(hidden)]
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    )
))]
pub use virtio_pci::{
    NativeVirtioBlock as PciNativeVirtioBlock, NativeVirtioNetwork as PciNativeVirtioNetwork,
};

/// Failure while validating or using the selected platform's native virtio
/// transport.
#[cfg(target_os = "uefi")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeVirtioError {
    /// The selected descriptor failed validation or named a transport that is
    /// incompatible with the compiled machine mechanisms.
    InvalidPlatform,
    /// Device discovery or initialization failed transactionally.
    Transport,
}

/// One initialized block capability selected from the validated platform's
/// native virtio transport.
#[cfg(target_os = "uefi")]
pub enum NativeVirtioBlock {
    /// Modern virtio PCI device.
    #[cfg(any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    ))]
    Pci(PciNativeVirtioBlock),
    /// Modern virtio-MMIO device.
    Mmio(MmioNativeVirtioBlock),
}

#[cfg(target_os = "uefi")]
impl NativeVirtioBlock {
    /// Immutable feature and geometry profile negotiated by the selected
    /// transport.
    #[must_use]
    pub fn profile(&self) -> troe_virtio::VirtioBlockProfile {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => device.profile(),
            Self::Mmio(device) => device.profile(),
        }
    }
}

#[cfg(target_os = "uefi")]
impl BlockDevice for NativeVirtioBlock {
    fn geometry(&self) -> BlockGeometry {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => device.geometry(),
            Self::Mmio(device) => device.geometry(),
        }
    }

    fn read_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        destination: &mut [u8],
    ) -> Result<(), BlockError> {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => device.read_blocks(start_block, block_count, destination),
            Self::Mmio(device) => device.read_blocks(start_block, block_count, destination),
        }
    }

    fn write_blocks(
        &mut self,
        start_block: u64,
        block_count: u32,
        source: &[u8],
        force_unit_access: bool,
    ) -> Result<(), BlockError> {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => {
                device.write_blocks(start_block, block_count, source, force_unit_access)
            }
            Self::Mmio(device) => {
                device.write_blocks(start_block, block_count, source, force_unit_access)
            }
        }
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => device.flush(),
            Self::Mmio(device) => device.flush(),
        }
    }
}

/// One initialized network capability selected from the validated platform's
/// native virtio transport.
#[cfg(target_os = "uefi")]
pub enum NativeVirtioNetwork {
    /// Modern virtio PCI network device.
    #[cfg(any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    ))]
    Pci(PciNativeVirtioNetwork),
    /// Modern virtio-MMIO network device.
    Mmio(MmioNativeVirtioNetwork),
}

#[cfg(target_os = "uefi")]
impl NativeVirtioNetwork {
    /// Connect completion delivery through the selected platform controller.
    ///
    /// # Errors
    ///
    /// Returns a transport failure if the device cannot establish exclusive
    /// interrupt ownership transactionally.
    pub fn enable_interrupts(&mut self) -> Result<(), NativeVirtioError> {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => device
                .enable_interrupts()
                .map_err(|_| NativeVirtioError::Transport),
            Self::Mmio(device) => device
                .enable_interrupts()
                .map_err(|_| NativeVirtioError::Transport),
        }
    }
}

#[cfg(target_os = "uefi")]
impl NetworkDevice for NativeVirtioNetwork {
    fn mac_address(&self) -> MacAddress {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => device.mac_address(),
            Self::Mmio(device) => device.mac_address(),
        }
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => device.transmit(frame),
            Self::Mmio(device) => device.transmit(frame),
        }
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        match self {
            #[cfg(any(
                feature = "platform-x86_64-q35-uefi",
                feature = "platform-x86_64-uefi-virtio-pci"
            ))]
            Self::Pci(device) => device.receive(),
            Self::Mmio(device) => device.receive(),
        }
    }
}

#[cfg(target_os = "uefi")]
fn wrap_mmio_blocks(
    devices: Vec<MmioNativeVirtioBlock>,
) -> Result<Vec<NativeVirtioBlock>, NativeVirtioError> {
    let mut wrapped = Vec::new();
    wrapped
        .try_reserve_exact(devices.len())
        .map_err(|_| NativeVirtioError::Transport)?;
    for device in devices {
        wrapped.push(NativeVirtioBlock::Mmio(device));
    }
    Ok(wrapped)
}

#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    )
))]
fn wrap_pci_blocks(
    devices: Vec<PciNativeVirtioBlock>,
) -> Result<Vec<NativeVirtioBlock>, NativeVirtioError> {
    let mut wrapped = Vec::new();
    wrapped
        .try_reserve_exact(devices.len())
        .map_err(|_| NativeVirtioError::Transport)?;
    for device in devices {
        wrapped.push(NativeVirtioBlock::Pci(device));
    }
    Ok(wrapped)
}

#[cfg(target_os = "uefi")]
fn mmio_device_ranges() -> Result<Vec<PhysicalRange>, NativeVirtioError> {
    let [range] =
        virtio_mmio::virtio_mmio_device_ranges().map_err(|_| NativeVirtioError::Transport)?;
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(1)
        .map_err(|_| NativeVirtioError::Transport)?;
    ranges.push(range);
    Ok(ranges)
}

/// Return the device-memory ranges required by the selected virtio transport.
///
/// # Errors
///
/// Fails before returning any range if the platform/transport composition is
/// invalid or transport discovery encounters malformed hardware.
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    )
))]
pub fn virtio_device_ranges() -> Result<Vec<PhysicalRange>, NativeVirtioError> {
    let platform = selected_platform().map_err(|_| NativeVirtioError::InvalidPlatform)?;
    match platform.virtio() {
        VirtioTransportKind::Pci { .. } => {
            virtio_pci::virtio_pci_device_ranges().map_err(|_| NativeVirtioError::Transport)
        }
        VirtioTransportKind::Mmio { .. } => mmio_device_ranges(),
    }
}

/// Return the device-memory ranges required by the selected virtio transport.
///
/// # Errors
///
/// Fails before returning any range if the platform/transport composition is
/// invalid or transport discovery encounters malformed hardware.
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
pub fn virtio_device_ranges() -> Result<Vec<PhysicalRange>, NativeVirtioError> {
    let platform = selected_platform().map_err(|_| NativeVirtioError::InvalidPlatform)?;
    match platform.virtio() {
        VirtioTransportKind::Mmio { .. } => mmio_device_ranges(),
        VirtioTransportKind::Pci { .. } => Err(NativeVirtioError::InvalidPlatform),
    }
}

/// Discover every native virtio block device using the selected platform's
/// transport.
///
/// # Errors
///
/// Fails transactionally if the selected descriptor is incompatible or any
/// advertised device violates the bounded transport contract.
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    )
))]
pub fn discover_virtio_blocks() -> Result<Vec<NativeVirtioBlock>, NativeVirtioError> {
    let platform = selected_platform().map_err(|_| NativeVirtioError::InvalidPlatform)?;
    match platform.virtio() {
        VirtioTransportKind::Pci { .. } => wrap_pci_blocks(
            virtio_pci::discover_virtio_pci_blocks().map_err(|_| NativeVirtioError::Transport)?,
        ),
        VirtioTransportKind::Mmio { .. } => wrap_mmio_blocks(
            virtio_mmio::discover_virtio_mmio_blocks().map_err(|_| NativeVirtioError::Transport)?,
        ),
    }
}

/// Discover every native virtio block device using the selected platform's
/// transport.
///
/// # Errors
///
/// Fails transactionally if the selected descriptor is incompatible or any
/// advertised device violates the bounded transport contract.
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
pub fn discover_virtio_blocks() -> Result<Vec<NativeVirtioBlock>, NativeVirtioError> {
    let platform = selected_platform().map_err(|_| NativeVirtioError::InvalidPlatform)?;
    match platform.virtio() {
        VirtioTransportKind::Mmio { .. } => wrap_mmio_blocks(
            virtio_mmio::discover_virtio_mmio_blocks().map_err(|_| NativeVirtioError::Transport)?,
        ),
        VirtioTransportKind::Pci { .. } => Err(NativeVirtioError::InvalidPlatform),
    }
}

/// Discover the optional native virtio network device using the selected
/// platform's transport.
///
/// # Errors
///
/// Fails transactionally if the selected descriptor is incompatible or the
/// device violates the bounded transport contract.
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-x86_64-q35-uefi",
        feature = "platform-x86_64-uefi-virtio-pci"
    )
))]
pub fn discover_virtio_network() -> Result<Option<NativeVirtioNetwork>, NativeVirtioError> {
    let platform = selected_platform().map_err(|_| NativeVirtioError::InvalidPlatform)?;
    match platform.virtio() {
        VirtioTransportKind::Pci { .. } => virtio_pci::discover_virtio_pci_network()
            .map(|device| device.map(NativeVirtioNetwork::Pci))
            .map_err(|_| NativeVirtioError::Transport),
        VirtioTransportKind::Mmio { .. } => virtio_mmio::discover_virtio_mmio_network()
            .map(|device| device.map(NativeVirtioNetwork::Mmio))
            .map_err(|_| NativeVirtioError::Transport),
    }
}

/// Discover the optional native virtio network device using the selected
/// platform's transport.
///
/// # Errors
///
/// Fails transactionally if the selected descriptor is incompatible or the
/// device violates the bounded transport contract.
#[cfg(all(
    target_os = "uefi",
    any(
        feature = "platform-aarch64-virt-uefi",
        feature = "platform-aarch64-uefi-virtio-mmio"
    )
))]
pub fn discover_virtio_network() -> Result<Option<NativeVirtioNetwork>, NativeVirtioError> {
    let platform = selected_platform().map_err(|_| NativeVirtioError::InvalidPlatform)?;
    match platform.virtio() {
        VirtioTransportKind::Mmio { .. } => virtio_mmio::discover_virtio_mmio_network()
            .map(|device| device.map(NativeVirtioNetwork::Mmio))
            .map_err(|_| NativeVirtioError::Transport),
        VirtioTransportKind::Pci { .. } => Err(NativeVirtioError::InvalidPlatform),
    }
}

/// Acknowledge only the transport selected by the validated platform.
///
/// Mechanism interrupt entry will call this façade after the controller route
/// has established ownership. Validation failure is treated as no owned source.
#[cfg(target_os = "uefi")]
fn acknowledge_network_interrupt_from_isr() -> bool {
    let Ok(platform) = selected_platform() else {
        return false;
    };
    match platform.virtio() {
        #[cfg(any(
            feature = "platform-x86_64-q35-uefi",
            feature = "platform-x86_64-uefi-virtio-pci"
        ))]
        VirtioTransportKind::Pci { .. } => virtio_pci::acknowledge_network_interrupt_from_isr(),
        VirtioTransportKind::Mmio { .. } => virtio_mmio::acknowledge_network_interrupt_from_isr(),
        #[cfg(any(
            feature = "platform-aarch64-virt-uefi",
            feature = "platform-aarch64-uefi-virtio-mmio"
        ))]
        VirtioTransportKind::Pci { .. } => false,
    }
}

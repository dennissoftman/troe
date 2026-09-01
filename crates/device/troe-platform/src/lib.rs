//! Validated immutable virtual-machine platform composition descriptors.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// Bounded, allocation-free ACPI and Flattened Devicetree discovery.
pub mod discovery;

/// Maximum accepted platform-name bytes.
pub const MAX_PLATFORM_NAME_BYTES: usize = 63;
const X86_APPLICATION_CALL_VECTOR: u8 = 0x80;

/// CPU architecture implemented by a machine backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    /// AMD64/x86-64 long mode.
    X86_64,
    /// 64-bit Arm.
    Aarch64,
}

/// Stable nonzero platform identity used by build and diagnostic records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformId(u16);

impl PlatformId {
    /// Pinned QEMU q35 UEFI platform.
    pub const X86_64_Q35_UEFI: Self = Self(1);
    /// Pinned Arm SBSA reference UEFI platform.
    pub const AARCH64_SBSA_REF: Self = Self(2);
    /// Discoverable x86-64 UEFI cloud contract using modern virtio PCI.
    pub const X86_64_UEFI_VIRTIO_PCI: Self = Self(3);
    /// Discoverable `AArch64` UEFI cloud contract using modern virtio MMIO.
    pub const AARCH64_UEFI_VIRTIO_MMIO: Self = Self(4);

    /// Construct a nonzero identity for a separately named platform.
    ///
    /// # Errors
    ///
    /// Rejects zero, which is reserved for absence/corruption.
    pub const fn new(raw: u16) -> Result<Self, PlatformError> {
        if raw == 0 {
            Err(PlatformError::InvalidIdentity)
        } else {
            Ok(Self(raw))
        }
    }

    /// Numeric identity encoded in diagnostics and manifests.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// Closed role names for owned byte-addressed MMIO apertures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioRole {
    /// x86 local APIC page.
    LocalApic,
    /// x86 I/O APIC page.
    IoApic,
    /// Arm `GICv2` distributor aperture.
    GicV2Distributor,
    /// Arm `GICv2` CPU-interface aperture.
    GicV2CpuInterface,
    /// Arm `GICv3` distributor aperture.
    GicV3Distributor,
    /// Arm `GICv3` redistributor region, one strided frame pair per CPU.
    GicV3Redistributor,
    /// Arm PL011 UART page.
    Pl011,
    /// Modern virtio-MMIO slot aperture.
    VirtioMmio,
    /// PCI Enhanced Configuration Access Mechanism aperture.
    PciEcam,
}

/// Closed role names for owned x86 I/O-port ranges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoPortRole {
    /// Primary 8259 PIC command/data ports.
    PicPrimary,
    /// Secondary 8259 PIC command/data ports.
    PicSecondary,
    /// PIT channel/control ports.
    Pit,
    /// i8042 keyboard data port.
    KeyboardData,
    /// PC system-control port used by PIT channel 2.
    SystemControl,
    /// i8042 keyboard status/command port.
    KeyboardStatus,
    /// 16550 COM1 register block.
    Serial,
    /// ACPI PM1 control register block.
    PowerManagement,
    /// PCI configuration mechanism 1 address/data block.
    PciConfiguration,
    /// Firmware-described reset-control register block.
    ResetControl,
    /// ACPI fixed-hardware power-management timer register.
    AcpiPmTimer,
}

/// Closed roles for statically routed interrupts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptRole {
    /// Recovery UART receive interrupt.
    Serial,
    /// Native keyboard receive interrupt.
    Keyboard,
    /// Architecture timer interrupt.
    Timer,
}

/// Interrupt electrical/virtual trigger behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriggerMode {
    /// Edge-triggered delivery.
    Edge,
    /// Level-triggered delivery.
    Level,
}

/// Interrupt active polarity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Polarity {
    /// Active-high signal.
    ActiveHigh,
    /// Active-low signal.
    ActiveLow,
}

/// One page-aligned, nonempty MMIO aperture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioRegion {
    role: MmioRole,
    base: u64,
    byte_len: u64,
}

impl MmioRegion {
    /// Construct a proposed platform MMIO region.
    #[must_use]
    pub const fn new(role: MmioRole, base: u64, byte_len: u64) -> Self {
        Self {
            role,
            base,
            byte_len,
        }
    }

    /// Semantic owner of the aperture.
    #[must_use]
    pub const fn role(self) -> MmioRole {
        self.role
    }

    /// First physical byte.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Complete aperture length.
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }

    const fn end(self) -> Option<u64> {
        self.base.checked_add(self.byte_len)
    }
}

/// One nonempty x86 I/O-port range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoPortRegion {
    role: IoPortRole,
    base: u16,
    count: u16,
}

impl IoPortRegion {
    /// Construct a proposed platform I/O-port range.
    #[must_use]
    pub const fn new(role: IoPortRole, base: u16, count: u16) -> Self {
        Self { role, base, count }
    }

    /// Semantic owner of the ports.
    #[must_use]
    pub const fn role(self) -> IoPortRole {
        self.role
    }

    /// First owned port.
    #[must_use]
    pub const fn base(self) -> u16 {
        self.base
    }

    /// Owned port count.
    #[must_use]
    pub const fn count(self) -> u16 {
        self.count
    }

    fn end(self) -> Option<u32> {
        u32::from(self.base).checked_add(u32::from(self.count))
    }

    fn contains(self, port: u16) -> bool {
        let port = u32::from(port);
        self.end()
            .is_some_and(|end| port >= u32::from(self.base) && port < end)
    }

    fn contains_span(self, first: u16, count: u16) -> bool {
        if count == 0 {
            return false;
        }
        let first = u32::from(first);
        first >= u32::from(self.base)
            && first
                .checked_add(u32::from(count))
                .is_some_and(|end| self.end().is_some_and(|resource_end| end <= resource_end))
    }
}

/// One statically selected interrupt route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptRoute {
    role: InterruptRole,
    line: u32,
    vector: u8,
    priority: u8,
    trigger: TriggerMode,
    polarity: Polarity,
}

impl InterruptRoute {
    /// Construct a proposed route.
    #[must_use]
    pub const fn new(
        role: InterruptRole,
        line: u32,
        vector: u8,
        priority: u8,
        trigger: TriggerMode,
        polarity: Polarity,
    ) -> Self {
        Self {
            role,
            line,
            vector,
            priority,
            trigger,
            polarity,
        }
    }

    /// Route purpose.
    #[must_use]
    pub const fn role(self) -> InterruptRole {
        self.role
    }

    /// GSI or GIC INTID.
    #[must_use]
    pub const fn line(self) -> u32 {
        self.line
    }

    /// CPU-visible vector or architecture IRQ-vector identity.
    #[must_use]
    pub const fn vector(self) -> u8 {
        self.vector
    }

    /// Controller priority byte; zero when the controller has no such field.
    #[must_use]
    pub const fn priority(self) -> u8 {
        self.priority
    }

    /// Trigger behavior.
    #[must_use]
    pub const fn trigger(self) -> TriggerMode {
        self.trigger
    }

    /// Active polarity.
    #[must_use]
    pub const fn polarity(self) -> Polarity {
        self.polarity
    }
}

/// Native console mechanism selected by a platform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleKind {
    /// 16550 UART in [`IoPortRole::Serial`].
    Uart16550,
    /// PL011 UART in [`MmioRole::Pl011`] with an exact input clock.
    Pl011 {
        /// UART reference clock in hertz.
        clock_hz: u32,
    },
}

/// Interrupt-controller topology.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptControllerKind {
    /// Local APIC plus I/O APIC and masked legacy PICs.
    X86Apic,
    /// GIC version 2 distributor and CPU interface.
    GicV2 {
        /// Distributor CPU-target mask for statically routed shared interrupts.
        cpu_target_mask: u8,
    },
    /// GIC version 3 distributor plus per-CPU redistributors.
    ///
    /// The CPU interface is reached through `ICC_*` system registers rather
    /// than an MMIO aperture, so only the distributor and the redistributor
    /// region are described here. Shared interrupts are routed by affinity
    /// instead of the version 2 target mask.
    GicV3 {
        /// Bytes between consecutive per-CPU redistributor frame pairs.
        redistributor_stride: u64,
    },
}

/// Monotonic/execution-lease timer composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerKind {
    /// TSC calibrated by PIT channel 2 and local-APIC lease vector.
    X86PitTsc {
        /// Local-APIC timer vector.
        timer_vector: u8,
        /// Local-APIC spurious vector.
        spurious_vector: u8,
    },
    /// TSC and local-APIC timer calibrated by the ACPI PM timer.
    X86AcpiPmTsc {
        /// Local-APIC timer vector.
        timer_vector: u8,
        /// Local-APIC spurious vector.
        spurious_vector: u8,
        /// Fixed-hardware PM timer I/O port.
        pm_timer_port: u16,
        /// Implemented PM timer counter bits, either 24 or 32.
        counter_bits: u8,
    },
    /// Arm generic physical timer routed as a GIC PPI.
    Aarch64Generic,
}

/// Terminal lifecycle mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerKind {
    /// q35 ACPI PM1 S5 and reset-control ports.
    Q35 {
        /// PM1 control port contained by [`IoPortRole::PowerManagement`].
        pm_control_port: u16,
        /// Reset-control port contained by [`IoPortRole::PciConfiguration`].
        reset_control_port: u16,
        /// Platform S5 sleep-type value.
        sleep_type: u8,
    },
    /// Reset-only x86 lifecycle contract; soft-off is unsupported.
    X86Reset {
        /// Firmware-validated reset-control port.
        reset_control_port: u16,
        /// Firmware-validated full-reset command byte.
        reset_value: u8,
    },
    /// PSCI 1.0 through the HVC conduit, reaching an implementation at EL2.
    PsciHvc,
    /// PSCI 1.0 through the SMC conduit, reaching an implementation at EL3.
    ///
    /// Firmware built on Trusted Firmware places PSCI in its EL3 runtime, so a
    /// hypervisor call from EL1 would reach an EL2 that has nothing to answer
    /// it. The conduit is a property of the platform, not of the architecture.
    PsciSmc,
}

/// PCI configuration transport selected by the platform contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciConfigurationKind {
    /// Legacy PCI configuration mechanism 1 through I/O ports.
    Mechanism1,
    /// ACPI MCFG Enhanced Configuration Access Mechanism aperture.
    Ecam,
}

/// Native keyboard integration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyboardKind {
    /// No native keyboard transport.
    None,
    /// First i8042 port using split data and status resources.
    I8042,
}

/// Preferred virtio transport and its platform-owned discovery bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioTransportKind {
    /// Modern virtio PCI functions behind a bounded configuration transport.
    Pci {
        /// Configuration transport used for every PCI config-space access.
        configuration: PciConfigurationKind,
        /// First PCI bus scanned.
        first_bus: u8,
        /// Last PCI bus scanned, inclusive.
        last_bus: u8,
        /// Maximum accepted I/O APIC input line.
        maximum_interrupt_line: u8,
        /// Dedicated CPU vector used for virtio `INTx`.
        network_vector: u8,
        /// Trigger behavior for the platform `INTx` route.
        network_trigger: TriggerMode,
        /// Active polarity for the platform `INTx` route.
        network_polarity: Polarity,
    },
    /// Modern virtio PCI functions whose `INTx` pins reach an Arm GIC.
    ///
    /// Arm platforms do not name a PCI function's interrupt in the
    /// configuration Interrupt Line byte. The pin instead reaches one of four
    /// consecutive shared peripheral interrupts through the standard swizzle,
    /// so the descriptor pins the first of those four rather than a ceiling on
    /// a configuration-space value.
    PciGic {
        /// Configuration transport used for every PCI config-space access.
        configuration: PciConfigurationKind,
        /// First PCI bus scanned.
        first_bus: u8,
        /// Last PCI bus scanned, inclusive.
        last_bus: u8,
        /// INTID reached by `INTA` on device zero.
        first_interrupt: u32,
        /// Controller priority for network completion.
        network_priority: u8,
        /// Trigger behavior for the four swizzled SPIs.
        network_trigger: TriggerMode,
        /// Active polarity for the four swizzled SPIs.
        network_polarity: Polarity,
    },
    /// Modern virtio-MMIO slots in [`MmioRole::VirtioMmio`].
    Mmio {
        /// Bytes per slot.
        slot_bytes: u32,
        /// Maximum slots inspected.
        slot_count: u16,
        /// INTID assigned to slot zero.
        first_interrupt: u32,
        /// Controller priority for network completion.
        network_priority: u8,
        /// Trigger behavior for the selected SPI.
        network_trigger: TriggerMode,
        /// Active polarity for the selected SPI.
        network_polarity: Polarity,
    },
}

/// Immutable proposed VM-platform composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformDescriptor<'a> {
    id: PlatformId,
    name: &'a str,
    architecture: Architecture,
    mmio: &'a [MmioRegion],
    io_ports: &'a [IoPortRegion],
    interrupts: &'a [InterruptRoute],
    console: ConsoleKind,
    controller: InterruptControllerKind,
    timer: TimerKind,
    power: PowerKind,
    keyboard: KeyboardKind,
    virtio: VirtioTransportKind,
}

impl<'a> PlatformDescriptor<'a> {
    /// Construct a proposed descriptor. Call [`Self::validate`] before use.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: PlatformId,
        name: &'a str,
        architecture: Architecture,
        mmio: &'a [MmioRegion],
        io_ports: &'a [IoPortRegion],
        interrupts: &'a [InterruptRoute],
        console: ConsoleKind,
        controller: InterruptControllerKind,
        timer: TimerKind,
        power: PowerKind,
        keyboard: KeyboardKind,
        virtio: VirtioTransportKind,
    ) -> Self {
        Self {
            id,
            name,
            architecture,
            mmio,
            io_ports,
            interrupts,
            console,
            controller,
            timer,
            power,
            keyboard,
            virtio,
        }
    }

    /// Validate every identity, resource, and controller relationship.
    ///
    /// # Errors
    ///
    /// Rejects malformed names/identities, architecture mismatches,
    /// invalid/overlapping/duplicate resources, interrupt collisions, and
    /// incompatible device/controller compositions.
    pub fn validate(&'a self) -> Result<ValidatedPlatform<'a>, PlatformError> {
        validate_name(self.name)?;
        self.validate_known_identity()?;
        validate_mmio(self.architecture, self.mmio)?;
        validate_io_ports(self.io_ports)?;
        validate_interrupts(self.architecture, self.interrupts)?;
        self.validate_composition()?;
        Ok(ValidatedPlatform { descriptor: self })
    }

    fn validate_known_identity(self) -> Result<(), PlatformError> {
        let valid = match (self.id, self.name) {
            (PlatformId::X86_64_Q35_UEFI, "x86_64-q35-uefi")
            | (PlatformId::X86_64_UEFI_VIRTIO_PCI, "x86_64-uefi-virtio-pci") => {
                self.architecture == Architecture::X86_64
            }
            (PlatformId::AARCH64_SBSA_REF, "aarch64-sbsa-ref")
            | (PlatformId::AARCH64_UEFI_VIRTIO_MMIO, "aarch64-uefi-virtio-mmio") => {
                self.architecture == Architecture::Aarch64
            }
            (
                PlatformId::X86_64_Q35_UEFI
                | PlatformId::AARCH64_SBSA_REF
                | PlatformId::X86_64_UEFI_VIRTIO_PCI
                | PlatformId::AARCH64_UEFI_VIRTIO_MMIO,
                _,
            )
            | (
                _,
                "x86_64-q35-uefi"
                | "aarch64-sbsa-ref"
                | "x86_64-uefi-virtio-pci"
                | "aarch64-uefi-virtio-mmio",
            ) => false,
            _ => true,
        };
        if valid {
            Ok(())
        } else {
            Err(PlatformError::InvalidIdentity)
        }
    }

    fn validate_composition(self) -> Result<(), PlatformError> {
        match (
            self.architecture,
            self.console,
            self.controller,
            self.timer,
            self.power,
            self.keyboard,
            self.virtio,
        ) {
            (Architecture::X86_64, _, _, _, _, _, _) => validate_x86_composition(self)?,
            (
                Architecture::Aarch64,
                ConsoleKind::Pl011 { clock_hz },
                InterruptControllerKind::GicV2 { .. } | InterruptControllerKind::GicV3 { .. },
                TimerKind::Aarch64Generic,
                PowerKind::PsciHvc | PowerKind::PsciSmc,
                KeyboardKind::None,
                VirtioTransportKind::Mmio {
                    slot_bytes,
                    slot_count,
                    first_interrupt,
                    network_priority,
                    network_trigger,
                    network_polarity,
                },
            ) => validate_aarch64_composition(
                self,
                clock_hz,
                self.controller,
                slot_bytes,
                slot_count,
                first_interrupt,
                network_priority,
                network_trigger,
                network_polarity,
            )?,
            (
                Architecture::Aarch64,
                ConsoleKind::Pl011 { clock_hz },
                InterruptControllerKind::GicV3 { .. },
                TimerKind::Aarch64Generic,
                PowerKind::PsciHvc | PowerKind::PsciSmc,
                KeyboardKind::None,
                VirtioTransportKind::PciGic {
                    configuration,
                    first_bus,
                    last_bus,
                    first_interrupt,
                    network_priority,
                    network_trigger,
                    network_polarity,
                },
            ) => validate_aarch64_pci_composition(
                self,
                clock_hz,
                self.controller,
                configuration,
                first_bus,
                last_bus,
                first_interrupt,
                network_priority,
                network_trigger,
                network_polarity,
            )?,
            _ => return Err(PlatformError::IncompatibleComposition),
        }
        Ok(())
    }
}

fn validate_x86_composition(descriptor: PlatformDescriptor<'_>) -> Result<(), PlatformError> {
    match (
        descriptor.console,
        descriptor.controller,
        descriptor.timer,
        descriptor.power,
        descriptor.keyboard,
        descriptor.virtio,
    ) {
        (
            ConsoleKind::Uart16550,
            InterruptControllerKind::X86Apic,
            TimerKind::X86PitTsc {
                timer_vector,
                spurious_vector,
            },
            PowerKind::Q35 {
                pm_control_port,
                reset_control_port,
                sleep_type,
            },
            KeyboardKind::I8042,
            VirtioTransportKind::Pci {
                configuration: PciConfigurationKind::Mechanism1,
                first_bus,
                last_bus,
                maximum_interrupt_line,
                network_vector,
                network_trigger,
                network_polarity,
            },
        ) => validate_x86_q35_composition(
            descriptor,
            timer_vector,
            spurious_vector,
            pm_control_port,
            reset_control_port,
            sleep_type,
            first_bus,
            last_bus,
            maximum_interrupt_line,
            network_vector,
            network_trigger,
            network_polarity,
        ),
        (
            ConsoleKind::Uart16550,
            InterruptControllerKind::X86Apic,
            TimerKind::X86AcpiPmTsc {
                timer_vector,
                spurious_vector,
                pm_timer_port,
                counter_bits,
            },
            PowerKind::X86Reset {
                reset_control_port,
                reset_value,
            },
            KeyboardKind::I8042,
            VirtioTransportKind::Pci {
                configuration: PciConfigurationKind::Ecam,
                first_bus,
                last_bus,
                maximum_interrupt_line,
                network_vector,
                network_trigger,
                network_polarity,
            },
        ) => validate_x86_ecam_composition(
            descriptor,
            timer_vector,
            spurious_vector,
            reset_control_port,
            reset_value,
            pm_timer_port,
            counter_bits,
            first_bus,
            last_bus,
            maximum_interrupt_line,
            network_vector,
            network_trigger,
            network_polarity,
        ),
        _ => Err(PlatformError::IncompatibleComposition),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_x86_q35_composition(
    descriptor: PlatformDescriptor<'_>,
    timer_vector: u8,
    spurious_vector: u8,
    pm_control_port: u16,
    reset_control_port: u16,
    sleep_type: u8,
    first_bus: u8,
    last_bus: u8,
    maximum_interrupt_line: u8,
    network_vector: u8,
    network_trigger: TriggerMode,
    network_polarity: Polarity,
) -> Result<(), PlatformError> {
    validate_x86_common_composition(
        descriptor,
        timer_vector,
        spurious_vector,
        first_bus,
        last_bus,
        maximum_interrupt_line,
        network_vector,
        network_trigger,
        network_polarity,
    )?;
    let pit = require_io(descriptor.io_ports, IoPortRole::Pit)?;
    let system_control = require_io(descriptor.io_ports, IoPortRole::SystemControl)?;
    let power = require_io(descriptor.io_ports, IoPortRole::PowerManagement)?;
    let pci = require_io(descriptor.io_ports, IoPortRole::PciConfiguration)?;
    if descriptor.io_ports.len() != 9
        || sleep_type > 7
        || !pit.contains_span(pit.base, 4)
        || !system_control.contains_span(system_control.base, 1)
        || !power.contains_span(pm_control_port, 2)
        || !pci.base.is_multiple_of(4)
        || !pci.contains_span(pci.base, 8)
        || !pci.contains(reset_control_port)
    {
        return Err(PlatformError::IncompatibleComposition);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_x86_ecam_composition(
    descriptor: PlatformDescriptor<'_>,
    timer_vector: u8,
    spurious_vector: u8,
    reset_control_port: u16,
    reset_value: u8,
    pm_timer_port: u16,
    counter_bits: u8,
    first_bus: u8,
    last_bus: u8,
    maximum_interrupt_line: u8,
    network_vector: u8,
    network_trigger: TriggerMode,
    network_polarity: Polarity,
) -> Result<(), PlatformError> {
    validate_x86_common_composition(
        descriptor,
        timer_vector,
        spurious_vector,
        first_bus,
        last_bus,
        maximum_interrupt_line,
        network_vector,
        network_trigger,
        network_polarity,
    )?;
    let reset = require_io(descriptor.io_ports, IoPortRole::ResetControl)?;
    let pm_timer = require_io(descriptor.io_ports, IoPortRole::AcpiPmTimer)?;
    if descriptor.io_ports.len() != 7
        || !reset.contains_span(reset_control_port, 1)
        || reset_value == 0
        || !pm_timer.contains_span(pm_timer_port, 4)
        || !matches!(counter_bits, 24 | 32)
    {
        return Err(PlatformError::IncompatibleComposition);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_x86_common_composition(
    descriptor: PlatformDescriptor<'_>,
    timer_vector: u8,
    spurious_vector: u8,
    first_bus: u8,
    last_bus: u8,
    maximum_interrupt_line: u8,
    network_vector: u8,
    network_trigger: TriggerMode,
    network_polarity: Polarity,
) -> Result<(), PlatformError> {
    for role in [MmioRole::LocalApic, MmioRole::IoApic] {
        require_mmio(descriptor.mmio, role)?;
    }
    for role in [
        IoPortRole::PicPrimary,
        IoPortRole::PicSecondary,
        IoPortRole::KeyboardData,
        IoPortRole::KeyboardStatus,
        IoPortRole::Serial,
    ] {
        require_io(descriptor.io_ports, role)?;
    }
    require_interrupt(descriptor.interrupts, InterruptRole::Serial)?;
    require_interrupt(descriptor.interrupts, InterruptRole::Keyboard)?;
    let primary_pic = require_io(descriptor.io_ports, IoPortRole::PicPrimary)?;
    let secondary_pic = require_io(descriptor.io_ports, IoPortRole::PicSecondary)?;
    let keyboard_data = require_io(descriptor.io_ports, IoPortRole::KeyboardData)?;
    let keyboard_status = require_io(descriptor.io_ports, IoPortRole::KeyboardStatus)?;
    let serial = require_io(descriptor.io_ports, IoPortRole::Serial)?;
    if descriptor.mmio.len() != 2
        || descriptor.interrupts.len() != 2
        || first_bus > last_bus
        || maximum_interrupt_line == 0
        || timer_vector < 32
        || spurious_vector < 32
        || network_vector < 32
        || timer_vector == spurious_vector
        || timer_vector == network_vector
        || spurious_vector == network_vector
        || network_trigger != TriggerMode::Level
        || network_polarity != Polarity::ActiveLow
        || descriptor
            .interrupts
            .iter()
            .any(|route| route.line > u32::from(maximum_interrupt_line))
        || [timer_vector, spurious_vector, network_vector].contains(&X86_APPLICATION_CALL_VECTOR)
        || [timer_vector, spurious_vector, network_vector]
            .iter()
            .any(|vector| {
                descriptor
                    .interrupts
                    .iter()
                    .any(|route| route.vector == *vector)
            })
        || !primary_pic.contains_span(primary_pic.base, 2)
        || !secondary_pic.contains_span(secondary_pic.base, 2)
        || !keyboard_data.contains_span(keyboard_data.base, 1)
        || !keyboard_status.contains_span(keyboard_status.base, 1)
        || !serial.contains_span(serial.base, 8)
    {
        return Err(PlatformError::IncompatibleComposition);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_aarch64_composition(
    descriptor: PlatformDescriptor<'_>,
    clock_hz: u32,
    controller: InterruptControllerKind,
    slot_bytes: u32,
    slot_count: u16,
    first_interrupt: u32,
    network_priority: u8,
    network_trigger: TriggerMode,
    network_polarity: Polarity,
) -> Result<(), PlatformError> {
    // The two GIC generations describe different apertures: version 2 has an
    // MMIO CPU interface, version 3 reaches it through `ICC_*` system registers
    // and instead needs one strided redistributor frame pair per CPU.
    let (distributor_role, second_role) = match controller {
        InterruptControllerKind::GicV2 { .. } => {
            (MmioRole::GicV2Distributor, MmioRole::GicV2CpuInterface)
        }
        InterruptControllerKind::GicV3 { .. } => {
            (MmioRole::GicV3Distributor, MmioRole::GicV3Redistributor)
        }
        InterruptControllerKind::X86Apic => {
            return Err(PlatformError::IncompatibleComposition);
        }
    };
    for role in [
        distributor_role,
        second_role,
        MmioRole::Pl011,
        MmioRole::VirtioMmio,
    ] {
        require_mmio(descriptor.mmio, role)?;
    }
    let serial_interrupt = require_interrupt(descriptor.interrupts, InterruptRole::Serial)?;
    let timer_interrupt = require_interrupt(descriptor.interrupts, InterruptRole::Timer)?;
    let distributor = require_mmio(descriptor.mmio, distributor_role)?;
    let cpu_interface = require_mmio(descriptor.mmio, second_role)?;
    let aperture = require_mmio(descriptor.mmio, MmioRole::VirtioMmio)?;
    // A version 2 target mask must name exactly one CPU; a version 3 stride
    // must hold both the RD and SGI frames of one redistributor.
    let controller_ok = match controller {
        InterruptControllerKind::GicV2 { cpu_target_mask } => cpu_target_mask.is_power_of_two(),
        InterruptControllerKind::GicV3 {
            redistributor_stride,
        } => {
            redistributor_stride >= GICV3_REDISTRIBUTOR_MINIMUM_STRIDE
                && redistributor_stride.is_power_of_two()
                && cpu_interface.byte_len >= redistributor_stride
        }
        InterruptControllerKind::X86Apic => false,
    };
    let described = u64::from(slot_bytes)
        .checked_mul(u64::from(slot_count))
        .ok_or(PlatformError::InvalidRange)?;
    let last_interrupt = first_interrupt
        .checked_add(u32::from(slot_count))
        .ok_or(PlatformError::InvalidInterrupt)?;
    if descriptor.mmio.len() != 4
        || !descriptor.io_ports.is_empty()
        || descriptor.interrupts.len() != 2
        || distributor.byte_len < 0x1000
        || cpu_interface.byte_len < 0x1000
        || !controller_ok
        || clock_hz < 16 * 115_200
        || slot_bytes < 0x118
        || !slot_bytes.is_multiple_of(4)
        || slot_count == 0
        || described != aperture.byte_len
        || first_interrupt < 32
        || last_interrupt > 1_020
        || network_priority == 0
        || network_trigger != TriggerMode::Edge
        || network_polarity != Polarity::ActiveHigh
        || timer_interrupt.line != 30
        || timer_interrupt.trigger != TriggerMode::Level
        || timer_interrupt.polarity != Polarity::ActiveHigh
        || serial_interrupt.line < 32
        || serial_interrupt.polarity != Polarity::ActiveHigh
        || descriptor
            .interrupts
            .iter()
            .any(|route| (first_interrupt..last_interrupt).contains(&route.line))
    {
        return Err(PlatformError::IncompatibleComposition);
    }
    Ok(())
}

/// Validate one `AArch64` composition whose virtio functions live on PCI.
///
/// The SBSA reference contract differs from the virtio-MMIO one in three ways
/// that matter here: the fourth aperture is a PCI Express configuration window
/// rather than a slot array, `INTx` reaches four consecutive shared peripheral
/// interrupts through the standard swizzle, and those four are level-triggered
/// and active high rather than edge-triggered.
#[allow(clippy::too_many_arguments)]
fn validate_aarch64_pci_composition(
    descriptor: PlatformDescriptor<'_>,
    clock_hz: u32,
    controller: InterruptControllerKind,
    configuration: PciConfigurationKind,
    first_bus: u8,
    last_bus: u8,
    first_interrupt: u32,
    network_priority: u8,
    network_trigger: TriggerMode,
    network_polarity: Polarity,
) -> Result<(), PlatformError> {
    for role in [
        MmioRole::GicV3Distributor,
        MmioRole::GicV3Redistributor,
        MmioRole::Pl011,
        MmioRole::PciEcam,
    ] {
        require_mmio(descriptor.mmio, role)?;
    }
    let serial_interrupt = require_interrupt(descriptor.interrupts, InterruptRole::Serial)?;
    let timer_interrupt = require_interrupt(descriptor.interrupts, InterruptRole::Timer)?;
    let distributor = require_mmio(descriptor.mmio, MmioRole::GicV3Distributor)?;
    let redistributor = require_mmio(descriptor.mmio, MmioRole::GicV3Redistributor)?;
    let ecam = require_mmio(descriptor.mmio, MmioRole::PciEcam)?;
    let InterruptControllerKind::GicV3 {
        redistributor_stride,
    } = controller
    else {
        return Err(PlatformError::IncompatibleComposition);
    };
    // ECAM addresses one 4 KiB function page per (bus, device, function), so
    // the window must cover every bus the descriptor asks to be scanned.
    let scanned_buses = u64::from(last_bus)
        .checked_sub(u64::from(first_bus))
        .ok_or(PlatformError::IncompatibleComposition)?
        .checked_add(1)
        .ok_or(PlatformError::InvalidRange)?;
    let required_window = scanned_buses
        .checked_mul(1 << 20)
        .ok_or(PlatformError::InvalidRange)?;
    // `INTA` through `INTD` occupy four consecutive INTIDs from the first.
    let last_interrupt = first_interrupt
        .checked_add(4)
        .ok_or(PlatformError::InvalidInterrupt)?;
    if descriptor.mmio.len() != 4
        || !descriptor.io_ports.is_empty()
        || descriptor.interrupts.len() != 2
        || configuration != PciConfigurationKind::Ecam
        || distributor.byte_len < 0x1000
        || redistributor.byte_len < 0x1000
        || redistributor_stride < GICV3_REDISTRIBUTOR_MINIMUM_STRIDE
        || !redistributor_stride.is_power_of_two()
        || redistributor.byte_len < redistributor_stride
        || clock_hz < 16 * 115_200
        || first_bus > last_bus
        || ecam.byte_len < required_window
        || first_interrupt < 32
        || last_interrupt > 1_020
        || network_priority == 0
        || network_trigger != TriggerMode::Level
        || network_polarity != Polarity::ActiveHigh
        || timer_interrupt.line != 30
        || timer_interrupt.trigger != TriggerMode::Level
        || timer_interrupt.polarity != Polarity::ActiveHigh
        || serial_interrupt.line < 32
        || serial_interrupt.polarity != Polarity::ActiveHigh
        || descriptor
            .interrupts
            .iter()
            .any(|route| (first_interrupt..last_interrupt).contains(&route.line))
    {
        return Err(PlatformError::IncompatibleComposition);
    }
    Ok(())
}

/// Borrowed proof that a platform descriptor passed complete validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedPlatform<'a> {
    descriptor: &'a PlatformDescriptor<'a>,
}

impl<'a> ValidatedPlatform<'a> {
    /// Stable platform identity.
    #[must_use]
    pub const fn id(self) -> PlatformId {
        self.descriptor.id
    }

    /// Canonical platform name.
    #[must_use]
    pub const fn name(self) -> &'a str {
        self.descriptor.name
    }

    /// Selected CPU architecture.
    #[must_use]
    pub const fn architecture(self) -> Architecture {
        self.descriptor.architecture
    }

    /// MMIO resource for one role.
    #[must_use]
    pub fn mmio(self, role: MmioRole) -> Option<MmioRegion> {
        self.descriptor
            .mmio
            .iter()
            .copied()
            .find(|resource| resource.role == role)
    }

    /// I/O-port resource for one role.
    #[must_use]
    pub fn io_ports(self, role: IoPortRole) -> Option<IoPortRegion> {
        self.descriptor
            .io_ports
            .iter()
            .copied()
            .find(|resource| resource.role == role)
    }

    /// Static interrupt route for one role.
    #[must_use]
    pub fn interrupt(self, role: InterruptRole) -> Option<InterruptRoute> {
        self.descriptor
            .interrupts
            .iter()
            .copied()
            .find(|route| route.role == role)
    }

    /// Console mechanism.
    #[must_use]
    pub const fn console(self) -> ConsoleKind {
        self.descriptor.console
    }

    /// Interrupt-controller topology.
    #[must_use]
    pub const fn interrupt_controller(self) -> InterruptControllerKind {
        self.descriptor.controller
    }

    /// Timer composition.
    #[must_use]
    pub const fn timer(self) -> TimerKind {
        self.descriptor.timer
    }

    /// Lifecycle mechanism.
    #[must_use]
    pub const fn power(self) -> PowerKind {
        self.descriptor.power
    }

    /// Native keyboard composition.
    #[must_use]
    pub const fn keyboard(self) -> KeyboardKind {
        self.descriptor.keyboard
    }

    /// Virtio transport and discovery bounds.
    #[must_use]
    pub const fn virtio(self) -> VirtioTransportKind {
        self.descriptor.virtio
    }
}

/// Fail-closed descriptor validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    /// Zero, mismatched known identity, or invalid canonical name.
    InvalidIdentity,
    /// Empty, unaligned, overflowing, or out-of-domain resource range.
    InvalidRange,
    /// Two resources overlap or repeat one semantic role.
    ResourceCollision,
    /// One interrupt is invalid or collides with another route.
    InvalidInterrupt,
    /// Required resources or architecture/device relationships are absent.
    IncompatibleComposition,
}

fn validate_name(name: &str) -> Result<(), PlatformError> {
    if name.is_empty()
        || name.len() > MAX_PLATFORM_NAME_BYTES
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
    {
        return Err(PlatformError::InvalidIdentity);
    }
    Ok(())
}

fn validate_mmio(
    architecture: Architecture,
    resources: &[MmioRegion],
) -> Result<(), PlatformError> {
    let physical_limit = match architecture {
        Architecture::X86_64 => 1_u64 << 52,
        Architecture::Aarch64 => 1_u64 << 48,
    };
    for (index, resource) in resources.iter().copied().enumerate() {
        let end = resource.end().ok_or(PlatformError::InvalidRange)?;
        if resource.byte_len == 0
            || !resource.base.is_multiple_of(4096)
            || !resource.byte_len.is_multiple_of(4096)
            || end <= resource.base
            || end > physical_limit
        {
            return Err(PlatformError::InvalidRange);
        }
        for other in &resources[..index] {
            let other_end = other.end().ok_or(PlatformError::InvalidRange)?;
            if other.role == resource.role || (resource.base < other_end && other.base < end) {
                return Err(PlatformError::ResourceCollision);
            }
        }
    }
    Ok(())
}

fn validate_io_ports(resources: &[IoPortRegion]) -> Result<(), PlatformError> {
    for (index, resource) in resources.iter().copied().enumerate() {
        let end = resource.end().ok_or(PlatformError::InvalidRange)?;
        if resource.count == 0 || end > 0x1_0000 {
            return Err(PlatformError::InvalidRange);
        }
        for other in &resources[..index] {
            let other_end = other.end().ok_or(PlatformError::InvalidRange)?;
            if other.role == resource.role
                || (u32::from(resource.base) < other_end && u32::from(other.base) < end)
            {
                return Err(PlatformError::ResourceCollision);
            }
        }
    }
    Ok(())
}

fn validate_interrupts(
    architecture: Architecture,
    routes: &[InterruptRoute],
) -> Result<(), PlatformError> {
    for (index, route) in routes.iter().copied().enumerate() {
        if route.vector < 32
            || (architecture == Architecture::Aarch64
                && (route.vector != 32 || route.priority == 0 || route.line >= 1_020))
            || (architecture == Architecture::X86_64
                && (route.priority != 0 || route.vector == X86_APPLICATION_CALL_VECTOR))
        {
            return Err(PlatformError::InvalidInterrupt);
        }
        for other in &routes[..index] {
            if other.role == route.role
                || other.line == route.line
                || (architecture == Architecture::X86_64 && other.vector == route.vector)
            {
                return Err(PlatformError::InvalidInterrupt);
            }
        }
    }
    Ok(())
}

fn require_mmio(resources: &[MmioRegion], role: MmioRole) -> Result<MmioRegion, PlatformError> {
    resources
        .iter()
        .copied()
        .find(|resource| resource.role == role)
        .ok_or(PlatformError::IncompatibleComposition)
}

fn require_io(resources: &[IoPortRegion], role: IoPortRole) -> Result<IoPortRegion, PlatformError> {
    resources
        .iter()
        .copied()
        .find(|resource| resource.role == role)
        .ok_or(PlatformError::IncompatibleComposition)
}

fn require_interrupt(
    routes: &[InterruptRoute],
    role: InterruptRole,
) -> Result<InterruptRoute, PlatformError> {
    routes
        .iter()
        .copied()
        .find(|route| route.role == role)
        .ok_or(PlatformError::IncompatibleComposition)
}

const Q35_MMIO: [MmioRegion; 2] = [
    MmioRegion::new(MmioRole::LocalApic, 0xfee0_0000, 0x1000),
    MmioRegion::new(MmioRole::IoApic, 0xfec0_0000, 0x1000),
];
const Q35_IO_PORTS: [IoPortRegion; 9] = [
    IoPortRegion::new(IoPortRole::PicPrimary, 0x20, 2),
    IoPortRegion::new(IoPortRole::PicSecondary, 0xa0, 2),
    IoPortRegion::new(IoPortRole::Pit, 0x40, 4),
    IoPortRegion::new(IoPortRole::KeyboardData, 0x60, 1),
    IoPortRegion::new(IoPortRole::SystemControl, 0x61, 1),
    IoPortRegion::new(IoPortRole::KeyboardStatus, 0x64, 1),
    IoPortRegion::new(IoPortRole::Serial, 0x3f8, 8),
    IoPortRegion::new(IoPortRole::PowerManagement, 0x604, 2),
    IoPortRegion::new(IoPortRole::PciConfiguration, 0xcf8, 8),
];
const Q35_INTERRUPTS: [InterruptRoute; 2] = [
    InterruptRoute::new(
        InterruptRole::Keyboard,
        1,
        0x31,
        0,
        TriggerMode::Edge,
        Polarity::ActiveHigh,
    ),
    InterruptRoute::new(
        InterruptRole::Serial,
        4,
        0x34,
        0,
        TriggerMode::Edge,
        Polarity::ActiveHigh,
    ),
];

/// Exact pinned x86-64 q35 UEFI platform descriptor.
pub const X86_64_Q35_UEFI: PlatformDescriptor<'static> = PlatformDescriptor::new(
    PlatformId::X86_64_Q35_UEFI,
    "x86_64-q35-uefi",
    Architecture::X86_64,
    &Q35_MMIO,
    &Q35_IO_PORTS,
    &Q35_INTERRUPTS,
    ConsoleKind::Uart16550,
    InterruptControllerKind::X86Apic,
    TimerKind::X86PitTsc {
        timer_vector: 0x30,
        spurious_vector: 0xff,
    },
    PowerKind::Q35 {
        pm_control_port: 0x604,
        reset_control_port: 0xcf9,
        sleep_type: 0,
    },
    KeyboardKind::I8042,
    VirtioTransportKind::Pci {
        configuration: PciConfigurationKind::Mechanism1,
        first_bus: 0,
        last_bus: 0,
        maximum_interrupt_line: 23,
        network_vector: 0x35,
        network_trigger: TriggerMode::Level,
        network_polarity: Polarity::ActiveLow,
    },
);

const X86_DISCOVERED_IO_PORTS: [IoPortRegion; 7] = [
    IoPortRegion::new(IoPortRole::PicPrimary, 0x20, 2),
    IoPortRegion::new(IoPortRole::PicSecondary, 0xa0, 2),
    IoPortRegion::new(IoPortRole::KeyboardData, 0x60, 1),
    IoPortRegion::new(IoPortRole::KeyboardStatus, 0x64, 1),
    IoPortRegion::new(IoPortRole::Serial, 0x3f8, 8),
    IoPortRegion::new(IoPortRole::AcpiPmTimer, 0x608, 4),
    IoPortRegion::new(IoPortRole::ResetControl, 0xcf9, 1),
];

/// Borrowed token for the immutable built-in q35 descriptor.
///
/// Consumers must first call [`PlatformDescriptor::validate`] in the current
/// boot and may then retain this zero-allocation token.
pub const VALIDATED_X86_64_Q35_UEFI: ValidatedPlatform<'static> = ValidatedPlatform {
    descriptor: &X86_64_Q35_UEFI,
};

/// Discoverable x86-64 UEFI/ACPI virtio-PCI cloud contract.
///
/// Firmware discovery must validate the runtime tables against this contract
/// before a consumer retains its corresponding validated token.
pub const X86_64_UEFI_VIRTIO_PCI: PlatformDescriptor<'static> = PlatformDescriptor::new(
    PlatformId::X86_64_UEFI_VIRTIO_PCI,
    "x86_64-uefi-virtio-pci",
    Architecture::X86_64,
    &Q35_MMIO,
    &X86_DISCOVERED_IO_PORTS,
    &Q35_INTERRUPTS,
    ConsoleKind::Uart16550,
    InterruptControllerKind::X86Apic,
    TimerKind::X86AcpiPmTsc {
        timer_vector: 0x30,
        spurious_vector: 0xff,
        pm_timer_port: 0x608,
        counter_bits: 24,
    },
    PowerKind::X86Reset {
        reset_control_port: 0xcf9,
        reset_value: 0x0f,
    },
    KeyboardKind::I8042,
    VirtioTransportKind::Pci {
        configuration: PciConfigurationKind::Ecam,
        first_bus: 0,
        last_bus: 0,
        maximum_interrupt_line: 23,
        network_vector: 0x35,
        network_trigger: TriggerMode::Level,
        network_polarity: Polarity::ActiveLow,
    },
);

/// Borrowed token for the discoverable x86-64 UEFI cloud contract.
///
/// Consumers must first validate both the immutable descriptor and the current
/// boot's firmware discovery evidence.
pub const VALIDATED_X86_64_UEFI_VIRTIO_PCI: ValidatedPlatform<'static> = ValidatedPlatform {
    descriptor: &X86_64_UEFI_VIRTIO_PCI,
};

/// Smallest `GICv3` redistributor stride: one 64 KiB RD frame plus one SGI
/// frame. Implementations with virtual LPIs use a larger stride, never smaller.
pub const GICV3_REDISTRIBUTOR_MINIMUM_STRIDE: u64 = 0x2_0000;

const VIRT_GICV3_MMIO: [MmioRegion; 4] = [
    MmioRegion::new(MmioRole::GicV3Distributor, 0x0800_0000, 0x0001_0000),
    MmioRegion::new(MmioRole::GicV3Redistributor, 0x080a_0000, 0x00f6_0000),
    MmioRegion::new(MmioRole::Pl011, 0x0900_0000, 0x1000),
    MmioRegion::new(MmioRole::VirtioMmio, 0x0a00_0000, 0x4000),
];
/// Arm SBSA reference platform apertures.
///
/// Fixed by the Server Base System Architecture reference design rather than
/// by any one emulator: a `GICv3` distributor and redistributor region, one
/// SBSA generic UART, and the PCI Express configuration aperture that carries
/// every virtio function.
const SBSA_REF_MMIO: [MmioRegion; 4] = [
    MmioRegion::new(MmioRole::GicV3Distributor, 0x4006_0000, 0x0001_0000),
    MmioRegion::new(MmioRole::GicV3Redistributor, 0x4008_0000, 0x0400_0000),
    MmioRegion::new(MmioRole::Pl011, 0x6000_0000, 0x1000),
    MmioRegion::new(MmioRole::PciEcam, 0xf000_0000, 0x1000_0000),
];

/// Arm SBSA reference interrupt routes.
///
/// The non-secure EL1 physical timer keeps its architectural PPI; the SBSA
/// generic UART is the first shared peripheral interrupt.
const SBSA_REF_INTERRUPTS: [InterruptRoute; 2] = [
    InterruptRoute::new(
        InterruptRole::Timer,
        30,
        32,
        0x40,
        TriggerMode::Level,
        Polarity::ActiveHigh,
    ),
    InterruptRoute::new(
        InterruptRole::Serial,
        33,
        32,
        0xa0,
        TriggerMode::Level,
        Polarity::ActiveHigh,
    ),
];

/// QEMU `virt` `GICv2` apertures, retained to exercise the version 2
/// validation path that device-tree discovery can still reach.
#[cfg(test)]
const VIRT_MMIO: [MmioRegion; 4] = [
    MmioRegion::new(MmioRole::GicV2Distributor, 0x0800_0000, 0x0001_0000),
    MmioRegion::new(MmioRole::GicV2CpuInterface, 0x0801_0000, 0x0001_0000),
    MmioRegion::new(MmioRole::Pl011, 0x0900_0000, 0x1000),
    MmioRegion::new(MmioRole::VirtioMmio, 0x0a00_0000, 0x4000),
];
const VIRT_INTERRUPTS: [InterruptRoute; 2] = [
    InterruptRoute::new(
        InterruptRole::Timer,
        30,
        32,
        0x40,
        TriggerMode::Level,
        Polarity::ActiveHigh,
    ),
    InterruptRoute::new(
        InterruptRole::Serial,
        33,
        32,
        0xa0,
        TriggerMode::Level,
        Polarity::ActiveHigh,
    ),
];

/// Exact pinned Arm SBSA reference UEFI platform descriptor.
///
/// The Server Base System Architecture is the closest thing `AArch64` has to
/// the fixed contract x86-64 inherited from the PC: a `GICv3` or later, an
/// architected generic timer, a PL011-compatible generic UART, PSCI, and PCI
/// Express. Pinning that contract rather than one emulator's `virt` board is
/// what lets the same image target a `SystemReady` machine.
///
/// Virtio remains the device model; on this platform it arrives as PCI
/// functions rather than MMIO slots, because SBSA describes no MMIO
/// transport aperture at all.
pub const AARCH64_SBSA_REF: PlatformDescriptor<'static> = PlatformDescriptor::new(
    PlatformId::AARCH64_SBSA_REF,
    "aarch64-sbsa-ref",
    Architecture::Aarch64,
    &SBSA_REF_MMIO,
    &[],
    &SBSA_REF_INTERRUPTS,
    ConsoleKind::Pl011 {
        clock_hz: 24_000_000,
    },
    InterruptControllerKind::GicV3 {
        redistributor_stride: GICV3_REDISTRIBUTOR_MINIMUM_STRIDE,
    },
    TimerKind::Aarch64Generic,
    PowerKind::PsciSmc,
    KeyboardKind::None,
    VirtioTransportKind::PciGic {
        configuration: PciConfigurationKind::Ecam,
        first_bus: 0,
        last_bus: 0,
        first_interrupt: 35,
        network_priority: 0x20,
        network_trigger: TriggerMode::Level,
        network_polarity: Polarity::ActiveHigh,
    },
);

/// Borrowed token for the immutable built-in SBSA reference descriptor.
///
/// Consumers must first call [`PlatformDescriptor::validate`] in the current
/// boot and may then retain this zero-allocation token.
pub const VALIDATED_AARCH64_SBSA_REF: ValidatedPlatform<'static> = ValidatedPlatform {
    descriptor: &AARCH64_SBSA_REF,
};

/// Discoverable `AArch64` UEFI/device-tree virtio-MMIO cloud contract.
///
/// Firmware discovery must validate the runtime tree against this contract
/// before a consumer retains its corresponding validated token.
pub const AARCH64_UEFI_VIRTIO_MMIO: PlatformDescriptor<'static> = PlatformDescriptor::new(
    PlatformId::AARCH64_UEFI_VIRTIO_MMIO,
    "aarch64-uefi-virtio-mmio",
    Architecture::Aarch64,
    &VIRT_GICV3_MMIO,
    &[],
    &VIRT_INTERRUPTS,
    ConsoleKind::Pl011 {
        clock_hz: 24_000_000,
    },
    InterruptControllerKind::GicV3 {
        redistributor_stride: GICV3_REDISTRIBUTOR_MINIMUM_STRIDE,
    },
    TimerKind::Aarch64Generic,
    PowerKind::PsciHvc,
    KeyboardKind::None,
    VirtioTransportKind::Mmio {
        slot_bytes: 0x200,
        slot_count: 32,
        first_interrupt: 48,
        network_priority: 0x20,
        network_trigger: TriggerMode::Edge,
        network_polarity: Polarity::ActiveHigh,
    },
);

/// Borrowed token for the discoverable `AArch64` UEFI cloud contract.
///
/// Consumers must first validate both the immutable descriptor and the current
/// boot's firmware discovery evidence.
pub const VALIDATED_AARCH64_UEFI_VIRTIO_MMIO: ValidatedPlatform<'static> = ValidatedPlatform {
    descriptor: &AARCH64_UEFI_VIRTIO_MMIO,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn q35_with<'a>(
        id: PlatformId,
        name: &'a str,
        mmio: &'a [MmioRegion],
        ports: &'a [IoPortRegion],
        interrupts: &'a [InterruptRoute],
    ) -> PlatformDescriptor<'a> {
        PlatformDescriptor::new(
            id,
            name,
            Architecture::X86_64,
            mmio,
            ports,
            interrupts,
            ConsoleKind::Uart16550,
            InterruptControllerKind::X86Apic,
            TimerKind::X86PitTsc {
                timer_vector: 0x30,
                spurious_vector: 0xff,
            },
            PowerKind::Q35 {
                pm_control_port: 0x604,
                reset_control_port: 0xcf9,
                sleep_type: 0,
            },
            KeyboardKind::I8042,
            VirtioTransportKind::Pci {
                configuration: PciConfigurationKind::Mechanism1,
                first_bus: 0,
                last_bus: 0,
                maximum_interrupt_line: 23,
                network_vector: 0x35,
                network_trigger: TriggerMode::Level,
                network_polarity: Polarity::ActiveLow,
            },
        )
    }

    #[test]
    fn exact_qemu_descriptors_validate() {
        let q35 = X86_64_Q35_UEFI
            .validate()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(q35, VALIDATED_X86_64_Q35_UEFI);
        assert_eq!(q35.name(), "x86_64-q35-uefi");
        assert_eq!(q35.architecture(), Architecture::X86_64);
        assert_eq!(
            q35.io_ports(IoPortRole::Serial).map(IoPortRegion::base),
            Some(0x3f8)
        );
        let sbsa = AARCH64_SBSA_REF
            .validate()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(sbsa, VALIDATED_AARCH64_SBSA_REF);
        assert_eq!(sbsa.name(), "aarch64-sbsa-ref");
        assert_eq!(sbsa.architecture(), Architecture::Aarch64);
        // The reference contract describes no virtio-MMIO aperture at all;
        // every virtio function arrives through PCI Express instead.
        assert_eq!(sbsa.mmio(MmioRole::VirtioMmio), None);
        assert_eq!(
            sbsa.mmio(MmioRole::PciEcam).map(MmioRegion::base),
            Some(0xf000_0000)
        );
        assert_eq!(
            sbsa.mmio(MmioRole::Pl011).map(MmioRegion::base),
            Some(0x6000_0000)
        );
        assert_eq!(
            sbsa.mmio(MmioRole::GicV3Distributor).map(MmioRegion::base),
            Some(0x4006_0000)
        );
        // The redistributor region replaces the version 2 CPU interface, and
        // must hold one strided frame pair per CPU the machine can start.
        let redistributors = sbsa
            .mmio(MmioRole::GicV3Redistributor)
            .unwrap_or_else(|| unreachable!());
        assert_eq!(redistributors.base(), 0x4008_0000);
        assert_eq!(redistributors.byte_len(), 0x0400_0000);
        assert!(redistributors.byte_len() >= GICV3_REDISTRIBUTOR_MINIMUM_STRIDE);
        assert_eq!(sbsa.mmio(MmioRole::GicV2CpuInterface), None);
        assert_eq!(
            sbsa.interrupt_controller(),
            InterruptControllerKind::GicV3 {
                redistributor_stride: GICV3_REDISTRIBUTOR_MINIMUM_STRIDE
            }
        );
        // `INTA` on device zero takes the first of the four swizzled SPIs.
        assert!(matches!(
            sbsa.virtio(),
            VirtioTransportKind::PciGic {
                configuration: PciConfigurationKind::Ecam,
                first_interrupt: 35,
                network_trigger: TriggerMode::Level,
                network_polarity: Polarity::ActiveHigh,
                ..
            }
        ));
        let discovered_x86 = X86_64_UEFI_VIRTIO_PCI
            .validate()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(discovered_x86, VALIDATED_X86_64_UEFI_VIRTIO_PCI);
        assert_eq!(
            discovered_x86.io_ports(IoPortRole::ResetControl),
            Some(IoPortRegion::new(IoPortRole::ResetControl, 0xcf9, 1))
        );
        assert_eq!(discovered_x86.io_ports(IoPortRole::PowerManagement), None);
        assert_eq!(discovered_x86.io_ports(IoPortRole::PciConfiguration), None);
        assert!(matches!(
            discovered_x86.virtio(),
            VirtioTransportKind::Pci {
                configuration: PciConfigurationKind::Ecam,
                ..
            }
        ));
        assert_eq!(
            discovered_x86.power(),
            PowerKind::X86Reset {
                reset_control_port: 0xcf9,
                reset_value: 0x0f,
            }
        );
        let discovered_arm = AARCH64_UEFI_VIRTIO_MMIO
            .validate()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(discovered_arm, VALIDATED_AARCH64_UEFI_VIRTIO_MMIO);
        assert!(matches!(
            discovered_arm.virtio(),
            VirtioTransportKind::Mmio {
                network_trigger: TriggerMode::Edge,
                network_polarity: Polarity::ActiveHigh,
                ..
            }
        ));
    }

    #[test]
    fn architecture_does_not_select_platform_identity() {
        let first_id = PlatformId::new(100).unwrap_or_else(|_| unreachable!());
        let second_id = PlatformId::new(101).unwrap_or_else(|_| unreachable!());
        let alternate_routes = [
            InterruptRoute::new(
                InterruptRole::Keyboard,
                1,
                0x31,
                0,
                TriggerMode::Level,
                Polarity::ActiveLow,
            ),
            Q35_INTERRUPTS[1],
        ];
        let first = q35_with(
            first_id,
            "synthetic-x86-a",
            &Q35_MMIO,
            &Q35_IO_PORTS,
            &Q35_INTERRUPTS,
        );
        let second = q35_with(
            second_id,
            "synthetic-x86-b",
            &Q35_MMIO,
            &Q35_IO_PORTS,
            &alternate_routes,
        );
        assert!(first.validate().is_ok());
        assert!(second.validate().is_ok());
        assert_eq!(first.architecture, second.architecture);
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn identity_and_composition_mismatch_fail() {
        let wrong_identity = q35_with(
            PlatformId::X86_64_Q35_UEFI,
            "not-q35",
            &Q35_MMIO,
            &Q35_IO_PORTS,
            &Q35_INTERRUPTS,
        );
        assert_eq!(
            wrong_identity.validate(),
            Err(PlatformError::InvalidIdentity)
        );
        let canonical_name_with_wrong_id = q35_with(
            PlatformId::new(121).unwrap_or_else(|_| unreachable!()),
            "x86_64-q35-uefi",
            &Q35_MMIO,
            &Q35_IO_PORTS,
            &Q35_INTERRUPTS,
        );
        assert_eq!(
            canonical_name_with_wrong_id.validate(),
            Err(PlatformError::InvalidIdentity)
        );
        let incompatible = PlatformDescriptor {
            architecture: Architecture::Aarch64,
            ..X86_64_Q35_UEFI
        };
        assert_eq!(incompatible.validate(), Err(PlatformError::InvalidIdentity));
    }

    #[test]
    fn malformed_and_overlapping_resources_fail_closed() {
        let unaligned = [MmioRegion::new(MmioRole::LocalApic, 1, 0x1000)];
        let profile = q35_with(
            PlatformId::new(102).unwrap_or_else(|_| unreachable!()),
            "unaligned-x86",
            &unaligned,
            &Q35_IO_PORTS,
            &Q35_INTERRUPTS,
        );
        assert_eq!(profile.validate(), Err(PlatformError::InvalidRange));

        let overlapping = [
            MmioRegion::new(MmioRole::LocalApic, 0x1000, 0x2000),
            MmioRegion::new(MmioRole::IoApic, 0x2000, 0x1000),
        ];
        let profile = q35_with(
            PlatformId::new(103).unwrap_or_else(|_| unreachable!()),
            "overlap-x86",
            &overlapping,
            &Q35_IO_PORTS,
            &Q35_INTERRUPTS,
        );
        assert_eq!(profile.validate(), Err(PlatformError::ResourceCollision));

        let overlapping_ports = [
            IoPortRegion::new(IoPortRole::PicPrimary, 0x20, 2),
            IoPortRegion::new(IoPortRole::PicSecondary, 0x21, 2),
        ];
        let profile = q35_with(
            PlatformId::new(104).unwrap_or_else(|_| unreachable!()),
            "port-overlap-x86",
            &Q35_MMIO,
            &overlapping_ports,
            &Q35_INTERRUPTS,
        );
        assert_eq!(profile.validate(), Err(PlatformError::ResourceCollision));

        let overflowing = [
            MmioRegion::new(MmioRole::LocalApic, 0xffff_ffff_ffff_f000, 0x2000),
            Q35_MMIO[1],
        ];
        let profile = q35_with(
            PlatformId::new(107).unwrap_or_else(|_| unreachable!()),
            "overflowing-x86",
            &overflowing,
            &Q35_IO_PORTS,
            &Q35_INTERRUPTS,
        );
        assert_eq!(profile.validate(), Err(PlatformError::InvalidRange));

        let outside_x86_physical_domain = [
            MmioRegion::new(MmioRole::LocalApic, (1_u64 << 52) - 0x1000, 0x2000),
            Q35_MMIO[1],
        ];
        let profile = q35_with(
            PlatformId::new(122).unwrap_or_else(|_| unreachable!()),
            "wide-address-x86",
            &outside_x86_physical_domain,
            &Q35_IO_PORTS,
            &Q35_INTERRUPTS,
        );
        assert_eq!(profile.validate(), Err(PlatformError::InvalidRange));

        let mut outside_aarch64_physical_domain = VIRT_MMIO;
        outside_aarch64_physical_domain[2] =
            MmioRegion::new(MmioRole::Pl011, (1_u64 << 48) - 0x1000, 0x2000);
        let profile = PlatformDescriptor {
            id: PlatformId::new(123).unwrap_or_else(|_| unreachable!()),
            name: "wide-address-arm",
            mmio: &outside_aarch64_physical_domain,
            ..AARCH64_SBSA_REF
        };
        assert_eq!(profile.validate(), Err(PlatformError::InvalidRange));

        let mut overflowing_ports = Q35_IO_PORTS;
        overflowing_ports[8] = IoPortRegion::new(IoPortRole::PciConfiguration, 0xffff, 2);
        let profile = q35_with(
            PlatformId::new(108).unwrap_or_else(|_| unreachable!()),
            "overflowing-ports-x86",
            &Q35_MMIO,
            &overflowing_ports,
            &Q35_INTERRUPTS,
        );
        assert_eq!(profile.validate(), Err(PlatformError::InvalidRange));
    }

    #[test]
    fn interrupt_collisions_and_invalid_priority_fail_closed() {
        let duplicate = [
            Q35_INTERRUPTS[0],
            InterruptRoute::new(
                InterruptRole::Serial,
                1,
                0x34,
                0,
                TriggerMode::Edge,
                Polarity::ActiveHigh,
            ),
        ];
        let profile = q35_with(
            PlatformId::new(105).unwrap_or_else(|_| unreachable!()),
            "irq-collision-x86",
            &Q35_MMIO,
            &Q35_IO_PORTS,
            &duplicate,
        );
        assert_eq!(profile.validate(), Err(PlatformError::InvalidInterrupt));

        let reserved_application_vector = [
            InterruptRoute::new(
                InterruptRole::Keyboard,
                1,
                X86_APPLICATION_CALL_VECTOR,
                0,
                TriggerMode::Edge,
                Polarity::ActiveHigh,
            ),
            Q35_INTERRUPTS[1],
        ];
        let profile = q35_with(
            PlatformId::new(119).unwrap_or_else(|_| unreachable!()),
            "reserved-vector-x86",
            &Q35_MMIO,
            &Q35_IO_PORTS,
            &reserved_application_vector,
        );
        assert_eq!(profile.validate(), Err(PlatformError::InvalidInterrupt));

        let reserved_timer = PlatformDescriptor {
            id: PlatformId::new(120).unwrap_or_else(|_| unreachable!()),
            name: "reserved-timer-x86",
            timer: TimerKind::X86PitTsc {
                timer_vector: X86_APPLICATION_CALL_VECTOR,
                spurious_vector: 0xff,
            },
            ..X86_64_Q35_UEFI
        };
        assert_eq!(
            reserved_timer.validate(),
            Err(PlatformError::IncompatibleComposition)
        );

        let invalid_arm = [
            InterruptRoute::new(
                InterruptRole::Timer,
                30,
                32,
                0,
                TriggerMode::Level,
                Polarity::ActiveHigh,
            ),
            VIRT_INTERRUPTS[1],
        ];
        let profile = PlatformDescriptor {
            id: PlatformId::new(106).unwrap_or_else(|_| unreachable!()),
            name: "invalid-arm-priority",
            interrupts: &invalid_arm,
            ..AARCH64_SBSA_REF
        };
        assert_eq!(profile.validate(), Err(PlatformError::InvalidInterrupt));
    }

    #[test]
    fn missing_resources_and_transport_mismatches_fail_before_use() {
        let missing_ioapic = q35_with(
            PlatformId::new(109).unwrap_or_else(|_| unreachable!()),
            "missing-ioapic-x86",
            &Q35_MMIO[..1],
            &Q35_IO_PORTS,
            &Q35_INTERRUPTS,
        );
        assert_eq!(
            missing_ioapic.validate(),
            Err(PlatformError::IncompatibleComposition)
        );

        let reversed_bus = PlatformDescriptor {
            id: PlatformId::new(110).unwrap_or_else(|_| unreachable!()),
            name: "reversed-bus-x86",
            virtio: VirtioTransportKind::Pci {
                configuration: PciConfigurationKind::Mechanism1,
                first_bus: 1,
                last_bus: 0,
                maximum_interrupt_line: 23,
                network_vector: 0x35,
                network_trigger: TriggerMode::Level,
                network_polarity: Polarity::ActiveLow,
            },
            ..X86_64_Q35_UEFI
        };
        assert_eq!(
            reversed_bus.validate(),
            Err(PlatformError::IncompatibleComposition)
        );

        let wrong_aperture = PlatformDescriptor {
            id: PlatformId::new(111).unwrap_or_else(|_| unreachable!()),
            name: "wrong-aperture-arm",
            virtio: VirtioTransportKind::Mmio {
                slot_bytes: 0x200,
                slot_count: 31,
                first_interrupt: 48,
                network_priority: 0x20,
                network_trigger: TriggerMode::Edge,
                network_polarity: Polarity::ActiveHigh,
            },
            ..AARCH64_SBSA_REF
        };
        assert_eq!(
            wrong_aperture.validate(),
            Err(PlatformError::IncompatibleComposition)
        );
    }

    #[test]
    fn every_consumed_resource_extent_and_route_shape_is_validated() {
        let mut short_serial_ports = Q35_IO_PORTS;
        short_serial_ports[6] = IoPortRegion::new(IoPortRole::Serial, 0x3f8, 7);
        let short_serial = q35_with(
            PlatformId::new(112).unwrap_or_else(|_| unreachable!()),
            "short-serial-x86",
            &Q35_MMIO,
            &short_serial_ports,
            &Q35_INTERRUPTS,
        );
        assert_eq!(
            short_serial.validate(),
            Err(PlatformError::IncompatibleComposition)
        );

        let invalid_sleep = PlatformDescriptor {
            id: PlatformId::new(113).unwrap_or_else(|_| unreachable!()),
            name: "invalid-sleep-x86",
            power: PowerKind::Q35 {
                pm_control_port: 0x604,
                reset_control_port: 0xcf9,
                sleep_type: 8,
            },
            ..X86_64_Q35_UEFI
        };
        assert_eq!(
            invalid_sleep.validate(),
            Err(PlatformError::IncompatibleComposition)
        );

        let wrong_timer_routes = [
            InterruptRoute::new(
                InterruptRole::Timer,
                29,
                32,
                0x40,
                TriggerMode::Level,
                Polarity::ActiveHigh,
            ),
            VIRT_INTERRUPTS[1],
        ];
        let wrong_timer = PlatformDescriptor {
            id: PlatformId::new(115).unwrap_or_else(|_| unreachable!()),
            name: "wrong-timer-arm",
            interrupts: &wrong_timer_routes,
            ..AARCH64_SBSA_REF
        };
        assert_eq!(
            wrong_timer.validate(),
            Err(PlatformError::IncompatibleComposition)
        );

        let stray_port = PlatformDescriptor {
            id: PlatformId::new(117).unwrap_or_else(|_| unreachable!()),
            name: "stray-port-arm",
            io_ports: &Q35_IO_PORTS[..1],
            ..AARCH64_SBSA_REF
        };
        assert_eq!(
            stray_port.validate(),
            Err(PlatformError::IncompatibleComposition)
        );

        let undersized_slot = PlatformDescriptor {
            id: PlatformId::new(118).unwrap_or_else(|_| unreachable!()),
            name: "short-slot-arm",
            virtio: VirtioTransportKind::Mmio {
                slot_bytes: 0x100,
                slot_count: 64,
                first_interrupt: 48,
                network_priority: 0x20,
                network_trigger: TriggerMode::Edge,
                network_polarity: Polarity::ActiveHigh,
            },
            ..AARCH64_SBSA_REF
        };
        assert_eq!(
            undersized_slot.validate(),
            Err(PlatformError::IncompatibleComposition)
        );
    }

    #[test]
    fn gicv2_topology_is_complete_and_single_target() {
        let missing_cpu_interface = [VIRT_MMIO[0], VIRT_MMIO[2], VIRT_MMIO[3]];
        let missing_cpu_interface = PlatformDescriptor {
            id: PlatformId::new(114).unwrap_or_else(|_| unreachable!()),
            name: "missing-gic-cpu-arm",
            mmio: &missing_cpu_interface,
            ..AARCH64_SBSA_REF
        };
        assert_eq!(
            missing_cpu_interface.validate(),
            Err(PlatformError::IncompatibleComposition)
        );

        for (id, name, cpu_target_mask) in [
            (116, "zero-gic-target-arm", 0),
            (124, "multi-gic-target-arm", 0b11),
        ] {
            let invalid_target = PlatformDescriptor {
                id: PlatformId::new(id).unwrap_or_else(|_| unreachable!()),
                name,
                controller: InterruptControllerKind::GicV2 { cpu_target_mask },
                ..AARCH64_SBSA_REF
            };
            assert_eq!(
                invalid_target.validate(),
                Err(PlatformError::IncompatibleComposition)
            );
        }
    }
}

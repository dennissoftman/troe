//! Bounded, allocation-free Flattened Devicetree discovery.
//!
//! [`discover`] accepts a complete DTB byte slice and produces only facts that
//! have been decoded and validated.  In particular, it never supplies default
//! addresses, interrupt parents, interrupt routes, or PCI bus ranges.  A caller
//! should validate the returned inventory against its architecture and policy,
//! then convert it into the platform capabilities it intends to publish.
//!
//! The parser supports the cloud-facing `AArch64` bindings TROE currently needs:
//! memory nodes, `/chosen/stdout-path` and its UART, PSCI, GICv2/GICv3, the Arm
//! architected timer, generic ECAM PCI hosts and `virtio,mmio`. Unsupported
//! nodes are structurally checked but are not published.

use core::str;

/// Largest DTB accepted by the discovery boundary.
pub const MAX_BLOB_BYTES: usize = 2 * 1024 * 1024;
/// Maximum structure tokens examined.
pub const MAX_TOKENS: usize = 4_096;
/// Maximum node nesting, including the root node.
pub const MAX_DEPTH: usize = 24;
/// Maximum number of nodes accepted.
pub const MAX_NODES: usize = 256;
/// Maximum number of properties accepted.
pub const MAX_PROPERTIES: usize = 1_024;
/// Maximum bytes in one property value.
pub const MAX_PROPERTY_BYTES: usize = 16 * 1024;
/// Maximum firmware memory reservations.
pub const MAX_RESERVATIONS: usize = 32;
/// Maximum published RAM extents.
pub const MAX_MEMORY_REGIONS: usize = 32;
/// Maximum generic ECAM hosts.
pub const MAX_PCI_HOSTS: usize = 4;
/// Maximum outbound windows on one PCI host.
pub const MAX_PCI_WINDOWS: usize = 16;
/// Maximum published virtio-MMIO devices.
pub const MAX_VIRTIO_MMIO_DEVICES: usize = 32;
/// Maximum register apertures retained for a GIC controller.
pub const MAX_GIC_REGIONS: usize = 8;
/// Maximum interrupts retained for an architected timer.
pub const MAX_TIMER_INTERRUPTS: usize = 4;
/// Maximum aliases retained while resolving `/chosen/stdout-path`.
pub const MAX_ALIASES: usize = 32;
/// Maximum supported UART candidates retained until stdout resolution.
pub const MAX_UARTS: usize = 16;
/// Maximum fixed-clock providers retained for supported UARTs.
pub const MAX_FIXED_CLOCKS: usize = 16;
/// Maximum clock references accepted on one supported UART.
pub const MAX_UART_CLOCKS: usize = 8;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_VERSION: u32 = 17;
const HEADER_BYTES: usize = 40;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const PAGE_BYTES: u64 = 4_096;
const ECAM_BUS_BYTES: u64 = 1 << 20;
const AARCH64_PHYSICAL_LIMIT: u64 = 1 << 48;

/// A discovery failure.  Every failure leaves the caller without an inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Input is shorter than an FDT header or a referenced scalar.
    Truncated,
    /// Header magic is not the FDT magic value.
    BadMagic,
    /// The blob exceeds [`MAX_BLOB_BYTES`].
    BlobTooLarge,
    /// This parser accepts only version 17 blobs.
    UnsupportedVersion,
    /// A header offset, size, or arithmetic operation is invalid.
    InvalidHeader,
    /// Header, reservation, structure, or strings regions overlap.
    OverlappingBlocks,
    /// The reservation table lacks its terminating zero pair.
    UnterminatedReservations,
    /// A range is empty, overflowing, or outside TROE's 48-bit Arm domain.
    InvalidRange,
    /// Two reservations or published physical resources overlap.
    OverlappingResources,
    /// A configured parser limit was exceeded.
    LimitExceeded,
    /// A structure token is unknown or occurs in an invalid state.
    InvalidToken,
    /// The root/node nesting is malformed.
    InvalidNesting,
    /// A node name is missing, invalid, or duplicated under one parent.
    InvalidNodeName,
    /// A property name offset/string is invalid.
    InvalidPropertyName,
    /// A property appears twice on one node.
    DuplicateProperty,
    /// A property occurs after the first child node.
    PropertyAfterChild,
    /// A property payload or its required padding is malformed.
    InvalidProperty,
    /// An encoded string or string-list is malformed.
    InvalidString,
    /// `#address-cells`, `#size-cells`, or `#interrupt-cells` is unsupported.
    UnsupportedCells,
    /// A resource cannot be decoded because its cell declaration is absent.
    MissingCells,
    /// A supported resource is below a bus whose address translation is not implemented.
    UnsupportedTranslation,
    /// A required binding property is absent.
    MissingProperty,
    /// A phandle is zero, contradictory, or reused by another node.
    InvalidPhandle,
    /// More than one supported meaning/controller is declared ambiguously.
    AmbiguousDevice,
    /// An interrupt does not refer to the discovered GIC.
    UnsupportedInterruptParent,
    /// A GIC interrupt tuple or electrical flags are invalid.
    InvalidInterrupt,
    /// A PCI binding value is outside the supported generic-ECAM contract.
    InvalidPci,
    /// A supported MMIO resource violates its binding alignment/size contract.
    InvalidAlignment,
}

/// One nonempty half-open physical address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    base: u64,
    byte_len: u64,
}

impl PhysicalRange {
    fn checked(base: u64, byte_len: u64) -> Result<Self, Error> {
        if byte_len == 0
            || base
                .checked_add(byte_len)
                .is_none_or(|end| end > AARCH64_PHYSICAL_LIMIT)
        {
            return Err(Error::InvalidRange);
        }
        Ok(Self { base, byte_len })
    }

    /// First physical byte.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Number of bytes in the range.
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }

    /// First byte after this range.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.base + self.byte_len
    }

    fn overlaps(self, other: Self) -> bool {
        self.base < other.end() && other.base < self.end()
    }
}

/// A validated `/chosen/stdout-path` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdoutPath<'a> {
    raw: &'a str,
    device: &'a str,
    options: Option<&'a str>,
    resolved_device: Option<&'a str>,
}

impl<'a> StdoutPath<'a> {
    /// Complete firmware value, excluding its terminating NUL.
    #[must_use]
    pub const fn raw(self) -> &'a str {
        self.raw
    }

    /// Absolute path or unresolved alias before the optional colon.
    #[must_use]
    pub const fn device(self) -> &'a str {
        self.device
    }

    /// Firmware-defined suffix after the first colon, if present.
    #[must_use]
    pub const fn options(self) -> Option<&'a str> {
        self.options
    }

    /// Whether `device` is already an absolute devicetree path.
    #[must_use]
    pub fn is_absolute(self) -> bool {
        self.device.starts_with('/')
    }

    /// Resolved absolute path. This is `None` when an alias was not supplied.
    #[must_use]
    pub const fn resolved_device(self) -> Option<&'a str> {
        self.resolved_device
    }
}

/// Firmware conduit used for PSCI calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PsciConduit {
    /// Secure-monitor calls.
    Smc,
    /// Hypervisor calls.
    Hvc,
}

/// Supported PSCI binding generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PsciVersion {
    /// Standard function IDs introduced by PSCI 0.2.
    V0_2,
    /// PSCI 1.0 or later compatible binding.
    V1_0,
}

/// A validated standard-function-ID PSCI node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Psci {
    version: PsciVersion,
    conduit: PsciConduit,
}

impl Psci {
    /// Binding generation.
    #[must_use]
    pub const fn version(self) -> PsciVersion {
        self.version
    }

    /// Exact firmware call conduit.
    #[must_use]
    pub const fn conduit(self) -> PsciConduit {
        self.conduit
    }
}

/// Supported recovery UART binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UartKind {
    /// Arm `PrimeCell` PL011.
    Pl011,
    /// 16550-compatible byte/word MMIO UART.
    Ns16550,
}

/// UART selected by the resolved `/chosen/stdout-path`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdoutUart {
    kind: UartKind,
    registers: PhysicalRange,
    clock_hz: Option<u32>,
    current_baud: Option<u32>,
    register_shift: Option<u32>,
    register_io_width: Option<u32>,
    interrupt: GicInterrupt,
}

impl StdoutUart {
    /// UART programming model.
    #[must_use]
    pub const fn kind(self) -> UartKind {
        self.kind
    }

    /// UART register aperture.
    #[must_use]
    pub const fn registers(self) -> PhysicalRange {
        self.registers
    }

    /// Firmware-supplied input clock; absence remains explicit.
    #[must_use]
    pub const fn clock_hz(self) -> Option<u32> {
        self.clock_hz
    }

    /// Firmware-supplied current baud rate; absence remains explicit.
    #[must_use]
    pub const fn current_baud(self) -> Option<u32> {
        self.current_baud
    }

    /// Firmware-supplied register shift; absence remains explicit.
    #[must_use]
    pub const fn register_shift(self) -> Option<u32> {
        self.register_shift
    }

    /// Firmware-supplied register access width; absence remains explicit.
    #[must_use]
    pub const fn register_io_width(self) -> Option<u32> {
        self.register_io_width
    }

    /// Unique UART interrupt routed through the discovered GIC.
    #[must_use]
    pub const fn interrupt(self) -> GicInterrupt {
        self.interrupt
    }
}

/// Supported generic interrupt-controller generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GicVersion {
    /// GIC architecture version 2.
    V2,
    /// GIC architecture version 3.
    V3,
}

/// A supported, validated GIC controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gic {
    version: GicVersion,
    phandle: u32,
    regions: [Option<PhysicalRange>; MAX_GIC_REGIONS],
    region_count: usize,
}

impl Gic {
    /// Controller generation selected by an exact compatible string.
    #[must_use]
    pub const fn version(self) -> GicVersion {
        self.version
    }

    /// Nonzero firmware phandle used to prove interrupt-parent relationships.
    #[must_use]
    pub const fn phandle(self) -> u32 {
        self.phandle
    }

    /// Register apertures in binding order.
    pub fn regions(&self) -> impl Iterator<Item = PhysicalRange> + '_ {
        self.regions[..self.region_count].iter().copied().flatten()
    }

    /// GIC distributor aperture (the first binding register range).
    #[must_use]
    pub const fn distributor(self) -> PhysicalRange {
        match self.regions[0] {
            Some(region) => region,
            None => unreachable!(),
        }
    }

    /// `GICv2` CPU-interface or `GICv3` redistributor aperture.
    #[must_use]
    pub const fn cpu_or_redistributor(self) -> PhysicalRange {
        match self.regions[1] {
            Some(region) => region,
            None => unreachable!(),
        }
    }
}

/// GIC interrupt namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptKind {
    /// Shared peripheral interrupt (INTID 32 and above).
    Spi,
    /// Private peripheral interrupt (INTID 16 through 31).
    Ppi,
}

/// Interrupt trigger behavior decoded from the GIC binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptTrigger {
    /// Edge-triggered.
    Edge,
    /// Level-triggered.
    Level,
}

/// Interrupt active polarity decoded from the GIC binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptPolarity {
    /// Active high/rising edge.
    ActiveHigh,
    /// Active low/falling edge.
    ActiveLow,
}

/// One validated three-cell GIC interrupt specifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GicInterrupt {
    kind: InterruptKind,
    intid: u32,
    trigger: InterruptTrigger,
    polarity: InterruptPolarity,
    ppi_cpu_mask: u8,
}

impl GicInterrupt {
    /// GIC interrupt kind.
    #[must_use]
    pub const fn kind(self) -> InterruptKind {
        self.kind
    }

    /// Absolute GIC INTID after applying the SPI/PPI binding offset.
    #[must_use]
    pub const fn intid(self) -> u32 {
        self.intid
    }

    /// Trigger behavior.
    #[must_use]
    pub const fn trigger(self) -> InterruptTrigger {
        self.trigger
    }

    /// Active polarity.
    #[must_use]
    pub const fn polarity(self) -> InterruptPolarity {
        self.polarity
    }

    /// `GICv2` PPI CPU mask. Zero means no mask was supplied or it is an SPI.
    #[must_use]
    pub const fn ppi_cpu_mask(self) -> u8 {
        self.ppi_cpu_mask
    }
}

/// Validated Arm architected-timer interrupt inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchitectedTimer {
    interrupts: [Option<GicInterrupt>; MAX_TIMER_INTERRUPTS],
    interrupt_count: usize,
}

impl ArchitectedTimer {
    /// Interrupts in firmware binding order; meanings stay explicit in firmware.
    pub fn interrupts(&self) -> impl Iterator<Item = GicInterrupt> + '_ {
        self.interrupts[..self.interrupt_count]
            .iter()
            .copied()
            .flatten()
    }

    /// Virtual-timer interrupt, present only when firmware supplied the third tuple.
    #[must_use]
    pub const fn virtual_timer(self) -> Option<GicInterrupt> {
        if self.interrupt_count >= 3 {
            self.interrupts[2]
        } else {
            None
        }
    }
}

/// Address-space class of a generic PCI host window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciSpace {
    /// PCI I/O space.
    Io,
    /// Non-prefetchable 32-bit memory space.
    Memory32,
    /// 64-bit-capable memory space.
    Memory64,
}

/// One decoded generic-ECAM `ranges` tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciWindow {
    space: PciSpace,
    prefetchable: bool,
    child_address: u64,
    parent: PhysicalRange,
}

impl PciWindow {
    /// Child PCI address-space class.
    #[must_use]
    pub const fn space(self) -> PciSpace {
        self.space
    }

    /// Whether firmware marked the window prefetchable.
    #[must_use]
    pub const fn prefetchable(self) -> bool {
        self.prefetchable
    }

    /// First PCI-bus address in the window.
    #[must_use]
    pub const fn child_address(self) -> u64 {
        self.child_address
    }

    /// CPU physical mapping and window length.
    #[must_use]
    pub const fn parent(self) -> PhysicalRange {
        self.parent
    }
}

/// Explicit PCI bus interval from `bus-range`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciBusRange {
    first: u8,
    last: u8,
}

impl PciBusRange {
    /// First bus number.
    #[must_use]
    pub const fn first(self) -> u8 {
        self.first
    }

    /// Last bus number, inclusive.
    #[must_use]
    pub const fn last(self) -> u8 {
        self.last
    }
}

/// One validated `pci-host-ecam-generic` node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciHost {
    ecam: PhysicalRange,
    bus_range: Option<PciBusRange>,
    windows: [Option<PciWindow>; MAX_PCI_WINDOWS],
    window_count: usize,
}

impl PciHost {
    /// ECAM register aperture.
    #[must_use]
    pub const fn ecam(self) -> PhysicalRange {
        self.ecam
    }

    /// Firmware-supplied bus range. Absence remains explicit.
    #[must_use]
    pub const fn bus_range(self) -> Option<PciBusRange> {
        self.bus_range
    }

    /// Outbound host windows in firmware order.
    pub fn windows(&self) -> impl Iterator<Item = PciWindow> + '_ {
        self.windows[..self.window_count].iter().copied().flatten()
    }
}

/// One validated `virtio,mmio` endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioMmio {
    registers: PhysicalRange,
    interrupt: GicInterrupt,
}

impl VirtioMmio {
    /// Device register aperture.
    #[must_use]
    pub const fn registers(self) -> PhysicalRange {
        self.registers
    }

    /// Device interrupt routed through the discovered GIC.
    #[must_use]
    pub const fn interrupt(self) -> GicInterrupt {
        self.interrupt
    }
}

/// Validated, bounded facts discovered from one DTB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inventory<'a> {
    stdout: Option<StdoutPath<'a>>,
    reservations: [Option<PhysicalRange>; MAX_RESERVATIONS],
    reservation_count: usize,
    memory: [Option<PhysicalRange>; MAX_MEMORY_REGIONS],
    memory_count: usize,
    psci: Option<Psci>,
    gic: Option<Gic>,
    timer: Option<ArchitectedTimer>,
    stdout_uart: Option<StdoutUart>,
    pci_hosts: [Option<PciHost>; MAX_PCI_HOSTS],
    pci_host_count: usize,
    virtio_mmio: [Option<VirtioMmio>; MAX_VIRTIO_MMIO_DEVICES],
    virtio_mmio_count: usize,
}

impl<'a> Inventory<'a> {
    /// Firmware-selected recovery/output path, if supplied.
    #[must_use]
    pub const fn stdout_path(&self) -> Option<StdoutPath<'a>> {
        self.stdout
    }

    /// Firmware memory-reservation table entries.
    pub fn reservations(&self) -> impl Iterator<Item = PhysicalRange> + '_ {
        self.reservations[..self.reservation_count]
            .iter()
            .copied()
            .flatten()
    }

    /// Published RAM extents.
    pub fn memory(&self) -> impl Iterator<Item = PhysicalRange> + '_ {
        self.memory[..self.memory_count].iter().copied().flatten()
    }

    /// The unique supported interrupt controller, if described.
    #[must_use]
    pub const fn gic(&self) -> Option<Gic> {
        self.gic
    }

    /// Standard-ID PSCI interface, if supplied.
    #[must_use]
    pub const fn psci(&self) -> Option<Psci> {
        self.psci
    }

    /// The unique enabled architected timer, if described.
    #[must_use]
    pub const fn timer(&self) -> Option<ArchitectedTimer> {
        self.timer
    }

    /// Supported UART selected by the resolved stdout path, if present.
    #[must_use]
    pub const fn stdout_uart(&self) -> Option<StdoutUart> {
        self.stdout_uart
    }

    /// Generic ECAM hosts.
    pub fn pci_hosts(&self) -> impl Iterator<Item = PciHost> + '_ {
        self.pci_hosts[..self.pci_host_count]
            .iter()
            .copied()
            .flatten()
    }

    /// Enabled virtio-MMIO endpoints.
    pub fn virtio_mmio_devices(&self) -> impl Iterator<Item = VirtioMmio> + '_ {
        self.virtio_mmio[..self.virtio_mmio_count]
            .iter()
            .copied()
            .flatten()
    }
}

#[derive(Clone, Copy)]
struct Header<'a> {
    structure: &'a [u8],
    strings: &'a [u8],
    reservations_offset: usize,
    total_size: usize,
    structure_offset: usize,
    strings_offset: usize,
}

#[derive(Clone, Copy)]
struct NodeFrame<'a> {
    id: u16,
    parent_id: Option<u16>,
    name: &'a [u8],
    parent_address_cells: Option<u32>,
    parent_size_cells: Option<u32>,
    child_address_cells: Option<u32>,
    child_size_cells: Option<u32>,
    interrupt_parent: Option<u32>,
    ancestors_enabled: bool,
    saw_child: bool,
    props: NodeProperties<'a>,
}

#[derive(Clone, Copy, Default)]
struct NodeProperties<'a> {
    compatible: Option<&'a [u8]>,
    device_type: Option<&'a [u8]>,
    status: Option<&'a [u8]>,
    reg: Option<&'a [u8]>,
    ranges: Option<&'a [u8]>,
    bus_range: Option<&'a [u8]>,
    interrupts: Option<&'a [u8]>,
    stdout_path: Option<&'a [u8]>,
    linux_stdout_path: Option<&'a [u8]>,
    phandle: Option<u32>,
    linux_phandle: Option<u32>,
    interrupt_controller: bool,
    interrupt_cells: Option<u32>,
    method: Option<&'a [u8]>,
    clock_frequency: Option<u32>,
    current_speed: Option<u32>,
    reg_shift: Option<u32>,
    reg_io_width: Option<u32>,
    clocks: Option<&'a [u8]>,
    clock_cells: Option<u32>,
}

#[derive(Clone, Copy)]
struct SeenNode<'a> {
    parent_id: Option<u16>,
    name: &'a [u8],
}

#[derive(Clone, Copy)]
struct SeenProperty {
    node_id: u16,
    name_offset: u32,
}

#[derive(Clone, Copy)]
struct SeenPhandle {
    node_id: u16,
    value: u32,
}

#[derive(Clone, Copy)]
struct PendingInterrupts<'a> {
    parent: u32,
    value: &'a [u8],
}

#[derive(Clone, Copy)]
struct PendingVirtio<'a> {
    registers: PhysicalRange,
    interrupts: PendingInterrupts<'a>,
}

#[derive(Clone, Copy)]
struct Alias<'a> {
    name: &'a str,
    path: &'a str,
}

#[derive(Clone, Copy)]
struct PendingUart<'a> {
    node_id: u16,
    kind: UartKind,
    registers: PhysicalRange,
    clock_hz: Option<u32>,
    clocks: Option<&'a [u8]>,
    current_baud: Option<u32>,
    register_shift: Option<u32>,
    register_io_width: Option<u32>,
    interrupts: PendingInterrupts<'a>,
}

#[derive(Clone, Copy)]
struct FixedClock {
    phandle: u32,
    frequency_hz: u32,
}

struct Parser<'a> {
    header: Header<'a>,
    frames: [Option<NodeFrame<'a>>; MAX_DEPTH],
    depth: usize,
    nodes: [Option<SeenNode<'a>>; MAX_NODES],
    node_count: usize,
    properties: [Option<SeenProperty>; MAX_PROPERTIES],
    property_count: usize,
    phandles: [Option<SeenPhandle>; MAX_NODES],
    phandle_count: usize,
    claimed: [Option<PhysicalRange>;
        MAX_MEMORY_REGIONS
            + MAX_GIC_REGIONS
            + MAX_PCI_HOSTS * (MAX_PCI_WINDOWS + 1)
            + MAX_VIRTIO_MMIO_DEVICES
            + MAX_UARTS],
    claimed_count: usize,
    pending_timer: Option<PendingInterrupts<'a>>,
    pending_virtio: [Option<PendingVirtio<'a>>; MAX_VIRTIO_MMIO_DEVICES],
    pending_virtio_count: usize,
    aliases: [Option<Alias<'a>>; MAX_ALIASES],
    alias_count: usize,
    pending_uarts: [Option<PendingUart<'a>>; MAX_UARTS],
    pending_uart_count: usize,
    fixed_clocks: [Option<FixedClock>; MAX_FIXED_CLOCKS],
    fixed_clock_count: usize,
    interrupt_ids: [Option<u32>; MAX_TIMER_INTERRUPTS + MAX_VIRTIO_MMIO_DEVICES + 1],
    interrupt_id_count: usize,
    inventory: Inventory<'a>,
}

/// Parse and validate a version-17 Flattened Devicetree blob.
///
/// The returned strings borrow `blob`; all other facts are copied into bounded
/// fixed-capacity arrays.  Any malformed supported resource rejects the entire
/// blob rather than being omitted.
///
/// # Errors
///
/// Returns an [`Error`] for malformed, ambiguous, overlapping, unsupported, or
/// over-limit input. No partial inventory is returned.
pub fn discover(blob: &[u8]) -> Result<Inventory<'_>, Error> {
    let header = parse_header(blob)?;
    let mut parser = Parser::new(header);
    parser.parse_reservations(blob)?;
    parser.parse_structure()?;
    parser.resolve_uart_clocks()?;
    parser.resolve_interrupts()?;
    parser.resolve_stdout_uart()?;
    Ok(parser.inventory)
}

impl<'a> Parser<'a> {
    fn new(header: Header<'a>) -> Self {
        Self {
            header,
            frames: [None; MAX_DEPTH],
            depth: 0,
            nodes: [None; MAX_NODES],
            node_count: 0,
            properties: [None; MAX_PROPERTIES],
            property_count: 0,
            phandles: [None; MAX_NODES],
            phandle_count: 0,
            claimed: [None;
                MAX_MEMORY_REGIONS
                    + MAX_GIC_REGIONS
                    + MAX_PCI_HOSTS * (MAX_PCI_WINDOWS + 1)
                    + MAX_VIRTIO_MMIO_DEVICES
                    + MAX_UARTS],
            claimed_count: 0,
            pending_timer: None,
            pending_virtio: [None; MAX_VIRTIO_MMIO_DEVICES],
            pending_virtio_count: 0,
            aliases: [None; MAX_ALIASES],
            alias_count: 0,
            pending_uarts: [None; MAX_UARTS],
            pending_uart_count: 0,
            fixed_clocks: [None; MAX_FIXED_CLOCKS],
            fixed_clock_count: 0,
            interrupt_ids: [None; MAX_TIMER_INTERRUPTS + MAX_VIRTIO_MMIO_DEVICES + 1],
            interrupt_id_count: 0,
            inventory: Inventory {
                stdout: None,
                reservations: [None; MAX_RESERVATIONS],
                reservation_count: 0,
                memory: [None; MAX_MEMORY_REGIONS],
                memory_count: 0,
                psci: None,
                gic: None,
                timer: None,
                stdout_uart: None,
                pci_hosts: [None; MAX_PCI_HOSTS],
                pci_host_count: 0,
                virtio_mmio: [None; MAX_VIRTIO_MMIO_DEVICES],
                virtio_mmio_count: 0,
            },
        }
    }

    fn parse_reservations(&mut self, blob: &[u8]) -> Result<(), Error> {
        let mut cursor = self.header.reservations_offset;
        let mut limit = self.header.total_size;
        for offset in [self.header.structure_offset, self.header.strings_offset] {
            if offset > cursor {
                limit = limit.min(offset);
            }
        }
        loop {
            let entry_end = cursor.checked_add(16).ok_or(Error::InvalidHeader)?;
            if entry_end > limit || entry_end > blob.len() {
                return Err(Error::UnterminatedReservations);
            }
            let address = read_be_u64(blob, cursor)?;
            let size = read_be_u64(blob, cursor + 8)?;
            cursor = entry_end;
            if address == 0 && size == 0 {
                break;
            }
            if self.inventory.reservation_count == MAX_RESERVATIONS {
                return Err(Error::LimitExceeded);
            }
            let range = PhysicalRange::checked(address, size)?;
            if self.inventory.reservations[..self.inventory.reservation_count]
                .iter()
                .flatten()
                .any(|other| range.overlaps(*other))
            {
                return Err(Error::OverlappingResources);
            }
            self.inventory.reservations[self.inventory.reservation_count] = Some(range);
            self.inventory.reservation_count += 1;
        }
        ensure_no_overlap(
            self.header.reservations_offset,
            cursor - self.header.reservations_offset,
            self.header.structure_offset,
            self.header.structure.len(),
        )?;
        ensure_no_overlap(
            self.header.reservations_offset,
            cursor - self.header.reservations_offset,
            self.header.strings_offset,
            self.header.strings.len(),
        )
    }

    fn parse_structure(&mut self) -> Result<(), Error> {
        let bytes = self.header.structure;
        let mut cursor = 0usize;
        let mut token_count = 0usize;
        let mut saw_root = false;
        let mut root_closed = false;

        loop {
            token_count = token_count.checked_add(1).ok_or(Error::LimitExceeded)?;
            if token_count > MAX_TOKENS {
                return Err(Error::LimitExceeded);
            }
            let token = take_u32(bytes, &mut cursor)?;
            match token {
                FDT_BEGIN_NODE => {
                    if root_closed || self.depth == MAX_DEPTH || self.node_count == MAX_NODES {
                        return Err(if root_closed {
                            Error::InvalidNesting
                        } else {
                            Error::LimitExceeded
                        });
                    }
                    let name = take_padded_cstr(bytes, &mut cursor)?;
                    validate_node_name(name, self.depth == 0)?;
                    if self.depth == 0 {
                        if saw_root {
                            return Err(Error::InvalidNesting);
                        }
                        saw_root = true;
                    }
                    self.begin_node(name)?;
                }
                FDT_END_NODE => {
                    if self.depth == 0 {
                        return Err(Error::InvalidNesting);
                    }
                    self.end_node()?;
                    if self.depth == 0 {
                        root_closed = true;
                    }
                }
                FDT_PROP => self.property(bytes, &mut cursor)?,
                FDT_NOP => {}
                FDT_END => {
                    if !saw_root || !root_closed || self.depth != 0 || cursor != bytes.len() {
                        return Err(Error::InvalidNesting);
                    }
                    return Ok(());
                }
                _ => return Err(Error::InvalidToken),
            }
        }
    }

    fn begin_node(&mut self, name: &'a [u8]) -> Result<(), Error> {
        let parent = if self.depth == 0 {
            None
        } else {
            let parent = self.frames[self.depth - 1].ok_or(Error::InvalidNesting)?;
            Some(parent)
        };
        if let Some(mut parent_frame) = parent {
            parent_frame.saw_child = true;
            self.frames[self.depth - 1] = Some(parent_frame);
        }
        let parent_id = parent.map(|frame| frame.id);
        if self.nodes[..self.node_count]
            .iter()
            .flatten()
            .any(|node| node.parent_id == parent_id && node.name == name)
        {
            return Err(Error::InvalidNodeName);
        }
        let id = u16::try_from(self.node_count).map_err(|_| Error::LimitExceeded)?;
        self.nodes[self.node_count] = Some(SeenNode { parent_id, name });
        self.node_count += 1;
        let ancestors_enabled = match parent {
            Some(parent) => parent.ancestors_enabled && parse_status(parent.props.status)?,
            None => true,
        };
        let frame = NodeFrame {
            id,
            parent_id,
            name,
            parent_address_cells: parent.and_then(|value| value.child_address_cells),
            parent_size_cells: parent.and_then(|value| value.child_size_cells),
            child_address_cells: None,
            child_size_cells: None,
            interrupt_parent: parent.and_then(|value| value.interrupt_parent),
            ancestors_enabled,
            saw_child: false,
            props: NodeProperties::default(),
        };
        self.frames[self.depth] = Some(frame);
        self.depth += 1;
        Ok(())
    }

    fn end_node(&mut self) -> Result<(), Error> {
        self.depth -= 1;
        let frame = self.frames[self.depth]
            .take()
            .ok_or(Error::InvalidNesting)?;
        self.finalize_node(&frame)
    }

    fn property(&mut self, bytes: &'a [u8], cursor: &mut usize) -> Result<(), Error> {
        if self.depth == 0 || self.property_count == MAX_PROPERTIES {
            return Err(if self.depth == 0 {
                Error::InvalidToken
            } else {
                Error::LimitExceeded
            });
        }
        let value_len =
            usize::try_from(take_u32(bytes, cursor)?).map_err(|_| Error::InvalidProperty)?;
        let name_offset =
            usize::try_from(take_u32(bytes, cursor)?).map_err(|_| Error::InvalidPropertyName)?;
        if value_len > MAX_PROPERTY_BYTES {
            return Err(Error::LimitExceeded);
        }
        let value = take_padded(bytes, cursor, value_len)?;
        let name = string_at(self.header.strings, name_offset)?;
        validate_property_name(name)?;
        let mut frame = self.frames[self.depth - 1].ok_or(Error::InvalidNesting)?;
        if frame.saw_child {
            return Err(Error::PropertyAfterChild);
        }
        if self.properties[..self.property_count]
            .iter()
            .flatten()
            .filter(|property| property.node_id == frame.id)
            .try_fold(false, |duplicate, property| {
                Ok::<bool, Error>(
                    duplicate
                        || string_at(
                            self.header.strings,
                            usize::try_from(property.name_offset)
                                .map_err(|_| Error::InvalidPropertyName)?,
                        )? == name,
                )
            })?
        {
            return Err(Error::DuplicateProperty);
        }
        self.properties[self.property_count] = Some(SeenProperty {
            node_id: frame.id,
            name_offset: u32::try_from(name_offset).map_err(|_| Error::InvalidPropertyName)?,
        });
        self.property_count += 1;

        self.decode_property(&mut frame, name, value)?;
        self.frames[self.depth - 1] = Some(frame);
        Ok(())
    }

    fn decode_property(
        &mut self,
        frame: &mut NodeFrame<'a>,
        name: &'a [u8],
        value: &'a [u8],
    ) -> Result<(), Error> {
        match name {
            b"compatible" => frame.props.compatible = Some(value),
            b"device_type" => frame.props.device_type = Some(value),
            b"status" => frame.props.status = Some(value),
            b"reg" => frame.props.reg = Some(value),
            b"ranges" => frame.props.ranges = Some(value),
            b"bus-range" => frame.props.bus_range = Some(value),
            b"interrupts" => frame.props.interrupts = Some(value),
            b"stdout-path" => frame.props.stdout_path = Some(value),
            b"linux,stdout-path" => frame.props.linux_stdout_path = Some(value),
            b"phandle" => frame.props.phandle = Some(single_u32(value)?),
            b"linux,phandle" => frame.props.linux_phandle = Some(single_u32(value)?),
            b"interrupt-parent" => {
                let parent = single_u32(value)?;
                if parent == 0 || parent == u32::MAX {
                    return Err(Error::InvalidPhandle);
                }
                frame.interrupt_parent = Some(parent);
            }
            b"interrupt-controller" => {
                if !value.is_empty() {
                    return Err(Error::InvalidProperty);
                }
                frame.props.interrupt_controller = true;
            }
            b"#interrupt-cells" => {
                let cells = single_u32(value)?;
                if cells == 0 || cells > 4 {
                    return Err(Error::UnsupportedCells);
                }
                frame.props.interrupt_cells = Some(cells);
            }
            b"#address-cells" => {
                let cells = single_u32(value)?;
                if cells == 0 || cells > 3 {
                    return Err(Error::UnsupportedCells);
                }
                frame.child_address_cells = Some(cells);
            }
            b"#size-cells" => {
                let cells = single_u32(value)?;
                if cells > 2 {
                    return Err(Error::UnsupportedCells);
                }
                frame.child_size_cells = Some(cells);
            }
            b"method" => frame.props.method = Some(value),
            b"clock-frequency" => frame.props.clock_frequency = Some(single_u32(value)?),
            b"clocks" => frame.props.clocks = Some(value),
            b"#clock-cells" => {
                let cells = single_u32(value)?;
                if cells > 4 {
                    return Err(Error::UnsupportedCells);
                }
                frame.props.clock_cells = Some(cells);
            }
            b"current-speed" => frame.props.current_speed = Some(single_u32(value)?),
            b"reg-shift" => frame.props.reg_shift = Some(single_u32(value)?),
            b"reg-io-width" => frame.props.reg_io_width = Some(single_u32(value)?),
            _ => {}
        }
        if frame.parent_id == Some(0) && frame.name == b"aliases" {
            self.record_alias(name, value)?;
        }
        Ok(())
    }

    fn finalize_node(&mut self, frame: &NodeFrame<'a>) -> Result<(), Error> {
        let enabled = frame.ancestors_enabled && parse_status(frame.props.status)?;
        if let (Some(first), Some(second)) = (frame.props.phandle, frame.props.linux_phandle)
            && first != second
        {
            return Err(Error::InvalidPhandle);
        }
        if let Some(phandle) = frame.props.phandle.or(frame.props.linux_phandle) {
            self.record_phandle(frame.id, phandle)?;
        }
        let compatible = match frame.props.compatible {
            Some(value) => Some(parse_compatible(value)?),
            None => None,
        };
        let device_type = match frame.props.device_type {
            Some(value) => Some(single_string(value)?),
            None => None,
        };

        if enabled && frame.parent_id == Some(0) && frame.name == b"chosen" {
            self.parse_chosen(frame.props)?;
        }

        let memory_named = frame.name == b"memory" || frame.name.starts_with(b"memory@");
        let is_memory = device_type == Some("memory");
        if memory_named && device_type != Some("memory") {
            return Err(Error::MissingProperty);
        }
        if enabled && is_memory {
            if frame.parent_id != Some(0) {
                return Err(Error::UnsupportedTranslation);
            }
            self.add_memory(frame)?;
        }

        if !enabled {
            return Ok(());
        }
        let Some(compatible) = compatible else {
            return Ok(());
        };
        let supported_count = usize::from(compatible.gic.is_some())
            + usize::from(compatible.timer)
            + usize::from(compatible.pci_ecam)
            + usize::from(compatible.virtio_mmio)
            + usize::from(compatible.psci.is_some())
            + usize::from(compatible.uart.is_some())
            + usize::from(compatible.fixed_clock);
        if supported_count > 1 {
            return Err(Error::AmbiguousDevice);
        }
        if supported_count != 0 && frame.parent_id != Some(0) {
            return Err(Error::UnsupportedTranslation);
        }
        if let Some(version) = compatible.gic {
            self.add_gic(frame, version)?;
        } else if compatible.timer {
            self.add_timer(frame)?;
        } else if compatible.pci_ecam {
            if device_type != Some("pci") {
                return Err(Error::MissingProperty);
            }
            self.add_pci_host(frame)?;
        } else if compatible.virtio_mmio {
            self.add_virtio(frame)?;
        } else if let Some(version) = compatible.psci {
            self.add_psci(frame, version)?;
        } else if let Some(kind) = compatible.uart {
            self.add_uart(frame, kind)?;
        } else if compatible.fixed_clock {
            self.add_fixed_clock(frame)?;
        }
        Ok(())
    }

    fn parse_chosen(&mut self, props: NodeProperties<'a>) -> Result<(), Error> {
        if props.stdout_path.is_some() && props.linux_stdout_path.is_some() {
            return Err(Error::DuplicateProperty);
        }
        let Some(value) = props.stdout_path.or(props.linux_stdout_path) else {
            return Ok(());
        };
        if self.inventory.stdout.is_some() {
            return Err(Error::DuplicateProperty);
        }
        let raw = single_string(value)?;
        if raw.is_empty()
            || raw.len() > 255
            || raw.as_bytes().contains(&b'/') && !raw.starts_with('/')
        {
            return Err(Error::InvalidString);
        }
        let (device, options) = match raw.split_once(':') {
            Some((device, options)) if !device.is_empty() && !options.is_empty() => {
                (device, Some(options))
            }
            Some(_) => return Err(Error::InvalidString),
            None => (raw, None),
        };
        if device.starts_with('/') {
            validate_absolute_path(device)?;
        } else {
            validate_alias_name(device)?;
        }
        self.inventory.stdout = Some(StdoutPath {
            raw,
            device,
            options,
            resolved_device: if device.starts_with('/') {
                Some(device)
            } else {
                None
            },
        });
        Ok(())
    }

    fn add_psci(&mut self, frame: &NodeFrame<'a>, version: PsciVersion) -> Result<(), Error> {
        if self.inventory.psci.is_some() {
            return Err(Error::AmbiguousDevice);
        }
        let method = single_string(frame.props.method.ok_or(Error::MissingProperty)?)?;
        let conduit = match method {
            "smc" => PsciConduit::Smc,
            "hvc" => PsciConduit::Hvc,
            _ => return Err(Error::InvalidProperty),
        };
        self.inventory.psci = Some(Psci { version, conduit });
        Ok(())
    }

    fn add_fixed_clock(&mut self, frame: &NodeFrame<'a>) -> Result<(), Error> {
        if self.fixed_clock_count == MAX_FIXED_CLOCKS {
            return Err(Error::LimitExceeded);
        }
        let phandle = frame
            .props
            .phandle
            .or(frame.props.linux_phandle)
            .ok_or(Error::MissingProperty)?;
        let frequency_hz = frame.props.clock_frequency.ok_or(Error::MissingProperty)?;
        if frequency_hz == 0 || frame.props.clock_cells != Some(0) {
            return Err(Error::InvalidProperty);
        }
        self.fixed_clocks[self.fixed_clock_count] = Some(FixedClock {
            phandle,
            frequency_hz,
        });
        self.fixed_clock_count += 1;
        Ok(())
    }

    fn add_uart(&mut self, frame: &NodeFrame<'a>, kind: UartKind) -> Result<(), Error> {
        if self.pending_uart_count == MAX_UARTS {
            return Err(Error::LimitExceeded);
        }
        let mut values = RegIter::new(
            frame.props.reg.ok_or(Error::MissingProperty)?,
            frame.parent_address_cells.ok_or(Error::MissingCells)?,
            frame.parent_size_cells.ok_or(Error::MissingCells)?,
        )?;
        let registers = values.next_range()?.ok_or(Error::MissingProperty)?;
        if values.next_range()?.is_some()
            || !registers.base.is_multiple_of(PAGE_BYTES)
            || registers.byte_len < 8
            || !registers.byte_len.is_multiple_of(4)
        {
            return Err(Error::InvalidAlignment);
        }
        if frame.props.clock_frequency == Some(0)
            || frame.props.current_speed == Some(0)
            || frame.props.reg_shift.is_some_and(|shift| shift > 4)
            || !matches!(frame.props.reg_io_width, None | Some(1 | 2 | 4))
        {
            return Err(Error::InvalidProperty);
        }
        if frame.props.clock_frequency.is_some() && frame.props.clocks.is_some() {
            return Err(Error::AmbiguousDevice);
        }
        if let Some(clocks) = frame.props.clocks
            && (clocks.is_empty()
                || !clocks.len().is_multiple_of(4)
                || clocks.len() / 4 > MAX_UART_CLOCKS)
        {
            return Err(Error::InvalidProperty);
        }
        self.claim(registers)?;
        let parent = frame.interrupt_parent.ok_or(Error::MissingProperty)?;
        let value = frame.props.interrupts.ok_or(Error::MissingProperty)?;
        if interrupt_tuple_count(value)? != 1 {
            return Err(Error::InvalidInterrupt);
        }
        self.pending_uarts[self.pending_uart_count] = Some(PendingUart {
            node_id: frame.id,
            kind,
            registers,
            clock_hz: frame.props.clock_frequency,
            clocks: frame.props.clocks,
            current_baud: frame.props.current_speed,
            register_shift: frame.props.reg_shift,
            register_io_width: frame.props.reg_io_width,
            interrupts: PendingInterrupts { parent, value },
        });
        self.pending_uart_count += 1;
        Ok(())
    }

    fn resolve_uart_clocks(&mut self) -> Result<(), Error> {
        for index in 0..self.pending_uart_count {
            let mut uart = self.pending_uarts[index].ok_or(Error::InvalidProperty)?;
            let Some(clocks) = uart.clocks else {
                continue;
            };
            let mut frequency = None;
            for encoded in clocks.chunks_exact(4) {
                let phandle =
                    u32::from_be_bytes(encoded.try_into().map_err(|_| Error::InvalidProperty)?);
                if phandle == 0 || phandle == u32::MAX {
                    return Err(Error::InvalidPhandle);
                }
                let mut providers = self.fixed_clocks[..self.fixed_clock_count]
                    .iter()
                    .flatten()
                    .filter(|provider| provider.phandle == phandle);
                let provider = providers.next().ok_or(Error::InvalidPhandle)?;
                if providers.next().is_some()
                    || frequency.is_some_and(|current| current != provider.frequency_hz)
                {
                    return Err(Error::AmbiguousDevice);
                }
                frequency = Some(provider.frequency_hz);
            }
            uart.clock_hz = Some(frequency.ok_or(Error::MissingProperty)?);
            self.pending_uarts[index] = Some(uart);
        }
        Ok(())
    }

    fn add_memory(&mut self, frame: &NodeFrame<'a>) -> Result<(), Error> {
        let reg = frame.props.reg.ok_or(Error::MissingProperty)?;
        let mut values = RegIter::new(
            reg,
            frame.parent_address_cells.ok_or(Error::MissingCells)?,
            frame.parent_size_cells.ok_or(Error::MissingCells)?,
        )?;
        let initial_count = self.inventory.memory_count;
        while let Some(range) = values.next_range()? {
            require_alignment(range, PAGE_BYTES)?;
            if self.inventory.memory_count == MAX_MEMORY_REGIONS {
                return Err(Error::LimitExceeded);
            }
            self.claim(range)?;
            self.inventory.memory[self.inventory.memory_count] = Some(range);
            self.inventory.memory_count += 1;
        }
        if self.inventory.memory_count == initial_count {
            return Err(Error::MissingProperty);
        }
        Ok(())
    }

    fn add_gic(&mut self, frame: &NodeFrame<'a>, version: GicVersion) -> Result<(), Error> {
        if self.inventory.gic.is_some() {
            return Err(Error::AmbiguousDevice);
        }
        if !frame.props.interrupt_controller || frame.props.interrupt_cells != Some(3) {
            return Err(Error::MissingProperty);
        }
        let phandle = frame
            .props
            .phandle
            .or(frame.props.linux_phandle)
            .ok_or(Error::MissingProperty)?;
        let reg = frame.props.reg.ok_or(Error::MissingProperty)?;
        let mut values = RegIter::new(
            reg,
            frame.parent_address_cells.ok_or(Error::MissingCells)?,
            frame.parent_size_cells.ok_or(Error::MissingCells)?,
        )?;
        let mut regions = [None; MAX_GIC_REGIONS];
        let mut count = 0usize;
        while let Some(range) = values.next_range()? {
            if count == MAX_GIC_REGIONS {
                return Err(Error::LimitExceeded);
            }
            require_alignment(range, PAGE_BYTES)?;
            self.claim(range)?;
            regions[count] = Some(range);
            count += 1;
        }
        if count < 2 {
            return Err(Error::MissingProperty);
        }
        self.inventory.gic = Some(Gic {
            version,
            phandle,
            regions,
            region_count: count,
        });
        Ok(())
    }

    fn add_timer(&mut self, frame: &NodeFrame<'a>) -> Result<(), Error> {
        if self.pending_timer.is_some() {
            return Err(Error::AmbiguousDevice);
        }
        let parent = frame.interrupt_parent.ok_or(Error::MissingProperty)?;
        let value = frame.props.interrupts.ok_or(Error::MissingProperty)?;
        let count = interrupt_tuple_count(value)?;
        if count == 0 || count > MAX_TIMER_INTERRUPTS {
            return Err(Error::InvalidInterrupt);
        }
        self.pending_timer = Some(PendingInterrupts { parent, value });
        Ok(())
    }

    fn add_pci_host(&mut self, frame: &NodeFrame<'a>) -> Result<(), Error> {
        if self.inventory.pci_host_count == MAX_PCI_HOSTS {
            return Err(Error::LimitExceeded);
        }
        if frame.child_address_cells != Some(3) || frame.child_size_cells != Some(2) {
            return Err(Error::UnsupportedCells);
        }
        let reg = frame.props.reg.ok_or(Error::MissingProperty)?;
        let mut reg_values = RegIter::new(
            reg,
            frame.parent_address_cells.ok_or(Error::MissingCells)?,
            frame.parent_size_cells.ok_or(Error::MissingCells)?,
        )?;
        let ecam = reg_values.next_range()?.ok_or(Error::MissingProperty)?;
        if reg_values.next_range()?.is_some()
            || !ecam.base.is_multiple_of(ECAM_BUS_BYTES)
            || !ecam.byte_len.is_multiple_of(ECAM_BUS_BYTES)
            || ecam.byte_len > 256 * ECAM_BUS_BYTES
        {
            return Err(Error::InvalidPci);
        }
        self.claim(ecam)?;
        let bus_range = match frame.props.bus_range {
            Some(value) => {
                if value.len() != 8 {
                    return Err(Error::InvalidPci);
                }
                let first = be_u32_at(value, 0)?;
                let last = be_u32_at(value, 4)?;
                if first > last || last > u32::from(u8::MAX) {
                    return Err(Error::InvalidPci);
                }
                let buses = u64::from(last - first + 1);
                if ecam.byte_len != buses * ECAM_BUS_BYTES {
                    return Err(Error::InvalidPci);
                }
                Some(PciBusRange {
                    first: u8::try_from(first).map_err(|_| Error::InvalidPci)?,
                    last: u8::try_from(last).map_err(|_| Error::InvalidPci)?,
                })
            }
            None => None,
        };
        let ranges = frame.props.ranges.ok_or(Error::MissingProperty)?;
        let parent_cells = frame.parent_address_cells.ok_or(Error::MissingCells)?;
        let mut windows: [Option<PciWindow>; MAX_PCI_WINDOWS] = [None; MAX_PCI_WINDOWS];
        let mut window_count = 0usize;
        let tuple_cells = 3usize
            .checked_add(usize::try_from(parent_cells).map_err(|_| Error::UnsupportedCells)?)
            .and_then(|value| value.checked_add(2))
            .ok_or(Error::InvalidPci)?;
        let tuple_bytes = tuple_cells.checked_mul(4).ok_or(Error::InvalidPci)?;
        if !ranges.len().is_multiple_of(tuple_bytes) {
            return Err(Error::InvalidPci);
        }
        let mut cursor = 0usize;
        while cursor < ranges.len() {
            if window_count == MAX_PCI_WINDOWS {
                return Err(Error::LimitExceeded);
            }
            let high = be_u32_at(ranges, cursor)?;
            cursor += 4;
            let child_address = read_cells(ranges, &mut cursor, 2)?;
            let parent_address = read_cells(ranges, &mut cursor, parent_cells)?;
            let size = read_cells(ranges, &mut cursor, 2)?;
            let window = decode_pci_window(high, child_address, parent_address, size)?;
            require_alignment(window.parent, PAGE_BYTES)?;
            if windows[..window_count].iter().flatten().any(|other| {
                same_pci_space_domain(other.space, window.space)
                    && child_ranges_overlap(
                        other.child_address,
                        other.parent.byte_len,
                        window.child_address,
                        window.parent.byte_len,
                    )
            }) {
                return Err(Error::OverlappingResources);
            }
            self.claim(window.parent)?;
            windows[window_count] = Some(window);
            window_count += 1;
        }
        let host = PciHost {
            ecam,
            bus_range,
            windows,
            window_count,
        };
        self.inventory.pci_hosts[self.inventory.pci_host_count] = Some(host);
        self.inventory.pci_host_count += 1;
        Ok(())
    }

    fn add_virtio(&mut self, frame: &NodeFrame<'a>) -> Result<(), Error> {
        if self.pending_virtio_count == MAX_VIRTIO_MMIO_DEVICES {
            return Err(Error::LimitExceeded);
        }
        let reg = frame.props.reg.ok_or(Error::MissingProperty)?;
        let mut values = RegIter::new(
            reg,
            frame.parent_address_cells.ok_or(Error::MissingCells)?,
            frame.parent_size_cells.ok_or(Error::MissingCells)?,
        )?;
        let registers = values.next_range()?.ok_or(Error::MissingProperty)?;
        if values.next_range()?.is_some()
            || !registers.base.is_multiple_of(0x200)
            || registers.byte_len != 0x200
        {
            return Err(Error::InvalidAlignment);
        }
        self.claim(registers)?;
        let parent = frame.interrupt_parent.ok_or(Error::MissingProperty)?;
        let value = frame.props.interrupts.ok_or(Error::MissingProperty)?;
        if interrupt_tuple_count(value)? != 1 {
            return Err(Error::InvalidInterrupt);
        }
        self.pending_virtio[self.pending_virtio_count] = Some(PendingVirtio {
            registers,
            interrupts: PendingInterrupts { parent, value },
        });
        self.pending_virtio_count += 1;
        Ok(())
    }

    fn resolve_interrupts(&mut self) -> Result<(), Error> {
        if self.pending_timer.is_none() && self.pending_virtio_count == 0 {
            return Ok(());
        }
        let gic = self
            .inventory
            .gic
            .ok_or(Error::UnsupportedInterruptParent)?;
        if let Some(pending) = self.pending_timer {
            ensure_interrupt_parent(pending.parent, gic)?;
            let mut values = [None; MAX_TIMER_INTERRUPTS];
            let mut cursor = 0usize;
            let mut count = 0usize;
            while cursor < pending.value.len() {
                let interrupt = decode_gic_interrupt(pending.value, &mut cursor)?;
                self.claim_interrupt(interrupt)?;
                values[count] = Some(interrupt);
                count += 1;
            }
            self.inventory.timer = Some(ArchitectedTimer {
                interrupts: values,
                interrupt_count: count,
            });
        }
        for index in 0..self.pending_virtio_count {
            let pending = self.pending_virtio[index].ok_or(Error::InvalidProperty)?;
            ensure_interrupt_parent(pending.interrupts.parent, gic)?;
            let mut cursor = 0usize;
            let interrupt = decode_gic_interrupt(pending.interrupts.value, &mut cursor)?;
            self.claim_interrupt(interrupt)?;
            let device = VirtioMmio {
                registers: pending.registers,
                interrupt,
            };
            self.inventory.virtio_mmio[self.inventory.virtio_mmio_count] = Some(device);
            self.inventory.virtio_mmio_count += 1;
        }
        Ok(())
    }

    fn record_alias(&mut self, name: &'a [u8], value: &'a [u8]) -> Result<(), Error> {
        if self.alias_count == MAX_ALIASES {
            return Err(Error::LimitExceeded);
        }
        let name = str::from_utf8(name).map_err(|_| Error::InvalidPropertyName)?;
        let path = single_string(value)?;
        validate_absolute_path(path)?;
        self.aliases[self.alias_count] = Some(Alias { name, path });
        self.alias_count += 1;
        Ok(())
    }

    fn resolve_stdout_uart(&mut self) -> Result<(), Error> {
        let Some(mut stdout) = self.inventory.stdout else {
            return Ok(());
        };
        let resolved = if let Some(path) = stdout.resolved_device {
            Some(path)
        } else {
            self.aliases[..self.alias_count]
                .iter()
                .flatten()
                .find(|alias| alias.name == stdout.device)
                .map(|alias| alias.path)
        };
        stdout.resolved_device = resolved;
        self.inventory.stdout = Some(stdout);
        let Some(path) = resolved else {
            return Ok(());
        };
        let mut selected = None;
        for index in 0..self.pending_uart_count {
            let candidate = self.pending_uarts[index].ok_or(Error::InvalidProperty)?;
            if self.node_matches_path(candidate.node_id, path)? {
                if selected.is_some() {
                    return Err(Error::AmbiguousDevice);
                }
                let gic = self
                    .inventory
                    .gic
                    .ok_or(Error::UnsupportedInterruptParent)?;
                ensure_interrupt_parent(candidate.interrupts.parent, gic)?;
                let mut cursor = 0usize;
                let interrupt = decode_gic_interrupt(candidate.interrupts.value, &mut cursor)?;
                self.claim_interrupt(interrupt)?;
                selected = Some(StdoutUart {
                    kind: candidate.kind,
                    registers: candidate.registers,
                    clock_hz: candidate.clock_hz,
                    current_baud: candidate.current_baud,
                    register_shift: candidate.register_shift,
                    register_io_width: candidate.register_io_width,
                    interrupt,
                });
            }
        }
        self.inventory.stdout_uart = selected;
        Ok(())
    }

    fn node_matches_path(&self, node_id: u16, path: &str) -> Result<bool, Error> {
        validate_absolute_path(path)?;
        let mut components = path[1..].rsplit('/');
        let mut current = Some(node_id);
        loop {
            let Some(id) = current else {
                return Ok(components.next().is_none());
            };
            let node = self.nodes[usize::from(id)].ok_or(Error::InvalidNesting)?;
            if node.parent_id.is_none() {
                return Ok(node.name.is_empty() && components.next().is_none());
            }
            let Some(component) = components.next() else {
                return Ok(false);
            };
            if node.name != component.as_bytes() {
                return Ok(false);
            }
            current = node.parent_id;
        }
    }

    fn record_phandle(&mut self, node_id: u16, value: u32) -> Result<(), Error> {
        if value == 0 || value == u32::MAX {
            return Err(Error::InvalidPhandle);
        }
        if let Some(existing) = self.phandles[..self.phandle_count]
            .iter()
            .flatten()
            .find(|entry| entry.value == value)
        {
            if existing.node_id != node_id {
                return Err(Error::InvalidPhandle);
            }
            return Ok(());
        }
        if self.phandle_count == MAX_NODES {
            return Err(Error::LimitExceeded);
        }
        self.phandles[self.phandle_count] = Some(SeenPhandle { node_id, value });
        self.phandle_count += 1;
        Ok(())
    }

    fn claim(&mut self, range: PhysicalRange) -> Result<(), Error> {
        if self.claimed[..self.claimed_count]
            .iter()
            .flatten()
            .any(|other| range.overlaps(*other))
        {
            return Err(Error::OverlappingResources);
        }
        if self.claimed_count == self.claimed.len() {
            return Err(Error::LimitExceeded);
        }
        self.claimed[self.claimed_count] = Some(range);
        self.claimed_count += 1;
        Ok(())
    }

    fn claim_interrupt(&mut self, interrupt: GicInterrupt) -> Result<(), Error> {
        if self.interrupt_ids[..self.interrupt_id_count].contains(&Some(interrupt.intid)) {
            return Err(Error::OverlappingResources);
        }
        if self.interrupt_id_count == self.interrupt_ids.len() {
            return Err(Error::LimitExceeded);
        }
        self.interrupt_ids[self.interrupt_id_count] = Some(interrupt.intid);
        self.interrupt_id_count += 1;
        Ok(())
    }
}

// Independent compatible-string families are accumulated before ambiguity is
// rejected; keeping each flag named makes that fail-closed check auditable.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Default)]
struct CompatibleKinds {
    gic: Option<GicVersion>,
    timer: bool,
    pci_ecam: bool,
    virtio_mmio: bool,
    psci: Option<PsciVersion>,
    uart: Option<UartKind>,
    fixed_clock: bool,
}

fn parse_compatible(value: &[u8]) -> Result<CompatibleKinds, Error> {
    let mut kinds = CompatibleKinds::default();
    for item in StringList::new(value)? {
        let item = item?;
        let gic = match item {
            "arm,cortex-a15-gic" | "arm,cortex-a7-gic" | "arm,gic-400" => Some(GicVersion::V2),
            "arm,gic-v3" => Some(GicVersion::V3),
            _ => None,
        };
        if let Some(version) = gic {
            if kinds.gic.is_some_and(|current| current != version) {
                return Err(Error::AmbiguousDevice);
            }
            kinds.gic = Some(version);
        }
        kinds.timer |= matches!(item, "arm,armv8-timer" | "arm,armv7-timer");
        kinds.pci_ecam |= item == "pci-host-ecam-generic";
        kinds.virtio_mmio |= item == "virtio,mmio";
        kinds.fixed_clock |= item == "fixed-clock";
        let psci = match item {
            "arm,psci-1.0" => Some(PsciVersion::V1_0),
            "arm,psci-0.2" => Some(PsciVersion::V0_2),
            _ => None,
        };
        if let Some(version) = psci {
            kinds.psci = Some(match (kinds.psci, version) {
                (Some(PsciVersion::V1_0), _) | (_, PsciVersion::V1_0) => PsciVersion::V1_0,
                _ => PsciVersion::V0_2,
            });
        }
        let uart = match item {
            "arm,pl011" => Some(UartKind::Pl011),
            "ns16550" | "ns16550a" => Some(UartKind::Ns16550),
            _ => None,
        };
        if let Some(kind) = uart {
            if kinds.uart.is_some_and(|current| current != kind) {
                return Err(Error::AmbiguousDevice);
            }
            kinds.uart = Some(kind);
        }
    }
    Ok(kinds)
}

struct StringList<'a> {
    remaining: &'a [u8],
}

impl<'a> StringList<'a> {
    fn new(value: &'a [u8]) -> Result<Self, Error> {
        if value.is_empty() || value.last() != Some(&0) {
            return Err(Error::InvalidString);
        }
        Ok(Self { remaining: value })
    }
}

impl<'a> Iterator for StringList<'a> {
    type Item = Result<&'a str, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let Some(end) = self.remaining.iter().position(|byte| *byte == 0) else {
            self.remaining = &[];
            return Some(Err(Error::InvalidString));
        };
        let value = &self.remaining[..end];
        self.remaining = &self.remaining[end + 1..];
        if value.is_empty() {
            return Some(Err(Error::InvalidString));
        }
        Some(str::from_utf8(value).map_err(|_| Error::InvalidString))
    }
}

struct RegIter<'a> {
    value: &'a [u8],
    cursor: usize,
    address_cells: u32,
    size_cells: u32,
}

impl<'a> RegIter<'a> {
    fn new(value: &'a [u8], address_cells: u32, size_cells: u32) -> Result<Self, Error> {
        if !(1..=2).contains(&address_cells) || !(1..=2).contains(&size_cells) {
            return Err(Error::UnsupportedCells);
        }
        let tuple_cells = address_cells
            .checked_add(size_cells)
            .ok_or(Error::UnsupportedCells)?;
        let tuple_bytes = usize::try_from(tuple_cells)
            .map_err(|_| Error::UnsupportedCells)?
            .checked_mul(4)
            .ok_or(Error::InvalidProperty)?;
        if value.is_empty() || !value.len().is_multiple_of(tuple_bytes) {
            return Err(Error::InvalidProperty);
        }
        Ok(Self {
            value,
            cursor: 0,
            address_cells,
            size_cells,
        })
    }

    fn next_range(&mut self) -> Result<Option<PhysicalRange>, Error> {
        if self.cursor == self.value.len() {
            return Ok(None);
        }
        let base = read_cells(self.value, &mut self.cursor, self.address_cells)?;
        let byte_len = read_cells(self.value, &mut self.cursor, self.size_cells)?;
        PhysicalRange::checked(base, byte_len).map(Some)
    }
}

fn parse_header(blob: &[u8]) -> Result<Header<'_>, Error> {
    if blob.len() < HEADER_BYTES {
        return Err(Error::Truncated);
    }
    if read_be_u32(blob, 0)? != FDT_MAGIC {
        return Err(Error::BadMagic);
    }
    let total_size = usize_from_header(blob, 4)?;
    if total_size > MAX_BLOB_BYTES {
        return Err(Error::BlobTooLarge);
    }
    if total_size < HEADER_BYTES || total_size > blob.len() {
        return Err(Error::InvalidHeader);
    }
    let structure_offset = usize_from_header(blob, 8)?;
    let strings_offset = usize_from_header(blob, 12)?;
    let reservations_offset = usize_from_header(blob, 16)?;
    let version = read_be_u32(blob, 20)?;
    let last_compatible = read_be_u32(blob, 24)?;
    if version != FDT_VERSION || last_compatible > FDT_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let strings_size = usize_from_header(blob, 32)?;
    let structure_size = usize_from_header(blob, 36)?;
    if !structure_offset.is_multiple_of(4)
        || !reservations_offset.is_multiple_of(8)
        || structure_offset < HEADER_BYTES
        || strings_offset < HEADER_BYTES
        || reservations_offset < HEADER_BYTES
        || structure_size < 12
        || strings_size == 0
    {
        return Err(Error::InvalidHeader);
    }
    let structure_end = structure_offset
        .checked_add(structure_size)
        .ok_or(Error::InvalidHeader)?;
    let strings_end = strings_offset
        .checked_add(strings_size)
        .ok_or(Error::InvalidHeader)?;
    if structure_end > total_size || strings_end > total_size {
        return Err(Error::InvalidHeader);
    }
    ensure_no_overlap(
        structure_offset,
        structure_size,
        strings_offset,
        strings_size,
    )?;
    Ok(Header {
        structure: &blob[structure_offset..structure_end],
        strings: &blob[strings_offset..strings_end],
        reservations_offset,
        total_size,
        structure_offset,
        strings_offset,
    })
}

fn ensure_no_overlap(
    first_offset: usize,
    first_len: usize,
    second_offset: usize,
    second_len: usize,
) -> Result<(), Error> {
    let first_end = first_offset
        .checked_add(first_len)
        .ok_or(Error::InvalidHeader)?;
    let second_end = second_offset
        .checked_add(second_len)
        .ok_or(Error::InvalidHeader)?;
    if first_offset < second_end && second_offset < first_end {
        Err(Error::OverlappingBlocks)
    } else {
        Ok(())
    }
}

fn usize_from_header(blob: &[u8], offset: usize) -> Result<usize, Error> {
    usize::try_from(read_be_u32(blob, offset)?).map_err(|_| Error::InvalidHeader)
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::Truncated)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u32::from_be_bytes(value))
}

fn read_be_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let end = offset.checked_add(8).ok_or(Error::Truncated)?;
    let value: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u64::from_be_bytes(value))
}

fn be_u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    read_be_u32(bytes, offset).map_err(|_| Error::InvalidProperty)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, Error> {
    let value = read_be_u32(bytes, *cursor)?;
    *cursor = cursor.checked_add(4).ok_or(Error::Truncated)?;
    Ok(value)
}

fn take_padded<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], Error> {
    let end = cursor.checked_add(len).ok_or(Error::Truncated)?;
    let value = bytes.get(*cursor..end).ok_or(Error::Truncated)?;
    let padded_end = align_up_4(end).ok_or(Error::Truncated)?;
    let _padding = bytes.get(end..padded_end).ok_or(Error::Truncated)?;
    *cursor = padded_end;
    Ok(value)
}

fn take_padded_cstr<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], Error> {
    let remaining = bytes.get(*cursor..).ok_or(Error::Truncated)?;
    let length = remaining
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::InvalidNodeName)?;
    let value = &remaining[..length];
    let consumed = length.checked_add(1).ok_or(Error::Truncated)?;
    let end = cursor.checked_add(consumed).ok_or(Error::Truncated)?;
    let padded_end = align_up_4(end).ok_or(Error::Truncated)?;
    let padding = bytes.get(end..padded_end).ok_or(Error::Truncated)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidNodeName);
    }
    *cursor = padded_end;
    Ok(value)
}

fn align_up_4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn string_at(strings: &[u8], offset: usize) -> Result<&[u8], Error> {
    let remaining = strings.get(offset..).ok_or(Error::InvalidPropertyName)?;
    let length = remaining
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::InvalidPropertyName)?;
    if length == 0 {
        return Err(Error::InvalidPropertyName);
    }
    Ok(&remaining[..length])
}

fn validate_node_name(name: &[u8], root: bool) -> Result<(), Error> {
    if root {
        return if name.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidNodeName)
        };
    }
    if name.is_empty()
        || name.len() > 127
        || name.contains(&b'/')
        || name.iter().any(|byte| {
            !matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b','
                    | b'.'
                    | b'_'
                    | b'+'
                    | b'-'
                    | b'@'
            )
        })
    {
        Err(Error::InvalidNodeName)
    } else {
        Ok(())
    }
}

fn validate_property_name(name: &[u8]) -> Result<(), Error> {
    if name.len() > 63
        || name.iter().any(|byte| {
            !matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b','
                    | b'.'
                    | b'_'
                    | b'+'
                    | b'?'
                    | b'#'
                    | b'-'
            )
        })
    {
        Err(Error::InvalidPropertyName)
    } else {
        Ok(())
    }
}

fn single_u32(value: &[u8]) -> Result<u32, Error> {
    if value.len() != 4 {
        return Err(Error::InvalidProperty);
    }
    be_u32_at(value, 0)
}

fn single_string(value: &[u8]) -> Result<&str, Error> {
    if value.is_empty() || value.last() != Some(&0) || value[..value.len() - 1].contains(&0) {
        return Err(Error::InvalidString);
    }
    str::from_utf8(&value[..value.len() - 1]).map_err(|_| Error::InvalidString)
}

fn validate_absolute_path(path: &str) -> Result<(), Error> {
    if path.len() < 2
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.split('/').skip(1).any(|component| {
            component.is_empty()
                || component.len() > 127
                || validate_node_name(component.as_bytes(), false).is_err()
        })
    {
        Err(Error::InvalidString)
    } else {
        Ok(())
    }
}

fn validate_alias_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 63
        || name.as_bytes().iter().any(|byte| {
            !matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b',' | b'.' | b'_' | b'+' | b'-')
        })
    {
        Err(Error::InvalidString)
    } else {
        Ok(())
    }
}

fn parse_status(value: Option<&[u8]>) -> Result<bool, Error> {
    let Some(value) = value else {
        return Ok(true);
    };
    Ok(matches!(single_string(value)?, "ok" | "okay"))
}

fn read_cells(value: &[u8], cursor: &mut usize, cells: u32) -> Result<u64, Error> {
    if !(1..=2).contains(&cells) {
        return Err(Error::UnsupportedCells);
    }
    let mut result = 0u64;
    for _ in 0..cells {
        result = (result << 32) | u64::from(be_u32_at(value, *cursor)?);
        *cursor = cursor.checked_add(4).ok_or(Error::InvalidProperty)?;
    }
    Ok(result)
}

fn require_alignment(range: PhysicalRange, alignment: u64) -> Result<(), Error> {
    if !range.base.is_multiple_of(alignment) || !range.byte_len.is_multiple_of(alignment) {
        Err(Error::InvalidAlignment)
    } else {
        Ok(())
    }
}

fn interrupt_tuple_count(value: &[u8]) -> Result<usize, Error> {
    if value.is_empty() || !value.len().is_multiple_of(12) {
        return Err(Error::InvalidInterrupt);
    }
    Ok(value.len() / 12)
}

fn ensure_interrupt_parent(parent: u32, gic: Gic) -> Result<(), Error> {
    if parent == gic.phandle {
        Ok(())
    } else {
        Err(Error::UnsupportedInterruptParent)
    }
}

fn decode_gic_interrupt(value: &[u8], cursor: &mut usize) -> Result<GicInterrupt, Error> {
    let raw_kind = be_u32_at(value, *cursor)?;
    *cursor += 4;
    let number = be_u32_at(value, *cursor)?;
    *cursor += 4;
    let flags = be_u32_at(value, *cursor)?;
    *cursor += 4;
    if flags & !0x0000_ff0f != 0 {
        return Err(Error::InvalidInterrupt);
    }
    let electrical = flags & 0x0f;
    let (trigger, polarity) = match electrical {
        1 => (InterruptTrigger::Edge, InterruptPolarity::ActiveHigh),
        2 => (InterruptTrigger::Edge, InterruptPolarity::ActiveLow),
        4 => (InterruptTrigger::Level, InterruptPolarity::ActiveHigh),
        8 => (InterruptTrigger::Level, InterruptPolarity::ActiveLow),
        _ => return Err(Error::InvalidInterrupt),
    };
    let ppi_cpu_mask = u8::try_from((flags >> 8) & 0xff).map_err(|_| Error::InvalidInterrupt)?;
    let (kind, intid) = match raw_kind {
        0 if number <= 987 && ppi_cpu_mask == 0 => (InterruptKind::Spi, number + 32),
        1 if number <= 15 => (InterruptKind::Ppi, number + 16),
        _ => return Err(Error::InvalidInterrupt),
    };
    Ok(GicInterrupt {
        kind,
        intid,
        trigger,
        polarity,
        ppi_cpu_mask,
    })
}

fn decode_pci_window(
    high: u32,
    child_address: u64,
    parent_address: u64,
    size: u64,
) -> Result<PciWindow, Error> {
    if high & !0x4300_0000 != 0 {
        return Err(Error::InvalidPci);
    }
    let space_code = (high >> 24) & 0x03;
    let prefetchable = high & 0x4000_0000 != 0;
    let space = match space_code {
        1 if !prefetchable => PciSpace::Io,
        2 => PciSpace::Memory32,
        3 => PciSpace::Memory64,
        _ => return Err(Error::InvalidPci),
    };
    let child_end = child_address.checked_add(size).ok_or(Error::InvalidPci)?;
    if matches!(space, PciSpace::Io | PciSpace::Memory32)
        && (child_address > u64::from(u32::MAX) || child_end > u64::from(u32::MAX) + 1)
    {
        return Err(Error::InvalidPci);
    }
    Ok(PciWindow {
        space,
        prefetchable,
        child_address,
        parent: PhysicalRange::checked(parent_address, size)?,
    })
}

fn same_pci_space_domain(first: PciSpace, second: PciSpace) -> bool {
    matches!((first, second), (PciSpace::Io, PciSpace::Io))
        || (!matches!(first, PciSpace::Io) && !matches!(second, PciSpace::Io))
}

fn child_ranges_overlap(first: u64, first_len: u64, second: u64, second_len: u64) -> bool {
    first.checked_add(first_len).is_none_or(|first_end| {
        second
            .checked_add(second_len)
            .is_none_or(|second_end| first < second_end && second < first_end)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn ok<T, E>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|_| unreachable!())
    }

    fn some<T>(value: Option<T>) -> T {
        value.unwrap_or_else(|| unreachable!())
    }

    const NAMES: &[&str] = &[
        "#address-cells",
        "#size-cells",
        "compatible",
        "device_type",
        "reg",
        "interrupt-parent",
        "interrupt-controller",
        "#interrupt-cells",
        "phandle",
        "interrupts",
        "stdout-path",
        "ranges",
        "bus-range",
        "status",
        "method",
        "clock-frequency",
        "clocks",
        "#clock-cells",
        "current-speed",
        "reg-shift",
        "reg-io-width",
        "serial0",
        "_odd",
    ];

    struct Dtb {
        structure: Vec<u8>,
        strings: Vec<u8>,
        reservations: Vec<(u64, u64)>,
    }

    impl Dtb {
        fn new() -> Self {
            let mut strings = Vec::new();
            for name in NAMES {
                strings.extend_from_slice(name.as_bytes());
                strings.push(0);
            }
            Self {
                structure: Vec::new(),
                strings,
                reservations: Vec::new(),
            }
        }

        fn token(&mut self, token: u32) {
            self.structure.extend_from_slice(&token.to_be_bytes());
        }

        fn begin(&mut self, name: &str) {
            self.token(FDT_BEGIN_NODE);
            self.structure.extend_from_slice(name.as_bytes());
            self.structure.push(0);
            while !self.structure.len().is_multiple_of(4) {
                self.structure.push(0);
            }
        }

        fn end_node(&mut self) {
            self.token(FDT_END_NODE);
        }

        fn prop(&mut self, name: &str, value: &[u8]) {
            let offset = self
                .strings
                .windows(name.len() + 1)
                .position(|window| window == [name.as_bytes(), &[0]].concat())
                .unwrap_or_else(|| unreachable!());
            self.token(FDT_PROP);
            self.structure
                .extend_from_slice(&ok(u32::try_from(value.len())).to_be_bytes());
            self.structure
                .extend_from_slice(&ok(u32::try_from(offset)).to_be_bytes());
            self.structure.extend_from_slice(value);
            while !self.structure.len().is_multiple_of(4) {
                self.structure.push(0);
            }
        }

        fn cell_prop(&mut self, name: &str, value: u32) {
            self.prop(name, &value.to_be_bytes());
        }

        fn reserve(&mut self, address: u64, size: u64) {
            self.reservations.push((address, size));
        }

        fn finish(mut self) -> Vec<u8> {
            self.token(FDT_END);
            let reserve_offset = HEADER_BYTES;
            let reserve_bytes = (self.reservations.len() + 1) * 16;
            let structure_offset = reserve_offset + reserve_bytes;
            let strings_offset = structure_offset + self.structure.len();
            let total_size = strings_offset + self.strings.len();
            let padded_total = (total_size + 3) & !3;
            let mut blob = vec![0; padded_total];
            put_u32(&mut blob, 0, FDT_MAGIC);
            put_u32(&mut blob, 4, ok(u32::try_from(padded_total)));
            put_u32(&mut blob, 8, ok(u32::try_from(structure_offset)));
            put_u32(&mut blob, 12, ok(u32::try_from(strings_offset)));
            put_u32(&mut blob, 16, ok(u32::try_from(reserve_offset)));
            put_u32(&mut blob, 20, FDT_VERSION);
            put_u32(&mut blob, 24, FDT_VERSION);
            put_u32(&mut blob, 32, ok(u32::try_from(self.strings.len())));
            put_u32(&mut blob, 36, ok(u32::try_from(self.structure.len())));
            for (index, (address, size)) in self.reservations.iter().copied().enumerate() {
                let offset = reserve_offset + index * 16;
                blob[offset..offset + 8].copy_from_slice(&address.to_be_bytes());
                blob[offset + 8..offset + 16].copy_from_slice(&size.to_be_bytes());
            }
            blob[structure_offset..strings_offset].copy_from_slice(&self.structure);
            blob[strings_offset..strings_offset + self.strings.len()]
                .copy_from_slice(&self.strings);
            blob
        }
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn cells(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect()
    }

    fn base_tree() -> Dtb {
        base_tree_with_interrupt_parent(1)
    }

    fn base_tree_with_interrupt_parent(interrupt_parent: u32) -> Dtb {
        // Version 3 machines leave the private-interrupt CPU mask empty.
        base_tree_with(interrupt_parent, 4)
    }

    fn base_tree_with(interrupt_parent: u32, timer_flags: u32) -> Dtb {
        let mut dtb = Dtb::new();
        dtb.begin("");
        dtb.cell_prop("#address-cells", 2);
        dtb.cell_prop("#size-cells", 2);
        dtb.cell_prop("interrupt-parent", interrupt_parent);

        dtb.begin("chosen");
        dtb.prop("stdout-path", b"/pl011@9000000:115200n8\0");
        dtb.end_node();

        dtb.begin("psci");
        dtb.prop("compatible", b"arm,psci-1.0\0arm,psci-0.2\0");
        dtb.prop("method", b"hvc\0");
        dtb.end_node();

        dtb.begin("pl011@9000000");
        dtb.prop("compatible", b"arm,pl011\0arm,primecell\0");
        dtb.prop("reg", &cells(&[0, 0x0900_0000, 0, 0x1000]));
        dtb.prop("clocks", &cells(&[8, 8]));
        dtb.cell_prop("current-speed", 115_200);
        dtb.prop("interrupts", &cells(&[0, 1, 4]));
        dtb.end_node();

        dtb.begin("clk24mhz");
        dtb.prop("compatible", b"fixed-clock\0");
        dtb.cell_prop("#clock-cells", 0);
        dtb.cell_prop("clock-frequency", 24_000_000);
        dtb.cell_prop("phandle", 8);
        dtb.end_node();

        dtb.begin("memory@40000000");
        dtb.prop("device_type", b"memory\0");
        dtb.prop("reg", &cells(&[0, 0x4000_0000, 0, 0x2000_0000]));
        dtb.end_node();

        dtb.begin("intc@8000000");
        dtb.prop("compatible", b"arm,gic-v3\0");
        dtb.prop("interrupt-controller", b"");
        dtb.cell_prop("#interrupt-cells", 3);
        dtb.cell_prop("phandle", 1);
        dtb.prop(
            "reg",
            &cells(&[
                0,
                0x0800_0000,
                0,
                0x0001_0000,
                0,
                0x080a_0000,
                0,
                0x0002_0000,
            ]),
        );
        dtb.end_node();

        dtb.begin("timer");
        dtb.prop("compatible", b"arm,armv8-timer\0");
        dtb.prop(
            "interrupts",
            &cells(&[
                1,
                13,
                timer_flags,
                1,
                14,
                timer_flags,
                1,
                11,
                timer_flags,
                1,
                10,
                timer_flags,
            ]),
        );
        dtb.end_node();

        dtb.begin("virtio_mmio@a000000");
        dtb.prop("compatible", b"virtio,mmio\0");
        dtb.prop("reg", &cells(&[0, 0x0a00_0000, 0, 0x200]));
        dtb.prop("interrupts", &cells(&[0, 16, 1]));
        dtb.end_node();
        dtb
    }

    #[test]
    fn the_private_interrupt_cpu_mask_separates_the_two_gic_generations() {
        // The third interrupt cell carries a CPU mask in bits 15:8. It names
        // the version 2 CPU interfaces a private interrupt reaches, and
        // version 3, which routes by affinity through the redistributor
        // instead, leaves it empty. A consumer that requires the mask to name
        // a CPU therefore rejects every version 3 machine, so the two shapes
        // are pinned here against each other.
        let mut version_three = base_tree();
        version_three.end_node();
        let blob = version_three.finish();
        let inventory = ok(discover(&blob));
        let timer = some(inventory.timer());
        let physical = some(timer.interrupts().nth(1));
        assert_eq!(physical.intid(), 30);
        assert_eq!(physical.kind(), InterruptKind::Ppi);
        assert_eq!(physical.ppi_cpu_mask(), 0);

        // The same four routes as a version 2 machine describes them, with
        // one CPU named in every mask.
        let mut version_two = base_tree_with(1, 0x104);
        version_two.end_node();
        let blob = version_two.finish();
        let inventory = ok(discover(&blob));
        let timer = some(inventory.timer());
        let physical = some(timer.interrupts().nth(1));
        assert_eq!(physical.intid(), 30);
        assert_eq!(physical.kind(), InterruptKind::Ppi);
        assert_eq!(physical.ppi_cpu_mask(), 1);
    }

    #[test]
    fn discovers_cloud_essentials_without_defaults() {
        let mut dtb = base_tree();
        dtb.begin("pcie@10000000");
        dtb.prop("compatible", b"pci-host-ecam-generic\0");
        dtb.prop("device_type", b"pci\0");
        dtb.cell_prop("#address-cells", 3);
        dtb.cell_prop("#size-cells", 2);
        dtb.prop("reg", &cells(&[0, 0x1000_0000, 0, 0x0100_0000]));
        dtb.prop("bus-range", &cells(&[0, 15]));
        dtb.prop(
            "ranges",
            &cells(&[0x0200_0000, 0, 0x4000_0000, 0, 0x6000_0000, 0, 0x0100_0000]),
        );
        dtb.end_node();
        dtb.end_node();
        let blob = dtb.finish();

        let inventory = ok(discover(&blob));
        let stdout = some(inventory.stdout_path());
        assert_eq!(stdout.device(), "/pl011@9000000");
        assert_eq!(stdout.options(), Some("115200n8"));
        assert_eq!(stdout.resolved_device(), Some("/pl011@9000000"));
        assert_eq!(some(inventory.psci()).conduit(), PsciConduit::Hvc);
        let uart = some(inventory.stdout_uart());
        assert_eq!(uart.kind(), UartKind::Pl011);
        assert_eq!(uart.clock_hz(), Some(24_000_000));
        assert_eq!(uart.interrupt().intid(), 33);
        assert_eq!(
            inventory.memory().collect::<Vec<_>>(),
            [PhysicalRange {
                base: 0x4000_0000,
                byte_len: 0x2000_0000
            }]
        );
        let gic = some(inventory.gic());
        assert_eq!(gic.version(), GicVersion::V3);
        assert_eq!(gic.regions().count(), 2);
        assert_eq!(some(some(inventory.timer()).virtual_timer()).intid(), 27);
        let virtio = some(inventory.virtio_mmio_devices().next());
        assert_eq!(virtio.registers().base(), 0x0a00_0000);
        assert_eq!(virtio.interrupt().intid(), 48);
        let host = some(inventory.pci_hosts().next());
        assert_eq!(some(host.bus_range()).last(), 15);
        assert_eq!(some(host.windows().next()).parent().base(), 0x6000_0000);
    }

    #[test]
    fn resolves_repeated_uart_fixed_clock_references_uniquely() {
        let mut dtb = base_tree();
        dtb.begin("virtio_mmio@a000200");
        dtb.prop("compatible", b"virtio,mmio\0");
        dtb.prop("reg", &cells(&[0, 0x0a00_0200, 0, 0x200]));
        dtb.prop("interrupts", &cells(&[0, 17, 1]));
        dtb.end_node();
        dtb.end_node();
        let blob = dtb.finish();
        let inventory = ok(discover(&blob));
        assert_eq!(some(inventory.stdout_uart()).clock_hz(), Some(24_000_000));
        assert_eq!(inventory.virtio_mmio_devices().count(), 2);
    }

    #[test]
    fn rejects_unknown_malformed_and_colliding_fixed_clocks() {
        let mut unknown = base_tree();
        unknown.end_node();
        let mut unknown = unknown.finish();
        let references = cells(&[8, 8]);
        let offset = some(
            unknown
                .windows(references.len())
                .position(|window| window == references),
        );
        put_u32(&mut unknown, offset + 4, 9);
        assert_eq!(discover(&unknown), Err(Error::InvalidPhandle));

        let mut malformed = Dtb::new();
        malformed.begin("");
        malformed.cell_prop("#address-cells", 2);
        malformed.cell_prop("#size-cells", 2);
        malformed.begin("uart@9000000");
        malformed.prop("compatible", b"arm,pl011\0");
        malformed.prop("reg", &cells(&[0, 0x0900_0000, 0, 0x1000]));
        malformed.prop("clocks", &[0, 0, 8]);
        malformed.end_node();
        malformed.end_node();
        assert_eq!(discover(&malformed.finish()), Err(Error::InvalidProperty));

        let mut colliding = Dtb::new();
        colliding.begin("");
        for name in ["clock-a", "clock-b"] {
            colliding.begin(name);
            colliding.prop("compatible", b"fixed-clock\0");
            colliding.cell_prop("#clock-cells", 0);
            colliding.cell_prop("clock-frequency", 24_000_000);
            colliding.cell_prop("phandle", 8);
            colliding.end_node();
        }
        colliding.end_node();
        assert_eq!(discover(&colliding.finish()), Err(Error::InvalidPhandle));
    }

    #[test]
    fn rejects_untranslated_supported_children_and_honors_disabled_ancestors() {
        let mut nested = Dtb::new();
        nested.begin("");
        nested.cell_prop("#address-cells", 2);
        nested.cell_prop("#size-cells", 2);
        nested.begin("soc");
        nested.cell_prop("#address-cells", 2);
        nested.cell_prop("#size-cells", 2);
        nested.prop("ranges", b"");
        nested.begin("virtio@a000000");
        nested.prop("compatible", b"virtio,mmio\0");
        nested.end_node();
        nested.end_node();
        nested.end_node();
        assert_eq!(
            discover(&nested.finish()),
            Err(Error::UnsupportedTranslation)
        );

        let mut disabled = Dtb::new();
        disabled.begin("");
        disabled.begin("soc");
        disabled.prop("status", b"disabled\0");
        disabled.begin("virtio@a000000");
        disabled.prop("compatible", b"virtio,mmio\0");
        disabled.end_node();
        disabled.end_node();
        disabled.end_node();
        let blob = disabled.finish();
        let inventory = ok(discover(&blob));
        assert_eq!(inventory.virtio_mmio_devices().count(), 0);
    }

    #[test]
    fn accepts_gicv2_and_unresolved_stdout_alias() {
        let mut dtb = Dtb::new();
        dtb.begin("");
        dtb.cell_prop("#address-cells", 2);
        dtb.cell_prop("#size-cells", 2);
        dtb.begin("chosen");
        dtb.prop("stdout-path", b"serial0:9600n8\0");
        dtb.end_node();
        dtb.begin("aliases");
        dtb.prop("serial0", b"/uart@9000000\0");
        dtb.end_node();
        dtb.begin("uart@9000000");
        dtb.prop("compatible", b"ns16550a\0");
        dtb.prop("reg", &cells(&[0, 0x0900_0000, 0, 0x1000]));
        dtb.cell_prop("reg-shift", 2);
        dtb.cell_prop("reg-io-width", 4);
        dtb.cell_prop("interrupt-parent", 4);
        dtb.prop("interrupts", &cells(&[0, 1, 4]));
        dtb.end_node();
        dtb.begin("intc@8000000");
        dtb.prop("compatible", b"arm,cortex-a15-gic\0");
        dtb.prop("interrupt-controller", b"");
        dtb.cell_prop("#interrupt-cells", 3);
        dtb.cell_prop("phandle", 4);
        dtb.prop(
            "reg",
            &cells(&[0, 0x800_0000, 0, 0x10000, 0, 0x801_0000, 0, 0x10000]),
        );
        dtb.end_node();
        dtb.end_node();
        let blob = dtb.finish();
        let inventory = ok(discover(&blob));
        assert_eq!(some(inventory.gic()).version(), GicVersion::V2);
        assert!(!some(inventory.stdout_path()).is_absolute());
        assert_eq!(
            some(inventory.stdout_path()).resolved_device(),
            Some("/uart@9000000")
        );
        assert_eq!(some(inventory.stdout_uart()).kind(), UartKind::Ns16550);
    }

    #[test]
    fn rejects_every_truncation_boundary() {
        let mut dtb = base_tree();
        dtb.end_node();
        let blob = dtb.finish();
        assert!(discover(&blob).is_ok());
        for length in 0..blob.len() {
            assert!(
                discover(&blob[..length]).is_err(),
                "accepted truncation at {length}"
            );
        }
    }

    #[test]
    fn accepts_exact_blob_ceiling_and_rejects_one_byte_more() {
        let mut exact = Dtb::new();
        exact.begin("");
        exact.end_node();
        let mut exact = exact.finish();
        exact.resize(MAX_BLOB_BYTES, 0);
        put_u32(&mut exact, 4, ok(u32::try_from(MAX_BLOB_BYTES)));
        assert!(discover(&exact).is_ok());

        exact.push(0);
        put_u32(&mut exact, 4, ok(u32::try_from(MAX_BLOB_BYTES + 1)));
        assert_eq!(discover(&exact), Err(Error::BlobTooLarge));
    }

    #[test]
    fn accepts_unaligned_total_size_with_aligned_internal_blocks() {
        let mut dtb = Dtb::new();
        dtb.begin("");
        dtb.end_node();
        let mut blob = dtb.finish();
        let strings_offset = ok(usize::try_from(ok(read_be_u32(&blob, 12))));
        let strings_size = ok(usize::try_from(ok(read_be_u32(&blob, 32))));
        let total_size = strings_offset + strings_size;
        assert!(!total_size.is_multiple_of(4));
        blob.truncate(total_size);
        put_u32(&mut blob, 4, ok(u32::try_from(total_size)));
        assert!(discover(&blob).is_ok());
    }

    #[test]
    fn rejects_header_block_overlap_and_unterminated_reservations() {
        let mut dtb = base_tree();
        dtb.end_node();
        let blob = dtb.finish();
        let mut overlapping = blob.clone();
        let structure = ok(read_be_u32(&overlapping, 8));
        put_u32(&mut overlapping, 12, structure);
        assert_eq!(discover(&overlapping), Err(Error::OverlappingBlocks));

        let mut unterminated = blob;
        unterminated[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&0x1000u64.to_be_bytes());
        unterminated[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&0x1000u64.to_be_bytes());
        assert_eq!(
            discover(&unterminated),
            Err(Error::UnterminatedReservations)
        );
    }

    #[test]
    fn inventories_reservations_and_rejects_reservation_overlap() {
        let mut valid = Dtb::new();
        valid.reserve(0x4000_0000, 0x2000);
        valid.reserve(0x5000_0000, 0x1000);
        valid.begin("");
        valid.end_node();
        let valid_blob = valid.finish();
        assert_eq!(
            ok(discover(&valid_blob)).reservations().collect::<Vec<_>>(),
            [
                PhysicalRange {
                    base: 0x4000_0000,
                    byte_len: 0x2000,
                },
                PhysicalRange {
                    base: 0x5000_0000,
                    byte_len: 0x1000,
                },
            ]
        );

        let mut overlapping = Dtb::new();
        overlapping.reserve(0x4000_0000, 0x2000);
        overlapping.reserve(0x4000_1000, 0x1000);
        overlapping.begin("");
        overlapping.end_node();
        assert_eq!(
            discover(&overlapping.finish()),
            Err(Error::OverlappingResources)
        );
    }

    #[test]
    fn rejects_bad_string_offset_and_compatible_encoding() {
        let mut bad_offset = Dtb::new();
        bad_offset.begin("");
        bad_offset.cell_prop("#address-cells", 2);
        bad_offset.end_node();
        let mut blob = bad_offset.finish();
        let structure = ok(usize::try_from(ok(read_be_u32(&blob, 8))));
        put_u32(&mut blob, structure + 16, u32::MAX);
        assert_eq!(discover(&blob), Err(Error::InvalidPropertyName));

        let mut bad_compatible = Dtb::new();
        bad_compatible.begin("");
        bad_compatible.begin("device");
        bad_compatible.prop("compatible", b"virtio,mmio");
        bad_compatible.end_node();
        bad_compatible.end_node();
        assert_eq!(
            discover(&bad_compatible.finish()),
            Err(Error::InvalidString)
        );
    }

    #[test]
    fn rejects_depth_and_cell_limits() {
        let mut too_deep = Dtb::new();
        too_deep.begin("");
        for _ in 1..=MAX_DEPTH {
            too_deep.begin("nested");
        }
        for _ in 0..=MAX_DEPTH {
            too_deep.end_node();
        }
        assert_eq!(discover(&too_deep.finish()), Err(Error::LimitExceeded));

        let mut bad_cells = Dtb::new();
        bad_cells.begin("");
        bad_cells.cell_prop("#address-cells", 4);
        bad_cells.end_node();
        assert_eq!(discover(&bad_cells.finish()), Err(Error::UnsupportedCells));
    }

    #[test]
    fn rejects_duplicate_discovered_interrupts() {
        let mut dtb = base_tree();
        dtb.end_node();
        let mut blob = dtb.finish();
        let needle = cells(&[0, 16, 1]);
        let offset = some(
            blob.windows(needle.len())
                .position(|window| window == needle),
        );
        put_u32(&mut blob, offset + 4, 1);
        assert_eq!(discover(&blob), Err(Error::OverlappingResources));
    }

    #[test]
    fn rejects_duplicate_properties_and_sibling_nodes() {
        let mut duplicate_property = Dtb::new();
        duplicate_property.begin("");
        duplicate_property.cell_prop("#address-cells", 2);
        duplicate_property.cell_prop("#address-cells", 2);
        duplicate_property.end_node();
        assert_eq!(
            discover(&duplicate_property.finish()),
            Err(Error::DuplicateProperty)
        );

        let mut duplicate_node = Dtb::new();
        duplicate_node.begin("");
        duplicate_node.begin("chosen");
        duplicate_node.end_node();
        duplicate_node.begin("chosen");
        duplicate_node.end_node();
        duplicate_node.end_node();
        assert_eq!(
            discover(&duplicate_node.finish()),
            Err(Error::InvalidNodeName)
        );
    }

    #[test]
    fn rejects_properties_after_children() {
        let mut dtb = Dtb::new();
        dtb.begin("");
        dtb.begin("child");
        dtb.end_node();
        dtb.cell_prop("#address-cells", 2);
        dtb.end_node();
        assert_eq!(discover(&dtb.finish()), Err(Error::PropertyAfterChild));
    }

    #[test]
    fn rejects_overlapping_memory_and_mmio() {
        let mut dtb = Dtb::new();
        dtb.begin("");
        dtb.cell_prop("#address-cells", 2);
        dtb.cell_prop("#size-cells", 2);
        dtb.cell_prop("interrupt-parent", 1);
        dtb.begin("memory@8000000");
        dtb.prop("device_type", b"memory\0");
        dtb.prop("reg", &cells(&[0, 0x0800_0000, 0, 0x1000_0000]));
        dtb.end_node();
        dtb.begin("intc@8000000");
        dtb.prop("compatible", b"arm,gic-v3\0");
        dtb.prop("interrupt-controller", b"");
        dtb.cell_prop("#interrupt-cells", 3);
        dtb.cell_prop("phandle", 1);
        dtb.prop(
            "reg",
            &cells(&[0, 0x0800_0000, 0, 0x10000, 0, 0x080a_0000, 0, 0x20000]),
        );
        dtb.end_node();
        dtb.end_node();
        assert_eq!(discover(&dtb.finish()), Err(Error::OverlappingResources));
    }

    #[test]
    fn rejects_overflowing_and_out_of_domain_pci_child_windows() {
        assert_eq!(
            decode_pci_window(0x0300_0000, u64::MAX - 0xfff, 0x4000_0000, 0x2000),
            Err(Error::InvalidPci)
        );
        assert_eq!(
            decode_pci_window(0x0100_0000, 0xffff_f000, 0x3eff_0000, 0x2000),
            Err(Error::InvalidPci)
        );
        assert!(
            decode_pci_window(0x0300_0000, u64::from(u32::MAX) + 1, 0x8000_0000, 0x1000,).is_ok()
        );
    }

    #[test]
    fn rejects_wrong_interrupt_parent_and_corrupt_flags() {
        let mut wrong_parent = base_tree_with_interrupt_parent(2);
        wrong_parent.end_node();
        assert_eq!(
            discover(&wrong_parent.finish()),
            Err(Error::UnsupportedInterruptParent)
        );

        let mut bad_flags = Dtb::new();
        bad_flags.begin("");
        bad_flags.cell_prop("#address-cells", 2);
        bad_flags.cell_prop("#size-cells", 2);
        bad_flags.cell_prop("interrupt-parent", 1);
        bad_flags.begin("intc");
        bad_flags.prop("compatible", b"arm,gic-v3\0");
        bad_flags.prop("interrupt-controller", b"");
        bad_flags.cell_prop("#interrupt-cells", 3);
        bad_flags.cell_prop("phandle", 1);
        bad_flags.prop(
            "reg",
            &cells(&[
                0,
                0x0800_0000,
                0,
                0x0001_0000,
                0,
                0x0810_0000,
                0,
                0x0002_0000,
            ]),
        );
        bad_flags.end_node();
        bad_flags.begin("timer");
        bad_flags.prop("compatible", b"arm,armv8-timer\0");
        bad_flags.prop("interrupts", &cells(&[1, 11, 3]));
        bad_flags.end_node();
        bad_flags.end_node();
        assert_eq!(discover(&bad_flags.finish()), Err(Error::InvalidInterrupt));
    }

    #[test]
    fn accepts_opaque_property_padding_and_rejects_structure_tail() {
        let mut dtb = Dtb::new();
        dtb.begin("");
        dtb.prop("status", b"ok\0");
        dtb.end_node();
        let mut blob = dtb.finish();
        let structure = ok(usize::try_from(ok(read_be_u32(&blob, 8))));
        let property_padding = structure + 8 + 12 + 3;
        blob[property_padding] = 1;
        assert!(discover(&blob).is_ok());

        let mut dtb = Dtb::new();
        dtb.begin("");
        dtb.end_node();
        dtb.token(FDT_END);
        dtb.token(FDT_NOP);
        assert_eq!(discover(&dtb.finish()), Err(Error::InvalidNesting));
    }
}

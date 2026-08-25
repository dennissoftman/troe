//! Strict, allocation-free ACPI discovery over immutable byte slices.
//!
//! The caller obtains the RSDP address from the UEFI configuration table and
//! provides a stable [`AcpiMemory`] implementation. Parsing is read-only and
//! does not grant MMIO, PCI, DMA, or interrupt authority. All lengths,
//! checksums, physical extents, singleton tables, entry encodings, duplicate
//! identities, and ranges used by the x86 virtio-cloud contract are validated
//! before a typed view is returned.

use core::convert::TryFrom;

const RSDP_V1_BYTES: usize = 20;
const RSDP_V2_BYTES: usize = 36;
const SDT_HEADER_BYTES: usize = 36;
const MCFG_PREFIX_BYTES: usize = 8;
const MCFG_ENTRY_BYTES: usize = 16;
const MADT_PREFIX_BYTES: usize = 8;
const ECAM_BUS_BYTES: u64 = 1 << 20;
const APIC_MMIO_BYTES: u64 = 1 << 12;
const X86_PHYSICAL_LIMIT: u64 = 1 << 52;

/// Maximum accepted extended RSDP size, including future reserved bytes.
pub const MAX_RSDP_BYTES: usize = 64;
/// Maximum bytes accepted for any one ACPI system-description table.
pub const MAX_SDT_BYTES: usize = 1024 * 1024;
/// Maximum entries accepted from one RSDT or XSDT.
pub const MAX_ROOT_ENTRIES: usize = 256;
/// Maximum PCI ECAM allocations accepted from MCFG.
pub const MAX_MCFG_ENTRIES: usize = 64;
/// Maximum variable entries accepted from MADT.
pub const MAX_MADT_ENTRIES: usize = 512;
/// Maximum copied firmware regions accepted by [`CopiedAcpiMemory`].
pub const MAX_COPIED_REGIONS: usize = MAX_ROOT_ENTRIES + 4;

/// Stable fail-closed ACPI discovery failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcpiError {
    /// A required byte range was not present in the supplied input or memory.
    Truncated,
    /// An RSDP or SDT signature did not match its required value.
    InvalidSignature,
    /// The RSDP revision is reserved or unsupported.
    UnsupportedRevision,
    /// A declared table or entry length is invalid or exceeds a hard ceiling.
    InvalidLength,
    /// An ACPI checksum did not sum to zero.
    ChecksumMismatch,
    /// A physical address is zero, overflowing, misaligned, or outside x86-64.
    InvalidAddress,
    /// Reserved bytes/bits or a reserved flag encoding were nonzero.
    InvalidReservedField,
    /// A root, MCFG, or MADT entry count exceeded its hard ceiling.
    TooManyEntries,
    /// A physical table, singleton, controller, route, or identity repeats.
    DuplicateEntry,
    /// Two firmware tables or discovered hardware ranges overlap.
    OverlappingRange,
    /// A required MCFG table was not present.
    MissingMcfg,
    /// A required MADT table was not present.
    MissingMadt,
    /// The discovered x86 interrupt topology cannot support bounded boot.
    IncompleteInterruptTopology,
    /// A table uses a defined encoding this bounded cloud profile cannot use.
    UnsupportedEncoding,
}

/// Half-open physical byte range validated against the x86-64 address domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    start: u64,
    byte_len: u64,
}

impl PhysicalRange {
    fn new(start: u64, byte_len: u64, alignment: u64) -> Result<Self, AcpiError> {
        let end = start
            .checked_add(byte_len)
            .ok_or(AcpiError::InvalidAddress)?;
        if start == 0
            || byte_len == 0
            || !start.is_multiple_of(alignment)
            || end <= start
            || end > X86_PHYSICAL_LIMIT
        {
            return Err(AcpiError::InvalidAddress);
        }
        Ok(Self { start, byte_len })
    }

    /// First physical byte.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Number of bytes in the range.
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }

    /// First byte after the range.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.start + self.byte_len
    }

    /// Whether this range intersects another half-open range.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

/// Stable immutable physical-memory lookup used by ACPI parsers.
///
/// Implementations must return the same bytes for repeated requests during one
/// discovery transaction. Returning a larger slice is allowed; parsers consume
/// only `byte_len` bytes. Mapping firmware memory is an architecture/machine
/// responsibility and stays outside this safe parser.
pub trait AcpiMemory {
    /// Borrow at least `byte_len` bytes beginning at `physical_address`.
    fn region(&self, physical_address: u64, byte_len: usize) -> Option<&[u8]>;
}

/// One contiguous immutable physical-memory window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryWindow<'a> {
    range: PhysicalRange,
    bytes: &'a [u8],
}

impl<'a> MemoryWindow<'a> {
    /// Construct a checked window.
    ///
    /// # Errors
    ///
    /// Rejects a zero/out-of-domain base, an empty window, or a slice length
    /// that cannot be represented as an x86 physical range.
    pub fn new(physical_base: u64, bytes: &'a [u8]) -> Result<Self, AcpiError> {
        let byte_len = u64::try_from(bytes.len()).map_err(|_| AcpiError::InvalidLength)?;
        let range = PhysicalRange::new(physical_base, byte_len, 1)?;
        Ok(Self { range, bytes })
    }

    /// Complete mapped physical range.
    #[must_use]
    pub const fn range(self) -> PhysicalRange {
        self.range
    }
}

impl AcpiMemory for MemoryWindow<'_> {
    fn region(&self, physical_address: u64, byte_len: usize) -> Option<&[u8]> {
        let offset = physical_address.checked_sub(self.range.start)?;
        let offset = usize::try_from(offset).ok()?;
        let end = offset.checked_add(byte_len)?;
        self.bytes.get(offset..end)
    }
}

/// One immutable firmware-table copy keyed by its original physical address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopiedAcpiRegion<'a> {
    range: PhysicalRange,
    bytes: &'a [u8],
}

impl<'a> CopiedAcpiRegion<'a> {
    /// Describe a machine-owned copy without granting access to live firmware
    /// memory.
    ///
    /// # Errors
    ///
    /// Rejects zero/out-of-domain addresses and empty or overflowing copies.
    pub fn new(physical_address: u64, bytes: &'a [u8]) -> Result<Self, AcpiError> {
        let byte_len = u64::try_from(bytes.len()).map_err(|_| AcpiError::InvalidLength)?;
        Ok(Self {
            range: PhysicalRange::new(physical_address, byte_len, 1)?,
            bytes,
        })
    }

    /// Original physical extent represented by this stable copy.
    #[must_use]
    pub const fn range(self) -> PhysicalRange {
        self.range
    }
}

/// Bounded, non-overlapping set of machine-owned firmware-table copies.
///
/// This is the direct integration adapter for early boot: copy each table into
/// fixed-capacity machine storage, retain its firmware physical key, validate
/// this view, and then run discovery without further firmware-memory reads.
pub struct CopiedAcpiMemory<'a> {
    regions: &'a [CopiedAcpiRegion<'a>],
}

impl<'a> CopiedAcpiMemory<'a> {
    /// Validate a bounded set of physical-address-keyed copies.
    ///
    /// # Errors
    ///
    /// Rejects an excessive region count, duplicate keys, or overlapping
    /// represented physical extents.
    pub fn new(regions: &'a [CopiedAcpiRegion<'a>]) -> Result<Self, AcpiError> {
        if regions.len() > MAX_COPIED_REGIONS {
            return Err(AcpiError::TooManyEntries);
        }
        for (index, region) in regions.iter().copied().enumerate() {
            for previous in &regions[..index] {
                if region.range.start == previous.range.start {
                    return Err(AcpiError::DuplicateEntry);
                }
                if region.range.overlaps(previous.range) {
                    return Err(AcpiError::OverlappingRange);
                }
            }
        }
        Ok(Self { regions })
    }

    /// Number of stable copies in the inventory.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }
}

impl AcpiMemory for CopiedAcpiMemory<'_> {
    fn region(&self, physical_address: u64, byte_len: usize) -> Option<&[u8]> {
        let requested_len = u64::try_from(byte_len).ok()?;
        let requested_end = physical_address.checked_add(requested_len)?;
        self.regions.iter().find_map(|region| {
            if physical_address < region.range.start || requested_end > region.range.end() {
                return None;
            }
            let offset = usize::try_from(physical_address - region.range.start).ok()?;
            region.bytes.get(offset..offset.checked_add(byte_len)?)
        })
    }
}

/// Parsed ACPI Root System Description Pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rsdp {
    revision: u8,
    oem_id: [u8; 6],
    byte_len: u32,
    rsdt_address: u32,
    xsdt_address: Option<u64>,
}

impl Rsdp {
    /// Parse and checksum an RSDP v1 or v2+ byte sequence.
    ///
    /// # Errors
    ///
    /// Rejects truncation, bad signatures/checksums, the reserved revision 1,
    /// invalid OEM bytes, invalid lengths, and unusable root addresses.
    pub fn parse(bytes: &[u8]) -> Result<Self, AcpiError> {
        let v1 = take(bytes, 0, RSDP_V1_BYTES)?;
        if take_array::<8>(v1, 0)? != *b"RSD PTR " {
            return Err(AcpiError::InvalidSignature);
        }
        if !checksum_valid(v1) {
            return Err(AcpiError::ChecksumMismatch);
        }
        let oem_id = take_array::<6>(v1, 9)?;
        if !valid_oem_bytes(&oem_id) {
            return Err(AcpiError::InvalidReservedField);
        }
        let revision = v1[15];
        let rsdt_address = read_u32(v1, 16)?;
        match revision {
            0 => {
                if rsdt_address == 0 {
                    return Err(AcpiError::InvalidAddress);
                }
                Ok(Self {
                    revision,
                    oem_id,
                    byte_len: u32::try_from(RSDP_V1_BYTES).map_err(|_| AcpiError::InvalidLength)?,
                    rsdt_address,
                    xsdt_address: None,
                })
            }
            1 => Err(AcpiError::UnsupportedRevision),
            _ => {
                let prefix = take(bytes, 0, RSDP_V2_BYTES)?;
                let byte_len = read_u32(prefix, 20)?;
                let byte_len_usize =
                    usize::try_from(byte_len).map_err(|_| AcpiError::InvalidLength)?;
                if !(RSDP_V2_BYTES..=MAX_RSDP_BYTES).contains(&byte_len_usize) {
                    return Err(AcpiError::InvalidLength);
                }
                let complete = take(bytes, 0, byte_len_usize)?;
                if !checksum_valid(complete) {
                    return Err(AcpiError::ChecksumMismatch);
                }
                let xsdt_raw = read_u64(prefix, 24)?;
                if take(prefix, 33, 3)?.iter().any(|byte| *byte != 0) {
                    return Err(AcpiError::InvalidReservedField);
                }
                let xsdt_address = (xsdt_raw != 0).then_some(xsdt_raw);
                if xsdt_address.is_none() && rsdt_address == 0 {
                    return Err(AcpiError::InvalidAddress);
                }
                if xsdt_address.is_some_and(|address| address >= X86_PHYSICAL_LIMIT) {
                    return Err(AcpiError::InvalidAddress);
                }
                Ok(Self {
                    revision,
                    oem_id,
                    byte_len,
                    rsdt_address,
                    xsdt_address,
                })
            }
        }
    }

    /// ACPI revision byte.
    #[must_use]
    pub const fn revision(self) -> u8 {
        self.revision
    }

    /// Six-byte ACPI OEM identity.
    #[must_use]
    pub const fn oem_id(self) -> [u8; 6] {
        self.oem_id
    }

    /// Checked RSDP byte length.
    #[must_use]
    pub const fn byte_len(self) -> u32 {
        self.byte_len
    }

    /// Optional 32-bit RSDT physical address.
    #[must_use]
    pub const fn rsdt_address(self) -> Option<u32> {
        if self.rsdt_address == 0 {
            None
        } else {
            Some(self.rsdt_address)
        }
    }

    /// Optional 64-bit XSDT physical address.
    #[must_use]
    pub const fn xsdt_address(self) -> Option<u64> {
        self.xsdt_address
    }

    fn selected_root(self) -> (RootKind, u64) {
        match self.xsdt_address {
            Some(address) => (RootKind::Xsdt, address),
            None => (RootKind::Rsdt, u64::from(self.rsdt_address)),
        }
    }
}

/// Root table format selected from the validated RSDP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootKind {
    /// ACPI 1.0 root with 32-bit table pointers.
    Rsdt,
    /// ACPI 2.0+ root with 64-bit table pointers.
    Xsdt,
}

impl RootKind {
    const fn entry_bytes(self) -> usize {
        match self {
            Self::Rsdt => 4,
            Self::Xsdt => 8,
        }
    }

    const fn signature(self) -> [u8; 4] {
        match self {
            Self::Rsdt => *b"RSDT",
            Self::Xsdt => *b"XSDT",
        }
    }
}

/// Validated common ACPI system-description-table header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdtHeader {
    signature: [u8; 4],
    byte_len: u32,
    revision: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
}

impl SdtHeader {
    /// Four-byte ACPI table signature.
    #[must_use]
    pub const fn signature(self) -> [u8; 4] {
        self.signature
    }

    /// Complete checked table length.
    #[must_use]
    pub const fn byte_len(self) -> u32 {
        self.byte_len
    }

    /// Table-specific revision.
    #[must_use]
    pub const fn revision(self) -> u8 {
        self.revision
    }

    /// Six-byte OEM identity.
    #[must_use]
    pub const fn oem_id(self) -> [u8; 6] {
        self.oem_id
    }

    /// Eight-byte OEM table identity.
    #[must_use]
    pub const fn oem_table_id(self) -> [u8; 8] {
        self.oem_table_id
    }
}

#[derive(Clone, Copy)]
struct Sdt<'a> {
    header: SdtHeader,
    bytes: &'a [u8],
}

impl<'a> Sdt<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, AcpiError> {
        let header_bytes = take(bytes, 0, SDT_HEADER_BYTES)?;
        let byte_len = read_u32(header_bytes, 4)?;
        let byte_len_usize = usize::try_from(byte_len).map_err(|_| AcpiError::InvalidLength)?;
        if !(SDT_HEADER_BYTES..=MAX_SDT_BYTES).contains(&byte_len_usize) {
            return Err(AcpiError::InvalidLength);
        }
        let complete = take(bytes, 0, byte_len_usize)?;
        if !checksum_valid(complete) {
            return Err(AcpiError::ChecksumMismatch);
        }
        let oem_id = take_array::<6>(header_bytes, 10)?;
        let oem_table_id = take_array::<8>(header_bytes, 16)?;
        if !valid_oem_bytes(&oem_id) || !valid_oem_bytes(&oem_table_id) {
            return Err(AcpiError::InvalidReservedField);
        }
        Ok(Self {
            header: SdtHeader {
                signature: take_array::<4>(header_bytes, 0)?,
                byte_len,
                revision: header_bytes[8],
                oem_id,
                oem_table_id,
            },
            bytes: complete,
        })
    }

    fn range(self, physical_address: u64) -> Result<PhysicalRange, AcpiError> {
        PhysicalRange::new(physical_address, u64::from(self.header.byte_len), 1)
    }

    fn body(self) -> &'a [u8] {
        &self.bytes[SDT_HEADER_BYTES..]
    }
}

#[derive(Clone, Copy)]
struct ValidatedChild<'a> {
    physical_address: u64,
    table: Sdt<'a>,
    range: PhysicalRange,
}

/// One validated root-table child summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTable {
    physical_address: u64,
    header: SdtHeader,
}

impl RootTable {
    /// Physical address referenced by the RSDT/XSDT.
    #[must_use]
    pub const fn physical_address(self) -> u64 {
        self.physical_address
    }

    /// Checked common table header.
    #[must_use]
    pub const fn header(self) -> SdtHeader {
        self.header
    }
}

/// Structurally validated ACPI root and every directly referenced child table.
pub struct AcpiTables<'a, M: AcpiMemory + ?Sized> {
    rsdp: Rsdp,
    rsdp_range: PhysicalRange,
    root_kind: RootKind,
    root_address: u64,
    root: Sdt<'a>,
    memory: &'a M,
    children: [Option<ValidatedChild<'a>>; MAX_ROOT_ENTRIES],
    child_count: usize,
}

impl<'a, M: AcpiMemory + ?Sized> AcpiTables<'a, M> {
    /// Validate an RSDP, its selected RSDT/XSDT, and every root child.
    ///
    /// `rsdp_physical_address` is the address supplied by the UEFI
    /// configuration table. The supplied RSDP bytes may contain trailing data;
    /// only the declared RSDP extent participates in validation.
    ///
    /// # Errors
    ///
    /// Rejects malformed/checksum-invalid data, unstable table headers,
    /// excessive entry counts, duplicate pointers, and any overlap among the
    /// RSDP, root, or child table physical extents.
    pub fn parse(
        rsdp_physical_address: u64,
        rsdp_bytes: &[u8],
        memory: &'a M,
    ) -> Result<Self, AcpiError> {
        let rsdp = Rsdp::parse(rsdp_bytes)?;
        let rsdp_range = PhysicalRange::new(rsdp_physical_address, u64::from(rsdp.byte_len), 1)?;
        let (root_kind, root_address) = rsdp.selected_root();
        let root = table_at(memory, root_address)?;
        if root.header.signature != root_kind.signature() {
            return Err(AcpiError::InvalidSignature);
        }
        let root_range = root.range(root_address)?;
        if rsdp_range.overlaps(root_range) {
            return Err(AcpiError::OverlappingRange);
        }
        let body_len = root.body().len();
        let entry_bytes = root_kind.entry_bytes();
        if !body_len.is_multiple_of(entry_bytes) {
            return Err(AcpiError::InvalidLength);
        }
        let entry_count = body_len / entry_bytes;
        if entry_count > MAX_ROOT_ENTRIES {
            return Err(AcpiError::TooManyEntries);
        }

        let mut tables = Self {
            rsdp,
            rsdp_range,
            root_kind,
            root_address,
            root,
            memory,
            children: [None; MAX_ROOT_ENTRIES],
            child_count: entry_count,
        };
        tables.validate_children()?;
        Ok(tables)
    }

    /// Parsed RSDP facts.
    #[must_use]
    pub const fn rsdp(&self) -> Rsdp {
        self.rsdp
    }

    /// Physical RSDP extent reserved by discovery.
    #[must_use]
    pub const fn rsdp_range(&self) -> PhysicalRange {
        self.rsdp_range
    }

    /// Selected root pointer width.
    #[must_use]
    pub const fn root_kind(&self) -> RootKind {
        self.root_kind
    }

    /// Physical root table extent reserved by discovery.
    #[must_use]
    pub fn root_range(&self) -> PhysicalRange {
        // Construction already validated this exact extent.
        PhysicalRange {
            start: self.root_address,
            byte_len: u64::from(self.root.header.byte_len),
        }
    }

    /// Number of root child pointers.
    #[must_use]
    pub const fn root_table_count(&self) -> usize {
        self.child_count
    }

    /// Return one previously validated root child summary by stable index.
    ///
    /// # Errors
    ///
    /// Returns [`AcpiError::Truncated`] only if an internal validated-cache
    /// invariant is violated.
    pub fn root_table(&self, index: usize) -> Result<Option<RootTable>, AcpiError> {
        if index >= self.root_table_count() {
            return Ok(None);
        }
        let child = self.validated_child(index)?;
        Ok(Some(RootTable {
            physical_address: child.physical_address,
            header: child.table.header,
        }))
    }

    fn root_entry_address(&self, index: usize) -> Result<u64, AcpiError> {
        let width = self.root_kind.entry_bytes();
        let offset = index.checked_mul(width).ok_or(AcpiError::InvalidLength)?;
        let body = self.root.body();
        match self.root_kind {
            RootKind::Rsdt => Ok(u64::from(read_u32(body, offset)?)),
            RootKind::Xsdt => read_u64(body, offset),
        }
    }

    fn table_by_signature(&self, signature: [u8; 4]) -> Result<Option<Sdt<'a>>, AcpiError> {
        let mut found = None;
        for index in 0..self.root_table_count() {
            let table = self.validated_child(index)?.table;
            if table.header.signature == signature {
                if found.is_some() {
                    return Err(AcpiError::DuplicateEntry);
                }
                found = Some(table);
            }
        }
        Ok(found)
    }

    fn validate_children(&mut self) -> Result<(), AcpiError> {
        let root_range = self.root_range();
        for index in 0..self.root_table_count() {
            let address = self.root_entry_address(index)?;
            if address == 0 || address >= X86_PHYSICAL_LIMIT {
                return Err(AcpiError::InvalidAddress);
            }
            for previous in self.children[..index].iter().flatten() {
                if address == previous.physical_address {
                    return Err(AcpiError::DuplicateEntry);
                }
            }
            let table = table_at(self.memory, address)?;
            let range = table.range(address)?;
            if range.overlaps(self.rsdp_range) || range.overlaps(root_range) {
                return Err(AcpiError::OverlappingRange);
            }
            for previous in self.children[..index].iter().flatten() {
                if range.overlaps(previous.range) {
                    return Err(AcpiError::OverlappingRange);
                }
            }
            self.children[index] = Some(ValidatedChild {
                physical_address: address,
                table,
                range,
            });
        }
        Ok(())
    }

    fn validated_child(&self, index: usize) -> Result<ValidatedChild<'a>, AcpiError> {
        self.children
            .get(index)
            .copied()
            .flatten()
            .ok_or(AcpiError::Truncated)
    }

    fn every_table_range_overlaps(&self, candidate: PhysicalRange) -> Result<bool, AcpiError> {
        if candidate.overlaps(self.rsdp_range) || candidate.overlaps(self.root_range()) {
            return Ok(true);
        }
        for index in 0..self.root_table_count() {
            if candidate.overlaps(self.validated_child(index)?.range) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// One checked PCI Segment Group ECAM allocation from MCFG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcamSegment {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
}

impl EcamSegment {
    /// PCI segment-group number.
    #[must_use]
    pub const fn segment_group(self) -> u16 {
        self.segment_group
    }

    /// Firmware ECAM base corresponding to bus zero.
    #[must_use]
    pub const fn base_address(self) -> u64 {
        self.base_address
    }

    /// First bus decoded by this allocation.
    #[must_use]
    pub const fn start_bus(self) -> u8 {
        self.start_bus
    }

    /// Last bus decoded by this allocation, inclusive.
    #[must_use]
    pub const fn end_bus(self) -> u8 {
        self.end_bus
    }

    /// Actual physical ECAM bytes decoded by this allocation.
    #[must_use]
    pub fn physical_range(self) -> PhysicalRange {
        let start = self.base_address + u64::from(self.start_bus) * ECAM_BUS_BYTES;
        let byte_len = (u64::from(self.end_bus) - u64::from(self.start_bus) + 1) * ECAM_BUS_BYTES;
        PhysicalRange { start, byte_len }
    }

    /// Compute one checked PCI configuration-register address.
    #[must_use]
    pub fn configuration_address(
        self,
        bus: u8,
        device: u8,
        function: u8,
        register_offset: u16,
    ) -> Option<u64> {
        if !(self.start_bus..=self.end_bus).contains(&bus)
            || device >= 32
            || function >= 8
            || register_offset >= 4096
        {
            return None;
        }
        Some(
            self.base_address
                + (u64::from(bus) << 20)
                + (u64::from(device) << 15)
                + (u64::from(function) << 12)
                + u64::from(register_offset),
        )
    }
}

/// Validated MCFG PCI ECAM allocations.
#[derive(Clone, Copy)]
pub struct Mcfg<'a> {
    entries: &'a [u8],
}

impl<'a> Mcfg<'a> {
    fn parse(table: Sdt<'a>) -> Result<Self, AcpiError> {
        if table.header.signature != *b"MCFG" {
            return Err(AcpiError::InvalidSignature);
        }
        let body = table.body();
        let reserved = take(body, 0, MCFG_PREFIX_BYTES)?;
        if reserved.iter().any(|byte| *byte != 0) {
            return Err(AcpiError::InvalidReservedField);
        }
        let entries = &body[MCFG_PREFIX_BYTES..];
        if entries.is_empty() || !entries.len().is_multiple_of(MCFG_ENTRY_BYTES) {
            return Err(AcpiError::InvalidLength);
        }
        let count = entries.len() / MCFG_ENTRY_BYTES;
        if count > MAX_MCFG_ENTRIES {
            return Err(AcpiError::TooManyEntries);
        }
        let mcfg = Self { entries };
        mcfg.validate_entries()?;
        Ok(mcfg)
    }

    /// Number of validated ECAM allocations.
    #[must_use]
    pub fn segment_count(self) -> usize {
        self.entries.len() / MCFG_ENTRY_BYTES
    }

    /// Return a checked allocation by firmware order.
    #[must_use]
    pub fn segment(self, index: usize) -> Option<EcamSegment> {
        if index >= self.segment_count() {
            return None;
        }
        parse_mcfg_entry(self.entries, index * MCFG_ENTRY_BYTES).ok()
    }

    fn validate_entries(self) -> Result<(), AcpiError> {
        for index in 0..self.segment_count() {
            let entry = parse_mcfg_entry(self.entries, index * MCFG_ENTRY_BYTES)?;
            for previous_index in 0..index {
                let previous = parse_mcfg_entry(self.entries, previous_index * MCFG_ENTRY_BYTES)?;
                if entry == previous {
                    return Err(AcpiError::DuplicateEntry);
                }
                let buses_overlap = entry.segment_group == previous.segment_group
                    && entry.start_bus <= previous.end_bus
                    && previous.start_bus <= entry.end_bus;
                if buses_overlap {
                    return Err(AcpiError::DuplicateEntry);
                }
                if entry.physical_range().overlaps(previous.physical_range()) {
                    return Err(AcpiError::OverlappingRange);
                }
            }
        }
        Ok(())
    }
}

fn parse_mcfg_entry(bytes: &[u8], offset: usize) -> Result<EcamSegment, AcpiError> {
    let entry = take(bytes, offset, MCFG_ENTRY_BYTES)?;
    if entry[12..16].iter().any(|byte| *byte != 0) {
        return Err(AcpiError::InvalidReservedField);
    }
    let base_address = read_u64(entry, 0)?;
    let start_bus = entry[10];
    let end_bus = entry[11];
    if start_bus > end_bus || !base_address.is_multiple_of(ECAM_BUS_BYTES) {
        return Err(AcpiError::InvalidAddress);
    }
    let end_offset = (u64::from(end_bus) + 1)
        .checked_mul(ECAM_BUS_BYTES)
        .ok_or(AcpiError::InvalidAddress)?;
    let end = base_address
        .checked_add(end_offset)
        .ok_or(AcpiError::InvalidAddress)?;
    if base_address == 0 || end > X86_PHYSICAL_LIMIT {
        return Err(AcpiError::InvalidAddress);
    }
    Ok(EcamSegment {
        base_address,
        segment_group: read_u16(entry, 8)?,
        start_bus,
        end_bus,
    })
}

/// MPS INTI polarity decoded from MADT flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntiPolarity {
    /// Use the source bus default.
    ConformsToBus,
    /// Active-high signal.
    ActiveHigh,
    /// Active-low signal.
    ActiveLow,
}

/// MPS INTI trigger mode decoded from MADT flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntiTrigger {
    /// Use the source bus default.
    ConformsToBus,
    /// Edge-triggered signal.
    Edge,
    /// Level-triggered signal.
    Level,
}

/// Checked MADT interrupt-source flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntiFlags {
    polarity: IntiPolarity,
    trigger: IntiTrigger,
}

impl IntiFlags {
    fn parse(raw: u16) -> Result<Self, AcpiError> {
        if raw & !0x000f != 0 {
            return Err(AcpiError::InvalidReservedField);
        }
        let polarity = match raw & 0b11 {
            0 => IntiPolarity::ConformsToBus,
            1 => IntiPolarity::ActiveHigh,
            3 => IntiPolarity::ActiveLow,
            _ => return Err(AcpiError::InvalidReservedField),
        };
        let trigger = match (raw >> 2) & 0b11 {
            0 => IntiTrigger::ConformsToBus,
            1 => IntiTrigger::Edge,
            3 => IntiTrigger::Level,
            _ => return Err(AcpiError::InvalidReservedField),
        };
        Ok(Self { polarity, trigger })
    }

    /// Encoded polarity, possibly inherited from the source bus.
    #[must_use]
    pub const fn polarity(self) -> IntiPolarity {
        self.polarity
    }

    /// Encoded trigger, possibly inherited from the source bus.
    #[must_use]
    pub const fn trigger(self) -> IntiTrigger {
        self.trigger
    }
}

/// One enabled or hot-pluggable local APIC processor record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessorApic {
    processor_uid: u32,
    apic_id: u32,
    enabled: bool,
    online_capable: bool,
    x2apic: bool,
}

impl ProcessorApic {
    /// ACPI processor identity.
    #[must_use]
    pub const fn processor_uid(self) -> u32 {
        self.processor_uid
    }

    /// Local APIC or x2APIC identity.
    #[must_use]
    pub const fn apic_id(self) -> u32 {
        self.apic_id
    }

    /// Whether firmware reports this processor enabled.
    #[must_use]
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Whether firmware permits this disabled processor to become enabled.
    #[must_use]
    pub const fn online_capable(self) -> bool {
        self.online_capable
    }

    /// Whether this is the 32-bit x2APIC encoding.
    #[must_use]
    pub const fn is_x2apic(self) -> bool {
        self.x2apic
    }
}

/// One I/O APIC controller record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoApic {
    id: u8,
    address: u32,
    global_interrupt_base: u32,
}

impl IoApic {
    /// Firmware I/O APIC identity.
    #[must_use]
    pub const fn id(self) -> u8 {
        self.id
    }

    /// Physical MMIO base.
    #[must_use]
    pub const fn address(self) -> u32 {
        self.address
    }

    /// First global system interrupt handled by the controller.
    #[must_use]
    pub const fn global_interrupt_base(self) -> u32 {
        self.global_interrupt_base
    }

    /// One-page controller register aperture to reserve before MMIO.
    #[must_use]
    pub fn physical_range(self) -> PhysicalRange {
        PhysicalRange {
            start: u64::from(self.address),
            byte_len: APIC_MMIO_BYTES,
        }
    }
}

/// One ISA interrupt-source override.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptSourceOverride {
    source_irq: u8,
    global_interrupt: u32,
    flags: IntiFlags,
}

impl InterruptSourceOverride {
    /// Legacy ISA interrupt input.
    #[must_use]
    pub const fn source_irq(self) -> u8 {
        self.source_irq
    }

    /// Routed global system interrupt.
    #[must_use]
    pub const fn global_interrupt(self) -> u32 {
        self.global_interrupt
    }

    /// Checked MPS INTI flags.
    #[must_use]
    pub const fn flags(self) -> IntiFlags {
        self.flags
    }

    /// Resolve ISA-conforming polarity to active high.
    #[must_use]
    pub const fn resolved_polarity(self) -> IntiPolarity {
        match self.flags.polarity {
            IntiPolarity::ConformsToBus => IntiPolarity::ActiveHigh,
            other => other,
        }
    }

    /// Resolve ISA-conforming trigger mode to edge triggered.
    #[must_use]
    pub const fn resolved_trigger(self) -> IntiTrigger {
        match self.flags.trigger {
            IntiTrigger::ConformsToBus => IntiTrigger::Edge,
            other => other,
        }
    }
}

/// One global-system-interrupt NMI source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NmiSource {
    flags: IntiFlags,
    global_interrupt: u32,
}

impl NmiSource {
    /// Checked MPS INTI flags.
    #[must_use]
    pub const fn flags(self) -> IntiFlags {
        self.flags
    }

    /// Global system interrupt delivered as NMI.
    #[must_use]
    pub const fn global_interrupt(self) -> u32 {
        self.global_interrupt
    }
}

/// One processor-local NMI route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalNmi {
    processor_uid: Option<u32>,
    flags: IntiFlags,
    lint: u8,
}

impl LocalNmi {
    /// Processor identity, or `None` when the route applies to all processors.
    #[must_use]
    pub const fn processor_uid(self) -> Option<u32> {
        self.processor_uid
    }

    /// Checked MPS INTI flags.
    #[must_use]
    pub const fn flags(self) -> IntiFlags {
        self.flags
    }

    /// Local APIC LINT input, zero or one.
    #[must_use]
    pub const fn lint(self) -> u8 {
        self.lint
    }
}

/// Relevant, validated x86 MADT entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MadtEntry {
    /// Processor local APIC/x2APIC identity and state.
    Processor(ProcessorApic),
    /// I/O APIC controller.
    IoApic(IoApic),
    /// Legacy ISA interrupt remapping.
    InterruptSourceOverride(InterruptSourceOverride),
    /// Global interrupt delivered as NMI.
    NmiSource(NmiSource),
    /// Local APIC LINT NMI route.
    LocalNmi(LocalNmi),
}

#[derive(Clone, Copy)]
struct RawMadtEntry<'a> {
    entry_type: u8,
    bytes: &'a [u8],
}

/// Iterator over relevant MADT entries in deterministic firmware order.
pub struct MadtEntries<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for MadtEntries<'_> {
    type Item = MadtEntry;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.bytes.len() {
            let raw = parse_raw_madt_entry(self.bytes, self.offset).ok()?;
            self.offset += raw.bytes.len();
            if let Some(entry) = relevant_madt_entry(raw).ok()? {
                return Some(entry);
            }
        }
        None
    }
}

/// Validated x86 MADT interrupt topology.
#[derive(Clone, Copy)]
pub struct Madt<'a> {
    local_apic_address: u64,
    flags: u32,
    entries: &'a [u8],
}

impl<'a> Madt<'a> {
    fn parse(table: Sdt<'a>) -> Result<Self, AcpiError> {
        if table.header.signature != *b"APIC" {
            return Err(AcpiError::InvalidSignature);
        }
        let body = table.body();
        let prefix = take(body, 0, MADT_PREFIX_BYTES)?;
        let legacy_address = u64::from(read_u32(prefix, 0)?);
        let flags = read_u32(prefix, 4)?;
        if flags & !1 != 0 {
            return Err(AcpiError::InvalidReservedField);
        }
        let entries = &body[MADT_PREFIX_BYTES..];
        let mut offset = 0;
        let mut count = 0;
        let mut override_address = None;
        while offset < entries.len() {
            let raw = parse_raw_madt_entry(entries, offset)?;
            validate_madt_entry_encoding(raw)?;
            if raw.entry_type == 5 {
                let address = read_u64(raw.bytes, 4)?;
                if override_address.replace(address).is_some() {
                    return Err(AcpiError::DuplicateEntry);
                }
            }
            offset += raw.bytes.len();
            count += 1;
            if count > MAX_MADT_ENTRIES {
                return Err(AcpiError::TooManyEntries);
            }
        }
        let local_apic_address = override_address.unwrap_or(legacy_address);
        PhysicalRange::new(local_apic_address, APIC_MMIO_BYTES, APIC_MMIO_BYTES)?;
        let madt = Self {
            local_apic_address,
            flags,
            entries,
        };
        madt.validate_semantics()?;
        Ok(madt)
    }

    /// Resolved local APIC physical address, including a type-5 override.
    #[must_use]
    pub const fn local_apic_address(self) -> u64 {
        self.local_apic_address
    }

    /// One-page local APIC register aperture to reserve before MMIO.
    #[must_use]
    pub fn local_apic_range(self) -> PhysicalRange {
        PhysicalRange {
            start: self.local_apic_address,
            byte_len: APIC_MMIO_BYTES,
        }
    }

    /// Whether dual 8259 legacy PICs are installed.
    #[must_use]
    pub const fn legacy_pic_compatible(self) -> bool {
        self.flags & 1 != 0
    }

    /// Iterate relevant x86 topology and route entries.
    #[must_use]
    pub const fn entries(self) -> MadtEntries<'a> {
        MadtEntries {
            bytes: self.entries,
            offset: 0,
        }
    }

    fn validate_semantics(self) -> Result<(), AcpiError> {
        let mut enabled_processors = 0usize;
        let mut io_apics = 0usize;
        let local_range = self.local_apic_range();
        let mut offset = 0;
        let mut index = 0;
        while offset < self.entries.len() {
            let raw = parse_raw_madt_entry(self.entries, offset)?;
            if let Some(entry) = relevant_madt_entry(raw)? {
                match entry {
                    MadtEntry::Processor(processor) => {
                        if processor.enabled {
                            enabled_processors += 1;
                        }
                    }
                    MadtEntry::IoApic(controller) => {
                        io_apics += 1;
                        if local_range.overlaps(controller.physical_range()) {
                            return Err(AcpiError::OverlappingRange);
                        }
                    }
                    MadtEntry::InterruptSourceOverride(_)
                    | MadtEntry::NmiSource(_)
                    | MadtEntry::LocalNmi(_) => {}
                }
                self.validate_against_previous(raw, index)?;
            } else {
                self.reject_identical_previous(raw, index)?;
            }
            offset += raw.bytes.len();
            index += 1;
        }
        if enabled_processors == 0 || io_apics == 0 {
            return Err(AcpiError::IncompleteInterruptTopology);
        }
        Ok(())
    }

    fn validate_against_previous(
        self,
        current: RawMadtEntry<'_>,
        current_index: usize,
    ) -> Result<(), AcpiError> {
        let current_relevant = relevant_madt_entry(current)?;
        let mut offset = 0;
        for _ in 0..current_index {
            let previous = parse_raw_madt_entry(self.entries, offset)?;
            if current.bytes == previous.bytes {
                return Err(AcpiError::DuplicateEntry);
            }
            if let (Some(current_entry), Some(previous_entry)) =
                (current_relevant, relevant_madt_entry(previous)?)
            {
                reject_madt_collision(current_entry, previous_entry)?;
            }
            offset += previous.bytes.len();
        }
        Ok(())
    }

    fn reject_identical_previous(
        self,
        current: RawMadtEntry<'_>,
        current_index: usize,
    ) -> Result<(), AcpiError> {
        let mut offset = 0;
        for _ in 0..current_index {
            let previous = parse_raw_madt_entry(self.entries, offset)?;
            if current.bytes == previous.bytes {
                return Err(AcpiError::DuplicateEntry);
            }
            offset += previous.bytes.len();
        }
        Ok(())
    }
}

fn parse_raw_madt_entry(bytes: &[u8], offset: usize) -> Result<RawMadtEntry<'_>, AcpiError> {
    let prefix = take(bytes, offset, 2)?;
    let byte_len = usize::from(prefix[1]);
    if byte_len < 2 {
        return Err(AcpiError::InvalidLength);
    }
    Ok(RawMadtEntry {
        entry_type: prefix[0],
        bytes: take(bytes, offset, byte_len)?,
    })
}

fn validate_madt_entry_encoding(entry: RawMadtEntry<'_>) -> Result<(), AcpiError> {
    let expected_len = match entry.entry_type {
        0 | 3 => Some(8),
        1 | 5 | 10 => Some(12),
        2 => Some(10),
        4 => Some(6),
        9 => Some(16),
        _ => None,
    };
    if expected_len.is_some_and(|length| entry.bytes.len() != length) {
        return Err(AcpiError::InvalidLength);
    }
    match entry.entry_type {
        0 => validate_processor_flags(read_u32(entry.bytes, 4)?),
        1 => {
            if entry.bytes[3] != 0 {
                return Err(AcpiError::InvalidReservedField);
            }
            PhysicalRange::new(
                u64::from(read_u32(entry.bytes, 4)?),
                APIC_MMIO_BYTES,
                APIC_MMIO_BYTES,
            )?;
            Ok(())
        }
        2 => {
            if entry.bytes[2] != 0 || entry.bytes[3] >= 16 {
                return Err(AcpiError::InvalidReservedField);
            }
            IntiFlags::parse(read_u16(entry.bytes, 8)?).map(|_| ())
        }
        3 => IntiFlags::parse(read_u16(entry.bytes, 2)?).map(|_| ()),
        4 => {
            IntiFlags::parse(read_u16(entry.bytes, 3)?)?;
            if entry.bytes[5] > 1 {
                return Err(AcpiError::InvalidReservedField);
            }
            Ok(())
        }
        5 => {
            if entry.bytes[2..4].iter().any(|byte| *byte != 0) {
                return Err(AcpiError::InvalidReservedField);
            }
            PhysicalRange::new(read_u64(entry.bytes, 4)?, APIC_MMIO_BYTES, APIC_MMIO_BYTES)?;
            Ok(())
        }
        9 => {
            if entry.bytes[2..4].iter().any(|byte| *byte != 0) {
                return Err(AcpiError::InvalidReservedField);
            }
            validate_processor_flags(read_u32(entry.bytes, 8)?)
        }
        10 => {
            IntiFlags::parse(read_u16(entry.bytes, 2)?)?;
            if entry.bytes[9] > 1 || entry.bytes[10..12].iter().any(|byte| *byte != 0) {
                return Err(AcpiError::InvalidReservedField);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_processor_flags(flags: u32) -> Result<(), AcpiError> {
    if flags & !0b11 != 0 {
        Err(AcpiError::InvalidReservedField)
    } else {
        Ok(())
    }
}

fn relevant_madt_entry(entry: RawMadtEntry<'_>) -> Result<Option<MadtEntry>, AcpiError> {
    let parsed = match entry.entry_type {
        0 => {
            let flags = read_u32(entry.bytes, 4)?;
            Some(MadtEntry::Processor(ProcessorApic {
                processor_uid: u32::from(entry.bytes[2]),
                apic_id: u32::from(entry.bytes[3]),
                enabled: flags & 1 != 0,
                online_capable: flags & 2 != 0,
                x2apic: false,
            }))
        }
        1 => Some(MadtEntry::IoApic(IoApic {
            id: entry.bytes[2],
            address: read_u32(entry.bytes, 4)?,
            global_interrupt_base: read_u32(entry.bytes, 8)?,
        })),
        2 => Some(MadtEntry::InterruptSourceOverride(
            InterruptSourceOverride {
                source_irq: entry.bytes[3],
                global_interrupt: read_u32(entry.bytes, 4)?,
                flags: IntiFlags::parse(read_u16(entry.bytes, 8)?)?,
            },
        )),
        3 => Some(MadtEntry::NmiSource(NmiSource {
            flags: IntiFlags::parse(read_u16(entry.bytes, 2)?)?,
            global_interrupt: read_u32(entry.bytes, 4)?,
        })),
        4 => Some(MadtEntry::LocalNmi(LocalNmi {
            processor_uid: (entry.bytes[2] != u8::MAX).then_some(u32::from(entry.bytes[2])),
            flags: IntiFlags::parse(read_u16(entry.bytes, 3)?)?,
            lint: entry.bytes[5],
        })),
        9 => {
            let flags = read_u32(entry.bytes, 8)?;
            Some(MadtEntry::Processor(ProcessorApic {
                processor_uid: read_u32(entry.bytes, 12)?,
                apic_id: read_u32(entry.bytes, 4)?,
                enabled: flags & 1 != 0,
                online_capable: flags & 2 != 0,
                x2apic: true,
            }))
        }
        10 => {
            let uid = read_u32(entry.bytes, 4)?;
            Some(MadtEntry::LocalNmi(LocalNmi {
                processor_uid: (uid != u32::MAX).then_some(uid),
                flags: IntiFlags::parse(read_u16(entry.bytes, 2)?)?,
                lint: entry.bytes[9],
            }))
        }
        _ => None,
    };
    Ok(parsed)
}

fn reject_madt_collision(current: MadtEntry, previous: MadtEntry) -> Result<(), AcpiError> {
    let collision = match (current, previous) {
        (MadtEntry::Processor(a), MadtEntry::Processor(b)) => {
            a.processor_uid == b.processor_uid || a.apic_id == b.apic_id
        }
        (MadtEntry::IoApic(a), MadtEntry::IoApic(b)) => {
            a.id == b.id
                || a.global_interrupt_base == b.global_interrupt_base
                || a.physical_range().overlaps(b.physical_range())
        }
        (MadtEntry::InterruptSourceOverride(a), MadtEntry::InterruptSourceOverride(b)) => {
            a.source_irq == b.source_irq || a.global_interrupt == b.global_interrupt
        }
        (MadtEntry::NmiSource(a), MadtEntry::NmiSource(b)) => {
            a.global_interrupt == b.global_interrupt
        }
        (MadtEntry::InterruptSourceOverride(a), MadtEntry::NmiSource(b))
        | (MadtEntry::NmiSource(b), MadtEntry::InterruptSourceOverride(a)) => {
            a.global_interrupt == b.global_interrupt
        }
        (MadtEntry::LocalNmi(a), MadtEntry::LocalNmi(b)) => {
            a.processor_uid == b.processor_uid && a.lint == b.lint
        }
        _ => false,
    };
    if collision {
        Err(AcpiError::DuplicateEntry)
    } else {
        Ok(())
    }
}

/// Address space used by a bounded ACPI register capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterSpace {
    /// Byte-addressed physical memory.
    SystemMemory,
    /// x86 I/O ports.
    SystemIo,
}

/// Validated ACPI Generic Address Structure restricted to directly usable x86
/// memory or I/O space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericRegister {
    space: RegisterSpace,
    address: u64,
    bit_width: u8,
    access_bytes: u8,
}

impl GenericRegister {
    /// Register address space.
    #[must_use]
    pub const fn space(self) -> RegisterSpace {
        self.space
    }

    /// Physical-memory address or I/O-port number.
    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }

    /// Complete supported register width.
    #[must_use]
    pub const fn bit_width(self) -> u8 {
        self.bit_width
    }

    /// Natural access width in bytes.
    #[must_use]
    pub const fn access_bytes(self) -> u8 {
        self.access_bytes
    }

    /// Physical register extent, or `None` for x86 I/O space.
    #[must_use]
    pub fn physical_range(self) -> Option<PhysicalRange> {
        (self.space == RegisterSpace::SystemMemory).then_some(PhysicalRange {
            start: self.address,
            byte_len: u64::from(self.access_bytes),
        })
    }

    fn overlaps(self, other: Self) -> bool {
        if self.space != other.space {
            return false;
        }
        let self_end = self.address + u64::from(self.access_bytes);
        let other_end = other.address + u64::from(other.access_bytes);
        self.address < other_end && other.address < self_end
    }
}

fn parse_gas(bytes: &[u8], expected_bit_width: u8) -> Result<GenericRegister, AcpiError> {
    let gas = take(bytes, 0, 12)?;
    let space = match gas[0] {
        0 => RegisterSpace::SystemMemory,
        1 => RegisterSpace::SystemIo,
        _ => return Err(AcpiError::UnsupportedEncoding),
    };
    if gas[1] != expected_bit_width || gas[2] != 0 {
        return Err(AcpiError::UnsupportedEncoding);
    }
    let natural_bytes = expected_bit_width
        .checked_div(8)
        .filter(|bytes| *bytes != 0 && expected_bit_width.is_multiple_of(8))
        .ok_or(AcpiError::UnsupportedEncoding)?;
    let access_bytes = match gas[3] {
        0 => natural_bytes,
        1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        _ => return Err(AcpiError::UnsupportedEncoding),
    };
    if access_bytes != natural_bytes {
        return Err(AcpiError::UnsupportedEncoding);
    }
    let address = read_u64(gas, 4)?;
    if address == 0 || !address.is_multiple_of(u64::from(access_bytes)) {
        return Err(AcpiError::InvalidAddress);
    }
    match space {
        RegisterSpace::SystemMemory => {
            PhysicalRange::new(address, u64::from(access_bytes), u64::from(access_bytes))?;
        }
        RegisterSpace::SystemIo => {
            let end = address
                .checked_add(u64::from(access_bytes))
                .ok_or(AcpiError::InvalidAddress)?;
            if end > 0x1_0000 {
                return Err(AcpiError::InvalidAddress);
            }
        }
    }
    Ok(GenericRegister {
        space,
        address,
        bit_width: expected_bit_width,
        access_bytes,
    })
}

fn gas_address(bytes: &[u8]) -> Result<u64, AcpiError> {
    read_u64(take(bytes, 0, 12)?, 4)
}

/// x86 serial register interface accepted from SPCR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialInterface {
    /// Full 16550 register interface.
    Uart16550,
    /// Full 16450 interface that accepts 16550 FCR writes.
    Uart16450,
}

/// Optional PCI identity for a serial controller described by SPCR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciSerialLocation {
    vendor_id: u16,
    device_id: u16,
    segment_group: u8,
    bus: u8,
    device: u8,
    function: u8,
    preserve_firmware_configuration: bool,
}

impl PciSerialLocation {
    /// PCI vendor identity.
    #[must_use]
    pub const fn vendor_id(self) -> u16 {
        self.vendor_id
    }

    /// PCI device identity.
    #[must_use]
    pub const fn device_id(self) -> u16 {
        self.device_id
    }

    /// PCI segment-group number (SPCR encodes only one byte).
    #[must_use]
    pub const fn segment_group(self) -> u8 {
        self.segment_group
    }

    /// PCI bus number.
    #[must_use]
    pub const fn bus(self) -> u8 {
        self.bus
    }

    /// PCI device number.
    #[must_use]
    pub const fn device(self) -> u8 {
        self.device
    }

    /// PCI function number.
    #[must_use]
    pub const fn function(self) -> u8 {
        self.function
    }

    /// Whether firmware requests retaining enumeration and power state.
    #[must_use]
    pub const fn preserve_firmware_configuration(self) -> bool {
        self.preserve_firmware_configuration
    }
}

/// Validated x86 serial console capability from SPCR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SerialConsole {
    interface: SerialInterface,
    register: GenericRegister,
    legacy_irq: Option<u8>,
    global_interrupt: Option<u32>,
    baud_rate: Option<u32>,
    uart_clock_hz: Option<u32>,
    flow_control: u8,
    pci: Option<PciSerialLocation>,
}

impl SerialConsole {
    /// UART register interface.
    #[must_use]
    pub const fn interface(self) -> SerialInterface {
        self.interface
    }

    /// Base register capability. Eight consecutive byte registers are required
    /// for the accepted 16450/16550 interface.
    #[must_use]
    pub const fn register(self) -> GenericRegister {
        self.register
    }

    /// Optional dual-8259 IRQ.
    #[must_use]
    pub const fn legacy_irq(self) -> Option<u8> {
        self.legacy_irq
    }

    /// Optional I/O-APIC global system interrupt.
    #[must_use]
    pub const fn global_interrupt(self) -> Option<u32> {
        self.global_interrupt
    }

    /// Configured or precise baud rate, or `None` when firmware state is kept.
    #[must_use]
    pub const fn baud_rate(self) -> Option<u32> {
        self.baud_rate
    }

    /// Optional UART input clock from SPCR revision 3+.
    #[must_use]
    pub const fn uart_clock_hz(self) -> Option<u32> {
        self.uart_clock_hz
    }

    /// DCD/RTS-CTS/XON-XOFF flow-control bitset.
    #[must_use]
    pub const fn flow_control(self) -> u8 {
        self.flow_control
    }

    /// Optional PCI identity and location.
    #[must_use]
    pub const fn pci(self) -> Option<PciSerialLocation> {
        self.pci
    }

    fn register_extent(self) -> Result<GenericRegister, AcpiError> {
        let byte_len = 8u64;
        match self.register.space {
            RegisterSpace::SystemMemory => {
                PhysicalRange::new(self.register.address, byte_len, 1)?;
            }
            RegisterSpace::SystemIo => {
                if self
                    .register
                    .address
                    .checked_add(byte_len)
                    .is_none_or(|end| end > 0x1_0000)
                {
                    return Err(AcpiError::InvalidAddress);
                }
            }
        }
        Ok(GenericRegister {
            access_bytes: u8::try_from(byte_len).map_err(|_| AcpiError::InvalidLength)?,
            ..self.register
        })
    }
}

/// Parsed optional SPCR table. A present but disabled SPCR has no console.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Spcr {
    console: Option<SerialConsole>,
}

impl Spcr {
    #[allow(clippy::too_many_lines)]
    fn parse(table: Sdt<'_>) -> Result<Self, AcpiError> {
        if table.header.signature != *b"SPCR" {
            return Err(AcpiError::InvalidSignature);
        }
        let revision = table.header.revision;
        if !(1..=4).contains(&revision) {
            return Err(AcpiError::UnsupportedRevision);
        }
        let required_len = if revision == 4 { 88 } else { 80 };
        if table.bytes.len() < required_len {
            return Err(AcpiError::InvalidLength);
        }
        if table.bytes[37..40].iter().any(|byte| *byte != 0) {
            return Err(AcpiError::InvalidReservedField);
        }
        let interface = match table.bytes[36] {
            0 => SerialInterface::Uart16550,
            1 => SerialInterface::Uart16450,
            _ => return Err(AcpiError::UnsupportedEncoding),
        };
        let base_gas = take(table.bytes, 40, 12)?;
        if gas_address(base_gas)? == 0 {
            return Ok(Self { console: None });
        }
        let register = parse_gas(base_gas, 8)?;
        let interrupt_type = table.bytes[52];
        if interrupt_type & !0b11 != 0 {
            return Err(AcpiError::UnsupportedEncoding);
        }
        let irq = table.bytes[53];
        let legacy_irq = if interrupt_type & 1 != 0 {
            if !matches!(irq, 2..=7 | 9..=12 | 14..=15) {
                return Err(AcpiError::InvalidReservedField);
            }
            Some(irq)
        } else {
            if irq != 0 {
                return Err(AcpiError::InvalidReservedField);
            }
            None
        };
        let gsi = read_u32(table.bytes, 54)?;
        let global_interrupt = if interrupt_type & 2 != 0 {
            Some(gsi)
        } else {
            if gsi != 0 {
                return Err(AcpiError::InvalidReservedField);
            }
            None
        };
        let configured_baud = match table.bytes[58] {
            0 => None,
            3 => Some(9_600),
            4 => Some(19_200),
            6 => Some(57_600),
            7 => Some(115_200),
            _ => return Err(AcpiError::InvalidReservedField),
        };
        if table.bytes[59] != 0 || table.bytes[60] != 1 {
            return Err(AcpiError::UnsupportedEncoding);
        }
        let flow_control = table.bytes[61];
        if flow_control & !0b111 != 0 || table.bytes[62] > 3 || table.bytes[63] != 0 {
            return Err(AcpiError::InvalidReservedField);
        }
        let device_id = read_u16(table.bytes, 64)?;
        let vendor_id = read_u16(table.bytes, 66)?;
        let pci_flags = read_u32(table.bytes, 71)?;
        if pci_flags & !1 != 0 {
            return Err(AcpiError::InvalidReservedField);
        }
        let pci = match (vendor_id, device_id) {
            (u16::MAX, u16::MAX) => {
                if table.bytes[68..71].iter().any(|byte| *byte != 0)
                    || pci_flags != 0
                    || table.bytes[75] != 0
                {
                    return Err(AcpiError::InvalidReservedField);
                }
                None
            }
            (u16::MAX, _) | (_, u16::MAX) => return Err(AcpiError::InvalidReservedField),
            _ => {
                if table.bytes[69] >= 32 || table.bytes[70] >= 8 {
                    return Err(AcpiError::InvalidReservedField);
                }
                Some(PciSerialLocation {
                    vendor_id,
                    device_id,
                    segment_group: table.bytes[75],
                    bus: table.bytes[68],
                    device: table.bytes[69],
                    function: table.bytes[70],
                    preserve_firmware_configuration: pci_flags & 1 != 0,
                })
            }
        };
        let uart_clock = read_u32(table.bytes, 76)?;
        if revision <= 2 && uart_clock != 0 {
            return Err(AcpiError::InvalidReservedField);
        }
        let uart_clock_hz = (uart_clock != 0).then_some(uart_clock);
        let precise_baud = if revision == 4 {
            read_u32(table.bytes, 80)?
        } else {
            0
        };
        if precise_baud != 0 && configured_baud.is_some() {
            return Err(AcpiError::InvalidReservedField);
        }
        if revision == 4 {
            validate_spcr_namespace(table.bytes)?;
        }
        let console = SerialConsole {
            interface,
            register,
            legacy_irq,
            global_interrupt,
            baud_rate: (precise_baud != 0)
                .then_some(precise_baud)
                .or(configured_baud),
            uart_clock_hz,
            flow_control,
            pci,
        };
        console.register_extent()?;
        Ok(Self {
            console: Some(console),
        })
    }

    /// Serial console capability, absent when firmware explicitly disables it.
    #[must_use]
    pub const fn console(self) -> Option<SerialConsole> {
        self.console
    }
}

fn validate_spcr_namespace(bytes: &[u8]) -> Result<(), AcpiError> {
    let byte_len = usize::from(read_u16(bytes, 84)?);
    let offset = usize::from(read_u16(bytes, 86)?);
    if byte_len < 2 || offset < 88 {
        return Err(AcpiError::InvalidLength);
    }
    let namespace = take(bytes, offset, byte_len)?;
    if namespace.last() != Some(&0)
        || namespace[..namespace.len() - 1]
            .iter()
            .any(|byte| !byte.is_ascii_graphic())
    {
        return Err(AcpiError::InvalidReservedField);
    }
    Ok(())
}

/// FADT reset register and value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetRegister {
    register: GenericRegister,
    value: u8,
}

impl ResetRegister {
    /// Register to write exactly once for a platform reset.
    #[must_use]
    pub const fn register(self) -> GenericRegister {
        self.register
    }

    /// Byte value that requests reset.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.value
    }
}

/// Checked ACPI fixed-hardware power-management timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmTimer {
    register: GenericRegister,
    counter_bits: u8,
}

impl PmTimer {
    /// Four-byte register containing the free-running counter.
    #[must_use]
    pub const fn register(self) -> GenericRegister {
        self.register
    }

    /// Implemented counter width, which is always 24 or 32 bits.
    #[must_use]
    pub const fn counter_bits(self) -> u8 {
        self.counter_bits
    }
}

/// Checked IA-PC boot-architecture flags from FADT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IaPcBootArchitecture {
    flags: u16,
}

impl IaPcBootArchitecture {
    fn parse(flags: u16) -> Result<Self, AcpiError> {
        if flags & !0x003f != 0 {
            return Err(AcpiError::InvalidReservedField);
        }
        Ok(Self { flags })
    }

    /// Whether firmware reports PC/AT legacy devices such as the 8254 timer.
    #[must_use]
    pub const fn legacy_devices_present(self) -> bool {
        self.flags & 1 != 0
    }

    /// Whether firmware reports an i8042 keyboard controller.
    #[must_use]
    pub const fn i8042_present(self) -> bool {
        self.flags & (1 << 1) != 0
    }

    /// Complete checked bitset, with all reserved bits proven zero.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.flags
    }
}

/// Validated fixed ACPI power/lifecycle facts from FADT.
///
/// PM control/sleep registers do not include an S5 sleep type. Machine code
/// must obtain that value from a separately bounded DSDT `_S5` AML evaluator
/// before constructing a power-off capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fadt {
    dsdt_range: PhysicalRange,
    sci_interrupt: u16,
    ia_pc_boot_architecture: IaPcBootArchitecture,
    hardware_reduced: bool,
    reset: Option<ResetRegister>,
    pm_timer: Option<PmTimer>,
    pm1a_control: Option<GenericRegister>,
    pm1b_control: Option<GenericRegister>,
    sleep_control: Option<GenericRegister>,
}

impl Fadt {
    fn parse<M: AcpiMemory + ?Sized>(table: Sdt<'_>, memory: &M) -> Result<Self, AcpiError> {
        if table.header.signature != *b"FACP" {
            return Err(AcpiError::InvalidSignature);
        }
        if !(1..=6).contains(&table.header.revision) {
            return Err(AcpiError::UnsupportedRevision);
        }
        if table.bytes.len() < 116 {
            return Err(AcpiError::InvalidLength);
        }
        let ia_pc_boot_architecture = IaPcBootArchitecture::parse(read_u16(table.bytes, 109)?)?;
        if table.bytes[111] != 0 {
            return Err(AcpiError::InvalidReservedField);
        }
        let flags = read_u32(table.bytes, 112)?;
        let hardware_reduced = flags & (1 << 20) != 0;
        let legacy_dsdt = u64::from(read_u32(table.bytes, 40)?);
        let extended_dsdt = if table.bytes.len() >= 148 {
            read_u64(table.bytes, 140)?
        } else {
            0
        };
        let dsdt_address = if extended_dsdt != 0 {
            extended_dsdt
        } else {
            legacy_dsdt
        };
        let dsdt = table_at(memory, dsdt_address)?;
        if dsdt.header.signature != *b"DSDT" {
            return Err(AcpiError::InvalidSignature);
        }
        let dsdt_range = dsdt.range(dsdt_address)?;

        let reset = if flags & (1 << 10) != 0 {
            if table.bytes.len() < 129 {
                return Err(AcpiError::InvalidLength);
            }
            Some(ResetRegister {
                register: parse_gas(take(table.bytes, 116, 12)?, 8)?,
                value: table.bytes[128],
            })
        } else {
            None
        };
        let pm_timer = parse_fadt_pm_timer(table.bytes, flags)?;

        let (primary_pm_control, secondary_pm_control, sleep_control) = if hardware_reduced {
            let sleep =
                if table.bytes.len() >= 256 && gas_address(take(table.bytes, 244, 12)?)? != 0 {
                    Some(parse_gas(take(table.bytes, 244, 12)?, 8)?)
                } else {
                    None
                };
            (None, None, sleep)
        } else {
            let register_len = table.bytes[89];
            if register_len < 2 {
                return Err(AcpiError::UnsupportedEncoding);
            }
            let primary = parse_fadt_pm_control(table.bytes, 64, 172)?
                .ok_or(AcpiError::UnsupportedEncoding)?;
            let secondary = parse_fadt_pm_control(table.bytes, 68, 184)?;
            (Some(primary), secondary, None)
        };

        let parsed = Self {
            dsdt_range,
            sci_interrupt: read_u16(table.bytes, 46)?,
            ia_pc_boot_architecture,
            hardware_reduced,
            reset,
            pm_timer,
            pm1a_control: primary_pm_control,
            pm1b_control: secondary_pm_control,
            sleep_control,
        };
        parsed.validate_register_collisions()?;
        Ok(parsed)
    }

    /// Validated DSDT extent containing AML needed for `_S5` evaluation.
    #[must_use]
    pub const fn dsdt_range(self) -> PhysicalRange {
        self.dsdt_range
    }

    /// SCI global interrupt/legacy IRQ identity.
    #[must_use]
    pub const fn sci_interrupt(self) -> u16 {
        self.sci_interrupt
    }

    /// Checked IA-PC legacy-device capability flags.
    #[must_use]
    pub const fn ia_pc_boot_architecture(self) -> IaPcBootArchitecture {
        self.ia_pc_boot_architecture
    }

    /// Whether the hardware-reduced ACPI programming model is active.
    #[must_use]
    pub const fn hardware_reduced(self) -> bool {
        self.hardware_reduced
    }

    /// Optional complete-system reset register.
    #[must_use]
    pub const fn reset(self) -> Option<ResetRegister> {
        self.reset
    }

    /// Optional fixed-hardware power-management timer.
    #[must_use]
    pub const fn pm_timer(self) -> Option<PmTimer> {
        self.pm_timer
    }

    /// Primary fixed-hardware PM1 control register.
    #[must_use]
    pub const fn pm1a_control(self) -> Option<GenericRegister> {
        self.pm1a_control
    }

    /// Optional secondary fixed-hardware PM1 control register.
    #[must_use]
    pub const fn pm1b_control(self) -> Option<GenericRegister> {
        self.pm1b_control
    }

    /// Hardware-reduced sleep-control register.
    #[must_use]
    pub const fn sleep_control(self) -> Option<GenericRegister> {
        self.sleep_control
    }

    fn registers(self) -> [Option<GenericRegister>; 5] {
        [
            self.reset.map(|reset| reset.register),
            self.pm_timer.map(|timer| timer.register),
            self.pm1a_control,
            self.pm1b_control,
            self.sleep_control,
        ]
    }

    fn validate_register_collisions(self) -> Result<(), AcpiError> {
        let registers = self.registers();
        for index in 0..registers.len() {
            let Some(register) = registers[index] else {
                continue;
            };
            for previous in registers[..index].iter().copied().flatten() {
                if register.overlaps(previous) {
                    return Err(AcpiError::OverlappingRange);
                }
            }
        }
        Ok(())
    }
}

fn parse_fadt_pm_timer(bytes: &[u8], flags: u32) -> Result<Option<PmTimer>, AcpiError> {
    let legacy_address = u64::from(read_u32(bytes, 76)?);
    let legacy_byte_len = bytes[91];

    let extended = match bytes.len() {
        ..=208 => None,
        209..=219 => return Err(AcpiError::InvalidLength),
        _ => {
            let gas = take(bytes, 208, 12)?;
            if gas.iter().all(|byte| *byte == 0) {
                None
            } else if gas_address(gas)? == 0 {
                return Err(AcpiError::InvalidAddress);
            } else {
                Some(parse_gas(gas, 32)?)
            }
        }
    };

    let legacy = if legacy_address == 0 {
        if legacy_byte_len != 0 && !(legacy_byte_len == 4 && extended.is_some()) {
            return Err(AcpiError::UnsupportedEncoding);
        }
        None
    } else {
        if legacy_byte_len != 4 {
            return Err(AcpiError::UnsupportedEncoding);
        }
        if legacy_address
            .checked_add(4)
            .is_none_or(|end| end > 0x1_0000)
            || !legacy_address.is_multiple_of(4)
        {
            return Err(AcpiError::InvalidAddress);
        }
        Some(GenericRegister {
            space: RegisterSpace::SystemIo,
            address: legacy_address,
            bit_width: 32,
            access_bytes: 4,
        })
    };

    let register = match (legacy, extended) {
        (Some(legacy), Some(extended)) if legacy != extended => {
            return Err(AcpiError::UnsupportedEncoding);
        }
        (Some(register), _) | (_, Some(register)) => register,
        (None, None) => return Ok(None),
    };
    Ok(Some(PmTimer {
        register,
        counter_bits: if flags & (1 << 8) == 0 { 24 } else { 32 },
    }))
}

fn parse_fadt_pm_control(
    bytes: &[u8],
    legacy_offset: usize,
    extended_offset: usize,
) -> Result<Option<GenericRegister>, AcpiError> {
    if bytes.len() >= extended_offset + 12 {
        let extended = take(bytes, extended_offset, 12)?;
        if gas_address(extended)? != 0 {
            return parse_gas(extended, 16).map(Some);
        }
    }
    let legacy_address = u64::from(read_u32(bytes, legacy_offset)?);
    if legacy_address == 0 {
        return Ok(None);
    }
    if legacy_address + 2 > 0x1_0000 || !legacy_address.is_multiple_of(2) {
        return Err(AcpiError::InvalidAddress);
    }
    Ok(Some(GenericRegister {
        space: RegisterSpace::SystemIo,
        address: legacy_address,
        bit_width: 16,
        access_bytes: 2,
    }))
}

/// Fully validated ACPI facts required before generic x86 PCI virtio boot.
pub struct X86VirtioAcpi<'a, M: AcpiMemory + ?Sized> {
    tables: AcpiTables<'a, M>,
    mcfg: Mcfg<'a>,
    madt: Madt<'a>,
    spcr: Option<Spcr>,
    fadt: Option<Fadt>,
}

impl<'a, M: AcpiMemory + ?Sized> X86VirtioAcpi<'a, M> {
    /// Discover a complete PCI-ECAM and APIC topology transactionally.
    ///
    /// # Errors
    ///
    /// In addition to root failures, rejects absent/duplicate MCFG or MADT,
    /// malformed table-specific entries, and overlaps among ACPI tables, ECAM
    /// windows, local APIC, and I/O APIC register pages.
    pub fn discover(
        rsdp_physical_address: u64,
        rsdp_bytes: &[u8],
        memory: &'a M,
    ) -> Result<Self, AcpiError> {
        let tables = AcpiTables::parse(rsdp_physical_address, rsdp_bytes, memory)?;
        let mcfg_table = tables
            .table_by_signature(*b"MCFG")?
            .ok_or(AcpiError::MissingMcfg)?;
        let madt_table = tables
            .table_by_signature(*b"APIC")?
            .ok_or(AcpiError::MissingMadt)?;
        let mcfg = Mcfg::parse(mcfg_table)?;
        let madt = Madt::parse(madt_table)?;
        let spcr = tables
            .table_by_signature(*b"SPCR")?
            .map(Spcr::parse)
            .transpose()?;
        let fadt = tables
            .table_by_signature(*b"FACP")?
            .map(|table| Fadt::parse(table, memory))
            .transpose()?;
        validate_x86_resource_ranges(&tables, mcfg, madt, spcr, fadt)?;
        Ok(Self {
            tables,
            mcfg,
            madt,
            spcr,
            fadt,
        })
    }

    /// Structurally validated root tables.
    #[must_use]
    pub const fn tables(&self) -> &AcpiTables<'a, M> {
        &self.tables
    }

    /// Validated PCI ECAM allocations.
    #[must_use]
    pub const fn mcfg(&self) -> Mcfg<'a> {
        self.mcfg
    }

    /// Validated x86 interrupt topology and routes.
    #[must_use]
    pub const fn madt(&self) -> Madt<'a> {
        self.madt
    }

    /// Optional validated serial-console description.
    #[must_use]
    pub const fn spcr(&self) -> Option<Spcr> {
        self.spcr
    }

    /// Optional validated fixed power/lifecycle description.
    #[must_use]
    pub const fn fadt(&self) -> Option<Fadt> {
        self.fadt
    }
}

fn validate_x86_resource_ranges<M: AcpiMemory + ?Sized>(
    tables: &AcpiTables<'_, M>,
    mcfg: Mcfg<'_>,
    madt: Madt<'_>,
    spcr: Option<Spcr>,
    fadt: Option<Fadt>,
) -> Result<(), AcpiError> {
    let local_apic = madt.local_apic_range();
    if tables.every_table_range_overlaps(local_apic)? {
        return Err(AcpiError::OverlappingRange);
    }
    for segment_index in 0..mcfg.segment_count() {
        let segment = mcfg
            .segment(segment_index)
            .ok_or(AcpiError::InvalidLength)?;
        let ecam = segment.physical_range();
        if ecam.overlaps(local_apic) || tables.every_table_range_overlaps(ecam)? {
            return Err(AcpiError::OverlappingRange);
        }
        for entry in madt.entries() {
            if let MadtEntry::IoApic(controller) = entry
                && ecam.overlaps(controller.physical_range())
            {
                return Err(AcpiError::OverlappingRange);
            }
        }
    }
    for entry in madt.entries() {
        if let MadtEntry::IoApic(controller) = entry
            && tables.every_table_range_overlaps(controller.physical_range())?
        {
            return Err(AcpiError::OverlappingRange);
        }
    }
    validate_optional_resource_ranges(tables, mcfg, madt, spcr, fadt)?;
    Ok(())
}

fn validate_optional_resource_ranges<M: AcpiMemory + ?Sized>(
    tables: &AcpiTables<'_, M>,
    mcfg: Mcfg<'_>,
    madt: Madt<'_>,
    spcr: Option<Spcr>,
    fadt: Option<Fadt>,
) -> Result<(), AcpiError> {
    let serial = spcr.and_then(Spcr::console);
    if let Some(console) = serial {
        let extent = console.register_extent()?;
        validate_register_against_inventory(tables, mcfg, madt, extent, fadt)?;
        if let Some(pci) = console.pci {
            let described = (0..mcfg.segment_count()).any(|index| {
                mcfg.segment(index).is_some_and(|segment| {
                    segment.segment_group == u16::from(pci.segment_group)
                        && (segment.start_bus..=segment.end_bus).contains(&pci.bus)
                })
            });
            if !described {
                return Err(AcpiError::InvalidAddress);
            }
        }
    }
    if let Some(fadt) = fadt {
        if tables.every_table_range_overlaps(fadt.dsdt_range)? {
            return Err(AcpiError::OverlappingRange);
        }
        if fadt.dsdt_range.overlaps(madt.local_apic_range()) {
            return Err(AcpiError::OverlappingRange);
        }
        for index in 0..mcfg.segment_count() {
            if mcfg
                .segment(index)
                .is_some_and(|segment| fadt.dsdt_range.overlaps(segment.physical_range()))
            {
                return Err(AcpiError::OverlappingRange);
            }
        }
        for entry in madt.entries() {
            if let MadtEntry::IoApic(controller) = entry
                && fadt.dsdt_range.overlaps(controller.physical_range())
            {
                return Err(AcpiError::OverlappingRange);
            }
        }
        for register in fadt.registers().into_iter().flatten() {
            validate_register_against_inventory(tables, mcfg, madt, register, Some(fadt))?;
            if serial.is_some_and(|console| {
                console
                    .register_extent()
                    .is_ok_and(|serial| register.overlaps(serial))
            }) {
                return Err(AcpiError::OverlappingRange);
            }
        }
    }
    Ok(())
}

fn validate_register_against_inventory<M: AcpiMemory + ?Sized>(
    tables: &AcpiTables<'_, M>,
    mcfg: Mcfg<'_>,
    madt: Madt<'_>,
    register: GenericRegister,
    fadt: Option<Fadt>,
) -> Result<(), AcpiError> {
    let Some(range) = register.physical_range() else {
        return Ok(());
    };
    if tables.every_table_range_overlaps(range)?
        || range.overlaps(madt.local_apic_range())
        || fadt.is_some_and(|fadt| range.overlaps(fadt.dsdt_range))
    {
        return Err(AcpiError::OverlappingRange);
    }
    for index in 0..mcfg.segment_count() {
        if mcfg
            .segment(index)
            .is_some_and(|segment| range.overlaps(segment.physical_range()))
        {
            return Err(AcpiError::OverlappingRange);
        }
    }
    for entry in madt.entries() {
        if let MadtEntry::IoApic(io_apic) = entry
            && range.overlaps(io_apic.physical_range())
        {
            return Err(AcpiError::OverlappingRange);
        }
    }
    Ok(())
}

fn table_at<M: AcpiMemory + ?Sized>(
    memory: &M,
    physical_address: u64,
) -> Result<Sdt<'_>, AcpiError> {
    if physical_address == 0 || physical_address >= X86_PHYSICAL_LIMIT {
        return Err(AcpiError::InvalidAddress);
    }
    let header_region = memory
        .region(physical_address, SDT_HEADER_BYTES)
        .ok_or(AcpiError::Truncated)?;
    let header = take(header_region, 0, SDT_HEADER_BYTES)?;
    let declared_len = read_u32(header, 4)?;
    let byte_len = usize::try_from(declared_len).map_err(|_| AcpiError::InvalidLength)?;
    if !(SDT_HEADER_BYTES..=MAX_SDT_BYTES).contains(&byte_len) {
        return Err(AcpiError::InvalidLength);
    }
    let range = PhysicalRange::new(physical_address, u64::from(declared_len), 1)?;
    if range.end() > X86_PHYSICAL_LIMIT {
        return Err(AcpiError::InvalidAddress);
    }
    let complete_region = memory
        .region(physical_address, byte_len)
        .ok_or(AcpiError::Truncated)?;
    let complete = take(complete_region, 0, byte_len)?;
    if &complete[..SDT_HEADER_BYTES] != header {
        return Err(AcpiError::ChecksumMismatch);
    }
    Sdt::parse(complete)
}

fn valid_oem_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b' ')
}

fn checksum_valid(bytes: &[u8]) -> bool {
    bytes.iter().copied().fold(0u8, u8::wrapping_add) == 0
}

fn take(bytes: &[u8], offset: usize, byte_len: usize) -> Result<&[u8], AcpiError> {
    let end = offset
        .checked_add(byte_len)
        .ok_or(AcpiError::InvalidLength)?;
    bytes.get(offset..end).ok_or(AcpiError::Truncated)
}

fn take_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], AcpiError> {
    take(bytes, offset, N)?
        .try_into()
        .map_err(|_| AcpiError::Truncated)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AcpiError> {
    Ok(u16::from_le_bytes(take_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AcpiError> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AcpiError> {
    Ok(u64::from_le_bytes(take_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use core::cell::Cell;
    use std::vec;
    use std::vec::Vec;

    const RSDP_ADDRESS: u64 = 0x1000;
    const XSDT_ADDRESS: u64 = 0x2000;
    const MCFG_ADDRESS: u64 = 0x3000;
    const MADT_ADDRESS: u64 = 0x4000;
    const EXTRA_ADDRESS: u64 = 0x5000;
    const DSDT_ADDRESS: u64 = 0x6000;
    const SPCR_ADDRESS: u64 = 0x7000;
    const FADT_ADDRESS: u64 = 0x8000;

    struct Mapping {
        address: u64,
        bytes: Vec<u8>,
    }

    struct TestMemory {
        mappings: Vec<Mapping>,
    }

    impl AcpiMemory for TestMemory {
        fn region(&self, physical_address: u64, byte_len: usize) -> Option<&[u8]> {
            self.mappings.iter().find_map(|mapping| {
                if mapping.address == physical_address && mapping.bytes.len() >= byte_len {
                    Some(mapping.bytes.as_slice())
                } else {
                    None
                }
            })
        }
    }

    struct CountingMemory {
        inner: TestMemory,
        region_calls: Cell<usize>,
    }

    impl AcpiMemory for CountingMemory {
        fn region(&self, physical_address: u64, byte_len: usize) -> Option<&[u8]> {
            self.region_calls.set(self.region_calls.get() + 1);
            self.inner.region(physical_address, byte_len)
        }
    }

    fn checksum(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        let sum = bytes.iter().copied().fold(0u8, u8::wrapping_add);
        bytes[checksum_offset] = 0u8.wrapping_sub(sum);
    }

    fn sdt(signature: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; SDT_HEADER_BYTES + body.len()];
        bytes[..4].copy_from_slice(&signature);
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        bytes[4..8].copy_from_slice(&len.to_le_bytes());
        bytes[8] = 1;
        bytes[10..16].copy_from_slice(b"TROE  ");
        bytes[16..24].copy_from_slice(b"CLOUDVM ");
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        bytes[28..32].copy_from_slice(b"TROE");
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[SDT_HEADER_BYTES..].copy_from_slice(body);
        checksum(&mut bytes, 9);
        bytes
    }

    fn rsdp_v2(root: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; RSDP_V2_BYTES];
        bytes[..8].copy_from_slice(b"RSD PTR ");
        bytes[9..15].copy_from_slice(b"TROE  ");
        bytes[15] = 2;
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        let rsdp_len = u32::try_from(RSDP_V2_BYTES).unwrap_or_default();
        bytes[20..24].copy_from_slice(&rsdp_len.to_le_bytes());
        bytes[24..32].copy_from_slice(&root.to_le_bytes());
        checksum(&mut bytes[..RSDP_V1_BYTES], 8);
        checksum(&mut bytes, 32);
        bytes
    }

    fn rsdp_v1(root: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; RSDP_V1_BYTES];
        bytes[..8].copy_from_slice(b"RSD PTR ");
        bytes[9..15].copy_from_slice(b"TROE  ");
        bytes[16..20].copy_from_slice(&root.to_le_bytes());
        checksum(&mut bytes, 8);
        bytes
    }

    fn mcfg(entries: &[(u64, u16, u8, u8)]) -> Vec<u8> {
        let mut body = vec![0u8; MCFG_PREFIX_BYTES + entries.len() * MCFG_ENTRY_BYTES];
        for (index, (base, segment, start, end)) in entries.iter().copied().enumerate() {
            let offset = MCFG_PREFIX_BYTES + index * MCFG_ENTRY_BYTES;
            body[offset..offset + 8].copy_from_slice(&base.to_le_bytes());
            body[offset + 8..offset + 10].copy_from_slice(&segment.to_le_bytes());
            body[offset + 10] = start;
            body[offset + 11] = end;
        }
        sdt(*b"MCFG", &body)
    }

    fn local_apic(processor_uid: u8, apic_id: u8, flags: u32) -> Vec<u8> {
        let mut entry = vec![0, 8, processor_uid, apic_id];
        entry.extend_from_slice(&flags.to_le_bytes());
        entry
    }

    fn io_apic(id: u8, address: u32, gsi_base: u32) -> Vec<u8> {
        let mut entry = vec![1, 12, id, 0];
        entry.extend_from_slice(&address.to_le_bytes());
        entry.extend_from_slice(&gsi_base.to_le_bytes());
        entry
    }

    fn iso(source: u8, gsi: u32, flags: u16) -> Vec<u8> {
        let mut entry = vec![2, 10, 0, source];
        entry.extend_from_slice(&gsi.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry
    }

    fn madt(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        for entry in entries {
            body.extend_from_slice(entry);
        }
        sdt(*b"APIC", &body)
    }

    fn xsdt(addresses: &[u64]) -> Vec<u8> {
        let mut body = Vec::new();
        for address in addresses {
            body.extend_from_slice(&address.to_le_bytes());
        }
        sdt(*b"XSDT", &body)
    }

    fn spcr(revision: u8) -> Vec<u8> {
        let byte_len = if revision == 4 { 90 } else { 80 };
        let mut bytes = sdt(*b"SPCR", &vec![0; byte_len - SDT_HEADER_BYTES]);
        bytes[8] = revision;
        bytes[36] = 0;
        bytes[40] = 1;
        bytes[41] = 8;
        bytes[43] = 1;
        bytes[44..52].copy_from_slice(&0x3f8u64.to_le_bytes());
        bytes[52] = 3;
        bytes[53] = 4;
        bytes[54..58].copy_from_slice(&4u32.to_le_bytes());
        bytes[58] = 7;
        bytes[60] = 1;
        bytes[62] = 2;
        bytes[64..66].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[66..68].copy_from_slice(&u16::MAX.to_le_bytes());
        if revision >= 3 {
            bytes[76..80].copy_from_slice(&1_843_200u32.to_le_bytes());
        }
        if revision == 4 {
            bytes[84..86].copy_from_slice(&2u16.to_le_bytes());
            bytes[86..88].copy_from_slice(&88u16.to_le_bytes());
            bytes[88] = b'.';
            bytes[89] = 0;
        }
        checksum(&mut bytes, 9);
        bytes
    }

    fn fadt() -> Vec<u8> {
        let mut bytes = sdt(*b"FACP", &vec![0; 244 - SDT_HEADER_BYTES]);
        bytes[8] = 6;
        bytes[40..44].copy_from_slice(&0x6000u32.to_le_bytes());
        bytes[46..48].copy_from_slice(&9u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&0x604u32.to_le_bytes());
        bytes[76..80].copy_from_slice(&0x608u32.to_le_bytes());
        bytes[89] = 2;
        bytes[91] = 4;
        bytes[112..116].copy_from_slice(&(1u32 << 10).to_le_bytes());
        bytes[116] = 1;
        bytes[117] = 8;
        bytes[119] = 1;
        bytes[120..128].copy_from_slice(&0xcf9u64.to_le_bytes());
        bytes[128] = 6;
        bytes[140..148].copy_from_slice(&DSDT_ADDRESS.to_le_bytes());
        bytes[208] = 1;
        bytes[209] = 32;
        bytes[212..220].copy_from_slice(&0x608u64.to_le_bytes());
        checksum(&mut bytes, 9);
        bytes
    }

    fn rsdt(addresses: &[u32]) -> Vec<u8> {
        let mut body = Vec::new();
        for address in addresses {
            body.extend_from_slice(&address.to_le_bytes());
        }
        sdt(*b"RSDT", &body)
    }

    fn valid_fixture() -> (Vec<u8>, TestMemory) {
        let rsdp = rsdp_v2(XSDT_ADDRESS);
        let root = xsdt(&[MCFG_ADDRESS, MADT_ADDRESS, EXTRA_ADDRESS]);
        let mcfg = mcfg(&[(0x8000_0000, 0, 0, 63)]);
        let madt = madt(&[
            local_apic(0, 0, 1),
            io_apic(1, 0xfec0_0000, 0),
            iso(0, 2, 0),
        ]);
        let extra = sdt(*b"TEST", &[1, 2, 3, 4]);
        (
            rsdp,
            TestMemory {
                mappings: vec![
                    Mapping {
                        address: XSDT_ADDRESS,
                        bytes: root,
                    },
                    Mapping {
                        address: MCFG_ADDRESS,
                        bytes: mcfg,
                    },
                    Mapping {
                        address: MADT_ADDRESS,
                        bytes: madt,
                    },
                    Mapping {
                        address: EXTRA_ADDRESS,
                        bytes: extra,
                    },
                ],
            },
        )
    }

    fn full_fixture(spcr_revision: u8) -> (Vec<u8>, TestMemory) {
        let rsdp = rsdp_v2(XSDT_ADDRESS);
        let root = xsdt(&[MCFG_ADDRESS, MADT_ADDRESS, SPCR_ADDRESS, FADT_ADDRESS]);
        (
            rsdp,
            TestMemory {
                mappings: vec![
                    Mapping {
                        address: XSDT_ADDRESS,
                        bytes: root,
                    },
                    Mapping {
                        address: MCFG_ADDRESS,
                        bytes: mcfg(&[(0x8000_0000, 0, 0, 63)]),
                    },
                    Mapping {
                        address: MADT_ADDRESS,
                        bytes: madt(&[
                            local_apic(0, 0, 1),
                            io_apic(1, 0xfec0_0000, 0),
                            iso(4, 4, 0),
                        ]),
                    },
                    Mapping {
                        address: SPCR_ADDRESS,
                        bytes: spcr(spcr_revision),
                    },
                    Mapping {
                        address: FADT_ADDRESS,
                        bytes: fadt(),
                    },
                    Mapping {
                        address: DSDT_ADDRESS,
                        bytes: sdt(*b"DSDT", &[0x08, b'_', b'S', b'5', b'_']),
                    },
                ],
            },
        )
    }

    #[test]
    fn discovers_complete_xsdt_cloud_contract() {
        let (rsdp, memory) = valid_fixture();
        let acpi = X86VirtioAcpi::discover(RSDP_ADDRESS, &rsdp, &memory);
        assert!(acpi.is_ok());
        let Ok(acpi) = acpi else { return };
        assert_eq!(acpi.tables().root_kind(), RootKind::Xsdt);
        assert_eq!(acpi.tables().root_table_count(), 3);
        assert_eq!(acpi.mcfg().segment_count(), 1);
        let Some(segment) = acpi.mcfg().segment(0) else {
            return;
        };
        assert_eq!(segment.segment_group(), 0);
        assert_eq!(
            segment.configuration_address(2, 3, 1, 0x44),
            Some(0x8021_9044)
        );
        assert_eq!(acpi.madt().local_apic_address(), 0xfee0_0000);
        assert!(acpi.madt().legacy_pic_compatible());
        let entries: Vec<_> = acpi.madt().entries().collect();
        assert_eq!(entries.len(), 3);
        let MadtEntry::InterruptSourceOverride(route) = entries[2] else {
            return;
        };
        assert_eq!(route.source_irq(), 0);
        assert_eq!(route.global_interrupt(), 2);
        assert_eq!(route.resolved_polarity(), IntiPolarity::ActiveHigh);
        assert_eq!(route.resolved_trigger(), IntiTrigger::Edge);
    }

    #[test]
    fn discovers_optional_spcr_and_fadt_inventory() {
        for revision in [1, 2, 3, 4] {
            let (rsdp, memory) = full_fixture(revision);
            let parsed = X86VirtioAcpi::discover(RSDP_ADDRESS, &rsdp, &memory);
            assert!(parsed.is_ok(), "SPCR revision {revision}");
            let Ok(parsed) = parsed else { continue };
            let Some(console) = parsed.spcr().and_then(Spcr::console) else {
                continue;
            };
            assert_eq!(console.interface(), SerialInterface::Uart16550);
            assert_eq!(console.register().space(), RegisterSpace::SystemIo);
            assert_eq!(console.register().address(), 0x3f8);
            assert_eq!(console.legacy_irq(), Some(4));
            assert_eq!(console.global_interrupt(), Some(4));
            assert_eq!(console.baud_rate(), Some(115_200));
            assert_eq!(
                console.uart_clock_hz(),
                (revision >= 3).then_some(1_843_200)
            );
            let Some(power) = parsed.fadt() else { continue };
            assert_eq!(power.dsdt_range().start(), DSDT_ADDRESS);
            assert_eq!(power.sci_interrupt(), 9);
            assert!(!power.hardware_reduced());
            let Some(reset) = power.reset() else { continue };
            assert_eq!(reset.register().address(), 0xcf9);
            assert_eq!(reset.value(), 6);
            let Some(timer) = power.pm_timer() else {
                continue;
            };
            assert_eq!(timer.register().space(), RegisterSpace::SystemIo);
            assert_eq!(timer.register().address(), 0x608);
            assert_eq!(timer.register().bit_width(), 32);
            assert_eq!(timer.register().access_bytes(), 4);
            assert_eq!(timer.counter_bits(), 24);
            assert_eq!(
                power.pm1a_control().map(GenericRegister::address),
                Some(0x604)
            );
        }
    }

    #[test]
    fn copied_table_inventory_drives_runtime_discovery() {
        let (rsdp, memory) = full_fixture(4);
        let regions: Vec<_> = memory
            .mappings
            .iter()
            .filter_map(|mapping| CopiedAcpiRegion::new(mapping.address, &mapping.bytes).ok())
            .collect();
        assert_eq!(regions.len(), memory.mappings.len());
        let copied = CopiedAcpiMemory::new(&regions);
        assert!(copied.is_ok());
        let Ok(copied) = copied else { return };
        assert_eq!(copied.region_count(), memory.mappings.len());
        assert!(X86VirtioAcpi::discover(RSDP_ADDRESS, &rsdp, &copied).is_ok());

        let bytes = [0u8; 32];
        let first = CopiedAcpiRegion::new(0x1000, &bytes);
        let second = CopiedAcpiRegion::new(0x1010, &bytes);
        assert!(first.is_ok() && second.is_ok());
        let (Ok(first), Ok(second)) = (first, second) else {
            return;
        };
        assert!(matches!(
            CopiedAcpiMemory::new(&[first, second]),
            Err(AcpiError::OverlappingRange)
        ));
    }

    #[test]
    fn optional_tables_are_checksum_and_truncation_closed() {
        let (rsdp, memory) = full_fixture(4);
        for target_address in [SPCR_ADDRESS, FADT_ADDRESS, DSDT_ADDRESS] {
            let Some(target) = memory
                .mappings
                .iter()
                .find(|mapping| mapping.address == target_address)
            else {
                continue;
            };
            for byte_index in 0..target.bytes.len() {
                let mappings = memory
                    .mappings
                    .iter()
                    .map(|mapping| {
                        let mut bytes = mapping.bytes.clone();
                        if mapping.address == target_address {
                            bytes[byte_index] = bytes[byte_index].wrapping_add(1);
                        }
                        Mapping {
                            address: mapping.address,
                            bytes,
                        }
                    })
                    .collect();
                assert!(
                    X86VirtioAcpi::discover(RSDP_ADDRESS, &rsdp, &TestMemory { mappings }).is_err()
                );
            }
            for length in 0..target.bytes.len() {
                let mappings = memory
                    .mappings
                    .iter()
                    .map(|mapping| Mapping {
                        address: mapping.address,
                        bytes: if mapping.address == target_address {
                            mapping.bytes[..length].to_vec()
                        } else {
                            mapping.bytes.clone()
                        },
                    })
                    .collect();
                assert!(
                    X86VirtioAcpi::discover(RSDP_ADDRESS, &rsdp, &TestMemory { mappings }).is_err()
                );
            }
        }
    }

    #[test]
    fn spcr_rejects_unsupported_width_and_reserved_interrupts() {
        let mut wrong_width = spcr(3);
        wrong_width[41] = 32;
        checksum(&mut wrong_width, 9);
        let parsed = Sdt::parse(&wrong_width).and_then(Spcr::parse);
        assert_eq!(parsed.err(), Some(AcpiError::UnsupportedEncoding));

        let mut unsupported_interrupt = spcr(3);
        unsupported_interrupt[52] |= 1 << 3;
        checksum(&mut unsupported_interrupt, 9);
        let parsed = Sdt::parse(&unsupported_interrupt).and_then(Spcr::parse);
        assert_eq!(parsed.err(), Some(AcpiError::UnsupportedEncoding));
    }

    #[test]
    fn fadt_exposes_checked_ia_pc_boot_architecture_flags() {
        let memory = TestMemory {
            mappings: vec![Mapping {
                address: DSDT_ADDRESS,
                bytes: sdt(*b"DSDT", &[0]),
            }],
        };
        let parse = |bytes: &[u8]| Sdt::parse(bytes).and_then(|table| Fadt::parse(table, &memory));

        let mut present = fadt();
        let flags: u16 = (1 << 0) | (1 << 1) | (1 << 5);
        present[109..111].copy_from_slice(&flags.to_le_bytes());
        checksum(&mut present, 9);
        let parsed = parse(&present);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else { return };
        let boot_architecture = parsed.ia_pc_boot_architecture();
        assert!(boot_architecture.legacy_devices_present());
        assert!(boot_architecture.i8042_present());
        assert_eq!(boot_architecture.raw(), flags);

        let mut reserved = fadt();
        reserved[109..111].copy_from_slice(&(1_u16 << 6).to_le_bytes());
        checksum(&mut reserved, 9);
        assert_eq!(
            parse(&reserved).err(),
            Some(AcpiError::InvalidReservedField)
        );

        let mut truncated = sdt(*b"FACP", &[0; 115 - SDT_HEADER_BYTES]);
        truncated[8] = 6;
        checksum(&mut truncated, 9);
        assert_eq!(parse(&truncated).err(), Some(AcpiError::InvalidLength));
    }

    #[test]
    fn fadt_reconciles_checked_legacy_and_extended_pm_timer() {
        let memory = TestMemory {
            mappings: vec![Mapping {
                address: DSDT_ADDRESS,
                bytes: sdt(*b"DSDT", &[0]),
            }],
        };
        let parse = |bytes: &[u8]| Sdt::parse(bytes).and_then(|table| Fadt::parse(table, &memory));

        let parsed = parse(&fadt());
        assert!(parsed.is_ok());
        let Some(timer) = parsed.ok().and_then(Fadt::pm_timer) else {
            return;
        };
        assert_eq!(timer.register().space(), RegisterSpace::SystemIo);
        assert_eq!(timer.register().address(), 0x608);
        assert_eq!(timer.register().bit_width(), 32);
        assert_eq!(timer.register().access_bytes(), 4);
        assert_eq!(timer.counter_bits(), 24);

        let mut wide_counter = fadt();
        let flags = read_u32(&wide_counter, 112).unwrap_or_default() | (1 << 8);
        wide_counter[112..116].copy_from_slice(&flags.to_le_bytes());
        checksum(&mut wide_counter, 9);
        assert_eq!(
            parse(&wide_counter)
                .ok()
                .and_then(Fadt::pm_timer)
                .map(PmTimer::counter_bits),
            Some(32)
        );

        let mut legacy_only = fadt();
        legacy_only[208..220].fill(0);
        checksum(&mut legacy_only, 9);
        assert!(parse(&legacy_only).is_ok_and(|parsed| parsed.pm_timer().is_some()));

        let mut extended_only = fadt();
        extended_only[76..80].fill(0);
        extended_only[91] = 0;
        checksum(&mut extended_only, 9);
        assert!(parse(&extended_only).is_ok_and(|parsed| parsed.pm_timer().is_some()));
    }

    #[test]
    fn fadt_rejects_malformed_or_conflicting_pm_timer() {
        let memory = TestMemory {
            mappings: vec![Mapping {
                address: DSDT_ADDRESS,
                bytes: sdt(*b"DSDT", &[0]),
            }],
        };
        let parse = |bytes: &[u8]| Sdt::parse(bytes).and_then(|table| Fadt::parse(table, &memory));

        let mut bad_legacy_length = fadt();
        bad_legacy_length[91] = 3;
        checksum(&mut bad_legacy_length, 9);
        assert_eq!(
            parse(&bad_legacy_length).err(),
            Some(AcpiError::UnsupportedEncoding)
        );

        let mut bad_extended_width = fadt();
        bad_extended_width[209] = 24;
        checksum(&mut bad_extended_width, 9);
        assert_eq!(
            parse(&bad_extended_width).err(),
            Some(AcpiError::UnsupportedEncoding)
        );

        let mut conflicting_addresses = fadt();
        conflicting_addresses[212..220].copy_from_slice(&0x60cu64.to_le_bytes());
        checksum(&mut conflicting_addresses, 9);
        assert_eq!(
            parse(&conflicting_addresses).err(),
            Some(AcpiError::UnsupportedEncoding)
        );

        let mut zero_extended_address = fadt();
        zero_extended_address[212..220].fill(0);
        checksum(&mut zero_extended_address, 9);
        assert_eq!(
            parse(&zero_extended_address).err(),
            Some(AcpiError::InvalidAddress)
        );

        let mut truncated_extended = fadt();
        truncated_extended.truncate(219);
        truncated_extended[4..8].copy_from_slice(&219u32.to_le_bytes());
        checksum(&mut truncated_extended, 9);
        assert_eq!(
            parse(&truncated_extended).err(),
            Some(AcpiError::InvalidLength)
        );

        let mut colliding = fadt();
        colliding[76..80].copy_from_slice(&0x604u32.to_le_bytes());
        colliding[212..220].copy_from_slice(&0x604u64.to_le_bytes());
        checksum(&mut colliding, 9);
        assert_eq!(parse(&colliding).err(), Some(AcpiError::OverlappingRange));
    }

    #[test]
    fn accepts_v1_rsdt_and_validates_all_children() {
        let root_address = u32::try_from(XSDT_ADDRESS).unwrap_or_default();
        let rsdp = rsdp_v1(root_address);
        let memory = TestMemory {
            mappings: vec![
                Mapping {
                    address: XSDT_ADDRESS,
                    bytes: rsdt(&[0x3000, 0x4000]),
                },
                Mapping {
                    address: MCFG_ADDRESS,
                    bytes: mcfg(&[(0x8000_0000, 0, 0, 0)]),
                },
                Mapping {
                    address: MADT_ADDRESS,
                    bytes: madt(&[local_apic(0, 0, 1), io_apic(1, 0xfec0_0000, 0)]),
                },
            ],
        };
        let parsed = X86VirtioAcpi::discover(RSDP_ADDRESS, &rsdp, &memory);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else { return };
        assert_eq!(parsed.tables().root_kind(), RootKind::Rsdt);
        assert_eq!(parsed.tables().rsdp().revision(), 0);
    }

    #[test]
    fn every_single_byte_rsdp_corruption_fails_checksum_or_structure() {
        let valid = rsdp_v2(XSDT_ADDRESS);
        for index in 0..valid.len() {
            let mut corrupt = valid.clone();
            corrupt[index] = corrupt[index].wrapping_add(1);
            assert!(Rsdp::parse(&corrupt).is_err(), "accepted byte {index}");
        }
    }

    #[test]
    fn every_rsdp_truncation_fails() {
        let valid = rsdp_v2(XSDT_ADDRESS);
        for length in 0..valid.len() {
            assert_eq!(Rsdp::parse(&valid[..length]), Err(AcpiError::Truncated));
        }
    }

    #[test]
    fn every_root_and_child_single_byte_corruption_fails() {
        let (rsdp, memory) = valid_fixture();
        for mapping_index in 0..memory.mappings.len() {
            for byte_index in 0..memory.mappings[mapping_index].bytes.len() {
                let mut mappings: Vec<Mapping> = memory
                    .mappings
                    .iter()
                    .map(|mapping| Mapping {
                        address: mapping.address,
                        bytes: mapping.bytes.clone(),
                    })
                    .collect();
                mappings[mapping_index].bytes[byte_index] =
                    mappings[mapping_index].bytes[byte_index].wrapping_add(1);
                let corrupt = TestMemory { mappings };
                assert!(
                    AcpiTables::parse(RSDP_ADDRESS, &rsdp, &corrupt).is_err(),
                    "accepted mapping {mapping_index} byte {byte_index}"
                );
            }
        }
    }

    #[test]
    fn every_table_truncation_fails_without_panicking() {
        let (rsdp, memory) = valid_fixture();
        for mapping_index in 0..memory.mappings.len() {
            let original_len = memory.mappings[mapping_index].bytes.len();
            for length in 0..original_len {
                let mappings = memory
                    .mappings
                    .iter()
                    .enumerate()
                    .map(|(index, mapping)| Mapping {
                        address: mapping.address,
                        bytes: if index == mapping_index {
                            mapping.bytes[..length].to_vec()
                        } else {
                            mapping.bytes.clone()
                        },
                    })
                    .collect();
                let truncated = TestMemory { mappings };
                assert!(AcpiTables::parse(RSDP_ADDRESS, &rsdp, &truncated).is_err());
            }
        }
    }

    #[test]
    fn rejects_duplicate_and_overlapping_root_children() {
        let rsdp = rsdp_v2(XSDT_ADDRESS);
        let table = sdt(*b"TEST", &[0; 32]);
        let duplicate = TestMemory {
            mappings: vec![
                Mapping {
                    address: XSDT_ADDRESS,
                    bytes: xsdt(&[EXTRA_ADDRESS, EXTRA_ADDRESS]),
                },
                Mapping {
                    address: EXTRA_ADDRESS,
                    bytes: table.clone(),
                },
            ],
        };
        assert!(matches!(
            AcpiTables::parse(RSDP_ADDRESS, &rsdp, &duplicate),
            Err(AcpiError::DuplicateEntry)
        ));

        let overlapping = TestMemory {
            mappings: vec![
                Mapping {
                    address: XSDT_ADDRESS,
                    bytes: xsdt(&[EXTRA_ADDRESS, EXTRA_ADDRESS + 16]),
                },
                Mapping {
                    address: EXTRA_ADDRESS,
                    bytes: table.clone(),
                },
                Mapping {
                    address: EXTRA_ADDRESS + 16,
                    bytes: table,
                },
            ],
        };
        assert!(matches!(
            AcpiTables::parse(RSDP_ADDRESS, &rsdp, &overlapping),
            Err(AcpiError::OverlappingRange)
        ));
    }

    #[test]
    fn rejects_bad_root_pointer_width_and_excessive_count() {
        let rsdp = rsdp_v2(XSDT_ADDRESS);
        let malformed = TestMemory {
            mappings: vec![Mapping {
                address: XSDT_ADDRESS,
                bytes: sdt(*b"XSDT", &[0; 7]),
            }],
        };
        assert!(matches!(
            AcpiTables::parse(RSDP_ADDRESS, &rsdp, &malformed),
            Err(AcpiError::InvalidLength)
        ));

        let too_many = TestMemory {
            mappings: vec![Mapping {
                address: XSDT_ADDRESS,
                bytes: sdt(*b"XSDT", &vec![0; (MAX_ROOT_ENTRIES + 1) * 8]),
            }],
        };
        assert!(matches!(
            AcpiTables::parse(RSDP_ADDRESS, &rsdp, &too_many),
            Err(AcpiError::TooManyEntries)
        ));
    }

    #[test]
    fn max_root_inventory_is_read_once_and_then_served_from_cache() {
        let mut addresses = Vec::with_capacity(MAX_ROOT_ENTRIES);
        let mut mappings = Vec::with_capacity(MAX_ROOT_ENTRIES + 1);
        for index in 0..MAX_ROOT_ENTRIES {
            let address = 0x10_000 + u64::try_from(index).unwrap_or_default() * 0x1000_u64;
            addresses.push(address);
            mappings.push(Mapping {
                address,
                bytes: sdt(*b"TEST", &[u8::try_from(index).unwrap_or_default()]),
            });
        }
        mappings.push(Mapping {
            address: XSDT_ADDRESS,
            bytes: xsdt(&addresses),
        });
        let memory = CountingMemory {
            inner: TestMemory { mappings },
            region_calls: Cell::new(0),
        };
        let rsdp = rsdp_v2(XSDT_ADDRESS);

        let parsed = AcpiTables::parse(RSDP_ADDRESS, &rsdp, &memory);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else { return };
        let expected_initial_reads = 2 * (MAX_ROOT_ENTRIES + 1);
        assert_eq!(memory.region_calls.get(), expected_initial_reads);
        assert_eq!(parsed.root_table_count(), MAX_ROOT_ENTRIES);

        for index in 0..MAX_ROOT_ENTRIES {
            assert!(matches!(parsed.root_table(index), Ok(Some(_))));
        }
        assert!(matches!(parsed.table_by_signature(*b"NONE"), Ok(None)));
        let candidate = PhysicalRange::new(0x8000_0000, 0x1000, 1);
        assert!(candidate.is_ok());
        let Ok(candidate) = candidate else { return };
        assert_eq!(parsed.every_table_range_overlaps(candidate), Ok(false));
        assert_eq!(memory.region_calls.get(), expected_initial_reads);
    }

    #[test]
    fn mcfg_rejects_bus_and_physical_overlaps_and_reserved_bytes() {
        let cases = [
            mcfg(&[(0x8000_0000, 0, 0, 31), (0x9000_0000, 0, 31, 63)]),
            mcfg(&[(0x8000_0000, 0, 0, 63), (0x8200_0000, 1, 0, 63)]),
        ];
        for malformed_mcfg in cases {
            let table = Sdt::parse(&malformed_mcfg);
            assert!(table.is_ok());
            let Ok(table) = table else { continue };
            assert!(Mcfg::parse(table).is_err());
        }

        let mut reserved = mcfg(&[(0x8000_0000, 0, 0, 0)]);
        reserved[SDT_HEADER_BYTES] = 1;
        checksum(&mut reserved, 9);
        let table = Sdt::parse(&reserved);
        assert!(table.is_ok());
        let Ok(table) = table else { return };
        assert_eq!(
            Mcfg::parse(table).err(),
            Some(AcpiError::InvalidReservedField)
        );
    }

    #[test]
    fn all_valid_ecam_coordinates_stay_inside_the_segment() {
        for start in [0u8, 1, 127, 255] {
            for end in [start, u8::MAX] {
                let table = mcfg(&[(0x1_0000_0000, 7, start, end)]);
                let parsed = Sdt::parse(&table).and_then(Mcfg::parse);
                assert!(parsed.is_ok());
                let Ok(parsed) = parsed else { continue };
                let Some(segment) = parsed.segment(0) else {
                    continue;
                };
                for bus in [start, end] {
                    let Some(address) = segment.configuration_address(bus, 31, 7, 4095) else {
                        continue;
                    };
                    assert!(address >= segment.physical_range().start());
                    assert!(address < segment.physical_range().end());
                }
                assert_eq!(segment.configuration_address(start, 32, 0, 0), None);
                assert_eq!(segment.configuration_address(start, 0, 8, 0), None);
                assert_eq!(segment.configuration_address(start, 0, 0, 4096), None);
            }
        }
    }

    #[test]
    fn madt_rejects_entry_lengths_reserved_flags_and_duplicates() {
        let malformed_entries = [
            vec![0, 7, 0, 0, 1, 0, 0],
            local_apic(0, 0, 4),
            iso(16, 16, 0),
            iso(1, 1, 0b10),
        ];
        for malformed in malformed_entries {
            let table = madt(&[local_apic(0, 0, 1), io_apic(1, 0xfec0_0000, 0), malformed]);
            let parsed = Sdt::parse(&table).and_then(Madt::parse);
            assert!(parsed.is_err());
        }

        let duplicate = madt(&[
            local_apic(0, 0, 1),
            local_apic(1, 0, 1),
            io_apic(1, 0xfec0_0000, 0),
        ]);
        assert!(Sdt::parse(&duplicate).and_then(Madt::parse).is_err());
    }

    #[test]
    fn madt_requires_enabled_cpu_and_nonoverlapping_io_apic() {
        let no_enabled_cpu = madt(&[local_apic(0, 0, 0), io_apic(1, 0xfec0_0000, 0)]);
        assert_eq!(
            Sdt::parse(&no_enabled_cpu).and_then(Madt::parse).err(),
            Some(AcpiError::IncompleteInterruptTopology)
        );

        let overlaps_local = madt(&[local_apic(0, 0, 1), io_apic(1, 0xfee0_0000, 0)]);
        assert_eq!(
            Sdt::parse(&overlaps_local).and_then(Madt::parse).err(),
            Some(AcpiError::OverlappingRange)
        );
    }

    #[test]
    fn discovers_x2apic_and_address_override_without_truncation() {
        let mut x2apic = vec![9, 16, 0, 0];
        x2apic.extend_from_slice(&0x1234u32.to_le_bytes());
        x2apic.extend_from_slice(&1u32.to_le_bytes());
        x2apic.extend_from_slice(&0x5678u32.to_le_bytes());
        let mut address_override = vec![5, 12, 0, 0];
        address_override.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());
        let table = madt(&[x2apic, io_apic(1, 0xfec0_0000, 0), address_override]);
        let parsed = Sdt::parse(&table).and_then(Madt::parse);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else { return };
        assert_eq!(parsed.local_apic_address(), 0x1_0000_0000);
        let Some(MadtEntry::Processor(processor)) = parsed.entries().next() else {
            return;
        };
        assert!(processor.is_x2apic());
        assert_eq!(processor.apic_id(), 0x1234);
        assert_eq!(processor.processor_uid(), 0x5678);
    }

    #[test]
    fn cloud_view_rejects_missing_singletons_and_resource_overlap() {
        let rsdp = rsdp_v2(XSDT_ADDRESS);
        let root = xsdt(&[MCFG_ADDRESS, MADT_ADDRESS]);
        let memory_missing_madt = TestMemory {
            mappings: vec![
                Mapping {
                    address: XSDT_ADDRESS,
                    bytes: xsdt(&[MCFG_ADDRESS]),
                },
                Mapping {
                    address: MCFG_ADDRESS,
                    bytes: mcfg(&[(0x8000_0000, 0, 0, 0)]),
                },
            ],
        };
        assert!(matches!(
            X86VirtioAcpi::discover(RSDP_ADDRESS, &rsdp, &memory_missing_madt),
            Err(AcpiError::MissingMadt)
        ));

        let memory_overlap = TestMemory {
            mappings: vec![
                Mapping {
                    address: XSDT_ADDRESS,
                    bytes: root,
                },
                Mapping {
                    address: MCFG_ADDRESS,
                    bytes: mcfg(&[(0xfee0_0000, 0, 0, 0)]),
                },
                Mapping {
                    address: MADT_ADDRESS,
                    bytes: madt(&[local_apic(0, 0, 1), io_apic(1, 0xfec0_0000, 0)]),
                },
            ],
        };
        assert!(matches!(
            X86VirtioAcpi::discover(RSDP_ADDRESS, &rsdp, &memory_overlap),
            Err(AcpiError::OverlappingRange)
        ));
    }

    #[test]
    fn contiguous_memory_window_is_bounds_checked() {
        let bytes = [0u8; 32];
        let window = MemoryWindow::new(0x1000, &bytes);
        assert!(window.is_ok());
        let Ok(window) = window else { return };
        assert_eq!(window.region(0x1000, 32), Some(bytes.as_slice()));
        assert_eq!(window.region(0x0fff, 1), None);
        assert_eq!(window.region(0x101f, 2), None);
        assert!(MemoryWindow::new(0, &bytes).is_err());
        assert!(MemoryWindow::new(0x1000, &[]).is_err());
    }
}

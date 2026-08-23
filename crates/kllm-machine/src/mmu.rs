//! PE image classification, owned page tables, and native fault vectors.

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
use core::cell::UnsafeCell;
use core::fmt;
#[cfg(target_os = "uefi")]
use core::ptr;

use kllm_memory::{BASE_PAGE_SIZE, MappingPermissions, PhysicalRange};
#[cfg(target_os = "uefi")]
use kllm_memory::{MappingMemoryType, MappingPlan};

const MAX_IMAGE_REGIONS: usize = 64;
const BASE_PAGE_BYTES: usize = 4096;
const PE_SIGNATURE: u32 = 0x0000_4550;
const PE32_PLUS_MAGIC: u16 = 0x020b;
const OPTIONAL_HEADER_MIN_BYTES: usize = 64;
const OPTIONAL_SECTION_ALIGNMENT_OFFSET: usize = 32;
const OPTIONAL_SIZE_OF_IMAGE_OFFSET: usize = 56;
const SECTION_HEADER_BYTES: usize = 40;
const SECTION_EXECUTE: u32 = 0x2000_0000;
const SECTION_WRITE: u32 = 0x8000_0000;

/// One page-granular permission region in the loaded PE image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageRegion {
    range: PhysicalRange,
    permissions: MappingPermissions,
}

impl ImageRegion {
    /// Identity-mapped physical image range.
    #[must_use]
    pub const fn range(self) -> PhysicalRange {
        self.range
    }

    /// Permissions derived from PE section characteristics.
    #[must_use]
    pub const fn permissions(self) -> MappingPermissions {
        self.permissions
    }
}

/// Complete page-granular layout of the running PE/COFF image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageLayout {
    regions: [Option<ImageRegion>; MAX_IMAGE_REGIONS],
    region_count: usize,
}

impl ImageLayout {
    /// Number of classified, non-overlapping image regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.region_count
    }

    /// Return a classified image region by index.
    #[must_use]
    pub const fn region(&self, index: usize) -> Option<ImageRegion> {
        if index < self.region_count {
            self.regions[index]
        } else {
            None
        }
    }
}

/// Observable owned page-table accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MmuStats {
    /// Base pages mapped by the architecture-neutral plan.
    pub mapped_pages: u64,
    /// Base pages consumed by architecture page tables.
    pub table_pages: u64,
}

/// Failures at the native MMU composition boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmuError {
    /// The loaded PE image is malformed or cannot be page-classified safely.
    InvalidImage,
    /// The architecture-neutral plan violates a backend invariant.
    InvalidPlan,
    /// The page-table arena is empty, unaligned, or cannot be addressed.
    InvalidTableArena,
    /// The bounded page-table arena was exhausted.
    TableArenaExhausted,
    /// A virtual or physical address is unsupported by the initial backend.
    AddressUnsupported,
    /// A required processor MMU feature is unavailable.
    UnsupportedCpu,
}

impl fmt::Display for MmuError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidImage => formatter.write_str("loaded PE image is invalid"),
            Self::InvalidPlan => formatter.write_str("mapping plan is invalid"),
            Self::InvalidTableArena => formatter.write_str("page-table arena is invalid"),
            Self::TableArenaExhausted => formatter.write_str("page-table arena exhausted"),
            Self::AddressUnsupported => formatter.write_str("mapping address is unsupported"),
            Self::UnsupportedCpu => formatter.write_str("required MMU feature is unavailable"),
        }
    }
}

fn parse_image_layout(image: &[u8], base: u64) -> Result<ImageLayout, MmuError> {
    if !base.is_multiple_of(BASE_PAGE_SIZE) || image.is_empty() {
        return Err(MmuError::InvalidImage);
    }
    let pe_offset = usize::try_from(read_u32(image, 0x3c)?).map_err(|_| MmuError::InvalidImage)?;
    if read_u32(image, pe_offset)? != PE_SIGNATURE {
        return Err(MmuError::InvalidImage);
    }
    let (section_count, table_start, image_bytes) = parse_image_header(image, pe_offset)?;
    let table_bytes = section_count
        .checked_mul(SECTION_HEADER_BYTES)
        .ok_or(MmuError::InvalidImage)?;
    let _table_end = image
        .get(table_start..checked_add(table_start, table_bytes)?)
        .ok_or(MmuError::InvalidImage)?;
    let mut layout = ImageLayout {
        regions: [None; MAX_IMAGE_REGIONS],
        region_count: 0,
    };
    let mut cursor = 0_u64;

    for index in 0..section_count {
        let header = checked_add(
            table_start,
            index
                .checked_mul(SECTION_HEADER_BYTES)
                .ok_or(MmuError::InvalidImage)?,
        )?;
        let virtual_size = u64::from(read_u32(image, checked_add(header, 8)?)?);
        let virtual_address = u64::from(read_u32(image, checked_add(header, 12)?)?);
        let raw_size = u64::from(read_u32(image, checked_add(header, 16)?)?);
        let size = virtual_size.max(raw_size);
        if size == 0 {
            continue;
        }
        if !virtual_address.is_multiple_of(BASE_PAGE_SIZE) {
            return Err(MmuError::InvalidImage);
        }
        let end = align_up(
            virtual_address
                .checked_add(size)
                .ok_or(MmuError::InvalidImage)?,
            BASE_PAGE_SIZE,
        )?;
        if virtual_address < cursor || end > image_bytes {
            return Err(MmuError::InvalidImage);
        }
        if cursor < virtual_address {
            push_image_region(
                &mut layout,
                base,
                cursor,
                virtual_address,
                MappingPermissions::READ_ONLY,
            )?;
        }
        let characteristics = read_u32(image, checked_add(header, 36)?)?;
        let executable = characteristics & SECTION_EXECUTE != 0;
        let writable = characteristics & SECTION_WRITE != 0;
        if executable && writable {
            return Err(MmuError::InvalidImage);
        }
        let permissions = if executable {
            MappingPermissions::READ_EXECUTE
        } else if writable {
            MappingPermissions::READ_WRITE
        } else {
            MappingPermissions::READ_ONLY
        };
        push_image_region(&mut layout, base, virtual_address, end, permissions)?;
        cursor = end;
    }
    if cursor < image_bytes {
        push_image_region(
            &mut layout,
            base,
            cursor,
            image_bytes,
            MappingPermissions::READ_ONLY,
        )?;
    }
    Ok(layout)
}

fn parse_image_header(image: &[u8], pe_offset: usize) -> Result<(usize, usize, u64), MmuError> {
    let section_count = usize::from(read_u16(image, checked_add(pe_offset, 6)?)?);
    let optional_bytes = usize::from(read_u16(image, checked_add(pe_offset, 20)?)?);
    if optional_bytes < OPTIONAL_HEADER_MIN_BYTES {
        return Err(MmuError::InvalidImage);
    }
    let optional_start = checked_add(pe_offset, 24)?;
    if read_u16(image, optional_start)? != PE32_PLUS_MAGIC {
        return Err(MmuError::InvalidImage);
    }
    let section_alignment = u64::from(read_u32(
        image,
        checked_add(optional_start, OPTIONAL_SECTION_ALIGNMENT_OFFSET)?,
    )?);
    let declared_image_bytes = u64::from(read_u32(
        image,
        checked_add(optional_start, OPTIONAL_SIZE_OF_IMAGE_OFFSET)?,
    )?);
    let actual_image_bytes = u64::try_from(image.len()).map_err(|_| MmuError::InvalidImage)?;
    if section_alignment != BASE_PAGE_SIZE
        || declared_image_bytes != actual_image_bytes
        || !declared_image_bytes.is_multiple_of(BASE_PAGE_SIZE)
    {
        return Err(MmuError::InvalidImage);
    }
    let table_start = checked_add(optional_start, optional_bytes)?;
    Ok((section_count, table_start, declared_image_bytes))
}

fn push_image_region(
    layout: &mut ImageLayout,
    base: u64,
    start: u64,
    end: u64,
    permissions: MappingPermissions,
) -> Result<(), MmuError> {
    if layout.region_count == MAX_IMAGE_REGIONS || start >= end {
        return Err(MmuError::InvalidImage);
    }
    let absolute_start = base.checked_add(start).ok_or(MmuError::InvalidImage)?;
    let page_count = (end - start) / BASE_PAGE_SIZE;
    let range = PhysicalRange::from_pages(absolute_start, page_count)
        .map_err(|_| MmuError::InvalidImage)?;
    layout.regions[layout.region_count] = Some(ImageRegion { range, permissions });
    layout.region_count += 1;
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, MmuError> {
    let raw: [u8; 2] = bytes
        .get(offset..checked_add(offset, 2)?)
        .ok_or(MmuError::InvalidImage)?
        .try_into()
        .map_err(|_| MmuError::InvalidImage)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, MmuError> {
    let raw: [u8; 4] = bytes
        .get(offset..checked_add(offset, 4)?)
        .ok_or(MmuError::InvalidImage)?
        .try_into()
        .map_err(|_| MmuError::InvalidImage)?;
    Ok(u32::from_le_bytes(raw))
}

fn checked_add(left: usize, right: usize) -> Result<usize, MmuError> {
    left.checked_add(right).ok_or(MmuError::InvalidImage)
}

fn align_up(value: u64, alignment: u64) -> Result<u64, MmuError> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
        .ok_or(MmuError::InvalidImage)
}

/// Read and page-classify the running PE image while its UEFI protocol lives.
///
/// # Errors
///
/// Returns [`MmuError::InvalidImage`] when the protocol is unavailable or the
/// bounded in-memory PE layout is malformed, overlapping, or contains W+X.
#[cfg(target_os = "uefi")]
pub fn loaded_image_layout() -> Result<ImageLayout, MmuError> {
    use uefi::boot;
    use uefi::proto::loaded_image::LoadedImage;

    let loaded = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|_| MmuError::InvalidImage)?;
    let (base, size) = loaded.info();
    let base_address = base as usize;
    let byte_count = checked_image_slice_bounds(base_address, size)?;
    // SAFETY: `checked_image_slice_bounds` establishes non-null, alignment,
    // isize, and non-wrapping bounds. LoadedImage guarantees that the single
    // live image allocation contains these initialized, immutable bytes until
    // the protocol is closed or the image is unloaded.
    let image = unsafe { core::slice::from_raw_parts(base.cast::<u8>(), byte_count) };
    parse_image_layout(image, base_address as u64)
}

fn checked_image_slice_bounds(base: usize, size: u64) -> Result<usize, MmuError> {
    let byte_count = usize::try_from(size).map_err(|_| MmuError::InvalidImage)?;
    if base == 0
        || !base.is_multiple_of(BASE_PAGE_BYTES)
        || byte_count == 0
        || !byte_count.is_multiple_of(BASE_PAGE_BYTES)
        || byte_count > isize::MAX as usize
        || base.checked_add(byte_count).is_none()
    {
        return Err(MmuError::InvalidImage);
    }
    Ok(byte_count)
}

#[cfg(target_os = "uefi")]
struct TableArena {
    cursor: u64,
    end: u64,
    used_pages: u64,
}

#[cfg(target_os = "uefi")]
impl TableArena {
    fn new(range: PhysicalRange) -> Result<Self, MmuError> {
        let _start = usize::try_from(range.start()).map_err(|_| MmuError::InvalidTableArena)?;
        let _end = usize::try_from(range.end()).map_err(|_| MmuError::InvalidTableArena)?;
        Ok(Self {
            cursor: range.start(),
            end: range.end(),
            used_pages: 0,
        })
    }

    fn allocate(&mut self) -> Result<u64, MmuError> {
        let next = self
            .cursor
            .checked_add(BASE_PAGE_SIZE)
            .ok_or(MmuError::TableArenaExhausted)?;
        if next > self.end {
            return Err(MmuError::TableArenaExhausted);
        }
        let address = usize::try_from(self.cursor).map_err(|_| MmuError::InvalidTableArena)?;
        let page_bytes =
            usize::try_from(BASE_PAGE_SIZE).map_err(|_| MmuError::InvalidTableArena)?;
        // SAFETY: The kernel grants this builder exclusive ownership of the
        // identity-mapped, page-aligned table arena until activation completes.
        unsafe { ptr::write_bytes(address as *mut u8, 0, page_bytes) };
        self.cursor = next;
        self.used_pages += 1;
        Ok(address as u64)
    }
}

/// Build and activate architecture-owned page tables for `plan`.
///
/// # Errors
///
/// Rejects an invalid mapping plan or table arena, unsupported addresses or
/// processor state, duplicate leaf entries, and table-arena exhaustion.
#[cfg(target_os = "uefi")]
pub fn install_mmu(plan: &MappingPlan, table_arena: PhysicalRange) -> Result<MmuStats, MmuError> {
    if !plan.enforces_global_w_xor_x() || plan.mappings().is_empty() {
        return Err(MmuError::InvalidPlan);
    }
    let capabilities = architecture_mmu_capabilities()?;
    architecture_validate_table_arena(table_arena, capabilities)?;
    let mut arena = TableArena::new(table_arena)?;
    let root = arena.allocate()?;
    for mapping in plan.mappings() {
        let permissions = mapping.permissions();
        let memory_type = mapping.memory_type();
        let pages = mapping.virtual_range().page_count();
        for page in 0..pages {
            let offset = page
                .checked_mul(BASE_PAGE_SIZE)
                .ok_or(MmuError::AddressUnsupported)?;
            let virtual_address = mapping
                .virtual_range()
                .start()
                .checked_add(offset)
                .ok_or(MmuError::AddressUnsupported)?;
            let physical_address = mapping
                .physical_range()
                .start()
                .checked_add(offset)
                .ok_or(MmuError::AddressUnsupported)?;
            architecture_map_page(
                &mut arena,
                root,
                virtual_address,
                physical_address,
                permissions,
                memory_type,
                capabilities,
            )?;
        }
    }
    architecture_activate(root, capabilities);
    Ok(MmuStats {
        mapped_pages: plan.page_count().map_err(|_| MmuError::InvalidPlan)?,
        table_pages: arena.used_pages,
    })
}

/// Install the architecture's native fatal exception vectors.
///
/// # Errors
///
/// Rejects an invalid emergency stack or unsupported execution level.
#[cfg(target_os = "uefi")]
pub fn install_exception_vectors(exception_stack: PhysicalRange) -> Result<(), MmuError> {
    architecture_install_exception_vectors(exception_stack)
}

/// Deliberately write through a read-only mapping for QEMU acceptance.
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub fn trigger_write_fault(address: usize) -> ! {
    // SAFETY: This is an explicit terminal acceptance probe. The selected byte
    // is in a readable kernel-image page that the owned MMU maps read-only.
    unsafe { ptr::write_volatile(address as *mut u8, 0) };
    let _written = crate::mechanism::write(b"fault probe failed: write returned\n");
    crate::mechanism::park()
}

/// Deliberately fetch from a non-executable mapping for QEMU acceptance.
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub fn trigger_execute_fault(address: usize) -> ! {
    // SAFETY: This is an explicit terminal acceptance probe. The address is
    // page-aligned owned runtime RAM, but the new page tables deny execution.
    let function: extern "C" fn() = unsafe { core::mem::transmute(address) };
    function();
    let _written = crate::mechanism::write(b"fault probe failed: execute returned\n");
    crate::mechanism::park()
}

/// Deliberately raise a non-page-fault exception for QEMU acceptance.
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub fn trigger_native_exception() -> ! {
    architecture_trigger_native_exception()
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_PRESENT: u64 = 1;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_WRITABLE: u64 = 1 << 1;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_WRITE_THROUGH: u64 = 1 << 3;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_CACHE_DISABLE: u64 = 1 << 4;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_NO_EXECUTE: u64 = 1 << 63;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy)]
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
struct ArchitectureMmuCapabilities {
    physical_address_bits: u8,
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_mmu_capabilities() -> Result<ArchitectureMmuCapabilities, MmuError> {
    let mut maximum_extended = 0_u32;
    // SAFETY: CPUID leaves memory untouched and is available in 64-bit mode.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0x8000_0000_u32 => maximum_extended,
            out("ecx") _,
            out("edx") _,
        );
    }
    if maximum_extended < 0x8000_0008 {
        return Err(MmuError::UnsupportedCpu);
    }
    let mut extended_features = 0_u32;
    // SAFETY: This CPUID leaf reports architectural extended feature bits.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0x8000_0001_u32 => _,
            out("ecx") _,
            out("edx") extended_features,
        );
    }
    if extended_features & (1 << 20) == 0 {
        return Err(MmuError::UnsupportedCpu);
    }
    let mut address_sizes = 0_u32;
    // SAFETY: The checked extended leaf reports supported address widths.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0x8000_0008_u32 => address_sizes,
            out("ecx") _,
            out("edx") _,
        );
    }
    let physical_address_bits = (address_sizes & 0xff) as u8;
    if !(32..=52).contains(&physical_address_bits) {
        return Err(MmuError::UnsupportedCpu);
    }
    Ok(ArchitectureMmuCapabilities {
        physical_address_bits,
    })
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_validate_table_arena(
    table_arena: PhysicalRange,
    capabilities: ArchitectureMmuCapabilities,
) -> Result<(), MmuError> {
    let limit = 1_u64 << capabilities.physical_address_bits;
    if table_arena.end() > limit {
        return Err(MmuError::AddressUnsupported);
    }
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const fn x86_virtual_address_is_canonical(address: u64) -> bool {
    address < (1_u64 << 47) || address >= 0xffff_8000_0000_0000
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_map_page(
    arena: &mut TableArena,
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: MappingPermissions,
    memory_type: MappingMemoryType,
    capabilities: ArchitectureMmuCapabilities,
) -> Result<(), MmuError> {
    let physical_limit = 1_u64 << capabilities.physical_address_bits;
    if !x86_virtual_address_is_canonical(virtual_address) || physical_address >= physical_limit {
        return Err(MmuError::AddressUnsupported);
    }
    let indexes = [
        ((virtual_address >> 39) & 0x1ff) as usize,
        ((virtual_address >> 30) & 0x1ff) as usize,
        ((virtual_address >> 21) & 0x1ff) as usize,
        ((virtual_address >> 12) & 0x1ff) as usize,
    ];
    let mut table = root;
    for index in indexes.iter().take(3).copied() {
        let entry = table_entry(table, index)?;
        // SAFETY: `entry` addresses one aligned u64 within an exclusively owned
        // table page allocated above; volatile access publishes it to hardware.
        let current = unsafe { ptr::read_volatile(entry) };
        table = if current & X86_PRESENT == 0 {
            let child = arena.allocate()?;
            // SAFETY: This builder exclusively owns the entry until CR3 loads.
            unsafe { ptr::write_volatile(entry, child | X86_PRESENT | X86_WRITABLE) };
            child
        } else {
            current & X86_ADDRESS_MASK
        };
    }
    let leaf = table_entry(table, indexes[3])?;
    // SAFETY: The leaf belongs to the exclusively owned page-table tree.
    if unsafe { ptr::read_volatile(leaf) } & X86_PRESENT != 0 {
        return Err(MmuError::InvalidPlan);
    }
    let mut flags = X86_PRESENT;
    if permissions.write {
        flags |= X86_WRITABLE;
    }
    if !permissions.execute {
        flags |= X86_NO_EXECUTE;
    }
    if memory_type == MappingMemoryType::Device {
        flags |= X86_WRITE_THROUGH | X86_CACHE_DISABLE;
    }
    // SAFETY: The checked physical address and flags form one terminal PTE.
    unsafe { ptr::write_volatile(leaf, physical_address | flags) };
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn table_entry(table: u64, index: usize) -> Result<*mut u64, MmuError> {
    let base = usize::try_from(table).map_err(|_| MmuError::AddressUnsupported)?;
    let offset = index
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(MmuError::AddressUnsupported)?;
    let address = base
        .checked_add(offset)
        .ok_or(MmuError::AddressUnsupported)?;
    Ok(address as *mut u64)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_activate(root: u64, _capabilities: ArchitectureMmuCapabilities) {
    let mut efer_low: u32;
    let mut efer_high: u32;
    // SAFETY: EFER is architectural in long mode; NX support was checked.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xc000_0080_u32,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nostack),
        );
        efer_low |= 1 << 11;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xc000_0080_u32,
            in("eax") efer_low,
            in("edx") efer_high,
            options(nostack),
        );
        let mut cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack));
        cr0 |= 1 << 16;
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack));
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack));
    }
}

#[cfg(all(
    target_os = "uefi",
    target_arch = "x86_64",
    feature = "acceptance-probes"
))]
fn architecture_trigger_native_exception() -> ! {
    // SAFETY: This is an explicit terminal acceptance probe for vector 6.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[repr(C, align(16))]
struct X86Idt([u128; 256]);

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
struct X86IdtCell(UnsafeCell<X86Idt>);

// SAFETY: The boot CPU initializes the IDT once before interrupts or faults use
// it, after which the table is immutable for the lifetime of the kernel.
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
unsafe impl Sync for X86IdtCell {}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
static X86_IDT: X86IdtCell = X86IdtCell(UnsafeCell::new(X86Idt([0; 256])));

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[repr(C, align(16))]
struct X86Gdt([u64; 8]);

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
struct X86GdtCell(UnsafeCell<X86Gdt>);

// SAFETY: The boot CPU initializes the GDT once before loading GDTR and the
// table is immutable afterward.
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
unsafe impl Sync for X86GdtCell {}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
static X86_GDT: X86GdtCell = X86GdtCell(UnsafeCell::new(X86Gdt([0; 8])));

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[repr(C, packed)]
struct X86Tss {
    reserved0: u32,
    privilege_stacks: [u64; 3],
    reserved1: u64,
    interrupt_stacks: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const _: () = assert!(core::mem::size_of::<X86Tss>() == 104);

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
impl X86Tss {
    const fn new() -> Self {
        Self {
            reserved0: 0,
            privilege_stacks: [0; 3],
            reserved1: 0,
            interrupt_stacks: [0; 7],
            reserved2: 0,
            reserved3: 0,
            io_map_base: 104,
        }
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[repr(C, align(16))]
struct X86TssStorage(X86Tss);

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
struct X86TssCell(UnsafeCell<X86TssStorage>);

// SAFETY: The boot CPU initializes the TSS once before loading TR, after which
// the descriptor and its emergency-stack pointer are immutable.
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
unsafe impl Sync for X86TssCell {}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
static X86_TSS: X86TssCell = X86TssCell(UnsafeCell::new(X86TssStorage(X86Tss::new())));

#[cfg(any(test, all(target_os = "uefi", target_arch = "x86_64")))]
const X86_CODE_SELECTOR: u16 = 0x08;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_DATA_SELECTOR: u16 = 0x10;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_TSS_SELECTOR: u16 = 0x18;

#[cfg(any(test, all(target_os = "uefi", target_arch = "x86_64")))]
fn x86_interrupt_gate(offset: u64, ist: u8) -> u128 {
    u128::from(offset & 0xffff)
        | (u128::from(X86_CODE_SELECTOR) << 16)
        | (u128::from(ist & 0x7) << 32)
        | (u128::from(0x8e_u8) << 40)
        | (u128::from((offset >> 16) & 0xffff) << 48)
        | (u128::from(offset >> 32) << 64)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_tss_descriptor(base: u64) -> (u64, u64) {
    let limit = (core::mem::size_of::<X86Tss>() - 1) as u64;
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89_u64 << 40)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[repr(C, packed)]
struct X86DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_install_exception_vectors(exception_stack: PhysicalRange) -> Result<(), MmuError> {
    if exception_stack.byte_count() < BASE_PAGE_SIZE {
        return Err(MmuError::InvalidTableArena);
    }
    // SAFETY: This is the unique boot-time initialization of the static TSS,
    // GDT, and IDT while interrupts remain disabled.
    unsafe {
        (*X86_TSS.0.get()).0.interrupt_stacks[0] = exception_stack.end();
        (*X86_GDT.0.get()).0[1] = 0x00af_9a00_0000_ffff;
        (*X86_GDT.0.get()).0[2] = 0x00cf_9200_0000_ffff;
        let (tss_low, tss_high) = x86_tss_descriptor(X86_TSS.0.get() as u64);
        (*X86_GDT.0.get()).0[3] = tss_low;
        (*X86_GDT.0.get()).0[4] = tss_high;

        let generic_no_error = x86_exception_no_error_entry as *const () as usize as u64;
        let generic_error = x86_exception_error_entry as *const () as usize as u64;
        for vector in 0..32 {
            let has_error_code = matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30);
            let offset = if vector == 14 {
                x86_page_fault_entry as *const () as usize as u64
            } else if has_error_code {
                generic_error
            } else {
                generic_no_error
            };
            let ist = u8::from(vector == 8);
            (*X86_IDT.0.get()).0[vector] = x86_interrupt_gate(offset, ist);
        }
        let input = x86_input_interrupt_entry as *const () as usize as u64;
        for vector in [
            crate::mechanism::X86_KEYBOARD_VECTOR,
            crate::mechanism::X86_SERIAL_VECTOR,
        ] {
            (*X86_IDT.0.get()).0[usize::from(vector)] = x86_interrupt_gate(input, 0);
        }
        let spurious = x86_spurious_interrupt_entry as *const () as usize as u64;
        (*X86_IDT.0.get()).0[usize::from(crate::mechanism::X86_SPURIOUS_VECTOR)] =
            x86_interrupt_gate(spurious, 0);
    }
    let gdt_descriptor = X86DescriptorTablePointer {
        limit: 63,
        base: X86_GDT.0.get() as u64,
    };
    let descriptor = X86DescriptorTablePointer {
        limit: 4095,
        base: X86_IDT.0.get() as u64,
    };
    // SAFETY: Interrupts are disabled. The assembly installs the initialized
    // descriptor tables, reloads fixed kernel selectors, loads the TSS, and does
    // not execute a faulting memory access between GDT and IDT replacement.
    unsafe {
        core::arch::asm!(
            "lgdt [{gdt}]",
            "push {code_selector}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, {data_selector:x}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov ax, {tss_selector:x}",
            "ltr ax",
            "lidt [{idt}]",
            gdt = in(reg) &raw const gdt_descriptor,
            idt = in(reg) &raw const descriptor,
            code_selector = const X86_CODE_SELECTOR,
            data_selector = in(reg) X86_DATA_SELECTOR,
            tss_selector = in(reg) X86_TSS_SELECTOR,
            out("rax") _,
        );
    }
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_input_interrupt_entry() {
    core::arch::naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rbx, rsp",
        "sub rsp, 560",
        "and rsp, -16",
        "fxsave64 [rsp]",
        "sub rsp, 32",
        "call {handler}",
        "add rsp, 32",
        "fxrstor64 [rsp]",
        "mov rsp, rbx",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "iretq",
        handler = sym x86_input_interrupt_handler,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
extern "C" fn x86_input_interrupt_handler() {
    crate::mechanism::handle_input_interrupt();
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_spurious_interrupt_entry() {
    core::arch::naked_asm!("iretq");
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_exception_no_error_entry() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "sub rsp, 32",
        "call {fatal}",
        fatal = sym x86_exception_fatal,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_exception_error_entry() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "sub rsp, 32",
        "call {fatal}",
        fatal = sym x86_exception_fatal,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
extern "C" fn x86_exception_fatal() -> ! {
    let _written = crate::mechanism::write(b"fault: native exception\n");
    crate::mechanism::park()
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_page_fault_entry() -> ! {
    core::arch::naked_asm!(
        "mov rdx, [rsp]",
        "mov rcx, cr2",
        "and rsp, -16",
        "sub rsp, 32",
        "call {fatal}",
        fatal = sym x86_page_fault_fatal,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
extern "C" fn x86_page_fault_fatal(_address: u64, error: u64) -> ! {
    let message = if error & (1 << 4) != 0 {
        b"fault: execute permission violation\n".as_slice()
    } else if error & (1 << 1) != 0 {
        b"fault: write permission violation\n".as_slice()
    } else {
        b"fault: page translation violation\n".as_slice()
    };
    let _written = crate::mechanism::write(message);
    crate::mechanism::park()
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_TABLE_OR_PAGE: u64 = 0b11;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_ACCESS_FLAG: u64 = 1 << 10;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_INNER_SHAREABLE: u64 = 0b11 << 8;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_READ_ONLY: u64 = 0b10 << 6;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_ATTR_DEVICE: u64 = 1 << 2;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_PXN: u64 = 1 << 53;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_UXN: u64 = 1 << 54;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;

#[derive(Clone, Copy)]
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
struct ArchitectureMmuCapabilities {
    physical_address_bits: u8,
    ips: u8,
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_mmu_capabilities() -> Result<ArchitectureMmuCapabilities, MmuError> {
    let mut current_el: u64;
    let mut features: u64;
    // SAFETY: These read-only architectural registers are available in the UEFI
    // AArch64 execution environment.
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) current_el, options(nomem, nostack));
        core::arch::asm!(
            "mrs {}, ID_AA64MMFR0_EL1",
            out(reg) features,
            options(nomem, nostack)
        );
    }
    if current_el >> 2 != 1 || ((features >> 28) & 0xf) == 0xf {
        return Err(MmuError::UnsupportedCpu);
    }
    let reported_parange = (features & 0xf) as u8;
    if reported_parange > 0b110 {
        return Err(MmuError::UnsupportedCpu);
    }
    let ips = reported_parange.min(0b101);
    let physical_address_bits = match ips {
        0b000 => 32,
        0b001 => 36,
        0b010 => 40,
        0b011 => 42,
        0b100 => 44,
        0b101 => 48,
        _ => return Err(MmuError::UnsupportedCpu),
    };
    Ok(ArchitectureMmuCapabilities {
        physical_address_bits,
        ips,
    })
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_validate_table_arena(
    table_arena: PhysicalRange,
    capabilities: ArchitectureMmuCapabilities,
) -> Result<(), MmuError> {
    let limit = 1_u64 << capabilities.physical_address_bits;
    if table_arena.end() > limit {
        return Err(MmuError::AddressUnsupported);
    }
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_map_page(
    arena: &mut TableArena,
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: MappingPermissions,
    memory_type: MappingMemoryType,
    capabilities: ArchitectureMmuCapabilities,
) -> Result<(), MmuError> {
    let physical_limit = 1_u64 << capabilities.physical_address_bits;
    if virtual_address >= (1_u64 << 48) || physical_address >= physical_limit {
        return Err(MmuError::AddressUnsupported);
    }
    let indexes = [
        ((virtual_address >> 39) & 0x1ff) as usize,
        ((virtual_address >> 30) & 0x1ff) as usize,
        ((virtual_address >> 21) & 0x1ff) as usize,
        ((virtual_address >> 12) & 0x1ff) as usize,
    ];
    let mut table = root;
    for index in indexes.iter().take(3).copied() {
        let entry = table_entry(table, index)?;
        // SAFETY: The entry belongs to the exclusively owned table tree.
        let current = unsafe { ptr::read_volatile(entry) };
        table = if current & AARCH64_TABLE_OR_PAGE == 0 {
            let child = arena.allocate()?;
            // SAFETY: The child is zeroed and the builder owns both tables.
            unsafe { ptr::write_volatile(entry, child | AARCH64_TABLE_OR_PAGE) };
            child
        } else {
            current & AARCH64_ADDRESS_MASK
        };
    }
    let leaf = table_entry(table, indexes[3])?;
    // SAFETY: The leaf belongs to the exclusively owned page-table tree.
    if unsafe { ptr::read_volatile(leaf) } & AARCH64_TABLE_OR_PAGE != 0 {
        return Err(MmuError::InvalidPlan);
    }
    let mut flags = AARCH64_TABLE_OR_PAGE | AARCH64_ACCESS_FLAG | AARCH64_UXN;
    if !permissions.write {
        flags |= AARCH64_READ_ONLY;
    }
    if !permissions.execute {
        flags |= AARCH64_PXN;
    }
    if memory_type == MappingMemoryType::Device {
        flags |= AARCH64_ATTR_DEVICE;
    } else {
        flags |= AARCH64_INNER_SHAREABLE;
    }
    // SAFETY: The checked physical address and attributes form one page entry.
    unsafe { ptr::write_volatile(leaf, physical_address | flags) };
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn table_entry(table: u64, index: usize) -> Result<*mut u64, MmuError> {
    let base = usize::try_from(table).map_err(|_| MmuError::AddressUnsupported)?;
    let offset = index
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(MmuError::AddressUnsupported)?;
    let address = base
        .checked_add(offset)
        .ok_or(MmuError::AddressUnsupported)?;
    Ok(address as *mut u64)
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_activate(root: u64, capabilities: ArchitectureMmuCapabilities) {
    const MAIR: u64 = 0x04ff;
    const TCR_BASE: u64 = 16 | (0b01 << 8) | (0b01 << 10) | (0b11 << 12) | (1 << 23);
    let tcr = TCR_BASE | (u64::from(capabilities.ips) << 32);
    let mut sctlr: u64;
    // SAFETY: EL1 and required translation features were checked before table
    // construction; these are the architectural EL1 translation controls.
    unsafe {
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
        core::arch::asm!("msr sctlr_el1, {}", in(reg) (sctlr & !1), options(nostack));
        core::arch::asm!("isb", options(nostack));
        core::arch::asm!("msr mair_el1, {}", in(reg) MAIR, options(nostack));
        core::arch::asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack));
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) root, options(nostack));
        core::arch::asm!("dsb sy", "tlbi vmalle1", "dsb sy", "isb", options(nostack));
        core::arch::asm!(
            "msr sctlr_el1, {}",
            in(reg) (sctlr | 1 | (1 << 19)),
            options(nostack),
        );
        core::arch::asm!("isb", options(nostack));
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
core::arch::global_asm!(
    ".text",
    ".balign 2048",
    ".global kllm_aarch64_vectors",
    "kllm_aarch64_vectors:",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_irq_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_irq_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_irq_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_irq_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "b kllm_aarch64_exception_entry",
    ".balign 128",
    "kllm_aarch64_exception_entry:",
    "msr daifset, #0xf",
    "mrs x0, esr_el1",
    "mrs x1, far_el1",
    "bl kllm_aarch64_exception_fatal",
    "b .",
    ".balign 128",
    "kllm_aarch64_irq_entry:",
    "msr daifset, #2",
    "sub sp, sp, #784",
    "stp q0, q1, [sp, #272]",
    "stp q2, q3, [sp, #304]",
    "stp q4, q5, [sp, #336]",
    "stp q6, q7, [sp, #368]",
    "stp q8, q9, [sp, #400]",
    "stp q10, q11, [sp, #432]",
    "stp q12, q13, [sp, #464]",
    "stp q14, q15, [sp, #496]",
    "stp q16, q17, [sp, #528]",
    "stp q18, q19, [sp, #560]",
    "stp q20, q21, [sp, #592]",
    "stp q22, q23, [sp, #624]",
    "stp q24, q25, [sp, #656]",
    "stp q26, q27, [sp, #688]",
    "stp q28, q29, [sp, #720]",
    "stp q30, q31, [sp, #752]",
    "stp x0, x1, [sp, #0]",
    "stp x2, x3, [sp, #16]",
    "stp x4, x5, [sp, #32]",
    "stp x6, x7, [sp, #48]",
    "stp x8, x9, [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "str x30, [sp, #240]",
    "mrs x9, fpcr",
    "mrs x10, fpsr",
    "str x9, [sp, #248]",
    "str x10, [sp, #256]",
    "bl kllm_aarch64_input_interrupt",
    "ldr x9, [sp, #248]",
    "ldr x10, [sp, #256]",
    "msr fpcr, x9",
    "msr fpsr, x10",
    "ldp q0, q1, [sp, #272]",
    "ldp q2, q3, [sp, #304]",
    "ldp q4, q5, [sp, #336]",
    "ldp q6, q7, [sp, #368]",
    "ldp q8, q9, [sp, #400]",
    "ldp q10, q11, [sp, #432]",
    "ldp q12, q13, [sp, #464]",
    "ldp q14, q15, [sp, #496]",
    "ldp q16, q17, [sp, #528]",
    "ldp q18, q19, [sp, #560]",
    "ldp q20, q21, [sp, #592]",
    "ldp q22, q23, [sp, #624]",
    "ldp q24, q25, [sp, #656]",
    "ldp q26, q27, [sp, #688]",
    "ldp q28, q29, [sp, #720]",
    "ldp q30, q31, [sp, #752]",
    "ldp x0, x1, [sp, #0]",
    "ldp x2, x3, [sp, #16]",
    "ldp x4, x5, [sp, #32]",
    "ldp x6, x7, [sp, #48]",
    "ldp x8, x9, [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x20, x21, [sp, #160]",
    "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]",
    "ldp x26, x27, [sp, #208]",
    "ldp x28, x29, [sp, #224]",
    "ldr x30, [sp, #240]",
    "add sp, sp, #784",
    "eret",
);

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe extern "C" {
    static kllm_aarch64_vectors: u8;
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_install_exception_vectors(_exception_stack: PhysicalRange) -> Result<(), MmuError> {
    let mut current_el: u64;
    // SAFETY: Reading CurrentEL is side-effect free.
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) current_el, options(nomem, nostack));
    }
    if current_el >> 2 != 1 {
        return Err(MmuError::UnsupportedCpu);
    }
    // SAFETY: The global assembly symbol is 2 KiB aligned and contains all 16
    // fixed-size architectural vector entries for the lifetime of the image.
    let vectors = ptr::addr_of!(kllm_aarch64_vectors) as u64;
    // SAFETY: VBAR_EL1 accepts this aligned, executable in-image vector table.
    unsafe {
        core::arch::asm!("msr vbar_el1, {}", in(reg) vectors, options(nostack));
        core::arch::asm!("isb", options(nostack));
    }
    Ok(())
}

#[cfg(all(
    target_os = "uefi",
    target_arch = "aarch64",
    feature = "acceptance-probes"
))]
fn architecture_trigger_native_exception() -> ! {
    // SAFETY: This is an explicit terminal acceptance probe for a synchronous
    // breakpoint exception handled by the owned VBAR table.
    unsafe { core::arch::asm!("brk #0", options(noreturn)) }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(no_mangle)]
extern "C" fn kllm_aarch64_input_interrupt() {
    crate::mechanism::handle_input_interrupt();
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(no_mangle)]
extern "C" fn kllm_aarch64_exception_fatal(esr: u64, _far: u64) -> ! {
    let exception_class = (esr >> 26) & 0x3f;
    let message = if exception_class == 0x21 {
        b"fault: execute permission violation\n".as_slice()
    } else if exception_class == 0x25 && esr & (1 << 6) != 0 {
        b"fault: write permission violation\n".as_slice()
    } else {
        b"fault: native exception\n".as_slice()
    };
    let _written = crate::mechanism::write(message);
    crate::mechanism::park()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        MmuError, X86_CODE_SELECTOR, checked_image_slice_bounds, parse_image_layout,
        x86_interrupt_gate,
    };
    use kllm_memory::MappingPermissions;
    use std::vec;
    use std::vec::Vec;

    fn image_with_sections(sections: &[(u32, u32, u32)]) -> Vec<u8> {
        let mut image = vec![0_u8; 0x5000];
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(&0x0000_4550_u32.to_le_bytes());
        let section_count = u16::try_from(sections.len()).unwrap_or(u16::MAX);
        image[0x86..0x88].copy_from_slice(&section_count.to_le_bytes());
        let optional_bytes = 0x70_u16;
        image[0x94..0x96].copy_from_slice(&optional_bytes.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x020b_u16.to_le_bytes());
        image[0xb8..0xbc].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[0xd0..0xd4].copy_from_slice(&0x5000_u32.to_le_bytes());
        for (index, (address, size, characteristics)) in sections.iter().copied().enumerate() {
            let header = 0x108 + index * 40;
            image[header + 8..header + 12].copy_from_slice(&size.to_le_bytes());
            image[header + 12..header + 16].copy_from_slice(&address.to_le_bytes());
            image[header + 16..header + 20].copy_from_slice(&size.to_le_bytes());
            image[header + 36..header + 40].copy_from_slice(&characteristics.to_le_bytes());
        }
        image
    }

    #[test]
    fn pe_sections_become_read_execute_read_only_and_read_write_regions() {
        let image = image_with_sections(&[
            (0x1000, 0x1000, 0x6000_0000),
            (0x2000, 0x1000, 0x4000_0000),
            (0x3000, 0x2000, 0xc000_0000),
        ]);
        let layout = parse_image_layout(&image, 0x20_0000).unwrap_or_else(|_| unreachable!());
        assert_eq!(layout.region_count(), 4);
        assert_eq!(
            layout.region(0).map(super::ImageRegion::permissions),
            Some(MappingPermissions::READ_ONLY)
        );
        assert_eq!(
            layout.region(1).map(super::ImageRegion::permissions),
            Some(MappingPermissions::READ_EXECUTE)
        );
        assert_eq!(
            layout.region(2).map(super::ImageRegion::permissions),
            Some(MappingPermissions::READ_ONLY)
        );
        assert_eq!(
            layout.region(3).map(super::ImageRegion::permissions),
            Some(MappingPermissions::READ_WRITE)
        );
    }

    #[test]
    fn pe_parser_rejects_writable_executable_and_overlapping_sections() {
        let writable_code = image_with_sections(&[(0x1000, 0x1000, 0xe000_0000)]);
        assert_eq!(
            parse_image_layout(&writable_code, 0x20_0000),
            Err(MmuError::InvalidImage)
        );

        let overlap =
            image_with_sections(&[(0x1000, 0x2000, 0x6000_0000), (0x2000, 0x1000, 0x4000_0000)]);
        assert_eq!(
            parse_image_layout(&overlap, 0x20_0000),
            Err(MmuError::InvalidImage)
        );
    }

    #[test]
    fn pe_parser_checks_signature_alignment_and_bounds() {
        let mut image = image_with_sections(&[(0x1000, 0x1000, 0x6000_0000)]);
        image[0x80] = 0;
        assert_eq!(
            parse_image_layout(&image, 0x20_0000),
            Err(MmuError::InvalidImage)
        );
        let image = image_with_sections(&[(0x1800, 0x1000, 0x6000_0000)]);
        assert_eq!(
            parse_image_layout(&image, 0x20_0000),
            Err(MmuError::InvalidImage)
        );
        let image = image_with_sections(&[(0x5000, 0x1000, 0x6000_0000)]);
        assert_eq!(
            parse_image_layout(&image, 0x20_0000),
            Err(MmuError::InvalidImage)
        );
    }

    #[test]
    fn loaded_image_slice_bounds_fail_closed() {
        assert_eq!(
            checked_image_slice_bounds(0, 0x1000),
            Err(MmuError::InvalidImage)
        );
        assert_eq!(
            checked_image_slice_bounds(0x20_0001, 0x1000),
            Err(MmuError::InvalidImage)
        );
        assert_eq!(
            checked_image_slice_bounds(0x20_0000, 0x1001),
            Err(MmuError::InvalidImage)
        );
        assert_eq!(
            checked_image_slice_bounds(0x20_0000, (isize::MAX as u64) + 1),
            Err(MmuError::InvalidImage)
        );
        assert_eq!(
            checked_image_slice_bounds(usize::MAX & !0xfff, 0x2000),
            Err(MmuError::InvalidImage)
        );
        assert_eq!(checked_image_slice_bounds(0x20_0000, 0x5000), Ok(0x5000));
    }

    #[test]
    fn x86_gate_always_references_the_owned_code_descriptor() {
        let gate = x86_interrupt_gate(0x1234_5678_9abc_def0, 1);
        assert_eq!(((gate >> 16) & 0xffff) as u16, X86_CODE_SELECTOR);
        assert_eq!(((gate >> 32) & 0x7) as u8, 1);
        assert_eq!(((gate >> 47) & 1) as u8, 1);
    }
}

//! PE image classification, owned page tables, and native fault vectors.

#[cfg(target_os = "uefi")]
use core::cell::UnsafeCell;
use core::fmt;
#[cfg(target_os = "uefi")]
use core::ptr;
#[cfg(target_os = "uefi")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use troe_memory::{BASE_PAGE_SIZE, MappingPermissions, PhysicalRange, VirtualRange};
#[cfg(target_os = "uefi")]
use troe_memory::{MappingMemoryType, MappingPlan, MappingPrivilege};

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
// Tiny KEX permits eight image segments plus startup, heap, and stack regions.
// Full uses at most sixteen image segments plus the same three fixed regions.
const MAX_USER_REGIONS: usize = 19;
#[cfg(target_os = "uefi")]
const ISOLATED_EXIT_CALL: u64 = 1;
#[cfg(target_os = "uefi")]
const APPLICATION_EXIT_CALL: u64 = 0;
#[cfg(target_os = "uefi")]
const APPLICATION_YIELD_CALL: u64 = 1;
#[cfg(target_os = "uefi")]
const APPLICATION_HANDLE_CALL: u64 = 2;
#[cfg(target_os = "uefi")]
const APPLICATION_LEASE_MILLISECONDS: u32 = 50;
#[cfg(target_os = "uefi")]
const APPLICATION_STARTUP_BYTES: usize = 4096;
#[cfg(target_os = "uefi")]
const OUTCOME_FAULT_BIT: u64 = 1 << 63;
#[cfg(target_os = "uefi")]
const OUTCOME_APPLICATION_YIELD: u64 = 1 << 62;
#[cfg(target_os = "uefi")]
const OUTCOME_APPLICATION_HANDLE_CALL: u64 = 1 << 61;

/// Native fault category contained at the user/kernel boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolatedFault {
    /// Instruction or data translation failed.
    Translation,
    /// A mapped page denied the requested access.
    Permission,
    /// The task raised another synchronous exception.
    IllegalInstruction,
    /// The task supplied an unknown call or invalid message range.
    InvalidCall,
    /// The task exhausted its maximum uninterrupted execution lease.
    ExecutionLeaseExpired,
}

/// Terminal result from one bounded cooperative unprivileged execution step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolatedOutcome {
    /// Task exited through the copied-message gate.
    Exited {
        /// Caller-selected process-style status.
        status: u8,
        /// Bytes copied into the kernel-owned destination.
        message_bytes: usize,
    },
    /// Native fault or invalid call was contained and returned to the kernel.
    Faulted(IsolatedFault),
}

/// Terminal result from the first bounded application ABI execution lease.
#[derive(Debug, Eq, PartialEq)]
pub enum ApplicationOutcome {
    /// The application invoked ABI call 0 with a fixed-width status.
    Exited {
        /// Caller-selected application status.
        status: u32,
    },
    /// The application invoked ABI call 1 and retained a bounded saved context.
    #[cfg(target_os = "uefi")]
    Yielded(ApplicationSession),
    /// The application invoked ABI call 2 with fully validated user ranges.
    #[cfg(target_os = "uefi")]
    HandleCall {
        /// Opaque resumable task and address-space state.
        application: ApplicationSession,
        /// Copied-call source and destination metadata.
        call: ApplicationCall,
    },
    /// A native fault, invalid ABI call, or lease expiry was contained.
    Faulted(IsolatedFault),
}

/// Opaque architecture-owned root and validated unprivileged mapping summary.
#[derive(Debug, Eq, PartialEq)]
pub struct UserAddressSpace {
    root: u64,
    regions: [Option<UserRegion>; MAX_USER_REGIONS],
    region_count: usize,
    stats: MmuStats,
}

impl UserAddressSpace {
    /// Page-table and mapped-page accounting for teardown validation.
    #[must_use]
    pub const fn stats(&self) -> MmuStats {
        self.stats
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserRegion {
    range: VirtualRange,
    physical: PhysicalRange,
    permissions: MappingPermissions,
}

/// Fully validated metadata for one suspended ABI handle call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "uefi")]
pub struct ApplicationCall {
    handle: u64,
    request_address: u64,
    request_bytes: usize,
    reply_address: u64,
    reply_capacity: usize,
}

#[cfg(target_os = "uefi")]
impl ApplicationCall {
    /// Opaque owner-scoped handle token supplied by the application.
    #[must_use]
    pub const fn handle(self) -> u64 {
        self.handle
    }

    /// Complete encoded request length, including the two-byte opcode prefix.
    #[must_use]
    pub const fn request_bytes(self) -> usize {
        self.request_bytes
    }

    /// Maximum reply bytes accepted by the application.
    #[must_use]
    pub const fn reply_capacity(self) -> usize {
        self.reply_capacity
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C, align(16))]
struct ArchitectureApplicationContext {
    floating_point: [u8; 512],
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    instruction: u64,
    code_selector: u64,
    flags: u64,
    stack: u64,
    stack_selector: u64,
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const _: () = {
    assert!(core::mem::size_of::<ArchitectureApplicationContext>() == 672);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, rax) == 512);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, r10) == 584);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, instruction) == 632);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, flags) == 648);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, stack) == 656);
};

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C, align(16))]
struct ArchitectureApplicationContext {
    general: [u64; 31],
    general_padding: u64,
    floating_point: [[u8; 16]; 32],
    fpcr: u64,
    fpsr: u64,
    instruction: u64,
    status: u64,
    stack: u64,
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const _: () = {
    assert!(core::mem::size_of::<ArchitectureApplicationContext>() == 816);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, floating_point) == 256);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, fpcr) == 768);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, instruction) == 784);
    assert!(core::mem::offset_of!(ArchitectureApplicationContext, stack) == 800);
};

/// Opaque saved application context, address-space root, and pending ABI call.
#[derive(Debug, Eq, PartialEq)]
#[cfg(target_os = "uefi")]
pub struct ApplicationSession {
    address_space: UserAddressSpace,
    context: ArchitectureApplicationContext,
    pending: ApplicationPending,
}

/// Kernel-selected completion supplied before resuming a suspended ABI call.
#[cfg(target_os = "uefi")]
pub enum ApplicationResume<'reply> {
    /// Complete one cooperative yield with zero-valued ABI results.
    Yield,
    /// Copy one successful dispatch reply and publish its typed result.
    HandleReply {
        /// Stable service reply status.
        status: u32,
        /// Complete kernel-owned reply payload.
        reply: &'reply [u8],
    },
}

#[cfg(target_os = "uefi")]
impl ApplicationSession {
    /// Copy the complete pending request from task-owned physical pages.
    ///
    /// The application is suspended and the kernel root retains identity
    /// mappings for allocated RAM, so the source cannot change during copy.
    ///
    /// # Errors
    ///
    /// Rejects a non-call session or a destination of the wrong length.
    pub fn copy_request(&self, destination: &mut [u8]) -> Result<(), MmuError> {
        let ApplicationPending::HandleCall(call) = self.pending else {
            return Err(MmuError::InvalidUserContext);
        };
        if destination.len() != call.request_bytes {
            return Err(MmuError::InvalidUserContext);
        }
        copy_user_from_physical(
            &self.address_space.regions,
            self.address_space.region_count,
            call.request_address,
            destination,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "uefi")]
enum ApplicationPending {
    Yield,
    HandleCall(ApplicationCall),
}

#[cfg(target_os = "uefi")]
struct IsolatedRunState {
    kind: RunKind,
    regions: [Option<UserRegion>; MAX_USER_REGIONS],
    region_count: usize,
    destination: *mut u8,
    destination_len: usize,
    application_context: Option<ArchitectureApplicationContext>,
    pending_application: Option<ApplicationPending>,
}

#[cfg(target_os = "uefi")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum RunKind {
    Stage6Probe,
    Application,
}

#[cfg(target_os = "uefi")]
struct IsolatedRunCell(UnsafeCell<Option<IsolatedRunState>>);

// SAFETY: Stage 6 remains single-CPU and cooperative. `run_isolated` is the
// unique initializer and clears the cell before returning; interrupts remain
// masked during EL0/ring-3 execution.
#[cfg(target_os = "uefi")]
unsafe impl Sync for IsolatedRunCell {}

#[cfg(target_os = "uefi")]
static ISOLATED_RUN: IsolatedRunCell = IsolatedRunCell(UnsafeCell::new(None));
#[cfg(target_os = "uefi")]
static ISOLATED_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "uefi")]
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);

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
    /// User entry, stack, mapping, or output bounds are invalid.
    InvalidUserContext,
    /// Another unprivileged execution boundary is already active.
    IsolationBusy,
    /// The architecture could not establish the bounded execution lease.
    ExecutionTimerUnavailable,
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
            Self::InvalidUserContext => formatter.write_str("isolated user context is invalid"),
            Self::IsolationBusy => formatter.write_str("isolated execution is already active"),
            Self::ExecutionTimerUnavailable => {
                formatter.write_str("application execution timer is unavailable")
            }
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
    let (root, stats) = build_tables(plan, table_arena)?;
    if KERNEL_ROOT
        .compare_exchange(0, root, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(MmuError::InvalidPlan);
    }
    let capabilities = architecture_mmu_capabilities()?;
    architecture_activate(root, capabilities);
    Ok(stats)
}

/// Build, but do not activate, one task address space containing validated
/// supervisor mappings and at least one explicit user mapping.
///
/// # Errors
///
/// Rejects all ordinary mapping/table failures, too many user regions, or a
/// plan without distinct executable and writable unprivileged mappings.
#[cfg(target_os = "uefi")]
pub fn build_user_address_space(
    plan: &MappingPlan,
    table_arena: PhysicalRange,
) -> Result<UserAddressSpace, MmuError> {
    let mut regions = [None; MAX_USER_REGIONS];
    let mut region_count = 0_usize;
    let mut executable = false;
    let mut writable = false;
    for mapping in plan.mappings() {
        if mapping.privilege() != MappingPrivilege::User {
            continue;
        }
        if mapping.memory_type() != MappingMemoryType::Normal || region_count == MAX_USER_REGIONS {
            return Err(MmuError::InvalidUserContext);
        }
        let permissions = mapping.permissions();
        executable |= permissions.execute;
        writable |= permissions.write;
        regions[region_count] = Some(UserRegion {
            range: mapping.virtual_range(),
            physical: mapping.physical_range(),
            permissions,
        });
        region_count += 1;
    }
    if !executable || !writable {
        return Err(MmuError::InvalidUserContext);
    }
    let (root, stats) = build_tables(plan, table_arena)?;
    Ok(UserAddressSpace {
        root,
        regions,
        region_count,
        stats,
    })
}

#[cfg(target_os = "uefi")]
fn build_tables(
    plan: &MappingPlan,
    table_arena: PhysicalRange,
) -> Result<(u64, MmuStats), MmuError> {
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
                mapping.privilege(),
                capabilities,
            )?;
        }
    }
    Ok((
        root,
        MmuStats {
            mapped_pages: plan.page_count().map_err(|_| MmuError::InvalidPlan)?,
            table_pages: arena.used_pages,
        },
    ))
}

/// Enter ring 3/EL0 with interrupts masked and return only through the bounded
/// exit-message gate or a contained synchronous fault.
///
/// `message_destination` is kernel-owned. The native handler validates the
/// complete untrusted source range against readable user mappings before
/// copying any byte. Nested execution and invalid entry/stack bounds fail
/// before activating the task root.
///
/// # Errors
///
/// Rejects invalid contexts, empty/oversize destinations, absent kernel root,
/// or an already-active isolated task.
#[cfg(target_os = "uefi")]
#[allow(clippy::needless_pass_by_value)] // Consuming the opaque root enforces one-shot use.
pub fn run_isolated(
    address_space: UserAddressSpace,
    entry: u64,
    stack_top: u64,
    message_destination: &mut [u8],
) -> Result<IsolatedOutcome, MmuError> {
    let UserAddressSpace {
        root,
        regions,
        region_count,
        stats: _,
    } = address_space;
    if message_destination.is_empty()
        || message_destination.len() > 4 * 1024
        || KERNEL_ROOT.load(Ordering::Acquire) == 0
        || !user_range_contains(&regions, region_count, entry, 1, false, true)
        || stack_top == 0
        || !stack_top.is_multiple_of(16)
        || !user_range_contains(&regions, region_count, stack_top - 1, 1, true, false)
    {
        return Err(MmuError::InvalidUserContext);
    }
    if ISOLATED_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(MmuError::IsolationBusy);
    }
    // SAFETY: The successful active transition gives this call unique access
    // until the native completion path returns; the destination borrow remains
    // live and inaccessible to safe Rust across that synchronous boundary.
    unsafe {
        *ISOLATED_RUN.0.get() = Some(IsolatedRunState {
            kind: RunKind::Stage6Probe,
            regions,
            region_count,
            destination: message_destination.as_mut_ptr(),
            destination_len: message_destination.len(),
            application_context: None,
            pending_application: None,
        });
    }
    let raw = architecture_run_isolated(root, entry, stack_top);
    // Clear the retained raw pointer and active flag immediately after native
    // completion, preventing reuse after the destination borrow ends.
    // SAFETY: Native execution has returned to this unique kernel call.
    unsafe { *ISOLATED_RUN.0.get() = None };
    ISOLATED_ACTIVE.store(false, Ordering::Release);
    decode_isolated_outcome(raw)
}

/// Enter an ABI 1.0 application with an armed 50 ms one-shot execution lease.
///
/// The startup page and entry point must be readable user mappings, the entry
/// must be executable, and the guarded stack must end at a 16-byte boundary.
/// The architecture boundary resets application-visible registers and enables
/// interrupt delivery only for the owned lease and already-owned input paths.
///
/// # Errors
///
/// Rejects an invalid context, unavailable execution timer, nested launch, or
/// malformed native completion before activating application code.
#[cfg(target_os = "uefi")]
#[allow(clippy::needless_pass_by_value)]
pub fn run_application(
    address_space: UserAddressSpace,
    entry: u64,
    stack_top: u64,
    startup_address: u64,
    startup_bytes: usize,
) -> Result<ApplicationOutcome, MmuError> {
    let UserAddressSpace {
        root,
        regions,
        region_count,
        stats,
    } = address_space;
    let user_stack = stack_top
        .checked_sub(8)
        .ok_or(MmuError::InvalidUserContext)?;
    if startup_bytes != APPLICATION_STARTUP_BYTES
        || KERNEL_ROOT.load(Ordering::Acquire) == 0
        || !user_range_contains(&regions, region_count, entry, 1, false, true)
        || !user_range_contains(
            &regions,
            region_count,
            startup_address,
            startup_bytes,
            false,
            false,
        )
        || !stack_top.is_multiple_of(16)
        || !user_range_contains(&regions, region_count, user_stack, 8, true, false)
    {
        return Err(MmuError::InvalidUserContext);
    }
    if ISOLATED_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(MmuError::IsolationBusy);
    }
    // SAFETY: The active transition gives this call exclusive state ownership
    // until the architecture completion path restores the kernel root.
    unsafe {
        *ISOLATED_RUN.0.get() = Some(IsolatedRunState {
            kind: RunKind::Application,
            regions,
            region_count,
            destination: ptr::null_mut(),
            destination_len: 0,
            application_context: None,
            pending_application: None,
        });
    }
    if crate::mechanism::arm_execution_timer(APPLICATION_LEASE_MILLISECONDS).is_err() {
        // SAFETY: No user entry occurred and this call still owns the state.
        unsafe { *ISOLATED_RUN.0.get() = None };
        ISOLATED_ACTIVE.store(false, Ordering::Release);
        return Err(MmuError::ExecutionTimerUnavailable);
    }
    let raw = architecture_run_application(root, entry, user_stack, startup_address, startup_bytes);
    crate::mechanism::disarm_execution_timer();
    // SAFETY: Native completion restored the kernel root and unique call frame.
    let state = unsafe { (*ISOLATED_RUN.0.get()).take() };
    ISOLATED_ACTIVE.store(false, Ordering::Release);
    let state = state.ok_or(MmuError::InvalidUserContext)?;
    decode_application_outcome(
        raw,
        UserAddressSpace {
            root,
            regions,
            region_count,
            stats,
        },
        state,
    )
}

/// Resume one scheduler-selected application with a fresh 50 ms lease.
///
/// # Errors
///
/// Rejects a mismatched completion, oversized reply, invalid retained context,
/// unavailable execution timer, or nested application execution.
#[cfg(target_os = "uefi")]
#[allow(clippy::needless_pass_by_value)]
pub fn resume_application(
    application: ApplicationSession,
    completion: ApplicationResume<'_>,
) -> Result<ApplicationOutcome, MmuError> {
    let ApplicationSession {
        address_space,
        mut context,
        pending,
    } = application;
    match (pending, completion) {
        (ApplicationPending::Yield, ApplicationResume::Yield) => {
            application_context_set_results(&mut context, 0, 0);
        }
        (
            ApplicationPending::HandleCall(call),
            ApplicationResume::HandleReply { status, reply },
        ) => {
            if reply.len() > call.reply_capacity {
                return Err(MmuError::InvalidUserContext);
            }
            copy_user_to_physical(
                &address_space.regions,
                address_space.region_count,
                call.reply_address,
                reply,
            )?;
            let reply_bytes =
                u32::try_from(reply.len()).map_err(|_| MmuError::InvalidUserContext)?;
            application_context_set_results(&mut context, status, reply_bytes);
        }
        _ => return Err(MmuError::InvalidUserContext),
    }
    if ISOLATED_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(MmuError::IsolationBusy);
    }
    let UserAddressSpace {
        root,
        regions,
        region_count,
        stats,
    } = address_space;
    // SAFETY: The active transition grants unique state ownership until the
    // architecture completion path restores the kernel root.
    unsafe {
        *ISOLATED_RUN.0.get() = Some(IsolatedRunState {
            kind: RunKind::Application,
            regions,
            region_count,
            destination: ptr::null_mut(),
            destination_len: 0,
            application_context: None,
            pending_application: None,
        });
    }
    if crate::mechanism::arm_execution_timer(APPLICATION_LEASE_MILLISECONDS).is_err() {
        // SAFETY: No user re-entry occurred and this call still owns the state.
        unsafe { *ISOLATED_RUN.0.get() = None };
        ISOLATED_ACTIVE.store(false, Ordering::Release);
        return Err(MmuError::ExecutionTimerUnavailable);
    }
    let raw = architecture_resume_application(root, &context);
    crate::mechanism::disarm_execution_timer();
    // SAFETY: Native completion restored the kernel root and unique call frame.
    let state = unsafe { (*ISOLATED_RUN.0.get()).take() };
    ISOLATED_ACTIVE.store(false, Ordering::Release);
    let state = state.ok_or(MmuError::InvalidUserContext)?;
    decode_application_outcome(
        raw,
        UserAddressSpace {
            root,
            regions,
            region_count,
            stats,
        },
        state,
    )
}

#[cfg(target_os = "uefi")]
fn decode_isolated_outcome(raw: u64) -> Result<IsolatedOutcome, MmuError> {
    if raw & OUTCOME_FAULT_BIT != 0 {
        let fault = decode_fault(raw)?;
        return Ok(IsolatedOutcome::Faulted(fault));
    }
    let status = u8::try_from((raw >> 32) & 0xff).map_err(|_| MmuError::InvalidUserContext)?;
    let message_bytes =
        usize::try_from(raw & 0xffff_ffff).map_err(|_| MmuError::InvalidUserContext)?;
    Ok(IsolatedOutcome::Exited {
        status,
        message_bytes,
    })
}

#[cfg(target_os = "uefi")]
fn decode_application_outcome(
    raw: u64,
    address_space: UserAddressSpace,
    mut state: IsolatedRunState,
) -> Result<ApplicationOutcome, MmuError> {
    if raw & OUTCOME_FAULT_BIT != 0 {
        return Ok(ApplicationOutcome::Faulted(decode_fault(raw)?));
    }
    if raw == OUTCOME_APPLICATION_YIELD || raw == OUTCOME_APPLICATION_HANDLE_CALL {
        let context = state
            .application_context
            .take()
            .ok_or(MmuError::InvalidUserContext)?;
        let pending = state
            .pending_application
            .take()
            .ok_or(MmuError::InvalidUserContext)?;
        let application = ApplicationSession {
            address_space,
            context,
            pending,
        };
        return match (raw, pending) {
            (OUTCOME_APPLICATION_YIELD, ApplicationPending::Yield) => {
                Ok(ApplicationOutcome::Yielded(application))
            }
            (OUTCOME_APPLICATION_HANDLE_CALL, ApplicationPending::HandleCall(call)) => {
                Ok(ApplicationOutcome::HandleCall { application, call })
            }
            _ => Err(MmuError::InvalidUserContext),
        };
    }
    let status = u32::try_from(raw).map_err(|_| MmuError::InvalidUserContext)?;
    Ok(ApplicationOutcome::Exited { status })
}

#[cfg(target_os = "uefi")]
fn decode_fault(raw: u64) -> Result<IsolatedFault, MmuError> {
    match raw & 0xff {
        1 => Ok(IsolatedFault::Translation),
        2 => Ok(IsolatedFault::Permission),
        3 => Ok(IsolatedFault::IllegalInstruction),
        4 => Ok(IsolatedFault::InvalidCall),
        5 => Ok(IsolatedFault::ExecutionLeaseExpired),
        _ => Err(MmuError::InvalidUserContext),
    }
}

#[cfg(target_os = "uefi")]
fn user_range_contains(
    regions: &[Option<UserRegion>; MAX_USER_REGIONS],
    count: usize,
    start: u64,
    byte_count: usize,
    require_write: bool,
    require_execute: bool,
) -> bool {
    let Ok(byte_count) = u64::try_from(byte_count) else {
        return false;
    };
    let Some(end) = start.checked_add(byte_count) else {
        return false;
    };
    byte_count != 0
        && regions[..count].iter().flatten().any(|region| {
            start >= region.range.start()
                && end <= region.range.end()
                && (!require_write || region.permissions.write)
                && (!require_execute || region.permissions.execute)
        })
}

#[cfg(target_os = "uefi")]
fn user_range_valid(
    regions: &[Option<UserRegion>; MAX_USER_REGIONS],
    count: usize,
    start: u64,
    byte_count: usize,
    require_write: bool,
) -> bool {
    byte_count == 0 || user_range_contains(regions, count, start, byte_count, require_write, false)
}

#[cfg(target_os = "uefi")]
fn user_ranges_overlap(first: u64, first_bytes: usize, second: u64, second_bytes: usize) -> bool {
    if first_bytes == 0 || second_bytes == 0 {
        return false;
    }
    let Ok(first_bytes) = u64::try_from(first_bytes) else {
        return true;
    };
    let Ok(second_bytes) = u64::try_from(second_bytes) else {
        return true;
    };
    let Some(first_end) = first.checked_add(first_bytes) else {
        return true;
    };
    let Some(second_end) = second.checked_add(second_bytes) else {
        return true;
    };
    first < second_end && second < first_end
}

#[cfg(target_os = "uefi")]
fn copy_user_from_physical(
    regions: &[Option<UserRegion>; MAX_USER_REGIONS],
    count: usize,
    start: u64,
    destination: &mut [u8],
) -> Result<(), MmuError> {
    if destination.is_empty() {
        return Ok(());
    }
    let byte_count = u64::try_from(destination.len()).map_err(|_| MmuError::InvalidUserContext)?;
    let end = start
        .checked_add(byte_count)
        .ok_or(MmuError::InvalidUserContext)?;
    let region = regions[..count]
        .iter()
        .flatten()
        .find(|region| start >= region.range.start() && end <= region.range.end())
        .ok_or(MmuError::InvalidUserContext)?;
    let offset = start
        .checked_sub(region.range.start())
        .ok_or(MmuError::InvalidUserContext)?;
    let physical = region
        .physical
        .start()
        .checked_add(offset)
        .and_then(|address| usize::try_from(address).ok())
        .ok_or(MmuError::InvalidUserContext)?;
    for (index, byte) in destination.iter_mut().enumerate() {
        // SAFETY: The application remains suspended, the complete translated
        // physical range belongs to its retained allocation, and the kernel
        // root identity-maps allocated normal RAM.
        *byte = unsafe { ptr::read_volatile((physical + index) as *const u8) };
    }
    Ok(())
}

#[cfg(target_os = "uefi")]
fn copy_user_to_physical(
    regions: &[Option<UserRegion>; MAX_USER_REGIONS],
    count: usize,
    start: u64,
    source: &[u8],
) -> Result<(), MmuError> {
    if source.is_empty() {
        return Ok(());
    }
    if !user_range_contains(regions, count, start, source.len(), true, false) {
        return Err(MmuError::InvalidUserContext);
    }
    let byte_count = u64::try_from(source.len()).map_err(|_| MmuError::InvalidUserContext)?;
    let end = start
        .checked_add(byte_count)
        .ok_or(MmuError::InvalidUserContext)?;
    let region = regions[..count]
        .iter()
        .flatten()
        .find(|region| start >= region.range.start() && end <= region.range.end())
        .ok_or(MmuError::InvalidUserContext)?;
    let offset = start
        .checked_sub(region.range.start())
        .ok_or(MmuError::InvalidUserContext)?;
    let physical = region
        .physical
        .start()
        .checked_add(offset)
        .and_then(|address| usize::try_from(address).ok())
        .ok_or(MmuError::InvalidUserContext)?;
    for (index, byte) in source.iter().copied().enumerate() {
        // SAFETY: The application remains suspended, the complete destination
        // is a retained writable task mapping, and kernel identity mappings
        // cover its allocated normal RAM.
        unsafe { ptr::write_volatile((physical + index) as *mut u8, byte) };
    }
    Ok(())
}

#[cfg(target_os = "uefi")]
fn isolated_syscall(opcode: u64, address: u64, length: u64, status: u64) -> u64 {
    if opcode != ISOLATED_EXIT_CALL || status > u64::from(u8::MAX) {
        return OUTCOME_FAULT_BIT | 4;
    }
    let Ok(length) = usize::try_from(length) else {
        return OUTCOME_FAULT_BIT | 4;
    };
    // SAFETY: Only the single active native exception path accesses the cell.
    let Some(state) = (unsafe { &mut *ISOLATED_RUN.0.get() }).as_mut() else {
        return OUTCOME_FAULT_BIT | 4;
    };
    if length > state.destination_len
        || !user_range_contains(
            &state.regions,
            state.region_count,
            address,
            length,
            false,
            false,
        )
    {
        return OUTCOME_FAULT_BIT | 4;
    }
    let Ok(source) = usize::try_from(address) else {
        return OUTCOME_FAULT_BIT | 4;
    };
    for offset in 0..length {
        // SAFETY: Full source and destination ranges were validated before any
        // byte is copied; the active task root maps the source and supervisor
        // kernel mappings cover the borrowed destination.
        let byte = unsafe { architecture_read_user_byte(source + offset) };
        // SAFETY: `offset < length <= destination_len` and the destination is
        // uniquely borrowed for the complete synchronous run.
        unsafe { ptr::write(state.destination.add(offset), byte) };
    }
    (status << 32) | length as u64
}

#[cfg(target_os = "uefi")]
fn application_syscall(
    call_number: u64,
    arguments: [u64; 5],
    context: ArchitectureApplicationContext,
) -> u64 {
    crate::mechanism::disarm_execution_timer();
    match call_number {
        APPLICATION_EXIT_CALL => match u32::try_from(arguments[0]) {
            Ok(status) => u64::from(status),
            Err(_) => encoded_fault(IsolatedFault::InvalidCall),
        },
        APPLICATION_YIELD_CALL => suspend_application(
            context,
            ApplicationPending::Yield,
            OUTCOME_APPLICATION_YIELD,
        ),
        APPLICATION_HANDLE_CALL => {
            let Ok(request_bytes) = usize::try_from(arguments[2]) else {
                return encoded_fault(IsolatedFault::InvalidCall);
            };
            let Ok(reply_capacity) = usize::try_from(arguments[4]) else {
                return encoded_fault(IsolatedFault::InvalidCall);
            };
            // The copied request begins with one little-endian u16 service
            // opcode. The remaining bytes are the service payload.
            if !(2..=4 * 1024).contains(&request_bytes)
                || reply_capacity > 4 * 1024
                || arguments[0] == 0
                || user_ranges_overlap(arguments[1], request_bytes, arguments[3], reply_capacity)
            {
                return encoded_fault(IsolatedFault::InvalidCall);
            }
            // SAFETY: The single native exception path uniquely accesses the
            // active state while nested exception delivery remains masked.
            let Some(state) = (unsafe { &mut *ISOLATED_RUN.0.get() }).as_ref() else {
                return encoded_fault(IsolatedFault::InvalidCall);
            };
            if !user_range_valid(
                &state.regions,
                state.region_count,
                arguments[1],
                request_bytes,
                false,
            ) || !user_range_valid(
                &state.regions,
                state.region_count,
                arguments[3],
                reply_capacity,
                true,
            ) {
                return encoded_fault(IsolatedFault::InvalidCall);
            }
            let call = ApplicationCall {
                handle: arguments[0],
                request_address: arguments[1],
                request_bytes,
                reply_address: arguments[3],
                reply_capacity,
            };
            suspend_application(
                context,
                ApplicationPending::HandleCall(call),
                OUTCOME_APPLICATION_HANDLE_CALL,
            )
        }
        _ => encoded_fault(IsolatedFault::InvalidCall),
    }
}

#[cfg(target_os = "uefi")]
fn suspend_application(
    context: ArchitectureApplicationContext,
    pending: ApplicationPending,
    outcome: u64,
) -> u64 {
    // SAFETY: The active exception path has exclusive access and returns to
    // the kernel immediately after installing this bounded saved context.
    let Some(state) = (unsafe { &mut *ISOLATED_RUN.0.get() }).as_mut() else {
        return encoded_fault(IsolatedFault::InvalidCall);
    };
    if state.kind != RunKind::Application
        || state.application_context.is_some()
        || state.pending_application.is_some()
    {
        return encoded_fault(IsolatedFault::InvalidCall);
    }
    state.application_context = Some(context);
    state.pending_application = Some(pending);
    outcome
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn application_context_set_results(
    context: &mut ArchitectureApplicationContext,
    status: u32,
    secondary: u32,
) {
    context.rax = u64::from(status);
    context.rdx = u64::from(secondary);
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn application_context_set_results(
    context: &mut ArchitectureApplicationContext,
    status: u32,
    secondary: u32,
) {
    context.general[0] = u64::from(status);
    context.general[1] = u64::from(secondary);
}

#[cfg(target_os = "uefi")]
fn active_run_kind() -> Option<RunKind> {
    // SAFETY: Native exception entries run with nested delivery masked while
    // the unique synchronous launcher retains the active state.
    unsafe { (&*ISOLATED_RUN.0.get()).as_ref().map(|state| state.kind) }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
unsafe fn architecture_read_user_byte(address: usize) -> u8 {
    let value: u64;
    // SAFETY: The caller validated the complete source mapping and the active
    // ring-3 page tables remain installed. When SMAP is active, AC is raised
    // only for this exact load and cleared before control returns to Rust.
    unsafe {
        core::arch::asm!(
            "mov {control}, cr4",
            "bt {control}, 21",
            "jnc 2f",
            "stac",
            "movzx {value}, byte ptr [{address}]",
            "clac",
            "jmp 3f",
            "2:",
            "movzx {value}, byte ptr [{address}]",
            "3:",
            control = out(reg) _,
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, readonly),
        );
    }
    value.to_le_bytes()[0]
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe fn architecture_read_user_byte(address: usize) -> u8 {
    let value: u64;
    // SAFETY: LDTRB performs an explicit unprivileged access, so PAN cannot
    // silently turn a valid copied-message source into an EL1 access. The full
    // range was validated against the active task's readable user mappings.
    unsafe {
        core::arch::asm!(
            "ldtrb {value:w}, [{address}]",
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, readonly),
        );
    }
    value.to_le_bytes()[0]
}

#[cfg(target_os = "uefi")]
const fn encoded_fault(fault: IsolatedFault) -> u64 {
    OUTCOME_FAULT_BIT
        | match fault {
            IsolatedFault::Translation => 1,
            IsolatedFault::Permission => 2,
            IsolatedFault::IllegalInstruction => 3,
            IsolatedFault::InvalidCall => 4,
            IsolatedFault::ExecutionLeaseExpired => 5,
        }
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
const X86_USER: u64 = 1 << 2;
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
    smep: bool,
    smap: bool,
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_mmu_capabilities() -> Result<ArchitectureMmuCapabilities, MmuError> {
    let mut maximum_basic = 0_u32;
    let control: u64;
    // SAFETY: CPUID leaf zero is available in 64-bit mode and reports the
    // maximum supported basic leaf without touching memory. CR4 is readable at
    // the current kernel privilege level.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0_u32 => maximum_basic,
            out("ecx") _,
            out("edx") _,
        );
        core::arch::asm!("mov {}, cr4", out(reg) control, options(nostack));
    }
    // This backend emits four-level tables and does not own CET or supervisor
    // protection-key state. Reject inherited modes before replacing tables or
    // descriptor state instead of faulting partway through the handoff.
    if control & ((1 << 12) | (1 << 23) | (1 << 24)) != 0 {
        return Err(MmuError::UnsupportedCpu);
    }
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
    let mut basic_features = 0_u32;
    if maximum_basic >= 7 {
        // SAFETY: Subleaf zero of the checked structured-feature leaf reports
        // SMEP/SMAP in EBX. RBX is preserved for LLVM's reserved use.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "mov esi, ebx",
                "pop rbx",
                inout("eax") 7_u32 => _,
                inout("ecx") 0_u32 => _,
                out("edx") _,
                out("esi") basic_features,
            );
        }
    }
    Ok(ArchitectureMmuCapabilities {
        physical_address_bits,
        smep: basic_features & (1 << 7) != 0,
        smap: basic_features & (1 << 20) != 0,
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
#[allow(clippy::too_many_arguments)]
fn architecture_map_page(
    arena: &mut TableArena,
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: MappingPermissions,
    memory_type: MappingMemoryType,
    privilege: MappingPrivilege,
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
            let user = u64::from(privilege == MappingPrivilege::User) * X86_USER;
            unsafe { ptr::write_volatile(entry, child | X86_PRESENT | X86_WRITABLE | user) };
            child
        } else {
            if privilege == MappingPrivilege::User && current & X86_USER == 0 {
                // SAFETY: Promoting a traversal entry does not expose any
                // supervisor leaf; each terminal PTE still carries its own U/S
                // bit. It is required when address ranges share upper levels.
                unsafe { ptr::write_volatile(entry, current | X86_USER) };
            }
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
    if privilege == MappingPrivilege::User {
        flags |= X86_USER;
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
fn architecture_activate(root: u64, capabilities: ArchitectureMmuCapabilities) {
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
        // The Stage 6 user gate is the owned DPL-3 interrupt entry. Firmware
        // syscall state is not part of the post-handoff contract.
        efer_low &= !1;
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
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
        // Normalize firmware-owned user-entry state, then enable supervisor
        // execution/access protection only when CPUID proves support.
        cr4 &= !((1 << 16) | (1 << 20) | (1 << 21) | (1 << 22));
        if capabilities.smep {
            cr4 |= 1 << 20;
        }
        if capabilities.smap {
            cr4 |= 1 << 21;
        }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack));
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0x174_u32,
            in("eax") 0_u32,
            in("edx") 0_u32,
            options(nostack),
        );
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
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_USER_DATA_SELECTOR: u16 = 0x2b;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_USER_CODE_SELECTOR: u16 = 0x33;

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
static X86_KERNEL_CONTEXT: AtomicU64 = AtomicU64::new(0);

#[cfg(any(test, all(target_os = "uefi", target_arch = "x86_64")))]
fn x86_interrupt_gate(offset: u64, ist: u8) -> u128 {
    x86_interrupt_gate_with_dpl(offset, ist, 0)
}

#[cfg(any(test, all(target_os = "uefi", target_arch = "x86_64")))]
fn x86_interrupt_gate_with_dpl(offset: u64, ist: u8, dpl: u8) -> u128 {
    u128::from(offset & 0xffff)
        | (u128::from(X86_CODE_SELECTOR) << 16)
        | (u128::from(ist & 0x7) << 32)
        | (u128::from(0x8e_u8 | ((dpl & 0x3) << 5)) << 40)
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
    let _capabilities = architecture_mmu_capabilities()?;
    // SAFETY: This is the unique boot-time initialization of the static TSS,
    // GDT, and IDT while interrupts remain disabled.
    unsafe {
        (*X86_TSS.0.get()).0.privilege_stacks[0] = exception_stack.end();
        (*X86_TSS.0.get()).0.interrupt_stacks[0] = exception_stack.end();
        (*X86_GDT.0.get()).0[1] = 0x00af_9a00_0000_ffff;
        (*X86_GDT.0.get()).0[2] = 0x00cf_9200_0000_ffff;
        let (tss_low, tss_high) = x86_tss_descriptor(X86_TSS.0.get() as u64);
        (*X86_GDT.0.get()).0[3] = tss_low;
        (*X86_GDT.0.get()).0[4] = tss_high;
        (*X86_GDT.0.get()).0[5] = 0x00cf_f200_0000_ffff;
        (*X86_GDT.0.get()).0[6] = 0x00af_fa00_0000_ffff;

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
            crate::mechanism::X86_NETWORK_VECTOR,
        ] {
            (*X86_IDT.0.get()).0[usize::from(vector)] = x86_interrupt_gate(input, 0);
        }
        let timer = x86_execution_timer_entry as *const () as usize as u64;
        (*X86_IDT.0.get()).0[usize::from(crate::mechanism::X86_TIMER_VECTOR)] =
            x86_interrupt_gate(timer, 0);
        let spurious = x86_spurious_interrupt_entry as *const () as usize as u64;
        (*X86_IDT.0.get()).0[usize::from(crate::mechanism::X86_SPURIOUS_VECTOR)] =
            x86_interrupt_gate(spurious, 0);
        let syscall = x86_isolated_syscall_entry as *const () as usize as u64;
        (*X86_IDT.0.get()).0[0x80] = x86_interrupt_gate_with_dpl(syscall, 0, 3);
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
fn architecture_run_isolated(root: u64, entry: u64, stack_top: u64) -> u64 {
    // SAFETY: `run_isolated` validated all mappings and exclusively installed
    // the active state. The naked boundary preserves every x64 callee-saved GPR
    // and the complete legacy/SSE state before entering ring 3.
    unsafe { x86_enter_isolated(root, entry, stack_top) }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_run_application(
    root: u64,
    entry: u64,
    stack_top: u64,
    startup_address: u64,
    startup_bytes: usize,
) -> u64 {
    // SAFETY: `run_application` validated the complete entry, startup, and
    // stack mappings and installed the unique active application state.
    unsafe {
        x86_enter_application(
            root,
            entry,
            stack_top,
            startup_address,
            startup_bytes as u64,
        )
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_resume_application(root: u64, context: &ArchitectureApplicationContext) -> u64 {
    // SAFETY: `resume_application` owns the saved context, validated root, and
    // unique active run state for the complete synchronous transition.
    unsafe { aarch64_resume_application(root, ptr::from_ref(context)) }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_resume_application(root: u64, context: &ArchitectureApplicationContext) -> u64 {
    // SAFETY: `resume_application` owns the saved context, validated root, and
    // unique active run state for the complete synchronous transition.
    unsafe { x86_resume_application(root, ptr::from_ref(context)) }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
unsafe extern "C" fn x86_enter_isolated(_root: u64, _entry: u64, _stack_top: u64) -> u64 {
    core::arch::naked_asm!(
        "push rbx",
        "push rbp",
        "push rdi",
        "push rsi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rax, rsp",
        "sub rsp, 544",
        "and rsp, -16",
        "fxsave64 [rsp]",
        "mov [rsp + 512], rax",
        "pushfq",
        "pop rax",
        "mov [rsp + 520], rax",
        "lea rax, [rip + {context}]",
        "mov [rax], rsp",
        "push {user_data}",
        "push r8",
        "push 2",
        "push {user_code}",
        "push rdx",
        "cli",
        "mov cr3, rcx",
        "iretq",
        context = sym X86_KERNEL_CONTEXT,
        user_data = const X86_USER_DATA_SELECTOR,
        user_code = const X86_USER_CODE_SELECTOR,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
static X86_DEFAULT_MXCSR: u32 = 0x1f80;

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
unsafe extern "C" fn x86_enter_application(
    _root: u64,
    _entry: u64,
    _stack_top: u64,
    _startup_address: u64,
    _startup_bytes: u64,
) -> u64 {
    core::arch::naked_asm!(
        "mov r10, r9",
        "mov r11, [rsp + 40]",
        "push rbx",
        "push rbp",
        "push rdi",
        "push rsi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rax, rsp",
        "sub rsp, 544",
        "and rsp, -16",
        "fxsave64 [rsp]",
        "mov [rsp + 512], rax",
        "pushfq",
        "pop rax",
        "mov [rsp + 520], rax",
        "mov [rsp + 528], r10",
        "mov [rsp + 536], r11",
        "lea rax, [rip + {context}]",
        "mov [rax], rsp",
        "mov rdi, [rsp + 528]",
        "mov rsi, [rsp + 536]",
        "push {user_data}",
        "push r8",
        "push 0x202",
        "push {user_code}",
        "push rdx",
        "cli",
        "mov cr3, rcx",
        "fninit",
        "ldmxcsr [rip + {default_mxcsr}]",
        "pxor xmm0, xmm0",
        "pxor xmm1, xmm1",
        "pxor xmm2, xmm2",
        "pxor xmm3, xmm3",
        "pxor xmm4, xmm4",
        "pxor xmm5, xmm5",
        "pxor xmm6, xmm6",
        "pxor xmm7, xmm7",
        "pxor xmm8, xmm8",
        "pxor xmm9, xmm9",
        "pxor xmm10, xmm10",
        "pxor xmm11, xmm11",
        "pxor xmm12, xmm12",
        "pxor xmm13, xmm13",
        "pxor xmm14, xmm14",
        "pxor xmm15, xmm15",
        "xor eax, eax",
        "xor ebx, ebx",
        "xor ebp, ebp",
        "xor ecx, ecx",
        "xor edx, edx",
        "xor r8d, r8d",
        "xor r9d, r9d",
        "xor r10d, r10d",
        "xor r11d, r11d",
        "xor r12d, r12d",
        "xor r13d, r13d",
        "xor r14d, r14d",
        "xor r15d, r15d",
        "iretq",
        context = sym X86_KERNEL_CONTEXT,
        default_mxcsr = sym X86_DEFAULT_MXCSR,
        user_data = const X86_USER_DATA_SELECTOR,
        user_code = const X86_USER_CODE_SELECTOR,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
unsafe extern "C" fn x86_resume_application(
    _root: u64,
    _context: *const ArchitectureApplicationContext,
) -> u64 {
    core::arch::naked_asm!(
        "mov r10, rdx",
        "push rbx",
        "push rbp",
        "push rdi",
        "push rsi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rax, rsp",
        "sub rsp, 544",
        "and rsp, -16",
        "fxsave64 [rsp]",
        "mov [rsp + 512], rax",
        "pushfq",
        "pop rax",
        "mov [rsp + 520], rax",
        "mov [rsp + 528], r10",
        "lea rax, [rip + {kernel_context}]",
        "mov [rax], rsp",
        "mov r10, [rsp + 528]",
        "push {user_data}",
        "push qword ptr [r10 + 656]",
        "push qword ptr [r10 + 648]",
        "push {user_code}",
        "push qword ptr [r10 + 632]",
        "cli",
        "mov cr3, rcx",
        "fxrstor64 [r10]",
        "mov rax, [r10 + 512]",
        "mov rbx, [r10 + 520]",
        "mov rcx, [r10 + 528]",
        "mov rdx, [r10 + 536]",
        "mov rbp, [r10 + 544]",
        "mov rsi, [r10 + 552]",
        "mov rdi, [r10 + 560]",
        "mov r8, [r10 + 568]",
        "mov r9, [r10 + 576]",
        "mov r11, [r10 + 592]",
        "mov r12, [r10 + 600]",
        "mov r13, [r10 + 608]",
        "mov r14, [r10 + 616]",
        "mov r15, [r10 + 624]",
        "mov r10, [r10 + 584]",
        "iretq",
        kernel_context = sym X86_KERNEL_CONTEXT,
        user_data = const X86_USER_DATA_SELECTOR,
        user_code = const X86_USER_CODE_SELECTOR,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_isolated_complete() -> ! {
    core::arch::naked_asm!(
        "mov r11, rax",
        "lea rax, [rip + {kernel_root}]",
        "mov rax, [rax]",
        "mov cr3, rax",
        "lea rax, [rip + {context}]",
        "mov rsp, [rax]",
        "mov r10, [rsp + 520]",
        "fxrstor64 [rsp]",
        "mov rsp, [rsp + 512]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rsi",
        "pop rdi",
        "pop rbp",
        "pop rbx",
        "push r10",
        "popfq",
        "mov rax, r11",
        "ret",
        kernel_root = sym KERNEL_ROOT,
        context = sym X86_KERNEL_CONTEXT,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_isolated_syscall_entry() -> ! {
    core::arch::naked_asm!(
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rbp",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        "sub rsp, 512",
        "fxsave64 [rsp]",
        "cld",
        "pushfq",
        "btr qword ptr [rsp], 18",
        "popfq",
        "mov rcx, rsp",
        "sub rsp, 32",
        "call {handler}",
        "jmp {complete}",
        handler = sym x86_isolated_syscall_handler,
        complete = sym x86_isolated_complete,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
extern "C" fn x86_isolated_syscall_handler(frame: *const ArchitectureApplicationContext) -> u64 {
    if !ISOLATED_ACTIVE.load(Ordering::Acquire) {
        x86_exception_fatal();
    }
    // SAFETY: The naked gate constructed one complete aligned frame on the
    // owned kernel stack and retains it for this synchronous handler call.
    let frame = unsafe { &*frame };
    match active_run_kind() {
        Some(RunKind::Stage6Probe) => isolated_syscall(frame.rax, frame.rdi, frame.rsi, frame.rdx),
        Some(RunKind::Application) => application_syscall(
            frame.rax,
            [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8],
            frame.clone(),
        ),
        None => x86_exception_fatal(),
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_execution_timer_entry() -> ! {
    core::arch::naked_asm!(
        "cld",
        "pushfq",
        "btr qword ptr [rsp], 18",
        "popfq",
        "mov rcx, [rsp + 8]",
        "and rsp, -16",
        "sub rsp, 32",
        "call {handler}",
        "jmp {complete}",
        handler = sym x86_execution_timer_handler,
        complete = sym x86_isolated_complete,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
extern "C" fn x86_execution_timer_handler(code_selector: u64) -> u64 {
    crate::mechanism::disarm_execution_timer();
    crate::mechanism::acknowledge_execution_timer_interrupt();
    if code_selector & 3 == 3
        && ISOLATED_ACTIVE.load(Ordering::Acquire)
        && active_run_kind() == Some(RunKind::Application)
    {
        encoded_fault(IsolatedFault::ExecutionLeaseExpired)
    } else {
        x86_exception_fatal()
    }
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
        "cld",
        "pushfq",
        "btr qword ptr [rsp], 18",
        "popfq",
        "mov rcx, [rsp + 8]",
        "and rsp, -16",
        "sub rsp, 32",
        "call {dispatch}",
        "jmp {complete}",
        dispatch = sym x86_exception_dispatch,
        complete = sym x86_isolated_complete,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[unsafe(naked)]
extern "C" fn x86_exception_error_entry() -> ! {
    core::arch::naked_asm!(
        "cld",
        "pushfq",
        "btr qword ptr [rsp], 18",
        "popfq",
        "mov rcx, [rsp + 16]",
        "and rsp, -16",
        "sub rsp, 32",
        "call {dispatch}",
        "jmp {complete}",
        dispatch = sym x86_exception_dispatch,
        complete = sym x86_isolated_complete,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
extern "C" fn x86_exception_dispatch(code_selector: u64) -> u64 {
    if code_selector & 3 == 3 && ISOLATED_ACTIVE.load(Ordering::Acquire) {
        encoded_fault(IsolatedFault::IllegalInstruction)
    } else {
        x86_exception_fatal()
    }
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
        "cld",
        "pushfq",
        "btr qword ptr [rsp], 18",
        "popfq",
        "mov rdx, [rsp]",
        "mov r8, [rsp + 16]",
        "mov rcx, cr2",
        "and rsp, -16",
        "sub rsp, 32",
        "call {dispatch}",
        "jmp {complete}",
        dispatch = sym x86_page_fault_dispatch,
        complete = sym x86_isolated_complete,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
extern "C" fn x86_page_fault_dispatch(address: u64, error: u64, code_selector: u64) -> u64 {
    if code_selector & 3 == 3 && ISOLATED_ACTIVE.load(Ordering::Acquire) {
        encoded_fault(if error & 1 == 0 {
            IsolatedFault::Translation
        } else {
            IsolatedFault::Permission
        })
    } else {
        x86_page_fault_fatal(address, error)
    }
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
const AARCH64_USER_READ_WRITE: u64 = 0b01 << 6;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_USER_READ_ONLY: u64 = 0b11 << 6;
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
#[allow(clippy::too_many_arguments)]
fn architecture_map_page(
    arena: &mut TableArena,
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: MappingPermissions,
    memory_type: MappingMemoryType,
    privilege: MappingPrivilege,
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
    let mut flags = AARCH64_TABLE_OR_PAGE | AARCH64_ACCESS_FLAG;
    if privilege == MappingPrivilege::User {
        flags |= AARCH64_PXN;
        flags |= if permissions.write {
            AARCH64_USER_READ_WRITE
        } else {
            AARCH64_USER_READ_ONLY
        };
        if !permissions.execute {
            flags |= AARCH64_UXN;
        }
    } else {
        flags |= AARCH64_UXN;
        if !permissions.write {
            flags |= AARCH64_READ_ONLY;
        }
        if !permissions.execute {
            flags |= AARCH64_PXN;
        }
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
static AARCH64_KERNEL_CONTEXT: AtomicU64 = AtomicU64::new(0);

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_run_isolated(root: u64, entry: u64, stack_top: u64) -> u64 {
    // SAFETY: `run_isolated` validated all mappings and exclusively installed
    // the active state. The naked boundary preserves AAPCS64 callee-saved GPR,
    // SIMD, and floating-point control state before entering EL0t.
    unsafe { aarch64_enter_isolated(root, entry, stack_top) }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_run_application(
    root: u64,
    entry: u64,
    stack_top: u64,
    startup_address: u64,
    startup_bytes: usize,
) -> u64 {
    // SAFETY: `run_application` validated the complete entry, startup, and
    // stack mappings and installed the unique active application state.
    unsafe {
        aarch64_enter_application(
            root,
            entry,
            stack_top,
            startup_address,
            startup_bytes as u64,
        )
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(naked)]
unsafe extern "C" fn aarch64_enter_isolated(_root: u64, _entry: u64, _stack_top: u64) -> u64 {
    core::arch::naked_asm!(
        "sub sp, sp, #272",
        "stp x19, x20, [sp, #0]",
        "stp x21, x22, [sp, #16]",
        "stp x23, x24, [sp, #32]",
        "stp x25, x26, [sp, #48]",
        "stp x27, x28, [sp, #64]",
        "stp x29, x30, [sp, #80]",
        "stp q8, q9, [sp, #96]",
        "stp q10, q11, [sp, #128]",
        "stp q12, q13, [sp, #160]",
        "stp q14, q15, [sp, #192]",
        "mrs x9, fpcr",
        "mrs x10, fpsr",
        "str x9, [sp, #224]",
        "str x10, [sp, #232]",
        "mrs x9, daif",
        "str x9, [sp, #240]",
        "mrs x9, sp_el0",
        "str x9, [sp, #248]",
        "mrs x9, tpidr_el0",
        "str x9, [sp, #256]",
        "adr x9, {context}",
        "mov x10, sp",
        "str x10, [x9]",
        "msr ttbr0_el1, x0",
        "dsb sy",
        "tlbi vmalle1",
        "dsb sy",
        "isb",
        "msr sp_el0, x2",
        "msr elr_el1, x1",
        "mov x9, #0x3c0",
        "msr spsr_el1, x9",
        "eret",
        context = sym AARCH64_KERNEL_CONTEXT,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(naked)]
#[allow(clippy::too_many_lines)]
unsafe extern "C" fn aarch64_enter_application(
    _root: u64,
    _entry: u64,
    _stack_top: u64,
    _startup_address: u64,
    _startup_bytes: u64,
) -> u64 {
    core::arch::naked_asm!(
        "sub sp, sp, #272",
        "stp x19, x20, [sp, #0]",
        "stp x21, x22, [sp, #16]",
        "stp x23, x24, [sp, #32]",
        "stp x25, x26, [sp, #48]",
        "stp x27, x28, [sp, #64]",
        "stp x29, x30, [sp, #80]",
        "stp q8, q9, [sp, #96]",
        "stp q10, q11, [sp, #128]",
        "stp q12, q13, [sp, #160]",
        "stp q14, q15, [sp, #192]",
        "mrs x9, fpcr",
        "mrs x10, fpsr",
        "str x9, [sp, #224]",
        "str x10, [sp, #232]",
        "mrs x9, daif",
        "str x9, [sp, #240]",
        "mrs x9, sp_el0",
        "str x9, [sp, #248]",
        "mrs x9, tpidr_el0",
        "str x9, [sp, #256]",
        "adr x9, {context}",
        "mov x10, sp",
        "str x10, [x9]",
        "msr ttbr0_el1, x0",
        "dsb sy",
        "tlbi vmalle1",
        "dsb sy",
        "isb",
        "msr sp_el0, x2",
        "msr elr_el1, x1",
        "msr spsr_el1, xzr",
        "msr fpcr, xzr",
        "msr fpsr, xzr",
        "msr tpidr_el0, xzr",
        "movi v0.16b, #0",
        "movi v1.16b, #0",
        "movi v2.16b, #0",
        "movi v3.16b, #0",
        "movi v4.16b, #0",
        "movi v5.16b, #0",
        "movi v6.16b, #0",
        "movi v7.16b, #0",
        "movi v8.16b, #0",
        "movi v9.16b, #0",
        "movi v10.16b, #0",
        "movi v11.16b, #0",
        "movi v12.16b, #0",
        "movi v13.16b, #0",
        "movi v14.16b, #0",
        "movi v15.16b, #0",
        "movi v16.16b, #0",
        "movi v17.16b, #0",
        "movi v18.16b, #0",
        "movi v19.16b, #0",
        "movi v20.16b, #0",
        "movi v21.16b, #0",
        "movi v22.16b, #0",
        "movi v23.16b, #0",
        "movi v24.16b, #0",
        "movi v25.16b, #0",
        "movi v26.16b, #0",
        "movi v27.16b, #0",
        "movi v28.16b, #0",
        "movi v29.16b, #0",
        "movi v30.16b, #0",
        "movi v31.16b, #0",
        "mov x0, x3",
        "mov x1, x4",
        "mov x2, xzr",
        "mov x3, xzr",
        "mov x4, xzr",
        "mov x5, xzr",
        "mov x6, xzr",
        "mov x7, xzr",
        "mov x8, xzr",
        "mov x9, xzr",
        "mov x10, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x17, xzr",
        "mov x18, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",
        "eret",
        context = sym AARCH64_KERNEL_CONTEXT,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(naked)]
#[allow(clippy::too_many_lines)]
unsafe extern "C" fn aarch64_resume_application(
    _root: u64,
    _context: *const ArchitectureApplicationContext,
) -> u64 {
    core::arch::naked_asm!(
        "mov x11, x1",
        "sub sp, sp, #272",
        "stp x19, x20, [sp, #0]",
        "stp x21, x22, [sp, #16]",
        "stp x23, x24, [sp, #32]",
        "stp x25, x26, [sp, #48]",
        "stp x27, x28, [sp, #64]",
        "stp x29, x30, [sp, #80]",
        "stp q8, q9, [sp, #96]",
        "stp q10, q11, [sp, #128]",
        "stp q12, q13, [sp, #160]",
        "stp q14, q15, [sp, #192]",
        "mrs x9, fpcr",
        "mrs x10, fpsr",
        "str x9, [sp, #224]",
        "str x10, [sp, #232]",
        "mrs x9, daif",
        "str x9, [sp, #240]",
        "mrs x9, sp_el0",
        "str x9, [sp, #248]",
        "mrs x9, tpidr_el0",
        "str x9, [sp, #256]",
        "adr x9, {kernel_context}",
        "mov x10, sp",
        "str x10, [x9]",
        "msr ttbr0_el1, x0",
        "dsb sy",
        "tlbi vmalle1",
        "dsb sy",
        "isb",
        "ldr x9, [x11, #800]",
        "msr sp_el0, x9",
        "ldr x9, [x11, #784]",
        "msr elr_el1, x9",
        "ldr x9, [x11, #792]",
        "msr spsr_el1, x9",
        "ldr x9, [x11, #768]",
        "ldr x10, [x11, #776]",
        "msr fpcr, x9",
        "msr fpsr, x10",
        "ldp q0, q1, [x11, #256]",
        "ldp q2, q3, [x11, #288]",
        "ldp q4, q5, [x11, #320]",
        "ldp q6, q7, [x11, #352]",
        "ldp q8, q9, [x11, #384]",
        "ldp q10, q11, [x11, #416]",
        "ldp q12, q13, [x11, #448]",
        "ldp q14, q15, [x11, #480]",
        "ldp q16, q17, [x11, #512]",
        "ldp q18, q19, [x11, #544]",
        "ldp q20, q21, [x11, #576]",
        "ldp q22, q23, [x11, #608]",
        "ldp q24, q25, [x11, #640]",
        "ldp q26, q27, [x11, #672]",
        "ldp q28, q29, [x11, #704]",
        "ldp q30, q31, [x11, #736]",
        "mov x30, x11",
        "ldp x0, x1, [x30, #0]",
        "ldp x2, x3, [x30, #16]",
        "ldp x4, x5, [x30, #32]",
        "ldp x6, x7, [x30, #48]",
        "ldp x8, x9, [x30, #64]",
        "ldp x10, x11, [x30, #80]",
        "ldp x12, x13, [x30, #96]",
        "ldp x14, x15, [x30, #112]",
        "ldp x16, x17, [x30, #128]",
        "ldp x18, x19, [x30, #144]",
        "ldp x20, x21, [x30, #160]",
        "ldp x22, x23, [x30, #176]",
        "ldp x24, x25, [x30, #192]",
        "ldp x26, x27, [x30, #208]",
        "ldp x28, x29, [x30, #224]",
        "ldr x30, [x30, #240]",
        "eret",
        kernel_context = sym AARCH64_KERNEL_CONTEXT,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(naked)]
extern "C" fn aarch64_isolated_complete() -> ! {
    core::arch::naked_asm!(
        "mov x11, x0",
        "adr x9, {kernel_root}",
        "ldr x10, [x9]",
        "msr ttbr0_el1, x10",
        "dsb sy",
        "tlbi vmalle1",
        "dsb sy",
        "isb",
        "adr x9, {context}",
        "ldr x9, [x9]",
        "mov sp, x9",
        "ldr x12, [sp, #240]",
        "ldr x9, [sp, #248]",
        "msr sp_el0, x9",
        "ldr x9, [sp, #256]",
        "msr tpidr_el0, x9",
        "ldr x9, [sp, #224]",
        "ldr x10, [sp, #232]",
        "msr fpcr, x9",
        "msr fpsr, x10",
        "ldp q8, q9, [sp, #96]",
        "ldp q10, q11, [sp, #128]",
        "ldp q12, q13, [sp, #160]",
        "ldp q14, q15, [sp, #192]",
        "ldp x19, x20, [sp, #0]",
        "ldp x21, x22, [sp, #16]",
        "ldp x23, x24, [sp, #32]",
        "ldp x25, x26, [sp, #48]",
        "ldp x27, x28, [sp, #64]",
        "ldp x29, x30, [sp, #80]",
        "add sp, sp, #272",
        "msr daif, x12",
        "mov x0, x11",
        "ret",
        kernel_root = sym KERNEL_ROOT,
        context = sym AARCH64_KERNEL_CONTEXT,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
core::arch::global_asm!(
    ".text",
    ".balign 2048",
    ".global troe_aarch64_vectors",
    "troe_aarch64_vectors:",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_irq_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_irq_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_lower_sync_entry",
    ".balign 128",
    "b troe_aarch64_irq_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_irq_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "b troe_aarch64_exception_entry",
    ".balign 128",
    "troe_aarch64_exception_entry:",
    "msr daifset, #0xf",
    "mrs x0, esr_el1",
    "mrs x1, far_el1",
    "bl troe_aarch64_exception_fatal",
    "b .",
    ".balign 128",
    "troe_aarch64_lower_sync_entry:",
    "msr daifset, #0xf",
    "sub sp, sp, #816",
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
    "stp q0, q1, [sp, #256]",
    "stp q2, q3, [sp, #288]",
    "stp q4, q5, [sp, #320]",
    "stp q6, q7, [sp, #352]",
    "stp q8, q9, [sp, #384]",
    "stp q10, q11, [sp, #416]",
    "stp q12, q13, [sp, #448]",
    "stp q14, q15, [sp, #480]",
    "stp q16, q17, [sp, #512]",
    "stp q18, q19, [sp, #544]",
    "stp q20, q21, [sp, #576]",
    "stp q22, q23, [sp, #608]",
    "stp q24, q25, [sp, #640]",
    "stp q26, q27, [sp, #672]",
    "stp q28, q29, [sp, #704]",
    "stp q30, q31, [sp, #736]",
    "mrs x9, fpcr",
    "mrs x10, fpsr",
    "str x9, [sp, #768]",
    "str x10, [sp, #776]",
    "mrs x9, elr_el1",
    "mrs x10, spsr_el1",
    "str x9, [sp, #784]",
    "str x10, [sp, #792]",
    "mrs x9, sp_el0",
    "str x9, [sp, #800]",
    "mrs x9, esr_el1",
    "lsr x10, x9, #26",
    "cmp x10, #0x15",
    "b.eq 1f",
    "mov x0, x9",
    "mrs x1, far_el1",
    "bl troe_aarch64_isolated_fault",
    "b troe_aarch64_isolated_complete_entry",
    "1:",
    "mov x0, sp",
    "mov x1, x9",
    "bl troe_aarch64_isolated_syscall",
    "b troe_aarch64_isolated_complete_entry",
    "troe_aarch64_isolated_complete_entry:",
    "b {isolated_complete}",
    ".balign 128",
    "troe_aarch64_irq_entry:",
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
    "bl troe_aarch64_input_interrupt",
    "cbnz x0, troe_aarch64_isolated_complete_entry",
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
    isolated_complete = sym aarch64_isolated_complete,
);

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe extern "C" {
    static troe_aarch64_vectors: u8;
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
    let vectors = ptr::addr_of!(troe_aarch64_vectors) as u64;
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
extern "C" fn troe_aarch64_input_interrupt() -> u64 {
    if crate::mechanism::handle_application_interrupt() {
        if ISOLATED_ACTIVE.load(Ordering::Acquire)
            && active_run_kind() == Some(RunKind::Application)
        {
            encoded_fault(IsolatedFault::ExecutionLeaseExpired)
        } else {
            troe_aarch64_exception_fatal(0, 0)
        }
    } else {
        0
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(no_mangle)]
extern "C" fn troe_aarch64_isolated_syscall(
    frame: *const ArchitectureApplicationContext,
    syndrome: u64,
) -> u64 {
    if !ISOLATED_ACTIVE.load(Ordering::Acquire) {
        troe_aarch64_exception_fatal(0, 0);
    }
    if syndrome & 0xffff != 0 {
        encoded_fault(IsolatedFault::InvalidCall)
    } else {
        // SAFETY: The lower-EL gate constructed one complete aligned frame on
        // the owned kernel stack and retains it for this synchronous call.
        let frame = unsafe { &*frame };
        match active_run_kind() {
            Some(RunKind::Stage6Probe) => isolated_syscall(
                frame.general[0],
                frame.general[1],
                frame.general[2],
                frame.general[3],
            ),
            Some(RunKind::Application) => application_syscall(
                frame.general[8],
                [
                    frame.general[0],
                    frame.general[1],
                    frame.general[2],
                    frame.general[3],
                    frame.general[4],
                ],
                frame.clone(),
            ),
            None => troe_aarch64_exception_fatal(0, 0),
        }
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(no_mangle)]
extern "C" fn troe_aarch64_isolated_fault(esr: u64, _address: u64) -> u64 {
    if !ISOLATED_ACTIVE.load(Ordering::Acquire) {
        troe_aarch64_exception_fatal(esr, 0);
    }
    let class = (esr >> 26) & 0x3f;
    let status = esr & 0x3f;
    let fault = if matches!(class, 0x20 | 0x24) && status & 0x3c == 0x04 {
        IsolatedFault::Translation
    } else if matches!(class, 0x20 | 0x24) && status & 0x3c == 0x0c {
        IsolatedFault::Permission
    } else {
        IsolatedFault::IllegalInstruction
    };
    encoded_fault(fault)
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[unsafe(no_mangle)]
extern "C" fn troe_aarch64_exception_fatal(esr: u64, _far: u64) -> ! {
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
    use std::vec;
    use std::vec::Vec;
    use troe_memory::MappingPermissions;

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

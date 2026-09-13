//! Allocation-free preflight for a static-TLS process and its initial thread.
//!
//! This composes a validated artifact with shared image/startup/heap reservations
//! and one managed thread window. It is not a native load plan or resource owner.
//! Charges model page-owned full-executable staging and an independent retained
//! initializer. Acquiring that backing, authenticating a package, serializing
//! admission and releasing only quiescent owners remain composition obligations.

use core::fmt;
use troe_abi::threading::{EncodingError, StartupDescriptor, Token};

use crate::{
    ApplicationLimits, KEX_V1_IMAGE_ALIGNMENT, KEX_V1_MIN_IMAGE_BASE, KEX_V1_USER_END,
    MAX_LOAD_RECORDS, PAGE_SIZE, SegmentPermissions,
    static_tls::StaticTlsLayout,
    thread_memory::{
        ThreadMemoryBudget, ThreadMemoryError, ThreadMemoryKind, ThreadMemoryPlan,
        additional_tables,
    },
    tls_artifact::{self, Artifact},
};

const MAX_REGIONS: usize = MAX_LOAD_RECORDS + 2 + 4;

/// Trusted placement; this supplies no entropy or address reservation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMemoryPlacement {
    /// Image base with the same 2 MiB alignment and lower bound as native KEX.
    pub image_base: u64,
    /// Heap growth reservation, including the initially committed heap pages.
    pub heap_capacity_pages: u64,
    /// Start of the initial thread's entire window, including its lower guard.
    pub initial_thread_base: u64,
}

/// Simultaneous remaining allowances after existing owners and system reserves.
///
/// Resident and ordinary-frame allowances must cover the peak while executable
/// staging and the independent initializer coexist. No field is a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMemoryBudget {
    /// Image, process startup, committed heap and initial thread user mappings.
    pub mapped_pages: u64,
    /// Peak logical pages, including page tables, initializer, staging and IPC.
    pub resident_pages: u64,
    /// Both complete virtual reservations, including all unmapped bytes.
    pub reserved_pages: u64,
    /// Peak new frames; excludes the IPC pair already backed by the boot arena.
    pub ordinary_frames: u64,
    /// Task pairs remaining after essential-service and teardown reservations.
    pub ipc_pairs: u64,
    /// Complete initial-thread TLS mapping, including control bytes and padding.
    pub tls_pages: u64,
    /// Page-owned immutable initializer backing, independent of image and TLS.
    pub template_pages: u64,
    /// Complete executable bytes simultaneously retained for verification.
    pub staging_bytes: u64,
}

/// Rejected geometry or memory envelope, before any allocation or publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessMemoryError {
    /// Invalid image placement or an address outside the supported user range.
    InvalidPlacement,
    /// Heap capacity is below the initial commit or above the application limit.
    InvalidHeapCapacity,
    /// Shared reservation overlaps any part of the initial thread's window.
    Overlap,
    /// Checked address, byte or page arithmetic overflowed.
    ArithmeticOverflow,
    /// TLS layout cannot fit the requested initial-thread allowance.
    Tls(tls_artifact::Error),
    /// Initial thread geometry is invalid.
    Thread(ThreadMemoryError),
    /// User mappings exceed the allowance.
    MappedPageBudget,
    /// Peak logical resident pages exceed the allowance.
    ResidentPageBudget,
    /// Complete reserved virtual pages exceed the allowance.
    ReservedPageBudget,
    /// Peak ordinary frames exceed the allowance.
    FrameBudget,
    /// No task IPC pair is available.
    IpcBudget,
    /// Complete initial-thread TLS pages exceed the allowance.
    TlsPageBudget,
    /// Retained immutable initializer pages exceed the allowance.
    TemplateBudget,
    /// Full executable staging bytes exceed the allowance.
    StagingBudget,
}

impl fmt::Display for ProcessMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPlacement => "process memory is outside the aligned user range",
            Self::InvalidHeapCapacity => "heap reservation violates the initial commit or limit",
            Self::Overlap => "shared process and initial-thread reservations overlap",
            Self::ArithmeticOverflow => "process memory arithmetic overflow",
            Self::Tls(error) => return error.fmt(formatter),
            Self::Thread(error) => return error.fmt(formatter),
            Self::MappedPageBudget => "process mappings exceed their page budget",
            Self::ResidentPageBudget => "peak process memory exceeds its resident-page budget",
            Self::ReservedPageBudget => "process reservations exceed their virtual-page budget",
            Self::FrameBudget => "peak process memory exceeds its ordinary-frame budget",
            Self::IpcBudget => "initial thread requires a task IPC pair",
            Self::TlsPageBudget => "initial thread TLS exceeds its page budget",
            Self::TemplateBudget => "immutable TLS initializer exceeds its backing budget",
            Self::StagingBudget => "executable verification exceeds its staging budget",
        })
    }
}

/// Purpose of one nonempty, page-aligned mapping in the composed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessMemoryKind {
    /// One validated image segment, retaining its artifact permissions.
    Image,
    /// One immutable, read-only/NX process startup page.
    Startup,
    /// Initially committed RW/NX heap; remaining capacity stays unmapped.
    Heap,
    /// A region in the managed initial thread's window.
    Thread(ThreadMemoryKind),
}

/// Required virtual mapping; carries no physical backing or live ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMemoryRegion {
    start: u64,
    pages: u64,
    permissions: SegmentPermissions,
    kind: ProcessMemoryKind,
}

impl ProcessMemoryRegion {
    /// First virtual byte.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }
    /// Exclusive virtual end.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.start + self.pages * PAGE_SIZE
    }
    /// Nonzero committed base pages.
    #[must_use]
    pub const fn pages(self) -> u64 {
        self.pages
    }
    /// Required closed user permission value; no writable executable regions.
    #[must_use]
    pub const fn permissions(self) -> SegmentPermissions {
        self.permissions
    }
    /// Purpose of this mapping.
    #[must_use]
    pub const fn kind(self) -> ProcessMemoryKind {
        self.kind
    }
}

/// Checked whole-process memory charges; excludes native/runtime metadata.
///
/// These counts assume dedicated page backing for the initializer and staged
/// executable. Allocator overhead, package metadata and extra verification or
/// I/O buffers are separate charges. Staging remains charged until its owner is
/// actually released; execution starting alone does not justify a refund.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMemoryCharges {
    shared_pages: u64,
    initial_thread_pages: u64,
    tls_pages: u64,
    reserved_pages: u64,
    table_pages: u64,
    template_pages: u64,
    staging_bytes: u64,
    staging_pages: u64,
}

impl ProcessMemoryCharges {
    /// Shared image segment pages, process startup and committed heap, once.
    #[must_use]
    pub const fn shared_pages(self) -> u64 {
        self.shared_pages
    }
    /// Initial thread's stack, TLS, IPC and immutable descriptor pages.
    #[must_use]
    pub const fn initial_thread_pages(self) -> u64 {
        self.initial_thread_pages
    }
    /// Complete initial-thread TLS mapping, including control bytes and padding.
    #[must_use]
    pub const fn tls_pages(self) -> u64 {
        self.tls_pages
    }
    /// Complete user mappings, excluding kernel-owned tables and loader backing.
    #[must_use]
    pub const fn mapped_pages(self) -> u64 {
        self.shared_pages + self.initial_thread_pages
    }
    /// Shared and thread reservations, counting guards, image holes and heap slack.
    #[must_use]
    pub const fn reserved_pages(self) -> u64 {
        self.reserved_pages
    }
    /// One root plus the union of all lower-table prefixes needed by user mappings.
    /// Architecture-specific kernel/shared root entries require separate backing.
    #[must_use]
    pub const fn table_pages(self) -> u64 {
        self.table_pages
    }
    /// Independent retained TLS initializer pages; zero for an empty prefix.
    #[must_use]
    pub const fn template_pages(self) -> u64 {
        self.template_pages
    }
    /// Complete executable byte length, including its exact initializer suffix.
    #[must_use]
    pub const fn staging_bytes(self) -> u64 {
        self.staging_bytes
    }
    /// Dedicated staging pages, rounded up independently of the initializer.
    #[must_use]
    pub const fn staging_pages(self) -> u64 {
        self.staging_pages
    }
    /// One initial thread always requires one task pair, including with empty TLS.
    #[must_use]
    pub const fn ipc_pairs(self) -> u64 {
        1
    }
    /// Resident charge after staging is released, with retained initializer backing.
    #[must_use]
    pub const fn resident_pages(self) -> u64 {
        self.mapped_pages() + self.table_pages + self.template_pages
    }
    /// Maximum logical pages during full-executable loading.
    #[must_use]
    pub const fn peak_resident_pages(self) -> u64 {
        self.resident_pages() + self.staging_pages
    }
    /// New frames after staging release; the two IPC pages already belong to boot.
    #[must_use]
    pub const fn ordinary_frames(self) -> u64 {
        self.resident_pages() - 2
    }
    /// New frames while staging is retained, excluding existing boot IPC backing.
    #[must_use]
    pub const fn peak_ordinary_frames(self) -> u64 {
        self.peak_resident_pages() - 2
    }
}

impl ProcessMemoryBudget {
    /// Check every resource together without reserving or changing any allowance.
    ///
    /// # Errors
    /// Returns the first exhausted resource class; resident/frame limits use peaks.
    pub fn check(self, charges: ProcessMemoryCharges) -> Result<(), ProcessMemoryError> {
        for (required, available, error) in [
            (
                charges.mapped_pages(),
                self.mapped_pages,
                ProcessMemoryError::MappedPageBudget,
            ),
            (
                charges.peak_resident_pages(),
                self.resident_pages,
                ProcessMemoryError::ResidentPageBudget,
            ),
            (
                charges.reserved_pages(),
                self.reserved_pages,
                ProcessMemoryError::ReservedPageBudget,
            ),
            (
                charges.peak_ordinary_frames(),
                self.ordinary_frames,
                ProcessMemoryError::FrameBudget,
            ),
            (1, self.ipc_pairs, ProcessMemoryError::IpcBudget),
            (
                charges.tls_pages(),
                self.tls_pages,
                ProcessMemoryError::TlsPageBudget,
            ),
            (
                charges.template_pages(),
                self.template_pages,
                ProcessMemoryError::TemplateBudget,
            ),
            (
                charges.staging_bytes(),
                self.staging_bytes,
                ProcessMemoryError::StagingBudget,
            ),
        ] {
            if required > available {
                return Err(error);
            }
        }
        Ok(())
    }
}

/// Composed immutable geometry, with no borrowed artifact or authority to execute.
///
/// The shared reservation is image span, process startup page, then heap capacity.
/// The thread window may be on either side but may not overlap any of it. All
/// bytes within those reservations but outside the returned mappings stay unmapped. Future
/// workers require distinct reservations and supplemental charges; these counts
/// do not grant the process its maximum thread quota in advance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMemoryPlan {
    placement: ProcessMemoryPlacement,
    shared_end: u64,
    startup_address: u64,
    entry_address: u64,
    trampoline_address: u64,
    tls: StaticTlsLayout,
    initial_thread: ThreadMemoryPlan,
    regions: [Option<ProcessMemoryRegion>; MAX_REGIONS],
    charges: ProcessMemoryCharges,
}

impl ProcessMemoryPlan {
    /// Compose checked image geometry, reserved heap capacity and the initial thread.
    ///
    /// This performs bounded work over at most 22 mapped regions, independent of
    /// their page counts. Callers must reserve addresses and all resource classes
    /// atomically against other admissions before allocating or copying anything.
    /// The returned plan cannot encode an admitted process startup or run a thread.
    ///
    /// # Errors
    /// Rejects invalid placement, overlap, overflow or any exhausted memory budget.
    pub fn new(
        artifact: &Artifact<'_>,
        placement: ProcessMemoryPlacement,
        budget: ProcessMemoryBudget,
    ) -> Result<Self, ProcessMemoryError> {
        if placement.image_base < KEX_V1_MIN_IMAGE_BASE
            || !placement.image_base.is_multiple_of(KEX_V1_IMAGE_ALIGNMENT)
        {
            return Err(ProcessMemoryError::InvalidPlacement);
        }
        if placement.heap_capacity_pages < artifact.heap_pages()
            || placement.heap_capacity_pages > ApplicationLimits::standard().heap_pages()
        {
            return Err(ProcessMemoryError::InvalidHeapCapacity);
        }
        let startup_address = add(placement.image_base, artifact.image_span_bytes())?;
        let heap_address = add(startup_address, PAGE_SIZE)?;
        let shared_end = add(heap_address, page_bytes(placement.heap_capacity_pages)?)?;
        if shared_end > KEX_V1_USER_END {
            return Err(ProcessMemoryError::InvalidPlacement);
        }
        let tls = artifact
            .metadata()
            .layout(artifact.target(), u64::MAX)
            .map_err(ProcessMemoryError::Tls)?;
        // Only geometry here. Whole-process budgets below include shared memory,
        // one root and peak loader backing instead of summing partial snapshots.
        let initial_thread = ThreadMemoryPlan::new(
            placement.initial_thread_base,
            artifact.stack_pages(),
            tls,
            ThreadMemoryBudget {
                mapped_pages: u64::MAX,
                resident_pages: u64::MAX,
                reserved_pages: u64::MAX,
                ordinary_frames: u64::MAX,
                ipc_pairs: u64::MAX,
            },
        )
        .map_err(ProcessMemoryError::Thread)?;
        if placement.image_base < initial_thread.reservation_end()
            && initial_thread.reservation_base() < shared_end
        {
            return Err(ProcessMemoryError::Overlap);
        }
        let (regions, shared_pages) = process_regions(
            artifact,
            placement.image_base,
            startup_address,
            initial_thread,
        )?;
        let table_pages = 1 + additional_tables(
            regions.map(|region| region.map_or((0, 0), |region| (region.start(), region.end()))),
        );
        let charges = ProcessMemoryCharges {
            shared_pages,
            initial_thread_pages: initial_thread.charges().mapped_pages(),
            tls_pages: tls.pages(),
            reserved_pages: add(
                (shared_end - placement.image_base) / PAGE_SIZE,
                initial_thread.charges().reserved_pages(),
            )?,
            table_pages,
            template_pages: pages_for(artifact.metadata().file_bytes)?,
            staging_bytes: artifact.encoded_bytes(),
            staging_pages: pages_for(artifact.encoded_bytes())?,
        };
        // Private fields, bounded user mappings and the capped executable length
        // bound all derived sums. Also reject an unrepresentable byte charge.
        page_bytes(charges.peak_resident_pages())?;
        page_bytes(charges.reserved_pages())?;
        budget.check(charges)?;
        Ok(Self {
            placement,
            shared_end,
            startup_address,
            entry_address: add(placement.image_base, artifact.entry_offset())?,
            trampoline_address: add(placement.image_base, artifact.metadata().trampoline_offset)?,
            tls,
            initial_thread,
            regions,
            charges,
        })
    }

    /// Half-open shared reservation, including image holes and uncommitted heap.
    #[must_use]
    pub const fn shared_reservation(&self) -> (u64, u64) {
        (self.placement.image_base, self.shared_end)
    }
    /// Shared immutable process startup address, immediately after the image span.
    #[must_use]
    pub const fn startup_address(&self) -> u64 {
        self.startup_address
    }
    /// Heap base; initial committed mapping may be empty.
    #[must_use]
    pub const fn heap_address(&self) -> u64 {
        self.startup_address + PAGE_SIZE
    }
    /// Reserved heap growth ceiling; growing the committed prefix needs new charges.
    #[must_use]
    pub const fn heap_capacity_pages(&self) -> u64 {
        self.placement.heap_capacity_pages
    }
    /// File-backed executable initial entry at the selected image base.
    #[must_use]
    pub const fn entry_address(&self) -> u64 {
        self.entry_address
    }
    /// File-backed executable worker trampoline at the selected image base.
    #[must_use]
    pub const fn trampoline_address(&self) -> u64 {
        self.trampoline_address
    }
    /// Checked initial thread window; its supplemental table charge is not added twice.
    #[must_use]
    pub const fn initial_thread(&self) -> ThreadMemoryPlan {
        self.initial_thread
    }
    /// TLS geometry bound to this artifact's target and declared template.
    #[must_use]
    pub const fn tls_layout(&self) -> StaticTlsLayout {
        self.tls
    }
    /// Shared regions followed by thread regions, not necessarily address ordered.
    pub fn regions(&self) -> impl Iterator<Item = ProcessMemoryRegion> + '_ {
        self.regions.iter().flatten().copied()
    }
    /// Steady and peak memory charges; no resources have been acquired.
    #[must_use]
    pub const fn charges(&self) -> ProcessMemoryCharges {
        self.charges
    }

    /// Compose the initial descriptor with zero worker entry/argument fields.
    ///
    /// The token is informational; this checks its kind but not live authority.
    /// Publication requires initialized backing and a complete process startup.
    ///
    /// # Errors
    /// Rejects a non-thread token or geometry rejected by the standalone codec.
    pub fn initial_descriptor(&self, thread: Token) -> Result<StartupDescriptor, EncodingError> {
        let [stack, tls, ipc, startup] = self.initial_thread.regions();
        let descriptor = StartupDescriptor {
            thread,
            process_startup: self.startup_address,
            stack_bottom: stack.start(),
            stack_top: stack.end(),
            tls_base: tls.start(),
            tls_bytes: tls.pages() * PAGE_SIZE,
            thread_pointer: self.initial_thread.thread_pointer(),
            ipc_tx: ipc.start(),
            entry: 0,
            argument: 0,
            initial: true,
            address: startup.start(),
        };
        descriptor.encode()?;
        Ok(descriptor)
    }
}

// The validated artifact has at most sixteen segments; startup, optional heap
// and the four thread mappings fit the fixed array exactly.
fn process_regions(
    artifact: &Artifact<'_>,
    image_base: u64,
    startup_address: u64,
    initial_thread: ThreadMemoryPlan,
) -> Result<([Option<ProcessMemoryRegion>; MAX_REGIONS], u64), ProcessMemoryError> {
    let heap_address = add(startup_address, PAGE_SIZE)?;
    let mut regions = [None; MAX_REGIONS];
    let mut count = 0;
    let mut shared_pages = 1 + artifact.heap_pages();
    for segment in artifact.segments() {
        let pages = segment.memory_bytes() / PAGE_SIZE;
        shared_pages = add(shared_pages, pages)?;
        regions[count] = Some(ProcessMemoryRegion {
            start: add(image_base, segment.image_offset())?,
            pages,
            permissions: segment.permissions(),
            kind: ProcessMemoryKind::Image,
        });
        count += 1;
    }
    regions[count] = Some(ProcessMemoryRegion {
        start: startup_address,
        pages: 1,
        permissions: SegmentPermissions::ReadOnly,
        kind: ProcessMemoryKind::Startup,
    });
    count += 1;
    if artifact.heap_pages() != 0 {
        regions[count] = Some(ProcessMemoryRegion {
            start: heap_address,
            pages: artifact.heap_pages(),
            permissions: SegmentPermissions::ReadWrite,
            kind: ProcessMemoryKind::Heap,
        });
        count += 1;
    }
    for region in initial_thread.regions() {
        regions[count] = Some(ProcessMemoryRegion {
            start: region.start(),
            pages: region.pages(),
            permissions: if region.writable() {
                SegmentPermissions::ReadWrite
            } else {
                SegmentPermissions::ReadOnly
            },
            kind: ProcessMemoryKind::Thread(region.kind()),
        });
        count += 1;
    }
    Ok((regions, shared_pages))
}

fn add(left: u64, right: u64) -> Result<u64, ProcessMemoryError> {
    left.checked_add(right)
        .ok_or(ProcessMemoryError::ArithmeticOverflow)
}
fn page_bytes(pages: u64) -> Result<u64, ProcessMemoryError> {
    pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ProcessMemoryError::ArithmeticOverflow)
}
fn pages_for(bytes: u64) -> Result<u64, ProcessMemoryError> {
    Ok(add(bytes, PAGE_SIZE - 1)? / PAGE_SIZE)
}

#[cfg(test)]
mod tests;

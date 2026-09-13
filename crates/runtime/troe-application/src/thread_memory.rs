//! Checked, allocation-free placement and memory charges for one managed thread.
//!
//! This portable plan does not reserve addresses, frames or IPC slots, publish
//! mappings, or enable native threads. Composition must serialize reservation
//! against other mappings and admissions. Context/wait/runtime metadata, shared
//! process memory, service reserves and teardown ownership are separate inputs
//! to complete admission; these memory charges cannot replace them.

use core::fmt;

use crate::{KEX_V1_USER_END, PAGE_SIZE, static_tls::StaticTlsLayout};

/// Rejected placement or insufficient remaining memory resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadMemoryError {
    /// A managed stack needs at least one committed page.
    EmptyStack,
    /// Checked address, page or byte arithmetic overflowed.
    ArithmeticOverflow,
    /// The reservation is misaligned, includes page zero or leaves user space.
    InvalidPlacement,
    /// Mapped stack, TLS, IPC and startup pages exceed the process allowance.
    MappedPageBudget,
    /// Logical resident pages, including supplemental tables, exceed allowance.
    ResidentPageBudget,
    /// The entire window, including guards and padding, exceeds its allowance.
    ReservedPageBudget,
    /// Stack, TLS, startup and supplemental tables exceed the frame allowance.
    FrameBudget,
    /// The caller has not made enough task IPC pairs available.
    IpcBudget,
}

impl fmt::Display for ThreadMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyStack => "thread stack must contain at least one page",
            Self::ArithmeticOverflow => "thread memory arithmetic overflow",
            Self::InvalidPlacement => "thread reservation is outside the aligned user range",
            Self::MappedPageBudget => "thread mappings exceed their page budget",
            Self::ResidentPageBudget => "thread memory exceeds its logical resident-page budget",
            Self::ReservedPageBudget => "thread window exceeds its reserved-page budget",
            Self::FrameBudget => "thread memory exceeds its ordinary-frame budget",
            Self::IpcBudget => "thread memory exceeds its task IPC-pair budget",
        })
    }
}

/// Simultaneous remaining allowances supplied by trusted composition.
///
/// Remove existing charges and essential-service/teardown reserves before
/// constructing this snapshot. IPC storage already belongs to the boot arena:
/// it consumes mapped-page and pair allowances, not ordinary free frames again.
/// Checking a snapshot does not reserve it against another caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadMemoryBudget {
    /// Remaining logically charged stack, TLS, IPC and startup mapping pages.
    pub mapped_pages: u64,
    /// Remaining logical resident allowance, including IPC and supplemental tables.
    pub resident_pages: u64,
    /// Remaining virtual pages, including unmapped guards/alignment gaps.
    pub reserved_pages: u64,
    /// Remaining ordinary frames after system minimum-free and other reserves.
    pub ordinary_frames: u64,
    /// Remaining task pairs after service reservations; excludes kernel pairs.
    pub ipc_pairs: u64,
}

impl ThreadMemoryBudget {
    /// Check every allowance, without changing accounting or allocating storage.
    ///
    /// # Errors
    /// Returns the first exhausted resource class. All limits must hold together.
    pub fn check(self, charges: ThreadMemoryCharges) -> Result<(), ThreadMemoryError> {
        if charges.mapped_pages > self.mapped_pages {
            return Err(ThreadMemoryError::MappedPageBudget);
        }
        if charges.resident_pages() > self.resident_pages {
            return Err(ThreadMemoryError::ResidentPageBudget);
        }
        if charges.reserved_pages > self.reserved_pages {
            return Err(ThreadMemoryError::ReservedPageBudget);
        }
        if charges.ordinary_frames() > self.ordinary_frames {
            return Err(ThreadMemoryError::FrameBudget);
        }
        if charges.ipc_pairs > self.ipc_pairs {
            return Err(ThreadMemoryError::IpcBudget);
        }
        Ok(())
    }
}

/// Immutable memory charges for one plan or a checked sum of several plans.
///
/// Supplemental tables are an upper bound for adding mappings to a shared root.
/// Unused reserved frames remain charged until their owner actually returns them.
/// Neither table sharing nor completion alone justifies an accounting refund.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ThreadMemoryCharges {
    mapped_pages: u64,
    reserved_pages: u64,
    table_pages: u64,
    ipc_pairs: u64,
}

impl ThreadMemoryCharges {
    /// Stack, TLS, both IPC pages and the read-only startup page, excluding tables.
    #[must_use]
    pub const fn mapped_pages(self) -> u64 {
        self.mapped_pages
    }

    /// Complete virtual window; includes unmapped guard and alignment pages.
    #[must_use]
    pub const fn reserved_pages(self) -> u64 {
        self.reserved_pages
    }

    /// Maximum additional table pages, excluding the already-owned process root.
    #[must_use]
    pub const fn table_pages(self) -> u64 {
        self.table_pages
    }

    /// Task IPC-pair reservations, each backed by two existing boot-arena pages.
    #[must_use]
    pub const fn ipc_pairs(self) -> u64 {
        self.ipc_pairs
    }

    /// New ordinary frames: stack, TLS, startup and tables, excluding boot IPC.
    #[must_use]
    pub const fn ordinary_frames(self) -> u64 {
        self.mapped_pages - self.ipc_pairs * 2 + self.table_pages
    }

    /// Logical resident charge including IPC and all supplemental table pages.
    #[must_use]
    pub const fn resident_pages(self) -> u64 {
        self.mapped_pages + self.table_pages
    }

    /// Checked cumulative charges; prepared and unreleased plans count too.
    ///
    /// # Errors
    /// Rejects overflow in any field or derived resident/byte count. This sums
    /// resources only: it cannot prove distinct virtual or physical ownership.
    pub fn checked_add(self, other: Self) -> Result<Self, ThreadMemoryError> {
        let sum = Self {
            mapped_pages: add(self.mapped_pages, other.mapped_pages)?,
            reserved_pages: add(self.reserved_pages, other.reserved_pages)?,
            table_pages: add(self.table_pages, other.table_pages)?,
            ipc_pairs: add(self.ipc_pairs, other.ipc_pairs)?,
        };
        // Private fields guarantee IPC pages are included in mapped_pages.
        // Bound derived expressions as well as the individually stored fields.
        page_bytes(add(sum.mapped_pages, sum.table_pages)?)?;
        page_bytes(sum.reserved_pages)?;
        Ok(sum)
    }
}

/// Required purpose and write permission of a thread-owned mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadMemoryKind {
    /// Committed user RW/NX stack.
    Stack,
    /// Complete user RW/NX TLS allocation.
    Tls,
    /// User RW/NX transmit and receive pages.
    Ipc,
    /// Immutable user read-only/NX startup descriptor page.
    Startup,
}

/// One nonempty page-aligned user region. Every region is nonexecutable.
///
/// A region carries no physical owner or authority to change a process mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadMemoryRegion {
    start: u64,
    pages: u64,
    kind: ThreadMemoryKind,
}

impl ThreadMemoryRegion {
    /// Purpose and required mapping permission.
    #[must_use]
    pub const fn kind(self) -> ThreadMemoryKind {
        self.kind
    }

    /// Whether composition must permit user writes; startup is read-only.
    #[must_use]
    pub const fn writable(self) -> bool {
        !matches!(self.kind, ThreadMemoryKind::Startup)
    }

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

    /// Nonzero mapped base-page count.
    #[must_use]
    pub const fn pages(self) -> u64 {
        self.pages
    }
}

/// Canonical window for a fixed, fully committed stack and static TLS template.
///
/// Ascending layout: lower guard, stack, upper stack guard, unmapped TLS alignment
/// gap, TLS, IPC TX/RX pair, read-only startup, final guard. Each guard and startup
/// mapping is one base page. The entire
/// window must remain exclusively reserved, including every unmapped byte.
/// Guards do not prevent a large stack-pointer jump; compiler stack probing is
/// a separate requirement. All regions share process authority and visibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadMemoryPlan {
    reservation_base: u64,
    reservation_end: u64,
    regions: [ThreadMemoryRegion; 4],
    thread_pointer: u64,
    charges: ThreadMemoryCharges,
}

impl ThreadMemoryPlan {
    /// Plan a kernel-selected window, checking geometry and all memory budgets.
    ///
    /// The stack top is page aligned (therefore 16-byte aligned); preparing an
    /// architecture entry frame/red zone belongs to the entry trampoline. There
    /// is no stack growth, caller-owned stack, physical mapping or ASLR source in
    /// this component. The caller must check collision with every live reservation
    /// and retain ownership before publishing any mapping or native thread.
    ///
    /// # Errors
    /// Rejects an empty stack, overflow, invalid placement or an exhausted budget.
    pub fn new(
        reservation_base: u64,
        stack_pages: u64,
        tls: StaticTlsLayout,
        budget: ThreadMemoryBudget,
    ) -> Result<Self, ThreadMemoryError> {
        if stack_pages == 0 {
            return Err(ThreadMemoryError::EmptyStack);
        }
        if reservation_base < PAGE_SIZE || !reservation_base.is_multiple_of(PAGE_SIZE) {
            return Err(ThreadMemoryError::InvalidPlacement);
        }
        let stack_start = add(reservation_base, PAGE_SIZE)?;
        let stack_end = add(stack_start, page_bytes(stack_pages)?)?;
        let after_guard = add(stack_end, PAGE_SIZE)?;
        let alignment = tls.mapping_alignment();
        let tls_start = add(after_guard, alignment - 1)? & !(alignment - 1);
        let ipc_start = add(tls_start, tls.mapped_bytes())?;
        let ipc_end = add(ipc_start, 2 * PAGE_SIZE)?;
        let startup_end = add(ipc_end, PAGE_SIZE)?;
        let reservation_end = add(startup_end, PAGE_SIZE)?;
        if reservation_end > KEX_V1_USER_END {
            return Err(ThreadMemoryError::InvalidPlacement);
        }
        let regions = [
            ThreadMemoryRegion {
                start: stack_start,
                pages: stack_pages,
                kind: ThreadMemoryKind::Stack,
            },
            ThreadMemoryRegion {
                start: tls_start,
                pages: tls.pages(),
                kind: ThreadMemoryKind::Tls,
            },
            ThreadMemoryRegion {
                start: ipc_start,
                pages: 2,
                kind: ThreadMemoryKind::Ipc,
            },
            ThreadMemoryRegion {
                start: ipc_end,
                pages: 1,
                kind: ThreadMemoryKind::Startup,
            },
        ];
        let charges = ThreadMemoryCharges {
            mapped_pages: add(add(stack_pages, tls.pages())?, 3)?,
            reserved_pages: (reservation_end - reservation_base) / PAGE_SIZE,
            table_pages: additional_tables(regions.map(|region| (region.start(), region.end()))),
            ipc_pairs: 1,
        };
        // The user-range bound also bounds every derived charge and address.
        budget.check(charges)?;
        Ok(Self {
            reservation_base,
            reservation_end,
            regions,
            thread_pointer: tls_start + tls.thread_pointer_offset(),
            charges,
        })
    }

    /// First byte of the complete reservation, including its lower guard.
    #[must_use]
    pub const fn reservation_base(self) -> u64 {
        self.reservation_base
    }

    /// Exclusive end, including the final guard.
    #[must_use]
    pub const fn reservation_end(self) -> u64 {
        self.reservation_end
    }

    /// Ordered mappings: RW/NX stack, TLS, IPC pair, then read-only/NX startup.
    /// Every byte in the reservation outside these regions stays unmapped.
    #[must_use]
    pub const fn regions(self) -> [ThreadMemoryRegion; 4] {
        self.regions
    }

    /// Checked virtual FS base or `TPIDR_EL0` value, never kernel identity.
    #[must_use]
    pub const fn thread_pointer(self) -> u64 {
        self.thread_pointer
    }

    /// All memory charges to reserve before native allocation/publication.
    #[must_use]
    pub const fn charges(self) -> ThreadMemoryCharges {
        self.charges
    }
}

fn add(left: u64, right: u64) -> Result<u64, ThreadMemoryError> {
    left.checked_add(right)
        .ok_or(ThreadMemoryError::ArithmeticOverflow)
}

fn page_bytes(pages: u64) -> Result<u64, ThreadMemoryError> {
    pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ThreadMemoryError::ArithmeticOverflow)
}

// Count prefixes of bounded, validated user mappings, excluding the root.
// Empty slots consume no tables. Sorting a fixed-size array handles placement
// before or after the image without allocation or walking individual pages.
pub(crate) fn additional_tables<const N: usize>(mut regions: [(u64, u64); N]) -> u64 {
    regions.sort_unstable();
    let mut total = 0;
    for shift in [21, 30, 39] {
        let mut previous = None;
        for (start, end) in regions {
            if start == end {
                continue;
            }
            let first = start >> shift;
            let last = (end - 1) >> shift;
            let uncounted = previous.map_or(first, |end: u64| first.max(end + 1));
            if uncounted <= last {
                total += last - uncounted + 1;
            }
            previous = Some(previous.map_or(last, |end| last.max(end)));
        }
    }
    total
}

#[cfg(test)]
mod tests;

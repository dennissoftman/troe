//! Owned, immutable process TLS with fallible preparation and retained accounting.
//!
//! Staging is moved in, validated while exclusively owned and retained until the
//! caller finishes consuming image bytes. The independent initializer exposes
//! only synchronous copies into exclusively borrowed destinations. No retained
//! initializer pointer, mutable access, clone or resumable reader escapes.
//! This is logical heap-buffer ownership, not native frame mapping/admission.

use crate::{
    PAGE_SIZE, Target,
    process_memory::{
        ProcessMemoryBudget, ProcessMemoryError, ProcessMemoryPlacement, ProcessMemoryPlan,
    },
    static_tls::StaticTlsError,
    tls_artifact::{self, Artifact},
};
use alloc::vec::Vec;
use core::{cell::Cell, fmt};

/// Rejected ownership transfer, allocation, geometry or initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsOwnerError {
    /// The shared backing account cannot retain another reservation.
    BackingBudget,
    /// Buffer/page arithmetic cannot be represented.
    ArithmeticOverflow,
    /// Fallible initializer allocation failed.
    AllocationFailed,
    /// The owned staging bytes are not a valid static-TLS artifact.
    Artifact(tls_artifact::Error),
    /// Canonical or actual-capacity process memory charges are rejected.
    Memory(ProcessMemoryError),
    /// Thread creation was permanently revoked for this initializer.
    Stopped,
    /// Destination geometry or size does not match this process's compiler TLS.
    Initialize(StaticTlsError),
}
impl fmt::Display for TlsOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackingBudget => formatter.write_str("TLS backing account exhausted"),
            Self::ArithmeticOverflow => formatter.write_str("TLS backing arithmetic overflow"),
            Self::AllocationFailed => formatter.write_str("TLS initializer allocation failed"),
            Self::Artifact(error) => error.fmt(formatter),
            Self::Memory(error) => error.fmt(formatter),
            Self::Stopped => formatter.write_str("TLS creation has stopped"),
            Self::Initialize(error) => error.fmt(formatter),
        }
    }
}

/// Live page-rounded allocation charges, including unused vector capacity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TlsBackingUsage {
    /// Full-executable staging pages still owned by prepared images.
    staging_pages: u64,
    /// Independent initializer pages, including stopped but unreleased owners.
    initializer_pages: u64,
}
impl TlsBackingUsage {
    /// Full-executable staging pages still owned by prepared images.
    #[must_use]
    pub const fn staging_pages(self) -> u64 {
        self.staging_pages
    }
    /// Initializer pages, including stopped but unreleased owners.
    #[must_use]
    pub const fn initializer_pages(self) -> u64 {
        self.initializer_pages
    }
    /// Combined backing charge; both classes compete for the same allowance.
    #[must_use]
    pub const fn pages(self) -> u64 {
        self.staging_pages + self.initializer_pages
    }
}

/// Shared, bounded logical backing account for serialized native composition.
///
/// Reservation uses interior mutability without lending a whole allocator or
/// runtime across a copy. This type is deliberately not `Sync`: SMP requires a
/// separately reviewed synchronization boundary. Owners borrow the account, so
/// it cannot be dropped or replaced while they remain live.
///
/// This does not own physical frames. Supply an allowance after system reserves.
/// Allocator bookkeeping, size classes and transient allocations remain bounded
/// by the allocator's own backing. Inline owner/account metadata is additional.
///
/// ```compile_fail
/// use troe_application::tls_owner::TlsBackingAccount;
/// fn require_sync<T: Sync>() {}
/// require_sync::<TlsBackingAccount>();
/// ```
pub struct TlsBackingAccount {
    limit: u64,
    used: Cell<TlsBackingUsage>,
}
impl TlsBackingAccount {
    /// Construct an empty account. Zero permits only zero-capacity buffers.
    #[must_use]
    pub const fn new(pages: u64) -> Self {
        Self {
            limit: pages,
            used: Cell::new(TlsBackingUsage {
                staging_pages: 0,
                initializer_pages: 0,
            }),
        }
    }
    /// Current retained allocations, never a promise of free physical frames.
    #[must_use]
    pub fn usage(&self) -> TlsBackingUsage {
        self.used.get()
    }

    fn reserve(&self, kind: BackingKind, pages: u64) -> Result<Reservation<'_>, TlsOwnerError> {
        self.increase(kind, pages)?;
        Ok(Reservation {
            account: self,
            kind,
            pages,
        })
    }
    fn increase(&self, kind: BackingKind, pages: u64) -> Result<(), TlsOwnerError> {
        let mut used = self.used.get();
        let total = used
            .pages()
            .checked_add(pages)
            .ok_or(TlsOwnerError::ArithmeticOverflow)?;
        if total > self.limit {
            return Err(TlsOwnerError::BackingBudget);
        }
        match kind {
            BackingKind::Staging => used.staging_pages += pages,
            BackingKind::Initializer => used.initializer_pages += pages,
        }
        self.used.set(used);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum BackingKind {
    Staging,
    Initializer,
}

struct Reservation<'account> {
    account: &'account TlsBackingAccount,
    kind: BackingKind,
    pages: u64,
}
impl Reservation<'_> {
    fn grow(&mut self, pages: u64) -> Result<(), TlsOwnerError> {
        let additional = pages
            .checked_sub(self.pages)
            .ok_or(TlsOwnerError::ArithmeticOverflow)?;
        self.account.increase(self.kind, additional)?;
        self.pages = pages;
        Ok(())
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let mut used = self.account.used.get();
        // Reservations are private and non-cloneable; each removes its charge
        // exactly once. All increases check the combined total first.
        match self.kind {
            BackingKind::Staging => used.staging_pages -= self.pages,
            BackingKind::Initializer => used.initializer_pages -= self.pages,
        }
        self.account.used.set(used);
    }
}

struct Backing<'account> {
    // Field drop order matters: release the allocation before its charge.
    bytes: Vec<u8>,
    reservation: Reservation<'account>,
}
impl<'account> Backing<'account> {
    fn staging(
        bytes: Vec<u8>,
        account: &'account TlsBackingAccount,
    ) -> Result<Self, TlsOwnerError> {
        let pages = capacity_pages(bytes.capacity())?;
        let reservation = account.reserve(BackingKind::Staging, pages)?;
        Ok(Self { bytes, reservation })
    }
}

/// Exclusively owned staged executable paired with its independent initializer.
///
/// Image materialization can borrow `artifact()` but cannot keep that borrow
/// across `release_staging()`. Neither operation authenticates a package or
/// publishes mappings. On any error/drop every accepted buffer is released
/// before its corresponding logical reservation is refunded.
///
/// Staging cannot be released while a reader still uses its bytes:
/// ```compile_fail
/// use troe_application::tls_owner::StagedTlsImage;
/// fn invalid(image: StagedTlsImage<'_>) {
///     if let Ok(view) = image.artifact() {
///         drop(image.release_staging());
///         let _ = view.template();
///     }
/// }
/// ```
pub struct StagedTlsImage<'account> {
    staging: Backing<'account>,
    process: ProcessTls<'account>,
    target: Target,
}
impl<'account> StagedTlsImage<'account> {
    /// Take staged bytes, validate their coherent contents and retain a TLS copy.
    ///
    /// The caller already owns the staging allocation and its upstream charge;
    /// successful transfer moves its capacity into `account`. Reserve initializer
    /// pages before fallible allocation. An allocator may report more capacity:
    /// recheck that capacity against both accounts before zeroing/copying bytes.
    /// Callers must keep the allocator's separate physical bound throughout.
    ///
    /// # Errors
    /// Invalid artifacts, budget exhaustion or allocation failure drop provisional
    /// buffers and refund accepted reservations. No process/TLS owner is published.
    pub fn prepare(
        staging: Vec<u8>,
        target: Target,
        placement: ProcessMemoryPlacement,
        budget: ProcessMemoryBudget,
        account: &'account TlsBackingAccount,
    ) -> Result<Self, TlsOwnerError> {
        Self::prepare_with(staging, target, placement, budget, account, allocate)
    }

    fn prepare_with(
        staging: Vec<u8>,
        target: Target,
        placement: ProcessMemoryPlacement,
        budget: ProcessMemoryBudget,
        account: &'account TlsBackingAccount,
        allocate: impl FnOnce(usize) -> Result<Vec<u8>, TlsOwnerError>,
    ) -> Result<Self, TlsOwnerError> {
        let staging = Backing::staging(staging, account)?;
        let artifact = Artifact::parse(&staging.bytes, target).map_err(TlsOwnerError::Artifact)?;
        let mut plan =
            ProcessMemoryPlan::new(&artifact, placement, budget).map_err(TlsOwnerError::Memory)?;
        plan.charge_backing(
            plan.charges().template_pages(),
            staging.reservation.pages,
            budget,
        )
        .map_err(TlsOwnerError::Memory)?;
        let pages = plan.charges().template_pages();
        // Declare the reservation before storage so allocation failure drops
        // storage first. After construction Backing enforces the same order.
        let mut reservation = account.reserve(BackingKind::Initializer, pages)?;
        let requested = usize::try_from(
            pages
                .checked_mul(PAGE_SIZE)
                .ok_or(TlsOwnerError::ArithmeticOverflow)?,
        )
        .map_err(|_| TlsOwnerError::ArithmeticOverflow)?;
        let mut bytes = allocate(requested)?;
        if bytes.capacity() < requested {
            return Err(TlsOwnerError::AllocationFailed);
        }
        reservation.grow(capacity_pages(bytes.capacity())?)?;
        plan.charge_backing(reservation.pages, staging.reservation.pages, budget)
            .map_err(TlsOwnerError::Memory)?;
        // No further allocation: every initialized or spare-capacity byte is
        // cleared before copying. Only the exact immutable suffix is the source.
        bytes.clear();
        bytes.resize(bytes.capacity(), 0);
        bytes[..artifact.template().len()].copy_from_slice(artifact.template());
        let process = ProcessTls {
            initializer: Backing { bytes, reservation },
            plan,
            stopped: false,
        };
        Ok(Self {
            staging,
            process,
            target,
        })
    }

    /// Borrow a freshly validated view of the immutable staged bytes.
    ///
    /// Revalidation avoids a self-referential owner or unsafe lifetime extension.
    /// # Errors
    /// Returns the artifact grammar error if its invariant cannot be established.
    pub fn artifact(&self) -> Result<Artifact<'_>, tls_artifact::Error> {
        Artifact::parse(&self.staging.bytes, self.target)
    }
    /// Initial-process plan with actual retained-capacity charges.
    #[must_use]
    pub const fn plan(&self) -> &ProcessMemoryPlan {
        &self.process.plan
    }

    /// Release staged executable backing after all image consumers have finished.
    ///
    /// Consuming this owner requires all artifact borrows to have ended. This
    /// transfers the immutable initializer, with its existing reservation, to the
    /// returned owner. It proves no image mapping or native-context publication.
    #[must_use]
    pub fn release_staging(self) -> ProcessTls<'account> {
        let Self {
            staging, process, ..
        } = self;
        drop(staging);
        process
    }
}

/// Immutable initializer retained by one process, independent of running image data.
///
/// Keep this owner in the process until native creation is revoked and contexts
/// are quiescent. Rust borrowing proves synchronous copy-reader quiescence only;
/// it cannot prove that machine contexts or page-table users have stopped. Safe
/// code cannot obtain an initializer pointer, clone its owner or mutate its bytes.
/// Dropping the owner releases backing and then its charge; dropping it also ends
/// every way to start a new copy through this value. Physical reuse/erasure remains
/// the native allocator's responsibility; heap drop is not certified zeroization.
pub struct ProcessTls<'account> {
    initializer: Backing<'account>,
    plan: ProcessMemoryPlan,
    stopped: bool,
}
impl ProcessTls<'_> {
    /// Plan retaining both steady and load-time peak charges for this image.
    /// Staging is no longer live; use the shared account for current backing usage.
    #[must_use]
    pub const fn plan(&self) -> &ProcessMemoryPlan {
        &self.plan
    }
    /// Immutable initialized byte count; excludes padding and zero-filled TLS.
    #[must_use]
    pub const fn file_bytes(&self) -> u64 {
        self.plan.tls_layout().file_bytes()
    }
    /// Current initializer backing charge, including unused capacity.
    #[must_use]
    pub const fn backing_pages(&self) -> u64 {
        self.initializer.reservation.pages
    }
    /// Permanently reject new initialization; retains backing and its charge.
    /// Exclusive access ensures every synchronous copy has returned first.
    pub fn stop_creation(&mut self) {
        self.stopped = true;
    }
    /// Whether initialization through this owner has been permanently revoked.
    #[must_use]
    pub const fn creation_stopped(&self) -> bool {
        self.stopped
    }

    /// Copy into an exclusively owned, unpublished TLS mapping for this process.
    ///
    /// This is synchronous and calls no userspace/runtime callbacks. The owner
    /// stays borrowed until all template reads finish. Its immutable source never
    /// comes from a running image; every destination byte is initialized by the
    /// checked compiler layout. Physical ownership and native publication are
    /// still the caller's obligations.
    ///
    /// # Errors
    /// Stopped creation or bad destination geometry leaves all bytes unchanged.
    pub fn initialize(
        &self,
        virtual_base: u64,
        destination: &mut [u8],
    ) -> Result<u64, TlsOwnerError> {
        if self.stopped {
            return Err(TlsOwnerError::Stopped);
        }
        let length =
            usize::try_from(self.file_bytes()).map_err(|_| TlsOwnerError::ArithmeticOverflow)?;
        self.plan
            .tls_layout()
            .initialize(virtual_base, &self.initializer.bytes[..length], destination)
            .map_err(TlsOwnerError::Initialize)
    }
}

fn capacity_pages(capacity: usize) -> Result<u64, TlsOwnerError> {
    let bytes = u64::try_from(capacity).map_err(|_| TlsOwnerError::ArithmeticOverflow)?;
    Ok(bytes
        .checked_add(PAGE_SIZE - 1)
        .ok_or(TlsOwnerError::ArithmeticOverflow)?
        / PAGE_SIZE)
}
fn allocate(bytes: usize) -> Result<Vec<u8>, TlsOwnerError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(bytes)
        .map_err(|_| TlsOwnerError::AllocationFailed)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests;

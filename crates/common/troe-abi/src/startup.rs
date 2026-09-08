//! Immutable startup record handed to a launching application.
//!
//! The kernel maps this record read-only directly above the image and passes
//! its address and mapped byte count to `_start`. Every value an application
//! needs is read from the record itself, so nothing here fixes a virtual
//! address, and the loader, the SDK, the capability manifest, and the service
//! supervisor all bound initial handles by the versioned capacity derived below.

/// Base page size of the startup region and of every KEX v1 mapping.
pub const PAGE_BYTES: usize = 4096;
/// Pages the kernel maps for the startup record.
///
/// The record reports the heap base, and the SDK recovers the image span from
/// the mapped byte count supplied at entry. The kernel asserts its backing
/// allocation agrees with this region; changing the count also requires
/// updating that allocation and its machine mapping.
pub const REGION_PAGES: usize = 1;
/// Mapped bytes of the startup region.
pub const REGION_BYTES: usize = REGION_PAGES * PAGE_BYTES;
/// ABI 1.0–1.2 header bytes preceding the handle descriptors.
pub const HEADER_BYTES: usize = 64;
/// First ABI minor with private TX/RX pages and the extended startup prefix.
pub const IPC_ABI_MINOR: u16 = 3;
/// ABI 1.3 prefix, including the two private virtual addresses.
pub const IPC_HEADER_BYTES: usize = 80;
/// Private payload pages belonging to an ABI 1.3 task.
pub const IPC_PAGES: usize = 2;
/// Private payload bytes, separate from the immutable startup mapping.
pub const IPC_BYTES: usize = IPC_PAGES * PAGE_BYTES;

/// Fixed prefix for an already validated ABI minor.
#[must_use]
pub const fn header_bytes(minor: u16) -> usize {
    if minor >= IPC_ABI_MINOR {
        IPC_HEADER_BYTES
    } else {
        HEADER_BYTES
    }
}

/// Private IPC page charge for an already validated ABI minor.
#[must_use]
pub const fn ipc_pages(minor: u16) -> usize {
    if minor >= IPC_ABI_MINOR { IPC_PAGES } else { 0 }
}

/// Descriptor capacity for the selected version's startup prefix.
#[must_use]
pub const fn max_initial_handles(minor: u16) -> usize {
    (REGION_BYTES - header_bytes(minor)) / HANDLE_BYTES
}
/// Bytes per initial handle descriptor.
pub const HANDLE_BYTES: usize = 24;
/// Command and standard-stream handles every application receives.
pub const MANDATORY_HANDLES: usize = 4;
/// ABI 1.0–1.2 descriptor capacity; use `max_initial_handles` for a launch.
pub const MAX_INITIAL_HANDLES: usize = (REGION_BYTES - HEADER_BYTES) / HANDLE_BYTES;

// SCFG stores a service's initial-handle budget in one byte and the startup
// header stores the count in two, so the derived capacity must fit both.
const _: () = assert!(MAX_INITIAL_HANDLES <= u8::MAX as usize);
const _: () = assert!(MANDATORY_HANDLES <= MAX_INITIAL_HANDLES);

const _: () = assert!(
    crate::requirements::MAX_REQUIREMENTS + MANDATORY_HANDLES <= max_initial_handles(IPC_ABI_MINOR)
);

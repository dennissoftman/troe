//! Immutable startup record handed to a launching application.
//!
//! The kernel maps this record read-only directly above the image and passes
//! its address and mapped byte count to `_start`. Every value an application
//! needs is read from the record itself, so nothing here fixes a virtual
//! address, and the loader, the SDK, the capability manifest, and the service
//! supervisor all bound initial handles by the one capacity derived below.

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
/// Fixed header bytes preceding the handle descriptors.
pub const HEADER_BYTES: usize = 64;
/// Bytes per initial handle descriptor.
pub const HANDLE_BYTES: usize = 24;
/// Command and standard-stream handles every application receives.
pub const MANDATORY_HANDLES: usize = 4;
/// Most initial handles one launch can hand over: the descriptor capacity of
/// the mapped region.
pub const MAX_INITIAL_HANDLES: usize = (REGION_BYTES - HEADER_BYTES) / HANDLE_BYTES;

// SCFG stores a service's initial-handle budget in one byte and the startup
// header stores the count in two, so the derived capacity must fit both.
const _: () = assert!(MAX_INITIAL_HANDLES <= u8::MAX as usize);
const _: () = assert!(MANDATORY_HANDLES <= MAX_INITIAL_HANDLES);

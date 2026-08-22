//! Audited native mechanisms for the pinned x86-64 and `AArch64` QEMU profiles.
#![no_std]
#![deny(unsafe_code)]

#[cfg(any(test, target_os = "uefi"))]
#[allow(unsafe_code)]
mod mechanism;

#[cfg(target_os = "uefi")]
pub use mechanism::{
    HeapStats, exit_boot_services_after_protocols, heap_stats, initialize_console, initialize_heap,
    mark_firmware_exited, park, probe_allocation_failure, read_byte, write,
};

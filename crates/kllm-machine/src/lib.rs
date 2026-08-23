//! Audited native mechanisms for the pinned x86-64 and `AArch64` QEMU profiles.
#![no_std]
#![deny(unsafe_code)]

#[cfg(any(test, target_os = "uefi"))]
#[allow(unsafe_code)]
mod mechanism;
#[cfg(any(test, target_os = "uefi"))]
#[allow(unsafe_code)]
mod mmu;

#[cfg(target_os = "uefi")]
pub use mechanism::{
    HeapStats, StackSwitchError, TaskStackError, current_stack_pointer, enter_owned_stack,
    exit_boot_services_after_protocols, heap_stats, initialize_console, initialize_heap,
    mark_firmware_exited, park, probe_allocation_failure, read_byte, run_task_step,
    take_interrupt_ownership, write,
};

#[cfg(any(test, target_os = "uefi"))]
pub use mmu::{ImageLayout, ImageRegion, MmuError, MmuStats};
#[cfg(target_os = "uefi")]
pub use mmu::{install_exception_vectors, install_mmu, loaded_image_layout};
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub use mmu::{trigger_execute_fault, trigger_native_exception, trigger_write_fault};

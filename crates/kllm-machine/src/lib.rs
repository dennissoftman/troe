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
    FramebufferError, HeapStats, InputInterruptError, OwnedFramebuffer, PhysicalMemoryError,
    StackSwitchError, TaskStackError, copy_to_physical, current_stack_pointer, enter_owned_stack,
    exit_boot_services_after_protocols, heap_stats, initialize_console, initialize_heap,
    initialize_input_interrupts, input_device_ranges, input_interrupt_stats, mark_firmware_exited,
    park, probe_allocation_failure, read_byte, run_task_step, take_interrupt_ownership,
    try_read_byte, try_read_keyboard_scancode, wait_for_input_event, write, zero_physical_range,
};

#[cfg(any(test, target_os = "uefi"))]
pub use mmu::{ApplicationOutcome, IsolatedFault, IsolatedOutcome, UserAddressSpace};
#[cfg(any(test, target_os = "uefi"))]
pub use mmu::{ImageLayout, ImageRegion, MmuError, MmuStats};
#[cfg(target_os = "uefi")]
pub use mmu::{
    build_user_address_space, install_exception_vectors, install_mmu, loaded_image_layout,
    run_application, run_isolated,
};
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub use mmu::{trigger_execute_fault, trigger_native_exception, trigger_write_fault};

//! Audited native mechanisms for TROE machine profiles.
#![no_std]
#![deny(unsafe_code)]

#[cfg(any(test, target_os = "uefi"))]
#[allow(unsafe_code)]
mod mechanism;
#[cfg(any(test, target_os = "uefi"))]
#[allow(unsafe_code)]
mod mmu;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
#[allow(unsafe_code)]
mod virtio_mmio;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod virtio_pci;

#[cfg(target_os = "uefi")]
pub use mechanism::{
    FramebufferError, HeapStats, InputInterruptError, OwnedFramebuffer, PhysicalMemoryError,
    StackSwitchError, TaskStackError, copy_to_physical, current_stack_pointer, enter_owned_stack,
    exit_boot_services_after_protocols, heap_stats, initialize_console, initialize_heap,
    initialize_input_interrupts, input_device_ranges, input_interrupt_stats, mark_firmware_exited,
    park, probe_allocation_failure, read_byte, run_task_step, take_interrupt_ownership,
    try_read_byte, try_read_keyboard_scancode, wait_for_input_event, write, zero_physical_range,
};

#[cfg(target_os = "uefi")]
pub use mmu::{
    ApplicationCall, ApplicationResume, ApplicationSession, build_user_address_space,
    install_exception_vectors, install_mmu, loaded_image_layout, resume_application,
    run_application, run_isolated,
};
#[cfg(any(test, target_os = "uefi"))]
pub use mmu::{ApplicationOutcome, IsolatedFault, IsolatedOutcome, UserAddressSpace};
#[cfg(any(test, target_os = "uefi"))]
pub use mmu::{ImageLayout, ImageRegion, MmuError, MmuStats};
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub use mmu::{trigger_execute_fault, trigger_native_exception, trigger_write_fault};

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
pub use virtio_mmio::{
    NativeVirtioBlock, NativeVirtioNetwork, VirtioMmioError, discover_virtio_mmio_blocks,
    discover_virtio_mmio_network, virtio_mmio_device_ranges,
};
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
pub use virtio_pci::{
    NativeVirtioBlock, NativeVirtioNetwork, VirtioPciError, discover_virtio_pci_blocks,
    discover_virtio_pci_network, virtio_pci_device_ranges,
};

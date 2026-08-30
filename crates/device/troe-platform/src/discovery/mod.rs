//! Bounded firmware discovery for platforms that are not fixed descriptors.
//!
//! Firmware adapters map immutable physical-memory ranges and implement
//! [`acpi::AcpiMemory`]. The parser never performs volatile or unchecked native reads.
//! Call [`acpi::AcpiTables::parse`] to validate and inspect a root table, or
//! [`acpi::X86VirtioAcpi::discover`] to require the ACPI facts needed before
//! generic PCI virtio discovery: PCI ECAM allocations and x86 interrupt
//! topology.
//!
//! Integration deliberately remains transactional. Machine code must retain
//! the returned validated view, reserve every [`acpi::PhysicalRange`] it
//! exposes, validate I/O-APIC input counts from controller registers, and only
//! then publish PCI, DMA, or interrupt capabilities.

/// Strict ACPI root, PCI-ECAM, and x86 interrupt-topology discovery.
pub mod acpi;
/// Strict Flattened Devicetree discovery for AArch64 cloud contracts.
pub mod fdt;

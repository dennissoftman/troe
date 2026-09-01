//! Enhanced Configuration Access Mechanism addressing.
//!
//! Where the window comes from is platform-specific — ACPI MCFG on the
//! discoverable x86-64 contract, the pinned aperture role on the Arm SBSA
//! reference platform — but the addressing arithmetic below is the same.

const ECAM_BUS_BYTES: u64 = 1 << 20;

/// Validated, selected segment-zero ECAM aperture for the bounded PCI scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EcamWindow {
    pub(crate) base_address: u64,
    pub(crate) first_bus: u8,
    pub(crate) last_bus: u8,
}

impl EcamWindow {
    pub(crate) const fn new(base_address: u64, first_bus: u8, last_bus: u8) -> Option<Self> {
        if base_address == 0 || !base_address.is_multiple_of(ECAM_BUS_BYTES) || first_bus > last_bus
        {
            return None;
        }
        Some(Self {
            base_address,
            first_bus,
            last_bus,
        })
    }

    pub(crate) fn physical_range(self) -> Option<(u64, u64)> {
        let bus_count = u64::from(self.last_bus)
            .checked_sub(u64::from(self.first_bus))?
            .checked_add(1)?;
        let start = self
            .base_address
            .checked_add(u64::from(self.first_bus).checked_mul(ECAM_BUS_BYTES)?)?;
        Some((start, bus_count.checked_mul(ECAM_BUS_BYTES)?))
    }

    pub(crate) fn configuration_address(
        self,
        bus: u8,
        device: u8,
        function: u8,
        register_offset: u8,
    ) -> Option<u64> {
        if !(self.first_bus..=self.last_bus).contains(&bus) || device >= 32 || function >= 8 {
            return None;
        }
        self.base_address
            .checked_add(u64::from(bus).checked_mul(ECAM_BUS_BYTES)?)?
            .checked_add(u64::from(device).checked_mul(1 << 15)?)?
            .checked_add(u64::from(function).checked_mul(1 << 12)?)?
            .checked_add(u64::from(register_offset))
    }
}

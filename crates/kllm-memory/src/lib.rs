//! Bounded, architecture-independent physical-memory ownership models.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Size of one base physical page.
pub const BASE_PAGE_SIZE: u64 = 4096;
/// Maximum firmware descriptors accepted by the normalization boundary.
pub const MAX_FIRMWARE_REGIONS: usize = 256;
/// Maximum explicit reservations accepted during early boot.
pub const MAX_RESERVATIONS: usize = 64;
/// Maximum normalized ranges produced after reservation splitting.
pub const MAX_NORMALIZED_REGIONS: usize = 512;

/// Failures produced while validating and normalizing physical memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMapError {
    /// A range begins at an address that is not base-page aligned.
    Unaligned,
    /// A range has no pages.
    Empty,
    /// Address or accounting arithmetic overflowed.
    Overflow,
    /// Two firmware-provided ranges overlap.
    FirmwareOverlap,
    /// A reservation includes bytes absent from the firmware map.
    ReservationUnmapped,
    /// An input or normalized range count exceeds its explicit bound.
    TooManyRegions,
}

impl fmt::Display for MemoryMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unaligned => formatter.write_str("physical range is not page aligned"),
            Self::Empty => formatter.write_str("physical range is empty"),
            Self::Overflow => formatter.write_str("physical range arithmetic overflowed"),
            Self::FirmwareOverlap => formatter.write_str("firmware memory ranges overlap"),
            Self::ReservationUnmapped => {
                formatter.write_str("reservation is not fully covered by the firmware map")
            }
            Self::TooManyRegions => formatter.write_str("memory region bound exceeded"),
        }
    }
}

/// A checked, half-open, base-page-aligned physical address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    start: u64,
    end: u64,
}

impl PhysicalRange {
    /// Construct a range from a base address and page count.
    ///
    /// # Errors
    ///
    /// Rejects an unaligned start, zero pages, or checked arithmetic overflow.
    pub fn from_pages(start: u64, page_count: u64) -> Result<Self, MemoryMapError> {
        if !start.is_multiple_of(BASE_PAGE_SIZE) {
            return Err(MemoryMapError::Unaligned);
        }
        if page_count == 0 {
            return Err(MemoryMapError::Empty);
        }
        let byte_count = page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(MemoryMapError::Overflow)?;
        let end = start
            .checked_add(byte_count)
            .ok_or(MemoryMapError::Overflow)?;
        Ok(Self { start, end })
    }

    /// First byte in the range.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// First byte after the range.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Number of bytes in the range.
    #[must_use]
    pub const fn byte_count(self) -> u64 {
        self.end - self.start
    }

    /// Number of base pages in the range.
    #[must_use]
    pub const fn page_count(self) -> u64 {
        self.byte_count() / BASE_PAGE_SIZE
    }
}

/// Ownership classification needed by the initial physical allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionKind {
    /// RAM that firmware permits the kernel to own after handoff.
    Usable,
    /// Firmware, device, image, metadata, or otherwise unavailable memory.
    Reserved,
}

/// One classified physical address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    range: PhysicalRange,
    kind: RegionKind,
}

impl MemoryRegion {
    /// Construct a classified range.
    #[must_use]
    pub const fn new(range: PhysicalRange, kind: RegionKind) -> Self {
        Self { range, kind }
    }

    /// Physical range covered by this region.
    #[must_use]
    pub const fn range(self) -> PhysicalRange {
        self.range
    }

    /// Ownership classification of this region.
    #[must_use]
    pub const fn kind(self) -> RegionKind {
        self.kind
    }
}

/// Checked byte accounting over a normalized memory map.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryMapStats {
    usable_bytes: u64,
    reserved_bytes: u64,
}

impl MemoryMapStats {
    /// Bytes the physical allocator may eventually own.
    #[must_use]
    pub const fn usable_bytes(self) -> u64 {
        self.usable_bytes
    }

    /// Bytes retained by firmware, devices, or explicit reservations.
    #[must_use]
    pub const fn reserved_bytes(self) -> u64 {
        self.reserved_bytes
    }

    /// Bytes described by the complete normalized map.
    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.usable_bytes + self.reserved_bytes
    }
}

/// Sorted, non-overlapping physical regions with explicit reservations applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedMemoryMap {
    regions: Vec<MemoryRegion>,
    stats: MemoryMapStats,
}

impl NormalizedMemoryMap {
    /// Normalize firmware regions and overlay explicit reservations.
    ///
    /// Firmware ranges may be unordered but must not overlap. Adjacent ranges
    /// with the same ownership are coalesced. Reservations may overlap each
    /// other, but every reserved byte must be described by the firmware map.
    ///
    /// # Errors
    ///
    /// Rejects count-bound violations, overlapping firmware ranges, unmapped
    /// reservations, and checked accounting overflow.
    pub fn build(
        firmware_regions: &[MemoryRegion],
        reservations: &[PhysicalRange],
    ) -> Result<Self, MemoryMapError> {
        if firmware_regions.len() > MAX_FIRMWARE_REGIONS || reservations.len() > MAX_RESERVATIONS {
            return Err(MemoryMapError::TooManyRegions);
        }

        let firmware = normalize_firmware(firmware_regions)?;
        let reservations = normalize_reservations(reservations);
        for reservation in &reservations {
            if !range_is_covered(*reservation, &firmware) {
                return Err(MemoryMapError::ReservationUnmapped);
            }
        }

        let mut regions = Vec::new();
        for region in &firmware {
            overlay_region(*region, &reservations, &mut regions)?;
        }
        let stats = calculate_stats(&regions)?;
        Ok(Self { regions, stats })
    }

    /// Sorted normalized regions.
    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Checked ownership accounting.
    #[must_use]
    pub const fn stats(&self) -> MemoryMapStats {
        self.stats
    }
}

fn normalize_firmware(regions: &[MemoryRegion]) -> Result<Vec<MemoryRegion>, MemoryMapError> {
    let mut sorted = regions.to_vec();
    sorted.sort_unstable_by_key(|region| region.range.start);

    let mut normalized: Vec<MemoryRegion> = Vec::new();
    for region in sorted {
        if let Some(previous) = normalized.last()
            && region.range.start < previous.range.end
        {
            return Err(MemoryMapError::FirmwareOverlap);
        }
        append_region(&mut normalized, region)?;
    }
    Ok(normalized)
}

fn normalize_reservations(reservations: &[PhysicalRange]) -> Vec<PhysicalRange> {
    let mut sorted = reservations.to_vec();
    sorted.sort_unstable_by_key(|range| range.start);

    let mut normalized: Vec<PhysicalRange> = Vec::new();
    for range in sorted {
        if let Some(previous) = normalized.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        normalized.push(range);
    }
    normalized
}

fn range_is_covered(range: PhysicalRange, regions: &[MemoryRegion]) -> bool {
    let mut cursor = range.start;
    for region in regions {
        if region.range.end <= cursor {
            continue;
        }
        if region.range.start > cursor {
            return false;
        }
        cursor = region.range.end.min(range.end);
        if cursor == range.end {
            return true;
        }
    }
    false
}

fn overlay_region(
    region: MemoryRegion,
    reservations: &[PhysicalRange],
    output: &mut Vec<MemoryRegion>,
) -> Result<(), MemoryMapError> {
    let mut cursor = region.range.start;
    for reservation in reservations {
        if reservation.end <= cursor || reservation.start >= region.range.end {
            continue;
        }
        if cursor < reservation.start {
            append_region(
                output,
                MemoryRegion::new(
                    PhysicalRange {
                        start: cursor,
                        end: reservation.start.min(region.range.end),
                    },
                    region.kind,
                ),
            )?;
        }
        let reserved_start = cursor.max(reservation.start);
        let reserved_end = region.range.end.min(reservation.end);
        if reserved_start < reserved_end {
            append_region(
                output,
                MemoryRegion::new(
                    PhysicalRange {
                        start: reserved_start,
                        end: reserved_end,
                    },
                    RegionKind::Reserved,
                ),
            )?;
            cursor = reserved_end;
        }
        if cursor == region.range.end {
            break;
        }
    }
    if cursor < region.range.end {
        append_region(
            output,
            MemoryRegion::new(
                PhysicalRange {
                    start: cursor,
                    end: region.range.end,
                },
                region.kind,
            ),
        )?;
    }
    Ok(())
}

fn append_region(
    output: &mut Vec<MemoryRegion>,
    region: MemoryRegion,
) -> Result<(), MemoryMapError> {
    if let Some(previous) = output.last_mut()
        && previous.kind == region.kind
        && previous.range.end == region.range.start
    {
        previous.range.end = region.range.end;
        return Ok(());
    }
    if output.len() >= MAX_NORMALIZED_REGIONS {
        return Err(MemoryMapError::TooManyRegions);
    }
    output.push(region);
    Ok(())
}

fn calculate_stats(regions: &[MemoryRegion]) -> Result<MemoryMapStats, MemoryMapError> {
    let mut stats = MemoryMapStats::default();
    for region in regions {
        let destination = match region.kind {
            RegionKind::Usable => &mut stats.usable_bytes,
            RegionKind::Reserved => &mut stats.reserved_bytes,
        };
        *destination = destination
            .checked_add(region.range.byte_count())
            .ok_or(MemoryMapError::Overflow)?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::{
        BASE_PAGE_SIZE, MAX_FIRMWARE_REGIONS, MemoryMapError, MemoryRegion, NormalizedMemoryMap,
        PhysicalRange, RegionKind,
    };
    use alloc::vec;

    fn pages(start_page: u64, count: u64) -> PhysicalRange {
        let start = start_page * BASE_PAGE_SIZE;
        PhysicalRange {
            start,
            end: start + count * BASE_PAGE_SIZE,
        }
    }

    fn region(start_page: u64, count: u64, kind: RegionKind) -> MemoryRegion {
        MemoryRegion::new(pages(start_page, count), kind)
    }

    #[test]
    fn range_construction_checks_alignment_empty_and_overflow() {
        assert_eq!(
            PhysicalRange::from_pages(1, 1),
            Err(MemoryMapError::Unaligned)
        );
        assert_eq!(PhysicalRange::from_pages(0, 0), Err(MemoryMapError::Empty));
        assert_eq!(
            PhysicalRange::from_pages(!(BASE_PAGE_SIZE - 1), 2),
            Err(MemoryMapError::Overflow)
        );
    }

    #[test]
    fn unordered_adjacent_firmware_ranges_are_coalesced() -> Result<(), MemoryMapError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(4, 2, RegionKind::Reserved),
                region(2, 2, RegionKind::Usable),
                region(0, 2, RegionKind::Usable),
            ],
            &[],
        )?;

        assert_eq!(
            map.regions(),
            &[
                region(0, 4, RegionKind::Usable),
                region(4, 2, RegionKind::Reserved)
            ]
        );
        assert_eq!(map.stats().usable_bytes(), 4 * BASE_PAGE_SIZE);
        assert_eq!(map.stats().reserved_bytes(), 2 * BASE_PAGE_SIZE);
        assert_eq!(map.stats().total_bytes(), 6 * BASE_PAGE_SIZE);
        Ok(())
    }

    #[test]
    fn overlapping_firmware_ranges_are_rejected() {
        assert_eq!(
            NormalizedMemoryMap::build(
                &[
                    region(0, 3, RegionKind::Usable),
                    region(2, 2, RegionKind::Reserved)
                ],
                &[]
            ),
            Err(MemoryMapError::FirmwareOverlap)
        );
    }

    #[test]
    fn reservation_splits_usable_memory_and_updates_accounting() -> Result<(), MemoryMapError> {
        let map = NormalizedMemoryMap::build(&[region(0, 10, RegionKind::Usable)], &[pages(3, 2)])?;

        assert_eq!(
            map.regions(),
            &[
                region(0, 3, RegionKind::Usable),
                region(3, 2, RegionKind::Reserved),
                region(5, 5, RegionKind::Usable),
            ]
        );
        assert_eq!(map.stats().usable_bytes(), 8 * BASE_PAGE_SIZE);
        assert_eq!(map.stats().reserved_bytes(), 2 * BASE_PAGE_SIZE);
        Ok(())
    }

    #[test]
    fn overlapping_reservations_merge_across_firmware_boundaries() -> Result<(), MemoryMapError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(0, 4, RegionKind::Usable),
                region(4, 2, RegionKind::Reserved),
                region(6, 4, RegionKind::Usable),
            ],
            &[pages(2, 5), pages(5, 3)],
        )?;

        assert_eq!(
            map.regions(),
            &[
                region(0, 2, RegionKind::Usable),
                region(2, 6, RegionKind::Reserved),
                region(8, 2, RegionKind::Usable),
            ]
        );
        Ok(())
    }

    #[test]
    fn reservation_cannot_cross_an_unmapped_gap() {
        assert_eq!(
            NormalizedMemoryMap::build(
                &[
                    region(0, 2, RegionKind::Usable),
                    region(4, 2, RegionKind::Usable)
                ],
                &[pages(1, 4)]
            ),
            Err(MemoryMapError::ReservationUnmapped)
        );
    }

    #[test]
    fn firmware_input_count_is_bounded() {
        let regions = vec![region(0, 1, RegionKind::Reserved); MAX_FIRMWARE_REGIONS + 1];
        assert_eq!(
            NormalizedMemoryMap::build(&regions, &[]),
            Err(MemoryMapError::TooManyRegions)
        );
    }
}

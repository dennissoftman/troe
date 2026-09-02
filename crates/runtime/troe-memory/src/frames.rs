//! Bitmap frame allocator over the usable spans of a normalized map.

use crate::{BASE_PAGE_SIZE, NormalizedMemoryMap, PhysicalRange, RegionKind};
use alloc::vec::Vec;
use core::fmt;

/// Failures produced by the physical-frame bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameAllocationError {
    /// Frame-count or bitmap-size arithmetic overflowed.
    Overflow,
    /// Bitmap metadata could not be allocated.
    MetadataExhausted,
    /// No free usable frame remains.
    Exhausted,
    /// The supplied address is unaligned, reserved, or absent from the map.
    InvalidFrame,
    /// A usable frame that was already free was released.
    DoubleFree,
}

impl fmt::Display for FrameAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => formatter.write_str("frame allocator arithmetic overflowed"),
            Self::MetadataExhausted => formatter.write_str("frame bitmap metadata exhausted"),
            Self::Exhausted => formatter.write_str("physical frames exhausted"),
            Self::InvalidFrame => formatter.write_str("physical frame is not allocator-owned"),
            Self::DoubleFree => formatter.write_str("physical frame was freed twice"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameSpan {
    range: PhysicalRange,
    first_frame: u64,
}

/// Compact ownership bitmaps over the usable spans in a normalized map.
///
/// Only usable pages consume bitmap bits, so high device ranges do not inflate
/// metadata. Live allocations and permanent reservations use distinct bitmaps;
/// a frame is free only when both corresponding bits are zero.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
pub struct FrameAllocator {
    spans: Vec<FrameSpan>,
    allocated_bitmap: Vec<u64>,
    reserved_bitmap: Vec<u64>,
    total_frames: u64,
    free_frames: u64,
}

impl FrameAllocator {
    /// Build an empty frame allocator over every usable normalized region.
    ///
    /// # Errors
    ///
    /// Rejects checked arithmetic overflow and fallible metadata allocation
    /// failure. Bitmap storage is derived from the supplied usable memory; no
    /// fixed physical-memory ceiling is imposed here.
    pub fn from_map(map: &NormalizedMemoryMap) -> Result<Self, FrameAllocationError> {
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(map.regions.len())
            .map_err(|_| FrameAllocationError::MetadataExhausted)?;
        let mut total_frames = 0_u64;
        for region in &map.regions {
            if region.kind != RegionKind::Usable {
                continue;
            }
            spans.push(FrameSpan {
                range: region.range,
                first_frame: total_frames,
            });
            total_frames = total_frames
                .checked_add(region.range.page_count())
                .ok_or(FrameAllocationError::Overflow)?;
        }

        let word_count = total_frames
            .checked_add(63)
            .ok_or(FrameAllocationError::Overflow)?
            / 64;
        let word_count = usize::try_from(word_count).map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocated_bitmap = Vec::new();
        allocated_bitmap
            .try_reserve_exact(word_count)
            .map_err(|_| FrameAllocationError::MetadataExhausted)?;
        allocated_bitmap.resize(word_count, 0);
        let mut reserved_bitmap = Vec::new();
        reserved_bitmap
            .try_reserve_exact(word_count)
            .map_err(|_| FrameAllocationError::MetadataExhausted)?;
        reserved_bitmap.resize(word_count, 0);

        Ok(Self {
            spans,
            allocated_bitmap,
            reserved_bitmap,
            total_frames,
            free_frames: total_frames,
        })
    }

    /// Allocate the lowest-addressed currently free physical frame.
    ///
    /// # Errors
    ///
    /// Returns [`FrameAllocationError::Exhausted`] when no frame is free.
    pub fn allocate(&mut self) -> Result<u64, FrameAllocationError> {
        if self.free_frames == 0 {
            return Err(FrameAllocationError::Exhausted);
        }
        for frame_index in 0..self.total_frames {
            if !self.is_unavailable(frame_index)? {
                self.set_allocated(frame_index, true)?;
                self.free_frames -= 1;
                return self
                    .address_for_index(frame_index)
                    .ok_or(FrameAllocationError::Overflow);
            }
        }
        Err(FrameAllocationError::Exhausted)
    }

    /// Allocate one physically contiguous, aligned frame range atomically.
    ///
    /// # Errors
    ///
    /// Rejects zero/non-power-of-two bounds, arithmetic overflow, or a lack of
    /// one free run wholly contained in a usable physical span. No bitmap bit
    /// changes unless the complete request can be satisfied.
    pub fn allocate_contiguous(
        &mut self,
        page_count: u64,
        alignment_pages: u64,
    ) -> Result<PhysicalRange, FrameAllocationError> {
        if page_count == 0 || alignment_pages == 0 || !alignment_pages.is_power_of_two() {
            return Err(FrameAllocationError::InvalidFrame);
        }
        if page_count > self.free_frames {
            return Err(FrameAllocationError::Exhausted);
        }
        for span in &self.spans {
            let span_pages = span.range.page_count();
            if span_pages < page_count {
                continue;
            }
            let last_start = span_pages
                .checked_sub(page_count)
                .ok_or(FrameAllocationError::Overflow)?;
            for local_start in 0..=last_start {
                let address = span
                    .range
                    .start
                    .checked_add(
                        local_start
                            .checked_mul(BASE_PAGE_SIZE)
                            .ok_or(FrameAllocationError::Overflow)?,
                    )
                    .ok_or(FrameAllocationError::Overflow)?;
                let alignment_bytes = alignment_pages
                    .checked_mul(BASE_PAGE_SIZE)
                    .ok_or(FrameAllocationError::Overflow)?;
                if !address.is_multiple_of(alignment_bytes) {
                    continue;
                }
                let first = span
                    .first_frame
                    .checked_add(local_start)
                    .ok_or(FrameAllocationError::Overflow)?;
                let end = first
                    .checked_add(page_count)
                    .ok_or(FrameAllocationError::Overflow)?;
                let mut free = true;
                for frame in first..end {
                    if self.is_unavailable(frame)? {
                        free = false;
                        break;
                    }
                }
                if !free {
                    continue;
                }
                let next_free = self
                    .free_frames
                    .checked_sub(page_count)
                    .ok_or(FrameAllocationError::Overflow)?;
                for frame in first..end {
                    self.set_allocated(frame, true)?;
                }
                self.free_frames = next_free;
                return PhysicalRange::from_pages(address, page_count)
                    .map_err(|_| FrameAllocationError::Overflow);
            }
        }
        Err(FrameAllocationError::Exhausted)
    }

    /// Mark every currently free allocator-owned frame in `range` unavailable.
    ///
    /// Frames outside usable spans are ignored, and reserving the same range
    /// repeatedly is idempotent. The returned count is the number of frames
    /// newly removed from the free pool.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic error if the allocator's internal accounting
    /// cannot represent the reservation.
    pub fn reserve_range(&mut self, range: PhysicalRange) -> Result<u64, FrameAllocationError> {
        let mut reserved = 0_u64;
        for span_index in 0..self.spans.len() {
            let span = self.spans[span_index];
            let overlap_start = span.range.start.max(range.start);
            let overlap_end = span.range.end.min(range.end);
            if overlap_start >= overlap_end {
                continue;
            }

            let first = span
                .first_frame
                .checked_add((overlap_start - span.range.start) / BASE_PAGE_SIZE)
                .ok_or(FrameAllocationError::Overflow)?;
            let page_count = (overlap_end - overlap_start) / BASE_PAGE_SIZE;
            let end = first
                .checked_add(page_count)
                .ok_or(FrameAllocationError::Overflow)?;
            for frame_index in first..end {
                if self.is_unavailable(frame_index)? {
                    continue;
                }
                let next_free = self
                    .free_frames
                    .checked_sub(1)
                    .ok_or(FrameAllocationError::Overflow)?;
                let next_reserved = reserved
                    .checked_add(1)
                    .ok_or(FrameAllocationError::Overflow)?;
                self.mark_reserved(frame_index)?;
                self.free_frames = next_free;
                reserved = next_reserved;
            }
        }
        Ok(reserved)
    }

    /// Return one previously allocated physical frame to the bitmap.
    ///
    /// # Errors
    ///
    /// Rejects unaligned, reserved, unmapped, and already-free addresses.
    pub fn free(&mut self, address: u64) -> Result<(), FrameAllocationError> {
        let frame_index = self
            .index_for_address(address)
            .ok_or(FrameAllocationError::InvalidFrame)?;
        if self.is_reserved(frame_index)? {
            return Err(FrameAllocationError::InvalidFrame);
        }
        if !self.is_allocated(frame_index)? {
            return Err(FrameAllocationError::DoubleFree);
        }
        self.set_allocated(frame_index, false)?;
        self.free_frames = self
            .free_frames
            .checked_add(1)
            .ok_or(FrameAllocationError::Overflow)?;
        Ok(())
    }

    /// Return a complete previously allocated contiguous range atomically.
    ///
    /// Every page is validated before the bitmap is changed, so an invalid or
    /// partially free range cannot cause partial teardown.
    ///
    /// # Errors
    ///
    /// Rejects a range containing an unmanaged, reserved, or already-free page.
    pub fn free_range(&mut self, range: PhysicalRange) -> Result<(), FrameAllocationError> {
        for page in 0..range.page_count() {
            let address = range
                .start
                .checked_add(
                    page.checked_mul(BASE_PAGE_SIZE)
                        .ok_or(FrameAllocationError::Overflow)?,
                )
                .ok_or(FrameAllocationError::Overflow)?;
            let index = self
                .index_for_address(address)
                .ok_or(FrameAllocationError::InvalidFrame)?;
            if self.is_reserved(index)? {
                return Err(FrameAllocationError::InvalidFrame);
            }
            if !self.is_allocated(index)? {
                return Err(FrameAllocationError::DoubleFree);
            }
        }
        let next_free = self
            .free_frames
            .checked_add(range.page_count())
            .ok_or(FrameAllocationError::Overflow)?;
        for page in 0..range.page_count() {
            let address = range.start + page * BASE_PAGE_SIZE;
            let index = self
                .index_for_address(address)
                .ok_or(FrameAllocationError::InvalidFrame)?;
            self.set_allocated(index, false)?;
        }
        self.free_frames = next_free;
        Ok(())
    }

    /// Number of usable frames represented by the bitmap.
    #[must_use]
    pub const fn total_frames(&self) -> u64 {
        self.total_frames
    }

    /// Number of frames currently available for allocation.
    #[must_use]
    pub const fn free_frames(&self) -> u64 {
        self.free_frames
    }

    /// Allocation and reservation bitmap storage bytes, excluding the bounded span table.
    #[must_use]
    pub fn bitmap_bytes(&self) -> usize {
        (self.allocated_bitmap.len() + self.reserved_bitmap.len()) * core::mem::size_of::<u64>()
    }

    fn is_allocated(&self, frame_index: u64) -> Result<bool, FrameAllocationError> {
        let (word, mask) = self.bitmap_location(frame_index)?;
        Ok(self.allocated_bitmap[word] & mask != 0)
    }

    fn is_reserved(&self, frame_index: u64) -> Result<bool, FrameAllocationError> {
        let (word, mask) = self.bitmap_location(frame_index)?;
        Ok(self.reserved_bitmap[word] & mask != 0)
    }

    fn is_unavailable(&self, frame_index: u64) -> Result<bool, FrameAllocationError> {
        Ok(self.is_allocated(frame_index)? || self.is_reserved(frame_index)?)
    }

    fn set_allocated(
        &mut self,
        frame_index: u64,
        allocated: bool,
    ) -> Result<(), FrameAllocationError> {
        let (word, mask) = self.bitmap_location(frame_index)?;
        if allocated {
            self.allocated_bitmap[word] |= mask;
        } else {
            self.allocated_bitmap[word] &= !mask;
        }
        Ok(())
    }

    fn mark_reserved(&mut self, frame_index: u64) -> Result<(), FrameAllocationError> {
        let (word, mask) = self.bitmap_location(frame_index)?;
        self.reserved_bitmap[word] |= mask;
        Ok(())
    }

    fn bitmap_location(&self, frame_index: u64) -> Result<(usize, u64), FrameAllocationError> {
        if frame_index >= self.total_frames {
            return Err(FrameAllocationError::Overflow);
        }
        let word = usize::try_from(frame_index / 64).map_err(|_| FrameAllocationError::Overflow)?;
        Ok((word, 1_u64 << (frame_index % 64)))
    }

    fn address_for_index(&self, frame_index: u64) -> Option<u64> {
        for span in &self.spans {
            let page_count = span.range.page_count();
            if frame_index >= span.first_frame && frame_index - span.first_frame < page_count {
                let offset = (frame_index - span.first_frame).checked_mul(BASE_PAGE_SIZE)?;
                return span.range.start.checked_add(offset);
            }
        }
        None
    }

    fn index_for_address(&self, address: u64) -> Option<u64> {
        if !address.is_multiple_of(BASE_PAGE_SIZE) {
            return None;
        }
        for span in &self.spans {
            if address >= span.range.start && address < span.range.end {
                let offset = (address - span.range.start) / BASE_PAGE_SIZE;
                return span.first_frame.checked_add(offset);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BASE_PAGE_SIZE, FrameAllocationError, FrameAllocator, MemoryRegion, NormalizedMemoryMap,
        PhysicalRange, RegionKind,
    };
    use alloc::{vec, vec::Vec};

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
    fn frame_bitmap_tracks_discontiguous_usable_ranges() -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(1, 2, RegionKind::Usable),
                region(3, 2, RegionKind::Reserved),
                region(5, 1, RegionKind::Usable),
            ],
            &[],
        )
        .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;

        assert_eq!(allocator.total_frames(), 3);
        assert_eq!(allocator.bitmap_bytes(), 16);
        assert_eq!(allocator.allocate(), Ok(BASE_PAGE_SIZE));
        assert_eq!(allocator.allocate(), Ok(2 * BASE_PAGE_SIZE));
        assert_eq!(allocator.allocate(), Ok(5 * BASE_PAGE_SIZE));
        assert_eq!(allocator.free_frames(), 0);
        assert_eq!(allocator.allocate(), Err(FrameAllocationError::Exhausted));
        Ok(())
    }

    #[test]
    fn frame_bitmap_rejects_invalid_and_double_free() -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(1, 1, RegionKind::Usable),
                region(2, 1, RegionKind::Reserved),
            ],
            &[],
        )
        .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let frame = allocator.allocate()?;

        assert_eq!(allocator.free(frame), Ok(()));
        assert_eq!(allocator.free(frame), Err(FrameAllocationError::DoubleFree));
        assert_eq!(
            allocator.free(2 * BASE_PAGE_SIZE),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(
            allocator.free(BASE_PAGE_SIZE + 1),
            Err(FrameAllocationError::InvalidFrame)
        );
        Ok(())
    }

    #[test]
    fn frame_bitmap_reserves_overlapping_device_pages_idempotently()
    -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(&[region(1, 8, RegionKind::Usable)], &[])
            .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let device = PhysicalRange::from_pages(3 * BASE_PAGE_SIZE, 3)
            .map_err(|_| FrameAllocationError::Overflow)?;

        assert_eq!(allocator.reserve_range(device), Ok(3));
        assert_eq!(allocator.reserve_range(device), Ok(0));
        assert_eq!(allocator.free_frames(), 5);
        let before = allocator.clone();
        assert_eq!(
            allocator.free(device.start()),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(allocator, before);
        let contiguous = allocator.allocate_contiguous(3, 1)?;
        assert_eq!(contiguous.start(), 6 * BASE_PAGE_SIZE);
        allocator.free_range(contiguous)?;

        while let Ok(frame) = allocator.allocate() {
            assert!(!device.contains(frame));
        }
        Ok(())
    }

    #[test]
    fn reservation_skips_live_allocations_without_changing_their_state()
    -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(&[region(1, 4, RegionKind::Usable)], &[])
            .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let allocated = allocator.allocate()?;
        let overlap = pages(1, 2);

        assert_eq!(allocated, BASE_PAGE_SIZE);
        assert_eq!(allocator.reserve_range(overlap), Ok(1));
        assert_eq!(allocator.free_frames(), 2);
        assert_eq!(allocator.free(allocated), Ok(()));
        assert_eq!(allocator.free_frames(), 3);

        assert_eq!(allocator.reserve_range(overlap), Ok(1));
        assert_eq!(allocator.reserve_range(overlap), Ok(0));
        assert_eq!(allocator.free_frames(), 2);
        let before = allocator.clone();
        assert_eq!(
            allocator.free(allocated),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(allocator, before);
        Ok(())
    }

    #[test]
    fn contiguous_frame_allocation_and_teardown_are_atomic() -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(&[region(1, 16, RegionKind::Usable)], &[])
            .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let isolated = allocator.allocate_contiguous(4, 4)?;
        assert_eq!(isolated.start(), 4 * BASE_PAGE_SIZE);
        assert_eq!(allocator.free_frames(), 12);

        let middle = isolated.start() + BASE_PAGE_SIZE;
        allocator.free(middle)?;
        let before = allocator.clone();
        assert_eq!(
            allocator.free_range(isolated),
            Err(FrameAllocationError::DoubleFree)
        );
        assert_eq!(allocator, before);
        assert_eq!(
            allocator.reserve_range(
                PhysicalRange::from_pages(middle, 1).map_err(|_| FrameAllocationError::Overflow)?,
            ),
            Ok(1)
        );
        let before = allocator.clone();
        assert_eq!(
            allocator.free_range(isolated),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(allocator, before);
        assert_eq!(allocator.free_frames(), 12);
        for page in [0, 2, 3] {
            allocator.free(isolated.start() + page * BASE_PAGE_SIZE)?;
        }
        assert_eq!(allocator.free_frames(), 15);
        Ok(())
    }

    #[test]
    fn frame_bitmap_matches_model_across_discontiguous_spans() -> Result<(), FrameAllocationError> {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum ModelState {
            Free,
            Allocated,
            Reserved,
        }

        let map = NormalizedMemoryMap::build(
            &[
                region(1, 7, RegionKind::Usable),
                region(8, 3, RegionKind::Reserved),
                region(16, 9, RegionKind::Usable),
            ],
            &[],
        )
        .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let mut addresses = Vec::new();
        for index in 0..allocator.total_frames() {
            addresses.push(
                allocator
                    .address_for_index(index)
                    .ok_or(FrameAllocationError::Overflow)?,
            );
        }
        let mut model = vec![ModelState::Free; addresses.len()];
        let address_count =
            u64::try_from(addresses.len()).map_err(|_| FrameAllocationError::Overflow)?;
        let mut random = 0x8d26_4e77_a1b9_c305_u64;

        for _ in 0..512 {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            match random % 3 {
                0 => {
                    let expected = model.iter().position(|state| *state == ModelState::Free);
                    if let Some(index) = expected {
                        assert_eq!(allocator.allocate(), Ok(addresses[index]));
                        model[index] = ModelState::Allocated;
                    } else {
                        assert_eq!(allocator.allocate(), Err(FrameAllocationError::Exhausted));
                    }
                }
                1 => {
                    random = random.rotate_left(17);
                    let range = pages(random % 28, 1 + (random >> 8) % 6);
                    let mut expected = 0_u64;
                    for (address, state) in addresses.iter().copied().zip(&mut model) {
                        if range.contains(address) && *state == ModelState::Free {
                            *state = ModelState::Reserved;
                            expected = expected
                                .checked_add(1)
                                .ok_or(FrameAllocationError::Overflow)?;
                        }
                    }
                    assert_eq!(allocator.reserve_range(range), Ok(expected));
                }
                _ => {
                    let index = usize::try_from(random % address_count)
                        .map_err(|_| FrameAllocationError::Overflow)?;
                    match model[index] {
                        ModelState::Free => assert_eq!(
                            allocator.free(addresses[index]),
                            Err(FrameAllocationError::DoubleFree)
                        ),
                        ModelState::Allocated => {
                            assert_eq!(allocator.free(addresses[index]), Ok(()));
                            model[index] = ModelState::Free;
                        }
                        ModelState::Reserved => assert_eq!(
                            allocator.free(addresses[index]),
                            Err(FrameAllocationError::InvalidFrame)
                        ),
                    }
                }
            }

            let expected_free = u64::try_from(
                model
                    .iter()
                    .filter(|state| **state == ModelState::Free)
                    .count(),
            )
            .map_err(|_| FrameAllocationError::Overflow)?;
            assert_eq!(allocator.free_frames(), expected_free);
            for (index, expected) in model.iter().copied().enumerate() {
                let frame_index =
                    u64::try_from(index).map_err(|_| FrameAllocationError::Overflow)?;
                assert_eq!(
                    allocator.is_allocated(frame_index)?,
                    expected == ModelState::Allocated
                );
                assert_eq!(
                    allocator.is_reserved(frame_index)?,
                    expected == ModelState::Reserved
                );
            }
        }
        Ok(())
    }

    #[test]
    fn contiguous_frame_bounds_fail_without_mutation() -> Result<(), FrameAllocationError> {
        let map = NormalizedMemoryMap::build(
            &[
                region(1, 2, RegionKind::Usable),
                region(3, 1, RegionKind::Reserved),
                region(4, 2, RegionKind::Usable),
            ],
            &[],
        )
        .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;
        let before = allocator.clone();
        assert_eq!(
            allocator.allocate_contiguous(3, 1),
            Err(FrameAllocationError::Exhausted)
        );
        assert_eq!(allocator, before);
        assert_eq!(
            allocator.allocate_contiguous(0, 1),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(
            allocator.allocate_contiguous(1, 3),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(
            allocator.allocate_contiguous(1, 1_u64 << 63),
            Err(FrameAllocationError::Overflow)
        );
        assert_eq!(
            allocator.free_range(pages(3, 1)),
            Err(FrameAllocationError::InvalidFrame)
        );
        assert_eq!(allocator, before);
        Ok(())
    }

    #[test]
    fn active_stack_reservation_is_never_allocatable() -> Result<(), FrameAllocationError> {
        let stack = pages(4, 2);
        let map = NormalizedMemoryMap::build(&[region(1, 8, RegionKind::Usable)], &[stack])
            .map_err(|_| FrameAllocationError::Overflow)?;
        let mut allocator = FrameAllocator::from_map(&map)?;

        while let Ok(frame) = allocator.allocate() {
            assert!(!stack.contains(frame));
        }
        assert_eq!(allocator.total_frames(), 6);
        assert_eq!(allocator.free_frames(), 0);
        Ok(())
    }

    #[test]
    fn permanent_table_stack_and_runtime_reservations_never_enter_the_frame_pool()
    -> Result<(), FrameAllocationError> {
        let boot_arena = pages(16, 24);
        let page_tables = pages(18, 4);
        let active_stack = pages(30, 4);
        let map = NormalizedMemoryMap::build(&[region(1, 96, RegionKind::Usable)], &[boot_arena])
            .map_err(|_| FrameAllocationError::Overflow)?;

        for seed in 0..32_u64 {
            let runtime_reserved = pages(48 + seed % 16, 1 + seed % 5);
            let mut base = FrameAllocator::from_map(&map)?;
            assert_eq!(base.reserve_range(page_tables), Ok(0));
            assert_eq!(base.reserve_range(active_stack), Ok(0));
            assert_eq!(base.reserve_range(boot_arena), Ok(0));
            assert_eq!(
                base.reserve_range(runtime_reserved),
                Ok(runtime_reserved.page_count())
            );
            assert_eq!(base.reserve_range(runtime_reserved), Ok(0));

            for permanent in [boot_arena, page_tables, active_stack, runtime_reserved] {
                let before = base.clone();
                assert_eq!(
                    base.free(permanent.start()),
                    Err(FrameAllocationError::InvalidFrame)
                );
                assert_eq!(base, before);
            }

            let expected: Vec<u64> = (1..97_u64)
                .map(|page| page * BASE_PAGE_SIZE)
                .filter(|address| {
                    !boot_arena.contains(*address) && !runtime_reserved.contains(*address)
                })
                .collect();
            assert_eq!(
                base.free_frames(),
                u64::try_from(expected.len()).map_err(|_| FrameAllocationError::Overflow)?
            );
            let mut singles = base.clone();
            for address in expected {
                assert_eq!(singles.allocate(), Ok(address));
            }
            assert_eq!(singles.allocate(), Err(FrameAllocationError::Exhausted));

            for page_count in 1..=8_u64 {
                for alignment_pages in [1, 2, 4, 8] {
                    let mut contiguous = base.clone();
                    while let Ok(range) =
                        contiguous.allocate_contiguous(page_count, alignment_pages)
                    {
                        for permanent in [boot_arena, page_tables, active_stack, runtime_reserved] {
                            assert!(
                                range.end() <= permanent.start()
                                    || range.start() >= permanent.end()
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

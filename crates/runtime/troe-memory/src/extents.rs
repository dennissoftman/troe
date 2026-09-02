//! Ordered physical extents addressed as one logical page sequence.

use crate::{BASE_PAGE_SIZE, PhysicalRange};
use alloc::vec::Vec;
use core::fmt;

/// Failures produced while building or addressing a physical extent sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentError {
    /// The sequence already holds its permitted number of extents.
    TooManyExtents,
    /// The requested range lies outside the sequence.
    OutOfRange,
    /// The request is empty.
    Empty,
    /// Address or accounting arithmetic overflowed.
    Overflow,
    /// Extent metadata could not be allocated.
    AllocationFailed,
}

impl fmt::Display for ExtentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyExtents => formatter.write_str("extent sequence is full"),
            Self::OutOfRange => formatter.write_str("range is outside the extent sequence"),
            Self::Empty => formatter.write_str("extent request is empty"),
            Self::Overflow => formatter.write_str("extent arithmetic overflowed"),
            Self::AllocationFailed => formatter.write_str("extent metadata allocation failed"),
        }
    }
}

/// An ordered run of physical extents addressed as one logical page sequence.
///
/// Callers that once owned a single contiguous reservation keep addressing
/// frames by logical page or byte offset. Only physical contiguity is given up,
/// which is what lets a large reservation succeed on a machine whose free
/// memory is fragmented. Appending coalesces a physically adjacent tail, so an
/// unfragmented allocator still produces exactly one extent.
#[derive(Debug, Default)]
pub struct PhysicalExtents {
    extents: Vec<PhysicalRange>,
    page_count: u64,
}

impl PhysicalExtents {
    /// Construct an empty sequence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            extents: Vec::new(),
            page_count: 0,
        }
    }

    /// Total pages across every extent.
    #[must_use]
    pub const fn page_count(&self) -> u64 {
        self.page_count
    }

    /// The extents in logical order.
    #[must_use]
    pub fn extents(&self) -> &[PhysicalRange] {
        &self.extents
    }

    /// Physical start of the first extent.
    ///
    /// This identifies one reservation for diagnostics. It is not the base of a
    /// contiguous run and must not be used to address anything beyond the first
    /// extent.
    ///
    /// # Errors
    ///
    /// Rejects an empty sequence.
    pub fn first_start(&self) -> Result<u64, ExtentError> {
        self.extents
            .first()
            .map(|extent| extent.start())
            .ok_or(ExtentError::Empty)
    }

    /// Append one extent, optionally coalescing a physically adjacent tail.
    ///
    /// `maximum` bounds the number of separate extents, so a caller that must
    /// describe the sequence in a bounded table refuses excessive fragmentation
    /// here rather than discovering it later.
    ///
    /// `coalesce` should be true in ordinary use: it keeps an unfragmented
    /// allocator producing exactly one extent. A caller may pass false to hold
    /// a sequence deliberately fragmented, so that code addressing it is
    /// exercised on inputs fragmentation would otherwise reach only rarely.
    ///
    /// # Errors
    ///
    /// Rejects a sequence already at `maximum`, failed metadata allocation, and
    /// checked arithmetic overflow.
    pub fn push(
        &mut self,
        range: PhysicalRange,
        maximum: usize,
        coalesce: bool,
    ) -> Result<(), ExtentError> {
        let page_count = self
            .page_count
            .checked_add(range.page_count())
            .ok_or(ExtentError::Overflow)?;
        if let Some(previous) = self.extents.last_mut()
            && coalesce
            && previous.end() == range.start()
        {
            let merged = previous
                .page_count()
                .checked_add(range.page_count())
                .ok_or(ExtentError::Overflow)?;
            *previous = PhysicalRange::from_pages(previous.start(), merged)
                .map_err(|_| ExtentError::Overflow)?;
            self.page_count = page_count;
            return Ok(());
        }
        if self.extents.len() >= maximum {
            return Err(ExtentError::TooManyExtents);
        }
        self.extents
            .try_reserve(1)
            .map_err(|_| ExtentError::AllocationFailed)?;
        self.extents.push(range);
        self.page_count = page_count;
        Ok(())
    }

    /// The first contiguous run of a logical page range.
    ///
    /// The returned run starts at `start_page` and covers at most `page_count`
    /// pages, stopping at the first extent boundary. Callers advance by the
    /// returned page count until the range is consumed.
    ///
    /// # Errors
    ///
    /// Rejects an empty request, a range outside the sequence, and checked
    /// arithmetic overflow.
    pub fn run_at(&self, start_page: u64, page_count: u64) -> Result<PhysicalRange, ExtentError> {
        if page_count == 0 {
            return Err(ExtentError::Empty);
        }
        let end_page = start_page
            .checked_add(page_count)
            .ok_or(ExtentError::Overflow)?;
        if end_page > self.page_count {
            return Err(ExtentError::OutOfRange);
        }
        let mut logical = 0_u64;
        for extent in &self.extents {
            let extent_end = logical
                .checked_add(extent.page_count())
                .ok_or(ExtentError::Overflow)?;
            if start_page < extent_end {
                let skip = start_page
                    .checked_sub(logical)
                    .ok_or(ExtentError::OutOfRange)?;
                let available = extent
                    .page_count()
                    .checked_sub(skip)
                    .ok_or(ExtentError::OutOfRange)?;
                let start = skip
                    .checked_mul(BASE_PAGE_SIZE)
                    .and_then(|bytes| extent.start().checked_add(bytes))
                    .ok_or(ExtentError::Overflow)?;
                return PhysicalRange::from_pages(start, available.min(page_count))
                    .map_err(|_| ExtentError::Overflow);
            }
            logical = extent_end;
        }
        Err(ExtentError::OutOfRange)
    }

    /// The first contiguous run of a logical byte range.
    ///
    /// Returns the extent holding `byte_offset`, the offset within it, and how
    /// many of the requested bytes it holds. A copy that straddles an extent
    /// boundary is split by advancing through successive calls.
    ///
    /// # Errors
    ///
    /// Rejects an empty request, a range outside the sequence, and checked
    /// arithmetic overflow.
    pub fn byte_run_at(
        &self,
        byte_offset: u64,
        byte_count: u64,
    ) -> Result<(PhysicalRange, usize, usize), ExtentError> {
        if byte_count == 0 {
            return Err(ExtentError::Empty);
        }
        let total = self
            .page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(ExtentError::Overflow)?;
        let end = byte_offset
            .checked_add(byte_count)
            .ok_or(ExtentError::Overflow)?;
        if end > total {
            return Err(ExtentError::OutOfRange);
        }
        let mut logical = 0_u64;
        for extent in &self.extents {
            let extent_end = logical
                .checked_add(extent.byte_count())
                .ok_or(ExtentError::Overflow)?;
            if byte_offset < extent_end {
                let within = byte_offset
                    .checked_sub(logical)
                    .ok_or(ExtentError::OutOfRange)?;
                let available = extent
                    .byte_count()
                    .checked_sub(within)
                    .ok_or(ExtentError::OutOfRange)?;
                let count = available.min(byte_count);
                return Ok((
                    *extent,
                    usize::try_from(within).map_err(|_| ExtentError::Overflow)?,
                    usize::try_from(count).map_err(|_| ExtentError::Overflow)?,
                ));
            }
            logical = extent_end;
        }
        Err(ExtentError::OutOfRange)
    }
}

#[cfg(test)]
mod tests {
    use crate::{BASE_PAGE_SIZE, ExtentError, PhysicalExtents, PhysicalRange};
    use alloc::vec::Vec;

    fn extent(start_page: u64, pages: u64) -> PhysicalRange {
        PhysicalRange::from_pages(start_page * BASE_PAGE_SIZE, pages)
            .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn adjacent_extents_coalesce_and_disjoint_ones_do_not() -> Result<(), ExtentError> {
        let mut extents = PhysicalExtents::new();
        extents.push(extent(10, 2), 8, true)?;
        extents.push(extent(12, 3), 8, true)?;
        assert_eq!(extents.extents().len(), 1);
        assert_eq!(extents.page_count(), 5);

        extents.push(extent(100, 1), 8, true)?;
        assert_eq!(extents.extents().len(), 2);
        assert_eq!(extents.page_count(), 6);

        // The bound counts separate extents, so a coalescing append still fits.
        let mut full = PhysicalExtents::new();
        full.push(extent(0, 1), 1, true)?;
        assert_eq!(
            full.push(extent(50, 1), 1, true),
            Err(ExtentError::TooManyExtents)
        );
        full.push(extent(1, 1), 1, true)?;
        assert_eq!(full.page_count(), 2);
        Ok(())
    }

    #[test]
    fn page_runs_stop_at_every_extent_boundary() -> Result<(), ExtentError> {
        let mut extents = PhysicalExtents::new();
        extents.push(extent(10, 2), 8, true)?;
        extents.push(extent(40, 3), 8, true)?;
        extents.push(extent(90, 1), 8, true)?;

        // Walking the whole sequence reproduces each extent in logical order.
        let mut page = 0;
        let mut seen = Vec::new();
        while page < extents.page_count() {
            let run = extents.run_at(page, extents.page_count() - page)?;
            seen.push((run.start() / BASE_PAGE_SIZE, run.page_count()));
            page += run.page_count();
        }
        assert_eq!(seen, [(10, 2), (40, 3), (90, 1)]);

        // A request starting mid-extent is clipped to that extent's tail.
        let middle = extents.run_at(3, 3)?;
        assert_eq!(
            (middle.start() / BASE_PAGE_SIZE, middle.page_count()),
            (41, 2)
        );
        // And a request narrower than the extent is clipped to the request.
        let narrow = extents.run_at(2, 1)?;
        assert_eq!(
            (narrow.start() / BASE_PAGE_SIZE, narrow.page_count()),
            (40, 1)
        );

        assert_eq!(extents.run_at(0, 0), Err(ExtentError::Empty));
        assert_eq!(extents.run_at(5, 2), Err(ExtentError::OutOfRange));
        assert_eq!(extents.run_at(6, 1), Err(ExtentError::OutOfRange));
        assert_eq!(extents.run_at(u64::MAX, 2), Err(ExtentError::Overflow));
        Ok(())
    }

    #[test]
    fn byte_runs_split_a_write_that_straddles_a_boundary() -> Result<(), ExtentError> {
        let mut extents = PhysicalExtents::new();
        extents.push(extent(10, 1), 8, true)?;
        extents.push(extent(40, 1), 8, true)?;

        // Eight bytes starting four before the boundary split four and four.
        let offset = BASE_PAGE_SIZE - 4;
        let (first, within, count) = extents.byte_run_at(offset, 8)?;
        assert_eq!(first.start(), 10 * BASE_PAGE_SIZE);
        assert_eq!((within, count), (4092, 4));
        let (second, within, count) = extents.byte_run_at(offset + count as u64, 4)?;
        assert_eq!(second.start(), 40 * BASE_PAGE_SIZE);
        assert_eq!((within, count), (0, 4));

        // A run wholly inside one extent is not split.
        let (only, within, count) = extents.byte_run_at(16, 32)?;
        assert_eq!(only.start(), 10 * BASE_PAGE_SIZE);
        assert_eq!((within, count), (16, 32));

        assert_eq!(extents.byte_run_at(0, 0), Err(ExtentError::Empty));
        assert_eq!(
            extents.byte_run_at(2 * BASE_PAGE_SIZE - 1, 2),
            Err(ExtentError::OutOfRange)
        );
        Ok(())
    }

    #[test]
    fn refusing_to_coalesce_keeps_adjacent_extents_separate() -> Result<(), ExtentError> {
        let mut joined = PhysicalExtents::new();
        joined.push(extent(10, 1), 8, true)?;
        joined.push(extent(11, 1), 8, true)?;
        assert_eq!(joined.extents().len(), 1);

        let mut split = PhysicalExtents::new();
        split.push(extent(10, 1), 8, false)?;
        split.push(extent(11, 1), 8, false)?;
        assert_eq!(split.extents().len(), 2);

        // Both describe the same logical sequence and address it identically.
        assert_eq!(joined.page_count(), split.page_count());
        for page in 0..joined.page_count() {
            assert_eq!(
                joined.run_at(page, 1)?.start(),
                split.run_at(page, 1)?.start()
            );
        }
        // Only the run boundaries differ, which is what the split exists to test.
        assert_eq!(joined.run_at(0, 2)?.page_count(), 2);
        assert_eq!(split.run_at(0, 2)?.page_count(), 1);
        Ok(())
    }

    #[test]
    fn a_region_walk_reproduces_the_contiguous_mapping() -> Result<(), ExtentError> {
        // The exact geometry a 14-page launch produced in QEMU: four extents of
        // 4, 4, 4 and 2 pages, with the stack starting mid-extent and spanning
        // three of them.
        let mut extents = PhysicalExtents::new();
        for (start, pages) in [(100, 4), (200, 4), (300, 4), (400, 2)] {
            extents.push(extent(start, pages), 8, false)?;
        }
        assert_eq!(extents.page_count(), 14);

        // Walk the stack region exactly as the mapping builder does.
        let (start_page, page_count, virtual_start) = (6, 8, 0x1000_0000_u64);
        let mut mapped = 0_u64;
        let mut records = Vec::new();
        while mapped < page_count {
            let run = extents.run_at(start_page + mapped, page_count - mapped)?;
            records.push((
                virtual_start + mapped * BASE_PAGE_SIZE,
                run.start(),
                run.page_count(),
            ));
            mapped += run.page_count();
        }
        assert_eq!(mapped, page_count);
        assert_eq!(
            records,
            [
                (0x1000_0000, 202 * BASE_PAGE_SIZE, 2),
                (0x1000_2000, 300 * BASE_PAGE_SIZE, 4),
                (0x1000_6000, 400 * BASE_PAGE_SIZE, 2),
            ]
        );

        // Resolving one page at a time must agree with the run walk, so no
        // page of the region is mapped to a different frame by the two paths.
        for page in 0..page_count {
            let single = extents.run_at(start_page + page, 1)?;
            let address = virtual_start + page * BASE_PAGE_SIZE;
            let (record_virtual, record_physical, _) = records
                .iter()
                .rev()
                .find(|(virtual_address, _, _)| *virtual_address <= address)
                .copied()
                .unwrap_or_else(|| unreachable!());
            assert_eq!(single.page_count(), 1);
            assert_eq!(single.start(), record_physical + (address - record_virtual));
        }
        Ok(())
    }

    #[test]
    fn an_empty_sequence_addresses_nothing() {
        let extents = PhysicalExtents::new();
        assert_eq!(extents.page_count(), 0);
        assert_eq!(extents.first_start(), Err(ExtentError::Empty));
        assert_eq!(extents.run_at(0, 1), Err(ExtentError::OutOfRange));
        assert_eq!(extents.byte_run_at(0, 1), Err(ExtentError::OutOfRange));
    }
}

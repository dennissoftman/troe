//! Checked, page-aligned physical address ranges.

use crate::{BASE_PAGE_SIZE, MemoryMapError};

/// A checked, half-open, base-page-aligned physical address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
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

    /// Whether `address` lies within this half-open range.
    #[must_use]
    pub const fn contains(self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
}

#[cfg(test)]
mod tests {
    use crate::{BASE_PAGE_SIZE, MemoryMapError, PhysicalRange};

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
}

//! Monotonic byte allocator over one reserved boot arena.

use crate::PhysicalRange;
use core::fmt;

/// Failures produced by the early monotonic allocator model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootAllocationError {
    /// A zero-byte allocation was requested.
    Empty,
    /// Alignment was zero or not a power of two.
    InvalidAlignment,
    /// Checked address or accounting arithmetic overflowed.
    Overflow,
    /// The reserved boot arena cannot satisfy the request.
    Exhausted,
    /// Allocation was attempted after the arena was sealed.
    Sealed,
}

impl fmt::Display for BootAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("boot allocation is empty"),
            Self::InvalidAlignment => formatter.write_str("boot allocation alignment is invalid"),
            Self::Overflow => formatter.write_str("boot allocation arithmetic overflowed"),
            Self::Exhausted => formatter.write_str("boot allocation arena is exhausted"),
            Self::Sealed => formatter.write_str("boot allocation arena is sealed"),
        }
    }
}

/// One checked byte allocation within the reserved boot arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootAllocation {
    start: u64,
    byte_count: u64,
}

impl BootAllocation {
    /// First byte assigned to the allocation.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Payload bytes assigned to the allocation.
    #[must_use]
    pub const fn byte_count(self) -> u64 {
        self.byte_count
    }

    /// First byte after the allocation.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.start + self.byte_count
    }
}

/// Bounded monotonic allocator over one explicitly reserved physical range.
///
/// This is a pure ownership model: it returns checked addresses but never
/// constructs references or dereferences physical memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootAllocator {
    arena: PhysicalRange,
    cursor: u64,
    allocated_bytes: u64,
    sealed: bool,
}

impl BootAllocator {
    /// Construct an empty allocator over a previously reserved arena.
    #[must_use]
    pub const fn new(arena: PhysicalRange) -> Self {
        Self {
            arena,
            cursor: arena.start,
            allocated_bytes: 0,
            sealed: false,
        }
    }

    /// Allocate payload bytes with a power-of-two alignment.
    ///
    /// A failed request does not change the cursor or accounting.
    ///
    /// # Errors
    ///
    /// Rejects zero bytes, invalid alignment, checked overflow, exhaustion, or
    /// any request after the allocator has been sealed.
    pub fn allocate(
        &mut self,
        byte_count: u64,
        alignment: u64,
    ) -> Result<BootAllocation, BootAllocationError> {
        if self.sealed {
            return Err(BootAllocationError::Sealed);
        }
        if byte_count == 0 {
            return Err(BootAllocationError::Empty);
        }
        if !alignment.is_power_of_two() {
            return Err(BootAllocationError::InvalidAlignment);
        }

        let alignment_mask = alignment - 1;
        let start = self
            .cursor
            .checked_add(alignment_mask)
            .ok_or(BootAllocationError::Overflow)?
            & !alignment_mask;
        let end = start
            .checked_add(byte_count)
            .ok_or(BootAllocationError::Overflow)?;
        if end > self.arena.end {
            return Err(BootAllocationError::Exhausted);
        }
        let allocated_bytes = self
            .allocated_bytes
            .checked_add(byte_count)
            .ok_or(BootAllocationError::Overflow)?;

        self.cursor = end;
        self.allocated_bytes = allocated_bytes;
        Ok(BootAllocation { start, byte_count })
    }

    /// Prevent all subsequent allocations.
    pub const fn seal(&mut self) {
        self.sealed = true;
    }

    /// Reserved arena backing this allocator.
    #[must_use]
    pub const fn arena(self) -> PhysicalRange {
        self.arena
    }

    /// Payload bytes returned to callers, excluding alignment padding.
    #[must_use]
    pub const fn allocated_bytes(self) -> u64 {
        self.allocated_bytes
    }

    /// Arena bytes consumed, including alignment padding.
    #[must_use]
    pub const fn consumed_bytes(self) -> u64 {
        self.cursor - self.arena.start
    }

    /// Bytes after the cursor that remain available for future requests.
    #[must_use]
    pub const fn remaining_bytes(self) -> u64 {
        self.arena.end - self.cursor
    }

    /// Whether the allocator rejects all further requests.
    #[must_use]
    pub const fn is_sealed(self) -> bool {
        self.sealed
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BASE_PAGE_SIZE, BootAllocation, BootAllocationError, BootAllocator, MemoryMapError,
        PhysicalRange,
    };

    fn pages(start_page: u64, count: u64) -> PhysicalRange {
        let start = start_page * BASE_PAGE_SIZE;
        PhysicalRange {
            start,
            end: start + count * BASE_PAGE_SIZE,
        }
    }
    #[test]
    fn boot_allocator_aligns_and_accounts_padding() {
        let mut allocator = BootAllocator::new(pages(1, 2));
        assert_eq!(
            allocator.allocate(3, 1),
            Ok(BootAllocation {
                start: BASE_PAGE_SIZE,
                byte_count: 3
            })
        );
        assert_eq!(
            allocator.allocate(4, 8),
            Ok(BootAllocation {
                start: BASE_PAGE_SIZE + 8,
                byte_count: 4
            })
        );
        assert_eq!(allocator.allocated_bytes(), 7);
        assert_eq!(allocator.consumed_bytes(), 12);
        assert_eq!(allocator.remaining_bytes(), 2 * BASE_PAGE_SIZE - 12);
    }

    #[test]
    fn boot_allocator_rejects_invalid_requests_without_mutation() {
        let mut allocator = BootAllocator::new(pages(0, 1));
        assert_eq!(allocator.allocate(0, 1), Err(BootAllocationError::Empty));
        assert_eq!(
            allocator.allocate(1, 3),
            Err(BootAllocationError::InvalidAlignment)
        );
        assert_eq!(allocator.consumed_bytes(), 0);
        assert_eq!(allocator.allocated_bytes(), 0);
    }

    #[test]
    fn boot_allocator_exhaustion_is_atomic() {
        let mut allocator = BootAllocator::new(pages(0, 1));
        assert_eq!(allocator.allocate(BASE_PAGE_SIZE, 1).map(|_| ()), Ok(()));
        assert_eq!(
            allocator.allocate(1, 1),
            Err(BootAllocationError::Exhausted)
        );
        assert_eq!(allocator.consumed_bytes(), BASE_PAGE_SIZE);
        assert_eq!(allocator.remaining_bytes(), 0);
    }

    #[test]
    fn boot_allocator_checked_alignment_overflow_is_atomic() -> Result<(), MemoryMapError> {
        let arena_start = u64::MAX - (2 * BASE_PAGE_SIZE - 1);
        let mut allocator = BootAllocator::new(PhysicalRange::from_pages(arena_start, 1)?);
        assert_eq!(
            allocator.allocate(1, 1_u64 << 63),
            Err(BootAllocationError::Overflow)
        );
        assert_eq!(allocator.consumed_bytes(), 0);
        Ok(())
    }

    #[test]
    fn sealed_boot_allocator_rejects_requests() {
        let mut allocator = BootAllocator::new(pages(0, 1));
        allocator.seal();
        assert!(allocator.is_sealed());
        assert_eq!(allocator.allocate(1, 1), Err(BootAllocationError::Sealed));
    }
}

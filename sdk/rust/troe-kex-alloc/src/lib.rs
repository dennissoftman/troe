//! Bounded constant-time allocation for freestanding KEX applications.
#![no_std]

use core::{alloc::Layout, ptr::NonNull};
use rlsf::Tlsf;
use troe_kex_sdk::HeapRegion;

type ApplicationTlsf = Tlsf<'static, u32, u16, 20, 16>;

/// Failure to initialize an allocator from the application's heap token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationError {
    /// The supplied heap is too small for TLSF metadata and one free block.
    RegionTooSmall,
}

/// Exact requested-byte counters maintained around the TLSF allocator.
///
/// TLSF itself rounds blocks for alignment and metadata. `live_bytes` tracks
/// the sizes requested by the language runtime, while `capacity_bytes` is the
/// memory region accepted by TLSF.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Bytes in the heap pool accepted by TLSF during initialization.
    pub capacity_bytes: usize,
    /// Sum of requested sizes for currently live allocations.
    pub live_bytes: usize,
    /// Highest observed `live_bytes` value.
    pub high_water_bytes: usize,
    /// Successful fresh allocations.
    pub allocations: u64,
    /// Successful deallocations, including zero-sized reallocations.
    pub deallocations: u64,
    /// Successful reallocations to nonzero sizes.
    pub reallocations: u64,
    /// Allocation or reallocation requests rejected by the bounded pool.
    pub failures: u64,
    /// Requested bytes copied when reallocation had to move a block.
    pub moved_bytes: u64,
}

/// One TLSF allocator owning one validated KEX heap region.
///
/// Allocation and deallocation are constant time. Reallocation is constant
/// time when it can resize in place and linear only when it must copy a block.
pub struct Heap {
    tlsf: ApplicationTlsf,
    statistics: Statistics,
}

impl Heap {
    /// Consume a validated single-owner heap token and initialize TLSF in it.
    ///
    /// # Errors
    ///
    /// Returns [`InitializationError::RegionTooSmall`] if the mapped region
    /// cannot hold TLSF's minimum free-block representation.
    pub fn new(region: HeapRegion) -> Result<Self, InitializationError> {
        let (start_address, byte_len) = region.into_raw_parts();
        // SAFETY: `HeapRegion` is a non-cloneable SDK token produced only after
        // validating the kernel-owned startup page. Its range is writable,
        // initially zeroed, and remains mapped for the complete app lifetime.
        unsafe { Self::from_raw_parts(start_address, byte_len) }
    }

    unsafe fn from_raw_parts(address: usize, byte_len: usize) -> Result<Self, InitializationError> {
        let mut tlsf = ApplicationTlsf::new();
        let start = NonNull::new(address as *mut u8).ok_or(InitializationError::RegionTooSmall)?;
        let block = NonNull::slice_from_raw_parts(start, byte_len);
        // SAFETY: The caller guarantees exclusive ownership of this writable
        // region for the allocator's full lifetime.
        let accepted = unsafe { tlsf.insert_free_block_ptr(block) }
            .ok_or(InitializationError::RegionTooSmall)?;
        Ok(Self {
            tlsf,
            statistics: Statistics {
                capacity_bytes: accepted.get(),
                ..Statistics::default()
            },
        })
    }

    /// Return an immutable snapshot of allocator counters.
    #[must_use]
    pub const fn statistics(&self) -> Statistics {
        self.statistics
    }

    /// Allocate one block satisfying `layout`.
    ///
    /// Returns `None` without changing existing allocations when the bounded
    /// heap has insufficient contiguous space or the size cannot be represented.
    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let pointer = self.tlsf.allocate(layout);
        if pointer.is_some() {
            self.statistics.allocations = self.statistics.allocations.saturating_add(1);
            self.add_live_bytes(layout.size());
        } else {
            self.statistics.failures = self.statistics.failures.saturating_add(1);
        }
        pointer
    }

    /// Release a block previously returned by this heap.
    ///
    /// # Safety
    ///
    /// `pointer` must still denote a live allocation from this `Heap`, and
    /// `layout` must be the layout used to allocate it.
    pub unsafe fn deallocate(&mut self, pointer: NonNull<u8>, layout: Layout) {
        // SAFETY: The caller upholds TLSF's pointer and alignment contract.
        unsafe { self.tlsf.deallocate(pointer, layout.align()) };
        self.statistics.live_bytes = self.statistics.live_bytes.saturating_sub(layout.size());
        self.statistics.deallocations = self.statistics.deallocations.saturating_add(1);
    }

    /// Resize a live allocation while preserving its prefix.
    ///
    /// A `new_size` of zero frees the allocation and returns `None`. On any
    /// other `None` result, the original allocation remains valid and unchanged.
    ///
    /// # Safety
    ///
    /// `pointer` must still denote a live allocation from this `Heap`, and
    /// `old_layout` must be the layout used to allocate it.
    pub unsafe fn reallocate(
        &mut self,
        pointer: NonNull<u8>,
        old_layout: Layout,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        if new_size == 0 {
            // SAFETY: Forwarded from this method's caller contract.
            unsafe { self.deallocate(pointer, old_layout) };
            return None;
        }
        let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
            self.statistics.failures = self.statistics.failures.saturating_add(1);
            return None;
        };
        // SAFETY: The caller upholds TLSF's pointer and alignment contract.
        let resized = unsafe { self.tlsf.reallocate(pointer, new_layout) };
        let Some(new_pointer) = resized else {
            self.statistics.failures = self.statistics.failures.saturating_add(1);
            return None;
        };
        self.statistics.reallocations = self.statistics.reallocations.saturating_add(1);
        self.statistics.live_bytes = self.statistics.live_bytes.saturating_sub(old_layout.size());
        self.add_live_bytes(new_size);
        if new_pointer != pointer {
            self.statistics.moved_bytes = self
                .statistics
                .moved_bytes
                .saturating_add(old_layout.size().min(new_size) as u64);
        }
        Some(new_pointer)
    }

    fn add_live_bytes(&mut self, bytes: usize) {
        self.statistics.live_bytes = self.statistics.live_bytes.saturating_add(bytes);
        self.statistics.high_water_bytes = self
            .statistics
            .high_water_bytes
            .max(self.statistics.live_bytes);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::Heap;
    use core::{alloc::Layout, mem::MaybeUninit, ptr::NonNull};
    use std::vec::Vec;

    #[repr(align(64))]
    struct Pool<const N: usize>([MaybeUninit<u8>; N]);

    fn heap<const N: usize>(pool: &mut Pool<N>) -> Heap {
        // SAFETY: Each test passes a unique, live, aligned pool which outlives
        // the returned heap and is not accessed except through that heap.
        unsafe { Heap::from_raw_parts(pool.0.as_mut_ptr() as usize, N) }
            .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn allocates_aligned_blocks_and_tracks_requested_bytes() {
        let mut pool = Pool([MaybeUninit::uninit(); 16 * 1024]);
        let mut heap = heap(&mut pool);
        let first_layout = Layout::from_size_align(37, 64).unwrap_or_else(|_| unreachable!());
        let second_layout = Layout::from_size_align(111, 16).unwrap_or_else(|_| unreachable!());
        let first = heap
            .allocate(first_layout)
            .unwrap_or_else(|| unreachable!());
        let second = heap
            .allocate(second_layout)
            .unwrap_or_else(|| unreachable!());
        assert_eq!(first.as_ptr() as usize % 64, 0);
        assert_eq!(second.as_ptr() as usize % 16, 0);
        assert_eq!(heap.statistics().live_bytes, 148);
        assert_eq!(heap.statistics().high_water_bytes, 148);
        // SAFETY: Both pointers are live allocations with their original layouts.
        unsafe {
            heap.deallocate(first, first_layout);
            heap.deallocate(second, second_layout);
        }
        assert_eq!(heap.statistics().live_bytes, 0);
        assert_eq!(heap.statistics().deallocations, 2);
    }

    #[test]
    fn reallocates_without_losing_the_prefix() {
        let mut pool = Pool([MaybeUninit::uninit(); 16 * 1024]);
        let mut heap = heap(&mut pool);
        let layout = Layout::from_size_align(128, 16).unwrap_or_else(|_| unreachable!());
        let pointer = heap.allocate(layout).unwrap_or_else(|| unreachable!());
        // SAFETY: The allocation contains 128 writable bytes.
        unsafe { pointer.as_ptr().write_bytes(0x5a, 128) };
        // SAFETY: `pointer` is live and `layout` is its original layout.
        let grown =
            unsafe { heap.reallocate(pointer, layout, 4096) }.unwrap_or_else(|| unreachable!());
        // SAFETY: The grown allocation preserves at least the original 128 bytes.
        let prefix = unsafe { core::slice::from_raw_parts(grown.as_ptr(), 128) };
        assert!(prefix.iter().all(|byte| *byte == 0x5a));
        assert_eq!(heap.statistics().live_bytes, 4096);
        let grown_layout = Layout::from_size_align(4096, 16).unwrap_or_else(|_| unreachable!());
        // SAFETY: `grown` is live and `grown_layout` is its current layout.
        unsafe { heap.deallocate(grown, grown_layout) };
    }

    #[test]
    fn fragmentation_recovers_and_oom_is_atomic() {
        let mut pool = Pool([MaybeUninit::uninit(); 16 * 1024]);
        let mut heap = heap(&mut pool);
        let layout = Layout::from_size_align(257, 16).unwrap_or_else(|_| unreachable!());
        let mut allocations = Vec::new();
        while let Some(pointer) = heap.allocate(layout) {
            allocations.push(pointer);
        }
        assert!(!allocations.is_empty());
        let live_before = heap.statistics().live_bytes;
        assert!(heap.allocate(layout).is_none());
        assert_eq!(heap.statistics().live_bytes, live_before);
        for pointer in allocations.iter().step_by(2).copied() {
            // SAFETY: Each selected pointer is live and is released exactly once.
            unsafe { heap.deallocate(pointer, layout) };
        }
        let replacements = allocations.len().div_ceil(2);
        for _ in 0..replacements {
            assert!(heap.allocate(layout).is_some());
        }
        for pointer in allocations.into_iter().skip(1).step_by(2) {
            // SAFETY: Each remaining original pointer is live and released once.
            unsafe { heap.deallocate(pointer, layout) };
        }
    }

    #[test]
    fn zero_reallocation_frees_the_block() {
        let mut pool = Pool([MaybeUninit::uninit(); 4096]);
        let mut heap = heap(&mut pool);
        let layout = Layout::from_size_align(64, 16).unwrap_or_else(|_| unreachable!());
        let pointer: NonNull<u8> = heap.allocate(layout).unwrap_or_else(|| unreachable!());
        // SAFETY: `pointer` is live and `layout` is its original layout.
        assert!(unsafe { heap.reallocate(pointer, layout, 0) }.is_none());
        assert_eq!(heap.statistics().live_bytes, 0);
        assert_eq!(heap.statistics().deallocations, 1);
    }
}

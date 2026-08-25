//! Constant-time TLSF allocation over runtime-selected growable backing.
#![no_std]

use core::{alloc::Layout, ptr::NonNull};
use rlsf::{FlexSource, FlexTlsf};
use troe_kex_sdk::HeapRegion;

const PAGE_BYTES: usize = 4096;
const GROWTH_QUANTUM_PAGES: usize = 64;
type ApplicationTlsf<S> = FlexTlsf<S, u32, u16, 20, 16>;

/// Backing-store contract used by the shared KEX heap.
///
/// Implementations may commit memory through the KEX ABI, a hosted test pool,
/// or a future libc virtual-memory layer. The reported capacity must cover the
/// complete contiguous allocation returned to TLSF.
///
/// # Safety
///
/// Implementations must uphold [`FlexSource`]'s ownership and in-place growth
/// contracts and keep every reported byte writable for the heap lifetime.
pub unsafe trait HeapSource: FlexSource {
    /// Complete currently committed byte length.
    fn capacity_bytes(&self) -> usize;

    /// Number of successful backing-store growth operations.
    fn growths(&self) -> u64;
}

/// Runtime-neutral source backed by one KEX application's virtual heap slot.
#[derive(Debug)]
pub struct ApplicationHeapSource {
    address: NonNull<u8>,
    mapped_bytes: usize,
    issued: bool,
    growths: u64,
}

impl ApplicationHeapSource {
    fn new(address: usize, mapped_bytes: usize) -> Result<Self, InitializationError> {
        Ok(Self {
            address: NonNull::new(address as *mut u8).ok_or(InitializationError::RegionTooSmall)?,
            mapped_bytes,
            issued: false,
            growths: 0,
        })
    }

    fn grow_to(&mut self, minimum_bytes: usize) -> Option<()> {
        if minimum_bytes <= self.mapped_bytes {
            return Some(());
        }
        let missing = minimum_bytes.checked_sub(self.mapped_bytes)?;
        let pages = growth_request_pages(missing)?;
        if pages == 0 {
            return Some(());
        }
        // SAFETY: `Heap` consumes the unique `HeapRegion` token and serializes
        // this source behind its mutable borrow. Every successful extension is
        // immediately returned to the same FlexTLSF instance.
        let mapped = unsafe { troe_kex_sdk::grow_heap(pages) }.ok()?;
        if mapped < minimum_bytes || mapped < self.mapped_bytes {
            return None;
        }
        self.mapped_bytes = mapped;
        self.growths = self.growths.saturating_add(1);
        Some(())
    }
}

fn growth_request_pages(missing_bytes: usize) -> Option<usize> {
    let required_pages = missing_bytes.checked_add(PAGE_BYTES - 1)? / PAGE_BYTES;
    Some(required_pages.max(GROWTH_QUANTUM_PAGES))
}

// SAFETY: The unique source owns one grow-only KEX virtual heap slot. The ABI
// never moves or unmaps committed pages during the application lifetime.
unsafe impl FlexSource for ApplicationHeapSource {
    unsafe fn alloc(&mut self, minimum_bytes: usize) -> Option<NonNull<[u8]>> {
        if self.issued {
            return None;
        }
        self.grow_to(minimum_bytes)?;
        self.issued = true;
        Some(NonNull::slice_from_raw_parts(
            self.address,
            self.mapped_bytes,
        ))
    }

    unsafe fn realloc_inplace_grow(
        &mut self,
        allocation: NonNull<[u8]>,
        minimum_bytes: usize,
    ) -> Option<usize> {
        if allocation.as_ptr().cast::<u8>() != self.address.as_ptr()
            || allocation.len() != self.mapped_bytes
        {
            return None;
        }
        self.grow_to(minimum_bytes)?;
        Some(self.mapped_bytes)
    }

    fn supports_realloc_inplace_grow(&self) -> bool {
        true
    }

    fn is_contiguous_growable(&self) -> bool {
        true
    }

    fn min_align(&self) -> usize {
        PAGE_BYTES
    }
}

// SAFETY: Capacity and growth counters describe the same allocation managed by
// the `FlexSource` implementation above.
unsafe impl HeapSource for ApplicationHeapSource {
    fn capacity_bytes(&self) -> usize {
        self.mapped_bytes
    }

    fn growths(&self) -> u64 {
        self.growths
    }
}

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
    /// Allocation or reallocation requests rejected after backing growth failed.
    pub failures: u64,
    /// Requested bytes copied when reallocation had to move a block.
    pub moved_bytes: u64,
    /// Successful backing-store growth operations.
    pub growths: u64,
}

/// One TLSF allocator owning one validated KEX heap region.
///
/// Allocation and deallocation are constant time. Reallocation is constant
/// time when it can resize in place and linear only when it must copy a block.
pub struct Heap<S: HeapSource = ApplicationHeapSource> {
    tlsf: ApplicationTlsf<S>,
    statistics: Statistics,
}

impl Heap<ApplicationHeapSource> {
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
        let source = ApplicationHeapSource::new(address, byte_len)?;
        Self::with_source(source)
    }
}

impl<S: HeapSource> Heap<S> {
    /// Initialize a heap from a runtime-specific growable backing store.
    ///
    /// This is the reusable construction point for libc and hosted tests.
    ///
    /// # Errors
    ///
    /// Returns [`InitializationError::RegionTooSmall`] when the source cannot
    /// provide TLSF's minimum pool representation.
    pub fn with_source(source: S) -> Result<Self, InitializationError> {
        let mut tlsf = ApplicationTlsf::new(source);
        let bootstrap_layout =
            Layout::from_size_align(1, 1).map_err(|_| InitializationError::RegionTooSmall)?;
        let bootstrap = tlsf
            .allocate(bootstrap_layout)
            .ok_or(InitializationError::RegionTooSmall)?;
        // SAFETY: `bootstrap` was just allocated with alignment one.
        unsafe { tlsf.deallocate(bootstrap, 1) };
        let capacity_bytes = tlsf.source_ref().capacity_bytes();
        Ok(Self {
            tlsf,
            statistics: Statistics {
                capacity_bytes,
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
    /// Returns `None` without changing existing allocations when backing growth
    /// cannot provide enough contiguous virtual space or the size cannot be
    /// represented.
    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let pointer = self.tlsf.allocate(layout);
        self.sync_source_statistics();
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
        self.sync_source_statistics();
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

    fn sync_source_statistics(&mut self) {
        self.statistics.capacity_bytes = self.tlsf.source_ref().capacity_bytes();
        self.statistics.growths = self.tlsf.source_ref().growths();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{Heap, HeapSource, growth_request_pages};
    use core::{alloc::Layout, mem::MaybeUninit, ptr::NonNull};
    use rlsf::FlexSource;
    use std::vec::Vec;

    #[repr(align(4096))]
    struct Pool<const N: usize>([MaybeUninit<u8>; N]);

    struct TestSource {
        start: NonNull<u8>,
        mapped: usize,
        maximum: usize,
        issued: bool,
        growths: u64,
    }

    // SAFETY: Tests keep the aligned backing pool alive and access it only
    // through the heap. Growth reveals an already allocated contiguous suffix.
    unsafe impl FlexSource for TestSource {
        unsafe fn alloc(&mut self, minimum: usize) -> Option<NonNull<[u8]>> {
            if self.issued || minimum > self.mapped {
                return None;
            }
            self.issued = true;
            Some(NonNull::slice_from_raw_parts(self.start, self.mapped))
        }

        unsafe fn realloc_inplace_grow(
            &mut self,
            allocation: NonNull<[u8]>,
            minimum: usize,
        ) -> Option<usize> {
            if allocation.as_ptr().cast::<u8>() != self.start.as_ptr()
                || allocation.len() != self.mapped
                || minimum > self.maximum
            {
                return None;
            }
            self.mapped = minimum.checked_add(4095)? / 4096 * 4096;
            if self.mapped > self.maximum {
                return None;
            }
            self.growths += 1;
            Some(self.mapped)
        }

        fn supports_realloc_inplace_grow(&self) -> bool {
            true
        }

        fn is_contiguous_growable(&self) -> bool {
            true
        }

        fn min_align(&self) -> usize {
            64
        }
    }

    // SAFETY: Counters report the exact test allocation managed above.
    unsafe impl HeapSource for TestSource {
        fn capacity_bytes(&self) -> usize {
            self.mapped
        }

        fn growths(&self) -> u64 {
            self.growths
        }
    }

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

    #[test]
    fn grows_a_generic_backing_source_and_preserves_allocations() {
        let mut pool = Pool([MaybeUninit::uninit(); 16 * 1024]);
        let source = TestSource {
            start: NonNull::new(pool.0.as_mut_ptr().cast::<u8>()).unwrap_or_else(|| unreachable!()),
            mapped: 4096,
            maximum: 16 * 1024,
            issued: false,
            growths: 0,
        };
        let mut heap = Heap::with_source(source).unwrap_or_else(|_| unreachable!());
        let first_layout = Layout::from_size_align(3000, 16).unwrap_or_else(|_| unreachable!());
        let first = heap
            .allocate(first_layout)
            .unwrap_or_else(|| unreachable!());
        // SAFETY: `first` owns 3000 writable bytes.
        unsafe { first.as_ptr().write_bytes(0xa5, first_layout.size()) };
        let second_layout =
            Layout::from_size_align(8 * 1024, 64).unwrap_or_else(|_| unreachable!());
        let second = heap
            .allocate(second_layout)
            .unwrap_or_else(|| unreachable!());
        assert!(second.as_ptr() as usize >= first.as_ptr() as usize + first_layout.size());
        // SAFETY: The first allocation remains live across source growth.
        let prefix = unsafe { core::slice::from_raw_parts(first.as_ptr(), first_layout.size()) };
        assert!(prefix.iter().all(|byte| *byte == 0xa5));
        assert!(heap.statistics().capacity_bytes > 4096);
        assert_eq!(heap.statistics().growths, 1);
    }

    #[test]
    fn oversized_growth_is_rejected_without_partial_capacity_change() {
        let mut pool = Pool([MaybeUninit::uninit(); 16 * 1024]);
        let source = TestSource {
            start: NonNull::new(pool.0.as_mut_ptr().cast::<u8>()).unwrap_or_else(|| unreachable!()),
            mapped: 4096,
            maximum: 8 * 1024,
            issued: false,
            growths: 0,
        };
        let mut heap = Heap::with_source(source).unwrap_or_else(|_| unreachable!());
        let oversized = Layout::from_size_align(12 * 1024, 64).unwrap_or_else(|_| unreachable!());
        assert!(heap.allocate(oversized).is_none());
        assert_eq!(heap.statistics().capacity_bytes, 4096);
        assert_eq!(heap.statistics().growths, 0);
        assert_eq!(heap.statistics().failures, 1);
    }

    #[test]
    fn large_request_is_not_split_into_growth_quanta() {
        assert_eq!(growth_request_pages(1), Some(64));
        assert_eq!(growth_request_pages(256 * 1024), Some(64));
        assert_eq!(growth_request_pages(100 * 1024 * 1024), Some(25_600));
    }
}

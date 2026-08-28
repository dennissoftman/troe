//! Constant-time TLSF allocation over runtime-selected growable backing.
#![no_std]

use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, Ordering},
};
use rlsf::{FlexSource, FlexTlsf};
use troe_kex_sdk::{HeapRegion, PrivateMemory, private_memory};

const PAGE_BYTES: usize = 4096;
const GROWTH_QUANTUM_PAGES: usize = 64;
/// Allocation size at which independent private mappings avoid fragmenting the
/// contiguous TLSF arena. This is a tuning boundary, not a functional limit.
pub const PRIVATE_MAPPING_THRESHOLD_BYTES: usize = 8 * 1024 * 1024;
const MAPPED_ALLOCATION_MAGIC: u64 = 0x544d_4150_4b45_5831;
// 4-byte base alignment gives TLSF five granularity bits on 64-bit targets.
// Fifty-nine first-level classes therefore cover the complete `usize` domain
// instead of imposing the former approximately 32 MiB maximum block size.
type ApplicationTlsf<S> = FlexTlsf<S, u64, u16, 59, 16>;

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
    /// A global allocator was initialized more than once.
    AlreadyInitialized,
}

/// Dynamically initialized global allocator for allocation-using KEX runtimes.
///
/// The application declares one static instance with `#[global_allocator]`,
/// then initializes it exactly once from [`troe_kex_sdk::CommandContext::take_heap`]
/// before constructing any allocation-backed values.
pub struct GlobalAllocator {
    locked: AtomicBool,
    heap: UnsafeCell<Option<Heap>>,
}

impl GlobalAllocator {
    /// Construct one uninitialized allocator suitable for static storage.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            heap: UnsafeCell::new(None),
        }
    }

    /// Initialize this allocator from the application's unique heap region.
    ///
    /// # Errors
    ///
    /// Rejects insufficient backing or repeated initialization.
    pub fn initialize(&self, region: HeapRegion) -> Result<(), InitializationError> {
        self.lock();
        // SAFETY: the spin lock serializes every access to this cell.
        let slot = unsafe { &mut *self.heap.get() };
        if slot.is_some() {
            self.unlock();
            return Err(InitializationError::AlreadyInitialized);
        }
        let heap = match Heap::new(region) {
            Ok(heap) => heap,
            Err(error) => {
                self.unlock();
                return Err(error);
            }
        };
        *slot = Some(heap);
        self.unlock();
        Ok(())
    }

    fn lock(&self) {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl Default for GlobalAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: `locked` serializes all access to the interior heap.
unsafe impl Sync for GlobalAllocator {}

// SAFETY: successful initialization gives this object exclusive ownership of
// one KEX heap, and every allocator operation is serialized by `locked`.
unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.lock();
        // SAFETY: the spin lock serializes access to the cell.
        let pointer = unsafe { &mut *self.heap.get() }
            .as_mut()
            .and_then(|heap| heap.allocate(layout))
            .map_or(ptr::null_mut(), NonNull::as_ptr);
        self.unlock();
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some(pointer) = NonNull::new(pointer) else {
            return;
        };
        self.lock();
        // SAFETY: forwarded from `GlobalAlloc`; the lock selects the owning heap.
        if let Some(heap) = unsafe { &mut *self.heap.get() }.as_mut() {
            unsafe { heap.deallocate(pointer, layout) };
        }
        self.unlock();
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Some(pointer) = NonNull::new(pointer) else {
            return ptr::null_mut();
        };
        self.lock();
        // SAFETY: forwarded from `GlobalAlloc`; the lock selects the owning heap.
        let resized = unsafe { &mut *self.heap.get() }
            .as_mut()
            .and_then(|heap| unsafe { heap.reallocate(pointer, layout, new_size) })
            .map_or(ptr::null_mut(), NonNull::as_ptr);
        self.unlock();
        resized
    }
}

/// Exact requested-byte counters maintained around the TLSF allocator.
///
/// TLSF itself rounds blocks for alignment and metadata. `live_bytes` tracks
/// the sizes requested by the language runtime, while `capacity_bytes` is the
/// memory region accepted by TLSF.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Bytes in the heap pool accepted by TLSF during initialization.
    pub capacity_bytes: u64,
    /// Sum of requested sizes for currently live allocations.
    pub live_bytes: u64,
    /// Highest observed `live_bytes` value.
    pub high_water_bytes: u64,
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
    /// Bytes currently owned by independent private mappings.
    pub private_mapped_bytes: u64,
    /// Currently live independent private mappings.
    pub private_mappings: u64,
}

/// One TLSF allocator owning one validated KEX heap region.
///
/// Allocation and deallocation are constant time. Reallocation is constant
/// time when it can resize in place and linear only when it must copy a block.
pub struct Heap<S: HeapSource = ApplicationHeapSource> {
    tlsf: ApplicationTlsf<S>,
    private_memory: Option<PrivateMemory>,
    statistics: Statistics,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct MappedAllocationHeader {
    magic: u64,
    address: u64,
    page_count: u64,
    requested_bytes: u64,
    alignment: u64,
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

    /// Initialize TLSF and route large allocations through independent private
    /// mappings so one contiguous heap never becomes a functional ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`InitializationError::RegionTooSmall`] when the initial heap
    /// cannot hold TLSF's minimum free-block representation.
    pub fn new_with_private_memory(
        region: HeapRegion,
        private_memory: PrivateMemory,
    ) -> Result<Self, InitializationError> {
        let mut heap = Self::new(region)?;
        heap.private_memory = Some(private_memory);
        Ok(heap)
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
        let capacity_bytes = u64::try_from(tlsf.source_ref().capacity_bytes()).unwrap_or(u64::MAX);
        Ok(Self {
            tlsf,
            private_memory: None,
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
        if self.private_memory.is_some() && layout.size() >= PRIVATE_MAPPING_THRESHOLD_BYTES {
            let pointer = self.allocate_private(layout);
            if pointer.is_some() {
                self.statistics.allocations = self.statistics.allocations.saturating_add(1);
                self.add_live_bytes(layout.size());
            } else {
                self.statistics.failures = self.statistics.failures.saturating_add(1);
            }
            return pointer;
        }
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
        if self.private_memory.is_some() && layout.size() >= PRIVATE_MAPPING_THRESHOLD_BYTES {
            if self.deallocate_private(pointer, layout) {
                self.statistics.live_bytes = self
                    .statistics
                    .live_bytes
                    .saturating_sub(u64::try_from(layout.size()).unwrap_or(u64::MAX));
                self.statistics.deallocations = self.statistics.deallocations.saturating_add(1);
            } else {
                self.statistics.failures = self.statistics.failures.saturating_add(1);
            }
            return;
        }
        // SAFETY: The caller upholds TLSF's pointer and alignment contract.
        unsafe { self.tlsf.deallocate(pointer, layout.align()) };
        self.statistics.live_bytes = self
            .statistics
            .live_bytes
            .saturating_sub(u64::try_from(layout.size()).unwrap_or(u64::MAX));
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
        let old_private =
            self.private_memory.is_some() && old_layout.size() >= PRIVATE_MAPPING_THRESHOLD_BYTES;
        let new_private =
            self.private_memory.is_some() && new_size >= PRIVATE_MAPPING_THRESHOLD_BYTES;
        if old_private || new_private {
            let new_pointer = self.allocate(new_layout)?;
            // SAFETY: Both allocations are live and disjoint, and the smaller
            // requested span is initialized according to the allocator contract.
            unsafe {
                ptr::copy_nonoverlapping(
                    pointer.as_ptr(),
                    new_pointer.as_ptr(),
                    old_layout.size().min(new_size),
                );
                self.deallocate(pointer, old_layout);
            }
            self.statistics.reallocations = self.statistics.reallocations.saturating_add(1);
            self.statistics.moved_bytes = self
                .statistics
                .moved_bytes
                .saturating_add(u64::try_from(old_layout.size().min(new_size)).unwrap_or(u64::MAX));
            return Some(new_pointer);
        }
        // SAFETY: The caller upholds TLSF's pointer and alignment contract.
        let resized = unsafe { self.tlsf.reallocate(pointer, new_layout) };
        self.sync_source_statistics();
        let Some(new_pointer) = resized else {
            self.statistics.failures = self.statistics.failures.saturating_add(1);
            return None;
        };
        self.statistics.reallocations = self.statistics.reallocations.saturating_add(1);
        self.statistics.live_bytes = self
            .statistics
            .live_bytes
            .saturating_sub(u64::try_from(old_layout.size()).unwrap_or(u64::MAX));
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
        self.statistics.live_bytes = self
            .statistics
            .live_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        self.statistics.high_water_bytes = self
            .statistics
            .high_water_bytes
            .max(self.statistics.live_bytes);
    }

    fn sync_source_statistics(&mut self) {
        self.statistics.capacity_bytes =
            u64::try_from(self.tlsf.source_ref().capacity_bytes()).unwrap_or(u64::MAX);
        self.statistics.growths = self.tlsf.source_ref().growths();
    }

    fn allocate_private(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let header_bytes = core::mem::size_of::<MappedAllocationHeader>();
        let total = layout
            .size()
            .checked_add(header_bytes)?
            .checked_add(layout.align().checked_sub(1)?)?;
        let page_count = total.checked_add(PAGE_BYTES - 1)? / PAGE_BYTES;
        let page_count = u64::try_from(page_count).ok()?;
        let memory = self.private_memory.as_mut()?;
        let address = memory
            .map_zeroed(page_count, 1, 0, private_memory::Protection::ReadWrite)
            .ok()?;
        let initialized = (|| {
            let raw = usize::try_from(address).ok()?;
            let alignment_mask = layout.align().checked_sub(1)?;
            let payload = raw.checked_add(header_bytes)?;
            let aligned = payload.checked_add(alignment_mask)? & !alignment_mask;
            let header_address = aligned.checked_sub(header_bytes)?;
            let pointer = NonNull::new(aligned as *mut u8)?;
            let header = MappedAllocationHeader {
                magic: MAPPED_ALLOCATION_MAGIC,
                address,
                page_count,
                requested_bytes: u64::try_from(layout.size()).ok()?,
                alignment: u64::try_from(layout.align()).ok()?,
            };
            let mapped_bytes = page_count.checked_mul(PAGE_BYTES as u64)?;
            Some((pointer, header_address, header, mapped_bytes))
        })();
        let Some((pointer, header_address, header, mapped_bytes)) = initialized else {
            let _cleaned = memory.unmap(address, page_count);
            return None;
        };
        // SAFETY: The header lies inside the fresh writable zeroed mapping and
        // precedes the aligned payload without overlap.
        unsafe {
            (header_address as *mut MappedAllocationHeader).write_unaligned(header);
        }
        self.statistics.private_mapped_bytes = self
            .statistics
            .private_mapped_bytes
            .saturating_add(mapped_bytes);
        self.statistics.private_mappings = self.statistics.private_mappings.saturating_add(1);
        Some(pointer)
    }

    fn deallocate_private(&mut self, pointer: NonNull<u8>, layout: Layout) -> bool {
        let Some(header_address) =
            (pointer.as_ptr() as usize).checked_sub(core::mem::size_of::<MappedAllocationHeader>())
        else {
            return false;
        };
        // SAFETY: The allocator contract requires this live pointer and its
        // original layout, so the immediately preceding mapping header exists.
        let header = unsafe { (header_address as *const MappedAllocationHeader).read_unaligned() };
        if header.magic != MAPPED_ALLOCATION_MAGIC
            || header.requested_bytes != u64::try_from(layout.size()).unwrap_or(u64::MAX)
            || header.alignment != u64::try_from(layout.align()).unwrap_or(u64::MAX)
        {
            return false;
        }
        let Some(memory) = self.private_memory.as_mut() else {
            return false;
        };
        if memory.unmap(header.address, header.page_count).is_err() {
            return false;
        }
        let mapped_bytes = header.page_count.saturating_mul(PAGE_BYTES as u64);
        self.statistics.private_mapped_bytes = self
            .statistics
            .private_mapped_bytes
            .saturating_sub(mapped_bytes);
        self.statistics.private_mappings = self.statistics.private_mappings.saturating_sub(1);
        true
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

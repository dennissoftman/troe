//! Pointer, allocator, port-I/O, and MMIO boundary.

#[cfg(target_os = "uefi")]
extern crate alloc;

#[cfg(target_os = "uefi")]
use alloc::boxed::Box;
#[cfg(target_os = "uefi")]
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
#[cfg(target_os = "uefi")]
use core::cell::UnsafeCell;
#[cfg(target_os = "uefi")]
use core::hint::spin_loop;
use core::ptr;
use core::ptr::NonNull;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
use core::sync::atomic::AtomicU64;
#[cfg(target_os = "uefi")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
use troe_driver::IoPortResource;
#[cfg(target_os = "uefi")]
use troe_driver::{
    BoundedInputQueue, InputEvent, InputQueueConfig, InputQueueStats, InputSource,
    InterruptResource, MmioResource, QueueError,
};
#[cfg(any(test, target_os = "uefi"))]
use troe_memory::PhysicalRange;
#[cfg(target_os = "uefi")]
use troe_task::TaskStep;
#[cfg(target_os = "uefi")]
use troe_terminal::{
    Color, FramebufferDescriptor, FramebufferPixelFormat, PixelSurface, SurfaceError,
};
#[cfg(target_os = "uefi")]
use uefi::mem::memory_map::MemoryMapOwned;

#[cfg(target_os = "uefi")]
const UART_SPIN_LIMIT: usize = 1_000_000;
#[cfg(any(test, target_os = "uefi"))]
const MIN_OWNED_STACK_BYTES: u64 = 16 * 1024;

/// Failure to validate an owned stack before the one-way stack transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "uefi")]
pub enum StackSwitchError {
    /// The supplied range is too small for the kernel continuation.
    TooSmall,
    /// The range end cannot be represented by the active architecture.
    AddressUnsupported,
    /// The initial stack pointer would violate the platform ABI alignment.
    Unaligned,
}

/// Failure to validate a guarded cooperative-task stack payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
pub enum TaskStackError {
    /// The mapped payload is too small for a bounded task continuation step.
    TooSmall,
    /// The range end cannot be represented by the active architecture.
    AddressUnsupported,
    /// The stack top would violate the common platform ABI alignment.
    Unaligned,
}

/// Checked access failure while initializing or zeroizing owned physical RAM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "uefi")]
pub enum PhysicalMemoryError {
    /// Range or slice arithmetic cannot be represented by the machine.
    AddressUnsupported,
    /// Requested bytes fall outside the explicitly owned physical range.
    OutOfBounds,
}

#[cfg(target_os = "uefi")]
struct StackLaunch<T: 'static> {
    context: *mut T,
    entry: fn(&mut T) -> !,
}

#[cfg(target_os = "uefi")]
struct TaskCall<T> {
    context: *mut T,
    step: fn(&mut T) -> TaskStep,
}

type OwnedTlsf = rlsf::Tlsf<'static, u32, u16, 20, 16>;

/// Observable general-heap accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeapStats {
    /// Bytes in the owned heap arena.
    pub total_bytes: usize,
    /// Requested payload bytes currently live in the owned heap.
    pub used_bytes: usize,
    /// Maximum observed consumed bytes.
    pub high_water_bytes: usize,
    /// Allocation requests rejected by the owned heap.
    pub failed_allocations: usize,
}

/// Failure to establish checked post-handoff framebuffer access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "uefi")]
pub enum FramebufferError {
    /// The physical base cannot be represented by the active architecture.
    AddressUnsupported,
}

/// Exclusively owned post-handoff framebuffer surface.
#[derive(Debug)]
#[cfg(target_os = "uefi")]
pub struct OwnedFramebuffer {
    descriptor: FramebufferDescriptor,
    base: usize,
}

/// Failure to configure owned interrupt-driven input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "uefi")]
pub enum InputInterruptError {
    /// Portable queue metadata could not be allocated before IRQ enablement.
    QueueMetadataExhausted,
    /// The one-time input runtime was already initialized.
    AlreadyInitialized,
    /// A pinned platform resource descriptor was invalid.
    InvalidResource,
    /// The interrupt controller did not expose the required input line.
    InterruptLineUnavailable,
}

/// Failure to arm the architecture-owned application execution timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "uefi")]
pub enum ExecutionTimerError {
    /// The pinned CPU does not expose the required deadline facility.
    Unsupported,
    /// Frequency or deadline arithmetic could not be represented safely.
    InvalidFrequency,
    /// A required interrupt-controller resource is unavailable.
    InterruptUnavailable,
}

#[cfg(target_os = "uefi")]
impl From<QueueError> for InputInterruptError {
    fn from(_error: QueueError) -> Self {
        Self::QueueMetadataExhausted
    }
}

#[cfg(target_os = "uefi")]
struct InputQueueCell(UnsafeCell<Option<BoundedInputQueue>>);

// SAFETY: The boot CPU initializes this cell once with interrupts masked.
// Main-context access masks IRQ delivery, and interrupt gates enter with IRQs
// masked, so exactly one mutable reference exists on the current single CPU.
#[cfg(target_os = "uefi")]
unsafe impl Sync for InputQueueCell {}

#[cfg(target_os = "uefi")]
static INPUT_QUEUE: InputQueueCell = InputQueueCell(UnsafeCell::new(None));

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
static X86_TSC_TICKS_PER_MILLISECOND: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "uefi")]
impl OwnedFramebuffer {
    /// Construct access from previously validated copied GOP metadata.
    ///
    /// # Errors
    ///
    /// Fails if the framebuffer base is not representable on this target.
    pub fn new(descriptor: FramebufferDescriptor) -> Result<Self, FramebufferError> {
        let base = usize::try_from(descriptor.base_address())
            .map_err(|_| FramebufferError::AddressUnsupported)?;
        Ok(Self { descriptor, base })
    }
}

#[cfg(target_os = "uefi")]
impl PixelSurface for OwnedFramebuffer {
    fn dimensions(&self) -> (usize, usize) {
        (self.descriptor.width(), self.descriptor.height())
    }

    fn write_pixel(&mut self, x: usize, y: usize, color: Color) -> Result<(), SurfaceError> {
        if x >= self.descriptor.width() || y >= self.descriptor.height() {
            return Err(SurfaceError::Bounds);
        }
        let pixel = y
            .checked_mul(self.descriptor.stride())
            .and_then(|row| row.checked_add(x))
            .ok_or(SurfaceError::Overflow)?;
        let offset = pixel.checked_mul(4).ok_or(SurfaceError::Overflow)?;
        let end = offset.checked_add(4).ok_or(SurfaceError::Overflow)?;
        if end > self.descriptor.byte_len() {
            return Err(SurfaceError::Bounds);
        }
        let bytes = match self.descriptor.pixel_format() {
            FramebufferPixelFormat::Rgb => [color.red, color.green, color.blue, 0],
            FramebufferPixelFormat::Bgr => [color.blue, color.green, color.red, 0],
        };
        for (index, byte) in bytes.into_iter().enumerate() {
            let address = self
                .base
                .checked_add(offset)
                .and_then(|value| value.checked_add(index))
                .ok_or(SurfaceError::Overflow)?;
            // SAFETY: FramebufferDescriptor construction proved the complete
            // byte range and geometry, the checked offset is within that range,
            // the MMU maps it RW/NX, and this owned surface is the sole writer.
            unsafe { ptr::write_volatile(address as *mut u8, byte) };
        }
        Ok(())
    }
}

struct HeapState {
    tlsf: OwnedTlsf,
    start: usize,
    end: usize,
    used_bytes: usize,
    high_water_bytes: usize,
    failed_allocations: usize,
    initialized: bool,
}

impl HeapState {
    const fn empty() -> Self {
        Self {
            tlsf: OwnedTlsf::new(),
            start: 0,
            end: 0,
            used_bytes: 0,
            high_water_bytes: 0,
            failed_allocations: 0,
            initialized: false,
        }
    }

    unsafe fn initialize(&mut self, start: usize, byte_count: usize) -> bool {
        if self.initialized || byte_count < 2 * rlsf::GRANULARITY {
            return false;
        }
        let Some(end) = start.checked_add(byte_count) else {
            return false;
        };
        let Some(pointer) =
            NonNull::new(ptr::slice_from_raw_parts_mut(start as *mut u8, byte_count))
        else {
            return false;
        };
        // SAFETY: The caller grants this allocator exclusive ownership of the
        // writable arena for the allocator's static lifetime.
        let Some(accepted) = (unsafe { self.tlsf.insert_free_block_ptr(pointer) }) else {
            return false;
        };
        self.start = start;
        self.end = start + accepted.get().min(end - start);
        self.initialized = true;
        true
    }

    fn allocate(&mut self, layout: Layout) -> *mut u8 {
        if let Some(allocation) = self.tlsf.allocate(layout) {
            self.used_bytes = self.used_bytes.saturating_add(layout.size());
            self.high_water_bytes = self.high_water_bytes.max(self.used_bytes);
            return allocation.as_ptr();
        }
        self.failed_allocations = self.failed_allocations.saturating_add(1);
        ptr::null_mut()
    }

    unsafe fn deallocate(&mut self, allocation: *mut u8, layout: Layout) {
        let Some(allocation) = NonNull::new(allocation) else {
            return;
        };
        // SAFETY: GlobalAlloc requires a unique pointer returned with the same
        // layout, satisfying TLSF's deallocation contract.
        unsafe { self.tlsf.deallocate(allocation, layout.align()) };
        self.used_bytes = self.used_bytes.saturating_sub(layout.size());
    }

    #[cfg(target_os = "uefi")]
    const fn contains(&self, address: usize) -> bool {
        self.initialized && address >= self.start && address < self.end
    }

    const fn stats(&self) -> HeapStats {
        HeapStats {
            total_bytes: self.end - self.start,
            used_bytes: self.used_bytes,
            high_water_bytes: self.high_water_bytes,
            failed_allocations: self.failed_allocations,
        }
    }
}

#[cfg(target_os = "uefi")]
struct LockedHeap {
    held: AtomicBool,
    state: UnsafeCell<HeapState>,
}

// SAFETY: Every access to the UnsafeCell is serialized by `held`.
#[cfg(target_os = "uefi")]
unsafe impl Sync for LockedHeap {}

#[cfg(target_os = "uefi")]
impl LockedHeap {
    const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            state: UnsafeCell::new(HeapState::empty()),
        }
    }

    fn with<R>(&self, operation: impl FnOnce(&mut HeapState) -> R) -> R {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        // SAFETY: This thread holds the exclusive lock until after the closure.
        let result = operation(unsafe { &mut *self.state.get() });
        self.held.store(false, Ordering::Release);
        result
    }
}

#[cfg(target_os = "uefi")]
static HEAP: LockedHeap = LockedHeap::new();
#[cfg(target_os = "uefi")]
struct HybridAllocator;
#[cfg(target_os = "uefi")]
static FIRMWARE_EXITED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "uefi")]
#[global_allocator]
static GLOBAL_ALLOCATOR: HybridAllocator = HybridAllocator;

// SAFETY: Owned allocations are serialized and non-overlapping. Before heap
// initialization, requests delegate to UEFI's matching allocator. Deallocation
// distinguishes owned pointers from pre-handoff firmware allocations.
#[cfg(target_os = "uefi")]
unsafe impl GlobalAlloc for HybridAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let initialized = HEAP.with(|heap| heap.initialized);
        if initialized {
            return HEAP.with(|heap| heap.allocate(layout));
        }
        if FIRMWARE_EXITED.load(Ordering::Acquire) {
            return ptr::null_mut();
        }
        // SAFETY: Boot services are still active and this exact allocator will
        // handle any matching pre-handoff deallocation.
        unsafe { uefi::allocator::Allocator.alloc(layout) }
    }

    unsafe fn dealloc(&self, allocation: *mut u8, layout: Layout) {
        if HEAP.with(|heap| heap.contains(allocation as usize)) {
            // SAFETY: The pointer belongs to the owned heap and GlobalAlloc's
            // contract guarantees a matching, unique deallocation.
            HEAP.with(|heap| unsafe { heap.deallocate(allocation, layout) });
        } else if !FIRMWARE_EXITED.load(Ordering::Acquire) {
            // SAFETY: This is a pre-heap pointer created by the UEFI allocator
            // while boot services remain active.
            unsafe { uefi::allocator::Allocator.dealloc(allocation, layout) };
        }
        // Non-heap allocations still alive at handoff become permanent loader
        // reservations; they must never be returned through dead boot services.
    }
}

/// Install the owned general heap over an exclusively reserved writable arena.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn initialize_heap(start: usize, byte_count: usize) -> bool {
    HEAP.with(|heap| {
        // SAFETY: The boot composition root supplies a fresh UEFI page
        // allocation and never aliases it after this ownership transfer.
        unsafe { heap.initialize(start, byte_count) }
    })
}

/// Prevent all future fallback to the UEFI allocator.
#[cfg(target_os = "uefi")]
pub fn mark_firmware_exited() {
    FIRMWARE_EXITED.store(true, Ordering::Release);
}

/// Return a consistent snapshot of general-heap counters.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn heap_stats() -> HeapStats {
    HEAP.with(|heap| heap.stats())
}

/// Verify that an impossible owned-heap request fails without invoking panic.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn probe_allocation_failure() -> bool {
    let stats = heap_stats();
    let Ok(layout) = Layout::from_size_align(stats.total_bytes.saturating_add(1), 8) else {
        return true;
    };
    // SAFETY: Direct allocation is checked for null and would be returned with
    // the matching layout if an implementation unexpectedly satisfied it.
    let allocation = unsafe { GLOBAL_ALLOCATOR.alloc(layout) };
    if allocation.is_null() {
        true
    } else {
        // SAFETY: This pointer came from the immediately preceding call.
        unsafe { GLOBAL_ALLOCATOR.dealloc(allocation, layout) };
        false
    }
}

/// Capture the final map and perform the one-way firmware handoff.
///
/// This internal composition boundary must be called only after all protocol
/// borrows have ended. The kernel calls it once, immediately before switching
/// every console and fatal path to this crate's native mechanisms.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn exit_boot_services_after_protocols() -> MemoryMapOwned {
    // SAFETY: The sole call site holds no UEFI protocol references, has already
    // installed the owned heap and native fatal console, and never invokes a
    // boot service after this returns.
    unsafe { uefi::boot::exit_boot_services(None) }
}

/// Move execution to a reserved stack and invoke a continuation that cannot return.
///
/// The context must live independently of the firmware stack. Validation failures
/// are reported before the stack pointer changes; a successful transition never
/// returns to its caller.
///
/// # Errors
///
/// Rejects a stack that is too small, unrepresentable, or ABI-misaligned.
#[cfg(target_os = "uefi")]
pub fn enter_owned_stack<T: 'static>(
    stack: PhysicalRange,
    context: &'static mut T,
    entry: fn(&mut T) -> !,
) -> Result<core::convert::Infallible, StackSwitchError> {
    if stack.byte_count() < MIN_OWNED_STACK_BYTES {
        return Err(StackSwitchError::TooSmall);
    }
    let stack_top =
        usize::try_from(stack.end()).map_err(|_| StackSwitchError::AddressUnsupported)?;
    if !stack_top.is_multiple_of(16) {
        return Err(StackSwitchError::Unaligned);
    }
    let launch = Box::leak(Box::new(StackLaunch {
        context: ptr::from_mut(context),
        entry,
    }));
    architecture_enter_owned_stack(
        stack_top,
        ptr::from_mut(launch).cast::<()>() as usize,
        stack_trampoline::<T> as *const () as usize,
    )
}

#[cfg(target_os = "uefi")]
extern "C" fn stack_trampoline<T: 'static>(launch: usize) -> ! {
    // SAFETY: `enter_owned_stack` leaks one unique `StackLaunch<T>` immediately
    // before transferring its address here; this continuation is non-returning.
    let launch = unsafe { &mut *(launch as *mut StackLaunch<T>) };
    // SAFETY: The caller supplied a unique static context, and the non-returning
    // transition makes this the only continuation that can access it.
    let context = unsafe { &mut *launch.context };
    (launch.entry)(context)
}

/// Execute one explicit continuation step on a task-owned guarded stack.
///
/// Cooperative tasks retain durable state in `context`. A yielded step returns
/// through this synchronous boundary, discarding only that step's native stack
/// frames. The scheduler can later invoke the continuation again on the same
/// stack. This keeps context switching architecture-local without exposing raw
/// saved-register state to portable code.
///
/// # Errors
///
/// Rejects a mapped stack payload that is too small, unrepresentable, or
/// improperly aligned. Guard pages are omitted from `stack` and remain the
/// mapping owner's responsibility.
#[cfg(target_os = "uefi")]
pub fn run_task_step<T>(
    stack: PhysicalRange,
    context: &mut T,
    step: fn(&mut T) -> TaskStep,
) -> Result<TaskStep, TaskStackError> {
    let stack_top = validate_task_stack(stack)?;
    let mut call = TaskCall {
        context: ptr::from_mut(context),
        step,
    };
    let raw = architecture_run_task_step(
        stack_top,
        ptr::from_mut(&mut call).cast::<()>() as usize,
        task_step_trampoline::<T> as *const () as usize,
    );
    match raw {
        0 => Ok(TaskStep::Yield),
        1 => Ok(TaskStep::ExitSuccess),
        _ => Ok(TaskStep::ExitFailure),
    }
}

#[cfg(target_os = "uefi")]
extern "C" fn task_step_trampoline<T>(call: usize) -> usize {
    // SAFETY: `run_task_step` supplies a unique live `TaskCall<T>` and waits
    // synchronously for this trampoline before accessing either value again.
    let call = unsafe { &mut *(call as *mut TaskCall<T>) };
    // SAFETY: The originating unique borrow of `context` remains suspended
    // across this stack call and the trampoline is its only active accessor.
    let context = unsafe { &mut *call.context };
    (call.step)(context) as usize
}

#[cfg(any(test, target_os = "uefi"))]
fn validate_task_stack(stack: PhysicalRange) -> Result<usize, TaskStackError> {
    if stack.byte_count() < MIN_OWNED_STACK_BYTES {
        return Err(TaskStackError::TooSmall);
    }
    let stack_top = usize::try_from(stack.end()).map_err(|_| TaskStackError::AddressUnsupported)?;
    if !stack_top.is_multiple_of(16) {
        return Err(TaskStackError::Unaligned);
    }
    Ok(stack_top)
}

/// Zero every byte in one kernel-owned, identity-mapped physical range.
///
/// This is used both before exposing frames to an unprivileged address space
/// and before returning them to the general frame allocator.
///
/// # Errors
///
/// Rejects unrepresentable or pointer-sized ranges before changing memory.
#[cfg(target_os = "uefi")]
pub fn zero_physical_range(range: PhysicalRange) -> Result<(), PhysicalMemoryError> {
    let start =
        usize::try_from(range.start()).map_err(|_| PhysicalMemoryError::AddressUnsupported)?;
    let byte_count =
        usize::try_from(range.byte_count()).map_err(|_| PhysicalMemoryError::AddressUnsupported)?;
    if byte_count > isize::MAX as usize || start.checked_add(byte_count).is_none() {
        return Err(PhysicalMemoryError::AddressUnsupported);
    }
    // SAFETY: The caller owns this complete identity-mapped physical range;
    // validation proves a non-wrapping pointer-sized byte span.
    unsafe { ptr::write_bytes(start as *mut u8, 0, byte_count) };
    Ok(())
}

/// Copy initialized bytes into one kernel-owned, identity-mapped range.
///
/// # Errors
///
/// Rejects offset/range overflow or any request outside `range` before writing.
#[cfg(target_os = "uefi")]
pub fn copy_to_physical(
    range: PhysicalRange,
    offset: usize,
    bytes: &[u8],
) -> Result<(), PhysicalMemoryError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let start =
        usize::try_from(range.start()).map_err(|_| PhysicalMemoryError::AddressUnsupported)?;
    let range_bytes =
        usize::try_from(range.byte_count()).map_err(|_| PhysicalMemoryError::AddressUnsupported)?;
    let end = offset
        .checked_add(bytes.len())
        .ok_or(PhysicalMemoryError::OutOfBounds)?;
    if end > range_bytes || range_bytes > isize::MAX as usize {
        return Err(PhysicalMemoryError::OutOfBounds);
    }
    let destination = start
        .checked_add(offset)
        .ok_or(PhysicalMemoryError::AddressUnsupported)?;
    // SAFETY: Complete source and destination spans are valid and disjoint:
    // safe Rust owns `bytes`, while `range` names externally owned physical RAM.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), destination as *mut u8, bytes.len()) };
    Ok(())
}

/// Mask architecture interrupts before replacing firmware exception state.
#[cfg(target_os = "uefi")]
pub fn take_interrupt_ownership() {
    architecture_take_interrupt_ownership();
}

/// Read the active stack pointer for ownership assertions.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn current_stack_pointer() -> usize {
    architecture_stack_pointer()
}

/// Initialize the native recovery UART selected by the active machine profile.
#[cfg(target_os = "uefi")]
pub fn initialize_console() {
    architecture_initialize_console();
}

/// Write bytes through the architecture-native polling UART.
///
/// Returns false if transmit readiness does not arrive within a fixed bound.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn write(bytes: &[u8]) -> bool {
    bytes.iter().copied().all(write_byte)
}

/// Block until one byte arrives from the architecture-native polling UART.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn read_byte() -> u8 {
    loop {
        if let Some(byte) = try_read_byte() {
            return byte;
        }
        spin_loop();
    }
}

/// Poll one byte from the architecture-native UART without blocking.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn try_read_byte() -> Option<u8> {
    architecture_try_read_byte()
}

/// Poll one native keyboard scan-code byte without blocking.
///
/// The pinned x86-64 q35 profile exposes a first PS/2 controller. The current
/// `AArch64` `virt` profile has no architecture-neutral keyboard transport yet.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn try_read_keyboard_scancode() -> Option<u8> {
    #[cfg(target_arch = "x86_64")]
    {
        let Ok(profile) = x86_input_profile() else {
            return None;
        };
        let data = profile.keyboard_ports.base_port();
        let status_port = data + 4;
        // SAFETY: The pinned q35 profile owns the legacy i8042 controller.
        let status = unsafe { port_read(status_port) };
        if status & 1 == 0 || status & (1 << 5) != 0 {
            None
        } else {
            // SAFETY: The status register reports one keyboard byte available.
            Some(unsafe { port_read(data) })
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        None
    }
}

/// Device-memory ranges required by the pinned interrupt-controller profile.
///
/// Empty array slots permit profiles with one contiguous controller aperture.
///
/// # Errors
///
/// Returns a typed failure if a pinned resource cannot form a checked page
/// range.
#[cfg(target_os = "uefi")]
pub fn input_device_ranges() -> Result<[Option<PhysicalRange>; 2], InputInterruptError> {
    architecture_input_device_ranges()
}

/// Preallocate the input queue, own the platform interrupt controller, and
/// enable receive interrupts.
///
/// # Errors
///
/// Fails atomically before global IRQ enablement if queue allocation, one-time
/// initialization, or platform resource validation fails.
#[cfg(target_os = "uefi")]
pub fn initialize_input_interrupts(config: InputQueueConfig) -> Result<(), InputInterruptError> {
    let queue = BoundedInputQueue::try_new(config)?;
    // SAFETY: Boot reaches this one-time initialization with architecture IRQs
    // masked. No interrupt entry or main-context consumer can access the cell.
    unsafe {
        let slot = &mut *INPUT_QUEUE.0.get();
        if slot.is_some() {
            return Err(InputInterruptError::AlreadyInitialized);
        }
        *slot = Some(queue);
    }
    architecture_initialize_input_interrupts(config)
}

/// Block in the architecture idle instruction until one queued input event is
/// available.
///
/// The empty check and IRQ-enable/sleep transition exclude a lost wakeup.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn wait_for_input_event() -> InputEvent {
    architecture_mask_input_interrupts();
    loop {
        // SAFETY: IRQ delivery is masked on the single boot CPU, so the main
        // consumer has exclusive access to the initialized queue.
        if let Some(event) = unsafe { input_queue_mut() }.and_then(BoundedInputQueue::pop) {
            architecture_enable_input_interrupts();
            return event;
        }
        // SAFETY: IRQ delivery remains masked, so main context retains
        // exclusive access while accounting the sleep transition.
        if let Some(queue) = unsafe { input_queue_mut() } {
            queue.record_idle_wait();
        }
        architecture_wait_for_input_interrupt();
        // The architecture helper returns with IRQ delivery masked again.
        // SAFETY: Main context therefore has exclusive queue access.
        if let Some(queue) = unsafe { input_queue_mut() } {
            queue.record_wakeup();
        }
    }
}

/// Return one queued input event without blocking.
#[cfg(target_os = "uefi")]
pub fn try_input_event() -> Option<InputEvent> {
    architecture_mask_input_interrupts();
    // SAFETY: IRQ delivery is masked on the single boot CPU.
    let event = unsafe { input_queue_mut() }.and_then(BoundedInputQueue::pop);
    architecture_enable_input_interrupts();
    event
}

/// Read milliseconds elapsed on the architecture monotonic counter.
///
/// Returns `None` when the pinned CPU does not report a usable counter
/// frequency. The value has no wall-clock meaning and is stable only for this
/// boot.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn monotonic_millis() -> Option<u64> {
    architecture_monotonic_millis()
}

/// Establish the architecture monotonic-counter frequency before firmware
/// boot services are released.
///
/// x86 uses CPUID when complete and otherwise measures TSC advancement across
/// one firmware-provided 10 ms stall. `AArch64` validates its architected counter
/// frequency directly.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn initialize_monotonic_clock() -> bool {
    architecture_initialize_monotonic_clock()
}

/// Snapshot interrupt input accounting without racing an interrupt producer.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn input_interrupt_stats() -> Option<InputQueueStats> {
    architecture_mask_input_interrupts();
    // SAFETY: IRQ delivery is masked on the single boot CPU.
    let stats = unsafe { input_queue_mut() }.map(|queue| queue.stats());
    architecture_enable_input_interrupts();
    stats
}

/// Dispatch one owned architecture interrupt into the bounded raw-event queue.
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
pub(crate) fn handle_input_interrupt() {
    // SAFETY: Architecture interrupt gates enter with IRQ delivery masked and
    // initialization enables a source only after installing this queue.
    if let Some(queue) = unsafe { input_queue_mut() } {
        let _timer = architecture_handle_input_interrupt(queue);
    }
}

/// Dispatch an interrupt taken during unprivileged application execution.
///
/// Returns `true` only for the owned execution-lease timer. Input interrupts
/// are serviced normally and return `false` so the application can resume.
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
pub(crate) fn handle_application_interrupt() -> bool {
    // SAFETY: The native interrupt entry masks nested IRQ delivery and the
    // single boot CPU is the only producer or consumer at this boundary.
    unsafe { input_queue_mut() }.is_some_and(architecture_handle_input_interrupt)
}

/// Arm a one-shot execution lease for unprivileged application code.
#[cfg(target_os = "uefi")]
pub(crate) fn arm_execution_timer(milliseconds: u32) -> Result<(), ExecutionTimerError> {
    if milliseconds == 0 {
        return Err(ExecutionTimerError::InvalidFrequency);
    }
    architecture_arm_execution_timer(milliseconds)
}

/// Disable the one-shot execution timer before doing kernel work.
#[cfg(target_os = "uefi")]
pub(crate) fn disarm_execution_timer() {
    architecture_disarm_execution_timer();
}

/// Complete controller acknowledgement for an execution-timer interrupt.
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
pub(crate) fn acknowledge_execution_timer_interrupt() {
    architecture_acknowledge_execution_timer_interrupt();
}

#[cfg(target_os = "uefi")]
unsafe fn input_queue_mut() -> Option<&'static mut BoundedInputQueue> {
    // SAFETY: Callers establish single-CPU exclusion by boot state or IRQ mask.
    unsafe { (&mut *INPUT_QUEUE.0.get()).as_mut() }
}

/// Park the current CPU permanently after an authorized halt.
#[cfg(target_os = "uefi")]
pub fn park() -> ! {
    loop {
        architecture_park();
    }
}

#[cfg(target_os = "uefi")]
fn resource_page_range(resource: MmioResource) -> Result<PhysicalRange, InputInterruptError> {
    if !resource
        .base_address()
        .is_multiple_of(troe_memory::BASE_PAGE_SIZE)
        || !resource
            .byte_len()
            .is_multiple_of(troe_memory::BASE_PAGE_SIZE)
    {
        return Err(InputInterruptError::InvalidResource);
    }
    PhysicalRange::from_pages(
        resource.base_address(),
        resource.byte_len() / troe_memory::BASE_PAGE_SIZE,
    )
    .map_err(|_| InputInterruptError::InvalidResource)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
pub(crate) const X86_KEYBOARD_VECTOR: u8 = 0x31;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
pub(crate) const X86_SERIAL_VECTOR: u8 = 0x34;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
pub(crate) const X86_TIMER_VECTOR: u8 = 0x30;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
pub(crate) const X86_SPURIOUS_VECTOR: u8 = 0xff;

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
struct X86InputProfile {
    lapic: MmioResource,
    ioapic: MmioResource,
    keyboard_ports: IoPortResource,
    serial_ports: IoPortResource,
    pit_ports: IoPortResource,
    system_control_port: IoPortResource,
    keyboard_interrupt: InterruptResource,
    serial_interrupt: InterruptResource,
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_input_profile() -> Result<X86InputProfile, InputInterruptError> {
    Ok(X86InputProfile {
        lapic: MmioResource::new(0xfee0_0000, 0x1000)
            .map_err(|_| InputInterruptError::InvalidResource)?,
        ioapic: MmioResource::new(0xfec0_0000, 0x1000)
            .map_err(|_| InputInterruptError::InvalidResource)?,
        keyboard_ports: IoPortResource::new(0x0060, 5)
            .map_err(|_| InputInterruptError::InvalidResource)?,
        serial_ports: IoPortResource::new(0x03f8, 8)
            .map_err(|_| InputInterruptError::InvalidResource)?,
        pit_ports: IoPortResource::new(0x0040, 4)
            .map_err(|_| InputInterruptError::InvalidResource)?,
        system_control_port: IoPortResource::new(0x0061, 1)
            .map_err(|_| InputInterruptError::InvalidResource)?,
        keyboard_interrupt: InterruptResource::new(1, X86_KEYBOARD_VECTOR)
            .map_err(|_| InputInterruptError::InvalidResource)?,
        serial_interrupt: InterruptResource::new(4, X86_SERIAL_VECTOR)
            .map_err(|_| InputInterruptError::InvalidResource)?,
    })
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_input_device_ranges() -> Result<[Option<PhysicalRange>; 2], InputInterruptError> {
    let profile = x86_input_profile()?;
    Ok([
        Some(resource_page_range(profile.lapic)?),
        Some(resource_page_range(profile.ioapic)?),
    ])
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_initialize_input_interrupts(
    _config: InputQueueConfig,
) -> Result<(), InputInterruptError> {
    const LAPIC_ID: usize = 0x020;
    const LAPIC_SPURIOUS: usize = 0x0f0;
    const LAPIC_SOFTWARE_ENABLE: u32 = 1 << 8;
    let profile = x86_input_profile()?;

    // SAFETY: The pinned q35 profile assigns the legacy PIC mask registers;
    // masking both controllers prevents firmware-era PIC delivery.
    unsafe {
        port_write(0x21, 0xff);
        port_write(0xa1, 0xff);
    }

    let ioapic_version = x86_ioapic_read(profile.ioapic, 1);
    let maximum_entry = (ioapic_version >> 16) & 0xff;
    if profile.keyboard_interrupt.line() > maximum_entry
        || profile.serial_interrupt.line() > maximum_entry
    {
        return Err(InputInterruptError::InterruptLineUnavailable);
    }
    for line in 0..=maximum_entry {
        x86_ioapic_write(profile.ioapic, 0x10 + line * 2, 1 << 16);
        x86_ioapic_write(profile.ioapic, 0x11 + line * 2, 0);
    }

    let lapic_base = usize::try_from(profile.lapic.base_address())
        .map_err(|_| InputInterruptError::InvalidResource)?;
    // SAFETY: The LAPIC page is mapped RW/NX as device memory before this call.
    let apic_id = unsafe { mmio_read32(lapic_base + LAPIC_ID) } >> 24;
    // SAFETY: The spurious-vector register belongs to the owned BSP LAPIC.
    unsafe {
        mmio_write32(
            lapic_base + LAPIC_SPURIOUS,
            LAPIC_SOFTWARE_ENABLE | u32::from(X86_SPURIOUS_VECTOR),
        );
    }
    x86_route_ioapic(profile.ioapic, profile.keyboard_interrupt, apic_id);
    x86_route_ioapic(profile.ioapic, profile.serial_interrupt, apic_id);

    // Retain bytes already present before enabling receive notification.
    // SAFETY: Initialization still runs with CPU interrupts masked.
    if let Some(queue) = unsafe { input_queue_mut() } {
        x86_drain_input_devices(queue);
    }
    // SAFETY: COM1's interrupt-enable register is owned by the pinned profile.
    unsafe {
        let serial_base = profile.serial_ports.base_port();
        port_write(serial_base + 1, 1);
    }
    architecture_enable_input_interrupts();
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_handle_input_interrupt(queue: &mut BoundedInputQueue) -> bool {
    const LAPIC_EOI: usize = 0x0b0;
    queue.record_interrupt();
    x86_drain_input_devices(queue);
    if let Ok(profile) = x86_input_profile()
        && let Ok(lapic_base) = usize::try_from(profile.lapic.base_address())
    {
        // SAFETY: Every routed input interrupt requires one LAPIC EOI write.
        unsafe { mmio_write32(lapic_base + LAPIC_EOI, 0) };
    }
    false
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_monotonic_millis() -> Option<u64> {
    let cached = X86_TSC_TICKS_PER_MILLISECOND.load(Ordering::Relaxed);
    let ticks_per_millisecond = if cached == 0 {
        let detected = x86_cpuid_tsc_frequency()
            .and_then(|frequency| frequency.checked_div(1_000))
            .filter(|ticks| *ticks != 0)?;
        X86_TSC_TICKS_PER_MILLISECOND.store(detected, Ordering::Relaxed);
        detected
    } else {
        cached
    };
    x86_read_tsc().checked_div(ticks_per_millisecond)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_initialize_monotonic_clock() -> bool {
    if let Some(ticks) = x86_cpuid_tsc_frequency()
        .and_then(|frequency| frequency.checked_div(1_000))
        .filter(|ticks| *ticks != 0)
    {
        X86_TSC_TICKS_PER_MILLISECOND.store(ticks, Ordering::Relaxed);
        return true;
    }
    let start = x86_read_tsc();
    uefi::boot::stall(core::time::Duration::from_millis(10));
    let Some(ticks_per_millisecond) = x86_read_tsc()
        .checked_sub(start)
        .and_then(|ticks| ticks.checked_div(10))
    else {
        return false;
    };
    if ticks_per_millisecond == 0 {
        return false;
    }
    X86_TSC_TICKS_PER_MILLISECOND.store(ticks_per_millisecond, Ordering::Relaxed);
    true
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_cpuid_tsc_frequency() -> Option<u64> {
    let maximum = core::arch::x86_64::__cpuid(0).eax;
    if maximum < 0x15 {
        return None;
    }
    let ratio = core::arch::x86_64::__cpuid(0x15);
    if ratio.eax != 0 && ratio.ebx != 0 && ratio.ecx != 0 {
        return u64::from(ratio.ecx)
            .checked_mul(u64::from(ratio.ebx))?
            .checked_div(u64::from(ratio.eax));
    }
    if maximum < 0x16 {
        return None;
    }
    u64::from(core::arch::x86_64::__cpuid(0x16).eax).checked_mul(1_000_000)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_read_tsc() -> u64 {
    let ticks: u64;
    // SAFETY: RDTSC reads the monotonically increasing invariant counter in
    // the pinned single-vCPU profiles. LFENCE orders it after prior work.
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") ticks,
            out("rdx") _,
            options(nomem, nostack)
        );
    }
    ticks
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_arm_execution_timer(milliseconds: u32) -> Result<(), ExecutionTimerError> {
    const LAPIC_LVT_TIMER: usize = 0x320;
    const LAPIC_INITIAL_COUNT: usize = 0x380;
    const LAPIC_CURRENT_COUNT: usize = 0x390;
    const LAPIC_DIVIDE_CONFIG: usize = 0x3e0;
    const LAPIC_MASKED: u32 = 1 << 16;
    const LAPIC_DIVIDE_BY_ONE: u32 = 0b1011;
    const PIT_CHANNEL_2_COMMAND: u8 = 0xb0;
    const PIT_TEN_MILLISECONDS: u16 = 11_932;
    const PIT_GATE_2: u8 = 1;
    const PIT_OUT_2: u8 = 1 << 5;
    const CALIBRATION_SPIN_LIMIT: usize = 10_000_000;
    let profile = x86_input_profile().map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let lapic = usize::try_from(profile.lapic.base_address())
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let pit_channel = profile.pit_ports.base_port() + 2;
    let pit_command = profile.pit_ports.base_port() + 3;
    let system_control = profile.system_control_port.base_port();
    // SAFETY: The typed PIT and system-control resources are owned by the
    // pinned q35 profile. Channel 2 is gated low while its one-shot is loaded.
    let original_control = unsafe { port_read(system_control) };
    unsafe {
        port_write(system_control, original_control & !PIT_GATE_2);
        port_write(pit_command, PIT_CHANNEL_2_COMMAND);
        port_write(pit_channel, PIT_TEN_MILLISECONDS.to_le_bytes()[0]);
        port_write(pit_channel, PIT_TEN_MILLISECONDS.to_le_bytes()[1]);
        mmio_write32(lapic + LAPIC_LVT_TIMER, LAPIC_MASKED);
        mmio_write32(lapic + LAPIC_DIVIDE_CONFIG, LAPIC_DIVIDE_BY_ONE);
        mmio_write32(lapic + LAPIC_INITIAL_COUNT, u32::MAX);
        port_write(system_control, (original_control & !0b10) | PIT_GATE_2);
    }
    let mut completed = false;
    for _ in 0..CALIBRATION_SPIN_LIMIT {
        // SAFETY: Polling the owned read-only channel-2 output latch.
        if unsafe { port_read(system_control) } & PIT_OUT_2 != 0 {
            completed = true;
            break;
        }
        spin_loop();
    }
    // SAFETY: Restore the exact pre-calibration system-control byte.
    unsafe { port_write(system_control, original_control) };
    if !completed {
        architecture_disarm_execution_timer();
        return Err(ExecutionTimerError::Unsupported);
    }
    // SAFETY: Reading the owned LAPIC current-count register has no side effect.
    let current = unsafe { mmio_read32(lapic + LAPIC_CURRENT_COUNT) };
    let elapsed = u64::from(u32::MAX - current);
    let lease_ticks = elapsed
        .checked_mul(u64::from(milliseconds))
        .and_then(|ticks| ticks.checked_div(10))
        .and_then(|ticks| u32::try_from(ticks).ok())
        .filter(|ticks| *ticks != 0)
        .ok_or(ExecutionTimerError::InvalidFrequency)?;
    // SAFETY: The vector is installed, divide state is fixed, and the checked
    // nonzero initial count selects one-shot mode by leaving mode bits clear.
    unsafe {
        mmio_write32(lapic + LAPIC_LVT_TIMER, u32::from(X86_TIMER_VECTOR));
        mmio_write32(lapic + LAPIC_INITIAL_COUNT, lease_ticks);
    }
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_disarm_execution_timer() {
    const LAPIC_LVT_TIMER: usize = 0x320;
    const LAPIC_INITIAL_COUNT: usize = 0x380;
    const LAPIC_MASKED: u32 = 1 << 16;
    if let Ok(profile) = x86_input_profile()
        && let Ok(lapic) = usize::try_from(profile.lapic.base_address())
    {
        // SAFETY: The kernel owns the LAPIC timer registers.
        unsafe {
            mmio_write32(lapic + LAPIC_LVT_TIMER, LAPIC_MASKED);
            mmio_write32(lapic + LAPIC_INITIAL_COUNT, 0);
        }
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_acknowledge_execution_timer_interrupt() {
    const LAPIC_EOI: usize = 0x0b0;
    if let Ok(profile) = x86_input_profile()
        && let Ok(lapic) = usize::try_from(profile.lapic.base_address())
    {
        // SAFETY: The active LAPIC timer interrupt requires one EOI write.
        unsafe { mmio_write32(lapic + LAPIC_EOI, 0) };
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_drain_input_devices(queue: &mut BoundedInputQueue) {
    let budget = queue.config().max_drain_per_interrupt();
    for _ in 0..budget {
        if let Some(byte) = try_read_keyboard_scancode() {
            let _result = queue.push(InputEvent::new(InputSource::Keyboard, byte));
            continue;
        }
        if let Some(byte) = architecture_try_read_byte() {
            let _result = queue.push(InputEvent::new(InputSource::Serial, byte));
            continue;
        }
        break;
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_route_ioapic(ioapic: MmioResource, interrupt: InterruptResource, apic_id: u32) {
    let register = 0x10 + interrupt.line() * 2;
    x86_ioapic_write(ioapic, register, 1 << 16);
    x86_ioapic_write(ioapic, register + 1, apic_id << 24);
    x86_ioapic_write(ioapic, register, u32::from(interrupt.vector()));
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_ioapic_read(ioapic: MmioResource, register: u32) -> u32 {
    let Ok(base) = usize::try_from(ioapic.base_address()) else {
        return 0;
    };
    // SAFETY: The IOAPIC selector/window registers are within the mapped page;
    // callers serialize access while interrupts are masked.
    unsafe {
        mmio_write32(base, register);
        mmio_read32(base + 0x10)
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_ioapic_write(ioapic: MmioResource, register: u32, value: u32) {
    let Ok(base) = usize::try_from(ioapic.base_address()) else {
        return;
    };
    // SAFETY: The IOAPIC selector/window registers are within the mapped page;
    // callers serialize access while interrupts are masked.
    unsafe {
        mmio_write32(base, register);
        mmio_write32(base + 0x10, value);
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_mask_input_interrupts() {
    // SAFETY: The boot CPU owns IF after firmware exit.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_enable_input_interrupts() {
    // SAFETY: IDT gates, queue, devices, and controllers are initialized first.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_wait_for_input_interrupt() {
    // SAFETY: STI delays maskable delivery through the following HLT boundary;
    // CLI remasks after wake so the queue can be checked exclusively.
    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const SERIAL_PORT: u16 = 0x03f8;

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_initialize_console() {
    // SAFETY: The pinned q35 profile exposes the standard COM1 register block.
    unsafe {
        port_write(SERIAL_PORT + 1, 0x00);
        port_write(SERIAL_PORT + 3, 0x80);
        port_write(SERIAL_PORT, 0x01);
        port_write(SERIAL_PORT + 1, 0x00);
        port_write(SERIAL_PORT + 3, 0x03);
        port_write(SERIAL_PORT + 2, 0xc7);
        port_write(SERIAL_PORT + 4, 0x0b);
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn write_byte(byte: u8) -> bool {
    for _ in 0..UART_SPIN_LIMIT {
        // SAFETY: The pinned q35 profile assigns COM1 at this legacy I/O range.
        if unsafe { port_read(SERIAL_PORT + 5) } & 0x20 != 0 {
            // SAFETY: The transmitter is ready and COM1 is exclusively owned.
            unsafe { port_write(SERIAL_PORT, byte) };
            return true;
        }
        spin_loop();
    }
    false
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_try_read_byte() -> Option<u8> {
    // SAFETY: The pinned q35 profile assigns COM1 at this legacy I/O range.
    if unsafe { port_read(SERIAL_PORT + 5) } & 1 == 0 {
        None
    } else {
        // SAFETY: The receiver reports one available byte.
        Some(unsafe { port_read(SERIAL_PORT) })
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_park() {
    // SAFETY: The terminal state owns interrupt policy and intentionally keeps
    // maskable interrupts disabled while halting forever.
    unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_take_interrupt_ownership() {
    // SAFETY: Boot services have ended, so firmware interrupt delivery must not
    // enter firmware handlers while the kernel replaces descriptor state.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_stack_pointer() -> usize {
    let stack_pointer: usize;
    // SAFETY: Reading RSP has no side effects.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
    }
    stack_pointer
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_enter_owned_stack(stack_top: usize, launch: usize, entry: usize) -> ! {
    // SAFETY: The validated range is exclusively reserved and the leaked launch
    // record outlives this non-returning transition. The call provides the x64
    // ABI shadow space and enters with the required stack alignment.
    unsafe {
        core::arch::asm!(
            "mov rsp, rax",
            "and rsp, -16",
            "sub rsp, 32",
            "call rdx",
            "ud2",
            in("rax") stack_top,
            in("rcx") launch,
            in("rdx") entry,
            options(noreturn),
        );
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_run_task_step(stack_top: usize, call: usize, entry: usize) -> usize {
    let result: usize;
    // SAFETY: `stack_top` is a validated, exclusively task-owned mapped range.
    // The old RSP is stored above the x64 ABI shadow space, the callback gets
    // the sole live call record in RCX, and RSP is restored before Rust resumes.
    unsafe {
        core::arch::asm!(
            "mov rax, rsp",
            "mov rsp, r8",
            "and rsp, -16",
            "sub rsp, 48",
            "mov [rsp + 32], rax",
            "mov rcx, r9",
            "call r10",
            "mov rsp, [rsp + 32]",
            in("r8") stack_top,
            in("r9") call,
            in("r10") entry,
            lateout("rax") result,
            clobber_abi("C"),
        );
    }
    result
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
unsafe fn port_read(port: u16) -> u8 {
    let value: u8;
    // SAFETY: The caller establishes that `port` is valid for byte input.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
unsafe fn port_write(port: u16, value: u8) {
    // SAFETY: The caller establishes that `port` is valid for byte output.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
unsafe fn mmio_read32(address: usize) -> u32 {
    // SAFETY: The caller proves that the address names an aligned mapped MMIO
    // register and owns the corresponding device operation.
    unsafe { ptr::read_volatile(address as *const u32) }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
unsafe fn mmio_write32(address: usize, value: u32) {
    // SAFETY: The caller proves that the address names an aligned writable MMIO
    // register and owns the corresponding device operation.
    unsafe { ptr::write_volatile(address as *mut u32, value) };
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
struct Aarch64InputProfile {
    gic: MmioResource,
    serial_interrupt: InterruptResource,
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn aarch64_input_profile() -> Result<Aarch64InputProfile, InputInterruptError> {
    Ok(Aarch64InputProfile {
        gic: MmioResource::new(0x0800_0000, 0x0002_0000)
            .map_err(|_| InputInterruptError::InvalidResource)?,
        serial_interrupt: InterruptResource::new(33, 32)
            .map_err(|_| InputInterruptError::InvalidResource)?,
    })
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_input_device_ranges() -> Result<[Option<PhysicalRange>; 2], InputInterruptError> {
    let profile = aarch64_input_profile()?;
    Ok([Some(resource_page_range(profile.gic)?), None])
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_initialize_input_interrupts(
    config: InputQueueConfig,
) -> Result<(), InputInterruptError> {
    const GICD_CTLR: usize = 0x000;
    const GICD_TYPER: usize = 0x004;
    const GICD_IGROUPR: usize = 0x080;
    const GICD_ISENABLER: usize = 0x100;
    const GICD_ICENABLER: usize = 0x180;
    const GICD_ICPENDR: usize = 0x280;
    const GICD_IPRIORITYR: usize = 0x400;
    const GICD_ITARGETSR: usize = 0x800;
    const GICD_ICFGR: usize = 0xc00;
    const GICC_CTLR: usize = 0x000;
    const GICC_PMR: usize = 0x004;
    const GICC_BPR: usize = 0x008;
    const GIC_CPU_OFFSET: usize = 0x1_0000;

    let profile = aarch64_input_profile()?;
    let distributor = usize::try_from(profile.gic.base_address())
        .map_err(|_| InputInterruptError::InvalidResource)?;
    let cpu = distributor + GIC_CPU_OFFSET;
    let intid = usize::try_from(profile.serial_interrupt.line())
        .map_err(|_| InputInterruptError::InvalidResource)?;

    // SAFETY: The complete pinned GICv2 aperture is mapped RW/NX as device
    // memory, and IRQ delivery remains masked during controller ownership.
    unsafe {
        mmio_write32(cpu + GICC_CTLR, 0);
        mmio_write32(distributor + GICD_CTLR, 0);
    }
    // SAFETY: GICD_TYPER is a read-only register inside the owned aperture.
    let typer = unsafe { mmio_read32(distributor + GICD_TYPER) };
    let register_count =
        usize::try_from((typer & 0x1f) + 1).map_err(|_| InputInterruptError::InvalidResource)?;
    let interrupt_count = register_count
        .checked_mul(32)
        .ok_or(InputInterruptError::InvalidResource)?;
    if intid >= interrupt_count {
        return Err(InputInterruptError::InterruptLineUnavailable);
    }
    for register in 0..register_count {
        let offset = register * 4;
        // SAFETY: TYPER bounds every implemented enable/pending register.
        unsafe {
            mmio_write32(distributor + GICD_ICENABLER + offset, u32::MAX);
            mmio_write32(distributor + GICD_ICPENDR + offset, u32::MAX);
        }
    }

    let word = intid / 32;
    let bit = 1_u32 << (intid % 32);
    // SAFETY: The selected INTID was checked against GICD_TYPER.
    unsafe {
        let group = mmio_read32(distributor + GICD_IGROUPR + word * 4);
        mmio_write32(distributor + GICD_IGROUPR + word * 4, group & !bit);
        gicv2_update_byte(
            distributor + GICD_IPRIORITYR,
            intid,
            config.interrupt_priority(),
        );
        gicv2_update_byte(distributor + GICD_ITARGETSR, intid, 0x01);
        let config_address = distributor + GICD_ICFGR + (intid / 16) * 4;
        let config_shift = (intid % 16) * 2;
        let config = mmio_read32(config_address) & !(0b10 << config_shift);
        mmio_write32(config_address, config);
        mmio_write32(distributor + GICD_ISENABLER + word * 4, bit);
        mmio_write32(cpu + GICC_PMR, 0xff);
        mmio_write32(cpu + GICC_BPR, 0);
        mmio_write32(cpu + GICC_CTLR, 1);
        mmio_write32(distributor + GICD_CTLR, 1);
    }

    // SAFETY: Initialization still runs with IRQ delivery masked.
    if let Some(queue) = unsafe { input_queue_mut() } {
        aarch64_drain_serial(queue);
    }
    // SAFETY: PL011 receive and receive-timeout mask bits are documented and
    // the device is mapped before this call.
    unsafe {
        mmio_write(
            PL011_INTERRUPT_MASK,
            PL011_RECEIVE_INTERRUPT | PL011_RECEIVE_TIMEOUT_INTERRUPT,
        );
        core::arch::asm!("dsb sy", "isb", options(nomem, nostack));
    }
    architecture_enable_input_interrupts();
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_handle_input_interrupt(queue: &mut BoundedInputQueue) -> bool {
    const GICC_IAR: usize = 0x00c;
    const GICC_EOIR: usize = 0x010;
    const GIC_CPU_OFFSET: usize = 0x1_0000;
    let Ok(profile) = aarch64_input_profile() else {
        return false;
    };
    let Ok(distributor) = usize::try_from(profile.gic.base_address()) else {
        return false;
    };
    let cpu = distributor + GIC_CPU_OFFSET;
    // SAFETY: GICC_IAR acknowledges the highest-priority pending interrupt.
    let acknowledge = unsafe { mmio_read32(cpu + GICC_IAR) };
    let intid = acknowledge & 0x03ff;
    let execution_timer = intid == AARCH64_EXECUTION_TIMER_INTID;
    if execution_timer {
        architecture_disarm_execution_timer();
    } else if intid == profile.serial_interrupt.line() {
        queue.record_interrupt();
        // Acknowledge the latched sources before draining. A byte arriving
        // after this write either joins the drain or asserts a fresh source;
        // clearing after the drain would erase that fresh event.
        // SAFETY: These bits clear only the acknowledged PL011 receive sources.
        unsafe {
            mmio_write(
                PL011_INTERRUPT_CLEAR,
                PL011_RECEIVE_INTERRUPT | PL011_RECEIVE_TIMEOUT_INTERRUPT,
            );
        }
        aarch64_drain_serial(queue);
    }
    if intid < 1020 {
        // SAFETY: A non-spurious IAR value must be returned verbatim to EOIR.
        unsafe { mmio_write32(cpu + GICC_EOIR, acknowledge) };
    }
    execution_timer
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const AARCH64_EXECUTION_TIMER_INTID: u32 = 30;

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_monotonic_millis() -> Option<u64> {
    let frequency: u64;
    let counter: u64;
    // SAFETY: CNTFRQ_EL0 and CNTPCT_EL0 are read-only at EL1 and the generic
    // counter is monotonic across the pinned single-vCPU profile.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) counter, options(nomem, nostack));
    }
    if frequency < 1_000 {
        return None;
    }
    counter.checked_mul(1_000)?.checked_div(frequency)
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_initialize_monotonic_clock() -> bool {
    architecture_monotonic_millis().is_some()
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_arm_execution_timer(milliseconds: u32) -> Result<(), ExecutionTimerError> {
    const GICD_IGROUPR: usize = 0x080;
    const GICD_ISENABLER: usize = 0x100;
    const GICD_IPRIORITYR: usize = 0x400;
    const GICD_ICFGR: usize = 0xc00;
    let profile = aarch64_input_profile().map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let distributor = usize::try_from(profile.gic.base_address())
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let intid = usize::try_from(AARCH64_EXECUTION_TIMER_INTID)
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let word = intid / 32;
    let bit = 1_u32 << (intid % 32);
    // SAFETY: PPI 30 is the architected non-secure physical timer interrupt;
    // the kernel owns the GIC distributor and configures it level-sensitive.
    unsafe {
        let group = mmio_read32(distributor + GICD_IGROUPR + word * 4);
        mmio_write32(distributor + GICD_IGROUPR + word * 4, group & !bit);
        gicv2_update_byte(distributor + GICD_IPRIORITYR, intid, 0x20);
        let config_address = distributor + GICD_ICFGR + (intid / 16) * 4;
        let config_shift = (intid % 16) * 2;
        let config = mmio_read32(config_address) & !(0b10 << config_shift);
        mmio_write32(distributor + GICD_ICFGR + (intid / 16) * 4, config);
        mmio_write32(distributor + GICD_ISENABLER + word * 4, bit);
    }
    let frequency: u64;
    let counter: u64;
    // SAFETY: CNTFRQ_EL0 and CNTPCT_EL0 are read-only at EL1.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) counter, options(nomem, nostack));
    }
    if frequency == 0 {
        return Err(ExecutionTimerError::Unsupported);
    }
    let ticks = frequency
        .checked_mul(u64::from(milliseconds))
        .and_then(|value| value.checked_div(1_000))
        .filter(|ticks| *ticks != 0)
        .ok_or(ExecutionTimerError::InvalidFrequency)?;
    let deadline = counter
        .checked_add(ticks)
        .ok_or(ExecutionTimerError::InvalidFrequency)?;
    // SAFETY: The checked deadline is programmed before enabling the EL1-owned
    // physical timer; ISB makes the one-shot state visible before user entry.
    unsafe {
        core::arch::asm!("msr cntp_cval_el0, {}", in(reg) deadline, options(nostack));
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1_u64, options(nostack));
        core::arch::asm!("isb", options(nostack));
    }
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_disarm_execution_timer() {
    // SAFETY: EL1 owns the physical timer control for application leases.
    unsafe {
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 0_u64, options(nostack));
        core::arch::asm!("isb", options(nostack));
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn aarch64_drain_serial(queue: &mut BoundedInputQueue) {
    for _ in 0..queue.config().max_drain_per_interrupt() {
        let Some(byte) = architecture_try_read_byte() else {
            break;
        };
        let _result = queue.push(InputEvent::new(InputSource::Serial, byte));
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe fn gicv2_update_byte(base: usize, index: usize, value: u8) {
    let address = base + (index / 4) * 4;
    let shift = (index % 4) * 8;
    // SAFETY: The caller bounds the register through GICD_TYPER and owns the
    // distributor while IRQ delivery is masked.
    let current = unsafe { mmio_read32(address) };
    let updated = (current & !(0xff << shift)) | (u32::from(value) << shift);
    // SAFETY: The same checked register is writable by the distributor owner.
    unsafe { mmio_write32(address, updated) };
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_mask_input_interrupts() {
    // SAFETY: The boot CPU owns DAIF after firmware exit.
    unsafe { core::arch::asm!("msr daifset, #2", "isb", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_enable_input_interrupts() {
    // SAFETY: VBAR, queue, device, and GIC are initialized before IRQ unmask.
    unsafe { core::arch::asm!("msr daifclr, #2", "isb", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_wait_for_input_interrupt() {
    // SAFETY: GICC_PMR leaves the owned IRQ eligible as a WFI wake source even
    // while PSTATE.I prevents exception entry. Sleeping masked closes the race
    // where a handler could run after unmask but before WFI. After wake, the
    // brief unmask dispatches the pending handler; the final mask restores
    // exclusive queue access before the caller rechecks it.
    unsafe {
        core::arch::asm!(
            "dsb sy",
            "wfi",
            "msr daifclr, #2",
            "isb",
            "msr daifset, #2",
            "isb",
            options(nomem, nostack)
        );
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_BASE: usize = 0x0900_0000;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_DATA: usize = 0x000;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_FLAGS: usize = 0x018;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_INTEGER_BAUD: usize = 0x024;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_FRACTIONAL_BAUD: usize = 0x028;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_LINE_CONTROL: usize = 0x02c;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_CONTROL: usize = 0x030;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_INTERRUPT_MASK: usize = 0x038;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_INTERRUPT_CLEAR: usize = 0x044;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_RECEIVE_INTERRUPT: u32 = 1 << 4;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
const PL011_RECEIVE_TIMEOUT_INTERRUPT: u32 = 1 << 6;

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_initialize_console() {
    // SAFETY: These are the documented PL011 registers in the pinned virt
    // profile. The 24 MHz clock divisors select approximately 115200 baud.
    unsafe {
        mmio_write(PL011_CONTROL, 0);
        mmio_write(PL011_INTERRUPT_CLEAR, 0x07ff);
        mmio_write(PL011_INTEGER_BAUD, 13);
        mmio_write(PL011_FRACTIONAL_BAUD, 1);
        mmio_write(PL011_LINE_CONTROL, 0x70);
        mmio_write(PL011_INTERRUPT_MASK, 0);
        mmio_write(PL011_CONTROL, 0x0301);
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn write_byte(byte: u8) -> bool {
    for _ in 0..UART_SPIN_LIMIT {
        // SAFETY: The pinned virt profile maps PL011 registers at this address.
        if unsafe { mmio_read(PL011_FLAGS) } & (1 << 5) == 0 {
            // SAFETY: The transmitter FIFO has capacity for one byte.
            unsafe { mmio_write(PL011_DATA, u32::from(byte)) };
            return true;
        }
        spin_loop();
    }
    false
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_try_read_byte() -> Option<u8> {
    // SAFETY: The pinned virt profile maps PL011 registers at this address.
    if unsafe { mmio_read(PL011_FLAGS) } & (1 << 4) != 0 {
        None
    } else {
        // SAFETY: The receiver FIFO reports one available byte.
        Some(unsafe { mmio_read(PL011_DATA) }.to_le_bytes()[0])
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_park() {
    // SAFETY: WFE in the terminal state has no memory effects; the surrounding
    // loop repeats if an event wakes the CPU.
    unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_take_interrupt_ownership() {
    // SAFETY: Boot services have ended and the kernel intentionally masks debug,
    // SError, IRQ, and FIQ delivery until it owns the interrupt controller.
    unsafe {
        core::arch::asm!("msr daifset, #0xf", "isb", options(nomem, nostack));
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_stack_pointer() -> usize {
    let stack_pointer: usize;
    // SAFETY: Reading SP has no side effects.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) stack_pointer, options(nomem, nostack));
    }
    stack_pointer
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_enter_owned_stack(stack_top: usize, launch: usize, entry: usize) -> ! {
    // SAFETY: The validated range is exclusively reserved and the leaked launch
    // record outlives this non-returning AAPCS64 transition.
    unsafe {
        core::arch::asm!(
            "mov sp, x9",
            "blr x10",
            "brk #0",
            in("x9") stack_top,
            in("x0") launch,
            in("x10") entry,
            options(noreturn),
        );
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_run_task_step(stack_top: usize, call: usize, entry: usize) -> usize {
    let result: usize;
    // SAFETY: `stack_top` is a validated, exclusively task-owned mapped range.
    // The old SP is stored in the new stack's top frame and restored after the
    // AAPCS64 callback returns; the unique call record is passed in X0.
    unsafe {
        core::arch::asm!(
            "mov x9, sp",
            "mov sp, x11",
            "sub sp, sp, #16",
            "str x9, [sp]",
            "blr x10",
            "ldr x9, [sp]",
            "mov sp, x9",
            inlateout("x0") call => result,
            in("x10") entry,
            in("x11") stack_top,
            clobber_abi("C"),
        );
    }
    result
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe fn mmio_read(offset: usize) -> u32 {
    // SAFETY: The caller supplies a valid aligned PL011 register offset.
    unsafe { ptr::read_volatile((PL011_BASE + offset) as *const u32) }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe fn mmio_write(offset: usize, value: u32) {
    // SAFETY: The caller supplies a valid aligned writable PL011 register.
    unsafe { ptr::write_volatile((PL011_BASE + offset) as *mut u32, value) };
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe fn mmio_read32(address: usize) -> u32 {
    // SAFETY: The caller proves that the address names an aligned mapped MMIO
    // register and owns the corresponding device operation.
    unsafe { ptr::read_volatile(address as *const u32) }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe fn mmio_write32(address: usize, value: u32) {
    // SAFETY: The caller proves that the address names an aligned writable MMIO
    // register and owns the corresponding device operation.
    unsafe { ptr::write_volatile(address as *mut u32, value) };
}

#[cfg(test)]
mod tests {
    use super::{HeapState, TaskStackError, validate_task_stack};
    use core::alloc::Layout;
    use troe_memory::PhysicalRange;

    #[repr(align(4096))]
    struct TestArena([u8; 4096]);

    #[test]
    fn owned_heap_aligns_coalesces_and_reuses() {
        let mut arena = TestArena([0; 4096]);
        let start = arena.0.as_mut_ptr() as usize;
        let mut heap = HeapState::empty();
        // SAFETY: `arena` is exclusively borrowed for the duration of the test.
        assert!(unsafe { heap.initialize(start, arena.0.len()) });
        let small = Layout::from_size_align(31, 64).unwrap_or(Layout::new::<u64>());
        let large = Layout::from_size_align(3000, 8).unwrap_or(Layout::new::<u64>());

        // SAFETY: The initialized test arena remains live and exclusive.
        let first = heap.allocate(small);
        assert!(!first.is_null());
        assert_eq!((first as usize) % 64, 0);
        // SAFETY: `first` is a unique live allocation from this heap.
        unsafe { heap.deallocate(first, small) };
        assert_eq!(heap.stats().used_bytes, 0);

        // This succeeds only if the split ranges were coalesced after free.
        // SAFETY: The initialized test arena remains live and exclusive.
        let reused = heap.allocate(large);
        assert!(!reused.is_null());
        // SAFETY: `reused` is a unique live allocation from this heap.
        unsafe { heap.deallocate(reused, large) };
        assert_eq!(heap.stats().used_bytes, 0);
    }

    #[test]
    fn owned_heap_failure_is_bounded_and_atomic() {
        let mut arena = TestArena([0; 4096]);
        let start = arena.0.as_mut_ptr() as usize;
        let mut heap = HeapState::empty();
        // SAFETY: `arena` is exclusively borrowed for the duration of the test.
        assert!(unsafe { heap.initialize(start, arena.0.len()) });
        let oversized = Layout::from_size_align(8192, 8).unwrap_or(Layout::new::<u64>());

        // SAFETY: The initialized test arena remains live and exclusive.
        assert!(heap.allocate(oversized).is_null());
        assert_eq!(heap.stats().used_bytes, 0);
        assert_eq!(heap.stats().failed_allocations, 1);
    }

    #[test]
    fn task_stack_validation_enforces_size_and_alignment() {
        let Ok(too_small) = PhysicalRange::from_pages(0x1000, 1) else {
            return;
        };
        assert_eq!(
            validate_task_stack(too_small),
            Err(TaskStackError::TooSmall)
        );

        let accepted = PhysicalRange::from_pages(0x20_0000, 8).unwrap_or(too_small);
        assert_eq!(validate_task_stack(accepted), Ok(0x20_8000));
    }
}

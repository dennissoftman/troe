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
#[cfg(target_os = "uefi")]
use core::sync::atomic::AtomicBool;
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
use core::sync::atomic::AtomicU32;
#[cfg(any(test, all(target_os = "uefi", target_arch = "x86_64")))]
use core::sync::atomic::AtomicU64;
#[cfg(any(test, target_os = "uefi"))]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(any(test, target_os = "uefi"))]
use troe_driver::InterruptResource;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
use troe_driver::IoPortResource;
#[cfg(target_os = "uefi")]
use troe_driver::{
    BoundedInputQueue, InputEvent, InputQueueConfig, InputQueueStats, InputSource, MmioResource,
    QueueError,
};
#[cfg(any(test, target_os = "uefi"))]
use troe_memory::PhysicalRange;
#[cfg(target_os = "uefi")]
use troe_task::TaskStep;
#[cfg(target_os = "uefi")]
use troe_terminal::{Color, FramebufferDescriptor, PixelSurface, SurfaceError};
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
#[cfg(any(test, target_os = "uefi"))]
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

/// Validated platform source carried across the machine interrupt boundary.
#[derive(Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
pub(crate) struct NetworkInterruptRoute {
    interrupt: InterruptResource,
    source: NetworkInterruptSource,
    priority: u8,
    trigger: troe_platform::TriggerMode,
    polarity: troe_platform::Polarity,
}

#[derive(Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
enum NetworkInterruptSource {
    #[cfg_attr(all(target_os = "uefi", target_arch = "aarch64"), allow(dead_code))]
    PciIntx { pin: u8 },
    #[cfg_attr(all(target_os = "uefi", target_arch = "x86_64"), allow(dead_code))]
    VirtioMmio { slot: u32 },
}

impl NetworkInterruptRoute {
    /// Validate one q35 PCI `INTx` pin/line against the selected descriptor.
    #[cfg(any(test, all(target_os = "uefi", target_arch = "x86_64")))]
    pub(crate) fn q35_pci_intx(line: u8, pin: u8) -> Result<Self, InputInterruptError> {
        #[cfg(test)]
        let platform = troe_platform::X86_64_Q35_UEFI
            .validate()
            .map_err(|_| InputInterruptError::InvalidResource)?;
        #[cfg(not(test))]
        let platform =
            crate::selected_platform().map_err(|_| InputInterruptError::InvalidResource)?;
        let troe_platform::VirtioTransportKind::Pci {
            maximum_interrupt_line,
            network_vector,
            network_trigger,
            network_polarity,
            ..
        } = platform.virtio()
        else {
            return Err(InputInterruptError::InvalidResource);
        };
        if !(1..=4).contains(&pin)
            || line > maximum_interrupt_line
            || [
                troe_platform::InterruptRole::Keyboard,
                troe_platform::InterruptRole::Serial,
            ]
            .into_iter()
            .filter_map(|role| platform.interrupt(role))
            .any(|route| route.line() == u32::from(line))
        {
            return Err(InputInterruptError::InvalidResource);
        }
        let interrupt = InterruptResource::new(u32::from(line), network_vector)
            .map_err(|_| InputInterruptError::InvalidResource)?;
        Ok(Self {
            interrupt,
            source: NetworkInterruptSource::PciIntx { pin },
            priority: 0,
            trigger: network_trigger,
            polarity: network_polarity,
        })
    }

    /// Derive and validate one QEMU `virt` MMIO slot-to-SPI route.
    #[cfg(any(test, target_os = "uefi"))]
    pub(crate) fn virtio_mmio(
        slot: u32,
        slot_count: u32,
        first_intid: u32,
    ) -> Result<Self, InputInterruptError> {
        #[cfg(test)]
        let platform = troe_platform::AARCH64_VIRT_UEFI
            .validate()
            .map_err(|_| InputInterruptError::InvalidResource)?;
        #[cfg(not(test))]
        let platform =
            crate::selected_platform().map_err(|_| InputInterruptError::InvalidResource)?;
        let troe_platform::VirtioTransportKind::Mmio {
            slot_count: described_slots,
            first_interrupt: described_first,
            network_priority,
            network_trigger,
            network_polarity,
            ..
        } = platform.virtio()
        else {
            return Err(InputInterruptError::InvalidResource);
        };
        if slot_count != u32::from(described_slots)
            || first_intid != described_first
            || slot >= slot_count
        {
            return Err(InputInterruptError::InvalidResource);
        }
        let intid = first_intid
            .checked_add(slot)
            .ok_or(InputInterruptError::InvalidResource)?;
        if !(32..=1019).contains(&intid)
            || [
                troe_platform::InterruptRole::Serial,
                troe_platform::InterruptRole::Timer,
            ]
            .into_iter()
            .filter_map(|role| platform.interrupt(role))
            .any(|route| route.line() == intid)
        {
            return Err(InputInterruptError::InvalidResource);
        }
        let vector = platform
            .interrupt(troe_platform::InterruptRole::Serial)
            .ok_or(InputInterruptError::InvalidResource)?
            .vector();
        let interrupt = InterruptResource::new(intid, vector)
            .map_err(|_| InputInterruptError::InvalidResource)?;
        Ok(Self {
            interrupt,
            source: NetworkInterruptSource::VirtioMmio { slot },
            priority: network_priority,
            trigger: network_trigger,
            polarity: network_polarity,
        })
    }

    const fn interrupt(&self) -> InterruptResource {
        self.interrupt
    }

    const fn source(&self) -> &NetworkInterruptSource {
        &self.source
    }

    const fn priority(&self) -> u8 {
        self.priority
    }

    const fn trigger(&self) -> troe_platform::TriggerMode {
        self.trigger
    }

    const fn polarity(&self) -> troe_platform::Polarity {
        self.polarity
    }
}

/// A validated route configured in the controller but still masked.
#[derive(Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
pub(crate) struct PreparedNetworkInterrupt {
    route: NetworkInterruptRoute,
}

/// Exclusive ownership of one unmasked network interrupt route.
#[derive(Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
pub(crate) struct ActiveNetworkInterrupt {
    route: NetworkInterruptRoute,
}

/// A controller-masked route awaiting transport-state revocation.
#[derive(Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
pub(crate) struct DeactivatedNetworkInterrupt {
    route: NetworkInterruptRoute,
}

/// Pure initialization phase used by target reset guards and host fault tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
pub(crate) enum DmaInitializationPhase {
    /// Device status has changed, but no queue address is visible yet.
    DeviceStateChanged,
    /// At least one queue address has become device-visible.
    QueuePublished,
    /// The device accepted `DRIVER_OK` and may consume queues.
    DriverOk,
    /// A fully constructed owner now enforces reset-before-release on drop.
    OwnershipTransferred,
}

/// Host-testable reset obligation for fallible native device construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
pub(crate) struct DmaInitializationState {
    phase: DmaInitializationPhase,
}

#[cfg(any(test, target_os = "uefi"))]
impl DmaInitializationState {
    pub(crate) const fn new() -> Self {
        Self {
            phase: DmaInitializationPhase::DeviceStateChanged,
        }
    }

    pub(crate) const fn mark_queue_published(&mut self) {
        self.phase = DmaInitializationPhase::QueuePublished;
    }

    pub(crate) const fn mark_driver_ok(&mut self) {
        self.phase = DmaInitializationPhase::DriverOk;
    }

    pub(crate) const fn transfer_ownership(&mut self) {
        self.phase = DmaInitializationPhase::OwnershipTransferred;
    }

    pub(crate) const fn cleanup_requires_reset(self) -> bool {
        !matches!(self.phase, DmaInitializationPhase::OwnershipTransferred)
    }

    #[cfg(test)]
    const fn phase(self) -> DmaInitializationPhase {
        self.phase
    }
}

/// Classification of a used-index observation with one descriptor outstanding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "uefi"))]
pub(crate) enum UsedIndexTransition {
    /// The device has not completed the outstanding descriptor.
    Empty,
    /// Exactly the one outstanding descriptor completed.
    Completed,
    /// The device skipped, replayed, or otherwise corrupted the used index.
    Invalid,
}

/// Validate the only legal used-index transitions for a one-in-flight queue.
#[cfg(any(test, target_os = "uefi"))]
pub(crate) const fn classify_used_index(current: u16, observed: u16) -> UsedIndexTransition {
    if observed == current {
        UsedIndexTransition::Empty
    } else if observed == current.wrapping_add(1) {
        UsedIndexTransition::Completed
    } else {
        UsedIndexTransition::Invalid
    }
}

/// Exclusively publish transport ISR state into an empty global slot.
#[cfg(any(test, target_os = "uefi"))]
pub(crate) fn claim_network_interrupt_publication(publication: &AtomicUsize, owned: usize) -> bool {
    owned != 0
        && publication
            .compare_exchange(0, owned, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

/// Revoke transport ISR state only when it still belongs to this route owner.
#[cfg(any(test, target_os = "uefi"))]
pub(crate) fn revoke_network_interrupt_publication(
    publication: &AtomicUsize,
    owned: usize,
) -> bool {
    owned != 0
        && publication
            .compare_exchange(owned, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
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

#[cfg(target_os = "uefi")]
static NETWORK_INTERRUPT_PENDING: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "uefi")]
static RUNTIME_TIMER_FIRED: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
static AARCH64_NETWORK_INTERRUPT_INTID: AtomicU32 = AtomicU32::new(u32::MAX);

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
static AARCH64_EXECUTION_TIMER_CONFIGURED: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
static X86_TSC_TICKS_PER_MILLISECOND: AtomicU64 = AtomicU64::new(0);

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
static X86_LAPIC_TICKS_PER_MILLISECOND: AtomicU64 = AtomicU64::new(0);

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
        let pixel = self.descriptor.encode_pixel(x, y, color)?;
        for (index, byte) in pixel.bytes().into_iter().enumerate() {
            let address = self
                .base
                .checked_add(pixel.byte_offset())
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
        let Ok(data_resource) = x86_ports(troe_platform::IoPortRole::KeyboardData) else {
            return None;
        };
        let Ok(status_resource) = x86_ports(troe_platform::IoPortRole::KeyboardStatus) else {
            return None;
        };
        let data = data_resource.base_port();
        let status_port = status_resource.base_port();
        // SAFETY: The validated platform descriptor owns both i8042 ports.
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
pub fn input_device_ranges() -> Result<[Option<PhysicalRange>; 3], InputInterruptError> {
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
    let result = architecture_initialize_input_interrupts(config);
    if result.is_err() {
        // SAFETY: Architecture initialization failed with IRQ delivery still
        // masked, so no producer can retain or access the provisional queue.
        unsafe {
            *INPUT_QUEUE.0.get() = None;
        }
    }
    result
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

/// Sleep until either bounded input or ambient network work is pending.
///
/// The check is performed with architecture IRQ delivery masked, closing the
/// lost-wakeup window before the architecture idle instruction.
#[cfg(target_os = "uefi")]
pub fn wait_for_runtime_event() {
    architecture_mask_input_interrupts();
    loop {
        // SAFETY: IRQ delivery is masked on the single boot CPU.
        let input_pending =
            unsafe { input_queue_mut() }.is_some_and(|queue| queue.stats().queued != 0);
        if input_pending || NETWORK_INTERRUPT_PENDING.load(Ordering::Acquire) {
            architecture_enable_input_interrupts();
            return;
        }
        // SAFETY: Main context has exclusive access while IRQs are masked.
        if let Some(queue) = unsafe { input_queue_mut() } {
            queue.record_idle_wait();
        }
        architecture_wait_for_input_interrupt();
        // SAFETY: The architecture wait helper returns with IRQs masked.
        if let Some(queue) = unsafe { input_queue_mut() } {
            queue.record_wakeup();
        }
    }
}

/// Sleep until bounded input/network work arrives or one runtime deadline fires.
///
/// This is distinct from an application execution lease: callers use it only
/// while no unprivileged context is active. The one-shot timer interrupt
/// returns to the kernel idle loop instead of completing an application fault.
/// The return value is `true` when the deadline timer fired and `false` when an
/// input or network event became pending first.
///
/// # Errors
///
/// Rejects a zero interval or unavailable architecture timer.
#[cfg(target_os = "uefi")]
pub fn wait_for_runtime_event_timeout(milliseconds: u32) -> Result<bool, ExecutionTimerError> {
    if milliseconds == 0 {
        return Err(ExecutionTimerError::InvalidFrequency);
    }
    architecture_mask_input_interrupts();
    // SAFETY: IRQ delivery is masked on the single boot CPU.
    let input_pending = unsafe { input_queue_mut() }.is_some_and(|queue| queue.stats().queued != 0);
    if input_pending || NETWORK_INTERRUPT_PENDING.load(Ordering::Acquire) {
        architecture_enable_input_interrupts();
        return Ok(false);
    }
    RUNTIME_TIMER_FIRED.store(false, Ordering::Release);
    if let Err(error) = architecture_arm_execution_timer(milliseconds) {
        architecture_disarm_execution_timer();
        architecture_enable_input_interrupts();
        return Err(error);
    }
    // Close the event-publication window after timer programming while IRQ
    // delivery remains masked.
    // SAFETY: Main context still has exclusive queue access.
    let input_pending = unsafe { input_queue_mut() }.is_some_and(|queue| queue.stats().queued != 0);
    if input_pending || NETWORK_INTERRUPT_PENDING.load(Ordering::Acquire) {
        architecture_disarm_execution_timer();
        architecture_enable_input_interrupts();
        return Ok(false);
    }
    // SAFETY: Main context has exclusive access while accounting the wait.
    if let Some(queue) = unsafe { input_queue_mut() } {
        queue.record_idle_wait();
    }
    architecture_wait_for_input_interrupt();
    // The architecture helper returns with IRQ delivery masked.
    architecture_disarm_execution_timer();
    // SAFETY: Main context again has exclusive queue access.
    if let Some(queue) = unsafe { input_queue_mut() } {
        queue.record_wakeup();
    }
    let timer_fired = RUNTIME_TIMER_FIRED.swap(false, Ordering::AcqRel);
    architecture_enable_input_interrupts();
    Ok(timer_fired)
}

/// Consume the coalesced indication that a network completion needs polling.
#[must_use]
#[cfg(target_os = "uefi")]
pub fn take_network_interrupt() -> bool {
    NETWORK_INTERRUPT_PENDING.swap(false, Ordering::AcqRel)
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

/// Read the architecture's highest-resolution monotonic benchmark counter.
///
/// The value is exposed only in acceptance images. QEMU results are suitable
/// for regression comparison but not real-hardware latency claims.
#[must_use]
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub fn benchmark_counter_ticks() -> u64 {
    architecture_benchmark_counter_ticks()
}

/// Return the benchmark counter frequency established for this boot.
#[must_use]
#[cfg(all(target_os = "uefi", feature = "acceptance-probes"))]
pub fn benchmark_counter_frequency_hz() -> Option<u64> {
    architecture_benchmark_counter_frequency_hz()
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

/// Complete one x86 kernel-runtime deadline interrupt.
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
pub(crate) fn handle_runtime_timer_interrupt() {
    architecture_disarm_execution_timer();
    architecture_acknowledge_execution_timer_interrupt();
    RUNTIME_TIMER_FIRED.store(true, Ordering::Release);
}

/// Configure a validated network route while leaving controller delivery masked.
#[cfg(target_os = "uefi")]
pub(crate) fn prepare_network_interrupt(
    route: NetworkInterruptRoute,
) -> Result<PreparedNetworkInterrupt, InputInterruptError> {
    architecture_prepare_network_interrupt(&route)?;
    Ok(PreparedNetworkInterrupt { route })
}

/// Unmask one prepared route after the transport has published ISR state.
#[cfg(target_os = "uefi")]
pub(crate) fn activate_network_interrupt(
    prepared: PreparedNetworkInterrupt,
) -> ActiveNetworkInterrupt {
    architecture_activate_network_interrupt(&prepared.route);
    NETWORK_INTERRUPT_PENDING.store(true, Ordering::Release);
    ActiveNetworkInterrupt {
        route: prepared.route,
    }
}

/// Roll back a masked prepared route when transport publication cannot commit.
#[cfg(target_os = "uefi")]
pub(crate) fn cancel_prepared_network_interrupt(prepared: PreparedNetworkInterrupt) {
    let PreparedNetworkInterrupt { route } = prepared;
    architecture_cancel_prepared_network_interrupt(&route);
}

/// Mask an active route while retaining the CPU IRQ mask for state revocation.
#[cfg(target_os = "uefi")]
pub(crate) fn deactivate_network_interrupt(
    active: ActiveNetworkInterrupt,
) -> DeactivatedNetworkInterrupt {
    let ActiveNetworkInterrupt { route } = active;
    architecture_deactivate_network_interrupt(&route);
    NETWORK_INTERRUPT_PENDING.store(false, Ordering::Release);
    DeactivatedNetworkInterrupt { route }
}

/// Re-enable CPU IRQ delivery after transport ISR state has been unpublished.
#[cfg(target_os = "uefi")]
pub(crate) fn finish_network_interrupt_deactivation(deactivated: DeactivatedNetworkInterrupt) {
    let DeactivatedNetworkInterrupt { route: _route } = deactivated;
    architecture_enable_input_interrupts();
}

/// Dispatch an interrupt taken during unprivileged application execution.
///
/// Returns `true` only for the owned execution-lease timer. Input interrupts
/// are serviced normally and return `false` so the application can resume.
#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
pub(crate) fn handle_application_interrupt() -> bool {
    // SAFETY: The native interrupt entry masks nested IRQ delivery and the
    // single boot CPU is the only producer or consumer at this boundary.
    let timer = unsafe { input_queue_mut() }.is_some_and(architecture_handle_input_interrupt);
    if timer {
        RUNTIME_TIMER_FIRED.store(true, Ordering::Release);
    }
    timer
}

/// Mask IRQ delivery and arm a one-shot execution lease.
///
/// IRQs remain masked on success. The architecture entry boundary publishes
/// its complete kernel return context before enabling delivery in userspace,
/// so the lease cannot observe an active run with a stale kernel context.
#[cfg(target_os = "uefi")]
pub(crate) fn prepare_application_execution(milliseconds: u32) -> Result<(), ExecutionTimerError> {
    if milliseconds == 0 {
        return Err(ExecutionTimerError::InvalidFrequency);
    }
    architecture_mask_input_interrupts();
    match architecture_arm_execution_timer(milliseconds) {
        Ok(()) => Ok(()),
        Err(error) => {
            architecture_disarm_execution_timer();
            Err(error)
        }
    }
}

/// Disable the one-shot execution timer while retaining the CPU IRQ mask.
///
/// Native completion restores the masked kernel state captured by the entry
/// boundary. The active run must be unpublished before IRQ delivery is
/// re-enabled with [`finish_application_execution`].
#[cfg(target_os = "uefi")]
pub(crate) fn quiesce_application_execution() {
    architecture_disarm_execution_timer();
}

/// Re-enable IRQ delivery after the active application state is unpublished.
#[cfg(target_os = "uefi")]
pub(crate) fn finish_application_execution() {
    architecture_enable_input_interrupts();
}

/// Disable the one-shot execution timer from an already-masked native gate.
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

/// Park the current CPU permanently after a terminal path.
#[cfg(target_os = "uefi")]
pub fn park() -> ! {
    loop {
        architecture_park();
    }
}

/// Request the pinned platform's soft-off transition.
///
/// If the platform rejects or unexpectedly returns from the request, the CPU
/// enters the same terminal parked state used by fatal paths.
#[cfg(target_os = "uefi")]
pub fn poweroff() -> ! {
    architecture_poweroff();
    park()
}

/// Request a cold reset from the pinned platform.
///
/// If the platform rejects or unexpectedly returns from the request, the CPU
/// enters the terminal parked state rather than resuming shell execution.
#[cfg(target_os = "uefi")]
pub fn reboot() -> ! {
    architecture_reboot();
    park()
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
fn x86_mmio(role: troe_platform::MmioRole) -> Result<MmioResource, InputInterruptError> {
    let resource = crate::selected_platform()
        .map_err(|_| InputInterruptError::InvalidResource)?
        .mmio(role)
        .ok_or(InputInterruptError::InvalidResource)?;
    MmioResource::new(resource.base(), resource.byte_len())
        .map_err(|_| InputInterruptError::InvalidResource)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_ports(role: troe_platform::IoPortRole) -> Result<IoPortResource, InputInterruptError> {
    let resource = crate::selected_platform()
        .map_err(|_| InputInterruptError::InvalidResource)?
        .io_ports(role)
        .ok_or(InputInterruptError::InvalidResource)?;
    IoPortResource::new(resource.base(), resource.count())
        .map_err(|_| InputInterruptError::InvalidResource)
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn platform_interrupt(
    role: troe_platform::InterruptRole,
) -> Result<InterruptResource, InputInterruptError> {
    let route = crate::selected_platform()
        .map_err(|_| InputInterruptError::InvalidResource)?
        .interrupt(role)
        .ok_or(InputInterruptError::InvalidResource)?;
    InterruptResource::new(route.line(), route.vector())
        .map_err(|_| InputInterruptError::InvalidResource)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_input_device_ranges() -> Result<[Option<PhysicalRange>; 3], InputInterruptError> {
    let lapic = x86_mmio(troe_platform::MmioRole::LocalApic)?;
    let ioapic = x86_mmio(troe_platform::MmioRole::IoApic)?;
    Ok([
        Some(resource_page_range(lapic)?),
        Some(resource_page_range(ioapic)?),
        None,
    ])
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_initialize_input_interrupts(
    _config: InputQueueConfig,
) -> Result<(), InputInterruptError> {
    const LAPIC_ID: usize = 0x020;
    const LAPIC_SPURIOUS: usize = 0x0f0;
    const LAPIC_SOFTWARE_ENABLE: u32 = 1 << 8;
    let platform = crate::selected_platform().map_err(|_| InputInterruptError::InvalidResource)?;
    let lapic = x86_mmio(troe_platform::MmioRole::LocalApic)?;
    let ioapic = x86_mmio(troe_platform::MmioRole::IoApic)?;
    let keyboard_route = platform
        .interrupt(troe_platform::InterruptRole::Keyboard)
        .ok_or(InputInterruptError::InvalidResource)?;
    let serial_route = platform
        .interrupt(troe_platform::InterruptRole::Serial)
        .ok_or(InputInterruptError::InvalidResource)?;
    let keyboard_interrupt = InterruptResource::new(keyboard_route.line(), keyboard_route.vector())
        .map_err(|_| InputInterruptError::InvalidResource)?;
    let serial_interrupt = InterruptResource::new(serial_route.line(), serial_route.vector())
        .map_err(|_| InputInterruptError::InvalidResource)?;
    let serial_ports = x86_ports(troe_platform::IoPortRole::Serial)?;
    let primary_pic = x86_ports(troe_platform::IoPortRole::PicPrimary)?;
    let secondary_pic = x86_ports(troe_platform::IoPortRole::PicSecondary)?;
    let (_, spurious_vector) =
        x86_timer_vectors(platform.timer()).ok_or(InputInterruptError::InvalidResource)?;

    let ioapic_version = x86_ioapic_read(ioapic, 1);
    let maximum_entry = (ioapic_version >> 16) & 0xff;
    if keyboard_interrupt.line() > maximum_entry || serial_interrupt.line() > maximum_entry {
        return Err(InputInterruptError::InterruptLineUnavailable);
    }
    let lapic_base =
        usize::try_from(lapic.base_address()).map_err(|_| InputInterruptError::InvalidResource)?;

    // SAFETY: The validated descriptor assigns both legacy PIC mask registers;
    // masking both controllers prevents firmware-era PIC delivery.
    unsafe {
        port_write(primary_pic.base_port() + 1, 0xff);
        port_write(secondary_pic.base_port() + 1, 0xff);
    }

    for line in 0..=maximum_entry {
        x86_ioapic_write(ioapic, 0x10 + line * 2, 1 << 16);
        x86_ioapic_write(ioapic, 0x11 + line * 2, 0);
    }

    // SAFETY: The LAPIC page is mapped RW/NX as device memory before this call.
    let apic_id = unsafe { mmio_read32(lapic_base + LAPIC_ID) } >> 24;
    // SAFETY: The spurious-vector register belongs to the owned BSP LAPIC.
    unsafe {
        mmio_write32(
            lapic_base + LAPIC_SPURIOUS,
            LAPIC_SOFTWARE_ENABLE | u32::from(spurious_vector),
        );
    }
    x86_route_ioapic(
        ioapic,
        keyboard_interrupt,
        keyboard_route.trigger(),
        keyboard_route.polarity(),
        apic_id,
    );
    x86_route_ioapic(
        ioapic,
        serial_interrupt,
        serial_route.trigger(),
        serial_route.polarity(),
        apic_id,
    );

    // Retain bytes already present before enabling receive notification.
    // SAFETY: Initialization still runs with CPU interrupts masked.
    if let Some(queue) = unsafe { input_queue_mut() } {
        let _drained = x86_drain_input_devices(queue);
    }
    // SAFETY: COM1's interrupt-enable register is owned by the pinned profile.
    unsafe {
        let serial_base = serial_ports.base_port();
        port_write(serial_base + 1, 1);
    }
    architecture_enable_input_interrupts();
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_handle_input_interrupt(queue: &mut BoundedInputQueue) -> bool {
    const LAPIC_EOI: usize = 0x0b0;
    if x86_drain_input_devices(queue) {
        queue.record_interrupt();
    }
    if crate::acknowledge_network_interrupt_from_isr() {
        NETWORK_INTERRUPT_PENDING.store(true, Ordering::Release);
    }
    if let Ok(lapic) = x86_mmio(troe_platform::MmioRole::LocalApic)
        && let Ok(lapic_base) = usize::try_from(lapic.base_address())
    {
        // SAFETY: Every routed input interrupt requires one LAPIC EOI write.
        unsafe { mmio_write32(lapic_base + LAPIC_EOI, 0) };
    }
    false
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_monotonic_millis() -> Option<u64> {
    x86_timer_vectors(crate::selected_platform().ok()?.timer())?;
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
    let Ok(platform) = crate::selected_platform() else {
        return false;
    };
    let ticks_per_millisecond = match platform.timer() {
        troe_platform::TimerKind::X86PitTsc { .. } => x86_cpuid_tsc_frequency()
            .and_then(|frequency| frequency.checked_div(1_000))
            .filter(|ticks| *ticks != 0)
            .or_else(x86_calibrate_tsc_with_firmware_stall),
        troe_platform::TimerKind::X86AcpiPmTsc {
            pm_timer_port,
            counter_bits,
            ..
        } => x86_ports(troe_platform::IoPortRole::AcpiPmTimer)
            .ok()
            .filter(|resource| resource.base_port() == pm_timer_port && resource.port_count() >= 4)
            .and_then(|resource| x86_calibrate_tsc_with_pm_timer(resource, counter_bits)),
        troe_platform::TimerKind::Aarch64Generic => None,
    };
    let Some(ticks_per_millisecond) = ticks_per_millisecond else {
        return false;
    };
    if ticks_per_millisecond == 0 {
        return false;
    }
    X86_TSC_TICKS_PER_MILLISECOND.store(ticks_per_millisecond, Ordering::Relaxed);
    true
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_timer_vectors(timer: troe_platform::TimerKind) -> Option<(u8, u8)> {
    match timer {
        troe_platform::TimerKind::X86PitTsc {
            timer_vector,
            spurious_vector,
        }
        | troe_platform::TimerKind::X86AcpiPmTsc {
            timer_vector,
            spurious_vector,
            ..
        } => Some((timer_vector, spurious_vector)),
        troe_platform::TimerKind::Aarch64Generic => None,
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_calibrate_tsc_with_firmware_stall() -> Option<u64> {
    let start = x86_read_tsc();
    uefi::boot::stall(core::time::Duration::from_millis(10));
    x86_read_tsc()
        .checked_sub(start)?
        .checked_div(10)
        .filter(|ticks| *ticks != 0)
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

#[cfg(all(
    target_os = "uefi",
    target_arch = "x86_64",
    feature = "acceptance-probes"
))]
fn architecture_benchmark_counter_ticks() -> u64 {
    x86_read_tsc()
}

#[cfg(all(
    target_os = "uefi",
    target_arch = "x86_64",
    feature = "acceptance-probes"
))]
fn architecture_benchmark_counter_frequency_hz() -> Option<u64> {
    X86_TSC_TICKS_PER_MILLISECOND
        .load(Ordering::Relaxed)
        .checked_mul(1_000)
        .filter(|frequency| *frequency != 0)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_PM_TIMER_HZ: u64 = 3_579_545;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_TIMER_CALIBRATION_TICKS: u32 = 35_795;
#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const X86_TIMER_CALIBRATION_SPINS: usize = 10_000_000;

#[cfg(any(test, all(target_os = "uefi", target_arch = "x86_64")))]
fn cached_nonzero<E>(
    cache: &AtomicU64,
    produce: impl FnOnce() -> Result<u64, E>,
) -> Result<u64, E> {
    let cached = cache.load(Ordering::Acquire);
    if cached != 0 {
        return Ok(cached);
    }
    let value = produce()?;
    if value != 0 {
        cache.store(value, Ordering::Release);
    }
    Ok(value)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_pm_timer_sample(resource: IoPortResource, counter_bits: u8) -> Option<u32> {
    if resource.port_count() < 4 || !matches!(counter_bits, 24 | 32) {
        return None;
    }
    let value: u32;
    // SAFETY: The descriptor-owned ACPI PM timer is a read-only naturally
    // aligned 32-bit I/O register. Counter width is masked after the read.
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            in("dx") resource.base_port(),
            out("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    Some(value & x86_pm_timer_mask(counter_bits)?)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
const fn x86_pm_timer_mask(counter_bits: u8) -> Option<u32> {
    match counter_bits {
        24 => Some(0x00ff_ffff),
        32 => Some(u32::MAX),
        _ => None,
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_pm_timer_elapsed(start: u32, current: u32, counter_bits: u8) -> Option<u32> {
    Some(current.wrapping_sub(start) & x86_pm_timer_mask(counter_bits)?)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_calibrate_tsc_with_pm_timer(resource: IoPortResource, counter_bits: u8) -> Option<u64> {
    let timer_start = x86_pm_timer_sample(resource, counter_bits)?;
    let tsc_start = x86_read_tsc();
    for _ in 0..X86_TIMER_CALIBRATION_SPINS {
        let current = x86_pm_timer_sample(resource, counter_bits)?;
        let elapsed = x86_pm_timer_elapsed(timer_start, current, counter_bits)?;
        if elapsed >= X86_TIMER_CALIBRATION_TICKS {
            return x86_read_tsc()
                .checked_sub(tsc_start)?
                .checked_mul(X86_PM_TIMER_HZ)?
                .checked_div(u64::from(elapsed))?
                .checked_div(1_000)
                .filter(|ticks| *ticks != 0);
        }
        spin_loop();
    }
    None
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_arm_execution_timer(milliseconds: u32) -> Result<(), ExecutionTimerError> {
    const LAPIC_LVT_TIMER: usize = 0x320;
    const LAPIC_INITIAL_COUNT: usize = 0x380;
    let platform =
        crate::selected_platform().map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let lapic_resource = x86_mmio(troe_platform::MmioRole::LocalApic)
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let lapic = usize::try_from(lapic_resource.base_address())
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let timer = platform.timer();
    let timer_vector = x86_timer_vectors(timer)
        .map(|(timer_vector, _spurious_vector)| timer_vector)
        .ok_or(ExecutionTimerError::InterruptUnavailable)?;
    let ticks_per_millisecond = cached_nonzero(&X86_LAPIC_TICKS_PER_MILLISECOND, || match timer {
        troe_platform::TimerKind::X86PitTsc { .. } => x86_calibrate_lapic_with_pit(lapic),
        troe_platform::TimerKind::X86AcpiPmTsc {
            pm_timer_port,
            counter_bits,
            ..
        } => {
            let timer = x86_ports(troe_platform::IoPortRole::AcpiPmTimer)
                .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
            if timer.base_port() != pm_timer_port || timer.port_count() < 4 {
                return Err(ExecutionTimerError::InterruptUnavailable);
            }
            x86_calibrate_lapic_with_pm_timer(lapic, timer, counter_bits)
        }
        troe_platform::TimerKind::Aarch64Generic => Err(ExecutionTimerError::InterruptUnavailable),
    })?;
    let lease_ticks = ticks_per_millisecond
        .checked_mul(u64::from(milliseconds))
        .and_then(|ticks| u32::try_from(ticks).ok())
        .filter(|ticks| *ticks != 0)
        .ok_or(ExecutionTimerError::InvalidFrequency)?;
    // SAFETY: The vector is installed, divide state is fixed, and the checked
    // nonzero initial count selects one-shot mode by leaving mode bits clear.
    unsafe {
        mmio_write32(lapic + LAPIC_LVT_TIMER, u32::from(timer_vector));
        mmio_write32(lapic + LAPIC_INITIAL_COUNT, lease_ticks);
    }
    Ok(())
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_prepare_lapic_calibration(lapic: usize) {
    const LAPIC_LVT_TIMER: usize = 0x320;
    const LAPIC_INITIAL_COUNT: usize = 0x380;
    const LAPIC_DIVIDE_CONFIG: usize = 0x3e0;
    const LAPIC_MASKED: u32 = 1 << 16;
    const LAPIC_DIVIDE_BY_ONE: u32 = 0b1011;
    // SAFETY: The validated LAPIC page is mapped as owned device memory. The
    // timer remains masked while its divide state and maximum count are set.
    unsafe {
        mmio_write32(lapic + LAPIC_LVT_TIMER, LAPIC_MASKED);
        mmio_write32(lapic + LAPIC_DIVIDE_CONFIG, LAPIC_DIVIDE_BY_ONE);
        mmio_write32(lapic + LAPIC_INITIAL_COUNT, u32::MAX);
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_lapic_elapsed(lapic: usize) -> u64 {
    const LAPIC_CURRENT_COUNT: usize = 0x390;
    // SAFETY: Reading the owned LAPIC current-count register has no side effect.
    u64::from(u32::MAX - unsafe { mmio_read32(lapic + LAPIC_CURRENT_COUNT) })
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_calibrate_lapic_with_pit(lapic: usize) -> Result<u64, ExecutionTimerError> {
    const PIT_CHANNEL_2_COMMAND: u8 = 0xb0;
    const PIT_TEN_MILLISECONDS: u16 = 11_932;
    const PIT_GATE_2: u8 = 1;
    const PIT_OUT_2: u8 = 1 << 5;
    let pit = x86_ports(troe_platform::IoPortRole::Pit)
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let system_control_resource = x86_ports(troe_platform::IoPortRole::SystemControl)
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let pit_channel = pit.base_port() + 2;
    let pit_command = pit.base_port() + 3;
    let system_control = system_control_resource.base_port();
    // SAFETY: These descriptor-owned resources exist only in pinned q35.
    let original_control = unsafe { port_read(system_control) };
    // SAFETY: Channel 2 is gated low while its one-shot is loaded.
    unsafe {
        port_write(system_control, original_control & !PIT_GATE_2);
        port_write(pit_command, PIT_CHANNEL_2_COMMAND);
        port_write(pit_channel, PIT_TEN_MILLISECONDS.to_le_bytes()[0]);
        port_write(pit_channel, PIT_TEN_MILLISECONDS.to_le_bytes()[1]);
    }
    x86_prepare_lapic_calibration(lapic);
    // SAFETY: Raising the validated channel-2 gate begins the one-shot.
    unsafe { port_write(system_control, (original_control & !0b10) | PIT_GATE_2) };
    let mut completed = false;
    for _ in 0..X86_TIMER_CALIBRATION_SPINS {
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
    x86_lapic_elapsed(lapic)
        .checked_div(10)
        .filter(|ticks| *ticks != 0)
        .ok_or(ExecutionTimerError::InvalidFrequency)
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_calibrate_lapic_with_pm_timer(
    lapic: usize,
    timer: IoPortResource,
    counter_bits: u8,
) -> Result<u64, ExecutionTimerError> {
    x86_prepare_lapic_calibration(lapic);
    let result = (|| {
        let start = x86_pm_timer_sample(timer, counter_bits)
            .ok_or(ExecutionTimerError::InvalidFrequency)?;
        for _ in 0..X86_TIMER_CALIBRATION_SPINS {
            let current = x86_pm_timer_sample(timer, counter_bits)
                .ok_or(ExecutionTimerError::InvalidFrequency)?;
            let elapsed = x86_pm_timer_elapsed(start, current, counter_bits)
                .ok_or(ExecutionTimerError::InvalidFrequency)?;
            if elapsed >= X86_TIMER_CALIBRATION_TICKS {
                return x86_lapic_elapsed(lapic)
                    .checked_mul(X86_PM_TIMER_HZ)
                    .and_then(|ticks| ticks.checked_div(u64::from(elapsed)))
                    .and_then(|ticks| ticks.checked_div(1_000))
                    .filter(|ticks| *ticks != 0)
                    .ok_or(ExecutionTimerError::InvalidFrequency);
            }
            spin_loop();
        }
        Err(ExecutionTimerError::Unsupported)
    })();
    if result.is_err() {
        architecture_disarm_execution_timer();
    }
    result
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_disarm_execution_timer() {
    const LAPIC_LVT_TIMER: usize = 0x320;
    const LAPIC_INITIAL_COUNT: usize = 0x380;
    const LAPIC_MASKED: u32 = 1 << 16;
    if let Ok(resource) = x86_mmio(troe_platform::MmioRole::LocalApic)
        && let Ok(lapic) = usize::try_from(resource.base_address())
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
    if let Ok(resource) = x86_mmio(troe_platform::MmioRole::LocalApic)
        && let Ok(lapic) = usize::try_from(resource.base_address())
    {
        // SAFETY: The active LAPIC timer interrupt requires one EOI write.
        unsafe { mmio_write32(lapic + LAPIC_EOI, 0) };
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_drain_input_devices(queue: &mut BoundedInputQueue) -> bool {
    let budget = queue.config().max_drain_per_interrupt();
    let mut drained = false;
    for _ in 0..budget {
        if let Some(byte) = try_read_keyboard_scancode() {
            let _result = queue.push(InputEvent::new(InputSource::Keyboard, byte));
            drained = true;
            continue;
        }
        if let Some(byte) = architecture_try_read_byte() {
            let _result = queue.push(InputEvent::new(InputSource::Serial, byte));
            drained = true;
            continue;
        }
        break;
    }
    drained
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_route_ioapic(
    ioapic: MmioResource,
    interrupt: InterruptResource,
    trigger: troe_platform::TriggerMode,
    polarity: troe_platform::Polarity,
    apic_id: u32,
) {
    let register = 0x10 + interrupt.line() * 2;
    x86_ioapic_write(ioapic, register, 1 << 16);
    x86_ioapic_write(ioapic, register + 1, apic_id << 24);
    x86_ioapic_write(
        ioapic,
        register,
        u32::from(interrupt.vector()) | x86_ioapic_mode_bits(trigger, polarity),
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_prepare_network_interrupt(
    route: &NetworkInterruptRoute,
) -> Result<(), InputInterruptError> {
    const LAPIC_ID: usize = 0x020;
    const IOAPIC_MASKED: u32 = 1 << 16;
    let NetworkInterruptSource::PciIntx { pin } = route.source() else {
        return Err(InputInterruptError::InvalidResource);
    };
    if !(1..=4).contains(pin) {
        return Err(InputInterruptError::InvalidResource);
    }
    let interrupt = route.interrupt();
    let lapic = x86_mmio(troe_platform::MmioRole::LocalApic)?;
    let ioapic = x86_mmio(troe_platform::MmioRole::IoApic)?;
    let electrical = x86_ioapic_electrical_bits(route)?;
    architecture_mask_input_interrupts();
    let result = (|| {
        let maximum_entry = (x86_ioapic_read(ioapic, 1) >> 16) & 0xff;
        if interrupt.line() > maximum_entry {
            return Err(InputInterruptError::InterruptLineUnavailable);
        }
        let lapic_base = usize::try_from(lapic.base_address())
            .map_err(|_| InputInterruptError::InvalidResource)?;
        // SAFETY: The mapped LAPIC ID register belongs to the boot CPU.
        let apic_id = unsafe { mmio_read32(lapic_base + LAPIC_ID) } >> 24;
        let register = 0x10 + interrupt.line() * 2;
        x86_ioapic_write(ioapic, register, 1 << 16);
        x86_ioapic_write(ioapic, register + 1, apic_id << 24);
        x86_ioapic_write(
            ioapic,
            register,
            u32::from(interrupt.vector()) | electrical | IOAPIC_MASKED,
        );
        Ok(())
    })();
    architecture_enable_input_interrupts();
    result
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_activate_network_interrupt(route: &NetworkInterruptRoute) {
    let Ok(ioapic) = x86_mmio(troe_platform::MmioRole::IoApic) else {
        park();
    };
    let Ok(electrical) = x86_ioapic_electrical_bits(route) else {
        park();
    };
    let interrupt = route.interrupt();
    architecture_mask_input_interrupts();
    x86_ioapic_write(
        ioapic,
        0x10 + interrupt.line() * 2,
        u32::from(interrupt.vector()) | electrical,
    );
    architecture_enable_input_interrupts();
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_deactivate_network_interrupt(route: &NetworkInterruptRoute) {
    const IOAPIC_MASKED: u32 = 1 << 16;
    let Ok(ioapic) = x86_mmio(troe_platform::MmioRole::IoApic) else {
        park();
    };
    let Ok(electrical) = x86_ioapic_electrical_bits(route) else {
        park();
    };
    let interrupt = route.interrupt();
    architecture_mask_input_interrupts();
    x86_ioapic_write(
        ioapic,
        0x10 + interrupt.line() * 2,
        u32::from(interrupt.vector()) | electrical | IOAPIC_MASKED,
    );
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_cancel_prepared_network_interrupt(route: &NetworkInterruptRoute) {
    architecture_deactivate_network_interrupt(route);
    architecture_enable_input_interrupts();
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_ioapic_electrical_bits(route: &NetworkInterruptRoute) -> Result<u32, InputInterruptError> {
    if route.priority() != 0 {
        return Err(InputInterruptError::InvalidResource);
    }
    Ok(x86_ioapic_mode_bits(route.trigger(), route.polarity()))
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn x86_ioapic_mode_bits(
    trigger: troe_platform::TriggerMode,
    polarity: troe_platform::Polarity,
) -> u32 {
    let trigger = match trigger {
        troe_platform::TriggerMode::Edge => 0,
        troe_platform::TriggerMode::Level => 1 << 15,
    };
    let polarity = match polarity {
        troe_platform::Polarity::ActiveHigh => 0,
        troe_platform::Polarity::ActiveLow => 1 << 13,
    };
    trigger | polarity
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
fn architecture_initialize_console() {
    let Ok(platform) = crate::selected_platform() else {
        return;
    };
    if platform.console() != troe_platform::ConsoleKind::Uart16550 {
        return;
    }
    let Ok(serial) = x86_ports(troe_platform::IoPortRole::Serial) else {
        return;
    };
    let base = serial.base_port();
    // SAFETY: The validated descriptor exposes an eight-register 16550 block.
    unsafe {
        port_write(base + 1, 0x00);
        port_write(base + 3, 0x80);
        port_write(base, 0x01);
        port_write(base + 1, 0x00);
        port_write(base + 3, 0x03);
        port_write(base + 2, 0xc7);
        port_write(base + 4, 0x0b);
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn write_byte(byte: u8) -> bool {
    let Ok(serial) = x86_ports(troe_platform::IoPortRole::Serial) else {
        return false;
    };
    let base = serial.base_port();
    for _ in 0..UART_SPIN_LIMIT {
        // SAFETY: The validated descriptor owns the 16550 status register.
        if unsafe { port_read(base + 5) } & 0x20 != 0 {
            // SAFETY: The transmitter is ready and COM1 is exclusively owned.
            unsafe { port_write(base, byte) };
            return true;
        }
        spin_loop();
    }
    false
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_try_read_byte() -> Option<u8> {
    let serial = x86_ports(troe_platform::IoPortRole::Serial).ok()?;
    let base = serial.base_port();
    // SAFETY: The validated descriptor owns the 16550 status register.
    if unsafe { port_read(base + 5) } & 1 == 0 {
        None
    } else {
        // SAFETY: The receiver reports one available byte.
        Some(unsafe { port_read(base) })
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_park() {
    // SAFETY: The terminal state owns interrupt policy and intentionally keeps
    // maskable interrupts disabled while halting forever.
    unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_poweroff() {
    const ACPI_SLEEP_ENABLE: u16 = 1 << 13;
    let Ok(platform) = crate::selected_platform() else {
        return;
    };
    let troe_platform::PowerKind::Q35 {
        pm_control_port,
        sleep_type,
        ..
    } = platform.power()
    else {
        return;
    };
    let value = (u16::from(sleep_type) << 10) | ACPI_SLEEP_ENABLE;
    // SAFETY: Descriptor validation proves the PM1 port belongs to its owned
    // range and supplies the selected platform's S5 sleep type.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") pm_control_port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[cfg(all(target_os = "uefi", target_arch = "x86_64"))]
fn architecture_reboot() {
    const Q35_RESET_SYSTEM: u8 = 0x06;
    let Ok(platform) = crate::selected_platform() else {
        return;
    };
    let (reset_control_port, reset_value) = match platform.power() {
        troe_platform::PowerKind::Q35 {
            reset_control_port, ..
        } => (reset_control_port, Q35_RESET_SYSTEM),
        troe_platform::PowerKind::X86Reset {
            reset_control_port,
            reset_value,
        } => (reset_control_port, reset_value),
        troe_platform::PowerKind::PsciHvc => return,
    };
    // SAFETY: The validated descriptor assigns the reset-control port; requesting
    // a full system reset is terminal and the caller parks if it returns.
    unsafe { port_write(reset_control_port, reset_value) };
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
fn aarch64_mmio(role: troe_platform::MmioRole) -> Result<MmioResource, InputInterruptError> {
    let resource = crate::selected_platform()
        .map_err(|_| InputInterruptError::InvalidResource)?
        .mmio(role)
        .ok_or(InputInterruptError::InvalidResource)?;
    MmioResource::new(resource.base(), resource.byte_len())
        .map_err(|_| InputInterruptError::InvalidResource)
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn aarch64_gicv2_cpu_target_mask() -> Result<u8, InputInterruptError> {
    let controller = crate::selected_platform()
        .map_err(|_| InputInterruptError::InvalidResource)?
        .interrupt_controller();
    let troe_platform::InterruptControllerKind::GicV2 { cpu_target_mask } = controller else {
        return Err(InputInterruptError::InvalidResource);
    };
    Ok(cpu_target_mask)
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_input_device_ranges() -> Result<[Option<PhysicalRange>; 3], InputInterruptError> {
    let distributor = aarch64_mmio(troe_platform::MmioRole::GicV2Distributor)?;
    let cpu_interface = aarch64_mmio(troe_platform::MmioRole::GicV2CpuInterface)?;
    let pl011 = aarch64_mmio(troe_platform::MmioRole::Pl011)?;
    Ok([
        Some(resource_page_range(distributor)?),
        Some(resource_page_range(cpu_interface)?),
        Some(resource_page_range(pl011)?),
    ])
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_initialize_input_interrupts(
    _config: InputQueueConfig,
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

    let gic_distributor = aarch64_mmio(troe_platform::MmioRole::GicV2Distributor)?;
    let gic_cpu_interface = aarch64_mmio(troe_platform::MmioRole::GicV2CpuInterface)?;
    let cpu_target_mask = aarch64_gicv2_cpu_target_mask()?;
    let serial_route = crate::selected_platform()
        .map_err(|_| InputInterruptError::InvalidResource)?
        .interrupt(troe_platform::InterruptRole::Serial)
        .ok_or(InputInterruptError::InvalidResource)?;
    let serial_interrupt = InterruptResource::new(serial_route.line(), serial_route.vector())
        .map_err(|_| InputInterruptError::InvalidResource)?;
    let pl011 = aarch64_mmio(troe_platform::MmioRole::Pl011)?;
    let pl011_base =
        usize::try_from(pl011.base_address()).map_err(|_| InputInterruptError::InvalidResource)?;
    let distributor = usize::try_from(gic_distributor.base_address())
        .map_err(|_| InputInterruptError::InvalidResource)?;
    let cpu = usize::try_from(gic_cpu_interface.base_address())
        .map_err(|_| InputInterruptError::InvalidResource)?;
    let intid = usize::try_from(serial_interrupt.line())
        .map_err(|_| InputInterruptError::InvalidResource)?;
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

    // SAFETY: All fallible profile validation is complete. The full GICv2
    // aperture is mapped RW/NX and IRQ delivery remains masked while ownership
    // is committed, so no failure can expose a partially initialized controller.
    unsafe {
        mmio_write32(cpu + GICC_CTLR, 0);
        mmio_write32(distributor + GICD_CTLR, 0);
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
            serial_route.priority(),
        );
        gicv2_update_byte(distributor + GICD_ITARGETSR, intid, cpu_target_mask);
        let config_address = distributor + GICD_ICFGR + (intid / 16) * 4;
        let config_shift = (intid % 16) * 2;
        let edge = match serial_route.trigger() {
            troe_platform::TriggerMode::Edge => 0b10,
            troe_platform::TriggerMode::Level => 0,
        };
        let config =
            (mmio_read32(config_address) & !(0b10 << config_shift)) | (edge << config_shift);
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
        pl011_write(
            pl011_base,
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
    let Ok(gic_cpu_interface) = aarch64_mmio(troe_platform::MmioRole::GicV2CpuInterface) else {
        return false;
    };
    let Ok(serial_interrupt) = platform_interrupt(troe_platform::InterruptRole::Serial) else {
        return false;
    };
    let Ok(timer_interrupt) = platform_interrupt(troe_platform::InterruptRole::Timer) else {
        return false;
    };
    let Ok(pl011) = aarch64_mmio(troe_platform::MmioRole::Pl011) else {
        return false;
    };
    let Ok(pl011_base) = usize::try_from(pl011.base_address()) else {
        return false;
    };
    let Ok(cpu) = usize::try_from(gic_cpu_interface.base_address()) else {
        return false;
    };
    // SAFETY: GICC_IAR acknowledges the highest-priority pending interrupt.
    let acknowledge = unsafe { mmio_read32(cpu + GICC_IAR) };
    let intid = acknowledge & 0x03ff;
    let execution_timer = intid == timer_interrupt.line();
    if execution_timer {
        architecture_disarm_execution_timer();
    } else if intid == AARCH64_NETWORK_INTERRUPT_INTID.load(Ordering::Acquire) {
        if crate::acknowledge_network_interrupt_from_isr() {
            NETWORK_INTERRUPT_PENDING.store(true, Ordering::Release);
        }
    } else if intid == serial_interrupt.line() {
        queue.record_interrupt();
        // Acknowledge the latched sources before draining. A byte arriving
        // after this write either joins the drain or asserts a fresh source;
        // clearing after the drain would erase that fresh event.
        // SAFETY: These bits clear only the acknowledged PL011 receive sources.
        unsafe {
            pl011_write(
                pl011_base,
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
fn architecture_prepare_network_interrupt(
    route: &NetworkInterruptRoute,
) -> Result<(), InputInterruptError> {
    const GICD_TYPER: usize = 0x004;
    const GICD_IGROUPR: usize = 0x080;
    const GICD_ICENABLER: usize = 0x180;
    const GICD_ICPENDR: usize = 0x280;
    const GICD_IPRIORITYR: usize = 0x400;
    const GICD_ITARGETSR: usize = 0x800;
    const GICD_ICFGR: usize = 0xc00;
    let NetworkInterruptSource::VirtioMmio { slot } = route.source() else {
        return Err(InputInterruptError::InvalidResource);
    };
    let platform = crate::selected_platform().map_err(|_| InputInterruptError::InvalidResource)?;
    let troe_platform::VirtioTransportKind::Mmio { slot_count, .. } = platform.virtio() else {
        return Err(InputInterruptError::InvalidResource);
    };
    if *slot >= u32::from(slot_count) {
        return Err(InputInterruptError::InvalidResource);
    }
    let intid = route.interrupt().line();
    if route.polarity() != troe_platform::Polarity::ActiveHigh || route.priority() == 0 {
        return Err(InputInterruptError::InvalidResource);
    }
    let gic = aarch64_mmio(troe_platform::MmioRole::GicV2Distributor)?;
    let cpu_target_mask = aarch64_gicv2_cpu_target_mask()?;
    architecture_mask_input_interrupts();
    let result = (|| {
        let distributor = usize::try_from(gic.base_address())
            .map_err(|_| InputInterruptError::InvalidResource)?;
        // SAFETY: GICD_TYPER is a read-only register in the mapped aperture.
        let count = usize::try_from((unsafe { mmio_read32(distributor + GICD_TYPER) } & 0x1f) + 1)
            .map_err(|_| InputInterruptError::InvalidResource)?
            .checked_mul(32)
            .ok_or(InputInterruptError::InvalidResource)?;
        let intid_index =
            usize::try_from(intid).map_err(|_| InputInterruptError::InvalidResource)?;
        if intid_index < 32 || intid_index >= count {
            return Err(InputInterruptError::InterruptLineUnavailable);
        }
        let word = intid_index / 32;
        let bit = 1_u32 << (intid_index % 32);
        // SAFETY: TYPER bounds the selected SPI registers; IRQs are masked.
        unsafe {
            mmio_write32(distributor + GICD_ICENABLER + word * 4, bit);
            mmio_write32(distributor + GICD_ICPENDR + word * 4, bit);
            let group = mmio_read32(distributor + GICD_IGROUPR + word * 4);
            mmio_write32(distributor + GICD_IGROUPR + word * 4, group & !bit);
            gicv2_update_byte(distributor + GICD_IPRIORITYR, intid_index, route.priority());
            gicv2_update_byte(distributor + GICD_ITARGETSR, intid_index, cpu_target_mask);
            let address = distributor + GICD_ICFGR + (intid_index / 16) * 4;
            let shift = (intid_index % 16) * 2;
            let edge = match route.trigger() {
                troe_platform::TriggerMode::Edge => 0b10,
                troe_platform::TriggerMode::Level => 0,
            };
            let config = (mmio_read32(address) & !(0b10 << shift)) | (edge << shift);
            mmio_write32(address, config);
            core::arch::asm!("dsb sy", "isb", options(nomem, nostack));
        }
        Ok(())
    })();
    architecture_enable_input_interrupts();
    result
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_activate_network_interrupt(route: &NetworkInterruptRoute) {
    const GICD_ISENABLER: usize = 0x100;
    let Ok(gic) = aarch64_mmio(troe_platform::MmioRole::GicV2Distributor) else {
        park();
    };
    let Ok(distributor) = usize::try_from(gic.base_address()) else {
        park();
    };
    let intid = route.interrupt().line();
    let Ok(intid_index) = usize::try_from(intid) else {
        park();
    };
    let word = intid_index / 32;
    let bit = 1_u32 << (intid_index % 32);
    architecture_mask_input_interrupts();
    if AARCH64_NETWORK_INTERRUPT_INTID
        .compare_exchange(u32::MAX, intid, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        park();
    }
    // SAFETY: Preparation validated the SPI against TYPER and configured it
    // while disabled. The published INTID precedes controller unmasking.
    unsafe {
        mmio_write32(distributor + GICD_ISENABLER + word * 4, bit);
        core::arch::asm!("dsb sy", "isb", options(nomem, nostack));
    }
    architecture_enable_input_interrupts();
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_deactivate_network_interrupt(route: &NetworkInterruptRoute) {
    const GICD_ICENABLER: usize = 0x180;
    let Ok(gic) = aarch64_mmio(troe_platform::MmioRole::GicV2Distributor) else {
        park();
    };
    let Ok(distributor) = usize::try_from(gic.base_address()) else {
        park();
    };
    let Ok(intid) = usize::try_from(route.interrupt().line()) else {
        park();
    };
    let word = intid / 32;
    let bit = 1_u32 << (intid % 32);
    architecture_mask_input_interrupts();
    // SAFETY: The active/prepared token names the TYPER-validated SPI.
    unsafe {
        mmio_write32(distributor + GICD_ICENABLER + word * 4, bit);
        core::arch::asm!("dsb sy", "isb", options(nomem, nostack));
    }
    if AARCH64_NETWORK_INTERRUPT_INTID
        .compare_exchange(
            route.interrupt().line(),
            u32::MAX,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        park();
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_cancel_prepared_network_interrupt(route: &NetworkInterruptRoute) {
    const GICD_ICENABLER: usize = 0x180;
    let Ok(gic) = aarch64_mmio(troe_platform::MmioRole::GicV2Distributor) else {
        park();
    };
    let Ok(distributor) = usize::try_from(gic.base_address()) else {
        park();
    };
    let Ok(intid) = usize::try_from(route.interrupt().line()) else {
        park();
    };
    let word = intid / 32;
    let bit = 1_u32 << (intid % 32);
    architecture_mask_input_interrupts();
    // SAFETY: Preparation validated the SPI against TYPER. Cancellation masks
    // only this uncommitted route and must not revoke another active route's
    // published INTID.
    unsafe {
        mmio_write32(distributor + GICD_ICENABLER + word * 4, bit);
        core::arch::asm!("dsb sy", "isb", options(nomem, nostack));
    }
    architecture_enable_input_interrupts();
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_monotonic_millis() -> Option<u64> {
    if crate::selected_platform().ok()?.timer() != troe_platform::TimerKind::Aarch64Generic {
        return None;
    }
    let frequency: u64;
    let counter: u64;
    // SAFETY: CNTFRQ_EL0 and CNTPCT_EL0 are read-only at EL1 and the generic
    // counter is monotonic across the pinned single-vCPU profile.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) counter, options(nomem, nostack));
    }
    counter_millis(counter, frequency)
}

#[cfg(any(test, all(target_os = "uefi", target_arch = "aarch64")))]
fn counter_millis(counter: u64, frequency: u64) -> Option<u64> {
    if frequency < 1_000 {
        return None;
    }
    let whole_seconds = counter.checked_div(frequency)?;
    let remainder = counter.checked_rem(frequency)?;
    whole_seconds
        .checked_mul(1_000)?
        .checked_add(remainder.checked_mul(1_000)?.checked_div(frequency)?)
}

#[cfg(all(
    target_os = "uefi",
    target_arch = "aarch64",
    feature = "acceptance-probes"
))]
fn architecture_benchmark_counter_ticks() -> u64 {
    let counter: u64;
    // SAFETY: CNTPCT_EL0 is read-only at EL1; ISB orders the timestamp after
    // preceding benchmark work on the pinned single-vCPU acceptance profile.
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {}, cntpct_el0",
            out(reg) counter,
            options(nomem, nostack)
        );
    }
    counter
}

#[cfg(all(
    target_os = "uefi",
    target_arch = "aarch64",
    feature = "acceptance-probes"
))]
fn architecture_benchmark_counter_frequency_hz() -> Option<u64> {
    let frequency: u64;
    // SAFETY: CNTFRQ_EL0 is a read-only generic-timer register at EL1.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack));
    }
    (frequency != 0).then_some(frequency)
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
    let gic = aarch64_mmio(troe_platform::MmioRole::GicV2Distributor)
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let timer_route = crate::selected_platform()
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?
        .interrupt(troe_platform::InterruptRole::Timer)
        .ok_or(ExecutionTimerError::InterruptUnavailable)?;
    if timer_route.polarity() != troe_platform::Polarity::ActiveHigh {
        return Err(ExecutionTimerError::InterruptUnavailable);
    }
    let distributor = usize::try_from(gic.base_address())
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let intid = usize::try_from(timer_route.line())
        .map_err(|_| ExecutionTimerError::InterruptUnavailable)?;
    let word = intid / 32;
    let bit = 1_u32 << (intid % 32);
    if !AARCH64_EXECUTION_TIMER_CONFIGURED.load(Ordering::Acquire) {
        // SAFETY: PPI 30 is the architected non-secure physical timer interrupt;
        // the caller masked IRQ delivery before this one-time configuration.
        unsafe {
            let group = mmio_read32(distributor + GICD_IGROUPR + word * 4);
            mmio_write32(distributor + GICD_IGROUPR + word * 4, group & !bit);
            gicv2_update_byte(distributor + GICD_IPRIORITYR, intid, timer_route.priority());
            let config_address = distributor + GICD_ICFGR + (intid / 16) * 4;
            let config_shift = (intid % 16) * 2;
            let edge = match timer_route.trigger() {
                troe_platform::TriggerMode::Edge => 0b10,
                troe_platform::TriggerMode::Level => 0,
            };
            let config =
                (mmio_read32(config_address) & !(0b10 << config_shift)) | (edge << config_shift);
            mmio_write32(distributor + GICD_ICFGR + (intid / 16) * 4, config);
            mmio_write32(distributor + GICD_ISENABLER + word * 4, bit);
        }
        AARCH64_EXECUTION_TIMER_CONFIGURED.store(true, Ordering::Release);
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
    const BAUD: u64 = 115_200;
    let Ok(platform) = crate::selected_platform() else {
        return;
    };
    let troe_platform::ConsoleKind::Pl011 { clock_hz } = platform.console() else {
        return;
    };
    let Ok(resource) = aarch64_mmio(troe_platform::MmioRole::Pl011) else {
        return;
    };
    let Ok(base) = usize::try_from(resource.base_address()) else {
        return;
    };
    let denominator = 16 * BAUD;
    let mut integer = u64::from(clock_hz) / denominator;
    let remainder = u64::from(clock_hz) % denominator;
    let mut fractional = (remainder * 64 + denominator / 2) / denominator;
    if fractional == 64 {
        integer += 1;
        fractional = 0;
    }
    let (Ok(integer), Ok(fractional)) = (u32::try_from(integer), u32::try_from(fractional)) else {
        return;
    };
    if integer == 0 || integer > 0xffff {
        return;
    }
    // SAFETY: The descriptor validates the PL011 aperture and input clock; the
    // computed divisors select approximately 115200 baud without fixed clocks.
    unsafe {
        pl011_write(base, PL011_CONTROL, 0);
        pl011_write(base, PL011_INTERRUPT_CLEAR, 0x07ff);
        pl011_write(base, PL011_INTEGER_BAUD, integer);
        pl011_write(base, PL011_FRACTIONAL_BAUD, fractional);
        pl011_write(base, PL011_LINE_CONTROL, 0x70);
        pl011_write(base, PL011_INTERRUPT_MASK, 0);
        pl011_write(base, PL011_CONTROL, 0x0301);
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn write_byte(byte: u8) -> bool {
    let Ok(resource) = aarch64_mmio(troe_platform::MmioRole::Pl011) else {
        return false;
    };
    let Ok(base) = usize::try_from(resource.base_address()) else {
        return false;
    };
    for _ in 0..UART_SPIN_LIMIT {
        // SAFETY: The validated descriptor owns the PL011 flag register.
        if unsafe { pl011_read(base, PL011_FLAGS) } & (1 << 5) == 0 {
            // SAFETY: The transmitter FIFO has capacity for one byte.
            unsafe { pl011_write(base, PL011_DATA, u32::from(byte)) };
            return true;
        }
        spin_loop();
    }
    false
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_try_read_byte() -> Option<u8> {
    let resource = aarch64_mmio(troe_platform::MmioRole::Pl011).ok()?;
    let base = usize::try_from(resource.base_address()).ok()?;
    // SAFETY: The validated descriptor owns the PL011 flag register.
    if unsafe { pl011_read(base, PL011_FLAGS) } & (1 << 4) != 0 {
        None
    } else {
        // SAFETY: The receiver FIFO reports one available byte.
        Some(unsafe { pl011_read(base, PL011_DATA) }.to_le_bytes()[0])
    }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_park() {
    // SAFETY: WFE in the terminal state has no memory effects; the surrounding
    // loop repeats if an event wakes the CPU.
    unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_poweroff() {
    const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
    let Ok(platform) = crate::selected_platform() else {
        return;
    };
    if platform.power() != troe_platform::PowerKind::PsciHvc {
        return;
    }
    let _unexpected_return = psci_hvc(PSCI_SYSTEM_OFF);
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn architecture_reboot() {
    const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
    let Ok(platform) = crate::selected_platform() else {
        return;
    };
    if platform.power() != troe_platform::PowerKind::PsciHvc {
        return;
    }
    let _unexpected_return = psci_hvc(PSCI_SYSTEM_RESET);
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
fn psci_hvc(function_id: u64) -> u64 {
    let mut result = function_id;
    // SAFETY: The pinned QEMU virt profile advertises PSCI 1.0 with the HVC
    // conduit. SYSTEM_OFF and SYSTEM_RESET take no arguments and are terminal
    // on success; x0 carries a stable PSCI error if firmware rejects the call.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") result,
            out("x1") _,
            out("x2") _,
            out("x3") _,
            options(nostack)
        );
    }
    result
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
unsafe fn pl011_read(base: usize, offset: usize) -> u32 {
    // SAFETY: The caller supplies a valid aligned PL011 register offset.
    unsafe { ptr::read_volatile((base + offset) as *const u32) }
}

#[cfg(all(target_os = "uefi", target_arch = "aarch64"))]
unsafe fn pl011_write(base: usize, offset: usize, value: u32) {
    // SAFETY: The caller supplies a valid aligned writable PL011 register.
    unsafe { ptr::write_volatile((base + offset) as *mut u32, value) };
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
    use super::{
        ActiveNetworkInterrupt, DeactivatedNetworkInterrupt, DmaInitializationPhase,
        DmaInitializationState, HeapState, InputInterruptError, NetworkInterruptRoute,
        NetworkInterruptSource, PreparedNetworkInterrupt, TaskStackError, UsedIndexTransition,
        cached_nonzero, claim_network_interrupt_publication, classify_used_index, counter_millis,
        revoke_network_interrupt_publication, validate_task_stack,
    };
    use core::alloc::Layout;
    use core::cell::Cell;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use troe_memory::PhysicalRange;

    #[repr(align(4096))]
    struct TestArena([u8; 4096]);

    #[test]
    fn timer_calibration_is_cached_after_one_nonzero_result() {
        let cache = AtomicU64::new(0);
        let calls = Cell::new(0_u8);
        let first = cached_nonzero(&cache, || {
            calls.set(calls.get() + 1);
            Ok::<u64, ()>(7)
        });
        let second = cached_nonzero(&cache, || {
            calls.set(calls.get() + 1);
            Ok::<u64, ()>(11)
        });
        assert_eq!(first, Ok(7));
        assert_eq!(second, Ok(7));
        assert_eq!(calls.get(), 1);
        assert_eq!(cache.load(Ordering::Acquire), 7);
    }

    #[test]
    fn counter_millisecond_scaling_preserves_long_uptime() {
        assert_eq!(counter_millis(u64::MAX, 1_000), Some(u64::MAX));
        assert_eq!(
            counter_millis(u64::MAX, 1_000_000_000),
            Some(18_446_744_073_709)
        );
        assert_eq!(counter_millis(999, 1_000), Some(999));
        assert_eq!(counter_millis(1, 999), None);
    }

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

    #[test]
    fn network_routes_reject_invalid_and_colliding_resources() {
        let Ok(route) = NetworkInterruptRoute::q35_pci_intx(11, 1) else {
            return;
        };
        assert!(matches!(
            route.source(),
            NetworkInterruptSource::PciIntx { pin: 1 }
        ));
        assert_eq!(route.interrupt().line(), 11);
        assert_eq!(route.priority(), 0);
        assert_eq!(route.trigger(), troe_platform::TriggerMode::Level);
        assert_eq!(route.polarity(), troe_platform::Polarity::ActiveLow);
        let prepared = PreparedNetworkInterrupt { route };
        let active = ActiveNetworkInterrupt {
            route: prepared.route,
        };
        let deactivated = DeactivatedNetworkInterrupt {
            route: active.route,
        };
        assert!(matches!(
            deactivated,
            DeactivatedNetworkInterrupt {
                route: NetworkInterruptRoute {
                    source: NetworkInterruptSource::PciIntx { pin: 1 },
                    ..
                }
            }
        ));
        for (line, pin) in [(11, 0), (11, 5), (1, 1), (4, 1), (24, 1), (u8::MAX, 1)] {
            assert_eq!(
                NetworkInterruptRoute::q35_pci_intx(line, pin),
                Err(InputInterruptError::InvalidResource)
            );
        }

        let first_result = NetworkInterruptRoute::virtio_mmio(0, 32, 48);
        assert!(matches!(
            first_result,
            Ok(NetworkInterruptRoute {
                source: NetworkInterruptSource::VirtioMmio { slot: 0 },
                ..
            })
        ));
        let Ok(first) = NetworkInterruptRoute::virtio_mmio(0, 32, 48) else {
            return;
        };
        assert_eq!(first.priority(), 0x20);
        assert_eq!(first.trigger(), troe_platform::TriggerMode::Edge);
        assert_eq!(first.polarity(), troe_platform::Polarity::ActiveHigh);
        assert!(NetworkInterruptRoute::virtio_mmio(31, 32, 48).is_ok());
        assert_eq!(
            NetworkInterruptRoute::virtio_mmio(32, 32, 48),
            Err(InputInterruptError::InvalidResource)
        );
        assert_eq!(
            NetworkInterruptRoute::virtio_mmio(0, 0, 48),
            Err(InputInterruptError::InvalidResource)
        );
        assert_eq!(
            NetworkInterruptRoute::virtio_mmio(0, 32, u32::MAX),
            Err(InputInterruptError::InvalidResource)
        );
        assert_eq!(
            NetworkInterruptRoute::virtio_mmio(0, 32, 33),
            Err(InputInterruptError::InvalidResource)
        );
        assert_eq!(
            NetworkInterruptRoute::virtio_mmio(0, 1, 1019),
            Err(InputInterruptError::InvalidResource)
        );
        assert_eq!(
            NetworkInterruptRoute::virtio_mmio(0, 1, 1020),
            Err(InputInterruptError::InvalidResource)
        );
        assert_ne!(
            InputInterruptError::QueueMetadataExhausted,
            InputInterruptError::AlreadyInitialized
        );
        assert_ne!(
            InputInterruptError::AlreadyInitialized,
            InputInterruptError::InterruptLineUnavailable
        );
    }

    #[test]
    fn fault_injection_at_every_dma_initialization_phase_requires_reset() {
        let mut state = DmaInitializationState::new();
        assert_eq!(state.phase(), DmaInitializationPhase::DeviceStateChanged);
        let after_device_state_change = state;

        state.mark_queue_published();
        assert_eq!(state.phase(), DmaInitializationPhase::QueuePublished);
        let after_queue_publication = state;

        state.mark_driver_ok();
        assert_eq!(state.phase(), DmaInitializationPhase::DriverOk);
        let after_driver_ok = state;

        for injected_failure in [
            after_device_state_change,
            after_queue_publication,
            after_driver_ok,
        ] {
            assert!(injected_failure.cleanup_requires_reset());
        }

        state.transfer_ownership();
        assert_eq!(state.phase(), DmaInitializationPhase::OwnershipTransferred);
        assert!(!state.cleanup_requires_reset());
    }

    #[test]
    fn one_in_flight_used_index_rejects_skips_and_replays() {
        assert_eq!(classify_used_index(7, 7), UsedIndexTransition::Empty);
        assert_eq!(classify_used_index(7, 8), UsedIndexTransition::Completed);
        assert_eq!(classify_used_index(7, 9), UsedIndexTransition::Invalid);
        assert_eq!(classify_used_index(7, 6), UsedIndexTransition::Invalid);
        assert_eq!(
            classify_used_index(u16::MAX, 0),
            UsedIndexTransition::Completed
        );
        assert_eq!(
            classify_used_index(u16::MAX, 1),
            UsedIndexTransition::Invalid
        );
    }

    #[test]
    fn network_interrupt_publication_is_exclusive_and_owner_checked() {
        let publication = AtomicUsize::new(0);
        assert!(!claim_network_interrupt_publication(&publication, 0));
        assert!(claim_network_interrupt_publication(&publication, 0x1000));
        assert!(!claim_network_interrupt_publication(&publication, 0x2000));
        assert_eq!(publication.load(Ordering::Acquire), 0x1000);

        assert!(!revoke_network_interrupt_publication(&publication, 0x2000));
        assert_eq!(publication.load(Ordering::Acquire), 0x1000);
        assert!(revoke_network_interrupt_publication(&publication, 0x1000));
        assert_eq!(publication.load(Ordering::Acquire), 0);
    }
}

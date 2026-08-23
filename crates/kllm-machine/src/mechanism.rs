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
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(test, target_os = "uefi"))]
use kllm_memory::PhysicalRange;
#[cfg(target_os = "uefi")]
use kllm_task::TaskStep;
#[cfg(target_os = "uefi")]
use kllm_terminal::{
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

/// Initialize the architecture-native UART for the pinned QEMU profile.
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
        const PS2_DATA: u16 = 0x0060;
        const PS2_STATUS: u16 = 0x0064;
        // SAFETY: The pinned q35 profile owns the legacy i8042 controller.
        let status = unsafe { port_read(PS2_STATUS) };
        if status & 1 == 0 || status & (1 << 5) != 0 {
            None
        } else {
            // SAFETY: The status register reports one keyboard byte available.
            Some(unsafe { port_read(PS2_DATA) })
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        None
    }
}

/// Park the current CPU permanently after an authorized halt.
#[cfg(target_os = "uefi")]
pub fn park() -> ! {
    loop {
        architecture_park();
    }
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

#[cfg(test)]
mod tests {
    use super::{HeapState, TaskStackError, validate_task_stack};
    use core::alloc::Layout;
    use kllm_memory::PhysicalRange;

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

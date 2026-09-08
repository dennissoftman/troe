//! Single-owner private IPC pages and the persistent server entry point.

use crate::{Error, HeapRegion, Startup, StartupError, interface};
pub use troe_abi::ipc::{Event, EventKind};

/// A startup-validated call capability. Copying it adds no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcHandle(pub(crate) u64);

/// Unique owner of the task's private TX/RX mappings.
///
/// Neither page can be borrowed across a call: the call requires exclusive
/// access to this token, and every received slice borrows it. This type cannot
/// be cloned or constructed by safe application code.
///
/// ```compile_fail
/// use troe_kex_sdk::{IpcPages, IpcHandle};
/// fn cannot_call_with_live_receive(pages: &mut IpcPages, handle: IpcHandle) {
///     let received = pages.rx();
///     pages.call(handle, 1, 0, 4096, 100, 0).ok();
///     core::hint::black_box(received);
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct IpcPages {
    tx: usize,
    rx: usize,
    received: usize,
}

impl IpcPages {
    pub(crate) const fn new(tx: usize, rx: usize) -> Self {
        Self {
            tx,
            rx,
            received: 0,
        }
    }

    /// Writable outbound page. Only the explicit call prefix is sent.
    pub fn tx(&mut self) -> &mut [u8; 4096] {
        // SAFETY: Only validated startup construction creates this unique
        // token; the kernel maps this page RW/NX for the task's lifetime.
        unsafe { &mut *(self.tx as *mut [u8; 4096]) }
    }

    /// Exact inbound prefix from the most recent completed call or receive.
    #[must_use]
    pub fn rx(&self) -> &[u8] {
        // SAFETY: The private RX mapping is live and no call can mutate it
        // while this shared borrow of the sole owner is retained.
        unsafe { core::slice::from_raw_parts(self.rx as *const u8, self.received) }
    }

    /// Borrow the distinct outbound page and exact inbound prefix together.
    pub fn buffers(&mut self) -> (&mut [u8; 4096], &[u8]) {
        // SAFETY: Startup proves these are distinct live mappings; this
        // exclusive owner prevents another borrow or call during their use.
        unsafe {
            (
                &mut *(self.tx as *mut [u8; 4096]),
                core::slice::from_raw_parts(self.rx as *const u8, self.received),
            )
        }
    }

    /// Send one complete private-page request and retain the exact reply.
    ///
    /// # Errors
    /// Rejects noncanonical lengths and returns typed service/transport failure.
    pub fn call(
        &mut self,
        handle: IpcHandle,
        opcode: u16,
        request_bytes: usize,
        reply_capacity: usize,
        deadline_millis: u64,
        object_parameter: u64,
    ) -> Result<(), Error> {
        self.received = 0;
        let args = [
            handle.0,
            u64::from(opcode),
            request_bytes as u64,
            reply_capacity as u64,
            deadline_millis,
            object_parameter,
        ];
        if troe_abi::ipc::Call::decode(args).is_none() {
            return Err(Error::InvalidCall);
        }
        let words = native(troe_abi::ipc::CALL, args)?;
        if words[1] > reply_capacity as u64 {
            return Err(Error::InvalidCall);
        }
        crate::decode_status(words[0])?;
        self.received = usize::try_from(words[1]).map_err(|_| Error::InvalidCall)?;
        Ok(())
    }
}

/// Startup authority and private pages for one persistent endpoint owner.
pub struct PersistentContext {
    pages: IpcPages,
    wait_set: u64,
    heap: Option<HeapRegion>,
    calls: [Option<(u32, u16, u16, IpcHandle)>; 32],
}

impl PersistentContext {
    fn from_startup(startup: &Startup<'_>) -> Result<Self, StartupError> {
        let endpoint = startup.required_handle(interface::SERVER_ENDPOINT, 2, 0)?;
        let wait_set = startup.required_handle(interface::WAIT_SET, 1, 0)?;
        let mut calls = [None; 32];
        let mut count = 0;
        for descriptor in startup.descriptors_before(startup.handle_count) {
            let descriptor = descriptor?;
            let required = if descriptor.value == endpoint.value {
                interface::rights::RECEIVE | interface::rights::REPLY
            } else if descriptor.value == wait_set.value {
                interface::rights::WAIT
            } else {
                if descriptor.rights == u32::from(interface::rights::CALL) {
                    let slot = calls.get_mut(count).ok_or(StartupError::MissingAuthority)?;
                    *slot = Some((
                        descriptor.interface,
                        descriptor.major,
                        descriptor.minor,
                        IpcHandle(descriptor.value),
                    ));
                    count += 1;
                }
                continue;
            };
            if descriptor.rights != u32::from(required) {
                return Err(StartupError::MissingAuthority);
            }
        }
        Ok(Self {
            pages: startup.ipc_pages()?.ok_or(StartupError::InvalidPage)?,
            wait_set: wait_set.value,
            heap: startup.heap_region()?,
            calls,
        })
    }

    /// Select a typed startup call grant without retaining the startup page.
    ///
    /// # Errors
    /// Rejects absent or ambiguous interface/version authority.
    pub fn call_handle(&self, interface: u32, major: u16, minor: u16) -> Result<IpcHandle, Error> {
        let mut matches = self
            .calls
            .iter()
            .flatten()
            .filter(|&&(id, ma, mi, _)| id == interface && ma == major && mi == minor);
        let handle = matches
            .next()
            .map(|entry| entry.3)
            .ok_or(Error::InvalidCall)?;
        if matches.next().is_some() {
            return Err(Error::InvalidCall);
        }
        Ok(handle)
    }

    /// Make a nested call with exclusive page ownership and an absolute deadline.
    ///
    /// ```compile_fail
    /// use troe_kex_sdk::{PersistentContext, IpcHandle};
    /// fn cannot_retain_rx(context: &mut PersistentContext, handle: IpcHandle) {
    ///     let request = context.rx();
    ///     context.call(handle, 1, 0, 4096, 100).ok();
    ///     core::hint::black_box(request);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns canonical service or transport failure; RX is empty on failure.
    pub fn call(
        &mut self,
        handle: IpcHandle,
        opcode: u16,
        request_bytes: usize,
        reply_capacity: usize,
        deadline_millis: u64,
    ) -> Result<(), Error> {
        self.pages.call(
            handle,
            opcode,
            request_bytes,
            reply_capacity,
            deadline_millis,
            0,
        )
    }

    /// Take the optional unique heap owner.
    pub fn take_heap(&mut self) -> Option<HeapRegion> {
        self.heap.take()
    }

    /// Outbound reply page.
    pub fn tx(&mut self) -> &mut [u8; 4096] {
        self.pages.tx()
    }

    /// Exact last received request prefix.
    #[must_use]
    pub fn rx(&self) -> &[u8] {
        self.pages.rx()
    }

    /// Borrow private TX and the exact RX prefix together.
    pub fn buffers(&mut self) -> (&mut [u8; 4096], &[u8]) {
        self.pages.buffers()
    }

    /// Consume one reply token and atomically receive or publish the next wait.
    ///
    /// # Errors
    /// Rejects noncanonical arguments or malformed native receive metadata.
    pub fn reply_wait(
        &mut self,
        token: u64,
        status: u32,
        reply_bytes: usize,
        deadline_millis: u64,
    ) -> Result<Event, Error> {
        self.pages.received = 0;
        let args = [
            self.wait_set,
            token,
            u64::from(status),
            reply_bytes as u64,
            deadline_millis,
            0,
        ];
        if troe_abi::ipc::ReplyWait::decode(args).is_none() {
            return Err(Error::InvalidCall);
        }
        let event =
            Event::decode(native(troe_abi::ipc::REPLY_WAIT, args)?).ok_or(Error::InvalidCall)?;
        self.pages.received = usize::from(event.request_bytes);
        Ok(event)
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn native(number: u64, words: [u64; 6]) -> Result<[u64; 6], Error> {
    let (mut a, mut d, mut di, mut si, mut r8, mut r9) =
        (number, words[2], words[0], words[1], words[4], words[5]);
    // SAFETY: Arguments are canonical and refer only to this task's private
    // pages; the gate preserves every register except these six results.
    unsafe {
        core::arch::asm!("int 0x80", inlateout("rax") a, inlateout("rdx") d,
        inlateout("rdi") di, inlateout("rsi") si, in("r10") words[3],
        inlateout("r8") r8, inlateout("r9") r9);
    }
    Ok([a, d, di, si, r8, r9])
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn native(number: u64, mut words: [u64; 6]) -> Result<[u64; 6], Error> {
    // SAFETY: Validated private-page arguments and the documented six-result
    // SVC convention; all other application registers are preserved.
    unsafe {
        core::arch::asm!("svc #0", in("x8") number,
        inlateout("x0") words[0], inlateout("x1") words[1], inlateout("x2") words[2],
        inlateout("x3") words[3], inlateout("x4") words[4], inlateout("x5") words[5]);
    }
    Ok(words)
}

#[cfg(not(all(
    target_os = "none",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn native(_number: u64, _words: [u64; 6]) -> Result<[u64; 6], Error> {
    Err(Error::UnsupportedTarget)
}

/// Run a persistent service from the kernel's raw startup pair.
///
/// # Safety
/// The startup pair and all mappings it describes must be the current task's
/// immutable kernel-supplied entry state, exclusively consumed once.
#[doc(hidden)]
pub unsafe fn run(start: *const u8, bytes: usize, main: fn(&mut PersistentContext) -> u32) -> ! {
    if start.is_null() || !crate::valid_startup_region_bytes(bytes) {
        crate::terminate(1);
    }
    // SAFETY: The entry contract supplies the validated mapped extent above.
    let raw = unsafe { core::slice::from_raw_parts(start, bytes) };
    let Ok(startup) = Startup::parse(raw) else {
        crate::terminate(1)
    };
    let Ok(mut context) = PersistentContext::from_startup(&startup) else {
        crate::terminate(1)
    };
    crate::terminate(main(&mut context))
}

/// Define the native entry for a persistent ABI 1.3 service.
#[macro_export]
macro_rules! persistent_entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        /// Enter this task exactly once with its immutable kernel startup state.
        ///
        /// # Safety
        /// The pointer and length must be the current task's mapped startup
        /// region. No existing context or private-page owner may be reused.
        pub unsafe extern "C" fn _start(start: *const u8, bytes: usize) -> ! {
            // SAFETY: Only the kernel enters this symbol with the startup pair.
            unsafe { $crate::__run_persistent(start, bytes, $main) }
        }
        #[panic_handler]
        fn panic(_information: &core::panic::PanicInfo<'_>) -> ! {
            $crate::terminate($crate::exit::FAILURE)
        }
    };
}

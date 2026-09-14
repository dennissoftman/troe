//! Explicit native-thread bootstrap and copied per-thread transport.
//!
//! Ordinary SDK entry remains ABI 1.3. This feature supplies an adapter for the
//! separately admitted native profile; it does not enable package admission.

use core::{
    marker::PhantomData,
    ptr, slice,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{CommandContext, Error, Handle, Startup, StartupError, interface};
pub use troe_abi::threading as wire;

mod startup;
#[cfg(test)]
mod tests;
mod trap;

static ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
#[repr(C)]
struct Local {
    descriptor: *const u8,
    tx: u64,
    rx: u64,
    control: u64,
    sync: u64,
    busy: u64,
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn __troe_native_local_v1() -> *mut Local;
}

#[allow(clippy::unnecessary_wraps)] // The hosted implementation is fallible.
fn local_pointer() -> Result<*mut Local, Error> {
    #[cfg(target_os = "none")]
    {
        // SAFETY: Only explicit kernel-native entry initializes this profile.
        // Subsequent calls require ENABLED; every worker binds before user code.
        Ok(unsafe { __troe_native_local_v1() })
    }
    #[cfg(not(target_os = "none"))]
    Err(Error::UnsupportedTarget)
}

pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

pub(crate) fn yield_now() -> Result<(), Error> {
    if trap::call(1, [0; 6])? != [0; 2] {
        return Err(Error::InvalidCall);
    }
    Ok(())
}

pub(crate) fn grow_heap(pages: u64) -> Result<(u32, usize), Error> {
    let words = trap::call(3, [pages, 0, 0, 0, 0, 0])?;
    Ok((
        u32::try_from(words[0]).map_err(|_| Error::InvalidCall)?,
        usize::try_from(words[1]).map_err(|_| Error::InvalidCall)?,
    ))
}

/// Initial process-header owner. Consuming it constructs at most one command
/// context and heap owner. No private IPC-page owner is exposed by this profile.
pub struct Initial {
    startup: Startup<'static>,
    image_base: u64,
}

impl Initial {
    /// Base used to encode an admitted worker's image-relative entry offset.
    #[must_use]
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Copy one exact interface/version grant for a low-level runtime adapter.
    ///
    /// # Errors
    /// Rejects absent, ambiguous or mismatched startup authority.
    pub fn handle(&self, interface: u32, major: u16, minor: u16) -> Result<u64, StartupError> {
        Ok(self.startup.required_handle(interface, major, minor)?.value)
    }

    /// Consume startup ownership for the ordinary typed command services.
    ///
    /// # Errors
    /// Rejects missing command/stream authority or invalid heap metadata.
    pub fn into_command(self) -> Result<CommandContext, StartupError> {
        CommandContext::from_startup(&self.startup)
    }
}

/// Bind the initial thread before executing any threaded SDK operation.
///
/// # Safety
/// Invoke exactly once at the kernel's ABI 1.4 initial entry, before starting
/// siblings. The process header and its referenced descriptor must be live,
/// immutable kernel mappings; TP, TLS and IPC must be initialized and privately
/// owned by this thread. No other heap or IPC owner may already exist. The shared
/// header remains mapped for the complete process lifetime.
///
/// # Errors
/// Rejects malformed metadata, duplicate initialization or unsupported targets.
pub unsafe fn initialize_initial(address: *const u8, bytes: usize) -> Result<Initial, Error> {
    if enabled() || address.is_null() || bytes != 4096 {
        return Err(Error::InvalidCall);
    }
    // SAFETY: The explicit kernel entry contract supplies this complete page.
    let page = unsafe { slice::from_raw_parts(address, bytes) };
    let reference =
        wire::StartupReference::decode(&page[80..96]).map_err(|_| Error::InvalidCall)?;
    // SAFETY: The entry contract includes the referenced live descriptor page.
    let descriptor = unsafe { read_descriptor(reference.address as *const u8, 128) }?;
    if !descriptor.initial {
        return Err(Error::InvalidCall);
    }
    let startup =
        startup::parse(page, address as u64, descriptor).map_err(|_| Error::InvalidCall)?;
    bind(descriptor, &startup)?;
    ENABLED.store(true, Ordering::Release);
    Ok(Initial {
        startup,
        image_base: crate::read_u64(page, 16).map_err(|_| Error::InvalidCall)?,
    })
}

unsafe fn read_descriptor(
    address: *const u8,
    bytes: usize,
) -> Result<wire::StartupDescriptor, Error> {
    if address.is_null() || !(address as usize).is_multiple_of(4096) || bytes != 128 {
        return Err(Error::InvalidCall);
    }
    // SAFETY: The native entry contract supplies the full immutable mapping,
    // even though the entry length names only its encoded prefix.
    let page = unsafe { slice::from_raw_parts(address, 4096) };
    let descriptor = wire::StartupDescriptor::decode_page(page).map_err(|_| Error::InvalidCall)?;
    if descriptor.address != address as u64 {
        return Err(Error::InvalidCall);
    }
    Ok(descriptor)
}

fn bind(descriptor: wire::StartupDescriptor, startup: &Startup<'_>) -> Result<(), Error> {
    let local = local_pointer()?;
    let local_address = local as u64;
    let local_end = local_address
        .checked_add(core::mem::size_of::<Local>() as u64)
        .ok_or(Error::InvalidCall)?;
    if trap::thread_pointer()? != descriptor.thread_pointer
        || local_address < descriptor.tls_base
        || local_end > descriptor.tls_base + descriptor.tls_bytes
        || !local_address.is_multiple_of(core::mem::align_of::<Local>() as u64)
    {
        return Err(Error::InvalidCall);
    }
    // SAFETY: The compiler helper names the current initialized TLS object;
    // its complete range has been checked before taking any typed copy.
    let old = unsafe { local.read() };
    if !old.descriptor.is_null()
        || old.busy != 0
        || old.tx != 0
        || old.rx != 0
        || old.control != 0
        || old.sync != 0
    {
        return Err(Error::InvalidCall);
    }
    let control = startup
        .required_handle(interface::THREAD_CONTROL, 1, 0)
        .map_err(|_| Error::MissingAuthority)?
        .value;
    let sync = startup
        .required_handle(interface::THREAD_SYNC, 1, 0)
        .map_err(|_| Error::MissingAuthority)?
        .value;
    // SAFETY: This unpublished local object has no outstanding SDK page loan.
    unsafe {
        local.write(Local {
            descriptor: descriptor.address as *const u8,
            tx: descriptor.ipc_tx,
            rx: descriptor.ipc_tx + 4096,
            control,
            sync,
            busy: 0,
        });
    }
    Ok(())
}

struct CallGuard {
    local: *mut Local,
    snapshot: Local,
    _thread: PhantomData<*mut ()>,
}

impl CallGuard {
    fn acquire() -> Result<Self, Error> {
        if !enabled() {
            return Err(Error::InvalidCall);
        }
        let local = local_pointer()?;
        // SAFETY: Explicit entry initialized this current thread's TLS; no
        // asynchronous user callback or cancellation can interrupt a page loan.
        let snapshot = unsafe { local.read() };
        if snapshot.descriptor.is_null() || snapshot.busy != 0 {
            return Err(Error::InvalidCall);
        }
        // SAFETY: Access is thread-local and no competing loan is live.
        unsafe {
            ptr::addr_of_mut!((*local).busy).write(1);
        }
        Ok(Self {
            local,
            snapshot,
            _thread: PhantomData,
        })
    }

    fn tx(&mut self) -> &mut [u8] {
        // SAFETY: Binding established this live page. The per-thread guard
        // excludes reentry and no public API exposes an additional page owner.
        unsafe { slice::from_raw_parts_mut(self.snapshot.tx as *mut u8, 4096) }
    }

    fn rx(&self, bytes: usize) -> &[u8] {
        // SAFETY: Callers validate bytes <= 4096 before taking this private
        // borrow. They copy/decode the complete result before dropping the guard.
        unsafe { slice::from_raw_parts(self.snapshot.rx as *const u8, bytes) }
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        // SAFETY: This non-Send guard owns the current thread's exact loan.
        unsafe {
            ptr::addr_of_mut!((*self.local).busy).write(0);
        }
    }
}

pub(crate) fn handle_call(
    handle: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<(u32, usize), Error> {
    if handle == 0 || !(2..=4096).contains(&request.len()) || reply.len() > 4096 {
        return Err(Error::InvalidCall);
    }
    let mut guard = CallGuard::acquire()?;
    guard.tx()[..request.len()].copy_from_slice(request);
    let words = trap::call(
        2,
        [
            handle,
            guard.snapshot.tx,
            request.len() as u64,
            guard.snapshot.rx,
            reply.len() as u64,
            0,
        ],
    )?;
    let status = u32::try_from(words[0]).map_err(|_| Error::InvalidCall)?;
    let count = usize::try_from(words[1]).map_err(|_| Error::InvalidCall)?;
    if count > reply.len() {
        return Err(Error::InvalidCall);
    }
    // Validate transport status before copying anything into the caller's span.
    crate::decode_status(words[0])?;
    reply[..count].copy_from_slice(guard.rx(count));
    Ok((status, count))
}

/// Execute one codec-validated scheduler operation through this thread's pages.
///
/// # Safety
/// Prepare/Start must target the admitted worker trampoline and an entry with
/// signature `unsafe extern "C" fn(u64) -> u64`. Its argument/storage must remain
/// valid through completion. Exit must run all required runtime cleanup first;
/// it must not abandon Rust references or shared state that needs this stack.
/// Kernel token/authority checks do not prove these language-level obligations.
///
/// # Errors
/// Reports codec, authority, framing, reentry or target failure. Operation-level
/// outcomes remain in the correlated response, including poison and timeouts.
pub unsafe fn call(request: wire::Request) -> Result<wire::Response, Error> {
    let encoded = request.encode().map_err(|_| Error::InvalidCall)?;
    let mut guard = CallGuard::acquire()?;
    let handle = if request.interface() == interface::THREAD_CONTROL {
        guard.snapshot.control
    } else {
        guard.snapshot.sync
    };
    let frame = wire::Call { handle }
        .encode()
        .map_err(|_| Error::InvalidCall)?;
    guard.tx()[..encoded.len()].copy_from_slice(&encoded);
    match wire::Completion::decode(trap::call(wire::CALL, frame)?) {
        Some(wire::Completion::Response) => {
            wire::Response::decode(request, guard.rx(32)).map_err(|_| Error::InvalidCall)
        }
        Some(wire::Completion::Rejected) => Err(Error::Denied),
        None => Err(Error::InvalidCall),
    }
}

/// Perform a copied ordinary service call for a native runtime adapter.
///
/// # Safety
/// The interface-specific request must uphold any memory or execution ownership
/// contract of the selected service. Kernel capability checks still apply.
///
/// # Errors
/// Returns ordinary SDK service/transport errors without exposing the RX page.
pub unsafe fn service_call(
    handle: u64,
    opcode: u16,
    payload: &[u8],
    reply: &mut [u8],
) -> Result<usize, Error> {
    if !enabled() {
        return Err(Error::InvalidCall);
    }
    crate::call(Handle { value: handle }, opcode, payload, reply)
}

/// Enter the admitted worker trampoline, bind TLS and consume its scalar result.
///
/// # Safety
/// The kernel must enter with this worker's live immutable descriptor, initialized
/// TLS/IPC and a prepared entry/argument satisfying `call`'s execution contract.
#[doc(hidden)]
pub unsafe fn run_worker(address: *const u8, bytes: usize) -> ! {
    let run = || -> Result<u64, Error> {
        if !enabled() {
            return Err(Error::InvalidCall);
        }
        // SAFETY: Forwarded from the trampoline entry contract.
        let descriptor = unsafe { read_descriptor(address, bytes) }?;
        if descriptor.initial {
            return Err(Error::InvalidCall);
        }
        // SAFETY: Shared process-header backing survives initial-thread exit.
        let page = unsafe { slice::from_raw_parts(descriptor.process_startup as *const u8, 4096) };
        let startup = startup::parse(page, descriptor.process_startup, descriptor)
            .map_err(|_| Error::InvalidCall)?;
        bind(descriptor, &startup)?;
        // SAFETY: Prepare's unsafe adapter contract fixes the worker ABI and
        // lifetimes; the kernel independently checked immutable executable entry.
        let entry: unsafe extern "C" fn(u64) -> u64 =
            unsafe { core::mem::transmute(descriptor.entry) };
        Ok(unsafe { entry(descriptor.argument) })
    };
    if let Ok(result) = run() {
        // SAFETY: The worker function returned and retained no trampoline loans.
        let _result = unsafe { call(wire::Request::Exit(result)) };
    }
    crate::terminate(crate::exit::FAILURE)
}

/// Define explicit ABI 1.4 initial/worker entries and a process-fault panic path.
/// The initial function accepts one [`Initial`] value and returns a process status.
#[macro_export]
macro_rules! threaded_entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        /// Enter the explicitly admitted initial native context.
        /// # Safety
        /// The arguments and TLS must satisfy the native kernel entry contract.
        pub unsafe extern "C" fn _start(address: *const u8, bytes: usize) -> ! {
            // Keep the kernel-entered trampoline reachable under section GC;
            // no ordinary language call names it before a worker is started.
            core::hint::black_box(__troe_thread_start_v1 as *const ());
            // SAFETY: Only the explicit native loader enters this symbol.
            match unsafe { $crate::threading::initialize_initial(address, bytes) } {
                Ok(initial) => $crate::terminate($main(initial)),
                Err(_) => $crate::terminate($crate::exit::FAILURE),
            }
        }
        #[unsafe(no_mangle)]
        /// Enter a worker prepared through the native SDK's unsafe call contract.
        /// # Safety
        /// The kernel supplies this worker's live descriptor and initialized TLS.
        pub unsafe extern "C" fn __troe_thread_start_v1(address: *const u8, bytes: usize) -> ! {
            // SAFETY: Forwarded from the native worker entry contract.
            unsafe { $crate::threading::run_worker(address, bytes) }
        }
        #[panic_handler]
        fn panic(_information: &core::panic::PanicInfo<'_>) -> ! {
            $crate::terminate($crate::exit::FAILURE)
        }
    };
}

//! Process-owned bootstrap storage; no C-retained pointer names an entry stack.

use core::{
    cell::UnsafeCell,
    ffi::c_char,
    marker::PhantomData,
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use troe_kex_runtime::environment;
use troe_kex_sdk::{CommandContext, command};

use crate::{Configuration, Host, InitializationError, Runtime};

struct Strings {
    arguments: [u8; command::MAX_ARGUMENT_BYTES + command::MAX_ARGUMENTS],
    argv: [*mut c_char; command::MAX_ARGUMENTS + 1],
    environment: [u8; command::MAX_ENVIRONMENT_BYTES
        + command::MAX_ENVIRONMENT
        + command::MAX_CWD_BYTES
        + 128],
    envp: [*mut c_char; command::MAX_ENVIRONMENT + 1],
    cwd: [u8; command::MAX_CWD_BYTES + 1],
}

impl Strings {
    const fn new() -> Self {
        Self {
            arguments: [0; command::MAX_ARGUMENT_BYTES + command::MAX_ARGUMENTS],
            argv: [ptr::null_mut(); command::MAX_ARGUMENTS + 1],
            environment: [0; command::MAX_ENVIRONMENT_BYTES
                + command::MAX_ENVIRONMENT
                + command::MAX_CWD_BYTES
                + 128],
            envp: [ptr::null_mut(); command::MAX_ENVIRONMENT + 1],
            cwd: [0; command::MAX_CWD_BYTES + 1],
        }
    }

    fn initialize(
        &mut self,
        invocation: command::Invocation<'_>,
        supplied: command::Environment<'_>,
    ) -> Result<Configuration, InitializationError> {
        let mut offset = 0;
        for (index, argument) in invocation.arguments().enumerate() {
            self.argv[index] = copy_string(argument, &mut self.arguments, &mut offset)?;
        }
        let mut pwd = [0; command::MAX_CWD_BYTES + 4];
        let mut entries = [""; command::MAX_ENVIRONMENT];
        let count = environment::child_entries(supplied, invocation.cwd(), &mut pwd, &mut entries)
            .map_err(|_| InitializationError::InvalidConfiguration)?;
        offset = 0;
        for (index, value) in entries[..count].iter().enumerate() {
            self.envp[index] = copy_string(value, &mut self.environment, &mut offset)?;
        }
        let cwd = copy_string(invocation.cwd(), &mut self.cwd, &mut 0)?;
        Ok(Configuration {
            host: ptr::null(),
            argc: i32::try_from(invocation.len())
                .map_err(|_| InitializationError::InvalidConfiguration)?,
            argv: self.argv.as_mut_ptr(),
            environment: self.envp.as_mut_ptr(),
            cwd,
        })
    }
}

fn copy_string(
    value: &str,
    storage: &mut [u8],
    offset: &mut usize,
) -> Result<*mut c_char, InitializationError> {
    let end = offset
        .checked_add(value.len())
        .and_then(|end| end.checked_add(1))
        .ok_or(InitializationError::InvalidConfiguration)?;
    if value.as_bytes().contains(&0) {
        return Err(InitializationError::InvalidConfiguration);
    }
    let destination = storage
        .get_mut(*offset..end)
        .ok_or(InitializationError::InvalidConfiguration)?;
    destination[..value.len()].copy_from_slice(value.as_bytes());
    destination[value.len()] = 0;
    *offset = end;
    Ok(destination.as_mut_ptr().cast())
}

/// Fixed storage for one process's C bridge, callback table and copied arguments.
///
/// Declare this as a static. Initialization is claimed once, including failures;
/// there is no reset or reuse that could invalidate a C-retained pointer. Storage
/// remains mapped until process teardown, independently of the initial stack.
/// This ownership mechanism does not enable concurrent C runtime execution.
pub struct ProcessStorage {
    claimed: AtomicBool,
    runtime: UnsafeCell<MaybeUninit<Runtime>>,
    host: UnsafeCell<MaybeUninit<Host>>,
    configuration: UnsafeCell<MaybeUninit<Configuration>>,
    strings: UnsafeCell<Strings>,
}

// SAFETY: Only one atomic claim can expose initialization access. No shared getter
// exposes any cell. The resulting handle is neither Send nor Sync; C access is
// separately subject to the unsafe FFI call contract. The storage never resets.
unsafe impl Sync for ProcessStorage {}

impl ProcessStorage {
    /// Construct unpublished process storage without allocation or pointers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            runtime: UnsafeCell::new(MaybeUninit::uninit()),
            host: UnsafeCell::new(MaybeUninit::uninit()),
            configuration: UnsafeCell::new(MaybeUninit::uninit()),
            strings: UnsafeCell::new(Strings::new()),
        }
    }

    /// Claim stable storage, copy command configuration and consume its heap.
    ///
    /// All strings, pointer arrays, callback context and configuration reside in
    /// this static before any pointer is returned. Temporary input records and
    /// environment-composition buffers may be dropped after this call.
    ///
    /// # Errors
    /// Rejects duplicate initialization, invalid configuration and heap failure.
    /// A failed attempt permanently consumes this storage's initialization claim.
    pub fn initialize(
        &'static self,
        command: &mut CommandContext,
        invocation: command::Invocation<'_>,
        environment: command::Environment<'_>,
    ) -> Result<ProcessRuntime, InitializationError> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            return Err(InitializationError::AlreadyInitialized);
        }
        // SAFETY: This caller owns the only claim. These cells have never been
        // exposed, and static storage cannot move after their pointers are made.
        unsafe {
            let mut configuration =
                (&mut *self.strings.get()).initialize(invocation, environment)?;
            let runtime = (&mut *self.runtime.get()).write(Runtime::new(command)?);
            let host = (&mut *self.host.get()).write(runtime.host());
            configuration.host = ptr::from_ref(host);
            (*self.configuration.get()).write(configuration);
        }
        Ok(ProcessRuntime {
            storage: self,
            _thread: PhantomData,
        })
    }
}

impl Default for ProcessStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique bootstrap handle; dropping it does not release process-owned storage.
///
/// This handle is neither Send nor Sync. Calling C still requires the runtime's
/// FFI ownership and finalization contract; stable pointers alone do not prove
/// allocator, libc or interpreter thread safety.
pub struct ProcessRuntime {
    storage: &'static ProcessStorage,
    _thread: PhantomData<*mut ()>,
}

impl ProcessRuntime {
    /// Address of the fully initialized process-owned C configuration.
    #[must_use]
    pub fn configuration(&self) -> *const Configuration {
        self.storage
            .configuration
            .get()
            .cast::<Configuration>()
            .cast_const()
    }

    /// Borrow the initialized bridge for statistics and callback context.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        // SAFETY: Only complete initialization constructs this handle. Its
        // Runtime never moves or resets; mutable fields use separate exclusions.
        unsafe { (&*self.storage.runtime.get()).assume_init_ref() }
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;

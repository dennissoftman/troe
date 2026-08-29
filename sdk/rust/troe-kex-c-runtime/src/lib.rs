//! Capability-scoped host callbacks for the freestanding TROE C runtime.
#![no_std]
#![allow(unsafe_code)]

use core::{
    ffi::{c_char, c_void},
    ptr::{self, NonNull},
    slice, str,
};

use troe_kex_alloc::{CAllocator, Heap};
use troe_kex_runtime::errno;
use troe_kex_sdk::{
    CommandContext, FILESYSTEM_LIST_BUFFER_BYTES, FileReplacement, FilesystemMutation, Random,
    ReadOnlyFilesystem, StandardInput, StandardOutput, Timer, WallClock, filesystem,
};

const RUNTIME_ABI: u32 = 1;
const OPEN_FILES: usize = 32;
const MAX_PATH_BYTES: usize = 256;

/// C-visible metadata returned by the capability bridge.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HostMetadata {
    /// Exact regular-file byte count.
    pub byte_count: u64,
    /// Stable process-local identity derived from the canonical path.
    pub identity: u64,
    /// One of the public C node-kind constants.
    pub kind: u32,
    /// Required zero padding.
    pub reserved: u32,
}

/// Exact callback table consumed by `troe_runtime_initialize`.
#[repr(C)]
pub struct Host {
    abi: u32,
    structure_bytes: u32,
    context: *mut c_void,
    allocate: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, usize, i32) -> *mut c_void,
    stream_read: unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> isize,
    stream_write: unsafe extern "C" fn(*mut c_void, i32, *const u8, usize) -> i32,
    file_open: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u32, *mut u64) -> i32,
    file_read: unsafe extern "C" fn(*mut c_void, u32, u64, *mut u8, usize) -> isize,
    file_close: unsafe extern "C" fn(*mut c_void, u32) -> i32,
    replace_begin:
        unsafe extern "C" fn(*mut c_void, *const u8, usize, i32, *mut u32, *mut u64) -> i32,
    replace_append: unsafe extern "C" fn(*mut c_void, u32, u64, *const u8, usize) -> i32,
    replace_finish: unsafe extern "C" fn(*mut c_void, u32, i32) -> i32,
    replace_read: unsafe extern "C" fn(*mut c_void, u32, u64, *mut u8, usize) -> isize,
    metadata: unsafe extern "C" fn(*mut c_void, *const u8, usize, i32, *mut HostMetadata) -> i32,
    directory_next: unsafe extern "C" fn(
        *mut c_void,
        *const u8,
        usize,
        u64,
        *mut u8,
        usize,
        *mut u32,
        *mut u64,
    ) -> isize,
    path_operation:
        unsafe extern "C" fn(*mut c_void, u32, *const u8, usize, *const u8, usize) -> i32,
    read_link: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8, usize) -> isize,
    monotonic_time: unsafe extern "C" fn(*mut c_void, *mut u64, *mut u64) -> i32,
    process_cpu_time: unsafe extern "C" fn(*mut c_void, *mut u64, *mut u64) -> i32,
    wall_time: unsafe extern "C" fn(*mut c_void, *mut u64) -> i32,
    sleep_until: unsafe extern "C" fn(*mut c_void, u64) -> i32,
    random_bytes: unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32,
    terminate: unsafe extern "C" fn(*mut c_void, u32) -> !,
}

/// Exact initialization record consumed by the shared C runtime.
#[repr(C)]
pub struct Configuration {
    /// Callback table that remains live for the C invocation.
    pub host: *const Host,
    /// C argument count.
    pub argc: i32,
    /// NUL-terminated C argument pointer array.
    pub argv: *mut *mut c_char,
    /// NUL-terminated `NAME=VALUE` pointer array.
    pub environment: *mut *mut c_char,
    /// Initial absolute or root-relative current directory.
    pub cwd: *const c_char,
}

struct PendingReplacement {
    replacement: FileReplacement,
    offset: u64,
}

/// Owned bridge state for one single-threaded C runtime invocation.
pub struct Runtime {
    allocator: CAllocator,
    stdin: StandardInput,
    stdout: StandardOutput,
    stderr: StandardOutput,
    filesystem: Option<ReadOnlyFilesystem>,
    mutation: Option<FilesystemMutation>,
    timer: Option<Timer>,
    wall_clock: Option<WallClock>,
    random: Option<Random>,
    files: [Option<filesystem::OpenFile>; OPEN_FILES],
    replacement: Option<PendingReplacement>,
}

/// Runtime bridge bootstrap failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationError {
    /// The executable did not request a C heap.
    MissingHeap,
    /// The heap allocator rejected the startup geometry.
    InvalidHeap,
}

impl Runtime {
    /// Take the command heap and snapshot every optional capability.
    ///
    /// # Errors
    ///
    /// Reports a missing or invalid initial heap. Missing service capabilities
    /// remain representable and produce `EACCES` only when C attempts to use them.
    pub fn new(command: &mut CommandContext) -> Result<Self, InitializationError> {
        let region = command
            .take_heap()
            .ok_or(InitializationError::MissingHeap)?;
        let heap = match command.private_memory() {
            Ok(private_memory) => Heap::new_with_private_memory(region, private_memory),
            Err(_) => Heap::new(region),
        }
        .map_err(|_| InitializationError::InvalidHeap)?;
        Ok(Self {
            allocator: CAllocator::from_heap(heap),
            stdin: command.stdin(),
            stdout: command.stdout(),
            stderr: command.stderr(),
            filesystem: command.filesystem().ok(),
            mutation: command.filesystem_mutation().ok(),
            timer: command.timer().ok(),
            wall_clock: command.wall_clock().ok(),
            random: command.random().ok(),
            files: [None; OPEN_FILES],
            replacement: None,
        })
    }

    /// Construct a callback table borrowing this object through its context pointer.
    ///
    /// The object must not move until the C runtime has finalized.
    #[must_use]
    pub fn host(&mut self) -> Host {
        Host {
            abi: RUNTIME_ABI,
            structure_bytes: u32::try_from(core::mem::size_of::<Host>()).unwrap_or(u32::MAX),
            context: ptr::from_mut(self).cast(),
            allocate: host_allocate,
            stream_read: host_stream_read,
            stream_write: host_stream_write,
            file_open: host_file_open,
            file_read: host_file_read,
            file_close: host_file_close,
            replace_begin: host_replace_begin,
            replace_append: host_replace_append,
            replace_finish: host_replace_finish,
            replace_read: host_replace_read,
            metadata: host_metadata,
            directory_next: host_directory_next,
            path_operation: host_path_operation,
            read_link: host_read_link,
            monotonic_time: host_monotonic_time,
            process_cpu_time: host_process_cpu_time,
            wall_time: host_wall_time,
            sleep_until: host_sleep_until,
            random_bytes: host_random_bytes,
            terminate: host_terminate,
        }
    }

    /// Return current allocation and private-mapping accounting.
    #[must_use]
    pub const fn allocator_statistics(&self) -> troe_kex_alloc::Statistics {
        self.allocator.statistics()
    }
}

unsafe fn runtime<'a>(context: *mut c_void) -> Option<&'a mut Runtime> {
    // SAFETY: Each callback receives the exclusive context installed by `host`.
    unsafe { context.cast::<Runtime>().as_mut() }
}

unsafe fn bytes<'a>(pointer: *const u8, length: usize) -> Option<&'a [u8]> {
    if length != 0 && pointer.is_null() {
        return None;
    }
    // SAFETY: The C ABI requires a readable span for each nonzero length.
    Some(unsafe {
        slice::from_raw_parts(
            if length == 0 {
                NonNull::<u8>::dangling().as_ptr().cast_const()
            } else {
                pointer
            },
            length,
        )
    })
}

unsafe fn bytes_mut<'a>(pointer: *mut u8, length: usize) -> Option<&'a mut [u8]> {
    if length != 0 && pointer.is_null() {
        return None;
    }
    // SAFETY: The C ABI requires a writable span for each nonzero length.
    Some(unsafe {
        slice::from_raw_parts_mut(
            if length == 0 {
                NonNull::<u8>::dangling().as_ptr()
            } else {
                pointer
            },
            length,
        )
    })
}

unsafe fn path<'a>(pointer: *const u8, length: usize) -> Result<&'a str, i32> {
    if length == 0 || length > MAX_PATH_BYTES {
        return Err(errno::EINVAL);
    }
    // SAFETY: Forwarded from the callback pointer contract.
    let value = unsafe { bytes(pointer, length) }.ok_or(errno::EINVAL)?;
    str::from_utf8(value).map_err(|_| errno::EINVAL)
}

const fn negative(error: i32) -> isize {
    -(error as isize)
}

fn positive(count: usize) -> isize {
    isize::try_from(count).unwrap_or_else(|_| negative(errno::EOVERFLOW))
}

unsafe extern "C" fn host_allocate(
    context: *mut c_void,
    pointer: *mut c_void,
    size: usize,
    alignment: usize,
    zeroed: i32,
) -> *mut c_void {
    // SAFETY: The host table owns an exclusive runtime context.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return ptr::null_mut();
    };
    if pointer.is_null() {
        return runtime
            .allocator
            .allocate(size, alignment, zeroed != 0)
            .map_or(ptr::null_mut(), |value| value.as_ptr().cast());
    }
    if size == 0 {
        // SAFETY: The C allocator ABI accepts only its own live pointers.
        let _released = unsafe { runtime.allocator.deallocate(pointer.cast()) };
        return ptr::null_mut();
    }
    // SAFETY: The C allocator ABI accepts only its own live pointers.
    unsafe { runtime.allocator.reallocate(pointer.cast(), size) }
        .map_or(ptr::null_mut(), |value| value.as_ptr().cast())
}

unsafe extern "C" fn host_stream_read(
    context: *mut c_void,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    // SAFETY: Callback pointer spans are validated before typed use.
    let (Some(runtime), Some(destination)) = (unsafe { runtime(context) }, unsafe {
        bytes_mut(destination, capacity)
    }) else {
        return negative(errno::EINVAL);
    };
    runtime
        .stdin
        .read(destination)
        .map_or_else(|error| negative(errno::from_kex(error)), positive)
}

unsafe extern "C" fn host_stream_write(
    context: *mut c_void,
    stream: i32,
    source: *const u8,
    length: usize,
) -> i32 {
    // SAFETY: Callback pointer spans are validated before typed use.
    let (Some(runtime), Some(source)) = (unsafe { runtime(context) }, unsafe {
        bytes(source, length)
    }) else {
        return errno::EINVAL;
    };
    let output = if stream == 1 {
        &mut runtime.stdout
    } else if stream == 2 {
        &mut runtime.stderr
    } else {
        return errno::EINVAL;
    };
    output
        .write_all(source)
        .map_or_else(errno::from_kex, |()| 0)
}

unsafe extern "C" fn host_file_open(
    context: *mut c_void,
    path_pointer: *const u8,
    path_length: usize,
    token: *mut u32,
    byte_count: *mut u64,
) -> i32 {
    // SAFETY: Scalar output pointers and path span come from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    if token.is_null() || byte_count.is_null() {
        return errno::EINVAL;
    }
    // SAFETY: Forwarded from this callback's path contract.
    let path = match unsafe { path(path_pointer, path_length) } {
        Ok(path) => path,
        Err(error) => return error,
    };
    let Some(filesystem) = runtime.filesystem.as_mut() else {
        return errno::EACCES;
    };
    let Some(index) = runtime.files.iter().position(Option::is_none) else {
        return errno::ENOMEM;
    };
    let file = match filesystem.open(path) {
        Ok(file) => file,
        Err(error) => return errno::from_kex(error),
    };
    runtime.files[index] = Some(file);
    // SAFETY: Nonnull scalar output pointers were checked above.
    unsafe {
        token.write(u32::try_from(index + 1).unwrap_or(u32::MAX));
        byte_count.write(file.byte_count);
    }
    0
}

fn file_index(token: u32) -> Option<usize> {
    usize::try_from(token)
        .ok()?
        .checked_sub(1)
        .filter(|index| *index < OPEN_FILES)
}

unsafe extern "C" fn host_file_read(
    context: *mut c_void,
    token: u32,
    offset: u64,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    // SAFETY: Callback pointer spans are validated before typed use.
    let (Some(runtime), Some(destination)) = (unsafe { runtime(context) }, unsafe {
        bytes_mut(destination, capacity)
    }) else {
        return negative(errno::EINVAL);
    };
    let Some(index) = file_index(token) else {
        return negative(errno::EINVAL);
    };
    let Some(file) = runtime.files[index] else {
        return negative(errno::EINVAL);
    };
    let Some(filesystem) = runtime.filesystem.as_mut() else {
        return negative(errno::EACCES);
    };
    filesystem
        .read(file, offset, destination)
        .map_or_else(|error| negative(errno::from_kex(error)), positive)
}

unsafe extern "C" fn host_file_close(context: *mut c_void, token: u32) -> i32 {
    // SAFETY: The host table owns an exclusive runtime context.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    let Some(index) = file_index(token) else {
        return errno::EINVAL;
    };
    let Some(file) = runtime.files[index].take() else {
        return errno::EINVAL;
    };
    let Some(filesystem) = runtime.filesystem.as_mut() else {
        return errno::EACCES;
    };
    filesystem.close(file).map_or_else(errno::from_kex, |()| 0)
}

unsafe extern "C" fn host_replace_begin(
    context: *mut c_void,
    path_pointer: *const u8,
    path_length: usize,
    preserve: i32,
    token: *mut u32,
    initial_offset: *mut u64,
) -> i32 {
    // SAFETY: Scalar output pointer and path span come from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    if token.is_null() || initial_offset.is_null() || runtime.replacement.is_some() {
        return if token.is_null() || initial_offset.is_null() {
            errno::EINVAL
        } else {
            errno::EBUSY
        };
    }
    // SAFETY: Forwarded from this callback's path contract.
    let path = match unsafe { path(path_pointer, path_length) } {
        Ok(path) => path,
        Err(error) => return error,
    };
    let Some(mutation) = runtime.mutation.as_mut() else {
        return errno::EACCES;
    };
    let replacement = match if preserve != 0 {
        mutation.begin_append(path)
    } else {
        mutation.begin_replace(path)
    } {
        Ok(replacement) => replacement,
        Err(error) => return errno::from_kex(error),
    };
    let offset = replacement.offset();
    runtime.replacement = Some(PendingReplacement {
        replacement,
        offset,
    });
    // SAFETY: The nonnull scalar output pointers were checked above.
    unsafe {
        token.write(1);
        initial_offset.write(offset);
    }
    0
}

unsafe extern "C" fn host_replace_append(
    context: *mut c_void,
    token: u32,
    offset: u64,
    source: *const u8,
    length: usize,
) -> i32 {
    // SAFETY: Callback pointer spans are validated before typed use.
    let (Some(runtime), Some(source)) = (unsafe { runtime(context) }, unsafe {
        bytes(source, length)
    }) else {
        return errno::EINVAL;
    };
    let Some(pending) = runtime.replacement.as_mut() else {
        return errno::EINVAL;
    };
    if token != 1 || pending.offset != offset {
        return errno::EINVAL;
    }
    if let Err(error) = pending.replacement.write_all(source) {
        return errno::from_kex(error);
    }
    let Ok(length) = u64::try_from(length) else {
        return errno::EOVERFLOW;
    };
    let Some(next) = pending.offset.checked_add(length) else {
        return errno::EOVERFLOW;
    };
    pending.offset = next;
    0
}

unsafe extern "C" fn host_replace_read(
    context: *mut c_void,
    token: u32,
    offset: u64,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    // SAFETY: Callback pointer spans are validated before typed use.
    let (Some(runtime), Some(destination)) = (unsafe { runtime(context) }, unsafe {
        bytes_mut(destination, capacity)
    }) else {
        return -(errno::EINVAL as isize);
    };
    let Some(pending) = runtime.replacement.as_mut() else {
        return -(errno::EINVAL as isize);
    };
    if token != 1 {
        return -(errno::EINVAL as isize);
    }
    match pending.replacement.read_at(offset, destination) {
        Ok(count) => isize::try_from(count).unwrap_or(-(errno::EOVERFLOW as isize)),
        Err(error) => -(errno::from_kex(error) as isize),
    }
}

unsafe extern "C" fn host_replace_finish(context: *mut c_void, token: u32, commit: i32) -> i32 {
    // SAFETY: The host table owns an exclusive runtime context.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    if token != 1 {
        return errno::EINVAL;
    }
    let Some(pending) = runtime.replacement.take() else {
        return errno::EINVAL;
    };
    let result = if commit != 0 {
        pending.replacement.commit()
    } else {
        pending.replacement.abort()
    };
    result.map_or_else(errno::from_kex, |()| 0)
}

const fn node_kind(kind: filesystem::NodeKind) -> u32 {
    match kind {
        filesystem::NodeKind::File => 1,
        filesystem::NodeKind::Directory => 2,
        filesystem::NodeKind::Symlink => 3,
    }
}

fn path_identity(path: &str) -> u64 {
    path.as_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

unsafe extern "C" fn host_metadata(
    context: *mut c_void,
    path_pointer: *const u8,
    path_length: usize,
    follow: i32,
    output: *mut HostMetadata,
) -> i32 {
    // SAFETY: Output pointer and path span come from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    if output.is_null() {
        return errno::EINVAL;
    }
    // SAFETY: Forwarded from this callback's path contract.
    let path = match unsafe { path(path_pointer, path_length) } {
        Ok(path) => path,
        Err(error) => return error,
    };
    let Some(filesystem) = runtime.filesystem.as_mut() else {
        return errno::EACCES;
    };
    let metadata = match if follow != 0 {
        filesystem.metadata(path)
    } else {
        filesystem.metadata_no_follow(path)
    } {
        Ok(metadata) => metadata,
        Err(error) => return errno::from_kex(error),
    };
    // SAFETY: The nonnull output pointer was checked above.
    unsafe {
        output.write(HostMetadata {
            byte_count: metadata.byte_count,
            identity: path_identity(path),
            kind: node_kind(metadata.kind),
            reserved: 0,
        });
    }
    0
}

unsafe extern "C" fn host_directory_next(
    context: *mut c_void,
    path_pointer: *const u8,
    path_length: usize,
    cursor: u64,
    name: *mut u8,
    name_capacity: usize,
    kind: *mut u32,
    next_cursor: *mut u64,
) -> isize {
    // SAFETY: Output pointers and path span come from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return negative(errno::EINVAL);
    };
    if kind.is_null() || next_cursor.is_null() {
        return negative(errno::EINVAL);
    }
    // SAFETY: Forwarded from this callback's path and output contracts.
    let path = match unsafe { path(path_pointer, path_length) } {
        Ok(path) => path,
        Err(error) => return negative(error),
    };
    // SAFETY: Forwarded from this callback's output contract.
    let Some(name_output) = (unsafe { bytes_mut(name, name_capacity) }) else {
        return negative(errno::EINVAL);
    };
    let Some(filesystem) = runtime.filesystem.as_mut() else {
        return negative(errno::EACCES);
    };
    let mut buffer = [0_u8; FILESYSTEM_LIST_BUFFER_BYTES];
    let page = match filesystem.list(path, cursor, 1, name_capacity, &mut buffer) {
        Ok(page) => page,
        Err(error) => return negative(errno::from_kex(error)),
    };
    let Some(entry) = page.entries().next() else {
        return 0;
    };
    if entry.name.len() > name_output.len() {
        return negative(errno::EOVERFLOW);
    }
    name_output[..entry.name.len()].copy_from_slice(entry.name.as_bytes());
    // `u64::MAX` is the C facade's process-local end sentinel.
    let next = page.next_cursor().unwrap_or(u64::MAX);
    // SAFETY: Nonnull scalar output pointers were checked above.
    unsafe {
        kind.write(node_kind(entry.kind));
        next_cursor.write(next);
    }
    positive(entry.name.len())
}

unsafe fn second_path<'a>(pointer: *const u8, length: usize) -> Result<&'a str, i32> {
    // SAFETY: Forwarded from the two-path callback contract.
    unsafe { path(pointer, length) }
}

unsafe extern "C" fn host_path_operation(
    context: *mut c_void,
    operation: u32,
    first_pointer: *const u8,
    first_length: usize,
    second_pointer: *const u8,
    second_length: usize,
) -> i32 {
    // SAFETY: Path spans come from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    // SAFETY: Forwarded from this callback's path contract.
    let first = match unsafe { path(first_pointer, first_length) } {
        Ok(path) => path,
        Err(error) => return error,
    };
    let Some(mutation) = runtime.mutation.as_mut() else {
        return errno::EACCES;
    };
    let result = match operation {
        1 => mutation.create_directory(first),
        2 => mutation.remove_directory(first),
        3 => mutation.remove(first),
        4..=6 => {
            // SAFETY: Forwarded from this callback's second-path contract.
            let second = match unsafe { second_path(second_pointer, second_length) } {
                Ok(path) => path,
                Err(error) => return error,
            };
            match operation {
                4 => mutation.rename(first, second),
                5 => mutation.create_symlink(first, second),
                6 => mutation.create_hard_link(first, second),
                _ => unreachable!(),
            }
        }
        _ => return errno::ENOTSUP,
    };
    result.map_or_else(errno::from_kex, |()| 0)
}

unsafe extern "C" fn host_read_link(
    context: *mut c_void,
    path_pointer: *const u8,
    path_length: usize,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    // SAFETY: Path and output spans come from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return negative(errno::EINVAL);
    };
    // SAFETY: Forwarded from this callback's path contract.
    let path = match unsafe { path(path_pointer, path_length) } {
        Ok(path) => path,
        Err(error) => return negative(error),
    };
    // SAFETY: Forwarded from this callback's output contract.
    let Some(destination) = (unsafe { bytes_mut(destination, capacity) }) else {
        return negative(errno::EINVAL);
    };
    let Some(filesystem) = runtime.filesystem.as_mut() else {
        return negative(errno::EACCES);
    };
    let mut buffer = [0_u8; filesystem::MAX_LINK_BYTES];
    let target = match filesystem.read_link(path, &mut buffer) {
        Ok(target) => target,
        Err(error) => return negative(errno::from_kex(error)),
    };
    if target.len() > destination.len() {
        return negative(errno::EOVERFLOW);
    }
    destination[..target.len()].copy_from_slice(target.as_bytes());
    positive(target.len())
}

unsafe extern "C" fn host_monotonic_time(
    context: *mut c_void,
    ticks: *mut u64,
    frequency: *mut u64,
) -> i32 {
    // SAFETY: Scalar output pointers come from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    if ticks.is_null() || frequency.is_null() {
        return errno::EINVAL;
    }
    let Some(timer) = runtime.timer.as_mut() else {
        return errno::EACCES;
    };
    let value = match timer.now() {
        Ok(value) => value,
        Err(error) => return errno::from_kex(error),
    };
    // SAFETY: Nonnull scalar output pointers were checked above.
    unsafe {
        ticks.write(value);
        frequency.write(1000);
    }
    0
}

unsafe extern "C" fn host_process_cpu_time(
    context: *mut c_void,
    ticks: *mut u64,
    frequency: *mut u64,
) -> i32 {
    // SAFETY: Scalar output pointers come from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    if ticks.is_null() || frequency.is_null() {
        return errno::EINVAL;
    }
    let Some(timer) = runtime.timer.as_mut() else {
        return errno::EACCES;
    };
    let value = match timer.process_cpu_time() {
        Ok(value) => value,
        Err(error) => return errno::from_kex(error),
    };
    // SAFETY: Nonnull scalar output pointers were checked above.
    unsafe {
        ticks.write(value.ticks);
        frequency.write(value.frequency_hz);
    }
    0
}

unsafe extern "C" fn host_wall_time(context: *mut c_void, seconds: *mut u64) -> i32 {
    // SAFETY: Scalar output pointer comes from the C runtime.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    if seconds.is_null() {
        return errno::EINVAL;
    }
    let Some(clock) = runtime.wall_clock.as_mut() else {
        return errno::EACCES;
    };
    let value = match clock.now() {
        Ok(value) => value,
        Err(error) => return errno::from_kex(error),
    };
    // SAFETY: Nonnull scalar output pointer was checked above.
    unsafe { seconds.write(value) };
    0
}

unsafe extern "C" fn host_sleep_until(context: *mut c_void, milliseconds: u64) -> i32 {
    // SAFETY: The host table owns an exclusive runtime context.
    let Some(runtime) = (unsafe { runtime(context) }) else {
        return errno::EINVAL;
    };
    let Some(timer) = runtime.timer.as_mut() else {
        return errno::EACCES;
    };
    timer
        .sleep_until(milliseconds)
        .map_or_else(errno::from_kex, |()| 0)
}

unsafe extern "C" fn host_random_bytes(
    context: *mut c_void,
    destination: *mut u8,
    length: usize,
) -> i32 {
    // SAFETY: Output span comes from the C runtime.
    let (Some(runtime), Some(destination)) = (unsafe { runtime(context) }, unsafe {
        bytes_mut(destination, length)
    }) else {
        return errno::EINVAL;
    };
    let Some(random) = runtime.random.as_mut() else {
        return errno::EACCES;
    };
    random
        .fill(destination)
        .map_or_else(errno::from_kex, |()| 0)
}

unsafe extern "C" fn host_terminate(_context: *mut c_void, status: u32) -> ! {
    troe_kex_sdk::terminate(status)
}

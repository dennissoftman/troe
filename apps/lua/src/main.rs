#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use core::{
    alloc::Layout,
    ffi::c_void,
    ptr::{self, NonNull},
    slice, str,
};
use troe_kex_alloc::Heap;
use troe_kex_sdk::{
    CommandContext, FilesystemMutation, INVOCATION_BUFFER_BYTES, Pipes, ProcessLauncher,
    ReadOnlyFilesystem, StandardInput, StandardOutput, Timer, WallClock, command, entry, exit,
    filesystem, pipe, process_launch,
};

const LUA_VERSION: &[u8] = b"Lua 5.5.1  Copyright (C) 1994-2026 Lua.org, PUC-Rio\n";
const HEAP_ALIGNMENT: usize = 16;
const LUA_SUCCESS: i32 = 0;
const LUA_SOURCE_FAILURE: i32 = 2;
const LUA_OUTPUT_FAILURE: i32 = 3;
const LUA_OUT_OF_MEMORY: i32 = 4;
const LUA_REQUESTED_EXIT: i32 = 5;
const LUA_ACTION_CODE: i32 = 1;
const LUA_ACTION_REQUIRE: i32 = 2;

#[derive(Clone, Copy)]
#[repr(C)]
struct LuaArgument {
    bytes: *const u8,
    length: usize,
}

const EMPTY_ARGUMENT: LuaArgument = LuaArgument {
    bytes: ptr::null(),
    length: 0,
};

#[derive(Clone, Copy)]
#[repr(C)]
struct LuaAction {
    kind: i32,
    bytes: *const u8,
    length: usize,
}

const EMPTY_ACTION: LuaAction = LuaAction {
    kind: 0,
    bytes: ptr::null(),
    length: 0,
};

#[repr(C)]
struct LuaHost {
    context: *mut c_void,
    allocate: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void,
    read: unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> isize,
    write: unsafe extern "C" fn(*mut c_void, i32, *const u8, usize) -> i32,
    process_cpu_time: unsafe extern "C" fn(*mut c_void, *mut u64, *mut u64) -> i32,
    wall_time: unsafe extern "C" fn(*mut c_void, *mut u64) -> i32,
    read_input: unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> isize,
    file_open: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u32, *mut u64) -> i32,
    file_read: unsafe extern "C" fn(*mut c_void, u32, u64, u64, *mut u8, usize) -> isize,
    file_close: unsafe extern "C" fn(*mut c_void, u32, u64) -> i32,
    file_replace: unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> i32,
    file_remove: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32,
    file_rename: unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> i32,
    file_mutation_available: i32,
    process_execute: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u32) -> i32,
    process_open: unsafe extern "C" fn(
        *mut c_void,
        *const u8,
        usize,
        i32,
        *mut u64,
        *mut u64,
        *mut u64,
    ) -> i32,
    process_read: unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> isize,
    process_write: unsafe extern "C" fn(*mut c_void, u64, *const u8, usize) -> i32,
    process_close: unsafe extern "C" fn(*mut c_void, u64, u64, u64, i32, *mut u32) -> i32,
    process_available: i32,
}

#[repr(C)]
struct LuaConfiguration {
    host: *mut LuaHost,
    source_name: *const u8,
    source_name_length: usize,
    arguments: *const LuaArgument,
    argument_count: usize,
    actions: *const LuaAction,
    action_count: usize,
    has_source: i32,
    warnings_enabled: i32,
    ignore_environment: i32,
    current_directory: *const u8,
    current_directory_length: usize,
    requested_exit: i32,
    requested_exit_status: u32,
    requested_exit_close: i32,
}

unsafe extern "C" {
    fn troe_lua_run(configuration: *mut LuaConfiguration) -> i32;
}

enum Source {
    Empty,
    StandardInput(StandardInput),
    File {
        filesystem: ReadOnlyFilesystem,
        file: filesystem::OpenFile,
        offset: u64,
    },
}

impl Source {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, ()> {
        match self {
            Self::Empty => Ok(0),
            Self::StandardInput(input) => input.read(destination).map_err(|_| ()),
            Self::File {
                filesystem,
                file,
                offset,
            } => {
                let count = filesystem
                    .read(*file, *offset, destination)
                    .map_err(|_| ())?;
                *offset = offset
                    .checked_add(u64::try_from(count).map_err(|_| ())?)
                    .ok_or(())?;
                Ok(count)
            }
        }
    }

    fn close(&mut self) -> Result<(), ()> {
        match self {
            Self::File {
                filesystem, file, ..
            } => filesystem.close(*file).map_err(|_| ()),
            Self::Empty | Self::StandardInput(_) => Ok(()),
        }
    }
}

struct ParsedInvocation<'invocation> {
    selection: Option<Selection<'invocation>>,
    actions: [LuaAction; command::MAX_ARGUMENTS],
    action_count: usize,
    warnings_enabled: bool,
    ignore_environment: bool,
    show_version: bool,
}

struct Runtime {
    heap: Heap,
    source: Source,
    stdout: StandardOutput,
    stderr: StandardOutput,
    timer: Timer,
    wall_clock: WallClock,
    stdin: StandardInput,
    filesystem: ReadOnlyFilesystem,
    mutation: FilesystemMutation,
    launcher: ProcessLauncher,
    pipes: Pipes,
    current_directory: [u8; filesystem::MAX_PATH_BYTES],
    current_directory_length: usize,
}

enum Selection<'invocation> {
    StandardInput {
        first_argument: usize,
    },
    File {
        path: &'invocation str,
        first_argument: usize,
    },
}

fn parse_invocation<'invocation>(
    invocation: command::Invocation<'invocation>,
) -> Result<ParsedInvocation<'invocation>, ()> {
    let mut parsed = ParsedInvocation {
        selection: None,
        actions: [EMPTY_ACTION; command::MAX_ARGUMENTS],
        action_count: 0,
        warnings_enabled: false,
        ignore_environment: false,
        show_version: false,
    };
    let mut index = 1;
    while let Some(argument) = invocation.argument(index) {
        let (kind, value, consumed) = match argument {
            "--" => {
                index += 1;
                parsed.selection = Some(match invocation.argument(index) {
                    Some(path) => Selection::File {
                        path,
                        first_argument: index + 1,
                    },
                    None => Selection::StandardInput {
                        first_argument: index + 1,
                    },
                });
                break;
            }
            "-" => {
                parsed.selection = Some(Selection::StandardInput {
                    first_argument: index + 1,
                });
                break;
            }
            "-E" => {
                parsed.ignore_environment = true;
                index += 1;
                continue;
            }
            "-W" => {
                parsed.warnings_enabled = true;
                index += 1;
                continue;
            }
            "-v" => {
                parsed.show_version = true;
                index += 1;
                continue;
            }
            "-e" => (
                LUA_ACTION_CODE,
                invocation.argument(index + 1).ok_or(())?,
                2,
            ),
            "-l" => (
                LUA_ACTION_REQUIRE,
                invocation.argument(index + 1).ok_or(())?,
                2,
            ),
            option if option.starts_with("-e") && option.len() > 2 => {
                (LUA_ACTION_CODE, &option[2..], 1)
            }
            option if option.starts_with("-l") && option.len() > 2 => {
                (LUA_ACTION_REQUIRE, &option[2..], 1)
            }
            option if option.starts_with('-') => return Err(()),
            path => {
                parsed.selection = Some(Selection::File {
                    path,
                    first_argument: index + 1,
                });
                break;
            }
        };
        parsed.actions[parsed.action_count] = LuaAction {
            kind,
            bytes: value.as_ptr(),
            length: value.len(),
        };
        parsed.action_count += 1;
        index += consumed;
    }
    if parsed.selection.is_none() && parsed.action_count == 0 {
        parsed.selection = Some(Selection::StandardInput {
            first_argument: invocation.len() + 1,
        });
    }
    Ok(parsed)
}

fn write_message(output: &mut StandardOutput, parts: &[&[u8]]) -> Result<(), ()> {
    for part in parts {
        output.write_all(part).map_err(|_| ())?;
    }
    Ok(())
}

fn run(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    match invocation.argument(1) {
        Some("-v" | "--version") if invocation.len() == 2 => {
            return if command.stdout().write_all(LUA_VERSION).is_ok() {
                exit::SUCCESS
            } else {
                exit::FAILURE
            };
        }
        Some("-h" | "--help") if invocation.len() == 2 => {
            return if write_message(
                &mut command.stdout(),
                &[
                    b"usage: lua [options] [script [args]]\n",
                    b"options: -e CODE  -l MODULE  -E  -W  -v  --  -\n",
                    b"       lua --version\n",
                ],
            )
            .is_ok()
            {
                exit::SUCCESS
            } else {
                exit::FAILURE
            };
        }
        _ => {}
    }
    let Ok(parsed) = parse_invocation(invocation) else {
        return common::usage(
            &mut command.stderr(),
            "lua",
            b"lua [options] [script [args]]",
        );
    };
    if parsed.show_version && command.stdout().write_all(LUA_VERSION).is_err() {
        return exit::FAILURE;
    }
    let Some(region) = command.take_heap() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"application heap is unavailable",
        );
        return exit::FAILURE;
    };
    let Ok(heap) = Heap::new(region) else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"cannot initialize application heap",
        );
        return exit::FAILURE;
    };
    let Ok(timer) = command.timer() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"timer capability is unavailable",
        );
        return exit::DENIED;
    };
    let Ok(wall_clock) = command.wall_clock() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"wall-clock capability is unavailable",
        );
        return exit::DENIED;
    };
    let Ok(mut filesystem) = command.filesystem() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"filesystem capability is unavailable",
        );
        return exit::DENIED;
    };
    let Ok(mutation) = command.filesystem_mutation() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"filesystem mutation capability is unavailable",
        );
        return exit::DENIED;
    };
    let Ok(launcher) = command.process_launcher() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"process-launch capability is unavailable",
        );
        return exit::DENIED;
    };
    let Ok(pipes) = command.pipes() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"pipe capability is unavailable",
        );
        return exit::DENIED;
    };

    let mut source_name_storage = [0_u8; filesystem::MAX_PATH_BYTES + 1];
    let mut stderr = command.stderr();
    let (source, source_name, argument_zero, first_argument, has_source) = match parsed.selection {
        None => (
            Source::Empty,
            &b"=(no script)"[..],
            invocation.argument(0).unwrap_or("lua"),
            invocation.len(),
            false,
        ),
        Some(Selection::StandardInput { first_argument }) => (
            Source::StandardInput(command.stdin()),
            &b"=stdin"[..],
            invocation.argument(0).unwrap_or("lua"),
            first_argument,
            true,
        ),
        Some(Selection::File {
            path,
            first_argument,
        }) => {
            let Ok(file) = filesystem.open(path) else {
                let _ = write_message(&mut stderr, &[b"lua: cannot open ", path.as_bytes(), b"\n"]);
                return exit::FAILURE;
            };
            source_name_storage[0] = b'@';
            source_name_storage[1..1 + path.len()].copy_from_slice(path.as_bytes());
            (
                Source::File {
                    filesystem,
                    file,
                    offset: 0,
                },
                &source_name_storage[..1 + path.len()],
                path,
                first_argument,
                true,
            )
        }
    };

    let mut arguments = [EMPTY_ARGUMENT; command::MAX_ARGUMENTS];
    arguments[0] = LuaArgument {
        bytes: argument_zero.as_ptr(),
        length: argument_zero.len(),
    };
    let mut argument_count = 1_usize;
    for index in first_argument..invocation.len() {
        let Some(argument) = invocation.argument(index) else {
            break;
        };
        arguments[argument_count] = LuaArgument {
            bytes: argument.as_ptr(),
            length: argument.len(),
        };
        argument_count += 1;
    }

    let mut current_directory = [0_u8; filesystem::MAX_PATH_BYTES];
    let current_directory_length = invocation.cwd().len();
    current_directory[..current_directory_length].copy_from_slice(invocation.cwd().as_bytes());
    let mut runtime = Runtime {
        heap,
        source,
        stdout: command.stdout(),
        stderr,
        timer,
        wall_clock,
        stdin: command.stdin(),
        filesystem,
        mutation,
        launcher,
        pipes,
        current_directory,
        current_directory_length,
    };
    let mut host = LuaHost {
        context: ptr::from_mut(&mut runtime).cast(),
        allocate: lua_allocate,
        read: lua_read,
        write: lua_write,
        process_cpu_time: lua_process_cpu_time,
        wall_time: lua_wall_time,
        read_input: lua_read_input,
        file_open: lua_file_open,
        file_read: lua_file_read,
        file_close: lua_file_close,
        file_replace: lua_file_replace,
        file_remove: lua_file_remove,
        file_rename: lua_file_rename,
        file_mutation_available: 1,
        process_execute: lua_process_execute,
        process_open: lua_process_open,
        process_read: lua_process_read,
        process_write: lua_process_write,
        process_close: lua_process_close,
        process_available: 1,
    };
    let mut configuration = LuaConfiguration {
        host: ptr::from_mut(&mut host),
        source_name: source_name.as_ptr(),
        source_name_length: source_name.len(),
        arguments: arguments.as_ptr(),
        argument_count,
        actions: parsed.actions.as_ptr(),
        action_count: parsed.action_count,
        has_source: i32::from(has_source),
        warnings_enabled: i32::from(parsed.warnings_enabled),
        ignore_environment: i32::from(parsed.ignore_environment),
        current_directory: invocation.cwd().as_ptr(),
        current_directory_length: invocation.cwd().len(),
        requested_exit: 0,
        requested_exit_status: exit::SUCCESS,
        requested_exit_close: 0,
    };
    // SAFETY: The C runtime is linked into this image. All pointed-to values
    // remain live and uniquely borrowed for the synchronous call, and every
    // callback validates C-provided pointers before constructing Rust slices.
    let result = unsafe { troe_lua_run(ptr::from_mut(&mut configuration)) };
    let close_failed = runtime.source.close().is_err();
    let leaked_bytes = runtime.heap.statistics().live_bytes;
    // `os.exit(_, false)` intentionally abandons Lua allocations; KEX process
    // teardown reclaims the complete application heap without running closers.
    let intentionally_unclosed =
        result == LUA_REQUESTED_EXIT && configuration.requested_exit_close == 0;
    if leaked_bytes != 0 && !intentionally_unclosed {
        common::report(
            &mut runtime.stderr,
            "lua",
            b"runtime left live heap allocations",
        );
        return exit::FAILURE;
    }
    if close_failed {
        common::report(&mut runtime.stderr, "lua", b"cannot close source file");
        return exit::FAILURE;
    }
    match result {
        LUA_SUCCESS => exit::SUCCESS,
        LUA_SOURCE_FAILURE | LUA_OUTPUT_FAILURE => exit::FAILURE,
        LUA_OUT_OF_MEMORY => {
            common::report(&mut runtime.stderr, "lua", b"memory exhausted");
            exit::FAILURE
        }
        LUA_REQUESTED_EXIT => configuration.requested_exit_status,
        _ => exit::FAILURE,
    }
}

unsafe extern "C" fn lua_allocate(
    context: *mut c_void,
    pointer: *mut c_void,
    old_size: usize,
    new_size: usize,
) -> *mut c_void {
    // SAFETY: `context` is installed from the unique `Runtime` borrow around
    // `troe_lua_run` and the C bridge invokes callbacks synchronously.
    let Some(runtime) = (unsafe { (context.cast::<Runtime>()).as_mut() }) else {
        return ptr::null_mut();
    };
    let Some(pointer) = NonNull::new(pointer.cast::<u8>()) else {
        if new_size == 0 {
            return ptr::null_mut();
        }
        let Ok(layout) = Layout::from_size_align(new_size, HEAP_ALIGNMENT) else {
            return ptr::null_mut();
        };
        return runtime
            .heap
            .allocate(layout)
            .map_or(ptr::null_mut(), |allocated| allocated.as_ptr().cast());
    };
    let Ok(old_layout) = Layout::from_size_align(old_size, HEAP_ALIGNMENT) else {
        return ptr::null_mut();
    };
    if new_size == 0 {
        // SAFETY: Lua supplies the same live pointer and old size previously
        // returned by this allocator callback.
        unsafe { runtime.heap.deallocate(pointer, old_layout) };
        return ptr::null_mut();
    }
    // SAFETY: Lua supplies the same live pointer and old size previously
    // returned by this allocator callback.
    unsafe { runtime.heap.reallocate(pointer, old_layout, new_size) }
        .map_or(ptr::null_mut(), |allocated| allocated.as_ptr().cast())
}

unsafe extern "C" fn lua_read(
    context: *mut c_void,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    if capacity == 0 {
        return 0;
    }
    // SAFETY: See `lua_allocate`; the C bridge supplies its live reader buffer.
    let Some(runtime) = (unsafe { (context.cast::<Runtime>()).as_mut() }) else {
        return -1;
    };
    let Some(destination) = NonNull::new(destination) else {
        return -1;
    };
    // SAFETY: The callback contract provides `capacity` writable bytes.
    let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), capacity) };
    runtime
        .source
        .read(destination)
        .ok()
        .and_then(|count| isize::try_from(count).ok())
        .unwrap_or(-1)
}

unsafe extern "C" fn lua_read_input(
    context: *mut c_void,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    if capacity == 0 {
        return 0;
    }
    let (Some(runtime), Some(destination)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(destination),
    ) else {
        return -1;
    };
    let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), capacity) };
    runtime
        .stdin
        .read(destination)
        .ok()
        .and_then(|count| isize::try_from(count).ok())
        .unwrap_or(-1)
}

unsafe extern "C" fn lua_file_open(
    context: *mut c_void,
    path: *const u8,
    path_length: usize,
    token: *mut u32,
    length: *mut u64,
) -> i32 {
    let (Some(runtime), Some(path), Some(mut token), Some(mut length)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(path.cast_mut()),
        NonNull::new(token),
        NonNull::new(length),
    ) else {
        return -1;
    };
    let path = unsafe { slice::from_raw_parts(path.as_ptr(), path_length) };
    let Ok(path) = str::from_utf8(path) else {
        return -1;
    };
    let Ok(file) = runtime.filesystem.open(path) else {
        return -1;
    };
    unsafe {
        *token.as_mut() = file.token();
        *length.as_mut() = file.byte_count;
    }
    0
}

unsafe extern "C" fn lua_file_read(
    context: *mut c_void,
    token: u32,
    length: u64,
    offset: u64,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    if capacity == 0 {
        return 0;
    }
    let (Some(runtime), Some(destination)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(destination),
    ) else {
        return -1;
    };
    let Ok(file) = filesystem::OpenFile::new(token, length) else {
        return -1;
    };
    let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), capacity) };
    runtime
        .filesystem
        .read(file, offset, destination)
        .ok()
        .and_then(|count| isize::try_from(count).ok())
        .unwrap_or(-1)
}

unsafe extern "C" fn lua_file_close(context: *mut c_void, token: u32, length: u64) -> i32 {
    let Some(runtime) = (unsafe { (context.cast::<Runtime>()).as_mut() }) else {
        return -1;
    };
    let Ok(file) = filesystem::OpenFile::new(token, length) else {
        return -1;
    };
    if runtime.filesystem.close(file).is_ok() {
        0
    } else {
        -1
    }
}

unsafe extern "C" fn lua_file_replace(
    context: *mut c_void,
    path: *const u8,
    path_length: usize,
    bytes: *const u8,
    length: usize,
) -> i32 {
    let (Some(runtime), Some(path)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(path.cast_mut()),
    ) else {
        return -1;
    };
    let path = unsafe { slice::from_raw_parts(path.as_ptr(), path_length) };
    let Ok(path) = str::from_utf8(path) else {
        return -1;
    };
    let bytes = if length == 0 {
        &[]
    } else {
        let Some(bytes) = NonNull::new(bytes.cast_mut()) else {
            return -1;
        };
        unsafe { slice::from_raw_parts(bytes.as_ptr(), length) }
    };
    let Ok(mut replacement) = runtime.mutation.begin_replace(path) else {
        return -1;
    };
    if replacement.write_all(bytes).is_err() {
        let _ = replacement.abort();
        return -1;
    }
    if replacement.commit().is_ok() { 0 } else { -1 }
}

unsafe extern "C" fn lua_file_remove(
    context: *mut c_void,
    path: *const u8,
    path_length: usize,
) -> i32 {
    let (Some(runtime), Some(path)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(path.cast_mut()),
    ) else {
        return -1;
    };
    let path = unsafe { slice::from_raw_parts(path.as_ptr(), path_length) };
    let Ok(path) = str::from_utf8(path) else {
        return -1;
    };
    if runtime.mutation.remove(path).is_ok() {
        0
    } else {
        -1
    }
}

unsafe extern "C" fn lua_file_rename(
    context: *mut c_void,
    old_path: *const u8,
    old_path_length: usize,
    new_path: *const u8,
    new_path_length: usize,
) -> i32 {
    let (Some(runtime), Some(old_path), Some(new_path)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(old_path.cast_mut()),
        NonNull::new(new_path.cast_mut()),
    ) else {
        return -1;
    };
    let old_path = unsafe { slice::from_raw_parts(old_path.as_ptr(), old_path_length) };
    let new_path = unsafe { slice::from_raw_parts(new_path.as_ptr(), new_path_length) };
    let (Ok(old_path), Ok(new_path)) = (str::from_utf8(old_path), str::from_utf8(new_path)) else {
        return -1;
    };
    if old_path == new_path {
        return 0;
    }
    let Ok(source) = runtime.filesystem.open(old_path) else {
        return -1;
    };
    let Ok(mut replacement) = runtime.mutation.begin_replace(new_path) else {
        let _ = runtime.filesystem.close(source);
        return -1;
    };
    let mut buffer = [0_u8; 4096];
    let mut offset = 0_u64;
    let mut failed = false;
    while offset < source.byte_count {
        let remaining = source.byte_count - offset;
        let requested = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let Ok(count) = runtime
            .filesystem
            .read(source, offset, &mut buffer[..requested])
        else {
            failed = true;
            break;
        };
        if count == 0 || replacement.write_all(&buffer[..count]).is_err() {
            failed = true;
            break;
        }
        let Ok(count) = u64::try_from(count) else {
            failed = true;
            break;
        };
        let Some(next) = offset.checked_add(count) else {
            failed = true;
            break;
        };
        offset = next;
    }
    if runtime.filesystem.close(source).is_err() {
        failed = true;
    }
    if failed {
        let _ = replacement.abort();
        return -1;
    }
    if replacement.commit().is_err() || runtime.mutation.remove(old_path).is_err() {
        return -1;
    }
    0
}

fn parse_process_arguments<'storage>(
    source: &[u8],
    storage: &'storage mut [u8; command::MAX_ARGUMENT_BYTES],
    ranges: &mut [(usize, usize); command::MAX_ARGUMENTS],
) -> Result<([&'storage str; command::MAX_ARGUMENTS], usize), ()> {
    let mut source_at = 0_usize;
    let mut storage_at = 0_usize;
    let mut count = 0_usize;
    while source_at < source.len() {
        while source.get(source_at).is_some_and(u8::is_ascii_whitespace) {
            source_at += 1;
        }
        if source_at == source.len() {
            break;
        }
        if count == ranges.len() {
            return Err(());
        }
        let start = storage_at;
        let mut quote = 0_u8;
        let mut token_present = false;
        while source_at < source.len() {
            let byte = source[source_at];
            if quote == 0 && byte.is_ascii_whitespace() {
                break;
            }
            if byte == b'\'' && quote != b'"' {
                token_present = true;
                quote = if quote == b'\'' { 0 } else { b'\'' };
                source_at += 1;
                continue;
            }
            if byte == b'"' && quote != b'\'' {
                token_present = true;
                quote = if quote == b'"' { 0 } else { b'"' };
                source_at += 1;
                continue;
            }
            if byte == b'\\' && quote != b'\'' {
                token_present = true;
                source_at += 1;
                if source_at == source.len() {
                    return Err(());
                }
                if storage_at == storage.len() {
                    return Err(());
                }
                storage[storage_at] = source[source_at];
                storage_at += 1;
                source_at += 1;
                continue;
            }
            if quote == 0 && b"|&;<>()$`".contains(&byte) {
                return Err(());
            }
            if storage_at == storage.len() {
                return Err(());
            }
            storage[storage_at] = byte;
            token_present = true;
            storage_at += 1;
            source_at += 1;
        }
        if quote != 0 || !token_present {
            return Err(());
        }
        ranges[count] = (start, storage_at);
        count += 1;
    }
    if count == 0 {
        return Err(());
    }
    let mut arguments = [""; command::MAX_ARGUMENTS];
    for (argument, (start, end)) in arguments[..count].iter_mut().zip(ranges[..count].iter()) {
        *argument = str::from_utf8(&storage[*start..*end]).map_err(|_| ())?;
    }
    Ok((arguments, count))
}

fn launch_command(
    runtime: &mut Runtime,
    source: &[u8],
    stdin: process_launch::StreamSpec,
    stdout: process_launch::StreamSpec,
) -> Result<process_launch::SpawnedChild, ()> {
    let mut argument_bytes = [0_u8; command::MAX_ARGUMENT_BYTES];
    let mut argument_ranges = [(0_usize, 0_usize); command::MAX_ARGUMENTS];
    let (arguments, argument_count) =
        parse_process_arguments(source, &mut argument_bytes, &mut argument_ranges)?;
    let cwd = str::from_utf8(&runtime.current_directory[..runtime.current_directory_length])
        .map_err(|_| ())?;
    let mut pwd_bytes = [0_u8; filesystem::MAX_PATH_BYTES + 4];
    pwd_bytes[..4].copy_from_slice(b"PWD=");
    pwd_bytes[4..4 + cwd.len()].copy_from_slice(cwd.as_bytes());
    let pwd = str::from_utf8(&pwd_bytes[..4 + cwd.len()]).map_err(|_| ())?;
    let environment = [
        "HOME=/",
        "PATH=/bin",
        "TMPDIR=/tmp",
        "SHELL=/bin/sh",
        "USER=root",
        "LOGNAME=root",
        pwd,
    ];
    runtime
        .launcher
        .spawn(
            cwd,
            &arguments[..argument_count],
            &environment,
            stdin,
            stdout,
            process_launch::StreamSpec::INHERIT,
        )
        .map_err(|_| ())
}

unsafe extern "C" fn lua_process_execute(
    context: *mut c_void,
    command: *const u8,
    command_length: usize,
    status: *mut u32,
) -> i32 {
    let (Some(runtime), Some(command), Some(mut status)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(command.cast_mut()),
        NonNull::new(status),
    ) else {
        return -1;
    };
    let command = unsafe { slice::from_raw_parts(command.as_ptr(), command_length) };
    let Ok(child) = launch_command(
        runtime,
        command,
        process_launch::StreamSpec::INHERIT,
        process_launch::StreamSpec::INHERIT,
    ) else {
        return -1;
    };
    let result = runtime.launcher.wait(child.token);
    let reaped = runtime.launcher.reap(child.token).is_ok();
    let Ok(result) = result else {
        return -1;
    };
    if !reaped {
        return -1;
    }
    unsafe { *status.as_mut() = result.exit_status };
    0
}

unsafe extern "C" fn lua_process_open(
    context: *mut c_void,
    command: *const u8,
    command_length: usize,
    mode: i32,
    child_token: *mut u64,
    pipe_token: *mut u64,
    script_identifier: *mut u64,
) -> i32 {
    let (
        Some(runtime),
        Some(command),
        Some(mut child_token),
        Some(mut pipe_token),
        Some(mut script_identifier),
    ) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(command.cast_mut()),
        NonNull::new(child_token),
        NonNull::new(pipe_token),
        NonNull::new(script_identifier),
    )
    else {
        return -1;
    };
    if mode != i32::from(b'r') && mode != i32::from(b'w') {
        return -1;
    }
    let command = unsafe { slice::from_raw_parts(command.as_ptr(), command_length) };
    let Ok(pipe) = runtime.pipes.create(pipe::MIN_CAPACITY) else {
        return -1;
    };
    let Ok(pipe_stream) = process_launch::StreamSpec::pipe(pipe.value()) else {
        let _ = runtime.pipes.close_writer(pipe);
        let _ = runtime.pipes.close_reader(pipe);
        return -1;
    };
    let (stdin, stdout) = if mode == i32::from(b'r') {
        (process_launch::StreamSpec::INHERIT, pipe_stream)
    } else {
        (pipe_stream, process_launch::StreamSpec::INHERIT)
    };
    let Ok(child) = launch_command(runtime, command, stdin, stdout) else {
        let _ = runtime.pipes.close_writer(pipe);
        let _ = runtime.pipes.close_reader(pipe);
        return -1;
    };
    let closed = if mode == i32::from(b'r') {
        runtime.pipes.close_writer(pipe)
    } else {
        runtime.pipes.close_reader(pipe)
    };
    if closed.is_err() {
        let _ = runtime.launcher.cancel(child.token);
        let _ = runtime.launcher.wait(child.token);
        let _ = runtime.launcher.reap(child.token);
        return -1;
    }
    unsafe {
        *child_token.as_mut() = child.token.value();
        *pipe_token.as_mut() = pipe.value();
        *script_identifier.as_mut() = 0;
    }
    0
}

unsafe extern "C" fn lua_process_read(
    context: *mut c_void,
    pipe_token: u64,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    if capacity == 0 {
        return 0;
    }
    let (Some(runtime), Some(destination)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(destination),
    ) else {
        return -1;
    };
    let Ok(token) = pipe::PipeToken::new(pipe_token) else {
        return -1;
    };
    let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), capacity) };
    runtime
        .pipes
        .read(token, destination)
        .ok()
        .and_then(|count| isize::try_from(count).ok())
        .unwrap_or(-1)
}

unsafe extern "C" fn lua_process_write(
    context: *mut c_void,
    pipe_token: u64,
    bytes: *const u8,
    length: usize,
) -> i32 {
    if length == 0 {
        return 0;
    }
    let (Some(runtime), Some(bytes)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(bytes.cast_mut()),
    ) else {
        return -1;
    };
    let Ok(token) = pipe::PipeToken::new(pipe_token) else {
        return -1;
    };
    let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr(), length) };
    if runtime.pipes.write_all(token, bytes).is_ok() {
        0
    } else {
        -1
    }
}

unsafe extern "C" fn lua_process_close(
    context: *mut c_void,
    child_token: u64,
    pipe_token: u64,
    script_identifier: u64,
    mode: i32,
    status: *mut u32,
) -> i32 {
    let (Some(runtime), Some(mut status)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(status),
    ) else {
        return -1;
    };
    let (Ok(child), Ok(pipe)) = (
        process_launch::ChildToken::new(child_token),
        pipe::PipeToken::new(pipe_token),
    ) else {
        return -1;
    };
    let endpoint_closed = if mode == i32::from(b'r') {
        runtime.pipes.close_reader(pipe)
    } else if mode == i32::from(b'w') {
        runtime.pipes.close_writer(pipe)
    } else {
        return -1;
    };
    let mut child_status = runtime.launcher.wait(child);
    if child_status.is_err() {
        let _ = runtime.launcher.cancel(child);
        child_status = runtime.launcher.wait(child);
    }
    let reaped = runtime.launcher.reap(child).is_ok();
    let _ = script_identifier;
    let Ok(child_status) = child_status else {
        return -1;
    };
    if endpoint_closed.is_err() || !reaped {
        return -1;
    }
    unsafe { *status.as_mut() = child_status.exit_status };
    0
}

unsafe extern "C" fn lua_write(
    context: *mut c_void,
    stream: i32,
    bytes: *const u8,
    length: usize,
) -> i32 {
    if length == 0 {
        return 0;
    }
    // SAFETY: See `lua_allocate`; the C bridge supplies a readable Lua string.
    let Some(runtime) = (unsafe { (context.cast::<Runtime>()).as_mut() }) else {
        return -1;
    };
    let Some(bytes) = NonNull::new(bytes.cast_mut()) else {
        return -1;
    };
    // SAFETY: The callback contract provides `length` readable bytes.
    let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr(), length) };
    let result = match stream {
        1 => runtime.stdout.write_all(bytes),
        2 => runtime.stderr.write_all(bytes),
        _ => return -1,
    };
    if result.is_ok() { 0 } else { -1 }
}

unsafe extern "C" fn lua_process_cpu_time(
    context: *mut c_void,
    ticks: *mut u64,
    frequency_hz: *mut u64,
) -> i32 {
    // SAFETY: See `lua_allocate`; the C shim supplies two writable result slots.
    let (Some(runtime), Some(mut ticks), Some(mut frequency_hz)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(ticks),
        NonNull::new(frequency_hz),
    ) else {
        return -1;
    };
    let Ok(sample) = runtime.timer.process_cpu_time() else {
        return -1;
    };
    // SAFETY: The callback contract provides two writable `u64` result slots.
    unsafe {
        *ticks.as_mut() = sample.ticks;
        *frequency_hz.as_mut() = sample.frequency_hz;
    }
    0
}

unsafe extern "C" fn lua_wall_time(context: *mut c_void, result: *mut u64) -> i32 {
    // SAFETY: See `lua_allocate`; the C shim supplies one writable result slot.
    let (Some(runtime), Some(mut result)) = (
        unsafe { (context.cast::<Runtime>()).as_mut() },
        NonNull::new(result),
    ) else {
        return -1;
    };
    let Ok(seconds) = runtime.wall_clock.now() else {
        return -1;
    };
    // SAFETY: The callback contract provides one writable `u64` result slot.
    unsafe {
        *result.as_mut() = seconds;
    }
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn troe_parse_decimal(bytes: *const u8, length: usize, result: *mut f64) -> i32 {
    if length == 0 {
        return -1;
    }
    let (Some(bytes), Some(mut result)) = (NonNull::new(bytes.cast_mut()), NonNull::new(result))
    else {
        return -1;
    };
    // SAFETY: The C scanner passes its live ASCII numeric token.
    let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr(), length) };
    let Ok(text) = str::from_utf8(bytes) else {
        return -1;
    };
    let Ok(value) = text.parse::<f64>() else {
        return -1;
    };
    // SAFETY: The C scanner passes one writable `double` result slot.
    unsafe { *result.as_mut() = value };
    0
}

macro_rules! unary_math {
    ($bridge:ident, $name:ident) => {
        #[unsafe(no_mangle)]
        extern "C" fn $bridge(value_bits: u64) -> u64 {
            libm::$name(f64::from_bits(value_bits)).to_bits()
        }
    };
}

unary_math!(troe_math_acos_bits, acos);
unary_math!(troe_math_asin_bits, asin);
unary_math!(troe_math_atan_bits, atan);
unary_math!(troe_math_ceil_bits, ceil);
unary_math!(troe_math_cos_bits, cos);
unary_math!(troe_math_exp_bits, exp);
unary_math!(troe_math_fabs_bits, fabs);
unary_math!(troe_math_floor_bits, floor);
unary_math!(troe_math_log_bits, log);
unary_math!(troe_math_log10_bits, log10);
unary_math!(troe_math_sin_bits, sin);
unary_math!(troe_math_sqrt_bits, sqrt);
unary_math!(troe_math_tan_bits, tan);

#[unsafe(no_mangle)]
extern "C" fn troe_math_atan2_bits(y_bits: u64, x_bits: u64) -> u64 {
    libm::atan2(f64::from_bits(y_bits), f64::from_bits(x_bits)).to_bits()
}

#[unsafe(no_mangle)]
extern "C" fn troe_math_fmod_bits(x_bits: u64, y_bits: u64) -> u64 {
    libm::fmod(f64::from_bits(x_bits), f64::from_bits(y_bits)).to_bits()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn troe_math_frexp_bits(value_bits: u64, exponent: *mut i32) -> u64 {
    let (fraction, parsed_exponent) = libm::frexp(f64::from_bits(value_bits));
    if let Some(mut exponent) = NonNull::new(exponent) {
        // SAFETY: The C caller supplies a writable exponent result slot.
        unsafe { *exponent.as_mut() = parsed_exponent };
    }
    fraction.to_bits()
}

#[unsafe(no_mangle)]
extern "C" fn troe_math_ldexp_bits(value_bits: u64, exponent: i32) -> u64 {
    libm::ldexp(f64::from_bits(value_bits), exponent).to_bits()
}

#[unsafe(no_mangle)]
extern "C" fn troe_math_pow_bits(x_bits: u64, y_bits: u64) -> u64 {
    libm::pow(f64::from_bits(x_bits), f64::from_bits(y_bits)).to_bits()
}

entry!(run);

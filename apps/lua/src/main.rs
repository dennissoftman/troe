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
use troe_kex_runtime::{self as kex_runtime, process::PipeMode};
use troe_kex_sdk::{
    CommandContext, ENVIRONMENT_BUFFER_BYTES, Error as KexError, FilesystemMutation,
    INVOCATION_BUFFER_BYTES, Pipes, ProcessLauncher, ReadOnlyFilesystem, StandardInput,
    StandardOutput, Timer, WallClock, command, entry, exit, filesystem, pipe, process_launch,
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
    environment_get: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8, usize) -> isize,
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
    seed: u32,
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
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, KexError> {
        match self {
            Self::Empty => Ok(0),
            Self::StandardInput(input) => input.read(destination),
            Self::File {
                filesystem,
                file,
                offset,
            } => {
                let count = filesystem.read(*file, *offset, destination)?;
                *offset = offset
                    .checked_add(u64::try_from(count).map_err(|_| KexError::Overflow)?)
                    .ok_or(KexError::Overflow)?;
                Ok(count)
            }
        }
    }

    fn close(&mut self) -> Result<(), KexError> {
        match self {
            Self::File {
                filesystem, file, ..
            } => filesystem.close(*file),
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
    environment: [u8; ENVIRONMENT_BUFFER_BYTES],
    environment_length: usize,
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
    let mut environment = [0_u8; ENVIRONMENT_BUFFER_BYTES];
    if command.environment(&mut environment).is_err() {
        return exit::FAILURE;
    }
    let environment_length = usize::from(u16::from_le_bytes([environment[0], environment[1]]));
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
    let Ok(private_memory) = command.private_memory() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"private-memory capability is unavailable",
        );
        return exit::DENIED;
    };
    let Ok(mut random) = command.random() else {
        common::report(
            &mut command.stderr(),
            "lua",
            b"random capability is unavailable",
        );
        return exit::DENIED;
    };
    let Ok(seed) = kex_runtime::random::next_u32(&mut random) else {
        common::report(&mut command.stderr(), "lua", b"random service failed");
        return exit::FAILURE;
    };
    let Ok(heap) = Heap::new_with_private_memory(region, private_memory) else {
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
        environment,
        environment_length,
    };
    let mut host = LuaHost {
        context: ptr::from_mut(&mut runtime).cast(),
        allocate: lua_allocate,
        read: lua_read,
        write: lua_write,
        process_cpu_time: lua_process_cpu_time,
        wall_time: lua_wall_time,
        environment_get: lua_environment_get,
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
        seed,
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

fn negative_errno(error: i32) -> isize {
    isize::try_from(error).map_or(-1, |value| -value)
}

fn read_result(result: Result<usize, KexError>) -> isize {
    match result {
        Ok(count) => {
            isize::try_from(count).unwrap_or_else(|_| negative_errno(kex_runtime::errno::EOVERFLOW))
        }
        Err(error) => negative_errno(kex_runtime::errno::from_kex(error)),
    }
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
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let Some(destination) = NonNull::new(destination) else {
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    // SAFETY: The callback contract provides `capacity` writable bytes.
    let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), capacity) };
    read_result(runtime.source.read(destination))
}

unsafe extern "C" fn lua_environment_get(
    context: *mut c_void,
    name: *const u8,
    name_length: usize,
    destination: *mut u8,
    capacity: usize,
) -> isize {
    let (Some(runtime), Some(name)) = (
        unsafe { (context.cast::<Runtime>()).as_ref() },
        NonNull::new(name.cast_mut()),
    ) else {
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let name = unsafe { slice::from_raw_parts(name.as_ptr(), name_length) };
    let Ok(name) = str::from_utf8(name) else {
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let Ok(cwd) = str::from_utf8(&runtime.current_directory[..runtime.current_directory_length])
    else {
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let Ok(environment) =
        command::Environment::parse(&runtime.environment[..runtime.environment_length])
    else {
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let Some(value) = kex_runtime::environment::get(environment, cwd, name) else {
        return negative_errno(kex_runtime::errno::ENOENT);
    };
    if value.len() > capacity {
        return negative_errno(kex_runtime::errno::EOVERFLOW);
    }
    if !value.is_empty() {
        let Some(destination) = NonNull::new(destination) else {
            return negative_errno(kex_runtime::errno::EINVAL);
        };
        let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), value.len()) };
        destination.copy_from_slice(value.as_bytes());
    }
    isize::try_from(value.len()).unwrap_or_else(|_| negative_errno(kex_runtime::errno::EOVERFLOW))
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
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), capacity) };
    read_result(runtime.stdin.read(destination))
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
        return kex_runtime::errno::EINVAL;
    };
    let path = unsafe { slice::from_raw_parts(path.as_ptr(), path_length) };
    let Ok(path) = str::from_utf8(path) else {
        return kex_runtime::errno::EINVAL;
    };
    let file = match runtime.filesystem.open(path) {
        Ok(file) => file,
        Err(error) => return kex_runtime::errno::from_kex(error),
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
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let Ok(file) = filesystem::OpenFile::new(token, length) else {
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), capacity) };
    read_result(runtime.filesystem.read(file, offset, destination))
}

unsafe extern "C" fn lua_file_close(context: *mut c_void, token: u32, length: u64) -> i32 {
    let Some(runtime) = (unsafe { (context.cast::<Runtime>()).as_mut() }) else {
        return kex_runtime::errno::EINVAL;
    };
    let Ok(file) = filesystem::OpenFile::new(token, length) else {
        return kex_runtime::errno::EINVAL;
    };
    match runtime.filesystem.close(file) {
        Ok(()) => 0,
        Err(error) => kex_runtime::errno::from_kex(error),
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
        return kex_runtime::errno::EINVAL;
    };
    let path = unsafe { slice::from_raw_parts(path.as_ptr(), path_length) };
    let Ok(path) = str::from_utf8(path) else {
        return kex_runtime::errno::EINVAL;
    };
    let bytes = if length == 0 {
        &[]
    } else {
        let Some(bytes) = NonNull::new(bytes.cast_mut()) else {
            return kex_runtime::errno::EINVAL;
        };
        unsafe { slice::from_raw_parts(bytes.as_ptr(), length) }
    };
    match kex_runtime::replace_bytes(&mut runtime.mutation, path, bytes) {
        Ok(()) => 0,
        Err(error) => kex_runtime::errno::from_runtime(error),
    }
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
        return kex_runtime::errno::EINVAL;
    };
    let path = unsafe { slice::from_raw_parts(path.as_ptr(), path_length) };
    let Ok(path) = str::from_utf8(path) else {
        return kex_runtime::errno::EINVAL;
    };
    match kex_runtime::remove_path(&mut runtime.filesystem, &mut runtime.mutation, path) {
        Ok(()) => 0,
        Err(error) => kex_runtime::errno::from_runtime(error),
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
        return kex_runtime::errno::EINVAL;
    };
    let old_path = unsafe { slice::from_raw_parts(old_path.as_ptr(), old_path_length) };
    let new_path = unsafe { slice::from_raw_parts(new_path.as_ptr(), new_path_length) };
    let (Ok(old_path), Ok(new_path)) = (str::from_utf8(old_path), str::from_utf8(new_path)) else {
        return kex_runtime::errno::EINVAL;
    };
    if old_path == new_path {
        return 0;
    }
    match runtime.mutation.rename(old_path, new_path) {
        Ok(()) => 0,
        Err(error) => kex_runtime::errno::from_kex(error),
    }
}

fn launch_command(
    runtime: &mut Runtime,
    source: &[u8],
    stdin: process_launch::StreamSpec,
    stdout: process_launch::StreamSpec,
) -> Result<process_launch::SpawnedChild, i32> {
    let cwd = str::from_utf8(&runtime.current_directory[..runtime.current_directory_length])
        .map_err(|_| kex_runtime::errno::EINVAL)?;
    let environment =
        command::Environment::parse(&runtime.environment[..runtime.environment_length])
            .map_err(|_| kex_runtime::errno::EINVAL)?;
    let mut pwd_bytes = [0_u8; filesystem::MAX_PATH_BYTES + 4];
    let mut entries = [""; command::MAX_ENVIRONMENT];
    let count =
        kex_runtime::environment::child_entries(environment, cwd, &mut pwd_bytes, &mut entries)
            .map_err(kex_runtime::errno::from_environment)?;
    kex_runtime::process::spawn_direct(
        &mut runtime.launcher,
        source,
        cwd,
        &entries[..count],
        stdin,
        stdout,
        process_launch::StreamSpec::INHERIT,
    )
    .map_err(kex_runtime::errno::from_process)
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
        return kex_runtime::errno::EINVAL;
    };
    let command = unsafe { slice::from_raw_parts(command.as_ptr(), command_length) };
    let child = match launch_command(
        runtime,
        command,
        process_launch::StreamSpec::INHERIT,
        process_launch::StreamSpec::INHERIT,
    ) {
        Ok(child) => child,
        Err(error) => return error,
    };
    let result = match kex_runtime::process::finish_child(&mut runtime.launcher, child.token) {
        Ok(result) => result,
        Err(error) => return kex_runtime::errno::from_process(error),
    };
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
        return kex_runtime::errno::EINVAL;
    };
    if mode != i32::from(b'r') && mode != i32::from(b'w') {
        return kex_runtime::errno::EINVAL;
    }
    let command = unsafe { slice::from_raw_parts(command.as_ptr(), command_length) };
    let cwd = match str::from_utf8(&runtime.current_directory[..runtime.current_directory_length]) {
        Ok(cwd) => cwd,
        Err(_) => return kex_runtime::errno::EINVAL,
    };
    let environment =
        match command::Environment::parse(&runtime.environment[..runtime.environment_length]) {
            Ok(environment) => environment,
            Err(_) => return kex_runtime::errno::EINVAL,
        };
    let mut pwd_bytes = [0_u8; filesystem::MAX_PATH_BYTES + 4];
    let mut entries = [""; command::MAX_ENVIRONMENT];
    let count = match kex_runtime::environment::child_entries(
        environment,
        cwd,
        &mut pwd_bytes,
        &mut entries,
    ) {
        Ok(count) => count,
        Err(error) => return kex_runtime::errno::from_environment(error),
    };
    let selected_mode = if mode == i32::from(b'r') {
        PipeMode::Read
    } else {
        PipeMode::Write
    };
    let child = match kex_runtime::process::open_piped_direct(
        &mut runtime.launcher,
        &mut runtime.pipes,
        command,
        cwd,
        &entries[..count],
        selected_mode,
    ) {
        Ok(child) => child,
        Err(error) => return kex_runtime::errno::from_process(error),
    };
    unsafe {
        *child_token.as_mut() = child.child.value();
        *pipe_token.as_mut() = child.pipe.value();
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
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let Ok(token) = pipe::PipeToken::new(pipe_token) else {
        return negative_errno(kex_runtime::errno::EINVAL);
    };
    let destination = unsafe { slice::from_raw_parts_mut(destination.as_ptr(), capacity) };
    read_result(runtime.pipes.read(token, destination))
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
        return kex_runtime::errno::EINVAL;
    };
    let Ok(token) = pipe::PipeToken::new(pipe_token) else {
        return kex_runtime::errno::EINVAL;
    };
    let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr(), length) };
    match runtime.pipes.write_all(token, bytes) {
        Ok(()) => 0,
        Err(error) => kex_runtime::errno::from_kex(error),
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
        return kex_runtime::errno::EINVAL;
    };
    let (Ok(child), Ok(pipe)) = (
        process_launch::ChildToken::new(child_token),
        pipe::PipeToken::new(pipe_token),
    ) else {
        return kex_runtime::errno::EINVAL;
    };
    let mode = if mode == i32::from(b'r') {
        PipeMode::Read
    } else if mode == i32::from(b'w') {
        PipeMode::Write
    } else {
        return kex_runtime::errno::EINVAL;
    };
    let _ = script_identifier;
    let child_status = match kex_runtime::process::close_piped(
        &mut runtime.launcher,
        &mut runtime.pipes,
        kex_runtime::process::PipedChild { child, pipe, mode },
    ) {
        Ok(status) => status,
        Err(error) => return kex_runtime::errno::from_process(error),
    };
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
        return kex_runtime::errno::EINVAL;
    };
    let Some(bytes) = NonNull::new(bytes.cast_mut()) else {
        return kex_runtime::errno::EINVAL;
    };
    // SAFETY: The callback contract provides `length` readable bytes.
    let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr(), length) };
    let result = match stream {
        1 => runtime.stdout.write_all(bytes),
        2 => runtime.stderr.write_all(bytes),
        _ => return kex_runtime::errno::EINVAL,
    };
    match result {
        Ok(()) => 0,
        Err(error) => kex_runtime::errno::from_kex(error),
    }
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
        return kex_runtime::errno::EINVAL;
    };
    let sample = match runtime.timer.process_cpu_time() {
        Ok(sample) => sample,
        Err(error) => return kex_runtime::errno::from_kex(error),
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
        return kex_runtime::errno::EINVAL;
    };
    let seconds = match runtime.wall_clock.now() {
        Ok(seconds) => seconds,
        Err(error) => return kex_runtime::errno::from_kex(error),
    };
    // SAFETY: The callback contract provides one writable `u64` result slot.
    unsafe {
        *result.as_mut() = seconds;
    }
    0
}

entry!(run);

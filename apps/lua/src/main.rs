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
    CommandContext, INVOCATION_BUFFER_BYTES, ReadOnlyFilesystem, StandardInput, StandardOutput,
    command, entry, exit, filesystem,
};

const LUA_VERSION: &[u8] = b"Lua 5.5.1  Copyright (C) 1994-2026 Lua.org, PUC-Rio\n";
const HEAP_ALIGNMENT: usize = 16;
const LUA_SUCCESS: i32 = 0;
const LUA_SOURCE_FAILURE: i32 = 2;
const LUA_OUTPUT_FAILURE: i32 = 3;
const LUA_OUT_OF_MEMORY: i32 = 4;

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

#[repr(C)]
struct LuaHost {
    context: *mut c_void,
    allocate: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void,
    read: unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> isize,
    write: unsafe extern "C" fn(*mut c_void, i32, *const u8, usize) -> i32,
    yield_now: unsafe extern "C" fn(*mut c_void) -> i32,
}

#[repr(C)]
struct LuaConfiguration {
    host: *mut LuaHost,
    source_name: *const u8,
    source_name_length: usize,
    arguments: *const LuaArgument,
    argument_count: usize,
}

unsafe extern "C" {
    fn troe_lua_run(configuration: *mut LuaConfiguration) -> i32;
}

enum Source<'invocation> {
    Inline {
        bytes: &'invocation [u8],
        offset: usize,
    },
    StandardInput(StandardInput),
    File {
        filesystem: ReadOnlyFilesystem,
        file: filesystem::OpenFile,
        offset: u64,
    },
}

impl Source<'_> {
    fn read(&mut self, destination: &mut [u8]) -> Result<usize, ()> {
        match self {
            Self::Inline { bytes, offset } => {
                let remaining = bytes.get(*offset..).ok_or(())?;
                let count = remaining.len().min(destination.len());
                destination[..count].copy_from_slice(&remaining[..count]);
                *offset = offset.checked_add(count).ok_or(())?;
                Ok(count)
            }
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
            Self::Inline { .. } | Self::StandardInput(_) => Ok(()),
        }
    }
}

struct Runtime<'invocation> {
    heap: Heap,
    source: Source<'invocation>,
    stdout: StandardOutput,
    stderr: StandardOutput,
}

enum Selection<'invocation> {
    Inline {
        code: &'invocation str,
        first_argument: usize,
    },
    StandardInput {
        first_argument: usize,
    },
    File {
        path: &'invocation str,
        first_argument: usize,
    },
}

fn select_source<'invocation>(
    invocation: command::Invocation<'invocation>,
) -> Result<Selection<'invocation>, ()> {
    let Some(first) = invocation.argument(1) else {
        return Ok(Selection::StandardInput { first_argument: 2 });
    };
    match first {
        "-e" => invocation
            .argument(2)
            .map(|code| Selection::Inline {
                code,
                first_argument: 3,
            })
            .ok_or(()),
        "-" => Ok(Selection::StandardInput { first_argument: 2 }),
        "--" => Ok(match invocation.argument(2) {
            Some(path) => Selection::File {
                path,
                first_argument: 3,
            },
            None => Selection::StandardInput { first_argument: 3 },
        }),
        option if option.starts_with('-') => option
            .strip_prefix("-e")
            .filter(|code| !code.is_empty())
            .map(|code| Selection::Inline {
                code,
                first_argument: 2,
            })
            .ok_or(()),
        path => Ok(Selection::File {
            path,
            first_argument: 2,
        }),
    }
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
                    b"usage: lua [-e CODE | FILE | -] [ARG...]\n",
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
    let Ok(selection) = select_source(invocation) else {
        return common::usage(
            &mut command.stderr(),
            "lua",
            b"lua [-e CODE | FILE | -] [ARG...]",
        );
    };
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

    let mut source_name_storage = [0_u8; filesystem::MAX_PATH_BYTES + 1];
    let mut stderr = command.stderr();
    let (source, source_name, argument_zero, first_argument) = match selection {
        Selection::Inline {
            code,
            first_argument,
        } => (
            Source::Inline {
                bytes: code.as_bytes(),
                offset: 0,
            },
            &b"=(command line)"[..],
            invocation.argument(0).unwrap_or("lua"),
            first_argument,
        ),
        Selection::StandardInput { first_argument } => (
            Source::StandardInput(command.stdin()),
            &b"=stdin"[..],
            invocation.argument(0).unwrap_or("lua"),
            first_argument,
        ),
        Selection::File {
            path,
            first_argument,
        } => {
            let Ok(mut filesystem) = command.filesystem() else {
                common::report(&mut stderr, "lua", b"filesystem capability is unavailable");
                return exit::FAILURE;
            };
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

    let mut runtime = Runtime {
        heap,
        source,
        stdout: command.stdout(),
        stderr,
    };
    let mut host = LuaHost {
        context: ptr::from_mut(&mut runtime).cast(),
        allocate: lua_allocate,
        read: lua_read,
        write: lua_write,
        yield_now: lua_yield,
    };
    let mut configuration = LuaConfiguration {
        host: ptr::from_mut(&mut host),
        source_name: source_name.as_ptr(),
        source_name_length: source_name.len(),
        arguments: arguments.as_ptr(),
        argument_count,
    };
    // SAFETY: The C runtime is linked into this image. All pointed-to values
    // remain live and uniquely borrowed for the synchronous call, and every
    // callback validates C-provided pointers before constructing Rust slices.
    let result = unsafe { troe_lua_run(ptr::from_mut(&mut configuration)) };
    let close_failed = runtime.source.close().is_err();
    let leaked_bytes = runtime.heap.statistics().live_bytes;
    if leaked_bytes != 0 {
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
    let Some(runtime) = (unsafe { (context.cast::<Runtime<'_>>()).as_mut() }) else {
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
    let Some(runtime) = (unsafe { (context.cast::<Runtime<'_>>()).as_mut() }) else {
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
    let Some(runtime) = (unsafe { (context.cast::<Runtime<'_>>()).as_mut() }) else {
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

unsafe extern "C" fn lua_yield(_context: *mut c_void) -> i32 {
    if troe_kex_sdk::yield_now().is_ok() {
        0
    } else {
        -1
    }
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

#![no_std]
#![no_main]

use core::{
    ffi::{c_char, c_void},
    fmt,
    fmt::Write as _,
    ptr,
};
use troe_kex_c_runtime::{Configuration, Runtime};
use troe_kex_runtime::environment;
use troe_kex_sdk::{
    CommandContext, ENVIRONMENT_BUFFER_BYTES, INVOCATION_BUFFER_BYTES, StandardOutput, command,
    entry, exit,
};

unsafe extern "C" {
    fn troe_runtime_initialize(configuration: *const Configuration) -> i32;
    fn troe_runtime_finalize();
    fn troe_cpython_run(
        argc: i32,
        argv: *mut *mut c_char,
        checkpoint_context: *mut c_void,
        checkpoint: unsafe extern "C" fn(*mut c_void),
    ) -> i32;
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct MetricSnapshot {
    live_bytes: u64,
    high_water_bytes: u64,
    capacity_bytes: u64,
    private_mapped_bytes: u64,
    private_mappings: u64,
}

#[repr(C)]
struct Checkpoint {
    runtime: *const Runtime,
    startup: MetricSnapshot,
}

struct OutputWriter<'output>(&'output mut StandardOutput);

impl fmt::Write for OutputWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

unsafe extern "C" fn capture_startup(context: *mut c_void) {
    // SAFETY: The C launcher calls this synchronously while the stack-owned
    // checkpoint and immovable Runtime are both live.
    let Some(checkpoint) = (unsafe { context.cast::<Checkpoint>().as_mut() }) else {
        return;
    };
    // SAFETY: `main` installs this pointer immediately before entering C and
    // does not move or destroy the Runtime until the C launcher returns.
    let Some(runtime) = (unsafe { checkpoint.runtime.as_ref() }) else {
        return;
    };
    let statistics = runtime.allocator_statistics();
    checkpoint.startup = MetricSnapshot {
        live_bytes: statistics.live_bytes,
        high_water_bytes: statistics.high_water_bytes,
        capacity_bytes: statistics.capacity_bytes,
        private_mapped_bytes: statistics.private_mapped_bytes,
        private_mappings: statistics.private_mappings,
    };
}

fn copy_c_string(value: &str, storage: &mut [u8], offset: &mut usize) -> Option<*mut c_char> {
    let end = offset.checked_add(value.len())?.checked_add(1)?;
    let destination = storage.get_mut(*offset..end)?;
    destination[..value.len()].copy_from_slice(value.as_bytes());
    destination[value.len()] = 0;
    let pointer = destination.as_mut_ptr().cast();
    *offset = end;
    Some(pointer)
}

fn main(command_context: &mut CommandContext) -> u32 {
    let mut invocation_buffer = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command_context.invocation(&mut invocation_buffer) else {
        return exit::FAILURE;
    };
    let mut environment_buffer = [0_u8; ENVIRONMENT_BUFFER_BYTES];
    let Ok(environment) = command_context.environment(&mut environment_buffer) else {
        return exit::FAILURE;
    };
    let mut x_option = false;
    let emit_metrics_argument = invocation.arguments().any(|argument| {
        if x_option {
            x_option = false;
            return argument == "troe_metrics";
        }
        if argument == "-X" {
            x_option = true;
            return false;
        }
        argument == "-Xtroe_metrics"
    });
    let emit_metrics = emit_metrics_argument
        || environment::get(environment, invocation.cwd(), "TROE_CPYTHON_METRICS") == Some("1");

    let mut argument_storage = [0_u8; command::MAX_ARGUMENT_BYTES + command::MAX_ARGUMENTS];
    let mut argument_pointers = [ptr::null_mut(); command::MAX_ARGUMENTS + 1];
    let mut argument_offset = 0;
    for (index, argument) in invocation.arguments().enumerate() {
        let Some(pointer) = copy_c_string(argument, &mut argument_storage, &mut argument_offset)
        else {
            return exit::FAILURE;
        };
        argument_pointers[index] = pointer;
    }

    let mut pwd_storage = [0_u8; command::MAX_CWD_BYTES + 4];
    let mut environment_entries = [""; command::MAX_ENVIRONMENT];
    let Ok(environment_count) = environment::child_entries(
        environment,
        invocation.cwd(),
        &mut pwd_storage,
        &mut environment_entries,
    ) else {
        return exit::FAILURE;
    };
    let mut environment_storage = [0_u8;
        command::MAX_ENVIRONMENT_BYTES + command::MAX_ENVIRONMENT + command::MAX_CWD_BYTES + 128];
    let mut environment_pointers = [ptr::null_mut(); command::MAX_ENVIRONMENT + 1];
    let mut environment_offset = 0;
    for (index, value) in environment_entries[..environment_count].iter().enumerate() {
        let Some(pointer) = copy_c_string(value, &mut environment_storage, &mut environment_offset)
        else {
            return exit::FAILURE;
        };
        environment_pointers[index] = pointer;
    }

    let mut cwd = [0_u8; command::MAX_CWD_BYTES + 1];
    let mut cwd_offset = 0;
    let Some(cwd_pointer) = copy_c_string(invocation.cwd(), &mut cwd, &mut cwd_offset) else {
        return exit::FAILURE;
    };

    let Ok(mut runtime) = Runtime::new(command_context) else {
        return exit::FAILURE;
    };
    let mut checkpoint = Checkpoint {
        runtime: ptr::from_ref(&runtime),
        startup: MetricSnapshot::default(),
    };
    let host = runtime.host();
    let configuration = Configuration {
        host: &host,
        argc: i32::try_from(invocation.len()).unwrap_or(i32::MAX),
        argv: argument_pointers.as_mut_ptr(),
        environment: environment_pointers.as_mut_ptr(),
        cwd: cwd_pointer,
    };

    // SAFETY: All configuration storage and the host callback state remain
    // live and immovable until CPython and the C compatibility runtime finish.
    let result = unsafe {
        if troe_runtime_initialize(&configuration) != 0 {
            return exit::FAILURE;
        }
        let result = troe_cpython_run(
            configuration.argc,
            configuration.argv,
            ptr::from_mut(&mut checkpoint).cast(),
            capture_startup,
        );
        troe_runtime_finalize();
        result
    };
    let statistics = runtime.allocator_statistics();
    if emit_metrics {
        let mut stderr = command_context.stderr();
        let _ignored = writeln!(
            OutputWriter(&mut stderr),
            "TROE_CPYTHON_METRICS version={} architecture={} startup_live_bytes={} startup_peak_bytes={} startup_capacity_bytes={} startup_private_mapped_bytes={} startup_private_mappings={} launch_peak_bytes={} final_live_bytes={} final_capacity_bytes={} final_private_mapped_bytes={} final_private_mappings={} allocations={} reallocations={} deallocations={} growths={} failures={}",
            env!("TROE_CPYTHON_VERSION"),
            env!("TROE_CPYTHON_ARCHITECTURE"),
            checkpoint.startup.live_bytes,
            checkpoint.startup.high_water_bytes,
            checkpoint.startup.capacity_bytes,
            checkpoint.startup.private_mapped_bytes,
            checkpoint.startup.private_mappings,
            statistics.high_water_bytes,
            statistics.live_bytes,
            statistics.capacity_bytes,
            statistics.private_mapped_bytes,
            statistics.private_mappings,
            statistics.allocations,
            statistics.reallocations,
            statistics.deallocations,
            statistics.growths,
            statistics.failures,
        );
    }
    if statistics.live_bytes != 0 || statistics.private_mappings != 0 {
        exit::FAILURE
    } else if result >= 0 {
        u32::try_from(result).unwrap_or(exit::FAILURE)
    } else {
        exit::FAILURE
    }
}

macro_rules! unary_math {
    ($name:ident) => {
        #[unsafe(no_mangle)]
        extern "C" fn $name(value: f64) -> f64 {
            libm::$name(value)
        }
    };
}

unary_math!(acosh);
unary_math!(asinh);
unary_math!(atanh);
unary_math!(cbrt);
unary_math!(cosh);
unary_math!(erf);
unary_math!(erfc);
unary_math!(exp2);
unary_math!(expm1);
unary_math!(log1p);
unary_math!(log2);
unary_math!(round);
unary_math!(sinh);
unary_math!(tanh);
unary_math!(trunc);

#[unsafe(no_mangle)]
extern "C" fn copysign(magnitude: f64, sign: f64) -> f64 {
    libm::copysign(magnitude, sign)
}

#[unsafe(no_mangle)]
extern "C" fn fma(left: f64, right: f64, addend: f64) -> f64 {
    libm::fma(left, right, addend)
}

#[unsafe(no_mangle)]
extern "C" fn hypot(left: f64, right: f64) -> f64 {
    libm::hypot(left, right)
}

#[unsafe(no_mangle)]
extern "C" fn nextafter(value: f64, direction: f64) -> f64 {
    libm::nextafter(value, direction)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn modf(value: f64, integer_part: *mut f64) -> f64 {
    let (fraction, integer) = libm::modf(value);
    if let Some(destination) = unsafe { integer_part.as_mut() } {
        *destination = integer;
    }
    fraction
}

entry!(main);

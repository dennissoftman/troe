#![no_std]
#![no_main]
// Bridges the generated CPython C runtime, so every call across that boundary
// is an FFI call. The interpreter's own entry points are declared here.
#![allow(unsafe_code)]

use core::{
    ffi::{c_char, c_void},
    fmt,
    fmt::Write as _,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};
use troe_kex_c_runtime::{Configuration, ProcessStorage, Runtime};
use troe_kex_runtime::environment;
use troe_kex_sdk::{
    CommandContext, ENVIRONMENT_BUFFER_BYTES, INVOCATION_BUFFER_BYTES, StandardOutput, entry, exit,
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

static STARTUP_METRICS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

struct OutputWriter<'output>(&'output mut StandardOutput);

impl fmt::Write for OutputWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.write_all(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

unsafe extern "C" fn capture_startup(context: *mut c_void) {
    // SAFETY: The launcher receives the process-owned Runtime pointer. It calls
    // this checkpoint synchronously and retains neither pointer nor callback.
    let Some(runtime) = (unsafe { context.cast::<Runtime>().as_ref() }) else {
        return;
    };
    let statistics = runtime.allocator_statistics();
    for (destination, value) in STARTUP_METRICS.iter().zip([
        statistics.live_bytes,
        statistics.high_water_bytes,
        statistics.capacity_bytes,
        statistics.private_mapped_bytes,
        statistics.private_mappings,
    ]) {
        destination.store(value, Ordering::Relaxed);
    }
}

static PROCESS: ProcessStorage = ProcessStorage::new();

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

    let Ok(process) = PROCESS.initialize(command_context, invocation, environment) else {
        return exit::FAILURE;
    };
    let runtime = process.runtime();
    // SAFETY: ProcessStorage publishes this immutable record only after complete
    // initialization; every C-retained pointer names process-owned storage.
    let configuration = unsafe { &*process.configuration() };

    // SAFETY: All configuration storage and the host callback state remain
    // live and immovable until CPython and the C compatibility runtime finish.
    let result = unsafe {
        if troe_runtime_initialize(configuration) != 0 {
            return exit::FAILURE;
        }
        let result = troe_cpython_run(
            configuration.argc,
            configuration.argv,
            ptr::from_ref(runtime).cast_mut().cast(),
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
            STARTUP_METRICS[0].load(Ordering::Relaxed),
            STARTUP_METRICS[1].load(Ordering::Relaxed),
            STARTUP_METRICS[2].load(Ordering::Relaxed),
            STARTUP_METRICS[3].load(Ordering::Relaxed),
            STARTUP_METRICS[4].load(Ordering::Relaxed),
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

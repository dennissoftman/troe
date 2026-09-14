#![no_std]
#![no_main]

use core::ffi::c_char;
use troe_kex_c_runtime::{Configuration, Host, InitializationError, ProcessStorage};
use troe_kex_sdk::{
    CommandContext, ENVIRONMENT_BUFFER_BYTES, INVOCATION_BUFFER_BYTES, entry, exit,
};

unsafe extern "C" {
    fn troe_runtime_initialize(configuration: *const Configuration) -> i32;
    fn troe_runtime_finalize();
    fn troe_c_missing_capability_probe() -> i32;
    fn troe_c_runtime_probe(argc: i32, argv: *mut *mut c_char, host: *const Host) -> i32;
}

static PROCESS: ProcessStorage = ProcessStorage::new();

fn main(command_context: &mut CommandContext) -> u32 {
    // SAFETY: The probe constructs and tears down its own callback-free host
    // table before the real command runtime is initialized.
    if unsafe { troe_c_missing_capability_probe() } != 0 {
        return exit::FAILURE;
    }
    let mut invocation_buffer = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command_context.invocation(&mut invocation_buffer) else {
        return exit::FAILURE;
    };
    let mut environment_buffer = [0_u8; ENVIRONMENT_BUFFER_BYTES];
    let Ok(environment) = command_context.environment(&mut environment_buffer) else {
        return exit::FAILURE;
    };
    let Ok(process) = PROCESS.initialize(command_context, invocation, environment) else {
        return exit::FAILURE;
    };
    if !matches!(
        PROCESS.initialize(command_context, invocation, environment),
        Err(InitializationError::AlreadyInitialized)
    ) {
        return exit::FAILURE;
    }
    // Retained C configuration must no longer depend on these source records.
    invocation_buffer.fill(0xa5);
    environment_buffer.fill(0xa5);
    let runtime = process.runtime();
    // SAFETY: ProcessStorage publishes this immutable record only after complete
    // initialization; every C-retained pointer names process-owned storage.
    let configuration = unsafe { &*process.configuration() };

    // SAFETY: Every configuration pointer refers to live fixed storage for the
    // complete C call, and the runtime state does not move while callbacks run.
    let result = unsafe {
        if troe_runtime_initialize(configuration) != 0 {
            return exit::FAILURE;
        }
        let result =
            troe_c_runtime_probe(configuration.argc, configuration.argv, configuration.host);
        troe_runtime_finalize();
        result
    };
    let statistics = runtime.allocator_statistics();
    if result == 0 && statistics.live_bytes == 0 && statistics.private_mappings == 0 {
        exit::SUCCESS
    } else {
        exit::FAILURE
    }
}

entry!(main);

#![no_std]
#![no_main]

use core::{ffi::c_char, ptr};
use troe_kex_c_runtime::{Configuration, Runtime};
use troe_kex_runtime::environment;
use troe_kex_sdk::{
    CommandContext, ENVIRONMENT_BUFFER_BYTES, INVOCATION_BUFFER_BYTES, command, entry, exit,
};

unsafe extern "C" {
    fn troe_runtime_initialize(configuration: *const Configuration) -> i32;
    fn troe_runtime_finalize();
    fn troe_c_missing_capability_probe() -> i32;
    fn troe_c_runtime_probe(argc: i32, argv: *mut *mut c_char) -> i32;
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
    let host = runtime.host();
    let configuration = Configuration {
        host: &host,
        argc: i32::try_from(invocation.len()).unwrap_or(i32::MAX),
        argv: argument_pointers.as_mut_ptr(),
        environment: environment_pointers.as_mut_ptr(),
        cwd: cwd_pointer,
    };
    // SAFETY: Every configuration pointer refers to live fixed storage for the
    // complete C call, and the runtime state does not move while callbacks run.
    let result = unsafe {
        if troe_runtime_initialize(&configuration) != 0 {
            return exit::FAILURE;
        }
        let result = troe_c_runtime_probe(configuration.argc, configuration.argv);
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

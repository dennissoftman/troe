#![no_std]
#![no_main]

use troe_kex_sdk::{
    SERVER_REQUEST_BUFFER_BYTES, ServerContext, exit, server_entry,
};

fn main(server: &mut ServerContext) -> u32 {
    let mut request_bytes = [0_u8; SERVER_REQUEST_BUFFER_BYTES];
    if server.receive(&mut request_bytes).is_err() {
        return exit::FAILURE;
    }
    fault_after_receive()
}

#[cfg(target_arch = "x86_64")]
fn fault_after_receive() -> ! {
    // SAFETY: This artifact exists only in acceptance images and deliberately
    // proves that an illegal server instruction is contained and reclaimed.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

#[cfg(target_arch = "aarch64")]
fn fault_after_receive() -> ! {
    // SAFETY: This artifact exists only in acceptance images and deliberately
    // proves that an illegal server instruction is contained and reclaimed.
    unsafe { core::arch::asm!("brk #0", options(noreturn)) }
}

server_entry!(main);

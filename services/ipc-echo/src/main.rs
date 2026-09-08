#![no_std]
#![no_main]
// Acceptance-only adversarial accesses prove supervisor isolation and NX.
#![allow(unsafe_code)]

use troe_kex_sdk::{EventKind, PersistentContext, exit, interface, persistent_entry, reply};

fn main(context: &mut PersistentContext) -> u32 {
    let mut token = 0;
    let mut bytes = 0;
    let mut deadline = u64::MAX;
    let mut last_opcode = 0;
    loop {
        let Ok(event) = context.reply_wait(token, reply::SUCCESS, bytes, deadline) else {
            return exit::FAILURE;
        };
        token = 0;
        bytes = 0;
        deadline = u64::MAX;
        if event.kind == EventKind::Deadline {
            if last_opcode == 17 {
                return exit::SUCCESS;
            }
            continue;
        }
        if event.kind != EventKind::Call
            || event.interface != interface::DIAGNOSTICS
            || !matches!(event.opcode, 1..=17)
            || event.request_bytes > event.reply_capacity
        {
            return exit::FAILURE;
        }
        last_opcode = event.opcode;
        match event.opcode {
            3 => loop {
                core::hint::spin_loop();
            },
            4 => return exit::SUCCESS,
            7 => {
                let Ok(bytes) = <[u8; 8]>::try_from(context.rx()) else {
                    return exit::FAILURE;
                };
                let address = u64::from_le_bytes(bytes);
                // SAFETY: Deliberately forbidden supervisor access in the
                // destructive acceptance fixture; the kernel must contain it.
                unsafe {
                    core::ptr::read_volatile(address as *const u8);
                }
                return exit::FAILURE;
            }
            8 => {
                let address = context.tx().as_ptr();
                // SAFETY: Deliberate NX violation in the destructive fixture.
                let execute: extern "C" fn() = unsafe { core::mem::transmute(address) };
                execute();
                return exit::FAILURE;
            }
            _ => {}
        }
        let (tx, rx) = context.buffers();
        tx[..rx.len()].copy_from_slice(rx);
        token = event.token;
        bytes = usize::from(event.request_bytes);
        match event.opcode {
            5 => token ^= 1 << 32,
            6 => bytes = usize::from(event.reply_capacity) + 1,
            13 => {
                token = 0;
                bytes = 0;
            }
            _ => {}
        }
        // A completed wait deadline makes the server runnable, so the next
        // client request must queue before this task publishes another wait.
        if matches!(event.opcode, 2 | 17) {
            deadline = 0;
        }
    }
}

persistent_entry!(main);

#![no_std]
#![no_main]

use troe_kex_sdk::{
    EventKind, PersistentContext, exit, interface, persistent_entry, reply, yield_now,
};

fn main(context: &mut PersistentContext) -> u32 {
    let mut initialized = false;
    let mut stopping = false;
    let mut token = 0;
    let mut status = 0;
    let mut bytes = 0;
    loop {
        let Ok(event) =
            context.reply_wait(token, status, bytes, if stopping { 0 } else { u64::MAX })
        else {
            return exit::FAILURE;
        };
        if stopping {
            return if event.kind == EventKind::Deadline {
                exit::SUCCESS
            } else {
                exit::FAILURE
            };
        }
        token = 0;
        status = 0;
        bytes = 0;
        if event.kind == EventKind::ClientClosed {
            continue;
        }
        if event.kind != EventKind::Call {
            return exit::FAILURE;
        }
        token = event.token;
        if event.interface == interface::SERVICE_LIFECYCLE {
            if !initialized
                && event.opcode == 1
                && event.request_bytes == 0
                && event.reply_capacity == 0
            {
                initialized = true;
            } else if initialized
                && event.opcode == 2
                && event.request_bytes == 0
                && event.reply_capacity == 0
            {
                stopping = true;
            } else {
                status = reply::INVALID_REQUEST;
            }
            continue;
        }
        if !initialized
            || event.interface != interface::DIAGNOSTICS
            || event.request_bytes > event.reply_capacity
        {
            status = reply::INVALID_REQUEST;
            continue;
        }
        if event.opcode == 2 && yield_now().is_err() {
            return exit::FAILURE;
        }
        let (tx, rx) = context.buffers();
        tx[..rx.len()].copy_from_slice(rx);
        bytes = usize::from(event.request_bytes);
        if event.opcode == 3
            && let Ok(handle) = context.call_handle(interface::DIAGNOSTICS, 1, 0)
        {
            let Some(deadline) = context
                .rx()
                .get(..8)
                .and_then(|v| <[u8; 8]>::try_from(v).ok())
                .map(u64::from_le_bytes)
            else {
                return exit::FAILURE;
            };
            if context.call(handle, 3, bytes, bytes, deadline).is_err() {
                status = reply::CONFLICT;
                bytes = 0;
            } else {
                let (tx, rx) = context.buffers();
                tx[..rx.len()].copy_from_slice(rx);
            }
        }
        if event.opcode == 4 {
            loop {
                core::hint::spin_loop();
            }
        }
    }
}
persistent_entry!(main);

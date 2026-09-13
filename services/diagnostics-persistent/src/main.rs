#![no_std]
#![no_main]

use troe_kex_sdk::{
    EventKind, PersistentContext, diagnostics, exit, interface, persistent_entry, reply,
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
        let valid = initialized
            && event.interface == interface::DIAGNOSTICS
            && event.opcode == diagnostics::GET_SNAPSHOT
            && usize::from(event.reply_capacity) >= diagnostics::SNAPSHOT_BYTES
            && diagnostics::decode_snapshot(context.rx()).is_ok();
        if valid {
            let (tx, rx) = context.buffers();
            tx[..rx.len()].copy_from_slice(rx);
            bytes = usize::from(event.request_bytes);
        } else {
            status = reply::INVALID_REQUEST;
        }
    }
}
persistent_entry!(main);

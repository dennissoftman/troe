#![no_std]
#![no_main]

use troe_kex_sdk::{
    SERVER_REQUEST_BUFFER_BYTES, ServerContext, diagnostics, exit, interface, reply, server_entry,
};

fn main(server: &mut ServerContext) -> u32 {
    let mut request_bytes = [0_u8; SERVER_REQUEST_BUFFER_BYTES];
    let Ok(request) = server.receive(&mut request_bytes) else {
        return exit::FAILURE;
    };
    let valid = request.interface() == interface::DIAGNOSTICS
        && request.opcode() == diagnostics::GET_SNAPSHOT
        && request.reply_capacity() >= diagnostics::SNAPSHOT_BYTES
        && diagnostics::decode_snapshot(request.payload()).is_ok();
    let result = if valid {
        server.reply(request.token(), reply::SUCCESS, request.payload())
    } else {
        server.reply(request.token(), reply::INVALID_REQUEST, &[])
    };
    if result.is_ok() {
        exit::SUCCESS
    } else {
        exit::FAILURE
    }
}

server_entry!(main);

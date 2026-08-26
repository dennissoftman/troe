#![no_std]
#![no_main]

use troe_kex_sdk::{
    Error, SERVER_REQUEST_BUFFER_BYTES, ServerContext, exit, interface, reply, server_entry,
};

fn main(server_context: &mut ServerContext) -> u32 {
    let mut request_bytes = [0_u8; SERVER_REQUEST_BUFFER_BYTES];
    loop {
        let request = match server_context.receive(&mut request_bytes) {
            Ok(request) => request,
            Err(Error::Conflict) => return exit::SUCCESS,
            Err(_) => return exit::FAILURE,
        };
        if request.interface() != interface::DIAGNOSTICS
            || !matches!(request.opcode(), 1 | 2)
            || request.reply_capacity() < request.payload().len()
        {
            return exit::FAILURE;
        }
        if server_context
            .reply(request.token(), reply::SUCCESS, request.payload())
            .is_err()
        {
            return exit::FAILURE;
        }
    }
}

server_entry!(main);

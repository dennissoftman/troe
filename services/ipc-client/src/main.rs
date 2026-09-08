#![no_std]
#![no_main]
// The synthetic acceptance client reads its kernel-seeded private heap only.
#![allow(unsafe_code)]

use troe_kex_sdk::{CommandContext, Error, entry, exit, yield_now};

fn main(context: &mut CommandContext) -> u32 {
    let Some(heap) = context.take_heap() else {
        return exit::FAILURE;
    };
    if heap.byte_len() < 32 {
        return exit::FAILURE;
    }
    // SAFETY: The unique startup heap owner proves these bytes are mapped and
    // writable. The acceptance launcher seeds three scalars before entry.
    let config = unsafe { core::slice::from_raw_parts(heap.start_address() as *const u64, 4) };
    let Ok(bytes) = usize::try_from(config[0]) else {
        return exit::FAILURE;
    };
    let Ok(opcode) = u16::try_from(config[1]) else {
        return exit::FAILURE;
    };
    let deadline = match opcode {
        10 => 0,
        11 => u64::MAX - 1,
        _ => config[2],
    };
    let argument = config[3];
    if bytes > 4096 {
        return exit::FAILURE;
    }
    let Ok(handle) = context.ipc_diagnostics() else {
        return exit::FAILURE;
    };
    let Some(mut pages) = context.take_ipc() else {
        return exit::FAILURE;
    };
    pages.tx()[..bytes].fill(0x5a);
    if opcode == 7 {
        pages.tx()[..8].copy_from_slice(&argument.to_le_bytes());
    }
    if yield_now().is_err() {
        return exit::FAILURE;
    }
    let mut batch = if opcode == 16 { u64::MAX } else { 64 };
    loop {
        for _ in 0..batch {
            let result = pages.call(
                handle,
                opcode,
                bytes,
                bytes,
                deadline,
                u64::from(opcode == 9),
            );
            if opcode >= 3
                && let Err(error) = result
            {
                let expected = match opcode {
                    4 | 17 => Error::Closed,
                    10 => Error::Timeout,
                    _ => Error::PeerDied,
                };
                return if error == expected && pages.rx().is_empty() {
                    exit::SUCCESS
                } else {
                    exit::FAILURE
                };
            }
            if result.is_err()
                || pages.rx().len() != bytes
                || pages.rx().iter().any(|byte| *byte != 0x5a)
            {
                return exit::FAILURE;
            }
        }
        if yield_now().is_err() {
            return exit::FAILURE;
        }
        batch = 256;
    }
}

entry!(main);

#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_sdk::{CommandContext, Error, INVOCATION_BUFFER_BYTES, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let Some(interval) = invocation.argument(1) else {
        return common::usage(&mut command.stderr(), "sleep", b"sleep MILLISECONDS");
    };
    if invocation.len() != 2 {
        return common::usage(&mut command.stderr(), "sleep", b"sleep MILLISECONDS");
    }
    let Ok(milliseconds) = interval.parse::<u64>() else {
        return common::usage(
            &mut command.stderr(),
            "sleep",
            b"invalid millisecond interval",
        );
    };
    let Ok(mut timer) = command.timer() else {
        return exit::DENIED;
    };
    let Ok(now) = timer.now() else {
        common::report(&mut command.stderr(), "sleep", b"runtime unavailable");
        return exit::FAILURE;
    };
    match timer.sleep_until(now.saturating_add(milliseconds)) {
        Ok(()) => exit::SUCCESS,
        Err(Error::Cancelled) => {
            common::report(&mut command.stderr(), "sleep", b"cancelled");
            exit::CANCELLED
        }
        Err(Error::Timeout) => {
            common::report(&mut command.stderr(), "sleep", b"operation timed out");
            exit::FAILURE
        }
        Err(_) => {
            common::report(&mut command.stderr(), "sleep", b"runtime unavailable");
            exit::FAILURE
        }
    }
}

entry!(main);

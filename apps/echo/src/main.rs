#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_app_printf::{EscapeOutcome, PrintError, render_escapes};
use troe_kex_sdk::{CommandContext, INVOCATION_BUFFER_BYTES, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let mut newline = true;
    let mut escapes = false;
    let mut first_argument = 1_usize;
    while first_argument < invocation.len() {
        let Some(argument) = invocation.argument(first_argument) else {
            return exit::FAILURE;
        };
        if argument == "--" {
            first_argument += 1;
            break;
        }
        if !argument.starts_with('-') || argument.len() == 1 {
            break;
        }
        if !argument
            .as_bytes()
            .iter()
            .skip(1)
            .all(|option| matches!(option, b'n' | b'e' | b'E'))
        {
            break;
        }
        for option in argument.as_bytes().iter().skip(1) {
            match option {
                b'n' => newline = false,
                b'e' => escapes = true,
                b'E' => escapes = false,
                _ => return exit::FAILURE,
            }
        }
        first_argument += 1;
    }

    let mut output = command.stdout();
    for index in first_argument..invocation.len() {
        if index != first_argument && output.write_all(b" ").is_err() {
            return common::stream_failure(&mut command.stderr(), "echo");
        }
        let Some(argument) = invocation.argument(index) else {
            return exit::FAILURE;
        };
        if escapes {
            match render_escapes(argument, |bytes| output.write_all(bytes)) {
                Ok(EscapeOutcome::Complete) => {}
                Ok(EscapeOutcome::Stop) => return exit::SUCCESS,
                Err(PrintError::Output(_)) => {
                    return common::stream_failure(&mut command.stderr(), "echo");
                }
                Err(PrintError::InvalidFormat | PrintError::InvalidNumber) => {
                    return exit::FAILURE;
                }
            }
        } else if output.write_all(argument.as_bytes()).is_err() {
            return common::stream_failure(&mut command.stderr(), "echo");
        }
    }
    if newline && output.write_all(b"\n").is_err() {
        return common::stream_failure(&mut command.stderr(), "echo");
    }
    exit::SUCCESS
}

entry!(main);

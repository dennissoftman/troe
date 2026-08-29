#![no_std]
#![no_main]

use troe_kex_sdk::{
    CommandContext, ENVIRONMENT_BUFFER_BYTES, INVOCATION_BUFFER_BYTES, command, entry, exit, pipe,
    process_launch,
};

/// Iterate the `--env` values among the leading options before `end`.
///
/// A value always contains `=`, so it can never be the literal `--env` and a
/// simple scan cannot mistake one for an option.
fn overrides<'a>(
    invocation: &'a command::Invocation<'a>,
    end: usize,
) -> impl Iterator<Item = &'a str> {
    (1..end).filter_map(move |index| {
        (invocation.argument(index) == Some("--env"))
            .then(|| invocation.argument(index + 1))
            .flatten()
    })
}

/// Split one canonical `NAME=VALUE` entry into its nonempty name and value.
fn split_entry(entry: &str) -> Option<(&str, &str)> {
    let (name, value) = entry.split_once('=')?;
    (!name.is_empty()).then_some((name, value))
}

fn failure(command: &mut CommandContext, message: &[u8], status: u32) -> u32 {
    let mut stderr = command.stderr();
    let _ignored = stderr.write_all(b"spawn: ");
    let _ignored = stderr.write_all(message);
    let _ignored = stderr.write_all(b"\n");
    status
}

fn report_status(command: &mut CommandContext, status: u32) -> Result<(), ()> {
    let mut digits = [0_u8; 10];
    let mut value = status;
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + u8::try_from(value % 10).map_err(|_| ())?;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut stderr = command.stderr();
    stderr.write_all(b"spawn-status: ").map_err(|_| ())?;
    stderr.write_all(&digits[start..]).map_err(|_| ())?;
    stderr.write_all(b"\n").map_err(|_| ())
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return failure(command, b"invalid invocation", exit::FAILURE);
    };
    // Options may appear in any order before the child invocation. Overrides
    // are read back out of the invocation rather than copied into a second
    // table, so parsing them costs no additional stack.
    let mut capture = false;
    let mut report = false;
    let mut first_child_argument = 1;
    loop {
        match invocation.argument(first_child_argument) {
            Some("--capture") => {
                capture = true;
                first_child_argument += 1;
            }
            Some("--status") => {
                report = true;
                first_child_argument += 1;
            }
            Some("--env") => {
                let Some(entry) = invocation.argument(first_child_argument + 1) else {
                    return failure(command, b"--env requires NAME=VALUE", exit::USAGE);
                };
                let Some((name, _)) = split_entry(entry) else {
                    return failure(command, b"--env requires NAME=VALUE", exit::USAGE);
                };
                if overrides(&invocation, first_child_argument)
                    .any(|earlier| split_entry(earlier).is_some_and(|(other, _)| other == name))
                {
                    return failure(command, b"--env repeats one name", exit::USAGE);
                }
                first_child_argument += 2;
            }
            _ => break,
        }
    }
    let option_end = first_child_argument;
    if invocation.len() <= first_child_argument {
        return failure(
            command,
            b"usage: spawn [--capture|--status] [--env NAME=VALUE]... COMMAND [ARG...]",
            exit::USAGE,
        );
    }

    let mut arguments = [""; command::MAX_ARGUMENTS];
    let argument_count = invocation.len() - first_child_argument;
    for (destination, index) in arguments[..argument_count]
        .iter_mut()
        .zip(first_child_argument..invocation.len())
    {
        let Some(argument) = invocation.argument(index) else {
            return failure(command, b"invalid arguments", exit::FAILURE);
        };
        *destination = argument;
    }

    let mut environment_bytes = [0_u8; ENVIRONMENT_BUFFER_BYTES];
    let Ok(environment) = command.environment(&mut environment_bytes) else {
        return failure(command, b"invalid environment", exit::FAILURE);
    };
    // Narrow the inherited environment before launch: an override replaces the
    // inherited entry of the same name so the child receives one canonical
    // value per name, which the encoding boundary requires.
    let mut environment_values = [""; command::MAX_ENVIRONMENT];
    let mut environment_count = 0_usize;
    for value in environment.iter() {
        let Some((name, _)) = split_entry(value) else {
            return failure(command, b"invalid environment", exit::FAILURE);
        };
        let replacement = overrides(&invocation, option_end)
            .find(|entry| split_entry(entry).is_some_and(|(other, _)| other == name));
        if environment_count == environment_values.len() {
            return failure(command, b"child environment is full", exit::FAILURE);
        }
        environment_values[environment_count] = replacement.unwrap_or(value);
        environment_count += 1;
    }
    for entry in overrides(&invocation, option_end) {
        let Some((name, _)) = split_entry(entry) else {
            return failure(command, b"--env requires NAME=VALUE", exit::USAGE);
        };
        let inherited = environment_values[..environment_count]
            .iter()
            .any(|existing| split_entry(existing).is_some_and(|(other, _)| other == name));
        if inherited {
            continue;
        }
        if environment_count == environment_values.len() {
            return failure(command, b"child environment is full", exit::FAILURE);
        }
        environment_values[environment_count] = entry;
        environment_count += 1;
    }

    let mut pipes = if capture {
        match command.pipes() {
            Ok(pipes) => Some(pipes),
            Err(_) => return failure(command, b"pipe authority unavailable", exit::DENIED),
        }
    } else {
        None
    };
    let capture_pipe = if let Some(pipes) = pipes.as_mut() {
        match pipes.create(pipe::MIN_CAPACITY) {
            Ok(token) => Some(token),
            Err(_) => return failure(command, b"pipe creation failed", exit::FAILURE),
        }
    } else {
        None
    };
    let child_stdout = match capture_pipe {
        Some(token) => match process_launch::StreamSpec::pipe(token.value()) {
            Ok(spec) => spec,
            Err(_) => return failure(command, b"invalid pipe token", exit::FAILURE),
        },
        None => process_launch::StreamSpec::INHERIT,
    };

    let mut launcher = match command.process_launcher() {
        Ok(launcher) => launcher,
        Err(_) => return failure(command, b"launch authority unavailable", exit::DENIED),
    };
    let child = match launcher.spawn(
        invocation.cwd(),
        &arguments[..argument_count],
        &environment_values[..environment_count],
        process_launch::StreamSpec::INHERIT,
        child_stdout,
        process_launch::StreamSpec::INHERIT,
    ) {
        Ok(child) => child,
        Err(_) => {
            if let (Some(pipes), Some(token)) = (pipes.as_mut(), capture_pipe) {
                let _ignored = pipes.close_writer(token);
                let _ignored = pipes.close_reader(token);
            }
            return failure(command, b"child launch failed", exit::FAILURE);
        }
    };

    if let (Some(pipes), Some(token)) = (pipes.as_mut(), capture_pipe) {
        if pipes.close_writer(token).is_err() {
            let _ignored = launcher.cancel(child.token);
            return failure(command, b"pipe close failed", exit::FAILURE);
        }
        let mut bytes = [0_u8; pipe::MAX_IO_BYTES];
        let mut stdout = command.stdout();
        loop {
            let count = match pipes.read(token, &mut bytes) {
                Ok(count) => count,
                Err(_) => {
                    let _ignored = launcher.cancel(child.token);
                    return exit::FAILURE;
                }
            };
            if count == 0 {
                break;
            }
            if stdout.write_all(&bytes[..count]).is_err() {
                let _ignored = launcher.cancel(child.token);
                return exit::FAILURE;
            }
        }
        if pipes.close_reader(token).is_err() {
            return exit::FAILURE;
        }
    }

    let status = match launcher.wait(child.token) {
        Ok(status) => status,
        Err(_) => return failure(command, b"child wait failed", exit::FAILURE),
    };
    if launcher.reap(child.token).is_err() {
        return failure(command, b"child reap failed", exit::FAILURE);
    }
    if report && report_status(command, status.exit_status).is_err() {
        return exit::FAILURE;
    }
    status.exit_status
}

entry!(main);

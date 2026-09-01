#![no_std]
#![no_main]

#[path = "../../common.rs"]
mod common;

use troe_kex_runtime::{
    time::{self, FORMAT_BUFFER_BYTES, FormatError},
    timezone::TimeZone,
};
use troe_kex_sdk::{
    CommandContext, ENVIRONMENT_BUFFER_BYTES, Error, INVOCATION_BUFFER_BYTES, StandardOutput,
    entry, exit,
};

/// Synopsis reported for any misuse.
const SYNOPSIS: &[u8] = b"date [-u] [+FORMAT]";

/// Rendering used when the invocation supplies no format.
///
/// ISO 8601 with an explicit offset, so one line is unambiguous without
/// knowing which zone the reader's machine runs in. `+FORMAT` reaches the
/// same conversions for anything else, including `%Z` for the abbreviation.
const DEFAULT_FORMAT: &[u8] = b"%Y-%m-%dT%H:%M:%S%z";

/// Read the zone the launcher composed.
///
/// A launcher refuses a `TZ` it cannot parse, so a value that reaches here has
/// already been validated. An absent one is UTC, which is also the conventional
/// default every launch carries.
fn launch_timezone(command: &CommandContext) -> TimeZone {
    let mut environment_bytes = [0_u8; ENVIRONMENT_BUFFER_BYTES];
    let Ok(environment) = command.environment(&mut environment_bytes) else {
        return TimeZone::utc();
    };
    environment
        .iter()
        .find_map(|entry| entry.strip_prefix("TZ="))
        .map_or_else(TimeZone::utc, |text| {
            TimeZone::parse_or_utc(text.as_bytes())
        })
}

fn write_formatted(
    stdout: &mut StandardOutput,
    calendar: time::CalendarTime,
    format: &[u8],
) -> Result<(), FormatError> {
    let mut rendered = [0_u8; FORMAT_BUFFER_BYTES];
    let count = time::format_calendar(calendar, format, &mut rendered)?;
    let Some(text) = rendered.get(..count) else {
        return Err(FormatError::BufferTooSmall);
    };
    stdout
        .write_all(text)
        .map_err(|_| FormatError::BufferTooSmall)?;
    stdout
        .write_all(b"\n")
        .map_err(|_| FormatError::BufferTooSmall)
}

fn main(command: &mut CommandContext) -> u32 {
    let mut invocation_bytes = [0_u8; INVOCATION_BUFFER_BYTES];
    let Ok(invocation) = command.invocation(&mut invocation_bytes) else {
        return exit::FAILURE;
    };
    let mut utc = false;
    let mut format: Option<&str> = None;
    for index in 1..invocation.len() {
        let Some(argument) = invocation.argument(index) else {
            return exit::FAILURE;
        };
        match argument {
            "-u" if !utc => utc = true,
            _ if argument.starts_with('+') && format.is_none() => {
                format = Some(&argument[1..]);
            }
            _ => return common::usage(&mut command.stderr(), "date", SYNOPSIS),
        }
    }

    let zone = if utc {
        TimeZone::utc()
    } else {
        launch_timezone(command)
    };
    let Ok(mut clock) = command.wall_clock() else {
        return exit::DENIED;
    };
    let seconds = match clock.now() {
        Ok(seconds) => seconds,
        // An unset clock is not the epoch. Printing 1970 would report a real
        // instant the machine has no basis for; ADR 0039 leaves the clock
        // unconfigured until a correction arrives.
        Err(Error::NotConfigured) => {
            common::report(
                &mut command.stderr(),
                "date",
                b"wall clock is not configured",
            );
            return exit::FAILURE;
        }
        Err(_) => {
            common::report(&mut command.stderr(), "date", b"wall clock is unavailable");
            return exit::FAILURE;
        }
    };
    let Ok(seconds) = i64::try_from(seconds) else {
        common::report(&mut command.stderr(), "date", b"wall clock is out of range");
        return exit::FAILURE;
    };

    let calendar = time::local_from_unix_seconds(&zone, seconds);
    let pattern = format.map_or(DEFAULT_FORMAT, str::as_bytes);
    let mut stdout = command.stdout();
    match write_formatted(&mut stdout, calendar, pattern) {
        Ok(()) => exit::SUCCESS,
        Err(FormatError::InvalidSpecifier(_)) => common::usage(
            &mut command.stderr(),
            "date",
            b"unsupported conversion in FORMAT",
        ),
        Err(FormatError::BufferTooSmall) => {
            common::report(&mut command.stderr(), "date", b"formatted date is too long");
            exit::FAILURE
        }
        Err(FormatError::InvalidCalendar) => {
            common::report(&mut command.stderr(), "date", b"wall clock is out of range");
            exit::FAILURE
        }
    }
}

entry!(main);

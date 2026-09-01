//! Unix-time and normalized civil-calendar conversion.
//!
//! Every conversion is available in UTC and in one zone described by a parsed
//! POSIX `TZ` string. A calendar carries the offset and abbreviation of the
//! instant it names, so formatting stays a function of its argument rather
//! than of any retained state.
#![allow(unsafe_code)]

use crate::timezone::{Abbreviation, MAX_ABBREVIATION_BYTES, TimeZone, ZoneOffset};

/// Broken-down calendar value in one zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CalendarTime {
    /// Full Gregorian year.
    pub year: i64,
    /// Month in the range 1 through 12.
    pub month: i32,
    /// Day of month beginning at 1.
    pub day: i32,
    /// Hour in the range 0 through 23.
    pub hour: i32,
    /// Minute in the range 0 through 59.
    pub minute: i32,
    /// Second in the range 0 through 59.
    pub second: i32,
    /// Weekday where Sunday is zero.
    pub week_day: i32,
    /// Day of year where January 1 is zero.
    pub year_day: i32,
    /// Seconds east of UTC for the zone this calendar was read in.
    pub gmt_offset: i32,
    /// One while the zone is in its daylight state, zero otherwise.
    pub daylight: i32,
    /// Zone abbreviation bytes; only `zone_length` of them are significant.
    pub zone: [u8; MAX_ABBREVIATION_BYTES],
    /// Significant bytes in `zone`.
    pub zone_length: u8,
}

impl CalendarTime {
    /// The zone abbreviation naming this calendar's offset.
    #[must_use]
    pub fn zone_bytes(&self) -> &[u8] {
        let length = usize::from(self.zone_length);
        self.zone.get(..length).unwrap_or(&[])
    }

    fn with_zone(mut self, state: ZoneOffset) -> Self {
        self.gmt_offset = state.seconds_east;
        self.daylight = i32::from(state.is_daylight);
        self = self.with_abbreviation(state.abbreviation);
        self
    }

    fn with_abbreviation(mut self, abbreviation: Abbreviation) -> Self {
        let bytes = abbreviation.as_bytes();
        if let Some(destination) = self.zone.get_mut(..bytes.len()) {
            destination.copy_from_slice(bytes);
            self.zone_length = u8::try_from(bytes.len()).unwrap_or(0);
        }
        self
    }
}

/// Normalized calendar result plus its Unix timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedTime {
    /// Whole seconds since the Unix epoch.
    pub seconds: i64,
    /// Corresponding normalized UTC calendar.
    pub calendar: CalendarTime,
}

/// Pointer-free C ABI result for normalized calendar conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CalendarResult {
    /// Zero on success and nonzero when arithmetic overflowed.
    pub status: i32,
    /// Whole seconds since the Unix epoch.
    pub seconds: i64,
    /// Normalized UTC fields.
    pub calendar: CalendarTime,
}

/// Maximum formatted date bytes produced through the initial C facade.
pub const FORMAT_BUFFER_BYTES: usize = 4096;

/// Calendar formatting failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    /// A calendar field was outside its documented range.
    InvalidCalendar,
    /// A `%` conversion is not part of the bounded C-locale profile.
    InvalidSpecifier(u8),
    /// The caller-provided output buffer is too small.
    BufferTooSmall,
}

/// Result returned by the bounded C formatting bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FormatResult {
    /// Bytes written when `status` is zero.
    pub count: usize,
    /// Zero on success, one for invalid calendar, two for a bad specifier, and
    /// three for invalid or insufficient buffers.
    pub status: i32,
    /// Invalid conversion byte when `status` is two.
    pub option: i32,
}

const WEEKDAY_SHORT: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const WEEKDAY_LONG: [&[u8]; 7] = [
    b"Sunday",
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
];
const MONTH_SHORT: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];
const MONTH_LONG: [&[u8]; 12] = [
    b"January",
    b"February",
    b"March",
    b"April",
    b"May",
    b"June",
    b"July",
    b"August",
    b"September",
    b"October",
    b"November",
    b"December",
];

struct Writer<'a> {
    destination: &'a mut [u8],
    count: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        let end = self
            .count
            .checked_add(bytes.len())
            .ok_or(FormatError::BufferTooSmall)?;
        let Some(destination) = self.destination.get_mut(self.count..end) else {
            return Err(FormatError::BufferTooSmall);
        };
        destination.copy_from_slice(bytes);
        self.count = end;
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), FormatError> {
        self.bytes(core::slice::from_ref(&byte))
    }

    fn number(&mut self, value: i64, width: usize, fill: u8) -> Result<(), FormatError> {
        let negative = value < 0;
        let mut magnitude = value.unsigned_abs();
        let mut reversed = [0_u8; 20];
        let mut digits = 0_usize;
        loop {
            reversed[digits] = b'0' + u8::try_from(magnitude % 10).unwrap_or(0);
            digits += 1;
            magnitude /= 10;
            if magnitude == 0 {
                break;
            }
        }
        let padding = width.saturating_sub(digits + usize::from(negative));
        if fill == b' ' {
            for _ in 0..padding {
                self.byte(fill)?;
            }
        }
        if negative {
            self.byte(b'-')?;
        }
        if fill == b'0' {
            for _ in 0..padding {
                self.byte(fill)?;
            }
        }
        for byte in reversed[..digits].iter().rev() {
            self.byte(*byte)?;
        }
        Ok(())
    }
}

fn calendar_indexes(calendar: CalendarTime) -> Result<(usize, usize), FormatError> {
    if !(1..=12).contains(&calendar.month)
        || !(1..=31).contains(&calendar.day)
        || !(0..=23).contains(&calendar.hour)
        || !(0..=59).contains(&calendar.minute)
        || !(0..=59).contains(&calendar.second)
        || !(0..=6).contains(&calendar.week_day)
        || !(0..=365).contains(&calendar.year_day)
        || usize::from(calendar.zone_length) > MAX_ABBREVIATION_BYTES
    {
        return Err(FormatError::InvalidCalendar);
    }
    Ok((
        usize::try_from(calendar.week_day).map_err(|_| FormatError::InvalidCalendar)?,
        usize::try_from(calendar.month - 1).map_err(|_| FormatError::InvalidCalendar)?,
    ))
}

/// Format one UTC calendar using the bounded POSIX C-locale conversion set.
///
/// # Errors
///
/// Rejects invalid fields, unsupported conversion bytes, and insufficient
/// output storage. No partial output length is returned on error.
pub fn format_calendar(
    calendar: CalendarTime,
    format: &[u8],
    destination: &mut [u8],
) -> Result<usize, FormatError> {
    let (week_day, month) = calendar_indexes(calendar)?;
    let mut output = Writer {
        destination,
        count: 0,
    };
    let mut index = 0_usize;
    while index < format.len() {
        if format[index] != b'%' {
            output.byte(format[index])?;
            index += 1;
            continue;
        }
        index += 1;
        let Some(option) = format.get(index).copied() else {
            return Err(FormatError::InvalidSpecifier(0));
        };
        let mut hour12 = calendar.hour % 12;
        if hour12 == 0 {
            hour12 = 12;
        }
        match option {
            b'a' => output.bytes(WEEKDAY_SHORT[week_day])?,
            b'A' => output.bytes(WEEKDAY_LONG[week_day])?,
            b'b' => output.bytes(MONTH_SHORT[month])?,
            b'B' => output.bytes(MONTH_LONG[month])?,
            b'c' => {
                output.bytes(WEEKDAY_SHORT[week_day])?;
                output.byte(b' ')?;
                output.bytes(MONTH_SHORT[month])?;
                output.byte(b' ')?;
                output.number(i64::from(calendar.day), 2, b' ')?;
                output.byte(b' ')?;
                output.number(i64::from(calendar.hour), 2, b'0')?;
                output.byte(b':')?;
                output.number(i64::from(calendar.minute), 2, b'0')?;
                output.byte(b':')?;
                output.number(i64::from(calendar.second), 2, b'0')?;
                output.byte(b' ')?;
                output.number(calendar.year, 0, b'0')?;
            }
            b'd' => output.number(i64::from(calendar.day), 2, b'0')?,
            b'H' => output.number(i64::from(calendar.hour), 2, b'0')?,
            b'I' => output.number(i64::from(hour12), 2, b'0')?,
            b'j' => output.number(i64::from(calendar.year_day + 1), 3, b'0')?,
            b'm' => output.number(i64::from(calendar.month), 2, b'0')?,
            b'M' => output.number(i64::from(calendar.minute), 2, b'0')?,
            b'p' => output.bytes(if calendar.hour < 12 { b"AM" } else { b"PM" })?,
            b'S' => output.number(i64::from(calendar.second), 2, b'0')?,
            b'U' => output.number(
                i64::from((calendar.year_day + 7 - calendar.week_day) / 7),
                2,
                b'0',
            )?,
            b'w' => output.number(i64::from(calendar.week_day), 0, b'0')?,
            b'W' => {
                let monday_day = (calendar.week_day + 6) % 7;
                output.number(i64::from((calendar.year_day + 7 - monday_day) / 7), 2, b'0')?;
            }
            b'x' => {
                output.number(i64::from(calendar.month), 2, b'0')?;
                output.byte(b'/')?;
                output.number(i64::from(calendar.day), 2, b'0')?;
                output.byte(b'/')?;
                output.number(calendar.year % 100, 2, b'0')?;
            }
            b'X' => {
                output.number(i64::from(calendar.hour), 2, b'0')?;
                output.byte(b':')?;
                output.number(i64::from(calendar.minute), 2, b'0')?;
                output.byte(b':')?;
                output.number(i64::from(calendar.second), 2, b'0')?;
            }
            b'y' => output.number(calendar.year % 100, 2, b'0')?,
            b'Y' => output.number(calendar.year, 0, b'0')?,
            b'z' => {
                let magnitude = calendar.gmt_offset.unsigned_abs();
                output.byte(if calendar.gmt_offset < 0 { b'-' } else { b'+' })?;
                output.number(i64::from(magnitude / 3600), 2, b'0')?;
                output.number(i64::from(magnitude % 3600 / 60), 2, b'0')?;
            }
            b'Z' => output.bytes(calendar.zone_bytes())?,
            b'%' => output.byte(b'%')?,
            _ => return Err(FormatError::InvalidSpecifier(option)),
        }
        index += 1;
    }
    Ok(output.count)
}

pub(crate) fn floor_divide(value: i64, divisor: i64) -> i64 {
    let quotient = value / divisor;
    let remainder = value % divisor;
    if remainder < 0 {
        quotient - 1
    } else {
        quotient
    }
}

pub(crate) fn days_from_civil(mut year: i64, month: i32, day: i32) -> Option<i64> {
    year = year.checked_sub(i64::from(month <= 2))?;
    let era = floor_divide(year, 400);
    let year_of_era = u32::try_from(year.checked_sub(era.checked_mul(400)?)?).ok()?;
    let adjusted_month = month.checked_add(if month > 2 { -3 } else { 9 })?;
    let day_of_year = (153_u32.checked_mul(u32::try_from(adjusted_month).ok()?)? + 2) / 5
        + u32::try_from(day.checked_sub(1)?).ok()?;
    let day_of_era =
        year_of_era.checked_mul(365)? + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(i64::from(day_of_era))?
        .checked_sub(719_468)
}

pub(crate) fn civil_from_days(mut days: i64) -> (i64, i32, i32) {
    days += 719_468;
    let era = floor_divide(days, 146_097);
    let day_of_era = u32::try_from(days - era * 146_097).unwrap_or(0);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let parsed_year = i64::from(year_of_era) + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = i32::try_from(day_of_year - (153 * month_prime + 2) / 5 + 1).unwrap_or(1);
    let month = i32::try_from(month_prime).unwrap_or(0) + if month_prime < 10 { 3 } else { -9 };
    (parsed_year + i64::from(month <= 2), month, day)
}

/// Convert every representable Unix timestamp to a broken-down UTC calendar.
#[must_use]
pub fn from_unix_seconds(seconds: i64) -> CalendarTime {
    fields_from_seconds(seconds).with_abbreviation(Abbreviation::utc())
}

/// Convert one Unix timestamp to a broken-down calendar in `zone`.
///
/// The result carries the offset, daylight state, and abbreviation in effect
/// at that instant, so formatting it needs no other input.
#[must_use]
pub fn local_from_unix_seconds(zone: &TimeZone, seconds: i64) -> CalendarTime {
    let state = crate::timezone::offset_at(zone, seconds);
    let local = seconds.saturating_add(i64::from(state.seconds_east));
    fields_from_seconds(local).with_zone(state)
}

/// Break one epoch-second count into calendar fields, carrying no zone.
fn fields_from_seconds(seconds: i64) -> CalendarTime {
    let days = floor_divide(seconds, 86_400);
    let day_seconds = seconds - days * 86_400;
    let (year, month, day) = civil_from_days(days);
    let mut week_day = i32::try_from((days + 4) % 7).unwrap_or(0);
    if week_day < 0 {
        week_day += 7;
    }
    let year_day = days_from_civil(year, 1, 1)
        .and_then(|start| i32::try_from(days - start).ok())
        .unwrap_or(0);
    CalendarTime {
        year,
        month,
        day,
        hour: i32::try_from(day_seconds / 3600).unwrap_or(0),
        minute: i32::try_from((day_seconds % 3600) / 60).unwrap_or(0),
        second: i32::try_from(day_seconds % 60).unwrap_or(0),
        week_day,
        year_day,
        gmt_offset: 0,
        daylight: 0,
        zone: [0_u8; MAX_ABBREVIATION_BYTES],
        zone_length: 0,
    }
}

/// Normalize potentially out-of-range calendar fields and convert to Unix time.
///
/// # Errors
///
/// Returns `None` when checked Gregorian arithmetic cannot be represented.
#[must_use]
pub fn normalize(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Option<NormalizedTime> {
    let seconds = naive_seconds(year, month, day, hour, minute, second)?;
    Some(NormalizedTime {
        seconds,
        calendar: from_unix_seconds(seconds),
    })
}

/// Normalize a broken-down time read as local wall time in `zone`.
///
/// Only the date and time fields and `daylight` are read, exactly as POSIX
/// `mktime` reads a `struct tm`; the weekday, year day, offset, and zone of the
/// argument are outputs and are ignored here. `daylight` follows the POSIX
/// `tm_isdst` convention: above zero selects the daylight offset, zero selects
/// standard, and below zero determines the state from the zone's rules.
///
/// The returned calendar is the normalized local reading of the resolved
/// instant, so for a nonexistent local time it differs from what was supplied.
///
/// # Errors
///
/// Returns `None` when checked Gregorian arithmetic cannot be represented.
#[must_use]
pub fn normalize_local(zone: &TimeZone, calendar: CalendarTime) -> Option<NormalizedTime> {
    let naive = naive_seconds(
        calendar.year,
        i64::from(calendar.month),
        i64::from(calendar.day),
        i64::from(calendar.hour),
        i64::from(calendar.minute),
        i64::from(calendar.second),
    )?;
    let (seconds, state) = crate::timezone::unix_from_local(zone, naive, calendar.daylight);
    let local = seconds.checked_add(i64::from(state.seconds_east))?;
    Some(NormalizedTime {
        seconds,
        calendar: fields_from_seconds(local).with_zone(state),
    })
}

/// Fold out-of-range calendar fields into one epoch-second count.
fn naive_seconds(
    mut year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Option<i64> {
    let month_zero = month.checked_sub(1)?;
    let month_years = floor_divide(month_zero, 12);
    let normalized_month = i32::try_from(
        month_zero
            .checked_sub(month_years.checked_mul(12)?)?
            .checked_add(1)?,
    )
    .ok()?;
    year = year.checked_add(month_years)?;
    let days = days_from_civil(year, normalized_month, 1)?.checked_add(day.checked_sub(1)?)?;
    let mut value = days.checked_mul(86_400)?;
    value = value.checked_add(hour.checked_mul(3600)?)?;
    value = value.checked_add(minute.checked_mul(60)?)?;
    value.checked_add(second)
}

/// C ABI bridge for [`from_unix_seconds`].
#[unsafe(no_mangle)]
pub extern "C" fn troe_runtime_calendar_from_seconds(seconds: i64) -> CalendarTime {
    from_unix_seconds(seconds)
}

/// C ABI bridge for [`normalize`] without borrowed pointers.
#[unsafe(no_mangle)]
pub extern "C" fn troe_runtime_normalize_calendar(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> CalendarResult {
    match normalize(year, month, day, hour, minute, second) {
        Some(value) => CalendarResult {
            status: 0,
            seconds: value.seconds,
            calendar: value.calendar,
        },
        None => CalendarResult {
            status: -1,
            seconds: 0,
            calendar: from_unix_seconds(0),
        },
    }
}

/// Borrow a caller-supplied `TZ` string for the duration of one call.
///
/// # Safety
///
/// A nonzero length must describe readable bytes that remain live for the call.
unsafe fn borrow_timezone<'a>(text: *const u8, length: usize) -> Option<&'a [u8]> {
    if length != 0 && text.is_null() {
        return None;
    }
    // SAFETY: The contract above requires readable `length` bytes; a dangling
    // nonnull pointer is valid for an empty slice.
    Some(unsafe {
        core::slice::from_raw_parts(
            if length == 0 {
                core::ptr::NonNull::<u8>::dangling().as_ptr().cast_const()
            } else {
                text
            },
            length,
        )
    })
}

/// C ABI bridge reporting whether one `TZ` string is accepted.
///
/// Launchers call this to refuse a bad value before a child exists. It reports
/// only whether the string parses; a Rust caller reads
/// [`timezone::parse`](crate::timezone::parse) for the typed reason instead.
///
/// # Safety
///
/// A nonzero length must describe readable bytes that remain live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn troe_runtime_validate_timezone(text: *const u8, length: usize) -> i32 {
    // SAFETY: The pointer contract is forwarded to the caller unchanged.
    let Some(text) = (unsafe { borrow_timezone(text, length) }) else {
        return 1;
    };
    i32::from(crate::timezone::parse(text).is_err())
}

/// Pointer-free summary of one zone's two states.
///
/// This is what a libc needs to publish `tzname`, `timezone`, and `daylight`
/// once, rather than inferring them from sample instants, which no single
/// hemisphere's sampling can do correctly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ZoneSummary {
    /// Seconds east of UTC in the standard state.
    pub standard_offset: i32,
    /// Seconds east of UTC in the daylight state, equal to the standard offset
    /// when the zone declares no daylight rules.
    pub daylight_offset: i32,
    /// One when the zone declares daylight rules, zero otherwise.
    pub observes_daylight: i32,
    /// Standard-state abbreviation bytes.
    pub standard: [u8; MAX_ABBREVIATION_BYTES],
    /// Significant bytes in `standard`.
    pub standard_length: u8,
    /// Daylight-state abbreviation bytes, empty when there are no rules.
    pub daylight: [u8; MAX_ABBREVIATION_BYTES],
    /// Significant bytes in `daylight`.
    pub daylight_length: u8,
}

fn copy_abbreviation(source: Abbreviation) -> ([u8; MAX_ABBREVIATION_BYTES], u8) {
    let mut bytes = [0_u8; MAX_ABBREVIATION_BYTES];
    let source = source.as_bytes();
    if let Some(destination) = bytes.get_mut(..source.len()) {
        destination.copy_from_slice(source);
    }
    (bytes, u8::try_from(source.len()).unwrap_or(0))
}

/// Summarize one zone's states.
#[must_use]
pub fn summarize(zone: &TimeZone) -> ZoneSummary {
    let (standard, standard_length) = copy_abbreviation(zone.standard_abbreviation());
    let (daylight, daylight_length) = zone
        .daylight_abbreviation()
        .map_or(([0_u8; MAX_ABBREVIATION_BYTES], 0), copy_abbreviation);
    ZoneSummary {
        standard_offset: zone.standard_offset(),
        daylight_offset: zone.daylight_offset().unwrap_or(zone.standard_offset()),
        observes_daylight: i32::from(zone.observes_daylight()),
        standard,
        standard_length,
        daylight,
        daylight_length,
    }
}

/// C ABI bridge for [`summarize`].
///
/// # Safety
///
/// A nonzero length must describe readable bytes that remain live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn troe_runtime_zone_summary(text: *const u8, length: usize) -> ZoneSummary {
    // SAFETY: The pointer contract is forwarded to the caller unchanged.
    let zone = match unsafe { borrow_timezone(text, length) } {
        Some(text) => TimeZone::parse_or_utc(text),
        None => TimeZone::utc(),
    };
    summarize(&zone)
}

/// C ABI bridge for [`local_from_unix_seconds`].
///
/// An unparsable `TZ` yields the UTC calendar, because conversion has no error
/// channel; launchers refuse such a value before a process can observe it.
///
/// # Safety
///
/// A nonzero length must describe readable bytes that remain live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn troe_runtime_local_calendar_from_seconds(
    text: *const u8,
    length: usize,
    seconds: i64,
) -> CalendarTime {
    // SAFETY: The pointer contract is forwarded to the caller unchanged.
    let zone = match unsafe { borrow_timezone(text, length) } {
        Some(text) => TimeZone::parse_or_utc(text),
        None => TimeZone::utc(),
    };
    local_from_unix_seconds(&zone, seconds)
}

/// C ABI bridge for [`normalize_local`].
///
/// # Safety
///
/// A nonzero length must describe readable bytes that remain live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn troe_runtime_normalize_local_calendar(
    text: *const u8,
    length: usize,
    calendar: CalendarTime,
) -> CalendarResult {
    // SAFETY: The pointer contract is forwarded to the caller unchanged.
    let zone = match unsafe { borrow_timezone(text, length) } {
        Some(text) => TimeZone::parse_or_utc(text),
        None => TimeZone::utc(),
    };
    match normalize_local(&zone, calendar) {
        Some(value) => CalendarResult {
            status: 0,
            seconds: value.seconds,
            calendar: value.calendar,
        },
        None => CalendarResult {
            status: -1,
            seconds: 0,
            calendar: from_unix_seconds(0),
        },
    }
}

/// Bounded C ABI bridge for [`format_calendar`].
///
/// # Safety
///
/// Nonzero input and output lengths must describe readable and writable spans,
/// respectively, that remain live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn troe_runtime_format_calendar(
    calendar: CalendarTime,
    format: *const u8,
    format_length: usize,
    destination: *mut u8,
    capacity: usize,
) -> FormatResult {
    let invalid_buffer = FormatResult {
        count: 0,
        status: 3,
        option: 0,
    };
    if (format_length != 0 && format.is_null()) || (capacity != 0 && destination.is_null()) {
        return invalid_buffer;
    }
    // SAFETY: The pointer contract above requires readable `format_length`
    // bytes; a dangling nonnull pointer is valid for an empty slice.
    let format = unsafe {
        core::slice::from_raw_parts(
            if format_length == 0 {
                core::ptr::NonNull::<u8>::dangling().as_ptr().cast_const()
            } else {
                format
            },
            format_length,
        )
    };
    // SAFETY: The pointer contract above requires writable `capacity` bytes;
    // a dangling nonnull pointer is valid for an empty slice.
    let destination = unsafe {
        core::slice::from_raw_parts_mut(
            if capacity == 0 {
                core::ptr::NonNull::<u8>::dangling().as_ptr()
            } else {
                destination
            },
            capacity,
        )
    };
    match format_calendar(calendar, format, destination) {
        Ok(count) => FormatResult {
            count,
            status: 0,
            option: 0,
        },
        Err(FormatError::InvalidCalendar) => FormatResult {
            count: 0,
            status: 1,
            option: 0,
        },
        Err(FormatError::InvalidSpecifier(option)) => FormatResult {
            count: 0,
            status: 2,
            option: i32::from(option),
        },
        Err(FormatError::BufferTooSmall) => invalid_buffer,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        CalendarResult, CalendarTime, FormatError, ZoneSummary, format_calendar, from_unix_seconds,
        local_from_unix_seconds, normalize, normalize_local,
    };
    use crate::timezone::{TimeZone, parse_str};

    /// United States Eastern, matching the timezone module's own fixtures.
    const EASTERN: &str = "EST5EDT,M3.2.0,M11.1.0";

    fn eastern() -> TimeZone {
        parse_str(EASTERN).unwrap_or_else(|_| std::process::abort())
    }

    #[test]
    fn leap_day_and_field_normalization_match_posix_calendar_rules() {
        let leap = from_unix_seconds(1_709_168_523);
        assert_eq!((leap.year, leap.month, leap.day), (2024, 2, 29));
        assert_eq!((leap.hour, leap.minute, leap.second), (1, 2, 3));
        assert_eq!((leap.week_day, leap.year_day), (4, 59));
        let Some(normalized) = normalize(2023, 13, 1, 12, 0, 0) else {
            std::process::abort();
        };
        assert_eq!(normalized.seconds, 1_704_110_400);
        assert_eq!(
            (
                normalized.calendar.year,
                normalized.calendar.month,
                normalized.calendar.day
            ),
            (2024, 1, 1)
        );
        let Some(previous) = normalize(2024, 3, 0, 12, 0, 0) else {
            std::process::abort();
        };
        assert_eq!(
            (
                previous.calendar.year,
                previous.calendar.month,
                previous.calendar.day
            ),
            (2024, 2, 29)
        );
    }

    /// The C runtime and the Lua shim mirror these structures field for field.
    /// A layout change here is an ABI break for every compiled `.kex`, so the
    /// exact sizes and offsets are pinned rather than merely assumed.
    #[test]
    fn the_c_abi_layout_matches_what_the_mirrors_declare() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(
            (size_of::<CalendarTime>(), align_of::<CalendarTime>()),
            (64, 8)
        );
        assert_eq!(offset_of!(CalendarTime, year), 0);
        assert_eq!(offset_of!(CalendarTime, month), 8);
        assert_eq!(offset_of!(CalendarTime, gmt_offset), 36);
        assert_eq!(offset_of!(CalendarTime, daylight), 40);
        assert_eq!(offset_of!(CalendarTime, zone), 44);
        assert_eq!(offset_of!(CalendarTime, zone_length), 60);
        assert_eq!(
            (size_of::<CalendarResult>(), align_of::<CalendarResult>()),
            (80, 8)
        );
        assert_eq!(offset_of!(CalendarResult, status), 0);
        assert_eq!(offset_of!(CalendarResult, seconds), 8);
        assert_eq!(offset_of!(CalendarResult, calendar), 16);
        assert_eq!(
            (size_of::<ZoneSummary>(), align_of::<ZoneSummary>()),
            (48, 4)
        );
        assert_eq!(offset_of!(ZoneSummary, standard_offset), 0);
        assert_eq!(offset_of!(ZoneSummary, standard), 12);
        assert_eq!(offset_of!(ZoneSummary, standard_length), 28);
        assert_eq!(offset_of!(ZoneSummary, daylight), 29);
        assert_eq!(offset_of!(ZoneSummary, daylight_length), 45);
    }

    #[test]
    fn a_local_calendar_carries_the_offset_it_was_read_through() {
        let zone = eastern();
        // 2026-01-15T12:00:00Z is 07:00 EST, and 2026-07-15T12:00:00Z is
        // 08:00 EDT.
        let winter = local_from_unix_seconds(&zone, 1_768_478_400);
        assert_eq!((winter.hour, winter.minute), (7, 0));
        assert_eq!((winter.year, winter.month, winter.day), (2026, 1, 15));
        assert_eq!(winter.gmt_offset, -5 * 3600);
        assert_eq!(winter.daylight, 0);
        assert_eq!(winter.zone_bytes(), b"EST");
        let summer = local_from_unix_seconds(&zone, 1_784_116_800);
        assert_eq!(summer.hour, 8);
        assert_eq!(summer.gmt_offset, -4 * 3600);
        assert_eq!(summer.daylight, 1);
        assert_eq!(summer.zone_bytes(), b"EDT");

        // The UTC conversion is unchanged and names itself.
        let utc = from_unix_seconds(1_784_116_800);
        assert_eq!(utc.hour, 12);
        assert_eq!(utc.gmt_offset, 0);
        assert_eq!(utc.zone_bytes(), b"UTC");
    }

    #[test]
    fn normalizing_local_fields_resolves_through_the_zone() {
        let zone = eastern();
        let mut fields = from_unix_seconds(0);
        fields.year = 2026;
        fields.month = 7;
        fields.day = 15;
        fields.hour = 8;
        fields.minute = 0;
        fields.second = 0;
        fields.daylight = -1;
        let Some(normalized) = normalize_local(&zone, fields) else {
            std::process::abort();
        };
        assert_eq!(normalized.seconds, 1_784_116_800);
        assert_eq!(normalized.calendar.zone_bytes(), b"EDT");
        assert_eq!(normalized.calendar.gmt_offset, -4 * 3600);
        // The same wall-clock fields read as UTC are a different instant.
        let Some(as_utc) = normalize(2026, 7, 15, 8, 0, 0) else {
            std::process::abort();
        };
        assert_eq!(as_utc.seconds, 1_784_116_800 - 4 * 3600);
    }

    #[test]
    fn zone_conversions_render_from_the_calendar_alone() {
        let zone = eastern();
        let mut output = [0_u8; 64];
        let summer = local_from_unix_seconds(&zone, 1_784_116_800);
        let count = format_calendar(summer, b"%Y-%m-%d %H:%M:%S %z %Z", &mut output)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&output[..count], b"2026-07-15 08:00:00 -0400 EDT");
        let winter = local_from_unix_seconds(&zone, 1_768_478_400);
        let count = format_calendar(winter, b"%z %Z", &mut output)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&output[..count], b"-0500 EST");
        // A half-hour zone keeps its minutes, and UTC renders as `+0000`.
        let Ok(india) = parse_str("<+0530>-5:30") else {
            std::process::abort();
        };
        let count = format_calendar(
            local_from_unix_seconds(&india, 1_784_116_800),
            b"%H:%M %z %Z",
            &mut output,
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&output[..count], b"17:30 +0530 +0530");
        let count = format_calendar(from_unix_seconds(0), b"%z %Z", &mut output)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&output[..count], b"+0000 UTC");
    }

    #[test]
    fn formatting_is_c_locale_and_bounded() {
        let calendar = from_unix_seconds(1_709_168_523);
        let mut output = [0_u8; 64];
        let count = format_calendar(calendar, b"%Y-%m-%d %H:%M:%S %a %j", &mut output)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&output[..count], b"2024-02-29 01:02:03 Thu 060");
        assert_eq!(
            format_calendar(calendar, b"%Q", &mut output),
            Err(FormatError::InvalidSpecifier(b'Q'))
        );
        assert_eq!(
            format_calendar(calendar, b"%Y", &mut output[..3]),
            Err(FormatError::BufferTooSmall)
        );
    }
}

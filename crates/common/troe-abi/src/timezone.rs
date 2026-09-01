//! POSIX `TZ` string grammar shared by every component that composes a launch.
//!
//! This module owns only the format: what a well-formed `TZ` value is, and the
//! parsed record one denotes. Evaluating an instant against those rules belongs
//! to the KEX runtime, which has the calendar arithmetic. The grammar lives here
//! for the reason [`command::CONVENTIONAL_ENVIRONMENT`] does — every composing
//! component agrees on it without any of them copying it.
//!
//! Offsets are reported as seconds **east** of UTC. A POSIX string writes them
//! west-positive, so `EST5` parses to `-18000`.
//!
//! See ADR 0067 for the decision and the forms it deliberately refuses.

/// Fewest bytes in an accepted zone abbreviation.
pub const MIN_ABBREVIATION_BYTES: usize = 3;
/// Most bytes in an accepted zone abbreviation.
pub const MAX_ABBREVIATION_BYTES: usize = 16;
/// Most bytes in an accepted `TZ` string.
pub const MAX_TZ_BYTES: usize = 128;
/// Largest magnitude accepted for a UTC offset, in hours.
pub const MAX_OFFSET_HOURS: i32 = 24;
/// Largest magnitude accepted for a transition time of day, in hours.
///
/// This is the `TZif` version 3 range rather than the narrower POSIX one,
/// so a footer lifted from one parses unchanged when dataset support lands.
pub const MAX_TRANSITION_HOURS: i32 = 167;
/// Transition time of day used when a rule states none, as POSIX requires.
pub const DEFAULT_TRANSITION_SECONDS: i32 = 2 * 3600;
/// The zone every unconfigured launch runs in.
pub const DEFAULT_TZ: &str = "UTC0";

/// Reason one `TZ` string was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The string is empty, over-long, or not ASCII.
    Malformed,
    /// A leading `:` selects the database form, which TROE does not provide.
    DatabaseForm,
    /// A daylight abbreviation appeared without the rules that govern it.
    MissingRules,
    /// An abbreviation is too short, too long, or holds an invalid byte.
    Abbreviation,
    /// An offset or transition time is malformed or out of range.
    Offset,
    /// A transition rule is malformed or out of range.
    Rule,
    /// Bytes remain after an otherwise complete specification.
    Trailing,
}

/// One zone abbreviation, stored inline so no result borrows its input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Abbreviation {
    bytes: [u8; MAX_ABBREVIATION_BYTES],
    length: u8,
}

impl Abbreviation {
    /// The abbreviation naming UTC, which every unconfigured launch reports.
    #[must_use]
    pub const fn utc() -> Self {
        let mut bytes = [0_u8; MAX_ABBREVIATION_BYTES];
        bytes[0] = b'U';
        bytes[1] = b'T';
        bytes[2] = b'C';
        Self { bytes, length: 3 }
    }

    /// The abbreviation's significant bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        let length = usize::from(self.length);
        self.bytes.get(..length).unwrap_or(&[])
    }

    fn new(source: &[u8]) -> Result<Self, ParseError> {
        if !(MIN_ABBREVIATION_BYTES..=MAX_ABBREVIATION_BYTES).contains(&source.len()) {
            return Err(ParseError::Abbreviation);
        }
        let mut bytes = [0_u8; MAX_ABBREVIATION_BYTES];
        let Some(destination) = bytes.get_mut(..source.len()) else {
            return Err(ParseError::Abbreviation);
        };
        destination.copy_from_slice(source);
        let length = u8::try_from(source.len()).map_err(|_| ParseError::Abbreviation)?;
        Ok(Self { bytes, length })
    }
}

/// The day a transition rule selects within one year.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleDay {
    /// `Mm.w.d`, where week 5 means the last such weekday of the month.
    MonthWeekDay {
        /// Month, 1 through 12.
        month: i32,
        /// Week, 1 through 5, where 5 selects the last such weekday.
        week: i32,
        /// Weekday, 0 through 6, counting from Sunday.
        weekday: i32,
    },
    /// `Jn`, counting 1 through 365 and never counting February 29.
    JulianNoLeap(i32),
    /// Bare `n`, counting 0 through 365 and counting February 29.
    ZeroBasedDay(i32),
}

/// One transition: which day, and the local time of day it happens at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition {
    /// The day within the year the transition falls on.
    pub day: RuleDay,
    /// Local time of day, which the accepted range lets fall outside one day.
    pub seconds: i32,
}

/// The daylight half of a zone, present only when the string declares rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Daylight {
    /// Abbreviation naming the daylight state.
    pub abbreviation: Abbreviation,
    /// Seconds east of UTC while daylight time is in effect.
    pub offset: i32,
    /// Transition into daylight time, timed in the standard offset.
    pub start: Transition,
    /// Transition back to standard time, timed in the daylight offset.
    pub end: Transition,
}

/// One parsed POSIX `TZ` string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeZone {
    standard: Abbreviation,
    standard_offset: i32,
    daylight: Option<Daylight>,
}

impl TimeZone {
    /// Parse one POSIX `TZ` string, falling back to UTC when it is refused.
    ///
    /// Launchers validate with [`parse`] and refuse a bad value before a
    /// child exists, so this fallback is unreachable for a composed launch.
    /// It exists because conversion has no error channel to report one
    /// through.
    #[must_use]
    pub fn parse_or_utc(input: &[u8]) -> Self {
        parse(input).unwrap_or_else(|_| Self::utc())
    }

    /// The zone every unconfigured launch runs in.
    #[must_use]
    pub fn utc() -> Self {
        parse(DEFAULT_TZ.as_bytes()).unwrap_or(Self {
            standard: Abbreviation::utc(),
            standard_offset: 0,
            daylight: None,
        })
    }

    /// True when the zone declares daylight rules at all.
    #[must_use]
    pub const fn observes_daylight(&self) -> bool {
        self.daylight.is_some()
    }

    /// Seconds east of UTC while the zone is in its standard state.
    #[must_use]
    pub const fn standard_offset(&self) -> i32 {
        self.standard_offset
    }

    /// The zone's standard-state abbreviation.
    #[must_use]
    pub const fn standard_abbreviation(&self) -> Abbreviation {
        self.standard
    }

    /// The zone's daylight rules, if it declares any.
    #[must_use]
    pub const fn daylight(&self) -> Option<Daylight> {
        self.daylight
    }

    /// Seconds east of UTC while the zone is in its daylight state, if any.
    #[must_use]
    pub fn daylight_offset(&self) -> Option<i32> {
        self.daylight.map(|daylight| daylight.offset)
    }

    /// The zone's daylight-state abbreviation, if it declares one.
    #[must_use]
    pub fn daylight_abbreviation(&self) -> Option<Abbreviation> {
        self.daylight.map(|daylight| daylight.abbreviation)
    }
}

fn parse_number(input: &[u8], index: &mut usize, digits: usize) -> Option<i32> {
    let start = *index;
    let mut value = 0_i32;
    while *index - start < digits {
        let Some(byte) = input.get(*index).copied() else {
            break;
        };
        if !byte.is_ascii_digit() {
            break;
        }
        value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
        *index += 1;
    }
    (*index > start).then_some(value)
}

/// Parse `[+|-]hh[:mm[:ss]]` into signed seconds exactly as written.
fn parse_hms(input: &[u8], index: &mut usize, max_hours: i32) -> Result<i32, ParseError> {
    let negative = match input.get(*index).copied() {
        Some(b'-') => {
            *index += 1;
            true
        }
        Some(b'+') => {
            *index += 1;
            false
        }
        _ => false,
    };
    let hours = parse_number(input, index, 3).ok_or(ParseError::Offset)?;
    if hours > max_hours {
        return Err(ParseError::Offset);
    }
    let mut seconds = hours.checked_mul(3600).ok_or(ParseError::Offset)?;
    for scale in [60, 1] {
        if input.get(*index).copied() != Some(b':') {
            break;
        }
        *index += 1;
        let part = parse_number(input, index, 2).ok_or(ParseError::Offset)?;
        if part > 59 {
            return Err(ParseError::Offset);
        }
        seconds = seconds
            .checked_add(part.checked_mul(scale).ok_or(ParseError::Offset)?)
            .ok_or(ParseError::Offset)?;
    }
    Ok(if negative { -seconds } else { seconds })
}

fn parse_abbreviation(input: &[u8], index: &mut usize) -> Result<Abbreviation, ParseError> {
    let start = *index;
    if input.get(*index).copied() == Some(b'<') {
        *index += 1;
        let content = *index;
        while input
            .get(*index)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'-')
        {
            *index += 1;
        }
        if input.get(*index).copied() != Some(b'>') {
            return Err(ParseError::Abbreviation);
        }
        let bytes = input.get(content..*index).ok_or(ParseError::Abbreviation)?;
        *index += 1;
        return Abbreviation::new(bytes);
    }
    while input.get(*index).is_some_and(u8::is_ascii_alphabetic) {
        *index += 1;
    }
    Abbreviation::new(input.get(start..*index).ok_or(ParseError::Abbreviation)?)
}

fn parse_rule_day(input: &[u8], index: &mut usize) -> Result<RuleDay, ParseError> {
    match input.get(*index).copied() {
        Some(b'M') => {
            *index += 1;
            let month = parse_number(input, index, 2).ok_or(ParseError::Rule)?;
            if input.get(*index).copied() != Some(b'.') {
                return Err(ParseError::Rule);
            }
            *index += 1;
            let week = parse_number(input, index, 1).ok_or(ParseError::Rule)?;
            if input.get(*index).copied() != Some(b'.') {
                return Err(ParseError::Rule);
            }
            *index += 1;
            let weekday = parse_number(input, index, 1).ok_or(ParseError::Rule)?;
            if !(1..=12).contains(&month) || !(1..=5).contains(&week) || !(0..=6).contains(&weekday)
            {
                return Err(ParseError::Rule);
            }
            Ok(RuleDay::MonthWeekDay {
                month,
                week,
                weekday,
            })
        }
        Some(b'J') => {
            *index += 1;
            let day = parse_number(input, index, 3).ok_or(ParseError::Rule)?;
            if !(1..=365).contains(&day) {
                return Err(ParseError::Rule);
            }
            Ok(RuleDay::JulianNoLeap(day))
        }
        Some(byte) if byte.is_ascii_digit() => {
            let day = parse_number(input, index, 3).ok_or(ParseError::Rule)?;
            if !(0..=365).contains(&day) {
                return Err(ParseError::Rule);
            }
            Ok(RuleDay::ZeroBasedDay(day))
        }
        _ => Err(ParseError::Rule),
    }
}

fn parse_transition(input: &[u8], index: &mut usize) -> Result<Transition, ParseError> {
    if input.get(*index).copied() != Some(b',') {
        return Err(ParseError::Rule);
    }
    *index += 1;
    let day = parse_rule_day(input, index)?;
    let seconds = if input.get(*index).copied() == Some(b'/') {
        *index += 1;
        parse_hms(input, index, MAX_TRANSITION_HOURS)?
    } else {
        DEFAULT_TRANSITION_SECONDS
    };
    Ok(Transition { day, seconds })
}

/// Parse one POSIX `TZ` string.
///
/// # Errors
///
/// Rejects the database form, an unsupported grammar, an out-of-range
/// offset or rule, a daylight abbreviation without rules, and any trailing
/// bytes. A refusal is total: no partially parsed zone is returned.
pub fn parse(input: &[u8]) -> Result<TimeZone, ParseError> {
    if input.is_empty() || input.len() > MAX_TZ_BYTES || !input.is_ascii() {
        return Err(ParseError::Malformed);
    }
    if input.first().copied() == Some(b':') {
        return Err(ParseError::DatabaseForm);
    }
    let mut index = 0_usize;
    let standard = parse_abbreviation(input, &mut index)?;
    let standard_offset = -parse_hms(input, &mut index, MAX_OFFSET_HOURS)?;
    if index == input.len() {
        return Ok(TimeZone {
            standard,
            standard_offset,
            daylight: None,
        });
    }
    let abbreviation = parse_abbreviation(input, &mut index)?;
    let offset = match input.get(index).copied() {
        Some(byte) if byte != b',' => -parse_hms(input, &mut index, MAX_OFFSET_HOURS)?,
        // POSIX leaves an omitted daylight offset one hour ahead of standard.
        _ => standard_offset
            .checked_add(3600)
            .ok_or(ParseError::Offset)?,
    };
    if index == input.len() {
        // A daylight abbreviation with no rules is implementation-defined
        // and historically resolves to United States rules. Guessing them
        // would produce a wrong answer indistinguishable from a right one.
        return Err(ParseError::MissingRules);
    }
    let start = parse_transition(input, &mut index)?;
    let end = parse_transition(input, &mut index)?;
    if index != input.len() {
        return Err(ParseError::Trailing);
    }
    Ok(TimeZone {
        standard,
        standard_offset,
        daylight: Some(Daylight {
            abbreviation,
            offset,
            start,
            end,
        }),
    })
}

/// Parse one POSIX `TZ` string held as text.
///
/// # Errors
///
/// Reports the same refusals as [`parse`].
pub fn parse_str(input: &str) -> Result<TimeZone, ParseError> {
    parse(input.as_bytes())
}

/// Validate the bytes of a configured zone file and return the zone string.
///
/// A configuration file is written by an operator with a text editor or a
/// shell redirection, so one trailing newline is expected rather than an
/// error. Nothing else is trimmed: interior or leading whitespace is not a
/// zone, and accepting it would make two files that look different mean the
/// same thing. See ADR 0068.
///
/// # Errors
///
/// Reports the same refusals as [`parse`], plus [`ParseError::Malformed`]
/// for bytes that are not UTF-8.
pub fn parse_configuration(bytes: &[u8]) -> Result<&str, ParseError> {
    let text = core::str::from_utf8(bytes).map_err(|_| ParseError::Malformed)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    parse(text.as_bytes())?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::{ParseError, RuleDay, parse, parse_str};

    fn zone(text: &str) -> super::TimeZone {
        parse_str(text).unwrap_or_else(|_| std::process::abort())
    }

    #[test]
    fn the_documented_forms_parse() {
        let utc = zone("UTC0");
        assert_eq!(utc.standard_offset(), 0);
        assert!(!utc.observes_daylight());
        assert_eq!(utc.standard_abbreviation().as_bytes(), b"UTC");

        // A POSIX offset is written west-positive and stored east-negative.
        let eastern = zone("EST5EDT,M3.2.0,M11.1.0");
        assert_eq!(eastern.standard_offset(), -5 * 3600);
        assert_eq!(eastern.daylight_offset(), Some(-4 * 3600));
        assert_eq!(
            eastern.daylight_abbreviation().map(|a| a.as_bytes().len()),
            Some(3)
        );
        let Some(daylight) = eastern.daylight() else {
            std::process::abort();
        };
        assert_eq!(
            daylight.start.day,
            RuleDay::MonthWeekDay {
                month: 3,
                week: 2,
                weekday: 0
            }
        );
        assert_eq!(daylight.start.seconds, super::DEFAULT_TRANSITION_SECONDS);

        // An omitted daylight offset is one hour ahead of standard.
        assert_eq!(
            zone("CET-1CEST,M3.5.0,M10.5.0/3").daylight_offset(),
            Some(2 * 3600)
        );
        // Quoted abbreviations carry the digits and signs modern zones need.
        let india = zone("<+0530>-5:30");
        assert_eq!(india.standard_offset(), 5 * 3600 + 1800);
        assert_eq!(india.standard_abbreviation().as_bytes(), b"+0530");
        // Seconds resolve, and both offset range ends are accepted.
        assert_eq!(zone("XXX-0:44:30").standard_offset(), 44 * 60 + 30);
        assert_eq!(zone("XXX24").standard_offset(), -24 * 3600);
        assert_eq!(zone("XXX-24").standard_offset(), 24 * 3600);
        // A transition time may reach the `TZif` version 3 range.
        assert!(parse_str("XXX0YYY,M1.1.0/-167,M2.1.0/167:59:59").is_ok());
        assert!(parse_str("XXX0YYY,J1,365").is_ok());
    }

    #[test]
    fn every_refused_form_is_refused() {
        assert_eq!(parse(b""), Err(ParseError::Malformed));
        assert_eq!(parse(&[0xff_u8; 8]), Err(ParseError::Malformed));
        assert_eq!(parse(&[b'X'; MAX_TZ_BYTES + 1]), Err(ParseError::Malformed));
        assert_eq!(parse(b":America/New_York"), Err(ParseError::DatabaseForm));
        assert_eq!(parse_str("EST5EDT"), Err(ParseError::MissingRules));
        assert_eq!(parse_str("ES5"), Err(ParseError::Abbreviation));
        assert_eq!(parse_str("<AB>5"), Err(ParseError::Abbreviation));
        assert_eq!(parse_str("<ABC5"), Err(ParseError::Abbreviation));
        assert_eq!(parse_str("XXX25"), Err(ParseError::Offset));
        assert_eq!(parse_str("XXX0:60"), Err(ParseError::Offset));
        assert_eq!(parse_str("XXX0YYY,M13.1.0,M2.1.0"), Err(ParseError::Rule));
        assert_eq!(parse_str("XXX0YYY,M1.6.0,M2.1.0"), Err(ParseError::Rule));
        assert_eq!(parse_str("XXX0YYY,M1.1.7,M2.1.0"), Err(ParseError::Rule));
        assert_eq!(parse_str("XXX0YYY,J0,M2.1.0"), Err(ParseError::Rule));
        assert_eq!(parse_str("XXX0YYY,J366,M2.1.0"), Err(ParseError::Rule));
        assert_eq!(parse_str("XXX0YYY,366,M2.1.0"), Err(ParseError::Rule));
        assert_eq!(parse_str("XXX0YYY,M1.1.0"), Err(ParseError::Rule));
        assert_eq!(
            parse_str("XXX0YYY,M1.1.0,M2.1.0x"),
            Err(ParseError::Trailing)
        );
        assert_eq!(
            parse_str("XXX0YYY,M1.1.0/168,M2.1.0"),
            Err(ParseError::Offset)
        );
    }

    #[test]
    fn a_configuration_file_accepts_one_trailing_newline_and_nothing_else() {
        use super::parse_configuration;
        let zone = "EST5EDT,M3.2.0,M11.1.0";
        for text in [
            "EST5EDT,M3.2.0,M11.1.0",
            "EST5EDT,M3.2.0,M11.1.0\n",
            "EST5EDT,M3.2.0,M11.1.0\r\n",
        ] {
            assert_eq!(parse_configuration(text.as_bytes()), Ok(zone), "{text:?}");
        }
        // Leading or interior whitespace is not part of a zone, and a file
        // holding two lines is not one zone.
        for text in [
            " UTC0",
            "UTC0 ",
            "UTC0\n\n",
            "UTC0\nEST5EDT,M3.2.0,M11.1.0\n",
        ] {
            assert!(parse_configuration(text.as_bytes()).is_err(), "{text:?}");
        }
        assert_eq!(parse_configuration(b""), Err(ParseError::Malformed));
        assert_eq!(parse_configuration(b"\n"), Err(ParseError::Malformed));
        assert_eq!(
            parse_configuration(&[0xff, 0xfe]),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            parse_configuration(b":America/New_York"),
            Err(ParseError::DatabaseForm)
        );
    }

    #[test]
    fn a_refused_string_still_yields_utc() {
        let fallback = super::TimeZone::parse_or_utc(b":America/New_York");
        assert_eq!(fallback, super::TimeZone::utc());
        assert_eq!(fallback.standard_offset(), 0);
        assert_eq!(fallback.standard_abbreviation().as_bytes(), b"UTC");
        assert!(!fallback.observes_daylight());
        // The conventional default the ABI composes must itself parse.
        assert_eq!(
            super::parse_str(super::DEFAULT_TZ),
            Ok(super::TimeZone::utc())
        );
    }

    use super::MAX_TZ_BYTES;
}

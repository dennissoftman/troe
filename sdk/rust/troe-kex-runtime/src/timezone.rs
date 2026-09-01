//! Local-time evaluation over a parsed POSIX `TZ` string.
//!
//! The grammar lives in [`troe_kex_sdk::timezone`], which every composing
//! component shares. This module is the other half: the rules engine that
//! answers what offset one instant falls under, and which instant one local
//! wall time names. It reads no file, allocates nothing, and answers each
//! query in constant time from the two candidate transitions of the query's
//! own year.
//!
//! It is the only such engine in the system. libc, Lua, and `CPython` all reach
//! it rather than carrying private copies that could disagree about a
//! transition. See ADR 0067.

use crate::time::{civil_from_days, days_from_civil, floor_divide};
pub use troe_kex_sdk::timezone::{
    Abbreviation, DEFAULT_TRANSITION_SECONDS, DEFAULT_TZ, Daylight, MAX_ABBREVIATION_BYTES,
    MAX_OFFSET_HOURS, MAX_TRANSITION_HOURS, MAX_TZ_BYTES, MIN_ABBREVIATION_BYTES, ParseError,
    RuleDay, TimeZone, Transition, parse, parse_str,
};

/// The zone state in effect at one instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZoneOffset {
    /// Seconds east of UTC.
    pub seconds_east: i32,
    /// True when the daylight rules put the zone in its daylight state.
    pub is_daylight: bool,
    /// The abbreviation naming that state.
    pub abbreviation: Abbreviation,
}

/// Whether a Gregorian year has a February 29.
const fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Days in one month of one year.
const fn days_in_month(year: i64, month: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Zero-based day of the year one rule selects, or `None` past the calendar.
fn rule_day_of_year(day: RuleDay, year: i64) -> Option<i64> {
    match day {
        RuleDay::MonthWeekDay {
            month,
            week,
            weekday,
        } => {
            let first = days_from_civil(year, month, 1)?;
            // 1970-01-01 was a Thursday, which is weekday 4 counting from
            // Sunday, so the epoch day number shifted by four gives the day.
            let first_weekday = i32::try_from((first + 4).rem_euclid(7)).ok()?;
            let delta = (weekday - first_weekday).rem_euclid(7);
            let mut date = 1 + delta + (week - 1) * 7;
            // Only a fifth week can overshoot; POSIX defines it as the last.
            while date > days_in_month(year, month) {
                date -= 7;
            }
            Some(days_from_civil(year, month, date)? - days_from_civil(year, 1, 1)?)
        }
        RuleDay::JulianNoLeap(day) => {
            let leap = i64::from(is_leap_year(year) && day >= 60);
            Some(i64::from(day - 1) + leap)
        }
        RuleDay::ZeroBasedDay(day) => Some(i64::from(day)),
    }
}

/// UTC instant of one transition, given the offset in effect just before it.
fn transition_instant(transition: Transition, year: i64, before_offset: i32) -> Option<i64> {
    let day = days_from_civil(year, 1, 1)?.checked_add(rule_day_of_year(transition.day, year)?)?;
    day.checked_mul(86_400)?
        .checked_add(i64::from(transition.seconds))?
        .checked_sub(i64::from(before_offset))
}

/// Gregorian year containing one epoch-second count read as UTC.
fn civil_year(seconds: i64) -> i64 {
    civil_from_days(floor_divide(seconds, 86_400)).0
}

fn standard_state(zone: &TimeZone) -> ZoneOffset {
    ZoneOffset {
        seconds_east: zone.standard_offset(),
        is_daylight: false,
        abbreviation: zone.standard_abbreviation(),
    }
}

const fn daylight_state(daylight: Daylight) -> ZoneOffset {
    ZoneOffset {
        seconds_east: daylight.offset,
        is_daylight: true,
        abbreviation: daylight.abbreviation,
    }
}

/// The zone state in effect at one Unix instant.
#[must_use]
pub fn offset_at(zone: &TimeZone, unix_seconds: i64) -> ZoneOffset {
    let Some(daylight) = zone.daylight() else {
        return standard_state(zone);
    };
    // The rules repeat every year, so the year of the instant read in standard
    // time selects the pair of transitions to compare against.
    let local = unix_seconds.saturating_add(i64::from(zone.standard_offset()));
    let year = civil_year(local);
    let (Some(start), Some(end)) = (
        transition_instant(daylight.start, year, zone.standard_offset()),
        transition_instant(daylight.end, year, daylight.offset),
    ) else {
        return standard_state(zone);
    };
    // A start that follows its end is the southern hemisphere, where the
    // daylight period wraps the year boundary rather than being an error.
    let active = if start <= end {
        unix_seconds >= start && unix_seconds < end
    } else {
        unix_seconds >= start || unix_seconds < end
    };
    if active {
        daylight_state(daylight)
    } else {
        standard_state(zone)
    }
}

/// Resolve a naive local wall time to a Unix instant and its zone state.
///
/// `local_seconds` counts seconds from the epoch as though the wall-clock
/// fields were UTC. `is_daylight` follows the POSIX `tm_isdst` convention:
/// above zero selects the daylight offset, zero selects standard, and below
/// zero determines the state from the rules.
///
/// A local time inside a spring-forward gap resolves through the offset in
/// effect before the transition, so the instant returned lands after it. A
/// local time inside a fall-back overlap resolves to its first occurrence.
#[must_use]
pub fn unix_from_local(zone: &TimeZone, local_seconds: i64, is_daylight: i32) -> (i64, ZoneOffset) {
    let Some(daylight) = zone.daylight() else {
        let instant = local_seconds.saturating_sub(i64::from(zone.standard_offset()));
        return (instant, standard_state(zone));
    };
    let standard_candidate = local_seconds.saturating_sub(i64::from(zone.standard_offset()));
    let daylight_candidate = local_seconds.saturating_sub(i64::from(daylight.offset));
    let instant = match is_daylight {
        0 => standard_candidate,
        value if value > 0 => daylight_candidate,
        _ => {
            let standard_fits = !offset_at(zone, standard_candidate).is_daylight;
            let daylight_fits = offset_at(zone, daylight_candidate).is_daylight;
            match (standard_fits, daylight_fits) {
                (true, false) => standard_candidate,
                (false, true) => daylight_candidate,
                // Ambiguous: the first occurrence is the earlier instant, which
                // is the one read through the larger offset.
                (true, true) => standard_candidate.min(daylight_candidate),
                // Nonexistent: the offset in effect before the transition is the
                // smaller one, giving the later instant.
                (false, false) => standard_candidate.max(daylight_candidate),
            }
        }
    };
    (instant, offset_at(zone, instant))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{TimeZone, offset_at, parse_str, unix_from_local};

    /// United States Eastern, whose 2026 transitions the fixtures below use.
    const EASTERN: &str = "EST5EDT,M3.2.0,M11.1.0";
    /// 2026-03-08T07:00:00Z, the instant Eastern enters daylight time.
    const EASTERN_START: i64 = 1_772_953_200;
    /// 2026-11-01T06:00:00Z, the instant Eastern leaves daylight time.
    const EASTERN_END: i64 = 1_793_512_800;

    fn zone(text: &str) -> TimeZone {
        parse_str(text).unwrap_or_else(|_| std::process::abort())
    }

    #[test]
    fn transitions_land_on_the_exact_second() {
        let eastern = zone(EASTERN);
        for (instant, daylight, abbreviation, offset) in [
            (EASTERN_START - 1, false, &b"EST"[..], -5 * 3600),
            (EASTERN_START, true, &b"EDT"[..], -4 * 3600),
            (EASTERN_END - 1, true, &b"EDT"[..], -4 * 3600),
            (EASTERN_END, false, &b"EST"[..], -5 * 3600),
            // 2026-01-15T12:00:00Z and 2026-07-15T12:00:00Z.
            (1_768_478_400, false, &b"EST"[..], -5 * 3600),
            (1_784_116_800, true, &b"EDT"[..], -4 * 3600),
        ] {
            let state = offset_at(&eastern, instant);
            assert_eq!(state.is_daylight, daylight, "at {instant}");
            assert_eq!(state.abbreviation.as_bytes(), abbreviation, "at {instant}");
            assert_eq!(state.seconds_east, offset, "at {instant}");
        }
    }

    #[test]
    fn a_daylight_period_that_wraps_the_year_is_ordinary() {
        // Australian Eastern: daylight runs October through April, so its
        // start follows its end within any single year.
        let sydney = zone("AEST-10AEDT,M10.1.0,M4.1.0/3");
        for (instant, daylight, offset) in [
            // 2026-10-03T16:00:00Z, the start, and the second before it.
            (1_791_043_200 - 1, false, 10 * 3600),
            (1_791_043_200, true, 11 * 3600),
            // 2026-04-04T16:00:00Z, the end, and the second before it.
            (1_775_318_400 - 1, true, 11 * 3600),
            (1_775_318_400, false, 10 * 3600),
            // Midsummer south of the equator is inside the wrapped period.
            (1_768_478_400, true, 11 * 3600),
        ] {
            let state = offset_at(&sydney, instant);
            assert_eq!(state.is_daylight, daylight, "at {instant}");
            assert_eq!(state.seconds_east, offset, "at {instant}");
        }
    }

    #[test]
    fn the_fifth_week_selects_the_last_such_weekday() {
        // European Union rules: the last Sunday of March and of October, which
        // in 2026 are the 29th and the 25th. Both land at 01:00 UTC, but only
        // because each transition time is read in the offset before it: 01:00
        // standard in March, and the default 02:00 daylight in October.
        let london = zone("GMT0BST,M3.5.0/1,M10.5.0");
        assert!(!offset_at(&london, 1_774_746_000 - 1).is_daylight);
        assert!(offset_at(&london, 1_774_746_000).is_daylight);
        assert!(offset_at(&london, 1_792_890_000 - 1).is_daylight);
        assert!(!offset_at(&london, 1_792_890_000).is_daylight);
    }

    #[test]
    fn julian_and_zero_based_days_differ_across_february() {
        // `J60` is March 1 in every year because it never counts February 29.
        // Bare `60` counts it, so it is March 1 in a leap year and March 2
        // otherwise. Both rules start at 00:00 UTC in a zone with no offset.
        let julian = zone("XXX0YYY0,J60/0,J300/0");
        let zero_based = zone("XXX0YYY0,60/0,300/0");
        // 2024-03-01T00:00:00Z and 2026-03-01T00:00:00Z.
        for start in [1_709_251_200_i64, 1_772_323_200] {
            assert!(!offset_at(&julian, start - 1).is_daylight, "at {start}");
            assert!(offset_at(&julian, start).is_daylight, "at {start}");
        }
        assert!(offset_at(&zero_based, 1_709_251_200).is_daylight);
        // 2026-03-02T00:00:00Z, one day later than the Julian rule.
        assert!(!offset_at(&zero_based, 1_772_323_200).is_daylight);
        assert!(offset_at(&zero_based, 1_772_409_600).is_daylight);
    }

    #[test]
    fn gaps_and_overlaps_resolve_as_decided() {
        let eastern = zone(EASTERN);
        // 2026-03-08T02:30 local, inside the spring gap, does not exist. The
        // offset in effect before the transition resolves it to 03:30 EDT.
        let (instant, state) = unix_from_local(&eastern, 1_772_937_000, -1);
        assert_eq!(instant, 1_772_955_000);
        assert!(state.is_daylight);
        assert!(instant > EASTERN_START);

        // 2026-11-01T01:30 local occurs twice. Determining the state selects
        // the first occurrence, which is the one still in daylight time.
        let (first, state) = unix_from_local(&eastern, 1_793_496_600, -1);
        assert_eq!(first, 1_793_511_000);
        assert!(state.is_daylight);
        assert!(first < EASTERN_END);

        // An explicit `tm_isdst` overrides the determination in both states.
        assert_eq!(unix_from_local(&eastern, 1_793_496_600, 1).0, 1_793_511_000);
        assert_eq!(unix_from_local(&eastern, 1_793_496_600, 0).0, 1_793_514_600);

        // Away from a transition every state agrees. 2026-07-15T12:00 local.
        let (summer, state) = unix_from_local(&eastern, 1_784_116_800, -1);
        assert_eq!(summer, 1_784_116_800 + 4 * 3600);
        assert!(state.is_daylight);
        assert_eq!(offset_at(&eastern, summer).seconds_east, -4 * 3600);
    }

    #[test]
    fn a_zone_without_rules_reports_one_state_at_every_instant() {
        // The grammar's refusals are pinned where the grammar lives; what
        // matters here is that evaluating the fallback never varies.
        let fallback = TimeZone::parse_or_utc(b":America/New_York");
        assert_eq!(fallback, TimeZone::utc());
        for instant in [-2_208_988_800_i64, 0, 1_768_478_400, 1_784_116_800] {
            let state = offset_at(&fallback, instant);
            assert_eq!(state.seconds_east, 0);
            assert!(!state.is_daylight);
            assert_eq!(state.abbreviation.as_bytes(), b"UTC");
        }
        let Ok(india) = parse_str("<+0530>-5:30") else {
            std::process::abort();
        };
        assert_eq!(
            offset_at(&india, 1_768_478_400).seconds_east,
            5 * 3600 + 1800
        );
        assert_eq!(
            unix_from_local(&india, 1_768_478_400, -1).0,
            1_768_478_400 - (5 * 3600 + 1800)
        );
    }

    #[test]
    fn conversion_round_trips_across_the_representable_range() {
        let eastern = zone(EASTERN);
        // A negative timestamp predates the epoch and still resolves.
        for instant in [-2_208_988_800_i64, -1, 0, 1_768_478_400, 1_784_116_800] {
            let state = offset_at(&eastern, instant);
            let local = instant + i64::from(state.seconds_east);
            let (returned, _) = unix_from_local(&eastern, local, i32::from(state.is_daylight));
            assert_eq!(returned, instant, "at {instant}");
        }
    }
}

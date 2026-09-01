//! DOS date and time stamps in FAT32 directory entries.

use crate::read_u16;
use troe_fs_api::FsError;

/// Short-entry offset of the creation time's tenths-of-a-second remainder.
pub(crate) const DIRECTORY_CREATE_TENTHS: usize = 13;
/// Short-entry offset of the creation time and date pair.
pub(crate) const DIRECTORY_CREATE_TIME: usize = 14;
/// Short-entry offset of the last-access date, which has no time part.
pub(crate) const DIRECTORY_ACCESS_DATE: usize = 18;
/// Short-entry offset of the last-write time and date pair.
pub(crate) const DIRECTORY_WRITE_TIME: usize = 22;
/// Short-entry byte ranges holding timestamps. They are disjoint because the
/// high half of the first cluster sits between the access date and the write
/// time.
const DIRECTORY_STAMP_RANGES: [core::ops::Range<usize>; 2] =
    [DIRECTORY_CREATE_TENTHS..20, DIRECTORY_WRITE_TIME..26];
/// First instant a FAT date encodes: its year field counts from 1980.
pub(crate) const DOS_EPOCH_SECONDS: u64 = 315_532_800;
/// Last instant a FAT date encodes, 2107-12-31T23:59:58, at the two-second
/// granularity of the write time.
pub(crate) const DOS_LAST_SECONDS: u64 = 4_354_819_198;
/// Seconds in one day, the step between DOS date fields.
const SECONDS_PER_DAY: u64 = 86_400;
/// One instant already reduced to the fields a FAT directory entry stores.
///
/// FAT records local time with no timezone field. A zone belongs to a launch
/// rather than to a mount, and this provider stamps writes on behalf of any
/// process, so there is no single offset it could apply. The wall clock's UTC
/// reading is written unconverted and a host reading the volume sees UTC.
/// Inventing an offset would be a guess, and a wrong one would be
/// indistinguishable from a correct one on the media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DosStamp {
    /// Year from 1980, month, and day, packed as FAT stores them.
    pub(crate) date: u16,
    /// Hour, minute, and seconds/2: the write time's granularity is 2 seconds.
    pub(crate) time: u16,
    /// The second the packed time cannot express, in tenths.
    pub(crate) tenths: u8,
}

impl DosStamp {
    /// Reduce a Unix UTC instant to the FAT fields, clamped to what FAT can
    /// encode.
    ///
    /// The representable range is 1980-01-01 through 2107-12-31. A clock
    /// outside it is clamped to the nearer end rather than refused, because a
    /// refusal would leave the fields zero and a zero DOS date is not an old
    /// date but an invalid one that `fsck.vfat` reports.
    pub(crate) fn from_unix_seconds(seconds: u64) -> Result<Self, FsError> {
        let seconds = seconds.clamp(DOS_EPOCH_SECONDS, DOS_LAST_SECONDS);
        let (year, month, day) = civil_from_days(seconds / SECONDS_PER_DAY)?;
        let day_seconds = seconds % SECONDS_PER_DAY;
        let hour = u16::try_from(day_seconds / 3_600).map_err(|_| FsError::Overflow)?;
        let minute = u16::try_from((day_seconds % 3_600) / 60).map_err(|_| FsError::Overflow)?;
        let second = u16::try_from(day_seconds % 60).map_err(|_| FsError::Overflow)?;
        let from_1980 = year.checked_sub(1980).ok_or(FsError::Overflow)?;
        Ok(Self {
            date: (from_1980 << 9) | (month << 5) | day,
            time: (hour << 11) | (minute << 5) | (second / 2),
            tenths: u8::try_from((second % 2) * 10).map_err(|_| FsError::Overflow)?,
        })
    }

    /// Recover the Unix UTC instant this stamp encodes.
    ///
    /// A zero date is an absent time rather than 1980: a FAT entry that was
    /// never stamped keeps the zeroes it was created with, and ADR 0058 leaves
    /// them exactly so whenever no wall time is known. FAT records the write
    /// time to two seconds, so the tenths field is not consulted.
    pub(crate) fn to_unix_seconds(self) -> Result<Option<u64>, FsError> {
        if self.date == 0 {
            return Ok(None);
        }
        let year = (self.date >> 9) + 1980;
        let month = (self.date >> 5) & 0xf;
        let day = self.date & 0x1f;
        let hour = u64::from(self.time >> 11);
        let minute = u64::from((self.time >> 5) & 0x3f);
        let second = u64::from((self.time & 0x1f) * 2);
        if hour > 23 || minute > 59 || second > 59 {
            return Err(FsError::Corrupt);
        }
        let days = days_from_civil(year, month, day)?;
        days.checked_mul(SECONDS_PER_DAY)
            .and_then(|seconds| seconds.checked_add(hour * 3_600))
            .and_then(|seconds| seconds.checked_add(minute * 60))
            .and_then(|seconds| seconds.checked_add(second))
            .map(Some)
            .ok_or(FsError::Overflow)
    }

    /// Read one directory entry's write time.
    pub(crate) fn read_modification(raw: &[u8]) -> Result<Option<u64>, FsError> {
        Self {
            date: read_u16(raw, DIRECTORY_WRITE_TIME + 2)?,
            time: read_u16(raw, DIRECTORY_WRITE_TIME)?,
            tenths: 0,
        }
        .to_unix_seconds()
    }

    /// Read one directory entry's creation time.
    ///
    /// The tenths byte carries the odd second the two-second time field cannot,
    /// so it is folded in rather than dropped.
    pub(crate) fn read_creation(raw: &[u8]) -> Result<Option<u64>, FsError> {
        let tenths = *raw.get(DIRECTORY_CREATE_TENTHS).ok_or(FsError::Corrupt)?;
        let Some(seconds) = (Self {
            date: read_u16(raw, DIRECTORY_CREATE_TIME + 2)?,
            time: read_u16(raw, DIRECTORY_CREATE_TIME)?,
            tenths,
        })
        .to_unix_seconds()?
        else {
            return Ok(None);
        };
        Ok(Some(seconds + u64::from(tenths) / 100))
    }

    /// Stamp this instant as an entry's creation time, and as the access date.
    pub(crate) fn write_creation(self, raw: &mut [u8]) -> Result<(), FsError> {
        *raw.get_mut(DIRECTORY_CREATE_TENTHS)
            .ok_or(FsError::Corrupt)? = self.tenths;
        put_u16_at(raw, DIRECTORY_CREATE_TIME, self.time)?;
        put_u16_at(raw, DIRECTORY_CREATE_TIME + 2, self.date)?;
        put_u16_at(raw, DIRECTORY_ACCESS_DATE, self.date)
    }

    /// Stamp this instant as an entry's last-write time, and as the access
    /// date, which FAT records to the day only.
    pub(crate) fn write_modification(self, raw: &mut [u8]) -> Result<(), FsError> {
        put_u16_at(raw, DIRECTORY_WRITE_TIME, self.time)?;
        put_u16_at(raw, DIRECTORY_WRITE_TIME + 2, self.date)?;
        put_u16_at(raw, DIRECTORY_ACCESS_DATE, self.date)
    }
}

/// Carry an entry's timestamps to the record that replaces it.
///
/// Renaming a name does not change when its contents were created or written,
/// so the new record inherits both stamps instead of taking a fresh one.
pub(crate) fn copy_timestamps(source: &[u8], destination: &mut [u8]) -> Result<(), FsError> {
    for range in DIRECTORY_STAMP_RANGES {
        let bytes = source.get(range.clone()).ok_or(FsError::Corrupt)?;
        destination
            .get_mut(range)
            .ok_or(FsError::Corrupt)?
            .copy_from_slice(bytes);
    }
    Ok(())
}

/// Split a day count since 1970-01-01 into its proleptic Gregorian date.
///
/// The era arithmetic is the standard shift of the year's origin to March, so
/// that a leap day falls at the end of a cycle and every month before it has a
/// fixed length.
/// Days since the Unix epoch for one proleptic Gregorian date.
///
/// The exact inverse of [`civil_from_days`], so a stamp written from an instant
/// and read back reports the same instant to FAT's two-second granularity.
pub(crate) fn days_from_civil(year: u16, month: u16, day: u16) -> Result<u64, FsError> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(FsError::Corrupt);
    }
    // The algorithm counts from March so a leap day lands at the end of a year.
    let year = u64::from(year) - u64::from(month <= 2);
    let era = year / 400;
    let year_of_era = year - era * 400;
    let month = u64::from(month);
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + u64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)
        .and_then(|days| days.checked_add(day_of_era))
        .and_then(|days| days.checked_sub(719_468))
        .ok_or(FsError::Overflow)
}

pub(crate) fn civil_from_days(days: u64) -> Result<(u16, u16, u16), FsError> {
    let shifted = days.checked_add(719_468).ok_or(FsError::Overflow)?;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    // A March-based year rolls over at January, not at the shifted origin.
    let year = if month <= 2 { year + 1 } else { year };
    Ok((
        u16::try_from(year).map_err(|_| FsError::Overflow)?,
        u16::try_from(month).map_err(|_| FsError::Overflow)?,
        u16::try_from(day).map_err(|_| FsError::Overflow)?,
    ))
}

fn put_u16_at(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), FsError> {
    bytes
        .get_mut(offset..offset.checked_add(2).ok_or(FsError::Overflow)?)
        .ok_or(FsError::Corrupt)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::time::{
        DOS_EPOCH_SECONDS, DOS_LAST_SECONDS, DosStamp, civil_from_days, days_from_civil,
    };
    use troe_fs_api::FsError;

    #[test]
    fn dos_stamps_round_trip_and_report_an_unstamped_entry_as_absent() -> Result<(), FsError> {
        // Every instant FAT can express reads back as the same instant, to the
        // two-second granularity the write time records.
        for seconds in [
            DOS_EPOCH_SECONDS,
            DOS_EPOCH_SECONDS + 59,
            1_788_000_000,
            1_788_000_001,
            DOS_LAST_SECONDS,
        ] {
            let stamp = DosStamp::from_unix_seconds(seconds)?;
            let expected = seconds - seconds % 2;
            assert_eq!(
                stamp.to_unix_seconds()?,
                Some(expected),
                "round trip at {seconds}"
            );
        }
        // A zero date is an entry that was never stamped, not 1980.
        assert_eq!(
            DosStamp {
                date: 0,
                time: 0,
                tenths: 0
            }
            .to_unix_seconds()?,
            None
        );
        // A month or day outside its field is corrupt rather than clamped.
        assert!(
            DosStamp {
                date: 0x21 | (0xd << 5),
                time: 0,
                tenths: 0
            }
            .to_unix_seconds()
            .is_err()
        );
        // The civil conversion is the exact inverse of the forward one.
        for day in [0_u64, 1, 3_652, 20_000, 50_000] {
            let (year, month, date) = civil_from_days(day)?;
            assert_eq!(days_from_civil(year, month, date)?, day, "day {day}");
        }
        Ok(())
    }

    #[test]
    fn dos_stamps_encode_the_fat_range_and_clamp_outside_it() -> Result<(), FsError> {
        // 1980-01-01T00:00:00, the first instant a FAT date can express.
        assert_eq!(
            DosStamp::from_unix_seconds(DOS_EPOCH_SECONDS)?,
            DosStamp {
                date: 33,
                time: 0,
                tenths: 0
            }
        );
        // 2026-08-29T10:40:00, an ordinary instant well inside the range.
        assert_eq!(
            DosStamp::from_unix_seconds(1_788_000_000)?,
            DosStamp {
                date: 23_837,
                time: 21_760,
                tenths: 0
            }
        );
        // The write time counts two-second units, so the odd second is carried
        // by the creation entry's tenths field instead.
        assert_eq!(
            DosStamp::from_unix_seconds(1_788_000_001)?,
            DosStamp {
                date: 23_837,
                time: 21_760,
                tenths: 10
            }
        );
        // 2107-12-31T23:59:58, the last instant a FAT date can express.
        assert_eq!(
            DosStamp::from_unix_seconds(DOS_LAST_SECONDS)?,
            DosStamp {
                date: 65_439,
                time: 49_021,
                tenths: 0
            }
        );
        // Outside the range the stamp clamps rather than encoding a year the
        // field cannot hold; a zero date would be invalid, not merely old.
        assert_eq!(
            DosStamp::from_unix_seconds(0)?,
            DosStamp::from_unix_seconds(DOS_EPOCH_SECONDS)?
        );
        assert_eq!(
            DosStamp::from_unix_seconds(u64::MAX)?,
            DosStamp::from_unix_seconds(DOS_LAST_SECONDS)?
        );
        Ok(())
    }
}

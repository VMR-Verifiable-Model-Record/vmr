//! UTC timestamps in the v0.1 profile `YYYY-MM-DDTHH:MM:SSZ`.
// ============================================================================
//  timestamp.rs — the record's one time format (spec §2 rule 7, D4 (a))
//
//  Every time-bearing string in a record or a trust store, and the
//  verifier's evaluation time, is exactly `YYYY-MM-DDTHH:MM:SSZ`: 20 ASCII
//  characters, a date of the proleptic Gregorian calendar (years 0000-9999,
//  real month lengths, 29 February only in leap years), 00-23 hours, 00-59
//  minutes and seconds — no leap second, no fraction, no offset, upper-case
//  T and Z. In that profile lexical order is chronological order, and every
//  instant has exactly one text.
//
//  Parsing turns the text into seconds since 1970-01-01T00:00:00Z (an i64,
//  negative before 1970) with integer arithmetic only. Nothing here reads a
//  clock: a Timestamp is always a caller's value (Law 1).
// ============================================================================

use crate::validate::FormatViolation;

/// A UTC instant with one-second resolution, from the v0.1 timestamp profile
/// `YYYY-MM-DDTHH:MM:SSZ` (spec §2 rule 7). Ordered chronologically;
/// `Display` gives back the profile text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Seconds since 1970-01-01T00:00:00Z.
    unix: i64,
}

/// Seconds since the epoch of 0000-01-01T00:00:00Z and of
/// 9999-12-31T23:59:59Z: the range the profile can write.
const MIN_UNIX: i64 = -62_167_219_200;
const MAX_UNIX: i64 = 253_402_300_799;
const SECONDS_PER_DAY: i64 = 86_400;

impl Timestamp {
    /// Parse a profile timestamp. Anything else — another RFC 3339 form, a
    /// date that does not exist, 24:00:00, a leap second — is a
    /// [`FormatViolation`] with rule `timestamp`.
    pub fn parse(text: &str) -> Result<Self, FormatViolation> {
        let bad = |why: &str| {
            Err(FormatViolation::new(
                "",
                "timestamp",
                format!(
                    "{} is not a UTC timestamp YYYY-MM-DDTHH:MM:SSZ: {why}",
                    crate::validate::quote(text)
                ),
            ))
        };
        let b = text.as_bytes();
        let shape_ok = b.len() == 20
            && b.iter().enumerate().all(|(i, &c)| match i {
                4 | 7 => c == b'-',
                10 => c == b'T',
                13 | 16 => c == b':',
                19 => c == b'Z',
                _ => c.is_ascii_digit(),
            });
        if !shape_ok {
            return bad("wrong shape (exactly 20 characters, digits, '-', 'T', ':', 'Z')");
        }
        // Every byte read below is an ASCII digit (checked above); reading by
        // iterator, not by slice, keeps this code free of panic paths.
        let num = |from: usize, to: usize| -> i64 {
            b.iter()
                .skip(from)
                .take(to - from)
                .fold(0, |acc, &c| acc * 10 + i64::from(c.wrapping_sub(b'0')))
        };
        let (year, month, day) = (num(0, 4), num(5, 7), num(8, 10));
        let (hour, minute, second) = (num(11, 13), num(14, 16), num(17, 19));
        if !(1..=12).contains(&month) {
            return bad("the month is not 01-12");
        }
        if day < 1 || day > days_in_month(year, month) {
            return bad("the date is not in the calendar");
        }
        if hour > 23 {
            return bad("the hour is not 00-23");
        }
        if minute > 59 {
            return bad("the minute is not 00-59");
        }
        if second > 59 {
            return bad("the second is not 00-59 (no leap seconds)");
        }
        let days = days_from_civil(year, month, day);
        Ok(Timestamp {
            unix: days * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second,
        })
    }

    /// The instant `unix` seconds after 1970-01-01T00:00:00Z, or `None` when
    /// it falls outside the years 0000–9999 the profile can write.
    pub fn from_unix_seconds(unix: i64) -> Option<Self> {
        (MIN_UNIX..=MAX_UNIX).contains(&unix).then_some(Timestamp { unix })
    }

    /// Seconds since 1970-01-01T00:00:00Z (negative before).
    pub fn unix_seconds(self) -> i64 {
        self.unix
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let days = self.unix.div_euclid(SECONDS_PER_DAY);
        let secs = self.unix.rem_euclid(SECONDS_PER_DAY);
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        )
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to the proleptic Gregorian date `y-m-d` (Howard
/// Hinnant's days_from_civil, integer-only; exact for all years here).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

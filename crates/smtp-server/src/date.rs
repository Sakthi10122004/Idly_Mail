//! RFC 5322 §3.3 date-time, for the Received header, without a date library.

use std::time::{SystemTime, UNIX_EPOCH};

const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Formats `t` in UTC, e.g. `Sat, 31 Oct 2026 13:53:06 +0000`.
/// RFC 5322 §3.3: `date-time = [ day-of-week "," ] date time [CFWS]`.
pub(crate) fn rfc5322(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday.
    let dow = DAYS
        .get(usize::try_from(days % 7).unwrap_or(0))
        .copied()
        .unwrap_or("Thu");
    let mon = MONTHS
        .get(usize::try_from(month.saturating_sub(1)).unwrap_or(0))
        .copied()
        .unwrap_or("Jan");
    format!(
        "{dow}, {day} {mon} {year} {:02}:{:02}:{:02} +0000",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month 1–12, day 1–31), proleptic
/// Gregorian. Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> String {
        rfc5322(UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[test]
    fn known_dates() {
        assert_eq!(at(0), "Thu, 1 Jan 1970 00:00:00 +0000");
        // 2000-02-29 (leap day in a century leap year) 12:34:56 UTC.
        assert_eq!(at(951_827_696), "Tue, 29 Feb 2000 12:34:56 +0000");
        // 2026-10-31 13:53:06 UTC.
        assert_eq!(at(1_793_454_786), "Sat, 31 Oct 2026 13:53:06 +0000");
        // 2100-03-01, after a non-leap century February.
        assert_eq!(at(4_107_542_400), "Mon, 1 Mar 2100 00:00:00 +0000");
    }
}

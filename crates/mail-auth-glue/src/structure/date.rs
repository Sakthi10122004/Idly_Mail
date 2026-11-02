//! The Date header field (RFC 5322 §3.3, with the obsolete forms of §4.3:
//! two- and three-digit years, named zones). Lenient: comments and a
//! missing weekday or seconds are fine.

/// Seconds since the Unix epoch (UTC), or None if it isn't a date.
pub fn parse(value: &str) -> Option<i64> {
    // Drop comments and a leading "Day,".
    let mut text = String::with_capacity(value.len());
    let mut depth = 0u32;
    for c in value.chars() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            _ if depth > 0 => {}
            ',' => text.push(' '),
            _ => text.push(c),
        }
    }
    let mut tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens
        .first()
        .is_some_and(|t| t.chars().all(char::is_alphabetic))
    {
        tokens.remove(0);
    }
    let day: i64 = tokens.first()?.parse().ok()?;
    let month = month(tokens.get(1)?)?;
    let year = year(tokens.get(2)?)?;
    let mut hms = tokens.get(3)?.split(':');
    let hour: i64 = hms.next()?.parse().ok()?;
    let minute: i64 = hms.next()?.parse().ok()?;
    let second: i64 = hms.next().map_or(Some(0), |s| s.parse().ok())?;
    let offset = tokens.get(4).map_or(Some(0), |z| zone(z))?;
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

fn month(m: &str) -> Option<i64> {
    let names = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let m = m.get(..3)?.to_ascii_lowercase();
    names.iter().position(|n| *n == m).map(|i| i as i64 + 1)
}

/// RFC 5322 §4.3: 2-digit years below 50 are 20xx, others 19xx; 3-digit
/// years add 1900.
fn year(y: &str) -> Option<i64> {
    let n: i64 = y.parse().ok()?;
    Some(match y.len() {
        2 if n < 50 => 2000 + n,
        2 => 1900 + n,
        3 => 1900 + n,
        4 => n,
        _ => return None,
    })
}

/// Zone offset in seconds east of UTC.
fn zone(z: &str) -> Option<i64> {
    if let Some(sign) = z.chars().next().filter(|c| *c == '+' || *c == '-') {
        let digits = z.get(1..)?;
        if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let hh: i64 = digits.get(..2)?.parse().ok()?;
        let mm: i64 = digits.get(2..)?.parse().ok()?;
        let secs = hh * 3600 + mm * 60;
        return Some(if sign == '-' { -secs } else { secs });
    }
    // RFC 5322 §4.3 obs-zone; unknown names count as UTC ("-0000").
    Some(match z.to_ascii_uppercase().as_str() {
        "EDT" => -4 * 3600,
        "EST" | "CDT" => -5 * 3600,
        "CST" | "MDT" => -6 * 3600,
        "MST" | "PDT" => -7 * 3600,
        "PST" => -8 * 3600,
        _ => 0,
    })
}

/// Days since 1970-01-01 (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5322_dates() {
        // RFC 5322 Appendix A.1.1.
        assert_eq!(parse("Fri, 21 Nov 1997 09:55:06 -0600"), Some(880_127_706));
        assert_eq!(parse("21 Nov 97 09:55:06 GMT"), Some(880_106_106));
        assert_eq!(parse("Mon, 2 Nov 2026 10:00:00 +0000"), Some(1_793_613_600));
        assert_eq!(
            parse("Thu,\r\n 13\r\n Feb\r\n 1969\r\n 23:32\r\n -0330 (Newfoundland Time)"),
            Some(-27_723_480)
        );
        assert_eq!(parse("1 Jan 2000 00:00:00 EST"), Some(946_702_800));
    }

    #[test]
    fn garbage() {
        for v in [
            "",
            "yesterday",
            "32 Jan 2000 00:00",
            "1 Foo 2000 00:00",
            "1 Jan 2000 25:00",
            "1 Jan 20000 00:00",
            "1 Jan 2000 00:00 +99",
        ] {
            assert_eq!(parse(v), None, "{v}");
        }
    }
}

use alloc::{format, string::String, string::ToString, vec::Vec};

/// Formats a Unix timestamp as a UTC date or datetime string.
/// When the time component is midnight (00:00:00 UTC), returns `"YYYY-MM-DD"`.
/// Otherwise returns `"YYYY-MM-DD HH:MM:SS"`.
pub(super) fn format_utc_date(timestamp: u32) -> String {
    // Uses Howard Hinnant's civil-from-days algorithm.
    let days = timestamp / 86400;
    let time_of_day = timestamp % 86400;
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    if time_of_day == 0 {
        format!("{:04}-{:02}-{:02}", y, m, d)
    } else {
        let h = time_of_day / 3600;
        let min = (time_of_day % 3600) / 60;
        let sec = time_of_day % 60;
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, h, min, sec)
    }
}

/// Parses a UTC date/datetime string as produced by [`format_utc_date`].
/// Accepts `"YYYY-MM-DD"` (midnight UTC) and `"YYYY-MM-DD HH:MM:SS"`.
/// Returns `None` if the string is malformed or the timestamp does not fit in `u32`.
#[cfg(test)]
pub(super) fn parse_utc_date_to_timestamp(s: &str) -> Option<u32> {
    let (date_str, time_str) = match s.find(' ') {
        Some(pos) => (&s[..pos], Some(&s[pos + 1..])),
        None => (s, None),
    };

    // Parse "YYYY-MM-DD"
    let dp: Vec<&str> = date_str.splitn(3, '-').collect();
    if dp.len() != 3 {
        return None;
    }
    let y: i64 = dp[0].parse().ok()?;
    let m: u32 = dp[1].parse().ok()?;
    let d: u32 = dp[2].parse().ok()?;
    if m < 1 || m > 12 || d < 1 || d > 31 {
        return None;
    }

    // Parse optional "HH:MM:SS"
    let time_of_day: i64 = match time_str {
        Some(t) => {
            let tp: Vec<&str> = t.splitn(3, ':').collect();
            if tp.len() != 3 {
                return None;
            }
            let h: u32 = tp[0].parse().ok()?;
            let min: u32 = tp[1].parse().ok()?;
            let sec: u32 = tp[2].parse().ok()?;
            if h >= 24 || min >= 60 || sec >= 60 {
                return None;
            }
            (h * 3600 + min * 60 + sec) as i64
        }
        None => 0,
    };

    let days = days_from_civil(y, m, d);
    let timestamp = days.checked_mul(86400)?.checked_add(time_of_day)?;
    u32::try_from(timestamp).ok()
}

/// Formats a number of seconds as a human-readable duration string.
/// Uses units `d` (days), `h` (hours), `m` (minutes), `s` (seconds).
/// Returns `"0s"` for zero. Example: `"1d 2h 30m"`.
pub(super) fn format_seconds(secs: u32) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    let mut parts: Vec<String> = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if seconds > 0 {
        parts.push(format!("{}s", seconds));
    }
    if parts.is_empty() {
        "0s".to_string()
    } else {
        parts.join(" ")
    }
}

/// Parses a human-readable duration string as produced by [`format_seconds`].
/// Accepts strings like `"0s"`, `"1d 2h 3m 4s"`, `"1h 30m"`, etc.
/// Parts must appear in decreasing order (d, h, m, s) without duplicates.
/// Returns `None` if the string is malformed or the total would overflow `u32`.
#[cfg(test)]
pub(super) fn parse_relative_time_to_seconds(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut total: u32 = 0;
    let mut last_unit: u8 = 0; // d=1, h=2, m=3, s=4; enforces ordering
    for token in s.split_ascii_whitespace() {
        // Use the last byte (must be an ASCII unit letter) to identify the unit.
        let unit_byte = *token.as_bytes().last()?;
        let unit: u8 = match unit_byte {
            b'd' => 1,
            b'h' => 2,
            b'm' => 3,
            b's' => 4,
            _ => return None,
        };
        if unit <= last_unit {
            return None; // out of order or duplicate unit
        }
        last_unit = unit;
        // The number occupies all bytes except the last (which is the ASCII unit letter).
        let num_str = &token[..token.len() - 1];
        let n: u32 = num_str.parse().ok()?;
        let secs = match unit_byte {
            b'd' => n.checked_mul(86400)?,
            b'h' => n.checked_mul(3600)?,
            b'm' => n.checked_mul(60)?,
            b's' => n,
            _ => unreachable!(),
        };
        total = total.checked_add(secs)?;
    }
    if last_unit == 0 {
        return None; // nothing was parsed
    }
    Some(total)
}

/// Inverse of the civil-from-days algorithm: given a (year, month, day) triple,
/// returns the number of days since the Unix epoch (1970-01-01).
#[cfg(test)]
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_utc_date ──────────────────────────────────────────────────────

    #[test]
    fn test_format_utc_date_known() {
        assert_eq!(format_utc_date(0), "1970-01-01");
        assert_eq!(format_utc_date(86400), "1970-01-02");
        assert_eq!(format_utc_date(86399), "1970-01-01 23:59:59");
        assert_eq!(format_utc_date(500_000_000), "1985-11-05 00:53:20");
        assert_eq!(format_utc_date(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(format_utc_date(1_609_459_200), "2021-01-01"); // midnight
        assert_eq!(format_utc_date(1_582_934_400), "2020-02-29"); // leap day, midnight
    }

    // ── parse_utc_date_to_timestamp ──────────────────────────────────────────

    #[test]
    fn test_parse_utc_date_known() {
        assert_eq!(parse_utc_date_to_timestamp("1970-01-01"), Some(0));
        assert_eq!(parse_utc_date_to_timestamp("1970-01-02"), Some(86400));
        assert_eq!(
            parse_utc_date_to_timestamp("1970-01-01 23:59:59"),
            Some(86399)
        );
        // explicit midnight time → same as date-only
        assert_eq!(parse_utc_date_to_timestamp("1970-01-01 00:00:00"), Some(0));
        assert_eq!(
            parse_utc_date_to_timestamp("1985-11-05 00:53:20"),
            Some(500_000_000)
        );
        assert_eq!(
            parse_utc_date_to_timestamp("2023-11-14 22:13:20"),
            Some(1_700_000_000)
        );
        assert_eq!(
            parse_utc_date_to_timestamp("2020-02-29"),
            Some(1_582_934_400) // leap day
        );
        // Pre-epoch date → None (timestamp would be negative)
        assert_eq!(parse_utc_date_to_timestamp("1969-12-31"), None);
    }

    #[test]
    fn test_parse_utc_date_invalid() {
        assert_eq!(parse_utc_date_to_timestamp(""), None);
        assert_eq!(parse_utc_date_to_timestamp("not-a-date"), None);
        assert_eq!(parse_utc_date_to_timestamp("1970-13-01"), None); // bad month
        assert_eq!(parse_utc_date_to_timestamp("1970-00-01"), None); // zero month
        assert_eq!(parse_utc_date_to_timestamp("1970-01-00"), None); // zero day
        assert_eq!(parse_utc_date_to_timestamp("1970-01-32"), None); // bad day
        assert_eq!(parse_utc_date_to_timestamp("1970-01-01 25:00:00"), None); // bad hour
        assert_eq!(parse_utc_date_to_timestamp("1970-01-01 00:60:00"), None); // bad minute
        assert_eq!(parse_utc_date_to_timestamp("1970-01-01 00:00:60"), None); // bad second
        assert_eq!(parse_utc_date_to_timestamp("1970-01"), None); // incomplete date
        assert_eq!(parse_utc_date_to_timestamp("1970-01-01 12:00"), None); // incomplete time
    }

    // ── format_utc_date roundtrip ────────────────────────────────────────────

    #[test]
    fn test_format_utc_date_roundtrip() {
        let cases: &[u32] = &[
            0,             // 1970-01-01 (epoch midnight)
            86399,         // 1970-01-01 23:59:59 (last second of epoch day)
            86400,         // 1970-01-02 (next midnight)
            1_000_000,     // mid-January 1970
            500_000_000,   // 1985-11-05 00:53:20
            1_700_000_000, // 2023-11-14 22:13:20
            1_609_459_200, // 2021-01-01 00:00:00 (midnight new year)
            1_582_934_400, // 2020-02-29 00:00:00 (leap day midnight)
        ];
        for &ts in cases {
            let formatted = format_utc_date(ts);
            let parsed = parse_utc_date_to_timestamp(&formatted);
            assert_eq!(
                parsed,
                Some(ts),
                "roundtrip failed for ts={}: formatted={:?}",
                ts,
                formatted
            );
        }
    }

    // ── format_seconds ───────────────────────────────────────────────────────

    #[test]
    fn test_format_seconds_known() {
        assert_eq!(format_seconds(0), "0s");
        assert_eq!(format_seconds(1), "1s");
        assert_eq!(format_seconds(60), "1m");
        assert_eq!(format_seconds(3600), "1h");
        assert_eq!(format_seconds(86400), "1d");
        assert_eq!(format_seconds(512), "8m 32s");
        assert_eq!(format_seconds(92160), "1d 1h 36m");
        assert_eq!(format_seconds(90061), "1d 1h 1m 1s");
        assert_eq!(format_seconds(93784), "1d 2h 3m 4s");
        // only hours and seconds, no days or minutes
        assert_eq!(format_seconds(3601), "1h 1s");
    }

    // ── parse_relative_time_to_seconds ───────────────────────────────────────

    #[test]
    fn test_parse_relative_time_known() {
        assert_eq!(parse_relative_time_to_seconds("0s"), Some(0));
        assert_eq!(parse_relative_time_to_seconds("1s"), Some(1));
        assert_eq!(parse_relative_time_to_seconds("1m"), Some(60));
        assert_eq!(parse_relative_time_to_seconds("1h"), Some(3600));
        assert_eq!(parse_relative_time_to_seconds("1d"), Some(86400));
        assert_eq!(parse_relative_time_to_seconds("8m 32s"), Some(512));
        assert_eq!(parse_relative_time_to_seconds("1d 1h 36m"), Some(92160));
        assert_eq!(parse_relative_time_to_seconds("1d 1h 1m 1s"), Some(90061));
        assert_eq!(parse_relative_time_to_seconds("1d 2h 3m 4s"), Some(93784));
        assert_eq!(parse_relative_time_to_seconds("1h 1s"), Some(3601));
    }

    #[test]
    fn test_parse_relative_time_invalid() {
        assert_eq!(parse_relative_time_to_seconds(""), None);
        assert_eq!(parse_relative_time_to_seconds("1x"), None); // unknown unit
        assert_eq!(parse_relative_time_to_seconds("1h 1d"), None); // wrong order
        assert_eq!(parse_relative_time_to_seconds("1h 1h"), None); // duplicate unit
        assert_eq!(parse_relative_time_to_seconds("abc"), None); // no unit
        assert_eq!(parse_relative_time_to_seconds("d"), None); // missing number
        assert_eq!(parse_relative_time_to_seconds("1d2h"), None); // no space between tokens
    }

    // ── format_seconds roundtrip ─────────────────────────────────────────────

    #[test]
    fn test_format_seconds_roundtrip() {
        let cases: &[u32] = &[
            0, 1, 59, 60, 61, 3600, 3601, 3660, 86400, 86401, 86460, 90000, 512,   // 8m 32s
            92160, // 1d 1h 36m
            90061, // 1d 1h 1m 1s
            93784, // 1d 2h 3m 4s
            3601,  // 1h 1s  (no minutes)
        ];
        for &secs in cases {
            let formatted = format_seconds(secs);
            let parsed = parse_relative_time_to_seconds(&formatted);
            assert_eq!(
                parsed,
                Some(secs),
                "roundtrip failed for secs={}: formatted={:?}",
                secs,
                formatted
            );
        }
    }
}

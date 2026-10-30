// days since 1970-01-01 -> (year, month, day); Hinnant's civil_from_days
pub fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// `Sun, 06 Nov 1994 08:49:37 GMT`, the form HTTP headers use.
pub fn http_date(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let s = t.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    // 1970-01-01 was a Thursday
    let wd = (days + 4).rem_euclid(7) as usize;
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        DAYS[wd],
        MONTHS[m as usize - 1],
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

/// `1994-11-06T08:49:37Z`
pub fn iso8601(t: i64) -> String {
    let (y, m, d) = civil(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(11_016), (2000, 2, 29));
        assert_eq!(civil(-1), (1969, 12, 31));
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(iso8601(784_111_777), "1994-11-06T08:49:37Z");
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59Z");
        // 2024-02-29 12:00 UTC
        assert_eq!(http_date(1_709_208_000), "Thu, 29 Feb 2024 12:00:00 GMT");
    }
}

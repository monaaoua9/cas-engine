/// "123", "64K", "1.5GiB", "10 mb": all suffixes are powers of 1024.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let split = t.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(t.len());
    let (num, unit) = t.split_at(split);

    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        other => return Err(format!("unknown size unit {other:?}")),
    };
    if num.is_empty() {
        return Err(format!("no number in {s:?}"));
    }
    let n: f64 = num.parse().map_err(|_| format!("bad number in {s:?}"))?;
    let bytes = n * mult as f64;
    if !bytes.is_finite() || bytes >= u64::MAX as f64 {
        return Err(format!("{s:?} is too large"));
    }
    Ok(bytes as u64)
}

pub fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_forms() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("123").unwrap(), 123);
        assert_eq!(parse_size("64K").unwrap(), 64 << 10);
        assert_eq!(parse_size("64kib").unwrap(), 64 << 10);
        assert_eq!(parse_size("2 MiB").unwrap(), 2 << 20);
        assert_eq!(parse_size("1.5G").unwrap(), 3 << 29);
        assert_eq!(parse_size(" 10gb ").unwrap(), 10 << 30);
        assert_eq!(parse_size("1T").unwrap(), 1 << 40);
        assert_eq!(parse_size("7b").unwrap(), 7);
    }

    #[test]
    fn rejects_nonsense() {
        for s in ["", "MiB", "12x", "1.2.3", "-5", "1e3", "99999999999999999999T"] {
            assert!(parse_size(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(1023), "1023 B");
        assert_eq!(human(1024), "1.0 KiB");
        assert_eq!(human(5 << 30), "5.0 GiB");
    }
}

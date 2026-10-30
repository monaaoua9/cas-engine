use std::collections::HashSet;

use crate::cursor::Cursor;
use crate::error::{Error, Result};
use crate::hash::{HASH_LEN, Hash};

const MAGIC: &[u8; 4] = b"CASS";
const VERSION: u8 = 1;
const MEMBER: usize = HASH_LEN + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub id: Hash,
    /// This snapshot (or an earlier one it shares the object with) is what put
    /// the object in the store, so forgetting the last such snapshot removes it.
    pub created: bool,
}

/// Named pointer to a root tree, plus every object the tree reaches so that
/// forgetting a snapshot knows what to release without walking anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub name: String,
    pub time: i64,
    pub root: Hash,
    pub source: String,
    pub members: Vec<Member>,
}

pub fn valid_snapshot_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && !n.starts_with('.')
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.members.len() * MEMBER + self.source.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(self.root.as_bytes());
        out.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&(self.source.len() as u32).to_le_bytes());
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(&(self.members.len() as u32).to_le_bytes());
        for m in &self.members {
            out.extend_from_slice(m.id.as_bytes());
            out.push(m.created as u8);
        }
        let sum = Hash::of(&out);
        out.extend_from_slice(sum.as_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Snapshot> {
        if buf.len() < 4 + 1 + 8 + HASH_LEN + HASH_LEN {
            return Err(Error::BadSnapshot("too short"));
        }
        let (body, sum) = buf.split_at(buf.len() - HASH_LEN);
        if Hash::of(body).as_bytes() != sum {
            return Err(Error::BadSnapshot("checksum mismatch"));
        }

        let mut c = Cursor::new(body, Error::BadSnapshot);
        if c.take(4)? != MAGIC {
            return Err(Error::BadSnapshot("bad magic"));
        }
        if c.u8()? != VERSION {
            return Err(Error::BadSnapshot("unsupported version"));
        }
        let time = c.i64()?;
        let root = c.hash()?;
        let n = c.u16()? as usize;
        let name = c.string(n)?;
        if !valid_snapshot_name(&name) {
            return Err(Error::BadSnapshot("bad name"));
        }
        let n = c.u32()? as usize;
        let source = c.string(n)?;

        let count = c.u32()? as usize;
        if count != c.left() / MEMBER || !c.left().is_multiple_of(MEMBER) {
            return Err(Error::BadSnapshot("member count does not match length"));
        }
        let mut members: Vec<Member> = Vec::with_capacity(count);
        for _ in 0..count {
            let id = c.hash()?;
            let created = match c.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::BadSnapshot("bad flag")),
            };
            if members.last().is_some_and(|p| p.id >= id) {
                return Err(Error::BadSnapshot("members not strictly sorted"));
            }
            members.push(Member { id, created });
        }
        Ok(Snapshot { name, time, root, source, members })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Retention {
    pub last: usize,
    pub daily: usize,
    pub weekly: usize,
    pub monthly: usize,
}

impl Retention {
    pub fn is_empty(&self) -> bool {
        self.last == 0 && self.daily == 0 && self.weekly == 0 && self.monthly == 0
    }
}

// days since 1970-01-01 -> (year, month); Hinnant's civil_from_days
fn year_month(days: i64) -> (i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    (y, m)
}

type Bucket = fn(i64) -> i64;

fn day(t: i64) -> i64 {
    t.div_euclid(86_400)
}

// epoch day 0 was a Thursday; shifting by 3 makes weeks start on Monday
fn week(t: i64) -> i64 {
    (day(t) + 3).div_euclid(7)
}

fn month(t: i64) -> i64 {
    let (y, m) = year_month(day(t));
    y * 12 + m
}

/// Names to keep. Within each bucket (day, week, month) the newest snapshot
/// wins, and each rule keeps its N most recent buckets. An empty policy keeps
/// everything rather than deleting it all.
pub fn keep_set(snaps: &[(String, i64)], p: &Retention) -> HashSet<String> {
    if p.is_empty() {
        return snaps.iter().map(|(n, _)| n.clone()).collect();
    }
    let mut sorted: Vec<&(String, i64)> = snaps.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));

    let mut keep = HashSet::new();
    for s in sorted.iter().take(p.last) {
        keep.insert(s.0.clone());
    }

    let rules: [(usize, Bucket); 3] = [(p.daily, day), (p.weekly, week), (p.monthly, month)];
    for (n, bucket) in rules {
        let mut seen = HashSet::new();
        for s in &sorted {
            if seen.len() == n {
                break;
            }
            if seen.insert(bucket(s.1)) {
                keep.insert(s.0.clone());
            }
        }
    }
    keep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(n: u8, created: bool) -> Snapshot {
        let mut members: Vec<Member> = (0..n).map(|i| Member { id: Hash::of(&[i]), created }).collect();
        members.sort_by_key(|m| m.id);
        Snapshot {
            name: "daily-1".into(),
            time: 1_700_000_000,
            root: Hash::of(b"root"),
            source: "/home/x".into(),
            members,
        }
    }

    #[test]
    fn roundtrip() {
        let s = snap(7, true);
        assert_eq!(Snapshot::decode(&s.encode()).unwrap(), s);
        let e = snap(0, false);
        assert_eq!(Snapshot::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn any_flipped_byte_is_rejected() {
        let enc = snap(3, true).encode();
        for i in 0..enc.len() {
            let mut bad = enc.clone();
            bad[i] ^= 0x04;
            assert!(Snapshot::decode(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn names() {
        assert!(valid_snapshot_name("snap-1700000000"));
        assert!(valid_snapshot_name("v1.2_rc"));
        for n in ["", ".hidden", "a/b", "a b", "..", "x\0", &"n".repeat(65)] {
            assert!(!valid_snapshot_name(n), "{n:?}");
        }
    }

    #[test]
    fn months_and_weeks() {
        // 2024-02-29 12:00 UTC
        assert_eq!(year_month(day(1_709_208_000)), (2024, 2));
        // 1970-01-01
        assert_eq!(year_month(0), (1970, 1));
        // 2000-03-01 is the day after a leap day
        assert_eq!(year_month(11_017), (2000, 3));
        // Monday 1970-01-05 starts a new week, Sunday 1970-01-04 is still in the old one
        assert_ne!(week(4 * 86_400), week(3 * 86_400));
        assert_eq!(week(4 * 86_400), week(10 * 86_400 + 86_399));
    }

    fn at(name: &str, day: i64, hour: i64) -> (String, i64) {
        (name.to_string(), day * 86_400 + hour * 3600)
    }

    #[test]
    fn keep_last_n() {
        let s = [at("a", 1, 0), at("b", 2, 0), at("c", 3, 0), at("d", 4, 0)];
        let k = keep_set(&s, &Retention { last: 2, ..Default::default() });
        assert_eq!(k, HashSet::from(["c".to_string(), "d".to_string()]));
    }

    #[test]
    fn daily_keeps_newest_of_each_day() {
        let s = [at("a1", 10, 1), at("a2", 10, 20), at("b", 11, 5), at("c1", 12, 3), at("c2", 12, 9)];
        let k = keep_set(&s, &Retention { daily: 2, ..Default::default() });
        assert_eq!(k, HashSet::from(["c2".to_string(), "b".to_string()]));
    }

    #[test]
    fn rules_union() {
        let s = [at("old", 100, 0), at("mid", 200, 0), at("new", 300, 0)];
        let k = keep_set(&s, &Retention { last: 1, monthly: 2, ..Default::default() });
        assert_eq!(k, HashSet::from(["new".to_string(), "mid".to_string()]));
    }

    #[test]
    fn empty_policy_keeps_everything() {
        let s = [at("a", 1, 0), at("b", 2, 0)];
        assert_eq!(keep_set(&s, &Retention::default()).len(), 2);
    }

    #[test]
    fn weekly_buckets_start_on_monday() {
        // days 4..=10 are one Monday-to-Sunday week, 11 starts the next
        let s = [at("mon", 4, 0), at("sun", 10, 0), at("nextmon", 11, 0)];
        let k = keep_set(&s, &Retention { weekly: 2, ..Default::default() });
        assert_eq!(k, HashSet::from(["sun".to_string(), "nextmon".to_string()]));
    }
}

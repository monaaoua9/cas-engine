use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::store::Stats;

/// Event counters kept by an open store; they start at zero each time it is opened.
#[derive(Default)]
pub struct Counters {
    pub(crate) puts: AtomicU64,
    pub(crate) put_bytes: AtomicU64,
    pub(crate) chunks_written: AtomicU64,
    pub(crate) chunks_deduped: AtomicU64,
    pub(crate) chunk_reads: AtomicU64,
    pub(crate) bytes_read: AtomicU64,
    pub(crate) corrupt_seen: AtomicU64,
    pub(crate) gc_runs: AtomicU64,
    pub(crate) quota_rejections: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub puts: u64,
    pub put_bytes: u64,
    pub chunks_written: u64,
    pub chunks_deduped: u64,
    pub chunk_reads: u64,
    pub bytes_read: u64,
    pub corrupt_seen: u64,
    pub gc_runs: u64,
    pub quota_rejections: u64,
}

impl Counters {
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            puts: self.puts.load(Relaxed),
            put_bytes: self.put_bytes.load(Relaxed),
            chunks_written: self.chunks_written.load(Relaxed),
            chunks_deduped: self.chunks_deduped.load(Relaxed),
            chunk_reads: self.chunk_reads.load(Relaxed),
            bytes_read: self.bytes_read.load(Relaxed),
            corrupt_seen: self.corrupt_seen.load(Relaxed),
            gc_runs: self.gc_runs.load(Relaxed),
            quota_rejections: self.quota_rejections.load(Relaxed),
        }
    }
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, v: impl std::fmt::Display) {
    let _ = writeln!(out, "# HELP cas_{name} {help}");
    let _ = writeln!(out, "# TYPE cas_{name} {kind}");
    let _ = writeln!(out, "cas_{name} {v}");
}

/// Prometheus text exposition format. `disk_bytes` and `max_bytes` come from
/// the store; `extra` lets a server add its own counters.
pub fn prometheus(st: &Stats, c: &CounterSnapshot, disk_bytes: u64, max_bytes: Option<u64>, extra: &[(&str, &str, u64)]) -> String {
    let mut o = String::new();
    metric(&mut o, "objects", "gauge", "objects stored", st.objects);
    metric(&mut o, "logical_bytes", "gauge", "sum of object sizes before dedup", st.logical_bytes);
    metric(&mut o, "live_chunks", "gauge", "chunks referenced by an object", st.live_chunks);
    metric(&mut o, "live_bytes", "gauge", "payload bytes of live chunks", st.live_bytes);
    metric(&mut o, "dead_chunks", "gauge", "unreferenced chunks waiting for gc", st.dead_chunks);
    metric(&mut o, "dead_bytes", "gauge", "payload bytes of dead chunks", st.dead_bytes);
    metric(&mut o, "segments", "gauge", "segment files", st.segments);
    metric(&mut o, "disk_bytes", "gauge", "bytes in segment files", disk_bytes);
    if let Some(m) = max_bytes {
        metric(&mut o, "quota_bytes", "gauge", "configured size limit", m);
    }
    metric(&mut o, "dedup_ratio", "gauge", "logical bytes over live payload bytes", format!("{:.4}", st.dedup_ratio()));

    metric(&mut o, "puts_total", "counter", "objects put since open", c.puts);
    metric(&mut o, "put_bytes_total", "counter", "logical bytes put since open", c.put_bytes);
    metric(&mut o, "chunks_written_total", "counter", "new chunks written", c.chunks_written);
    metric(&mut o, "chunks_deduped_total", "counter", "chunks skipped because already stored", c.chunks_deduped);
    metric(&mut o, "chunk_reads_total", "counter", "chunks read and verified", c.chunk_reads);
    metric(&mut o, "read_bytes_total", "counter", "plain bytes returned by chunk reads", c.bytes_read);
    metric(&mut o, "corrupt_chunks_seen_total", "counter", "chunk reads that failed their check", c.corrupt_seen);
    metric(&mut o, "gc_runs_total", "counter", "gc runs", c.gc_runs);
    metric(&mut o, "quota_rejections_total", "counter", "writes refused for lack of quota", c.quota_rejections);
    for (name, help, v) in extra {
        metric(&mut o, name, "counter", help, v);
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_is_well_formed() {
        let st = Stats { objects: 3, logical_bytes: 300, live_bytes: 100, ..Stats::default() };
        let c = CounterSnapshot { puts: 5, ..Default::default() };
        let t = prometheus(&st, &c, 123, Some(1000), &[("net_requests_total", "requests served", 7)]);

        assert!(t.contains("cas_objects 3\n"));
        assert!(t.contains("cas_dedup_ratio 3.0000\n"));
        assert!(t.contains("cas_disk_bytes 123\n"));
        assert!(t.contains("cas_quota_bytes 1000\n"));
        assert!(t.contains("# TYPE cas_puts_total counter\ncas_puts_total 5\n"));
        assert!(t.contains("cas_net_requests_total 7\n"));
        // every sample line has a HELP and TYPE above it
        let samples = t.lines().filter(|l| !l.starts_with('#')).count();
        assert_eq!(t.lines().filter(|l| l.starts_with("# HELP")).count(), samples);
        assert_eq!(t.lines().filter(|l| l.starts_with("# TYPE")).count(), samples);
        assert!(t.ends_with('\n'));
    }

    #[test]
    fn quota_line_only_when_set() {
        let t = prometheus(&Stats::default(), &CounterSnapshot::default(), 0, None, &[]);
        assert!(!t.contains("quota_bytes"));
    }
}

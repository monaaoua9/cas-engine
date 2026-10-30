use std::hint::black_box;

use cas::{Algorithm, Chunker, ChunkerConfig, Compression, Hash, Kdf, Password, Store, StoreConfig};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const SIZE: usize = 32 << 20;

fn noise(len: usize) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

// words from a small vocabulary: compresses roughly 2-3x, which is what logs and source look like
fn text(len: usize) -> Vec<u8> {
    const WORDS: [&str; 16] = [
        "error",
        "request",
        "user",
        "timeout",
        "retry",
        "cache",
        "miss",
        "hit",
        "connection",
        "closed",
        "index",
        "segment",
        "chunk",
        "refcount",
        "flush",
        "sync",
    ];
    let mut x = 0xD1B5_4A32_D192_ED03u64;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(WORDS[(x >> 20) as usize % WORDS.len()].as_bytes());
        out.push(if x.is_multiple_of(9) { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

fn chunking(c: &mut Criterion) {
    let data = noise(SIZE);
    let mut g = c.benchmark_group("chunker");
    g.throughput(Throughput::Bytes(SIZE as u64));
    g.bench_function("rabin_split", |b| {
        b.iter(|| {
            let n = Chunker::new(&data[..], ChunkerConfig::default())
                .unwrap()
                .map(|c| c.unwrap().data.len())
                .sum::<usize>();
            black_box(n)
        })
    });
    g.bench_function("gear_split", |b| {
        let cfg = ChunkerConfig { algorithm: Algorithm::Gear, ..ChunkerConfig::default() };
        b.iter(|| {
            let n = Chunker::new(&data[..], cfg).unwrap().map(|c| c.unwrap().data.len()).sum::<usize>();
            black_box(n)
        })
    });
    g.bench_function("blake3_whole_buffer", |b| b.iter(|| black_box(Hash::of(&data))));
    g.finish();
}

fn store(c: &mut Criterion) {
    let data = noise(SIZE);
    let mut g = c.benchmark_group("store");
    g.throughput(Throughput::Bytes(SIZE as u64));
    g.sample_size(10);

    g.bench_function("put_cold", |b| {
        b.iter_batched(
            || tempfile::tempdir().unwrap(),
            |dir| {
                let mut s = Store::open(dir.path(), StoreConfig::default()).unwrap();
                black_box(s.put_bytes(&data).unwrap());
                s.sync().unwrap();
                dir
            },
            criterion::BatchSize::PerIteration,
        )
    });

    g.bench_function("put_cold_gear", |b| {
        let cfg = StoreConfig {
            chunker: ChunkerConfig { algorithm: Algorithm::Gear, ..ChunkerConfig::default() },
            ..StoreConfig::default()
        };
        b.iter_batched(
            || tempfile::tempdir().unwrap(),
            |dir| {
                let mut s = Store::open(dir.path(), cfg.clone()).unwrap();
                black_box(s.put_bytes(&data).unwrap());
                s.sync().unwrap();
                dir
            },
            criterion::BatchSize::PerIteration,
        )
    });

    let dir = tempfile::tempdir().unwrap();
    let mut s = Store::open(dir.path(), StoreConfig::default()).unwrap();
    let id = s.put_bytes(&data).unwrap().id;
    g.bench_function("put_dedup_hit", |b| b.iter(|| black_box(s.put_bytes(&data).unwrap())));
    g.bench_function("get_verify", |b| b.iter(|| black_box(s.read_to_vec(&id).unwrap())));
    g.finish();
}

fn put_cold(
    g: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>,
    name: &str,
    cfg: &StoreConfig,
    data: &[u8],
) {
    g.bench_function(name, |b| {
        b.iter_batched(
            || tempfile::tempdir().unwrap(),
            |dir| {
                let mut s = Store::open(dir.path(), cfg.clone()).unwrap();
                black_box(s.put_bytes(data).unwrap());
                s.sync().unwrap();
                dir
            },
            criterion::BatchSize::PerIteration,
        )
    });
}

// compression and encryption, against the plain store on the same bytes
fn transforms(c: &mut Criterion) {
    let random = noise(SIZE);
    let words = text(SIZE);
    let plain = StoreConfig::default();
    let lz4 = StoreConfig { compression: Compression::Lz4, ..StoreConfig::default() };
    // a tiny kdf: the password is stretched once per open, not per chunk, so it isn't what's measured
    let enc = StoreConfig {
        password: Some(Password::from(b"bench".to_vec())),
        kdf: Kdf { memory_kib: 8, passes: 1, lanes: 1 },
        ..StoreConfig::default()
    };

    let d = tempfile::tempdir().unwrap();
    let mut s = Store::open(d.path(), lz4.clone()).unwrap();
    let r = s.put_bytes(&words).unwrap();
    eprintln!("lz4 on the text sample: {} bytes stored for {}", r.stored_bytes, r.size);

    let mut g = c.benchmark_group("transforms");
    g.throughput(Throughput::Bytes(SIZE as u64));
    g.sample_size(10);

    put_cold(&mut g, "put_text_plain", &plain, &words);
    put_cold(&mut g, "put_text_lz4", &lz4, &words);
    put_cold(&mut g, "put_random_lz4", &lz4, &random);
    put_cold(&mut g, "put_random_encrypted", &enc, &random);

    let id = s.put_bytes(&words).unwrap().id;
    g.bench_function("get_text_lz4", |b| b.iter(|| black_box(s.read_to_vec(&id).unwrap())));

    let d = tempfile::tempdir().unwrap();
    let mut e = Store::open(d.path(), enc).unwrap();
    let id = e.put_bytes(&random).unwrap().id;
    g.bench_function("get_random_encrypted", |b| b.iter(|| black_box(e.read_to_vec(&id).unwrap())));
    g.finish();
}

criterion_group!(benches, chunking, store, transforms);
criterion_main!(benches);

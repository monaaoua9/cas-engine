use std::hint::black_box;

use cas::{Algorithm, Chunker, ChunkerConfig, Hash, Store, StoreConfig};
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

criterion_group!(benches, chunking, store);
criterion_main!(benches);

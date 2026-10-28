#![no_main]

use cas::{Algorithm, Chunker, ChunkerConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for algorithm in [Algorithm::Rabin, Algorithm::Gear] {
        let cfg = ChunkerConfig { algorithm, min_size: 64, avg_size: 256, max_size: 1024 };
        let mut joined = Vec::with_capacity(data.len());
        for c in Chunker::new(data, cfg).unwrap() {
            let c = c.unwrap();
            assert!(c.data.len() <= cfg.max_size);
            joined.extend_from_slice(&c.data);
        }
        assert_eq!(joined, data);
    }
});

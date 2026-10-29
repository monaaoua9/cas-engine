# cas-engine: benchmarks

Measured 2026-10-29.

| | |
|---|---|
| CPU | Intel i5-8365U, 4 cores / 8 threads, 1.6 GHz base |
| RAM / disk | 8 GB, SSD |
| OS | Windows 11 |
| Toolchain | Rust 1.99.1, `--release` |

Reproduce:

```
cargo bench --bench throughput -- --warm-up-time 1 --measurement-time 3
```

Criterion, 32 MiB of random data. I ran the whole benchmark three times; each cell is the median of the three runs' central estimates, with the min–max in brackets.

| benchmark | throughput |
|---|---:|
| Rabin split only | 168 MiB/s (168 – 187) |
| Gear split only | 412 MiB/s (407 – 462) |
| BLAKE3 over one buffer | 2,310 MiB/s (2,227 – 2,595) |
| `put`, new data, Rabin | 178 MiB/s (162 – 182) |
| `put`, new data, Gear | 260 MiB/s (258 – 268) |
| `put`, every chunk already stored (dedup hit) | 271 MiB/s (195 – 281) |
| `get` with per-chunk hash verification | 324 MiB/s (321 – 496) |

## Reading these numbers

- **The chunker is the bottleneck.** Rabin alone does 168 MiB/s and a full `put` of new data does 178, so the pipeline is limited by chunking, not hashing (BLAKE3 is more than ten times faster) or segment writes. Chunking is serial by nature: each byte depends on the previous fingerprint through a table lookup.
- Gear is about 2.4× faster than Rabin at splitting and 1.5× faster end to end.
- A dedup hit skips the segment write but still chunks and hashes, so it's about 1.5× faster than a cold Rabin put rather than free.
- The `get` row had one run far above the others (496 vs 321–324 MiB/s). I don't know why; take the median.
- The README says the same Rabin benchmark has read anywhere from 170 to 380 MiB/s on different runs, and today's three runs sat at the low end of that. Compare ratios inside one table, not absolute numbers across days.
- Nothing here compares cas-engine with restic, borg or another store.

# cas-engine: benchmarks

Measured 2026-10-31, on version 0.3.0 plus the benchmark additions in this commit.

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

Criterion, 32 MiB of data per iteration. I ran the whole benchmark three times back to back; each cell is the median of the three runs' central estimates, with the min–max in brackets. Throughput is always counted in logical (uncompressed, plaintext) bytes.

This is a low-spec laptop that had other terminals open and a nearly full system drive, so timings move a lot between runs and between days. Read the ratios inside one table, not the absolute numbers.

## Core store

| benchmark | throughput |
|---|---:|
| Rabin split only | 301 MiB/s (296 – 308) |
| Gear split only | 649 MiB/s (624 – 691) |
| BLAKE3 over one buffer | 2,327 MiB/s (2,036 – 2,385) |
| `put`, new data, Rabin | 165 MiB/s (138 – 168) |
| `put`, new data, Gear | 244 MiB/s (205 – 251) |
| `put`, every chunk already stored (dedup hit) | 250 MiB/s (223 – 267) |
| `get` with per-chunk hash verification | 452 MiB/s (386 – 462) |

## Compression and encryption

Same machine, same session, same three runs. "Text" is 32 MiB of words from a 16-word vocabulary (a stand-in for logs and source); "random" is incompressible. The password is stretched once when a store is opened, so the key derivation is not in these numbers (the benchmark uses a tiny Argon2id setting for that reason).

| benchmark | throughput |
|---|---:|
| `put`, text, no compression | 165 MiB/s (161 – 171) |
| `put`, text, lz4 | 158 MiB/s (140 – 164) |
| `put`, random, lz4 (nothing shrinks, so chunks are stored as they were) | 163 MiB/s (147 – 168) |
| `put`, random, encrypted | 154 MiB/s (142 – 157) |
| `get`, text, lz4 | 322 MiB/s (287 – 322) |
| `get`, random, encrypted | 264 MiB/s (247 – 265) |

lz4 stored the text sample in 13.9 MB for 33.6 MB of input (41%, about 2.4×).

## Reading these numbers

- **The chunker is still the bottleneck on `put`.** Rabin alone does 301 MiB/s and a full `put` of new data does 165, so the pipeline is limited by chunking and the segment writes behind it, not hashing (BLAKE3 is about eight times faster than the chunker). Gear is 2.2× faster than Rabin at splitting and 1.5× faster end to end.
- A dedup hit skips the segment write but still chunks and hashes, so it's about 1.5× faster than a cold Rabin put rather than free.
- **Compression costs almost nothing on write.** lz4 text and plain text put are within each other's run-to-run range (158 vs 165), and trying lz4 on incompressible data didn't show a measurable cost either (163 vs the 165 of the plain random `put` above). A likely reason is that the single chunking thread sets the pace and the extra work happens on the other side of it, but I did not profile that.
- **Encryption on write is a small cost, on read a visible one.** Encrypted `put` is about 7% below plain (154 vs 165, with overlapping ranges, so don't read much into the exact figure). Encrypted `get` is clearly slower: 264 against 452 for the plain verified read, and the ranges don't overlap. A read has to decrypt and authenticate each chunk as well as verify its hash; I didn't break the cost down further.
- `get` on lz4 text (322) is lower than plain `get` (452) while moving less data from disk; decompression is the extra work, and the figure counts decompressed bytes.
- **Absolute numbers moved a lot since last time.** The previous version of this file (2026-10-29) had Rabin split at 168 MiB/s and `get` at 324; today the same, unchanged code reads 301 and 452. That is the machine, not the code, and it is why nothing here should be compared across dates. The README's note that the same benchmark has read anywhere from 170 to 380 MiB/s on different days still holds.
- I did not benchmark the network path (push/pull, TLS): over loopback on this machine it would mostly measure thread scheduling. Nothing here compares cas-engine with restic, borg or another store.

# cas

[![ci](https://github.com/monaaoua9/cas-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/monaaoua9/cas-engine/actions/workflows/ci.yml)

A content-addressed, immutable, deduplicating object store in Rust.

Files are cut into content-defined chunks with a Rabin rolling fingerprint, every chunk is keyed by its BLAKE3 hash, and a file is named by the Merkle root over its chunk list. Chunks live in append-only segment files, found through a memory-mapped hash index. Reference counts plus a compacting GC give the space back when objects are deleted.

Why it is built this way: [docs/DESIGN.md](docs/DESIGN.md).

```
$ cas put backup.tar
3f1c...e9a2                                  # object id = Merkle root
1.2 GiB in 4811 chunks, 412 new (101.3 MiB)

$ cas stats
objects        6
logical size   7.1 GiB
live chunks    6930 (1.4 GiB)
dedup ratio    5.07x
```

## How a file is stored

```mermaid
flowchart LR
    F[file / stream] --> R[Rabin chunker<br/>min / avg / max]
    R -->|chunk| H[BLAKE3]
    H -->|hash known?| I{index}
    I -- no --> S[append to active segment]
    I -- yes --> D[dedup, skip write]
    S --> X[(index.bin<br/>mmap)]
    H --> L[chunk refs<br/>hash + len]
    L --> M[Merkle tree]
    M -->|root = object id| MF[manifests/id.mf]
```

```mermaid
graph TD
    root["root = H(1 ‖ n01 ‖ n23)"]
    n01["n01 = H(1 ‖ l0 ‖ l1)"]
    n23["n23 = H(1 ‖ l2 ‖ l3)"]
    l0["l0 = H(0 ‖ len ‖ chunk0)"]
    l1["l1 = H(0 ‖ len ‖ chunk1)"]
    l2["l2 = H(0 ‖ len ‖ chunk2)"]
    l3["l3 = H(0 ‖ len ‖ chunk3)"]
    root --> n01 & n23
    n01 --> l0 & l1
    n23 --> l2 & l3
```

Leaf and node hashes carry different one-byte prefixes, and an odd node at the end of a level is promoted unchanged rather than duplicated. That rules out the two classic Merkle pitfalls (leaf/node confusion and the duplicate-last-leaf collision). Leaves also bind the chunk length, so the id pins down content, order and sizes.

`cas prove <id> <chunk>` prints an inclusion proof; a verifier needs only the root, the chunk hash and about log2(n) sibling hashes.

## On-disk layout

```
store/
  LOCK                 exclusive file lock, one process at a time
  index.bin            mmap'd open-addressing hash table (rebuildable cache)
  segments/seg-N.dat   append-only: [hash 32][len u32][payload] ...
  manifests/<id>.mf    immutable, written tmp + fsync + rename
```

| Piece | What it is | Source of truth for |
|---|---|---|
| segments | chunk bytes, self-describing records | the data |
| manifests | ordered chunk list + trailer checksum | which chunks belong to which object |
| index.bin | hash -> (segment, offset, len, refcount) | nothing, it is derived |

Because the index is derived, recovery is simple: a header flag records a clean shutdown. If it is missing (crash, deleted file) the store rescans segments (re-hashing every payload, truncating a torn tail on the newest segment) and recomputes refcounts from the manifests. A torn write in the middle of an older segment is reported, never silently cut.

Write ordering for `put`: chunk bytes are fsynced, then the manifest is renamed into place, then refcounts are bumped. A crash at any point leaves either nothing visible or a rebuildable store; the index is marked dirty before refcounts can be wrong, so GC never sees undercounted data.

## Garbage collection

Objects are deleted by removing the manifest and decrementing one reference per distinct chunk. Bytes stay in the segment (it is immutable) until `cas gc`, which picks sealed segments whose dead fraction passes `gc_threshold`, copies their live chunks to a fresh segment (verifying each hash on the way), fsyncs, and only then unlinks the old files. A crash mid-GC leaves duplicates, which the next rebuild tolerates.

## Layout of the crate

| Module | Role |
|---|---|
| `chunker` | streaming content-defined chunking over any `Read`: Rabin (GF(2) polynomial tables) or Gear |
| `hash` | 32-byte BLAKE3 digest newtype, hex parse/print |
| `merkle` | tree, inclusion proofs, verification |
| `manifest` | object recipe + binary encoding with checksum |
| `segment` | record format, scanning, positional reads |
| `index` | mmap hash table (the only `unsafe` in the crate, one call) |
| `store` | put / get / remove / verify / scrub / gc / stats |
| `main.rs` | `cas` command line |

## Usage

```
cas [-s DIR] put <file>
cas [-s DIR] get <id> <out>
cas [-s DIR] rm <id>
cas [-s DIR] ls
cas [-s DIR] verify [id]       # no id: every manifest and every chunk
cas [-s DIR] prove <id> <n>
cas [-s DIR] gc
cas [-s DIR] stats
```

As a library:

```rust
use cas::{Store, StoreConfig};

let mut store = Store::open("./data", StoreConfig::default())?;
let put = store.put_file("backup.tar")?;
let bytes = store.read_to_vec(&put.id)?;
store.remove(&put.id)?;
store.gc()?;
```

Defaults (Rabin; `--chunker gear` or `ChunkerConfig { algorithm: Algorithm::Gear, .. }` for Gear): chunks 64 KiB min / 256 KiB avg-step / 1 MiB max, 64 MiB segments, GC threshold 30%. The average step is on top of the minimum, so typical chunks run around 320 KiB.

## Performance

`cargo bench` (criterion, 32 MiB of random data, release build, one run on a Windows laptop with other things open, so treat it as a rough floor):

| Benchmark | Throughput |
|---|---|
| Rabin split only | ~170 MiB/s |
| Gear split only (`--chunker gear`) | ~340 MiB/s |
| BLAKE3, one buffer | ~1.2 GiB/s |
| `put`, new data, Rabin | ~97 MiB/s |
| `put`, new data, Gear | ~176 MiB/s |
| `get` with per-chunk hash verification | ~390 MiB/s |

Both algorithms behave the same way (min/avg/max sizes, resync after an insertion, deterministic), so the choice is speed versus tradition: Rabin matches what restic and LBFS do, Gear is about twice as fast here. Data stored with one stays readable under the other; the same bytes chunked by different algorithms simply become two objects that do not share chunks.

Chunking runs on its own thread, so hashing and segment writes overlap with it. This machine is noisy: the same Rabin benchmark has read anywhere from 170 to 380 MiB/s on different runs, so compare ratios inside one table, not numbers across runs. `cargo bench` on your own hardware is the real answer.

The chunker is the bottleneck: each byte depends on the previous fingerprint through a table lookup, so it cannot be vectorised. The window is the input slice itself (no ring buffer) and the first `min_size - 48` bytes of every chunk are skipped, which together doubled its speed.

## Reading

`open_reader` gives a `Read + Seek` view that decodes one chunk at a time, and `read_range` is built on it. Reads take `&self` and the store is `Sync`, so any number of threads can read the same store; writes and `gc` need `&mut self`, which means a caller who wants both wraps the store in an `RwLock` and `gc` blocks readers while it runs.

## Testing

| Layer | What it checks |
|---|---|
| unit tests | chunk bounds, boundary resync after insertion, fast loop against a ring-buffer reference, Merkle proofs, index against a `HashMap` |
| `tests/store.rs` | round trips, dedup, GC with shared chunks, recovery, bit rot, tampered manifest, lock, streaming reader, concurrent readers |
| `tests/props.rs` (proptest) | random put/remove/gc/reopen sequences against a model; chunker reassembly and read-size independence; manifest and segment parsers on arbitrary bytes; truncated segment is always a clean prefix; tampered Merkle proofs |
| `tests/crash_failpoints.rs` | the binary exits at named points inside put/rm/gc (`cargo test --features failpoints`), then the store must reopen, verify, keep committed data, and gc cleanly |
| `tests/crash_kill.rs` | the binary is killed at arbitrary times during put and gc |
| `fuzz/` | libFuzzer targets for `Manifest::decode`, `segment::scan` and both chunkers (`cargo +nightly fuzz run manifest_decode`); CI runs 60 s per target on every push; a separate `fuzz` workflow runs 30 min per target every Sunday (and on demand) and uploads the crashing input if it finds one |

One failpoint test exists because of a real hazard: a put whose chunks are all already stored changes no index slot until refcounts are bumped, so the dirty flag has to be set before the manifest becomes visible. Removing that line makes `crash_on_dedup_only_put_does_not_lose_data` fail.

## Limits and non-goals

- Single writer per store (file lock).
- No encryption or compression; chunks are stored as-is. Both would sit in the segment record format and are left out on purpose.
- Directory fsync after rename/unlink is done on Unix; on Windows it is a no-op because there is no equivalent call.
- The crash tests kill the process, not the machine, so they do not cover the OS losing unsynced pages on power failure.
- Chunking is one serial thread by nature; hashing and I/O are a second thread. A single `put` does not scale past two cores.

## Development

```
cargo test --features failpoints
cargo clippy --all-targets --all-features -- -D warnings
cargo bench
```

# cas-engine: design decisions

Why the store is built this way. How a file is stored, the on-disk layout, GC and the test matrix are in the [README](../README.md).

## Scope

A content-addressed, immutable, deduplicating object store in Rust. One writer per store, any number of readers. No encryption or compression, left out on purpose.

## Decisions

**Content-defined chunking, so an insertion doesn't change every chunk.** Files are cut with a Rabin rolling fingerprint (or Gear, about twice as fast here and a different set of boundaries). Rabin matches what restic and LBFS do. Data stored with one stays readable under the other; the same bytes chunked differently just become two objects that don't share chunks.

**The object id is a Merkle root, with domain separation.** Leaf and node hashes get different one-byte prefixes, an odd node is promoted unchanged instead of duplicated, and leaves bind the chunk length. That rules out leaf/node confusion and the duplicate-last-leaf collision, and the id pins down content, order and sizes. Inclusion proofs fall out for free (`cas prove`).

**Append-only segments are the only source of truth for data; the index is a cache.** `index.bin` is a memory-mapped open-addressing table derived from segments and manifests. A header flag records a clean shutdown; if it's missing, the store rescans segments (re-hashing every payload, truncating a torn tail on the newest segment) and recomputes refcounts from the manifests. A torn write in the middle of an older segment is reported, never silently cut. Cost: recovery after a crash is a full scan.

**Write ordering of `put`:** fsync the chunk bytes, rename the manifest into place, then bump refcounts. The index is marked dirty before refcounts can be wrong, so GC never sees undercounted data. One failpoint test exists because of a real hazard here: a put whose chunks are all already stored changes no index slot until refcounts are bumped, so the dirty flag must be set before the manifest becomes visible. Removing that line makes `crash_on_dedup_only_put_does_not_lose_data` fail.

**Reference counts plus compacting GC instead of mark-and-sweep.** Deleting removes the manifest and decrements one reference per distinct chunk. Bytes stay in the immutable segment until `cas gc` copies the live chunks of sealed segments that passed `gc_threshold` into a fresh one (verifying each hash), fsyncs, then unlinks the old files. A crash mid-GC leaves duplicates, which the next rebuild tolerates. GC blocks readers while it runs.

**One `unsafe` call in the crate**, for the mmap. Everything else is safe Rust.

**Chunker on its own thread.** Chunking is serial by nature (each byte depends on the previous fingerprint through a table lookup), so hashing and segment writes overlap with it on a second thread. A single `put` doesn't scale past two cores.

## How it's checked

Property tests (random put/remove/gc/reopen sequences against a model; truncated segments always leave a clean prefix; tampered Merkle proofs), failpoint crash tests where the binary exits at named points inside put/rm/gc, kill-based crash tests at arbitrary times, and libFuzzer targets for the manifest decoder, the segment scanner and both chunkers (60 s per target on every push, 30 min weekly).

## Not covered

The crash tests kill the process, not the machine, so they don't cover the OS losing unsynced pages on power failure. Directory fsync after rename/unlink is done on Unix; on Windows it's a no-op.

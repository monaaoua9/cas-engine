# cas-engine: design decisions

Why the store is built this way. How a file is stored, the on-disk layout, GC and the test matrix are in the [README](../README.md).

## Scope

A content-addressed, immutable, deduplicating object store in Rust. One writer per store, any number of readers. On top of the object store: directory snapshots, optional per-chunk compression and encryption, a small network protocol for syncing stores, a read-only WebDAV view, and tar import/export. Not a backup scheduler, not a filesystem, and no multi-writer or distributed mode.

## Storage core

**Content-defined chunking, so an insertion doesn't change every chunk.** Files are cut with a Rabin rolling fingerprint (or Gear, about twice as fast here and a different set of boundaries). Rabin matches what restic and LBFS do. Data stored with one stays readable under the other; the same bytes chunked differently just become two objects that don't share chunks.

**The object id is a Merkle root, with domain separation.** Leaf and node hashes get different one-byte prefixes, an odd node is promoted unchanged instead of duplicated, and leaves bind the chunk length. That rules out leaf/node confusion and the duplicate-last-leaf collision, and the id pins down content, order and sizes. Inclusion proofs fall out for free (`cas prove`).

**Append-only segments are the only source of truth for data; the index is a cache.** `index.bin` is a memory-mapped open-addressing table derived from segments and manifests. A header flag records a clean shutdown; if it's missing, the store rescans segments (re-hashing every payload, truncating a torn tail on the newest segment) and recomputes refcounts from the manifests. A torn write in the middle of an older segment is reported, never silently cut. Cost: recovery after a crash is a full scan.

**Write ordering of `put`:** fsync the chunk bytes, rename the manifest into place, then bump refcounts. The index is marked dirty before refcounts can be wrong, so GC never sees undercounted data. One failpoint test exists because of a real hazard here: a put whose chunks are all already stored changes no index slot until refcounts are bumped, so the dirty flag must be set before the manifest becomes visible. Removing that line makes `crash_on_dedup_only_put_does_not_lose_data` fail.

**Reference counts plus compacting GC instead of mark-and-sweep.** Deleting removes the manifest and decrements one reference per distinct chunk. Bytes stay in the immutable segment until `cas gc` copies the live chunks of sealed segments that passed `gc_threshold` into a fresh one (verifying each hash), fsyncs, then unlinks the old files. A crash mid-GC leaves duplicates, which the next rebuild tolerates. GC blocks readers while it runs. Quota checks are skipped during GC, because compaction temporarily needs room for both copies.

**One `unsafe` call in the crate**, for the mmap. Everything else is safe Rust.

**Chunker on its own thread.** Chunking is serial by nature (each byte depends on the previous fingerprint through a table lookup), so hashing and segment writes overlap with it on a second thread. A single `put` doesn't scale past two cores.

## Compression and encryption

**Per chunk, below the id.** Compression and encryption happen after chunking and hashing, on each chunk's stored form. The record layout (v2) carries a codec byte and a short checksum, so a segment can be scanned and checked without any key. lz4 is only kept when the result is smaller; otherwise the chunk is stored as it was. A store without a FORMAT file is opened with the old v1 layout and keeps working, it just can't use either feature.

**Encryption decided at creation.** XChaCha20-Poly1305 with a random master key, wrapped by an Argon2id-derived key. Changing the password rewraps the master key and rewrites nothing else. A password on a plain store, or none on an encrypted one, is an error, not a silent no-op.

**Chunk ids are a keyed hash in encrypted stores.** A plain BLAKE3 id would let anyone holding the store test whether a known file is in it. The cost is that two encrypted stores only share chunks if they share a key. The chunk id and its role are also bound into the AEAD associated data, so a ciphertext moved to another id or swapped between manifests fails to open instead of decrypting to the wrong thing.

**Metadata is sealed too.** Manifests, tree objects and snapshot records go through the same sealing. What stays visible: the number and sizes of chunks, object count, snapshot names (they are file names) and timing. Keys are not zeroed in memory.

## Snapshots

**A directory is an ordinary object.** A tree is a sorted list of (name, kind, mode, mtime, size, id) entries, encoded and stored through the same chunker and manifests as a file. A directory's id depends only on its contents, so an unchanged subtree has the same id in every snapshot, costs nothing, and `snapshot diff` skips equal ids without descending.

**Names are checked twice.** On creation and again on decode: no `/`, `\`, NUL, `.` or `..`, strictly sorted, no duplicates. A hostile store therefore can't make `restore` write outside its destination, and restore refuses a non-empty destination.

**Forget releases only what the snapshot created.** Each member carries a `created` flag, set when the snapshot added the object or inherited from an earlier snapshot that did. An object stored with `cas put` before any snapshot saw it is never removed by a forget. The known gap goes the other way: bytes you `put` that happen to equal something a snapshot created are removed with it.

**Retention is a union of rules** (last N, daily, ISO weekly with Monday start, monthly), and an empty policy is an error rather than "delete everything".

## Network

**A framed binary protocol, not HTTP.** `len | tag | body`, 32 MiB frame cap, one request in flight per connection. Sync is the operation that matters: the sender asks which chunk ids the receiver lacks, sends only those, then the manifest, then the snapshot record. A second push of the same data moves nothing.

**Chunks travel as stored.** Compressed chunks stay compressed and an encrypted store never puts plaintext on the wire. The receiver decodes and re-hashes every chunk before keeping it, so a lying peer can't plant data under the wrong id.

**A mutual token proof, then TLS on top.** Each side proves it knows the shared secret by keying BLAKE3 over the server's nonce (labels "client" and "server" stop one proof being replayed as the other), so a client doesn't hand data to an impostor. With TLS (rustls, ring backend) the token still runs inside the tunnel: TLS gives confidentiality and server identity, the token decides who may use the store. The client trusts exactly the certificate it is given, not the system store, which suits a self-signed certificate made with `cas tls-cert`. No client certificates.

**One `RwLock` around the store, thread per connection.** Readers run in parallel, writers wait. Simple, and enough for a handful of clients; a slow reader holding the lock delays a writer, which is the known price.

**Snapshot conflicts are reported and left alone.** The same name with different contents on both sides never gets overwritten.

## WebDAV, HTTP and tar

**WebDAV is read-only on purpose.** Snapshots are immutable, so the share is too: OPTIONS, PROPFIND, GET and HEAD, everything that would write gets 405. ETag is the object id, ranges are supported, and optional Basic auth takes the token as the password. The HTTP layer behind it is small and strict (line, header and body limits, no chunked request bodies) rather than a general server; `--http-tls` puts the same certificate on it.

**tar in and out for interchange.** Export writes ustar with GNU long-name records; import reads ustar, GNU and pax. Entries that can't be represented (paths with `..`, non-UTF-8 names, devices, links to files not in the archive) are skipped and listed. A malformed archive is an error and leaves no snapshot; hard links to an earlier file become a second entry for the same object. Owners and sub-second mtimes are dropped.

## How it's checked

Property tests (random put/remove/gc/reopen sequences against a model; truncated segments always leave a clean prefix; tampered Merkle proofs), failpoint crash tests where the binary exits at named points inside put/rm/gc, kill-based crash tests at arbitrary times, and integration tests for encryption, repair, quotas, sync (store to store and over sockets, TLS, hostile frames), WebDAV, tar (including against the system `tar`) and the CLI. libFuzzer targets cover the manifest, segment, tree, format, wire-frame, HTTP-request and tar parsers and both chunkers: 60 s per target on every push, 30 min weekly.

## Not covered

The crash tests kill the process, not the machine, so they don't cover the OS losing unsynced pages on power failure. Directory fsync after rename/unlink is done on Unix; on Windows it's a no-op. Owners and extended attributes are not recorded in snapshots. There is no client authentication beyond the shared token, and the WebDAV and metrics ports are plain HTTP unless `--http-tls` is given.

# Changelog

## Unreleased

## 0.3.0 - 2026-10-31

- TLS for the cas protocol (`serve --tls-cert/--tls-key`, `push/pull --tls-ca`, `cas tls-cert` to make a self-signed certificate)
- tar import keeps hard links as extra entries for the same object

## 0.2.0 - 2026-10-30

- `cas serve`, `push`, `pull`: framed TCP protocol with a mutual token handshake, read-only mode, only missing chunks are sent; chunks cross the wire as stored (compressed or encrypted)
- Read-only WebDAV share of the snapshots (`serve --dav-listen`) with Range, ETag and optional Basic auth, and an HTTP `/metrics` listener
- `cas export` / `cas import`: snapshots as tar (ustar, GNU long names, pax on read)
- `cas check` and `cas repair --from`, `--max-size` quota, `cas metrics` (Prometheus), `--json` on every command, `cas bench`
- Per-chunk lz4 compression (`--compress lz4`) and encryption (XChaCha20-Poly1305, Argon2id, keyed chunk ids; `--password-file`, `cas passwd`); new v2 record layout with a FORMAT file, stores written before it keep working
- Directory snapshots: `cas snapshot create/ls/show/restore/diff/verify/forget/prune`, tree objects, retention rules (keep-last/daily/weekly/monthly)
- Gear (FastCDC-style) chunker as an alternative to Rabin, `--chunker gear` on the CLI; about 2x faster
- Weekly 30-minute fuzz run in its own workflow, uploads crash inputs; the CI badge is not affected by it
- API docs, SECURITY.md, CI jobs for docs and MSRV 1.89; cargo-audit runs weekly in its own workflow so a new advisory does not turn the CI badge red

## 0.1.0

First release.

- Rabin content-defined chunking (48-byte window, configurable min/avg/max), BLAKE3 chunk hashes
- Object id is the Merkle root of the chunk list; inclusion proofs via `cas prove`
- Append-only segment files, immutable manifests, automatic deduplication
- Memory-mapped open-addressing index, rebuilt from segments and manifests after an unclean shutdown
- Reference counting and compacting garbage collection
- Streaming `Read + Seek` object reader, concurrent readers
- Property tests, crash-injection tests (failpoints and hard kills), libFuzzer targets, criterion benchmarks

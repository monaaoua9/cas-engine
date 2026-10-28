# Changelog

## Unreleased

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

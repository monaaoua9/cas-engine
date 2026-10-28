# Changelog

## 0.1.0

First release.

- Rabin content-defined chunking (48-byte window, configurable min/avg/max), BLAKE3 chunk hashes
- Object id is the Merkle root of the chunk list; inclusion proofs via `cas prove`
- Append-only segment files, immutable manifests, automatic deduplication
- Memory-mapped open-addressing index, rebuilt from segments and manifests after an unclean shutdown
- Reference counting and compacting garbage collection
- Streaming `Read + Seek` object reader, concurrent readers
- Property tests, crash-injection tests (failpoints and hard kills), libFuzzer targets, criterion benchmarks

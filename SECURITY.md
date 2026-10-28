# Security

Report vulnerabilities privately through GitHub's "Report a vulnerability" button on the Security tab, not in a public issue.

In scope: anything that lets a crafted segment, manifest or index file cause memory unsafety, a panic on untrusted input, silent acceptance of corrupted data, or data loss after a crash. The single `unsafe` call (mapping the index file) is in `src/index.rs`.

Out of scope: the store is not encrypted and does not defend against someone who can already write to its directory.

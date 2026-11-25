# Real rehearsal seeds

The WAL and history-log corpora include 24 checksum-verified files from the
five-node PulseVM test-network evidence supplied for the handover rehearsal.
`MANIFEST.tsv` preserves the source descriptions with paths updated to this
corpus layout; `SHA256SUMS` records the source-file hashes. The files contain
public test-chain data and are used as fuzz seeds, not as expected-output
fixtures.

The WAL target is bounded to a 2,000,000-byte input in CI so it can exercise the
largest whole-log seed (`tornreal-262144.bin`). The current scanner cheaply
checks candidate frame prefixes before hashing them. The repo's replay tool in
`scripts/plw-replay-tool/` uses the same prefix filter and budget semantics.
